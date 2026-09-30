#!/usr/bin/env python3
"""
waf_flood_test.py
------------------
본인 소유의 ALB/WAF 엔드포인트로 (제한된 동시성·시간 안에서) HTTP 요청을 보내
WAF Rate-based Rule이 차단(403/429)을 시작하는지 확인하는 검증 도구.

* 반드시 본인이 소유·관리하는 리소스에만 사용하십시오.
* 이 도구는 rate limit "탐지 여부"를 확인하기 위한 것이며, 부하 상한이 걸려 있습니다
  (동시성 <= 50, 지속 <= 60s). 서비스 마비가 아니라 방어 규칙 검증이 목적입니다.
* 상태코드 분포로 WAF 탐지 여부를 판단합니다:
    - 200 만 계속 → 아직 rate limit 미도달 (상한 내에서 동시성/시간을 늘리세요)
    - 403 / 429 등장 → WAF가 탐지·차단 시작한 것

실행법: pip install requests
      python waf_flood_test.py <대상 URL> -c 50 -d 30
"""

import argparse
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

# ── 부하 상한 (대시보드 검증기와 동일하게 고정) ─────────
MAX_CONCURRENCY = 50   # 동시 워커 수 상한
MAX_DURATION = 60      # 지속 시간(초) 상한

# ── 집계용 전역 상태 ─────────────────────────────
counter = Counter()          # 상태코드별 카운트 (예: {200: 1500, 403: 320})
errors = 0                   # 연결 실패 등 예외 카운트
lock = threading.Lock()
stop_flag = threading.Event()


def send_one(url: str, timeout: float, verify: bool, headers: dict | None = None):
    """요청 1건 전송 후 상태코드를 집계."""
    global errors
    try:
        r = requests.get(url, timeout=timeout, verify=verify, headers=headers or None)
        with lock:
            counter[r.status_code] += 1
    except requests.RequestException:
        with lock:
            errors += 1


def worker(url: str, timeout: float, verify: bool, headers: dict | None = None):
    """stop_flag가 설정될 때까지 계속 요청을 보내는 워커."""
    while not stop_flag.is_set():
        send_one(url, timeout, verify, headers)


def build_headers(header_list: list[str], cookie: str | None) -> dict:
    """'-H "Name: value"' 반복 인자와 --cookie 값을 requests용 헤더 dict로 합친다."""
    headers: dict = {}
    for item in header_list or []:
        if ':' in item:
            name, value = item.split(':', 1)
            name = name.strip()
            if name:
                headers[name] = value.strip()
    if cookie:
        headers['Cookie'] = cookie
    return headers


def reporter(interval: float):
    """interval초마다 현재 상태코드 분포를 출력."""
    prev_total = 0
    while not stop_flag.is_set():
        time.sleep(interval)
        with lock:
            snapshot = dict(counter)
            total = sum(snapshot.values())
            err = errors
        rps = (total - prev_total) / interval
        prev_total = total
        blocked = snapshot.get(403, 0) + snapshot.get(429, 0)
        ok = snapshot.get(200, 0)
        block_ratio = (blocked / total * 100) if total else 0
        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"총 {total:>6} | ~{rps:5.0f} req/s | "
            f"200={ok:<6} 차단(403/429)={blocked:<6} "
            f"({block_ratio:4.1f}%) | 오류={err}"
        )


def main():
    p = argparse.ArgumentParser(description="WAF rate-limit 탐지 검증 도구 (부하 상한 적용)")
    p.add_argument("url", help="검증할 대상 URL (본인 소유 ALB/WAF 엔드포인트, 예: http://your-alb.example.com/)")
    p.add_argument("-c", "--concurrency", type=int, default=50,
                   help=f"동시 워커 수 (기본 50, 최대 {MAX_CONCURRENCY})")
    p.add_argument("-d", "--duration", type=float, default=30,
                   help=f"지속 시간(초) (기본 30, 최대 {MAX_DURATION})")
    p.add_argument("-t", "--timeout", type=float, default=5,
                   help="요청 타임아웃(초) (기본 5)")
    p.add_argument("-i", "--interval", type=float, default=2,
                   help="중간 보고 주기(초) (기본 2)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="HTTPS 인증서 검증을 건너뜁니다 (자체 서명/사설 CA 대상용). http 대상에는 영향 없음.")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="추가 요청 헤더 (반복 가능, 예: -H 'Authorization: Bearer xxx')")
    p.add_argument("--cookie", default=None,
                   help="요청에 사용할 Cookie 헤더 값 (예: 'session=abc; token=xyz')")
    args = p.parse_args()

    # 상한 적용: 이 도구는 방어 규칙 검증용이므로 무제한 플러드로 쓰이지 않도록 고정 상한을 강제한다.
    concurrency = max(1, min(args.concurrency, MAX_CONCURRENCY))
    duration = max(1.0, min(args.duration, float(MAX_DURATION)))
    if concurrency != args.concurrency or duration != args.duration:
        print(f"[상한] 동시성 {args.concurrency}->{concurrency}, "
              f"지속 {args.duration}->{duration}s 로 제한합니다 "
              f"(최대 {MAX_CONCURRENCY} / {MAX_DURATION}s).")

    # --insecure면 인증서 검증을 끈다. https 자체서명 대상용이며, http 대상에는 영향이 없다.
    verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = build_headers(args.header, args.cookie)

    print(f"대상   : {args.url}")
    print(f"동시성 : {concurrency}  |  지속: {duration}s  |  인증서 검증: {'off' if args.insecure else 'on'}")
    if headers:
        print(f"세션   : 헤더 {len(headers)}개 적용 ({', '.join(sorted(headers))})")
    print("-" * 60)

    rep = threading.Thread(target=reporter, args=(args.interval,), daemon=True)
    rep.start()

    start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for _ in range(concurrency):
            pool.submit(worker, args.url, args.timeout, verify, headers)
        time.sleep(duration)
        stop_flag.set()

    elapsed = time.time() - start
    total = sum(counter.values())
    blocked = counter.get(403, 0) + counter.get(429, 0)

    print("-" * 60)
    print("■ 최종 결과")
    print(f"  경과 시간   : {elapsed:.1f}s")
    print(f"  총 요청     : {total}  (평균 {total/elapsed:.0f} req/s)")
    print(f"  상태코드 분포: {dict(counter)}")
    print(f"  연결 오류   : {errors}")
    print("-" * 60)
    # 이모지 대신 ASCII 태그를 쓴다: 일부 콘솔(예: Windows cp949)에서 이모지가
    # 인코딩 오류로 출력을 막으면, 탐지 판정에 쓰는 아래 문자열까지 유실된다.
    if blocked > 0:
        print(f"[탐지] WAF 탐지 확인: 차단 응답(403/429) {blocked}건 발생")
    else:
        print("[미도달] 차단 응답 없음 → rate limit 미도달. "
              "상한 내에서 -c(동시성) 또는 -d(시간)를 늘려 다시 시도하십시오.")


if __name__ == "__main__":
    main()
