#!/usr/bin/env bash
# 로그 정리: 최신 job N개만 남기고 오래된 것은 삭제한다.
# job 하나 = logs/<id>.txt + logs/<id>.json 한 쌍. .txt 수정시각 기준으로 최신 N개 유지.
# 대시보드 이력은 메모리에 있으므로 이 파일들을 지워도 앱 동작에는 영향 없다.
set -euo pipefail

# 유지할 개수 (기본 10). 첫 번째 인자로 덮어쓸 수 있음: ./cleanup-logs.sh 20
KEEP="${1:-10}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"

if [[ ! -d "$LOG_DIR" ]]; then
  echo "로그 디렉터리가 없습니다: $LOG_DIR"
  exit 0
fi

# .txt 로그를 수정시각 최신순으로 나열
mapfile -t TXT_LOGS < <(ls -1t "$LOG_DIR"/*.txt 2>/dev/null || true)
TOTAL="${#TXT_LOGS[@]}"

if (( TOTAL <= KEEP )); then
  echo "현재 job 로그 ${TOTAL}개 (유지 기준 ${KEEP}개 이하) — 삭제할 것 없음."
  exit 0
fi

DELETED=0
# 최신 KEEP개는 건너뛰고, 그 뒤(오래된 것)를 삭제
for (( i=KEEP; i<TOTAL; i++ )); do
  txt="${TXT_LOGS[$i]}"
  json="${txt%.txt}.json"      # 같은 id의 json 짝도 함께 삭제
  rm -f -- "$txt" "$json"
  (( DELETED++ )) || true
done

echo "job 로그 정리 완료: 총 ${TOTAL}개 중 최신 ${KEEP}개 유지, ${DELETED}개 삭제."

# sqlmap / zap 작업 디렉터리도 남은 job과 무관하게 커질 수 있어 함께 비운다.
# (남길 job과 매핑돼 있지 않은 부산물이므로 통째로 정리)
if compgen -G "$LOG_DIR/sqlmap-work/*" > /dev/null; then
  rm -rf -- "$LOG_DIR"/sqlmap-work/*
  echo "  · sqlmap-work 정리됨"
fi
if compgen -G "$LOG_DIR/zap-work/*" > /dev/null; then
  rm -rf -- "$LOG_DIR"/zap-work/*
  echo "  · zap-work 정리됨"
fi
