# Attack Lab — 공격 시뮬레이션 대시보드

7가지 공격 시나리오(SQL Injection, XSS, Directory Search, Login Brute Force, Port Scan, Credential Misuse, Vulnerable Image)를 표준 보안 도구로 실행하고 결과를 확인하는 대시보드입니다. 대시보드 자체는 `127.0.0.1:5050`에만 바인딩됩니다.

**대상은 시나리오별 공격 표면마다 직접 등록합니다** (더 이상 로컬 앱 하나로 고정되어 있지 않습니다). 등록할 때마다 "이 대상을 테스트할 권한이 있음을 확인합니다" 체크박스에 동의해야 저장됩니다 — 본인이 소유했거나 테스트 권한이 있는 대상만 등록하세요.

## 설치

```bash
cd ~/attack-simulator/attack-simulator-dashboard
python3 -m venv .venv && source .venv/bin/activate   # 선택 사항
pip install -r requirements.txt
./install-tools.sh   # sqlmap, zaproxy, gobuster, hydra, nmap, awscli, trivy 설치
```

도구별로 따로 설치하려면:

| 시나리오 | 도구 | apt 패키지 |
|---|---|---|
| SQL Injection | SQLmap | `sqlmap` |
| Cross-Site Scripting | OWASP ZAP | `zaproxy` |
| Directory Search | Gobuster | `gobuster` |
| Login Brute Force | Hydra | `hydra` |
| Port Scan | Nmap | `nmap` |
| Credential Misuse | AWS CLI | `awscli` |
| Vulnerable Image | Trivy | `trivy` |

Credential Misuse는 추가로 **본인 소유 AWS 계정의 읽기 전용 테스트 전용 IAM 프로파일**이 필요합니다 (`aws configure --profile <이름>`, `default` 프로파일은 등록 불가).

## 실행

```bash
python3 app.py
```

브라우저에서 `http://127.0.0.1:5050` 접속 → 시나리오 선택 → "+ 공격 표면 추가"로 대상을 등록.

- 각 공격 표면은 시나리오에 맞는 대상 정보(URL, 호스트, AWS 프로파일, 이미지 등)와 권한 확인 체크박스를 요구합니다.
- 각 행의 `실행`으로 한 대상만, 체크박스 + `선택 대상 실행`으로 여러 대상, `전체 순차 실행`으로 최대 10개를 순서대로 검사합니다.
- 각 검사는 최대 120초이며 동시에 하나의 묶음만 진행합니다.
- 검사 결과는 `logs/<실행 ID>.txt`와 `logs/<실행 ID>.json`에 남습니다. 웹 UI 실행 이력은 서버 재시작 시 초기화되지만(최근 200개까지 메모리 유지), 로그 파일은 계속 남습니다.
- 공격 표면 설정은 `config/<시나리오>_surfaces.json`에 유지됩니다. 재시작해도 등록된 표면은 남습니다. JSON 파일로 일괄 등록("파일에서 가져오기")도 지원하며, 예시는 `examples/`에 있습니다.

## 주의

- 각 도구의 "취약점/발견" 요약은 해당 도구 기준의 판정일 뿐이며, 대상 앱이나 인프라의 다른 방어 계층(WAF, CSRF 등)에 의해 실제로는 확인이 안 될 수 있습니다 — 실행 로그를 함께 확인하세요.
- `POST`는 폼 데이터만 지원하며, JSON 본문은 아직 지원하지 않습니다.
- Credential Misuse는 읽기 전용 조회(신원 확인, IAM 사용자/역할/액세스 키 목록) 4개로 고정되어 있으며, 리소스 열람이나 변경 작업은 지원하지 않습니다.
- 대상 등록 시 권한 확인 체크박스는 최소한의 안전장치일 뿐, 실제 테스트 권한 확인 책임은 사용자에게 있습니다.
