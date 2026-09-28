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

## 사용법

**1. 대시보드 실행**

```bash
python3 app.py
```

브라우저에서 `http://127.0.0.1:5050`에 접속합니다.

**2. 시나리오 선택 → 공격 표면 등록**

시나리오를 고른 뒤 "+ 공격 표면 추가"로 테스트 대상을 등록합니다.

- 각 공격 표면은 시나리오에 맞는 대상 정보(URL, 호스트, AWS 프로파일, 이미지 등)와 권한 확인 체크박스를 요구합니다.
- JSON 파일로 일괄 등록("파일에서 가져오기")도 지원하며, 예시는 `examples/`에 있습니다.

**3. 검사 실행**

| 방법 | 대상 |
|---|---|
| 각 행의 `실행` | 한 대상만 |
| 체크박스 + `선택 대상 실행` | 선택한 여러 대상 |
| `전체 순차 실행` | 등록된 표면을 최대 10개까지 순서대로 |

각 검사는 최대 120초이며, 동시에 하나의 묶음만 진행합니다.

**4. 결과 확인**

- 검사 결과는 `logs/<실행 ID>.txt`와 `logs/<실행 ID>.json`에 남습니다.
- 웹 UI 실행 이력은 서버 재시작 시 초기화되지만(최근 200개까지 메모리 유지), 로그 파일은 계속 남습니다.
- 공격 표면 설정은 `config/<시나리오>_surfaces.json`에 유지되어 재시작해도 남습니다.

## 주의

- 각 도구의 "취약점/발견" 요약은 해당 도구 기준의 판정일 뿐이며, 대상 앱이나 인프라의 다른 방어 계층(WAF, CSRF 등)에 의해 실제로는 확인이 안 될 수 있습니다 — 실행 로그를 함께 확인하세요.
- `POST`는 폼 데이터만 지원하며, JSON 본문은 아직 지원하지 않습니다.
- Credential Misuse는 읽기 전용 조회(신원 확인, IAM 사용자/역할/액세스 키 목록) 4개로 고정되어 있으며, 리소스 열람이나 변경 작업은 지원하지 않습니다.
- 대상 등록 시 권한 확인 체크박스는 최소한의 안전장치일 뿐, 실제 테스트 권한 확인 책임은 사용자에게 있습니다.

## 용어 표기 규칙

문서·코드·UI 전반에서 아래 용어를 일관되게 사용합니다.

| 용어 | 가리키는 것 | 예 |
|---|---|---|
| **도구 (tool)** | 시나리오가 실제로 실행하는 보안 실행 프로그램 | SQLmap, OWASP ZAP, Gobuster, Hydra, Nmap, AWS CLI, Trivy |
| **apt 패키지** | `apt install`로 설치하는 시스템 패키지 (도구의 설치 단위, 소문자) | `sqlmap`, `zaproxy`, `gobuster`, `hydra`, `nmap`, `awscli`, `trivy` |
| **파이썬 라이브러리** | `pip install`로 설치하는 파이썬 의존성 (`requirements.txt`) | Flask |
| **시나리오 (scenario)** | 하나의 공격 유형과 그에 매핑된 도구 | SQL Injection → SQLmap |
| **공격 표면 (surface)** | 시나리오별로 등록하는 개별 테스트 대상 | URL, 호스트, AWS 프로파일, 이미지 |

- **"라이브러리"는 `pip` 대상 파이썬 의존성에만** 씁니다. 보안 도구나 그 묶음을 "라이브러리"라고 부르지 않습니다.
- 대문자 제품명(`SQLmap`)은 **도구**, 소문자 이름(`sqlmap`)은 **apt 패키지 이름**으로 구분합니다.
