"""Attack Lab v9: preset security scans across multiple scenarios, user-supplied targets."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

from flask import Flask, abort, jsonify, render_template, request

BASE = Path(__file__).resolve().parent
LOG_DIR = BASE / 'logs'
CONFIG_DIR = BASE / 'config'
# Seed values only, used to pre-fill the bundled default surfaces and to
# backfill surfaces saved before per-surface targets existed. Each surface now
# carries its own target (base_url / host) plus an explicit authorized flag —
# see valid_*_surface below — so this is no longer an enforced restriction.
DEFAULT_BASE_URL = 'http://127.0.0.1:5000'
DEFAULT_PORTSCAN_HOST = '127.0.0.1'
BASE_URL_RE = re.compile(r'https?://[A-Za-z0-9.-]{1,253}(:\d{1,5})?')
HOST_RE = re.compile(r'[A-Za-z0-9.-]{1,253}')
PORT = 5050
MAX_SURFACES = 20
MAX_BATCH = 10
MAX_LOG_CHARS = 100_000
MAX_PARSE_CHARS = 2_000_000  # Separate, larger cap for the structured-output buffer used to detect findings.
MAX_PORTSCAN_PORTS = 2000
TIMEOUT_SECONDS = 120
MAX_JOBS_IN_MEMORY = 200
MAX_BATCHES_IN_MEMORY = 50
DIRECTORY_WORDLISTS = {
    'common': '/usr/share/wordlists/dirb/common.txt',
    'small': '/usr/share/wordlists/dirb/small.txt',
    'big': '/usr/share/wordlists/dirb/big.txt',
}
WORDLIST_DIR = BASE / 'wordlists'
BRUTEFORCE_WORDLISTS = {
    'quick': (WORDLIST_DIR / 'bruteforce_users_quick.txt', WORDLIST_DIR / 'bruteforce_passwords_quick.txt'),
    'standard': (WORDLIST_DIR / 'bruteforce_users_standard.txt', WORDLIST_DIR / 'bruteforce_passwords_standard.txt'),
}
IMAGE_REF_RE = re.compile(r'[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*(:[A-Za-z0-9_.-]{1,64})?')
# Read-only identity/inventory calls only — no resource enumeration (EC2/S3), no
# CloudTrail/GuardDuty lookups, and never a mutating call. Keeping this a fixed
# whitelist (rather than a free-form command field) is the point: it's the only
# scenario that talks to a real AWS account instead of the local loopback lab.
AWS_READONLY_COMMANDS = {
    'whoami': ['sts', 'get-caller-identity'],
    'iam-users': ['iam', 'list-users'],
    'iam-roles': ['iam', 'list-roles'],
    'iam-access-keys': ['iam', 'list-access-keys'],
}
ZAP_WORK_DIR = LOG_DIR / 'zap-work'
LOG_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=65_536, JSON_AS_ASCII=False)

SCENARIOS = [
    {'id': 'sqli', 'index': '01', 'name': 'SQL Injection', 'tool': 'SQLmap', 'layer': 'WEB / DATABASE', 'description': '등록된 API의 SQL 삽입 취약점을 검사합니다.', 'detector': 'WAF · 앱 로그', 'enabled': True},
    {'id': 'xss', 'index': '02', 'name': 'Cross-Site Scripting', 'tool': 'OWASP ZAP', 'layer': 'WEB / BROWSER', 'description': '입력값 반영과 스크립트 실행 위험을 검증합니다.', 'detector': 'WAF · 앱 로그', 'enabled': True},
    {'id': 'directory', 'index': '03', 'name': 'Directory Search', 'tool': 'Gobuster', 'layer': 'WEB / ROUTES', 'description': '웹 경로 탐색 요청과 응답을 분석합니다.', 'detector': 'ALB · 앱 로그', 'enabled': True},
    {'id': 'bruteforce', 'index': '04', 'name': 'Login Brute Force', 'tool': 'Hydra', 'layer': 'AUTH / WEB', 'description': '반복적인 인증 실패 패턴을 관찰합니다.', 'detector': 'WAF · 인증 로그', 'enabled': True},
    {'id': 'portscan', 'index': '05', 'name': 'Port Scan', 'tool': 'Nmap', 'layer': 'NETWORK / EC2', 'description': '대상 네트워크의 포트 탐색 패턴을 관찰합니다.', 'detector': 'VPC Flow · GuardDuty', 'enabled': True},
    {'id': 'credential', 'index': '06', 'name': 'Credential Misuse', 'tool': 'AWS CLI', 'layer': 'IAM / CLOUD', 'description': '자격증명의 API 사용 이력과 이상 징후를 확인합니다.', 'detector': 'CloudTrail · GuardDuty', 'enabled': True},
    {'id': 'image', 'index': '07', 'name': 'Vulnerable Image', 'tool': 'Trivy', 'layer': 'CONTAINER / K3S', 'description': '컨테이너 이미지의 알려진 취약점을 스캔합니다.', 'detector': 'Trivy · Inspector', 'enabled': True},
]

lock = threading.RLock()
jobs: dict[str, dict] = {}
active_batch: str | None = None
batches: dict[str, dict] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def write_json(path: Path, data) -> None:
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    tmp.replace(path)


def load_json_list(path: Path, defaults: list[dict]) -> list[dict]:
    if not path.exists():
        write_json(path, defaults)
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError(f'{path.name}은 배열이어야 합니다.')
    return data


def safe_post() -> bool:
    # Browser can't send a custom header on a simple cross-origin form POST.
    origin = request.headers.get('Origin')
    return (request.headers.get('X-Lab-Request') == 'attack-lab-v6' and
            request.host in ('127.0.0.1:5050', 'localhost:5050') and
            (origin is None or origin in ('http://127.0.0.1:5050', 'http://localhost:5050')))


@app.before_request
def restrict_host():
    if request.host not in ('127.0.0.1:5050', 'localhost:5050'):
        abort(403)
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and not safe_post():
        return jsonify({'error': '로컬 대시보드 요청만 허용합니다.'}), 403


# ---------------------------------------------------------------------------
# Per-scenario surface validation
# ---------------------------------------------------------------------------

def valid_base_url(data: dict) -> str:
    base_url = data.get('base_url', '')
    if not isinstance(base_url, str) or not BASE_URL_RE.fullmatch(base_url):
        raise ValueError('대상 URL은 "http://호스트[:포트]" 형식으로 입력하세요 (경로 없이, 스킴 포함).')
    return base_url


def require_authorized(data: dict) -> None:
    if data.get('authorized') is not True:
        raise ValueError('이 대상을 테스트할 권한이 있음을 확인해야 등록할 수 있습니다.')


def valid_sqli_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    method = data.get('method', '')
    endpoint = data.get('endpoint', '')
    parameter = data.get('parameter', '')
    test_value = data.get('test_value', '')
    base_url = valid_base_url(data)
    require_authorized(data)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if method not in ('GET', 'POST'):
        raise ValueError('GET 또는 POST(form)만 지원합니다.')
    if not isinstance(endpoint, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{0,95}', endpoint) or '//' in endpoint or '..' in endpoint:
        raise ValueError('엔드포인트는 /item처럼 경로만 입력하세요. 전체 URL, .., //는 사용할 수 없습니다.')
    if not isinstance(parameter, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,39}', parameter):
        raise ValueError('파라미터 이름은 영문, 숫자, 밑줄로 입력하세요.')
    if not isinstance(test_value, str) or not re.fullmatch(r'[^\r\n]{1,64}', test_value):
        raise ValueError('기본값은 줄바꿈 없이 1~64자로 입력하세요.')
    return {'name': name.strip(), 'base_url': base_url, 'method': method, 'endpoint': endpoint,
            'parameter': parameter, 'test_value': test_value, 'authorized': True}


def valid_bruteforce_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    method = data.get('method', '')
    endpoint = data.get('endpoint', '')
    user_field = data.get('user_field', '')
    pass_field = data.get('pass_field', '')
    failure_string = data.get('failure_string', '')
    wordlist = data.get('wordlist', '')
    base_url = valid_base_url(data)
    require_authorized(data)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if method not in ('GET', 'POST'):
        raise ValueError('GET 또는 POST(form)만 지원합니다.')
    if not isinstance(endpoint, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{0,95}', endpoint) or '//' in endpoint or '..' in endpoint:
        raise ValueError('로그인 경로는 /login처럼 경로만 입력하세요. 전체 URL, .., //는 사용할 수 없습니다.')
    if not isinstance(user_field, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,39}', user_field):
        raise ValueError('아이디 필드명은 영문, 숫자, 밑줄로 입력하세요.')
    if not isinstance(pass_field, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,39}', pass_field):
        raise ValueError('비밀번호 필드명은 영문, 숫자, 밑줄로 입력하세요.')
    if not isinstance(failure_string, str) or not re.fullmatch(r"[^:\r\n]{1,64}", failure_string.strip()):
        raise ValueError('실패 응답 문자열은 1~64자, 콜론(:)과 줄바꿈 없이 입력하세요.')
    if wordlist not in BRUTEFORCE_WORDLISTS:
        raise ValueError(f'자격증명 목록은 {", ".join(BRUTEFORCE_WORDLISTS)} 중 하나여야 합니다.')
    return {'name': name.strip(), 'base_url': base_url, 'method': method, 'endpoint': endpoint, 'user_field': user_field,
            'pass_field': pass_field, 'failure_string': failure_string.strip(), 'wordlist': wordlist, 'authorized': True}


def valid_xss_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    endpoint = data.get('endpoint', '')
    parameter = data.get('parameter', '')
    test_value = data.get('test_value', '')
    base_url = valid_base_url(data)
    require_authorized(data)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if not isinstance(endpoint, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{0,95}', endpoint) or '//' in endpoint or '..' in endpoint:
        raise ValueError('엔드포인트는 /item처럼 경로만 입력하세요. 전체 URL, .., //는 사용할 수 없습니다.')
    if not isinstance(parameter, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,39}', parameter):
        raise ValueError('파라미터 이름은 영문, 숫자, 밑줄로 입력하세요.')
    if not isinstance(test_value, str) or not re.fullmatch(r'[^\r\n]{1,64}', test_value):
        raise ValueError('기본값은 줄바꿈 없이 1~64자로 입력하세요.')
    return {'name': name.strip(), 'base_url': base_url, 'endpoint': endpoint, 'parameter': parameter,
            'test_value': test_value, 'authorized': True}


def valid_credential_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    profile = data.get('profile', '')
    command_key = data.get('command_key', '')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if not isinstance(profile, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', profile):
        raise ValueError('프로파일 이름은 영문, 숫자, -, _ 로 1~64자 입력하세요.')
    if profile.strip().lower() == 'default':
        raise ValueError('"default" 프로파일은 사용할 수 없습니다. 읽기 전용 테스트 전용 프로파일을 별도로 만드세요.')
    if command_key not in AWS_READONLY_COMMANDS:
        raise ValueError(f'명령은 {", ".join(AWS_READONLY_COMMANDS)} 중 하나여야 합니다.')
    return {'name': name.strip(), 'profile': profile, 'command_key': command_key}


def valid_directory_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    base_path = data.get('base_path', '')
    wordlist = data.get('wordlist', '')
    base_url = valid_base_url(data)
    require_authorized(data)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if not isinstance(base_path, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{0,95}', base_path) or '//' in base_path or '..' in base_path:
        raise ValueError('기준 경로는 /app처럼 경로만 입력하세요. 전체 URL, .., //는 사용할 수 없습니다.')
    if wordlist not in DIRECTORY_WORDLISTS:
        raise ValueError(f'워드리스트는 {", ".join(DIRECTORY_WORDLISTS)} 중 하나여야 합니다.')
    return {'name': name.strip(), 'base_url': base_url, 'base_path': base_path, 'wordlist': wordlist, 'authorized': True}


def _expand_port_count(spec: str) -> int:
    total = 0
    for token in spec.split(','):
        if '-' in token:
            lo, hi = token.split('-', 1)
            total += int(hi) - int(lo) + 1
        else:
            total += 1
    return total


def valid_portscan_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    ports = data.get('ports', '')
    host = data.get('host', '')
    require_authorized(data)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise ValueError('호스트는 도메인 또는 IP 형식으로 입력하세요 (스킴/경로 없이).')
    if not isinstance(ports, str) or not re.fullmatch(r'\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?){0,19}', ports):
        raise ValueError('포트는 "80", "1-1024", "22,80,443"처럼 최대 20개 구간까지 입력하세요.')
    for token in ports.split(','):
        parts = [int(p) for p in token.split('-')]
        if any(p < 1 or p > 65535 for p in parts) or (len(parts) == 2 and parts[0] > parts[1]):
            raise ValueError('포트 번호는 1~65535 범위여야 하며, 범위는 작은 값-큰 값 순서여야 합니다.')
    if _expand_port_count(ports) > MAX_PORTSCAN_PORTS:
        raise ValueError(f'한 번에 검사할 포트는 최대 {MAX_PORTSCAN_PORTS}개까지입니다.')
    return {'name': name.strip(), 'host': host, 'ports': ports, 'authorized': True}


def valid_image_surface(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('요청 형식이 올바르지 않습니다.')
    name = data.get('name', '')
    image = data.get('image', '')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError('이름은 1~48자여야 합니다.')
    if not isinstance(image, str) or not 1 <= len(image) <= 128 or not IMAGE_REF_RE.fullmatch(image):
        raise ValueError('이미지는 "nginx:1.25"처럼 이름[:태그] 형식으로 입력하세요. 레지스트리 호스트는 지원하지 않습니다.')
    return {'name': name.strip(), 'image': image}


# ---------------------------------------------------------------------------
# Per-scenario command builders — each returns (subprocess argv, display target)
# ---------------------------------------------------------------------------

def command_for_sqli(surface: dict, job_id: str) -> tuple[list[str], str]:
    url = surface['base_url'] + surface['endpoint']
    cmd = [shutil.which('sqlmap') or 'sqlmap']
    if surface['method'] == 'GET':
        target = url + '?' + urlencode({surface['parameter']: surface['test_value']})
        cmd += ['-u', target]
    else:
        target = url + ' [POST form]'
        cmd += ['-u', url, '--method=POST', '--data', urlencode({surface['parameter']: surface['test_value']})]
    cmd += ['-p', surface['parameter'], '--batch', '--level=1', '--risk=1', '--threads=1',
            '--technique=BEU', '--timeout=5', '--retries=0', '--flush-session', '--disable-coloring',
            '--output-dir', str(LOG_DIR / 'sqlmap-work')]
    return cmd, target


def zap_report_path(job_id: str) -> Path:
    return ZAP_WORK_DIR / f'{job_id}.json'


def free_local_port() -> int:
    # ZAP's own internal proxy defaults to 8080, which commonly collides with
    # other tools already running on the machine (Burp, other proxies). Ask
    # the OS for an unused loopback port instead of hardcoding one.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def command_for_xss(surface: dict, job_id: str) -> tuple[list[str], str]:
    url = surface['base_url'] + surface['endpoint'] + '?' + urlencode({surface['parameter']: surface['test_value']})
    ZAP_WORK_DIR.mkdir(exist_ok=True)
    report = zap_report_path(job_id)
    port = free_local_port()
    cmd = [shutil.which('zaproxy') or 'zaproxy', '-cmd', '-silent', '-host', '127.0.0.1', '-port', str(port),
           '-quickurl', url, '-quickout', str(report)]
    return cmd, url


def command_for_bruteforce(surface: dict, job_id: str) -> tuple[list[str], str]:
    parsed = urlparse(surface['base_url'])
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    scheme_prefix = 'https' if parsed.scheme == 'https' else 'http'
    module = f'{scheme_prefix}-post-form' if surface['method'] == 'POST' else f'{scheme_prefix}-get-form'
    user_file, pass_file = BRUTEFORCE_WORDLISTS[surface['wordlist']]
    form_spec = (f"{surface['endpoint']}:{surface['user_field']}=^USER^&{surface['pass_field']}=^PASS^:"
                 f"F={surface['failure_string']}")
    cmd = [shutil.which('hydra') or 'hydra', '-L', str(user_file), '-P', str(pass_file),
           '-f', '-I', '-t', '4', '-w', '5', '-s', str(port), host, module, form_spec]
    return cmd, f'{host}:{port}{surface["endpoint"]} ({module})'


def command_for_credential(surface: dict, job_id: str) -> tuple[list[str], str]:
    subcmd = AWS_READONLY_COMMANDS[surface['command_key']]
    cmd = [shutil.which('aws') or 'aws', '--profile', surface['profile'],
           '--output', 'json', '--no-cli-pager'] + subcmd
    return cmd, f'profile={surface["profile"]} · aws {" ".join(subcmd)}'


def command_for_directory(surface: dict, job_id: str) -> tuple[list[str], str]:
    url = surface['base_url'] + surface['base_path']
    wordlist = DIRECTORY_WORDLISTS[surface['wordlist']]
    cmd = [shutil.which('gobuster') or 'gobuster', 'dir', '-u', url, '-w', wordlist, '-k',
           '-t', '10', '--timeout', '5s', '-q', '--no-progress', '--no-error', '--no-color']
    return cmd, url


def command_for_portscan(surface: dict, job_id: str) -> tuple[list[str], str]:
    host = surface['host']
    cmd = [shutil.which('nmap') or 'nmap', '-oX', '-', '-Pn', '--max-retries', '1',
           '-T4', '--host-timeout', '100s', '-p', surface['ports'], host]
    return cmd, f'{host}:{surface["ports"]}'


def command_for_image(surface: dict, job_id: str) -> tuple[list[str], str]:
    image = surface['image']
    cmd = [shutil.which('trivy') or 'trivy', 'image', '--format', 'json', '--timeout', '100s', image]
    return cmd, image


# ---------------------------------------------------------------------------
# Per-scenario result detection — each returns (finding_found, summary)
# ---------------------------------------------------------------------------

def detect_sqli(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    # SQLmap's injection-point section is evidence of a positive result.
    pattern = r'(?m)^Parameter:\s*' + re.escape(surface['parameter']) + r'\s*\('
    found = bool(re.search(pattern, output, re.I))
    return found, ('취약점 탐지됨 · SQLmap 기준' if found else '검사 완료 · 취약점 미확인')


def detect_xss(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    # ZAP writes its report to -quickout rather than stdout, so read it from disk.
    count = 0
    try:
        data = json.loads(zap_report_path(job_id).read_text(encoding='utf-8'))
        for site in data.get('site') or []:
            for alert in site.get('alerts') or []:
                name = (alert.get('alert') or alert.get('name') or '').lower()
                if 'cross site scripting' in name or 'xss' in name:
                    count += int(alert.get('count') or 1)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        count = 0
    return count > 0, (f'XSS 취약점 {count}건 발견 · ZAP 기준' if count else '검사 완료 · XSS 미확인')


def detect_bruteforce(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    # Hydra sometimes inserts a "misc: ..." field between host and login; match loosely across it.
    match = re.search(r'(?m)^\[\d+\]\[https?-(?:post|get)-form\]\s+host:\s+\S+.*?login:\s+(\S+)\s+password:\s+(\S+)', output)
    if match:
        return True, f'유효한 자격증명 발견 · {match.group(1)}/{match.group(2)} · Hydra 기준'
    return False, '검사 완료 · 유효한 자격증명 없음'


def detect_credential(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return False, '검사 완료 · 응답 파싱 실패'
    key = surface['command_key']
    if key == 'whoami':
        return True, f'자격증명 유효 · {data.get("Arn", "?")} · AWS CLI 기준'
    if key == 'iam-users':
        count = len(data.get('Users') or [])
        return count > 0, (f'IAM 사용자 {count}명 조회됨 · AWS CLI 기준' if count else '검사 완료 · 조회된 사용자 없음')
    if key == 'iam-roles':
        count = len(data.get('Roles') or [])
        return count > 0, (f'IAM 역할 {count}개 조회됨 · AWS CLI 기준' if count else '검사 완료 · 조회된 역할 없음')
    if key == 'iam-access-keys':
        count = len(data.get('AccessKeyMetadata') or [])
        return count > 0, (f'액세스 키 {count}개 조회됨 · AWS CLI 기준' if count else '검사 완료 · 조회된 액세스 키 없음')
    return False, '검사 완료'


def detect_directory(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    hits = re.findall(r'(?m)^(\S+)\s+\(Status:\s*(\d{3})\)', output)
    found = len(hits) > 0
    return found, (f'노출된 경로 {len(hits)}개 발견 · Gobuster 기준' if found else '검사 완료 · 발견된 경로 없음')


def detect_portscan(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    count = 0
    try:
        root = ET.fromstring(output)
        for port_el in root.iter('port'):
            state = port_el.find('state')
            if state is not None and state.get('state') == 'open':
                count += 1
    except ET.ParseError:
        count = 0
    return count > 0, (f'열린 포트 {count}개 발견 · Nmap 기준' if count else '검사 완료 · 열린 포트 없음')


def detect_image(surface: dict, output: str, returncode: int, job_id: str) -> tuple[bool, str]:
    count = 0
    try:
        data = json.loads(output)
        for result in data.get('Results') or []:
            count += len(result.get('Vulnerabilities') or [])
    except (json.JSONDecodeError, AttributeError):
        count = 0
    return count > 0, (f'취약점 {count}건 발견 · Trivy 기준' if count else '검사 완료 · 취약점 없음')


def migrate_base_url_surfaces(surfaces: list[dict]) -> tuple[list[dict], bool]:
    # Surfaces saved before per-surface targets existed have neither field;
    # backfill them so old registrations keep working without edits.
    changed = False
    for s in surfaces:
        if 'base_url' not in s:
            s['base_url'] = DEFAULT_BASE_URL
            changed = True
        if 'authorized' not in s:
            s['authorized'] = True
            changed = True
    return surfaces, changed


def migrate_portscan_surfaces(surfaces: list[dict]) -> tuple[list[dict], bool]:
    changed = False
    for s in surfaces:
        if 'host' not in s:
            s['host'] = DEFAULT_PORTSCAN_HOST
            changed = True
        if 'authorized' not in s:
            s['authorized'] = True
            changed = True
    return surfaces, changed


SCENARIO_REGISTRY = {
    'sqli': {
        'file': CONFIG_DIR / 'sqli_surfaces.json',
        'defaults': [{'id': 'item-id', 'name': '상품 상세 조회', 'base_url': DEFAULT_BASE_URL, 'method': 'GET',
                      'endpoint': '/item', 'parameter': 'id', 'test_value': '1', 'authorized': True}],
        'validate': valid_sqli_surface, 'command': command_for_sqli, 'detect': detect_sqli,
        'tool_bin': 'sqlmap', 'missing_msg': 'SQLmap이 설치되지 않았습니다. sudo apt install sqlmap -y',
        'migrate': migrate_base_url_surfaces,
    },
    'xss': {
        'file': CONFIG_DIR / 'xss_surfaces.json',
        'defaults': [{'id': 'item-xss', 'name': '상품 상세 조회 XSS 점검', 'base_url': DEFAULT_BASE_URL,
                      'endpoint': '/item', 'parameter': 'id', 'test_value': '1', 'authorized': True}],
        'validate': valid_xss_surface, 'command': command_for_xss, 'detect': detect_xss,
        'tool_bin': 'zaproxy', 'missing_msg': 'ZAP이 설치되지 않았습니다. sudo apt install zaproxy -y',
        'migrate': migrate_base_url_surfaces,
    },
    'bruteforce': {
        'file': CONFIG_DIR / 'bruteforce_surfaces.json',
        'defaults': [{'id': 'login-quick', 'name': '로그인 폼 무차별 대입', 'base_url': DEFAULT_BASE_URL, 'method': 'POST',
                      'endpoint': '/login', 'user_field': 'username', 'pass_field': 'password',
                      'failure_string': 'invalid', 'wordlist': 'quick', 'authorized': True}],
        'validate': valid_bruteforce_surface, 'command': command_for_bruteforce, 'detect': detect_bruteforce,
        'tool_bin': 'hydra', 'missing_msg': 'Hydra가 설치되지 않았습니다. sudo apt install hydra -y',
        'migrate': migrate_base_url_surfaces,
    },
    'credential': {
        'file': CONFIG_DIR / 'credential_surfaces.json',
        # No invented default profile: this is the only scenario that touches a
        # real AWS account, so the user must deliberately register their own
        # dedicated read-only test profile before anything can run.
        'defaults': [],
        'validate': valid_credential_surface, 'command': command_for_credential, 'detect': detect_credential,
        'tool_bin': 'aws', 'missing_msg': 'AWS CLI가 설치되지 않았습니다. sudo apt install awscli -y',
    },
    'directory': {
        'file': CONFIG_DIR / 'directory_surfaces.json',
        'defaults': [{'id': 'root-common', 'name': '루트 경로 탐색', 'base_url': DEFAULT_BASE_URL,
                      'base_path': '/', 'wordlist': 'common', 'authorized': True}],
        'validate': valid_directory_surface, 'command': command_for_directory, 'detect': detect_directory,
        'tool_bin': 'gobuster', 'missing_msg': 'Gobuster가 설치되지 않았습니다. sudo apt install gobuster -y',
        'migrate': migrate_base_url_surfaces,
    },
    'portscan': {
        'file': CONFIG_DIR / 'portscan_surfaces.json',
        'defaults': [{'id': 'top-ports', 'name': '주요 포트 스캔', 'host': DEFAULT_PORTSCAN_HOST,
                      'ports': '1-1024', 'authorized': True}],
        'validate': valid_portscan_surface, 'command': command_for_portscan, 'detect': detect_portscan,
        'tool_bin': 'nmap', 'missing_msg': 'Nmap이 설치되지 않았습니다. sudo apt install nmap -y',
        'migrate': migrate_portscan_surfaces,
    },
    'image': {
        'file': CONFIG_DIR / 'image_surfaces.json',
        'defaults': [{'id': 'nginx-sample', 'name': '예시 웹 서버 이미지', 'image': 'nginx:1.25'}],
        'validate': valid_image_surface, 'command': command_for_image, 'detect': detect_image,
        'tool_bin': 'trivy', 'missing_msg': 'Trivy가 설치되지 않았습니다. sudo apt install trivy -y',
    },
}


def load_scenario_surfaces(cfg: dict) -> list[dict]:
    surfaces = load_json_list(cfg['file'], cfg['defaults'])
    migrate = cfg.get('migrate')
    if migrate:
        surfaces, changed = migrate(surfaces)
        if changed:
            write_json(cfg['file'], surfaces)
    return surfaces


surfaces_by_scenario: dict[str, list[dict]] = {
    scenario: load_scenario_surfaces(cfg) for scenario, cfg in SCENARIO_REGISTRY.items()
}


def registry_or_404(scenario: str) -> dict:
    cfg = SCENARIO_REGISTRY.get(scenario)
    if cfg is None:
        abort(404)
    return cfg


@app.get('/')
def home():
    return render_template('index.html', scenarios=SCENARIOS, default_base_url=DEFAULT_BASE_URL,
                            default_host=DEFAULT_PORTSCAN_HOST)


@app.get('/api/health')
def health():
    tools = {cfg['tool_bin']: bool(shutil.which(cfg['tool_bin'])) for cfg in SCENARIO_REGISTRY.values()}
    with lock:
        counts = {scenario: len(surfaces) for scenario, surfaces in surfaces_by_scenario.items()}
    return jsonify({'tools': tools, 'mode': 'dashboard-loopback',
                    'enabled_scenarios': list(SCENARIO_REGISTRY.keys()), 'surface_counts': counts})


@app.get('/api/surfaces/<scenario>')
def list_surfaces(scenario):
    registry_or_404(scenario)
    with lock:
        return jsonify(list(surfaces_by_scenario[scenario]))


@app.post('/api/surfaces/<scenario>')
def add_surface(scenario):
    cfg = registry_or_404(scenario)
    try:
        obj = cfg['validate'](request.get_json(silent=True))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    with lock:
        if active_batch:
            return jsonify({'error': '검사가 끝난 후 공격 표면을 수정하세요.'}), 409
        surfaces = surfaces_by_scenario[scenario]
        if len(surfaces) >= MAX_SURFACES:
            return jsonify({'error': f'최대 {MAX_SURFACES}개까지 등록할 수 있습니다.'}), 409
        obj['id'] = uuid.uuid4().hex[:12]
        surfaces.append(obj)
        write_json(cfg['file'], surfaces)
    return jsonify(obj), 201


@app.post('/api/surfaces/<scenario>/bulk')
def import_surfaces(scenario):
    cfg = registry_or_404(scenario)
    payload = request.get_json(silent=True)
    items = payload.get('surfaces') if isinstance(payload, dict) else payload
    if not isinstance(items, list) or not items:
        return jsonify({'error': '가져올 표면 배열이 비어 있거나 형식이 올바르지 않습니다.'}), 400
    if len(items) > MAX_SURFACES:
        return jsonify({'error': f'한 번에 가져올 수 있는 표면은 최대 {MAX_SURFACES}개입니다.'}), 400
    validated = []
    for idx, item in enumerate(items):
        try:
            validated.append(cfg['validate'](item))
        except ValueError as exc:
            return jsonify({'error': f'{idx + 1}번째 항목 오류: {exc}'}), 400
    with lock:
        if active_batch:
            return jsonify({'error': '검사가 끝난 후 공격 표면을 수정하세요.'}), 409
        surfaces = surfaces_by_scenario[scenario]
        if len(surfaces) + len(validated) > MAX_SURFACES:
            return jsonify({'error': f'최대 {MAX_SURFACES}개까지 등록할 수 있습니다. (현재 {len(surfaces)}개)'}), 409
        for obj in validated:
            obj['id'] = uuid.uuid4().hex[:12]
            surfaces.append(obj)
        write_json(cfg['file'], surfaces)
    return jsonify({'imported': len(validated), 'surfaces': validated}), 201


@app.put('/api/surfaces/<scenario>/<surface_id>')
def update_surface(scenario, surface_id):
    cfg = registry_or_404(scenario)
    try:
        obj = cfg['validate'](request.get_json(silent=True))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    with lock:
        if active_batch:
            return jsonify({'error': '검사가 끝난 후 공격 표면을 수정하세요.'}), 409
        surfaces = surfaces_by_scenario[scenario]
        old = next((s for s in surfaces if s['id'] == surface_id), None)
        if old is None:
            abort(404)
        old.update(obj)
        write_json(cfg['file'], surfaces)
        return jsonify(dict(old))


@app.delete('/api/surfaces/<scenario>/<surface_id>')
def delete_surface(scenario, surface_id):
    cfg = registry_or_404(scenario)
    with lock:
        if active_batch:
            return jsonify({'error': '검사가 끝난 후 공격 표면을 수정하세요.'}), 409
        surfaces = surfaces_by_scenario[scenario]
        if not any(s['id'] == surface_id for s in surfaces):
            abort(404)
        surfaces_by_scenario[scenario] = [s for s in surfaces if s['id'] != surface_id]
        write_json(cfg['file'], surfaces_by_scenario[scenario])
    return jsonify({'deleted': surface_id})


def append_log(job: dict, text: str) -> None:
    with lock:
        job['log'] = (job['log'] + text)[-MAX_LOG_CHARS:]


def exposed(job: dict, include_log=True) -> dict:
    keys = ('id', 'batch_id', 'scenario', 'surface_id', 'surface_name', 'target',
            'status', 'started_at', 'finished_at', 'summary', 'vulnerability_found', 'exit_code')
    data = {k: job.get(k) for k in keys}
    if include_log:
        data['log'] = job['log']
    return data


def save_job(job: dict) -> None:
    target = LOG_DIR / job['id']
    target.with_suffix('.txt').write_text(job['log'], encoding='utf-8')
    target.with_suffix('.json').write_text(json.dumps(exposed(job, include_log=False), ensure_ascii=False, indent=2), encoding='utf-8')


def prune_memory() -> None:
    # In-memory history only (logs on disk are untouched); keeps long-running
    # processes from growing jobs/batches without bound.
    with lock:
        if len(jobs) > MAX_JOBS_IN_MEMORY:
            for job_id in list(jobs.keys())[:len(jobs) - MAX_JOBS_IN_MEMORY]:
                del jobs[job_id]
        if len(batches) > MAX_BATCHES_IN_MEMORY:
            completed = [b['id'] for b in batches.values() if b['id'] != active_batch]
            for batch_id in completed[:len(batches) - MAX_BATCHES_IN_MEMORY]:
                del batches[batch_id]


def execute_job(job: dict, surface: dict, cfg: dict) -> None:
    with lock:
        job['status'] = 'running'
        job['started_at'] = now()
    command, _ = cfg['command'](surface, job['id'])
    append_log(job, f'[{now()}] {surface["name"]} · {job["target"]}\n')
    stdout_chunks: list[str] = []
    stdout_len = 0
    try:
        with subprocess.Popen(command, cwd=BASE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, errors='replace', bufsize=1, stdin=subprocess.DEVNULL,
                              start_new_session=True) as proc:
            drained_out = threading.Event()
            drained_err = threading.Event()

            def read_stdout():
                nonlocal stdout_len
                assert proc.stdout is not None
                for line in proc.stdout:
                    append_log(job, line)
                    if stdout_len < MAX_PARSE_CHARS:
                        stdout_chunks.append(line)
                        stdout_len += len(line)
                drained_out.set()

            def read_stderr():
                assert proc.stderr is not None
                for line in proc.stderr:
                    append_log(job, line)
                drained_err.set()

            threading.Thread(target=read_stdout, daemon=True).start()
            threading.Thread(target=read_stderr, daemon=True).start()
            begin = time.monotonic()
            while proc.poll() is None and time.monotonic() - begin < TIMEOUT_SECONDS:
                time.sleep(0.2)
            if proc.poll() is None:
                # kill the whole process group, not just the direct child: tools
                # like Hydra (-t N) fork worker processes that would otherwise
                # survive, keep the stdout/stderr pipes open, and wedge the
                # reader threads (and the batch lock) forever.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    proc.kill()
                proc.wait(timeout=5)
                status = 'timeout'
                append_log(job, '\n[제한] 최대 실행 시간이 초과되었습니다.\n')
            else:
                status = 'completed' if proc.returncode == 0 else 'failed'
            drained_out.wait(timeout=3)
            drained_err.wait(timeout=3)
            with lock:
                if status == 'completed':
                    found, summary = cfg['detect'](surface, ''.join(stdout_chunks), proc.returncode, job['id'])
                else:
                    found, summary = False, '검사 중단 · 로그 확인 필요'
                job['vulnerability_found'] = found
                job['status'] = status
                job['exit_code'] = proc.returncode
                job['summary'] = summary
    except FileNotFoundError:
        append_log(job, f'{cfg["tool_bin"]}이 없습니다. {cfg["missing_msg"]}\n')
        with lock:
            job['status'], job['summary'] = 'failed', f'{cfg["tool_bin"]} 미설치'
    except Exception as exc:
        append_log(job, f'검사 오류: {type(exc).__name__}: {exc}\n')
        with lock:
            job['status'], job['summary'] = 'failed', '실행 오류 · 로그 확인 필요'
    finally:
        with lock:
            job['finished_at'] = now()
        save_job(job)
        prune_memory()


def execute_batch(batch_id: str, scenario: str, selected: list[dict]) -> None:
    global active_batch
    cfg = SCENARIO_REGISTRY[scenario]
    try:
        for surface in selected:
            with lock:
                job = next(j for j in jobs.values() if j['batch_id'] == batch_id and j['surface_id'] == surface['id'])
                batches[batch_id]['current_job_id'] = job['id']
            execute_job(job, surface, cfg)
        with lock:
            batches[batch_id]['status'] = 'completed'
            batches[batch_id]['current_job_id'] = None
    finally:
        with lock:
            batches[batch_id]['finished_at'] = now()
            active_batch = None


@app.post('/api/run/<scenario>')
def run_scenario(scenario):
    global active_batch
    cfg = SCENARIO_REGISTRY.get(scenario)
    if cfg is None:
        abort(404)
    data = request.get_json(silent=True)
    ids = data.get('surface_ids') if isinstance(data, dict) else None
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_BATCH or not all(isinstance(v, str) for v in ids) or len(ids) != len(set(ids)):
        return jsonify({'error': f'고유한 공격 표면 ID를 1~{MAX_BATCH}개 선택하세요.'}), 400
    if not shutil.which(cfg['tool_bin']):
        return jsonify({'error': cfg['missing_msg']}), 422
    with lock:
        if active_batch:
            return jsonify({'error': '다른 검사가 진행 중입니다.'}), 409
        pool = surfaces_by_scenario[scenario]
        selected = [dict(s) for s in pool if s['id'] in ids]
        if len(selected) != len(ids):
            return jsonify({'error': '존재하지 않는 공격 표면이 포함되어 있습니다.'}), 404
        # Keep UI checkbox order stable.
        selected.sort(key=lambda s: ids.index(s['id']))
        batch_id = uuid.uuid4().hex[:12]
        batch = {'id': batch_id, 'status': 'running', 'started_at': now(),
                 'finished_at': None, 'current_job_id': None, 'job_ids': []}
        for s in selected:
            job_id = uuid.uuid4().hex[:12]
            _, target = cfg['command'](s, job_id)
            job = {'id': job_id, 'batch_id': batch_id, 'scenario': scenario,
                   'surface_id': s['id'], 'surface_name': s['name'], 'target': target, 'status': 'queued',
                   'started_at': None, 'finished_at': None, 'summary': '실행 대기 중',
                   'vulnerability_found': None, 'exit_code': None, 'log': ''}
            jobs[job['id']] = job
            batch['job_ids'].append(job['id'])
        batches[batch_id] = batch
        active_batch = batch_id
    threading.Thread(target=execute_batch, args=(batch_id, scenario, selected), daemon=True).start()
    return jsonify({'batch_id': batch_id, 'job_ids': batch['job_ids']}), 202


@app.get('/api/batches/<batch_id>')
def batch_status(batch_id):
    with lock:
        batch = batches.get(batch_id)
        if batch is None:
            abort(404)
        return jsonify({**batch, 'jobs': [exposed(jobs[jid], include_log=False) for jid in batch['job_ids']]})


@app.get('/api/jobs')
def recent_jobs():
    with lock:
        recent = list(reversed(list(jobs.values())))[:40]
        return jsonify([exposed(j, include_log=False) for j in recent])


@app.get('/api/jobs/<job_id>')
def job_status(job_id):
    with lock:
        job = jobs.get(job_id)
        if job is None:
            abort(404)
        return jsonify(exposed(job))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=PORT, debug=False, threaded=True)
