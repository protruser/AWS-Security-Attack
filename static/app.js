'use strict';

const $ = (id) => document.getElementById(id);
const rows = [...document.querySelectorAll('[data-select]')];
let selectedScenario = rows[0];
let surfaces = [];
let selectedIds = new Set();
let editingId = null;
let activeBatch = null;
let batchPoll = null;
let pollFailures = 0;
const MAX_POLL_FAILURES = 3;
let toolStatus = {};
let surfacesLoading = false;
const AUTH_FIELD = {key: 'authorized', label: '테스트 권한 확인', type: 'checkbox',
  checkboxLabel: '이 대상을 테스트할 권한이 있음을 확인합니다', required: true};

// Each implemented scenario declares its own surface fields (for the editor
// form), how to render one row's detail column, and which /api/health tool
// key gates running it. Scenarios absent from this map are shown as
// "PLANNED" and their surfaces section stays hidden.
const SCENARIOS_META = {
  credential: {
    tool: 'aws',
    scopeLabel: '대상 계정',
    scopeDesc: '본인 소유 계정의 읽기 전용 테스트 전용 IAM 프로파일만 등록하세요. 실제 AWS API가 호출됩니다.',
    sectionDesc: 'AWS CLI 프로파일과 읽기 전용 조회 명령을 등록하고 관리합니다.',
    editorNote: '"default" 프로파일은 사용할 수 없습니다. 반드시 읽기 전용(ReadOnlyAccess 등) 권한만 가진 별도 테스트용 프로파일을 aws configure로 먼저 만들어두세요.',
    addLabel: '+ 공격 표면 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '자격증명 점검'},
      {key: 'profile', label: 'AWS CLI 프로파일', maxlength: 64, required: true, placeholder: 'attack-lab-readonly'},
      {key: 'command_key', label: '조회 명령', type: 'select', options: [
        ['whoami', 'whoami · 자격증명 신원 확인'],
        ['iam-users', 'iam-users · IAM 사용자 목록'],
        ['iam-roles', 'iam-roles · IAM 역할 목록'],
        ['iam-access-keys', 'iam-access-keys · 액세스 키 목록'],
      ]},
    ],
    detail: (s) => `profile=${s.profile} · ${s.command_key}`,
  },
  xss: {
    tool: 'zaproxy',
    scopeLabel: '대상 설정',
    scopeDesc: 'ZAP이 이 경로에서 시작해 크롤링·능동 스캔으로 XSS 위험을 검사합니다.',
    sectionDesc: '대상 URL, 크롤링을 시작할 API 경로와 시드 파라미터를 등록하고 관리합니다.',
    editorNote: 'ZAP이 이 경로부터 사이트를 크롤링하며 검사합니다. 스캔에 최대 120초까지 걸릴 수 있습니다. 본인이 테스트 권한을 가진 대상만 등록하세요.',
    addLabel: '+ 공격 표면 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '상품 상세 조회'},
      {key: 'base_url', label: '대상 URL', maxlength: 128, required: true, placeholder: 'http://127.0.0.1:5000'},
      {key: 'endpoint', label: 'API 경로', maxlength: 96, required: true, placeholder: '/item'},
      {key: 'parameter', label: '시드 파라미터', maxlength: 40, required: true, placeholder: 'id'},
      {key: 'test_value', label: '기본값', maxlength: 64, required: true, placeholder: '1'},
      AUTH_FIELD,
    ],
    detail: (s) => `${s.base_url}${s.endpoint}?${s.parameter}=${s.test_value}`,
  },
  sqli: {
    tool: 'sqlmap',
    scopeLabel: '대상 설정',
    scopeDesc: '현재 등록한 대상에서 검사할 API 경로와 파라미터를 설정합니다.',
    sectionDesc: '대상 URL, API 경로, 검사 파라미터를 등록하고 관리합니다.',
    editorNote: '등록한 API 경로가 실제로 존재해야 합니다. JSON 본문과 인증 헤더는 이 버전에서 지원하지 않습니다. 본인이 테스트 권한을 가진 대상만 등록하세요.',
    addLabel: '+ 공격 표면 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '상품 검색'},
      {key: 'base_url', label: '대상 URL', maxlength: 128, required: true, placeholder: 'http://127.0.0.1:5000'},
      {key: 'method', label: 'HTTP 메서드', type: 'select', options: [['GET', 'GET'], ['POST', 'POST (form)']]},
      {key: 'endpoint', label: 'API 경로', maxlength: 96, required: true, placeholder: '/search'},
      {key: 'parameter', label: '검사 파라미터', maxlength: 40, required: true, placeholder: 'keyword'},
      {key: 'test_value', label: '기본값', maxlength: 64, required: true, placeholder: 'phone'},
      AUTH_FIELD,
    ],
    detail: (s) => `${s.base_url} · ${s.method} ${s.endpoint} · 파라미터 ${s.parameter}=${s.test_value}`,
  },
  bruteforce: {
    tool: 'hydra',
    scopeLabel: '대상 설정',
    scopeDesc: '등록한 대상의 로그인 폼에 사전 기반 자격증명 대입을 시도합니다.',
    sectionDesc: '대상 URL, 로그인 폼 경로, 필드명, 실패 판별 문자열을 등록하고 관리합니다.',
    editorNote: '실패한 로그인 응답에 공통으로 나타나는 문자열(예: "invalid")을 입력하세요. 콜론(:)은 사용할 수 없습니다. 본인이 테스트 권한을 가진 대상만 등록하세요.',
    addLabel: '+ 공격 표면 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '로그인 폼 대입'},
      {key: 'base_url', label: '대상 URL', maxlength: 128, required: true, placeholder: 'http://127.0.0.1:5000'},
      {key: 'method', label: 'HTTP 메서드', type: 'select', options: [['POST', 'POST (form)'], ['GET', 'GET']]},
      {key: 'endpoint', label: '로그인 경로', maxlength: 96, required: true, placeholder: '/login'},
      {key: 'user_field', label: '아이디 필드명', maxlength: 40, required: true, placeholder: 'username'},
      {key: 'pass_field', label: '비밀번호 필드명', maxlength: 40, required: true, placeholder: 'password'},
      {key: 'failure_string', label: '실패 응답 문자열', maxlength: 64, required: true, placeholder: 'invalid'},
      {key: 'wordlist', label: '자격증명 목록', type: 'select',
        options: [['quick', 'quick (3×5, 빠름)'], ['standard', 'standard (7×10)']]},
      AUTH_FIELD,
    ],
    detail: (s) => `${s.base_url} · ${s.method} ${s.endpoint} · ${s.user_field}/${s.pass_field} · ${s.wordlist}`,
  },
  directory: {
    tool: 'gobuster',
    scopeLabel: '대상 설정',
    scopeDesc: '등록한 대상에서 경로 탐색을 시작할 기준 경로와 워드리스트를 설정합니다.',
    sectionDesc: '대상 URL, 기준 경로와 워드리스트를 등록하고 관리합니다.',
    editorNote: '기준 경로는 실제로 존재하는 상위 경로를 입력하세요. 결과는 404가 아닌 응답만 표시됩니다. 본인이 테스트 권한을 가진 대상만 등록하세요.',
    addLabel: '+ 공격 표면 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '루트 경로 탐색'},
      {key: 'base_url', label: '대상 URL', maxlength: 128, required: true, placeholder: 'http://127.0.0.1:5000'},
      {key: 'base_path', label: '기준 경로', maxlength: 96, required: true, placeholder: '/'},
      {key: 'wordlist', label: '워드리스트', type: 'select',
        options: [['common', 'common (기본)'], ['small', 'small (빠름)'], ['big', 'big (느림 · 정밀)']]},
      AUTH_FIELD,
    ],
    detail: (s) => `${s.base_url}${s.base_path} · 워드리스트 ${s.wordlist}`,
  },
  portscan: {
    tool: 'nmap',
    scopeLabel: '대상 설정',
    scopeDesc: '등록한 호스트의 포트 범위를 검사합니다.',
    sectionDesc: '검사할 대상 호스트와 포트 범위를 등록하고 관리합니다.',
    editorNote: '포트는 "80", "1-1024", "22,80,443"처럼 최대 20개 구간 · 총 2000개까지 입력할 수 있습니다. 본인이 테스트 권한을 가진 대상만 등록하세요.',
    addLabel: '+ 포트 범위 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '주요 포트 스캔'},
      {key: 'host', label: '대상 호스트', maxlength: 253, required: true, placeholder: '127.0.0.1'},
      {key: 'ports', label: '포트 범위', maxlength: 64, required: true, placeholder: '1-1024'},
      AUTH_FIELD,
    ],
    detail: (s) => `${s.host} · 포트 ${s.ports}`,
  },
  image: {
    tool: 'trivy',
    scopeLabel: '검사 대상',
    scopeDesc: 'Trivy가 이미지를 내려받아 알려진 취약점을 스캔합니다. 프라이빗 레지스트리 인증은 지원하지 않습니다.',
    sectionDesc: '스캔할 컨테이너 이미지를 등록하고 관리합니다.',
    editorNote: '이미지는 "nginx:1.25"처럼 이름[:태그] 형식으로 입력하세요. 레지스트리 호스트는 지원하지 않습니다.',
    addLabel: '+ 이미지 추가',
    fields: [
      {key: 'name', label: '표면 이름', maxlength: 48, required: true, placeholder: '예시 이미지'},
      {key: 'image', label: '이미지:태그', maxlength: 128, required: true, placeholder: 'nginx:1.25'},
    ],
    detail: (s) => s.image,
  },
};

async function api(url, options = {}) {
  const method = options.method || 'GET';
  const headers = method === 'GET' ? {} : {'Content-Type': 'application/json', 'X-Lab-Request': 'attack-lab-v6'};
  const response = await fetch(url, {cache: 'no-store', ...options, headers: {...headers, ...(options.headers || {})}});
  const content = await response.json();
  if (!response.ok) throw new Error(content.error || `요청 실패 (${response.status})`);
  return content;
}

function notice(text) { $('surfaceHint').textContent = text; }
function active() { return Boolean(activeBatch); }
function currentMeta() { return SCENARIOS_META[selectedScenario?.dataset.select]; }

function renderScenario(row) {
  if (!row) return;
  selectedScenario = row;
  rows.forEach(r => { r.classList.toggle('selected', r === row); r.setAttribute('aria-pressed', String(r === row)); });
  const s = row.dataset;
  $('detailIndex').textContent = `SCENARIO / ${s.index}`;
  $('detailBadge').textContent = s.enabled === 'true' ? 'READY TO RUN' : 'IN DEVELOPMENT';
  $('detailBadge').classList.toggle('planned', s.enabled !== 'true');
  $('detailLayer').textContent = s.layer;
  $('detailName').textContent = s.name;
  $('detailDescription').textContent = s.description;
  $('detailTool').textContent = s.tool;
  $('detailDetector').textContent = s.detector;
  $('detailMode').textContent = s.enabled === 'true' ? 'CONFIGURED' : 'NOT CONNECTED';
  $('actionArrow').textContent = s.enabled === 'true' ? '↘' : '—';
  $('actionHint').textContent = s.enabled === 'true'
    ? '아래에서 공격 표면을 등록하고 실행 대상을 선택하세요.'
    : '이 시나리오의 실행 모듈은 아직 연결되지 않았습니다.';
  $('runLabel').textContent = s.enabled === 'true' ? '공격 표면 선택으로 이동' : '추후 연동 예정';
  $('runSelected').disabled = s.enabled !== 'true';

  const meta = SCENARIOS_META[s.select];
  $('surfaces').hidden = !meta;
  editingId = null; selectedIds = new Set();
  $('surfaceForm').hidden = true;
  if (meta) {
    $('surfaceScenarioName').textContent = s.name;
    $('surfaceSectionDesc').textContent = meta.sectionDesc;
    $('surfaceScopeLabel').textContent = meta.scopeLabel;
    $('surfaceScopeDesc').textContent = meta.scopeDesc;
    $('editorNote').textContent = meta.editorNote;
    $('addSurface').textContent = meta.addLabel;
    $('importSurfaces').title = `JSON 배열 업로드 · 각 항목 필드: ${meta.fields.map(f => f.key).join(', ')}`;
    // Clear stale surfaces synchronously so renderSurfaces() (called from the
    // in-flight refreshHealth() below) never pairs the new scenario's `meta`
    // with the previous scenario's surface objects while fetchSurfaces() is pending.
    surfaces = [];
    surfacesLoading = true;
    renderSurfaces();
    fetchSurfaces();
    refreshHealth();
  }
}

function actionButton(text, css, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = css;
  button.textContent = text;
  button.disabled = active();
  button.addEventListener('click', handler);
  return button;
}

function refreshButtons() {
  const meta = currentMeta();
  const toolReady = Boolean(meta && toolStatus[meta.tool]);
  $('runSelectedSurfaces').disabled = active() || !toolReady || selectedIds.size === 0;
  $('runAllSurfaces').disabled = active() || !toolReady || surfaces.length === 0 || surfaces.length > 10;
  $('addSurface').disabled = active() || surfaces.length >= 20;
  $('selectAll').checked = surfaces.length > 0 && selectedIds.size === surfaces.length;
  $('selectAll').indeterminate = selectedIds.size > 0 && selectedIds.size < surfaces.length;
  $('surfaceCount').textContent = String(surfaces.length).padStart(2, '0');
}

function renderSurfaces() {
  const meta = currentMeta();
  const tbody = $('surfaceRows');
  tbody.replaceChildren();
  if (!meta) { refreshButtons(); return; }
  const toolReady = Boolean(toolStatus[meta.tool]);
  if (!surfaces.length) {
    const tr = document.createElement('tr'); const td = document.createElement('td');
    td.colSpan = 4;
    td.textContent = surfacesLoading ? '공격 표면을 불러오는 중...' : `등록된 공격 표면이 없습니다. [${meta.addLabel}]로 등록하세요.`;
    tr.append(td); tbody.append(tr);
  }
  for (const s of surfaces) {
    const tr = document.createElement('tr');
    const check = document.createElement('input'); check.type = 'checkbox';
    check.checked = selectedIds.has(s.id); check.disabled = active();
    check.setAttribute('aria-label', `${s.name} 선택`);
    check.addEventListener('change', () => { if (check.checked) selectedIds.add(s.id); else selectedIds.delete(s.id); refreshButtons(); });
    const checkTd = document.createElement('td'); checkTd.append(check);
    const name = document.createElement('td'); name.textContent = s.name;
    const detailTd = document.createElement('td'); const detailCode = document.createElement('code'); detailCode.textContent = meta.detail(s); detailTd.append(detailCode);
    const actions = document.createElement('td');
    const runBtn = actionButton('실행', 'small-action', () => start([s.id]));
    if (!toolReady) runBtn.disabled = true;
    actions.append(runBtn, actionButton('편집', 'small-action', () => openEditor(s)),
      actionButton('삭제', 'small-action danger', () => removeSurface(s)));
    tr.append(checkTd, name, detailTd, actions);
    tbody.append(tr);
  }
  refreshButtons();
}

async function fetchSurfaces() {
  const meta = currentMeta();
  if (!meta) return;
  const scenario = selectedScenario.dataset.select;
  try {
    surfaces = await api(`/api/surfaces/${scenario}`);
    selectedIds = new Set([...selectedIds].filter(id => surfaces.some(s => s.id === id)));
    if (surfaces.length === 1 && selectedIds.size === 0) selectedIds.add(surfaces[0].id);
  } catch (err) {
    notice(`공격 표면 조회 실패: ${err.message}`);
  } finally {
    surfacesLoading = false;
    renderSurfaces();
  }
}

function openEditor(surface = null) {
  const meta = currentMeta();
  if (!meta) return;
  editingId = surface?.id || null;
  $('editorTitle').textContent = surface ? '공격 표면 편집' : '공격 표면 추가';
  const grid = $('editorFields');
  grid.replaceChildren();
  for (const field of meta.fields) {
    const label = document.createElement('label');
    let input;
    if (field.type === 'checkbox') {
      label.className = 'checkbox-field';
      input = document.createElement('input');
      input.type = 'checkbox';
      input.required = Boolean(field.required);
      input.checked = surface ? surface[field.key] === true : false;
      const span = document.createElement('span'); span.textContent = field.checkboxLabel || field.label;
      input.id = `field-${field.key}`;
      label.append(input, span);
      grid.append(label);
      continue;
    }
    const span = document.createElement('span'); span.textContent = field.label; label.append(span);
    if (field.type === 'select') {
      input = document.createElement('select');
      for (const [value, text] of field.options) {
        const opt = document.createElement('option'); opt.value = value; opt.textContent = text; input.append(opt);
      }
      input.value = surface?.[field.key] ?? field.options[0][0];
    } else {
      input = document.createElement('input');
      input.type = 'text';
      input.maxLength = field.maxlength;
      input.required = Boolean(field.required);
      input.placeholder = field.placeholder || '';
      input.value = surface?.[field.key] ?? '';
    }
    input.id = `field-${field.key}`;
    label.append(input);
    grid.append(label);
  }
  $('surfaceForm').hidden = false;
  $('surfaceForm').scrollIntoView({behavior: 'smooth', block: 'center'});
  grid.querySelector('input, select')?.focus();
}

async function removeSurface(surface) {
  if (!window.confirm(`'${surface.name}' 공격 표면을 삭제하시겠습니까?`)) return;
  const scenario = selectedScenario.dataset.select;
  try {
    await api(`/api/surfaces/${scenario}/${encodeURIComponent(surface.id)}`, {method: 'DELETE'});
    selectedIds.delete(surface.id);
    await fetchSurfaces(); notice('공격 표면을 삭제했습니다.');
  } catch (err) { notice(err.message); }
}

$('surfaceForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const meta = currentMeta();
  if (!meta) return;
  const scenario = selectedScenario.dataset.select;
  const data = {};
  for (const field of meta.fields) {
    const el = $(`field-${field.key}`);
    data[field.key] = field.type === 'checkbox' ? el.checked : el.value.trim();
  }
  try {
    const record = await api(editingId ? `/api/surfaces/${scenario}/${encodeURIComponent(editingId)}` : `/api/surfaces/${scenario}`,
      {method: editingId ? 'PUT' : 'POST', body: JSON.stringify(data)});
    selectedIds.add(record.id);
    $('surfaceForm').hidden = true; editingId = null;
    await fetchSurfaces(); notice('공격 표면이 저장되었습니다.');
  } catch (err) { notice(`저장 실패: ${err.message}`); }
});
$('addSurface').addEventListener('click', () => openEditor());
$('importSurfaces').addEventListener('click', () => $('importFile').click());
$('importFile').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  event.target.value = '';
  if (!file) return;
  const meta = currentMeta();
  if (!meta) return;
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch (err) {
    notice(`파일을 읽을 수 없습니다: JSON 형식이 아닙니다. (${err.message})`);
    return;
  }
  const scenario = selectedScenario.dataset.select;
  try {
    const result = await api(`/api/surfaces/${scenario}/bulk`, {method: 'POST', body: JSON.stringify(parsed)});
    await fetchSurfaces();
    notice(`${result.imported}개의 공격 표면을 가져왔습니다.`);
  } catch (err) { notice(`가져오기 실패: ${err.message}`); }
});
$('cancelSurface').addEventListener('click', () => { $('surfaceForm').hidden = true; editingId = null; });
$('selectAll').addEventListener('change', (e) => { selectedIds = e.target.checked ? new Set(surfaces.map(s => s.id)) : new Set(); renderSurfaces(); });

async function start(ids) {
  if (active()) return;
  if (ids.length > 10) { notice('전체 실행은 한 번에 10개까지 지원합니다. 대상을 선택해서 실행하세요.'); return; }
  const scenario = selectedScenario.dataset.select;
  try {
    const result = await api(`/api/run/${scenario}`, {method: 'POST', body: JSON.stringify({surface_ids: ids})});
    activeBatch = result.batch_id;
    notice(`${ids.length}개의 검사를 순차적으로 실행하고 있습니다.`);
    $('activity').scrollIntoView({behavior: 'smooth', block: 'start'});
    refreshButtons(); renderSurfaces();
    await pollBatch();
    if (activeBatch) batchPoll = setInterval(pollBatch, 1100);
  } catch (err) { notice(`실행 실패: ${err.message}`); }
}
$('runSelectedSurfaces').addEventListener('click', () => start([...selectedIds]));
$('runAllSurfaces').addEventListener('click', () => start(surfaces.map(s => s.id)));

function showJob(job) {
  $('jobName').textContent = `${job.surface_name} / ${job.target} / ${job.id}`;
  $('executionId').textContent = `RUN ${job.id}`;
  $('resultSummary').textContent = job.summary || '실행 대기';
  if (job.log !== undefined) {
    const box = $('console');
    const atBottom = box.scrollTop + box.clientHeight + 35 >= box.scrollHeight;
    box.textContent = job.log || '$ 검사 실행을 준비하고 있습니다...';
    if (atBottom) box.scrollTop = box.scrollHeight;
  }
  $('liveState').textContent = String(job.status).toUpperCase();
  $('liveDot').style.background = ['queued', 'running'].includes(job.status) ? '#63b98a' : '#929e92';
}

async function pollBatch() {
  if (!activeBatch) return;
  const batchId = activeBatch;
  try {
    const batch = await api(`/api/batches/${encodeURIComponent(batchId)}`);
    pollFailures = 0;
    const job = batch.jobs.find(j => j.id === batch.current_job_id) || batch.jobs[batch.jobs.length - 1];
    if (job) showJob(await api(`/api/jobs/${encodeURIComponent(job.id)}`));
    if (batch.status === 'completed') {
      clearInterval(batchPoll); batchPoll = null;
      activeBatch = null;
      const positives = batch.jobs.filter(j => j.vulnerability_found === true).length;
      notice(`검사 완료 · 총 ${batch.jobs.length}개 중 탐지 ${positives}개. 결과는 아래 실행 기록에서 확인하세요.`);
      renderSurfaces(); await refreshHistory();
    }
  } catch (err) {
    pollFailures += 1;
    if (pollFailures < MAX_POLL_FAILURES) {
      notice(`상태 조회 재시도 중... (${pollFailures}/${MAX_POLL_FAILURES}) ${err.message}`);
      return;
    }
    clearInterval(batchPoll); batchPoll = null;
    activeBatch = null; pollFailures = 0;
    notice(`상태 조회 오류: ${err.message}. 서버가 종료되었는지 확인하세요. 화면이 잠겨 있으면 새로고침을 눌러 복구할 수 있습니다.`);
    refreshButtons(); renderSurfaces();
  }
}

async function refreshHistory() {
  try {
    const history = await api('/api/jobs');
    $('runsCount').textContent = String(history.length).padStart(2, '0');
    const list = $('history'); list.replaceChildren();
    if (!history.length) { const p = document.createElement('p'); p.className = 'empty'; p.textContent = '아직 실행 기록이 없습니다.'; list.append(p); return; }
    for (const job of history) {
      const row = document.createElement('div'); row.className = 'history-row';
      const details = document.createElement('div'); details.className = 'history-detail';
      const title = document.createElement('strong'); title.textContent = `${job.surface_name} / ${job.status}`;
      const sub = document.createElement('small'); sub.textContent = `${job.started_at || '대기 중'} · ${job.id}`;
      details.append(title, sub);
      row.append(details, actionButton('VIEW ↗', 'small-action', async () => {
        try { showJob(await api(`/api/jobs/${encodeURIComponent(job.id)}`)); $('activity').scrollIntoView({behavior: 'smooth'}); }
        catch (err) { notice(err.message); }
      })); list.append(row);
    }
  } catch (err) { $('history').textContent = `실행 기록 조회 실패: ${err.message}`; }
}

async function refreshHealth() {
  try {
    const data = await api('/api/health');
    toolStatus = data.tools || {};
    const meta = currentMeta();
    if (meta) {
      const ready = Boolean(toolStatus[meta.tool]);
      $('toolStatus').textContent = ready ? 'INSTALLED' : 'NOT FOUND';
      $('toolDesc').textContent = ready ? `${meta.tool} 실행 준비 완료` : `sudo apt install ${meta.tool} -y`;
    } else {
      $('toolStatus').textContent = 'N/A';
      $('toolDesc').textContent = '이 시나리오는 아직 연동되지 않았습니다.';
    }
    for (const row of rows) {
      const rowMeta = SCENARIOS_META[row.dataset.select];
      if (!rowMeta) continue;
      const statusEl = document.getElementById(`status-${row.dataset.select}`);
      if (statusEl) statusEl.textContent = toolStatus[rowMeta.tool] ? 'READY' : 'MISSING';
    }
  } catch (err) { toolStatus = {}; $('toolStatus').textContent = 'OFFLINE'; $('toolDesc').textContent = err.message; }
  renderSurfaces();
}

rows.forEach(r => r.addEventListener('click', () => renderScenario(r)));
$('runSelected').addEventListener('click', () => { if (currentMeta()) $('surfaces').scrollIntoView({behavior: 'smooth', block: 'start'}); });
$('refreshBtn').addEventListener('click', async () => { await Promise.all([refreshHealth(), fetchSurfaces(), refreshHistory()]); if (activeBatch) await pollBatch(); });
$('copyBtn').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('console').textContent); $('copyBtn').textContent = 'COPIED'; setTimeout(() => $('copyBtn').textContent = 'COPY LOG', 1500); }
  catch (_) { $('copyBtn').textContent = 'COPY FAILED'; }
});
$('clearBtn').addEventListener('click', () => {
  // Display-only: clears what's shown here, not the saved logs/ files or job history.
  $('console').textContent = '$ 화면을 비웠습니다. 저장된 로그 파일은 그대로 남아 있습니다.';
});
function clock() { $('clock').textContent = new Intl.DateTimeFormat('ko-KR', {hour:'2-digit', minute:'2-digit', hour12:false}).format(new Date()); }
clock(); setInterval(clock, 30_000);
renderScenario(selectedScenario);
refreshHistory();
