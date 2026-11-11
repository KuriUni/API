(() => {
  'use strict';
  const API = '/license/api/sunabar/v1/';
  const KEY_SLOT = 'sunabar-api-key-v1';
  const TIMEOUT = 20000;
  const $ = (id) => document.getElementById(id);
  const specs = {
    health: { title: '稼働状態', group: 'SYSTEM', method: 'GET', endpoint: 'health.php', body: {}, key: false, risk: 'READ ONLY', description: '中継先APIとデータベースの準備状態を確認します。' },
    products: { title: '製品一覧', group: 'LICENSE', method: 'GET', endpoint: 'products.php', body: {}, risk: 'READ ONLY', description: 'このエミュレーターで利用できる製品を取得します。' },
    issue: { title: 'デモライセンス発行', group: 'LICENSE', method: 'POST', endpoint: 'licenses.php', body: { product_id: 101, license_mode: 'single', label: 'Sunabar practice' }, risk: 'CREATE', description: 'Sunabar専用のデモライセンスを発行します。' },
    verify: { title: 'ライセンス検証', group: 'LICENSE', method: 'POST', endpoint: 'verify.php', body: { license_key: '', product_id: 101 }, risk: 'READ ONLY', description: 'ライセンスキーと製品IDの組み合わせを検証します。' },
    list: { title: 'ライセンス一覧', group: 'LICENSE', method: 'GET', endpoint: 'license-list.php', body: {}, risk: 'READ ONLY', description: 'この専用キーで作成したライセンスを取得します。' },
    revoke: { title: 'ライセンス失効', group: 'LICENSE', method: 'POST', endpoint: 'license-revoke.php', body: { license_id: '' }, risk: 'CHANGE STATE', description: '指定ライセンスを失効します。端末セッションも無効になります。' },
    activate: { title: '端末認証', group: 'DEVICE SESSION', method: 'POST', endpoint: 'activate.php', body: { license_key: '', device_id: 'sunabar-v2-device-01' }, risk: 'CREATE SESSION', description: 'デモライセンスを使って端末セッションを開始します。' },
    check: { title: 'セッション確認', group: 'DEVICE SESSION', method: 'POST', endpoint: 'session-check.php', body: { access_token: '', device_id: 'sunabar-v2-device-01' }, risk: 'READ ONLY', description: 'アクセストークンが有効か確認します。' },
    refresh: { title: 'セッション更新', group: 'DEVICE SESSION', method: 'POST', endpoint: 'session-refresh.php', body: { refresh_token: '', device_id: 'sunabar-v2-device-01' }, risk: 'ROTATES TOKENS', description: 'トークンを更新します。成功後は前のトークンを使えません。' },
    deactivate: { title: 'セッション終了', group: 'DEVICE SESSION', method: 'POST', endpoint: 'session-deactivate.php', body: { refresh_token: '', device_id: 'sunabar-v2-device-01' }, risk: 'END SESSION', description: '端末セッションを終了します。' },
  };
  const guides = {
    health: ['中継サーバーとデモ用データベースが応答するか確認します。ここで失敗すると他の操作も進みません。', 'products'],
    products: ['デモで使える製品IDとライセンス方式を確認します。次の発行で使う製品を選びます。', 'issue'],
    issue: ['デモライセンスを1件発行します。返ったキーは検証と端末認証で使います。', 'verify'],
    verify: ['発行したキーが有効か、製品IDと一致するかを確認します。', 'activate'],
    list: ['この専用キーで発行したライセンスを一覧します。失効済みも確認できます。', ''],
    revoke: ['デモライセンスを失効させます。端末セッションも終了します。', ''],
    activate: ['ライセンスを使って端末セッションを開始し、トークンを取得します。', 'check'],
    check: ['アクセストークンが有効か確認します。', 'refresh'],
    refresh: ['更新トークンでトークンをローテーションします。古いトークンは使えなくなります。', 'deactivate'],
    deactivate: ['端末セッションを終了します。', ''],
  };
  const errors = {
    invalid_api_key: ['APIキーを確認', 'キーが無効か、発行元のワークスペースが異なります。専用キーを再発行してください。'],
    expired_token: ['APIキーの期限切れ', '専用キーは24時間で期限切れになります。新しいキーを発行してください。'],
    invalid_license: ['ライセンスを確認', 'キー、製品ID、状態、有効期限を確認してください。'],
    license_unavailable: ['ライセンスを利用できません', 'デモライセンスが失効・期限切れ、または製品IDが一致していない可能性があります。'],
    invalid_session_token: ['セッション情報を確認', '更新操作後は古いトークンを使えません。最新の応答にあるトークンを使ってください。'],
    device_limit_reached: ['端末数の上限', 'このライセンスで登録できる端末数の上限に達しています。'],
    license_issue_limit: ['発行上限', '時間をおいてから再試行してください。'],
    invalid_device_id: ['端末IDを確認', '端末IDは空欄にできません。入力内容を確認してください。'],
    sunabar_upstream_unavailable: ['中継先を利用できません', '稼働状態を確認し、少し時間をおいて再試行してください。'],
    network_error: ['接続を確認', 'ブラウザーから同一サイトのAPI中継先へ接続できませんでした。'],
  };
  let current = 'health';
  let busy = false;
  let lastResponse = null;
  let lastLicense = null;
  let lastSession = null;
  let lastProducts = null;
  let requestCount = 0;
  let history = [];
  let flowRunning = false;
  const drafts = {};

  function readKey() {
    try {
      const value = JSON.parse(sessionStorage.getItem(KEY_SLOT) || 'null');
      if (value?.key && Number(value.expires_at) * 1000 > Date.now()) return value;
      sessionStorage.removeItem(KEY_SLOT);
    } catch { /* session storage may be disabled */ }
    return null;
  }
  function path(name) { return `${API}${specs[name].endpoint}`; }
  function json(value) { return JSON.stringify(value, null, 2); }
  function safeText(value) { return typeof value === 'string' ? value : JSON.stringify(value); }
  function buildCatalog() {
    const cat = $('catalog-grid'); const nav = $('operation-list');
    Object.entries(specs).forEach(([name, op], index) => {
      const tile = document.createElement('button'); tile.type = 'button'; tile.className = 'catalog-item';
      const num = document.createElement('span'); num.className = 'catalog-num'; num.textContent = String(index + 1).padStart(2, '0');
      const label = document.createElement('span'); const title = document.createElement('b'); title.textContent = op.title; const meta = document.createElement('small'); meta.textContent = `${op.method} · ${op.group}`; label.append(title, meta); tile.append(num, label); tile.addEventListener('click', () => openOperation(name)); cat.append(tile);
      const item = document.createElement('button'); item.type = 'button'; item.className = 'operation'; item.dataset.operation = name;
      const method = document.createElement('span'); method.className = 'operation-method'; method.textContent = op.method;
      const text = document.createElement('span'); text.textContent = op.title; item.append(method, text); item.addEventListener('click', () => openOperation(name)); nav.append(item);
    });
  }
  function updateKeyState() {
    const hasKey = Boolean(readKey()); const status = $('key-status');
    status.replaceChildren(); const dot = document.createElement('i'); status.append(dot, document.createTextNode(hasKey ? 'APIキー準備済み' : 'キー未発行')); status.classList.toggle('key-ready', hasKey);
    $('auth-state').textContent = specs[current].key === false ? '認証不要' : (hasKey ? 'キー設定済み' : 'キーが必要');
    const key = readKey(); $('api-key-value').value = key?.key || ''; $('api-key-value').type = 'password'; $('copy-key').disabled = !key;
    $('key-expiry').textContent = key ? `有効期限 ${new Date(key.expires_at * 1000).toLocaleString('ja-JP')}` : '';
    $('issue-api-key').textContent = key ? '新しいキーを発行' : '専用キーを発行';
  }
  function renderGuide(name) {
    const box = $('operation-guide'); const info = guides[name]; if (!box) return;
    box.replaceChildren(); const title = document.createElement('b'); title.textContent = 'この操作のあと';
    const text = document.createElement('span'); text.textContent = info ? info[0] : specs[name].description;
    box.append(title, text);
    const next = info && info[1];
    if (next && specs[next]) { const button = document.createElement('button'); button.type = 'button'; button.className = 'text-button'; button.textContent = `次へ: ${specs[next].title} →`; button.addEventListener('click', () => openOperation(next)); box.append(button); }
  }
  function chooseProductId(preferred) {
    const ids = (lastProducts || []).map((product) => Number(product.id)); const value = Number(preferred);
    if (Number.isInteger(value) && value > 0 && (!ids.length || ids.includes(value))) return value;
    return ids[0] || (Number.isInteger(value) && value > 0 ? value : 101);
  }
  function renderProductOptions() {
    const list = $('flow-product-options'); if (!list) return;
    list.replaceChildren(...(lastProducts || []).map((product) => { const option = document.createElement('option'); option.value = String(product.id); option.textContent = `${product.name || product.code || '製品'} (${product.id})`; option.label = option.textContent; return option; }));
    const input = $('flow-product-id'); const ids = (lastProducts || []).map((product) => Number(product.id));
    if (input && ids.length && !ids.includes(Number(input.value))) input.value = String(ids[0]);
    if (ids.length) $('product-hint').textContent = `選択できます: ${(lastProducts || []).map((product) => `${product.name || product.code} (${product.id})`).join(' / ')}`;
  }
  function sampleBody() {
    try { const value = JSON.parse($('request-body').value || '{}'); return value && typeof value === 'object' && !Array.isArray(value) ? value : specs[current].body; } catch { return specs[current].body; }
  }
  function renderSamples() {
    const op = specs[current]; const url = `${location.origin}${path(current)}`; const pretty = json(sampleBody());
    const keyValue = op.key === false ? '' : 'YOUR_SUNABAR_API_KEY';
    const NL = String.fromCharCode(10); const BS = String.fromCharCode(92);
    const curlLines = [`curl -X ${op.method} '${url}'`, "  -H 'Accept: application/json'"];
    if (keyValue) curlLines.push(`  -H 'X-Sunabar-API-Key: ${keyValue}'`);
    if (op.method === 'POST') { curlLines.push("  -H 'Content-Type: application/json'"); curlLines.push(`  -d '${pretty.replace(/'/g, "'" + BS + "''")}'`); }
    const curl = curlLines.map((line, index) => index === curlLines.length - 1 ? line : line + ' ' + BS).join(NL);
    const jsHeaders = ["'Accept': 'application/json'", ...(keyValue ? [`'X-Sunabar-API-Key': '${keyValue}'`] : []), ...(op.method === 'POST' ? ["'Content-Type': 'application/json'"] : [])];
    const js = [`const res = await fetch('${path(current)}', {`, `  method: '${op.method}',`, `  headers: { ${jsHeaders.join(', ')} }${op.method === 'POST' ? ',' : ''}`, ...(op.method === 'POST' ? [`  body: JSON.stringify(${pretty})`] : []), '});', 'const data = await res.json();', 'console.log(data);'].join(NL);
    const pyHeaders = ['"Accept": "application/json"', ...(keyValue ? [`"X-Sunabar-API-Key": "${keyValue}"`] : [])];
    const python = ['import requests', '', `url = "${url}"`, `headers = {${pyHeaders.join(', ')}}`, op.method === 'POST' ? `r = requests.post(url, headers=headers, json=${pretty})` : 'r = requests.get(url, headers=headers)', 'print(r.status_code)', 'print(r.json())'].join(NL);
    const codes = { curl, js, python };
    document.querySelectorAll('.code-sample').forEach((node) => { node.textContent = codes[node.dataset.code] || ''; });
  }
  function openOperation2(name, save = true) {
    if (!specs[name]) return;
    if (save && $('request-body')) drafts[current] = $('request-body').value;
    current = name; const op = specs[name];
    document.querySelectorAll('.operation').forEach((el) => el.classList.toggle('active', el.dataset.operation === name));
    $('operation-title').textContent = op.title; $('operation-category').textContent = op.group; $('operation-description').textContent = op.description;
    $('method-badge').textContent = op.method; $('method-badge').className = `method-badge ${op.method.toLowerCase()}`;
    $('endpoint-host').textContent = location.host || '同一サイト'; $('endpoint-path').textContent = `${API}${op.endpoint}`;
    $('request-body').value = drafts[name] ?? json(op.body); $('form-error').textContent = '';
    const risk = $('operation-risk'); risk.textContent = op.risk; risk.classList.toggle('mutation', /CHANGE|ROTATES|CREATE|END/.test(op.risk));
    $('request-hint').textContent = op.key === false ? 'APIキー不要の読み取り操作です。' : (hasKeyHint());
    updateKeyState();
  }
  function openOperation(name, save = true) {
    openOperation2(name, save); renderGuide(name); renderSamples();
  }
  function hasKeyHint() { return readKey() ? '同一タブのSunabar専用キーを使用します。' : '実行前にSunabar専用キーが必要です。'; }
  function switchView(view) {
    document.querySelectorAll('.view-tab').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
    document.querySelectorAll('.view').forEach((v) => { const active = v.id === `view-${view}`; v.hidden = !active; v.classList.toggle('active', active); });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  function responseDiagnostic(result) {
    const box = $('response-diagnostic'); const code = result.body?.error || result.body?.code;
    if (result.status > 0 && result.status < 400 && result.body?.ok !== false) { box.hidden = true; box.replaceChildren(); return; }
    const detail = errors[code] || [result.status ? `HTTP ${result.status} を確認` : '接続エラー', result.body?.message || result.body?.detail || 'JSON本文、キー、要求方法、サーバー状態を確認してください。'];
    box.hidden = false; box.replaceChildren(); const title = document.createElement('b'); title.textContent = `${detail[0]}${code ? ` · ${code}` : ''}`; const body = document.createElement('span'); body.textContent = detail[1]; box.append(title, body);
  }
  function showResponse(result) {
    lastResponse = result;
    $('response-status').textContent = result.status ? `HTTP ${result.status}` : '接続エラー';
    $('response-status').className = `status-pill ${result.status >= 400 || !result.status ? 'error' : ''}`;
    $('response-time').textContent = `${result.duration.toFixed(1)} ms`;
    const bodyText = json(result.body); $('response-size').textContent = `${new Blob([bodyText]).size} bytes`;
    $('response-request-id').textContent = `Request ID ${result.request_id || result.body?.request_id || result.body?.data?.request_id || '—'}`;
    $('response-json').textContent = bodyText; $('copy-response').disabled = false; responseDiagnostic(result);
    const license = result.body?.data?.license; const key = license?.product_key || license?.license_key || '';
    $('product-key-result').hidden = !key; $('product-key-value').textContent = key;
    if (key) $('product-key-message').textContent = '';
    const sess = lastSession; $('session-state').classList.toggle('session-active', Boolean(sess)); $('session-state').innerHTML = sess ? '<i></i>セッション準備済み' : '<i></i>セッション未開始';
    $('device-indicator').className = `metric-dot ${sess ? '' : 'neutral'}`; $('device-status').textContent = sess ? '端末認証済み' : '未認証';
    $('device-detail').textContent = sess ? `端末ID: ${sess.device_id}` : 'アクセストークンと更新トークンはメモリー内';
  }
  function redact(value, key = '') {
    if (/api.?key|access.?token|refresh.?token|license.?key|product.?key|authorization|password|secret/i.test(key)) return value ? '[REDACTED]' : value;
    if (Array.isArray(value)) return value.map((v) => redact(v));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v, k)]));
    return value;
  }
  function addHistory(name, result, body) {
    const entry = { id: crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`, at: new Date().toISOString(), name, method: specs[name].method, path: path(name), status: result.status, duration: result.duration, request_id: result.request_id || result.body?.request_id || result.body?.data?.request_id || '', request: redact(body), response: redact(result.body) };
    history.unshift(entry); history = history.slice(0, 50); renderHistory();
  }
  function renderHistory() {
    const body = $('history-rows'); const search = $('history-search').value.trim().toLowerCase(); const filter = $('history-filter').value;
    const rows = history.filter((r) => (filter === 'all' || (filter === 'success' ? r.status >= 200 && r.status < 400 : r.status < 200 || r.status >= 400)) && `${r.method} ${r.path} ${r.status} ${r.request_id} ${JSON.stringify(r.response)}`.toLowerCase().includes(search));
    $('history-count').textContent = `${rows.length} 件`;
    if (!rows.length) { const tr = document.createElement('tr'); tr.className = 'history-empty'; const td = document.createElement('td'); td.colSpan = 6; td.textContent = history.length ? '条件に一致する履歴がありません。' : 'まだ履歴がありません。フロー実行かAPIコンソールから要求を送ってください。'; tr.append(td); body.replaceChildren(tr); return; }
    body.replaceChildren(...rows.map((entry) => {
      const tr = document.createElement('tr'); const time = document.createElement('td'); time.textContent = new Date(entry.at).toLocaleTimeString('ja-JP');
      const opCell = document.createElement('td'); opCell.className = 'history-operation'; const title = document.createElement('b'); title.textContent = specs[entry.name].title; const endpoint = document.createElement('code'); endpoint.textContent = `${entry.method} ${entry.path}`; opCell.append(title, endpoint);
      const status = document.createElement('td'); status.className = `history-status ${entry.status < 200 || entry.status >= 400 ? 'error' : ''}`; status.textContent = entry.status || 'ERR';
      const duration = document.createElement('td'); duration.textContent = `${entry.duration.toFixed(0)} ms`; const rid = document.createElement('td'); rid.textContent = entry.request_id || '—';
      const action = document.createElement('td'); const open = document.createElement('button'); open.type = 'button'; open.className = 'history-open'; open.textContent = '再表示'; open.addEventListener('click', () => { openOperation(entry.name); drafts[entry.name] = json(entry.request); $('request-body').value = drafts[entry.name]; showResponse({ status: entry.status, body: entry.response, duration: entry.duration }); switchView('console'); }); action.append(open); tr.append(time, opCell, status, duration, rid, action); return tr;
    }));
  }
  function updateKeyFromResponse(name, request, result) {
    const data = result.body?.data;
    if (name === 'products' && Array.isArray(data?.products)) { lastProducts = data.products; renderProductOptions(); }
    if (name === 'issue' && data?.license) {
      lastLicense = data.license;
      drafts.verify = json({ license_key: data.license.license_key || data.license.product_key, product_id: data.license.product_id ?? request.product_id });
      drafts.activate = json({ license_key: data.license.license_key || data.license.product_key, device_id: request.device_id || 'sunabar-v2-device-01' });
      drafts.revoke = json({ license_id: data.license.license_id });
      $('license-indicator').className = 'metric-dot'; $('license-status').textContent = '発行済み'; $('license-detail').textContent = `ライセンスID: ${data.license.license_id || '取得済み'}`;
      if (current !== name) drafts[current] = $('request-body').value;
    }
    if ((name === 'activate' || name === 'refresh') && data?.session) {
      lastSession = { ...data.session, device_id: request.device_id || lastSession?.device_id, license_id: data.license_id || lastSession?.license_id };
      drafts.check = json({ access_token: lastSession.access_token, device_id: lastSession.device_id });
      drafts.refresh = json({ refresh_token: lastSession.refresh_token, device_id: lastSession.device_id });
      drafts.deactivate = json({ refresh_token: lastSession.refresh_token, device_id: lastSession.device_id });
    }
    if (name === 'deactivate' && result.body?.data?.status === 'deactivated') lastSession = null;
    if (name === 'revoke' && result.body?.ok) { lastSession = null; }
  }
  async function request(name, body, { fromFlow = false } = {}) {
    if (busy) throw new Error('別の要求を実行中です。');
    const op = specs[name]; const key = readKey();
    if (op.key !== false && !key) { if (!fromFlow) { $('key-dialog').showModal(); $('key-message').textContent = '先に専用APIキーを発行してください。'; } throw new Error('専用APIキーがありません。発行してから再開してください。'); }
    busy = true; $('send').disabled = true;
    const started = performance.now(); let result;
    try {
      const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), TIMEOUT);
      try {
        const response = await fetch(path(name), { method: op.method, cache: 'no-store', credentials: 'omit', signal: controller.signal, headers: { Accept: 'application/json', ...(op.key !== false && key ? { 'X-Sunabar-API-Key': key.key } : {}), ...(op.method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, ...(op.method === 'POST' ? { body: json(body || {}) } : {}) });
        const responseBody = await response.json().catch(() => ({ ok: false, error: 'invalid_server_response', message: 'JSON以外の応答を受信しました。' }));
        result = { status: response.status, body: responseBody, request_id: response.headers.get('X-Request-ID') || responseBody.request_id || '', duration: performance.now() - started };
        if (response.status === 401 && ['expired_token', 'invalid_api_key'].includes(responseBody.error)) { sessionStorage.removeItem(KEY_SLOT); updateKeyState(); }
      } finally { clearTimeout(timer); }
    } catch (err) { result = { status: 0, body: { ok: false, error: 'network_error', message: err.name === 'AbortError' ? '20秒以内に応答がありませんでした。' : err.message }, duration: performance.now() - started }; }
    busy = false; $('send').disabled = false; requestCount++; $('request-count').textContent = String(requestCount);
    if (result.status >= 200 && result.status < 300 && result.body?.ok) updateKeyFromResponse(name, body || {}, result);
    showResponse(result); addHistory(name, result, body || {}); return result;
  }
  function recordFlow(title, steps) {
    $('flow-progress').hidden = false; $('flow-title').textContent = title; $('flow-summary').hidden = true;
    $('flow-log').replaceChildren(...steps.map((step) => { const li = document.createElement('li'); li.dataset.name = step.name; const b = document.createElement('b'); b.textContent = specs[step.name].method; const span = document.createElement('span'); span.textContent = specs[step.name].title; li.append(b, span); return li; }));
    $('flow-counter').textContent = `0 / ${steps.length}`; $('flow-progress-bar').style.width = '0%';
  }
  function setFlowStep(index, state, steps) {
    const li = $('flow-log').children[index]; if (li) li.className = state;
    $('flow-counter').textContent = `${Math.min(index + (state === 'done' || state === 'failed' ? 1 : 0), steps.length)} / ${steps.length}`;
    $('flow-progress-bar').style.width = `${Math.round((index + (state === 'done' ? 1 : 0)) / steps.length * 100)}%`;
  }
  async function runFlow(title, steps) {
    if (flowRunning || busy) return; flowRunning = true; recordFlow(title, steps);
    ['run-license-flow', 'run-session-flow', 'run-tour', 'load-products'].forEach((id) => { $(id).disabled = true; });
    const summary = $('flow-summary'); let failed = false;
    try {
      for (let i = 0; i < steps.length; i++) {
        setFlowStep(i, 'running', steps);
        const step = steps[i]; const body = typeof step.body === 'function' ? step.body() : step.body;
        const result = await request(step.name, body, { fromFlow: true });
        if (result.status < 200 || result.status >= 300 || !result.body?.ok) { setFlowStep(i, 'failed', steps); failed = true; summary.textContent = `「${specs[step.name].title}」で停止しました。応答の診断を確認し、修正してから個別に再実行してください。`; break; }
        setFlowStep(i, 'done', steps);
      }
      if (!failed) summary.textContent = title.includes('通し') ? `通し実習が完了しました。発行ライセンスID: ${lastLicense?.license_id || '—'}。履歴から各応答を確認できます。` : '全ステップが完了しました。各要求の応答と履歴から、入力と出力のつながりを確認できます。';
    } catch (error) { failed = true; summary.textContent = error.message; }
    summary.hidden = false; if (failed) summary.style.color = '#aa3b46'; else summary.style.color = '#187653';
    ['run-license-flow', 'run-session-flow', 'run-tour', 'load-products'].forEach((id) => { $(id).disabled = false; }); flowRunning = false;
  }
  async function issueKey() {
    const button = $('issue-api-key'); button.disabled = true; button.textContent = '発行中…'; $('key-message').textContent = '';
    try {
      const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), TIMEOUT);
      let response; try { response = await fetch(`${API}key.php`, { method: 'POST', cache: 'no-store', credentials: 'omit', signal: ctl.signal, headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: '{}' }); } finally { clearTimeout(timer); }
      const body = await response.json().catch(() => ({})); if (!response.ok || !body.ok || !body.data?.api_key) throw new Error(body.message || body.error || `HTTP ${response.status}`);
      sessionStorage.setItem(KEY_SLOT, JSON.stringify({ key: body.data.api_key, expires_at: body.data.expires_at })); lastLicense = null; lastSession = null; updateKeyState(); $('api-key-value').type = 'text'; $('key-message').textContent = 'キーを発行しました。このタブの間だけ利用できます。'; $('license-indicator').className = 'metric-dot neutral'; $('license-status').textContent = '未作成'; $('license-detail').textContent = 'このタブで発行したデモライセンス';
      return true;
    } catch (err) { $('key-message').textContent = `発行できませんでした: ${err.message}`; return false; }
    finally { button.disabled = false; button.textContent = readKey() ? '新しいキーを発行' : '専用キーを発行'; }
  }
  async function ensureKey() { if (readKey()) return true; await issueKey(); if (!readKey()) $('key-dialog').showModal(); return Boolean(readKey()); }
  function downloadJson(filename, data) {
    const blob = new Blob([json(data)], { type: 'application/json;charset=utf-8' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function resetAll() {
    if (busy) return; sessionStorage.removeItem(KEY_SLOT); lastResponse = null; lastLicense = null; lastSession = null; lastProducts = null; history = []; requestCount = 0; $('request-count').textContent = '0'; Object.keys(drafts).forEach((k) => delete drafts[k]);
    $('flow-product-id').value = '101'; $('product-hint').textContent = '「一覧」を押すと製品名から選べます。'; renderProductOptions();
    $('license-indicator').className = 'metric-dot neutral'; $('license-status').textContent = '未作成'; $('license-detail').textContent = 'このタブで発行したデモライセンス'; $('device-indicator').className = 'metric-dot neutral'; $('device-status').textContent = '未認証'; $('device-detail').textContent = 'アクセストークンと更新トークンはメモリー内';
    $('response-status').textContent = '未実行'; $('response-status').className = 'status-empty'; $('response-time').textContent = '— ms'; $('response-size').textContent = '— bytes'; $('response-request-id').textContent = 'Request ID —'; $('response-json').textContent = '要求を送ると、HTTP状態・応答・診断情報がここに表示されます。'; $('copy-response').disabled = true; $('response-diagnostic').hidden = true; $('product-key-result').hidden = true; $('flow-progress').hidden = true; renderHistory(); updateKeyState(); openOperation('health', false);
  }
  document.querySelectorAll('.view-tab').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.view)));
  document.querySelectorAll('[data-go-view]').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.goView)));
  $('open-console').addEventListener('click', () => switchView('console')); $('open-history').addEventListener('click', () => switchView('history'));
  $('health-check').addEventListener('click', async () => { openOperation('health'); const r = await request('health', {}); $('relay-indicator').className = `metric-dot ${r.status >= 200 && r.status < 300 && r.body?.ok ? '' : 'error'}`; $('relay-status').textContent = r.status >= 200 && r.status < 300 && r.body?.ok ? '稼働中' : '確認が必要'; $('relay-detail').textContent = r.status ? `HTTP ${r.status} · ${r.duration.toFixed(0)} ms` : 'APIへの接続を確認してください。'; switchView('console'); });
  $('run-license-flow').addEventListener('click', () => {
    const id = Number($('flow-product-id').value); const label = $('flow-label').value.trim();
    if (!Number.isInteger(id) || id < 1) { $('flow-progress').hidden = false; $('flow-summary').hidden = false; $('flow-summary').textContent = '製品IDは1以上の整数で入力してください。'; $('flow-summary').style.color = '#aa3b46'; return; }
    if (!readKey()) { $('key-dialog').showModal(); $('key-message').textContent = 'この実習を始める前に専用キーを発行してください。発行後、もう一度フローを実行します。'; return; }
    runFlow('デモライセンス発行・検証', [{ name: 'products', body: {} }, { name: 'issue', body: { product_id: id, license_mode: 'single', label: label || 'Sunabar practice' } }, { name: 'verify', body: () => ({ license_key: lastLicense?.license_key || lastLicense?.product_key || '', product_id: id }) }]);
  });
  $('run-session-flow').addEventListener('click', () => {
    if (!readKey()) { $('key-dialog').showModal(); $('key-message').textContent = 'この実習を始める前に専用キーを発行してください。'; return; }
    const device = $('flow-device-id').value.trim(); if (!device) { $('flow-progress').hidden = false; $('flow-summary').hidden = false; $('flow-summary').textContent = '端末IDを入力してください。'; $('flow-summary').style.color = '#aa3b46'; return; }
    if (!lastLicense?.license_key && !lastLicense?.product_key) { switchView('console'); openOperation('issue'); $('form-error').textContent = '先にデモライセンスを発行してください。発行後にセッションフローを実行できます。'; return; }
    runFlow('端末セッションの開始・更新・終了', [
      { name: 'activate', body: () => ({ license_key: lastLicense.license_key || lastLicense.product_key, device_id: device }) },
      { name: 'check', body: () => ({ access_token: lastSession?.access_token || '', device_id: device }) },
      { name: 'refresh', body: () => ({ refresh_token: lastSession?.refresh_token || '', device_id: device }) },
      { name: 'deactivate', body: () => ({ refresh_token: lastSession?.refresh_token || '', device_id: device }) },
    ]);
  });
  $('load-products').addEventListener('click', async () => {
    if (!readKey()) { $('key-dialog').showModal(); $('key-message').textContent = '製品一覧の取得には専用キーが必要です。発行してから再試行してください。'; return; }
    try {
      const result = await request('products', {}, { fromFlow: true });
      if (result.status >= 200 && result.status < 300 && lastProducts?.length) $('product-hint').textContent = `選択できます: ${lastProducts.map((product) => `${product.name || product.code} (${product.id})`).join(' / ')}`;
    } catch (error) { $('product-hint').textContent = error.message; }
  });
  $('run-tour').addEventListener('click', async () => {
    if (flowRunning || busy) return;
    if (!await ensureKey()) return;
    const device = ($('flow-device-id')?.value || '').trim() || 'sunabar-v2-device-01';
    const preferred = Number($('flow-product-id').value);
    await runFlow('はじめての通し実習', [
      { name: 'health', body: {} },
      { name: 'products', body: {} },
      { name: 'issue', body: () => ({ product_id: chooseProductId(preferred), license_mode: 'single', label: 'Sunabar tour' }) },
      { name: 'verify', body: () => ({ license_key: lastLicense?.license_key || lastLicense?.product_key || '', product_id: lastLicense?.product_id ?? chooseProductId(preferred) }) },
      { name: 'activate', body: () => ({ license_key: lastLicense?.license_key || lastLicense?.product_key || '', device_id: device }) },
      { name: 'check', body: () => ({ access_token: lastSession?.access_token || '', device_id: device }) },
      { name: 'refresh', body: () => ({ refresh_token: lastSession?.refresh_token || '', device_id: device }) },
      { name: 'deactivate', body: () => ({ refresh_token: lastSession?.refresh_token || '', device_id: device }) },
    ]);
  });
  document.querySelectorAll('.code-copy').forEach((button) => button.addEventListener('click', async () => {
    const node = document.querySelector(`.code-sample[data-code="${button.dataset.code}"]`); if (!node) return;
    try { await navigator.clipboard.writeText(node.textContent); button.textContent = 'コピーしました'; window.setTimeout(() => { button.textContent = 'コピー'; }, 1500); } catch { button.textContent = '選択してコピー'; }
  }));
  $('request-body').addEventListener('input', renderSamples);
  $('send').addEventListener('click', async () => {
    $('form-error').textContent = ''; let body;
    try { body = JSON.parse($('request-body').value || '{}'); if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('JSONのトップレベルはオブジェクトにしてください。'); }
    catch (err) { $('form-error').textContent = err.message; return; }
    if (current === 'revoke' && !window.confirm('指定したデモライセンスを失効しますか？この操作は元に戻せません。')) return;
    await request(current, body);
  });
  $('request-body').addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') $('send').click(); });
  $('reset-body').addEventListener('click', () => { drafts[current] = json(specs[current].body); $('request-body').value = drafts[current]; $('form-error').textContent = ''; renderSamples(); });
  $('operation-search').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); document.querySelectorAll('.operation').forEach((b) => { b.hidden = !`${b.textContent} ${specs[b.dataset.operation].group} ${specs[b.dataset.operation].endpoint}`.toLowerCase().includes(q); }); });
  $('history-search').addEventListener('input', renderHistory); $('history-filter').addEventListener('change', renderHistory);
  $('export-history').addEventListener('click', () => downloadJson(`sunabar-v2-history-${new Date().toISOString().slice(0, 10)}.json`, { exported_at: new Date().toISOString(), redacted: true, entries: history }));
  $('clear-history').addEventListener('click', () => { history = []; renderHistory(); });
  $('reset').addEventListener('click', resetAll);
  $('open-key').addEventListener('click', () => { updateKeyState(); $('key-dialog').showModal(); }); $('close-key').addEventListener('click', () => $('key-dialog').close()); $('issue-api-key').addEventListener('click', issueKey);
  $('toggle-key').addEventListener('click', () => { $('api-key-value').type = $('api-key-value').type === 'password' ? 'text' : 'password'; });
  $('copy-key').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('api-key-value').value); $('key-message').textContent = 'コピーしました。'; } catch { $('key-message').textContent = 'コピーに失敗しました。キーを選択してコピーしてください。'; } });
  $('copy-path').addEventListener('click', async () => { try { await navigator.clipboard.writeText(`${location.origin}${$('endpoint-path').textContent}`); } catch { /* clipboard may not be available */ } });
  $('copy-response').addEventListener('click', async () => { if (lastResponse) try { await navigator.clipboard.writeText(json(lastResponse.body)); } catch { /* clipboard may not be available */ } });
  $('copy-product-key').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('product-key-value').textContent); $('product-key-message').textContent = 'コピーしました。'; } catch { $('product-key-message').textContent = 'キーを選択してコピーしてください。'; } });
  buildCatalog(); updateKeyState(); openOperation('health', false); renderHistory();
})();
