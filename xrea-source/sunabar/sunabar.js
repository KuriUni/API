(() => {
  'use strict';

  const API_BASE = '/license/api/sunabar/v1/';
  const KEY_STORAGE = 'sunabar-api-key-v1';
  const operations = {
    health: {
      title: '稼働状態を確認', description: 'APIとDBの準備状態を確認します。APIキーは不要です。',
      method: 'GET', path: `${API_BASE}health.php`, body: '{}', requiresKey: false,
    },
    products: {
      title: '製品一覧を取得', description: 'このエミュレーターで利用できる製品を取得します。',
      method: 'GET', path: `${API_BASE}products.php`, body: '{}',
    },
    issue: {
      title: 'デモライセンスを発行', description: '発行したキーはSunabar内だけで使えます。',
      method: 'POST', path: `${API_BASE}licenses.php`,
      body: '{\n  "product_id": 101,\n  "license_mode": "single",\n  "label": "Sunabar sample"\n}',
    },
    verify: {
      title: 'ライセンスを検証', description: '直近の発行キーを自動入力します。必要ならJSONを編集してください。',
      method: 'POST', path: `${API_BASE}verify.php`, body: '{\n  "license_key": "",\n  "product_id": 101\n}',
    },
    list: {
      title: 'ライセンス一覧', description: 'この専用キーで作成したライセンスを一覧します。',
      method: 'GET', path: `${API_BASE}license-list.php`, body: '{}',
    },
    revoke: {
      title: 'ライセンスを失効', description: '一覧や発行結果のlicense_idを指定します。失効すると端末セッションも使えなくなります。',
      method: 'POST', path: `${API_BASE}license-revoke.php`, body: '{\n  "license_id": ""\n}',
    },
    activate: {
      title: '端末を認証', description: '直近のデモライセンスを自動入力し、端末用トークンを発行します。',
      method: 'POST', path: `${API_BASE}activate.php`,
      body: '{\n  "license_key": "",\n  "device_id": "sunabar-demo-device-01"\n}',
    },
    check: {
      title: '端末セッションを確認', description: '直近の認証・更新で得たアクセストークンを自動入力します。',
      method: 'POST', path: `${API_BASE}session-check.php`,
      body: '{\n  "access_token": "",\n  "device_id": "sunabar-demo-device-01"\n}',
    },
    refresh: {
      title: '端末セッションを更新', description: '直近の更新トークンを使います。更新後は古いトークンが使えなくなります。',
      method: 'POST', path: `${API_BASE}session-refresh.php`,
      body: '{\n  "refresh_token": "",\n  "device_id": "sunabar-demo-device-01"\n}',
    },
    deactivate: {
      title: '端末セッションを終了', description: '直近の更新トークンに紐づく端末セッションを無効化します。',
      method: 'POST', path: `${API_BASE}session-deactivate.php`,
      body: '{\n  "refresh_token": "",\n  "device_id": "sunabar-demo-device-01"\n}',
    },
  };

  const byId = (id) => document.getElementById(id);
  const REQUEST_TIMEOUT_MS = 20000;
  let current = 'health';
  let lastResponse = null;
  let lastLicense = null;
  let lastSession = null;
  let requestBusy = false;
  const drafts = Object.create(null);

  async function fetchWithTimeout(url, options) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) throw new Error('サーバーの応答が20秒以内にありませんでした。時間をおいて再試行してください。');
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  function readKey() {
    try {
      const saved = JSON.parse(sessionStorage.getItem(KEY_STORAGE) || 'null');
      if (saved && typeof saved.key === 'string' && Number(saved.expires_at) > Date.now() / 1000) return saved;
      sessionStorage.removeItem(KEY_STORAGE);
    } catch { /* storage is optional */ }
    return null;
  }

  function readObject(text) {
    try {
      const value = JSON.parse(text || '{}');
      return value && !Array.isArray(value) && typeof value === 'object' ? value : {};
    } catch { return {}; }
  }

  function setDraft(name, value) {
    drafts[name] = JSON.stringify(value, null, 2);
  }

  function seedLicense(license) {
    if (!license || !license.license_key) return;
    lastLicense = license;
    setDraft('verify', { license_key: license.license_key, product_id: license.product_id });
    setDraft('activate', { license_key: license.license_key, device_id: 'sunabar-demo-device-01' });
    setDraft('revoke', { license_id: license.license_id });
  }

  function seedSession(session, deviceId, licenseId) {
    if (!session?.access_token || !session?.refresh_token) return;
    lastSession = { ...session, device_id: deviceId, license_id: licenseId };
    setDraft('check', { access_token: session.access_token, device_id: deviceId });
    setDraft('refresh', { refresh_token: session.refresh_token, device_id: deviceId });
    setDraft('deactivate', { refresh_token: session.refresh_token, device_id: deviceId });
  }

  function renderKey() {
    const saved = readKey();
    const status = byId('key-status');
    status.innerHTML = saved ? '<i></i> API KEY READY' : '<i></i> API KEY REQUIRED';
    status.classList.toggle('key-ready', Boolean(saved));
    byId('auth-state').textContent = operations[current].requiresKey === false ? '認証不要' : (saved ? '設定済み' : '未設定');
    const input = byId('api-key-value');
    input.value = saved ? saved.key : '';
    input.type = 'password';
    byId('copy-key').disabled = !saved;
    byId('key-expiry').textContent = saved ? `有効期限 ${new Date(saved.expires_at * 1000).toLocaleString('ja-JP')}` : '';
  }

  function renderOperation(name, saveCurrent = true) {
    if (!operations[name]) return;
    if (saveCurrent && byId('request-body')) drafts[current] = byId('request-body').value;
    current = name;
    const operation = operations[name];
    document.querySelectorAll('.operation').forEach((button) => button.classList.toggle('active', button.dataset.operation === name));
    byId('operation-title').textContent = operation.title;
    byId('operation-description').textContent = operation.description;
    const endpoint = new URL(operation.path, document.baseURI);
    byId('endpoint-path').textContent = endpoint.pathname;
    byId('endpoint-host').textContent = location.host;
    byId('method-badge').textContent = operation.method;
    byId('method-badge').className = `method-badge ${operation.method.toLowerCase()}`;
    byId('request-body').value = drafts[name] ?? operation.body;
    byId('form-error').textContent = '';
    byId('request-fields').replaceChildren();
    renderKey();
  }

  function handleSuccessfulResponse(name, requestBody, result) {
    const data = result.body?.data;
    if (name === 'issue' && data?.license) seedLicense(data.license);
    if (name === 'activate' && data?.session) seedSession(data.session, requestBody.device_id, data.license_id);
    if (name === 'refresh' && data?.session && lastSession) seedSession(data.session, lastSession.device_id, data.license_id);
    if (name === 'deactivate' && data?.status === 'deactivated') {
      lastSession = null;
      setDraft('check', { access_token: '', device_id: requestBody.device_id });
      setDraft('refresh', { refresh_token: '', device_id: requestBody.device_id });
      setDraft('deactivate', { refresh_token: '', device_id: requestBody.device_id });
    }
  }

  function showResponse(result) {
    lastResponse = result;
    const productKey = result.body?.data?.license?.product_key || result.body?.data?.license?.license_key || '';
    byId('product-key-result').hidden = !productKey;
    byId('product-key-value').textContent = productKey;
    byId('product-key-message').textContent = '';
    const text = JSON.stringify(result.body, null, 2);
    const status = byId('response-status');
    status.textContent = result.status ? `HTTP ${result.status}` : '接続エラー';
    status.className = `status-pill ${result.status >= 400 || result.status === 0 ? 'error' : ''}`;
    byId('response-json').textContent = text;
    byId('response-time').textContent = `${result.duration.toFixed(1)} ms`;
    byId('response-size').textContent = `${new Blob([text]).size} bytes`;
    byId('copy-response').disabled = false;
  }

  function appendHistory(name, result, requestBody) {
    const history = byId('history-list');
    history.querySelector('.empty-history')?.remove();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'history-item';
    const time = document.createElement('span');
    time.textContent = new Date().toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const label = document.createElement('b');
    label.textContent = `${operations[name].method} ${new URL(operations[name].path, document.baseURI).pathname}`;
    const badge = document.createElement('span');
    badge.className = 'history-status';
    badge.textContent = result.status || 'ERR';
    button.append(time, label, badge);
    button.title = 'クリックするとこのリクエストの入力と結果を表示します';
    button.addEventListener('click', () => {
      renderOperation(name);
      drafts[name] = JSON.stringify(requestBody, null, 2);
      byId('request-body').value = drafts[name];
      showResponse(result);
    });
    history.prepend(button);
    while (history.children.length > 8) history.lastElementChild.remove();
  }

  async function issueApiKey() {
    const button = byId('issue-api-key');
    button.disabled = true;
    button.textContent = 'キーを発行中…';
    byId('key-message').textContent = '';
    try {
      const response = await fetchWithTimeout(new URL(`${API_BASE}key.php`, document.baseURI), {
        method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: '{}',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok || !data.data?.api_key) throw new Error(data.message || data.error || `HTTP ${response.status}`);
      sessionStorage.setItem(KEY_STORAGE, JSON.stringify({ key: data.data.api_key, expires_at: data.data.expires_at }));
      lastLicense = null;
      lastSession = null;
      for (const name of ['verify', 'activate', 'revoke', 'check', 'refresh', 'deactivate']) delete drafts[name];
      renderKey();
      if (['verify', 'activate', 'revoke', 'check', 'refresh', 'deactivate'].includes(current)) renderOperation(current, false);
      byId('api-key-value').type = 'text';
      byId('key-message').textContent = 'APIキーを発行しました。このキーはSunabar専用です。';
    } catch (error) {
      byId('key-message').textContent = `発行できませんでした: ${error.message}`;
    } finally {
      button.disabled = false;
      button.textContent = readKey() ? '新しいキーを発行' : '専用キーを発行';
    }
  }

  async function runRequest() {
    if (requestBusy) return;
    byId('form-error').textContent = '';
    const operation = operations[current];
    const saved = readKey();
    if (operation.requiresKey !== false && !saved) {
      byId('form-error').textContent = '先にSunabar専用APIキーを発行してください。';
      byId('key-dialog').showModal();
      renderKey();
      return;
    }
    let body;
    try {
      body = JSON.parse(byId('request-body').value || '{}');
      if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error('JSONのトップレベルはオブジェクトにしてください。');
    } catch (error) {
      byId('form-error').textContent = error.message || 'JSONを確認してください。';
      return;
    }
    if (current === 'revoke' && !window.confirm('このデモライセンスを失効しますか？')) return;
    const started = performance.now();
    let result;
    requestBusy = true;
    byId('send').disabled = true;
    try {
      const response = await fetchWithTimeout(new URL(operation.path, document.baseURI), {
        method: operation.method, cache: 'no-store', credentials: 'omit',
        headers: {
          Accept: 'application/json',
          ...(saved && operation.requiresKey !== false ? { 'X-Sunabar-API-Key': saved.key } : {}),
          ...(operation.method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(operation.method === 'POST' ? { body: JSON.stringify(body) } : {}),
      });
      result = { status: response.status, body: await response.json().catch(() => ({ ok: false, error: 'invalid_server_response' })) };
      if (response.status === 401 && ['expired_token', 'invalid_api_key'].includes(result.body.error)) {
        sessionStorage.removeItem(KEY_STORAGE);
        renderKey();
      }
    } catch (error) {
      result = { status: 0, body: { ok: false, error: 'network_error', message: `Sunabar APIに接続できません: ${error.message}` } };
    } finally {
      requestBusy = false;
      byId('send').disabled = false;
    }
    result.duration = performance.now() - started;
    if (result.status >= 200 && result.status < 300 && result.body?.ok) handleSuccessfulResponse(current, body, result);
    showResponse(result);
    appendHistory(current, result, body);
  }

  document.querySelectorAll('.operation').forEach((button) => button.addEventListener('click', () => renderOperation(button.dataset.operation)));
  byId('send').addEventListener('click', runRequest);
  byId('reset-body').addEventListener('click', () => {
    drafts[current] = operations[current].body;
    byId('request-body').value = operations[current].body;
    byId('form-error').textContent = '';
  });
  byId('open-key').addEventListener('click', () => { renderKey(); byId('key-dialog').showModal(); });
  byId('close-key').addEventListener('click', () => byId('key-dialog').close());
  byId('issue-api-key').addEventListener('click', issueApiKey);
  byId('toggle-key').addEventListener('click', () => { const input = byId('api-key-value'); input.type = input.type === 'password' ? 'text' : 'password'; });
  byId('copy-key').addEventListener('click', async () => { try { await navigator.clipboard.writeText(byId('api-key-value').value); byId('key-message').textContent = 'APIキーをコピーしました。'; } catch { byId('key-message').textContent = 'コピーできません。キーを選択してコピーしてください。'; } });
  byId('copy-path').addEventListener('click', async () => { try { await navigator.clipboard.writeText(`${location.origin}${byId('endpoint-path').textContent}`); } catch { /* clipboard may be unavailable */ } });
  byId('copy-response').addEventListener('click', async () => { if (lastResponse) { try { await navigator.clipboard.writeText(JSON.stringify(lastResponse.body, null, 2)); } catch { /* clipboard may be unavailable */ } } });
  byId('copy-product-key').addEventListener('click', async () => { try { await navigator.clipboard.writeText(byId('product-key-value').textContent); byId('product-key-message').textContent = 'コピーしました。'; } catch { byId('product-key-message').textContent = 'キーを選択してコピーしてください。'; } });
  byId('clear-history').addEventListener('click', () => { byId('history-list').innerHTML = '<p class="empty-history">まだリクエストはありません。</p>'; });
  byId('reset').addEventListener('click', () => {
    sessionStorage.removeItem(KEY_STORAGE);
    lastLicense = null;
    lastSession = null;
    Object.keys(drafts).forEach((key) => delete drafts[key]);
    byId('history-list').innerHTML = '<p class="empty-history">まだリクエストはありません。</p>';
    byId('response-status').textContent = '未実行';
    byId('product-key-result').hidden = true;
    byId('product-key-value').textContent = '';
    byId('response-status').className = 'status-empty';
    byId('response-json').innerHTML = '<span class="json-placeholder">操作を選んでAPIを呼び出してください。</span>';
    byId('response-time').textContent = '— ms';
    byId('response-size').textContent = '—';
    byId('copy-response').disabled = true;
    byId('form-error').textContent = '';
    byId('key-message').textContent = '';
    byId('api-key-value').value = '';
    byId('key-expiry').textContent = '';
    byId('issue-api-key').textContent = '専用キーを発行';
    lastResponse = null;
    renderKey();
    renderOperation('health');
  });

  renderKey();
  renderOperation('health', false);
})();
