(() => {
  'use strict';

  const API_BASE = 'api/v1/';
  const KEY_STORAGE = 'sunabar-api-key-v1';
  const operations = {
    products: { title: '製品一覧を取得', description: '利用可能な製品をAPIから取得します。', method: 'GET', path: `${API_BASE}products`, body: '{}' },
    issue: { title: 'ライセンスを発行', description: '実ソフトには使えないデモライセンスを発行します。', method: 'POST', path: `${API_BASE}licenses`, body: '{\n  "product_id": 101,\n  "license_mode": "single",\n  "label": "Sunabar sample"\n}' },
    verify: { title: 'ライセンスを検証', description: '発行レスポンスのlicense_keyを貼り付けて状態を確認します。', method: 'POST', path: `${API_BASE}verify`, body: '{\n  "license_key": "",\n  "product_id": 101\n}' },
    list: { title: 'ライセンス一覧', description: 'このキーで発行したライセンスを最大100件表示します。', method: 'GET', path: `${API_BASE}licenses/list`, body: '{}' },
    revoke: { title: 'ライセンスを失効', description: '一覧や発行結果にあるlicense_idを指定します。失効後は検証できません。', method: 'POST', path: `${API_BASE}licenses/revoke`, body: '{\n  "license_id": ""\n}' },
    activate: { title: '端末を有効化', description: 'デモライセンスを端末IDに紐づけ、アクセストークンと更新トークンを発行します。', method: 'POST', path: 'api/v1/activate', body: '{\n  "license_key": "",\n  "device_id": "demo-device-01"\n}' },
    check: { title: 'アクセストークンを確認', description: '有効なアクセストークンと端末IDを確認します。', method: 'POST', path: 'api/v1/session/check', body: '{\n  "access_token": "",\n  "device_id": "demo-device-01"\n}' },
    refresh: { title: 'トークンを更新', description: '更新トークンを一度使うと、新しいペアに入れ替わります。', method: 'POST', path: 'api/v1/session/refresh', body: '{\n  "refresh_token": "",\n  "device_id": "demo-device-01"\n}' },
    deactivate: { title: '端末を無効化', description: '更新トークンを失効させ、この端末のセッションを停止します。', method: 'POST', path: 'api/v1/session/deactivate', body: '{\n  "refresh_token": "",\n  "device_id": "demo-device-01"\n}' },

  };
  const byId = (id) => document.getElementById(id);
  let current = 'products';
  let lastResponse = null;

  function readKey() {
    try {
      const saved = JSON.parse(sessionStorage.getItem(KEY_STORAGE) || 'null');
      if (saved && typeof saved.key === 'string' && Number(saved.expires_at) > Date.now() / 1000) return saved;
      sessionStorage.removeItem(KEY_STORAGE);
    } catch { /* storage is optional */ }
    return null;
  }

  function renderKey() {
    const saved = readKey();
    const status = byId('key-status');
    status.innerHTML = saved ? '<i></i> API KEY READY' : '<i></i> API KEY REQUIRED';
    status.classList.toggle('key-ready', Boolean(saved));
    byId('auth-state').textContent = saved ? '設定済み' : '未設定';
    const input = byId('api-key-value');
    input.value = saved ? saved.key : '';
    input.type = 'password';
    byId('copy-key').disabled = !saved;
    byId('key-expiry').textContent = saved ? `有効期限 ${new Date(saved.expires_at * 1000).toLocaleString('ja-JP')}` : '';
  }

  function renderOperation(name) {
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
    byId('request-body').value = operation.body;
    byId('form-error').textContent = '';
    byId('request-fields').replaceChildren();
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

  function appendHistory(name, result) {
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
    button.addEventListener('click', () => showResponse(result));
    history.prepend(button);
    while (history.children.length > 8) history.lastElementChild.remove();
  }

  async function issueApiKey() {
    const button = byId('issue-api-key');
    button.disabled = true;
    button.textContent = 'キーを発行中…';
    byId('key-message').textContent = '';
    try {
      const response = await fetch(new URL(`${API_BASE}key`, document.baseURI), {
        method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: '{}',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok || !data.data?.api_key) throw new Error(data.message || data.error || `HTTP ${response.status}`);
      sessionStorage.setItem(KEY_STORAGE, JSON.stringify({ key: data.data.api_key, expires_at: data.data.expires_at }));
      renderKey();
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
    byId('form-error').textContent = '';
    const saved = readKey();
    if (!saved) {
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
    const operation = operations[current];
    const started = performance.now();
    if (current === 'revoke' && !window.confirm('このデモライセンスを失効しますか？')) return;
    let result;
    try {
      const response = await fetch(new URL(operation.path, document.baseURI), {
        method: operation.method, cache: 'no-store', credentials: 'omit',
        headers: { Accept: 'application/json', 'X-Sunabar-API-Key': saved.key,
          ...(operation.method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
        ...(operation.method === 'POST' ? { body: JSON.stringify(body) } : {}),
      });
      result = { status: response.status, body: await response.json().catch(() => ({ ok: false, error: 'invalid_server_response' })) };
      if (response.status === 401 && ['expired_token', 'invalid_api_key'].includes(result.body.error)) {
        sessionStorage.removeItem(KEY_STORAGE);
        renderKey();
      }
    } catch (error) {
      result = { status: 0, body: { ok: false, error: 'network_error', message: `Sunabar APIに接続できません: ${error.message}` } };
    }
    result.duration = performance.now() - started;
    showResponse(result);
    appendHistory(current, result);
  }

  async function runSimulation() {
    if (!window.confirm('専用APIキーでデモライセンスを発行し、端末認証・トークン確認・更新・ログアウトを試します。最後にライセンスを失効します。履歴レコードはDBに残ります。開始しますか？')) return;
    const button = byId('run-simulation');
    const status = byId('simulation-status');
    const output = byId('simulation-output');
    const steps = [...document.querySelectorAll('[data-sim-step]')];
    const results = [];
    const deviceId = 'sunabar-demo-device-01';
    let saved = readKey();
    let license = null;
    let session = null;
    button.disabled = true;
    button.textContent = '実行中…';
    steps.forEach((step) => { step.className = ''; });
    status.textContent = 'Sunabarのソフト認証フローを実行しています。';
    output.textContent = '通信中…';

    async function request(path, method, body, apiKey) {
      const response = await fetch(new URL(path, document.baseURI), {
        method, cache: 'no-store', credentials: 'omit',
        headers: { Accept: 'application/json', ...(apiKey ? { 'X-Sunabar-API-Key': apiKey } : {}),
          ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
        ...(method === 'POST' ? { body: JSON.stringify(body || {}) } : {}),
      });
      const payload = await response.json().catch(() => ({ ok: false, error: 'invalid_server_response' }));
      if (!response.ok || payload.ok === false) throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
      return { status: response.status, payload };
    }

    async function step(index, label, action) {
      steps[index].className = 'running';
      status.textContent = `${index + 1}/7 ${label}…`;
      const result = await action();
      steps[index].className = 'done';
      results.push({ step: label, status: result.status, response: result.payload });
      output.textContent = JSON.stringify(results, null, 2);
      return result.payload;
    }

    try {
      if (saved) {
        steps[0].className = 'done';
        results.push({ step: '専用APIキー', status: '既存キーを使用' });
        output.textContent = JSON.stringify(results, null, 2);
      } else {
        const keyPath = `${API_BASE}key${API_BASE.startsWith('/') ? '.php' : ''}`;
        const keyResult = await step(0, '専用APIキー', () => request(keyPath, 'POST', {}, ''));
        const keyData = keyResult.data || {};
        if (!keyData.api_key) throw new Error('APIキーが応答にありません。');
        sessionStorage.setItem(KEY_STORAGE, JSON.stringify({ key: keyData.api_key, expires_at: keyData.expires_at }));
        saved = readKey();
        renderKey();
      }

      const issued = await step(1, 'ライセンス発行', () => request(operations.issue.path, 'POST', {
        product_id: 101, license_mode: 'single', label: 'Sunabar guided demo'
      }, saved.key));
      license = issued.data?.license;
      const licenseKey = license?.license_key || license?.product_key;
      if (!licenseKey || !license?.license_id) throw new Error('ライセンス情報が応答にありません。');

      const activated = await step(2, '端末認証', () => request(operations.activate.path, 'POST', {
        license_key: licenseKey, device_id: deviceId
      }, saved.key));
      session = activated.data?.session;
      if (!session?.access_token || !session?.refresh_token) throw new Error('アクセストークンまたは更新トークンが応答にありません。');

      await step(3, '利用確認', () => request(operations.check.path, 'POST', {
        access_token: session.access_token, device_id: deviceId
      }, saved.key));

      const refreshed = await step(4, 'トークン更新', () => request(operations.refresh.path, 'POST', {
        refresh_token: session.refresh_token, device_id: deviceId
      }, saved.key));
      session = refreshed.data?.session;
      if (!session?.access_token || !session?.refresh_token) throw new Error('更新後のトークンが応答にありません。');

      await step(5, 'ログアウト', () => request(operations.deactivate.path, 'POST', {
        refresh_token: session.refresh_token, device_id: deviceId
      }, saved.key));
      session = null;

      await step(6, 'デモキー失効', () => request(operations.revoke.path, 'POST', {
        license_id: license.license_id
      }, saved.key));
      status.textContent = '完了：端末認証からログアウトまで成功し、デモライセンスも失効しました。';
    } catch (error) {
      const failed = steps.find((item) => item.classList.contains('running'));
      if (failed) failed.className = 'failed';
      results.push({ error: error.message });
      if (saved && license?.license_id) {
        if (session?.refresh_token) {
          try {
            const cleanup = await request(operations.deactivate.path, 'POST', { refresh_token: session.refresh_token, device_id: deviceId }, saved.key);
            results.push({ step: '中断時のログアウト', status: cleanup.status });
          } catch (cleanupError) { results.push({ step: '中断時のログアウト', error: cleanupError.message }); }
        }
        try {
          const cleanup = await request(operations.revoke.path, 'POST', { license_id: license.license_id }, saved.key);
          results.push({ step: '中断時のデモキー失効', status: cleanup.status });
        } catch (cleanupError) { results.push({ step: '中断時のデモキー失効', error: cleanupError.message }); }
      }
      status.textContent = `中断しました：${error.message}。実行結果に後片付けの成否を表示しています。`;
      output.textContent = JSON.stringify(results, null, 2);
    } finally {
      button.disabled = false;
      button.textContent = '▶ もう一度シミュレーション';
    }
  }

  document.querySelectorAll('.operation').forEach((button) => button.addEventListener('click', () => renderOperation(button.dataset.operation)));
  byId('send').addEventListener('click', runRequest);
  byId('run-simulation').addEventListener('click', runSimulation);
  byId('reset-body').addEventListener('click', () => { byId('request-body').value = operations[current].body; byId('form-error').textContent = ''; });
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
    document.querySelectorAll('[data-sim-step]').forEach((step) => { step.className = ''; });
    byId('simulation-status').textContent = '実行すると、作成したデモライセンスは最後に失効します（履歴はDBに残ります）。';
    byId('simulation-output').textContent = 'まだ実行していません。';
    byId('run-simulation').textContent = '▶ シミュレーション開始';
    lastResponse = null;
    renderKey();
    renderOperation('products');
  });

  renderKey();
  renderOperation('products');
})();
