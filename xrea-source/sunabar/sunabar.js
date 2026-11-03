(() => {
  'use strict';

  const API_BASE = '/license/api/sunabar/v1/';
  const KEY_STORAGE = 'sunabar-api-key-v1';
  const operations = {
    products: { title: '製品一覧を取得', description: '利用可能な製品をAPIから取得します。', method: 'GET', path: `${API_BASE}products.php`, body: '{}' },
    issue: { title: 'ライセンスを発行', description: '実ソフトには使えないデモライセンスを発行します。', method: 'POST', path: `${API_BASE}licenses.php`, body: '{\n  "product_id": 101,\n  "license_mode": "single",\n  "label": "Sunabar sample"\n}' },
    verify: { title: 'ライセンスを検証', description: '発行レスポンスのlicense_keyを貼り付けて状態を確認します。', method: 'POST', path: `${API_BASE}verify.php`, body: '{\n  "license_key": "",\n  "product_id": 101\n}' },
    list: { title: 'ライセンス一覧', description: 'このキーで発行したライセンスを最大100件表示します。', method: 'GET', path: `${API_BASE}license-list.php`, body: '{}' },
    revoke: { title: 'ライセンスを失効', description: '一覧や発行結果にあるlicense_idを指定します。失効後は検証できません。', method: 'POST', path: `${API_BASE}license-revoke.php`, body: '{\n  "license_id": ""\n}' },
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
    const productKey = result.body?.data?.license?.product_key || '';
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
      const response = await fetch(new URL(`${API_BASE}key.php`, document.baseURI), {
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

  document.querySelectorAll('.operation').forEach((button) => button.addEventListener('click', () => renderOperation(button.dataset.operation)));
  byId('send').addEventListener('click', runRequest);
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
    lastResponse = null;
    renderKey();
    renderOperation('products');
  });

  renderKey();
  renderOperation('products');
})();
