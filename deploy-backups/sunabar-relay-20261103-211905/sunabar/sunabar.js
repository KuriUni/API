(() => {
  'use strict';

  const operations = {
    products: {
      title: '製品一覧を取得', description: 'サンプルテナントで利用できる製品を取得します。', method: 'GET', path: '/mock/v1/products', fields: [], body: '{}',
    },
    issue: {
      title: 'ライセンスを発行', description: '選択した製品のデモ用ライセンスキーを発行します。', method: 'POST', path: '/mock/v1/licenses',
      fields: [{ name: 'Content-Type', value: 'application/json' }],
      body: '{\n  "product_id": 101,\n  "license_mode": "single",\n  "label": "Sunabar sample"\n}',
    },
    verify: {
      title: 'ライセンスを確認', description: 'サンプルキーまたはこのタブで発行したデモキーの状態を確認します。', method: 'POST', path: '/mock/v1/verify',
      fields: [{ name: 'Content-Type', value: 'application/json' }],
      body: '{\n  "license_key": "SUNABAR-DEMO-VALID-001",\n  "product_id": 101\n}',
    },
  };
  const products = [
    { id: 101, code: 'TUTI-DESKTOP', name: 'TUTI Desktop', status: 'active', license_modes: ['single', 'volume', 'evaluation'] },
    { id: 102, code: 'MNSL-CLIENT', name: 'My Number Smart Login', status: 'active', license_modes: ['single', 'volume'] },
    { id: 103, code: 'SAMPLE-APP', name: 'Sample App', status: 'active', license_modes: ['single', 'evaluation'] },
  ];
  const byId = (id) => document.getElementById(id);
  const memoryKey = 'sunabar-demo-licenses-v1';
  let current = 'products';
  let lastResponse = null;

  function loadLicenses() {
    try {
      const data = JSON.parse(sessionStorage.getItem(memoryKey) || '[]');
      return Array.isArray(data) ? data.filter((item) => item && typeof item.key === 'string') : [];
    } catch {
      return [];
    }
  }

  function saveLicenses(licenses) {
    try { sessionStorage.setItem(memoryKey, JSON.stringify(licenses)); } catch { /* keep the current response usable */ }
  }

  function renderOperation(name) {
    current = name;
    const operation = operations[name];
    document.querySelectorAll('.operation').forEach((button) => button.classList.toggle('active', button.dataset.operation === name));
    byId('operation-title').textContent = operation.title;
    byId('operation-description').textContent = operation.description;
    byId('endpoint-path').textContent = operation.path;
    byId('method-badge').textContent = operation.method;
    byId('method-badge').className = `method-badge ${operation.method.toLowerCase()}`;
    byId('request-body').value = operation.body;
    byId('form-error').textContent = '';
    const fields = byId('request-fields');
    fields.replaceChildren();
    for (const field of operation.fields) {
      const wrapper = document.createElement('div');
      wrapper.className = 'field';
      const label = document.createElement('label');
      label.textContent = field.name;
      const value = document.createElement('input');
      value.readOnly = true;
      value.value = field.value;
      wrapper.append(label, value);
      fields.append(wrapper);
    }
  }

  function error(status, code, message) {
    return { status, body: { ok: false, error: code, message } };
  }

  function simulate(name, requestBody) {
    const operation = operations[name];
    if (name === 'products') return { status: 200, body: { ok: true, data: { products } } };
    if (name === 'issue') {
      const productId = Number(requestBody.product_id);
      const product = products.find((item) => item.id === productId && item.status === 'active');
      if (!Number.isInteger(productId) || productId < 1) return error(422, 'invalid_product_id', 'product_idは1以上の整数で指定してください。');
      if (!product) return error(404, 'product_not_found', 'このサンプル環境に製品がありません。製品一覧を確認してください。');
      const mode = String(requestBody.license_mode || 'single');
      if (!product.license_modes.includes(mode)) return error(422, 'invalid_license_mode', 'この製品では指定したライセンス方式を利用できません。');
      const randomPart = globalThis.crypto?.randomUUID?.().replaceAll('-', '').slice(0, 20).toUpperCase()
        || `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`.toUpperCase();
      const key = `SUNABAR-DEMO-${randomPart}`;
      const record = { key, product_id: product.id, product_name: product.name, license_mode: mode, label: String(requestBody.label || '').slice(0, 100), status: 'active', issued_at: new Date().toISOString() };
      saveLicenses([...loadLicenses(), record]);
      return { status: 201, body: { ok: true, data: { license: record }, note: 'This is a simulated key. It cannot activate real software.' } };
    }
    if (name === 'verify') {
      const key = String(requestBody.license_key || '').trim();
      if (!key) return error(422, 'license_key_required', 'license_keyを入力してください。');
      const saved = loadLicenses().find((item) => item.key === key);
      const sample = key === 'SUNABAR-DEMO-VALID-001' ? { product_id: 101, product_name: 'TUTI Desktop', license_mode: 'single', status: 'active' }
        : key === 'SUNABAR-DEMO-REVOKED-001' ? { product_id: 102, product_name: 'My Number Smart Login', license_mode: 'single', status: 'revoked' } : null;
      const record = saved || sample;
      if (!record) return error(404, 'license_not_found', 'サンプルキーが見つかりません。発行操作を行うか、用意されたサンプルキーを入力してください。');
      if (requestBody.product_id !== undefined && Number(requestBody.product_id) !== Number(record.product_id)) return error(409, 'product_mismatch', 'ライセンスとproduct_idが一致しません。');
      return { status: 200, body: { ok: true, data: { valid: record.status === 'active', license: { product_id: record.product_id, product_name: record.product_name, license_mode: record.license_mode, status: record.status } } } };
    }
    return error(404, 'operation_not_found', `Unknown local simulation path: ${operation.path}`);
  }

  function appendHistory(name, result, timestamp) {
    const history = byId('history-list');
    const empty = history.querySelector('.empty-history');
    if (empty) empty.remove();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'history-item';
    const time = document.createElement('span');
    time.textContent = new Date(timestamp).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const label = document.createElement('b');
    label.textContent = `${operations[name].method} ${operations[name].path}`;
    const resultBadge = document.createElement('span');
    resultBadge.className = 'history-status';
    resultBadge.textContent = String(result.status);
    button.append(time, label, resultBadge);
    button.addEventListener('click', () => showResponse(result));
    history.prepend(button);
    while (history.children.length > 8) history.lastElementChild.remove();
  }

  function showResponse(result) {
    lastResponse = result;
    const text = JSON.stringify(result.body, null, 2);
    const status = byId('response-status');
    status.textContent = `HTTP ${result.status}`;
    status.className = `status-pill ${result.status >= 400 ? 'error' : ''}`;
    byId('response-json').textContent = text;
    byId('response-time').textContent = `${result.duration.toFixed(2)} ms`;
    byId('response-size').textContent = `${new Blob([text]).size} bytes`;
    byId('copy-response').disabled = false;
  }

  byId('send').addEventListener('click', () => {
    byId('form-error').textContent = '';
    let body;
    try {
      body = JSON.parse(byId('request-body').value || '{}');
      if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error('JSONのトップレベルはオブジェクトにしてください。');
    } catch (failure) {
      byId('form-error').textContent = failure.message || 'JSONを確認してください。';
      return;
    }
    const started = performance.now();
    const result = simulate(current, body);
    result.duration = performance.now() - started;
    showResponse(result);
    appendHistory(current, result, Date.now());
  });
  document.querySelectorAll('.operation').forEach((button) => button.addEventListener('click', () => renderOperation(button.dataset.operation)));
  byId('reset-body').addEventListener('click', () => { byId('request-body').value = operations[current].body; byId('form-error').textContent = ''; });
  byId('copy-path').addEventListener('click', async () => { try { await navigator.clipboard.writeText(byId('endpoint-path').textContent); } catch { /* clipboard may be unavailable on local files */ } });
  byId('copy-response').addEventListener('click', async () => { if (lastResponse) { try { await navigator.clipboard.writeText(JSON.stringify(lastResponse.body, null, 2)); } catch { /* clipboard may be unavailable */ } } });
  byId('clear-history').addEventListener('click', () => { byId('history-list').innerHTML = '<p class="empty-history">まだ実行したリクエストはありません。</p>'; });
  byId('reset').addEventListener('click', () => {
    try { sessionStorage.removeItem(memoryKey); } catch { /* ignore unavailable storage */ }
    byId('history-list').innerHTML = '<p class="empty-history">まだ実行したリクエストはありません。</p>';
    byId('response-status').textContent = '未実行';
    byId('response-status').className = 'status-empty';
    byId('response-json').innerHTML = '<span class="json-placeholder">左の操作を選び、リクエストを実行してください。</span>';
    byId('response-time').textContent = '— ms';
    byId('response-size').textContent = '—';
    byId('copy-response').disabled = true;
    byId('form-error').textContent = '';
    lastResponse = null;
    renderOperation('products');
  });
  byId('response-tab').addEventListener('click', () => {});
  renderOperation('products');
})();
