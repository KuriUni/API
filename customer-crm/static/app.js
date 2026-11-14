(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const ENVIRONMENTS = [
    { value: '', label: '指定なし' },
    { value: 'production', label: '本番' },
    { value: 'sandbox', label: 'サンドボックス' }
  ];
  const state = { me: null, csrf: '', route: '/dashboard', routeToken: 0, customers: [] };

  const ICONS = {
    dashboard: 'M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z',
    building: 'M4 21V4a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v4h4a1 1 0 0 1 1 1v12h-6v-4H9v4H4Zm3-4h2v-2H7v2Zm0-4h2v-2H7v2Zm0-4h2V7H7v2Zm5 4h2v-2h-2v2Zm0-4h2V7h-2v2Zm6 8h-1v-2h1v2Zm0-4h-1v-2h1v2Z',
    key: 'M14 2a6 6 0 0 0-5.66 8H3v4h2v2h2v2h4v-4h1.34A6 6 0 1 0 14 2Zm2.5 4.5a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3Z',
    chart: 'M4 19h16v2H4v-2Zm2-2h3V9H6v8Zm5 0h3V5h-3v12Zm5 0h3v-5h-3v5Z',
    invoice: 'M6 2h12a1 1 0 0 1 1 1v19l-3-2-2 2-2-2-2 2-2-2-3 2V3a1 1 0 0 1 1-1Zm1 4v2h10V6H7Zm0 4v2h10v-2H7Zm0 4v2h6v-2H7Z',
    activity: 'M4 4h16v2H4V4Zm0 5h10v2H4V9Zm0 5h16v2H4v-2Zm0 5h10v2H4v-2Z',
    search: 'M10 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm0-14a6 6 0 1 0 0 12 6 6 0 0 0 0-12Zm6.32 12.9 1.42-1.42 4.24 4.24-1.42 1.42-4.24-4.24Z',
    plus: 'M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6V5Z',
    edit: 'm4.5 16.5 10-10 3 3-10 10H4.5v-3ZM6 15l3 3M14.5 3.5l3 3 2-2-3-3-2 2Z',
    trash: 'M7 21a2 2 0 0 1-2-2V7h14v12a2 2 0 0 1-2 2H7ZM5 4h5V2h4v2h5v2H5V4Zm4 5v8h2V9H9Zm4 0v8h2V9h-2Z',
    sync: 'M12 4V1L8 5l4 4V6a6 6 0 0 1 5.2 9l1.5 1.5A8 8 0 0 0 12 4Zm0 14a6 6 0 0 1-5.2-9L5.3 7.5A8 8 0 0 0 12 20v3l4-4-4-4v3Z',
    arrowLeft: 'M11.67 3.87 3.54 12l8.13 8.13 1.42-1.42L7.36 13H21v-2H7.36l5.73-5.71-1.42-1.42Z',
    x: 'M6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4 17.6 5 12 10.6 6.4 5Z',
    external: 'M14 3h7v7h-2V6.4l-8.3 8.3-1.4-1.4L17.6 5H14V3ZM5 5h5v2H7v10h10v-3h2v5H5V5Z',
    briefcase: 'M9 4h6a2 2 0 0 1 2 2v2h4v12H3V8h4V6a2 2 0 0 1 2-2Zm0 4h6V6H9v2Zm-4 2v6h14v-6H5Z',
    clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm1-13h-2v6l5 3 1-1.7-4-2.3V7Z'
  };

  function icon(name) {
    return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[name] || ICONS.activity}"/></svg>`;
  }

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[ch]));
  }

  const numberFormat = new Intl.NumberFormat('ja-JP');
  function yen(value) {
    return `¥${numberFormat.format(Number(value || 0))}`;
  }
  function compactYen(value) {
    const n = Number(value || 0);
    if (n >= 100000000) return `${(n / 100000000).toFixed(1)}億円`;
    if (n >= 10000) return `${Math.round(n / 10000)}万円`;
    return yen(n);
  }
  function formatDate(value) {
    const text = String(value || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return value ? String(value) : '—';
    const [y, m, d] = text.split('-');
    return `${y}/${m}/${d}`;
  }
  function formatDateTime(value) {
    const text = String(value || '');
    if (!text) return '—';
    return text.replace('T', ' ').slice(0, 16);
  }
  function ago(value) {
    if (!value) return '未同期';
    const then = new Date(String(value).replace(' ', 'T'));
    if (Number.isNaN(then.getTime())) return String(value);
    const diff = Math.round((Date.now() - then.getTime()) / 60000);
    if (diff < 1) return 'たった今';
    if (diff < 60) return `${diff}分前`;
    if (diff < 1440) return `${Math.round(diff / 60)}時間前`;
    return `${Math.round(diff / 1440)}日前`;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set('Content-Type', 'application/json');
    if (options.method && options.method !== 'GET') headers.set('X-CSRF-Token', state.csrf);
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
    if (response.status === 401) {
      location.replace('/login');
      throw new Error('ログインが必要です');
    }
    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json().catch(() => null) : null;
    if (!response.ok) {
      const detail = data?.detail;
      const message = Array.isArray(detail)
        ? detail.map(item => item.msg || String(item)).join(' / ')
        : detail || '処理に失敗しました';
      throw new Error(message);
    }
    return data;
  }

  function toast(message, error = false) {
    const node = $('toast');
    node.textContent = message;
    node.classList.toggle('error', error);
    node.classList.add('show');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => node.classList.remove('show'), 3600);
  }

  function setView(html) { $('view').innerHTML = html; }
  function loadingView() {
    return `<div class="loading-state"><div class="skeleton wide"></div><div class="skeleton"></div><div class="skeleton short"></div></div>`;
  }
  function errorView(message) {
    return `<div class="card empty-state"><div class="empty-icon">${icon('x')}</div><h3>読み込めませんでした</h3><p>${esc(message)}</p><button class="button" data-action="reload">再読み込み</button></div>`;
  }
  function emptyState(title, text, action = '') {
    return `<div class="card empty-state"><div class="empty-icon">${icon('search')}</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${action}</div>`;
  }
  function pageHead(eyebrow, title, subtitle, actions) {
    return `<div class="page-head"><div><p class="eyebrow">${esc(eyebrow)}</p><h1>${esc(title)}</h1><p class="muted">${esc(subtitle)}</p></div><div class="page-head-actions">${actions || ''}</div></div>`;
  }
  function envBadge(environment) {
    const label = environment === 'sandbox' ? 'サンドボックス' : environment === 'production' ? '本番' : '指定なし';
    const klass = environment === 'sandbox' ? 'rank-B' : environment === 'production' ? 'rank-S' : 'rank-C';
    return `<span class="badge ${klass}">${esc(label)}</span>`;
  }

  function updateNav(path) {
    const base = '/' + path.split('/').filter(Boolean)[0];
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.route === base);
    });
  }
  function parseRoute() {
    const raw = (location.hash || '#/dashboard').replace(/^#/, '');
    const [pathPart, queryPart = ''] = raw.split('?');
    return { path: pathPart || '/dashboard', params: new URLSearchParams(queryPart) };
  }
  function navigate(path) {
    const target = `#${path}`;
    if (location.hash === target) route(); else location.hash = target;
  }
  function closeSidebar() {
    $('sidebar').classList.remove('open');
    $('sidebar-overlay').hidden = true;
  }
  function openSidebar() {
    $('sidebar').classList.add('open');
    $('sidebar-overlay').hidden = false;
  }

  function bindShell() {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => { navigate(item.dataset.route); closeSidebar(); });
    });
    $('menu-button').addEventListener('click', openSidebar);
    $('sidebar-overlay').addEventListener('click', closeSidebar);
    $('global-search').addEventListener('submit', event => {
      event.preventDefault();
      const query = $('global-query').value.trim();
      navigate(`/licenses${query ? `?q=${encodeURIComponent(query)}` : ''}`);
    });
    $('quick-create').addEventListener('click', () => openCustomerForm());
    $('logout-button').addEventListener('click', async () => {
      try { await api('/api/logout', { method: 'POST' }); } finally { location.replace('/login'); }
    });
    window.addEventListener('hashchange', route);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') { closeSidebar(); closeModal(); }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        $('global-query').focus();
      }
    });
    $('view').addEventListener('click', onViewClick);
    $('view').addEventListener('submit', onViewSubmit);
  }

  async function init() {
    bindShell();
    $('topbar-date').textContent = new Date().toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' });
    if (!location.hash) history.replaceState(null, '', '#/dashboard');
    try {
      state.me = await api('/api/me');
      state.csrf = state.me.csrf;
      const name = state.me.name || '管理者';
      $('sidebar-name').textContent = name;
      $('sidebar-avatar').textContent = String(name).slice(0, 1);
      route();
    } catch (error) {
      if (!String(error.message).includes('ログイン')) setView(errorView(error.message));
    }
  }

  async function route() {
    const { path, params } = parseRoute();
    state.route = path;
    updateNav(path);
    closeSidebar();
    closeModal();
    state.routeToken += 1;
    const token = state.routeToken;
    setView(loadingView());
    try {
      if (path === '/dashboard' || path === '/') await renderDashboard(token);
      else if (path === '/customers') await renderCustomers(params, token);
      else if (/^\/customers\/\d+$/.test(path)) await renderCustomerDetail(Number(path.split('/')[2]), token);
      else if (path === '/licenses') await renderLicenses(params, token);
      else if (path === '/billing') await renderBilling(params, token);
      else setView(emptyState('ページが見つかりません', 'サイドバーから画面を選び直してください。'));
    } catch (error) {
      if (token === state.routeToken && !String(error.message).includes('ログイン')) {
        setView(errorView(error.message));
        toast(error.message, true);
      }
    }
  }

  // ---------------------------------------------------------------- dashboard
  async function renderDashboard(token) {
    const data = await api('/api/dashboard');
    if (token !== state.routeToken) return;
    const k = data.kpis;
    const customers = data.customers;
    const rows = customers.length ? customers.map(customer => `
      <tr>
        <td><a class="inline-link" href="#/customers/${customer.id}">${esc(customer.name)}</a><div class="table-sub">${esc(customer.slug || 'slug 未設定')}</div></td>
        <td>${envBadge(customer.environment)}</td>
        <td>${numberFormat.format(customer.active_licenses)} / ${numberFormat.format(customer.licenses)}</td>
        <td>${customer.month_charge ? yen(customer.month_charge) : '—'}</td>
        <td>${customer.unpaid_count ? `${customer.unpaid_count}件 / ${yen(customer.unpaid_amount)}` : '—'}</td>
        <td>${customer.error_message ? `<span class="badge rank-C" title="${esc(customer.error_message)}">エラー</span>` : customer.last_sync ? esc(ago(customer.last_sync)) : '<span class="muted">未同期</span>'}</td>
      </tr>`).join('') : '';
    const events = data.events.length ? data.events.map(event => `
      <div class="mini-activity">
        <span class="mini-activity-dot ${Number(event.status_code) >= 400 ? 'note' : 'meeting'}"></span>
        <div class="mini-activity-copy">
          <strong>${esc(event.operation || '')}</strong>
          <small><a class="inline-link" href="#/customers/${event.customer_id}">${esc(event.customer_name)}</a> · HTTP ${esc(event.status_code ?? '')} · ${esc(formatDateTime(event.used_at))}</small>
        </div>
      </div>`).join('') : '<p class="panel-note">APIイベントはまだありません。顧客を追加して同期してください。</p>';
    setView(`
      ${pageHead('TUTI API', 'ダッシュボード', 'TUTIテナントの契約・ライセンス・API利用料をまとめて確認します。',
        `${customers.length ? '<button class="button" data-action="sync-all">すべて同期</button>' : ''}<button class="button primary" data-action="new-customer">顧客を追加</button>`)}
      ${customers.length === 0 ? emptyState('顧客がまだありません', 'TUTIのテナントAPIキーを登録すると、契約・ライセンス・請求・API利用状況を取り込みます。', '<button class="button primary" data-action="new-customer">顧客を追加</button>') : `
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('building')}顧客</span><strong>${numberFormat.format(k.active_customers)}<small>社</small></strong><p class="metric-note">同期済み ${numberFormat.format(k.synced_customers)} 社</p></article>
        <article class="metric"><span class="metric-label">${icon('key')}ライセンス</span><strong>${numberFormat.format(k.licenses)}<small>件</small></strong><p class="metric-note">稼働中 ${numberFormat.format(k.active_licenses)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}今月のAPI利用料</span><strong>${yen(k.month_charge)}</strong><p class="metric-note">${esc(data.month)} 時点</p></article>
        <article class="metric ${k.error_customers ? 'alert' : ''}"><span class="metric-label">${icon('invoice')}未払い請求</span><strong>${numberFormat.format(k.unpaid_count)}<small>件</small></strong><p class="metric-note">${yen(k.unpaid_amount)}${k.error_customers ? ` · 同期エラー ${k.error_customers}社` : ''}</p></article>
      </section>
      <div class="dash-grid">
        <div class="dash-stack">
          <section class="card list-card">
            <div class="section-head"><div><p class="eyebrow">CUSTOMERS</p><h2>顧客</h2></div><a class="inline-link" href="#/customers">一覧へ →</a></div>
            <div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>環境</th><th>ライセンス</th><th>今月利用料</th><th>未払い</th><th>同期</th></tr></thead><tbody>${rows}</tbody></table></div>
          </section>
        </div>
        <div class="dash-stack">
          <section class="card list-card">
            <div class="section-head"><div><p class="eyebrow">RECENT API EVENTS</p><h2>最近のAPIイベント</h2></div></div>
            <div class="activity-mini">${events}</div>
          </section>
        </div>
      </div>`}`);
  }

  // ---------------------------------------------------------------- customers
  async function renderCustomers(params, token) {
    const data = await api('/api/customers');
    if (token !== state.routeToken) return;
    state.customers = data.items;
    const q = (params.get('q') || '').trim().toLowerCase();
    const items = q
      ? data.items.filter(item => `${item.name} ${item.slug}`.toLowerCase().includes(q))
      : data.items;
    const rows = items.map(customer => `
      <tr>
        <td><a class="inline-link" href="#/customers/${customer.id}">${esc(customer.name)}</a><div class="table-sub">${esc(customer.slug || 'slug 未設定')} · ${esc(customer.key_hint)}</div></td>
        <td>${envBadge(customer.environment)}</td>
        <td>${numberFormat.format(customer.active_licenses)} / ${numberFormat.format(customer.licenses)}<div class="table-sub">製品 ${customer.products} 件</div></td>
        <td>${customer.month_charge ? yen(customer.month_charge) : '—'}</td>
        <td>${customer.unpaid_count ? `${customer.unpaid_count}件` : '—'}</td>
        <td>${customer.error_message ? `<span class="badge rank-C">同期エラー</span>` : customer.last_sync ? esc(ago(customer.last_sync)) : '<span class="muted">未同期</span>'}</td>
        <td class="cell-actions">
          <button class="icon-button" data-action="sync-customer" data-id="${customer.id}" title="同期" aria-label="同期">${icon('sync')}</button>
          <button class="icon-button" data-action="edit-customer" data-id="${customer.id}" title="編集" aria-label="編集">${icon('edit')}</button>
          <button class="icon-button" data-action="delete-customer" data-id="${customer.id}" title="削除" aria-label="削除">${icon('trash')}</button>
        </td>
      </tr>`).join('');
    setView(`
      ${pageHead('CUSTOMERS', '顧客', 'TUTIテナントを顧客として管理します。APIキーは暗号化して保存されます。',
        '<button class="button" data-action="sync-all">すべて同期</button><button class="button primary" data-action="new-customer">顧客を追加</button>')}
      ${data.items.length ? `
      <section class="card detail-section">
        <form class="toolbar" data-filter="customers"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="顧客名・slugで検索" aria-label="顧客を検索"></label>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/customers">解除</a>
        </div></form>
        ${items.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>環境</th><th>ライセンス</th><th>今月利用料</th><th>未払い</th><th>同期</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
          : emptyState('該当する顧客がありません', '検索条件を変えてください。')}
      </section>` : emptyState('顧客がまだありません', 'TUTIのテナントAPIキーを登録すると、契約・ライセンス・請求データを取得します。',
        '<button class="button primary" data-action="new-customer">顧客を追加</button>')}`);
  }

  async function renderCustomerDetail(customerId, token) {
    const data = await api(`/api/customers/${customerId}`);
    if (token !== state.routeToken) return;
    const customer = data.customer;
    const licenses = data.licenses || [];
    const invoices = data.invoices || [];
    const events = data.events || [];
    const usage = data.usage || {};
    const products = data.products || [];
    const scopeErrors = Object.entries(data.scopes || {})
      .filter(([, value]) => value.error)
      .map(([scope, value]) => `<p class="panel-note">${esc(scope)}: ${esc(value.error)}</p>`).join('');
    const usageRows = Array.isArray(usage.details) ? usage.details : [];
    const licenseRows = licenses.map(row => `
      <tr>
        <td>#${esc(row.id)}</td>
        <td>${esc(row.product_code || row.product_id || '')}</td>
        <td>${esc(row.label || '（ラベルなし）')}</td>
        <td>${row.active ? '<span class="badge rank-S">稼働中</span>' : '<span class="badge rank-C">停止</span>'}</td>
        <td>${esc(row.environment || '')}</td>
        <td>${esc(row.max_devices ?? '')}</td>
        <td>${row.expires_at ? esc(formatDate(row.expires_at)) : '無期限'}</td>
        <td>${row.created_at ? esc(formatDate(row.created_at)) : ''}</td>
      </tr>`).join('');
    const invoiceRows = invoices.map(row => `
      <tr>
        <td>${esc(row.invoice_number || '')}</td>
        <td>${esc(row.billing_period || '')}</td>
        <td>${esc(yen(row.total_yen ?? 0))}</td>
        <td>${esc(row.status || '')}</td>
        <td>${row.due_date ? esc(formatDate(row.due_date)) : ''}</td>
      </tr>`).join('');
    const eventRows = events.map(row => `
      <tr><td>${esc(formatDateTime(row.used_at))}</td><td>${esc(row.operation || '')}</td><td>${esc(row.status_code ?? '')}</td><td><code>${esc(row.request_id || '')}</code></td></tr>`).join('');
    setView(`
      <div class="detail-hero">
        <div>
          <p class="eyebrow">CUSTOMER</p>
          <h1>${esc(customer.name)}</h1>
          <div class="detail-meta">
            ${envBadge(customer.environment)}
            <span>${icon('key')}${esc(customer.key_hint)}</span>
            <span>${icon('external')}${esc(customer.base_url)}</span>
            <span>${icon('clock')}最終同期 ${esc(customer.last_sync ? formatDateTime(customer.last_sync) : '未同期')}</span>
          </div>
          ${customer.note ? `<p class="muted">${esc(customer.note)}</p>` : ''}
        </div>
        <div class="detail-actions">
          <a class="button quiet" href="#/customers">${icon('arrowLeft')}一覧</a>
          <button class="button" data-action="edit-customer" data-id="${customer.id}">編集</button>
          <button class="button primary" data-action="sync-customer" data-id="${customer.id}">今すぐ同期</button>
        </div>
      </div>
      ${scopeErrors ? `<section class="card detail-section"><div class="section-head"><div><p class="eyebrow">SYNC NOTES</p><h2>取得できなかった項目</h2></div></div>${scopeErrors}</section>` : ''}
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('key')}ライセンス</span><strong>${numberFormat.format(customer.licenses)}<small>件</small></strong><p class="metric-note">稼働中 ${numberFormat.format(customer.active_licenses)} 件 / サンドボックス ${numberFormat.format(customer.sandbox_licenses)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}今月のAPI利用料</span><strong>${yen(customer.month_charge)}</strong><p class="metric-note">${numberFormat.format(usage.total_requests || 0)} リクエスト</p></article>
        <article class="metric"><span class="metric-label">${icon('invoice')}未払い請求</span><strong>${numberFormat.format(customer.unpaid_count)}<small>件</small></strong><p class="metric-note">${yen(customer.unpaid_amount)}</p></article>
        <article class="metric"><span class="metric-label">${icon('briefcase')}製品</span><strong>${numberFormat.format(products.length)}<small>件</small></strong><p class="metric-note">${esc((data.scopes?.status?.payload?.tenant || {}).slug || customer.slug || '')}</p></article>
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">LICENSES</p><h2>ライセンス <span class="result-count">${licenses.length}件</span></h2></div></div>
        ${licenses.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>ID</th><th>製品</th><th>ラベル</th><th>状態</th><th>環境</th><th>端末上限</th><th>有効期限</th><th>発行日</th></tr></thead><tbody>${licenseRows}</tbody></table></div>`
          : '<p class="panel-note">ライセンスがありません。同期を実行してください。</p>'}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">API USAGE</p><h2>API利用料 ${usage.period ? `（${esc(usage.period)}）` : ''}</h2></div><span class="muted">${usage.total_requests !== undefined ? `課金対象 ${numberFormat.format(usage.billable_requests || 0)} / 全体 ${numberFormat.format(usage.total_requests || 0)}` : ''}</span></div>
        ${usageRows.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>API</th><th>リクエスト数</th><th>単価</th><th>課金</th></tr></thead><tbody>${usageRows.map(row => `<tr><td>${esc(row.api || '')}</td><td>${numberFormat.format(row.requests || 0)}</td><td>${esc(row.unit_credit || '')}</td><td>${esc(row.charge_credit || '')}</td></tr>`).join('')}</tbody></table></div>`
          : '<p class="panel-note">この期間の課金対象API呼び出しはありません。</p>'}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">INVOICES</p><h2>請求書</h2></div></div>
        ${invoiceRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>請求番号</th><th>対象月</th><th>金額</th><th>状態</th><th>支払期限</th></tr></thead><tbody>${invoiceRows}</tbody></table></div>` : '<p class="panel-note">請求書はまだありません。</p>'}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">AUDIT</p><h2>最近のAPIイベント</h2></div></div>
        ${eventRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>日時</th><th>操作</th><th>HTTP</th><th>リクエストID</th></tr></thead><tbody>${eventRows}</tbody></table></div>` : '<p class="panel-note">APIイベントはまだありません。</p>'}
      </section>`);
  }

  // ---------------------------------------------------------------- licenses
  async function renderLicenses(params, token) {
    const query = new URLSearchParams();
    ['q', 'environment', 'status', 'customer_id'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/licenses?${query.toString()}`);
    if (token !== state.routeToken) return;
    const customers = state.customers.length ? state.customers : (await api('/api/customers')).items;
    const items = data.items;
    const rows = items.map(row => `
      <tr>
        <td><a class="inline-link" href="#/customers/${row.customer_id}">${esc(row.customer_name)}</a></td>
        <td>#${esc(row.id)}</td>
        <td>${esc(row.product_code || row.product_id || '')}</td>
        <td>${esc(row.label || '（ラベルなし）')}</td>
        <td>${row.active ? '<span class="badge rank-S">稼働中</span>' : '<span class="badge rank-C">停止</span>'}</td>
        <td>${esc(row.environment || '')}</td>
        <td>${esc(row.max_devices ?? '')}</td>
        <td>${row.expires_at ? esc(formatDate(row.expires_at)) : '無期限'}</td>
      </tr>`).join('');
    setView(`
      ${pageHead('LICENSES', 'ライセンス', '全顧客のライセンスを横断して検索します。', '<a class="button quiet" href="/api/export/licenses.csv">CSV出力</a>')}
      <section class="card detail-section">
        <form class="toolbar" data-filter="licenses"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="顧客・ラベル・製品コード・ID" aria-label="ライセンスを検索"></label>
          <select class="select" name="environment" aria-label="環境">
            <option value="">すべての環境</option>
            <option value="production" ${params.get('environment') === 'production' ? 'selected' : ''}>本番</option>
            <option value="sandbox" ${params.get('environment') === 'sandbox' ? 'selected' : ''}>サンドボックス</option>
          </select>
          <select class="select" name="status" aria-label="状態">
            <option value="">すべての状態</option>
            <option value="active" ${params.get('status') === 'active' ? 'selected' : ''}>稼働中</option>
            <option value="paused" ${params.get('status') === 'paused' ? 'selected' : ''}>停止</option>
          </select>
          <select class="select" name="customer_id" aria-label="顧客">
            <option value="">すべての顧客</option>
            ${customers.map(customer => `<option value="${customer.id}" ${String(params.get('customer_id')) === String(customer.id) ? 'selected' : ''}>${esc(customer.name)}</option>`).join('')}
          </select>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/licenses">解除</a>
        </div></form>
        ${items.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>ID</th><th>製品</th><th>ラベル</th><th>状態</th><th>環境</th><th>端末上限</th><th>有効期限</th></tr></thead><tbody>${rows}</tbody></table></div>`
          : emptyState('ライセンスがありません', '顧客を追加して同期すると、この一覧に表示されます。')}
      </section>`);
  }

  // ---------------------------------------------------------------- billing
  async function renderBilling(params, token) {
    const query = new URLSearchParams();
    ['period', 'status', 'customer_id'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const [invoiceData, customersData] = await Promise.all([
      api(`/api/invoices?${query.toString()}`),
      state.customers.length ? Promise.resolve({ items: state.customers }) : api('/api/customers')
    ]);
    if (token !== state.routeToken) return;
    const customers = customersData.items;
    const invoices = invoiceData.items;
    const usageRows = customers.filter(customer => customer.last_sync).map(customer => `
      <tr>
        <td><a class="inline-link" href="#/customers/${customer.id}">${esc(customer.name)}</a></td>
        <td>${esc(customer.usage_period || '—')}</td>
        <td>${yen(customer.month_charge)}</td>
        <td>${numberFormat.format(customer.unpaid_count)}件 / ${yen(customer.unpaid_amount)}</td>
        <td>${esc(ago(customer.last_sync))}</td>
      </tr>`).join('');
    const invoiceRows = invoices.map(row => `
      <tr>
        <td><a class="inline-link" href="#/customers/${row.customer_id}">${esc(row.customer_name)}</a></td>
        <td>${esc(row.invoice_number || '')}</td>
        <td>${esc(row.billing_period || '')}</td>
        <td>${esc(yen(row.total_yen ?? 0))}</td>
        <td>${esc(row.status || '')}</td>
        <td>${row.issue_date ? esc(formatDate(row.issue_date)) : ''}</td>
        <td>${row.due_date ? esc(formatDate(row.due_date)) : ''}</td>
      </tr>`).join('');
    const unpaid = invoices.filter(row => String(row.status) === 'issued');
    setView(`
      ${pageHead('BILLING', '請求', '全顧客の請求書とAPI利用料をまとめて確認します。', '<a class="button quiet" href="/api/export/invoices.csv">CSV出力</a>')}
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('invoice')}請求書</span><strong>${numberFormat.format(invoices.length)}<small>件</small></strong><p class="metric-note">未払い ${numberFormat.format(unpaid.length)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}未払い金額</span><strong>${yen(unpaid.reduce((sum, row) => sum + Number(row.total_yen || 0), 0))}</strong><p class="metric-note">status = issued</p></article>
        <article class="metric"><span class="metric-label">${icon('building')}対象顧客</span><strong>${numberFormat.format(new Set(invoices.map(row => row.customer_id)).size)}<small>社</small></strong><p class="metric-note">請求書のある顧客</p></article>
        <article class="metric"><span class="metric-label">${icon('clock')}今月の利用料</span><strong>${yen(customers.reduce((sum, customer) => sum + Number(customer.month_charge || 0), 0))}</strong><p class="metric-note">API利用料の合計</p></article>
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">INVOICES</p><h2>請求書 <span class="result-count">${invoices.length}件</span></h2></div></div>
        <form class="toolbar" data-filter="billing"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="period" value="${esc(params.get('period') || '')}" placeholder="対象月（例 2026-11）" aria-label="対象月"></label>
          <select class="select" name="status" aria-label="状態">
            <option value="">すべての状態</option>
            <option value="issued" ${params.get('status') === 'issued' ? 'selected' : ''}>発行済み</option>
            <option value="paid" ${params.get('status') === 'paid' ? 'selected' : ''}>支払済み</option>
          </select>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/billing">解除</a>
        </div></form>
        ${invoiceRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>請求番号</th><th>対象月</th><th>金額</th><th>状態</th><th>発行日</th><th>支払期限</th></tr></thead><tbody>${invoiceRows}</tbody></table></div>`
          : emptyState('請求書がありません', '顧客を追加して同期すると、請求書がここに表示されます。')}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">API USAGE</p><h2>顧客別の今月の利用料</h2></div></div>
        ${usageRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>対象月</th><th>利用料</th><th>未払い</th><th>同期</th></tr></thead><tbody>${usageRows}</tbody></table></div>`
          : '<p class="panel-note">同期済みの顧客がまだありません。</p>'}
      </section>`);
  }

  // ---------------------------------------------------------------- forms
  function openModal({ title, subtitle = '', body, submitLabel = '保存', wide = false, onSubmit }) {
    closeModal();
    const root = $('modal-root');
    root.innerHTML = `
      <div class="modal-backdrop" data-modal-backdrop>
        <section class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <form id="modal-form">
            <div class="modal-head"><div><h2 id="modal-title">${esc(title)}</h2>${subtitle ? `<p>${esc(subtitle)}</p>` : ''}</div><button class="icon-button" type="button" data-modal-close aria-label="閉じる">${icon('x')}</button></div>
            <div class="modal-body">${body}<p class="form-error" hidden></p></div>
            <div class="modal-foot"><button class="button" type="button" data-modal-close>キャンセル</button><button class="button primary" type="submit">${esc(submitLabel)}</button></div>
          </form>
        </section>
      </div>`;
    const form = $('modal-form');
    root.querySelectorAll('[data-modal-close]').forEach(button => button.addEventListener('click', () => closeModal()));
    root.querySelector('[data-modal-backdrop]').addEventListener('mousedown', event => {
      if (event.target === event.currentTarget) closeModal();
    });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const errorNode = form.querySelector('.form-error');
      const original = submit.textContent;
      submit.disabled = true;
      submit.textContent = '保存中…';
      errorNode.hidden = true;
      try {
        await onSubmit(form);
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
        submit.disabled = false;
        submit.textContent = original;
      }
    });
    const first = form.querySelector('input:not([type=hidden]), select, textarea');
    if (first) setTimeout(() => first.focus(), 30);
  }

  function closeModal() {
    const root = $('modal-root');
    if (root) root.replaceChildren();
  }

  function field(label, name, value = '', options = {}) {
    const attrs = [
      `type="${esc(options.type || 'text')}"`, `name="${esc(name)}"`, `value="${esc(value ?? '')}"`,
      options.placeholder ? `placeholder="${esc(options.placeholder)}"` : '',
      options.required ? 'required' : '',
      options.maxlength ? `maxlength="${esc(options.maxlength)}"` : '',
      options.autocomplete ? `autocomplete="${esc(options.autocomplete)}"` : 'autocomplete="off"'
    ].filter(Boolean).join(' ');
    return `<label class="field${options.full ? ' full' : ''}"><span>${esc(label)}${options.required ? '<em>必須</em>' : ''}</span><input ${attrs}></label>`;
  }

  function textArea(label, name, value = '', options = {}) {
    return `<label class="field${options.full ? ' full' : ''}"><span>${esc(label)}</span><textarea name="${esc(name)}" placeholder="${esc(options.placeholder || '')}" maxlength="${esc(options.maxlength || 2000)}">${esc(value || '')}</textarea></label>`;
  }

  function selectField(label, name, options, value = '') {
    return `<label class="field"><span>${esc(label)}</span><select name="${esc(name)}">${options.map(option => {
      const optionValue = typeof option === 'string' ? option : option.value;
      const optionLabel = typeof option === 'string' ? option : option.label;
      return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value ?? '') ? 'selected' : ''}>${esc(optionLabel)}</option>`;
    }).join('')}</select></label>`;
  }

  function openCustomerForm(customer = null) {
    const editing = Boolean(customer);
    const body = `<div class="form-grid">
      ${field('顧客名', 'name', customer?.name || '', { required: true, maxlength: 120, placeholder: '株式会社サンプル' })}
      ${field('slug', 'slug', customer?.slug || '', { maxlength: 80, placeholder: 'sample-inc' })}
      ${selectField('環境', 'environment', ENVIRONMENTS, customer?.environment ?? '')}
      ${field('ベースURL', 'base_url', customer?.base_url || 'https://2415.jp', { maxlength: 300, placeholder: 'https://2415.jp' })}
      ${field(editing ? 'テナントAPIキー（変更する場合のみ）' : 'テナントAPIキー', 'api_key', '', { type: 'password', autocomplete: 'new-password', maxlength: 140, placeholder: 'baas_live_…' })}
      ${textArea('メモ', 'note', customer?.note || '', { full: true, placeholder: '契約内容、担当者、連絡先など' })}
      <label class="check-field"><input type="checkbox" name="active" ${customer?.active === false ? '' : 'checked'}> 有効にする</label>
    </div>`;
    openModal({
      title: editing ? '顧客を編集' : '顧客を追加',
      subtitle: 'TUTIテナントのAPIキーを登録します。キーは暗号化して保存され、画面には再表示しません。',
      body, wide: true, submitLabel: editing ? '更新する' : '追加する',
      onSubmit: async form => {
        const values = new FormData(form);
        const payload = {
          name: String(values.get('name') || '').trim(),
          slug: String(values.get('slug') || '').trim(),
          environment: String(values.get('environment') || ''),
          base_url: String(values.get('base_url') || '').trim(),
          api_key: String(values.get('api_key') || '').trim(),
          note: String(values.get('note') || '').trim(),
          active: form.elements.active.checked
        };
        if (!payload.name) throw new Error('顧客名を入力してください');
        if (!editing && !payload.api_key) throw new Error('テナントAPIキーを入力してください');
        const result = editing
          ? await api(`/api/customers/${customer.id}`, { method: 'PUT', body: JSON.stringify(payload) })
          : await api('/api/customers', { method: 'POST', body: JSON.stringify(payload) });
        closeModal();
        state.customers = [];
        toast(editing ? '顧客を更新しました' : '顧客を追加しました。同期を実行します');
        if (editing) {
          await route();
        } else {
          navigate(`/customers/${result.id}`);
          try {
            await api(`/api/customers/${result.id}/sync`, { method: 'POST' });
            toast('同期しました');
            await route();
          } catch (error) {
            toast(`同期に失敗しました: ${error.message}`, true);
          }
        }
      }
    });
  }

  function openDeleteCustomer(customer) {
    openModal({
      title: '顧客を削除',
      subtitle: '保存済みのキャッシュも削除されます。TUTI側のライセンスや契約は変更されません。',
      body: `<p><strong>${esc(customer.name)}</strong> を削除しますか？</p>`,
      submitLabel: '削除する',
      onSubmit: async () => {
        await api(`/api/customers/${customer.id}`, { method: 'DELETE' });
        closeModal();
        state.customers = [];
        toast('顧客を削除しました');
        if (state.route.startsWith(`/customers/${customer.id}`)) navigate('/customers'); else await route();
      }
    });
  }

  // ---------------------------------------------------------------- events
  async function onViewClick(event) {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const id = Number(button.dataset.id || 0);
    try {
      if (action === 'reload') return route();
      if (action === 'new-customer') return openCustomerForm();
      if (action === 'edit-customer') {
        const customer = state.customers.find(item => item.id === id) || (await api(`/api/customers/${id}`)).customer;
        return openCustomerForm(customer);
      }
      if (action === 'delete-customer') {
        const customer = state.customers.find(item => item.id === id) || (await api(`/api/customers/${id}`)).customer;
        return openDeleteCustomer(customer);
      }
      if (action === 'sync-customer') {
        button.disabled = true;
        const result = await api(`/api/customers/${id}/sync`, { method: 'POST' });
        toast(result.ok ? '同期しました' : '一部の項目を取得できませんでした', !result.ok);
        state.customers = [];
        return route();
      }
      if (action === 'sync-all') {
        button.disabled = true;
        button.textContent = '同期中…';
        const result = await api('/api/sync-all', { method: 'POST' });
        toast(result.ok ? `${result.synced}社を同期しました` : `${result.synced}/${result.total}社を同期（一部エラー）`, !result.ok);
        state.customers = [];
        return route();
      }
    } catch (error) {
      toast(error.message, true);
    }
  }

  function onViewSubmit(event) {
    const form = event.target.closest('form[data-filter]');
    if (!form) return;
    event.preventDefault();
    const data = new FormData(form);
    const params = new URLSearchParams();
    for (const [key, value] of data.entries()) {
      if (String(value).trim()) params.set(key, String(value).trim());
    }
    navigate(`/${form.dataset.filter}?${params.toString()}`);
  }

  init();
})();
