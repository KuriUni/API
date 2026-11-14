(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const state = {
    me: null, csrf: '', route: '/dashboard', routeToken: 0,
    connection: null, tenantOptions: [], customers: []
  };
  const STATE_LABELS = { active: '有効', paused: '停止', expired: '期限切れ', expiring: '期限間近', revoked: '失効' };
  const STATE_CLASS = { active: 'rank-S', paused: 'rank-C', expired: 'rank-C', expiring: 'rank-B', revoked: 'rank-C' };
  const INVOICE_LABELS = { draft: '下書き', issued: '発行済み', paid: '入金済み', void: '無効' };
  const INVOICE_CLASS = { draft: 'rank-C', issued: 'rank-B', paid: 'rank-S', void: 'rank-C' };

  const ICONS = {
    dashboard: 'M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z',
    building: 'M4 21V4a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v4h4a1 1 0 0 1 1 1v12h-6v-4H9v4H4Zm3-4h2v-2H7v2Zm0-4h2v-2H7v2Zm0-4h2V7H7v2Zm5 4h2v-2h-2v2Zm0-4h2V7h-2v2Zm6 8h-1v-2h1v2Zm0-4h-1v-2h1v2Z',
    key: 'M14 2a6 6 0 0 0-5.66 8H3v4h2v2h2v2h4v-4h1.34A6 6 0 1 0 14 2Zm2.5 4.5a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3Z',
    chart: 'M4 19h16v2H4v-2Zm2-2h3V9H6v8Zm5 0h3V5h-3v12Zm5 0h3v-5h-3v5Z',
    invoice: 'M6 2h12a1 1 0 0 1 1 1v19l-3-2-2 2-2-2-2 2-2-2-3 2V3a1 1 0 0 1 1-1Zm1 4v2h10V6H7Zm0 4v2h10v-2H7Zm0 4v2h6v-2H7Z',
    clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm1-13h-2v6l5 3 1-1.7-4-2.3V7Z',
    search: 'M10 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm0-14a6 6 0 1 0 0 12 6 6 0 0 0 0-12Zm6.32 12.9 1.42-1.42 4.24 4.24-1.42 1.42-4.24-4.24Z',
    sync: 'M12 4V1L8 5l4 4V6a6 6 0 0 1 5.2 9l1.5 1.5A8 8 0 0 0 12 4Zm0 14a6 6 0 0 1-5.2-9L5.3 7.5A8 8 0 0 0 12 20v3l4-4-4-4v3Z',
    lock: 'M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm0 2a3 3 0 0 1 3 3v3H9V7a3 3 0 0 1 3-3Zm0 9a2 2 0 0 1 1 3.73V19h-2v-2.27A2 2 0 0 1 12 13Z',
    arrowLeft: 'M11.67 3.87 3.54 12l8.13 8.13 1.42-1.42L7.36 13H21v-2H7.36l5.73-5.71-1.42-1.42Z',
    x: 'M6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4 17.6 5 12 10.6 6.4 5Z',
    external: 'M14 3h7v7h-2V6.4l-8.3 8.3-1.4-1.4L17.6 5H14V3ZM5 5h5v2H7v10h10v-3h2v5H5V5Z',
    alert: 'M12 2 1 21h22L12 2Zm0 5 7.5 12h-15L12 7Zm-1 5v4h2v-4h-2Zm0 5v2h2v-2h-2Z'
  };

  function icon(name) {
    return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[name] || ICONS.dashboard}"/></svg>`;
  }
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[ch]));
  }
  const numberFormat = new Intl.NumberFormat('ja-JP');
  function yen(value) { return `¥${numberFormat.format(Math.round(Number(value || 0)))}`; }
  function formatDate(value) {
    const text = String(value || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return value ? String(value).slice(0, 10) : '—';
    return text.replaceAll('-', '/');
  }
  function formatDateTime(value) { return value ? String(value).replace('T', ' ').slice(0, 16) : '—'; }
  function ago(value) {
    if (!value) return '未同期';
    const then = new Date(String(value).replace(' ', 'T'));
    if (Number.isNaN(then.getTime())) return String(value);
    const minutes = Math.round((Date.now() - then.getTime()) / 60000);
    if (minutes < 1) return 'たった今';
    if (minutes < 60) return `${minutes}分前`;
    if (minutes < 1440) return `${Math.round(minutes / 60)}時間前`;
    return `${Math.round(minutes / 1440)}日前`;
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
      const message = Array.isArray(detail) ? detail.map(item => item.msg || String(item)).join(' / ')
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
    toast.timer = setTimeout(() => node.classList.remove('show'), 4000);
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
  function stateBadge(value) {
    return `<span class="badge ${STATE_CLASS[value] || 'rank-C'}">${esc(STATE_LABELS[value] || value || '—')}</span>`;
  }
  function invoiceBadge(value) {
    return `<span class="badge ${INVOICE_CLASS[value] || 'rank-C'}">${esc(INVOICE_LABELS[value] || value || '—')}</span>`;
  }
  function tenantStatusBadge(value) {
    const klass = value === 'active' ? 'rank-S' : 'rank-C';
    const label = value === 'active' ? '有効' : value === 'suspended' ? '停止' : value || '—';
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
    if (location.hash === `#${path}`) route(); else location.hash = `#${path}`;
  }
  function closeSidebar() { $('sidebar').classList.remove('open'); $('sidebar-overlay').hidden = true; }
  function openSidebar() { $('sidebar').classList.add('open'); $('sidebar-overlay').hidden = false; }

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
    $('quick-create').addEventListener('click', syncAll);
    $('logout-button').addEventListener('click', async () => {
      try { await api('/api/logout', { method: 'POST' }); } finally { location.replace('/login'); }
    });
    window.addEventListener('hashchange', route);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') closeSidebar();
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
      state.connection = await api('/api/connection');
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
    state.routeToken += 1;
    const token = state.routeToken;
    setView(loadingView());
    try {
      if (path === '/dashboard' || path === '/') await renderDashboard(token);
      else if (path === '/tenants') await renderTenants(params, token);
      else if (/^\/tenants\/\d+$/.test(path)) await renderTenantDetail(Number(path.split('/')[2]), token);
      else if (path === '/licenses') await renderLicenses(params, token);
      else if (path === '/billing') await renderBilling(params, token);
      else if (path === '/connection') await renderConnection(token);
      else setView(emptyState('ページが見つかりません', 'サイドバーから画面を選び直してください。'));
    } catch (error) {
      if (token === state.routeToken && !String(error.message).includes('ログイン')) {
        setView(errorView(error.message));
        toast(error.message, true);
      }
    }
  }

  function connectedBanner() {
    if (state.connection?.connected) return '';
    return `<section class="card notice-card">
      <div class="notice-icon">${icon('lock')}</div>
      <div><h3>TUTIに接続していません</h3>
      <p class="muted">管理者SSOでログインすると、全テナントの契約・ライセンス・請求を管理APIから読み取ります。テナントAPIキーの登録は不要です。</p></div>
      <a class="button primary" href="#/connection">接続する</a>
    </section>`;
  }

  // ------------------------------------------------------------- dashboard
  async function renderDashboard(token) {
    state.connection = await api('/api/connection');
    const data = state.connection.connected ? await api('/api/dashboard') : null;
    if (token !== state.routeToken) return;
    if (!data) {
      setView(`${pageHead('ADMIN', 'ダッシュボード', '管理者としてTUTIの全テナントを横断して確認します。', '')}
        ${connectedBanner()}`);
      return;
    }
    const k = data.kpis;
    const tenantRows = data.tenants.length ? data.tenants.map(row => `
      <tr>
        <td><a class="inline-link" href="#/tenants/${row.tenant_id}">${esc(row.name)}</a><div class="table-sub">${esc(row.slug)}</div></td>
        <td>${numberFormat.format(row.active_licenses)} / ${numberFormat.format(row.licenses)}</td>
        <td>${row.expiring_licenses ? `<span class="badge rank-B">${row.expiring_licenses}件</span>` : '—'}</td>
        <td>${row.unpaid_count ? `${row.unpaid_count}件 / ${yen(row.unpaid_amount)}` : '—'}</td>
      </tr>`).join('') : '';
    const invoiceRows = data.recent_invoices.length ? data.recent_invoices.map(row => `
      <tr>
        <td>${esc(row.invoice_number)}</td>
        <td>${esc(row.customer_name || '')}</td>
        <td>${esc(row.billing_period)}</td>
        <td>${esc(yen(row.total_yen))}</td>
        <td>${invoiceBadge(row.status)}</td>
      </tr>`).join('') : '';
    setView(`
      ${pageHead('ADMIN CONSOLE', 'ダッシュボード', '管理者としてTUTIの全テナントを横断して確認します。',
        `<button class="button" data-action="sync">今すぐ同期</button><a class="button quiet" href="#/connection">接続</a>`)}
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('building')}契約先</span><strong>${numberFormat.format(k.active_tenants)}<small>件</small></strong><p class="metric-note">全 ${numberFormat.format(k.tenants)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('key')}ライセンス</span><strong>${numberFormat.format(k.active_licenses)}<small>件</small></strong><p class="metric-note">全 ${numberFormat.format(k.licenses)} 件 / 30日以内に期限 ${numberFormat.format(k.expiring_licenses)} 件</p></article>
        <article class="metric ${k.expired_licenses ? 'alert' : ''}"><span class="metric-label">${icon('clock')}期限切れ</span><strong>${numberFormat.format(k.expired_licenses)}<small>件</small></strong><p class="metric-note">要フォロー</p></article>
        <article class="metric ${k.unpaid_count ? 'alert' : ''}"><span class="metric-label">${icon('invoice')}未払い請求</span><strong>${numberFormat.format(k.unpaid_count)}<small>件</small></strong><p class="metric-note">${yen(k.unpaid_amount)}</p></article>
      </section>
      <div class="dash-grid">
        <div class="dash-stack">
          <section class="card list-card">
            <div class="section-head"><div><p class="eyebrow">TENANTS</p><h2>契約先</h2></div><a class="inline-link" href="#/tenants">一覧へ →</a></div>
            ${tenantRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>契約先</th><th>ライセンス</th><th>期限間近</th><th>未払い</th></tr></thead><tbody>${tenantRows}</tbody></table></div>`
              : '<p class="panel-note">契約先がありません。同期を実行してください。</p>'}
          </section>
          <section class="card list-card">
            <div class="section-head"><div><p class="eyebrow">INVOICES</p><h2>最近の請求書</h2></div><a class="inline-link" href="#/billing">請求へ →</a></div>
            ${invoiceRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>請求番号</th><th>契約先</th><th>対象月</th><th>金額</th><th>状態</th></tr></thead><tbody>${invoiceRows}</tbody></table></div>`
              : '<p class="panel-note">請求書がありません。</p>'}
          </section>
        </div>
        <div class="dash-stack">
          <section class="card list-card">
            <div class="section-head"><div><p class="eyebrow">DATA SOURCE</p><h2>接続状態</h2></div></div>
            <div class="tuti-meta">
              <div><span class="muted">ベースURL</span><strong>${esc(state.connection.base_url)}</strong></div>
              <div><span class="muted">接続方法</span><strong>${state.connection.source === 'environment' ? '環境変数' : 'SSO'}</strong></div>
              <div><span class="muted">最終同期</span><strong>${esc(data.last_sync ? formatDateTime(data.last_sync) : '未同期')}</strong></div>
              <div><span class="muted">契約先</span><strong>${numberFormat.format(k.tenants)} 件</strong></div>
            </div>
            ${Object.entries(data.sync || {}).filter(([, value]) => value.error).map(([scope, value]) =>
              `<p class="panel-note">${esc(scope)}: ${esc(value.error)}</p>`).join('')}
          </section>
        </div>
      </div>`);
  }

  // --------------------------------------------------------------- tenants
  async function renderTenants(params, token) {
    const data = await api(`/api/tenants?q=${encodeURIComponent(params.get('q') || '')}`);
    if (token !== state.routeToken) return;
    state.tenantOptions = data.items;
    const rows = data.items.map(row => `
      <tr>
        <td><a class="inline-link" href="#/tenants/${row.tenant_id}">${esc(row.name)}</a><div class="table-sub">${esc(row.slug)} · #${row.tenant_id}</div></td>
        <td>${tenantStatusBadge(row.status)}</td>
        <td>${esc(row.environment || '—')}</td>
        <td>${numberFormat.format(row.active_licenses)} / ${numberFormat.format(row.licenses)}</td>
        <td>${row.expiring_licenses ? `<span class="badge rank-B">${row.expiring_licenses}件</span>` : '—'}</td>
        <td>${row.unpaid_count ? `${row.unpaid_count}件 / ${yen(row.unpaid_amount)}` : '—'}</td>
      </tr>`).join('');
    const connected = state.connection?.connected;
    setView(`
      ${pageHead('TENANTS', '契約先', 'TUTIに登録されているテナントを、管理APIからそのまま表示します。',
        connected ? '<button class="button" data-action="sync">同期</button>' : '<a class="button primary" href="#/connection">接続する</a>')}
      ${connectedBanner()}
      ${data.items.length ? `
      <section class="card detail-section">
        <form class="toolbar" data-filter="tenants"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="契約先名・slugで検索" aria-label="契約先を検索"></label>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/tenants">解除</a>
        </div></form>
        <div class="table-wrap"><table class="data"><thead><tr><th>契約先</th><th>状態</th><th>環境</th><th>ライセンス</th><th>期限間近</th><th>未払い</th></tr></thead><tbody>${rows}</tbody></table></div>
      </section>` : (connected
        ? emptyState('契約先がありません', '同期を実行すると、管理APIからテナント一覧を取得します。', '<button class="button primary" data-action="sync">同期する</button>')
        : emptyState('TUTIに接続していません', '管理者SSOでログインすると、契約先一覧を取得します。', '<a class="button primary" href="#/connection">接続する</a>'))}`);
  }

  async function renderTenantDetail(tenantId, token) {
    const data = await api(`/api/tenants/${tenantId}`);
    if (token !== state.routeToken) return;
    const tenant = data.tenant;
    const summary = data.summary;
    const licenseRows = data.licenses.map(row => `
      <tr>
        <td>#${row.license_id}</td>
        <td>${esc(row.label || '（ラベルなし）')}</td>
        <td>${stateBadge(row.state)}</td>
        <td>${esc(row.max_devices)}</td>
        <td>${esc(row.active_sessions)}</td>
        <td>${row.expires_at ? esc(formatDate(row.expires_at)) : '無期限'}</td>
        <td>${row.created_at ? esc(formatDate(row.created_at)) : ''}</td>
      </tr>`).join('');
    const invoiceRows = data.invoices.map(row => `
      <tr>
        <td>${esc(row.invoice_number)}</td>
        <td>${esc(row.billing_period)}</td>
        <td>${esc(yen(row.total_yen))}</td>
        <td>${invoiceBadge(row.status)}</td>
        <td>${row.due_date ? esc(formatDate(row.due_date)) : ''}</td>
      </tr>`).join('');
    setView(`
      <div class="detail-hero">
        <div>
          <p class="eyebrow">TENANT #${esc(tenant.tenant_id)}</p>
          <h1>${esc(tenant.name)}</h1>
          <div class="detail-meta">
            ${tenantStatusBadge(tenant.status)}
            <span>${esc(tenant.slug)}</span>
            <span>${icon('external')}${esc(tenant.environment || '—')}</span>
            <span>${icon('clock')}取得 ${esc(ago(tenant.fetched_at))}</span>
          </div>
        </div>
        <div class="detail-actions">
          <a class="button quiet" href="#/tenants">${icon('arrowLeft')}一覧</a>
          <a class="button quiet" href="#/licenses?tenant_id=${tenant.tenant_id}">ライセンス</a>
          <a class="button quiet" href="#/billing?tenant_id=${tenant.tenant_id}">請求</a>
        </div>
      </div>
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('key')}ライセンス</span><strong>${numberFormat.format(summary.licenses)}<small>件</small></strong><p class="metric-note">有効 ${numberFormat.format(summary.active_licenses)} 件</p></article>
        <article class="metric ${summary.expiring_licenses ? 'alert' : ''}"><span class="metric-label">${icon('clock')}期限間近</span><strong>${numberFormat.format(summary.expiring_licenses)}<small>件</small></strong><p class="metric-note">30日以内</p></article>
        <article class="metric ${summary.unpaid_count ? 'alert' : ''}"><span class="metric-label">${icon('invoice')}未払い</span><strong>${numberFormat.format(summary.unpaid_count)}<small>件</small></strong><p class="metric-note">${yen(summary.unpaid_amount)}</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}入金済み</span><strong>${yen(summary.paid_amount)}</strong><p class="metric-note">累計</p></article>
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">LICENSES</p><h2>ライセンス <span class="result-count">${data.licenses.length}件</span></h2></div></div>
        ${licenseRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>ID</th><th>ラベル</th><th>状態</th><th>端末上限</th><th>接続中</th><th>有効期限</th><th>発行日</th></tr></thead><tbody>${licenseRows}</tbody></table></div>`
          : '<p class="panel-note">ライセンスがありません。</p>'}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">INVOICES</p><h2>請求書 <span class="result-count">${data.invoices.length}件</span></h2></div></div>
        ${invoiceRows ? `<div class="table-wrap"><table class="data"><thead><tr><th>請求番号</th><th>対象月</th><th>金額</th><th>状態</th><th>支払期限</th></tr></thead><tbody>${invoiceRows}</tbody></table></div>`
          : '<p class="panel-note">請求書がありません。</p>'}
      </section>`);
  }

  // -------------------------------------------------------------- licenses
  async function renderLicenses(params, token) {
    const query = new URLSearchParams();
    ['q', 'state', 'tenant_id', 'page'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/licenses?${query.toString()}`);
    if (token !== state.routeToken) return;
    const tenants = state.tenantOptions.length ? state.tenantOptions : (await api('/api/tenants')).items;
    state.tenantOptions = tenants;
    const pages = Math.max(1, Math.ceil(data.total / data.limit));
    const rows = data.items.map(row => `
      <tr>
        <td><a class="inline-link" href="#/tenants/${row.tenant_id}">${esc(row.tenant_name || '（不明）')}</a></td>
        <td>#${esc(row.license_id)}</td>
        <td>${esc(row.label || '（ラベルなし）')}</td>
        <td>${stateBadge(row.state)}</td>
        <td>${esc(row.max_devices)}</td>
        <td>${esc(row.active_sessions)}</td>
        <td>${row.expires_at ? esc(formatDate(row.expires_at)) : '無期限'}</td>
      </tr>`).join('');
    setView(`
      ${pageHead('LICENSES', 'ライセンス', '全テナントのライセンスを管理APIから横断検索します。',
        '<a class="button quiet" href="/api/export/licenses.csv">CSV出力</a>')}
      ${connectedBanner()}
      <section class="card detail-section">
        <form class="toolbar" data-filter="licenses"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="ID・ラベル・契約先" aria-label="ライセンスを検索"></label>
          <select class="select" name="state" aria-label="状態">
            <option value="">すべての状態</option>
            ${Object.entries(STATE_LABELS).map(([value, label]) =>
              `<option value="${value}" ${params.get('state') === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
          <select class="select" name="tenant_id" aria-label="契約先">
            <option value="">すべての契約先</option>
            ${tenants.map(row => `<option value="${row.tenant_id}" ${String(params.get('tenant_id')) === String(row.tenant_id) ? 'selected' : ''}>${esc(row.name)}</option>`).join('')}
          </select>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/licenses">解除</a>
        </div></form>
        ${rows ? `<div class="table-wrap"><table class="data"><thead><tr><th>契約先</th><th>ID</th><th>ラベル</th><th>状態</th><th>端末上限</th><th>接続中</th><th>有効期限</th></tr></thead><tbody>${rows}</tbody></table></div>
          ${pagination(data.page, pages, data.total)}`
          : emptyState('ライセンスがありません', state.connection?.connected ? '同期を実行するか、検索条件を変えてください。' : 'TUTIに接続してください。')}
      </section>`);
  }

  // --------------------------------------------------------------- billing
  async function renderBilling(params, token) {
    const query = new URLSearchParams();
    ['q', 'status', 'tenant_id', 'page'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/invoices?${query.toString()}`);
    if (token !== state.routeToken) return;
    const pages = Math.max(1, Math.ceil(data.total / data.limit));
    const rows = data.items.map(row => `
      <tr>
        <td><a class="inline-link" href="#/tenants/${row.tenant_id}">${esc(row.customer_name || row.tenant_slug || '')}</a></td>
        <td>${esc(row.invoice_number)}</td>
        <td>${esc(row.billing_period)}</td>
        <td>${esc(yen(row.total_yen))}</td>
        <td>${invoiceBadge(row.status)}</td>
        <td>${row.issue_date ? esc(formatDate(row.issue_date)) : ''}</td>
        <td>${row.due_date ? esc(formatDate(row.due_date)) : ''}</td>
      </tr>`).join('');
    const summary = data.summary || {};
    setView(`
      ${pageHead('BILLING', '請求', '全テナントのAPI利用料請求を管理APIから表示します。',
        '<a class="button quiet" href="/api/export/invoices.csv">CSV出力</a>')}
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('invoice')}発行済み</span><strong>${numberFormat.format(summary.issued || 0)}<small>件</small></strong><p class="metric-note">未入金</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}入金済み</span><strong>${yen(summary.paid_total || 0)}</strong><p class="metric-note">${numberFormat.format(summary.paid || 0)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('clock')}下書き</span><strong>${numberFormat.format(summary.draft || 0)}<small>件</small></strong><p class="metric-note">未発行</p></article>
        <article class="metric"><span class="metric-label">${icon('x')}無効</span><strong>${numberFormat.format(summary.void || 0)}<small>件</small></strong><p class="metric-note">取消済み</p></article>
      </section>
      <section class="card detail-section">
        <form class="toolbar" data-filter="billing"><div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="請求番号・契約先" aria-label="請求書を検索"></label>
          <select class="select" name="status" aria-label="状態">
            <option value="">すべての状態</option>
            ${Object.entries(INVOICE_LABELS).map(([value, label]) =>
              `<option value="${value}" ${params.get('status') === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
          <button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/billing">解除</a>
        </div></form>
        ${rows ? `<div class="table-wrap"><table class="data"><thead><tr><th>契約先</th><th>請求番号</th><th>対象月</th><th>金額</th><th>状態</th><th>発行日</th><th>支払期限</th></tr></thead><tbody>${rows}</tbody></table></div>
          ${pagination(data.page, pages, data.total)}`
          : emptyState('請求書がありません', state.connection?.connected ? '同期を実行するか、検索条件を変えてください。' : 'TUTIに接続してください。')}
      </section>`);
  }

  function pagination(page, pages, total) {
    return `<div class="pagination"><span class="pagination-info">${total}件 · ${page} / ${pages}ページ</span><div class="pagination-buttons"><button class="button" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>前へ</button><button class="button" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>次へ</button></div></div>`;
  }

  // ------------------------------------------------------------ connection
  async function renderConnection(token) {
    state.connection = await api('/api/connection');
    if (token !== state.routeToken) return;
    const c = state.connection;
    const syncRows = Object.entries(c.sync || {}).map(([scope, value]) => `
      <tr><td>${esc(scope)}</td><td>${value.total}</td><td>${esc(value.fetched_at ? formatDateTime(value.fetched_at) : '—')}</td>
      <td>${value.error ? `<span class="badge rank-C" title="${esc(value.error)}">エラー</span>` : '<span class="badge rank-S">OK</span>'}</td></tr>`).join('');
    setView(`
      ${pageHead('CONNECTION', '接続', '管理者SSOでログインし、管理APIから全テナントのデータを読み取ります。', '')}
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">ADMIN SESSION</p><h2>${c.connected ? 'TUTIに接続済み' : 'TUTIに未接続'}</h2></div>
          ${c.connected ? '<span class="badge rank-S">接続中</span>' : '<span class="badge rank-C">未接続</span>'}</div>
        <div class="tuti-meta">
          <div><span class="muted">ベースURL</span><strong>${esc(c.base_url)}</strong></div>
          <div><span class="muted">接続方法</span><strong>${c.source === 'environment' ? '環境変数 TUTI_ADMIN_SESSION' : '管理者SSO'}</strong></div>
          <div><span class="muted">接続日時</span><strong>${esc(c.connected_at ? formatDateTime(c.connected_at) : '—')}</strong></div>
          <div><span class="muted">最終同期</span><strong>${esc(c.last_sync ? formatDateTime(c.last_sync) : '未同期')}</strong></div>
        </div>
        <div class="connection-actions">
          ${c.connected ? '<button class="button primary" data-action="sync">今すぐ同期</button>' : ''}
          ${c.connected && c.source !== 'environment' ? '<button class="button" data-action="disconnect">接続を解除</button>' : ''}
          <button class="button ${c.connected ? 'quiet' : 'primary'}" data-action="connect" ${c.env_configured ? 'disabled' : ''}>SSOでログイン</button>
        </div>
        ${c.env_configured ? '<p class="panel-note">TUTI_ADMIN_SESSION が設定されているため、SSOログインは無効です。</p>' : ''}
        <div id="sso-state" role="status"></div>
        <p class="muted">SSOはブラウザで開きます。Passkey再認証が必要な場合があります。認証後、このタブに戻ってください（自動で接続されます）。</p>
        <p class="muted">読み取り専用です。ライセンスの発行・停止、請求の発行・入金は管理センターで操作してください。</p>
      </section>
      ${syncRows ? `<section class="card detail-section"><div class="section-head"><div><p class="eyebrow">SYNC</p><h2>同期したデータ</h2></div></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>対象</th><th>件数</th><th>取得日時</th><th>状態</th></tr></thead><tbody>${syncRows}</tbody></table></div>
        ${Object.entries(c.sync || {}).filter(([, value]) => value.error).map(([scope, value]) => `<p class="panel-note">${esc(scope)}: ${esc(value.error)}</p>`).join('')}
      </section>` : ''}`);
  }

  async function startSso() {
    const target = $('sso-state');
    target.textContent = 'ブラウザでSSOを開始しています…';
    const ssoWindow = window.open('about:blank', 'tuti-sso', 'width=520,height=720');
    if (ssoWindow) ssoWindow.document.write('<p style="font:15px system-ui;padding:24px">TUTIのSSOを準備しています…</p>');
    try {
      const flow = await api('/api/connection/start', { method: 'POST', body: JSON.stringify({ base_url: state.connection?.base_url || '' }) });
      if (ssoWindow) ssoWindow.location.replace(flow.url); else window.open(flow.url, 'tuti-sso');
      target.textContent = 'ブラウザで認証を完了してください。';
      const deadline = Date.now() + (flow.expires_in || 300) * 1000;
      while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        const status = await api(`/api/connection/poll?state=${encodeURIComponent(flow.state)}`);
        if (status.status === 'connected') {
          toast('TUTIに接続しました');
          state.connection = await api('/api/connection');
          await api('/api/sync', { method: 'POST' });
          navigate('/dashboard');
          route();
          return;
        }
        if (status.status === 'error' || status.status === 'expired' || status.status === 'unknown') {
          target.textContent = 'SSOを完了できませんでした。もう一度お試しください。';
          return;
        }
      }
      target.textContent = 'SSOがタイムアウトしました。もう一度お試しください。';
    } catch (error) {
      target.textContent = error.message;
    }
  }

  async function syncAll() {
    if (!state.connection?.connected) { navigate('/connection'); return; }
    try {
      toast('同期しています…');
      const result = await api('/api/sync', { method: 'POST' });
      toast(result.ok ? `同期しました（契約先 ${result.counts.tenants} / ライセンス ${result.counts.licenses} / 請求 ${result.counts.invoices}）`
        : '一部のデータを取得できませんでした', !result.ok);
      state.connection = await api('/api/connection');
      await route();
    } catch (error) {
      toast(error.message, true);
      if (String(error.message).includes('接続していません')) navigate('/connection');
    }
  }

  function onViewClick(event) {
    const pageButton = event.target.closest('[data-page]');
    if (pageButton) {
      const { path, params } = parseRoute();
      params.set('page', pageButton.dataset.page);
      navigate(`${path}?${params.toString()}`);
      return;
    }
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    if (action === 'reload') { route(); return; }
    if (action === 'sync') { button.disabled = true; syncAll(); return; }
    if (action === 'connect') { button.disabled = true; startSso(); return; }
    if (action === 'disconnect') {
      api('/api/connection/disconnect', { method: 'POST' }).then(() => {
        toast('接続を解除しました');
        state.connection = { connected: false };
        route();
      }).catch(error => toast(error.message, true));
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
