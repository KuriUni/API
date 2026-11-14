(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const STAGES = ['リード', '初回接触', '提案', '交渉', '受注', '失注'];
  const RANKS = ['S', 'A', 'B', 'C'];
  const KIND_LABELS = { call: '電話', email: 'メール', meeting: '商談', visit: '訪問', note: 'メモ' };
  const PRIORITY_LABELS = { high: '高', medium: '中', low: '低' };
  const TUTI_SCOPE_LABELS = { status: 'サービス状態', products: '製品', licenses: 'ライセンス', usage: 'API利用料', invoices: '請求書', audit: 'APIイベント' };
  const RANK_LABELS = { S: 'Sランク', A: 'Aランク', B: 'Bランク', C: 'Cランク' };
  const state = {
    me: null,
    csrf: '',
    route: '/dashboard',
    routeToken: 0,
    options: { owners: [], industries: [], ranks: [], stages: STAGES },
    lookups: null
  };

  const ICONS = {
    dashboard: 'M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z',
    building: 'M4 21V4a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v4h4a1 1 0 0 1 1 1v12h-6v-4H9v4H4Zm3-4h2v-2H7v2Zm0-4h2v-2H7v2Zm0-4h2V7H7v2Zm5 4h2v-2h-2v2Zm0-4h2V7h-2v2Zm6 8h-1v-2h1v2Zm0-4h-1v-2h1v2Z',
    user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0 2c-4.42 0-8 2.24-8 5v2h16v-2c0-2.76-3.58-5-8-5Z',
    chart: 'M4 19h16v2H4v-2Zm2-2h3V9H6v8Zm5 0h3V5h-3v12Zm5 0h3v-5h-3v5Z',
    activity: 'M4 4h16v2H4V4Zm0 5h10v2H4V9Zm0 5h16v2H4v-2Zm0 5h10v2H4v-2Z',
    check: 'M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17Z',
    search: 'M10 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm0-14a6 6 0 1 0 0 12 6 6 0 0 0 0-12Zm6.32 12.9 1.42-1.42 4.24 4.24-1.42 1.42-4.24-4.24Z',
    plus: 'M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6V5Z',
    edit: 'm4.5 16.5 10-10 3 3-10 10H4.5v-3ZM6 15l3 3M14.5 3.5l3 3 2-2-3-3-2 2Z',
    trash: 'M7 21a2 2 0 0 1-2-2V7h14v12a2 2 0 0 1-2 2H7ZM5 4h5V2h4v2h5v2H5V4Zm4 5v8h2V9H9Zm4 0v8h2V9h-2Z',
    phone: 'M6.6 10.8a15.1 15.1 0 0 0 6.6 6.6l2.2-2.2a1 1 0 0 1 1-.25 11.4 11.4 0 0 0 3.6.57 1 1 0 0 1 1 1V20a1 1 0 0 1-1 1A17 17 0 0 1 3 4a1 1 0 0 1 1-1h3.5a1 1 0 0 1 1 1c0 1.25.2 2.46.57 3.6a1 1 0 0 1-.25 1l-2.22 2.2Z',
    mail: 'M3 5h18v14H3V5Zm2 2v.5l7 4.5 7-4.5V7H5Zm0 3v7h14v-7l-7 4.5L5 10Z',
    globe: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-3.1a15.6 15.6 0 0 0-1.2-5.1A8 8 0 0 1 18.9 11ZM12 4.1c.9 1.3 1.6 3.4 1.8 6H10.2c.2-2.6.9-4.7 1.8-6ZM4.3 13h3.1c.2 1.9.6 3.6 1.2 5.1A8 8 0 0 1 4.3 13Zm3.1-2H4.3a8 8 0 0 1 4.3-5.1A15.6 15.6 0 0 0 7.4 11ZM12 19.9c-.9-1.3-1.6-3.4-1.8-6h3.6c-.2 2.6-.9 4.7-1.8 6Zm2.6-.8c.6-1.5 1-3.2 1.2-5.1h3.1a8 8 0 0 1-4.3 5.1Z',
    map: 'M12 2a7 7 0 0 0-7 7c0 5.25 7 13 7 13s7-7.75 7-13a7 7 0 0 0-7-7Zm0 9.5A2.5 2.5 0 1 1 12 6a2.5 2.5 0 0 1 0 5.5Z',
    calendar: 'M7 2h2v2h6V2h2v2h3v18H4V4h3V2Zm11 8H6v10h12V10ZM6 6v2h12V6H6Z',
    clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm1-13h-2v6l5 3 1-1.7-4-2.3V7Z',
    arrowLeft: 'M11.67 3.87 3.54 12l8.13 8.13 1.42-1.42L7.36 13H21v-2H7.36l5.73-5.71-1.42-1.42Z',
    x: 'M6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4 17.6 5 12 10.6 6.4 5Z',
    external: 'M14 3h7v7h-2V6.4l-8.3 8.3-1.4-1.4L17.6 5H14V3ZM5 5h5v2H7v10h10v-3h2v5H5V5Z',
    briefcase: 'M9 4h6a2 2 0 0 1 2 2v2h4v12H3V8h4V6a2 2 0 0 1 2-2Zm0 4h6V6H9v2Zm-4 2v6h14v-6H5Z',
    users: 'M9 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0 2c-4.42 0-8 2.24-8 5v2h16v-2c0-2.76-3.58-5-8-5Zm7-2a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm0 2c-.7 0-1.36.08-1.97.2A7.5 7.5 0 0 1 18 19v2h5v-2c0-2.48-3.13-4.5-7-4.5Z',
    trend: 'M3 17.5 9 11l4 4 7-7V12h2V4h-8v2h4.6L12 12.6l-4-4L2 15.1l1.5 1.5Z'
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
  function parseDate(value) {
    if (!value) return null;
    const text = String(value).slice(0, 10);
    const date = new Date(`${text}T00:00:00`);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  function formatDate(value) {
    const date = parseDate(value);
    if (!date) return '未設定';
    return `${date.getFullYear()}/${String(date.getMonth() + 1).padStart(2, '0')}/${String(date.getDate()).padStart(2, '0')}`;
  }
  function formatShortDate(value) {
    const date = parseDate(value);
    if (!date) return '';
    return `${String(date.getMonth() + 1).padStart(2, '0')}/${String(date.getDate()).padStart(2, '0')}`;
  }
  function formatDateTime(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return formatDate(value);
    return `${formatShortDate(value)} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
  }
  function todayISO() {
    const date = new Date();
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  }
  function dayDiff(value) {
    const date = parseDate(value);
    if (!date) return null;
    const today = parseDate(todayISO());
    return Math.round((date - today) / 86400000);
  }
  function dueLabel(value) {
    const diff = dayDiff(value);
    if (diff === null) return '期限なし';
    if (diff < 0) return `${-diff}日超過`;
    if (diff === 0) return '今日';
    if (diff === 1) return '明日';
    return `${diff}日後`;
  }
  function dueClass(value) {
    const diff = dayDiff(value);
    if (diff === null) return '';
    if (diff < 0) return 'overdue';
    if (diff === 0) return 'today';
    return '';
  }
  function localDateTimeValue(value) {
    if (!value) {
      const now = new Date();
      now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
      return now.toISOString().slice(0, 16);
    }
    return String(value).slice(0, 16);
  }
  function initial(name) {
    return esc(String(name || '?').slice(0, 1));
  }
  function tone(id) {
    return `tone-${Number(id || 0) % 4}`;
  }
  function stageClass(stage) {
    return `stage-${esc(stage)}`;
  }
  function priorityClass(priority) {
    return `priority-${esc(priority)}`;
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
    toast.timer = setTimeout(() => node.classList.remove('show'), 2800);
  }

  function setView(html) {
    $('view').innerHTML = html;
  }

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

  function badgeRank(rank) {
    return `<span class="badge rank-${esc(rank)}">${esc(RANK_LABELS[rank] || rank || '未設定')}</span>`;
  }
  function badgeStage(stage) {
    return `<span class="badge ${stageClass(stage)}">${esc(stage)}</span>`;
  }
  function badgePriority(priority) {
    return `<span class="badge ${priorityClass(priority)}">${esc(PRIORITY_LABELS[priority] || priority)}</span>`;
  }
  function badgeKind(kind) {
    return `<span class="badge kind">${esc(KIND_LABELS[kind] || kind)}</span>`;
  }

  function activityRow(activity, showCompany = true) {
    const company = showCompany && activity.company_name
      ? `<a class="inline-link" href="#/companies/${Number(activity.company_id)}">${esc(activity.company_name)}</a>`
      : '';
    const related = [activity.contact_name, activity.deal_title].filter(Boolean).map(esc).join(' · ');
    return `
      <div class="timeline-item kind-${esc(activity.kind)}">
        <div class="timeline-head">${badgeKind(activity.kind)}<strong>${esc(activity.subject)}</strong><time>${esc(formatDateTime(activity.occurred_at))}</time></div>
        ${activity.body ? `<p class="timeline-body">${esc(activity.body)}</p>` : ''}
        <div class="timeline-sub">${company}${related ? `<span>${related}</span>` : ''}${activity.created_by ? `<span>${esc(activity.created_by)}</span>` : ''}<button class="inline-link" data-action="delete-activity" data-id="${Number(activity.id)}">削除</button></div>
      </div>`;
  }

  function contactRow(contact, showCompany = false) {
    return `
      <div class="contact-row">
        <span class="avatar">${initial(contact.name)}</span>
        <div class="contact-copy">
          <strong>${esc(contact.name)} ${contact.is_primary ? '<span class="badge">主担当</span>' : ''}</strong>
          <small>${esc(contact.title || '役職未設定')}${showCompany && contact.company_name ? ` · <a href="#/companies/${Number(contact.company_id)}">${esc(contact.company_name)}</a>` : ''}</small>
          <small>${contact.email ? `<a href="mailto:${esc(contact.email)}">${esc(contact.email)}</a>` : ''}${contact.phone ? ` · ${esc(contact.phone)}` : ''}</small>
        </div>
        <div class="row-actions">
          <button class="icon-button" data-action="edit-contact" data-id="${Number(contact.id)}" title="編集" aria-label="連絡先を編集">${icon('edit')}</button>
          <button class="icon-button" data-action="delete-contact" data-id="${Number(contact.id)}" title="削除" aria-label="連絡先を削除">${icon('trash')}</button>
        </div>
      </div>`;
  }

  function dealRow(deal, showCompany = true) {
    return `
      <div class="deal-row">
        <div class="deal-copy">
          <strong>${esc(deal.title)}</strong>
          <small>${showCompany && deal.company_name ? `${esc(deal.company_name)} · ` : ''}${esc(deal.owner || '担当未設定')} · ${esc(deal.expected_close ? `完了予定 ${formatDate(deal.expected_close)}` : '完了予定未設定')}</small>
        </div>
        ${badgeStage(deal.stage)}
        <span class="deal-amount">${yen(deal.amount)}</span>
        <div class="row-actions">
          <button class="icon-button" data-action="edit-deal" data-id="${Number(deal.id)}" title="編集" aria-label="案件を編集">${icon('edit')}</button>
          <button class="icon-button" data-action="delete-deal" data-id="${Number(deal.id)}" title="削除" aria-label="案件を削除">${icon('trash')}</button>
        </div>
      </div>`;
  }

  function taskRow(task, showCompany = false) {
    const done = task.status === 'done';
    const company = showCompany && task.company_name
      ? `<a href="#/companies/${Number(task.company_id)}">${esc(task.company_name)}</a>`
      : '';
    return `
      <div class="task-row">
        <input type="checkbox" data-task-toggle="${Number(task.id)}" ${done ? 'checked' : ''} aria-label="${esc(task.title)}を${done ? '未完了' : '完了'}にする">
        <div class="task-copy ${done ? 'done' : ''}">
          <strong>${esc(task.title)}</strong>
          <small>${badgePriority(task.priority)} ${task.due_date ? `期限 ${formatDate(task.due_date)}（${dueLabel(task.due_date)}）` : '期限なし'}${company ? ` · ${company}` : ''}</small>
        </div>
        <div class="row-actions">
          <button class="icon-button" data-action="edit-task" data-id="${Number(task.id)}" title="編集" aria-label="タスクを編集">${icon('edit')}</button>
          <button class="icon-button" data-action="delete-task" data-id="${Number(task.id)}" title="削除" aria-label="タスクを削除">${icon('trash')}</button>
        </div>
      </div>`;
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
    const path = pathPart || '/dashboard';
    return { path, params: new URLSearchParams(queryPart) };
  }

  function navigate(path) {
    const target = `#${path}`;
    if (location.hash === target) {
      route();
    } else {
      location.hash = target;
    }
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
      item.addEventListener('click', () => {
        navigate(item.dataset.route);
        closeSidebar();
      });
    });
    $('menu-button').addEventListener('click', openSidebar);
    $('sidebar-overlay').addEventListener('click', closeSidebar);
    $('global-search').addEventListener('submit', event => {
      event.preventDefault();
      const query = $('global-query').value.trim();
      navigate(`/companies${query ? `?q=${encodeURIComponent(query)}` : ''}`);
    });
    $('quick-create').addEventListener('click', quickCreate);
    $('logout-button').addEventListener('click', async () => {
      try {
        await api('/api/logout', { method: 'POST' });
      } finally {
        location.replace('/login');
      }
    });
    window.addEventListener('hashchange', route);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        closeSidebar();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        $('global-query').focus();
      }
    });
    $('view').addEventListener('click', onViewClick);
    $('view').addEventListener('submit', onViewSubmit);
    $('view').addEventListener('change', onViewChange);
    $('view').addEventListener('dragstart', onDragStart);
    $('view').addEventListener('dragover', onDragOver);
    $('view').addEventListener('dragleave', onDragLeave);
    $('view').addEventListener('drop', onDrop);
  }

  function updateDate() {
    const now = new Date();
    $('topbar-date').textContent = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')}`;
  }

  async function loadOptions() {
    try {
      state.options = await api('/api/options');
    } catch {
      state.options = { owners: [], industries: [], ranks: [], stages: STAGES };
    }
  }

  async function ensureLookups(force = false) {
    if (!state.lookups || force) state.lookups = await api('/api/lookups');
    return state.lookups;
  }

  async function init() {
    bindShell();
    updateDate();
    if (!location.hash) history.replaceState(null, '', '#/dashboard');
    try {
      state.me = await api('/api/me');
      state.csrf = state.me.csrf;
      const name = state.me.name || '管理者';
      $('sidebar-name').textContent = name;
      $('sidebar-avatar').textContent = String(name).slice(0, 1);
      await Promise.all([loadOptions(), ensureLookups(false)]);
      route();
    } catch (error) {
      if (!String(error.message).includes('ログイン')) {
        setView(errorView(error.message));
      }
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
      if (path === '/dashboard' || path === '/') {
        await renderDashboard(token);
      } else if (path === '/companies') {
        await renderCompanies(params, token);
      } else if (/^\/companies\/\d+$/.test(path)) {
        await renderCompanyDetail(Number(path.split('/')[2]), token);
      } else if (path === '/contacts') {
        await renderContacts(params, token);
      } else if (path === '/deals') {
        await renderDeals(params, token);
      } else if (path === '/activities') {
        await renderActivities(params, token);
      } else if (path === '/tasks') {
        await renderTasks(params, token);
      } else if (path === '/tuti') {
        await renderTuti(params, token);
      } else {
        setView(emptyState('ページが見つかりません', 'サイドバーから画面を選び直してください。'));
      }
    } catch (error) {
      if (token === state.routeToken && !String(error.message).includes('ログイン')) {
        setView(errorView(error.message));
        toast(error.message, true);
      }
    }
  }

  function quickCreate() {
    const path = state.route;
    if (/^\/companies\/\d+$/.test(path)) {
      const companyId = Number(path.split('/')[2]);
      openActivityForm(null, companyId);
    } else if (path.startsWith('/companies')) {
      openCompanyForm();
    } else if (path.startsWith('/contacts')) {
      openContactForm();
    } else if (path.startsWith('/deals')) {
      openDealForm();
    } else if (path.startsWith('/activities')) {
      openActivityForm();
    } else if (path.startsWith('/tasks')) {
      openTaskForm();
    } else {
      openCompanyForm();
    }
  }

  async function renderDashboard(token) {
    const data = await api('/api/dashboard');
    if (token !== state.routeToken) return;
    const maxPipeline = Math.max(...data.stages.map(stage => Number(stage.amount) || 0), 1);
    const stageRows = data.stages.map(stage => {
      const percent = Math.round((Number(stage.amount) / maxPipeline) * 100);
      return `<div class="pipeline-row"><span class="pipeline-label">${esc(stage.stage)}</span><progress class="meter" max="100" value="${percent}" aria-label="${esc(stage.stage)} ${percent}%"></progress><span class="pipeline-value">${stage.count}件<strong>${compactYen(stage.amount)}</strong></span></div>`;
    }).join('');
    const tasks = data.tasks.length
      ? data.tasks.map(task => `
        <div class="mini-task ${dueClass(task.due_date)}">
          <input type="checkbox" data-task-toggle="${Number(task.id)}" aria-label="${esc(task.title)}を完了にする">
          <div class="mini-task-copy"><strong>${esc(task.title)}</strong><small>${esc(task.company_name)} · ${task.due_date ? dueLabel(task.due_date) : '期限なし'} · ${badgePriority(task.priority)}</small></div>
          <a class="inline-link" href="#/companies/${Number(task.company_id)}">顧客</a>
        </div>`).join('')
      : '<p class="panel-note">期限付きのタスクはありません。</p>';
    const activities = data.activities.length
      ? data.activities.map(activity => `
        <div class="mini-activity">
          <span class="mini-activity-dot ${esc(activity.kind)}"></span>
          <div class="mini-activity-copy"><strong>${esc(activity.subject)}</strong><small><a class="inline-link" href="#/companies/${Number(activity.company_id)}">${esc(activity.company_name)}</a> · ${esc(formatDateTime(activity.occurred_at))}</small></div>
        </div>`).join('')
      : '<p class="panel-note">活動履歴はまだありません。</p>';
    const top = data.top_companies.length
      ? data.top_companies.map(company => {
        const max = Number(data.top_companies[0].amount) || 1;
        return `<div class="top-row"><div><div class="top-name">${esc(company.name)}</div><progress class="meter small" max="100" value="${Math.round((Number(company.amount) / max) * 100)}"></progress></div><span class="top-amount">${compactYen(company.amount)}</span></div>`;
      }).join('')
      : '<p class="panel-note">進行中の案件はありません。</p>';
    setView(`
      <section class="dash-hero">
        <div><p class="eyebrow">GOOD MORNING</p><h1>${esc(state.me?.name || '管理者')}さん、今日もいきましょう。</h1><p>顧客との接点と、次にやるべきことをまとめています。</p></div>
        <div class="dash-hero-actions"><button class="button primary" data-action="new-company">${icon('plus')}顧客を追加</button><button class="button" data-action="new-activity">${icon('activity')}活動を記録</button></div>
      </section>
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('building')}顧客</span><strong>${numberFormat.format(data.counts.companies)}<small>社</small></strong><p class="metric-note">連絡先 ${numberFormat.format(data.counts.contacts)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('briefcase')}進行中案件</span><strong>${numberFormat.format(data.counts.open_deals)}<small>件</small></strong><p class="metric-note">パイプライン ${compactYen(data.counts.pipeline)}</p></article>
        <article class="metric"><span class="metric-label">${icon('trend')}今月の受注</span><strong>${compactYen(data.counts.won_month)}</strong><p class="metric-note">ステージ更新ベース</p></article>
        <article class="metric ${Number(data.counts.overdue_tasks) ? 'alert' : ''}"><span class="metric-label">${icon('clock')}期限超過タスク</span><strong>${numberFormat.format(data.counts.overdue_tasks)}<small>件</small></strong><p class="metric-note">今日のタスク ${numberFormat.format(data.counts.today_tasks)} 件</p></article>
      </section>
      <div class="dash-grid">
        <div class="dash-stack">
          <section class="card pipeline-card"><div class="section-head"><div><p class="eyebrow">SALES PIPELINE</p><h2>パイプライン</h2></div><a class="inline-link" href="#/deals">案件ボードを見る →</a></div><div class="pipeline-list">${stageRows}</div></section>
          <section class="card list-card"><div class="section-head"><div><p class="eyebrow">RECENT ACTIVITY</p><h2>最近の活動</h2></div><a class="inline-link" href="#/activities">すべて見る →</a></div><div class="activity-mini">${activities}</div></section>
        </div>
        <div class="dash-stack">
          <section class="card list-card"><div class="section-head"><div><p class="eyebrow">NEXT ACTIONS</p><h2>今日のタスク</h2></div><a class="inline-link" href="#/tasks">タスク一覧 →</a></div><div class="dash-tasks">${tasks}</div></section>
          <section class="card list-card"><div class="section-head"><div><p class="eyebrow">TOP ACCOUNTS</p><h2>パイプライン上位</h2></div></div><div class="top-list">${top}</div></section>
        </div>
      </div>`);
  }

  function companyFilters(params) {
    const industryOptions = ['', ...(state.options.industries || [])].map(value => `<option value="${esc(value)}" ${params.get('industry') === value ? 'selected' : ''}>${value ? esc(value) : 'すべての業種'}</option>`).join('');
    const rankOptions = ['', ...(state.options.ranks || [])].map(value => `<option value="${esc(value)}" ${params.get('rank') === value ? 'selected' : ''}>${value ? esc(value) : 'すべてのランク'}</option>`).join('');
    const ownerOptions = ['', ...(state.options.owners || [])].map(value => `<option value="${esc(value)}" ${params.get('owner') === value ? 'selected' : ''}>${value ? esc(value) : 'すべての担当'}</option>`).join('');
    return `
      <form class="toolbar" data-filter="companies">
        <div class="toolbar-left">
          <label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="顧客名・カナ・住所で検索" aria-label="顧客を検索"></label>
          <select class="select" name="industry" aria-label="業種で絞り込み">${industryOptions}</select>
          <select class="select" name="rank" aria-label="ランクで絞り込み">${rankOptions}</select>
          <select class="select" name="owner" aria-label="担当で絞り込み">${ownerOptions}</select>
          <button class="button" type="submit">絞り込む</button>
          <a class="button quiet" href="#/companies">解除</a>
        </div>
        <div class="toolbar-right"><button class="button primary" type="button" data-action="new-company">${icon('plus')}顧客を追加</button></div>
      </form>`;
  }

  async function renderCompanies(params, token) {
    const query = new URLSearchParams();
    ['q', 'industry', 'rank', 'owner', 'page'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/companies?${query.toString()}`);
    if (token !== state.routeToken) return;
    const rows = data.items.map(company => `
      <tr>
        <td><div class="cell-main"><span class="company-avatar ${tone(company.id)}">${initial(company.name)}</span><div class="cell-main-copy"><a class="cell-link" href="#/companies/${Number(company.id)}"><strong>${esc(company.name)}</strong></a><small>${esc(company.name_kana || company.industry || '業種未設定')}</small></div></div></td>
        <td>${company.industry ? `<span class="badge">${esc(company.industry)}</span>` : '<span class="muted">—</span>'}</td>
        <td>${badgeRank(company.rank)}</td>
        <td>${esc(company.owner || '未設定')}</td>
        <td>${numberFormat.format(company.contact_count)}</td>
        <td>${numberFormat.format(company.open_deal_count)}</td>
        <td>${compactYen(company.pipeline_amount)}</td>
        <td>${company.last_activity_at ? esc(formatShortDate(company.last_activity_at)) : '<span class="muted">—</span>'}</td>
        <td><div class="row-actions"><button class="icon-button" data-action="edit-company" data-id="${Number(company.id)}" title="編集" aria-label="顧客を編集">${icon('edit')}</button><button class="icon-button" data-action="delete-company" data-id="${Number(company.id)}" title="削除" aria-label="顧客を削除">${icon('trash')}</button></div></td>
      </tr>`).join('');
    setView(`
      ${pageHead('CUSTOMERS', '顧客', `${data.total}社の顧客を管理しています。`, `<button class="button" data-action="export-companies">${icon('external')}CSV</button>`)}
      ${companyFilters(params)}
      <div class="toolbar"><div class="result-count">${data.total}件中 ${data.items.length}件を表示</div></div>
      ${data.items.length ? `<div class="card table-card"><div class="table-wrap"><table class="data"><thead><tr><th>顧客</th><th>業種</th><th>ランク</th><th>担当</th><th>連絡先</th><th>進行中</th><th>パイプライン</th><th>最終活動</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>${pagination(data.page, data.pages, data.total)}</div>` : emptyState('顧客がまだありません', '最初の顧客を追加して、連絡先や案件を紐づけましょう。', `<button class="button primary" data-action="new-company">${icon('plus')}顧客を追加</button>`)}`);
  }

  function pagination(page, pages, total) {
    return `<div class="pagination"><span class="pagination-info">${total}件 · ${page} / ${pages}ページ</span><div class="pagination-buttons"><button class="button" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>前へ</button><button class="button" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>次へ</button></div></div>`;
  }

  async function renderCompanyDetail(companyId, token) {
    const data = await api(`/api/companies/${companyId}`);
    if (token !== state.routeToken) return;
    const company = data.company;
    const contactItems = data.contacts.length
      ? data.contacts.map(contact => contactRow(contact)).join('')
      : '<p class="panel-note">連絡先はまだ登録されていません。</p>';
    const dealItems = data.deals.length
      ? data.deals.map(deal => dealRow(deal, false)).join('')
      : '<p class="panel-note">案件はまだ登録されていません。</p>';
    const activityItems = data.activities.length
      ? data.activities.map(activity => activityRow(activity, false)).join('')
      : '<p class="panel-note">活動履歴はまだありません。最初の商談やメモを記録しましょう。</p>';
    const taskItems = data.tasks.length
      ? data.tasks.map(task => taskRow(task)).join('')
      : '<p class="panel-note">タスクはありません。</p>';
    const website = company.website ? `<span>${icon('globe')}<a href="${esc(company.website)}" target="_blank" rel="noreferrer noopener">${esc(company.website.replace(/^https?:\/\//, ''))}</a></span>` : '';
    const phone = company.phone ? `<span>${icon('phone')}${esc(company.phone)}</span>` : '';
    const address = company.address ? `<span>${icon('map')}${esc(company.address)}</span>` : '';
    setView(`
      <div class="breadcrumb"><a class="inline-link" href="#/companies">顧客</a>${icon('arrowLeft')}<span>${esc(company.name)}</span></div>
      <section class="detail-hero">
        <div class="detail-identity"><span class="detail-logo ${tone(company.id)}">${initial(company.name)}</span><div><h1>${esc(company.name)}</h1><div class="detail-sub"><span>${esc(company.name_kana || 'カナ未設定')}</span>${badgeRank(company.rank)}${company.industry ? `<span class="badge">${esc(company.industry)}</span>` : ''}<span>担当 ${esc(company.owner || '未設定')}</span></div><div class="detail-meta">${phone}${website}${address}</div></div></div>
        <div class="detail-actions"><button class="button" data-action="new-contact" data-company-id="${Number(company.id)}">${icon('user')}連絡先</button><button class="button" data-action="new-deal" data-company-id="${Number(company.id)}">${icon('briefcase')}案件</button><button class="button primary" data-action="new-activity" data-company-id="${Number(company.id)}">${icon('plus')}活動を記録</button><button class="button" data-action="edit-company" data-id="${Number(company.id)}">${icon('edit')}編集</button><button class="button danger" data-action="delete-company" data-id="${Number(company.id)}" aria-label="顧客を削除">${icon('trash')}</button></div>
      </section>
      <section class="detail-metrics">
        <div class="detail-metric"><span>連絡先</span><strong>${numberFormat.format(data.contacts.length)}</strong></div>
        <div class="detail-metric"><span>進行中案件</span><strong>${numberFormat.format(company.open_deal_count)}</strong></div>
        <div class="detail-metric"><span>パイプライン</span><strong>${compactYen(company.pipeline_amount)}</strong></div>
        <div class="detail-metric"><span>タスク</span><strong>${numberFormat.format(data.tasks.filter(task => task.status === 'open').length)}</strong></div>
      </section>
      ${company.note ? `<div class="card card-pad detail-edit-note">${esc(company.note)}</div>` : ''}
      <div class="detail-grid">
        <div class="detail-stack">
          <section class="card detail-section"><div class="section-head"><div><p class="eyebrow">DEALS</p><h2>案件</h2></div><button class="inline-link" data-action="new-deal" data-company-id="${Number(company.id)}">＋ 案件を追加</button></div><div class="deal-list">${dealItems}</div></section>
          <section class="card detail-section"><div class="section-head"><div><p class="eyebrow">ACTIVITY</p><h2>活動履歴</h2></div><button class="inline-link" data-action="new-activity" data-company-id="${Number(company.id)}">＋ 活動を記録</button></div><div class="timeline">${activityItems}</div></section>
        </div>
        <div class="detail-stack">
          <section class="card detail-section"><div class="section-head"><div><p class="eyebrow">CONTACTS</p><h2>連絡先</h2></div><button class="inline-link" data-action="new-contact" data-company-id="${Number(company.id)}">＋ 追加</button></div><div class="contact-list">${contactItems}</div></section>
          <section class="card detail-section"><div class="section-head"><div><p class="eyebrow">TASKS</p><h2>タスク</h2></div><button class="inline-link" data-action="new-task" data-company-id="${Number(company.id)}">＋ 追加</button></div><div class="task-list">${taskItems}</div></section>
        </div>
      </div>`);
  }

  async function renderContacts(params, token) {
    const query = new URLSearchParams();
    ['q', 'company_id', 'page'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/contacts?${query.toString()}`);
    if (token !== state.routeToken) return;
    const options = (state.lookups?.companies || []).map(company => `<option value="${Number(company.id)}" ${params.get('company_id') === String(company.id) ? 'selected' : ''}>${esc(company.name)}</option>`).join('');
    const rows = data.items.map(contact => `
      <tr><td><div class="cell-main"><span class="avatar">${initial(contact.name)}</span><div class="cell-main-copy"><strong>${esc(contact.name)}</strong><small>${esc(contact.title || '役職未設定')}</small></div></div></td><td><a class="cell-link" href="#/companies/${Number(contact.company_id)}">${esc(contact.company_name)}</a></td><td>${contact.email ? `<a class="inline-link" href="mailto:${esc(contact.email)}">${esc(contact.email)}</a>` : '<span class="muted">—</span>'}</td><td>${esc(contact.phone || contact.mobile || '—')}</td><td>${contact.is_primary ? '<span class="badge">主担当</span>' : '<span class="muted">—</span>'}</td><td><div class="row-actions"><button class="icon-button" data-action="edit-contact" data-id="${Number(contact.id)}" aria-label="連絡先を編集">${icon('edit')}</button><button class="icon-button" data-action="delete-contact" data-id="${Number(contact.id)}" aria-label="連絡先を削除">${icon('trash')}</button></div></td></tr>`).join('');
    setView(`
      ${pageHead('CONTACTS', '連絡先', `${data.total}件の連絡先を管理しています。`, `<button class="button primary" data-action="new-contact">${icon('plus')}連絡先を追加</button>`)}
      <form class="toolbar" data-filter="contacts"><div class="toolbar-left"><label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="名前・メール・顧客名で検索" aria-label="連絡先を検索"></label><select class="select" name="company_id" aria-label="顧客で絞り込み"><option value="">すべての顧客</option>${options}</select><button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/contacts">解除</a></div></form>
      ${data.items.length ? `<div class="card table-card"><div class="table-wrap"><table class="data"><thead><tr><th>名前</th><th>顧客</th><th>メール</th><th>電話</th><th>主担当</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>${pagination(data.page, data.pages, data.total)}</div>` : emptyState('連絡先がありません', '顧客に紐づく担当者を登録すると、活動履歴と一緒に管理できます。', `<button class="button primary" data-action="new-contact">${icon('plus')}連絡先を追加</button>`)}`);
  }

  async function renderDeals(params, token) {
    const query = new URLSearchParams();
    ['q', 'owner'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/deals?${query.toString()}`);
    if (token !== state.routeToken) return;
    const ownerOptions = ['', ...(state.options.owners || [])].map(value => `<option value="${esc(value)}" ${params.get('owner') === value ? 'selected' : ''}>${value ? esc(value) : 'すべての担当'}</option>`).join('');
    const columns = STAGES.map(stage => {
      const items = data.items.filter(deal => deal.stage === stage);
      const amount = items.reduce((sum, deal) => sum + Number(deal.amount || 0), 0);
      const cards = items.length ? items.map(deal => `
        <button type="button" class="kanban-card" draggable="true" data-deal-id="${Number(deal.id)}" data-action="edit-deal" data-id="${Number(deal.id)}">
          <div class="kanban-card-company">${esc(deal.company_name)}</div>
          <div class="kanban-card-title">${esc(deal.title)}</div>
          <div class="kanban-card-meta"><span>${esc(deal.owner || '担当未設定')}</span><span class="kanban-card-amount">${compactYen(deal.amount)}</span></div>
          <div class="kanban-card-meta"><span>${esc(deal.expected_close ? formatShortDate(deal.expected_close) : '完了予定なし')}</span><span>${Number(deal.probability)}%</span></div>
        </button>`).join('') : '<div class="kanban-empty">案件をここにドラッグ</div>';
      return `<section class="kanban-column" data-stage="${esc(stage)}"><div class="kanban-head"><span class="kanban-title"><span class="stage-dot"></span>${esc(stage)}</span><span class="kanban-count">${items.length}件</span></div><div class="kanban-amount">${compactYen(amount)}</div><div class="kanban-cards" data-drop-stage="${esc(stage)}">${cards}</div></section>`;
    }).join('');
    setView(`
      ${pageHead('PIPELINE', '案件パイプライン', `${data.items.length}件の案件 · ドラッグ＆ドロップでステージを更新`, `<button class="button" data-action="export-deals">${icon('external')}CSV</button><button class="button primary" data-action="new-deal">${icon('plus')}案件を追加</button>`)}
      <form class="toolbar" data-filter="deals"><div class="toolbar-left"><label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="案件名・顧客名で検索" aria-label="案件を検索"></label><select class="select" name="owner" aria-label="担当で絞り込み">${ownerOptions}</select><button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/deals">解除</a></div></form>
      <div class="kanban">${columns}</div>`);
  }

  async function renderActivities(params, token) {
    const query = new URLSearchParams();
    ['q', 'kind'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    const data = await api(`/api/activities?${query.toString()}`);
    if (token !== state.routeToken) return;
    const kindOptions = [['', 'すべての種類'], ...Object.entries(KIND_LABELS)].map(([value, label]) => `<option value="${esc(value)}" ${params.get('kind') === value ? 'selected' : ''}>${esc(label)}</option>`).join('');
    const items = data.items.length ? `<div class="card detail-section"><div class="timeline">${data.items.map(activity => activityRow(activity)).join('')}</div></div>` : emptyState('活動履歴がありません', '電話・メール・商談・訪問の記録を残すと、顧客との文脈がチームに共有されます。', `<button class="button primary" data-action="new-activity">${icon('plus')}活動を記録</button>`);
    setView(`
      ${pageHead('ACTIVITY', '活動履歴', `${data.items.length}件の活動を表示しています。`, `<button class="button primary" data-action="new-activity">${icon('plus')}活動を記録</button>`)}
      <form class="toolbar" data-filter="activities"><div class="toolbar-left"><label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="件名・本文・顧客名で検索" aria-label="活動を検索"></label><select class="select" name="kind" aria-label="種類で絞り込み">${kindOptions}</select><button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/activities">解除</a></div></form>
      ${items}`);
  }

  async function renderTasks(params, token) {
    const query = new URLSearchParams();
    ['q', 'status'].forEach(key => { if (params.get(key)) query.set(key, params.get(key)); });
    if (!query.get('status')) query.set('status', 'open');
    const data = await api(`/api/tasks?${query.toString()}`);
    if (token !== state.routeToken) return;
    const grouped = { overdue: [], today: [], upcoming: [], done: [] };
    data.items.forEach(task => {
      if (task.status === 'done') grouped.done.push(task);
      else if (task.due_date && dayDiff(task.due_date) < 0) grouped.overdue.push(task);
      else if (task.due_date && dayDiff(task.due_date) === 0) grouped.today.push(task);
      else grouped.upcoming.push(task);
    });
    const sections = [
      ['overdue', '期限超過', grouped.overdue],
      ['today', '今日', grouped.today],
      ['upcoming', '今後', grouped.upcoming],
      ['done', '完了', grouped.done]
    ].map(([key, title, items]) => {
      if (!items.length) return '';
      return `<section class="card detail-section"><div class="section-head"><div><p class="eyebrow">${key === 'done' ? 'COMPLETED' : 'OPEN TASKS'}</p><h2>${title} <span class="result-count">${items.length}件</span></h2></div></div><div class="task-list">${items.map(task => taskRow(task, true)).join('')}</div></section>`;
    }).join('');
    setView(`
      ${pageHead('TASKS', 'タスク', '次にやるべきことを、期限と優先度で整理しています。', `<button class="button primary" data-action="new-task">${icon('plus')}タスクを追加</button>`)}
      <form class="toolbar" data-filter="tasks"><div class="toolbar-left"><label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="タスク名・顧客名で検索" aria-label="タスクを検索"></label><select class="select" name="status" aria-label="状態で絞り込み"><option value="open" ${query.get('status') !== 'done' ? 'selected' : ''}>未完了</option><option value="done" ${query.get('status') === 'done' ? 'selected' : ''}>完了</option><option value="all" ${query.get('status') === 'all' ? 'selected' : ''}>すべて</option></select><button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/tasks">解除</a></div></form>
      ${sections || emptyState('タスクはありません', '顧客や案件に紐づくタスクを追加して、次のアクションを忘れずに進めましょう。', `<button class="button primary" data-action="new-task">${icon('plus')}タスクを追加</button>`)}`);
  }

  async function renderTuti(params, token) {
    const data = await api('/api/tuti/overview');
    if (token !== state.routeToken) return;
    const config = data.config || {};
    const scopes = data.scopes || {};
    const payload = scope => (scopes[scope] || {}).payload || null;
    const status = payload('status');
    const productRows = (payload('products') || {}).products || [];
    const licenseRows = (payload('licenses') || {}).licenses || [];
    const usage = payload('usage');
    const invoices = (payload('invoices') || {}).invoices || [];
    const events = (payload('audit') || {}).events || [];
    const query = (params.get('q') || '').trim().toLowerCase();
    const visible = query
      ? licenseRows.filter(row => [row.id, row.label, row.product_code, row.environment].join(' ').toLowerCase().includes(query))
      : licenseRows;
    const activeCount = licenseRows.filter(row => row.active).length;
    const sandboxCount = licenseRows.filter(row => row.environment === 'sandbox').length;
    const charge = usage ? Number(usage.total_charge_yen_equivalent ?? usage.total_charge_credit ?? 0) : null;
    const syncButton = config.configured
      ? '<button class="button primary" data-action="tuti-sync">今すぐ同期</button>'
      : '';
    const setup = config.configured ? `
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">CONNECTION</p><h2>接続先</h2></div><span class="badge rank-S">API接続済み</span></div>
        <div class="tuti-meta">
          <div><span class="muted">ベースURL</span><strong>${esc(config.base || '')}</strong></div>
          <div><span class="muted">環境</span><strong>${esc(config.environment || 'auto')}</strong></div>
          <div><span class="muted">APIキー</span><strong>${esc(config.key_hint || '設定済み')}</strong></div>
          <div><span class="muted">最終同期</span><strong>${data.last_sync ? esc(formatDateTime(data.last_sync)) : '未同期'}</strong></div>
        </div>
      </section>` : `
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">SETUP REQUIRED</p><h2>TUTI APIキーが未設定です</h2></div><span class="badge rank-C">未接続</span></div>
        <p class="muted">テナントAPIキーを環境変数に設定してアプリを再起動すると、契約・ライセンス・API利用料・請求書をこの画面に取り込めます。キーは画面にもログにも保存しません。</p>
        <pre class="code-block">$env:TUTI_API_BASE='https://2415.jp'
$env:TUTI_API_KEY='baas_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
$env:TUTI_API_ENV='production'  # sandbox の場合は sandbox
.\Start-CustomerCrm.ps1</pre>
        <p class="muted">キーは TUTI 管理センターでテナントごとに発行され、読み取りには <code>tenant:read</code> スコープが必要です。</p>
        ${data.last_sync ? `<p class="muted">以下の数値は ${esc(formatDateTime(data.last_sync))} に取得したキャッシュです。キーを設定して再起動したあと「今すぐ同期」で更新してください。</p>` : ''}
      </section>`;
    const failureNotice = ['status', 'products', 'licenses', 'usage', 'invoices', 'audit']
      .filter(scope => (scopes[scope] || {}).error)
      .map(scope => `<p class="panel-note">${esc(TUTI_SCOPE_LABELS[scope] || scope)}: ${esc(scopes[scope].error)}</p>`)
      .join('');
    const licenseTable = visible.length ? `
      <div class="table-wrap"><table class="data"><thead><tr><th>ID</th><th>製品</th><th>ラベル</th><th>状態</th><th>環境</th><th>端末上限</th><th>有効期限</th><th>発行日</th></tr></thead><tbody>
      ${visible.map(row => `<tr>
        <td>#${esc(row.id)}</td>
        <td>${esc(row.product_code || row.product_id || '')}</td>
        <td>${esc(row.label || '（ラベルなし）')}</td>
        <td>${row.active ? '<span class="badge rank-S">稼働中</span>' : '<span class="badge rank-C">停止</span>'}</td>
        <td>${esc(row.environment || '')}</td>
        <td>${esc(row.max_devices ?? '')}</td>
        <td>${row.expires_at ? esc(formatDate(row.expires_at)) : '無期限'}</td>
        <td>${row.created_at ? esc(formatDate(row.created_at)) : ''}</td>
      </tr>`).join('')}
      </tbody></table></div>` : emptyState('ライセンスがありません', config.configured ? '同期すると、このテナントのライセンスがここに並びます。' : 'TUTI APIキーを設定すると、ライセンスを取り込めます。');
    const usageRows = usage && Array.isArray(usage.details) ? usage.details : [];
    const invoiceRows = Array.isArray(invoices) ? invoices : ((payload('invoices') || {}).items || []);
    const invoicesTable = invoiceRows.length ? `
      <div class="table-wrap"><table class="data"><thead><tr><th>請求番号</th><th>対象月</th><th>金額</th><th>状態</th><th>発行日</th><th>支払期限</th></tr></thead><tbody>
      ${invoiceRows.map(row => `<tr><td>${esc(row.invoice_number || '')}</td><td>${esc(row.billing_period || '')}</td><td>${esc(yen(row.total_yen ?? 0))}</td><td>${esc(row.status || '')}</td><td>${row.issue_date ? esc(formatDate(row.issue_date)) : ''}</td><td>${row.due_date ? esc(formatDate(row.due_date)) : ''}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="panel-note">請求書はまだありません。</p>';
    const usageTable = usageRows.length ? `
      <div class="table-wrap"><table class="data"><thead><tr><th>API</th><th>リクエスト数</th><th>単価</th><th>課金単位</th></tr></thead><tbody>
      ${usageRows.map(row => `<tr><td>${esc(row.api || '')}</td><td>${esc(row.requests ?? 0)}</td><td>${esc(row.unit_credit || '')}</td><td>${esc(row.charge_credit || '')}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="panel-note">この期間の課金対象API呼び出しはありません。</p>';
    const eventRows = events.length ? `
      <div class="table-wrap"><table class="data"><thead><tr><th>日時</th><th>操作</th><th>HTTP</th><th>リクエストID</th></tr></thead><tbody>
      ${events.map(row => `<tr><td>${esc(formatDateTime(row.used_at))}</td><td>${esc(row.operation || '')}</td><td>${esc(row.status_code ?? '')}</td><td><code>${esc(row.request_id || '')}</code></td></tr>`).join('')}
      </tbody></table></div>` : '<p class="panel-note">APIイベントはまだありません。</p>';
    setView(`
      ${pageHead('TUTI API', 'TUTI連携', '契約・ライセンス・API利用料・請求書を、TUTIの管理APIから直接読み取ります。', `${syncButton}${config.configured ? '<a class="button quiet" href="/api/export/tuti-licenses.csv">ライセンスCSV</a>' : ''}`)}
      ${failureNotice ? `<section class="card detail-section"><div class="section-head"><div><p class="eyebrow">SYNC NOTES</p><h2>取得できなかった項目</h2></div></div>${failureNotice}</section>` : ''}
      ${setup}
      <section class="metrics">
        <article class="metric"><span class="metric-label">${icon('briefcase')}ライセンス</span><strong>${numberFormat.format(licenseRows.length)}<small>件</small></strong><p class="metric-note">稼働中 ${numberFormat.format(activeCount)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('globe')}サンドボックス</span><strong>${numberFormat.format(sandboxCount)}<small>件</small></strong><p class="metric-note">本番 ${numberFormat.format(licenseRows.length - sandboxCount)} 件</p></article>
        <article class="metric"><span class="metric-label">${icon('chart')}今月のAPI利用料</span><strong>${charge === null ? '-' : yen(charge)}</strong><p class="metric-note">${usage ? `${numberFormat.format(usage.total_requests || 0)} リクエスト / ${esc(usage.period || '')}` : '未同期'}</p></article>
        <article class="metric"><span class="metric-label">${icon('users')}製品</span><strong>${numberFormat.format(productRows.length)}<small>件</small></strong><p class="metric-note">${status ? `テナント ${esc((status.tenant || {}).slug || '')}` : '未同期'}</p></article>
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">LICENSES</p><h2>ライセンス <span class="result-count">${visible.length}件</span></h2></div></div>
        <form class="toolbar" data-filter="tuti"><div class="toolbar-left"><label class="search-field">${icon('search')}<input type="search" name="q" value="${esc(params.get('q') || '')}" placeholder="ラベル・製品コード・IDで絞り込み" aria-label="ライセンスを検索"></label><button class="button" type="submit">絞り込む</button><a class="button quiet" href="#/tuti">解除</a></div></form>
        ${licenseTable}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">API USAGE</p><h2>API利用料 ${usage ? `（${esc(usage.period || '')}）` : ''}</h2></div><span class="muted">${usage ? `課金対象 ${numberFormat.format(usage.billable_requests || 0)} / 全体 ${numberFormat.format(usage.total_requests || 0)}` : ''}</span></div>
        ${usageTable}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">INVOICES</p><h2>請求書</h2></div></div>
        ${invoicesTable}
      </section>
      <section class="card detail-section">
        <div class="section-head"><div><p class="eyebrow">AUDIT</p><h2>最近のAPIイベント</h2></div></div>
        ${eventRows}
      </section>`);
  }

  async function onViewClick(event) {
    const routeLink = event.target.closest('a[data-route]');
    if (routeLink) {
      event.preventDefault();
      navigate(routeLink.dataset.route);
      return;
    }
    const pageButton = event.target.closest('[data-page]');
    if (pageButton) {
      const { params } = parseRoute();
      params.set('page', pageButton.dataset.page);
      navigate(`${state.route}?${params.toString()}`);
      return;
    }
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const id = Number(button.dataset.id || 0);
    const companyId = Number(button.dataset.companyId || 0);
    try {
      if (action === 'reload') return route();
      if (action === 'new-company') return openCompanyForm();
      if (action === 'edit-company') return openCompanyForm(await getCompany(id));
      if (action === 'delete-company') return deleteCompany(id);
      if (action === 'new-contact') return openContactForm(null, companyId || null);
      if (action === 'edit-contact') return openContactForm(await getContact(id));
      if (action === 'delete-contact') return deleteContact(id);
      if (action === 'new-deal') return openDealForm(null, companyId || null);
      if (action === 'edit-deal') return openDealForm(await getDeal(id));
      if (action === 'delete-deal') return deleteDeal(id);
      if (action === 'new-activity') return openActivityForm(null, companyId || null);
      if (action === 'delete-activity') return deleteActivity(id);
      if (action === 'new-task') return openTaskForm(null, companyId || null);
      if (action === 'edit-task') return openTaskForm(await getTask(id));
      if (action === 'delete-task') return deleteTask(id);
      if (action === 'export-companies') return location.assign('/api/export/companies.csv');
      if (action === 'export-deals') return location.assign('/api/export/deals.csv');
      if (action === 'tuti-sync') {
        button.disabled = true;
        button.textContent = '同期中…';
        const result = await api('/api/tuti/sync', { method: 'POST' });
        toast(result.ok ? 'TUTI API と同期しました' : '一部の項目を取得できませんでした', !result.ok);
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

  async function onViewChange(event) {
    const select = event.target.closest('form[data-filter] select');
    if (select) {
      select.form.requestSubmit();
      return;
    }
    const checkbox = event.target.closest('[data-task-toggle]');
    if (checkbox) {
      try {
        await api(`/api/tasks/${Number(checkbox.dataset.taskToggle)}`, {
          method: 'PATCH',
          body: JSON.stringify({ status: checkbox.checked ? 'done' : 'open' })
        });
        toast(checkbox.checked ? 'タスクを完了にしました' : 'タスクを未完了に戻しました');
        await route();
      } catch (error) {
        checkbox.checked = !checkbox.checked;
        toast(error.message, true);
      }
    }
  }

  function onDragStart(event) {
    const card = event.target.closest('[data-deal-id]');
    if (!card) return;
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', card.dataset.dealId);
    card.classList.add('dragging');
  }
  function onDragOver(event) {
    const zone = event.target.closest('[data-drop-stage]');
    if (!zone) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    zone.classList.add('drag-over');
  }
  function onDragLeave(event) {
    const zone = event.target.closest('[data-drop-stage]');
    if (zone && !zone.contains(event.relatedTarget)) zone.classList.remove('drag-over');
  }
  async function onDrop(event) {
    const zone = event.target.closest('[data-drop-stage]');
    if (!zone) return;
    event.preventDefault();
    zone.classList.remove('drag-over');
    const dealId = Number(event.dataTransfer.getData('text/plain'));
    const stage = zone.dataset.dropStage;
    if (!dealId) return;
    try {
      await api(`/api/deals/${dealId}/stage`, { method: 'PATCH', body: JSON.stringify({ stage }) });
      toast(`ステージを「${stage}」に更新しました`);
      await route();
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function getCompany(id) {
    return (await api(`/api/companies/${id}`)).company;
  }
  async function getContact(id) {
    return api(`/api/contacts/${id}`);
  }
  async function getDeal(id) {
    return api(`/api/deals/${id}`);
  }
  async function getTask(id) {
    return api(`/api/tasks/${id}`);
  }

  async function deleteCompany(id) {
    if (!window.confirm('この顧客を削除しますか？\n連絡先・案件・活動・タスクもすべて削除されます。')) return;
    await api(`/api/companies/${id}`, { method: 'DELETE' });
    state.lookups = null;
    toast('顧客を削除しました');
    if (state.route.startsWith(`/companies/${id}`)) navigate('/companies'); else await route();
  }
  async function deleteContact(id) {
    if (!window.confirm('この連絡先を削除しますか？')) return;
    await api(`/api/contacts/${id}`, { method: 'DELETE' });
    state.lookups = null;
    toast('連絡先を削除しました');
    await route();
  }
  async function deleteDeal(id) {
    if (!window.confirm('この案件を削除しますか？')) return;
    await api(`/api/deals/${id}`, { method: 'DELETE' });
    state.lookups = null;
    toast('案件を削除しました');
    await route();
  }
  async function deleteActivity(id) {
    if (!window.confirm('この活動履歴を削除しますか？')) return;
    await api(`/api/activities/${id}`, { method: 'DELETE' });
    toast('活動履歴を削除しました');
    await route();
  }
  async function deleteTask(id) {
    if (!window.confirm('このタスクを削除しますか？')) return;
    await api(`/api/tasks/${id}`, { method: 'DELETE' });
    toast('タスクを削除しました');
    await route();
  }

  function field(label, name, value = '', options = {}) {
    const required = options.required ? '<em>必須</em>' : '';
    const full = options.full ? ' full' : '';
    const attrs = [
      `type="${esc(options.type || 'text')}"`, `name="${esc(name)}"`,
      `value="${esc(value ?? '')}"`,
      options.placeholder ? `placeholder="${esc(options.placeholder)}"` : '',
      options.required ? 'required' : '',
      options.min !== undefined ? `min="${esc(options.min)}"` : '',
      options.max !== undefined ? `max="${esc(options.max)}"` : '',
      options.step !== undefined ? `step="${esc(options.step)}"` : '',
      options.maxlength ? `maxlength="${esc(options.maxlength)}"` : '',
      options.autocomplete ? `autocomplete="${esc(options.autocomplete)}"` : 'autocomplete="off"'
    ].filter(Boolean).join(' ');
    return `<label class="field${full}"><span>${esc(label)}${required}</span><input ${attrs}></label>`;
  }

  function textArea(label, name, value = '', options = {}) {
    return `<label class="field${options.full ? ' full' : ''}"><span>${esc(label)}</span><textarea name="${esc(name)}" placeholder="${esc(options.placeholder || '')}" maxlength="${esc(options.maxlength || 4000)}">${esc(value || '')}</textarea></label>`;
  }

  function selectField(label, name, options, value = '', extra = {}) {
    const optionHtml = options.map(option => {
      const optionValue = typeof option === 'string' ? option : option.value;
      const optionLabel = typeof option === 'string' ? option : option.label;
      return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value ?? '') ? 'selected' : ''}>${esc(optionLabel)}</option>`;
    }).join('');
    return `<label class="field${extra.full ? ' full' : ''}"><span>${esc(label)}</span><select name="${esc(name)}" ${extra.required ? 'required' : ''}>${optionHtml}</select></label>`;
  }

  function companySelect(selected) {
    return selectField('顧客', 'company_id', (state.lookups?.companies || []).map(company => ({ value: company.id, label: company.name })), selected, { required: true });
  }

  function contactOptions(companyId, selected) {
    const contacts = (state.lookups?.contacts || []).filter(contact => !companyId || Number(contact.company_id) === Number(companyId));
    return [{ value: '', label: '連絡先を選択しない' }, ...contacts.map(contact => ({ value: contact.id, label: `${contact.name}${contact.title ? `（${contact.title}）` : ''}` }))]
      .map(option => ({ ...option, value: option.value, label: option.label }));
  }
  function dealOptions(companyId, selected) {
    const deals = (state.lookups?.deals || []).filter(deal => !companyId || Number(deal.company_id) === Number(companyId));
    return [{ value: '', label: '案件を選択しない' }, ...deals.map(deal => ({ value: deal.id, label: `${deal.title}（${deal.stage}）` }))]
      .map(option => ({ ...option, value: option.value, label: option.label }));
  }

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
    const close = () => closeModal();
    root.querySelectorAll('[data-modal-close]').forEach(button => button.addEventListener('click', close));
    root.querySelector('[data-modal-backdrop]').addEventListener('mousedown', event => {
      if (event.target === event.currentTarget) close();
    });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const errorNode = form.querySelector('.form-error');
      errorNode.hidden = true;
      submit.disabled = true;
      const original = submit.textContent;
      submit.textContent = '保存中…';
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
    document.addEventListener('keydown', modalEscape);
    return form;
  }

  function modalEscape(event) {
    if (event.key === 'Escape' && $('modal-root').children.length) closeModal();
  }

  function closeModal() {
    $('modal-root').replaceChildren();
    document.removeEventListener('keydown', modalEscape);
  }

  function formValues(form) {
    const values = {};
    new FormData(form).forEach((value, key) => { values[key] = value; });
    if (form.elements.is_primary) values.is_primary = form.elements.is_primary.checked;
    return values;
  }

  async function openCompanyForm(company = null) {
    const editing = Boolean(company);
    const body = `<div class="form-grid">
      ${field('顧客名', 'name', company?.name || '', { required: true, maxlength: 160, placeholder: '株式会社サンプル' })}
      ${field('カナ', 'name_kana', company?.name_kana || '', { maxlength: 160, placeholder: 'カブシキガイシャサンプル' })}
      ${selectField('業種', 'industry', state.options.industries || [], company?.industry || '')}
      ${selectField('ランク', 'rank', RANKS.map(rank => ({ value: rank, label: RANK_LABELS[rank] })), company?.rank || 'B')}
      ${field('担当者', 'owner', company?.owner || '', { maxlength: 80, placeholder: '佐藤 健' })}
      ${field('電話番号', 'phone', company?.phone || '', { maxlength: 60, placeholder: '03-0000-0000' })}
      ${field('Webサイト', 'website', company?.website || '', { maxlength: 300, placeholder: 'https://example.jp', full: true })}
      ${field('住所', 'address', company?.address || '', { maxlength: 300, full: true, placeholder: '東京都千代田区…' })}
      ${textArea('メモ', 'note', company?.note || '', { full: true, placeholder: '意思決定者、課題、次回アクションなど' })}
    </div>`;
    openModal({
      title: editing ? '顧客を編集' : '顧客を追加',
      subtitle: '会社情報と担当者を登録します。',
      body,
      submitLabel: editing ? '更新する' : '追加する',
      wide: true,
      onSubmit: async form => {
        const values = formValues(form);
        const payload = {
          name: values.name, name_kana: values.name_kana || '', industry: values.industry || '',
          website: values.website || '', phone: values.phone || '', address: values.address || '',
          rank: values.rank || 'B', owner: values.owner || '', note: values.note || ''
        };
        const result = await api(editing ? `/api/companies/${company.id}` : '/api/companies', {
          method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload)
        });
        state.lookups = null;
        await loadOptions();
        closeModal();
        toast(editing ? '顧客を更新しました' : '顧客を追加しました');
        if (!editing) navigate(`/companies/${result.id}`); else await route();
      }
    });
  }

  async function openContactForm(contact = null, companyId = null) {
    await ensureLookups();
    const editing = Boolean(contact);
    const selectedCompany = contact?.company_id || companyId || state.lookups.companies[0]?.id || '';
    const body = `<div class="form-grid">
      ${companySelect(selectedCompany)}
      ${field('氏名', 'name', contact?.name || '', { required: true, maxlength: 120, placeholder: '山田 太郎' })}
      ${field('役職', 'title', contact?.title || '', { maxlength: 120, placeholder: '情報システム部長' })}
      ${field('メール', 'email', contact?.email || '', { type: 'email', maxlength: 200, placeholder: 'name@example.jp' })}
      ${field('電話', 'phone', contact?.phone || '', { maxlength: 60 })}
      ${field('携帯', 'mobile', contact?.mobile || '', { maxlength: 60 })}
      <label class="check-field"><input type="checkbox" name="is_primary" ${contact?.is_primary ? 'checked' : ''}> 主担当にする</label>
      ${textArea('メモ', 'note', contact?.note || '', { full: true })}
    </div>`;
    openModal({
      title: editing ? '連絡先を編集' : '連絡先を追加',
      subtitle: '顧客に紐づく担当者を登録します。',
      body,
      submitLabel: editing ? '更新する' : '追加する',
      wide: true,
      onSubmit: async form => {
        const values = formValues(form);
        const payload = {
          company_id: Number(values.company_id), name: values.name, title: values.title || '',
          email: values.email || '', phone: values.phone || '', mobile: values.mobile || '',
          note: values.note || '', is_primary: Boolean(values.is_primary)
        };
        await api(editing ? `/api/contacts/${contact.id}` : '/api/contacts', {
          method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload)
        });
        state.lookups = null;
        closeModal();
        toast(editing ? '連絡先を更新しました' : '連絡先を追加しました');
        await route();
      }
    });
  }

  async function openDealForm(deal = null, companyId = null) {
    await ensureLookups();
    const editing = Boolean(deal);
    const selectedCompany = deal?.company_id || companyId || state.lookups.companies[0]?.id || '';
    const body = `<div class="form-grid">
      ${companySelect(selectedCompany)}
      ${field('案件名', 'title', deal?.title || '', { required: true, maxlength: 160, placeholder: '基幹システム刷新' })}
      ${selectField('ステージ', 'stage', STAGES, deal?.stage || 'リード')}
      ${field('金額（円）', 'amount', deal?.amount ?? 0, { type: 'number', min: 0, step: 1000 })}
      ${field('確度（%）', 'probability', deal?.probability ?? 0, { type: 'number', min: 0, max: 100, step: 5 })}
      ${field('完了予定日', 'expected_close', deal?.expected_close || '', { type: 'date' })}
      ${field('担当者', 'owner', deal?.owner || '', { maxlength: 80 })}
      ${textArea('メモ', 'note', deal?.note || '', { full: true })}
    </div>`;
    openModal({
      title: editing ? '案件を編集' : '案件を追加',
      subtitle: '金額とステージを登録すると、パイプラインに反映されます。',
      body,
      submitLabel: editing ? '更新する' : '追加する',
      wide: true,
      onSubmit: async form => {
        const values = formValues(form);
        const payload = {
          company_id: Number(values.company_id), title: values.title, stage: values.stage,
          amount: Number(values.amount || 0), probability: Number(values.probability || 0),
          expected_close: values.expected_close || '', owner: values.owner || '', note: values.note || ''
        };
        await api(editing ? `/api/deals/${deal.id}` : '/api/deals', {
          method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload)
        });
        state.lookups = null;
        closeModal();
        toast(editing ? '案件を更新しました' : '案件を追加しました');
        await route();
      }
    });
  }

  async function openActivityForm(activity = null, companyId = null) {
    await ensureLookups();
    const selectedCompany = companyId || activity?.company_id || state.lookups.companies[0]?.id || '';
    const body = `<div class="form-grid">
      ${companySelect(selectedCompany)}
      ${selectField('種類', 'kind', Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label })), activity?.kind || 'meeting')}
      ${field('件名', 'subject', activity?.subject || '', { required: true, maxlength: 200, full: true, placeholder: '初回提案 / 定例ミーティング' })}
      ${selectField('連絡先', 'contact_id', contactOptions(selectedCompany, activity?.contact_id || ''), activity?.contact_id || '')}
      ${selectField('関連案件', 'deal_id', dealOptions(selectedCompany, activity?.deal_id || ''), activity?.deal_id || '')}
      ${field('日時', 'occurred_at', localDateTimeValue(activity?.occurred_at), { type: 'datetime-local', full: true })}
      ${textArea('内容', 'body', activity?.body || '', { full: true, placeholder: '話した内容、次回アクション、所感など' })}
    </div>`;
    const form = openModal({
      title: '活動を記録',
      subtitle: '商談・電話・メールなどの接点を残します。',
      body,
      submitLabel: '記録する',
      wide: true,
      onSubmit: async formNode => {
        const values = formValues(formNode);
        const payload = {
          company_id: Number(values.company_id), contact_id: values.contact_id ? Number(values.contact_id) : null,
          deal_id: values.deal_id ? Number(values.deal_id) : null, kind: values.kind,
          subject: values.subject, body: values.body || '', occurred_at: values.occurred_at || ''
        };
        await api('/api/activities', { method: 'POST', body: JSON.stringify(payload) });
        closeModal();
        toast('活動を記録しました');
        await route();
      }
    });
    const companySelectNode = form.elements.company_id;
    const contactSelect = form.elements.contact_id;
    const dealSelect = form.elements.deal_id;
    companySelectNode.addEventListener('change', () => {
      const value = Number(companySelectNode.value);
      contactSelect.innerHTML = contactOptions(value, '').map(option => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('');
      dealSelect.innerHTML = dealOptions(value, '').map(option => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('');
    });
  }

  async function openTaskForm(task = null, companyId = null) {
    await ensureLookups();
    const editing = Boolean(task);
    const selectedCompany = task?.company_id || companyId || state.lookups.companies[0]?.id || '';
    const body = `<div class="form-grid">
      ${companySelect(selectedCompany)}
      ${selectField('関連案件', 'deal_id', dealOptions(selectedCompany, task?.deal_id || ''), task?.deal_id || '')}
      ${field('タスク名', 'title', task?.title || '', { required: true, maxlength: 200, full: true, placeholder: '見積書を送付する' })}
      ${field('期限', 'due_date', task?.due_date || todayISO(), { type: 'date' })}
      ${selectField('優先度', 'priority', [{ value: 'high', label: '高' }, { value: 'medium', label: '中' }, { value: 'low', label: '低' }], task?.priority || 'medium')}
      ${field('メモ', 'note', task?.note || '', { maxlength: 2000, full: true })}
    </div>`;
    const form = openModal({
      title: editing ? 'タスクを編集' : 'タスクを追加',
      subtitle: '次のアクションを期限付きで管理します。',
      body,
      submitLabel: editing ? '更新する' : '追加する',
      wide: true,
      onSubmit: async form => {
        const values = formValues(form);
        const payload = {
          company_id: Number(values.company_id), deal_id: values.deal_id ? Number(values.deal_id) : null,
          title: values.title, due_date: values.due_date || '', priority: values.priority,
          status: task?.status || 'open', note: values.note || ''
        };
        await api(editing ? `/api/tasks/${task.id}` : '/api/tasks', {
          method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload)
        });
        closeModal();
        toast(editing ? 'タスクを更新しました' : 'タスクを追加しました');
        await route();
      }
    });
    form.elements.company_id.addEventListener('change', () => {
      form.elements.deal_id.innerHTML = dealOptions(Number(form.elements.company_id.value), '')
        .map(option => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('');
    });
  }

  init();
})();
