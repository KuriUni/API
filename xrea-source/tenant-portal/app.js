(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const defaultBase = () => `${window.location.origin}${(window.location.pathname.match(/^(.*)\/(?:tenant-portal|mobile-manager)(?:\/|$)/) || [])[1] || ''}`;
  const PAGE_SIZE = 100;
  let activeRequests = 0;
  const state = { base: '', environment: 'production', key: '', tenantSsoSession: '', tenant: '', memberships: [], page: 'overview', products: [], licenses: [], auditEvents: [], auditFilter: { operation: '', clientId: '', status: '' }, licenseFilter: { search: '', product: '' }, noticeTimer: 0, issuePending: null, taskBusy: false, taskVersion: 0, productSearch: '', billingPeriod: new Date().toISOString().slice(0,7), reissueBusy: false, authBusy: false, viewVersion: 0, connectionVersion: 0, stripeReturn: null };
  Object.assign(state,{selectedTenantId:0,tenantSelectionBusy:false,tenantLinkBusy:false});
  $('base-url').value = defaultBase();
  const ssoLoginBase = defaultBase();
  $('tenant-sso-login').href = `${ssoLoginBase}/admin_api.php?tenant_sso_start=1`;
  const titles = { overview: ['概要', 'ワークスペースの状況と、よく使う操作。'], products: ['製品', '製品とライセンス発行先を管理します。'], licenses: ['ライセンス', '発行済みライセンスの確認と新規発行ができます。'], billing: ['利用・請求', 'API利用と請求の集計を確認します。'], audit: ['操作履歴', '操作と通信の記録を、必要な条件で探せます。'], settings: ['設定・セキュリティ', '接続情報、SSO ID、APIキーを管理します。'] };
  const text = (value, fallback = '—') => value === null || value === undefined || value === '' ? fallback : String(value);
  const element = (tag, className, value) => { const node = document.createElement(tag); if (className) node.className = className; if (value !== undefined) node.textContent = String(value); return node; };
  const button = (label, action, style = 'button-secondary') => { const node = element('button', `button ${style}`, label); node.type = 'button'; node.addEventListener('click', action); return node; };
  const iconPaths = {
    grid: ['M3 3h7v7H3z','M14 3h7v7h-7z','M3 14h7v7H3z','M14 14h7v7h-7z'],
    box: ['M12 3 3 7.5v9L12 21l9-4.5v-9L12 3Z','m3 7.5 9 4.5 9-4.5','M12 12v9','m7.5 5.25 9 4.5'],
    key: ['M15.5 3a5.5 5.5 0 1 1-4.9 8L3 18.6V21h3v-3h3v-3l2.6-2.6','M16 7h.01'],
    receipt: ['M6 3h12v18l-3-2-3 2-3-2-3 2V3Z','M9 7h6','M9 11h6','M9 15h3'],
    history: ['M3 10a9 9 0 1 1 2 8','M3 4v6h6','M12 7v5l3 2'],
    shield: ['M12 3 4 6v6c0 4.5 8 9 8 9s8-4.5 8-9V6l-8-3Z','m8 12 3 3 5-6'],
    settings: ['M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1 1-3Z','M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z'],
    fingerprint: ['M4 9a8 8 0 0 1 16 0','M7 17v-6a5 5 0 0 1 10 0v5','M10 20v-9a2 2 0 1 1 4 0v7','M4 13v4','M17 20v-1','M13 22l1-1'],
    arrow: ['M4 12h16','m14 6 6 6-6 6'], chevron: ['m6 9 6 6 6-6'],
    plus: ['M12 5v14','M5 12h14'], close: ['m6 6 12 12','M18 6 6 18'],
    refresh: ['M20 7v5h-5','M4 17v-5h5','M6 6a8 8 0 0 1 13 4','M18 18a8 8 0 0 1-13-4'],
    logout: ['M9 4H4v16h5','M8 12h13','m16 7 5 5-5 5'],
    eye: ['M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z','M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z'],
    lock: ['M5 10h14v11H5z','M8 10V7a4 4 0 1 1 8 0v3','M12 14v3'],
    check: ['m5 12 4 4L19 6'], search: ['M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15Z','m16 16 5 5']
  };
  function icon(name) { const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'icon'); svg.setAttribute('aria-hidden', 'true'); for (const d of iconPaths[name] || iconPaths.grid) { const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', d); svg.append(path); } return svg; }
  document.querySelectorAll('[data-icon]').forEach((node) => node.replaceChildren(icon(node.dataset.icon)));
  function actionButton(label, name, action, style = 'button-secondary') { const node = button(label, action, style); node.prepend(icon(name)); return node; }
  function dateText(value) { if (!value) return '—'; const parsed = new Date(String(value).replace(' ', 'T') + (String(value).includes('Z') || /[+-]\d{2}:\d{2}$/.test(String(value)) ? '' : 'Z')); return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString('ja-JP', { year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' }); }
  function emptyState(title, description, name = 'box', action = null) { const node = element('div', 'empty-state'); node.append(icon(name), element('strong', '', title), element('p', '', description)); if (action) node.append(action); return node; }
  function showLoading() { const target = $('page-content'); resetNode(target); const node = element('div', 'loading-view'); const grid = element('div', 'skeleton-grid'); for (let i=0;i<4;i++) grid.append(element('div', 'skeleton-card')); node.append(element('p', 'loading-label', 'ワークスペースを読み込んでいます…'), grid, element('div', 'skeleton-panel')); target.append(node); target.setAttribute('aria-busy', 'true'); }
  function pageFailure(error, version) { if (version !== state.viewVersion || (!state.key && !state.tenantSsoSession)) return; const panelNode = panel('情報を読み込めませんでした', error.message); panelNode.append(actionButton('もう一度読み込む', 'refresh', () => { showLoading(); loadPage().catch((e) => pageFailure(e, state.viewVersion)); })); shell(panelNode, version); }
  function openTask(title, subtitle, content, category = 'WORKSPACE') { if (state.taskBusy) return; state.taskVersion++; $('task-title').textContent = title; $('task-subtitle').textContent = subtitle; $('task-category').textContent = category; $('task-content').replaceChildren(content); if (!$('task-dialog').open) $('task-dialog').showModal(); }
  function taskBusy(busy) { state.taskBusy = busy; $('close-task-dialog').disabled = busy; }
  function requestChoice(message, initial = null, title = '操作の確認') {
    return new Promise((resolve) => {
      const dialog = $('confirm-dialog'); $('confirm-title').textContent = title; $('confirm-message').textContent = message; $('confirm-input-host').replaceChildren();
      let input = null; if (initial !== null) { input = element('input'); input.value = initial; input.maxLength = 160; input.setAttribute('aria-label', title); $('confirm-input-host').append(input); }
      $('confirm-accept').textContent = initial !== null ? '保存する' : '続ける';
      const done = (accepted) => { cleanup(); dialog.close(); resolve(accepted ? (input ? input.value.trim() : true) : (input ? null : false)); };
      const accept = () => { if (input && !input.value.trim()) { input.focus(); return; } done(true); }; const cancel = () => done(false); const dismiss = (e) => { e.preventDefault(); cancel(); }; const enter = (e) => { if (e.key==='Enter' && input) { e.preventDefault(); accept(); } };
      const cleanup = () => { $('confirm-accept').removeEventListener('click',accept); $('confirm-cancel').removeEventListener('click',cancel); dialog.removeEventListener('cancel',dismiss); dialog.removeEventListener('keydown',enter); dialog.removeEventListener('close',cancel); };
      $('confirm-accept').addEventListener('click',accept); $('confirm-cancel').addEventListener('click',cancel); dialog.addEventListener('cancel',dismiss); dialog.addEventListener('keydown',enter); dialog.addEventListener('close',cancel); dialog.showModal(); if (input) { input.focus(); input.select(); } else $('confirm-cancel').focus();
    });
  }
  const confirmAction = (message) => requestChoice(message);
  const askText = (message, initial) => requestChoice(message, initial, message);
  function notice(message, error = false) { const box = $('notice'); window.clearTimeout(state.noticeTimer); box.textContent = message; box.classList.toggle('error', error); box.classList.remove('hidden'); box.setAttribute('role', error ? 'alert' : 'status'); state.noticeTimer = window.setTimeout(() => box.classList.add('hidden'), 6500); }
  function errorMessage(data, status) { const messages = { tenant_sso_admin_identity: 'Admin SSO identity detected. Signing out so you can continue with a contractor SSO ID.', sso_reauthentication_required: 'SSO IDで再認証してから5分以内に実行してください。', unauthorized: 'APIキーを確認してください。', invalid_api_key: 'APIキーが正しくないか、期限切れです。', insufficient_scope: 'この機能を使う権限がAPIキーにありません。管理者へ必要なスコープを確認してください。', server_not_writable: '現在は読み取り専用です。時間をおいて再度お試しください。', product_quota_exceeded: '契約プランの製品上限に達しています。', license_quota_exceeded: '契約プランのライセンス上限に達しています。', product_not_found: '発行先の製品を確認してください。', product_code_exists: 'この製品コードはすでに使われています。', invalid_license_mode: 'ライセンス方式が正しくありません。', invalid_portal_session: 'Passkeyセッションの有効期限が切れました。Passkeyで再接続してください。', unknown_credential: 'このPasskeyは登録されていないか、解除されています。', challenge_expired: '認証の有効期限が切れました。もう一度お試しください。', credential_already_registered: 'このPasskeyはすでに登録されています。', passkey_limit_reached: '登録できるPasskeyはテナントごとに25個までです。', passkey_management_key_required: 'Passkey管理には tenant:read と licenses:write 権限のあるAPIキーが必要です。', key_reissue_not_available: '登録元のAPIキーが失効・停止・期限切れのため再発行できません。管理者へお問い合わせください。', key_reissue_scope_mismatch: 'このPasskeyの権限では元のAPIキーを再発行できません。管理者へお問い合わせください。', key_reissue_result_expired: '再試行できる時間が過ぎたか、発行済みキーが失効しています。500円の請求記録を「利用・請求」で確認し、管理者へお問い合わせください。', key_reissue_request_owner_mismatch: '前回と同じPasskeyで再接続して再試行してください。', key_reissue_failed: '再発行結果を確認できませんでした。同じ画面から再試行してください。', stripe_not_configured: 'カード決済はまだ設定されていません。管理者へお問い合わせください。', invoice_not_payable: 'この請求書は現在お支払いできません。状態を確認してください。', invoice_not_found: '請求書が見つかりません。画面を再読み込みしてください。', stripe_checkout_completed: 'この請求書の決済はすでに完了しています。状態を更新してください。', stripe_live_sandbox_blocked: '本番決済はSandboxでは利用できません。', stripe_checkout_failed: '決済画面を開始できませんでした。時間をおいて再度お試しください。', key_reissue_pending: '決済を確認しています。少し待ってから再度お試しください。', key_reissue_result_ready: '前回の再発行は完了しています。結果を確認します。', key_reissue_result_expired: '決済結果の表示期限が切れたか、決済が完了していません。二重決済を避けるため管理者へお問い合わせください。', invoice_amount_invalid: '請求額を確認できないためカード決済を利用できません。管理者へお問い合わせください。', invoice_amount_too_small: '請求額が少ないためカード決済を利用できません。管理者へお問い合わせください。', rate_limited: 'APIアクセスが分速上限に達しました。1分ほど待ってから再度お試しください。', tenant_rate_limited: '契約全体のAPI分速上限に達しました。1分ほど待ってから再度お試しください。', api_monthly_limit_reached: '今月のAPI利用上限に達しました。契約管理者に上限の変更をご相談ください。', passkey_reauthentication_required: 'この操作は、Passkeyで再接続してから5分以内に実行してください。', tenant_api_key_required: '連携したAPIキーが無効・停止・期限切れ、または権限不足のためログインできません。有効なAPIキーを確認してください。', tenant_already_linked: 'このテナントはすでに共通IDに登録されています。', tenant_membership_required: 'この共通IDには選択したテナントが登録されていません。', common_id_sso_not_ready: '共通IDログインは利用できますが、別ドメインSSOのサーバー設定またはDB移行が未完了です。管理者へお知らせください。', tenant_sso_session_required: 'SSO IDのセッションが終了しました。SSO IDで再接続してください。', tenant_sso_ticket_invalid: 'SSO認証の有効期限が切れました。もう一度ログインしてください。' }; const code = String(data?.error || data?.error_code || ''); return messages[code] || data?.message || (code ? `${code} (HTTP ${status})` : `サーバーとの通信に失敗しました (HTTP ${status})`); }
  async function api(path, options = {}) {
    if(!state.key&&(!state.tenantSsoSession||!state.selectedTenantId))throw new Error('利用するテナント契約を選択してください。');
    const connection=state.connectionVersion;const headers=new Headers(options.headers||{});headers.set('Accept','application/json');if(state.key)headers.set('X-Tenant-API-Key',state.key);if(state.tenantSsoSession)headers.set('X-Tenant-SSO-Session',state.tenantSsoSession);headers.set('X-BaaS-Environment',state.environment);if(options.body!==undefined)headers.set('Content-Type','application/json');if(options.idempotency)headers.set('Idempotency-Key',options.idempotency);
    const controller=new AbortController();const deadline=window.setTimeout(()=>controller.abort(),45000);activeRequests++;$('page-content').setAttribute('aria-busy','true');
    try{const response=await fetch(`${state.base}${path}`,{method:options.method||'GET',headers,body:options.body===undefined?undefined:JSON.stringify(options.body),signal:controller.signal,cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});let data={};try{data=await response.json();}catch{throw new Error('サーバーの応答を読み取れませんでした。同じ画面から再試行してください。');}if(connection!==state.connectionVersion)throw new Error('接続が変更されました。');if(!response.ok||data.ok===false){const message=errorMessage(data,response.status);if(response.status===401&&state.tenantSsoSession){disconnect(false);$('connect-error').textContent=message;}throw new Error(message);}return data;}
    catch(error){if(error.name==='AbortError')throw new Error('応答に時間がかかっています。同じ内容で再試行してください。');throw error;}
    finally{window.clearTimeout(deadline);activeRequests=Math.max(0,activeRequests-1);if(!activeRequests)$('page-content').setAttribute('aria-busy','false');}
  }
  function setConnected(tenant, environment, page='overview') { state.selectedTenantId=state.tenantSsoSession?Number(state.memberships.find(item=>item.slug===tenant&&item.environment===environment)?.tenant_id||0):0; $('tenant-choice-panel').hidden=true; $('tenant-sso-link-panel').hidden=true; state.tenant = tenant || '接続済みテナント'; state.environment = environment || 'production'; $('tenant-name').textContent = state.tenant; $('tenant-initial').textContent = state.tenant.slice(0,1).toUpperCase(); $('auth-label').textContent = state.tenantSsoSession ? 'SSO ID' : 'APIキー接続'; $('account-settings').classList.remove('hidden'); $('env-label').textContent = state.environment.toUpperCase(); $('env-label').classList.toggle('sandbox',state.environment==='sandbox'); $('connection-state').classList.add('connected'); $('connection-state').replaceChildren(element('i'), document.createTextNode('接続中')); $('connect-view').classList.add('hidden'); $('portal-view').classList.remove('hidden'); $('disconnect').classList.remove('hidden');     const selector=$('tenant-switcher');selector.replaceChildren();for(const item of state.memberships){const option=element('option','',`${item.name||item.slug} · ${String(item.environment).toUpperCase()} · ${contractKeyLabel(item)}`);option.value=String(item.tenant_id);option.selected=Number(item.tenant_id)===state.selectedTenantId;selector.append(option);}selector.classList.toggle('hidden',(!state.tenantSsoSession)||state.memberships.length<2);$('switch-tenant').classList.toggle('hidden',(!state.tenantSsoSession)||state.memberships.length<2); setPage(page); handleStripeReturn(); if (takeReissueResume() && state.tenantSsoSession) { void openKeyReissue(); } }
  function reissueStorageKey() { return `tuti-key-reissue:${state.base}:${state.environment}:${state.tenant}`; }
  function readPendingReissue() { try { return window.sessionStorage.getItem(reissueStorageKey()) || ''; } catch { return ''; } }
  function setPendingReissue(value) { try { if (value) window.sessionStorage.setItem(reissueStorageKey(), value); else window.sessionStorage.removeItem(reissueStorageKey()); return true; } catch { return false; } }
  function reissueResumeKey() { return 'tuti-key-reissue-resume'; }
  function setReissueResume(value) { try { if (value) window.sessionStorage.setItem(reissueResumeKey(), '1'); else window.sessionStorage.removeItem(reissueResumeKey()); } catch {} }
  function takeReissueResume() { try { const active = window.sessionStorage.getItem(reissueResumeKey()) === '1'; window.sessionStorage.removeItem(reissueResumeKey()); return active; } catch { return false; } }
  function ssoReauthUrl() { return String(state.base || defaultBase()).replace(/\/+$/, '') + '/admin_api.php?tenant_sso_start=1&step_up=1'; }
  function startSsoReauth() { setReissueResume(true); window.location.assign(ssoReauthUrl()); }
  function reissueKeyView(result) {
    const host = element('div');
    host.append(element('p', '', result.paid_immediately ? 'お支払いが完了しました。再発行料500円（税込）をStripeで即時決済し、新しいAPIキーを発行しました。' : `再発行しました。再発行料500円（税込）を${text(result.billing_period)}の請求書に加算します。`));
    if (result.old_key_expires_at_utc) host.append(element('p', '', `旧キーの切替期限（UTC）: ${result.old_key_expires_at_utc}`));
    const key = element('input', 'mono'); key.type = 'text'; key.readOnly = true; key.value = result.api_key; key.autocomplete = 'off'; key.spellcheck = false; key.setAttribute('aria-label', '再発行されたAPIキー');
    const copied = element('p', 'form-foot');
    const copy = button('APIキーをコピー', async () => { try { await navigator.clipboard.writeText(key.value); copied.textContent = 'コピーしました。安全な場所に保管してください。'; } catch { key.focus(); key.select(); copied.textContent = 'キーを選択しました。手動でコピーしてください。'; } });
    host.append(key, copy, copied, element('p', 'form-foot', '閉じるとキーの表示を消去します。次の再発行には再び500円がかかります。'));
    if (result.paid_immediately && result.mode === 'test') host.append(element('p', 'form-foot', 'Stripeテストモードの決済です。'));
    return host;
  }
  async function openKeyReissueResult(requestId) {
    if (!state.tenantSsoSession) return;
    const dialog = $('reissue-dialog');
    $('reissue-content').replaceChildren(element('p', 'loading-label', '決済結果を確認しています…'));
    if (!dialog.open) dialog.showModal();
    let last = null;
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        const result = await api('/api/baas/v1/tenant-sso.php', { method: 'POST', body: { action: 'key_reissue_result', request_id: requestId } });
        setPendingReissue('');
        $('reissue-content').replaceChildren(reissueKeyView(result));
        return;
      } catch (error) {
        last = error;
        if (!String(error.message).includes('確認中')) break;
        await new Promise((resolve) => window.setTimeout(resolve, 2500));
      }
    }
    const host = $('reissue-content'); host.replaceChildren();
    host.append(element('p', 'form-error', last ? last.message : '決済結果を確認できませんでした。'));
    host.append(button('結果を再確認', () => openKeyReissueResult(requestId), 'button-secondary'));
    host.append(element('p', 'form-foot', '決済が完了しているのに表示できない場合は、二重決済を避けるため管理者へお問い合わせください。'));
  }
  async function openKeyReissue() {
    if (!state.tenantSsoSession || state.reissueBusy) return;
    const host = $('reissue-content'); host.replaceChildren(element('p', 'loading-label', '請求方法を確認しています…'));
    if (!$('reissue-dialog').open) $('reissue-dialog').showModal();
    let methods = { stripe: { enabled: false } };
    try { methods = await api('/api/baas/v1/tenant-sso.php', { method: 'POST', body: { action: 'billing_methods' } }); } catch { methods = { stripe: { enabled: false } }; }
    if (!$('reissue-dialog').open) return;
    const immediate = Boolean(methods && methods.stripe && methods.stripe.enabled);
    const pending = readPendingReissue();
    host.replaceChildren();
    const price = element('div', 'reissue-price'); const priceCopy = element('div');
    priceCopy.append(element('b', '', 'APIキー再発行料'), element('small', '', immediate ? 'カードで即時決済' : '月次請求書に加算'));
    const amount = element('strong', '', immediate ? '¥500相当' : '¥500'); amount.append(element('span', '', ' / 回・税込'));
    price.append(priceCopy, amount); host.append(price);
    host.append(element('p', '', immediate
      ? '元のAPIキーは再表示できないため、新しいAPIキーを発行します。日本円500円を基準に、Stripe決済画面で日本円または対応する現地通貨を選んで即時決済できます。決済完了後に新しいキーを表示します。Sandboxも同額です。'
      : '元のAPIキーは再表示できないため、新しいAPIキーを発行します。再発行料は1回500円（税込）で、月次請求書に加算されます。Sandboxも同額です。'));
    host.append(element('p', '', '旧キーは60分後に無効になります（元の有効期限が先に来る場合はその期限まで）。利用中のアプリのAPIキーを切り替えてください。新しいキーの権限・有効期限は引き継ぎます。'));
    host.append(element('p', 'form-foot', immediate
      ? 'SSO ID認証から5分以内に実行してください。決済後にWebhookでキーが有効化され、この画面にキーが表示されます。通信に失敗しても、同じリクエストIDで結果を取得できます。'
      : 'SSO ID認証から5分以内に実行してください。キーはこの画面で確認・コピーし、安全に保管してください。閉じると画面から消去します。通信に失敗した場合は、同じSSO IDで10分以内に再試行すると追加請求せず結果を取得できます。'));
    if (pending) host.append(element('p', 'invoice-test-warning', immediate ? '前回の決済が残っています。同じリクエストの再試行では追加請求されません。' : '前回の再発行結果を確認します。同じリクエストの再試行では追加の500円は発生しません。'));
    const agreement = element('label', 'checkbox-confirm'); const checkbox = element('input'); checkbox.type = 'checkbox';
    agreement.append(checkbox, element('span', '', immediate ? '日本円500円相当の即時決済（選択通貨により為替換算手数料が加算される場合があります）と、旧キーの切替期限を確認しました。' : '再発行料500円（税込）の月次請求への加算と、旧キーの切替期限を確認しました。'));
    host.append(agreement);
    const errorBox = element('p', 'form-error'); errorBox.setAttribute('role', 'alert');
    let reauthArmed = false;
    const submit = button(immediate ? (pending ? '前回の決済結果を確認' : '500円相当を支払って再発行') : (pending ? '前回の結果を再取得' : '500円で再発行する'), async () => {
      if (state.reissueBusy || !state.tenantSsoSession || !checkbox.checked) return;
      if (reauthArmed) { startSsoReauth(); return; }
      if (immediate && pending) { openKeyReissueResult(pending); return; }
      let requestId = pending;
      if (!requestId) {
        requestId = crypto.randomUUID().replaceAll('-', '');
        if (!setPendingReissue(requestId)) { errorBox.textContent = '二重決済防止のため、この操作にはブラウザーのセッションストレージが必要です。'; return; }
      }
      state.reissueBusy = true; submit.disabled = true; $('close-reissue-dialog').disabled = true; errorBox.textContent = '';
      try {
        if (immediate) {
          const result = await api('/api/baas/v1/tenant-sso.php', { method: 'POST', idempotency: requestId, body: { action: 'create_key_reissue_checkout', confirm_fee_yen: 500 } });
          if (result && result.checkout_url) { notice('Stripeの決済画面へ移動します。'); window.location.assign(result.checkout_url); return; }
          errorBox.textContent = '決済画面を開始できませんでした。';
        } else {
          const result = await api('/api/baas/v1/tenant-sso.php', { method: 'POST', idempotency: requestId, body: { action: 'reissue_api_key', confirm_fee_yen: 500 } });
          setPendingReissue('');
          host.replaceChildren(reissueKeyView(result));
        }
      } catch (error) {
        if (immediate && (String(error.message).includes('確認中') || String(error.message).includes('完了しています'))) { openKeyReissueResult(requestId); return; }
        if (String(error.message).includes('SSO IDで再認証')) {
          reauthArmed = true;
          errorBox.textContent = error.message;
          submit.textContent = 'SSO IDで再認証';
          submit.disabled = false;
          return;
        }
        errorBox.textContent = error.message;
        submit.textContent = '同じリクエストで再試行';
      } finally {
        state.reissueBusy = false;
        if ($('reissue-dialog').open) submit.disabled = !checkbox.checked;
        $('close-reissue-dialog').disabled = false;
      }
    }, 'button-primary');
    submit.disabled = true;
    checkbox.addEventListener('change', () => { submit.disabled = !checkbox.checked || state.reissueBusy; });
    host.append(submit, errorBox);
    if (immediate && pending) host.append(button('決済結果を再確認', () => openKeyReissueResult(pending), 'button-secondary'));
    if (immediate && pending) host.append(button('前回の決済を確認できず、新しく支払う', async () => {
      if (state.reissueBusy || !await confirmAction('前回の決済が完了している場合、新しく支払うと二重請求になります。決済履歴を確認してから続けてください。新しく支払いますか？')) return;
      if (!setPendingReissue('')) { notice('リクエスト情報を消去できませんでした。', true); return; }
      $('reissue-dialog').close(); openKeyReissue();
    }, 'button-quiet'));
    if (!immediate && pending) host.append(button('新しい再発行を開始（別途500円）', async () => {
      if (state.reissueBusy || !await confirmAction('前回の再発行が完了している場合は、その500円に加えて、新しい再発行に500円がかかります。前回の結果取得を終了して、新しい再発行の確認画面を開きますか？')) return;
      if (!setPendingReissue('')) { errorBox.textContent = '前回のリクエスト情報を消去できませんでした。'; return; }
      $('reissue-dialog').close(); openKeyReissue();
    }));
  }

  function handleStripeReturn() {
    const hash = String(window.location.hash || '');
    const match = hash.match(/^#stripe=(success|cancel)(?:&|$)/);
    const stashed = state.stripeReturn;
    if (!match && !stashed) return;
    const params = new URLSearchParams(hash.replace(/^#/, ''));
    const status = match ? match[1] : (stashed && stashed.status);
    const reissue = params.get('reissue') || (stashed && stashed.reissue);
    state.stripeReturn = null;
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    if (!status) return;
    if (reissue) {
      if (status === 'success') { setPage('settings'); notice('決済を受け付けました。結果を確認しています…'); void openKeyReissueResult(reissue); }
      else { setPage('settings'); notice('カード決済をキャンセルしました。', true); }
      return;
    }
    notice(status === 'success' ? 'Stripeの決済画面から戻りました。反映には少し時間がかかる場合があります。' : 'カード決済をキャンセルしました。', status !== 'success');
    setPage('billing');
  }
  function resetNode(node) { node.replaceChildren(); }
  function panel(title, subtitle = '') { const card = element('section', 'panel'); const head = element('div', 'panel-heading'); const copy = document.createElement('div'); copy.append(element('h2', '', title)); if (subtitle) copy.append(element('p', '', subtitle)); head.append(copy); card.append(head); return card; }
  function metric(label, value, foot = '') { const card = element('article', 'metric-card'); card.append(element('div', 'metric-label', label), element('div', 'metric-value', Number(value || 0).toLocaleString('ja-JP'))); if (foot) card.append(element('div', 'metric-foot', foot)); return card; }
  function table(headers, rows) { const wrap = element('div', 'table-wrap'); const tableNode = document.createElement('table'); const thead = document.createElement('thead'); const headRow = document.createElement('tr'); headers.forEach((header) => { const th = element('th', '', header); th.scope='col'; headRow.append(th); }); thead.append(headRow); tableNode.append(thead); const body = document.createElement('tbody'); rows.forEach((row) => { const tr = document.createElement('tr'); row.forEach((value, index) => { const td = document.createElement('td'); td.dataset.label = headers[index]; if (value instanceof Node) td.append(value); else td.textContent = text(value); tr.append(td); }); body.append(tr); }); if (!rows.length) { const tr = document.createElement('tr'); const td = element('td', 'empty-state', 'まだデータがありません。登録後にここへ表示されます。'); td.colSpan = headers.length; tr.append(td); body.append(tr); } tableNode.append(body); wrap.append(tableNode); return wrap; }
  function statusBadge(status) { const known = { active: ['有効', 'active'], retiring: ['切替中', 'paused'], expired: ['期限切れ', 'inactive'], suspended: ['停止中', 'inactive'], archived: ['アーカイブ', 'archived'], inactive: ['停止', 'inactive'], revoked: ['失効', 'inactive'], deleted: ['削除済み', 'deleted'], issued: ['未払い', 'paused'], paid: ['入金済み', 'active'] }; const item = known[String(status)] || [text(status), '']; return element('span', `badge ${item[1]}`, item[0]); }
  function shell(content, version = state.viewVersion) { if (version !== state.viewVersion || (!state.key && !state.tenantSsoSession)) return; const target=$('page-content'); resetNode(target); target.append(content); target.setAttribute('aria-busy','false'); $('updated-at').textContent=`更新 ${new Date().toLocaleTimeString('ja-JP',{hour:'2-digit',minute:'2-digit'})}`; }
  function setPage(page) { if (!titles[page] || (!state.key && (!state.tenantSsoSession||!state.selectedTenantId))) return; state.page=page; document.querySelectorAll('.nav-item').forEach((item) => { const selected=item.dataset.page===page; item.classList.toggle('active',selected); if(selected)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current'); }); $('page-title').textContent=titles[page][0]; $('page-subtitle').textContent=titles[page][1]; document.title=`${titles[page][0]} · TUTI BaaS`; $('page-title').focus({preventScroll:true}); showLoading(); loadPage().catch((error) => pageFailure(error,state.viewVersion)); }
  async function connect(event) { event.preventDefault(); if(state.authBusy)return; $('connect-error').textContent = ''; const inputKey = $('api-key').value.trim(); let base; try { base = new URL($('base-url').value.trim()); } catch { $('connect-error').textContent = 'API接続先のURLを確認してください。'; return; } if (base.protocol !== 'https:') { $('connect-error').textContent = 'API接続先にはHTTPSのURLを入力してください。'; return; } if (base.origin !== window.location.origin || base.pathname.replace(/\/$/, '') !== (defaultBase().endsWith('/license') ? '/license' : '')) { $('connect-error').textContent = 'API接続先には、このポータルと同じホストのAPIルートを指定してください。'; return; } if (!/^baas_(prod|sandbox)_/.test(inputKey)) { $('connect-error').textContent = 'Tenant APIキーの形式を確認してください。'; return; } const environment = $('environment').value; if ((environment === 'production') !== inputKey.startsWith('baas_prod_')) { $('connect-error').textContent = '選択した環境とAPIキーの種類が一致しません。'; return; } state.authBusy=true; $('connect-submit').disabled=true; $('connect-submit').textContent='接続しています…'; state.connectionVersion++; state.base = base.href.replace(/\/+$/, ''); state.environment = environment; state.key = inputKey;  state.tenantSsoSession = ''; $('api-key').value = ''; try { const result = await api('/api/baas/v1/status.php'); setConnected(result.tenant?.slug, environment); } catch (error) { state.key=''; $('connect-error').textContent=error.message; } finally { state.authBusy=false; $('connect-submit').disabled=false; $('connect-submit').replaceChildren(document.createTextNode('APIキーで接続'),icon('arrow')); } }
  async function logoutPortal() {
    const token=state.tenantSsoSession;
    const base=state.base||defaultBase();
    const environment=state.environment;
    $('disconnect').disabled=true;
    if(token){
      try{
        await fetch(base+'/api/baas/v1/tenant-sso.php',{
          method:'POST',
          headers:{'Content-Type':'application/json','X-Tenant-SSO-Session':token,'X-BaaS-Environment':environment},
          body:JSON.stringify({action:'logout'}),
          cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'
        });
      }catch{}
    }
    state.tenantSsoSession='';
    disconnect(false);
    $('disconnect').disabled=false;
    if(token){
      const returnTo=window.location.origin+window.location.pathname;
      const logoutUrl=new URL('https://sso.2415.jp/logout');
      logoutUrl.searchParams.set('post_logout_redirect_uri',returnTo);
      window.location.assign(logoutUrl.href);
    }
  }
  function disconnect(endCommonId = true) { const endProviderSession=Boolean(state.tenantSsoSession&&endCommonId); if(state.tenantSsoSession&&state.base)fetch(`${state.base}/api/baas/v1/tenant-sso.php`,{method:'POST',headers:{'Content-Type':'application/json','X-Tenant-SSO-Session':state.tenantSsoSession,'X-BaaS-Environment':state.environment},body:JSON.stringify({action:'logout'}),cache:'no-store',credentials:'omit',keepalive:true}).catch(()=>{});  state.connectionVersion++; state.viewVersion++; state.key = '';  state.tenantSsoSession = ''; state.base = ''; state.tenant = ''; state.memberships = []; state.selectedTenantId=0; state.tenantSelectionBusy=false; state.tenantLinkBusy=false; $('tenant-choice-panel').hidden=true; $('tenant-choice-list').replaceChildren(); $('tenant-choice-error').textContent=''; $('tenant-sso-link-panel').hidden=true; $('tenant-sso-api-key').value=''; $('tenant-sso-link-error').textContent=''; $('tenant-sso-login').hidden=false; $('api-connect-details').hidden=false; state.products = []; state.licenses = []; state.issuePending = null; state.productSearch='';state.licenseFilter={search:'',product:''};state.auditFilter={operation:'',clientId:'',status:''};state.billingPeriod=new Date().toISOString().slice(0,7);$('api-key').value = ''; $('connect-form').reset(); $('base-url').value = defaultBase(); $('api-key').type='password'; $('toggle-key').setAttribute('aria-pressed','false'); $('toggle-key').setAttribute('aria-label','APIキーを表示'); $('account-settings').classList.add('hidden'); $('reissue-dialog').close();$('reissue-content').replaceChildren();$('task-dialog').close(); $('confirm-dialog').close();  $('task-content').replaceChildren(); $('connect-error').textContent=''; $('notice').classList.add('hidden'); document.title='TUTI BaaS · 契約者ポータル'; $('connect-view').classList.remove('hidden'); $('portal-view').classList.add('hidden'); $('disconnect').classList.add('hidden');       $('connection-state').classList.remove('connected'); $('connection-state').textContent = '未接続'; const dot = document.createElement('i'); $('connection-state').prepend(dot); resetNode($('page-content')); if(endProviderSession){const returnTo=`https://${window.location.host}${window.location.pathname}`;window.location.assign(`https://sso.2415.jp/logout?post_logout_redirect_uri=${encodeURIComponent(returnTo)}`);} }
  async function loadPage() { const views={overview,products:productsPage,licenses:licensesPage,billing:billingPage,audit:auditPage,settings:settingsPage};const pending=views[state.page]?.();const version=state.viewVersion;try{await pending;}catch(error){if(version===state.viewVersion)throw error;} }
  async function overview() {
    const version=++state.viewVersion;
    const [status,products,licenses]=await Promise.all([api('/api/baas/v1/status.php'),api(`/api/baas/v1/products.php?limit=${PAGE_SIZE}`),api(`/api/baas/v1/licenses.php?limit=${PAGE_SIZE}`)]);
    if(version!==state.viewVersion)return; state.products=products.products||[];state.licenses=licenses.licenses||[];
    const root=document.createDocumentFragment(); const banner=element('section','overview-banner');const copy=element('div');copy.append(element('p','eyebrow','WORKSPACE OVERVIEW'),element('h2','',`${state.tenant} のワークスペース`),element('p','','製品の管理からライセンス発行まで、ここから始められます。'));
    const actions=element('div','quick-actions');actions.append(actionButton('製品を追加','plus',()=>{setPage('products');openProductForm();}),actionButton('ライセンスを発行','key',()=>{setPage('licenses');openLicenseForm();},'button-primary'));banner.append(copy,actions);root.append(banner);
    const active=Number(status.usage?.active_licenses||0), total=Number(status.usage?.licenses||0);const grid=element('div','metric-grid');
    [['製品',status.usage?.products,'登録されている製品','box'],['ライセンス',total,'発行済みのライセンス','key'],['有効なライセンス',active,'利用できるライセンス','check'],['停止中のライセンス',Math.max(0,total-active),'利用を停止したライセンス','lock']].forEach(([label,value,foot,name])=>{const card=metric(label,value,foot);const mark=element('span','metric-symbol');mark.append(icon(name));card.append(mark);grid.append(card);});root.append(grid);
    const columns=element('div','two-column');const recent=panel('最近のライセンス','直近の発行記録を確認できます。');recent.querySelector('.panel-heading').append(button('すべて見る',()=>setPage('licenses'),'button-quiet'));
    if(state.licenses.length)recent.append(table(['ID','製品','ラベル','状態','発行日'],state.licenses.slice(0,5).map(row=>[row.id,row.product_code,row.label,statusBadge(Number(row.active)?'active':'inactive'),dateText(row.created_at)])));else recent.append(emptyState('最初のライセンスを発行しましょう','製品を登録すると、その製品のライセンスを発行できます。','key',actionButton('製品を管理','box',()=>setPage('products'))));
    const health=panel('ライセンスの稼働状況','発行済みライセンスの状態');const summary=element('div','health-summary');summary.append(element('strong','',total?`${Math.round(active/total*100)}%`:'—'),element('span','','有効なライセンスの割合'));const track=element('div','health-track');const progress=element('progress');progress.max=Math.max(1,total);progress.value=active;progress.setAttribute('aria-label',`${total}件中${active}件が有効`);track.append(progress);const legend=element('div','health-legend');legend.append(element('span','',`有効 ${active}件`),element('span','',`停止 ${Math.max(0,total-active)}件`));const secure=element('div','overview-security');const securityCopy=element('div');securityCopy.append(element('strong','',state.tenantSsoSession?'SSO IDで接続中':'SSO IDで接続'),element('p','','認証情報はSSOサービスで管理します。'),button('セキュリティ設定を見る',()=>setPage('settings'),'button-quiet'));secure.append(icon('shield'),securityCopy);health.append(summary,track,legend,secure);columns.append(recent,health);root.append(columns);shell(root,version);
  }
  function contractKeyLabel(contract){return [contract.key_name||'連携APIキー',contract.key_prefix?`${contract.key_prefix}…`:'',contract.source_client_id?`ID ${contract.source_client_id}`:''].filter(Boolean).join(' · ');}
  function clearTenantWorkspace(){
    state.selectedTenantId=0;state.tenant='';state.connectionVersion++;state.viewVersion++;
    state.products=[];state.licenses=[];state.auditEvents=[];state.issuePending=null;state.productSearch='';state.licenseFilter={search:'',product:''};state.auditFilter={operation:'',clientId:'',status:''};
    state.taskVersion++;$('task-dialog').close();$('task-content').replaceChildren();$('reissue-dialog').close();$('reissue-content').replaceChildren();$('confirm-dialog').close();$('page-content').replaceChildren();
  }
  function showTenantChoice(message=''){
    clearTenantWorkspace();$('connect-view').classList.remove('hidden');$('portal-view').classList.add('hidden');$('account-settings').classList.add('hidden');$('disconnect').classList.remove('hidden');
    $('tenant-sso-login').hidden=true;$('api-connect-details').hidden=true;$('tenant-sso-link-panel').hidden=true;$('tenant-choice-panel').hidden=false;$('connect-error').textContent=message;
    $('connection-state').classList.remove('connected');$('connection-state').textContent='SSO認証済み · 契約を選択';
    const list=$('tenant-choice-list');list.replaceChildren(element('legend','','連携済みのテナント契約'));
    for(const contract of state.memberships){
      const label=element('label','contract-option'),radio=element('input');radio.type='radio';radio.name='tenant-contract';radio.value=String(contract.tenant_id);radio.required=true;
      const copy=element('span','contract-option-copy');copy.append(element('strong','',contract.name||contract.slug),element('span','contract-identity',`${contract.slug} · ${contract.environment==='sandbox'?'検証環境（Sandbox）':'本番環境（Production）'}`),element('span','contract-key',contractKeyLabel(contract)),element('span','contract-scopes',`権限：${(contract.scopes||[]).join(' / ')}`));
      label.append(radio,copy);radio.addEventListener('change',()=>{$('tenant-choice-submit').disabled=state.tenantSelectionBusy;$('tenant-choice-error').textContent='';});list.append(label);
    }
    $('tenant-choice-submit').disabled=true;$('tenant-choice-error').textContent='';$('tenant-choice-title').focus();
  }
  async function selectTenantContract(tenantId){
    if(!state.tenantSsoSession||!tenantId||state.tenantSelectionBusy||state.reissueBusy||state.taskBusy)return;
    const token=state.tenantSsoSession;state.tenantSelectionBusy=true;showTenantChoice();$('tenant-choice-submit').textContent='契約を確認しています…';$('tenant-choice-add').disabled=true;
    try{
      const result=await tenantSsoRequest('switch_tenant',{tenant_id:tenantId});
      const tenant=(result.memberships||[]).find(x=>Number(x.tenant_id)===tenantId);if(!tenant)throw new Error('選択した契約を利用できません。契約一覧を更新して確認してください。');
      state.memberships=result.memberships;state.selectedTenantId=tenantId;state.environment=tenant.environment;
      await api('/api/baas/v1/status.php');setConnected(tenant.slug,tenant.environment);
      $('tenant-choice-panel').hidden=true;$('tenant-sso-link-panel').hidden=true;notice(`${tenant.name||tenant.slug} · ${contractKeyLabel(tenant)} で接続しました。`);
    }catch(error){if(state.tenantSsoSession===token){showTenantChoice();$('tenant-choice-error').textContent=error.message||'選択した契約へ接続できませんでした。再選択してください。';}}
    finally{if(state.tenantSsoSession===token){state.tenantSelectionBusy=false;$('tenant-choice-submit').textContent='選択した契約で接続';$('tenant-choice-add').disabled=false;}}
  }
  async function switchTenant(){await selectTenantContract(Number($('tenant-switcher').value));}
  async function linkTenant() {
    if(!state.tenantSsoSession||state.tenantLinkBusy)return;const input=$('common-id-api-key');const key=input.value.trim();
    if(!/^baas_(?:prod|live|sandbox)_[A-Za-z0-9_-]{32,120}$/.test(key)){notice('リンク先テナントのTenant APIキーを確認してください。',true);return;}
    const env=key.startsWith('baas_sandbox_')?'sandbox':'production';
    state.tenantLinkBusy=true;
    try{const data=await tenantSsoRequest('link_tenant',{select_tenant:false},key,env);state.memberships=data.memberships||[];input.value='';showTenantChoice('契約をSSO IDへ追加しました。利用する契約を選択してください。');}
    catch(error){notice(error.message||'テナントを追加できませんでした。',true);}
    finally{input.value='';state.tenantLinkBusy=false;}
  }

  async function tenantSsoRequest(action,body={},apiKey='',environment=state.environment){
    const session=state.tenantSsoSession;
    const headers=new Headers({'Accept':'application/json','Content-Type':'application/json','X-Tenant-SSO-Session':state.tenantSsoSession,'X-BaaS-Environment':environment});
    if(apiKey)headers.set('X-Tenant-API-Key',apiKey);
    const response=await fetch(`${state.base||defaultBase()}/api/baas/v1/tenant-sso.php`,{method:'POST',headers,body:JSON.stringify({action,...body}),cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
    const data=await response.json().catch(()=>({}));if(state.tenantSsoSession!==session)throw new Error('接続が変更されました。');if(!response.ok||data.ok===false){const message=errorMessage(data,response.status);if(response.status===401&&state.tenantSsoSession){disconnect(false);$('connect-error').textContent=message;}throw new Error(message);}return data;
  }

  if(new URLSearchParams(window.location.search).get('state')==='tenant-admin-identity'){history.replaceState(null,'',window.location.pathname);$('connect-error').textContent='\u7ba1\u7406\u8005SSO\u30bb\u30c3\u30b7\u30e7\u30f3\u3092\u7d42\u4e86\u3057\u307e\u3057\u305f\u3002\u5951\u7d04\u8005\u7528SSO ID\u3067\u30ed\u30b0\u30a4\u30f3\u3057\u3066\u304f\u3060\u3055\u3044\u3002';}
  async function restoreTenantSsoTicket(){
    const match=window.location.hash.match(/(?:^#|&)sso_ticket=([A-Za-z0-9_-]{43})(?:&|$)/);if(!match)return;
    const returnParams=new URLSearchParams(window.location.hash.replace(/^#/,''));
    state.stripeReturn={status:returnParams.get('stripe'),reissue:returnParams.get('reissue')};
    history.replaceState(null,'',window.location.pathname+window.location.search);
    $('connect-error').textContent='SSO IDを確認しています…';
    try{const response=await fetch(`${defaultBase()}/api/baas/v1/tenant-sso.php`,{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/json'},body:JSON.stringify({action:'bootstrap',ticket:match[1]}),cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});const data=await response.json().catch(()=>({}));if(data.error==='tenant_sso_admin_identity'){const returnTo=window.location.origin+window.location.pathname;const logoutUrl=new URL('https://sso.2415.jp/logout');logoutUrl.searchParams.set('post_logout_redirect_uri',returnTo);logoutUrl.searchParams.set('state','tenant-admin-identity');window.location.replace(logoutUrl.href);return;}if(!response.ok||!data.ok)throw new Error(errorMessage(data,response.status));state.base=defaultBase();state.key='';state.tenantSsoSession=data.session_token;state.memberships=data.memberships||[];state.connectionVersion++;
      if(state.memberships.length>1){showTenantChoice('SSO IDを確認しました。利用するテナントとAPIキーを選択してください。');}
      else if(state.memberships.length===1){const tenant=state.memberships[0];state.selectedTenantId=Number(tenant.tenant_id);state.environment=tenant.environment;await api('/api/baas/v1/status.php');setConnected(tenant.slug,tenant.environment);}
      else{$('connect-error').textContent='SSO IDを確認しました。契約APIキーを入力して連携してください。';$('tenant-sso-link-panel').hidden=false;$('tenant-sso-login').hidden=true;$('api-connect-details').hidden=true;$('tenant-sso-api-key').focus();}
    }catch(error){if(state.tenantSsoSession)disconnect(false);$('connect-error').textContent=error.message||'SSO IDを確認できませんでした。もう一度ログインしてください。';}
  }

  async function linkFirstTenant(event){
    event.preventDefault();if(!state.tenantSsoSession||state.tenantLinkBusy||state.tenantSelectionBusy)return;const input=$('tenant-sso-api-key'),button=$('tenant-sso-link-submit'),key=input.value.trim();$('tenant-sso-link-error').textContent='';
    if(!/^baas_(?:prod|live|sandbox)_[A-Za-z0-9_-]{32,120}$/.test(key)){$('tenant-sso-link-error').textContent='Tenant APIキーの形式を確認してください。';return;}
    const environment=key.startsWith('baas_sandbox_')?'sandbox':'production';state.tenantLinkBusy=true;button.disabled=true;button.textContent='APIキーを確認しています…';
    try{const result=await tenantSsoRequest('link_tenant',{select_tenant:false},key,environment);input.value='';state.memberships=result.memberships||[];showTenantChoice('契約APIを共通SSO IDへ追加しました。利用する契約を選択してください。');}
    catch(error){$('tenant-sso-link-error').textContent=error.message||'APIキーを連携できませんでした。';}
    finally{input.value='';state.tenantLinkBusy=false;button.disabled=false;button.textContent='このテナントをSSO IDに連携';}
  }
  async function settingsPage() {
    const version=++state.viewVersion;
    const root=element('div','security-grid');
    const connection=panel('接続情報','現在のワークスペースと認証方法');
    const mark=element('div','security-heading');mark.append(icon('shield'));connection.prepend(mark);
    const details=element('dl','connection-details');
    [['ワークスペース',state.tenant],['環境',state.environment==='sandbox'?'検証環境 · Sandbox':'本番環境 · Production'],['認証方法',state.tenantSsoSession?'SSO ID':'APIキー'],['接続先',new URL(state.base).host]].forEach(([label,value])=>details.append(element('dt','',label),element('dd','',value)));
    connection.append(details,element('p','settings-warning','認証情報は接続中だけ保持します。この画面を閉じるか切断すると、もう一度接続が必要です。'));
    const currentContract=state.memberships.find(item=>Number(item.tenant_id)===state.selectedTenantId);
    if(currentContract){details.append(element('dt','','利用中のAPIキー'),element('dd','',contractKeyLabel(currentContract)));}
    const security=panel('SSO IDの認証管理','ログインとパスキーはSSOサービスで管理します。');
    const account=element('a','button button-secondary','SSO IDの設定を開く');account.href='https://sso.2415.jp/account';account.target='_blank';account.rel='noopener noreferrer';security.append(account);
    if(state.tenantSsoSession){security.append(actionButton('APIキー再発行（500円）','key',openKeyReissue));const reauth=element('a','button button-secondary','SSO IDで再認証');reauth.href=ssoReauthUrl();reauth.addEventListener('click',()=>setReissueResume(true));security.append(reauth);}
    root.append(connection,security);
    if(state.environment==='production'){
      const sandbox=panel('Sandbox APIキー','本番テナントに紐づく検証環境のAPIキーを管理します。Sandboxキーは検証環境だけで使われ、本番データには接続できません。');
      sandbox.dataset.sandboxKeys='true';sandbox.append(element('p','loading-label','Sandboxキーを読み込んでいます…'));root.append(sandbox);
    }else{
      const sandbox=panel('Sandbox APIキー','検証用キーの発行と管理には、本番テナントへ切り替えてください。');sandbox.append(element('p','settings-warning','現在はSandboxテナントに接続中です。SSO IDで、本番契約へ切り替えると管理できます。'));root.append(sandbox);
    }
    if(state.tenantSsoSession){const link=panel('別の契約APIキーを共通SSO IDに追加','追加先テナントの管理権限を持つTenant APIキーで所有を確認します。APIキーはこの操作中だけ送信し、保存しません。');const form=element('form','toolbar');const apiKey=element('input');apiKey.id='common-id-api-key';apiKey.type='password';apiKey.autocomplete='off';apiKey.placeholder='baas_prod_… または baas_sandbox_…';apiKey.setAttribute('aria-label','追加先のTenant APIキー');apiKey.required=true;const add=element('button','button button-primary','テナントを追加');add.type='submit';form.append(apiKey,add);form.addEventListener('submit',event=>{event.preventDefault();linkTenant();});link.append(form,element('p','form-foot','tenant:read 権限のあるAPIキーが必要です。追加後に利用する契約を選択します。ほかのテナントとの連携は保持します。'));root.append(link);}
    const sandboxHost=root.querySelector('[data-sandbox-keys]');
    shell(root,version);
    if(sandboxHost)await renderSandboxKeys(sandboxHost,version);
  }

  function revealSandboxKey(result,title,version){
    const view=element('div','sandbox-key-result');view.append(element('p','settings-warning','APIキーは発行時に一度だけ表示します。安全な保管先へコピーしてください。'));
    const input=element('input','mono');input.type='password';input.readOnly=true;input.value=String(result.api_key||'');input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','新しいSandbox APIキー');
    const actions=element('div','inline-actions');const toggle=button('表示',()=>{const hidden=input.type==='password';input.type=hidden?'text':'password';toggle.textContent=hidden?'隠す':'表示';});const copy=button('キーをコピー',async()=>{try{await navigator.clipboard.writeText(input.value);notice('Sandbox APIキーをコピーしました。安全な場所へ保管してください。');}catch{input.type='text';input.focus();input.select();notice('キーを選択しました。手動でコピーして安全に保管してください。',true);}} ,'button-primary');actions.append(toggle,copy);view.append(input,actions,element('p','form-foot','この画面を閉じるとキーの表示を消去します。再表示はできません。'));
    if(result.grace_expires_at)view.append(element('p','form-foot',`旧キーは ${result.grace_expires_at} UTC まで利用できます。アプリを新しいキーへ切り替えてください。`));
    openTask(title,'発行したキーをクライアントへ設定してください。',view,'SANDBOX API KEY');input.focus();
    if(version===state.viewVersion){const host=document.querySelector('[data-sandbox-keys]');if(host)renderSandboxKeys(host,version).catch(error=>notice(error.message,true));}
  }

  function sandboxIdempotency(action,clientId='',signature=''){
    const storageKey=`tuti-sandbox-key:${state.tenant}:${action}:${clientId}`;let value='';
    try{const raw=sessionStorage.getItem(storageKey);let saved=null;if(raw){try{saved=JSON.parse(raw)}catch{saved=null}}if(saved&&saved.signature===signature&&typeof saved.value==='string')value=saved.value;if(!value){value=crypto.randomUUID().replaceAll('-','');sessionStorage.setItem(storageKey,JSON.stringify({value,signature}));}}catch{throw new Error('再試行情報を保存できません。ブラウザーのセッションストレージを有効にしてください。');}
    return {storageKey,value};
  }

  async function renderSandboxKeys(host,version){
    host.replaceChildren(element('p','loading-label','Sandbox APIキーを読み込んでいます…'));
    try{
      const data=await api('/api/baas/v1/sandbox-keys.php');if(version!==state.viewVersion||!host.isConnected)return;
      const toolbar=element('div','page-tools');toolbar.append(element('p','form-foot',data.sandbox_slug?`検証テナント: ${data.sandbox_slug}`:'検証テナントはまだありません。発行時に自動作成します。'),actionButton('Sandboxキーを発行','plus',()=>openSandboxKeyForm(host,version),'button-primary'),button('更新',()=>renderSandboxKeys(host,version).catch(error=>notice(error.message,true))));
      host.replaceChildren(toolbar);
      const rows=(data.api_clients||[]).map(client=>{
        const scopes=Array.isArray(client.scopes_json)?client.scopes_json:(()=>{try{return JSON.parse(client.scopes_json||'[]')}catch{return []}})();
        const expiryText=String(client.expires_at||'');const expiryDate=expiryText?new Date(expiryText.replace(' ','T')+(/[zZ]|[+-]\d{2}:\d{2}$/.test(expiryText)?'':'Z')):null;const expired=Boolean(expiryDate&&!Number.isNaN(expiryDate.getTime())&&expiryDate.getTime()<=Date.now());
        const status=client.revoked_at?'revoked':expired?'expired':client.status;
        const actions=element('div','inline-actions');
        if(['active','retiring'].includes(client.status)&&!client.revoked_at&&!expired){
          if(client.status==='active')actions.append(button('交換',()=>rotateSandboxKey(client,host,version)));
          actions.append(button('失効',async()=>{if(!await confirmAction(`「${client.name}」をすぐに失効します。接続中のアプリはSandbox APIへ接続できなくなります。続けますか？`))return;try{await api('/api/baas/v1/sandbox-keys.php',{method:'POST',body:{action:'revoke',client_id:Number(client.id)}});notice('Sandbox APIキーを失効しました。');await renderSandboxKeys(host,version);}catch(error){notice(error.message,true);}},'button-danger'));
        }
        const scopeText=element('span','scope-list',scopes.join(' · ')||'権限情報なし');
        return [client.name,`#${client.id} · ${client.key_prefix}…`,statusBadge(status),scopeText,`${Number(client.rate_limit_per_minute||0).toLocaleString('ja-JP')}/分`,`${client.expires_at?`期限 ${dateText(client.expires_at)}`:'期限なし'} · 最終利用 ${dateText(client.last_used_at)}${client.grace_expires_at?` · 旧キー ${dateText(client.grace_expires_at)}まで`:''}`,actions];
      });
      host.append(rows.length?table(['クライアント','識別子','状態','権限','上限','期限・利用状況','操作'],rows):emptyState('Sandbox APIキーはありません','検証用クライアントを発行すると、ここで権限・利用状態を確認できます。','key'));
      host.append(element('p','form-foot','秘密キーはサーバーへ暗号化して保存し、発行・交換完了時だけ表示します。表示を閉じた後は新しいキーへ交換してください。'));
    }catch(error){if(version!==state.viewVersion||!host.isConnected)return;const failure=element('div','sandbox-key-error');failure.append(element('p','form-error',error.message));failure.append(button('再読み込み',()=>renderSandboxKeys(host,version).catch(next=>notice(next.message,true))));host.replaceChildren(failure);}
  }

  function openSandboxKeyForm(host,version){
    const form=element('form','form-grid');const name=element('input');name.required=true;name.maxLength=120;name.value='Sandbox Client';name.setAttribute('aria-label','クライアント名');form.append(field('クライアント名',name));
    const scopeBox=element('fieldset','sandbox-scopes');scopeBox.append(element('legend','','許可する操作（必要最小限を選択）'));
    const available=[['tenant:read','状態・製品・利用状況の参照'],['products:write','Sandbox製品の作成・変更'],['licenses:read','Sandboxライセンスの参照'],['licenses:write','Sandboxライセンスの発行・変更']];
    for(const [scope,label] of available){const wrap=element('label','checkbox-confirm');const check=element('input');check.type='checkbox';check.value=scope;check.checked=['tenant:read','licenses:write'].includes(scope);wrap.append(check,element('span','',`${scope} — ${label}`));scopeBox.append(wrap);}
    const limit=element('select');[60,120,300,600].forEach(value=>limit.add(new Option(`${value} リクエスト / 分`,String(value))));limit.value='120';form.append(scopeBox,field('レート制限',limit));
    const error=element('p','form-error');error.setAttribute('role','alert');const submit=element('button','button button-primary','Sandbox APIキーを発行');submit.type='submit';form.append(error,submit);
    form.addEventListener('submit',async event=>{event.preventDefault();if(!form.reportValidity()||state.taskBusy)return;const scopes=[...scopeBox.querySelectorAll('input:checked')].map(input=>input.value);if(!scopes.length){error.textContent='少なくとも1つの権限を選んでください。';return;}const signature=JSON.stringify({name:name.value.trim(),scopes,rate_limit_per_minute:Number(limit.value)});let idem;try{idem=sandboxIdempotency('issue','',signature);}catch(failure){error.textContent=failure.message;return;}taskBusy(true);submit.disabled=true;error.textContent='';try{const result=await api('/api/baas/v1/sandbox-keys.php',{method:'POST',idempotency:idem.value,body:{action:'issue',idempotency_key:idem.value,name:name.value.trim(),scopes,rate_limit_per_minute:Number(limit.value)}});try{sessionStorage.removeItem(idem.storageKey);}catch{}taskBusy(false);revealSandboxKey(result,'Sandbox APIキーを発行しました',version);}catch(failure){error.textContent=`${failure.message} 同じ内容で再送すると、重複発行を避けて結果を確認できます。`;submit.disabled=false;}finally{taskBusy(false);submit.disabled=false;}});
    openTask('Sandbox APIキーを発行','検証専用キーを作成します。本番APIには接続できません。',form,'SANDBOX API KEY');
  }

  async function rotateSandboxKey(client,host,version){
    if(!await confirmAction(`「${client.name}」の新しいキーを発行し、旧キーを60分後に失効します。接続先を切り替えられる状態で続けますか？`))return;
    let idem;try{idem=sandboxIdempotency('rotate',String(client.id),JSON.stringify({client_id:Number(client.id),grace_minutes:60}));}catch(error){notice(error.message,true);return;}
    try{const result=await api('/api/baas/v1/sandbox-keys.php',{method:'POST',idempotency:idem.value,body:{action:'rotate',client_id:Number(client.id),grace_minutes:60,idempotency_key:idem.value}});try{sessionStorage.removeItem(idem.storageKey);}catch{}revealSandboxKey(result,'Sandbox APIキーを交換しました',version);}
    catch(error){notice(`${error.message} 同じ操作を再実行すると結果を確認できます。`,true);}
  }
  function field(labelText, control) { const wrap = element('label'); wrap.append(element('span', '', labelText), control); return wrap; }
  async function productsPage(cursor=0,append=false,searchText=state.productSearch) {
    if(state.page!=='products')return; state.productSearch=searchText;const version=++state.viewVersion;const params=new URLSearchParams({limit:String(PAGE_SIZE)});if(cursor)params.set('cursor',String(cursor));if(searchText)params.set('search',searchText);
    const data=await api(`/api/baas/v1/products.php?${params}`);if(version!==state.viewVersion)return;state.products=append?[...state.products,...(data.products||[])]:data.products||[];
    const list=panel('登録済み製品',`${state.products.length}件を表示${data.next_cursor?' · 続きを読み込めます':''}`);list.querySelector('.panel-heading').append(actionButton('製品を追加','plus',openProductForm,'button-primary'));
    const toolbar=element('form','toolbar');const search=element('input');search.type='search';search.placeholder='製品名・コードで検索';search.value=searchText;search.setAttribute('aria-label','製品名・コード');const submit=element('button','button button-secondary','検索');submit.type='submit';toolbar.append(search,submit);if(searchText)toolbar.append(button('検索をクリア',()=>productsPage(0,false,'').catch(e=>notice(e.message,true)),'button-quiet clear-filter'));toolbar.addEventListener('submit',event=>{event.preventDefault();productsPage(0,false,search.value.trim()).catch(e=>notice(e.message,true));});list.append(toolbar);
    const rows=state.products.map(row=>{const actions=element('div','inline-actions');if(row.status!=='deleted'){actions.append(button('編集',()=>openProductForm(row)),button(row.status==='archived'?'復元':'アーカイブ',async()=>{const action=row.status==='archived'?'restore':'archive';if(!await confirmAction(`「${row.name}」を${action==='archive'?'アーカイブ':'復元'}しますか？`))return;try{await api('/api/baas/v1/products.php',{method:'POST',body:{action,product_id:Number(row.id)}});notice('製品の状態を更新しました。');await productsPage(0,false,searchText);}catch(e){notice(e.message,true);}},'button-quiet'));}const name=element('div');name.append(element('strong','',row.name),element('small','mono',row.code));return[row.id,name,statusBadge(row.status),dateText(row.created_at),actions];});
    if(rows.length)list.append(table(['ID','製品','状態','登録日','操作'],rows));else list.append(emptyState(searchText?'該当する製品がありません':'製品を登録しましょう',searchText?'検索する名前やコードを変更してください。':'ライセンスを発行する製品の名前とコードを登録します。','box',searchText?null:actionButton('最初の製品を追加','plus',openProductForm,'button-primary')));
    if(data.next_cursor){const more=element('div','pagination');more.append(button('さらに読み込む',async event=>{event.currentTarget.disabled=true;try{await productsPage(data.next_cursor,true,searchText);}catch(e){event.currentTarget.disabled=false;notice(e.message,true);}}));list.append(more);}shell(list,version);
  }
  function openProductForm(product=null) {
    if(product instanceof Event)product=null; if(state.taskBusy)return;
    const form=element('form','form-grid');const name=element('input');name.required=true;name.maxLength=160;name.placeholder='例：業務管理アプリ';name.value=product?.name||'';form.append(field('製品名',name));const code=element('input');code.required=true;code.maxLength=64;code.pattern='[a-z0-9][a-z0-9_-]{1,63}';code.placeholder='例：business-app';code.autocapitalize='none';code.spellcheck=false;code.value=product?.code||'';code.disabled=Boolean(product);const codeField=field('製品コード',code);codeField.append(element('small','input-hint','半角英小文字・数字・ハイフン・アンダースコア。登録後は変更できません。'));form.append(codeField);const errorBox=element('p','form-error span-all');errorBox.setAttribute('role','alert');const submit=element('button','button button-primary span-all',product?'変更を保存':'製品を登録');submit.type='submit';form.append(errorBox,submit);
    form.addEventListener('submit',async event=>{event.preventDefault();if(!form.reportValidity()||state.taskBusy)return;const connection=state.connectionVersion;taskBusy(true);submit.disabled=true;errorBox.textContent='';try{await api('/api/baas/v1/products.php',{method:'POST',body:product?{action:'update',product_id:Number(product.id),name:name.value.trim()}:{code:code.value.trim(),name:name.value.trim()}});if(connection!==state.connectionVersion)return;$('reissue-dialog').close();$('reissue-content').replaceChildren();$('task-dialog').close();notice(product?'製品を更新しました。':'製品を登録しました。ライセンスを発行できます。');if(state.page==='products')await productsPage();}catch(e){errorBox.textContent=e.message;}finally{taskBusy(false);submit.disabled=false;}});openTask(product?'製品を編集':'製品を追加','製品の名前とコードを設定します。',form,'PRODUCT');name.focus();
  }
  async function licensesPage(cursor=0,append=false) {
    if(state.page!=='licenses')return;const version=++state.viewVersion;const {search:searchText,product:productId}=state.licenseFilter;const qs=new URLSearchParams({limit:String(PAGE_SIZE)});if(cursor)qs.set('cursor',String(cursor));if(searchText)qs.set('search',searchText);if(productId)qs.set('product_id',productId);
    const [data,products]=await Promise.all([api(`/api/baas/v1/licenses.php?${qs}`),api(`/api/baas/v1/products.php?limit=${PAGE_SIZE}`)]);if(version!==state.viewVersion)return;state.products=products.products||[];state.licenses=append?[...state.licenses,...(data.licenses||[])]:data.licenses||[];
    const list=panel('発行済みライセンス',`${state.licenses.length}件を表示 · 状態や接続端末を管理できます。`);const issueActions=element('div','inline-actions');issueActions.append(actionButton('1件発行','plus',openLicenseForm,'button-primary'),actionButton('一括発行','key',openBulkLicenseForm));list.querySelector('.panel-heading').append(issueActions);const form=element('form','toolbar');const search=element('input');search.type='search';search.placeholder='ラベル・IDで検索';search.value=searchText;search.setAttribute('aria-label','ライセンスのラベル・ID');const filter=element('select');filter.setAttribute('aria-label','製品で絞り込む');filter.add(new Option('すべての製品',''));state.products.forEach(p=>filter.add(new Option(p.name,p.id)));filter.value=productId;const submit=element('button','button button-secondary','検索');submit.type='submit';form.append(search,filter,submit);if(searchText||productId)form.append(button('条件をクリア',()=>{state.licenseFilter={search:'',product:''};licensesPage().catch(e=>notice(e.message,true));},'button-quiet clear-filter'));form.addEventListener('submit',event=>{event.preventDefault();state.licenseFilter={search:search.value.trim(),product:filter.value};licensesPage().catch(e=>notice(e.message,true));});list.append(form);
    if(state.licenses.length)list.append(renderLicenseTable(state.licenses));else list.append(emptyState(searchText||productId?'該当するライセンスがありません':'ライセンスを発行しましょう',searchText||productId?'検索条件を変えてお試しください。':'製品を選び、用途に合ったライセンスを発行できます。','key',searchText||productId?null:actionButton('最初のライセンスを発行','plus',openLicenseForm,'button-primary')));
    if(data.next_cursor){const more=element('div','pagination');more.append(button('さらに読み込む',async event=>{event.currentTarget.disabled=true;try{await licensesPage(data.next_cursor,true);}catch(e){event.currentTarget.disabled=false;notice(e.message,true);}}));list.append(more);}shell(list,version);
  }
  async function openLicenseForm() {
    if(state.taskBusy)return;const connection=state.connectionVersion;const loading=element('p','loading-label','製品を読み込んでいます…');openTask('ライセンスを発行','製品と発行方式を選んでください。',loading,'LICENSE');const taskVersion=state.taskVersion;
    let products;try{products=(await api(`/api/baas/v1/products.php?limit=${PAGE_SIZE}`)).products||[];}catch(e){if(connection===state.connectionVersion&&taskVersion===state.taskVersion&&$('task-dialog').open)$('task-content').replaceChildren(element('p','form-error',e.message));return;}if(connection!==state.connectionVersion||taskVersion!==state.taskVersion||!$('task-dialog').open)return;
    const active=products.filter(p=>p.status==='active');if(!active.length){$('task-content').replaceChildren(emptyState('先に製品を登録してください','有効な製品を登録すると、ライセンスを発行できます。','box',actionButton('製品を追加','plus',()=>{$('reissue-dialog').close();$('reissue-content').replaceChildren();$('task-dialog').close();setPage('products');openProductForm();},'button-primary')));return;}
    const form=element('form','form-grid');const product=element('select');product.required=true;product.add(new Option('発行する製品を選択',''));active.forEach(p=>product.add(new Option(`${p.name} · ${p.code}`,p.id)));if(active.length===1)product.value=String(active[0].id);
    const mode=element('select');[['single','1台用'],['volume','複数台用'],['evaluation','評価版']].forEach(([v,l])=>mode.add(new Option(l,v)));const devices=element('input');devices.type='number';devices.min='2';devices.max='10000';devices.value='10';const days=element('input');days.type='number';days.min='1';days.max='3650';days.value='30';const deviceField=field('利用できる端末数',devices);const dayField=field('評価できる日数',days);
    form.append(field('対象の製品',product),field('発行方式',mode),deviceField,dayField);const advanced=element('details','advanced-settings');advanced.append(element('summary','','ラベル・有効期限を設定（任意）'));const options=element('div','form-grid');const label=element('input');label.maxLength=100;label.placeholder='例：営業チーム';const expires=element('input');expires.type='datetime-local';const expiry=field('有効期限',expires);expiry.append(element('small','input-hint','端末の現地時刻で指定します。未入力なら無期限です。'));options.append(field('管理用のラベル',label),expiry);advanced.append(options);form.append(advanced);
    const review=element('div','issue-review span-all');const reviewCopy=element('div');review.append(icon('key'),reviewCopy);const update=()=>{devices.disabled=mode.value!=='volume';days.disabled=mode.value!=='evaluation';deviceField.classList.toggle('hidden',devices.disabled);dayField.classList.toggle('hidden',days.disabled);reviewCopy.replaceChildren(element('strong','',`${product.selectedOptions[0]?.textContent||'製品を選択'} / ${mode.selectedOptions[0].textContent}`),element('p','','発行されたキーは完了画面で一度だけ表示します。コピーして安全な場所に保管してください。'));};product.addEventListener('change',update);mode.addEventListener('change',update);update();const errorBox=element('p','form-error span-all');errorBox.setAttribute('role','alert');const submit=element('button','button button-primary span-all','ライセンスを発行');submit.type='submit';form.append(review,errorBox,submit);
    form.addEventListener('submit',async event=>{event.preventDefault();if(!form.reportValidity()||state.taskBusy)return;const body={action:'issue',product_id:Number(product.value),license_mode:mode.value,label:label.value.trim()};if(mode.value==='volume')body.max_devices=Number(devices.value);if(mode.value==='evaluation')body.evaluation_days=Number(days.value);if(expires.value)body.expires_at=new Date(expires.value).toISOString().slice(0,19).replace('T',' ');const signature=JSON.stringify(body);const storageKey=`tuti-license-issue:${state.tenant}:${state.environment}`;let saved;try{saved=JSON.parse(sessionStorage.getItem(storageKey)||'null');if(!saved||saved.signature!==signature)saved={signature,idem:crypto.randomUUID().replaceAll('-','')};sessionStorage.setItem(storageKey,JSON.stringify(saved));}catch{errorBox.textContent='再試行用の情報を保存できませんでした。ブラウザーの設定を確認してください。';return;}state.issuePending=saved;body.idempotency_key=saved.idem;taskBusy(true);submit.disabled=true;submit.textContent='発行結果を確認しています…';errorBox.textContent='';
      try{const issued=await api('/api/baas/v1/licenses.php',{method:'POST',body,idempotency:saved.idem});if(connection!==state.connectionVersion||!$('task-dialog').open)return;try{sessionStorage.removeItem(storageKey);}catch{}state.issuePending=null;showIssued(issued);if(state.page==='licenses')licensesPage().catch(e=>notice(`発行は完了しています。一覧を更新できませんでした：${e.message}`,true));}
      catch(e){errorBox.textContent=`${e.message} 同じ内容で再試行すると、追加発行せずに結果を確認します。`;}
      finally{taskBusy(false);submit.disabled=false;submit.textContent='ライセンスを発行';}
    });$('task-content').replaceChildren(form);product.focus();
  }
  function createBulkRecovery(connection, taskVersion) {
    const recovery = element('div', 'form-grid');
    const jobInput = element('input'); jobInput.placeholder = '発行ジョブID（32文字）'; jobInput.maxLength = 32;
    const errorBox = element('p', 'form-error span-all'); errorBox.setAttribute('role', 'alert');
    try {
      const saved = JSON.parse(sessionStorage.getItem(`tuti-license-bulk-issue:${state.tenant}:${state.environment}:last-job`) ||
        sessionStorage.getItem(`tuti-license-bulk-issue:${state.tenant}:${state.environment}`) || 'null');
      if (/^[a-f0-9]{32}$/.test(saved?.jobId || '')) jobInput.value = saved.jobId;
    } catch {}
    const resume = button('発行済み・処理中ジョブを確認', () => {
      const jobId = jobInput.value.trim().toLowerCase();
      if (!/^[a-f0-9]{32}$/.test(jobId)) { errorBox.textContent = '32文字の発行ジョブIDを入力してください。'; return; }
      const view = element('div', 'form-grid');
      view.append(element('p', 'form-foot span-all', `発行ジョブ ${jobId}`));
      $('task-content').replaceChildren(view); renderBulkJobActions(view, jobId, connection, taskVersion);
    });
    recovery.append(field('前回のジョブを再確認', jobInput), resume, errorBox);
    return recovery;
  }
  async function openBulkLicenseForm() {
    if (state.taskBusy) return;
    const connection = state.connectionVersion;
    const loading = element('p', 'loading-label', '製品を読み込んでいます…');
    openTask('ライセンスを一括発行', '件数を指定して、複数のライセンスキーをまとめて発行します。', loading, 'BULK LICENSE');
    const taskVersion = state.taskVersion;
    const recovery = createBulkRecovery(connection, taskVersion);
    $('task-content').replaceChildren(loading, recovery);
    let products;
    try {
      products = (await api(`/api/baas/v1/products.php?limit=${PAGE_SIZE}`)).products || [];
    } catch (error) {
      if (connection === state.connectionVersion && taskVersion === state.taskVersion && $('task-dialog').open) {
        $('task-content').replaceChildren(element('p', 'form-error', error.message), recovery);
      }
      return;
    }
    if (connection !== state.connectionVersion || taskVersion !== state.taskVersion || !$('task-dialog').open) return;

    const active = products.filter((product) => product.status === 'active');
    if (!active.length) {
      $('task-content').replaceChildren(emptyState('先に製品を登録してください', '有効な製品を登録すると、一括発行できます。', 'box'), recovery);
      return;
    }

    const form = element('form', 'form-grid');
    const product = element('select');
    product.required = true;
    product.add(new Option('発行する製品を選択', ''));
    active.forEach((item) => product.add(new Option(`${item.name} · ${item.code}`, item.id)));
    if (active.length === 1) product.value = String(active[0].id);
    const count = element('input');
    count.type = 'number'; count.min = '1'; count.max = '100000'; count.value = '10'; count.required = true;
    const mode = element('select');
    [['single', '1台用'], ['volume', '複数台用'], ['evaluation', '評価版']].forEach(([value, label]) => mode.add(new Option(label, value)));
    const devices = element('input'); devices.type = 'number'; devices.min = '2'; devices.max = '10000'; devices.value = '10';
    const days = element('input'); days.type = 'number'; days.min = '1'; days.max = '3650'; days.value = '30';
    const deviceField = field('利用できる端末数', devices);
    const dayField = field('評価できる日数', days);
    const label = element('input'); label.maxLength = 100; label.placeholder = '例：営業チーム';
    form.append(field('対象の製品', product), field('発行件数（最大100,000件）', count), field('発行方式', mode), deviceField, dayField, field('管理用ラベル（任意）', label));
    const explanation = element('p', 'form-foot span-all', '大量発行はバックグラウンド処理になります。完了後に、発行キーを含むCSVを明示操作でダウンロードできます。');
    const errorBox = element('p', 'form-error span-all'); errorBox.setAttribute('role', 'alert');
    const submit = element('button', 'button button-primary span-all', '内容を確認して一括発行'); submit.type = 'submit';
    const updateMode = () => {
      deviceField.classList.toggle('hidden', mode.value !== 'volume');
      dayField.classList.toggle('hidden', mode.value !== 'evaluation');
      devices.disabled = mode.value !== 'volume';
      days.disabled = mode.value !== 'evaluation';
    };
    mode.addEventListener('change', updateMode); updateMode();
    form.append(explanation, errorBox, submit);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!form.reportValidity() || state.taskBusy) return;
      const body = {
        product_id: Number(product.value), count: Number(count.value), license_mode: mode.value,
        label: label.value.trim(),
      };
      if (mode.value === 'volume') body.max_devices = Number(devices.value);
      if (mode.value === 'evaluation') body.evaluation_days = Number(days.value);
      submit.disabled = true; submit.textContent = '料金を確認しています…'; errorBox.textContent = '';
      let quote;
      try {
        const quoteQuery = new URLSearchParams({ action: 'quote', count: String(body.count) });
        quote = await api(`/api/baas/v8/issuance.php?${quoteQuery}`);
      } catch (error) {
        errorBox.textContent = error.message; submit.disabled = false; submit.textContent = '内容を確認して一括発行'; return;
      }
      if (connection !== state.connectionVersion || taskVersion !== state.taskVersion || !$('task-dialog').open) { submit.disabled = false; submit.textContent = '内容を確認して一括発行'; return; }
      const pricing = quote.pricing || {};
      const confirmation = await confirmAction(`${product.selectedOptions[0].textContent}を${body.count.toLocaleString('ja-JP')}件、一括発行します。料金目安は${pricing.charge_credit || '—'} Cr（${pricing.mode || '料金設定'}）です。発行後のキーはCSVで一度に取得してください。続けますか？`);
      if (!confirmation || connection !== state.connectionVersion || taskVersion !== state.taskVersion || !$('task-dialog').open) { submit.disabled = false; submit.textContent = '内容を確認して一括発行'; return; }

      const signature = JSON.stringify(body);
      const storageKey = `tuti-license-bulk-issue:${state.tenant}:${state.environment}`;
      let pending;
      try {
        pending = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
        if (!pending || pending.signature !== signature) pending = { signature, idempotencyKey: crypto.randomUUID().replaceAll('-', '') };
        sessionStorage.setItem(storageKey, JSON.stringify(pending));
      } catch {
        errorBox.textContent = '安全な再試行情報を保存できません。ブラウザーの設定を確認してください。';
        submit.disabled = false; submit.textContent = '内容を確認して一括発行';
        return;
      }
      taskBusy(true); submit.disabled = true; submit.textContent = '発行を受け付けています…'; errorBox.textContent = '';
      try {
        const result = await api('/api/baas/v8/issuance.php', {
          method: 'POST', body: { ...body, idempotency_key: pending.idempotencyKey, execution_mode: Number(body.count) > 100 ? 'async' : 'auto' }, idempotency: pending.idempotencyKey,
        });
        if (connection !== state.connectionVersion || taskVersion !== state.taskVersion || !$('task-dialog').open) return;
        const resultView = element('div', 'form-grid');
        const progress = element('div', 'issue-review span-all');
        progress.append(icon('check'), element('div', '', `発行ジョブ ${result.job?.job_id || ''} を受け付けました。`));
        const details = element('p', 'form-foot span-all', `状態: ${result.job?.status || result.execution} · 成功 ${Number(result.job?.succeeded_count ?? result.count ?? 0).toLocaleString('ja-JP')}件 · 失敗 ${Number(result.job?.failed_count || 0).toLocaleString('ja-JP')}件`);
        resultView.append(progress, details);
        const jobId = String(result.job?.job_id || result.plan?.job_id || '');
        if (jobId) {
          pending.jobId = jobId;
          try { sessionStorage.setItem(storageKey, JSON.stringify(pending)); } catch {}
          try { sessionStorage.setItem(storageKey + ':last-job', JSON.stringify({ jobId })); } catch {}
          renderBulkJobActions(resultView, jobId, connection, taskVersion);
        }
        if (result.execution === 'completed_inline' && Array.isArray(result.items)) {
          resultView.append(actionButton('発行キーをCSVで保存', 'key', () => downloadCsv('license-keys.csv', [['ライセンスID', '指紋', 'ライセンスキー'], ...result.items.map((item) => [item.license_id, item.key_fingerprint, item.product_key])] ), 'button-primary'));
        }
        if (result.job?.terminal) {
          try { sessionStorage.removeItem(storageKey); } catch {}
        }
        $('task-content').replaceChildren(resultView);
      } catch (error) {
        errorBox.textContent = `${error.message} 同じ内容で再試行すると、同じ発行ジョブの結果を確認します。`;
      } finally {
        taskBusy(false); submit.disabled = false; submit.textContent = '内容を確認して一括発行';
      }
    });
    $('task-content').replaceChildren(form, recovery);
    product.focus();
  }

  function renderBulkJobActions(container, jobId, connection, taskVersion) {
    const statusLine = element('p', 'form-foot span-all', '発行状況を確認しています…');
    const controls = element('div', 'inline-actions span-all');
    let updating = false; let timer = 0; let autoRefresh = false;
    const isCurrent = () => connection === state.connectionVersion && taskVersion === state.taskVersion && $('task-dialog').open && container.isConnected;
    async function refreshJob() {
      if (updating || !isCurrent()) return;
      window.clearTimeout(timer);
      if (document.hidden) { if (autoRefresh) timer = window.setTimeout(refreshJob, 30000); return; }
      updating = true; refreshStatus.disabled = true;
      let terminal = false; let nextDelay = 10000;
      try {
        const result = await api(`/api/baas/v8/issuance.php?job_id=${encodeURIComponent(jobId)}`);
        if (!isCurrent()) return;
        const job = result.job;
        terminal = Boolean(job.terminal);
        nextDelay = Math.max(10000, Math.min(30000, Number(job.retry_after_ms) || 10000));
        const retry = Number(job.retry_count) ? ` · 再試行 ${job.retry_count}回${job.retry_after_ms > 0 ? '（待機中）' : ''}` : '';
        statusLine.textContent = `状態: ${job.status} · ${job.progress_percent}% · 成功 ${job.succeeded_count}件 · 失敗 ${job.failed_count}件${retry}`;
        cancelJob.disabled = job.status === 'cancel_requested';
        if (job.terminal) {
          autoRefresh = false; autoStatus.disabled = true; autoStatus.textContent = '自動更新（完了）';
          cancelJob.classList.add('hidden');
          const storageKey = `tuti-license-bulk-issue:${state.tenant}:${state.environment}`;
          try { const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); if (saved?.jobId === jobId) sessionStorage.removeItem(storageKey); } catch {}
        }
        if (job.terminal && Number(job.succeeded_count) > 0) {
          statusLine.classList.toggle('success', job.status === 'completed');
          if (!controls.querySelector('[data-download-results]')) {
            const reveal = actionButton('発行キーをCSVで保存', 'key', async () => {
              reveal.disabled = true; reveal.textContent = 'キーを取得しています…';
              try {
                const csv = await TutiBulkJobs.collectCsvPages(async (cursor) => {
                  const query = new URLSearchParams({ job_id: jobId, cursor: String(cursor), limit: '500', reveal: 'true' });
                  return api(`/api/baas/v8/issuance-results.php?${query}`);
                }, jobId, Number(job.succeeded_count), isCurrent, (count, total) => {
                  reveal.textContent = `キーを取得中 ${count.toLocaleString('ja-JP')} / ${total.toLocaleString('ja-JP')}件`;
                });
                if (!isCurrent()) return;
                downloadCsvParts(`license-keys-${jobId.slice(0, 8)}.csv`, csv.parts);
                statusLine.textContent = `${csv.count.toLocaleString('ja-JP')}件のキーをCSVに保存しました。安全な場所で管理してください。`;
              } catch (error) { notice(error.message, true); }
              finally { reveal.disabled = false; reveal.textContent = '発行キーをCSVで保存'; }
            }, 'button-primary');
            reveal.dataset.downloadResults = 'true'; controls.append(reveal);
          }
        }
      } catch (error) { if (isCurrent()) statusLine.textContent = error.message; nextDelay = 30000; }
      finally {
        updating = false; refreshStatus.disabled = false;
        if (isCurrent() && !terminal && autoRefresh) timer = window.setTimeout(refreshJob, nextDelay);
      }
    }
    const refreshStatus = button('進捗を更新', refreshJob);
    const autoStatus = button('自動更新を開始（API利用料あり）', async () => {
      autoRefresh = !autoRefresh;
      autoStatus.textContent = autoRefresh ? '自動更新を停止' : '自動更新を開始（API利用料あり）';
      if (autoRefresh) await refreshJob(); else window.clearTimeout(timer);
    });
    const cancelJob = button('ジョブを停止', async () => {
      if (!await confirmAction('処理中のジョブを停止します。停止前に発行済みのキーは取り消されません。続けますか？')) return;
      cancelJob.disabled = true;
      try { await api('/api/baas/v8/issuance-cancel.php', { method: 'POST', body: { job_id: jobId } }); await refreshJob(); }
      catch (error) { statusLine.textContent = error.message; cancelJob.disabled = false; }
    }, 'button-danger');
    controls.append(refreshStatus, cancelJob, autoStatus); container.append(statusLine, controls);
    timer = window.setTimeout(refreshJob, 0);
  }

  function renderLicenseTable(rows) { const values = rows.map((row) => { const actions = element('div', 'inline-actions'); const detail = button('端末', async () => showDevices(row.id)); const toggle = button(Number(row.active) ? '停止' : '再開', async () => { const action = Number(row.active) ? 'deactivate' : 'activate'; if (!await confirmAction(`ライセンス #${row.id} を${action === 'deactivate' ? '停止' : '再開'}します。続けますか？`)) return; try { await api('/api/baas/v1/licenses.php', { method: 'POST', body: { action, license_id: Number(row.id) } }); notice('ライセンス状態を更新しました。'); await licensesPage(); } catch (error) { notice(error.message, true); } }); actions.append(detail, toggle); return [row.id, row.product_code, row.label, statusBadge(Number(row.active) ? 'active' : 'inactive'), row.max_devices, row.expires_at ? dateText(row.expires_at) : '無期限', actions]; }); return table(['ID', '製品', 'ラベル', '状態', '上限', '期限', '操作'], values); }
  async function showDevices(id) { if(state.taskBusy)return;openTask(`ライセンス #${id} の端末`,'このライセンスに接続した端末を確認できます。',element('p','loading-label','端末を読み込んでいます…'),'DEVICES');const connection=state.connectionVersion;const taskVersion=state.taskVersion;try{const data=await api(`/api/baas/v1/licenses.php?license_id=${encodeURIComponent(id)}`);if(connection!==state.connectionVersion||taskVersion!==state.taskVersion||!$('task-dialog').open)return;const rows=(data.devices||[]).map(d=>[d.id,d.device_label||'端末名なし',dateText(d.first_activated_at),dateText(d.last_seen_at),statusBadge(d.revoked_at?'revoked':'active')]);$('task-content').replaceChildren(rows.length?table(['ID','端末名','初回認証','最終利用','状態'],rows):emptyState('接続した端末はまだありません','このライセンスで認証すると、端末がここへ表示されます。','key'));}catch(e){if(connection===state.connectionVersion&&taskVersion===state.taskVersion&&$('task-dialog').open)$('task-content').replaceChildren(element('p','form-error',e.message));} }
  function showIssued(data) { const view=element('div');const mark=element('div','success-mark');mark.append(icon('check'));view.append(mark,element('h3','success-title','ライセンスを発行しました'),element('p','success-subtitle',`ライセンス #${data.license_id} · キーを保存してから閉じてください。`));const key=element('div','key-result mono',data.product_key||'');key.tabIndex=0;key.setAttribute('aria-label','発行されたライセンスキー');const actions=element('div','key-actions');actions.append(actionButton('キーをコピー','key',async event=>{try{await navigator.clipboard.writeText(key.textContent);event.currentTarget.textContent='コピーしました';}catch{const range=document.createRange();range.selectNodeContents(key);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);notice('キーを選択しました。手動でコピーしてください。',true);}},'button-primary'));view.append(key,actions,element('p','form-foot','この画面を閉じるとキーの表示を消去します。'));$('task-title').textContent='発行完了';$('task-subtitle').textContent='';$('task-content').replaceChildren(view);key.focus(); }
  const billingLabels = { requests: 'APIリクエスト数', request_count: 'APIリクエスト数', total_requests: 'APIリクエスト数', billable_requests: '課金対象リクエスト', non_billable_requests: '非課金リクエスト', total_charge_units: '請求対象ユニット', total_charge_credit: '請求クレジット', total_charge_yen_equivalent: '円換算参考額', credits: '利用クレジット', total_credits: '利用クレジット', amount: '請求額', total_amount: '請求額', licenses_issued: '発行ライセンス数', products: '製品数', active_licenses: '有効ライセンス数' };
  function downloadCsvParts(filename, parts) { const blob = new Blob(parts, { type: 'text/csv;charset=utf-8' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = filename; link.click(); window.setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
  function downloadCsv(filename, rows) { downloadCsvParts(filename, ['\uFEFF', ...rows.map(TutiBulkJobs.csvLine)]); }
  async function billingPage(period = state.billingPeriod, invoiceFilter = null) {
    if(state.page!=='billing')return;state.billingPeriod=period;const version=++state.viewVersion;
    const [data, invoiceData] = await Promise.all([api(`/api/baas/v1/billing.php?period=${encodeURIComponent(period)}`), api('/api/baas/v1/invoices.php')]);
    if(version!==state.viewVersion)return;
    const root = document.createDocumentFragment();
    const invoicePanel = panel('発行済み請求書', '管理者が確定した請求書を確認できます。印刷画面から「PDFとして保存」できます。');
    if (invoiceData.production_ready === false) invoicePanel.append(element('p', 'invoice-test-warning', 'API利用料金はテスト設定（TEST_ONLY）です。APIキー再発行料は1回500円（税込）です。'));
    if (invoiceData.stripe?.test_mode) invoicePanel.append(element('p', 'invoice-test-warning', 'カード決済はStripeテストモードです。テスト用カードでのみ決済され、実際の請求は発生しません。'));
    else if (invoiceData.stripe?.configured && !invoiceData.stripe.enabled) invoicePanel.append(element('p', 'invoice-test-warning', 'カード決済の設定はありますが、現在は無効です。管理者へお問い合わせください。'));
    const invoices = invoiceData.invoices || [];
    const periodSelect = document.createElement('select');
    periodSelect.setAttribute('aria-label', '請求書の対象月');
    periodSelect.add(new Option('すべての月', ''));
    (invoiceData.periods || []).forEach((value) => periodSelect.add(new Option(value, value)));
    const selectedPeriod = invoiceFilter === null ? (invoices.some((item) => item.billing_period === period) ? period : '') : invoiceFilter;
    periodSelect.value = selectedPeriod;
    const invoiceToolbar = element('div', 'toolbar'); invoiceToolbar.append(field('対象月', periodSelect));
    invoicePanel.append(invoiceToolbar);
    const invoiceList = element('div', 'invoice-list');
    const visibleInvoices = selectedPeriod ? invoices.filter((item) => item.billing_period === selectedPeriod) : invoices;
    if (!visibleInvoices.length) invoiceList.append(element('p', 'empty-state', 'このテナントに発行済みの請求書はありません。請求書は管理者による発行後にここへ表示されます。'));
    const showInvoice = (invoice) => {
      state.viewVersion++;
      const doc = element('article', 'invoice-document');
      const top = element('div', 'invoice-title-row'); const issuer = invoice.snapshot?.issuer_name || invoice.issuer_name;
      top.append(element('div', '', issuer), element('h2', '', '請求書')); doc.append(top);
      const details = element('div', 'invoice-meta');
      [['請求書番号', invoice.invoice_number], ['対象期間', invoice.billing_period], ['発行日', invoice.issue_date], ['お支払期限', invoice.due_date], ['発行者', issuer], ['登録番号', invoice.snapshot?.issuer_registration_number || invoice.issuer_registration_number || '—'], ['宛先', invoice.snapshot?.customer_name || invoice.customer_name], ['状態', invoice.status === 'paid' ? '入金済み' : 'お支払い待ち']].forEach(([label, value]) => { const item = element('div'); item.append(element('small', '', label), element('strong', '', text(value))); details.append(item); });
      doc.append(details);
      const lines = invoice.snapshot?.line_items || [];
      const savedItems = invoice.snapshot?.items || [];
      const invoiceItems = Array.isArray(savedItems) && savedItems.length
        ? savedItems
        : lines.map((line) => ({ description: line.api || line.operation || 'API利用料', environment: line.environment, quantity: line.requests ?? line.count ?? 0, unit: '回', unit_price_yen: line.unit_credit ?? '—', amount_yen: line.charge_credit ?? (line.charge_units !== undefined ? (Number(line.charge_units) / 1000).toFixed(3) : '—') }));
      if (!invoiceItems.length) invoiceItems.push({ description: 'API利用料（対象期間）', quantity: invoice.snapshot?.total_requests ?? 0, unit: '回', unit_price_yen: '—', amount_yen: invoice.subtotal_yen });
      const breakdown = panel('請求項目', '項目ごとの利用量と料金'); const invoiceItemList = element('div', 'invoice-item-list');
      invoiceItems.forEach((item) => { const card = element('article', 'invoice-line-card'); const heading = element('div', 'invoice-line-heading'); heading.append(element('strong', '', item.description || 'API利用料'), element('b', 'invoice-line-amount', `¥${text(item.amount_yen)}`)); card.append(heading); if (item.environment && item.environment !== '—') card.append(element('span', 'invoice-environment', item.environment === 'production' ? 'Production' : item.environment === 'sandbox' ? 'Sandbox' : item.environment)); const values = element('div', 'invoice-line-values'); values.append(element('span', '', `数量 ${Number(item.quantity || 0).toLocaleString('ja-JP')} ${item.unit || '回'}`), element('span', '', `単価 ¥${text(item.unit_price_yen)}`)); card.append(values); invoiceItemList.append(card); }); breakdown.append(invoiceItemList);
      const sections = invoice.snapshot?.sections || [];
      if (Array.isArray(sections) && sections.length) { const sectionPanel = panel('テナント・環境別の集計'); sectionPanel.append(table(['テナント', '環境', '全リクエスト', '課金対象', 'API利用額'], sections.map((section) => [section.tenant_name || section.tenant_slug, section.environment, section.total_requests, section.billable_requests, `¥${section.total_charge_yen}`]))); breakdown.append(sectionPanel); }
      const totals = element('dl', 'invoice-totals'); [['小計', invoice.subtotal_yen], [`消費税（${(invoice.tax_rate_basis_points / 100).toFixed(2)}%）`, invoice.tax_yen], ['調整額', invoice.adjustment_yen], ['合計（税込）', invoice.total_yen]].forEach(([label, value], index) => { totals.append(element('dt', index === 3 ? 'total' : '', label), element('dd', index === 3 ? 'total' : '', `¥${text(value)}`)); });
      const foot = element('div', 'invoice-foot'); if (invoice.notes) foot.append(element('p', '', invoice.notes)); foot.append(element('p', '', '金額は請求書発行時点の確定スナップショットです。')); doc.append(breakdown, totals, foot);
      const actions = element('div', 'invoice-actions no-print'); actions.append(button('← 請求書一覧', () => billingPage(period, selectedPeriod).catch((error) => notice(error.message, true))));
      if (invoice.status === 'issued' && invoiceData.stripe?.enabled && state.tenantSsoSession) {
        const open = invoice.stripe_payment && invoice.stripe_payment.status === 'open';
        const pay = button(open ? 'カードで支払いを続ける' : 'カードで支払う', async () => {
          pay.disabled = true;
          try {
            const result = await api('/api/baas/v1/tenant-sso.php', { method: 'POST', body: { action: 'create_invoice_checkout', invoice_id: invoice.id } });
            if (result.checkout_url) { notice('Stripeの決済画面へ移動します。'); window.location.assign(result.checkout_url); return; }
            pay.disabled = false;
          } catch (error) { pay.disabled = false; notice(error.message, true); if (String(error.message).includes('完了')) billingPage(period, selectedPeriod).catch(() => {}); }
        }, open ? 'button-secondary' : 'button-primary');
        actions.append(pay);
        actions.append(element('p', 'form-foot', invoiceData.stripe.test_mode ? 'Stripeテストモード（テストカードのみ）· 決済後にWebhookで請求書が入金済みになります。' : 'カード決済後、Webhookで請求書が入金済みになります。'));
      }
      actions.append(button('印刷・PDF保存', () => { document.body.classList.add('print-invoice'); window.print(); window.setTimeout(() => document.body.classList.remove('print-invoice'), 500); }, 'button-primary'));
      shell(doc); $('page-content').append(actions);
    };
    visibleInvoices.forEach((invoice) => { const card = element('button', 'invoice-row'); card.type = 'button'; const left = element('span'); left.append(element('strong', '', `${invoice.billing_period} · ${invoice.invoice_number}`), element('small', '', `発行日 ${invoice.issue_date} · 期限 ${invoice.due_date}`)); const right = element('span', 'invoice-row-total'); right.append(element('strong', '', `¥${invoice.total_yen}`), statusBadge(invoice.status)); card.append(left, right); card.addEventListener('click', () => showInvoice(invoice)); invoiceList.append(card); });
    periodSelect.addEventListener('change', () => billingPage(period, periodSelect.value).catch((error) => notice(error.message, true)));
    invoicePanel.append(invoiceList); root.append(invoicePanel);

    const summary = panel(`API利用集計 · ${text(data.period, period)}`, 'この画面は利用実績の確認用です。お支払い金額は発行済み請求書でご確認ください。');
    if (data.production_ready === false) summary.append(element('p', 'invoice-test-warning', 'API利用料金はテスト設定（TEST_ONLY）です。APIキー再発行料はテスト料金の割引対象外で、1回500円（税込）です。'));
    const periodForm = element('form', 'toolbar'); const picker = element('input'); picker.type = 'month'; picker.value = period; picker.setAttribute('aria-label', '利用集計月'); const load = element('button', 'button button-secondary', '月を表示'); load.type = 'submit'; periodForm.append(picker, load); periodForm.addEventListener('submit', (event) => { event.preventDefault(); billingPage(picker.value, selectedPeriod).catch((error) => notice(error.message, true)); }); summary.append(periodForm);
    const grid = element('div', 'metric-grid');
    const total = Number(data.total_charge_yen_equivalent ?? data.total_charge_credit ?? 0);
    const metrics = [
      ['APIリクエスト', data.total_requests, '期間中の全リクエスト'],
      ['課金対象', data.billable_requests, '料金計算に含まれる回数'],
      ['非課金', data.non_billable_requests, '対象外・未対応の操作など'],
      ['料金目安', `¥${Number.isFinite(total) ? total.toLocaleString('ja-JP', { minimumFractionDigits: 3, maximumFractionDigits: 3 }) : '0.000'}`, '確定額は請求書を確認'],
    ];
    metrics.forEach(([label, value, foot]) => { const card = element('article', 'metric-card'); card.append(element('div', 'metric-label', label), element('div', 'metric-value', text(value, '0')), element('div', 'metric-foot', foot)); grid.append(card); });
    summary.append(grid, element('p', 'form-foot', `対象期間（UTC）: ${text(data.period_start_utc)} 〜 ${text(data.period_end_utc)} · 表示する時刻はUTCです。料金の確定額は請求書をご確認ください。`));
    const fees = data.api_key_reissue_fees || {};
    const feeSummary=element('div','fee-summary');const feeCopy=element('div');feeCopy.append(element('strong','','APIキー再発行料'),element('p','',`${Number(fees.count||0)}回 · 1回500円（税込）を月次請求へ加算`));feeSummary.append(feeCopy,element('span','fee-total',`¥${Number(fees.amount_yen||0).toLocaleString('ja-JP')}`));summary.append(feeSummary);
    const models = data.api_pricing_models || {};
    if (Object.keys(models).length) {
      const pricing = panel('ライセンス発行APIの料金目安', '1回の発行リクエストで指定するキー数に応じた料金です。通常のAPI利用料金は下の利用内訳をご覧ください。');
      const rows = Object.entries(models).map(([name, model]) => [name.includes('.v8.') ? 'V8' : (name.includes('.v7.') ? 'V7（旧版）' : 'V6（旧版）'), model.production_formula || model.basis || '料金モデル', model.production_formula ? 'Sandboxは本番の10%' : 'V6料金から10%引き']);
      pricing.append(table(['方式', '本番の料金計算', 'Sandbox'], rows));
      pricing.append(element('p', 'form-foot', '新しい一括発行はV8で、1回あたり最大100,000キーです。旧版の料金は過去の利用確認用です。料金は1リクエスト単位で計算され、現在の設定はテスト用です。'));
      const detail=element('details','billing-details');detail.append(element('summary','','ライセンス発行APIの料金を見る'),pricing);summary.append(detail);
    }
    if (Array.isArray(data.details) && data.details.length) {
      const breakdown = panel('API別の利用内訳', '単価・利用回数・料金をAPIごとにまとめています。');
      breakdown.append(table(['API', '単価（円換算）', '回数', '利用額（円換算）'], data.details.map((row) => [element('code', 'mono', row.api), `${text(row.unit_credit)} Cr`, Number(row.requests || 0).toLocaleString('ja-JP'), `${text(row.charge_credit)} Cr`])));
      breakdown.append(element('p', 'form-foot', 'Cr（クレジット）は円換算の参考単位です。請求書発行時に端数・税額等を含めて確定します。'));
      summary.append(breakdown);
    } else summary.append(element('p', 'empty-state', 'この期間に表示できるAPI利用データはありません。'));
    const exportButton = button('利用明細をCSV保存', () => downloadCsv(`billing-${period}.csv`, [['API', '単価（Cr）', '回数', '料金目安（Cr）', '内部単位'], ...(data.details || []).map((row) => [row.api, row.unit_credit, row.requests, row.charge_credit, row.charge_units])]));
    summary.append(exportButton); root.prepend(summary); shell(root,version);
  }
  async function auditPage(cursor = 0, append = false) {
    if(state.page!=='audit')return;const version=++state.viewVersion;
    const filter = { ...state.auditFilter };
    const qs = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (cursor) qs.set('cursor', String(cursor));
    if (filter.operation) qs.set('operation', filter.operation);
    if (filter.clientId) qs.set('client_id', filter.clientId);
    if (filter.status) qs.set('status', filter.status);
    const data = await api(`/api/baas/v1/audit.php?${qs}`);
    if(version!==state.viewVersion)return;
    state.auditEvents = append ? [...state.auditEvents, ...(data.events || [])] : (data.events || []);
    let view = append ? $('page-content').querySelector('[data-audit-panel]') : null;
    if (!view) { view = panel('API操作履歴', 'APIキーや秘密値は履歴に含めません。'); view.dataset.auditPanel = 'true'; }
    const form = view.querySelector('[data-audit-filter]') || element('form', 'toolbar');
    form.dataset.auditFilter = 'true';
    if (!form.querySelector('input')) {
      const operation = element('input'); operation.type = 'search'; operation.placeholder = '操作名で検索'; operation.setAttribute('aria-label','操作名'); operation.value = filter.operation;
      const clientId = element('input'); clientId.type = 'number'; clientId.min = '1'; clientId.placeholder = 'Client ID'; clientId.value = filter.clientId; clientId.setAttribute('aria-label', 'Client ID');
      const status = document.createElement('select'); [['', 'すべての結果'], ['success', '成功 (2xx)'], ['client_error', 'クライアントエラー (4xx)'], ['server_error', 'サーバーエラー (5xx)']].forEach(([value, label]) => status.add(new Option(label, value))); status.value = filter.status;
      const submit = element('button', 'button button-secondary', '絞り込む'); submit.type = 'submit'; form.append(operation, clientId, status, submit);
      form.addEventListener('submit', (event) => { event.preventDefault(); state.auditFilter = { operation: operation.value.trim(), clientId: clientId.value.trim(), status: status.value }; auditPage().catch((error) => notice(error.message, true)); });
    }
    const exportButton = view.querySelector('[data-audit-export]') || button('CSVをダウンロード', () => downloadCsv('tenant-api-audit.csv', [['日時', 'クライアント', '操作', 'HTTP', 'リクエストID'], ...state.auditEvents.map((row) => [row.used_at, row.client_id, row.operation, row.status_code, row.request_id])]));
    exportButton.dataset.auditExport = 'true';
    const oldMore = view.querySelector('[data-audit-more]'); if (oldMore) oldMore.remove();
    const oldTable = view.querySelector('.table-wrap'); if (oldTable) oldTable.remove();const oldEmpty=view.querySelector('.empty-state');if(oldEmpty)oldEmpty.remove();
    const rows = state.auditEvents.map((row) => [dateText(row.used_at), row.client_id, row.operation, element('span',`badge ${Number(row.status_code)<400?'active':'inactive'}`,String(row.status_code)), element('code', 'mono', row.request_id)]);
    view.append(form, exportButton, rows.length?table(['日時', 'クライアント', '操作', 'HTTP', 'リクエストID'], rows):emptyState('該当する操作履歴がありません','検索条件を変更するか、操作後に更新してください。','history'));
    if (data.next_cursor) {
      const more = button('さらに表示', async (event) => { const control = event.currentTarget; control.disabled = true; control.textContent = '読み込み中…'; try { await auditPage(data.next_cursor, true); } catch (error) { control.disabled = false; control.textContent = '再試行'; notice(error.message, true); } }, 'button-secondary');
      more.dataset.auditMore = 'true'; view.append(more);
    }
    if (!append) shell(view,version);
  }

  document.querySelector('.brand').addEventListener('click',event=>{if(state.key||state.tenantSsoSession){event.preventDefault();setPage('overview');}});
  $('account-settings').addEventListener('click',()=>setPage('settings'));
  $('toggle-key').addEventListener('click',()=>{const visible=$('api-key').type==='password';$('api-key').type=visible?'text':'password';$('toggle-key').setAttribute('aria-pressed',String(visible));$('toggle-key').setAttribute('aria-label',visible?'APIキーを隠す':'APIキーを表示');});
  $('environment').addEventListener('change',()=>{$('api-key').placeholder=$('environment').value==='sandbox'?'baas_sandbox_…':'baas_prod_…';});
  $('close-task-dialog').addEventListener('click',()=>{if(!state.taskBusy)$('reissue-dialog').close();$('reissue-content').replaceChildren();$('task-dialog').close();});
  $('task-dialog').addEventListener('cancel',event=>{if(state.taskBusy)event.preventDefault();});
  $('task-dialog').addEventListener('close',()=>{if(!$('task-dialog').open){state.taskVersion++;$('task-content').replaceChildren();}});
  $('connect-form').addEventListener('submit', connect); $('tenant-sso-link-form').addEventListener('submit',linkFirstTenant);  $('switch-tenant').addEventListener('click', switchTenant);     $('disconnect').addEventListener('click', () => { void logoutPortal(); }); $('refresh').addEventListener('click', () => { showLoading(); loadPage().catch((error) => pageFailure(error,state.viewVersion)); }); $('navigation').addEventListener('click', (event) => { const item = event.target.closest('[data-page]'); if (item) setPage(item.dataset.page); }); window.addEventListener('pagehide', () => disconnect(false));
  $('close-reissue-dialog').addEventListener('click',()=>{if(!state.reissueBusy)$('reissue-dialog').close();});
  $('reissue-dialog').addEventListener('cancel',event=>{if(state.reissueBusy)event.preventDefault();});
  $('reissue-dialog').addEventListener('close',()=>{$('reissue-content').replaceChildren();});
  $('tenant-choice-form').addEventListener('submit',event=>{event.preventDefault();const selected=$('tenant-choice-list').querySelector('input[name="tenant-contract"]:checked');if(selected)selectTenantContract(Number(selected.value));});
  $('tenant-choice-add').addEventListener('click',()=>{if(state.tenantSelectionBusy||state.tenantLinkBusy)return;$('tenant-choice-panel').hidden=true;$('tenant-sso-link-panel').hidden=false;$('tenant-choice-back').hidden=!state.memberships.length;$('tenant-sso-api-key').focus();});
  $('tenant-choice-back').addEventListener('click',()=>{if(state.tenantLinkBusy)return;$('tenant-sso-api-key').value='';$('tenant-sso-link-error').textContent='';showTenantChoice();});
  restoreTenantSsoTicket();
})();
