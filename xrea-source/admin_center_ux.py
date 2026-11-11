"""Progressive UX enhancements for the Python admin center.

The admin page has grown into a single long document.  These additions keep the
existing server-rendered controls intact while making the page easier to scan:
a command palette, session/permission chips, toast feedback, copy buttons for
one-time secrets, a client-side table filter, active section navigation and a
back-to-top control.
"""
import html


CSS = '''
.wrap>header{flex-wrap:wrap}
.wrap>header>div:first-child{flex:1 1 420px;min-width:0}
.admin-tools{display:flex;align-items:center;justify-content:flex-end;gap:9px;flex-wrap:wrap;min-width:0}
.admin-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
#logout{flex:0 0 auto;white-space:nowrap}
@media(min-width:761px){.admin-tools{margin-left:auto}}
.meta-chip{display:inline-flex;align-items:center;min-height:28px;padding:3px 9px;border:1px solid #d4e2df;border-radius:999px;background:#f4f8f7;color:#476468;font-size:11px;font-weight:700;line-height:1.35;text-decoration:none;white-space:nowrap}
.meta-chip.ok{border-color:#b6dfd2;background:#eaf7f1;color:#176447}
.meta-chip.warn{border-color:#ecd7a8;background:#fff8e9;color:#8a5a12}
.meta-chip.role{border-color:#b9d9d8;background:#edf8f6;color:#08675e}
.meta-chip:hover{filter:brightness(.98)}
.cmdk-trigger{display:inline-flex;align-items:center;gap:7px;min-height:34px;padding:5px 10px;border:1px solid #b9d7d2;border-radius:9px;background:#fff;color:#20585a;font:inherit;font-size:12px;font-weight:700;cursor:pointer}
.cmdk-trigger:hover{background:#f3fbf9;border-color:#8ac8be}
.cmdk-trigger kbd{padding:1px 5px;border:1px solid #d7e4e1;border-radius:5px;background:#f4f8f7;color:#617a7b;font:10px/1.5 ui-monospace,monospace}
.quick-nav a.active{border-color:#5ab5a6;background:#effaf7;color:#065e56;box-shadow:inset 0 0 0 1px #9ed8ce}
.quick-nav a.active small{color:#08796d}
.quick-nav a:focus-visible,.cmdk-item:focus-visible,.copy-button:focus-visible{outline:2px solid #08796d;outline-offset:2px}
.list-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0 0}
.list-tools label{margin:0;white-space:nowrap}
.list-tools input{flex:1 1 240px;min-width:0}
#license-results{max-height:70vh;overflow:auto;border-radius:4px}
#license-results thead th{position:sticky;top:0;z-index:1;background:#eef5f3;box-shadow:inset 0 -1px 0 #dbe8e5}
#license-results td button{margin:2px}
#license-results tbody tr:hover{background:#f8fbfa}
.copy-button{min-height:30px;margin:4px 0 4px 8px;padding:4px 9px;font-size:12px}
.toast-region{position:fixed;right:18px;bottom:18px;z-index:1200;display:flex;flex-direction:column;gap:8px;width:min(380px,calc(100vw - 36px));pointer-events:none}
.toast{display:flex;align-items:flex-start;gap:10px;padding:11px 12px;border:1px solid #cfe3df;border-left:4px solid #08796d;border-radius:10px;background:#fff;box-shadow:0 10px 30px #17343b24;color:#18353b;font-size:13px;line-height:1.5;pointer-events:auto;animation:toast-in .18s ease-out}
.toast.error{border-left-color:#b33a46;color:#8d2530}
.toast.success{border-left-color:#18825c}
.toast.leaving{opacity:0;transform:translateY(5px);transition:opacity .2s,transform .2s}
.toast span{flex:1;overflow-wrap:anywhere}
.toast button{min-height:24px;padding:0 4px;border:0;background:transparent;color:#7a8e8e;font-size:17px;line-height:1;cursor:pointer}
@keyframes toast-in{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
.cmdk{position:fixed;inset:0;z-index:1100;display:grid;place-items:start center;padding:10vh 12px 24px}
.cmdk[hidden]{display:none}
.cmdk-backdrop{position:absolute;inset:0;background:#0c2226b8;backdrop-filter:blur(3px)}
.cmdk-panel{position:relative;width:min(660px,100%);max-height:min(76vh,680px);display:flex;flex-direction:column;overflow:hidden;border:1px solid #cfe0dd;border-radius:17px;background:#fff;box-shadow:0 24px 70px #061c20a6}
.cmdk-head{padding:14px 16px 10px;border-bottom:1px solid #e6efed}
.cmdk-head label{display:block;margin:0 0 7px;color:#6a8183;font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.cmdk-head input{width:100%;min-height:42px;padding:10px 12px;border:1px solid #b9d3d0;border-radius:9px;font:inherit;font-size:15px}
.cmdk-list{overflow:auto;padding:8px;display:flex;flex-direction:column;gap:3px}
.cmdk-empty{padding:24px 14px;color:#718589;text-align:center}
.cmdk-item{display:flex;align-items:center;justify-content:space-between;gap:14px;width:100%;min-height:48px;padding:8px 11px;border:1px solid transparent;border-radius:9px;background:transparent;color:#18353b;font:inherit;text-align:left;cursor:pointer}
.cmdk-item:hover,.cmdk-item[aria-selected="true"]{border-color:#bfe2db;background:#effaf7}
.cmdk-item b{display:block;font-size:14px}
.cmdk-item small{display:block;margin-top:1px;color:#6d8385;font-size:11px}
.cmdk-item .go{color:#7a9694;font-size:13px}
.cmdk-help{padding:9px 16px;border-top:1px solid #e6efed;color:#74898a;font-size:11px}
.cmdk-help kbd{padding:0 4px;border:1px solid #dbe6e4;border-radius:4px;background:#f6f9f8;font:10px/1.6 ui-monospace,monospace}
#back-top{position:fixed;right:18px;bottom:82px;z-index:900;display:grid;place-items:center;width:40px;height:40px;border:1px solid #c7dcd8;border-radius:999px;background:#fffffff2;color:#255d5d;font-size:18px;box-shadow:0 6px 20px #17343b1f;cursor:pointer}
#back-top[hidden]{display:none}
#back-top:hover{background:#effaf7}
.section-flash{animation:section-flash 1.1s ease-out}
@keyframes section-flash{0%{box-shadow:0 0 0 3px #5ab5a666}100%{box-shadow:0 6px 24px #17343b0c}}
@media(max-width:760px){
 .wrap>header>div:first-child{flex:1 1 100%}
 .admin-tools{width:100%;justify-content:flex-start}
 .admin-meta{width:100%}
 .cmdk-trigger{order:2}
 #logout{order:3}
 .meta-chip{font-size:10px;padding:3px 7px}
 .cmdk{padding:5vh 8px 12px}
 .cmdk-panel{max-height:84vh}
 .list-tools{gap:6px}
 .list-tools input{flex:1 1 100%}
 #license-results{max-height:none}
 .quick-nav{display:flex;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:thin}
 .quick-nav a{flex:0 0 165px}
 #back-top{bottom:76px;right:12px}
 .toast-region{right:10px;bottom:10px;width:calc(100vw - 20px)}
}
@media(prefers-reduced-motion:reduce){.toast,.section-flash{animation:none!important}}
'''


def _header_tools(role_label, passkey_recent, step_up_url):
    if passkey_recent:
        passkey = '<span class="meta-chip ok" title="直近2分以内にPasskeyで再認証済み">Passkey: 再認証済み</span>'
    else:
        passkey = ('<a class="meta-chip warn" href="%s" title="発行・変更などの操作前にPasskeyで再認証してください">'
                   'Passkey: 再認証する</a>' % html.escape(step_up_url, quote=True))
    return (
        '<div class="admin-tools">'
        '<button type="button" class="cmdk-trigger" id="cmdk-open" aria-haspopup="dialog" '
        'aria-controls="cmdk">検索・移動 <kbd>Ctrl K</kbd></button>'
        '<div class="admin-meta" aria-label="権限とセッションの状態">'
        '<span class="meta-chip role" title="現在の管理者権限">権限: %s</span>'
        '%s'
        '<span class="meta-chip" title="管理セッションは無操作が30分続くと終了します">30分で自動終了</span>'
        '</div>' % (html.escape(role_label), passkey)
    )


def _overlay_html():
    return '''
<div class="toast-region" id="toast-region" aria-live="polite" aria-atomic="false"></div>
<div class="cmdk" id="cmdk" hidden>
  <div class="cmdk-backdrop" data-cmdk-close></div>
  <div class="cmdk-panel" role="dialog" aria-modal="true" aria-labelledby="cmdk-title">
    <div class="cmdk-head">
      <label id="cmdk-title" for="cmdk-input">管理センター内を検索・移動</label>
      <input id="cmdk-input" type="search" autocomplete="off" spellcheck="false" placeholder="例: ライセンス、監査、APIキー、請求書">
    </div>
    <div class="cmdk-list" id="cmdk-list" role="listbox" aria-labelledby="cmdk-title"></div>
    <div class="cmdk-help"><kbd>↑</kbd><kbd>↓</kbd> 選択　<kbd>Enter</kbd> 実行　<kbd>Esc</kbd> 閉じる　<kbd>Ctrl K</kbd> でいつでも開く</div>
  </div>
</div>
<button id="back-top" type="button" hidden aria-label="ページ上部へ戻る">↑</button>
'''


JS = r'''
(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  const typing = (target) => target && (target.matches('input, textarea, select') || target.isContentEditable);

  // Toast notifications for existing status elements -----------------------
  const toastRegion = byId('toast-region');
  const noisy = /(しています|取得中|読み込み中|処理中|待機|コピーしました)/;
  const truncate = (value, limit) => value.length > limit ? value.slice(0, limit - 1) + '…' : value;
  function toast(message, kind) {
    if (!toastRegion || !message) return;
    const item = document.createElement('div');
    item.className = 'toast ' + (kind || 'success');
    const text = document.createElement('span');
    text.textContent = truncate(String(message), 180);
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '×';
    close.setAttribute('aria-label', '通知を閉じる');
    close.addEventListener('click', () => item.remove());
    item.append(text, close);
    toastRegion.append(item);
    setTimeout(() => { item.classList.add('leaving'); setTimeout(() => item.remove(), 220); }, 5200);
  }
  function watchStatus(id, label) {
    const el = byId(id);
    if (!el) return;
    let last = '';
    const check = () => {
      const text = (el.textContent || '').trim();
      if (!text || text === last || noisy.test(text)) return;
      last = text;
      const failed = el.classList.contains('error');
      toast(failed || !label ? text : label(text), failed ? 'error' : 'success');
    };
    new MutationObserver(check).observe(el, { childList: true, characterData: true, subtree: true });
    check();
  }
  watchStatus('status');
  watchStatus('license-status');
  watchStatus('tenant-status');
  watchStatus('csv-status', () => 'CSV一括発行を処理しました。結果を確認してください。');
  watchStatus('issued-key', () => 'ライセンスを発行しました。表示中のキーをコピーして保管してください。');
  watchStatus('tenant-key-secret', () => 'APIキーを更新しました。表示中のキーをコピーして保管してください。');
  watchStatus('password-status');
  watchStatus('contractor-status');
  watchStatus('sso-identity-status');
  watchStatus('one-time-grant-status');

  // Copy buttons for one-time secrets --------------------------------------
  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      toast('クリップボードにコピーしました。', 'success');
    } catch (error) {
      const area = document.createElement('textarea');
      area.value = value;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      try {
        document.execCommand('copy');
        toast('クリップボードにコピーしました。', 'success');
      } catch (fallbackError) {
        toast('コピーできませんでした。表示中の値を手動で選択してください。', 'error');
      } finally {
        area.remove();
      }
    }
  }
  function installCopy(id, extract, label) {
    const el = byId(id);
    if (!el) return;
    let last = '';
    const update = () => {
      const text = (el.textContent || '').trim();
      if (!text || text === last) return;
      last = text;
      const value = extract(text);
      if (!value) return;
      let button = el.nextElementSibling;
      if (!button || !button.classList.contains('copy-button')) {
        button = document.createElement('button');
        button.type = 'button';
        button.className = 'secondary copy-button';
        button.textContent = label || 'コピー';
        el.insertAdjacentElement('afterend', button);
      }
      button.onclick = () => copyText(value);
    };
    new MutationObserver(update).observe(el, { childList: true, characterData: true, subtree: true });
    update();
  }
  installCopy('issued-key', (text) => {
    const marker = text.match(/発行キー[^:]*:\s*([^\s/]+)/);
    const fallback = text.match(/([A-Z0-9][A-Z0-9-]{15,})/);
    return marker ? marker[1] : (fallback ? fallback[1] : '');
  });
  installCopy('tenant-key-secret', (text) => {
    const marker = text.match(/APIキー[^:]*:\s*(\S+)/);
    const fallback = text.match(/([A-Za-z0-9][A-Za-z0-9._-]{19,})/);
    return marker ? marker[1] : (fallback ? fallback[1] : '');
  }, 'キーをコピー');
  installCopy('csv-status', (text) => {
    const keys = text.match(/([A-Z0-9][A-Z0-9-]{15,})/g);
    return keys && keys.length ? keys.join('\n') : '';
  }, '全キーをコピー');

  // Table filter -----------------------------------------------------------
  const filter = byId('license-filter');
  const filterCount = byId('license-filter-count');
  const resultBox = byId('license-results');
  function applyFilter() {
    if (!filter || !resultBox) return;
    const query = filter.value.trim().toLowerCase();
    const rows = [...resultBox.querySelectorAll('tbody tr')];
    if (!rows.length) { if (filterCount) filterCount.textContent = ''; return; }
    let shown = 0;
    for (const row of rows) {
      const match = !query || (row.textContent || '').toLowerCase().includes(query);
      row.hidden = !match;
      if (match) shown += 1;
      else {
        const pick = row.querySelector('.license-pick');
        if (pick) pick.checked = false;
      }
    }
    if (filterCount) filterCount.textContent = shown + ' / ' + rows.length + ' 件';
    if (typeof window.updateBulkButton === 'function') window.updateBulkButton();
  }
  if (filter) filter.addEventListener('input', applyFilter);
  if (resultBox) new MutationObserver(applyFilter).observe(resultBox, { childList: true, subtree: true });

  // Active section navigation ---------------------------------------------
  const navLinks = new Map([...document.querySelectorAll('.quick-nav a[href^="#"]')]
    .map((link) => [link.getAttribute('href').slice(1), link]));
  if ('IntersectionObserver' in window && navLinks.size) {
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        navLinks.forEach((link) => { link.classList.remove('active'); link.removeAttribute('aria-current'); });
        const active = navLinks.get(entry.target.id);
        if (active) { active.classList.add('active'); active.setAttribute('aria-current', 'location'); }
      }
    }, { rootMargin: '-120px 0px -62% 0px', threshold: 0 });
    document.querySelectorAll('section.card[id]').forEach((section) => observer.observe(section));
  }

  // Command palette --------------------------------------------------------
  const catalog = [
    { id: 'device-management', label: '端末・セッション', detail: '登録端末と有効セッションを確認', keys: 'device session terminal 端末' },
    { id: 'license-management', label: 'ライセンス管理', detail: '一覧・監査ログ・一括操作', keys: 'license audit 監査 一括' },
    { id: 'license-issuance', label: 'ライセンス発行', detail: '個別発行・CSV一括発行', keys: 'issue csv 発行' },
    { id: 'tenant-management', label: 'テナント管理', detail: '契約先とAPIクライアント', keys: 'tenant api key 契約' },
    { id: 'api-workbench-link', label: '業務API実行', detail: '契約先のBaaS APIを試す', keys: 'workbench baas api' },
    { id: 'admin-principal-management', label: '管理者設定', detail: '管理者権限とアカウント', keys: 'admin principal role 権限' },
    { id: 'common-id-management', label: '共通ID・所属', detail: 'テナント所属の確認と解除', keys: 'sso common id 所属' },
    { id: 'one-time-issuance-grant', label: '今回1件だけの発行権限', detail: 'SSO IDへ24時間の一時権限', keys: 'grant one time 一時' },
    { id: 'admin-password-change', label: '緊急用パスワード', detail: '管理者パスワードの変更', keys: 'password パスワード' },
    { id: 'error-diagnostics', label: 'エラー診断', detail: 'エラーIDから診断情報を取得', keys: 'error diagnose 診断' },
    { id: 'contractor-sso-create', label: '契約者SSO ID招待', detail: 'メールでパスキー登録を案内', keys: 'contractor invite sso 招待' },
    { id: 'sso-identity-recovery', label: 'SSO ID復旧', detail: '登録メールからSSO IDを照合', keys: 'recovery sso 復旧' },
    { id: 'api-invoices-link', label: 'API請求書', detail: '利用明細・請求書管理を開く', keys: 'invoice billing 請求' }
  ];
  const actions = [
    { label: '有効ライセンス一覧を表示', detail: 'ライセンス管理', keys: 'license list 一覧', section: 'license-management', button: 'load-licenses' },
    { label: '削除済みライセンスを表示', detail: 'ライセンス管理', keys: 'deleted 削除', section: 'license-management', button: 'load-deleted' },
    { label: '監査ログを検索', detail: 'ライセンス管理', keys: 'audit 監査', section: 'license-management', focus: 'audit-q' },
    { label: '電話申請一覧を表示', detail: 'ライセンス管理', keys: 'phone 電話', section: 'license-management', button: 'load-phone' },
    { label: '端末を取得', detail: 'ライセンスID / キーを入力', keys: 'device terminal 端末', section: 'device-management', focus: 'license' },
    { label: '契約先一覧を表示', detail: 'テナント管理', keys: 'tenant 契約', section: 'tenant-management', button: 'load-tenants' },
    { label: 'APIクライアント一覧を表示', detail: 'テナント管理', keys: 'api key client apiキー', section: 'tenant-management', button: 'load-tenant-keys' },
    { label: '管理者一覧を取得', detail: '管理者設定', keys: 'admin principal 管理者', section: 'admin-principal-management', button: 'load-admin-principals' },
    { label: '共通IDの所属を確認', detail: '共通ID・所属', keys: 'sso membership 所属', section: 'common-id-management', button: 'load-common-id-memberships' },
    { label: 'API請求書を開く', detail: '請求書管理', keys: 'invoice billing 請求', href: 'admin_api.php?view=api-invoices' },
    { label: '管理者向けヘルプを開く', detail: '操作手順と困ったとき', keys: 'help ヘルプ', href: 'admin_api.php?view=help' }
  ];
  const cmdk = byId('cmdk');
  const cmdkInput = byId('cmdk-input');
  const cmdkList = byId('cmdk-list');
  const cmdkOpen = byId('cmdk-open');
  let activeItems = [];
  let selected = 0;
  let previousFocus = null;
  function visible(id) {
    const el = byId(id);
    return Boolean(el && !el.hidden && getComputedStyle(el).display !== 'none');
  }
  function scrollToSection(id) {
    const section = byId(id);
    if (!section) return;
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    section.classList.remove('section-flash');
    void section.offsetWidth;
    section.classList.add('section-flash');
    setTimeout(() => section.classList.remove('section-flash'), 1200);
    try { history.replaceState(null, '', '#' + id); } catch (error) { /* ignore */ }
  }
  function runCommand(item) {
    closePalette();
    if (item.href) { location.href = item.href; return; }
    if (item.section) scrollToSection(item.section);
    if (item.focus) {
      const field = byId(item.focus);
      if (field) setTimeout(() => field.focus({ preventScroll: true }), 220);
    }
    if (item.button) {
      const button = byId(item.button);
      if (button && !button.disabled && !button.hidden) setTimeout(() => button.click(), 180);
    }
  }
  function buildItems(query) {
    const q = (query || '').trim().toLowerCase();
    const items = [];
    for (const item of catalog) {
      if (!visible(item.id)) continue;
      items.push({ label: item.label, detail: item.detail, keys: item.keys, section: item.id });
    }
    for (const item of actions) {
      if (item.section && !visible(item.section)) continue;
      if (item.button && (!byId(item.button) || byId(item.button).hidden || byId(item.button).disabled)) continue;
      items.push(item);
    }
    if (!q) return items;
    return items.filter((item) => (item.label + ' ' + (item.detail || '') + ' ' + (item.keys || '')).toLowerCase().includes(q));
  }
  function renderPalette(query) {
    activeItems = buildItems(query);
    selected = 0;
    cmdkList.replaceChildren();
    if (!activeItems.length) {
      const empty = document.createElement('div');
      empty.className = 'cmdk-empty';
      empty.textContent = '一致する項目がありません。別の言葉で検索してください。';
      cmdkList.append(empty);
      return;
    }
    activeItems.forEach((item, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'cmdk-item';
      button.setAttribute('role', 'option');
      button.setAttribute('aria-selected', index === selected ? 'true' : 'false');
      const text = document.createElement('span');
      const label = document.createElement('b');
      label.textContent = item.label;
      text.append(label);
      if (item.detail) {
        const detail = document.createElement('small');
        detail.textContent = item.detail;
        text.append(detail);
      }
      const go = document.createElement('span');
      go.className = 'go';
      go.textContent = item.button ? '実行' : '開く';
      button.append(text, go);
      button.addEventListener('click', () => runCommand(item));
      button.addEventListener('mousemove', () => selectPalette(index));
      cmdkList.append(button);
    });
  }
  function selectPalette(index) {
    if (!activeItems.length) return;
    selected = Math.max(0, Math.min(activeItems.length - 1, index));
    [...cmdkList.querySelectorAll('.cmdk-item')].forEach((item, position) => {
      item.setAttribute('aria-selected', position === selected ? 'true' : 'false');
      if (position === selected) item.scrollIntoView({ block: 'nearest' });
    });
  }
  function openPalette() {
    if (!cmdk) return;
    previousFocus = document.activeElement;
    cmdk.hidden = false;
    cmdkInput.value = '';
    renderPalette('');
    setTimeout(() => cmdkInput.focus(), 20);
  }
  function closePalette() {
    if (!cmdk) return;
    cmdk.hidden = true;
    if (previousFocus && previousFocus.focus) previousFocus.focus({ preventScroll: true });
  }
  if (cmdkOpen) cmdkOpen.addEventListener('click', openPalette);
  if (cmdk) {
    cmdk.querySelectorAll('[data-cmdk-close]').forEach((element) => element.addEventListener('click', closePalette));
    cmdkInput.addEventListener('input', () => renderPalette(cmdkInput.value));
    cmdk.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') { event.preventDefault(); closePalette(); return; }
      if (event.key === 'ArrowDown') { event.preventDefault(); selectPalette(selected + 1); return; }
      if (event.key === 'ArrowUp') { event.preventDefault(); selectPalette(selected - 1); return; }
      if (event.key === 'Enter' && activeItems.length) { event.preventDefault(); runCommand(activeItems[selected]); }
    });
  }
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && cmdk && !cmdk.hidden) { event.preventDefault(); closePalette(); return; }
    if (event.key === 'Enter' && (event.target.id === 'license' || event.target.id === 'search')) {
      const loadButton = byId('load');
      if (loadButton && !loadButton.disabled) { event.preventDefault(); loadButton.click(); }
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openPalette();
      return;
    }
    if (cmdk && !cmdk.hidden) return;
    if (event.key === '/' && !typing(event.target)) {
      event.preventDefault();
      const license = byId('license');
      if (license && !license.closest('[hidden]')) { license.focus(); license.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
      else openPalette();
    }
  });

  // Back to top ------------------------------------------------------------
  const backTop = byId('back-top');
  if (backTop) {
    const updateBackTop = () => { backTop.hidden = window.scrollY < 560; };
    window.addEventListener('scroll', updateBackTop, { passive: true });
    updateBackTop();
    backTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }
})();
'''


def enhance_admin_center(page, role_label, passkey_recent, step_up_url):
    """Apply additive CSS/HTML/JS to the already rendered admin page bytes."""
    page = page.replace(b'</style>', CSS.encode('utf-8') + b'</style>', 1)
    page = page.replace(
        '<button class="secondary" id="logout">ログアウト</button>'.encode('utf-8'),
        (_header_tools(role_label, passkey_recent, step_up_url)
         + '<button class="secondary" id="logout">ログアウト</button></div>').encode('utf-8'),
        1,
    )
    page = page.replace(
        b'<div id="license-results"></div>',
        ('<div class="list-tools"><label for="license-filter">表示中の行を絞り込む</label>'
         '<input id="license-filter" type="search" autocomplete="off" placeholder="ID・ラベル・状態・操作名で検索">'
         '<span id="license-filter-count" class="muted" role="status"></span></div>'
         '<div id="license-results"></div>').encode('utf-8'),
        1,
    )
    page = page.replace(
        b'</body>',
        _overlay_html().encode('utf-8') + b'<script>' + JS.encode('utf-8') + b'</script></body>',
        1,
    )
    return page
