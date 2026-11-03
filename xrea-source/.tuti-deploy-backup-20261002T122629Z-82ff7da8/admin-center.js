(() => {
  'use strict';
  const csrf = document.querySelector('meta[name="admin-csrf"]')?.content || '';
  const endpoint = new URL('ha/web-passkey-manage.php', location.href);
  const list = document.getElementById('passkeys');
  const announce = (message, isError = false) => {
    let node = document.getElementById('admin-toast');
    if (!node) {
      node = document.createElement('div');
      node.id = 'admin-toast';
      node.setAttribute('role', 'status');
      node.setAttribute('aria-live', 'polite');
      document.body.append(node);
    }
    node.textContent = message;
    node.classList.toggle('error', isError);
    node.classList.add('visible');
    window.clearTimeout(announce.timer);
    announce.timer = window.setTimeout(() => node.classList.remove('visible'), 4200);
  };

  document.querySelectorAll('[data-filter-input]').forEach((input) => {
    const listId = input.dataset.filterInput;
    const rows = [...document.querySelectorAll(`[data-filter-row="${CSS.escape(listId || '')}"]`)];
    const empty = document.querySelector(`[data-filter-empty="${CSS.escape(listId || '')}"]`);
    input.addEventListener('input', () => {
      const query = input.value.trim().toLocaleLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const match = row.textContent.toLocaleLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible += 1;
      });
      if (empty) empty.hidden = visible !== 0;
    });
  });

  const tenantPicker = document.getElementById('api-key-tenant');
  tenantPicker?.addEventListener('change', () => {
    document.querySelectorAll('[data-tenant-id]').forEach((row) => {
      row.classList.toggle('is-selected', row.dataset.tenantId === tenantPicker.value);
    });
  });
  tenantPicker?.dispatchEvent(new Event('change'));
  document.addEventListener('click', (event) => {
    const button = event.target instanceof Element ? event.target.closest('[data-select-tenant]') : null;
    if (!(button instanceof HTMLButtonElement) || !(tenantPicker instanceof HTMLSelectElement)) return;
    tenantPicker.value = button.dataset.selectTenant || '';
    tenantPicker.dispatchEvent(new Event('change', { bubbles: true }));
    document.getElementById('api-key-tenant')?.focus({ preventScroll: true });
    document.getElementById('api-key-tenant')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  async function call(action, values = {}) {
    const response = await fetch(endpoint, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ action, ...values }),
    });
    let result;
    try { result = await response.json(); } catch { throw new Error(`応答を読み取れません (HTTP ${response.status})`); }
    if (!response.ok || !result.ok) throw new Error(result.error || `操作に失敗しました (HTTP ${response.status})`);
    return result;
  }

  function actionButton(label, className, action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;
    button.addEventListener('click', action);
    return button;
  }

  async function load() {
    list.setAttribute('aria-busy', 'true');
    list.replaceChildren(Object.assign(document.createElement('div'), { className: 'passkey-empty', textContent: 'パスキーを読み込んでいます…' }));
    try {
      const result = await call('list');
      list.replaceChildren();
      for (const credential of result.credentials || []) {
        const row = document.createElement('article');
        row.className = 'passkey-row';
        const summary = document.createElement('div');
        summary.className = 'passkey-summary';
        const title = document.createElement('b');
        title.textContent = credential.label || '名称未設定';
        const detail = document.createElement('small');
        detail.textContent = `最終利用: ${credential.last_used_at || '未使用'}`;
        summary.append(title, detail);
        const actions = document.createElement('div');
        actions.className = 'passkey-row-actions';
        actions.append(
          actionButton('名前を変更', 'secondary', async () => {
            const label = window.prompt('パスキーの新しい名前', credential.label || '管理用パスキー');
            if (!label?.trim()) return;
            try { await call('rename', { id: credential.id, label: label.trim() }); announce('パスキー名を更新しました'); await load(); }
            catch (error) { announce(error.message, true); }
          }),
          actionButton('失効', 'danger', async () => {
            if (!window.confirm(`「${credential.label || '名称未設定'}」を失効しますか？`)) return;
            try { await call('revoke', { id: credential.id }); announce('パスキーを失効しました'); await load(); }
            catch (error) { announce(error.message, true); }
          }),
        );
        row.append(summary, actions);
        list.append(row);
      }
      if (!list.childElementCount) list.append(Object.assign(document.createElement('div'), { className: 'passkey-empty', textContent: '登録済みパスキーがありません。追加して管理者アクセスを保護してください。' }));
    } catch (error) {
      list.replaceChildren(Object.assign(document.createElement('div'), { className: 'passkey-empty error', textContent: error.message }));
    } finally {
      list.removeAttribute('aria-busy');
    }
  }

  document.getElementById('reload-key')?.addEventListener('click', load);
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.confirmPermanent === '1') {
      const expected = form.dataset.confirmId || '';
      const typed = window.prompt(`完全削除は取り消せません。続行するにはライセンス ID「${expected}」を入力してください。`);
      if (typed !== expected || !window.confirm('関連する端末・電話認証・発行記録も削除します。よろしいですか？')) {
        event.preventDefault();
        return;
      }
      const confirmation = form.elements.namedItem('confirm_id');
      if (confirmation instanceof HTMLInputElement) confirmation.value = typed;
    }
    const submitter = event.submitter;
    let message = form.dataset.confirmMessage || submitter?.dataset.confirmMessage;
    if (form.id === 'license-bulk-form') {
      const count = document.querySelectorAll('.license-select:checked').length;
      const operation = form.elements.namedItem('operation')?.value || '';
      const descriptions = { pause: '選択したライセンスを停止し、登録端末のセッションも失効させます。再開後も端末は再認証が必要です。', resume: '選択したライセンスを再開します。失効済み端末セッションは復元されません。', delete: '選択したライセンスを論理削除します。削除済み一覧から停止状態で復元できます。', restore: '選択したライセンスを停止状態で復元します。', label_prefix: '選択したライセンスのラベル先頭に文字を追加します。' };
      message = `対象 ${count} 件。${descriptions[operation] || '選択した項目を更新します。'} 続けるには直前のパスキー認証が必要です。`;
    }
    if (message && !window.confirm(message)) event.preventDefault();
  });
  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element ? event.target.closest('[data-copy-value]') : null;
    if (!(button instanceof HTMLButtonElement)) return;
    const value = button.dataset.copyValue || '';
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = 'コピーしました';
    } catch {
      const field = document.createElement('textarea');
      field.value = value;
      field.setAttribute('readonly', '');
      field.style.position = 'fixed';
      field.style.opacity = '0';
      document.body.append(field);
      field.select();
      const copied = document.execCommand('copy');
      field.remove();
      button.textContent = copied ? 'コピーしました' : 'コピーできませんでした';
    }
  });
  document.getElementById('create-license-form')?.addEventListener('submit', (event) => {
    if (!window.confirm('入力内容でライセンスを発行します。よろしいですか？')) event.preventDefault();
  });
  const issueForm = document.getElementById('create-license-form');
  const issueMode = issueForm?.elements.namedItem('license_mode');
  if (issueForm && issueMode instanceof HTMLSelectElement) {
    const updateIssueFields = () => {
      const mode = issueMode.value;
      issueForm.querySelector('[data-license-mode-field="volume"]')?.toggleAttribute('hidden', mode !== 'volume');
      issueForm.querySelector('[data-license-mode-field="evaluation"]')?.toggleAttribute('hidden', mode !== 'evaluation');
      issueForm.querySelector('[data-license-mode-field="expiry"]')?.toggleAttribute('hidden', mode === 'evaluation' || mode === 'rejected');
    };
    issueMode.addEventListener('change', updateIssueFields);
    updateIssueFields();
  }
  document.getElementById('add-key')?.addEventListener('click', async () => {
    const label = window.prompt('追加するパスキーの名前', '管理用パスキー');
    if (!label?.trim()) return;
    try {
      const result = await call('enroll', { label: label.trim() });
      if (!result.url) throw new Error('登録URLが返されませんでした');
      location.assign(result.url);
    } catch (error) { announce(error.message, true); }
  });
  if (list) load();
})();
