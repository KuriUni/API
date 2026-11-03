(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const token = $('meta[name="ha-session"]').content;
  const apiUrl = $('meta[name="api-url"]').content;
  const form = $('#invoice-form');
  const labels = { draft: '下書き', issued: '発行済み', paid: '入金済み', void: '無効' };
  let invoices = [];
  let preview = null;

  const escapeHtml = (value) => String(value ?? '—').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const statusText = (status) => labels[status] || status || '未設定';
  const money = (value) => `${Number(value || 0).toLocaleString('ja-JP', {
    minimumFractionDigits: 3, maximumFractionDigits: 3
  })} 円`;

  if ($('meta[name="fresh-passkey"]').content !== '1') $('#stepup').hidden = false;

  function notify(message, isError = false) {
    const target = $('#notice');
    target.textContent = message;
    target.classList.toggle('error', isError);
    target.hidden = false;
    target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function api(data) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    let response;
    try {
      response = await fetch(apiUrl, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-HA-Session': token },
        body: JSON.stringify(data),
        signal: controller.signal
      });
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('サーバー応答が15秒以内にありませんでした。');
      throw new Error('サーバーに接続できませんでした。');
    } finally {
      window.clearTimeout(timeout);
    }
    const raw = await response.text();
    let result;
    try { result = JSON.parse(raw); }
    catch { throw new Error(`サーバー応答を読み取れませんでした（HTTP ${response.status}）。`); }
    if (!response.ok || !result.ok) {
      if (result.error === 'passkey_reauthentication_required') $('#stepup').hidden = false;
      const message = result.error === 'not_found'
        ? '管理セッションの期限切れ、または権限不足です。再ログインしてください。'
        : result.error || `HTTP ${response.status}`;
      throw new Error(result.request_id ? `${message}（照合ID: ${result.request_id}）` : message);
    }
    return result;
  }

  function formData() {
    const data = Object.fromEntries(new FormData(form).entries());
    data.tax_rate_basis_points = Math.round(Number(data.tax_rate_percent || 0) * 100);
    delete data.tax_rate_percent;
    return data;
  }

  function updateMetrics(rows) {
    const issued = rows.filter((row) => row.status === 'issued');
    $('#stat-outstanding').textContent = money(issued.reduce((sum, row) => sum + Number(row.total_yen || 0), 0));
    $('#stat-issued').textContent = issued.length.toLocaleString('ja-JP');
    $('#stat-draft').textContent = rows.filter((row) => row.status === 'draft').length.toLocaleString('ja-JP');
    $('#stat-paid').textContent = rows.filter((row) => row.status === 'paid').length.toLocaleString('ja-JP');
    $('#stat-all').textContent = rows.length.toLocaleString('ja-JP');
  }

  function renderPreview(invoice) {
    preview = invoice;
    const card = $('#preview-card');
    const items = invoice.items || invoice.snapshot?.items || [];
    card.innerHTML = `
      <div class="preview-heading"><div><span class="preview-kicker">PREVIEW</span><h3>発行内容の確認</h3></div><span class="preview-number">${escapeHtml(invoice.invoice_number || '新規請求書')}</span></div>
      <div class="preview-summary">
        <div><small>利用料・税抜</small><strong>${money(invoice.subtotal_yen)}</strong></div>
        <div><small>消費税</small><strong>${money(invoice.tax_yen)}</strong></div>
        <div class="preview-total"><small>請求合計</small><strong>${money(invoice.total_yen)}</strong></div>
      </div>
      <div class="preview-meta"><span>${escapeHtml(invoice.customer_name)}</span><span>${escapeHtml(invoice.period || invoice.billing_period)}</span><span>期限 ${escapeHtml(invoice.due_date)}</span></div>
      ${invoice.mode === 'TEST_ONLY' ? '<p class="mode-warning">テスト料金設定で計算しています。実運用の請求額として発行しないでください。</p>' : ''}
      <div class="table-scroll"><table class="items"><thead><tr><th>請求項目</th><th>環境</th><th>数量</th><th>単価</th><th>金額</th></tr></thead><tbody>${items.map((item) => `<tr><td>${escapeHtml(item.description)}</td><td>${escapeHtml(item.environment)}</td><td>${Number(item.quantity || 0).toLocaleString('ja-JP')} ${escapeHtml(item.unit)}</td><td>${money(item.unit_price_yen)}</td><td>${money(item.amount_yen)}</td></tr>`).join('') || '<tr><td colspan="5">利用明細はありません。</td></tr>'}</tbody></table></div>`;
    card.hidden = false;
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function loadTenants() {
    const select = $('#tenant');
    const status = $('#tenant-status');
    const retry = $('#retry-tenants');
    select.disabled = true;
    retry.disabled = true;
    retry.hidden = true;
    status.hidden = false;
    status.classList.remove('is-error');
    status.textContent = 'テナント一覧を取得しています…';
    try {
      const result = await api({ action: 'tenants' });
      const tenants = result.tenants || [];
      select.innerHTML = tenants.map((tenant) =>
        `<option value="${Number(tenant.id)}">${escapeHtml(tenant.name)} · ${escapeHtml(tenant.slug)}</option>`
      ).join('') || '<option value="">テナントがありません</option>';
      select.disabled = tenants.length === 0;
      status.textContent = tenants.length ? `${tenants.length.toLocaleString('ja-JP')} 件のテナントを読み込みました。` : '請求対象のテナントがありません。';
      status.classList.toggle('is-error', tenants.length === 0);
      if (result.mode === 'TEST_ONLY') {
        const mode = $('#mode-note');
        mode.textContent = '料金設定は TEST_ONLY です。実運用の請求額として発行できる状態ではありません。';
        mode.hidden = false;
      }
    } catch (error) {
      select.innerHTML = '<option value="">読み込みに失敗しました</option>';
      select.disabled = true;
      status.textContent = `テナントを読み込めませんでした。${error.message}`;
      status.classList.add('is-error');
      retry.hidden = false;
      notify(`テナント一覧を取得できません: ${error.message}`, true);
    } finally {
      retry.disabled = false;
    }
  }

  function invoiceMarkup(invoice, index) {
    const items = invoice.snapshot?.items || [];
    const status = String(invoice.status || 'unknown').replace(/[^a-z0-9_-]/gi, '');
    return `<article class="invoice-card">
      <button class="invoice-head" type="button" data-open="${index}" aria-expanded="false" aria-controls="detail-${index}">
        <span class="invoice-symbol" aria-hidden="true">¥</span>
        <span class="invoice-title"><b>${escapeHtml(invoice.invoice_number)} <span class="invoice-separator">·</span> ${escapeHtml(invoice.customer_name)}</b><small>${escapeHtml(invoice.billing_period)} <span>／</span> ${escapeHtml(invoice.account_slug)}</small></span>
        <span class="invoice-total"><small>請求額</small><strong>${money(invoice.total_yen)}</strong></span>
        <span class="invoice-status status-${status}">${escapeHtml(statusText(invoice.status))}</span>
        <span class="invoice-chevron" aria-hidden="true">⌄</span>
      </button>
      <div class="invoice-detail" id="detail-${index}" hidden>
        <dl><div><dt>発行日</dt><dd>${escapeHtml(invoice.issue_date)}</dd></div><div><dt>支払期限</dt><dd>${escapeHtml(invoice.due_date)}</dd></div><div><dt>税抜</dt><dd>${money(invoice.subtotal_yen)}</dd></div><div><dt>消費税</dt><dd>${money(invoice.tax_yen)}</dd></div><div><dt>請求状態</dt><dd>${escapeHtml(statusText(invoice.status))}</dd></div><div><dt>備考</dt><dd>${escapeHtml(invoice.notes || '—')}</dd></div></dl>
        <div class="table-scroll"><table class="items"><thead><tr><th>請求項目</th><th>環境</th><th>数量</th><th>単価</th><th>金額</th></tr></thead><tbody>${items.map((item) => `<tr><td>${escapeHtml(item.description)}</td><td>${escapeHtml(item.environment)}</td><td>${Number(item.quantity || 0).toLocaleString('ja-JP')} ${escapeHtml(item.unit)}</td><td>${money(item.unit_price_yen)}</td><td>${money(item.amount_yen)}</td></tr>`).join('') || '<tr><td colspan="5">明細なし</td></tr>'}</tbody></table></div>
        <div class="invoice-actions">${invoice.status === 'issued' ? `<button type="button" data-action="mark_paid" data-id="${Number(invoice.id)}" class="secondary">入金済みにする</button>` : ''}${['draft', 'issued'].includes(invoice.status) ? `<button type="button" data-action="void" data-id="${Number(invoice.id)}" class="quiet">無効にする</button>` : ''}${invoice.status === 'draft' ? `<button type="button" data-action="delete_draft" data-id="${Number(invoice.id)}" class="quiet">下書きを削除</button>` : ''}</div>
      </div>
    </article>`;
  }

  function renderList() {
    const query = $('#invoice-search').value.trim().toLocaleLowerCase('ja-JP');
    const statusFilter = $('#invoice-filter').value;
    const visible = invoices.filter((invoice) => {
      const matchesStatus = statusFilter === 'all' || invoice.status === statusFilter;
      const searchable = [invoice.invoice_number, invoice.customer_name, invoice.account_slug, invoice.billing_period].join(' ').toLocaleLowerCase('ja-JP');
      return matchesStatus && (!query || searchable.includes(query));
    });
    $('#invoice-result-count').textContent = `${visible.length.toLocaleString('ja-JP')} 件`;
    const list = $('#invoice-list');
    if (!invoices.length) {
      list.innerHTML = '<div class="empty-state"><span class="empty-icon" aria-hidden="true">¥</span><h3>請求書はまだありません</h3><p>請求対象を選び、利用明細を確認して作成してください。</p><a href="#invoice-create">最初の請求書を作成</a></div>';
      return;
    }
    if (!visible.length) {
      list.innerHTML = '<div class="empty-state compact-empty"><h3>条件に合う請求書がありません</h3><p>検索語を短くするか、状態の絞り込みを変更してください。</p><button type="button" class="quiet" id="clear-invoice-filters">絞り込みを解除</button></div>';
      return;
    }
    list.innerHTML = visible.map(invoiceMarkup).join('');
  }

  async function loadList() {
    const refresh = $('#refresh');
    refresh.disabled = true;
    refresh.classList.add('is-loading');
    $('#invoice-list').innerHTML = '<div class="loading-state"><span class="loading-spinner" aria-hidden="true"></span><span>請求データを読み込んでいます…</span></div>';
    try {
      const result = await api({ action: 'list' });
      invoices = result.invoices || [];
      updateMetrics(invoices);
      renderList();
    } catch (error) {
      $('#invoice-list').innerHTML = '<div class="empty-state compact-empty"><h3>請求一覧を読み込めません</h3><p>接続を確認し、更新をお試しください。</p></div>';
      notify(`一覧を取得できません: ${error.message}`, true);
    } finally {
      refresh.disabled = false;
      refresh.classList.remove('is-loading');
    }
  }

  async function create(action) {
    if (!form.reportValidity()) return;
    try {
      const result = await api({ ...formData(), action });
      const issuedInvoice = result.invoice;
      notify(action === 'issue' ? '請求書を発行しました。' : '下書きを保存しました。');
      renderPreview(issuedInvoice.snapshot || issuedInvoice || preview || {});
      await loadList();
    } catch (error) {
      notify(`処理できません: ${error.message}`, true);
    }
  }

  $('#preview').addEventListener('click', async () => {
    if (!form.reportValidity()) return;
    try {
      const result = await api({ ...formData(), action: 'preview' });
      renderPreview(result.invoice);
    } catch (error) {
      notify(`プレビューに失敗しました: ${error.message}`, true);
    }
  });
  $('#save-draft').addEventListener('click', () => create('save_draft'));
  $('#issue').addEventListener('click', () => {
    if (!form.reportValidity()) return;
    if (window.confirm('この内容で請求書を発行しますか？発行後は明細が固定されます。')) create('issue');
  });
  $('#refresh').addEventListener('click', loadList);
  $('#retry-tenants').addEventListener('click', loadTenants);
  $('#invoice-search').addEventListener('input', renderList);
  $('#invoice-filter').addEventListener('change', renderList);
  $('#toggle-form').addEventListener('click', () => {
    form.hidden = !form.hidden;
    const button = $('#toggle-form');
    button.textContent = form.hidden ? 'フォームを開く' : 'フォームをたたむ';
    button.setAttribute('aria-expanded', String(!form.hidden));
  });
  $('#invoice-list').addEventListener('click', async (event) => {
    const clearButton = event.target.closest('#clear-invoice-filters');
    if (clearButton) {
      $('#invoice-search').value = '';
      $('#invoice-filter').value = 'all';
      renderList();
      return;
    }
    const button = event.target.closest('button');
    if (!button) return;
    if (button.dataset.open !== undefined) {
      const detail = $(`#detail-${button.dataset.open}`);
      detail.hidden = !detail.hidden;
      button.setAttribute('aria-expanded', String(!detail.hidden));
      return;
    }
    if (!button.dataset.action) return;
    if (!window.confirm('請求書の状態を変更します。続けますか？')) return;
    button.disabled = true;
    try {
      await api({ action: button.dataset.action, invoice_id: Number(button.dataset.id) });
      notify('請求書を更新しました。');
      await loadList();
    } catch (error) {
      button.disabled = false;
      notify(`更新できません: ${error.message}`, true);
    }
  });

  const now = new Date();
  const localToday = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
  form.elements.period.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  form.elements.issue_date.value = localToday;
  const due = new Date(now);
  due.setDate(due.getDate() + 30);
  form.elements.due_date.value = new Date(due.getTime() - due.getTimezoneOffset() * 60000).toISOString().slice(0, 10);

  loadTenants();
  loadList();
})();
