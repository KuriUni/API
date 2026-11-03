(() => {
  'use strict';

  const panel = document.querySelector('.cluster-status');
  const list = document.querySelector('#cluster-sites');
  const refresh = document.querySelector('#cluster-refresh');
  const updated = document.querySelector('#cluster-updated');
  if (!panel || !list || !refresh || !updated) return;

  const roleLabels = {
    primary: 'Primary',
    standby: 'Standby',
    promoted: 'Promoted',
    maintenance: 'メンテナンス中',
  };

  function render(card, state, detail, role = '') {
    const dot = card.querySelector('.cluster-dot');
    const label = card.querySelector('.cluster-site-state');
    const note = card.querySelector('.cluster-site-role');
    dot.className = `cluster-dot is-${state}`;
    label.textContent = state === 'online' ? '稼働中' : state === 'degraded' ? '要確認' : state === 'checking' ? '確認中' : '応答なし';
    note.textContent = role ? `${roleLabels[role] || '役割確認済み'} · ${detail}` : detail;
  }

  async function check(card) {
    const host = card.dataset.host;
    render(card, 'checking', '状態を取得しています');
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(`https://${host}/license/ha/health.php`, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const payload = await response.json();
      if (response.ok && payload.ok === true) {
        render(card, 'online', '正常に応答しています');
      } else if (payload.probe === 'ready') {
        render(card, 'degraded', 'サイト応答あり・一部機能を確認してください');
      } else {
        render(card, 'offline', '接続先から正常な状態を取得できません');
      }
    } catch {
      render(card, 'offline', '接続できないか、応答が時間切れです');
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function update() {
    const currentHost = panel.dataset.currentHost;
    const cards = [...list.querySelectorAll('.cluster-site')].filter(card => card.dataset.host !== currentHost);
    refresh.disabled = true;
    refresh.setAttribute('aria-busy', 'true');
    refresh.textContent = '確認中';
    await Promise.all(cards.map(check));
    const time = new Intl.DateTimeFormat('ja-JP', {
      hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo',
    }).format(new Date());
    updated.textContent = `最終確認 ${time}（日本時間）`;
    refresh.disabled = false;
    refresh.removeAttribute('aria-busy');
    refresh.textContent = '再確認';
  }

  refresh.addEventListener('click', update);
  update();
})();
