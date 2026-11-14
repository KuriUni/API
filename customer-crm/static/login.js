(() => {
  const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  const submit = document.getElementById('login-submit');
  const hint = document.getElementById('demo-hint');

  fetch('/api/auth-info', { credentials: 'same-origin' })
    .then(response => response.ok ? response.json() : null)
    .then(info => { if (info?.demo_mode) hint.hidden = false; })
    .catch(() => {});

  form.addEventListener('submit', async event => {
    event.preventDefault();
    error.hidden = true;
    submit.disabled = true;
    submit.textContent = '確認中…';
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        error.textContent = data.detail || 'ログインできませんでした';
        error.hidden = false;
        return;
      }
      location.replace('/');
    } catch {
      error.textContent = '通信に失敗しました。時間をおいて再試行してください。';
      error.hidden = false;
    } finally {
      submit.disabled = false;
      submit.textContent = 'ログイン';
    }
  });

  document.documentElement.dataset.loginReady = '1';
})();
