(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let secret = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  let cleared = false, timer, envelope = null, keyData = null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  function clear(message = '結果を消去しました。もう一度見る場合は、新しいQRを発行してください。') {
    cleared = true; secret = ''; envelope = null;
    if (keyData) keyData.fill(0); keyData = null;
    controller.abort(); clearTimeout(timer); clearTimeout(timeout);
    $('photo').removeAttribute('src'); $('attributes').textContent = ''; $('match').textContent = '';
    $('result').hidden = true; $('open').hidden = true; $('state').textContent = message;
  }
  $('clear').onclick = () => clear();
  document.addEventListener('visibilitychange', () => { if (document.hidden) clear(); });
  window.addEventListener('pagehide', () => clear());
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  if (!/^[a-f0-9]{32}\.[a-f0-9]{48}\.[A-Za-z0-9_-]{43}$/.test(secret)) {
    clear('QRの情報が正しくありません。新しいQRを読み取ってください。'); return;
  }
  $('open').disabled = true;
  // Claim immediately so refreshing the sender does not interrupt an open page.
  (async () => {
    try {
      if (!crypto.subtle) throw new Error('crypto');
      const [id, token, encodedKey] = secret.split('.'); secret = '';
      const response = await fetch(location.pathname, {method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action: 'read', id, token})});
      if (!response.ok) throw new Error('unavailable');
      const received = await response.json();
      if (cleared) return;
      envelope = received; keyData = decode(encodedKey);
      timer = setTimeout(() => clear(), 60000);
      $('open').disabled = false;
      $('state').textContent = '結果を取得しました。取得から60秒以内に「結果を表示する」を押してください。';
    } catch (_) { if (!cleared) clear('結果を取得できませんでした。送信元の最新QRを読み取ってください。'); }
    finally { clearTimeout(timeout); }
  })();
  $('open').onclick = async () => {
    if (cleared || !envelope || !keyData) return;
    $('open').disabled = true;
    try {
      const received = envelope; envelope = null;
      const key = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, ['decrypt']);
      if (keyData) keyData.fill(0); keyData = null;
      const plain = await crypto.subtle.decrypt({name: 'AES-GCM', iv: decode(received.iv)}, key, decode(received.cipher));
      const data = JSON.parse(new TextDecoder().decode(plain)); new Uint8Array(plain).fill(0);
      if (cleared) return;
      if (data.version !== 1 || typeof data.attributes !== 'string' || typeof data.match !== 'string'
          || typeof data.photo !== 'string' || !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(data.photo)) throw new Error('invalid');
      $('photo').src = data.photo; $('attributes').textContent = data.attributes; $('match').textContent = data.match;
      $('result').hidden = false; $('open').hidden = true;
      $('state').textContent = '読み取り結果を表示中です。取得から60秒後に消去します。';
    } catch (_) { if (!cleared) clear('結果を復号できませんでした。新しいQRを発行してください。'); }
  };
})();
