(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const session = document.querySelector('meta[name="api-session"]')?.content || '';
  const base = (document.querySelector('meta[name="api-base"]')?.content || '').replace(/\/+$/, '');
  const tenant = $('mnsl-card-tenant');
  const start = $('mnsl-card-start');
  const state = $('mnsl-card-state');
  if (!tenant || !start || !state || !session || !base) return;

  const apiUrl = `${base}/api/baas/v1/mnsl-card-auth.php`;
  const bridgeUrl = 'http://127.0.0.1:17891';
  let busy = false;
  let bridgeReady = false;

  function show(message, kind = 'working') {
    state.textContent = message;
    state.dataset.kind = kind;
  }

  function environment() {
    return tenant.selectedOptions[0]?.dataset.env || 'production';
  }

  async function api(body) {
    const response = await fetch(apiUrl, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-HA-Session': session,
        'X-Tenant-ID': tenant.value,
        'X-BaaS-Environment': environment(),
      },
      body: JSON.stringify(body),
    });
    let payload;
    try { payload = await response.json(); }
    catch { throw new Error('サーバーの応答を読み取れませんでした。'); }
    if (!response.ok || payload.ok !== true) {
      const messages = {
        admin_scope_required: '管理者パスキーで再ログインし、テナント閲覧権限を確認してください。',
        operator_admin_required: '管理者用の受付画面から実行してください。',
        environment_mismatch: '選択したお客様の環境と画面の環境が一致しません。',
        server_not_writable: '現在は処理を受け付けられません。時間をおいて再度お試しください。',
        card_challenge_expired_or_used: '読み取り期限が切れました。最初からやり直してください。',
        card_proof_signature_invalid: 'カード署名を検証できませんでした。カードを入れ直して再試行してください。',
        card_proof_invalid_key: 'このカードの認証用公開鍵には対応していません。',
      };
      throw new Error(messages[payload.error] || payload.message || '受付APIを実行できませんでした。');
    }
    return payload;
  }

  async function checkBridge() {
    bridgeReady = false;
    start.disabled = true;
    if (!tenant.value) {
      show('対象のお客様を選択してください。');
      return;
    }
    show('このWindows端末でカード読取ブリッジを確認しています…');
    try {
      const response = await fetch(`${bridgeUrl}/health`, {
        method: 'GET', cache: 'no-store', mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer',
      });
      const result = await response.json();
      if (!response.ok || result.ok !== true || result.bridge !== 'mnsl-card-web') throw new Error('bridge_not_ready');
      bridgeReady = true;
      start.disabled = false;
      show('カード読取ブリッジに接続しました。カードを入れて読み取りを開始できます。', 'success');
    } catch {
      show('この端末のカード読取ブリッジが見つかりません。Windows用ブリッジをダウンロードして起動し、この受付画面を再読み込みしてください。macOSやスマートフォンではこのWindows CSP連携を使えません。', 'error');
    }
  }

  tenant.addEventListener('change', checkBridge);
  start.addEventListener('click', async () => {
    if (busy || !bridgeReady || !tenant.value) return;
    busy = true;
    start.disabled = true;
    show('サーバーが一回限りの署名チャレンジを発行しています…');
    try {
      const challenge = await api({ action: 'challenge' });
      show('ブリッジ画面で署名を確認してください。カード側でPIN入力を求められる場合があります…');
      let localResponse;
      try {
        localResponse = await fetch(`${bridgeUrl}/sign`, {
          method: 'POST',
          cache: 'no-store',
          mode: 'cors',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ flow_id: challenge.flow_id, nonce: challenge.nonce }),
        });
      } catch {
        throw new Error('Windowsブリッジに接続できません。起動状態を確認し、必要なら受付画面を再読み込みしてください。');
      }
      let proof;
      try { proof = await localResponse.json(); }
      catch { throw new Error('カード読取ブリッジの応答を読み取れませんでした。'); }
      if (!localResponse.ok || proof.ok !== true) {
        const localErrors = {
          user_cancelled: 'カード署名をキャンセルしました。必要であれば最初からやり直してください。',
          card_sign_failed: 'カード署名に失敗しました。カード、リーダー、JPKI CSPとPIN入力を確認してください。',
          origin_not_allowed: '受付Web画面の接続元をブリッジが許可していません。',
        };
        throw new Error(localErrors[proof.error] || 'カード読取ブリッジを実行できませんでした。');
      }
      show('サーバーでカード署名を検証しています…');
      const verified = await api({
        action: 'verify',
        flow_id: challenge.flow_id,
        nonce: challenge.nonce,
        signature: proof.signature,
        public_key_spki: proof.public_key_spki,
      });
      const time = verified.verified_at_utc ? new Date(verified.verified_at_utc).toLocaleString('ja-JP') : '記録済み';
      show(`カード内の鍵による署名を確認しました。確認時刻: ${time} · 受付番号 ${verified.reference || '発行済み'}。証明書の発行元・失効状態は未検証です。`, 'success');
    } catch (error) {
      show(error instanceof Error ? error.message : 'カード読み取りを完了できませんでした。', 'error');
    } finally {
      busy = false;
      start.disabled = !bridgeReady;
    }
  });

  checkBridge();
})();
