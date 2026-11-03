(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const session = document.querySelector('meta[name="api-session"]')?.content || '';
  const base = (document.querySelector('meta[name="api-base"]')?.content || '').replace(/\/+$/, '');
  const tenant = $('mnsl-card-tenant');
  const start = $('mnsl-android-start');
  const state = $('mnsl-android-state');
  const qrPanel = $('mnsl-android-qr-panel');
  const qrBox = $('mnsl-android-qr');
  const qrLink = $('mnsl-android-link');
  if (!tenant || !start || !state || !qrPanel || !qrBox || !qrLink || !session || !base) return;

  const apiUrl = `${base}/api/baas/v1/mnsl-android-card-read.php`;
  let activeFlow = '';
  let busy = false;
  let generation = 0;

  function show(message, kind = 'working') {
    state.textContent = message;
    state.dataset.kind = kind;
  }

  function environment() {
    return tenant.selectedOptions[0]?.dataset.env || 'production';
  }

  async function api(body) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    let response, payload;
    try {
      response = await fetch(apiUrl, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-HA-Session': session,
          'X-Tenant-ID': tenant.value,
          'X-BaaS-Environment': environment(),
        },
        body: JSON.stringify(body),
      });
      try { payload = await response.json(); }
      catch (error) {
        if (error instanceof Error && error.name === 'AbortError') throw error;
        throw new Error('サーバーの応答を読み取れませんでした。');
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('サーバーからの応答に時間がかかっています。作成済みの依頼がある場合は3分以内に失効します。画面を再読み込みしてから、必要な場合だけ再発行してください。');
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok || payload.ok !== true) {
      const messages = {
        admin_scope_required: '管理者パスキーで再ログインし、テナント閲覧権限を確認してください。',
        operator_admin_required: '管理者用の受付画面から実行してください。',
        environment_mismatch: '選択したお客様の環境と受付画面の環境が一致しません。',
        server_not_writable: '現在は受付できません。時間をおいて再度お試しください。',
      };
      throw new Error(messages[payload.error] || payload.message || 'カード読み取り依頼を作成できませんでした。');
    }
    return payload;
  }

  function gfMultiply(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11D);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }

  function appendBits(bits, value, length) {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  }

  function qrMatrix(text) {
    if (/[^\x00-\x7F]/.test(text)) throw new Error('QRコードへ変換できない文字が含まれています。');
    const bytes = Array.from(text, (character) => character.charCodeAt(0));
    const dataCodewords = 108;
    const eccCodewords = 26;
    if (bytes.length > 106) throw new Error('QRコードの情報量が上限を超えました。');
    const bits = [];
    appendBits(bits, 0x4, 4); // Byte mode, version 5 uses an 8-bit length field.
    appendBits(bits, bytes.length, 8);
    for (const byte of bytes) appendBits(bits, byte, 8);
    const maxBits = dataCodewords * 8;
    appendBits(bits, 0, Math.min(4, maxBits - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) {
      let value = 0;
      for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j];
      data.push(value);
    }
    for (let pad = 0; data.length < dataCodewords; pad++) data.push(pad % 2 === 0 ? 0xEC : 0x11);

    let generator = [1];
    let root = 1;
    for (let i = 0; i < eccCodewords; i++) {
      const next = Array(generator.length + 1).fill(0);
      for (let j = 0; j < generator.length; j++) {
        next[j] ^= generator[j];
        next[j + 1] ^= gfMultiply(generator[j], root);
      }
      generator = next;
      root = gfMultiply(root, 2);
    }
    const remainder = data.concat(Array(eccCodewords).fill(0));
    for (let i = 0; i < data.length; i++) {
      const factor = remainder[i];
      for (let j = 0; j < generator.length; j++) remainder[i + j] ^= gfMultiply(generator[j], factor);
    }
    const codewords = data.concat(remainder.slice(data.length));
    const stream = [];
    for (const byte of codewords) appendBits(stream, byte, 8);

    const size = 37;
    const modules = Array.from({ length: size }, () => Array(size).fill(false));
    const functionModule = Array.from({ length: size }, () => Array(size).fill(false));
    const setFunction = (x, y, dark) => {
      if (x >= 0 && x < size && y >= 0 && y < size) {
        modules[y][x] = dark;
        functionModule[y][x] = true;
      }
    };
    const finder = (cx, cy) => {
      for (let dy = -1; dy <= 7; dy++) for (let dx = -1; dx <= 7; dx++) {
        const x = cx + dx, y = cy + dy;
        const inside = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
        const ring = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
        setFunction(x, y, inside && ring !== 2);
      }
    };
    finder(0, 0); finder(size - 7, 0); finder(0, size - 7);
    for (let i = 8; i < size - 8; i++) {
      setFunction(6, i, i % 2 === 0);
      setFunction(i, 6, i % 2 === 0);
    }
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
      setFunction(30 + dx, 30 + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }

    const formatData = (1 << 3); // Error correction level L, mask pattern 0.
    let formatRemainder = formatData;
    for (let i = 0; i < 10; i++) formatRemainder = (formatRemainder << 1) ^ (((formatRemainder >>> 9) & 1) * 0x537);
    const formatBits = ((formatData << 10) | formatRemainder) ^ 0x5412;
    const bit = (i) => ((formatBits >>> i) & 1) !== 0;
    for (let i = 0; i <= 5; i++) setFunction(8, i, bit(i));
    setFunction(8, 7, bit(6)); setFunction(8, 8, bit(7)); setFunction(7, 8, bit(8));
    for (let i = 9; i < 15; i++) setFunction(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) setFunction(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) setFunction(8, size - 15 + i, bit(i));
    setFunction(8, size - 8, true);

    let bitIndex = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        const y = (((right + 1) & 2) === 0) ? size - 1 - vert : vert;
        for (let offset = 0; offset < 2; offset++) {
          const x = right - offset;
          if (!functionModule[y][x]) {
            let value = bitIndex < stream.length ? stream[bitIndex] !== 0 : false;
            if ((x + y) % 2 === 0) value = !value;
            modules[y][x] = value;
            bitIndex++;
          }
        }
      }
    }
    return modules;
  }

  function qrSvg(text) {
    const matrix = qrMatrix(text);
    const quiet = 4;
    const viewSize = matrix.length + quiet * 2;
    let path = '';
    for (let y = 0; y < matrix.length; y++) for (let x = 0; x < matrix.length; x++) {
      if (matrix[y][x]) path += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewSize} ${viewSize}" role="img" aria-label="Androidアプリ起動用QRコード"><rect width="100%" height="100%" fill="#fff"/><path d="${path}" fill="#102a2a"/></svg>`;
  }

  function clearFlow() {
    generation++;
    activeFlow = '';
    busy = false;
    start.disabled = !tenant.value;
    qrPanel.hidden = true;
    qrBox.replaceChildren();
    qrLink.removeAttribute('href');
    show('Androidのカード読取アプリを使う場合、対象のお客様を選んでQRコードを発行してください。');
  }

  async function poll(flowId, thisGeneration) {
    while (activeFlow === flowId && generation === thisGeneration) {
      await new Promise((resolve) => setTimeout(resolve, 1400));
      if (activeFlow !== flowId || generation !== thisGeneration) return;
      try {
        const result = await api({ action: 'status', flow_id: flowId });
        if (result.state === 'read_complete') {
          show('Androidアプリから読み取り完了の報告を受信しました。個人情報はWebへ送られていません。', 'success');
          activeFlow = '';
          start.disabled = !tenant.value;
          return;
        }
        if (result.state === 'read_failed') {
          show(result.failure_code === 'user_cancelled' ? 'Androidアプリで読み取りが中止されました。必要なら新しいQRコードを発行してください。' : 'Androidアプリで読み取りが完了しませんでした。必要なら新しいQRコードを発行してください。', 'error');
          activeFlow = '';
          start.disabled = !tenant.value;
          return;
        }
        if (result.state === 'expired') {
          show('QRコードの期限が切れました。もう一度発行してください。', 'error');
          activeFlow = '';
          start.disabled = !tenant.value;
          return;
        }
        show('QRコードをAndroidで読み取り、アプリの案内に沿ってカードを読み取ってください。残り時間は約3分です。');
      } catch (error) {
        if (/再ログイン|権限/.test(error.message)) {
          show(error.message, 'error');
          activeFlow = '';
          start.disabled = !tenant.value;
          return;
        }
      }
    }
  }

  tenant.addEventListener('change', clearFlow);
  start.addEventListener('click', async () => {
    if (busy || !tenant.value) return;
    busy = true;
    start.disabled = true;
    qrPanel.hidden = true;
    show('一回限りのAndroid読み取り依頼を作成しています…');
    try {
      const created = await api({ action: 'create' });
      if (!/^[A-Za-z0-9_-]{20}$/.test(created.flow_id || '') || !/^[A-Za-z0-9_-]{20}$/.test(created.nonce || '')) {
        throw new Error('読み取り依頼の形式が正しくありません。');
      }
      const link = new URL(created.app_path, window.location.origin);
      link.searchParams.set('f', created.flow_id);
      link.hash = created.nonce;
      qrBox.innerHTML = qrSvg(link.toString());
      qrLink.href = link.toString();
      qrPanel.hidden = false;
      show('QRコードをAndroidのカメラで読み取ってください。読み取り結果は完了・失敗だけWebへ返ります。');
      activeFlow = created.flow_id;
      const thisGeneration = ++generation;
      busy = false;
      poll(created.flow_id, thisGeneration);
    } catch (error) {
      busy = false;
      start.disabled = !tenant.value;
      show(error instanceof Error ? error.message : 'QRコードを発行できませんでした。', 'error');
    }
  });
})();
