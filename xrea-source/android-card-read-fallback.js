(() => {
  'use strict';
  const link = document.getElementById('open-app');
  const host = window.location.hostname.toLowerCase();
  const params = new URLSearchParams(window.location.search);
  const flowIds = params.getAll('f');
  const nonce = window.location.hash.slice(1);
  if (!link || !['2415.jp', 'backup.2415.jp'].includes(host)
      || Array.from(params.keys()).length !== 1 || flowIds.length !== 1
      || !/^[A-Za-z0-9_-]{20}$/.test(flowIds[0])
      || !/^[A-Za-z0-9_-]{20}$/.test(nonce)) return;

  const target = `${host}/license/ha/android-card-read.php?f=${flowIds[0]}`;
  link.href = `intent://${target}#Intent;scheme=https;package=jp.tuti.mynumbernfc;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;S.mnsl_web_read_nonce=${nonce};end`;
  link.hidden = false;
})();
