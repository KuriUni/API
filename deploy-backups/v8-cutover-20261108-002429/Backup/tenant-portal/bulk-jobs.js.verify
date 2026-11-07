(() => {
  'use strict';
  function csvLine(values) {
    return values.map((value) => {
      let text = String(value ?? '');
      if (/^[\s]*[=+\-@\t\r]/.test(text)) text = `'${text}`;
      return `"${text.replaceAll('"', '""')}"`;
    }).join(',') + '\r\n';
  }
  async function collectCsvPages(fetchPage, jobId, expectedCount, isCurrent, onProgress = () => {}) {
    if (!/^[a-f0-9]{32}$/.test(jobId) || !Number.isSafeInteger(expectedCount) || expectedCount < 1 || expectedCount > 100000) throw new Error('発行件数またはジョブIDを確認できません。');
    const parts = ['\uFEFF' + csvLine(['ライセンスID', '指紋', 'ライセンスキー'])];
    let cursor = 0; let count = 0; let more = true;
    while (more) {
      if (!isCurrent()) throw new Error('接続または画面が変更されたため、取得を中止しました。');
      const page = await fetchPage(cursor);
      if (!isCurrent()) throw new Error('接続または画面が変更されたため、取得を中止しました。');
      if (page.job?.job_id !== jobId || !Array.isArray(page.items) || page.items.length > 1000 || typeof page.has_more !== 'boolean') throw new Error('結果ページの形式が正しくありません。');
      let last = cursor; let chunk = '';
      for (const item of page.items) {
        if (!Number.isSafeInteger(item.item) || item.item <= last || typeof item.product_key !== 'string' || !item.product_key) throw new Error('発行キーの順序または内容に不整合があります。');
        last = item.item; count++;
        if (count > expectedCount) throw new Error('発行件数を超える結果を受信しました。');
        chunk += csvLine([item.license_id, item.key_fingerprint, item.product_key]);
      }
      parts.push(chunk);
      more = page.has_more;
      if (more && (!page.items.length || page.next_cursor !== last || last <= cursor)) throw new Error('結果の取得位置が進まないため、中止しました。');
      cursor = last;
      onProgress(count, expectedCount);
    }
    if (count !== expectedCount) throw new Error('発行済み件数と取得件数が一致しません。削除済みライセンスの有無を確認してください。');
    return { parts, count };
  }
  globalThis.TutiBulkJobs = Object.freeze({ csvLine, collectCsvPages });
})();
