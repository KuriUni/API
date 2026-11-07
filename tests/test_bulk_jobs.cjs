const { test } = require('node:test');
const assert = require('node:assert/strict');
require('../xrea-source/tenant-portal/bulk-jobs.js');
const { collectCsvPages, csvLine } = globalThis.TutiBulkJobs;
const jobId = 'a'.repeat(32);
const item = n => ({ item: n, license_id: n, key_fingerprint: 'test', product_key: `DEMO-${n}` });
const page = (items, more = false, cursor = null) => ({ job: { job_id: jobId }, items, has_more: more, next_cursor: cursor });

test('CSV escapes formulas, embedded quotes, commas and newlines', () => {
  assert.equal(csvLine(['=SUM(A1)', '"quoted",\nline', 'safe']), '"\'=SUM(A1)","""quoted"",\nline","safe"\r\n');
  assert.match(csvLine([' \t+1']), /^"'/);
});
test('100,000 results are collected as page strings with bounded page objects', async () => {
  let calls = 0;
  const result = await collectCsvPages(async cursor => {
    calls++;
    const end = Math.min(cursor + 500, 100000);
    return page(Array.from({ length: end - cursor }, (_, i) => item(cursor + i + 1)), end < 100000, end < 100000 ? end : null);
  }, jobId, 100000, () => true);
  assert.equal(result.count, 100000); assert.equal(calls, 200); assert.equal(result.parts.length, 201);
});
test('stalled cursor, missing rows and foreign job responses are rejected', async () => {
  await assert.rejects(() => collectCsvPages(async () => page([], true, 0), jobId, 1, () => true));
  await assert.rejects(() => collectCsvPages(async () => page([item(1)]), jobId, 2, () => true));
  await assert.rejects(() => collectCsvPages(async () => ({ ...page([item(1)]), job: { job_id: 'b'.repeat(32) } }), jobId, 1, () => true));
});
test('connection change aborts before any downloaded keys can be saved', async () => {
  let current = true;
  await assert.rejects(() => collectCsvPages(async () => { current = false; return page([item(1)]); }, jobId, 1, () => current));
});
test('duplicate item numbers and missing keys are rejected', async () => {
  await assert.rejects(() => collectCsvPages(async () => page([item(1), item(1)]), jobId, 2, () => true));
  await assert.rejects(() => collectCsvPages(async () => page([{ ...item(1), product_key: '' }]), jobId, 1, () => true));
});
