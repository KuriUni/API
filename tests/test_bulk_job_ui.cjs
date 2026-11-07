const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../xrea-source/tenant-portal/app.js'), 'utf8');
const start = source.indexOf('  function renderBulkJobActions(');
const end = source.indexOf('  function renderLicenseTable(', start);
assert.ok(start > 0 && end > start);

function mount() {
  const timers = new Map(); let sequence = 0; let calls = 0;
  const state = { connectionVersion: 1, taskVersion: 1, tenant: 'test', environment: 'sandbox' };
  const dialog = { open: true };
  const document = { hidden: false };
  let terminal = false;
  const element = (tag, className, textContent) => ({
    textContent, children: [], isConnected: true,
    classList: { add() {}, toggle() {} }, dataset: {},
    append(...children) { this.children.push(...children); }, querySelector() { return null; },
  });
  const button = (label, action) => Object.assign(element('button', '', label), { action });
  const context = {
    state, document, element, button, $: () => dialog,
    window: { setTimeout(action) { const id = ++sequence; timers.set(id, action); return id; }, clearTimeout(id) { timers.delete(id); } },
    api: async () => { calls++; return { job: { status: terminal ? 'cancelled' : 'queued', terminal, progress_percent: 0, succeeded_count: 0, failed_count: 0 } }; },
    sessionStorage: { getItem() { return null; }, removeItem() {} }, confirmAction: async () => false,
  };
  vm.runInNewContext(source.slice(start, end) + '\nglobalThis.mount = renderBulkJobActions;', context);
  const container = element('div');
  context.mount(container, 'a'.repeat(32), 1, 1);
  const auto = container.children[1].children.find(button => button.textContent.startsWith('自動更新'));
  const runNext = async () => { const next = timers.entries().next().value; assert.ok(next); timers.delete(next[0]); await next[1](); };
  return { state, dialog, document, auto, timers, runNext, calls: () => calls, finish: () => { terminal = true; } };
}

test('automatic billable polling is off until the user opts in', async () => {
  const ui = mount(); await ui.runNext();
  assert.equal(ui.calls(), 1); assert.equal(ui.timers.size, 0);
  await ui.auto.action(); assert.equal(ui.calls(), 2); assert.equal(ui.timers.size, 1);
  await ui.auto.action(); assert.equal(ui.timers.size, 0);
});
test('closing the dialog and changing the account stop further requests', async () => {
  for (const change of [ui => { ui.dialog.open = false; }, ui => { ui.state.connectionVersion++; }]) {
    const ui = mount(); await ui.runNext(); await ui.auto.action();
    const before = ui.calls(); change(ui); await ui.runNext();
    assert.equal(ui.calls(), before); assert.equal(ui.timers.size, 0);
  }
});
test('hidden tabs do not poll and terminal jobs stop their timer', async () => {
  const ui = mount(); await ui.runNext(); await ui.auto.action();
  const before = ui.calls(); ui.document.hidden = true; await ui.runNext(); assert.equal(ui.calls(), before);
  ui.document.hidden = false; ui.finish(); await ui.runNext();
  assert.equal(ui.auto.disabled, true); assert.equal(ui.timers.size, 0);
});
