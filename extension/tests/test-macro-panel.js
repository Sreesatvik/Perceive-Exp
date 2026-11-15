// Panel UI for workflows: opt-in toggle, explicit choice (never automatic replay),
// result messages, saved-workflow count/delete.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mountPanel } from '../src/content/panel/panel.js';
import { STATE_KEY, clampState, DEFAULT_STATE } from '../src/content/panel/panelState.js';

console.log('=== RUNNING MACRO PANEL TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

function setup({ macros = 'default', saved = null, lookupResult = { found: false }, runResult = { success: true, steps: 3 } } = {}) {
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', { pretendToBeVisual: true });
  const win = dom.window;
  Object.defineProperty(win, 'innerWidth', { value: 1000, configurable: true });
  Object.defineProperty(win, 'innerHeight', { value: 800, configurable: true });
  const data = saved ? { [STATE_KEY]: saved } : {};
  const store = { get: async (k) => ({ [k]: data[k] }), set: async (o) => Object.assign(data, o) };
  const runs = [];
  const calls = { lookup: [], list: 0, clear: 0 };
  const svc = macros === 'default' ? {
    async lookup(i) { calls.lookup.push(i); if (lookupResult instanceof Error) throw lookupResult; return lookupResult; },
    async list() { calls.list++; return svc.items; },
    async clear() { calls.clear++; svc.items = []; return true; },
    items: [{ macro_id: 'x' }, { macro_id: 'y' }],
  } : macros;
  const panel = mountPanel({ runTask: (i, o) => { runs.push([i, o]); return Promise.resolve(runResult); }, macros: svc, win, chromeApi: {}, store });
  const q = (sel) => panel.host.shadowRoot.querySelector(sel);
  return { panel, q, runs, calls, svc, data };
}

await t('Workflows are OFF by default (and the state clamp/default agree)', async () => {
  assert.strictEqual(DEFAULT_STATE.macros, false);
  assert.strictEqual(clampState({}, 1000, 800).macros, false);
  assert.strictEqual(clampState({ macros: 'yes' }, 1000, 800).macros, true);
  const { panel, q } = setup();
  await panel.ready;
  assert.strictEqual(q('.macros-btn').textContent, 'Workflows: OFF');
  assert.strictEqual(q('.macros-btn').getAttribute('aria-pressed'), 'false');
  assert.ok(!q('.macro-info').classList.contains('show'));
});

await t('workflows OFF: submission is unchanged — runTask is called synchronously with no workflow options and no lookup happens', async () => {
  const { panel, q, runs, calls } = setup();
  await panel.ready;
  q('.task').value = 'log in with password hunter2';
  q('.run-btn').click();
  assert.deepStrictEqual(runs, [['log in with password hunter2', {}]], 'synchronous, exactly as before');
  assert.strictEqual(calls.lookup.length, 0);
  assert.strictEqual(q('.task').value, '', 'task text cleared as before');
});

await t('the toggle persists, shows the saved-workflow count, and can delete them', async () => {
  const { panel, q, calls, data, svc } = setup();
  await panel.ready;
  panel.toggle();                                                    // open the panel
  q('.macros-btn').click();
  assert.strictEqual(q('.macros-btn').textContent, 'Workflows: ON');
  await tick();
  assert.ok(q('.macro-info').classList.contains('show'));
  assert.strictEqual(q('.macro-count').textContent, 'Saved workflows on this site: 2');
  assert.strictEqual(Object.values(data)[0].macros, true, 'persisted with the panel state');
  q('.macro-clear').click();
  await tick(20);
  assert.strictEqual(calls.clear, 1);
  assert.strictEqual(q('.macro-count').textContent, 'Saved workflows on this site: 0');
  assert.strictEqual(q('.macro-clear').style.display, 'none');
  assert.deepStrictEqual(svc.items, []);
});

await t('the saved-workflow count is NOT re-queried on every drag/resize tick', async () => {
  const { panel, q, calls } = setup({ saved: { x: 100, y: 100, width: 300, height: 300, open: true, macros: true } });
  await panel.ready;
  await tick();
  const before = calls.list;
  const win = panel.host.ownerDocument.defaultView;
  const ev = (type, x, y, target) => target.dispatchEvent(new win.MouseEvent(type, { clientX: x, clientY: y, bubbles: true, composed: true }));
  ev('pointerdown', 150, 110, q('.header'));
  for (let i = 0; i < 20; i++) ev('pointermove', 150 + i * 5, 110 + i * 3, win);
  ev('pointerup', 0, 0, win);
  await tick();
  assert.strictEqual(calls.list, before);
});

await t('workflows ON, no saved workflow: runs normally (recording enabled) with no prompt', async () => {
  const { panel, q, runs, calls } = setup({ lookupResult: { found: false } });
  await panel.ready;
  q('.macros-btn').click();
  q('.task').value = 'search google for cats';
  q('.run-btn').click();
  await tick();
  assert.deepStrictEqual(calls.lookup, ['search google for cats']);
  assert.deepStrictEqual(runs, [['search google for cats', { macros: true }]]);
  assert.ok(!q('.choice').classList.contains('show'));
});

await t('EXPLICIT CHOICE: a saved workflow is offered, nothing runs until the user picks, and "Run workflow" replays', async () => {
  const { panel, q, runs } = setup({ lookupResult: { found: true, steps: 5 } });
  await panel.ready;
  q('.macros-btn').click();
  q('.task').value = 'log in and pick Hyderabad';
  q('.run-btn').click();
  await tick(20);
  assert.ok(q('.choice').classList.contains('show'));
  assert.match(q('.wf-msg').textContent, /Saved workflow available for this task \(5 steps\)/);
  assert.match(q('.wf-msg').textContent, /risky step will still ask for your confirmation/);
  assert.ok(!q('.wf-msg').textContent.includes('log in and pick'), 'the task text is never shown back');
  await tick(30);
  assert.deepStrictEqual(runs, [], 'NO automatic replay: the task has not started');
  assert.match(q('.status').textContent, /Waiting for you/);
  q('.wf-run').click();
  await tick(20);
  assert.deepStrictEqual(runs, [['log in and pick Hyderabad', { macros: true, useMacro: true }]]);
  assert.ok(!q('.choice').classList.contains('show'));
});

await t('"Plan with AI" runs normally (still recording); "Cancel" starts nothing', async () => {
  const a = setup({ lookupResult: { found: true, steps: 2 } });
  await a.panel.ready;
  a.q('.macros-btn').click();
  a.q('.task').value = 't1';
  a.q('.run-btn').click();
  await tick(20);
  a.q('.wf-ai').click();
  await tick(20);
  assert.deepStrictEqual(a.runs, [['t1', { macros: true, useMacro: false }]]);

  const b = setup({ lookupResult: { found: true, steps: 2 } });
  await b.panel.ready;
  b.q('.macros-btn').click();
  b.q('.task').value = 't2';
  b.q('.run-btn').click();
  await tick(20);
  b.q('.wf-cancel').click();
  await tick(20);
  assert.deepStrictEqual(b.runs, []);
  assert.match(b.q('.status').textContent, /Cancelled/);
  assert.strictEqual(b.q('.run-btn').disabled, false, 'the panel is usable again');
});

await t('a lookup that throws never blocks the task', async () => {
  const { panel, q, runs } = setup({ lookupResult: new Error('background dead') });
  await panel.ready;
  q('.macros-btn').click();
  q('.task').value = 'do it';
  q('.run-btn').click();
  await tick(20);
  assert.deepStrictEqual(runs, [['do it', { macros: true }]]);
});

await t('workflows ON but no service available (e.g. restricted context): falls back to the plain path', async () => {
  const { panel, q, runs } = setup({ macros: null });
  await panel.ready;
  q('.macros-btn').click();
  q('.task').value = 'x';
  q('.run-btn').click();
  assert.deepStrictEqual(runs, [['x', {}]]);
});

await t('result messages: saved / declined / quota / replayed / fell back, plus LLM-call count and time', async () => {
  const { panel, q } = setup();
  const m = { llm_calls: 4, total_ms: 12345 };
  panel.showResult({ success: true, steps: 5, macro: { outcome: 'saved' }, metrics: m });
  assert.strictEqual(q('.status').textContent, '✓ Task complete (5 steps) · workflow saved · LLM calls: 4 · 12.3s');
  panel.showResult({ success: true, steps: 5, macro: { outcome: 'declined' } });
  assert.match(q('.status').textContent, /workflow not saved/);
  panel.showResult({ success: true, steps: 5, macro: { outcome: 'save_failed', reason: 'storage_quota' } });
  assert.match(q('.status').textContent, /could not be saved \(storage full\)/);
  panel.showResult({ success: true, steps: 3, macro: { outcome: 'replayed' }, metrics: { llm_calls: 1, total_ms: 4000 } });
  assert.match(q('.status').textContent, /replayed a saved workflow · LLM calls: 1 · 4\.0s/);
  panel.showResult({ success: true, steps: 3, macro: { outcome: 'fell_back' } });
  assert.match(q('.status').textContent, /workflow stopped; AI finished the task/);
  panel.showResult({ success: true, steps: 2 });
  assert.strictEqual(q('.status').textContent, '✓ Task complete (2 steps)', 'no macro/metrics => unchanged text');
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
