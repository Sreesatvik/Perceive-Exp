// Floating in-page panel: creation, singleton, toggle, task submission,
// message routing, persistence, drag/resize bounds, and the toolbar
// fallback for restricted pages (transport.js).
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mountPanel, HOST_ID } from '../src/content/panel/panel.js';
import { clampState, STATE_KEY, MIN_WIDTH } from '../src/content/panel/panelState.js';

console.log('=== RUNNING FLOATING PANEL TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

function setup({ saved } = {}) {
  const dom = new JSDOM('<!DOCTYPE html><html><body><div id="app"></div></body></html>', { pretendToBeVisual: true });
  const win = dom.window;
  Object.defineProperty(win, 'innerWidth', { value: 1000, configurable: true });
  Object.defineProperty(win, 'innerHeight', { value: 800, configurable: true });
  const data = saved ? { [STATE_KEY]: saved } : {};
  const store = { get: async (k) => ({ [k]: data[k] }), set: async (o) => Object.assign(data, o) };
  let listener = null;
  const sent = [];
  const chromeApi = {
    runtime: { onMessage: { addListener: (fn) => { listener = fn; } }, sendMessage: (m, cb) => { sent.push(m); if (cb) cb(); }, lastError: undefined },
    storage: { local: { get: async () => ({ backendApiKey: 'k' }), set: async () => {} } },
  };
  const runs = [];
  const panel = mountPanel({ runTask: (i) => { runs.push(i); return Promise.resolve({ success: true, steps: 2 }); }, win, chromeApi, store });
  const route = (message) => { let r; listener(message, {}, (x) => { r = x; }); return r; };
  const q = (sel) => panel.host.shadowRoot.querySelector(sel);
  const ev = (type, x, y, target = win) => target.dispatchEvent(new win.MouseEvent(type, { clientX: x, clientY: y, bubbles: true, composed: true }));
  return { win, panel, data, sent, runs, route, q, ev };
}

await t('creates one shadow-DOM host on documentElement, closed by default, no style leak', async () => {
  const { win, panel } = setup();
  await panel.ready;
  const host = win.document.getElementById(HOST_ID);
  assert.ok(host && host.shadowRoot);
  assert.strictEqual(host.parentNode, win.document.documentElement);
  assert.strictEqual(host.style.display, 'none');
  assert.strictEqual(win.document.querySelector('style'), null);
});

await t('mounting again (orchestrator re-run) returns the same instance, no duplicate', async () => {
  const { win, panel } = setup();
  const again = mountPanel({ runTask: () => {}, win, chromeApi: {}, store: null });
  assert.strictEqual(again, panel);
  assert.strictEqual(win.document.querySelectorAll(`#${HOST_ID}`).length, 1);
});

await t('SPA wiping the DOM re-attaches the same host, never a second', async () => {
  const { win, panel } = setup();
  win.document.documentElement.removeChild(panel.host);
  await tick(20);
  assert.strictEqual(win.document.querySelectorAll(`#${HOST_ID}`).length, 1);
  assert.strictEqual(win.document.getElementById(HOST_ID), panel.host);
});

await t('TOGGLE_PANEL message opens/closes and replies; persists open state', async () => {
  const { panel, route, data } = setup();
  await panel.ready;
  assert.deepStrictEqual(route({ type: 'TOGGLE_PANEL' }), { ok: true, open: true });
  assert.strictEqual(panel.host.style.display, 'block');
  assert.deepStrictEqual(route({ type: 'TOGGLE_PANEL' }), { ok: true, open: false });
  assert.strictEqual(panel.host.style.display, 'none');
  assert.strictEqual(route({ type: 'SOMETHING_ELSE' }), undefined);
  await tick();
  assert.strictEqual(data[STATE_KEY].open, false);
});

await t('close and minimize buttons work; reopen via toggle', async () => {
  const { panel, q } = setup();
  await panel.ready;
  panel.toggle();
  q('.min-btn').click();
  assert.strictEqual(panel.getState().minimized, true);
  q('.min-btn').click();
  q('.close-btn').click();
  assert.strictEqual(panel.getState().open, false);
  panel.toggle();
  assert.strictEqual(panel.getState().open, true);
});

await t('task submission: calls runTask, clears textarea, shows result; empty is rejected', async () => {
  const { panel, q, runs } = setup();
  await panel.ready;
  q('.run-btn').click();
  assert.strictEqual(runs.length, 0);
  assert.match(q('.status').textContent, /Enter a task/);
  q('.task').value = "log in with password 'hunter2'";
  q('.run-btn').click();
  assert.deepStrictEqual(runs, ["log in with password 'hunter2'"]);
  assert.strictEqual(q('.task').value, '', 'raw credential text must not stay on screen');
  assert.match(q('.status').textContent, /Running/);
  await tick();
  assert.match(q('.status').textContent, /Task complete \(2 steps\)/);
  assert.strictEqual(q('.run-btn').disabled, false);
});

await t('failed result renders the reason; object reasons are stringified', async () => {
  const { panel, q } = setup();
  panel.showResult({ success: false, reason: { a: 1 } });
  assert.match(q('.status').textContent, /Task failed: \{"a":1\}/);
  panel.showResult({ success: false, reason: 'UNRESOLVED_SENSITIVE_REFERENCE', message: 'need a value' });
  assert.match(q('.status').textContent, /need a value/);
});

await t('dashboard button routes OPEN_DASHBOARD to the background', async () => {
  const { q, sent } = setup();
  q('.dash-btn').click();
  assert.deepStrictEqual(sent.map((m) => m.type), ['OPEN_DASHBOARD']);
});

await t('settings button routes OPEN_SETTINGS; page key handlers never see keys typed in the panel', async () => {
  const { win, panel, q, sent } = setup();
  q('.settings-tab-btn').click();
  assert.deepStrictEqual(sent.map((m) => m.type), ['OPEN_SETTINGS']);
  let pageSaw = 0;
  win.addEventListener('keydown', () => { pageSaw++; }, true); // registered after the panel
  q('.key-input').dispatchEvent(new win.KeyboardEvent('keydown', { key: 'a', bubbles: true, composed: true }));
  assert.strictEqual(pageSaw, 0);
});

await t('requestSecret opens the panel, resolves the value once, clears the input; cancel gives null', async () => {
  const { panel, q } = setup();
  await panel.ready;
  assert.strictEqual(panel.getState().open, false);
  const p1 = panel.requestSecret('re-enter password');
  assert.strictEqual(panel.getState().open, true);
  assert.ok(q('.secret').classList.contains('show'));
  q('.secret-input').value = 'hunter2';
  q('.secret-ok').click();
  assert.strictEqual(await p1, 'hunter2');
  assert.strictEqual(q('.secret-input').value, '');
  assert.ok(!q('.secret').classList.contains('show'));
  const p2 = panel.requestSecret('again');
  q('.secret-cancel').click();
  assert.strictEqual(await p2, null);
  const p3 = panel.requestSecret('empty');
  q('.secret-ok').click();
  assert.strictEqual(await p3, null, 'empty input counts as cancel');
});

await t('drag moves via header, ignores control buttons, stays in viewport, persists', async () => {
  const { panel, q, ev, data } = setup({ saved: { x: 100, y: 100, width: 300, height: 300, open: true } });
  await panel.ready;
  ev('pointerdown', 150, 110, q('.header'));
  ev('pointermove', 250, 210);
  ev('pointerup', 250, 210);
  assert.deepStrictEqual([panel.getState().x, panel.getState().y], [200, 200]);
  ev('pointerdown', 250, 210, q('.close-btn'));
  ev('pointermove', 0, 0);
  assert.strictEqual(panel.getState().x, 200, 'button press must not start a drag');
  ev('pointerdown', 250, 210, q('.header'));
  ev('pointermove', 99999, 99999);
  ev('pointerup', 0, 0);
  assert.ok(panel.getState().x <= 1000 - 300 && panel.getState().y <= 800 - 40);
  await tick();
  assert.strictEqual(data[STATE_KEY].x, panel.getState().x);
});

await t('resize via grip respects min and viewport limits', async () => {
  const { panel, q, ev } = setup({ saved: { x: 10, y: 10, width: 300, height: 300, open: true } });
  await panel.ready;
  ev('pointerdown', 310, 310, q('.grip'));
  ev('pointermove', 410, 360);
  assert.deepStrictEqual([panel.getState().width, panel.getState().height], [400, 350]);
  ev('pointermove', -5000, -5000);
  assert.strictEqual(panel.getState().width, MIN_WIDTH);
  ev('pointermove', 99999, 99999);
  ev('pointerup', 0, 0);
  assert.ok(panel.getState().width <= 1000 && panel.getState().height <= 800);
});

await t('persisted state restored (and clamped) on a fresh mount', async () => {
  const { panel } = setup({ saved: { x: 5000, y: 5000, width: 50, height: 50, open: true, minimized: true } });
  await panel.ready;
  const s = panel.getState();
  assert.strictEqual(s.open, true);
  assert.strictEqual(s.minimized, true);
  assert.strictEqual(s.width, MIN_WIDTH);
  assert.ok(s.x <= 1000 - s.width && s.y <= 800 - 40);
});

await t('suspendForCapture hides an open panel; resume restores it', async () => {
  const { panel } = setup({ saved: { x: 10, y: 10, width: 300, height: 300, open: true } });
  await panel.ready;
  await panel.suspendForCapture();
  assert.strictEqual(panel.host.style.visibility, 'hidden');
  panel.resumeAfterCapture();
  assert.strictEqual(panel.host.style.visibility, '');
});

await t('clampState never yields NaN for garbage input', async () => {
  const s = clampState({ x: 'a', y: NaN, width: undefined, height: null }, 800, 600);
  for (const v of [s.x, s.y, s.width, s.height]) assert.ok(Number.isFinite(v));
});

// --- toolbar click: toggle, else fall back to popup (restricted pages) ---
async function loadTransport() {
  let onClicked = null;
  const calls = [];
  global.chrome = {
    runtime: { onMessage: { addListener() {} }, lastError: undefined, getURL: (p) => p },
    storage: { local: { get: async () => ({}) }, session: { setAccessLevel: async (o) => { calls.push(['access', o.accessLevel]); } } },
    tabs: { onRemoved: { addListener() {} }, sendMessage: null },
    offscreen: { hasDocument: async () => true, createDocument: async () => {} },
    action: {
      onClicked: { addListener: (fn) => { onClicked = fn; } },
      setPopup: async (o) => { calls.push(['setPopup', o.popup]); },
      openPopup: async () => { calls.push(['openPopup']); },
    },
  };
  await import(`../src/background/transport.js?panel=${Math.random()}`);
  return { onClicked, calls };
}

await t('toolbar click on a supported page sends TOGGLE_PANEL and does not open the popup', async () => {
  const { onClicked, calls } = await loadTransport();
  const sends = [];
  global.chrome.tabs.sendMessage = (id, m, cb) => { sends.push([id, m.type]); cb({ ok: true, open: true }); };
  onClicked({ id: 7 });
  assert.deepStrictEqual(sends, [[7, 'TOGGLE_PANEL']]);
  assert.ok(!calls.some((c) => c[0] === 'openPopup'));
  assert.ok(calls.some((c) => c[0] === 'access'));
});

await t('toolbar click on a restricted page (no content script) falls back to the popup', async () => {
  const { onClicked, calls } = await loadTransport();
  global.chrome.tabs.sendMessage = (id, m, cb) => {
    global.chrome.runtime.lastError = { message: 'Receiving end does not exist.' };
    cb(undefined);
    global.chrome.runtime.lastError = undefined;
  };
  onClicked({ id: 3 });
  await tick(10);
  assert.deepStrictEqual(
    calls.filter((c) => c[0] !== 'access').map((c) => c.join(':')),
    ['setPopup:src/popup/popup.html', 'openPopup', 'setPopup:']
  );
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
