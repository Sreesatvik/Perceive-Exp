// transport.js (background worker) wiring for macros: message routing, sender/origin
// rules end-to-end, and the navigation stash carrying macro state + run metrics.
import assert from 'assert';

console.log('=== RUNNING MACRO TRANSPORT TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const EXT = 'ext-id-transport';
const H = (c) => c.repeat(64);
const desc = () => ({ tag: 'input', role: 'textbox', input_type: 'text', name_attr_hmac: H('e'), stable_id_hmac: null, name_hmac: H('a'),
  ctx: { form_hmac: H('b'), landmark_role: 'form', landmark_hmac: H('c') }, sensitivity: { is_sensitive: false, type: null } });
const body = (fp = H('d')) => ({ origin: 'https://example.com', task_fp: fp, created_at: 0, steps: [
  { i: 0, type: 'type', precondition: { pathname_hmac: H('f') }, target: desc(), value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1 }, post: [{ kind: 'field_filled' }] }] });

function harness({ withStorage = true } = {}) {
  let listener = null;
  const data = new Map();
  const storage = {
    async get(k) { const out = {}; for (const key of (Array.isArray(k) ? k : [k])) if (data.has(key)) out[key] = JSON.parse(JSON.stringify(data.get(key))); return out; },
    async set(o) { for (const [key, v] of Object.entries(o)) data.set(key, JSON.parse(JSON.stringify(v))); },
    async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); },
  };
  global.chrome = {
    runtime: { id: EXT, onMessage: { addListener: (fn) => { listener = fn; } }, getURL: (p) => `chrome-extension://${EXT}/${p}`, lastError: undefined },
    storage: { local: withStorage ? storage : undefined },
    tabs: { onRemoved: { addListener() {} }, create() {} },
    offscreen: { hasDocument: async () => true, createDocument: async () => {} },
  };
  global.fetch = async () => { throw new Error('unused'); };
  return { getListener: () => listener, data, teardown: () => { delete global.chrome; delete global.fetch; } };
}
const invoke = (listener, message, sender) => new Promise((resolve) => { const r = listener(message, sender, resolve); if (r !== true) setTimeout(() => resolve('__no_async_response__'), 50); });
const tabSender = (tabId, url) => ({ id: EXT, frameId: 0, tab: { id: tabId, url }, url });
const load = async () => { await import(`../src/background/transport.js?m=${Date.now()}-${Math.random()}`); };

await t('macro messages are routed through the tested handler: put -> lookup round trip for the sender\'s origin', async () => {
  const h = harness();
  try {
    await load();
    const L = h.getListener();
    const A = tabSender(1, 'https://example.com/login');
    const key = await invoke(L, { type: 'MACRO_GET_KEY' }, A);
    assert.match(key.key, /^[0-9a-f]{64}$/);
    const put = await invoke(L, { type: 'MACRO_PUT', body: body() }, A);
    assert.strictEqual(put.ok, true);
    const hit = await invoke(L, { type: 'MACRO_LOOKUP', task_fp: H('d') }, A);
    assert.strictEqual(hit.macro.macro_id, put.macro_id);
    assert.strictEqual((await invoke(L, { type: 'MACRO_LOOKUP', task_fp: H('d') }, tabSender(2, 'https://other.example/'))).macro, null, 'another origin sees nothing');
  } finally { h.teardown(); }
});

await t('senders that are not our own top-frame http(s) content script are refused, end to end', async () => {
  const h = harness();
  try {
    await load();
    const L = h.getListener();
    for (const s of [{ id: 'other-ext', frameId: 0, tab: { id: 1, url: 'https://example.com/' } }, { id: EXT, frameId: 0, url: 'chrome-extension://x/popup.html' },
      tabSender(1, 'chrome://settings'), { ...tabSender(1, 'https://example.com/'), frameId: 2 }]) {
      assert.deepStrictEqual(await invoke(L, { type: 'MACRO_GET_KEY' }, s), { ok: false, error: 'forbidden_sender' });
    }
    assert.strictEqual(h.data.size, 0, 'nothing was written');
  } finally { h.teardown(); }
});

await t('without chrome.storage.local the macro API reports "unavailable" and nothing else breaks', async () => {
  const h = harness({ withStorage: false });
  try {
    await load();
    const L = h.getListener();
    assert.deepStrictEqual(await invoke(L, { type: 'MACRO_LIST' }, tabSender(1, 'https://example.com/')), { ok: false, error: 'unavailable' });
    const stash = await invoke(L, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1 }, tabSender(3, 'https://example.com/'));
    assert.strictEqual(stash.success, true, 'the existing resume feature is unaffected');
  } finally { h.teardown(); }
});

await t('the navigation stash carries macro state and run metrics; one-shot like everything else in it', async () => {
  const h = harness();
  try {
    await load();
    const L = h.getListener();
    const s = tabSender(7, 'https://example.com/login');
    const macro = { mode: 'replay', macroId: '123e4567-e89b-42d3-a456-426614174000', replay: { index: 4, pendingVerify: 3 } };
    await invoke(L, { type: 'STASH_RESUME_STATE', sessionId: 'sess', taskInstruction: 'tokenized', backendStepNumber: 4, stepNumber: 4, pendingTierTwoValues: [],
      macro, metrics: { llm_calls: 2, plan_ms: 1500.5, total_ms: 9000, exec_ms: 30, bogus: 'x' } }, s);
    const got = await invoke(L, { type: 'GET_RESUME_STATE' }, s);
    assert.deepStrictEqual(got.resumeState.macro, macro);
    assert.deepStrictEqual(got.resumeState.metrics, { llm_calls: 2, plan_ms: 1500.5, replay_steps: 0, replay_validate_ms: 0, exec_ms: 30, final_ms: 0, total_ms: 9000 }, 'unknown keys dropped, missing ones zeroed');
    assert.strictEqual((await invoke(L, { type: 'GET_RESUME_STATE' }, s)).resumeState, null, 'consumed');
  } finally { h.teardown(); }
});

await t('stash hygiene: oversized macro state is dropped; non-numeric / negative / huge metrics are zeroed; no macro => null', async () => {
  const h = harness();
  try {
    await load();
    const L = h.getListener();
    const s = tabSender(8, 'https://example.com/');
    await invoke(L, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1,
      macro: { mode: 'record', recorder: { steps: [], pad: 'x'.repeat(70 * 1024) } }, metrics: { llm_calls: -5, plan_ms: 'NaN', total_ms: 1e12, exec_ms: Infinity } }, s);
    const got = (await invoke(L, { type: 'GET_RESUME_STATE' }, s)).resumeState;
    assert.strictEqual(got.macro, null);
    assert.deepStrictEqual(Object.values(got.metrics), [0, 0, 0, 0, 0, 0, 0]);
    await invoke(L, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1 }, s);
    const plain = (await invoke(L, { type: 'GET_RESUME_STATE' }, s)).resumeState;
    assert.strictEqual(plain.macro, null);
    assert.deepStrictEqual(plain.metrics, { llm_calls: 0, plan_ms: 0, replay_steps: 0, replay_validate_ms: 0, exec_ms: 0, final_ms: 0, total_ms: 0 });
  } finally { h.teardown(); }
});

await t('non-macro messages still work and MACRO_-prefixed lookalikes are not routed', async () => {
  const h = harness();
  try {
    await load();
    const L = h.getListener();
    const A = tabSender(1, 'https://example.com/');
    assert.deepStrictEqual(await invoke(L, { type: 'MACRO_EVIL' }, A), '__no_async_response__', 'unknown MACRO_* types are not handled at all');
    const open = await invoke(L, { type: 'OPEN_SETTINGS' }, A);
    assert.strictEqual(open.success, true);
    assert.deepStrictEqual(await invoke(L, { type: 12345 }, A), '__no_async_response__');
  } finally { h.teardown(); }
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
