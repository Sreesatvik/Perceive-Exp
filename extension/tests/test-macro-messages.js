// Background macro message handling: sender validation and origin derivation.
import assert from 'assert';
import { handleMacroMessage, senderOrigin, MACRO_MESSAGE_TYPES } from '../src/background/macroMessages.js';
import { createMacroStore } from '../src/background/macroStore.js';

console.log('=== RUNNING MACRO MESSAGE TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const EXT = 'extension-id-123';
const H = (c) => c.repeat(64);
const desc = () => ({ tag: 'input', role: 'textbox', input_type: 'text', name_attr_hmac: H('e'), stable_id_hmac: null, name_hmac: H('a'),
  ctx: { form_hmac: H('b'), landmark_role: 'form', landmark_hmac: H('c') }, sensitivity: { is_sensitive: false, type: null } });
const body = (fp = H('d')) => ({ origin: 'https://example.com', task_fp: fp, created_at: 0, steps: [
  { i: 0, type: 'type', precondition: { pathname_hmac: H('f') }, target: desc(), value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1 }, post: [{ kind: 'field_filled' }] }] });

const senderFor = (url, over = {}) => ({ id: EXT, frameId: 0, tab: { id: 1, url }, url, ...over });
const A = senderFor('https://example.com/login?x=1#frag');
const B = senderFor('https://other.example/page');

function fakeStorage() {
  const data = new Map();
  return { data,
    async get(k) { const out = {}; for (const key of (Array.isArray(k) ? k : [k])) if (data.has(key)) out[key] = JSON.parse(JSON.stringify(data.get(key))); return out; },
    async set(o) { for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); },
    async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); } };
}
const setup = () => { const storage = fakeStorage(); const store = createMacroStore({ storage }); return { storage, store, call: (sender, message) => handleMacroMessage({ store, sender, message, extensionId: EXT }) }; };

await t('senderOrigin: derived from the tab URL (scheme+host+port only); path/query/hash never leak in', async () => {
  assert.strictEqual(senderOrigin(A, EXT), 'https://example.com');
  assert.strictEqual(senderOrigin(senderFor('http://localhost:8080/a'), EXT), 'http://localhost:8080');
  assert.strictEqual(senderOrigin(senderFor('https://user:pw@example.com/x'), EXT), 'https://example.com');
});

await t('senderOrigin refuses: foreign extension, no tab, sub-frames, non-http(s), garbage', async () => {
  assert.strictEqual(senderOrigin({ ...A, id: 'someone-else' }, EXT), null);
  assert.strictEqual(senderOrigin({ id: EXT, frameId: 0, url: 'https://example.com/' }, EXT), null, 'popup/options pages have no tab');
  assert.strictEqual(senderOrigin({ ...A, frameId: 3 }, EXT), null);
  for (const u of ['chrome://settings', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,x', 'about:blank', 'chrome-extension://x/popup.html', '', 'not a url']) {
    assert.strictEqual(senderOrigin(senderFor(u), EXT), null, u);
  }
  assert.strictEqual(senderOrigin(null, EXT), null);
  assert.strictEqual(senderOrigin(undefined, EXT), null);
});

await t('every macro message from a bad sender is refused and touches nothing', async () => {
  const { call, storage } = setup();
  for (const type of MACRO_MESSAGE_TYPES) {
    for (const s of [null, { ...A, id: 'evil' }, { id: EXT, frameId: 0 }, senderFor('chrome://x'), { ...A, frameId: 1 }]) {
      assert.deepStrictEqual(await call(s, { type, task_fp: H('d'), body: body(), macro_id: '123e4567-e89b-42d3-a456-426614174000', success: true }), { ok: false, error: 'forbidden_sender' }, type);
    }
  }
  assert.strictEqual(storage.data.size, 0, 'not even a key was created');
});

await t('put + lookup + get round-trip for the sender\'s origin', async () => {
  const { call } = setup();
  const key = (await call(A, { type: 'MACRO_GET_KEY' })).key;
  assert.match(key, /^[0-9a-f]{64}$/);
  const put = await call(A, { type: 'MACRO_PUT', body: body() });
  assert.strictEqual(put.ok, true);
  const hit = await call(A, { type: 'MACRO_LOOKUP', task_fp: H('d') });
  assert.strictEqual(hit.macro.macro_id, put.macro_id);
  assert.strictEqual((await call(A, { type: 'MACRO_GET', macro_id: put.macro_id })).macro.macro_id, put.macro_id);
  assert.strictEqual((await call(A, { type: 'MACRO_LIST' })).macros.length, 1);
});

await t('ORIGIN ISOLATION: another tab/origin cannot see, get, delete, record results on, or clear these macros', async () => {
  const { call } = setup();
  const put = await call(A, { type: 'MACRO_PUT', body: body() });
  assert.strictEqual((await call(B, { type: 'MACRO_LOOKUP', task_fp: H('d') })).macro, null);
  assert.strictEqual((await call(B, { type: 'MACRO_GET', macro_id: put.macro_id })).macro, null);
  assert.strictEqual((await call(B, { type: 'MACRO_LIST' })).macros.length, 0);
  assert.strictEqual((await call(B, { type: 'MACRO_DELETE', macro_id: put.macro_id })).removed, 0);
  assert.strictEqual((await call(B, { type: 'MACRO_RECORD_RESULT', macro_id: put.macro_id, success: false, hard: true })).error, 'not_found');
  await call(B, { type: 'MACRO_CLEAR' });
  assert.strictEqual((await call(A, { type: 'MACRO_LIST' })).macros.length, 1, 'B\'s clear did not touch A');
  assert.strictEqual((await call(A, { type: 'MACRO_LOOKUP', task_fp: H('d') })).macro.macro_id, put.macro_id);
});

await t('ORIGIN SPOOFING: an origin field inside the message or body is ignored; the sender\'s origin always wins', async () => {
  const { call } = setup();
  const put = await call(B, { type: 'MACRO_PUT', origin: 'https://example.com', body: body() });   // body says example.com, sender is other.example
  assert.strictEqual(put.ok, true);
  assert.strictEqual((await call(A, { type: 'MACRO_LOOKUP', task_fp: H('d'), origin: 'https://other.example' })).macro, null, 'not filed under example.com');
  const got = await call(B, { type: 'MACRO_LOOKUP', task_fp: H('d'), origin: 'https://example.com' });
  assert.strictEqual(got.macro.origin, 'https://other.example');
});

await t('bad requests are rejected without touching storage: ids, fingerprints, unknown types, invalid bodies', async () => {
  const { call } = setup();
  assert.strictEqual((await call(A, { type: 'MACRO_LOOKUP', task_fp: 'nope' })).error, 'bad_request');
  assert.strictEqual((await call(A, { type: 'MACRO_GET', macro_id: '../../etc' })).error, 'bad_request');
  assert.strictEqual((await call(A, { type: 'MACRO_DELETE', macro_id: 5 })).error, 'bad_request');
  assert.strictEqual((await call(A, { type: 'MACRO_RECORD_RESULT', macro_id: 'x', success: true })).error, 'bad_request');
  assert.strictEqual((await call(A, { type: 'MACRO_NOPE' })).error, 'unknown_message');
  assert.strictEqual((await call(A, { type: 'MACRO_PUT', body: { ...body(), raw_password: 'hunter2' } })).ok, false);
  assert.strictEqual((await call(A, { type: 'MACRO_PUT', body: null })).ok, false);
  assert.strictEqual((await call(A, { type: 'MACRO_LIST' })).macros.length, 0);
});

await t('quarantined macros are not returned by GET/LOOKUP; results recorded through the message API', async () => {
  const { call } = setup();
  const put = await call(A, { type: 'MACRO_PUT', body: body() });
  assert.strictEqual((await call(A, { type: 'MACRO_RECORD_RESULT', macro_id: put.macro_id, success: false, hard: true })).status, 'quarantined');
  assert.strictEqual((await call(A, { type: 'MACRO_LOOKUP', task_fp: H('d') })).macro, null);
  assert.strictEqual((await call(A, { type: 'MACRO_GET', macro_id: put.macro_id })).macro, null);
  assert.strictEqual((await call(A, { type: 'MACRO_LIST' })).macros[0].status, 'quarantined');
});

await t('the storage layer failing never throws out of the handler', async () => {
  const storage = fakeStorage();
  storage.get = async () => { throw new Error('boom'); };
  const store = createMacroStore({ storage });
  const r = await handleMacroMessage({ store, sender: A, message: { type: 'MACRO_LIST' }, extensionId: EXT });
  assert.deepStrictEqual(r, { ok: false, error: 'internal_error' });
  assert.deepStrictEqual(await handleMacroMessage({ store: null, sender: A, message: { type: 'MACRO_LIST' }, extensionId: EXT }), { ok: false, error: 'unavailable' });
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
