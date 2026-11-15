// Macro storage: isolation, bounds, integrity, corruption, quota, concurrency.
import assert from 'assert';
import { createMacroStore } from '../src/background/macroStore.js';
import { LIMITS } from '../src/macro/schema.js';

console.log('=== RUNNING MACRO STORE TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const H = (c) => c.repeat(64);
const desc = () => ({ tag: 'input', role: 'textbox', input_type: 'text', name_attr_hmac: H('e'), stable_id_hmac: null, name_hmac: H('a'),
  ctx: { form_hmac: H('b'), landmark_role: 'form', landmark_hmac: H('c') }, sensitivity: { is_sensitive: false, type: null } });
const body = (fp = H('d'), o = {}) => ({ origin: 'https://example.com', task_fp: fp, created_at: 0,
  steps: [
    { i: 0, type: 'type', precondition: { pathname_hmac: H('f') }, target: desc(), value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1 }, post: [{ kind: 'field_filled' }] },
    { i: 1, type: 'click', precondition: { pathname_hmac: H('f') }, target: { ...desc(), tag: 'button', role: 'button', input_type: 'submit', name_attr_hmac: null }, value_source: null, post: [{ kind: 'pathname_is', pathname_hmac: H('9') }] },
  ], ...o });
const fp = (i) => i.toString(16).padStart(64, '0');

function fakeStorage({ failSet = null } = {}) {
  const data = new Map();
  let sets = 0;
  return {
    data, get sets() { return sets; },
    failSet: failSet, // mutable: set to an Error to make writes fail
    async get(k) { const keys = Array.isArray(k) ? k : [k]; const out = {}; for (const key of keys) if (data.has(key)) out[key] = JSON.parse(JSON.stringify(data.get(key))); return out; },
    async set(o) { if (this.failSet) throw this.failSet; sets++; for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); },
    async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); },
  };
}
const mk = (opts) => { const storage = fakeStorage(); const clock = { t: 1_800_000_000_000 }; const store = createMacroStore({ storage, now: () => clock.t, ...opts }); return { storage, store, clock }; };
const A = 'https://example.com', B = 'https://other.example';

await t('put then lookup round-trips; ids are random; stats start at zero', async () => {
  const { store } = mk();
  const r = await store.put(A, body());
  assert.strictEqual(r.ok, true);
  const hit = await store.lookup(A, H('d'));
  assert.strictEqual(hit.macro.macro_id, r.macro_id);
  assert.deepStrictEqual(hit.macro.stats, { replays: 0, successes: 0, consecutive_failures: 0 });
  assert.strictEqual(hit.macro.status, 'active');
  assert.strictEqual(hit.macro.steps.length, 2);
});

await t('origin isolation: same task on another origin never matches', async () => {
  const { store } = mk();
  await store.put(A, body());
  assert.strictEqual((await store.lookup(B, H('d'))).macro, null);
  await store.put(B, body(H('d')));
  assert.notStrictEqual((await store.lookup(B, H('d'))).macro.macro_id, (await store.lookup(A, H('d'))).macro.macro_id);
  assert.deepStrictEqual((await store.list(A)).macros.length, 1);
});

await t('the CALLER-supplied origin always wins over any origin inside the body', async () => {
  const { store } = mk();
  const r = await store.put(A, body(H('d'), { origin: 'https://evil.example' }));
  assert.strictEqual(r.ok, true);
  assert.strictEqual((await store.lookup(A, H('d'))).macro.origin, A);
  assert.strictEqual((await store.lookup('https://evil.example', H('d'))).macro, null);
});

await t('bad origins and bad requests are rejected, never stored', async () => {
  const { store, storage } = mk();
  for (const o of ['javascript:alert(1)', 'https://a.example/path', '', null, undefined, 'file:///etc', 'https://' + 'a'.repeat(300)]) {
    assert.strictEqual((await store.put(o, body())).ok, false);
    assert.strictEqual((await store.lookup(o, H('d'))).macro, null);
  }
  assert.strictEqual((await store.lookup(A, 'not-hex')).error, 'bad_request');
  assert.ok(![...storage.data.keys()].some((k) => k.startsWith('perceive.macro.v1.')));
});

await t('invalid candidates are rejected before any write (closed schema)', async () => {
  const { store, storage } = mk();
  const before = storage.sets;
  for (const b of [null, 5, {}, body(H('d'), { steps: [] }), { ...body(), raw_password: 'hunter2' }, body(H('d'), { steps: [{ i: 0, type: 'eval' }] })]) {
    assert.strictEqual((await store.put(A, b)).ok, false);
  }
  assert.strictEqual(storage.sets, before, 'no write happened at all');
  assert.ok(![...storage.data.keys()].some((k) => k.startsWith('perceive.macro.v1.')));
});

await t('a re-save of the same task replaces the old macro (one per origin+task)', async () => {
  const { store } = mk();
  const a = await store.put(A, body());
  const b = await store.put(A, body());
  assert.notStrictEqual(a.macro_id, b.macro_id);
  assert.strictEqual((await store.list(A)).macros.length, 1);
  assert.strictEqual((await store.lookup(A, H('d'))).macro.macro_id, b.macro_id);
});

await t('per-origin cap: evicts least-recently-used, never the one just saved', async () => {
  const { store, clock } = mk();
  for (let i = 0; i < LIMITS.MAX_MACROS_PER_ORIGIN; i++) { clock.t += 1000; await store.put(A, body(fp(i))); }
  clock.t += 1000;
  const r = await store.put(A, body(fp(999)));
  assert.strictEqual(r.ok, true);
  const list = (await store.list(A)).macros;
  assert.strictEqual(list.length, LIMITS.MAX_MACROS_PER_ORIGIN);
  assert.strictEqual((await store.lookup(A, fp(0))).macro, null, 'oldest evicted');
  assert.notStrictEqual((await store.lookup(A, fp(999))).macro, null, 'newest kept');
});

await t('eviction prefers quarantined macros over healthy ones', async () => {
  const { store, clock } = mk();
  const ids = [];
  for (let i = 0; i < LIMITS.MAX_MACROS_PER_ORIGIN; i++) { clock.t += 1000; ids.push((await store.put(A, body(fp(i)))).macro_id); }
  await store.recordResult(A, ids[10], { success: false, hard: true }); // quarantine a mid-aged one
  clock.t += 1000;
  await store.put(A, body(fp(500)));
  assert.strictEqual((await store.list(A)).macros.some((m) => m.macro_id === ids[10]), false, 'quarantined one evicted');
  assert.notStrictEqual((await store.lookup(A, fp(0))).macro, null, 'oldest healthy one kept');
});

await t('global origin cap: least-recently-touched origin is evicted', async () => {
  const { store, storage, clock } = mk();
  for (let i = 0; i < LIMITS.MAX_ORIGINS; i++) { clock.t += 10; await store.put(`https://o${i}.example`, body(fp(1))); }
  clock.t += 10;
  await store.put('https://new.example', body(fp(1)));
  assert.strictEqual((await store.lookup('https://o0.example', fp(1))).macro, null);
  assert.notStrictEqual((await store.lookup('https://new.example', fp(1))).macro, null);
  assert.ok(!storage.data.has('perceive.macro.v1.https://o0.example'), 'evicted origin key removed');
});

await t('tampered macro (integrity HMAC mismatch) is dropped, reported and purged — never returned', async () => {
  const { store, storage } = mk();
  await store.put(A, body());
  const k = 'perceive.macro.v1.' + A;
  const entry = storage.data.get(k);
  entry.macros[0].steps[1].post[0].pathname_hmac = H('0');       // edit a step without the key
  const res = await store.lookup(A, H('d'));
  assert.strictEqual(res.macro, null);
  assert.strictEqual(res.dropped, 1);
  assert.strictEqual(res.dropped_by_reason.corrupt, 1);
  assert.strictEqual((await store.list(A)).macros.length, 0, 'purged');
});

await t('schema-invalid, wrong-origin and unsupported-version entries are dropped', async () => {
  const { store, storage } = mk();
  await store.put(A, body());
  await store.put(B, body());
  const kA = 'perceive.macro.v1.' + A;
  const good = storage.data.get(kA).macros[0];
  storage.data.get(kA).macros.push({ ...good, macro_id: '123e4567-e89b-42d3-a456-426614174111', schema_version: 9 });          // future version
  storage.data.get(kA).macros.push({ ...good, macro_id: '123e4567-e89b-42d3-a456-426614174222', extra: 'x' });                   // unknown key
  storage.data.get(kA).macros.push(storage.data.get('perceive.macro.v1.' + B).macros[0]);                                        // filed under the wrong origin
  storage.data.get(kA).macros.push('garbage', null, 7);
  const res = await store.lookup(A, H('d'));
  assert.ok(res.macro, 'the good macro still works');
  assert.strictEqual(res.dropped, 6);
  assert.strictEqual(res.dropped_by_reason.unsupported_version, 1);
  assert.strictEqual(storage.data.get(kA).macros.length, 1, 'bad entries purged');
});

await t('structurally corrupt origin entry (not the expected shape) is discarded safely', async () => {
  const { store, storage } = mk();
  await store.put(A, body());
  storage.data.set('perceive.macro.v1.' + A, { v: 1, macros: 'nope' });
  const res = await store.lookup(A, H('d'));
  assert.deepStrictEqual([res.macro, res.error], [null, 'corrupt_store']);
  assert.strictEqual(storage.data.has('perceive.macro.v1.' + A), false);
  storage.data.set('perceive.macro.v1.' + A, 'string');
  assert.strictEqual((await store.lookup(A, H('d'))).macro, null);
});

await t('macros unused for the TTL expire', async () => {
  const { store, clock } = mk();
  await store.put(A, body());
  clock.t += LIMITS.UNUSED_TTL_MS + 1;
  const res = await store.lookup(A, H('d'));
  assert.strictEqual(res.macro, null);
  assert.strictEqual(res.dropped_by_reason.expired, 1);
});

await t('quota failure: reported safely, existing macros untouched, no partial write', async () => {
  const { store, storage } = mk();
  const ok = await store.put(A, body(fp(1)));
  const snapshot = JSON.stringify([...storage.data.entries()]);
  storage.failSet = new Error('QUOTA_BYTES quota exceeded');
  const r = await store.put(A, body(fp(2)));
  assert.deepStrictEqual([r.ok, r.error], [false, 'storage_quota']);
  storage.failSet = new Error('disk on fire');
  assert.strictEqual((await store.put(A, body(fp(3)))).error, 'storage_error');
  storage.failSet = null;
  assert.strictEqual(JSON.stringify([...storage.data.entries()]), snapshot, 'nothing changed');
  assert.strictEqual((await store.lookup(A, fp(1))).macro.macro_id, ok.macro_id);
});

await t('a write failure during recordResult/delete is reported, never thrown', async () => {
  const { store, storage } = mk();
  const { macro_id } = await store.put(A, body());
  storage.failSet = new Error('quota');
  assert.strictEqual((await store.recordResult(A, macro_id, { success: true })).ok, false);
  assert.strictEqual((await store.delete(A, macro_id)).ok, false);
});

await t('delete / clearOrigin / clearAll', async () => {
  const { store, storage } = mk();
  const a1 = await store.put(A, body(fp(1)));
  await store.put(A, body(fp(2)));
  await store.put(B, body(fp(1)));
  assert.deepStrictEqual(await store.delete(A, a1.macro_id), { ok: true, removed: 1 });
  assert.deepStrictEqual(await store.delete(A, a1.macro_id), { ok: true, removed: 0 });
  assert.strictEqual((await store.list(A)).macros.length, 1);
  await store.clearOrigin(A);
  assert.strictEqual((await store.list(A)).macros.length, 0);
  assert.strictEqual((await store.list(B)).macros.length, 1, 'other origin untouched');
  assert.strictEqual((await store.clearAll()).ok, true);
  assert.strictEqual((await store.list(B)).macros.length, 0);
  assert.ok(![...storage.data.keys()].some((k) => k.startsWith('perceive.macro.v1.')));
});

await t('recordResult: stats, success resets streak, 3 consecutive failures or 1 hard failure quarantines', async () => {
  const { store } = mk();
  const { macro_id } = await store.put(A, body());
  await store.recordResult(A, macro_id, { success: false });
  await store.recordResult(A, macro_id, { success: false });
  assert.strictEqual((await store.lookup(A, H('d'))).macro.stats.consecutive_failures, 2);
  await store.recordResult(A, macro_id, { success: true });
  let m = (await store.lookup(A, H('d'))).macro;
  assert.deepStrictEqual(m.stats, { replays: 3, successes: 1, consecutive_failures: 0 });
  for (let i = 0; i < 3; i++) await store.recordResult(A, macro_id, { success: false });
  assert.strictEqual((await store.lookup(A, H('d'))).macro, null, 'quarantined macros are never offered');
  assert.strictEqual((await store.list(A)).macros[0].status, 'quarantined');

  const b = await store.put(A, body(fp(7)));
  assert.strictEqual((await store.recordResult(A, b.macro_id, { success: false, hard: true })).status, 'quarantined');
  assert.strictEqual((await store.recordResult(A, '123e4567-e89b-42d3-a456-426614174999', { success: true })).error, 'not_found');
});

await t('stats updates do not break the integrity HMAC (mutable fields are outside it)', async () => {
  const { store } = mk();
  const { macro_id } = await store.put(A, body());
  await store.recordResult(A, macro_id, { success: true });
  assert.notStrictEqual((await store.lookup(A, H('d'))).macro, null);
});

await t('concurrent writes are serialized: none are lost', async () => {
  const { store } = mk();
  await Promise.all(Array.from({ length: 12 }, (_, i) => store.put(A, body(fp(i + 1)))));
  assert.strictEqual((await store.list(A)).macros.length, 12);
});

await t('the install key is created once and shared by concurrent callers', async () => {
  const { store, storage } = mk();
  const keys = await Promise.all([store.getKey(), store.getKey(), store.getKey()]);
  assert.strictEqual(new Set(keys).size, 1);
  assert.match(keys[0], /^[0-9a-f]{64}$/);
  const store2 = createMacroStore({ storage });
  assert.strictEqual(await store2.getKey(), keys[0], 'persisted across worker restarts');
});

await t('a macro made under a different install key fails integrity (cannot be forged/imported)', async () => {
  const a = mk(), b = mk();
  await a.store.put(A, body());
  b.storage.data.set('perceive.macro.v1.' + A, a.storage.data.get('perceive.macro.v1.' + A));
  const res = await b.store.lookup(A, H('d'));
  assert.strictEqual(res.macro, null);
  assert.strictEqual(res.dropped_by_reason.corrupt, 1);
});

await t('nothing but hashes/references lands in storage (scan the whole persisted blob)', async () => {
  const { store, storage } = mk();
  await store.put(A, body());
  const blob = JSON.stringify([...storage.data.entries()]);
  for (const forbidden of ['hunter2', 'password123', '@', 'Jane', 'jane', '4111', '9876543210', 'label_text', 'task_instruction', 'raw_value']) {
    assert.ok(!blob.includes(forbidden), `stored blob contains "${forbidden}"`);
  }
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
