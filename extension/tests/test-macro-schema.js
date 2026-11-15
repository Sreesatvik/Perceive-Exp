// Macro schema: strict validation (closed schema, bounded, no free text).
import assert from 'assert';
import { validateMacro, validateCandidateBody, canonicalJson, macroBody, LIMITS, SCHEMA_VERSION } from '../src/macro/schema.js';
import { hmacHex, randomKeyHex } from '../src/macro/hmac.js';

console.log('=== RUNNING MACRO SCHEMA TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const H = 'a'.repeat(64);
const desc = (o = {}) => ({ tag: 'input', role: 'textbox', input_type: 'text', name_attr_hmac: H, stable_id_hmac: null, name_hmac: H,
  ctx: { form_hmac: H, landmark_role: 'form', landmark_hmac: H }, sensitivity: { is_sensitive: false, type: null }, ...o });
const stepType = (i = 0, o = {}) => ({ i, type: 'type', precondition: { pathname_hmac: H }, target: desc(), value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1 }, post: [{ kind: 'field_filled' }], ...o });
const stepClick = (i = 1, o = {}) => ({ i, type: 'click', precondition: { pathname_hmac: H }, target: desc({ tag: 'button', role: 'button', input_type: 'submit', name_attr_hmac: null }), value_source: null, post: [{ kind: 'pathname_is', pathname_hmac: H }], ...o });
const macro = (o = {}) => ({ macro_id: '123e4567-e89b-42d3-a456-426614174000', schema_version: 1, origin: 'https://example.com', task_fp: H,
  created_at: 1790000000000, last_used_at: null, status: 'active', stats: { replays: 0, successes: 0, consecutive_failures: 0 },
  steps: [stepType(0), stepClick(1)], integrity: H, ...o });
const bad = (m, re) => {
  const r = validateMacro(m);
  assert.strictEqual(r.ok, false, 'expected rejection');
  if (re) assert.ok(r.errors.some((e) => re.test(e)), JSON.stringify(r.errors));
  return r;
};

await t('a well-formed macro validates', async () => { assert.deepStrictEqual(validateMacro(macro()), { ok: true }); });

await t('non-objects and arrays are rejected', async () => {
  for (const v of [null, undefined, 5, 'x', [], () => 1]) assert.strictEqual(validateMacro(v).ok, false);
});

await t('unsupported version is reported distinctly (never executed)', async () => {
  assert.strictEqual(validateMacro(macro({ schema_version: 2 })).reason, 'unsupported_version');
  assert.strictEqual(validateMacro(macro({ schema_version: '1' })).reason, 'unsupported_version');
});

await t('unknown keys are rejected at every level (closed schema)', async () => {
  bad({ ...macro(), extra: 1 }, /unknown key/);
  bad(macro({ stats: { replays: 0, successes: 0, consecutive_failures: 0, x: 1 } }), /stats\.x/);
  bad(macro({ steps: [{ ...stepType(0), raw_value: 'hunter2' }, stepClick(1)] }), /raw_value/);
  bad(macro({ steps: [stepType(0, { target: { ...desc(), label_text: 'Jane Doe' } }), stepClick(1)] }), /label_text/);
  bad(macro({ steps: [stepType(0, { post: [{ kind: 'field_filled', text: 'x' }] }), stepClick(1)] }), /post\[0\]/);
});

await t('there is no field that can hold raw text: free-text in hash/id/value fields is rejected', async () => {
  bad(macro({ steps: [stepType(0, { target: desc({ name_hmac: 'Jane Doe jane@x.com' }) }), stepClick(1)] }), /name_hmac/);
  bad(macro({ task_fp: 'search for my password hunter2' }), /task_fp/);
  bad(macro({ steps: [stepType(0, { value_source: { kind: 'literal', value: 'hunter2' } }), stepClick(1)] }), /value_source/);
  bad(macro({ steps: [stepType(0, { value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1, value: 'x' } }), stepClick(1)] }), /unknown key/);
  bad(macro({ steps: [stepType(0, { target: desc({ stable_id_hmac: 'jane doe@x.com' }) }), stepClick(1)] }), /stable_id_hmac/);
});

await t('bounds: step count, ordinals, spans, wait ms, pathname length, macro size', async () => {
  bad(macro({ steps: [] }));
  bad(macro({ steps: Array.from({ length: LIMITS.MAX_STEPS + 1 }, (_, i) => stepClick(i)) }), /steps: count/);
  bad(macro({ steps: [stepType(0, { value_source: { kind: 'token_slot', type: 'NAME', ordinal: 10 } }), stepClick(1)] }), /ordinal/);
  bad(macro({ steps: [stepType(0, { value_source: { kind: 'task_span', w0: 3, w1: 3 } }), stepClick(1)] }), /span/);
  bad(macro({ steps: [{ i: 0, type: 'wait', precondition: { pathname_hmac: H }, target: null, value_source: { kind: 'literal_ms', ms: 999999 }, post: [] }] }), /ms/);
  bad(macro({ steps: [stepType(0, { precondition: { pathname_hmac: '/login' } }), stepClick(1)] }), /pathname_hmac/);   // a plain path can never be stored
  const big = Array.from({ length: LIMITS.MAX_STEPS }, (_, i) => stepClick(i, {
    target: desc({ stable_id_hmac: H, name_attr_hmac: H }),
    post: [{ kind: 'pathname_is', pathname_hmac: H }, { kind: 'element_appeared', role: 'heading', tag: 'h1', name_hmac: H }, { kind: 'element_gone', role: 'dialog', tag: 'div', name_hmac: H }],
    precondition: { pathname_hmac: H },
  }));
  // The largest LEGAL macro (every per-field bound maxed) stays under the size backstop...
  assert.strictEqual(validateMacro(macro({ steps: big })).ok, true);
  assert.ok(new TextEncoder().encode(JSON.stringify(macro({ steps: big }))).length < LIMITS.MAX_MACRO_BYTES);
  // ...so the byte cap only ever triggers on oversized junk, and is checked first.
  const r = bad({ ...macro(), padding: 'x'.repeat(LIMITS.MAX_MACRO_BYTES) });
  assert.strictEqual(r.reason, 'too_large');
});

await t('field types and enums: origin, uuid, status, sensitivity, step type', async () => {
  bad(macro({ origin: 'javascript:alert(1)' }), /origin/);
  bad(macro({ origin: 'https://example.com/path' }), /origin/);
  bad(macro({ macro_id: 'not-a-uuid' }), /macro_id/);
  bad(macro({ status: 'admin' }), /status/);
  bad(macro({ steps: [stepType(0, { target: desc({ sensitivity: { is_sensitive: true, type: 'SSN' } }) }), stepClick(1)] }), /sensitivity\.type/);
  bad(macro({ steps: [stepClick(0, { type: 'task_complete' })] }), /type/);
  bad(macro({ steps: [stepClick(0, { type: 'eval' })] }), /type/);
});

await t('step index must be its position; wait has no target; value_source only where allowed', async () => {
  bad(macro({ steps: [stepClick(3)] }), /\.i/);
  bad(macro({ steps: [{ i: 0, type: 'wait', precondition: { pathname_hmac: H }, target: desc(), value_source: { kind: 'literal_ms', ms: 100 }, post: [] }] }), /target/);
  bad(macro({ steps: [stepClick(0, { value_source: { kind: 'literal_ms', ms: 5 } })] }), /value_source/);
  bad(macro({ steps: [stepType(0, { value_source: { kind: 'literal_ms', ms: 5 } }), stepClick(1)] }), /not allowed/);
});

await t('state-changing steps need a real postcondition; type steps need a field-level one', async () => {
  bad(macro({ steps: [stepClick(0, { post: [] })] }), /needs a postcondition/);
  bad(macro({ steps: [stepType(0, { post: [{ kind: 'pathname_is', pathname_hmac: H }] })] }), /field_filled/);
  bad(macro({ steps: [{ i: 0, type: 'select_custom', precondition: { pathname_hmac: H }, target: desc({ tag: 'button', role: 'button' }), value_source: { kind: 'task_span', w0: 1, w1: 2 }, post: [{ kind: 'field_filled' }] }] }), /select_shows/);
  assert.strictEqual(validateMacro(macro({ steps: [{ i: 0, type: 'scroll', precondition: { pathname_hmac: H }, target: desc(), value_source: null, post: [] }] })).ok, true);
});

await t('an element with fewer than 2 independent anchors can never be a target', async () => {
  const noCtx = { form_hmac: null, landmark_role: null, landmark_hmac: null };
  bad(macro({ steps: [stepClick(0, { target: desc({ name_hmac: null, name_attr_hmac: null, stable_id_hmac: null, ctx: noCtx }) })] }), /weak identity/);
  bad(macro({ steps: [stepClick(0, { target: desc({ name_hmac: H, name_attr_hmac: null, stable_id_hmac: null, ctx: noCtx }) })] }), /weak identity/);   // one anchor only
  assert.strictEqual(validateMacro(macro({ steps: [stepClick(0, { target: desc({ name_hmac: H, name_attr_hmac: H, stable_id_hmac: null, ctx: noCtx }) })] })).ok, true);
});

await t('non-JSON-safe / hostile objects never throw', async () => {
  const cyc = macro(); cyc.self = cyc;
  assert.doesNotThrow(() => validateMacro(cyc));
  assert.strictEqual(validateMacro(cyc).ok, false);
  const proto = JSON.parse('{"__proto__":{"x":1},"macro_id":"x"}');
  assert.doesNotThrow(() => validateMacro(proto));
});

await t('candidate bodies validate through the same rules', async () => {
  const { macro_id, schema_version, last_used_at, status, stats, integrity, ...body } = macro();
  assert.deepStrictEqual(validateCandidateBody(body), { ok: true });
  assert.strictEqual(validateCandidateBody({ ...body, steps: [] }).ok, false);
});

await t('canonicalJson is key-order independent; macroBody excludes mutable fields', async () => {
  assert.strictEqual(canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] }), canonicalJson({ a: [2, { c: 2, d: 1 }], b: 1 }));
  const m = macro();
  const b1 = canonicalJson(macroBody(m));
  m.stats.replays = 9; m.last_used_at = 5; m.status = 'quarantined';
  assert.strictEqual(canonicalJson(macroBody(m)), b1);
  m.steps[0].precondition.pathname_hmac = 'b'.repeat(64);
  assert.notStrictEqual(canonicalJson(macroBody(m)), b1, 'core changes must change the integrity input');
});

await t('hmacHex: deterministic, keyed, 64 hex; bad keys rejected', async () => {
  const k1 = randomKeyHex(), k2 = randomKeyHex();
  const a = await hmacHex(k1, 'Login');
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.strictEqual(a, await hmacHex(k1, 'Login'));
  assert.notStrictEqual(a, await hmacHex(k2, 'Login'));
  assert.notStrictEqual(a, await hmacHex(k1, 'login'));
  await assert.rejects(() => hmacHex('short', 'x'));
});

assert.strictEqual(SCHEMA_VERSION, 1);
console.log(`\n${n}/${n} passed`);
process.exit(0);
