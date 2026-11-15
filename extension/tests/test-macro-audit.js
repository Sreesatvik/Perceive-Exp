// Phase 6 audit regressions: nothing page-derived is persisted as plain text,
// recordings are single-origin, and postconditions are causal.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { createRecorder } from '../src/macro/recorder.js';
import { canonicalizeTask } from '../src/macro/fingerprint.js';
import { validateMacro } from '../src/macro/schema.js';
import { createMacroStore } from '../src/background/macroStore.js';
import { classifyElement } from '../../dev2/dom-heuristics.js';
import { randomKeyHex } from '../src/macro/hmac.js';

console.log('=== RUNNING MACRO AUDIT REGRESSION TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const KEY = randomKeyHex();
const ORIGIN = 'https://example.com';
const TOK = '[NAME_aaaaaaaaaa]';
const TASK = canonicalizeTask(`sign in as ${TOK} and continue`);
const FP = 'f'.repeat(64);
// Values that must NEVER reach storage (sanitized markers, not real secrets).
const CANARIES = ['reset-tok-CANARY-9f8e7d', 'janedoe-CANARY', 'Jane-Doe-CANARY', 'acct-CANARY-name'];

const sumOf = (el) => { const c = classifyElement(el); return { tag: c.tag, role: c.role, label_text: c.label_text, is_sensitive: !!c.is_sensitive && c.sensitivity_type !== 'UNKNOWN' && c.sensitivity_type != null, sensitivity_type: c.sensitivity_type }; };
const env = (html, url) => { const dom = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url, pretendToBeVisual: true }); return { dom, doc: dom.window.document, win: dom.window }; };
const rec = (o = {}) => createRecorder({ keyHex: KEY, origin: ORIGIN, taskFp: FP, task: TASK, ...o });
async function step(r, e, id, action, effect) {
  const el = e.doc.getElementById(id);
  await r.beginStep({ action, summary: sumOf(el), el, doc: e.doc, win: e.win });
  if (effect) effect(el);
  await r.completeStep({ doc: e.doc, win: e.win, el });
}

await t('PERSISTENCE: reset tokens / usernames in the path and person names in id/name attributes never appear in the candidate or the stored bytes', async () => {
  const e = env(`<main><form id="acct-CANARY-name" action="/x"><input id="user" name="janedoe-CANARY" type="text" aria-label="Jane-Doe-CANARY">
    <button id="go" type="submit" name="acct-CANARY-name">Continue</button></form></main>`, `https://example.com/reset/reset-tok-CANARY-9f8e7d/janedoe-CANARY`);
  const r = rec();
  await step(r, e, 'user', { type: 'type', target_element_id: 'user', value: TOK }, (el) => { el.value = 'x'; });
  await step(r, e, 'go', { type: 'click', target_element_id: 'go' }, () => {
    e.dom.reconfigure({ url: 'https://example.com/welcome/janedoe-CANARY' });
    e.doc.body.innerHTML = '<h1>Hi Jane-Doe-CANARY</h1>';
  });
  const c = r.candidate();
  assert.ok(c);
  const storage = { d: new Map(), async get(k) { const o = {}; for (const x of [].concat(k)) if (this.d.has(x)) o[x] = JSON.parse(JSON.stringify(this.d.get(x))); return o; }, async set(o) { for (const [k, v] of Object.entries(o)) this.d.set(k, JSON.parse(JSON.stringify(v))); }, async remove(k) { for (const x of [].concat(k)) this.d.delete(x); } };
  const store = createMacroStore({ storage });
  assert.strictEqual((await store.put(ORIGIN, c.body)).ok, true);
  const bytes = JSON.stringify([...storage.d.entries()]) + JSON.stringify(c.body);
  for (const s of CANARIES) assert.ok(!bytes.includes(s), `storage leaks "${s}"`);
  assert.ok(!/\/reset\/|\/welcome/.test(bytes), 'no plain pathnames');
});

await t('SCHEMA: plain-text identifiers, paths and unknown roles/tags are rejected as stored fields', async () => {
  const c = (() => { const H = 'a'.repeat(64); return { macro_id: '123e4567-e89b-42d3-a456-426614174000', schema_version: 1, origin: ORIGIN, task_fp: H, created_at: 1, last_used_at: null, status: 'active', stats: { replays: 0, successes: 0, consecutive_failures: 0 }, integrity: H,
    steps: [{ i: 0, type: 'click', precondition: { pathname_hmac: H }, target: { tag: 'button', role: 'button', input_type: null, name_attr_hmac: H, stable_id_hmac: null, name_hmac: H, ctx: { form_hmac: null, landmark_role: null, landmark_hmac: null }, sensitivity: { is_sensitive: false, type: null } }, value_source: null, post: [{ kind: 'pathname_is', pathname_hmac: H }] }] }; })();
  assert.strictEqual(validateMacro(c).ok, true);
  const mut = (f) => { const m = JSON.parse(JSON.stringify(c)); f(m.steps[0]); return validateMacro(m).ok; };
  assert.strictEqual(mut((s) => { s.precondition = { pathname: '/reset/tok' }; }), false);
  assert.strictEqual(mut((s) => { s.target.name_attr_hmac = 'janedoe'; }), false);
  assert.strictEqual(mut((s) => { s.target.role = 'Jane Doe'; }), false);
  assert.strictEqual(mut((s) => { s.target.tag = 'x-janedoe'; }), false);
  assert.strictEqual(mut((s) => { s.post = [{ kind: 'pathname_is', pathname: '/welcome/jane' }]; }), false);
});

await t('CROSS-ORIGIN: a recording that touches another origin is tainted (never a macro), at begin, complete and restore', async () => {
  const good = env('<input id="user" type="text" name="u"><button id="go" name="go">Go</button>', 'https://example.com/a');
  const evil = env('<input id="user" type="text" name="u"><button id="go" name="go">Go</button>', 'https://attacker.example/a');
  // begin on the wrong origin
  const r1 = rec();
  await step(r1, evil, 'user', { type: 'type', target_element_id: 'user', value: TOK }, (el) => { el.value = 'x'; });
  assert.strictEqual(r1.tainted, 'cross_origin');
  assert.strictEqual(r1.candidate(), null);
  // completes on another origin (navigated away mid-step)
  const r2 = rec();
  const el = good.doc.getElementById('user');
  await r2.beginStep({ action: { type: 'type', target_element_id: 'user', value: TOK }, summary: sumOf(el), el, doc: good.doc, win: good.win });
  await r2.completeStep({ doc: evil.doc, win: evil.win, el: null });
  assert.strictEqual(r2.tainted, 'cross_origin');
  // resume state from a different origin
  const r3 = rec();
  await step(r3, good, 'user', { type: 'type', target_element_id: 'user', value: TOK }, (e2) => { e2.value = 'x'; });
  const wire = JSON.parse(JSON.stringify(r3.serialize()));
  assert.strictEqual(wire.origin, ORIGIN);
  const r4 = createRecorder({ keyHex: KEY, origin: 'https://attacker.example', taskFp: FP, task: TASK, restore: wire });
  assert.strictEqual(r4.tainted, 'cross_origin');
  assert.strictEqual(r4.candidate(), null);
});

await t('CAUSAL: a click that changed nothing yields no postcondition even if a heading/dialog already existed (recorder refuses the step)', async () => {
  const e = env('<h1>Dashboard</h1><div role="dialog" aria-label="Terms">t</div><button id="go" name="go" aria-expanded="true">Go</button>', 'https://example.com/a');
  const r = rec();
  await step(r, e, 'go', { type: 'click', target_element_id: 'go' }, null);   // no-op
  assert.strictEqual(r.truncated, 'unverifiable_step');
  assert.strictEqual(r.candidate(), null);
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
