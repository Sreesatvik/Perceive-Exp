// Recorder: candidate macros, value provenance, taint vs truncate, navigation
// survival, and privacy of everything it emits.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { createRecorder, valueSourceFor, saveSummary } from '../src/macro/recorder.js';
import { canonicalizeTask } from '../src/macro/fingerprint.js';
import { validateCandidateBody, LIMITS } from '../src/macro/schema.js';
import { classifyElement } from '../../dev2/dom-heuristics.js';
import { randomKeyHex } from '../src/macro/hmac.js';
import { pathHmac } from '../src/macro/postcondition.js';

console.log('=== RUNNING MACRO RECORDER TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const KEY = randomKeyHex();
const ORIGIN = 'https://example.com';
const TOK_USER = '[NAME_aaaaaaaaaa]', TOK_PW = '[PASSWORD_bbbbbbbbbb]';
const TASK = canonicalizeTask(`log in with username ${TOK_USER} and password ${TOK_PW} then select Hyderabad from the city dropdown`);
const FP = 'f'.repeat(64);

const LOGIN = `<main><form id="login-form" action="/session">
  <label for="user">Username</label><input id="user" name="username" type="text">
  <label for="pw">Password</label><input id="pw" name="password" type="password">
  <button id="signin" type="submit">Sign in</button></form></main>`;

function env(html = LOGIN, url = 'https://example.com/login') {
  const dom = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url, pretendToBeVisual: true });
  return { dom, doc: dom.window.document, win: dom.window };
}
const sumOf = (el) => { const c = classifyElement(el); return { tag: c.tag, role: c.role, label_text: c.label_text, is_sensitive: !!c.is_sensitive && c.sensitivity_type !== 'UNKNOWN' && c.sensitivity_type != null, sensitivity_type: c.sensitivity_type }; };
const rec = (opts = {}) => createRecorder({ keyHex: KEY, origin: ORIGIN, taskFp: FP, task: TASK, ...opts });

async function step(r, e, id, action, effect) {
  const el = e.doc.getElementById(id);
  await r.beginStep({ action, summary: sumOf(el), el, doc: e.doc, win: e.win });
  if (effect) effect(el);
  await r.completeStep({ doc: e.doc, win: e.win, el });
}
const typeAct = (id, value) => ({ type: 'type', target_element_id: id, value });

await t('records a login flow: hashed descriptors, value REFERENCES, real postconditions', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'jane_doe_real_username'; });
  await step(r, e, 'pw', typeAct('pw', TOK_PW), (el) => { el.value = 'S3cret-Real-Pass!'; });
  await step(r, e, 'signin', { type: 'click', target_element_id: 'signin' }, () => {
    e.dom.reconfigure({ url: 'https://example.com/home' });
    e.doc.body.innerHTML = '<h1>Dashboard</h1>';
  });
  const c = r.candidate();
  assert.ok(c, 'candidate produced');
  assert.strictEqual(c.body.steps.length, 3);
  assert.deepStrictEqual(c.body.steps.map((s) => s.type), ['type', 'type', 'click']);
  assert.deepStrictEqual(c.body.steps[0].value_source, { kind: 'token_slot', type: 'NAME', ordinal: 1 });
  assert.deepStrictEqual(c.body.steps[1].value_source, { kind: 'token_slot', type: 'PASSWORD', ordinal: 1 });
  assert.deepStrictEqual(c.body.steps[0].post, [{ kind: 'field_filled' }]);
  assert.deepStrictEqual(c.body.steps[2].post[0], { kind: 'pathname_is', pathname_hmac: await pathHmac(KEY, '/home') });
  assert.strictEqual(c.body.steps[1].target.sensitivity.type, 'PASSWORD');
  assert.deepStrictEqual(validateCandidateBody(c.body), { ok: true });
  assert.deepStrictEqual(c.lines, ['Enter [NAME]', 'Enter [PASSWORD]', 'Click "Sign in"']);
});

await t('PRIVACY: nothing typed, no label, no token suffix, no page text is in the candidate body or the summary', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'jane_doe_real_username'; });
  await step(r, e, 'pw', typeAct('pw', TOK_PW), (el) => { el.value = 'S3cret-Real-Pass!'; });
  await step(r, e, 'signin', { type: 'click', target_element_id: 'signin' }, () => { e.doc.body.insertAdjacentHTML('beforeend', '<h1>Welcome Jane Doe</h1>'); });
  const c = r.candidate();
  const blob = JSON.stringify(c) + saveSummary({ origin: ORIGIN, lines: c.lines, truncated: c.truncated });
  for (const secret of ['jane_doe_real_username', 'S3cret-Real-Pass!', 'aaaaaaaaaa', 'bbbbbbbbbb', 'Welcome Jane Doe', 'Username', 'Password', '/session', 'log in with']) {
    assert.ok(!blob.includes(secret), `leaked "${secret}"`);
  }
  assert.ok(!JSON.stringify(r.serialize()).includes('S3cret-Real-Pass!'));
});

await t('provenance: token must come from the task; an unknown token stops recording (prefix kept)', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'x'; });
  await step(r, e, 'pw', typeAct('pw', '[PASSWORD_zzzzzzzzzz]'), (el) => { el.value = 'y'; });   // never in the task
  assert.strictEqual(r.truncated, 'token_not_from_task');
  assert.strictEqual(r.tainted, null);
  const c = r.candidate();
  assert.strictEqual(c.body.steps.length, 1, 'macro is the safe prefix');
  await step(r, e, 'signin', { type: 'click', target_element_id: 'signin' }, () => { e.doc.body.insertAdjacentHTML('beforeend', '<h1>x</h1>'); });
  assert.strictEqual(r.candidate().body.steps.length, 1, 'nothing recorded after a truncation');
});

await t('provenance: literal values — user\'s own words only; invented, sensitive-field, PII-shaped and raw-secret values are refused', async () => {
  const sel = { tag: 'select', role: 'combobox', label_text: 'City', is_sensitive: false, sensitivity_type: null };
  const sens = { tag: 'input', role: 'textbox', label_text: 'Password', is_sensitive: true, sensitivity_type: 'PASSWORD' };
  const plain = { tag: 'input', role: 'textbox', label_text: 'Q', is_sensitive: false, sensitivity_type: null };
  assert.deepStrictEqual(valueSourceFor({ type: 'select_custom', value: 'Hyderabad' }, sel, TASK), { kind: 'task_span', w0: TASK.words.indexOf('Hyderabad'), w1: TASK.words.indexOf('Hyderabad') + 1 });
  assert.strictEqual(valueSourceFor({ type: 'type', value: 'Mumbai' }, plain, TASK).refuse, 'value_without_provenance');         // LLM-invented
  assert.strictEqual(valueSourceFor({ type: 'type', value: 'Hyderabad' }, sens, TASK).refuse, 'literal_into_sensitive_field');    // literals never go to sensitive fields
  assert.strictEqual(valueSourceFor({ type: 'type', value: 'hunter2' }, sens, TASK).refuse, 'literal_into_sensitive_field');
  assert.strictEqual(valueSourceFor({ type: 'type', value: '9876543210' }, plain, TASK).refuse, 'pii_shaped_literal');
  assert.strictEqual(valueSourceFor({ type: 'type', value: 'a@b.com' }, plain, TASK).refuse, 'pii_shaped_literal');
  assert.strictEqual(valueSourceFor({ type: 'type', value: '[NOT_A_TOKEN]' }, plain, TASK).refuse, 'unresolved_token_shape');
  assert.strictEqual(valueSourceFor({ type: 'type', value: '' }, plain, TASK).refuse, 'empty_value');
  assert.strictEqual(valueSourceFor({ type: 'type', value: 'x' }, plain, null).refuse, 'no_task_context');
  assert.strictEqual(valueSourceFor({ type: 'click' }, plain, TASK), null);
  assert.deepStrictEqual(valueSourceFor({ type: 'wait', value: '1500' }, null, TASK), { kind: 'literal_ms', ms: 1500 });
  assert.strictEqual(valueSourceFor({ type: 'wait', value: '999999' }, null, TASK).refuse, 'wait_value');
});

await t('a raw secret typed by a buggy/manipulated LLM (not a token) is never recorded', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'pw', typeAct('pw', 'hunter2'), (el) => { el.value = 'hunter2'; });
  assert.strictEqual(r.truncated, 'literal_into_sensitive_field');
  assert.strictEqual(r.candidate(), null, 'no steps => no candidate');
  assert.ok(!JSON.stringify(r.serialize()).includes('hunter2'));
});

await t('select step: value is a task word-span; postcondition select_shows', async () => {
  const e = env('<main><form action="/x" id="f"><label for="city">City</label><select id="city" name="city"><option value="hyd">Hyderabad</option><option value="blr">Bangalore</option></select></form></main>');
  const r = rec();
  await step(r, e, 'city', { type: 'type', target_element_id: 'city', value: 'Hyderabad' }, (el) => { el.value = 'hyd'; });
  const c = r.candidate();
  assert.strictEqual(c.body.steps[0].value_source.kind, 'task_span');
  assert.deepStrictEqual(c.body.steps[0].post, [{ kind: 'select_shows' }]);
  assert.deepStrictEqual(c.lines, ['Select "Hyderabad"']);
});

await t('unverifiable step (nothing observable changed) truncates: the click "returning" is not evidence', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'x'; });
  await step(r, e, 'signin', { type: 'click', target_element_id: 'signin' }, () => { /* the click did nothing visible */ });
  assert.strictEqual(r.truncated, 'unverifiable_step');
  assert.strictEqual(r.candidate().body.steps.length, 1);
});

await t('weak identity (unlabeled, unnamed, no context) truncates', async () => {
  const e = env('<div><button id="mystery" type="button"></button></div>');
  const r = rec();
  await step(r, e, 'mystery', { type: 'click', target_element_id: 'mystery' }, () => {});
  assert.strictEqual(r.truncated, 'weak_identity');
  assert.strictEqual(r.candidate(), null);
});

await t('taint: the WHOLE run is discarded (failure/rejection/injection), even with valid steps; taint outranks truncation', async () => {
  const e = env();
  const r = rec();
  await step(r, e, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'x'; });
  assert.ok(r.candidate());
  r.taint('server_rejected');
  assert.strictEqual(r.candidate(), null);
  assert.strictEqual(r.tainted, 'server_rejected');
  r.taint('second_reason');
  assert.strictEqual(r.tainted, 'server_rejected', 'first reason kept');
  await step(r, e, 'pw', typeAct('pw', TOK_PW), (el) => { el.value = 'y'; });
  assert.strictEqual(r.stepCount, 1, 'nothing more recorded');
});

await t('unsupported action types taint the run (task_complete / ask_user_confirmation are never macro steps)', async () => {
  const e = env();
  for (const type of ['ask_user_confirmation', 'task_complete', 'task_failed', 'eval']) {
    const r = rec();
    await step(r, e, 'user', { type, target_element_id: 'user' }, null);
    assert.strictEqual(r.tainted, 'unsupported_action', type);
    assert.strictEqual(r.candidate(), null);
  }
});

await t('a step begun but never completed blocks the candidate (no half-recorded steps)', async () => {
  const e = env();
  const r = rec();
  await r.beginStep({ action: typeAct('user', TOK_USER), summary: sumOf(e.doc.getElementById('user')), el: e.doc.getElementById('user'), doc: e.doc, win: e.win });
  assert.ok(r.hasPending());
  assert.strictEqual(r.candidate(), null);
});

await t('survives a page navigation: serialize -> JSON -> restore on the NEW page derives the navigation postcondition', async () => {
  const e1 = env();
  const r1 = rec();
  await step(r1, e1, 'user', typeAct('user', TOK_USER), (el) => { el.value = 'x'; });
  const el = e1.doc.getElementById('signin');
  await r1.beginStep({ action: { type: 'click', target_element_id: 'signin' }, summary: sumOf(el), el, doc: e1.doc, win: e1.win });
  const wire = JSON.parse(JSON.stringify(r1.serialize()));            // what the background keeps in memory
  // --- the page navigates; a fresh content script starts on the new page ---
  const e2 = env('<h1>Dashboard</h1>', 'https://example.com/home');
  const r2 = rec({ restore: wire });
  assert.ok(r2.hasPending());
  await r2.completeStep({ doc: e2.doc, win: e2.win, el: null });
  const c = r2.candidate();
  assert.strictEqual(c.body.steps.length, 2);
  assert.deepStrictEqual(c.body.steps[1].post[0], { kind: 'pathname_is', pathname_hmac: await pathHmac(KEY, '/home') });
  assert.deepStrictEqual(validateCandidateBody(c.body), { ok: true });
});

await t('restore is defensive: garbage state yields an empty recorder, never a throw or a bogus macro', async () => {
  for (const bad of [null, 5, 'x', [], { steps: 'nope' }, { steps: [{ nope: 1 }], display: [1, {}] }, { pending: { before: { pathname: '/', items: [] } } }]) {
    let r;
    assert.doesNotThrow(() => { r = rec({ restore: bad }); });
    assert.strictEqual(r.candidate(), null, JSON.stringify(bad));
  }
});

await t('step cap: recording stops at MAX_STEPS', async () => {
  const e = env('<main><form action="/x"><input id="a" name="alpha" type="text"><label for="a">A</label></form></main>');
  const r = rec();
  for (let i = 0; i < LIMITS.MAX_STEPS + 3; i++) await step(r, e, 'a', { type: 'scroll', target_element_id: 'a' }, null);
  assert.strictEqual(r.stepCount, LIMITS.MAX_STEPS);
  assert.strictEqual(r.truncated, 'max_steps');
});

await t('display lines never show a sensitive/PII/long label, only its role', async () => {
  for (const [html, expected] of [
    ['<main><form action="/x" id="f"><button id="b" type="submit">jane.doe@corp.com</button></form></main>', 'Click a button'],
    ['<main><form action="/x" id="f"><button id="b" type="submit">Proceed to the extremely long checkout flow now</button></form></main>', 'Click a button'],
    ['<main><form action="/x" id="f"><button id="b" type="submit">Continue</button></form></main>', 'Click "Continue"'],
  ]) {
    const e = env(html);
    const r = rec();
    await step(r, e, 'b', { type: 'click', target_element_id: 'b' }, () => { e.doc.body.insertAdjacentHTML('beforeend', '<h1>Next</h1>'); });
    assert.deepStrictEqual(r.candidate().lines, [expected]);
  }
});

await t('saveSummary: matches the agreed layout, caps long lists, states the guarantee, mentions a truncated macro', async () => {
  const s = saveSummary({ origin: 'https://example.com', lines: ['Click "Login"', 'Enter [USERNAME]', 'Enter [PASSWORD]', 'Select "Hyderabad"', 'Click "Submit"'], truncated: null });
  assert.ok(s.startsWith('Save workflow?\n\nexample.com\n5 steps\n'));
  assert.ok(s.includes('• Enter [PASSWORD]') && s.includes('Sensitive values are not stored.'));
  assert.ok(!s.includes('AI'), 'no truncation note when complete');
  const long = saveSummary({ origin: 'https://a.example:8443', lines: Array.from({ length: 12 }, (_, i) => `Click "B${i}"`), truncated: 'value_without_provenance' });
  assert.ok(long.includes('…and 4 more') && long.includes('a.example:8443') && long.includes('planned by the AI'));
  assert.ok(saveSummary({ origin: 'https://a.example', lines: ['Click "X"'], truncated: null }).includes('1 step\n'));
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
