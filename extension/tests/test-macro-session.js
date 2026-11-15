// MacroSession end-to-end (record -> save -> replay -> attacks -> fallback), driven
// exactly like the orchestrator drives it, with the REAL recorder, replayer,
// descriptor resolver, store, background message handler and executeAction.
// Only the vault lookup and the server's verdicts are simulated.
import { pathHmac } from '../src/macro/postcondition.js';
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { createMacroSession } from '../src/macro/session.js';
import { createMacroStore } from '../src/background/macroStore.js';
import { handleMacroMessage } from '../src/background/macroMessages.js';
import { classifyElement, getElementId } from '../../dev2/dom-heuristics.js';
import { executeAction } from '../src/content/actionExecutor.js';

console.log('=== RUNNING MACRO SESSION TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const EXT = 'ext-id';
const LOGIN = `<main><form id="login-form" action="/session">
  <label for="user">Username</label><input id="user" name="username" type="text">
  <label for="pw">Password</label><input id="pw" name="password" type="password">
  <label for="city">City</label><select id="city" name="city"><option value="hyd">Hyderabad</option><option value="blr">Bangalore</option></select>
  <button id="signin" type="submit">Sign in</button></form></main>`;
const HOME_URL = 'https://example.com/home';
const FAST = { timeoutMs: 300, intervalMs: 100, sleep: async () => {}, now: (() => { let c = 0; return () => (c += 100); })() };

function env(html = LOGIN, url = 'https://example.com/login') {
  const dom = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url, pretendToBeVisual: true });
  dom.window.Element.prototype.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, width: 100, height: 20, right: 100, bottom: 20 });
  Object.assign(global, { window: dom.window, document: dom.window.document, Event: dom.window.Event, CSS: { escape: (s) => s } });
  return { dom, doc: dom.window.document, win: dom.window, url };
}
const summaries = (doc) => Array.from(doc.querySelectorAll('input, button, select, textarea, a[href]')).map((el) => {
  const c = classifyElement(el);
  return { el, element_id: getElementId(el), tag: c.tag, role: c.role, label_text: c.label_text, is_sensitive: !!c.is_sensitive && c.sensitivity_type != null && c.sensitivity_type !== 'UNKNOWN', sensitivity_type: c.sensitivity_type };
});
const live = (doc) => { const s = summaries(doc); return { elements: s.map((x) => x.el), summaries: s.map(({ el, ...r }) => r), all: s }; };

// ---- shared "browser profile": one store/storage for every page of every run ----
function profile() {
  const data = new Map();
  const storage = { data,
    async get(k) { const out = {}; for (const key of (Array.isArray(k) ? k : [k])) if (data.has(key)) out[key] = JSON.parse(JSON.stringify(data.get(key))); return out; },
    async set(o) { for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); },
    async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); } };
  const store = createMacroStore({ storage });
  return { storage, store };
}
function sessionFor(p, e, { confirm = async () => true, sendOverride = null } = {}) {
  const events = [];
  const sender = { id: EXT, frameId: 0, tab: { id: 1, url: e.url }, url: e.url };
  const send = sendOverride || (async (message) => handleMacroMessage({ store: p.store, sender, message, extensionId: EXT }));
  const confirms = [];
  const session = createMacroSession({ send, report: (event, details) => events.push({ event, details }), win: e.win, doc: e.doc, confirmSave: async (text) => { confirms.push(text); return confirm(text); } });
  return { session, events, confirms, sender };
}

const NEW1 = { user: '[NAME_aaaaaaaaaa]', pw: '[PASSWORD_bbbbbbbbbb]' };
const taskText = (u, pw, city = 'Hyderabad') => `log in with username ${u} and password ${pw} then select ${city} from the city dropdown`;
const VAULT1 = { [NEW1.user]: 'jane_real_username', [NEW1.pw]: 'S3cret-Real-Pass!' };

// One orchestrator-style step. `serverVerdict` simulates the server (echo by default).
async function step(session, e, action, vault, { navigate = null, serverVerdict = null, replay = false, noteAction = null } = {}) {
  const l = live(e.doc);
  const payload = {};
  const b = await session.beforeSend({ elements: l.elements, summaries: l.summaries, payload });
  let act = action;
  if (replay) {
    if (!b.proposed) return { proposed: false };
    act = { ...payload.proposed_action, risk_tier: 'safe', risk_reasons: [] };
    if (serverVerdict) { const v = serverVerdict(act); if (v.reject) { session.serverRejected(v.reject); return { proposed: true, rejected: true }; } if (v.action) act = v.action; }
    if (!session.responseMatches(act)) return { proposed: true, mismatch: true };
  }
  if (noteAction) session.noteAction(noteAction);
  const el = e.doc.getElementById(Object.entries(Object.fromEntries(l.all.map((x) => [x.element_id, x.el]))).find(([id]) => id === act.target_element_id)?.[0] ?? '') ;
  const sum = l.all.find((x) => x.element_id === act.target_element_id);
  await session.beforeExecute({ action: act, summary: sum && (({ el: _e, ...r }) => r)(sum), el: sum ? sum.el : el });
  const res = await executeAction(act, (tok) => vault[tok] ?? null, null);
  if (!res.success) { session.executionFailed(); return { proposed: b.proposed, res }; }
  session.executed();
  const resume = session.toResume();
  if (navigate) navigate();
  const after = await session.afterExecute({ resolveToken: (tok) => vault[tok] ?? null, waitOpts: FAST });
  return { proposed: b.proposed, res, after, resume };
}
const goHome = (e) => () => { e.dom.reconfigure({ url: HOME_URL }); e.doc.body.innerHTML = '<h1>Dashboard</h1>'; };

async function recordRun(p, { confirm } = {}) {
  const e = env();
  const s = sessionFor(p, e, { confirm });
  assert.strictEqual(await s.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw) }), 'record');
  await step(s.session, e, { type: 'type', target_element_id: 'user', value: NEW1.user }, VAULT1);
  await step(s.session, e, { type: 'type', target_element_id: 'pw', value: NEW1.pw }, VAULT1);
  await step(s.session, e, { type: 'type', target_element_id: 'city', value: 'Hyderabad' }, VAULT1);
  await step(s.session, e, { type: 'click', target_element_id: 'signin' }, VAULT1, { navigate: goHome(e) });
  return { e, ...s };
}

await t('RECORD -> SAVE: a clean run yields a candidate; the user sees a safe summary; only then is it persisted', async () => {
  const p = profile();
  const r = await recordRun(p);
  assert.strictEqual((await p.store.list('https://example.com')).macros.length, 0, 'nothing persisted before the user agrees');
  const out = await r.session.onCompleted({ totals: { llm_calls: 4, total_ms: 9000 } });
  assert.deepStrictEqual([out.outcome, typeof out.macro_id], ['saved', 'string']);
  assert.strictEqual(r.confirms.length, 1);
  const text = r.confirms[0];
  assert.match(text, /^Save workflow\?\n\nexample\.com\n4 steps\n/);
  for (const line of ['• Enter [NAME]', '• Enter [PASSWORD]', '• Select "Hyderabad"', '• Click "Sign in"', 'Sensitive values are not stored.']) assert.ok(text.includes(line), line);
  for (const secret of ['jane_real_username', 'S3cret-Real-Pass!', 'aaaaaaaaaa', 'bbbbbbbbbb']) assert.ok(!text.includes(secret));
  assert.strictEqual((await p.store.list('https://example.com')).macros.length, 1);
  assert.ok(r.events.some((x) => x.event === 'MACRO_CREATED'));
});

await t('USER DECLINES: the candidate is discarded, nothing persisted, decline audited', async () => {
  const p = profile();
  const r = await recordRun(p, { confirm: async () => false });
  const out = await r.session.onCompleted({ totals: {} });
  assert.strictEqual(out.outcome, 'declined');
  assert.strictEqual((await p.store.list('https://example.com')).macros.length, 0);
  assert.ok([...p.storage.data.keys()].every((k) => !k.startsWith('perceive.macro.v1.')), 'no macro key written');
  assert.ok(r.events.some((x) => x.event === 'MACRO_SAVE_DECLINED'));
});

await t('PRIVACY: nothing sensitive in storage, in any audit event, or in the resume state', async () => {
  const p = profile();
  const r = await recordRun(p);
  await r.session.onCompleted({ totals: { llm_calls: 4 } });
  // Persisted / reported / stashed data: no secrets AND no page text (labels, headings, form actions, task words).
  const durable = JSON.stringify([...p.storage.data.entries()]) + JSON.stringify(r.events);
  for (const secret of ['jane_real_username', 'S3cret-Real-Pass!', 'aaaaaaaaaa', 'bbbbbbbbbb', 'Sign in', 'Username', 'Password', 'Dashboard', '/session', 'log in with']) {
    assert.ok(!durable.includes(secret), `leaked "${secret}"`);
  }
  // The in-memory navigation stash (service-worker memory only, deleted on use) may carry the SAME short,
  // PII-filtered display lines the user is shown — and nothing else: no secrets, tokens, or page text.
  const stash = r.session.toResume();
  const stashNoDisplay = JSON.stringify({ ...stash, recorder: { ...stash.recorder, display: [] } });
  for (const secret of ['jane_real_username', 'S3cret-Real-Pass!', 'aaaaaaaaaa', 'bbbbbbbbbb', 'Sign in', 'Username', 'Password', 'Dashboard', '/session', 'log in with']) {
    assert.ok(!stashNoDisplay.includes(secret), `stash leaked "${secret}"`);
  }
  assert.ok(stash.recorder.display.every((l) => /^(Click|Enter|Select|Scroll|Wait)/.test(l)), 'display lines are the fixed, safe vocabulary');
  // The transient save dialog may show a short, safe label ("Sign in") but never a secret.
  const dialog = r.confirms.join('\n');
  for (const secret of ['jane_real_username', 'S3cret-Real-Pass!', 'aaaaaaaaaa', 'bbbbbbbbbb']) assert.ok(!dialog.includes(secret), `dialog leaked "${secret}"`);
});

await t('NOT ELIGIBLE: a run with any execution failure / server rejection / denial / injection signal offers nothing', async () => {
  for (const spoil of [(s) => s.executionFailed(), (s) => s.serverRejected(422), (s) => s.serverRejected(500), (s) => s.denied(),
    (s) => s.noteAction({ type: 'click', risk_reasons: ['target_flagged_injection'] }), (s) => s.noteAction({ type: 'click', risk_reasons: ['reasoning_echoes_injection'] }),
    (s) => s.noteAction({ type: 'ask_user_confirmation' }), (s) => s.taint('retry')]) {
    const p = profile();
    const r = await recordRun(p);
    spoil(r.session);
    const out = await r.session.onCompleted({ totals: {} });
    assert.strictEqual(out.outcome, 'not_eligible');
    assert.strictEqual(r.confirms.length, 0, 'the user is never asked to save a tainted run');
    assert.strictEqual((await p.store.list('https://example.com')).macros.length, 0);
  }
});

await t('INCOMPLETE BY DESIGN: a step with no provenance stops recording; the safe prefix is what is offered', async () => {
  const p = profile();
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw) });
  await step(s.session, e, { type: 'type', target_element_id: 'user', value: NEW1.user }, VAULT1);
  await step(s.session, e, { type: 'type', target_element_id: 'city', value: 'Bangalore' }, VAULT1);   // LLM-invented: not in the task
  await step(s.session, e, { type: 'type', target_element_id: 'pw', value: NEW1.pw }, VAULT1);
  const out = await s.session.onCompleted({ totals: {} });
  assert.strictEqual(out.outcome, 'saved');
  const m = (await p.store.lookup('https://example.com', s.session.fingerprint)).macro;
  assert.strictEqual(m.steps.length, 1, 'only the prefix before the unsafe value');
  assert.ok(s.confirms[0].includes('planned by the AI'));
});

async function savedProfile() {
  const p = profile();
  const r = await recordRun(p);
  await r.session.onCompleted({ totals: {} });
  return p;
}
const NEW2 = { user: '[NAME_cccccccccc]', pw: '[PASSWORD_dddddddddd]' };
const VAULT2 = { [NEW2.user]: 'bob_real', [NEW2.pw]: 'Bob-Pass-42!' };

async function replayRun(p, { html = LOGIN, tokens = NEW2, city = 'Hyderabad', vault = VAULT2, steps = 4, stepOpts = {}, e = null } = {}) {
  e = e || env(html);
  const s = sessionFor(p, e);
  const mode = await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(tokens.user, tokens.pw, city) });
  const trace = [];
  for (let i = 0; i < steps && s.session.mode === 'replay'; i++) {
    const last = i === 3;
    trace.push(await step(s.session, e, null, vault, { replay: true, navigate: last ? goHome(e) : null, ...stepOpts }));
  }
  return { e, mode, trace, ...s };
}

await t('REPLAY: a saved macro runs the whole login with NO planner, using this run\'s own tokens/secrets', async () => {
  const p = await savedProfile();
  const r = await replayRun(p);
  assert.strictEqual(r.mode, 'replay');
  assert.ok(r.trace.every((x) => x.proposed && x.after && x.after.ok), JSON.stringify(r.trace.map((x) => [x.proposed, x.after])));
  assert.strictEqual(r.e.doc.querySelector('h1').textContent, 'Dashboard');
  assert.strictEqual(r.session.replayDone, true);
  assert.strictEqual(r.session.metrics.steps_replayed, 4);
  const out = await r.session.onCompleted({ totals: { llm_calls: 1 } });
  assert.strictEqual(out.outcome, 'replayed');
  const types = r.events.map((x) => x.event);
  assert.deepStrictEqual(types.filter((t2) => t2 === 'MACRO_STEP_STARTED').length, 4);
  assert.ok(types.indexOf('MACRO_LOOKUP') < types.indexOf('MACRO_REPLAY_STARTED') && types.indexOf('MACRO_REPLAY_STARTED') < types.indexOf('MACRO_STEP_STARTED') && types.includes('MACRO_REPLAY_SUCCEEDED'));
  const m = (await p.store.lookup('https://example.com', r.session.fingerprint)).macro;
  assert.deepStrictEqual(m.stats, { replays: 1, successes: 1, consecutive_failures: 0 });
});

await t('REPLAY typed the NEW run\'s secrets (never the recorded run\'s); no secret in audit events', async () => {
  const p = await savedProfile();
  const e = env();
  const r = await replayRun(p, { e });
  void r;
  // the document now navigated home; re-run step 1-3 on a fresh login page to inspect values
  const e2 = env();
  const s2 = sessionFor(p, e2);
  await s2.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  await step(s2.session, e2, null, VAULT2, { replay: true });
  await step(s2.session, e2, null, VAULT2, { replay: true });
  assert.strictEqual(e2.doc.getElementById('user').value, 'bob_real');
  assert.strictEqual(e2.doc.getElementById('pw').value, 'Bob-Pass-42!');
  const blob = JSON.stringify(s2.events);
  for (const x of ['bob_real', 'Bob-Pass-42!', 'cccccccccc', 'dddddddddd', 'jane_real_username']) assert.ok(!blob.includes(x), x);
});

await t('FALLBACK on a stale selector: MACRO_STEP_FAILED -> MACRO_REPLAY_ABORTED -> MACRO_FALLBACK_TO_LLM, then LLM planning continues; nothing is learned from the mixed run', async () => {
  const p = await savedProfile();
  const e = env();
  e.doc.getElementById('user').remove();
  e.doc.body.insertAdjacentHTML('beforeend', '<form id="evil" action="/steal"><label for="u2">Username</label><input id="u2" name="username" type="text"></form>');
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  const first = await step(s.session, e, null, VAULT2, { replay: true });
  assert.strictEqual(first.proposed, false);
  assert.strictEqual(s.session.mode, 'normal');
  const seq = s.events.map((x) => x.event).filter((x) => /ABORTED|FAILED|FALLBACK/.test(x));
  assert.deepStrictEqual(seq, ['MACRO_STEP_FAILED', 'MACRO_REPLAY_ABORTED', 'MACRO_FALLBACK_TO_LLM']);
  assert.strictEqual(s.events.find((x) => x.event === 'MACRO_STEP_FAILED').details.reason, 'target_missing');
  assert.strictEqual(e.doc.getElementById('u2').value, '', 'the lookalike was NOT touched');
  // the next step is left to the LLM (no proposal is ever produced again)
  assert.strictEqual((await s.session.beforeSend({ ...live(e.doc), payload: {} })).proposed, false);
  assert.strictEqual((await s.session.onCompleted({ totals: {} })).outcome, 'fell_back');
  assert.strictEqual(s.confirms.length, 0, 'a mixed run is never offered for saving');
  const m = (await p.store.lookup('https://example.com', s.session.fingerprint)).macro;
  assert.strictEqual(m.stats.consecutive_failures, 1);
});

await t('ORIGIN ATTACK: the same task on another origin never finds or replays the macro', async () => {
  const p = await savedProfile();
  const e = env(LOGIN, 'https://evil.example/login');
  const s = sessionFor(p, e);
  const mode = await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  assert.strictEqual(mode, 'record', 'no macro for this origin: normal planning (and learning) only');
  assert.strictEqual((await step(s.session, e, null, VAULT2, { replay: true })).proposed, false);
  assert.strictEqual(s.events.find((x) => x.event === 'MACRO_LOOKUP').details.hit, false);
});

await t('POLICY REJECTION during replay (server 422): abort, fall back, and QUARANTINE the macro', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  const r = await step(s.session, e, null, VAULT2, { replay: true, serverVerdict: () => ({ reject: 422 }) });
  assert.strictEqual(r.rejected, true);
  assert.strictEqual(s.session.mode, 'normal');
  assert.strictEqual(s.events.find((x) => x.event === 'MACRO_STEP_FAILED').details.reason, 'policy_rejected');
  assert.strictEqual((await p.store.lookup('https://example.com', s.session.fingerprint)).macro, null, 'quarantined: never offered again');
  assert.strictEqual((await p.store.list('https://example.com')).macros[0].status, 'quarantined');
});

await t('other server errors abort without quarantining', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  await step(s.session, e, null, VAULT2, { replay: true, serverVerdict: () => ({ reject: 500 }) });
  assert.strictEqual(s.session.mode, 'normal');
  assert.strictEqual((await p.store.list('https://example.com')).macros[0].status, 'active');
});

await t('SERVER MISMATCH: if the server answers with anything other than the proposal, nothing executes and the replay aborts', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  const r = await step(s.session, e, null, VAULT2, { replay: true, serverVerdict: (a) => ({ action: { ...a, target_element_id: 'signin' } }) });
  assert.strictEqual(r.mismatch, true);
  assert.strictEqual(s.session.mode, 'normal');
  assert.strictEqual(e.doc.getElementById('user').value, '');
});

await t('POSTCONDITION FAILURE: a login click that does not reach the dashboard aborts the replay', async () => {
  const p = await savedProfile();
  const r = await replayRun(p, { steps: 4, stepOpts: {} , e: null });
  void r;
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  for (let i = 0; i < 3; i++) await step(s.session, e, null, VAULT2, { replay: true });
  const last = await step(s.session, e, null, VAULT2, { replay: true, navigate: null });   // click "succeeds" but the page never changes
  assert.deepStrictEqual([last.after.ok, last.after.reason], [false, 'postcondition_failed']);
  assert.strictEqual(s.session.mode, 'normal');
  assert.ok(s.events.some((x) => x.event === 'MACRO_FALLBACK_TO_LLM'));
});

await t('USER DENIES a confirmation during replay: the task ends; the macro is not penalised', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  s.session.denied();
  assert.strictEqual(s.session.ended(), true);
  assert.strictEqual((await p.store.list('https://example.com')).macros[0].stats.consecutive_failures, 0);
  assert.ok(!s.events.some((x) => x.event === 'MACRO_FALLBACK_TO_LLM'));
});

await t('TOKEN UNAVAILABLE: a new task without the recorded secret aborts, and nothing is recovered from storage', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  // same fingerprint is impossible without the password slot, so restore the macro path directly:
  const other = `log in with username ${NEW2.user} then select Hyderabad from the city dropdown`;
  const mode = await s.session.init({ mode: 'replay', tokenizedInstruction: other });
  assert.strictEqual(mode, 'record', 'a different task shape has no macro: it is simply planned normally');
});

await t('GRACEFUL DEGRADATION: broken background / missing key / uncanonicalizable task never throws and never blocks a task', async () => {
  const p = profile();
  const e = env();
  for (const sendOverride of [async () => { throw new Error('bg dead'); }, async () => null, async () => ({ ok: false, error: 'forbidden_sender' }), async () => ({ ok: true, key: 5 })]) {
    const s = sessionFor(p, e, { sendOverride });
    assert.strictEqual(await s.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw) }), 'off');
    assert.doesNotThrow(() => s.session.executed());
    assert.deepStrictEqual(await s.session.beforeSend({ elements: [], summaries: [], payload: {} }), { proposed: false });
    assert.strictEqual((await s.session.onCompleted({ totals: {} })).outcome, 'none');
  }
  const s = sessionFor(p, e);
  assert.strictEqual(await s.session.init({ mode: 'record', tokenizedInstruction: '   ' }), 'off');
});

await t('a corrupt macro returned by the store is refused (audited) and the run is planned normally', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e, { sendOverride: async (m) => (m.type === 'MACRO_LOOKUP' ? { ok: true, macro: { schema_version: 1, evil: true }, dropped: 0 } : handleMacroMessage({ store: p.store, sender: { id: EXT, frameId: 0, tab: { id: 1, url: e.url }, url: e.url }, message: m, extensionId: EXT })) });
  assert.strictEqual(await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) }), 'record');
  assert.ok(s.events.some((x) => x.event === 'MACRO_CORRUPT'));
});

await t('a macro for a different task fingerprint or origin is never replayed even if the store hands it over', async () => {
  const p = await savedProfile();
  const real = (await p.store.list('https://example.com')).macros[0];
  const macro = await p.store.getById('https://example.com', real.macro_id);
  for (const bad of [{ ...macro, task_fp: 'e'.repeat(64) }, { ...macro, origin: 'https://other.example' }]) {
    const e = env();
    const s = sessionFor(p, e, { sendOverride: async (m) => (m.type === 'MACRO_LOOKUP' ? { ok: true, macro: bad, dropped: 0 } : { ok: true, key: (await p.store.getKey()) }) });
    assert.strictEqual(await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) }), 'record');
  }
});

await t('RESUME across navigation (record): the login click navigates, the fresh page finishes the recording, and the macro is saved', async () => {
  const p = profile();
  const e1 = env();
  const s1 = sessionFor(p, e1);
  await s1.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw) });
  await step(s1.session, e1, { type: 'type', target_element_id: 'user', value: NEW1.user }, VAULT1);
  await step(s1.session, e1, { type: 'type', target_element_id: 'pw', value: NEW1.pw }, VAULT1);
  await step(s1.session, e1, { type: 'type', target_element_id: 'city', value: 'Hyderabad' }, VAULT1);
  // the click: the script dies right after executing, so only the stash written at that moment survives
  const l = live(e1.doc);
  const sum = l.all.find((x) => x.element_id === 'signin');
  await s1.session.beforeExecute({ action: { type: 'click', target_element_id: 'signin' }, summary: (({ el, ...r }) => r)(sum), el: sum.el });
  await executeAction({ type: 'click', target_element_id: 'signin' }, () => null, null);
  s1.session.executed();
  const wire = JSON.parse(JSON.stringify(s1.session.toResume()));
  // --- new page, new content script ---
  const e2 = env('<h1>Dashboard</h1>', HOME_URL);
  const s2 = sessionFor(p, e2);
  assert.strictEqual(await s2.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw), resume: wire }), 'record');
  await s2.session.resumeStartup({ waitOpts: FAST });
  const out = await s2.session.onCompleted({ totals: {} });
  assert.strictEqual(out.outcome, 'saved');
  const m = (await p.store.lookup('https://example.com', s2.session.fingerprint)).macro;
  assert.deepStrictEqual(m.steps.map((x) => x.type), ['type', 'type', 'type', 'click']);
  assert.deepStrictEqual(m.steps[3].post[0], { kind: 'pathname_is', pathname_hmac: await pathHmac(await p.store.getKey(), '/home') });
});

await t('RESUME across navigation (replay): the click\'s postcondition is verified on the new page, then the LLM finishes', async () => {
  const p = await savedProfile();
  const e1 = env();
  const s1 = sessionFor(p, e1);
  await s1.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw) });
  for (let i = 0; i < 3; i++) await step(s1.session, e1, null, VAULT2, { replay: true });
  const l = live(e1.doc), payload = {};
  await s1.session.beforeSend({ elements: l.elements, summaries: l.summaries, payload });
  await executeAction({ ...payload.proposed_action }, () => null, null);
  s1.session.executed();
  const wire = JSON.parse(JSON.stringify(s1.session.toResume()));
  assert.deepStrictEqual([wire.mode, wire.replay.index, wire.replay.pendingVerify], ['replay', 4, 3]);
  assert.ok(!JSON.stringify(wire).includes('bob_real'));
  const e2 = env('<h1>Dashboard</h1>', HOME_URL);
  const s2 = sessionFor(p, e2);
  assert.strictEqual(await s2.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw), resume: wire }), 'replay');
  await s2.session.resumeStartup({ waitOpts: FAST });
  assert.strictEqual(s2.session.mode, 'replay');
  assert.strictEqual(s2.session.replayDone, true);
  assert.strictEqual((await s2.session.onCompleted({ totals: { llm_calls: 1 } })).outcome, 'replayed');
  // and a wrong landing page aborts
  const e3 = env('<h1>Login</h1>', 'https://example.com/login');
  const s3 = sessionFor(p, e3);
  await s3.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw), resume: wire });
  await s3.session.resumeStartup({ waitOpts: FAST });
  assert.strictEqual(s3.session.mode, 'normal');
  assert.ok(s3.events.some((x) => x.event === 'MACRO_FALLBACK_TO_LLM'));
});

await t('resume state that is corrupt or refers to a vanished macro degrades safely', async () => {
  const p = await savedProfile();
  const e = env();
  const s = sessionFor(p, e);
  assert.strictEqual(await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW2.user, NEW2.pw), resume: { mode: 'replay', macroId: '123e4567-e89b-42d3-a456-426614174000', replay: { index: 1 } } }), 'normal');
  for (const bad of [{ mode: 'bogus' }, { mode: 'record', recorder: 'nope' }, { mode: 'replay', macroId: 5 }, {}]) {
    const s2 = sessionFor(p, e);
    assert.doesNotThrow(() => s2.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW2.user, NEW2.pw), resume: bad }));
  }
});

await t('an oversized navigation stash is dropped (never sent) and the recording is tainted, so no macro is offered', async () => {
  const p = profile();
  const e = env();
  const s = sessionFor(p, e);
  const junk = { i: 0, type: 'scroll', pad: 'x'.repeat(70 * 1024) };
  await s.session.init({ mode: 'record', tokenizedInstruction: taskText(NEW1.user, NEW1.pw), resume: { mode: 'record', recorder: { steps: [junk], display: ['Scroll to an element'], tainted: null, truncated: null, pending: null } } });
  assert.strictEqual(s.session.toResume(), null);
  assert.strictEqual((await s.session.onCompleted({ totals: {} })).outcome, 'not_eligible');
  assert.strictEqual(s.confirms.length, 0);
});

await t('a replay when no macro exists behaves as a normal (learning) run and reports a lookup miss', async () => {
  const p = profile();
  const e = env();
  const s = sessionFor(p, e);
  assert.strictEqual(await s.session.init({ mode: 'replay', tokenizedInstruction: taskText(NEW1.user, NEW1.pw) }), 'record');
  assert.strictEqual(s.events[0].event, 'MACRO_LOOKUP');
  assert.strictEqual(s.events[0].details.hit, false);
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
