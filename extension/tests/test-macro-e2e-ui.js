// END-TO-END through the floating PANEL (not test mode): the real orchestrator
// bundle, the real panel UI, and the REAL native confirm() gate for risky
// actions (no fixture auto-approval). Proves that workflows are opt-in, that
// replay is never automatic, and that a replay is never "already approved".
import assert from 'assert';
import { makeEnv, newProfile, TASK, SECRET1, SECRET2, ORIGIN } from './helpers/macro-e2e-env.js';

console.log('=== RUNNING MACRO PANEL END-TO-END (real confirm gate) TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const RISKY = /^Perceive agent wants to execute/;
function answers({ approveRisky = () => true } = {}) {
  return (text) => (/^Save workflow\?/.test(text) ? true : RISKY.test(text) ? approveRisky(text) : true);
}

async function uiEnv(profile, opts = {}) {
  const e = await makeEnv(profile, { ui: true, confirmAnswer: answers(), ...opts });
  return e;
}

async function recordViaPanel(profile) {
  const e = await uiEnv(profile);
  e.enableWorkflows();
  e.submit(TASK(SECRET1.user, SECRET1.pw));
  await e.waitFor(e.finished, 40000, 'first (recording) run to finish');
  return e;
}

await t('workflows are OFF by default: a plain panel run works, reports LLM calls, and records/offers nothing', async () => {
  const profile = newProfile();
  const e = await uiEnv(profile);
  assert.strictEqual(e.panel.getState().macros, false);
  e.panel.toggle();
  e.submit(TASK(SECRET1.user, SECRET1.pw));
  await e.waitFor(e.finished, 40000, 'run');
  assert.match(e.status(), /^✓ Task complete/);
  assert.match(e.status(), /LLM calls: 5/);
  assert.ok(!/workflow/.test(e.status()));
  assert.ok(!e.confirms.some((c) => /^Save workflow/.test(c)), 'no save prompt when workflows are off');
  assert.strictEqual((await profile.store.list(ORIGIN)).macros.length, 0);
  assert.deepStrictEqual(e.errors, []);
});

await t('with workflows ON, a clean run asks before saving (native dialog, safe summary) and the panel reflects it', async () => {
  const profile = newProfile();
  const e = await recordViaPanel(profile);
  assert.match(e.status(), /^✓ Task complete.*workflow saved/);
  const save = e.confirms.filter((c) => /^Save workflow\?/.test(c));
  assert.strictEqual(save.length, 1);
  assert.ok(save[0].includes('Enter [PASSWORD]') && save[0].includes('Sensitive values are not stored.'));
  assert.ok(![SECRET1.user, SECRET1.pw].some((s) => save[0].includes(s)));
  await e.waitFor(() => /Saved workflows on this site: 1/.test(e.q('.macro-count').textContent), 3000, 'count refresh');
  assert.deepStrictEqual(e.errors, []);
});

await t('NEVER AUTOMATIC: a saved workflow is OFFERED; nothing runs (no server call) until the user chooses', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const e = await uiEnv(profile);
  e.enableWorkflows();
  e.submit(TASK(SECRET2.user, SECRET2.pw));
  await e.waitFor(() => e.q('.choice').classList.contains('show'), 10000, 'the choice prompt');
  assert.match(e.q('.wf-msg').textContent, /Saved workflow available for this task \(4 steps\)/);
  await new Promise((r) => setTimeout(r, 400));
  assert.strictEqual(e.serverCalls.length, 0, 'not a single request before the user picks');
  assert.strictEqual(e.doc.getElementById('user').value, '', 'nothing typed');
  e.q('.wf-cancel').click();
  await e.waitFor(() => /Cancelled/.test(e.status()), 5000, 'cancel');
  assert.strictEqual(e.serverCalls.length, 0);
});

await t('"Run workflow": replays with ONE LLM call, and RISKY steps still go through the real confirmation dialog', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const e = await uiEnv(profile);
  e.enableWorkflows();
  e.submit(TASK(SECRET2.user, SECRET2.pw));
  await e.waitFor(() => e.q('.choice').classList.contains('show'), 10000, 'choice');
  e.q('.wf-run').click();
  await e.waitFor(e.finished, 40000, 'replay to finish');
  assert.match(e.status(), /^✓ Task complete.*replayed a saved workflow · LLM calls: 1/);
  const risky = e.confirms.filter((c) => RISKY.test(c));
  // username + password fields (sensitive) and the submit click (client-side submit-button heuristic) all ask, exactly as in a planned run
  assert.strictEqual(risky.length, 3, JSON.stringify(risky.map((c) => c.split('\n')[2])));
  assert.ok(risky.every((c) => /AI-provided reason \(unverified/.test(c) && /macro replay step \d\/4/.test(c)), 'fixed replay text in the dialog, never page text');
  const fieldDialogs = risky.filter((c) => /type on target/.test(c));
  assert.strictEqual(fieldDialogs.length, 2);
  assert.ok(fieldDialogs.every((c) => /Flagged by Perceive policy: sensitive_target/.test(c)), 'the server verdict is shown for the sensitive fields');
  assert.ok(risky.some((c) => /click on target/.test(c)));
  assert.strictEqual(e.serverCalls.filter((c) => c.proposed).length, 4);
  assert.deepStrictEqual(e.errors, []);
});

await t('"already approved last time" does not exist: EVERY replay asks again', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const counts = [];
  for (let i = 0; i < 2; i++) {
    const e = await uiEnv(profile);
    e.enableWorkflows();
    e.submit(TASK(SECRET2.user, SECRET2.pw));
    await e.waitFor(() => e.q('.choice').classList.contains('show'), 10000, 'choice');
    e.q('.wf-run').click();
    await e.waitFor(e.finished, 40000, 'replay');
    counts.push(e.confirms.filter((c) => RISKY.test(c)).length);
  }
  assert.ok(counts[0] >= 1 && counts[1] === counts[0], JSON.stringify(counts));
});

await t('DENYING the risky confirmation during replay ends the task: nothing typed, no fallback, macro not penalised', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const e = await uiEnv(profile, { confirmAnswer: answers({ approveRisky: () => false }) });
  e.enableWorkflows();
  e.submit(TASK(SECRET2.user, SECRET2.pw));
  await e.waitFor(() => e.q('.choice').classList.contains('show'), 10000, 'choice');
  e.q('.wf-run').click();
  await e.waitFor(e.finished, 40000, 'task end');
  assert.match(e.status(), /Task failed: User denied risky action/);
  assert.ok(!e.typed.some(([, v]) => v === SECRET2.pw), 'the password was never typed');
  assert.ok(!e.events.some((x) => x.event === 'MACRO_FALLBACK_TO_LLM'), 'a refusal is not a replay failure');
  const m = (await profile.store.list(ORIGIN)).macros[0];
  assert.deepStrictEqual(m.stats, { replays: 0, successes: 0, consecutive_failures: 0 });
  assert.strictEqual(m.status, 'active');
});

await t('"Plan with AI" ignores the saved workflow (no proposals) and plans every step with the LLM', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const e = await uiEnv(profile);
  e.enableWorkflows();
  e.submit(TASK(SECRET2.user, SECRET2.pw));
  await e.waitFor(() => e.q('.choice').classList.contains('show'), 10000, 'choice');
  e.q('.wf-ai').click();
  await e.waitFor(e.finished, 40000, 'AI run');
  assert.match(e.status(), /LLM calls: 5/);
  assert.strictEqual(e.serverCalls.filter((c) => c.proposed).length, 0);
});

await t('a workflow recorded on a page is NOT offered when the toggle is OFF (opt-in gate)', async () => {
  const profile = newProfile();
  await recordViaPanel(profile);
  const e = await uiEnv(profile);
  e.panel.toggle();                                     // workflows stay OFF
  e.submit(TASK(SECRET2.user, SECRET2.pw));
  await e.waitFor(e.finished, 40000, 'run');
  assert.ok(!e.q('.choice').classList.contains('show'));
  assert.match(e.status(), /LLM calls: 5/);
  assert.strictEqual(e.events.filter((x) => x.event === 'MACRO_LOOKUP').length, 0, 'no lookup at all when the feature is off');
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
