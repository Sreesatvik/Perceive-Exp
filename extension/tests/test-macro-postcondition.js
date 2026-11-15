// Postconditions: derivation from before/after observations, live checking,
// and deterministic polling. "The click returned" is never evidence.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { pathnameTemplate, pathHmac, pageSignature, targetState, derivePostconditions, checkPostconditions, waitForPostconditions } from '../src/macro/postcondition.js';
import { randomKeyHex, hmacHex } from '../src/macro/hmac.js';

console.log('=== RUNNING MACRO POSTCONDITION TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const KEY = randomKeyHex();
const mk = (html, url = 'https://example.com/login') => { const w = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url, pretendToBeVisual: true }).window; return { doc: w.document, win: w }; };
const sig = ({ doc, win }) => pageSignature(doc, win, KEY);
const H = (s) => hmacHex(KEY, `name|${s}`);

await t('pathnameTemplate generalizes ids, keeps words, bounds length, refuses odd characters', async () => {
  assert.strictEqual(pathnameTemplate('/accounts/login'), '/accounts/login');
  assert.strictEqual(pathnameTemplate('/users/12345/orders/987'), '/users/:id/orders/:id');
  assert.strictEqual(pathnameTemplate('/item/123e4567-e89b-42d3-a456-426614174000'), '/item/:id');
  assert.strictEqual(pathnameTemplate('/p/a1b2c3d4e5f6'), '/p/:id');
  assert.strictEqual(pathnameTemplate('/'), '/');
  assert.strictEqual(pathnameTemplate('/a b/<script>'), '/:x/:x');
  assert.ok(pathnameTemplate('/' + 'a/'.repeat(200)).length <= 200);
  assert.strictEqual(pathnameTemplate(null), '/');
});

await t('pageSignature: hashed names only, hidden elements excluded, no raw text', async () => {
  const p = mk('<h1>Welcome Jane Doe</h1><button>Pay</button><button style="display:none">Secret hidden</button><button style="opacity:0">Faded</button><a href="/x">Go</a>');
  const s = await sig(p);
  assert.strictEqual(s.pathname, await pathHmac(KEY, '/login'));
  assert.ok(!JSON.stringify(s.pathname).includes('login'));
  assert.ok(s.items.has(`heading|h1|${await H('welcome jane doe')}`));
  assert.ok(s.items.has(`button|button|${await H('pay')}`));
  assert.ok(!s.items.has(`button|button|${await H('secret hidden')}`));
  assert.ok(!s.items.has(`button|button|${await H('faded')}`));
  const blob = JSON.stringify([...s.items.values()]);
  assert.ok(!/Jane|Doe|Secret|Pay/i.test(blob), 'signature must contain only hashes');
});

const step = (o) => ({ type: 'click', targetTag: 'button', targetRole: 'button', targetNameHmac: 'a'.repeat(64), ...o });
const T = (o = {}) => ({ connected: true, visible: true, expanded: null, ...o });

await t('derive: typing => field_filled; native select typed => select_shows; select_custom => select_shows; scroll/wait => none', async () => {
  const e = { pathname: 'a'.repeat(64), items: new Map() };
  assert.deepStrictEqual(derivePostconditions(step({ type: 'type', targetTag: 'input' }), e, e, T(), T()), [{ kind: 'field_filled' }]);
  assert.deepStrictEqual(derivePostconditions(step({ type: 'type', targetTag: 'select' }), e, e, T(), T()), [{ kind: 'select_shows' }]);
  assert.deepStrictEqual(derivePostconditions(step({ type: 'select_custom' }), e, e, T(), T()), [{ kind: 'select_shows' }]);
  assert.deepStrictEqual(derivePostconditions(step({ type: 'scroll' }), e, e, T(), T()), []);
  assert.deepStrictEqual(derivePostconditions(step({ type: 'wait' }), e, e, T(), T()), []);
  assert.deepStrictEqual(derivePostconditions(step({ type: 'delete_everything' }), e, e, T(), T()), []);
});

await t('derive: a click that navigated => pathname_is (generalized), regardless of other noise', async () => {
  const before = { pathname: 'a'.repeat(64), items: new Map() };
  const after = { pathname: 'b'.repeat(64), items: new Map([['heading|h1|x', { role: 'heading', tag: 'h1', name_hmac: 'b'.repeat(64) }]]) };
  const p = derivePostconditions(step(), before, after, T(), T());
  assert.deepStrictEqual(p[0], { kind: 'pathname_is', pathname_hmac: 'b'.repeat(64) });
});

await t('derive: dropdown opened => expanded_state; modal closed (target gone) => element_gone', async () => {
  const e = { pathname: 'a'.repeat(64), items: new Map() };
  assert.deepStrictEqual(derivePostconditions(step(), e, e, T({ expanded: false }), T({ expanded: true })), [{ kind: 'expanded_state', expanded: true }]);
  const gone = derivePostconditions(step(), e, e, T({ visible: true }), T({ visible: false, connected: false }));
  assert.deepStrictEqual(gone, [{ kind: 'element_gone', role: 'button', tag: 'button', name_hmac: 'a'.repeat(64) }]);
});

await t('derive: new heading/dialog/alert appearing is preferred evidence; weak new controls only if nothing else', async () => {
  const before = { pathname: 'a'.repeat(64), items: new Map() };
  const items = new Map([
    ['button|button|w', { role: 'button', tag: 'button', name_hmac: 'c'.repeat(64) }],
    ['heading|h2|s', { role: 'heading', tag: 'h2', name_hmac: 'd'.repeat(64) }],
    ['dialog|div|t', { role: 'dialog', tag: 'div', name_hmac: 'e'.repeat(64) }],
  ]);
  const p = derivePostconditions(step(), before, { pathname: 'a'.repeat(64), items }, T(), T());
  assert.deepStrictEqual(p.map((x) => x.role).sort(), ['dialog', 'heading']);
  assert.ok(p.length <= 3);
  const weakOnly = derivePostconditions(step(), before, { pathname: 'a'.repeat(64), items: new Map([['button|button|w', { role: 'button', tag: 'button', name_hmac: 'c'.repeat(64) }]]) }, T(), T());
  assert.strictEqual(weakOnly.length, 1);
});

await t('derive: NO observable change => NO postcondition ("the click returned" is not evidence)', async () => {
  const e = { pathname: 'a'.repeat(64), items: new Map([['button|button|x', { role: 'button', tag: 'button', name_hmac: 'c'.repeat(64) }]]) };
  assert.deepStrictEqual(derivePostconditions(step(), e, e, T(), T()), []);
});

await t('check field_filled: sensitive => presence only (never compared); literal must equal what was typed', async () => {
  const p = mk('<input id="a"><input id="b">');
  const a = p.doc.getElementById('a'), b = p.doc.getElementById('b');
  const ctx = (el, extra) => ({ doc: p.doc, win: p.win, keyHex: KEY, targetEl: el, ...extra });
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }], ctx(a, {})), ['field_filled']);
  a.value = 's3cret-Value!';
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }], ctx(a, { expectedValue: 'anything', expectedIsSensitive: true })), []);
  b.value = 'cats';
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }], ctx(b, { expectedValue: 'cats', expectedIsSensitive: false })), []);
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }], ctx(b, { expectedValue: 'dogs', expectedIsSensitive: false })), ['field_filled']);
  b.remove();
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }], ctx(b, {})), ['field_filled'], 'detached element never counts');
});

await t('check select_shows: native select (text/value/normalized) and custom trigger text', async () => {
  const p = mk('<select id="s"><option value="hyd">Hyderabad</option><option value="blr">Bangalore</option></select><button id="dd">Pick</button>');
  const s = p.doc.getElementById('s'), dd = p.doc.getElementById('dd');
  const c = (el, v) => checkPostconditions([{ kind: 'select_shows' }], { doc: p.doc, win: p.win, keyHex: KEY, targetEl: el, expectedValue: v });
  s.value = 'blr';
  assert.deepStrictEqual(await c(s, 'Bangalore'), []);
  assert.deepStrictEqual(await c(s, 'blr'), []);
  assert.deepStrictEqual(await c(s, ' bangalore '), []);
  assert.deepStrictEqual(await c(s, 'Hyderabad'), ['select_shows']);
  assert.deepStrictEqual(await c(s, null), ['select_shows']);
  assert.deepStrictEqual(await c(dd, 'Green'), ['select_shows']);
  dd.textContent = 'Green';
  assert.deepStrictEqual(await c(dd, 'green'), []);
});

await t('check pathname_is / expanded_state', async () => {
  const p = mk('<button id="b" aria-expanded="false">x</button>', 'https://example.com/users/4242/home');
  const b = p.doc.getElementById('b');
  const c = (post) => checkPostconditions(post, { doc: p.doc, win: p.win, keyHex: KEY, targetEl: b });
  assert.deepStrictEqual(await c([{ kind: 'pathname_is', pathname_hmac: await pathHmac(KEY, '/users/4242/home') }]), []);
  assert.deepStrictEqual(await c([{ kind: 'pathname_is', pathname_hmac: await pathHmac(KEY, '/users/:id/login') }]), ['pathname_is']);
  assert.deepStrictEqual(await c([{ kind: 'expanded_state', expanded: true }]), ['expanded_state']);
  b.setAttribute('aria-expanded', 'true');
  assert.deepStrictEqual(await c([{ kind: 'expanded_state', expanded: true }]), []);
});

await t('check element_appeared / element_gone against the live DOM', async () => {
  const p = mk('<h1>Login</h1><div id="modal" role="dialog" aria-label="Terms">t</div>');
  const dash = { kind: 'element_appeared', role: 'heading', tag: 'h1', name_hmac: await H('dashboard') };
  const modalGone = { kind: 'element_gone', role: 'dialog', tag: 'div', name_hmac: await H('terms') };
  const c = (post) => checkPostconditions(post, { doc: p.doc, win: p.win, keyHex: KEY, targetEl: null });
  assert.deepStrictEqual(await c([dash, modalGone]), ['element_appeared', 'element_gone']);
  p.doc.querySelector('h1').textContent = 'Dashboard';
  p.doc.getElementById('modal').remove();
  assert.deepStrictEqual(await c([dash, modalGone]), []);
});

await t('CAUSAL: an element that was ALREADY present/expanded before the step is not evidence the step worked', async () => {
  const p = mk('<h1>Dashboard</h1><div id="modal" role="dialog" aria-label="Terms">t</div><button id="b" aria-expanded="true">x</button>');
  const b = p.doc.getElementById('b');
  const before = { keys: new Set([...(await sig(p)).items.keys()]), expanded: true };
  const appeared = { kind: 'element_appeared', role: 'heading', tag: 'h1', name_hmac: await H('dashboard') };
  const gone = { kind: 'element_gone', role: 'dialog', tag: 'div', name_hmac: await H('nothing here') };
  const exp = { kind: 'expanded_state', expanded: true };
  const c = (post, bf) => checkPostconditions(post, { doc: p.doc, win: p.win, keyHex: KEY, targetEl: b, before: bf });
  assert.deepStrictEqual(await c([appeared, exp], null), [], 'without a before-state the plain state check holds');
  assert.deepStrictEqual(await c([appeared, exp], before), ['element_appeared', 'expanded_state'], 'no-op click: pre-existing state must NOT count');
  const beforeGone = { keys: new Set(), expanded: false };
  assert.deepStrictEqual(await c([gone], beforeGone), ['element_gone'], 'absent before AND after is not a disappearance');
  // a real transition passes
  const empty = { keys: new Set(), expanded: false };
  assert.deepStrictEqual(await c([appeared, exp], empty), []);
});

await t('ALL postconditions must hold (conjunction); an unknown kind never holds', async () => {
  const p = mk('<input id="a" value="x">');
  const ctx = { doc: p.doc, win: p.win, keyHex: KEY, targetEl: p.doc.getElementById('a') };
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'field_filled' }, { kind: 'pathname_is', pathname_hmac: 'e'.repeat(64) }], ctx), ['pathname_is']);
  assert.deepStrictEqual(await checkPostconditions([{ kind: 'totally_made_up' }], ctx), ['totally_made_up']);
});

await t('waitForPostconditions: succeeds once the page settles (deterministic clock), fails at the timeout, never assumes success', async () => {
  const p = mk('<input id="a">');
  const el = p.doc.getElementById('a');
  const clock = { t: 0 };
  const sleep = async (ms) => { clock.t += ms; if (clock.t >= 300) el.value = 'filled'; };
  const opts = { sleep, now: () => clock.t, timeoutMs: 3000, intervalMs: 100 };
  const ok = await waitForPostconditions([{ kind: 'field_filled' }], { doc: p.doc, win: p.win, keyHex: KEY, targetEl: el }, opts);
  assert.deepStrictEqual(ok, { ok: true, failed: [] });
  assert.ok(clock.t <= 400, 'returned promptly once true');

  const never = mk('<input id="a">');
  const c2 = { t: 0 };
  const res = await waitForPostconditions([{ kind: 'field_filled' }], { doc: never.doc, win: never.win, keyHex: KEY, targetEl: never.doc.getElementById('a') }, { sleep: async (ms) => { c2.t += ms; }, now: () => c2.t, timeoutMs: 1000, intervalMs: 100 });
  assert.deepStrictEqual(res, { ok: false, failed: ['field_filled'] });
  assert.ok(c2.t >= 1000 && c2.t < 1200);

  assert.deepStrictEqual(await waitForPostconditions([], {}), { ok: false, failed: ['none_defined'] });
  assert.deepStrictEqual(await waitForPostconditions(null, {}), { ok: false, failed: ['none_defined'] });
});

await t('targetState reads visibility/expanded/connectedness without touching text', async () => {
  const p = mk('<button id="b" aria-expanded="true">x</button><button id="h" style="display:none">y</button>');
  assert.deepStrictEqual(targetState(p.doc.getElementById('b'), p.win), { connected: true, visible: true, expanded: true });
  assert.deepStrictEqual(targetState(p.doc.getElementById('h'), p.win), { connected: true, visible: false, expanded: null });
  assert.deepStrictEqual(targetState(null, p.win), { connected: false, visible: false, expanded: null });
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
