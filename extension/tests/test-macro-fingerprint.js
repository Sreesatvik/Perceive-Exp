// Task fingerprint + canonicalization + value-provenance spans.
import assert from 'assert';
import { canonicalizeTask, taskFingerprint, findSpan, spanValue } from '../src/macro/fingerprint.js';
import { randomKeyHex } from '../src/macro/hmac.js';

console.log('=== RUNNING MACRO FINGERPRINT TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

const KEY = randomKeyHex();
const O = 'https://example.com';
const fpOf = async (task, origin = O, key = KEY) => taskFingerprint(key, origin, canonicalizeTask(task).canonicalLower);

await t('tokens are rewritten to per-type ordinals; no token suffix survives', async () => {
  const c = canonicalizeTask("Log in with username [NAME_ab12cd34ef] and password [PASSWORD_zz99yy88xx].");
  assert.strictEqual(c.canonical, 'Log in with username [NAME#1] and password [PASSWORD#1].');
  // Only canonical/canonicalLower/words can ever feed a stored value; none may hold a suffix.
  assert.ok(!/ab12cd34ef|zz99yy88xx/.test(JSON.stringify([c.canonical, c.canonicalLower, c.words])));
  assert.deepStrictEqual(c.slotByToken['[NAME_ab12cd34ef]'], { type: 'NAME', ordinal: 1 });
  assert.strictEqual(c.tokenBySlot['PASSWORD#1'], '[PASSWORD_zz99yy88xx]');
});

await t('different secrets (different token suffixes), same task => SAME fingerprint', async () => {
  const a = await fpOf('log in with username [NAME_aaaaaaaaaa] and password [PASSWORD_bbbbbbbbbb]');
  const b = await fpOf('log in with username [NAME_cccccccccc] and password [PASSWORD_dddddddddd]');
  assert.strictEqual(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

await t('repeated token = one ordinal; distinct tokens of a type get 1,2 in order of first appearance', async () => {
  const c = canonicalizeTask('copy [EMAIL_aaaaaaaaaa] into a and [EMAIL_bbbbbbbbbb] into b then [EMAIL_aaaaaaaaaa] again');
  assert.strictEqual(c.canonical, 'copy [EMAIL#1] into a and [EMAIL#2] into b then [EMAIL#1] again');
  assert.strictEqual(c.tokenBySlot['EMAIL#2'], '[EMAIL_bbbbbbbbbb]');
});

await t('normalization: case, whitespace, unicode width, zero-width chars, outer quotes/trailing punctuation', async () => {
  const base = await fpOf('select Hyderabad from the city dropdown');
  for (const v of ['Select   Hyderabad from the  city dropdown.', ' "SELECT hyderabad FROM the city dropdown" ', 'select\tHyderabad\nfrom the city dropdown!', 'sel​ect Hyderabad from the city dropdown',
    'Ｓelect Hyderabad from the city dropdown']) {
    assert.strictEqual(await fpOf(v), base, JSON.stringify(v));
  }
});

await t('different tasks, different literal text, different origins, different keys => different fingerprints', async () => {
  const base = await fpOf('search google for cats');
  assert.notStrictEqual(await fpOf('search google for dogs'), base);
  assert.notStrictEqual(await fpOf('search google for cats please'), base);
  assert.notStrictEqual(await fpOf('search google for cats', 'https://other.example'), base);
  assert.notStrictEqual(await fpOf('search google for cats', O, randomKeyHex()), base);
});

await t('a different token TYPE or extra token changes the fingerprint', async () => {
  const a = await fpOf('enter [NAME_aaaaaaaaaa] in the box');
  assert.notStrictEqual(await fpOf('enter [EMAIL_aaaaaaaaaa] in the box'), a);
  assert.notStrictEqual(await fpOf('enter [NAME_aaaaaaaaaa] and [NAME_bbbbbbbbbb] in the box'), a);
});

await t('canonical text never contains a vault token or raw secret', async () => {
  const c = canonicalizeTask("login with username 'x' and password [PASSWORD_zz99yy88xx]");
  assert.ok(!c.canonical.includes('zz99yy88xx'));
  assert.ok(!/\[[A-Z_]+_[a-z0-9]{6,}\]/.test(c.canonical));
});

await t('hostile / degenerate inputs never throw and never yield a fingerprint input', async () => {
  for (const bad of [null, undefined, 5, {}, [], '', '   ', '​​', '...']) assert.strictEqual(canonicalizeTask(bad), null, String(bad));
  const huge = 'a '.repeat(100000);
  assert.ok(canonicalizeTask(huge).canonical.length <= 4000);
  assert.ok(canonicalizeTask('[NAME_short] [NAME_aaaaaaaaaaaaaaaaaaaa]').canonical.includes('[NAME_short]'), 'non-token lookalikes are left as literal text');
});

await t('findSpan: verbatim, case-insensitive, edge punctuation ignored; returns word indices only', async () => {
  const c = canonicalizeTask('Search Google for cats.');
  assert.deepStrictEqual(findSpan(c.words, 'cats'), { w0: 3, w1: 4 });
  assert.deepStrictEqual(findSpan(c.words, 'CATS'), { w0: 3, w1: 4 });
  assert.deepStrictEqual(findSpan(c.words, 'Google for'), { w0: 1, w1: 3 });
  const q = canonicalizeTask("search for 'red shoes' now");
  assert.deepStrictEqual(findSpan(q.words, 'red shoes'), { w0: 2, w1: 4 });
});

await t('findSpan REFUSES values that are not verbatim in the task (LLM-invented values have no provenance)', async () => {
  const c = canonicalizeTask('Search Google for cats.');
  assert.strictEqual(findSpan(c.words, 'dogs'), null);
  assert.strictEqual(findSpan(c.words, 'cats and dogs'), null);
  assert.strictEqual(findSpan(c.words, ''), null);
  assert.strictEqual(findSpan(c.words, 'x'.repeat(500)), null);
  assert.strictEqual(findSpan(null, 'cats'), null);
  assert.strictEqual(findSpan(c.words, 5), null);
});

await t('findSpan never overlaps a token placeholder (secrets are never "literals")', async () => {
  const c = canonicalizeTask('log in with password [PASSWORD_zz99yy88xx] now');
  assert.strictEqual(findSpan(c.words, '[PASSWORD#1]'), null);
  assert.strictEqual(findSpan(c.words, 'password [PASSWORD#1] now'), null);
});

await t('spanValue re-derives the value from the NEW task (case preserved) and validates bounds', async () => {
  const older = canonicalizeTask('Select Hyderabad from the city dropdown.');
  const span = findSpan(older.words, 'hyderabad');
  const newer = canonicalizeTask('select HYDERABAD from the city dropdown');
  assert.strictEqual(await fpOf('Select Hyderabad from the city dropdown.'), await fpOf('select HYDERABAD from the city dropdown'));
  assert.strictEqual(spanValue(newer.words, span.w0, span.w1), 'HYDERABAD');
  assert.strictEqual(spanValue(newer.words, 99, 100), null);
  assert.strictEqual(spanValue(newer.words, 2, 2), null);
  assert.strictEqual(spanValue(newer.words, -1, 2), null);
  assert.strictEqual(spanValue(newer.words, 0.5, 2), null);
  const withTok = canonicalizeTask('type [NAME_aaaaaaaaaa] here');
  assert.strictEqual(spanValue(withTok.words, 1, 2), null, 'a span that now covers a placeholder is refused');
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
