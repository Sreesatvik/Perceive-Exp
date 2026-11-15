// Component-level measurements of the REAL macro code, in Node + jsdom
// (NOT Chrome; layout is absent, so DOM costs are lower than in a browser).
// Run: node tests/bench-macro.mjs
import { JSDOM } from 'jsdom';
import { performance } from 'perf_hooks';
import { createMacroStore } from '../src/background/macroStore.js';
import { canonicalizeTask, taskFingerprint } from '../src/macro/fingerprint.js';
import { describeElement, resolveDescriptor } from '../src/macro/descriptor.js';
import { pageSignature } from '../src/macro/postcondition.js';
import { classifyElement } from '../../dev2/dom-heuristics.js';
import { randomKeyHex } from '../src/macro/hmac.js';

const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
  return { n: s.length, median_ms: +q(0.5).toFixed(3), p95_ms: +q(0.95).toFixed(3), max_ms: +s[s.length - 1].toFixed(3) };
};
async function time(n, fn) { const xs = []; for (let i = 0; i < n; i++) { const t0 = performance.now(); await fn(i); xs.push(performance.now() - t0); } return stats(xs); }

const KEY = randomKeyHex();
const H = (c) => c.repeat(64);

// ---- a realistic-size page: 300 interactive elements in forms, plus headings
const rows = Array.from({ length: 100 }, (_, i) => `<form action="/f${i}"><label for="a${i}">Field ${i}</label><input id="a${i}" name="f${i}" type="text"><button type="submit">Save ${i}</button><a href="/x${i}">Link ${i}</a></form>`).join('');
const dom = new JSDOM(`<!DOCTYPE html><html><body><h1>Dashboard</h1><main>${rows}<form action="/login" id="login"><label for="pw">Password</label><input id="pw" name="password" type="password"><button id="go" type="submit">Sign in</button></form></main></body></html>`, { url: 'https://example.com/login' });
const doc = dom.window.document, win = dom.window;
const els = Array.from(doc.querySelectorAll('input, button, select, textarea, a[href]'));
const cands = els.map((el) => { const c = classifyElement(el); return { el, tag: c.tag, role: c.role, label_text: c.label_text, is_sensitive: !!c.is_sensitive && c.sensitivity_type != null && c.sensitivity_type !== 'UNKNOWN', sensitivity_type: c.sensitivity_type }; });
const target = cands.find((c) => c.el.id === 'go');
const desc = await describeElement(target.el, { keyHex: KEY, summary: target });

const results = {};
results[`describeElement (1 element)`] = await time(100, () => describeElement(target.el, { keyHex: KEY, summary: target }));
results[`resolveDescriptor over ${cands.length} live elements`] = await time(100, () => resolveDescriptor(desc, cands, { keyHex: KEY }));
results[`pageSignature (hashed page state, ${cands.length}+ elements)`] = await time(50, () => pageSignature(doc, win, KEY));
results['canonicalizeTask + fingerprint'] = await time(500, async () => {
  const t = canonicalizeTask("log in with username [NAME_aaaaaaaaaa] and password [PASSWORD_bbbbbbbbbb] then select Hyderabad from the city dropdown");
  return taskFingerprint(KEY, 'https://example.com', t.canonicalLower);
});

// ---- store lookup with 20 macros in the origin (the per-origin cap), in-memory storage adapter
const data = new Map();
const storage = { async get(k) { const o = {}; for (const key of (Array.isArray(k) ? k : [k])) if (data.has(key)) o[key] = JSON.parse(JSON.stringify(data.get(key))); return o; },
  async set(o) { for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); }, async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); } };
const store = createMacroStore({ storage });
const d = () => ({ tag: 'input', role: 'textbox', input_type: 'text', name_attr_hmac: H('e'), stable_id_hmac: null, name_hmac: H('a'), ctx: { form_hmac: H('b'), landmark_role: 'form', landmark_hmac: H('c') }, sensitivity: { is_sensitive: false, type: null } });
for (let i = 0; i < 20; i++) {
  await store.put('https://example.com', { origin: 'https://example.com', task_fp: i.toString(16).padStart(64, '0'), created_at: 0,
    steps: Array.from({ length: 10 }, (_, k) => ({ i: k, type: 'type', precondition: { pathname_hmac: H('f') }, target: d(), value_source: { kind: 'token_slot', type: 'NAME', ordinal: 1 }, post: [{ kind: 'field_filled' }] })) });
}
results['store.lookup (20 macros x 10 steps, validate + integrity HMAC each; in-memory storage)'] = await time(50, () => store.lookup('https://example.com', (7).toString(16).padStart(64, '0')));

console.log('MEASURED (real code, Node + jsdom; not Chrome)\n');
console.table(results);
process.exit(0);
