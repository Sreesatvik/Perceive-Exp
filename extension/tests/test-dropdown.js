// Dropdown handling: native <select> (via the existing `type` action) and
// ARIA custom dropdowns (`select_custom`), incl. token resolution.
import assert from 'assert';
import { JSDOM } from 'jsdom';

console.log('=== RUNNING DROPDOWN TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}

function page(html) {
  const dom = new JSDOM(`<!DOCTYPE html><body>${html}</body>`, { pretendToBeVisual: true });
  const w = dom.window;
  Object.assign(global, { window: w, document: w.document, Event: w.Event });
  global.CSS = { escape: (s) => s };
  // jsdom computes no layout; give every element a real-looking box so the
  // executor's interactability check passes.
  w.Element.prototype.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, width: 100, height: 20, right: 100, bottom: 20 });
  return w;
}

const { executeAction } = await import('../src/content/actionExecutor.js');
const { selectCustomOption, matchOption } = await import('../src/content/dropdown.js');

const CITIES = `<select id="city"><option value="">Choose</option><option value="hyd">Hyderabad</option>
  <option value="blr">Bangalore</option><option value="del" disabled>Delhi</option><option value="bom">Mumbai</option>
  <option value="bo2">Mumbai Central</option></select>`;
const type = (id, value) => ({ type: 'type', target_element_id: id, value, risk_tier: 'safe' });
const noTokens = () => null;

// ------------------------------------------------------------- native
await t('native: exact option text resolves to its value', async () => {
  const w = page(CITIES);
  const r = await executeAction(type('city', 'Hyderabad'), noTokens);
  assert.strictEqual(r.success, true);
  assert.strictEqual(w.document.getElementById('city').value, 'hyd');
});

await t('native: option value works directly', async () => {
  const w = page(CITIES);
  assert.strictEqual((await executeAction(type('city', 'blr'), noTokens)).success, true);
  assert.strictEqual(w.document.getElementById('city').value, 'blr');
});

await t('native: case/whitespace/diacritic normalization', async () => {
  const w = page(CITIES);
  assert.strictEqual((await executeAction(type('city', '  hyderaBAD \n'), noTokens)).success, true);
  assert.strictEqual(w.document.getElementById('city').value, 'hyd');
});

await t('native: exact match beats a fuzzy one ("Mumbai" vs "Mumbai Central")', async () => {
  const w = page(CITIES);
  await executeAction(type('city', 'Mumbai'), noTokens);
  assert.strictEqual(w.document.getElementById('city').value, 'bom');
});

await t('native: unique partial match is allowed, ambiguous is refused', async () => {
  const w = page(CITIES);
  assert.strictEqual((await executeAction(type('city', 'central'), noTokens)).success, true);
  assert.strictEqual(w.document.getElementById('city').value, 'bo2');
  const r = await executeAction(type('city', 'mum'), noTokens);
  assert.deepStrictEqual([r.success, r.error], [false, 'ambiguous_option']);
});

await t('native: nonexistent and disabled options fail structurally, selection unchanged', async () => {
  const w = page(CITIES);
  for (const v of ['Chennai', 'Delhi']) {
    const r = await executeAction(type('city', v), noTokens);
    assert.deepStrictEqual([r.success, r.error], [false, 'option_not_found']);
  }
  assert.strictEqual(w.document.getElementById('city').value, '');
});

await t('native: fires bubbling input then change, exactly once each', async () => {
  const w = page(CITIES);
  const seen = [];
  w.document.body.addEventListener('input', (e) => seen.push(`input:${e.target.value}`));
  w.document.body.addEventListener('change', (e) => seen.push(`change:${e.target.value}`));
  await executeAction(type('city', 'Hyderabad'), noTokens);
  assert.deepStrictEqual(seen, ['input:hyd', 'change:hyd']);
});

await t('native: a controlled select that reverts the change is reported as verification failure', async () => {
  const w = page(CITIES);
  const sel = w.document.getElementById('city');
  sel.addEventListener('change', () => { sel.selectedIndex = 0; }); // React-style controlled value snapping back
  const r = await executeAction(type('city', 'Hyderabad'), noTokens);
  assert.deepStrictEqual([r.success, r.error], [false, 'select_verification_failed']);
});

await t('native: a framework that re-renders (replaces) the <option> nodes still verifies correctly', async () => {
  const w = page(CITIES);
  const sel = w.document.getElementById('city');
  sel.addEventListener('change', () => { // React-style: rebuild options from state
    const chosen = sel.value;
    sel.innerHTML = ['hyd:Hyderabad', 'blr:Bangalore'].map((s) => { const [v, t] = s.split(':'); return `<option value="${v}"${v === chosen ? ' selected' : ''}>${t}</option>`; }).join('');
  });
  const r = await executeAction(type('city', 'Hyderabad'), noTokens);
  assert.strictEqual(r.success, true);
  assert.strictEqual(sel.value, 'hyd');
});

await t('native: select_custom aimed at a <select> still works (no dead end for the planner)', async () => {
  const w = page(CITIES);
  const r = await executeAction({ ...type('city', 'Bangalore'), type: 'select_custom' }, noTokens);
  assert.strictEqual(r.success, true);
  assert.strictEqual(w.document.getElementById('city').value, 'blr');
});

await t('type into a plain <input> is unchanged (no regression)', async () => {
  const w = page('<input id="name">');
  const events = [];
  w.document.getElementById('name').addEventListener('input', () => events.push('input'));
  assert.strictEqual((await executeAction(type('name', 'Ada'), noTokens)).success, true);
  assert.strictEqual(w.document.getElementById('name').value, 'Ada');
  assert.deepStrictEqual(events, ['input']);
});

// ------------------------------------------------------------- custom
// A minimal ARIA select: button trigger + listbox toggled on click; picking
// an option marks aria-selected and mirrors its text onto the trigger.
function widget(w, { id, options, portal = false, broken = false, sink = null }) {
  const doc = w.document;
  const wrap = doc.createElement('div');
  wrap.innerHTML = `<button id="${id}" aria-haspopup="listbox" aria-expanded="false" ${portal ? '' : `aria-controls="${id}-lb"`}>Pick</button>`;
  const trigger = wrap.firstChild;
  const lb = doc.createElement('div');
  lb.setAttribute('role', 'listbox');
  lb.id = `${id}-lb`;
  lb.style.display = 'none';
  for (const text of options) {
    const o = doc.createElement('div');
    o.setAttribute('role', 'option');
    o.textContent = text;
    o.addEventListener('click', () => {
      if (sink) sink.push(`${id}:${text}`);
      if (broken) return;
      lb.querySelectorAll('[role=option]').forEach((x) => x.setAttribute('aria-selected', String(x === o)));
      trigger.textContent = text;
      trigger.setAttribute('aria-expanded', 'false');
      lb.style.display = 'none';
    });
    lb.appendChild(o);
  }
  trigger.addEventListener('click', () => {
    trigger.setAttribute('aria-expanded', 'true');
    lb.style.display = 'block';
    if (portal && !lb.isConnected) doc.body.appendChild(lb); // portalled listbox, no aria-controls
  });
  if (!portal) wrap.appendChild(lb);
  doc.body.appendChild(wrap);
  return { trigger, lb };
}

const custom = (id, value) => ({ type: 'select_custom', target_element_id: id, value, risk_tier: 'safe' });

await t('custom: opens the dropdown, clicks the matching option, verifies', async () => {
  const w = page('');
  const { trigger } = widget(w, { id: 'd1', options: ['Red', 'Green', 'Blue'] });
  const r = await executeAction(custom('d1', 'green'), noTokens);
  assert.deepStrictEqual([r.success, r.selected], [true, 'Green']);
  assert.strictEqual(trigger.textContent, 'Green');
});

await t('custom: option below the fold is scrolled into view before the click', async () => {
  const w = page('');
  const { lb } = widget(w, { id: 'd1', options: Array.from({ length: 60 }, (_, i) => `Item ${i}`) });
  const scrolled = [];
  w.Element.prototype.scrollIntoView = function () { scrolled.push(this.textContent); };
  const r = await executeAction(custom('d1', 'Item 58'), noTokens);
  assert.strictEqual(r.success, true);
  assert.deepStrictEqual(scrolled, ['Item 58']);
  assert.strictEqual(lb.querySelector('[aria-selected=true]').textContent, 'Item 58');
});

await t('custom: nonexistent option fails structurally and clicks nothing', async () => {
  const w = page('');
  const sink = [];
  widget(w, { id: 'd1', options: ['Red', 'Green'], sink });
  const r = await executeAction(custom('d1', 'Purple'), noTokens);
  assert.deepStrictEqual([r.success, r.error], [false, 'option_not_found']);
  assert.deepStrictEqual(sink, []);
});

await t('custom: click that does not change the selection => select_verification_failed', async () => {
  const w = page('');
  widget(w, { id: 'd1', options: ['Red'], broken: true });
  const r = await selectCustomOption(w.document.getElementById('d1'), 'Red', { verifyTimeoutMs: 100 });
  assert.deepStrictEqual([r.success, r.error], [false, 'select_verification_failed']);
});

await t('custom: no listbox ever appears => listbox_not_found', async () => {
  const w = page('<button id="d1" aria-haspopup="listbox">Pick</button>');
  const r = await selectCustomOption(w.document.getElementById('d1'), 'Red', { openTimeoutMs: 100 });
  assert.deepStrictEqual([r.success, r.error], [false, 'listbox_not_found']);
});

await t('custom: two dropdowns with the same option text — only the targeted one is touched', async () => {
  const w = page('');
  const sink = [];
  const a = widget(w, { id: 'a', options: ['Red', 'Blue'], sink });
  const b = widget(w, { id: 'b', options: ['Red', 'Blue'], sink });
  a.lb.style.display = 'block'; // A is left open, with its own "Red" visible
  const r = await executeAction(custom('b', 'Red'), noTokens);
  assert.strictEqual(r.success, true);
  assert.deepStrictEqual(sink, ['b:Red']);
  assert.strictEqual(b.trigger.textContent, 'Red');
  assert.strictEqual(a.trigger.textContent, 'Pick');
});

await t('custom: portalled listbox without aria-controls is found via "appeared after click"', async () => {
  const w = page('');
  const sink = [];
  widget(w, { id: 'other', options: ['Red'], sink }).lb.style.display = 'block';
  const p = widget(w, { id: 'p', options: ['Red', 'Blue'], portal: true, sink });
  const r = await executeAction(custom('p', 'Blue'), noTokens);
  assert.strictEqual(r.success, true);
  assert.deepStrictEqual(sink, ['p:Blue']);
  assert.strictEqual(p.trigger.textContent, 'Blue');
});

await t('custom: an option elsewhere on the page with the same text is never clicked', async () => {
  const w = page('<button id="decoy" onclick="void 0">Green</button><div role="option" id="stray">Green</div>');
  let strayClicked = false;
  w.document.getElementById('stray').addEventListener('click', () => { strayClicked = true; });
  widget(w, { id: 'd1', options: ['Red'] });
  const r = await selectCustomOption(w.document.getElementById('d1'), 'Green', { openTimeoutMs: 200 });
  assert.strictEqual(r.success, false);
  assert.strictEqual(strayClicked, false);
});

await t('custom: aria-disabled options are not selectable', async () => {
  const w = page('');
  const { lb } = widget(w, { id: 'd1', options: ['Red', 'Blue'] });
  lb.firstChild.setAttribute('aria-disabled', 'true');
  const r = await executeAction(custom('d1', 'Red'), noTokens);
  assert.deepStrictEqual([r.success, r.error], [false, 'option_not_found']);
});

// ------------------------------------------------------------- security
await t('token: bracketed value resolves through the vault for native select', async () => {
  const w = page(CITIES);
  const seen = [];
  const r = await executeAction(type('city', '[NAME_abc123]'), (tok) => { seen.push(tok); return 'Bangalore'; });
  assert.strictEqual(r.success, true);
  assert.deepStrictEqual(seen, ['[NAME_abc123]']);
  assert.strictEqual(w.document.getElementById('city').value, 'blr');
});

await t('token: bracketed value resolves for select_custom too', async () => {
  const w = page('');
  const { trigger } = widget(w, { id: 'd1', options: ['Red', 'Blue'] });
  const r = await executeAction(custom('d1', '[NAME_abc123]'), () => 'Blue');
  assert.strictEqual(r.success, true);
  assert.strictEqual(trigger.textContent, 'Blue');
});

await t('token: unresolvable token fails closed and never acts (both paths)', async () => {
  const w = page(CITIES);
  const sink = [];
  widget(w, { id: 'd1', options: ['Red', '[PASSWORD_x1]'], sink });
  for (const a of [type('city', '[PASSWORD_x1]'), custom('d1', '[PASSWORD_x1]')]) {
    const r = await executeAction(a, () => null);
    assert.deepStrictEqual([r.success, r.error], [false, 'unresolvable_token']);
  }
  assert.strictEqual(w.document.getElementById('city').value, '');
  assert.deepStrictEqual(sink, [], 'the literal token text must never be matched/clicked');
});

await t('token: resolved secret is not leaked into the result or logs', async () => {
  const w = page(CITIES);
  const logged = [];
  const orig = console.log; const origW = console.warn;
  console.log = (...a) => logged.push(a.join(' ')); console.warn = (...a) => logged.push(a.join(' '));
  let r;
  try { r = await executeAction(type('city', '[NAME_abc123]'), () => 'Bangalore'); } finally { console.log = orig; console.warn = origW; }
  assert.ok(!logged.some((l) => l.includes('Bangalore')), 'resolved value must not be logged');
  assert.ok(!('value' in r));
});

await t('matchOption is deterministic: exact value > exact text > normalized > unique partial', async () => {
  const items = [{ text: 'A B', value: 'x' }, { text: 'x', value: 'y' }];
  assert.strictEqual(matchOption(items, 'x').item.value, 'x');
  assert.strictEqual(matchOption(items, 'a  b').item.value, 'x');
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
