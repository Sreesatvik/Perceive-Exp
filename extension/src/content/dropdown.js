// Dropdown handling for actionExecutor.js.
//  - selectNativeOption: <select> (used by the existing `type` action, so
//    the planner keeps emitting `type` for selects — backward compatible).
//  - selectCustomOption: ARIA listbox/combobox widgets (`select_custom`).
// Both take an already-RESOLVED plain string (token resolution happens in
// actionExecutor.js, exactly as for `type`) and return the executor's
// { success, error? } shape, verifying the result rather than assuming it.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function normalize(s) {
  return String(s == null ? '' : s)
    .normalize('NFKD').replace(/[̀-ͯ]/g, '') // strip diacritics
    .replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * Deterministic matching, strictest first: exact value, exact text,
 * normalized value/text, then a UNIQUE normalized substring match.
 * `items` = [{ text, value }]. Returns { item } | { error }.
 */
export function matchOption(items, wanted) {
  const w = String(wanted);
  const nw = normalize(w);
  if (!nw) return { error: 'option_not_found' };
  const tiers = [
    (i) => i.value === w,
    (i) => i.text === w || i.text.trim() === w.trim(),
    (i) => normalize(i.value) === nw || normalize(i.text) === nw,
  ];
  for (const test of tiers) {
    const hit = items.find(test);
    if (hit) return { item: hit };
  }
  const partial = items.filter((i) => normalize(i.text).includes(nw));
  if (partial.length === 1) return { item: partial[0] };
  return { error: partial.length > 1 ? 'ambiguous_option' : 'option_not_found' };
}

const viewOf = (el) => (el.ownerDocument && el.ownerDocument.defaultView) || window;

function fire(el, type, Ctor) {
  const V = viewOf(el);
  el.dispatchEvent(new (V[Ctor] || V.Event)(type, { bubbles: true, cancelable: true, view: V }));
}

// ---------------------------------------------------------------- native

export async function selectNativeOption(select, wanted) {
  const items = Array.from(select.options)
    .filter((o) => !o.disabled)
    .map((o) => ({ text: o.text, value: o.value, option: o }));
  const m = matchOption(items, wanted);
  if (m.error) return { success: false, error: m.error };

  const { option } = m.item;
  // selectedIndex/selected rather than `.value =`: unambiguous when two
  // options share a value, and it goes through the real DOM setter.
  if (select.multiple) option.selected = true;
  else select.selectedIndex = option.index;
  fire(select, 'input');
  fire(select, 'change');

  await sleep(0); // let a controlled component re-render (and possibly revert)
  // Re-read the LIVE options: a framework may have replaced the <option>
  // nodes, so the one we clicked can be detached by now.
  const stillSelected = Array.from(select.selectedOptions)
    .some((o) => o.value === option.value && o.text === option.text);
  return stillSelected
    ? { success: true, domChanged: true, selected: option.text.trim() }
    : { success: false, error: 'select_verification_failed' };
}

// ---------------------------------------------------------------- custom

function isShown(el) {
  if (!el || !el.isConnected) return false;
  const V = viewOf(el);
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    if (n.hidden || n.getAttribute('aria-hidden') === 'true') return false;
    const st = V.getComputedStyle(n);
    if (st.display === 'none' || st.visibility === 'hidden') return false;
  }
  return true;
}

const visibleListboxes = (doc) => Array.from(doc.querySelectorAll('[role="listbox"]')).filter(isShown);

function byIdRef(trigger, attr) {
  const doc = trigger.ownerDocument;
  return (trigger.getAttribute(attr) || '').split(/\s+/).filter(Boolean)
    .map((id) => doc.getElementById(id)).filter(Boolean);
}

const optionText = (o) => (o.getAttribute('aria-label') || o.textContent || '').trim();

/**
 * Finds THE listbox belonging to `trigger` — never just "any text on the
 * page": ARIA relationship first (aria-controls/aria-owns, and the trigger
 * itself when it is the listbox's container), then a listbox that appeared
 * because of our click, then one that lives inside the trigger's own
 * container. Two unrelated candidates => ambiguous, fail closed.
 */
function findListbox(trigger, before) {
  const doc = trigger.ownerDocument;
  for (const el of [...byIdRef(trigger, 'aria-controls'), ...byIdRef(trigger, 'aria-owns')]) {
    const lb = el.getAttribute('role') === 'listbox' ? el : el.querySelector('[role="listbox"]');
    if (lb && isShown(lb)) return { listbox: lb };
  }
  const inside = trigger.querySelector('[role="listbox"]');
  if (inside && isShown(inside)) return { listbox: inside };

  const now = visibleListboxes(doc);
  const fresh = now.filter((lb) => !before.has(lb));
  if (fresh.length === 1) return { listbox: fresh[0] };
  const pool = fresh.length > 1 ? fresh : now;
  const near = pool.filter((lb) => trigger.parentElement && trigger.parentElement.contains(lb));
  if (near.length === 1) return { listbox: near[0] };
  if (pool.length === 1) return { listbox: pool[0] };
  return pool.length ? { error: 'ambiguous_listbox' } : { listbox: null };
}

async function waitFor(fn, timeoutMs, stepMs = 50) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() >= end) return null;
    await sleep(stepMs);
  }
}

function selectionShown(trigger, option, text) {
  if (option.isConnected && option.getAttribute('aria-selected') === 'true') return true;
  const nt = normalize(text);
  const shown = normalize(trigger.value !== undefined && trigger.value !== '' ? trigger.value : trigger.textContent);
  return shown === nt || (shown.length > 0 && shown.includes(nt));
}

export async function selectCustomOption(trigger, wanted, { openTimeoutMs = 1500, verifyTimeoutMs = 700 } = {}) {
  const doc = trigger.ownerDocument;
  const before = new Set(visibleListboxes(doc));
  const alreadyOpen = trigger.getAttribute('aria-expanded') === 'true';
  if (!alreadyOpen) trigger.click();

  let lookupError = null;
  const listbox = await waitFor(() => {
    const r = findListbox(trigger, before);
    if (r.error) { lookupError = r.error; return null; }
    if (r.listbox && r.listbox.querySelector('[role="option"]')) return r.listbox;
    return null;
  }, openTimeoutMs);
  if (!listbox) return { success: false, error: lookupError || 'listbox_not_found' };

  const options = Array.from(listbox.querySelectorAll('[role="option"]'))
    .filter((o) => o.getAttribute('aria-disabled') !== 'true' && isShown(o));
  const m = matchOption(options.map((o) => ({ text: optionText(o), value: o.getAttribute('data-value') || o.getAttribute('value') || '', el: o })), wanted);
  if (m.error) return { success: false, error: m.error };

  const opt = m.item.el;
  if (opt.scrollIntoView) opt.scrollIntoView({ block: 'nearest' }); // option may sit below the list's fold
  fire(opt, 'mousedown', 'MouseEvent');
  fire(opt, 'mouseup', 'MouseEvent');
  opt.click();

  const ok = await waitFor(() => selectionShown(trigger, opt, m.item.text), verifyTimeoutMs);
  return ok
    ? { success: true, domChanged: true, selected: m.item.text }
    : { success: false, error: 'select_verification_failed' };
}
