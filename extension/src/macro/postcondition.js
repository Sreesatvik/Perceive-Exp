// Step postconditions: "did this step actually have its intended effect?"
// "The DOM click returned" is NOT evidence — executeAction reports success for
// any click that didn't throw. A postcondition is an observable page state
// derived, at recording time, from what really changed between the page
// before and after the step, and re-checked on the live DOM at replay.
//
// Everything persisted here is a hash, an enum or a generalized pathname.

import { hmacHex } from './hmac.js';
import { normalizeName } from './descriptor.js';
import { ARIA_ROLES, HTML_TAGS } from './schema.js';
import { isElementVisible } from '../content/visibility.js';

const MAX_ITEMS = 300;
const INTERESTING = 'a[href], button, input, select, textarea, [role="button"], [role="dialog"], [role="alertdialog"], [role="alert"], [role="status"], [role="tab"], h1, h2, h3, [role="heading"]';
const STRONG_ROLES = new Set(['heading', 'dialog', 'alertdialog', 'alert', 'status']);
const SEGMENT_OK = /^[A-Za-z0-9._~:%@+\-]+$/;

/** Generalizes ids out of a pathname: numeric/uuid/hex/long-digit segments become ":id". */
export function pathnameTemplate(pathname) {
  if (typeof pathname !== 'string') return '/';
  const segs = pathname.split('/').filter((s) => s !== '').slice(0, 12).map((seg) => {
    if (!SEGMENT_OK.test(seg)) return ':x';
    if (/^\d+$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(seg) || (/[0-9a-f]{8,}/i.test(seg) && /\d/.test(seg)) || /\d{5,}/.test(seg)) return ':id';
    return seg;
  });
  const out = '/' + segs.join('/');
  return out.slice(0, 200);
}

function roleOf(el) {
  const explicit = (el.getAttribute('role') || '').toLowerCase();
  if (explicit) return explicit;
  const tag = el.tagName.toLowerCase();
  if (/^h[1-6]$/.test(tag)) return 'heading';
  if (tag === 'a') return 'link';
  if (tag === 'button') return 'button';
  if (tag === 'select') return 'combobox';
  if (tag === 'dialog') return 'dialog';
  return tag === 'input' ? (el.type === 'checkbox' ? 'checkbox' : 'textbox') : 'generic';
}

function nameOf(el) {
  return normalizeName(el.getAttribute('aria-label') || (el.labels && el.labels[0] && el.labels[0].textContent) || el.innerText || el.textContent || el.getAttribute('placeholder') || '');
}

/**
 * Snapshot of the page as hashes: generalized pathname + the set of visible
 * "interesting" elements as { role, tag, name_hmac } keys.
 */
export async function pageSignature(doc, win, keyHex) {
  const items = new Map();
  const els = Array.from(doc.querySelectorAll(INTERESTING)).slice(0, MAX_ITEMS * 2);
  for (const el of els) {
    if (items.size >= MAX_ITEMS) break;
    if (!isElementVisible(el, win)) continue;
    const name = nameOf(el);
    if (!name) continue;
    const role = roleOf(el);
    const tag = el.tagName.toLowerCase();
    if (!ARIA_ROLES.has(role) || !HTML_TAGS.has(tag)) continue;
    const name_hmac = await hmacHex(keyHex, `name|${name}`);
    items.set(`${role}|${tag}|${name_hmac}`, { role, tag, name_hmac });
  }
  return { pathname: await pathHmac(keyHex, win.location.pathname), items };
}

/** Keyed hash of the generalized pathname (a path can carry tokens/usernames: never stored plain). */
export const pathHmac = (keyHex, pathname) => hmacHex(keyHex, `path|${pathnameTemplate(pathname)}`);

const expandedOf = (el) => {
  const v = el && el.getAttribute ? el.getAttribute('aria-expanded') : null;
  return v === 'true' ? true : v === 'false' ? false : null;
};

/** What we need to remember about the target around a step (no text, no values). */
export function targetState(el, win) {
  return { connected: !!(el && el.isConnected), visible: !!(el && el.isConnected && isElementVisible(el, win)), expanded: expandedOf(el) };
}

/**
 * Derives up to MAX strong postconditions for a recorded step from what
 * observably changed. Returns [] when nothing verifiable changed — the
 * recorder then refuses the whole macro (`unverifiable_step`).
 *
 * @param {{ type: string, targetTag: string, targetNameHmac: string|null, targetRole: string }} step
 * @param {{ pathname: string, items: Map }} before
 * @param {{ pathname: string, items: Map }} after
 * @param {{ connected: boolean, visible: boolean, expanded: boolean|null }} tBefore
 * @param {{ connected: boolean, visible: boolean, expanded: boolean|null }} tAfter
 */
export function derivePostconditions(step, before, after, tBefore, tAfter) {
  if (step.type === 'scroll' || step.type === 'wait') return [];
  if (step.type === 'type') return [{ kind: step.targetTag === 'select' ? 'select_shows' : 'field_filled' }];
  if (step.type === 'select_custom') return [{ kind: 'select_shows' }];
  if (step.type !== 'click') return [];

  const post = [];
  if (before.pathname !== after.pathname) post.push({ kind: 'pathname_is', pathname_hmac: after.pathname });
  if (tBefore.expanded !== null && tAfter.expanded !== null && tBefore.expanded !== tAfter.expanded) post.push({ kind: 'expanded_state', expanded: tAfter.expanded });
  if (tBefore.visible && !tAfter.visible && step.targetNameHmac) {
    post.push({ kind: 'element_gone', role: step.targetRole, tag: step.targetTag, name_hmac: step.targetNameHmac });
  }
  const appeared = [];
  for (const [k, v] of after.items) if (!before.items.has(k)) appeared.push(v);
  appeared.sort((a, b) => Number(STRONG_ROLES.has(b.role)) - Number(STRONG_ROLES.has(a.role)));
  for (const v of appeared) {
    if (post.length >= 3) break;
    if (STRONG_ROLES.has(v.role) || post.length === 0) post.push({ kind: 'element_appeared', role: v.role, tag: v.tag, name_hmac: v.name_hmac });
  }
  // Something disappearing from the page counts as evidence only when nothing else changed.
  if (post.length === 0) {
    for (const [k, v] of before.items) {
      if (!after.items.has(k) && STRONG_ROLES.has(v.role)) { post.push({ kind: 'element_gone', role: v.role, tag: v.tag, name_hmac: v.name_hmac }); break; }
    }
  }
  return post.slice(0, 3);
}

const normLoose = (s) => normalizeName(s);

function selectShows(el, expected) {
  if (!el || !el.isConnected || expected == null) return false;
  const want = normLoose(expected);
  if (!want) return false;
  if (el.tagName.toLowerCase() === 'select') {
    return Array.from(el.selectedOptions || []).some((o) => o.value === expected || normLoose(o.text) === want || normLoose(o.value) === want || normLoose(o.text).includes(want));
  }
  const shown = normLoose(el.value !== undefined && el.value !== '' ? el.value : el.textContent);
  return shown.length > 0 && shown.includes(want);
}

/**
 * Checks ONE set of postconditions right now.
 * @returns {Promise<string[]>} kinds that do NOT hold (empty = all hold)
 */
export async function checkPostconditions(list, { doc, win, keyHex, targetEl, expectedValue, expectedIsSensitive, before = null }) {
  const failed = [];
  let sig = null;
  for (const p of list) {
    let ok = false;
    switch (p.kind) {
      case 'field_filled':
        ok = !!(targetEl && targetEl.isConnected && String(targetEl.value ?? '') !== '');
        // A non-sensitive literal must also be what we typed (sensitive values: presence only — never compared/logged).
        if (ok && expectedValue != null && !expectedIsSensitive) ok = String(targetEl.value).trim() === String(expectedValue).trim() || normLoose(targetEl.value) === normLoose(expectedValue);
        break;
      case 'select_shows':
        ok = selectShows(targetEl, expectedValue);
        break;
      case 'pathname_is':
        ok = (await pathHmac(keyHex, win.location.pathname)) === p.pathname_hmac;
        break;
      case 'expanded_state':
        ok = !!targetEl && targetEl.isConnected && expandedOf(targetEl) === p.expanded;
        if (ok && before) ok = before.expanded !== p.expanded;          // must be a CHANGE caused by the step, not a pre-existing state
        break;
      case 'element_appeared':
      case 'element_gone': {
        sig = sig || await pageSignature(doc, win, keyHex);
        const present = sig.items.has(`${p.role}|${p.tag}|${p.name_hmac}`);
        ok = p.kind === 'element_appeared' ? present : !present;
        if (ok && before) ok = before.keys.has(`${p.role}|${p.tag}|${p.name_hmac}`) === (p.kind === 'element_gone');   // must be a transition, not pre-existing
        break;
      }
      default: ok = false;
    }
    if (!ok) failed.push(p.kind);
  }
  return failed;
}

/**
 * Polls until every postcondition holds or the timeout elapses (pages settle
 * asynchronously). Injectable sleep/now keep tests deterministic.
 * @returns {Promise<{ ok: boolean, failed: string[] }>}
 */
export async function waitForPostconditions(list, ctx, { timeoutMs = 3000, intervalMs = 100, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now() } = {}) {
  if (!Array.isArray(list) || list.length === 0) return { ok: false, failed: ['none_defined'] };   // never assume success
  const start = now();
  let failed = [];
  for (;;) {
    failed = await checkPostconditions(list, ctx);
    if (failed.length === 0) return { ok: true, failed: [] };
    if (now() - start >= timeoutMs) return { ok: false, failed };
    await sleep(intervalMs);
  }
}
