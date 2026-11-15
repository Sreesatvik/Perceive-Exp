// Target descriptors: how a macro re-finds an element WITHOUT storing ids,
// selectors, attribute values or any label text.
//
// Identity = a set of independent ANCHORS, ALL recorded as keyed hashes:
//   name_hmac       normalized accessible name (label_text)
//   name_attr_hmac  the form control's `name` attribute
//   stable_id_hmac  the element `id`, only if it looks non-generated and unique
//   form_hmac       the enclosing form's identity
//   landmark_hmac   the enclosing landmark/dialog identity
// Nothing page-derived is stored as plain text (an id or name can carry a
// person's name or a token). tag / role / input type are checked against fixed
// allow-lists; an element outside them cannot be recorded.
//
// Resolution is FAIL-CLOSED. A live element is the target only if it agrees
// with EVERY recorded anchor and sensitivity classification, and is the ONLY
// such element. Anchors are never "relaxed" to find a match: if the real
// element vanished and only a lookalike (same label, different form/landmark,
// or different sensitivity) remains, the result is target_missing — an
// attacker cannot get a weaker match accepted. The id anchor is a tie-breaker
// and is tolerated as changed only when the recorded id no longer exists.
// A descriptor needs >= 2 anchors, otherwise a step is not recordable.

import { hmacHex } from './hmac.js';
import { ARIA_ROLES, HTML_TAGS, INPUT_TYPES } from './schema.js';

export const MIN_ANCHORS = 2;
const MAX_NAME_CHARS = 200;
const MAX_ID_SCAN = 3000;

export const normalizeName = (text) =>
  String(text == null ? '' : text).normalize('NFKC').replace(/[​-‍⁠﻿­]/g, '').replace(/\s+/g, ' ').trim().toLowerCase().slice(0, MAX_NAME_CHARS);

const IDENT = /^[A-Za-z0-9_:.\-]{1,80}$/;

/** Heuristic: ids that frameworks generate per render are not identity. */
export function looksStableIdentifier(id) {
  if (typeof id !== 'string' || !IDENT.test(id)) return false;
  if (/^(?::r|r\d|ember|react|radix|headlessui|ext-el-|mui-|__)/i.test(id)) return false;   // framework / our own generated ids
  if (/\d{5,}/.test(id)) return false;                                                       // long digit runs (counters, timestamps)
  if (/[0-9a-f]{8,}/i.test(id) && /\d/.test(id)) return false;                               // hash-like
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(id)) return false;                                   // uuid
  return true;
}

const IMPLICIT_LANDMARK = { dialog: 'dialog', form: 'form', nav: 'navigation', main: 'main', header: 'banner', footer: 'contentinfo', aside: 'complementary' };
const LANDMARK_SELECTOR = 'dialog, [role="dialog"], [role="alertdialog"], form, [role="form"], nav, [role="navigation"], main, [role="main"], header, footer, aside, [role="region"][aria-label]';

// keyed-hash helpers (domain-separated so one kind of value can never collide with another)
const hName = (keyHex, s) => hmacHex(keyHex, `name|${s}`);
const hNameAttr = (keyHex, s) => hmacHex(keyHex, `nameattr|${s}`);
const hId = (keyHex, s) => hmacHex(keyHex, `id|${s}`);

function landmarkOf(el) {
  const lm = el.parentElement && el.parentElement.closest ? el.parentElement.closest(LANDMARK_SELECTOR) : null;
  if (!lm) return null;
  const raw = (lm.getAttribute('role') || IMPLICIT_LANDMARK[lm.tagName.toLowerCase()] || 'region').toLowerCase();
  const role = ARIA_ROLES.has(raw) ? raw : 'region';
  const label = normalizeName(lm.getAttribute('aria-label') || '');
  const id = looksStableIdentifier(lm.id) ? lm.id : '';
  return { role, ident: `${label}|${id}` };
}

function formOf(el) {
  const f = el.form || (el.closest ? el.closest('form') : null);
  if (!f || typeof f.getAttribute !== 'function') return null;
  const rawId = f.getAttribute('id') || '';           // attribute API: a child <input name="id"> cannot clobber it
  const rawName = f.getAttribute('name') || '';
  const id = looksStableIdentifier(rawId) ? rawId : '';
  const name = looksStableIdentifier(rawName) ? rawName : '';
  let action = '';
  try { action = new URL(f.getAttribute('action') || '', f.ownerDocument.location.href).pathname; } catch (_e) { action = ''; }
  return `${id}|${name}|${action.slice(0, 120)}`;
}

function inputTypeOf(el) {
  const tag = el.tagName.toLowerCase();
  if (tag !== 'input' && tag !== 'button') return null;
  const t = (el.getAttribute('type') || el.type || '').toLowerCase();
  return INPUT_TYPES.has(t) ? t : null;
}

const idOf = (el) => (el.getAttribute ? el.getAttribute('id') || '' : '');

const countAnchors = (d) => (d && typeof d === 'object' && d.ctx && typeof d.ctx === 'object'
  ? [d.name_hmac, d.name_attr_hmac, d.stable_id_hmac, d.ctx.form_hmac, d.ctx.landmark_hmac].filter((v) => v !== null && v !== undefined).length
  : 0);

/**
 * Builds a descriptor from a live element. Returns null when the element has
 * fewer than MIN_ANCHORS independent anchors, or a tag/role outside the fixed
 * allow-lists (cannot be re-found / persisted safely).
 *
 * @param {Element} el
 * @param {{ keyHex: string, summary: { tag: string, role: string, label_text: string|null, is_sensitive: boolean, sensitivity_type: string|null } }} ctx
 */
export async function describeElement(el, { keyHex, summary }) {
  if (!el || !el.tagName || !summary) return null;
  const tag = String(summary.tag || el.tagName).toLowerCase();
  const role = String(summary.role || 'generic').toLowerCase();
  if (!HTML_TAGS.has(tag) || !ARIA_ROLES.has(role)) return null;

  const name = normalizeName(summary.label_text);
  const nameAttrRaw = el.getAttribute('name') || '';
  const idRaw = idOf(el);
  const idUnique = idRaw && looksStableIdentifier(idRaw)
    && Array.from(el.ownerDocument.querySelectorAll('[id]')).filter((e) => idOf(e) === idRaw).length === 1;
  const lm = landmarkOf(el);
  const form = formOf(el);

  const d = {
    tag, role,
    input_type: inputTypeOf(el),
    name_attr_hmac: looksStableIdentifier(nameAttrRaw) ? await hNameAttr(keyHex, nameAttrRaw) : null,
    stable_id_hmac: idUnique ? await hId(keyHex, idRaw) : null,
    name_hmac: name ? await hName(keyHex, name) : null,
    ctx: {
      form_hmac: form ? await hmacHex(keyHex, `form|${form}`) : null,
      landmark_role: lm ? lm.role : null,
      landmark_hmac: lm && lm.ident !== '|' ? await hmacHex(keyHex, `landmark|${lm.role}|${lm.ident}`) : null,
    },
    sensitivity: { is_sensitive: !!summary.is_sensitive, type: summary.is_sensitive ? (summary.sensitivity_type || null) : null },
  };
  if (countAnchors(d) < MIN_ANCHORS) return null;
  return d;
}

/** Number of independent anchors (exported for tests). */
export { countAnchors };

/**
 * @typedef {{ el: Element, tag: string, role: string, label_text: string|null, is_sensitive: boolean, sensitivity_type: string|null }} Candidate
 * @returns {Promise<{ ok: true, el: Element, index: number } | { ok: false, reason: 'target_missing'|'target_ambiguous'|'identity_conflict'|'bad_descriptor' }>}
 */
export async function resolveDescriptor(desc, candidates, { keyHex }) {
  if (!desc || typeof desc !== 'object' || !desc.sensitivity || typeof desc.sensitivity !== 'object' || !Array.isArray(candidates)
      || typeof desc.tag !== 'string' || typeof desc.role !== 'string' || countAnchors(desc) < MIN_ANCHORS) return { ok: false, reason: 'bad_descriptor' };

  // 1) cheap synchronous narrowing on non-anchor identity
  const pool = [];
  candidates.forEach((c, index) => {
    if (!c || !c.el || String(c.tag).toLowerCase() !== desc.tag || String(c.role).toLowerCase() !== desc.role) return;
    if (!!c.is_sensitive !== desc.sensitivity.is_sensitive) return;
    if (desc.sensitivity.is_sensitive && desc.sensitivity.type !== null && c.sensitivity_type !== desc.sensitivity.type) return;
    if (desc.input_type !== null && inputTypeOf(c.el) !== desc.input_type) return;
    pool.push({ c, index });
  });

  // 2) EVERY recorded anchor must agree (no relaxing)
  const matches = [];
  for (const { c, index } of pool) {
    const el = c.el;
    if (desc.name_attr_hmac !== null) {
      const raw = el.getAttribute('name');
      if (!raw || (await hNameAttr(keyHex, raw)) !== desc.name_attr_hmac) continue;
    }
    if (desc.name_hmac !== null && (await hName(keyHex, normalizeName(c.label_text))) !== desc.name_hmac) continue;
    if (desc.ctx.form_hmac !== null) {
      const f = formOf(el);
      if (!f || (await hmacHex(keyHex, `form|${f}`)) !== desc.ctx.form_hmac) continue;
    }
    if (desc.ctx.landmark_role !== null || desc.ctx.landmark_hmac !== null) {
      const lm = landmarkOf(el);
      if (!lm || lm.role !== desc.ctx.landmark_role) continue;
      if (desc.ctx.landmark_hmac !== null && (await hmacHex(keyHex, `landmark|${lm.role}|${lm.ident}`)) !== desc.ctx.landmark_hmac) continue;
    }
    matches.push({ el, index });
  }

  if (matches.length === 0) return { ok: false, reason: 'target_missing' };

  // 3) uniqueness; the id is only a tie-breaker between otherwise identical matches
  let chosen = matches;
  if (matches.length > 1) {
    chosen = [];
    if (desc.stable_id_hmac !== null) {
      for (const m of matches) if (idOf(m.el) && (await hId(keyHex, idOf(m.el))) === desc.stable_id_hmac) chosen.push(m);
    }
    if (chosen.length !== 1) return { ok: false, reason: 'target_ambiguous' };
  }

  // 4) id rule: a changed id is tolerated only if the recorded id no longer exists
  //    on ANY element (a re-render), never if it now belongs to a different element (hijack).
  const [{ el, index }] = chosen;
  if (desc.stable_id_hmac !== null && !(idOf(el) && (await hId(keyHex, idOf(el))) === desc.stable_id_hmac)) {
    const withIds = Array.from(el.ownerDocument.querySelectorAll('[id]')).slice(0, MAX_ID_SCAN);
    for (const other of withIds) {
      if (other !== el && (await hId(keyHex, idOf(other))) === desc.stable_id_hmac) return { ok: false, reason: 'identity_conflict' };
    }
  }
  return { ok: true, el, index };
}
