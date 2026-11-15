// Deterministic task identity for macros — no similarity/semantic matching.
//
// Input is the TOKENIZED task instruction (values already replaced by vault
// tokens like [PASSWORD_ab12cd34ef]). Token suffixes are random per session,
// so they are rewritten to per-type ordinals ([PASSWORD#1]); two runs of the
// same task with different secrets therefore share one canonical form, and
// the canonical text itself contains no sensitive value.
//
// The fingerprint is HMAC(install_key, "v1|origin|canonical_lower"): the task
// text is never stored, and a copy of the macro store can't be used to guess
// tasks offline without the key.

import { hmacHex } from './hmac.js';

// Vault tokens: [TYPE_<10 lowercase alphanumerics>] (token-vault.js).
const TOKEN_RE = /\[([A-Z_]+)_([a-z0-9]{6,16})\]/g;
const PLACEHOLDER_WORD = /\[[A-Z_]+#\d+\]/;
const ZERO_WIDTH = /[​-‍⁠﻿­]/g;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
const MAX_TASK_CHARS = 4000;

/**
 * @param {string} tokenizedInstruction
 * @returns {{ canonical: string, canonicalLower: string, words: string[],
 *             slotByToken: Record<string,{type:string,ordinal:number}>,
 *             tokenBySlot: Record<string,string> } | null}
 */
export function canonicalizeTask(tokenizedInstruction) {
  if (typeof tokenizedInstruction !== 'string' || !tokenizedInstruction.trim()) return null;
  const text = tokenizedInstruction.slice(0, MAX_TASK_CHARS)
    .normalize('NFKC').replace(ZERO_WIDTH, '').replace(CONTROL, ' ').replace(/\s+/g, ' ').trim();
  if (!text) return null;

  const slotByToken = {};
  const tokenBySlot = {};
  const counters = {};
  const canonical = text.replace(TOKEN_RE, (token, type) => {
    if (!slotByToken[token]) {
      counters[type] = (counters[type] || 0) + 1;
      slotByToken[token] = { type, ordinal: counters[type] };
      tokenBySlot[`${type}#${counters[type]}`] = token;
    }
    const { ordinal } = slotByToken[token];
    return `[${type}#${ordinal}]`;
  });

  const canonicalLower = canonical.toLowerCase().replace(/^[\s"'`]+|[\s"'`.!?;,]+$/g, '');
  if (!canonicalLower) return null;
  return { canonical, canonicalLower, words: canonical.split(' '), slotByToken, tokenBySlot };
}

/** Keyed fingerprint bound to the origin. Hex, 64 chars. */
export function taskFingerprint(keyHex, origin, canonicalLower) {
  return hmacHex(keyHex, `v1|${origin}|${canonicalLower}`);
}

/**
 * Word span [w0,w1) of `words` whose text equals `value` (case-insensitive,
 * edge punctuation ignored). Provenance proof for a literal typed value: it
 * must be a verbatim part of the user's own task, and must not overlap a
 * token placeholder. Returns null when no such span exists.
 */
export function findSpan(words, value) {
  if (!Array.isArray(words) || typeof value !== 'string') return null;
  const want = value.normalize('NFKC').replace(ZERO_WIDTH, '').replace(/\s+/g, ' ').trim().toLowerCase();
  if (!want || want.length > 200) return null;
  const wantWords = want.split(' ').map((w, i) => (i === 0 ? w.replace(/^[^\p{L}\p{N}]+/u, '') : w)).map((w, i, a) => (i === a.length - 1 ? w.replace(/[^\p{L}\p{N}]+$/u, '') : w));
  const n = wantWords.length;
  for (let s = 0; s + n <= words.length; s++) {
    let ok = true;
    for (let k = 0; k < n && ok; k++) {
      let w = words[s + k];
      if (PLACEHOLDER_WORD.test(w)) { ok = false; break; }
      if (k === 0) w = w.replace(/^[^\p{L}\p{N}]+/u, '');
      if (k === n - 1) w = w.replace(/[^\p{L}\p{N}]+$/u, '');
      ok = w.toLowerCase() === wantWords[k];
    }
    if (ok) return { w0: s, w1: s + n };
  }
  return null;
}

/**
 * The text of a recorded span in the CURRENT task (case preserved, edge
 * punctuation of the first/last word trimmed). Null if out of range or the
 * span now touches a token placeholder (the tasks are not equivalent).
 */
export function spanValue(words, w0, w1) {
  if (!Array.isArray(words) || !Number.isInteger(w0) || !Number.isInteger(w1) || w0 < 0 || w1 > words.length || w0 >= w1) return null;
  const parts = words.slice(w0, w1);
  if (parts.some((w) => PLACEHOLDER_WORD.test(w))) return null;
  parts[0] = parts[0].replace(/^[^\p{L}\p{N}]+/u, '');
  parts[parts.length - 1] = parts[parts.length - 1].replace(/[^\p{L}\p{N}]+$/u, '');
  const v = parts.join(' ');
  return v ? v : null;
}

