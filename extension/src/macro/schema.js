// Macro schema v1 + strict validation. A macro is ONLY a planning shortcut:
// it stores how to re-find things and where values come from, never a value.
//
// Design rules enforced here (not just documented):
//   * closed schema — unknown keys anywhere are rejected;
//   * NO PAGE-DERIVED PLAIN TEXT: labels, ids, `name` attributes, form context,
//     URL paths and the task itself are stored ONLY as keyed hashes (64 hex
//     chars); the only plain strings are members of fixed allow-lists (HTML
//     tags, ARIA roles, input types, sensitivity types) plus the origin;
//   * values are references (token slot / task word span / bounded number);
//   * bounded: steps, sizes, ordinals;
//   * origin-scoped and integrity-checked (see canonicalJson / macroBody).

export const SCHEMA_VERSION = 1;

export const LIMITS = Object.freeze({
  MAX_STEPS: 20,               // matches RETRY_CONFIG.MAX_STEPS: a longer run couldn't complete anyway
  MAX_POST_PER_STEP: 3,
  MAX_MACRO_BYTES: 32 * 1024,
  MAX_MACROS_PER_ORIGIN: 20,
  MAX_ORIGINS: 50,
  MAX_WORD_INDEX: 500,
  MAX_WAIT_MS: 5000,
  UNUSED_TTL_MS: 90 * 24 * 60 * 60 * 1000,
  QUARANTINE_AFTER_FAILURES: 3,
});

export const STEP_TYPES = Object.freeze(['click', 'type', 'select_custom', 'scroll', 'wait']);
export const STATUSES = Object.freeze(['active', 'quarantined']);
export const SENSITIVITY_TYPES = Object.freeze(['PASSWORD', 'CARD_NUMBER', 'AADHAAR', 'OTP', 'NAME', 'AMOUNT', 'EMAIL', 'PHONE', 'IFSC', 'UNKNOWN']);
export const TOKEN_SLOT_TYPES = SENSITIVITY_TYPES.filter((t) => t !== 'UNKNOWN');
export const POST_KINDS = Object.freeze(['field_filled', 'select_shows', 'pathname_is', 'element_appeared', 'element_gone', 'expanded_state']);

// Fixed vocabularies. A page can put arbitrary text in `role`, `type` or a custom
// tag name, so anything outside these sets is never persisted (and such an
// element simply cannot be recorded).
export const ARIA_ROLES = new Set(('alert alertdialog application article banner blockquote button caption cell checkbox code columnheader combobox '
  + 'complementary contentinfo definition deletion dialog directory document emphasis feed figure form generic grid gridcell group heading img '
  + 'insertion link list listbox listitem log main marquee math meter menu menubar menuitem menuitemcheckbox menuitemradio navigation none note '
  + 'option paragraph presentation progressbar radio radiogroup region row rowgroup rowheader scrollbar search searchbox separator slider spinbutton '
  + 'status strong subscript superscript switch tab table tablist tabpanel term textbox time timer toolbar tooltip tree treegrid treeitem').split(' '));
export const HTML_TAGS = new Set(('a article aside button details dialog div fieldset footer form h1 h2 h3 h4 h5 h6 header img input label li main nav ol option p '
  + 'section select span summary table td textarea th tr ul').split(' '));
export const INPUT_TYPES = new Set(('button checkbox color date datetime-local email file hidden image month number password radio range reset search submit tel '
  + 'text time url week').split(' '));

const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(?::\d{1,5})?$/;

export const isValidOrigin = (o) => typeof o === 'string' && o.length <= 200 && ORIGIN.test(o);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;
const isStr = (v, re) => typeof v === 'string' && re.test(v);
const inSet = (set) => (v) => typeof v === 'string' && set.has(v);
const nullable = (v, ok) => v === null || ok(v);
const isHash = (v) => isStr(v, HEX64);

function exactKeys(obj, allowed, path, errs) {
  if (!isObj(obj)) { errs.push(`${path}: not an object`); return false; }
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) errs.push(`${path}.${k}: unknown key`);
  for (const k of allowed) if (!(k in obj)) errs.push(`${path}.${k}: missing`);
  return true;
}

function checkDescriptor(d, path, errs) {
  if (!exactKeys(d, ['tag', 'role', 'input_type', 'name_attr_hmac', 'stable_id_hmac', 'name_hmac', 'ctx', 'sensitivity'], path, errs)) return;
  if (!inSet(HTML_TAGS)(d.tag)) errs.push(`${path}.tag`);
  if (!inSet(ARIA_ROLES)(d.role)) errs.push(`${path}.role`);
  if (!nullable(d.input_type, inSet(INPUT_TYPES))) errs.push(`${path}.input_type`);
  if (!nullable(d.name_attr_hmac, isHash)) errs.push(`${path}.name_attr_hmac`);
  if (!nullable(d.stable_id_hmac, isHash)) errs.push(`${path}.stable_id_hmac`);
  if (!nullable(d.name_hmac, isHash)) errs.push(`${path}.name_hmac`);
  if (exactKeys(d.ctx, ['form_hmac', 'landmark_role', 'landmark_hmac'], `${path}.ctx`, errs)) {
    if (!nullable(d.ctx.form_hmac, isHash)) errs.push(`${path}.ctx.form_hmac`);
    if (!nullable(d.ctx.landmark_role, inSet(ARIA_ROLES))) errs.push(`${path}.ctx.landmark_role`);
    if (!nullable(d.ctx.landmark_hmac, isHash)) errs.push(`${path}.ctx.landmark_hmac`);
  }
  if (exactKeys(d.sensitivity, ['is_sensitive', 'type'], `${path}.sensitivity`, errs)) {
    if (typeof d.sensitivity.is_sensitive !== 'boolean') errs.push(`${path}.sensitivity.is_sensitive`);
    if (!nullable(d.sensitivity.type, inSet(new Set(SENSITIVITY_TYPES)))) errs.push(`${path}.sensitivity.type`);
  }
  // An element needs >= 2 independent anchors to be re-found safely (see macro/descriptor.js).
  const anchors = [d.name_hmac, d.name_attr_hmac, d.stable_id_hmac, d.ctx && d.ctx.form_hmac, d.ctx && d.ctx.landmark_hmac].filter((v) => v !== null && v !== undefined).length;
  if (anchors < 2) errs.push(`${path}: weak identity (needs >= 2 anchors)`);
}

function checkValueSource(v, path, errs) {
  if (!isObj(v)) { errs.push(`${path}: not an object`); return; }
  if (v.kind === 'token_slot') {
    exactKeys(v, ['kind', 'type', 'ordinal'], path, errs);
    if (!TOKEN_SLOT_TYPES.includes(v.type)) errs.push(`${path}.type`);
    if (!isInt(v.ordinal, 1, 9)) errs.push(`${path}.ordinal`);
  } else if (v.kind === 'task_span') {
    exactKeys(v, ['kind', 'w0', 'w1'], path, errs);
    if (!isInt(v.w0, 0, LIMITS.MAX_WORD_INDEX) || !isInt(v.w1, 1, LIMITS.MAX_WORD_INDEX) || !(v.w0 < v.w1)) errs.push(`${path}.span`);
  } else if (v.kind === 'literal_ms') {
    exactKeys(v, ['kind', 'ms'], path, errs);
    if (!isInt(v.ms, 0, LIMITS.MAX_WAIT_MS)) errs.push(`${path}.ms`);
  } else {
    errs.push(`${path}.kind`);
  }
}

function checkPost(p, path, errs) {
  if (!isObj(p) || !POST_KINDS.includes(p.kind)) { errs.push(`${path}.kind`); return; }
  switch (p.kind) {
    case 'field_filled':
    case 'select_shows':
      exactKeys(p, ['kind'], path, errs); break;
    case 'pathname_is':
      exactKeys(p, ['kind', 'pathname_hmac'], path, errs);
      if (!isHash(p.pathname_hmac)) errs.push(`${path}.pathname_hmac`);
      break;
    case 'element_appeared':
    case 'element_gone':
      exactKeys(p, ['kind', 'role', 'tag', 'name_hmac'], path, errs);
      if (!inSet(ARIA_ROLES)(p.role)) errs.push(`${path}.role`);
      if (!inSet(HTML_TAGS)(p.tag)) errs.push(`${path}.tag`);
      if (!isHash(p.name_hmac)) errs.push(`${path}.name_hmac`);
      break;
    case 'expanded_state':
      exactKeys(p, ['kind', 'expanded'], path, errs);
      if (typeof p.expanded !== 'boolean') errs.push(`${path}.expanded`);
      break;
    default: break;
  }
}

function checkStep(s, idx, errs) {
  const path = `steps[${idx}]`;
  if (!exactKeys(s, ['i', 'type', 'precondition', 'target', 'value_source', 'post'], path, errs)) return;
  if (s.i !== idx) errs.push(`${path}.i`);
  if (!STEP_TYPES.includes(s.type)) errs.push(`${path}.type`);
  if (exactKeys(s.precondition, ['pathname_hmac'], `${path}.precondition`, errs) && !isHash(s.precondition.pathname_hmac)) errs.push(`${path}.precondition.pathname_hmac`);

  const needsTarget = s.type !== 'wait';
  if (needsTarget) checkDescriptor(s.target, `${path}.target`, errs);
  else if (s.target !== null) errs.push(`${path}.target: must be null for wait`);

  const needsValue = s.type === 'type' || s.type === 'select_custom' || s.type === 'wait';
  if (needsValue) {
    checkValueSource(s.value_source, `${path}.value_source`, errs);
    if (isObj(s.value_source) && ((s.type === 'wait') !== (s.value_source.kind === 'literal_ms'))) errs.push(`${path}.value_source: kind not allowed for ${s.type}`);
  } else if (s.value_source !== null) errs.push(`${path}.value_source: must be null for ${s.type}`);

  if (!Array.isArray(s.post) || s.post.length > LIMITS.MAX_POST_PER_STEP) { errs.push(`${path}.post`); return; }
  s.post.forEach((p, k) => checkPost(p, `${path}.post[${k}]`, errs));
  // A state-changing step must be verifiable; scroll/wait change no page state.
  if ((s.type === 'click' || s.type === 'type' || s.type === 'select_custom') && s.post.length === 0) errs.push(`${path}.post: state-changing step needs a postcondition`);
  // A type/select step's postcondition must be about the field, never a bare page-diff.
  if (s.type === 'type' && !s.post.some((p) => p.kind === 'field_filled' || p.kind === 'select_shows')) errs.push(`${path}.post: type step needs field_filled/select_shows`);
  if (s.type === 'select_custom' && !s.post.some((p) => p.kind === 'select_shows')) errs.push(`${path}.post: select step needs select_shows`);
}

/** Canonical (sorted-key) JSON — the byte string the integrity HMAC covers. */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

/** The IMMUTABLE core the integrity HMAC covers (stats/status/last_used change over time). */
export function macroBody(m) {
  return { macro_id: m.macro_id, schema_version: m.schema_version, origin: m.origin, task_fp: m.task_fp, created_at: m.created_at, steps: m.steps };
}

/**
 * Strict structural validation. Never throws.
 * @returns {{ ok: true } | { ok: false, reason: 'unsupported_version'|'too_large'|'invalid', errors: string[] }}
 */
export function validateMacro(m) {
  if (!isObj(m)) return { ok: false, reason: 'invalid', errors: ['not an object'] };
  if (m.schema_version !== SCHEMA_VERSION) return { ok: false, reason: 'unsupported_version', errors: [`schema_version ${String(m.schema_version).slice(0, 12)}`] };
  let size = Infinity;
  try { size = new TextEncoder().encode(JSON.stringify(m)).length; } catch (_e) { /* cyclic etc. */ }
  if (size > LIMITS.MAX_MACRO_BYTES) return { ok: false, reason: 'too_large', errors: [`size ${size}`] };

  const errs = [];
  if (!exactKeys(m, ['macro_id', 'schema_version', 'origin', 'task_fp', 'created_at', 'last_used_at', 'status', 'stats', 'steps', 'integrity'], 'macro', errs)) {
    return { ok: false, reason: 'invalid', errors: errs.slice(0, 20) };
  }
  if (!isStr(m.macro_id, UUID)) errs.push('macro_id');
  if (!isValidOrigin(m.origin)) errs.push('origin');
  if (!isHash(m.task_fp)) errs.push('task_fp');
  if (!isInt(m.created_at, 0, 8.64e15)) errs.push('created_at');
  if (!nullable(m.last_used_at, (v) => isInt(v, 0, 8.64e15))) errs.push('last_used_at');
  if (!STATUSES.includes(m.status)) errs.push('status');
  if (!isHash(m.integrity)) errs.push('integrity');
  if (exactKeys(m.stats, ['replays', 'successes', 'consecutive_failures'], 'stats', errs)) {
    for (const k of ['replays', 'successes', 'consecutive_failures']) if (!isInt(m.stats[k], 0, 1e9)) errs.push(`stats.${k}`);
  }
  if (!Array.isArray(m.steps) || m.steps.length === 0 || m.steps.length > LIMITS.MAX_STEPS) errs.push('steps: count');
  else m.steps.forEach((s, i) => checkStep(s, i, errs));

  return errs.length ? { ok: false, reason: 'invalid', errors: errs.slice(0, 20) } : { ok: true };
}

/** Validates an in-memory candidate (no id/integrity/stats yet) by filling neutral placeholders. */
export function validateCandidateBody(body) {
  return validateMacro({
    ...body,
    schema_version: SCHEMA_VERSION,
    macro_id: '00000000-0000-4000-8000-000000000000',
    last_used_at: null,
    status: 'active',
    stats: { replays: 0, successes: 0, consecutive_failures: 0 },
    integrity: '0'.repeat(64),
  });
}
