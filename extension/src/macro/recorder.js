// Records a CANDIDATE macro while a normal (LLM-planned) task runs.
// Nothing here persists anything: the candidate is only handed to the user for
// an explicit save decision (see orchestrator + panel).
//
// What is recorded per step: action type, a hashed target descriptor, a safe
// value REFERENCE and hashed/enum postconditions. Never recorded: the LLM's
// action object, raw values, DOM snapshots, screenshots, page text.
//
// Two ways a run can stop yielding a macro:
//   taint(reason)     the WHOLE run is unsafe to learn from (a failure, a
//                     server rejection, an injection signal, ...): no macro.
//   truncate(reason)  this step can't be recorded safely (value without
//                     provenance, weak identity, unverifiable): recording stops
//                     and the macro is the safe PREFIX before it — the LLM
//                     finishes the task on replay.

import { describeElement } from './descriptor.js';
import { pageSignature, targetState, derivePostconditions } from './postcondition.js';
import { findSpan } from './fingerprint.js';
import { validateCandidateBody, STEP_TYPES, TOKEN_SLOT_TYPES, LIMITS } from './schema.js';
import { detectPII } from '../../dev2/pii-patterns.js';

const TOKEN_SHAPE = /^\[([A-Z_]+)_[a-z0-9]{6,16}\]$/;
const MAX_DISPLAY_LABEL = 30;
const MAX_DISPLAY_LINES = 8;

/**
 * Where does a typed/selected value come from? Returns a value_source, or
 * { refuse: reason } when its provenance can't be established safely.
 */
export function valueSourceFor(action, summary, task) {
  const type = action.type;
  if (type === 'wait') {
    const ms = Number.parseInt(action.value, 10);
    return Number.isInteger(ms) && ms >= 0 && ms <= LIMITS.MAX_WAIT_MS ? { kind: 'literal_ms', ms } : { refuse: 'wait_value' };
  }
  if (type !== 'type' && type !== 'select_custom') return null;
  const v = action.value;
  if (typeof v !== 'string' || v === '') return { refuse: 'empty_value' };
  if (!task) return { refuse: 'no_task_context' };

  const tok = TOKEN_SHAPE.exec(v);
  if (tok) {
    const slot = task.slotByToken[v];
    if (!slot || !TOKEN_SLOT_TYPES.includes(slot.type) || slot.ordinal > 9) return { refuse: 'token_not_from_task' };   // a token the task never contained
    return { kind: 'token_slot', type: slot.type, ordinal: slot.ordinal };
  }
  if (v.startsWith('[') && v.endsWith(']')) return { refuse: 'unresolved_token_shape' };
  // A literal. It must be the user's own words (provenance), never aimed at a
  // sensitive field (those take tokens), and never PII-shaped.
  if (summary && summary.is_sensitive) return { refuse: 'literal_into_sensitive_field' };
  if (detectPII(v).length > 0) return { refuse: 'pii_shaped_literal' };
  const span = findSpan(task.words, v);
  return span ? { kind: 'task_span', w0: span.w0, w1: span.w1 } : { refuse: 'value_without_provenance' };
}

function safeLabel(summary) {
  const l = summary && typeof summary.label_text === 'string' ? summary.label_text.replace(/\s+/g, ' ').trim() : '';
  if (!l || l.length > MAX_DISPLAY_LABEL || summary.is_sensitive || detectPII(l).length > 0) return null;
  return l.replace(/["\u0000-\u001f]/g, '');
}

/** One human-readable line for the save dialog. Transient: never persisted, never a raw sensitive value. */
function displayLine(step, summary, task, valueSource) {
  const label = safeLabel(summary);
  const what = label ? `"${label}"` : (summary && summary.role ? `a ${String(summary.role).replace(/[^a-z-]/gi, '')}` : 'an element');
  switch (step.type) {
    case 'click': return `Click ${what}`;
    case 'scroll': return `Scroll to ${what}`;
    case 'wait': return 'Wait briefly';
    case 'type':
    case 'select_custom': {
      const verb = step.type === 'select_custom' || (summary && summary.tag === 'select') ? 'Select' : 'Enter';
      if (valueSource.kind === 'token_slot') return `${verb} [${valueSource.type}]`;
      const words = task ? task.words.slice(valueSource.w0, valueSource.w1).join(' ').replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, '') : '';
      return words && words.length <= MAX_DISPLAY_LABEL && detectPII(words).length === 0 && !/[\[\]"]/.test(words) ? `${verb} "${words}"` : `${verb} a value from your task`;
    }
    default: return 'Step';
  }
}

export function createRecorder({ keyHex, origin, taskFp, task, restore = null }) {
  const steps = [];
  const display = [];
  let pending = null;
  let tainted = null;
  let truncated = null;

  if (restore && typeof restore === 'object') {                       // navigation resume
    if (Array.isArray(restore.steps)) steps.push(...restore.steps.slice(0, LIMITS.MAX_STEPS));
    if (Array.isArray(restore.display)) display.push(...restore.display.filter((d) => typeof d === 'string').slice(0, LIMITS.MAX_STEPS).map((d) => d.slice(0, 80)));
    if (restore.origin !== origin) tainted = 'cross_origin';
    else tainted = typeof restore.tainted === 'string' ? restore.tainted : null;
    truncated = typeof restore.truncated === 'string' ? restore.truncated : null;
    if (restore.pending && typeof restore.pending === 'object') {
      const p = restore.pending;
      pending = { ...p, before: { pathname: p.before.pathname, items: new Map(p.before.items) } };
    }
  }

  const stopped = () => tainted !== null || truncated !== null;

  const api = {
    get tainted() { return tainted; },
    get truncated() { return truncated; },
    get stepCount() { return steps.length; },
    hasPending: () => pending !== null,

    taint(reason) { if (tainted === null) tainted = String(reason).slice(0, 60); pending = null; },
    truncate(reason) { if (truncated === null && tainted === null) truncated = String(reason).slice(0, 60); pending = null; },

    /**
     * Call BEFORE executing an action (captures the "before" state).
     * @param {{ action: {type:string, target_element_id?:string|null, value?:string|null}, summary: object|null, el: Element|null, doc: Document, win: Window }} c
     */
    async beginStep({ action, summary, el, doc, win }) {
      pending = null;
      if (stopped()) return;
      if (win.location.origin !== origin) return api.taint('cross_origin');
      if (steps.length >= LIMITS.MAX_STEPS) return api.truncate('max_steps');
      if (!STEP_TYPES.includes(action.type)) return api.taint('unsupported_action');

      const valueSource = valueSourceFor(action, summary, task);
      if (valueSource && valueSource.refuse) return api.truncate(valueSource.refuse);

      let target = null;
      if (action.type !== 'wait') {
        if (!el || !summary) return api.truncate('no_target');
        target = await describeElement(el, { keyHex, summary });
        if (!target) return api.truncate('weak_identity');
      }
      const before = await pageSignature(doc, win, keyHex);
      pending = {
        type: action.type, target, valueSource, before,
        tBefore: el ? targetState(el, win) : { connected: false, visible: false, expanded: null },
        precondition: { pathname_hmac: before.pathname },
        line: displayLine(action, summary, task, valueSource),
      };
    },

    /** Call AFTER the action executed and the page settled (or, after a navigation, on the new page). */
    async completeStep({ doc, win, el }) {
      const p = pending;
      pending = null;
      if (!p || stopped()) return;
      if (win.location.origin !== origin) return api.taint('cross_origin');
      const after = await pageSignature(doc, win, keyHex);
      const tAfter = el ? targetState(el, win) : { connected: false, visible: false, expanded: null };
      const post = derivePostconditions(
        { type: p.type, targetTag: p.target ? p.target.tag : '', targetRole: p.target ? p.target.role : '', targetNameHmac: p.target ? p.target.name_hmac : null },
        p.before, after, p.tBefore, tAfter,
      );
      const needsPost = p.type === 'click' || p.type === 'type' || p.type === 'select_custom';
      if (needsPost && post.length === 0) return api.truncate('unverifiable_step');
      steps.push({ i: steps.length, type: p.type, precondition: p.precondition, target: p.target, value_source: p.valueSource, post });
      display.push(p.line);
    },

    /**
     * The candidate body (no id/integrity/stats — the store adds those) plus a
     * safe, transient summary for the confirmation dialog. Null unless the run
     * was clean and produced at least one valid step.
     */
    candidate() {
      if (tainted !== null || pending !== null || steps.length === 0) return null;
      const body = { origin, task_fp: taskFp, created_at: 0, steps: steps.map((s) => ({ ...s })) };
      const v = validateCandidateBody(body);
      if (!v.ok) return null;
      return { body, lines: display.slice(0, steps.length), truncated };
    },

    /** Serializable state for surviving a page navigation (extension-internal, in memory only). */
    serialize() {
      return {
        origin, steps, display, tainted, truncated,
        pending: pending ? { ...pending, before: { pathname: pending.before.pathname, items: [...pending.before.items] } } : null,
      };
    },
  };
  return api;
}

export { displayLine as _displayLine };

/** Text for the save confirmation. Contains no raw sensitive values by construction. */
export function saveSummary({ origin, lines, truncated }) {
  const shown = lines.slice(0, MAX_DISPLAY_LINES).map((l) => `• ${l}`);
  if (lines.length > MAX_DISPLAY_LINES) shown.push(`• …and ${lines.length - MAX_DISPLAY_LINES} more`);
  const host = origin.replace(/^https?:\/\//, '');
  return [
    'Save workflow?', '', host, `${lines.length} step${lines.length === 1 ? '' : 's'}`, '', ...shown, '',
    truncated ? 'The rest of this task will still be planned by the AI.' : '',
    'Sensitive values are not stored.',
  ].filter((l, i, a) => !(l === '' && a[i - 1] === '')).join('\n');
}
