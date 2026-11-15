// Macro replay STATE MACHINE. It never acts on the page: it resolves the
// current target and value for the next recorded step and returns a PROPOSAL
// that the orchestrator sends through the normal pipeline (server validation,
// policy, confirmation, the existing action executor). Afterwards it verifies
// the step's postconditions.
//
// Every failure aborts the whole replay (never "continue with the rest"); the
// orchestrator then carries on in normal LLM-planning mode.
//
// Per step:  prepare()  ->  [server validate, confirm, execute]  ->
//            commitExecuted()  ->  verifyExecuted()
// A click may navigate, destroying this content script between commit and
// verify. commitExecuted() therefore advances `index` and, for clicks, leaves
// `pendingVerify` = the executed step; a resumed script calls
// verifyAfterNavigation() to check that step's page-level postconditions.

import { resolveDescriptor } from './descriptor.js';
import { spanValue } from './fingerprint.js';
import { pathHmac, pageSignature, waitForPostconditions } from './postcondition.js';

/** Reason codes (also the audit vocabulary). */
export const ABORT = Object.freeze({
  ORIGIN: 'origin_mismatch', PRECONDITION: 'precondition_failed', VALUE: 'value_unavailable', ALIGN: 'snapshot_misaligned',
  MISSING: 'target_missing', AMBIGUOUS: 'target_ambiguous', CONFLICT: 'identity_conflict', BAD_DESCRIPTOR: 'bad_descriptor',
  POST: 'postcondition_failed', SERVER_MISMATCH: 'server_mismatch', POLICY: 'policy_rejected', DENIED: 'denied_by_user',
  EXEC: 'execution_failed', ERROR: 'internal_error', TOKEN: 'token_unresolvable', CORRUPT: 'macro_invalid',
});

const RESOLVE_REASON = { target_missing: ABORT.MISSING, target_ambiguous: ABORT.AMBIGUOUS, identity_conflict: ABORT.CONFLICT };

export function createReplay({ macro, task, keyHex, restore = null }) {
  let index = 0;                 // next step to PREPARE
  let aborted = null;            // { reason, phase, step }
  let pendingVerify = null;      // executed step whose postconditions are still unchecked (survives a navigation)
  let current = null;            // what prepare() resolved for the step in flight

  if (restore && typeof restore === 'object') {
    if (Number.isInteger(restore.index) && restore.index >= 0 && restore.index <= macro.steps.length) index = restore.index;
    if (Number.isInteger(restore.pendingVerify) && restore.pendingVerify >= 0 && restore.pendingVerify < macro.steps.length) pendingVerify = restore.pendingVerify;
  }

  const abort = (reason, phase = 'step') => {
    if (aborted === null) aborted = { reason, phase, step: Math.max(0, Math.min(current ? current.i : index, macro.steps.length - 1)) };
    return { ok: false, reason: aborted.reason };
  };

  /** The concrete value for a step, from the CURRENT task — never from storage. */
  function valueFor(step) {
    const vs = step.value_source;
    if (!vs) return { ok: true, value: null, token: null, sensitive: false };
    if (vs.kind === 'literal_ms') return { ok: true, value: String(vs.ms), token: null, sensitive: false };
    if (vs.kind === 'token_slot') {
      const token = task && task.tokenBySlot[`${vs.type}#${vs.ordinal}`];
      return token ? { ok: true, value: token, token, sensitive: true } : { ok: false };
    }
    if (vs.kind === 'task_span') {
      const v = task ? spanValue(task.words, vs.w0, vs.w1) : null;
      return v ? { ok: true, value: v, token: null, sensitive: false } : { ok: false };
    }
    return { ok: false };
  }

  return {
    get macroId() { return macro.macro_id; },
    get index() { return index; },
    get total() { return macro.steps.length; },
    get aborted() { return aborted; },
    get done() { return aborted === null && index >= macro.steps.length && pendingVerify === null; },
    get active() { return aborted === null && (index < macro.steps.length || pendingVerify !== null); },
    get pendingVerifyIndex() { return pendingVerify; },
    abort,

    /**
     * Resolve the next step against the LIVE page.
     * `summaries[i]` is the server-bound dom_summary entry for `elements[i]`.
     * @returns {Promise<{ok:true, proposed_action, replay} | {ok:false, reason}>}
     */
    async prepare({ elements, summaries, win }) {
      if (aborted) return { ok: false, reason: aborted.reason };
      if (index >= macro.steps.length) return { ok: false, reason: 'replay_done' };
      const step = macro.steps[index];
      current = null;

      if (win.location.origin !== macro.origin) return abort(ABORT.ORIGIN);                    // origin comes from the browser, never from page content
      if ((await pathHmac(keyHex, win.location.pathname)) !== step.precondition.pathname_hmac) return abort(ABORT.PRECONDITION);

      const val = valueFor(step);
      if (!val.ok) return abort(step.value_source && step.value_source.kind === 'token_slot' ? ABORT.TOKEN : ABORT.VALUE);

      let targetEl = null;
      let targetId = null;
      if (step.target) {
        if (!Array.isArray(elements) || !Array.isArray(summaries) || elements.length !== summaries.length) return abort(ABORT.ALIGN);
        const candidates = elements.map((el, i) => ({ el, tag: summaries[i].tag, role: summaries[i].role, label_text: summaries[i].label_text, is_sensitive: !!summaries[i].is_sensitive, sensitivity_type: summaries[i].sensitivity_type }));
        const r = await resolveDescriptor(step.target, candidates, { keyHex });
        if (!r.ok) return abort(RESOLVE_REASON[r.reason] || ABORT.BAD_DESCRIPTOR);
        targetEl = r.el;
        targetId = summaries[r.index].element_id;
      }

      const proposed = { type: step.type };
      if (targetId !== null) proposed.target_element_id = targetId;
      if (step.type === 'type' || step.type === 'select_custom' || step.type === 'wait') proposed.value = val.value;
      // Transition postconditions (appeared/gone/expanded) only count if they were NOT already true before the step.
      let before = null;
      if (step.post.some((p) => p.kind === 'element_appeared' || p.kind === 'element_gone' || p.kind === 'expanded_state')) {
        const sig = await pageSignature(win.document, win, keyHex);
        before = { keys: new Set(sig.items.keys()), expanded: targetEl ? targetEl.getAttribute('aria-expanded') === 'true' ? true : targetEl.getAttribute('aria-expanded') === 'false' ? false : null : null };
      }
      current = { i: step.i, step, targetEl, value: val.value, token: val.token, sensitive: val.sensitive, before };
      return { ok: true, proposed_action: proposed, replay: { macro_id: macro.macro_id, step_index: step.i, total_steps: macro.steps.length } };
    },

    /** Is the server's answer exactly what we proposed? (Never execute anything else.) */
    matchesProposal(action, proposed) {
      return !!action && action.type === proposed.type
        && (action.target_element_id ?? null) === (proposed.target_element_id ?? null)
        && (action.value ?? null) === (proposed.value ?? null);
    },

    /** The step was executed. Advance; a click may navigate, so its verification stays pending. */
    commitExecuted() {
      if (!current) return;
      index = current.i + 1;
      pendingVerify = current.step.type === 'click' ? current.i : null;
    },

    /** Verify the just-executed step on the live page (postconditions must ALL hold; unverifiable => abort). */
    async verifyExecuted({ doc, win, resolveToken, waitOpts }) {
      if (aborted) return { ok: false, reason: aborted.reason };
      if (!current) return abort(ABORT.ERROR, 'postcondition');
      const { step } = current;
      if (step.type === 'scroll' || step.type === 'wait') { pendingVerify = null; return { ok: true }; }    // no page state to verify
      const expectedValue = current.token ? resolveToken(current.token) : current.value;
      const res = await waitForPostconditions(step.post, { doc, win, keyHex, targetEl: current.targetEl, expectedValue, expectedIsSensitive: current.sensitive, before: current.before }, waitOpts);
      if (!res.ok) return abort(ABORT.POST, 'postcondition');
      pendingVerify = null;
      return { ok: true };
    },

    /**
     * On a fresh page after a navigation: check the executed click's
     * postconditions. The old target no longer exists, so only page-level
     * ones can apply; anything else is unverifiable and aborts.
     */
    async verifyAfterNavigation({ doc, win, waitOpts }) {
      if (aborted) return { ok: false, reason: aborted.reason };
      if (pendingVerify === null) return { ok: true };
      const step = macro.steps[pendingVerify];
      const pageLevel = (kind) => kind === 'pathname_is' || kind === 'element_appeared' || kind === 'element_gone';
      if (!step.post.length || !step.post.every((p) => pageLevel(p.kind))) return abort(ABORT.POST, 'postcondition');
      const res = await waitForPostconditions(step.post, { doc, win, keyHex, targetEl: null }, waitOpts);
      if (!res.ok) return abort(ABORT.POST, 'postcondition');
      pendingVerify = null;
      return { ok: true };
    },

    /** State that survives a navigation (extension-internal, in memory only; never a value). */
    serialize() { return { index, pendingVerify }; },
  };
}
