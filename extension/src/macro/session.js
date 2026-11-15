// MacroSession: the ONLY surface the orchestrator touches. It owns the
// recorder / replayer for one task run and keeps every macro concern out of
// the orchestrator's step loop, so that:
//   * a macro problem can never break a normal task: every public method
//     catches its own errors and degrades to plain LLM planning;
//   * replay never bypasses the pipeline: it only produces PROPOSALS
//     (payload.proposed_action) and verifies postconditions afterwards.
//
// Modes:  'off' (no macros)  'record' (learning from a normal run)
//         'replay' (executing a saved macro)  'normal' (a replay aborted —
//         the run continues under LLM planning; nothing is recorded from it)

import { canonicalizeTask, taskFingerprint } from './fingerprint.js';
import { createRecorder, saveSummary } from './recorder.js';
import { createReplay, ABORT } from './replayer.js';
import { validateMacro } from './schema.js';

const MAX_RESUME_BYTES = 60 * 1024;

export function createMacroSession({ send, report, win, doc, confirmSave, now = () => Date.now() }) {
  let mode = 'off';
  let keyHex = null;
  let task = null;
  let fp = null;
  let recorder = null;
  let replay = null;
  let macro = null;
  let inFlight = null;              // the proposal currently being validated/executed
  let lastEl = null;                // live element of the step in flight (for postconditions)
  let ended = false;
  let abortNote = null;             // fixed-vocabulary hint handed to the LLM once, after an abort
  const metrics = { lookup_ms: 0, resolve_ms: 0, exec_ms: 0, verify_ms: 0, steps_replayed: 0, aborted: null };

  const safeReport = (event, details) => { try { const r = report(event, details); if (r && typeof r.catch === 'function') r.catch(() => {}); } catch (_e) { /* audit is best-effort */ } };
  const ids = () => (macro ? { macro_id: macro.macro_id, total_steps: macro.steps.length } : {});

  function degrade(reason) {                      // an internal error: macros off for the rest of this run
    if (mode === 'replay') return abortToFallback(ABORT.ERROR, 'step');
    if (mode === 'record' && recorder) recorder.taint(reason || 'internal_error');
    return false;
  }

  /** The single failure path: abort the macro, audit, and continue under LLM planning. */
  function abortToFallback(reason, phase = 'step', { hard = false } = {}) {
    if (mode !== 'replay') return false;
    if (replay) replay.abort(reason, phase);
    const step = replay && replay.aborted ? replay.aborted.step : 0;
    metrics.aborted = reason;
    safeReport('MACRO_STEP_FAILED', { ...ids(), step_index: step, reason, phase });
    safeReport('MACRO_REPLAY_ABORTED', { ...ids(), step_index: step, reason });
    safeReport('MACRO_FALLBACK_TO_LLM', { ...ids(), step_index: step, reason });
    if (macro) send({ type: 'MACRO_RECORD_RESULT', macro_id: macro.macro_id, success: false, hard }).catch(() => {});
    abortNote = `Saved workflow stopped (${reason}); continue this task with normal planning from the current page.`;
    mode = 'normal';
    inFlight = null;
    return false;
  }

  const guard = (fn, fallback) => async (...args) => { try { return await fn(...args); } catch (_e) { degrade('internal_error'); return fallback; } };

  const api = {
    get mode() { return mode; },
    get replaying() { return mode === 'replay' && replay !== null && replay.active; },
    get replayDone() { return mode === 'replay' && replay !== null && replay.done; },
    get fingerprint() { return fp; },
    metrics,
    ended: () => ended,

    /**
     * @param {{ mode: 'record'|'replay', tokenizedInstruction: string, resume?: object|null }} o
     * @returns {Promise<string>} the resulting mode
     */
    init: guard(async ({ mode: requested, tokenizedInstruction, resume = null }) => {
      mode = 'off';
      const k = await send({ type: 'MACRO_GET_KEY' });
      if (!k || !k.ok || typeof k.key !== 'string') return mode;
      keyHex = k.key;
      task = canonicalizeTask(tokenizedInstruction);
      if (!task) return mode;
      fp = await taskFingerprint(keyHex, win.location.origin, task.canonicalLower);

      if (resume && typeof resume === 'object') {
        if (resume.mode === 'record') { recorder = createRecorder({ keyHex, origin: win.location.origin, taskFp: fp, task, restore: resume.recorder }); mode = 'record'; }
        else if (resume.mode === 'replay' && typeof resume.macroId === 'string') {
          const g = await send({ type: 'MACRO_GET', macro_id: resume.macroId });
          if (g && g.ok && g.macro && validateMacro(g.macro).ok && g.macro.origin === win.location.origin && g.macro.task_fp === fp) {
            macro = g.macro; replay = createReplay({ macro, task, keyHex, restore: resume.replay }); mode = 'replay';
          } else { mode = 'normal'; safeReport('MACRO_FALLBACK_TO_LLM', { reason: 'macro_unavailable_after_navigation', phase: 'resume' }); }
        } else if (resume.mode === 'normal') mode = 'normal';
        return mode;
      }

      if (requested === 'replay') {
        const t0 = now();
        const r = await send({ type: 'MACRO_LOOKUP', task_fp: fp });
        metrics.lookup_ms = now() - t0;
        const m = r && r.ok ? r.macro : null;
        safeReport('MACRO_LOOKUP', { hit: !!m, dropped: (r && r.dropped) || 0, lookup_ms: metrics.lookup_ms });
        if (m && (r.dropped || 0) > 0) safeReport('MACRO_CORRUPT', { count: r.dropped });
        if (m && validateMacro(m).ok && m.origin === win.location.origin && m.task_fp === fp) {
          macro = m; replay = createReplay({ macro, task, keyHex }); mode = 'replay';
          safeReport('MACRO_REPLAY_STARTED', { ...ids(), steps: macro.steps.length });
          return mode;
        }
        if (m) safeReport('MACRO_CORRUPT', { count: 1 });
      }
      recorder = createRecorder({ keyHex, origin: win.location.origin, taskFp: fp, task });
      mode = 'record';
      return mode;
    }, 'off'),

    /** After a navigation: settle whatever the previous page left pending. */
    resumeStartup: guard(async ({ waitOpts } = {}) => {
      if (mode === 'record' && recorder && recorder.hasPending()) await recorder.completeStep({ doc, win, el: null });
      if (mode === 'replay' && replay && replay.pendingVerifyIndex !== null) {
        const t0 = now();
        const r = await replay.verifyAfterNavigation({ doc, win, waitOpts });
        metrics.verify_ms += now() - t0;
        if (!r.ok) abortToFallback(r.reason, 'postcondition');
      }
    }, undefined),

    /** Adds the proposal to the outgoing payload when replaying. On any problem: abort -> the LLM plans this step. */
    beforeSend: guard(async ({ elements, summaries, payload, stepNumber }) => {
      inFlight = null; lastEl = null;
      if (mode !== 'replay' || !replay || replay.aborted || replay.index >= replay.total) return { proposed: false };   // not replaying, or every recorded step is done
      if (replay.pendingVerifyIndex !== null) { abortToFallback(ABORT.POST, 'postcondition'); return { proposed: false }; }   // never propose past an unverified step
      const t0 = now();
      const prep = await replay.prepare({ elements, summaries, win });
      metrics.resolve_ms += now() - t0;
      if (!prep.ok) {
        if (prep.reason === 'replay_done') return { proposed: false };
        abortToFallback(prep.reason);
        return { proposed: false };
      }
      payload.proposed_action = prep.proposed_action;
      payload.replay = prep.replay;
      inFlight = prep.proposed_action;
      safeReport('MACRO_STEP_STARTED', { ...ids(), step_index: prep.replay.step_index, phase: 'step' });
      return { proposed: true };
    }, { proposed: false }),

    /** The server answered a proposal: it must be EXACTLY what we proposed. */
    responseMatches(action) {
      try {
        if (!inFlight) return true;
        if (replay.matchesProposal(action, inFlight)) return true;
        abortToFallback(ABORT.SERVER_MISMATCH);
        return false;
      } catch (_e) { degrade('internal_error'); return false; }
    },

    /** Record mode: capture the "before" state of the step about to execute. */
    beforeExecute: guard(async ({ action, summary, el }) => {
      lastEl = el || null;
      if (mode === 'record' && recorder) await recorder.beginStep({ action, summary, el, doc, win });
    }, undefined),

    /** The action executed. (Replay: advance; record: nothing yet.) Call the stash right after this. */
    executed() {
      try { if (mode === 'replay' && replay && inFlight) replay.commitExecuted(); } catch (_e) { degrade('internal_error'); }
    },

    /** Record mode: after the page settled. Replay: verify postconditions. */
    afterExecute: guard(async ({ resolveToken, waitOpts }) => {
      if (mode === 'record' && recorder) { await recorder.completeStep({ doc, win, el: lastEl }); return { ok: true }; }
      if (mode === 'replay' && replay && inFlight) {
        const t0 = now();
        const r = await replay.verifyExecuted({ doc, win, resolveToken, waitOpts });
        metrics.verify_ms += now() - t0;
        inFlight = null;
        if (!r.ok) { abortToFallback(r.reason, 'postcondition'); return { ok: false, reason: r.reason }; }
        metrics.steps_replayed += 1;
      }
      return { ok: true };
    }, { ok: false }),

    addExecMs(ms) { metrics.exec_ms += ms; },

    /** One-shot note for the next LLM request after a replay aborted (client-generated, fixed vocabulary). */
    consumeAbortNote() { const n = abortNote; abortNote = null; return n; },

    /** Something went wrong executing the step. */
    executionFailed() { if (mode === 'record' && recorder) recorder.taint('execution_failed'); else abortToFallback(ABORT.EXEC); },

    /** The server refused (status from the transport error). A policy rejection also quarantines the macro. */
    serverRejected(status) {
      if (mode === 'record' && recorder) recorder.taint(`server_${status || 'error'}`);
      else if (status === 422) abortToFallback(ABORT.POLICY, 'step', { hard: true });
      else abortToFallback(ABORT.ERROR);
    },

    /** The user declined a confirmation: the task ends (no fallback, no penalty). */
    denied() { ended = true; if (mode === 'record' && recorder) recorder.taint('denied_by_user'); },

    taint(reason) { if (mode === 'record' && recorder) recorder.taint(reason); },
    /** Any run-level anomaly (retry, LLM asked for confirmation, injection-flagged action...). */
    noteAction(action) {
      if (mode !== 'record' || !recorder || !action) return;
      const reasons = Array.isArray(action.risk_reasons) ? action.risk_reasons : [];
      if (reasons.includes('target_flagged_injection') || reasons.includes('reasoning_echoes_injection')) recorder.taint('injection_signal');
      if (action.type === 'ask_user_confirmation') recorder.taint('llm_asked_confirmation');
    },

    /** State that survives a page navigation (extension-internal, in memory; no values). */
    toResume() {
      try {
        let s = null;
        if (mode === 'record' && recorder) s = { mode: 'record', recorder: recorder.serialize() };
        else if (mode === 'replay' && replay && macro) s = { mode: 'replay', macroId: macro.macro_id, replay: replay.serialize() };
        else if (mode === 'normal') s = { mode: 'normal' };
        if (s && JSON.stringify(s).length > MAX_RESUME_BYTES) { if (recorder) recorder.taint('resume_state_too_large'); return null; }
        return s;
      } catch (_e) { return null; }
    },

    /**
     * The task finished successfully (task_complete accepted AFTER the existing
     * completion validation). Record mode: offer the candidate to the user;
     * replay mode: bookkeeping. Returns a small outcome for the UI.
     */
    onCompleted: guard(async ({ totals }) => {
      if (mode === 'replay' && replay && replay.aborted === null && macro) {
        await send({ type: 'MACRO_RECORD_RESULT', macro_id: macro.macro_id, success: true }).catch(() => {});
        safeReport('MACRO_REPLAY_SUCCEEDED', { ...ids(), steps: metrics.steps_replayed, ...totals, lookup_ms: metrics.lookup_ms, resolve_ms: metrics.resolve_ms, exec_ms: metrics.exec_ms, mode: 'replay' });
        return { outcome: 'replayed' };
      }
      if (mode !== 'record' || !recorder) return { outcome: mode === 'normal' ? 'fell_back' : 'none' };
      const cand = recorder.candidate();
      if (!cand) return { outcome: 'not_eligible', reason: recorder.tainted || recorder.truncated || 'no_steps' };
      const yes = await confirmSave(saveSummary({ origin: win.location.origin, lines: cand.lines, truncated: cand.truncated }));
      if (!yes) { safeReport('MACRO_SAVE_DECLINED', { steps: cand.body.steps.length }); return { outcome: 'declined' }; }
      const put = await send({ type: 'MACRO_PUT', body: cand.body });
      if (put && put.ok) { safeReport('MACRO_CREATED', { macro_id: put.macro_id, steps: cand.body.steps.length, mode: 'normal', ...totals }); return { outcome: 'saved', macro_id: put.macro_id }; }
      return { outcome: 'save_failed', reason: (put && put.error) || 'unknown' };
    }, { outcome: 'error' }),
  };
  return api;
}
