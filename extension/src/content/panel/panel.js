// Floating in-page agent panel. UI only: it never touches the vault,
// redaction, or action execution — a task run is delegated to the injected
// `runTask` (orchestrator.js's startTask).
//
// Privacy note: the panel is visible on the page, so it would be captured by
// chrome.tabs.captureVisibleTab and OCR'd along with everything else. The
// orchestrator therefore calls suspendForCapture()/resumeAfterCapture()
// around every capture, and the task textarea is cleared the moment a task
// is submitted so a raw credential typed into it never lingers on screen.
import { loadState, saveState, clampState, sessionStore } from './panelState.js';

export const HOST_ID = 'perceive-agent-panel-host';

const CSS = `
:host { all: initial; }
.panel { box-sizing: border-box; width: 100%; height: 100%; display: flex; flex-direction: column;
  background: #1a1a1a; color: #eaeaea; border: 1px solid #3a3a3a; border-radius: 8px; overflow: hidden;
  font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; box-shadow: 0 8px 28px rgba(0,0,0,.45); }
.header { display: flex; align-items: center; gap: 6px; padding: 8px 10px; background: #222; cursor: move;
  user-select: none; touch-action: none; }
.title { flex: 1; font-weight: 600; font-size: 13px; }
.header button { width: 24px; height: 24px; padding: 0; background: transparent; color: #aaa; border: 0;
  border-radius: 4px; cursor: pointer; font-size: 14px; }
.header button:hover { background: #34373d; color: #fff; }
.body { flex: 1; display: flex; flex-direction: column; gap: 8px; padding: 10px; min-height: 0; overflow: auto; }
:host(.min) .body, :host(.min) .secret { display: none; flex-direction: column; gap: 6px; padding: 8px; background: #2b2417; border: 1px solid #6b5a2a; border-radius: 4px; }
.secret.show { display: flex; }
.secret .row { display: flex; gap: 6px; }
.secret .row button { flex: 1; }
.choice { display: none; flex-direction: column; gap: 6px; padding: 8px; background: #172433; border: 1px solid #2f5d8a; border-radius: 4px; }
.choice.show { display: flex; }
.choice .row { display: flex; gap: 6px; }
.choice .row button { flex: 1; }
.macro-info { display: none; font-size: 11px; color: #9ab; align-items: center; justify-content: space-between; gap: 6px; }
.macro-info.show { display: flex; }
.grip { display: none; }
textarea, input { box-sizing: border-box; width: 100%; background: #262626; color: #eaeaea; border: 1px solid #3a3a3a;
  border-radius: 4px; padding: 8px; font: 12px inherit; }
textarea { flex: 1; min-height: 60px; resize: none; }
button.act { padding: 8px; background: #28a745; color: #fff; border: 0; border-radius: 4px; cursor: pointer; font-size: 13px; }
button.act:hover:not(:disabled) { background: #218838; }
button.act:disabled { opacity: .6; cursor: default; }
button.sec { padding: 6px; background: #2a2d33; color: #eaeaea; border: 0; border-radius: 4px; cursor: pointer; font-size: 11px; }
button.sec:hover { background: #34373d; }
.status { font-size: 11px; padding: 6px 8px; background: #262626; border-radius: 4px; color: #7fd77f; word-break: break-word; }
.status.err { color: #f08a8a; }
.status.run { color: #f0d98a; }
details { font-size: 11px; color: #999; }
summary { cursor: pointer; user-select: none; }
details input { margin: 6px 0; }
.grip { position: absolute; right: 0; bottom: 0; width: 16px; height: 16px; cursor: nwse-resize; touch-action: none;
  background: linear-gradient(135deg, transparent 50%, #666 50%, #666 60%, transparent 60%, transparent 70%, #666 70%, #666 80%, transparent 80%); }
`;

const TEMPLATE = `
<div class="panel">
  <div class="header" part="header">
    <span class="title">Perceive</span>
    <button class="min-btn" title="Minimize" aria-label="Minimize">&#8211;</button>
    <button class="close-btn" title="Close" aria-label="Close">&#10005;</button>
  </div>
  <div class="body">
    <textarea class="task" placeholder="Describe a task, e.g. Log in with username 'x' and password 'y'"></textarea>
    <div class="secret" role="alertdialog">
      <div class="secret-msg"></div>
      <input type="password" class="secret-input" autocomplete="off">
      <div class="row"><button class="act secret-ok">Continue</button><button class="sec secret-cancel">Cancel</button></div>
    </div>
    <button class="act run-btn">Run Task</button>
    <div class="status" role="status">● Ready</div>
    <button class="sec overlay-btn" aria-pressed="false">Vision Overlay: OFF</button>
    <button class="sec macros-btn" aria-pressed="false">Workflows: OFF</button>
    <div class="macro-info"><span class="macro-count"></span><button class="sec macro-clear">Delete all</button></div>
    <div class="choice" role="alertdialog">
      <div class="wf-msg"></div>
      <div class="row"><button class="act wf-run">Run workflow</button><button class="sec wf-ai">Plan with AI</button><button class="sec wf-cancel">Cancel</button></div>
    </div>
    <button class="sec dash-btn">Open audit dashboard</button>
    <details class="settings">
      <summary>Backend settings</summary>
      <input type="password" class="key-input" placeholder="Backend API key (X-API-Key)">
      <button class="sec save-key-btn">Save key</button>
      <div class="key-status"></div>
      <button class="sec settings-tab-btn">Open settings in a tab</button>
    </details>
  </div>
  <div class="grip"></div>
</div>`;

function formatReason(reason) {
  if (reason && typeof reason !== 'string') {
    try { return JSON.stringify(reason); } catch (_e) { return String(reason); }
  }
  return reason || 'unknown error';
}

/**
 * Mounts the single panel for this content-script context. Returns the
 * existing instance if one was already mounted (no duplicates, ever).
 */
export function mountPanel({ runTask, overlay = null, macros = null, win = window, chromeApi = globalThis.chrome, store = sessionStore(chromeApi) } = {}) {
  if (win.__perceivePanel) return win.__perceivePanel;

  const doc = win.document;
  const host = doc.createElement('div');
  host.id = HOST_ID;
  const root = host.attachShadow({ mode: 'open' });
  root.innerHTML = `<style>${CSS}</style>${TEMPLATE}`;
  const $ = (sel) => root.querySelector(sel);

  let state = clampState({}, win.innerWidth, win.innerHeight);
  let running = false;
  let macroInfoShown = false;
  let touched = false; // user acted before persisted state finished loading

  const apply = () => {
    Object.assign(host.style, {
      all: 'initial', position: 'fixed', zIndex: '2147483647', boxSizing: 'border-box',
      left: `${state.x}px`, top: `${state.y}px`, width: `${state.width}px`,
      height: state.minimized ? '' : `${state.height}px`,
      display: state.open ? 'block' : 'none',
    });
    host.classList.toggle('min', state.minimized);
    $('.min-btn').innerHTML = state.minimized ? '&#9633;' : '&#8211;';
    $('.overlay-btn').textContent = `Vision Overlay: ${state.overlay ? 'ON' : 'OFF'}`;
    $('.overlay-btn').setAttribute('aria-pressed', String(state.overlay));
    if (overlay) overlay.setEnabled(state.overlay); // idempotent; no-op when unchanged
    $('.macros-btn').textContent = `Workflows: ${state.macros ? 'ON' : 'OFF'}`;
    $('.macros-btn').setAttribute('aria-pressed', String(state.macros));
    // Refresh the saved-workflow count only when the block BECOMES visible (not on every drag/resize tick).
    const showMacroInfo = !!(macros && state.macros && state.open);
    $('.macro-info').classList.toggle('show', showMacroInfo);
    if (showMacroInfo && !macroInfoShown) refreshMacroInfo();
    macroInfoShown = showMacroInfo;
  };
  const persist = () => saveState(store, state);
  const update = (patch, save = true) => {
    touched = true;
    state = clampState({ ...state, ...patch }, win.innerWidth, win.innerHeight);
    apply();
    if (save) persist();
  };

  // Keep page hotkeys from firing while typing in the panel.
  // Capture phase on window so we win over page listeners registered after us
  // (a page listener registered earlier can still intercept — see the
  // "Open settings in a tab" fallback below).
  for (const ev of ['keydown', 'keyup', 'keypress']) {
    win.addEventListener(ev, (e) => {
      if (e.composedPath && e.composedPath().includes(host)) e.stopImmediatePropagation();
    }, true);
  }

  // --- drag / resize (pointer events on the window, so a fast drag can't escape the handle) ---
  const track = (onMove) => {
    const move = (e) => onMove(e);
    const up = () => {
      win.removeEventListener('pointermove', move, true);
      win.removeEventListener('pointerup', up, true);
      persist();
    };
    win.addEventListener('pointermove', move, true);
    win.addEventListener('pointerup', up, true);
  };
  $('.header').addEventListener('pointerdown', (e) => {
    if (e.target.closest && e.target.closest('button')) return; // no drag from controls
    const dx = e.clientX - state.x;
    const dy = e.clientY - state.y;
    track((m) => update({ x: m.clientX - dx, y: m.clientY - dy }, false));
  });
  $('.grip').addEventListener('pointerdown', (e) => {
    e.preventDefault();
    const sx = e.clientX, sy = e.clientY, sw = state.width, sh = state.height;
    track((m) => update({ width: sw + m.clientX - sx, height: sh + m.clientY - sy }, false));
  });
  win.addEventListener('resize', () => update({}, false));

  // --- status / task ---
  const setStatus = (text, kind = '') => {
    const el = $('.status');
    el.textContent = text;
    el.className = `status ${kind}`.trim();
  };
  const setRunning = (v) => {
    running = v;
    $('.run-btn').disabled = v;
  };
  const showResult = (result) => {
    setRunning(false);
    if (!result) return setStatus('⚠ Task ended with no result', 'err');
    if (result.success) {
      const extra = [];
      const o = result.macro && result.macro.outcome;
      if (o === 'saved') extra.push('workflow saved');
      else if (o === 'declined') extra.push('workflow not saved');
      else if (o === 'save_failed') extra.push(`workflow could not be saved (${result.macro.reason === 'storage_quota' ? 'storage full' : 'storage error'})`);
      else if (o === 'replayed') extra.push('replayed a saved workflow');
      else if (o === 'fell_back') extra.push('workflow stopped; AI finished the task');
      if (result.metrics) extra.push(`LLM calls: ${result.metrics.llm_calls} · ${(result.metrics.total_ms / 1000).toFixed(1)}s`);
      if (o === 'saved') refreshMacroInfo();
      return setStatus(`✓ Task complete${result.steps ? ` (${result.steps} steps)` : ''}${extra.length ? ` · ${extra.join(' · ')}` : ''}`);
    }
    setStatus(result.reason === 'UNRESOLVED_SENSITIVE_REFERENCE'
      ? `⚠ ${result.message}`
      : `⚠ Task failed: ${formatReason(result.reason)}`, 'err');
  };
  // Shows running state for a task promise the orchestrator started (also
  // used for tasks resumed after a page navigation).
  const trackTask = (promise) => {
    setRunning(true);
    setStatus('● Running...', 'run');
    return Promise.resolve(promise).then(showResult, (err) => {
      setRunning(false);
      setStatus(`⚠ ${err && err.message ? err.message : err}`, 'err');
    });
  };
  const submit = () => {
    if (running) return null;
    const task = $('.task');
    const instruction = task.value.trim();
    if (!instruction) { setStatus('Enter a task first', 'err'); return null; }
    task.value = ''; // never leave a typed credential on screen (see header note)
    if (macros && state.macros) return trackTask(runWithWorkflows(instruction));
    return trackTask(runTask(instruction, {}));
  };
  $('.run-btn').addEventListener('click', submit);

  // Workflows (opt-in). Looks for a saved workflow for THIS task on THIS site; if one
  // exists the user explicitly chooses between replaying it and normal AI planning.
  // Replay is never automatic.
  let pendingChoice = null;
  const closeChoice = (v) => { $('.choice').classList.remove('show'); if (pendingChoice) { pendingChoice(v); pendingChoice = null; } };
  $('.wf-run').addEventListener('click', () => closeChoice('workflow'));
  $('.wf-ai').addEventListener('click', () => closeChoice('ai'));
  $('.wf-cancel').addEventListener('click', () => closeChoice('cancel'));
  const offerWorkflow = (found) => {
    if (pendingChoice) pendingChoice('cancel');
    update({ open: true, minimized: false });
    $('.wf-msg').textContent = `Saved workflow available for this task (${found.steps} step${found.steps === 1 ? '' : 's'}). Every risky step will still ask for your confirmation.`;
    $('.choice').classList.add('show');
    setStatus('⏸ Waiting for you', 'run');
    return new Promise((resolve) => { pendingChoice = resolve; });
  };
  const runWithWorkflows = async (instruction) => {
    const options = { macros: true };
    let found = null;
    try { found = await macros.lookup(instruction); } catch (_e) { found = null; }
    if (found && found.found) {
      const choice = await offerWorkflow(found);
      if (choice === 'cancel') return { success: false, reason: 'Cancelled' };
      options.useMacro = choice === 'workflow';
      setStatus('● Running...', 'run');
    }
    return runTask(instruction, options);
  };
  async function refreshMacroInfo() {
    try {
      const list = macros ? await macros.list() : [];
      const n = Array.isArray(list) ? list.length : 0;
      $('.macro-count').textContent = `Saved workflows on this site: ${n}`;
      $('.macro-clear').style.display = n ? '' : 'none';
    } catch (_e) { $('.macro-count').textContent = 'Saved workflows: unavailable'; }
  }
  $('.macro-clear').addEventListener('click', async () => {
    try { await macros.clear(); } catch (_e) { /* ignore */ }
    refreshMacroInfo();
  });

  // Asks the user to re-enter a Tier-1 value (e.g. a password) the page
  // reload wiped from the in-memory vault. Resolves with the value, or null
  // if cancelled. The value is handed only to the caller (which puts it in
  // the vault); the input is cleared as soon as it is submitted.
  let pendingSecret = null;
  const closeSecret = (value) => {
    $('.secret').classList.remove('show');
    $('.secret-input').value = '';
    if (pendingSecret) { pendingSecret(value); pendingSecret = null; }
  };
  $('.secret-ok').addEventListener('click', () => closeSecret($('.secret-input').value || null));
  $('.secret-cancel').addEventListener('click', () => closeSecret(null));
  $('.secret-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') closeSecret($('.secret-input').value || null); });
  const requestSecret = (message) => {
    if (pendingSecret) pendingSecret(null); // superseded
    update({ open: true, minimized: false });
    $('.secret-msg').textContent = message;
    $('.secret').classList.add('show');
    setStatus('⏸ Waiting for you', 'run');
    return new Promise((resolve) => { pendingSecret = resolve; });
  };

  // --- window controls / links ---
  $('.min-btn').addEventListener('click', () => update({ minimized: !state.minimized }));
  $('.close-btn').addEventListener('click', () => update({ open: false }));
  $('.overlay-btn').addEventListener('click', () => update({ overlay: !state.overlay }));
  $('.macros-btn').addEventListener('click', () => update({ macros: !state.macros }));
  $('.dash-btn').addEventListener('click', () => {
    try { chromeApi.runtime.sendMessage({ type: 'OPEN_DASHBOARD' }, () => { void chromeApi.runtime.lastError; }); } catch (_e) { /* ignore */ }
  });

  // Fallback if the host page interferes with typing here: the popup page,
  // opened as a normal tab, has the same key field on a page we control.
  $('.settings-tab-btn').addEventListener('click', () => {
    try { chromeApi.runtime.sendMessage({ type: 'OPEN_SETTINGS' }, () => { void chromeApi.runtime.lastError; }); } catch (_e) { /* ignore */ }
  });

  // --- API key (same chrome.storage.local key the popup uses) ---
  const keyStatus = $('.key-status');
  const local = chromeApi && chromeApi.storage && chromeApi.storage.local;
  if (local) {
    Promise.resolve(local.get('backendApiKey')).then((r) => {
      if (r && r.backendApiKey) $('.key-input').value = r.backendApiKey;
      else { $('.settings').open = true; keyStatus.textContent = 'Not set — tasks will fail without this.'; }
    }).catch(() => {});
  }
  $('.save-key-btn').addEventListener('click', async () => {
    const value = $('.key-input').value.trim();
    if (!value) { keyStatus.textContent = 'Enter a key first'; return; }
    await local.set({ backendApiKey: value });
    keyStatus.textContent = '✓ Saved';
  });

  // --- visibility API used by the toolbar toggle and the capture path ---
  const toggle = () => update({ open: !state.open });
  const attach = () => { if (!host.isConnected) (doc.documentElement || doc).appendChild(host); };
  attach();
  // Re-attach the SAME host if a SPA/framework wipes it; never creates a second one.
  if (typeof win.MutationObserver === 'function' && doc.documentElement) {
    new win.MutationObserver(() => attach()).observe(doc.documentElement, { childList: true });
  }

  const frame = () => new Promise((resolve) => {
    const t = setTimeout(resolve, 100); // rAF never fires in a hidden tab; don't hang capture
    if (win.requestAnimationFrame) win.requestAnimationFrame(() => win.requestAnimationFrame(() => { clearTimeout(t); resolve(); }));
  });
  const api = {
    host, toggle, trackTask, submit, setStatus, showResult, requestSecret, offerWorkflow,
    getState: () => ({ ...state }),
    ready: null,
    async suspendForCapture() {
      if (!state.open) return;
      host.style.visibility = 'hidden';
      await frame();
    },
    resumeAfterCapture() { host.style.visibility = ''; },
  };
  win.__perceivePanel = api;

  if (chromeApi && chromeApi.runtime && chromeApi.runtime.onMessage) {
    chromeApi.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message && message.type === 'TOGGLE_PANEL') {
        toggle();
        sendResponse({ ok: true, open: state.open });
      }
    });
  }

  apply();
  api.ready = loadState(store).then((saved) => {
    if (touched) return;
    state = clampState(saved, win.innerWidth, win.innerHeight);
    apply();
  });
  return api;
}
