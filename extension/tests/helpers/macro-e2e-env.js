// Shared harness for the macro end-to-end suites: the REAL orchestrator bundle
// (esbuild, in memory) running in jsdom. Test doubles: the scripted "server"
// (LLM + validation), the screenshot canvas, and the browser chrome.* APIs.
// The real Python server is covered by server/tests.
import { JSDOM } from 'jsdom';
import * as esbuild from 'esbuild';
import path from 'path';
import { fileURLToPath } from 'url';
import { webcrypto } from 'crypto';
import { createMacroStore } from '../../src/background/macroStore.js';
import { handleMacroMessage } from '../../src/background/macroMessages.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let bundleText = null;
export async function getBundle() {
  if (!bundleText) {
    const built = await esbuild.build({
      entryPoints: [path.join(__dirname, '..', '..', 'src', 'content', 'orchestrator.js')],
      bundle: true, write: false, format: 'iife', platform: 'browser', target: 'chrome109', logLevel: 'silent',
    });
    bundleText = built.outputFiles[0].text;
  }
  return bundleText;
}

export const EXT = 'ext-e2e';
export const ORIGIN = 'https://example.com';
export const LOGIN_HTML = `<main><form id="login-form" action="/session">
  <label for="user">Username</label><input id="user" name="username" type="text">
  <label for="pw">Password</label><input id="pw" name="password" type="password">
  <label for="city">City</label><select id="city" name="city"><option value="">Choose</option><option value="hyd">Hyderabad</option><option value="blr">Bangalore</option></select>
  <button id="signin" type="submit">Sign in</button></form></main>`;
export const DASH_HTML = '<h1>Dashboard city overview</h1><a href="/logout" id="logout">Log out</a>';
export const TASK = (u, p) => `log in with username '${u}' and password '${p}' then select Hyderabad from the city dropdown`;
export const SECRET1 = { user: 'jane_real_username', pw: 'S3cret-Real-Pass9' };
export const SECRET2 = { user: 'bob_real_username', pw: 'Bob-Other-Pass42' };

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- shared "browser profile"
export function newProfile() {
  const data = new Map();
  const storage = { data,
    async get(k) { const out = {}; for (const key of (Array.isArray(k) ? k : [k])) if (data.has(key)) out[key] = JSON.parse(JSON.stringify(data.get(key))); return out; },
    async set(o) { for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); },
    async remove(k) { for (const key of (Array.isArray(k) ? k : [k])) data.delete(key); } };
  return { storage, store: createMacroStore({ storage }), auditEvents: [] };
}

// ---------------------------------------------------------------- scripted server (LLM + validation double)
function llmPlan(payload) {
  const els = payload.dom_summary.elements;
  const byId = (id) => els.find((e) => e.element_id === id);
  const inst = payload.task_instruction;
  const tok = (re) => (re.exec(inst) || [null])[0];
  if (byId('user') && !byId('user').has_value) return { type: 'type', target_element_id: 'user', value: tok(/\[NAME_[a-z0-9]+\]/), reasoning_short: 'enter username' };
  if (byId('pw') && !byId('pw').has_value) return { type: 'type', target_element_id: 'pw', value: tok(/\[PASSWORD_[a-z0-9]+\]/), reasoning_short: 'enter password' };
  if (byId('city') && !byId('city').has_value) return { type: 'type', target_element_id: 'city', value: 'Hyderabad', reasoning_short: 'choose city' };
  if (byId('signin')) return { type: 'click', target_element_id: 'signin', reasoning_short: 'sign in' };
  return { type: 'task_complete', reasoning_short: 'done' };
}
function validate(payload, action) {                       // the JS stand-in for policy.assess_action / the PII guard
  const els = payload.dom_summary.elements;
  const target = action.target_element_id ? els.find((e) => e.element_id === action.target_element_id) : null;
  if (action.target_element_id && !target) return { reject: 422, why: 'target_not_in_page' };
  if (/^\[(PASSWORD|OTP|CARD_NUMBER|AADHAAR)_/.test(action.value || '') && !(target && target.is_sensitive)) return { reject: 422, why: 'tier1_token_into_non_sensitive_field' };
  const risky = !!(target && target.is_sensitive);
  return { action: { ...action, risk_tier: risky ? 'risky' : 'safe', risk_reasons: risky ? ['sensitive_target'] : [] } };
}

export const ALL_EVENTS = [];   // every reported event, across all environments (optionally dumped by the caller)

/**
 * One page + one content-script realm.
 * @param {object} profile   from newProfile()
 * @param {object} [o]
 * @param {boolean} [o.ui]   true: NOT test mode — the floating panel is mounted, RUN goes through the panel and the real
 *                           (non-fixture) native confirm() gates risky actions.
 * @param {(text:string)=>boolean} [o.confirmAnswer] answer for window.confirm dialogs (default: approve everything)
 */
export async function makeEnv(profile, { html = LOGIN_HTML, url = ORIGIN + '/login', llmLatencyMs = 0, serverHook = null, saveAnswer = true, ui = false, confirmAnswer = null } = {}) {
  const BUNDLE = await getBundle();
  const dom = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url, runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  const events = []; const confirms = []; const serverCalls = []; const stashes = [];
  Object.defineProperty(w, 'innerWidth', { value: 1000, configurable: true });
  Object.defineProperty(w, 'innerHeight', { value: 800, configurable: true });
  Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true });
  w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
  w.CSS = { escape: (x) => String(x).replace(/([^a-zA-Z0-9_-])/g, '\\$1') };
  w.Element.prototype.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, width: 100, height: 20, right: 100, bottom: 20 });
  w.HTMLCanvasElement.prototype.getContext = () => ({ drawImage() {}, fillRect() {}, getImageData: () => ({ data: new Uint8ClampedArray(4) }), clearRect() {} });
  w.HTMLCanvasElement.prototype.toDataURL = () => 'data:image/png;base64,AAAA';
  w.Worker = class { constructor() { throw new Error('no workers in jsdom'); } };       // OCR fails open, instantly
  w.Image = class { set src(_v) { setTimeout(() => { if (this.onload) this.onload(); }, 0); } };   // screenshot "decodes" instantly
  w.confirm = (text) => {
    confirms.push(text);
    if (confirmAnswer) return confirmAnswer(text);
    return /^Save workflow\?/.test(text) ? saveAnswer : true;
  };
  if (!ui) w.__PERCEIVE_TEST_MODE__ = true;

  const sender = () => ({ id: EXT, frameId: 0, tab: { id: 1, url: w.location.href }, url: w.location.href });
  const respond = async (msg) => {
    switch (msg.type) {
      case 'SEND_PAYLOAD': {
        const p = msg.payload;
        serverCalls.push({ proposed: !!p.proposed_action, step: p.step_number });
        if (serverHook) { const h = serverHook(p); if (h) return h; }
        let action;
        if (p.proposed_action) {
          action = { ...p.proposed_action, reasoning_short: `macro replay step ${p.replay.step_index + 1}/${p.replay.total_steps}` };
        } else {
          if (llmLatencyMs) await sleep(llmLatencyMs);
          action = llmPlan(p);
        }
        const v = validate(p, action);
        if (v.reject) return { success: false, error: `Server returned ${v.reject}: {"detail":"${v.why}"}` };
        // transport.js hands the orchestrator the WHOLE server response as `action`
        return { success: true, action: { session_id: p.session_id, step_number: p.step_number + 1, action: v.action, confidence: 0.9 } };
      }
      case 'CAPTURE_TAB_STATE': return { success: true, screenshotDataUrl: 'data:image/png;base64,AAAA' };
      case 'DETECT_FACES': return { success: true, faces: [] };
      case 'REPORT_PIPELINE_EVENT':
        events.push({ event: msg.eventType, details: msg.details, step: msg.stepNumber });
        ALL_EVENTS.push({ step_number: msg.stepNumber, event_type: msg.eventType, details: msg.details });
        profile.auditEvents.push(msg.eventType);
        return undefined;
      case 'STASH_RESUME_STATE': stashes.push(msg); return { success: true };
      case 'GET_RESUME_STATE': return { success: true, resumeState: null };
      case 'END_SESSION': return { success: true };
      default:
        if (typeof msg.type === 'string' && msg.type.startsWith('MACRO_')) return handleMacroMessage({ store: profile.store, sender: sender(), message: msg, extensionId: EXT });
        return { success: false, error: 'unhandled ' + msg.type };
    }
  };
  w.chrome = {
    runtime: {
      id: EXT, lastError: undefined, getURL: (x) => x,
      onMessage: { addListener() {} },
      sendMessage(msg, cb) { respond(msg).then((r) => { if (cb) cb(r); }, (e) => { if (cb) cb({ success: false, error: String(e && e.message) }); }); },
    },
    storage: { local: { get: async () => ({ backendApiKey: 'k' }), set: async () => {} }, session: { get: async () => ({}), set: async () => {}, remove: async () => {}, clear: async () => {} } },
  };
  const errors = [];
  w.addEventListener('error', (e) => errors.push(e.message));
  w.console.error = (...a) => { const m = a.map(String).join(' '); if (!/\[Vision\]|Not implemented/.test(m)) errors.push(m); };
  w.console.warn = () => {}; w.console.log = () => {}; w.console.info = () => {};

  const canvas = { width: 1000, height: 800, toDataURL: () => 'data:image/png;base64,AAAA', getContext: () => ({ getImageData: () => ({ data: new Uint8ClampedArray(4) }), drawImage() {} }) };
  const captureOverride = async () => ({ elements: Array.from(w.document.querySelectorAll('input, button, select, textarea, a[href]')), canvas });
  // sign-in: an in-page (SPA-style) navigation so a single JS realm can carry the whole task
  const b = w.document.getElementById('signin');
  if (b) b.addEventListener('click', (ev) => { ev.preventDefault(); dom.reconfigure({ url: ORIGIN + '/home' }); w.document.body.innerHTML = DASH_HTML; });
  const typed = [];
  w.document.addEventListener('input', (ev) => { typed.push([ev.target.id, ev.target.value]); }, true);
  w.document.addEventListener('change', (ev) => { typed.push([ev.target.id, ev.target.value]); }, true);
  w.eval(BUNDLE);

  const env = { dom, w, doc: w.document, events, confirms, serverCalls, errors, typed, stashes };
  // test mode: run the loop directly
  env.run = (task, options) => w.__runTaskLoop(task, captureOverride, null, options);

  // UI mode: drive the real floating panel
  if (ui) {
    const panel = w.__perceivePanel;
    const q = (sel) => panel.host.shadowRoot.querySelector(sel);
    env.panel = panel;
    env.q = q;
    env.status = () => q('.status').textContent;
    env.enableWorkflows = () => { if (!panel.getState().open) panel.toggle(); if (!panel.getState().macros) q('.macros-btn').click(); };
    env.submit = (task) => { q('.task').value = task; q('.run-btn').click(); };
    env.waitFor = async (pred, timeoutMs = 30000, label = 'condition') => {
      const end = Date.now() + timeoutMs;
      for (;;) { if (pred()) return; if (Date.now() > end) throw new Error(`timeout waiting for ${label}; status="${q('.status').textContent}"`); await sleep(25); }
    };
    env.finished = () => /^(✓|⚠)/.test(q('.status').textContent);
  }
  return env;
}
