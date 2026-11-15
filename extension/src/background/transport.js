console.log('transport.js loaded');
import { validateActionResponse } from '../shared/schemas.js';

import { assertSafeToSend } from '../../dev2/leakage-auditor.js';
import { assertChannelsConsistent } from '../../dev2/channel-consistency-check.js';
import { detectPII } from '../../dev2/pii-patterns.js';
import { captureTabState } from './captureService.js';
import { maybeSaveDemoScreenshot } from './demoCapture.js';
import { VISION_TIMEOUT_MS } from '../shared/constants.js';
import { createMacroStore, chromeLocalAdapter } from './macroStore.js';
import { handleMacroMessage, MACRO_MESSAGE_TYPES } from './macroMessages.js';

const BACKEND_URL = 'http://localhost:8000';
const ANALYZE_ENDPOINT = '/analyze';
const TIMEOUT_MS = 30000;

// --- Mid-task navigation resume ---
//
// The content script running orchestrator.js's task loop is destroyed
// outright when a click action navigates the page (a real native
// targetElement.click() — no cleanup hook is guaranteed to run before the
// JS realm is torn down). The freshly-injected content script on the new
// page has no memory of the task that was running. This in-memory Map,
// owned by the background service worker (which persists across a tab's
// navigation, unlike the content script), is how the new page's
// orchestrator.js learns "a task was mid-flight on this tab, resume it."
//
// Deliberately NOT chrome.storage: an in-memory Map here is simpler,
// requires no separate TTL-driven cleanup for "browser closed and reopened
// days later" (a killed/restarted service worker's Map is just gone, no
// stale entry to expire), and never puts task state where a storage
// inspector could see it at rest.
//
// Deliberately stores the ALREADY-TOKENIZED task instruction, never the
// raw one — orchestrator.js sends this right after a successful click,
// using payload.task_instruction (the string actually sent to the
// backend, post-tokenizeCredentialsInInstruction), not the raw
// taskInstruction closure variable. A raw credential must never sit here,
// even in memory, even briefly — same principle the token vault and
// Part 2's local-only value relay already follow. See orchestrator.js's
// resume branch for why this means the resumed run skips
// tokenizeCredentialsInInstruction()'s OTP/missing-credential gate.
//
// pendingTierTwoValues is the ONE deliberate, narrow exception to "never a
// raw value here": a Tier-2 value (phone/name/email/amount/ifsc — see
// dev2/sensitivity-tiers.js's TIER_2_TYPES) that's still referenced by the
// persisted instruction and whose token could otherwise never be resolved
// again by the resumed page's brand-new vault. TIER 1 (password/card/
// aadhaar/otp) values are NEVER included, by construction, in what
// orchestrator.js's extractPendingTierTwoValues() sends here — see that
// function's own header comment for the full reasoning; this file does
// not re-derive or re-check tiering itself, it only stores what it's
// given.
const resumeStateByTab = new Map(); // tabId -> { sessionId, taskInstruction, backendStepNumber, stepNumber, pendingTierTwoValues, macro, storedAt }
const RESUME_STATE_TTL_MS = 30 * 60 * 1000; // matches dev2/session-vault-manager.js's DEFAULT_SESSION_TTL_MS

// Run totals carried across a navigation (numbers only; anything else is dropped).
const METRIC_KEYS = ['llm_calls', 'plan_ms', 'replay_steps', 'replay_validate_ms', 'exec_ms', 'final_ms', 'total_ms'];
function sanitizeRunMetrics(m) {
    const src = m && typeof m === 'object' ? m : {};
    const out = {};
    for (const k of METRIC_KEYS) out[k] = typeof src[k] === 'number' && Number.isFinite(src[k]) && src[k] >= 0 && src[k] < 1e9 ? src[k] : 0;
    return out;
}

// Task macros (durable workflows). Storage + validation live HERE, in the
// background worker; content scripts reach them only through MACRO_* messages,
// and the origin is always derived from the message sender (macroMessages.js).
let macroStore = null;
function getMacroStore() {
    if (macroStore) return macroStore;
    const storage = chromeLocalAdapter();
    macroStore = storage ? createMacroStore({ storage }) : null;
    return macroStore;
}

async function getBackendApiKey() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
        return null; // test harness / non-extension context
    }
    const result = await chrome.storage.local.get('backendApiKey');
    return result.backendApiKey || null;
}

class PayloadLeakageError extends Error {
    constructor(message) {
        super(message);
        this.name = "PayloadLeakageError";
    }
}

class TransportError extends Error {
    constructor(message) {
        super(message);
        this.name = "TransportError";
    }
}

// Phase D.2: best-effort, fire-and-forget report of a pipeline event that
// happens purely client-side and would otherwise never reach the server's
// hash-chained audit log at all (see server/app/main.py's
// ALLOWED_CLIENT_EVENT_TYPES for why only these two events use this path).
// Must never throw into the caller and must never block/delay it — a
// failure to report an audit event is not allowed to affect the real
// pipeline (same "best-effort, swallow failures" discipline as
// demoCapture.js and artifact_store.py).
export async function reportPipelineEvent(sessionId, stepNumber, eventType, details) {
    try {
        const apiKey = await getBackendApiKey();
        if (!apiKey) return;
        await fetch(`${BACKEND_URL}/session/${sessionId}/event`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
            body: JSON.stringify({ step_number: stepNumber, event_type: eventType, details: details || null }),
        });
    } catch (e) {
        console.warn(`[Transport] Failed to report pipeline event ${eventType} (non-fatal):`, e);
    }
}

/**
 * Sends sanitized payload to backend and returns action response.
 */
export async function sendToBackend(payload) {
    try {
      assertSafeToSend(payload, detectPII);
      if (payload.redacted_regions) {
        assertChannelsConsistent(payload, payload.redacted_regions);
      }
    } catch (err) {
      // The blocked payload never reaches /analyze, so this is the ONLY
      // place this violation can ever be recorded — report it (fire and
      // forget) before throwing so the caller's control flow is unchanged.
      reportPipelineEvent(payload.session_id, payload.step_number, 'FIREWALL_BLOCK', { reason: err.message });
      throw new PayloadLeakageError(err.message);
    }

    const jsonString = JSON.stringify(payload);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const apiKey = await getBackendApiKey();
        if (!apiKey) {
            console.error('[Transport] No backend API key configured \u2014 set one via the extension options page');
            throw new TransportError('No backend API key configured');
        }

        const response = await fetch(`${BACKEND_URL}${ANALYZE_ENDPOINT}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
            body: jsonString,
            signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            let errorDetail = '';
            try {
                const errorBody = await response.json();
                errorDetail = JSON.stringify(errorBody);
            } catch (e) {
                errorDetail = await response.text().catch(() => '(could not read error body)');
            }
            console.error('[Transport] Backend rejected request:', response.status, errorDetail);
            throw new TransportError(`Server returned ${response.status}: ${errorDetail}`);
        }

        const actionResponse = await response.json();
        
        // Schema validation
        validateActionResponse(actionResponse, payload.session_id, payload.step_number);  
        
        return actionResponse;
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            throw new TransportError('Request timed out');
        }
        throw err;
    }
}

// --- Phase 5.2: multi-tab/frame session binding ---
//
// Everything reaching this background service worker arrives via
// chrome.runtime.onMessage, which is global across every tab/frame the
// content script runs in — nothing previously stopped a message CLAIMING
// to be for session X from actually being processed regardless of which
// tab/frame it came from. This binds each session_id to the (tabId,
// frameId) that first used it, and rejects anything else claiming that
// session afterwards.
const sessionContext = new Map(); // session_id -> { tabId, frameId, networkBudget: { remaining } }

const MAX_TASK_NETWORK_RETRIES = 8; // Phase 5.3: task-level ceiling, shared across every step's retries

function bindOrVerifySessionContext(sessionId, sender) {
  const senderTabId = sender && sender.tab ? sender.tab.id : undefined;
  const senderFrameId = sender ? sender.frameId : undefined;

  const existing = sessionContext.get(sessionId);
  if (!existing) {
    sessionContext.set(sessionId, {
      tabId: senderTabId,
      frameId: senderFrameId,
      networkBudget: { remaining: MAX_TASK_NETWORK_RETRIES },
    });
    return { ok: true, budget: sessionContext.get(sessionId).networkBudget };
  }

  if (existing.tabId !== senderTabId || existing.frameId !== senderFrameId) {
    return { ok: false };
  }
  return { ok: true, budget: existing.networkBudget };
}

// --- Phase 5.3: network/provider resilience ---
//
// Distinct from the server's own hallucination-retry loop (main.py retries
// malformed LLM JSON up to MAX_RETRIES with no client involvement at all).
// This handles transient PROVIDER/NETWORK failures the client can see —
// the server returning 429 (rate limited) or, if ever fronted by a proxy,
// 502/503/504 — with bounded exponential backoff and jitter, instead of
// the previous behavior of immediately looping again with zero delay.
const RETRYABLE_STATUS_CODES = [429, 502, 503, 504];
const MAX_NETWORK_RETRIES_PER_STEP = 3;
const BASE_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 8000;

function parseStatusCodeFromTransportError(err) {
  const match = /Server returned (\d+)/.exec(err && err.message || '');
  return match ? parseInt(match[1], 10) : null;
}

function backoffDelayMs(attempt) {
  const exp = Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
  return exp + Math.random() * exp * 0.3; // + up to 30% jitter
}

/**
 * Wraps sendToBackend with bounded exponential backoff + jitter for
 * retryable provider errors, gated by a shared per-task budget in addition
 * to this call's own per-step cap — whichever runs out first stops retrying.
 * @param {object} payload
 * @param {{ remaining: number }} [taskBudget] - shared across a session's steps
 */
export async function sendToBackendWithRetry(payload, taskBudget) {
  let attempt = 0;
  for (;;) {
    try {
      return await sendToBackend(payload);
    } catch (err) {
      const status = err instanceof TransportError ? parseStatusCodeFromTransportError(err) : null;
      const retryable = RETRYABLE_STATUS_CODES.includes(status);
      const taskBudgetLeft = taskBudget ? taskBudget.remaining : 0;

      if (!retryable || attempt >= MAX_NETWORK_RETRIES_PER_STEP || taskBudgetLeft <= 0) {
        throw err;
      }

      if (taskBudget) taskBudget.remaining--;
      const delayMs = backoffDelayMs(attempt);
      attempt++;
      console.warn(`[Transport] Retryable provider error (${status}) — backing off ${Math.round(delayMs)}ms (attempt ${attempt}/${MAX_NETWORK_RETRIES_PER_STEP}, task budget ${taskBudgetLeft - 1} left)`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

// --- Face detection: worker owned by an OFFSCREEN DOCUMENT ---
//
// Two real, empirically-found bugs shaped this, in order:
//
// 1. Spawning `new Worker(chrome-extension://.../faceDetectionWorker.bundle.js)`
//    directly from a content script broke on a real, security-conscious site
//    (observed live on leetcode.com):
//      SecurityError: Failed to construct 'Worker': Script at
//      'chrome-extension://.../faceDetectionWorker.bundle.js' cannot be
//      accessed from origin 'https://leetcode.com'.
//    This is the HOST PAGE's own CSP (worker-src) rejecting a cross-origin
//    worker script — independent of manifest.json's web_accessible_resources,
//    which only controls whether the extension PERMITS the resource to be
//    fetched, not whether the page's own CSP allows constructing a Worker
//    from it. This is what motivated moving worker ownership OUT of the
//    content script.
//
// 2. Moving it into THIS file (the background service worker) instead was
//    also wrong, found in later live Chrome testing: Chrome does not support
//    creating a dedicated Worker from within a Service Worker context AT
//    ALL — `new Worker(...)` here throws `ReferenceError: Worker is not
//    defined` synchronously. (manifest.json declares this service worker as
//    `"type": "module"`, but the restriction is on Service Workers spawning
//    Workers in general, not specific to module-type ones.) That failure was
//    silently swallowed by detectFaces()'s own fail-open catch in
//    visionPipeline.js, so face detection ran with zero faces detected on
//    every single page, with no visible error apart from a console log in
//    the CONTENT SCRIPT's console (where that catch block executes) reading
//    "Worker is not defined" — which is easy to misread as a content-script
//    bug when the actual throw happened here.
//
// The fix: a chrome.offscreen document (src/background/offscreen.html +
// offscreenFaceDetection.js) is a real window/DOM context — unlike a
// service worker, it CAN spawn a classic Worker — and it lives at the
// extension's own chrome-extension:// origin, so it is never subject to any
// host page's CSP like a content script is. This file's job shrinks to:
// ensure that document exists, then relay the request to it and forward its
// response back exactly as it did when it owned the worker directly, so
// visionPipeline.js's DETECT_FACES contract is unchanged.
const OFFSCREEN_DOCUMENT_URL = 'src/background/offscreen.html';
let creatingOffscreenDocument = null;

async function ensureOffscreenDocument() {
    if (await chrome.offscreen.hasDocument()) return;

    if (creatingOffscreenDocument) {
        await creatingOffscreenDocument;
        return;
    }

    creatingOffscreenDocument = chrome.offscreen.createDocument({
        url: OFFSCREEN_DOCUMENT_URL,
        reasons: ['WORKERS'],
        justification: 'Service workers cannot spawn a dedicated Worker; MediaPipe face detection needs a real window/DOM context to run its classic Worker.',
    });
    try {
        await creatingOffscreenDocument;
    } finally {
        creatingOffscreenDocument = null;
    }
}

// Raced against VISION_TIMEOUT_MS, covering BOTH ensureOffscreenDocument()
// (document creation can itself stall) and the OFFSCREEN_DETECT_FACES round
// trip (the offscreen doc's own worker/model load can stall) as one budget —
// the offscreen-document lifecycle logic in ensureOffscreenDocument() itself
// is unchanged. Same settled-flag pattern as orchestrator.js's
// sendMessageAsync (9.5.4): a late-arriving response after timeout is a
// no-op, and the timer is cleared on normal resolution.
function detectFacesInBackground(width, height, pixels, config) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const timeoutId = setTimeout(() => {
            if (settled) return;
            settled = true;
            reject(new Error(`OFFSCREEN_DETECT_FACES timed out after ${VISION_TIMEOUT_MS}ms`));
        }, VISION_TIMEOUT_MS);

        (async () => {
            await ensureOffscreenDocument();
            if (settled) return; // timed out while the offscreen document was being created

            chrome.runtime.sendMessage(
                { type: 'OFFSCREEN_DETECT_FACES', width, height, pixels, config },
                (response) => {
                    if (settled) return; // already timed out — ignore a late-arriving response
                    settled = true;
                    clearTimeout(timeoutId);
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                        return;
                    }
                    if (!response || !response.success) {
                        reject(new Error((response && response.error) || 'Offscreen face detection failed'));
                        return;
                    }
                    // Phase B.5: latency_ms (real per-fixture timing, e.g. for
                    // the Step 2 union-of-two-models case) passed through
                    // alongside faces when the caller requested it via config.
                    if (response.latency_ms !== undefined || response.config_actually_applied !== undefined) {
                        resolve({ faces: response.faces || [], latency_ms: response.latency_ms, config_actually_applied: response.config_actually_applied });
                    } else {
                        resolve(response.faces || []);
                    }
                }
            );
        })().catch((err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timeoutId);
            reject(err);
        });
    });
}

/**
 * Sends a fire-and-forget POST to /session/{sessionId}/end in the background.
 */
async function endSessionOnBackend(sessionId, reason) {
    try {
        const apiKey = await getBackendApiKey();
        if (!apiKey) {
            console.error('[Transport] No backend API key configured \u2014 set one via the extension options page');
            return;
        }

        const response = await fetch(`${BACKEND_URL}/session/${sessionId}/end`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
            body: JSON.stringify({ reason }),
        });
        if (!response.ok) {
            console.warn('[Transport] END_SESSION backend call failed:', response.status);
        }
    } catch (err) {
        console.warn('[Transport] END_SESSION fetch error:', err.message);
    }
}

// Background script message listener for passing messages from content script
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'SEND_PAYLOAD') {
          const sessionId = message.payload && message.payload.session_id;
          const binding = bindOrVerifySessionContext(sessionId, sender);

          if (!binding.ok) {
              // Phase 5.2: a message claiming an existing session_id from a
              // DIFFERENT tab/frame than the one that started it is rejected
              // outright — never forwarded to the backend at all.
              console.error(`[Transport] Rejected SEND_PAYLOAD for session ${sessionId}: sender tab/frame does not match the session's bound context`);
              sendResponse({ success: false, error: 'session_context_mismatch', errorType: 'SessionContextError' });
              return true;
          }

          sendToBackendWithRetry(message.payload, binding.budget)
              .then(action => {
                  sendResponse({ success: true, action });
              })
              .catch(error => {
                  sendResponse({ success: false, error: error.message, errorType: error.name });
              });
          return true; // Keep message channel open for async response
      }

      if (message.type === 'REPORT_PIPELINE_EVENT') {
          // Fire-and-forget from the content script's perspective: don't
          // keep the message channel open waiting on the network call, and
          // never let a reporting failure surface to the caller.
          reportPipelineEvent(message.sessionId, message.stepNumber, message.eventType, message.details);
          return false;
      }

      if (message.type === 'CAPTURE_TAB_STATE') {
          const tabId = sender && sender.tab ? sender.tab.id : undefined;
          const windowId = sender && sender.tab ? sender.tab.windowId : undefined;
          captureTabState(tabId, windowId)
              .then(result => {
                  if (result.success) {
                      // Best-effort, gated by DEMO_MODE_ENABLED (default off)
                      // inside demoCapture.js — never blocks or affects the
                      // response either way.
                      maybeSaveDemoScreenshot(message.sessionId, message.stepNumber, result.screenshotDataUrl)
                          .catch(() => { /* already logged inside demoCapture.js */ });
                  }
                  sendResponse(result);
              })
              .catch(error => sendResponse({ success: false, error: error.message }));
          return true; // Keep message channel open for async response
      }

      if (message.type === 'DETECT_FACES') {
          detectFacesInBackground(message.width, message.height, message.pixels, message.config)
              .then(result => {
                  // Phase B.5: detectFacesInBackground() resolves a plain
                  // faces array normally, or { faces, latency_ms } when
                  // latency was requested/returned — normalize both shapes
                  // into one response object rather than double-wrapping.
                  const isLatencyShape = result && !Array.isArray(result) && 'faces' in result;
                  sendResponse(isLatencyShape ? { success: true, ...result } : { success: true, faces: result });
              })
              .catch(error => {
                  sendResponse({ success: false, error: error.message });
              });
          return true; // Keep message channel open for async response
      }

      if (message.type === 'STASH_RESUME_STATE') {
          const tabId = sender && sender.tab ? sender.tab.id : undefined;
          if (tabId === undefined) {
              // No real tab (e.g. the plain-webpage test harness has no
              // chrome.tabs at all) — nothing meaningful to key this by.
              sendResponse({ success: false, error: 'no_tab_id' });
              return false;
          }
          resumeStateByTab.set(tabId, {
              sessionId: message.sessionId,
              taskInstruction: message.taskInstruction,
              backendStepNumber: message.backendStepNumber,
              stepNumber: message.stepNumber,
              // Tier-2-only pending vault values (see orchestrator.js's
              // extractPendingTierTwoValues) — same Map, same one-shot/TTL
              // rules as every other field here; no new storage location.
              pendingTierTwoValues: Array.isArray(message.pendingTierTwoValues) ? message.pendingTierTwoValues : [],
              // Macro recording/replay state (see macro/session.js toResume): indexes and hashes only,
              // held in this in-memory Map like everything else here. Bounded; anything else is dropped.
              macro: message.macro && typeof message.macro === 'object' && JSON.stringify(message.macro).length <= 60 * 1024 ? message.macro : null,
              metrics: sanitizeRunMetrics(message.metrics),
              storedAt: Date.now(),
          });
          sendResponse({ success: true });
          return false;
      }

      if (message.type === 'GET_RESUME_STATE') {
          const tabId = sender && sender.tab ? sender.tab.id : undefined;
          if (tabId === undefined) {
              sendResponse({ success: true, resumeState: null });
              return false;
          }

          // One-shot: delete on read, unconditionally, regardless of
          // whether the caller goes on to use it successfully. A second
          // GET_RESUME_STATE for the same tab (e.g. an unrelated later
          // navigation) must never resurface the same record — a stale
          // resume silently reappearing is a worse failure mode than a
          // resume occasionally not firing when it theoretically could.
          const record = resumeStateByTab.get(tabId);
          resumeStateByTab.delete(tabId);

          if (!record) {
              sendResponse({ success: true, resumeState: null });
              return false;
          }

          if (Date.now() - record.storedAt > RESUME_STATE_TTL_MS) {
              sendResponse({ success: true, resumeState: null });
              return false;
          }

          sendResponse({ success: true, resumeState: record });
          return false;
      }

      if (message.type === 'OPEN_DASHBOARD') {
          chrome.tabs.create({ url: chrome.runtime.getURL('src/panel/auditDashboard.html') });
          sendResponse({ success: true });
          return false;
      }

      if (typeof message.type === 'string' && MACRO_MESSAGE_TYPES.has(message.type)) {
          handleMacroMessage({ store: getMacroStore(), sender, message, extensionId: chrome.runtime.id })
              .then(sendResponse)
              .catch(() => sendResponse({ ok: false, error: 'internal_error' }));
          return true; // async response
      }

      if (message.type === 'OPEN_SETTINGS') {
          chrome.tabs.create({ url: chrome.runtime.getURL('src/popup/popup.html') });
          sendResponse({ success: true });
          return false;
      }

      if (message.type === 'END_SESSION') {
          sessionContext.delete(message.sessionId);
          endSessionOnBackend(message.sessionId, message.reason)
              .then(() => {
                  sendResponse({ success: true });
              })
              .catch(error => {
                  sendResponse({ success: false, error: error.message });
              });
          return true; // Keep message channel open for async response
      }
  });
}

// Phase 5.3: teardown-on-tab-destruction. If a tab closes mid-task, its
// content-script JS realm (and the in-memory token vault living there) is
// already torn down by the browser automatically — but this background
// service worker's OWN bookkeeping (the session binding + retry budget
// above) is not, and would otherwise leak or go stale. Local cleanup here
// is unconditional and synchronous; the best-effort backend notification
// is fire-and-forget and never gates it.
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((closedTabId) => {
    for (const [sessionId, ctx] of sessionContext.entries()) {
      if (ctx.tabId === closedTabId) {
        sessionContext.delete(sessionId);
        endSessionOnBackend(sessionId, 'tab_destroyed').catch(() => {
          // Local state above is already cleared regardless of this outcome.
        });
      }
    }
    // A closed tab can never come back to consume its own resume state.
    resumeStateByTab.delete(closedTabId);
  });
}

// --- Toolbar icon = toggle for the in-page panel ---
//
// manifest.json declares no default_popup, so action.onClicked fires. If the
// content script can't answer (restricted pages like chrome://, the Web
// Store, PDF viewer, or a tab opened before the extension loaded) we fall
// back to the classic popup, which owns the error explanation for those
// cases. The popup is set only for the duration of openPopup() so the next
// click toggles the panel again.
const POPUP_PATH = 'src/popup/popup.html';

async function openFallbackPopup() {
  try {
    await chrome.action.setPopup({ popup: POPUP_PATH });
    await chrome.action.openPopup();
  } catch (e) {
    console.warn('[Transport] Could not open fallback popup:', e && e.message);
  } finally {
    chrome.action.setPopup({ popup: '' }).catch(() => {});
  }
}

if (typeof chrome !== 'undefined' && chrome.action && chrome.action.onClicked) {
  // Lets content scripts use chrome.storage.session (panel geometry).
  if (chrome.storage && chrome.storage.session && chrome.storage.session.setAccessLevel) {
    chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }).catch(() => {});
  }
  chrome.action.onClicked.addListener((tab) => {
    if (!tab || tab.id === undefined) { openFallbackPopup(); return; }
    chrome.tabs.sendMessage(tab.id, { type: 'TOGGLE_PANEL' }, (response) => {
      if (chrome.runtime.lastError || !response || !response.ok) openFallbackPopup();
    });
  });
}
