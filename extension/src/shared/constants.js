export const ACTION_TYPES = {
    CLICK: 'click',
    TYPE: 'type',
    SELECT_CUSTOM: 'select_custom',
    SCROLL: 'scroll',
    WAIT: 'wait',
    ASK_USER_CONFIRMATION: 'ask_user_confirmation',
    TASK_COMPLETE: 'task_complete',
    TASK_FAILED: 'task_failed'
};

export const RISK_TIERS = {
    SAFE: 'safe',
    RISKY: 'risky'
};

export const RETRY_CONFIG = {
    MAX_STEPS: 20,
    MAX_RETRIES_PER_STEP: 3,
    STEP_TIMEOUT_MS: 20000,
    POST_ACTION_DELAY_MS: 800,
    // Bug found live: a real false-positive face detection correctly
    // triggered dev2/channel-consistency-check.js's mismatch guard
    // (FIREWALL_BLOCK), which orchestrator.js retried — but with NO delay
    // before the retry's re-capture, unlike the success path above. Chrome's
    // own chrome.tabs.captureVisibleTab has an internal rate quota (~2
    // calls/second, i.e. captures need >=500ms apart to reliably succeed);
    // retrying instantly blew through that quota, and the resulting
    // capture_failed masked the real root cause entirely. Deliberately
    // LONGER than POST_ACTION_DELAY_MS (not just reused) for two reasons:
    // (1) POST_ACTION_DELAY_MS exists to let a successful action's page
    // transition settle, a different concern than clearing an external API
    // rate quota; (2) a failure retry may follow a burst of recent capture
    // attempts, not a single completed step, so extra margin beyond the
    // bare 500ms floor is warranted rather than just barely clearing it.
    POST_FAILURE_RETRY_DELAY_MS: 1500
};

// Separate from RETRY_CONFIG.STEP_TIMEOUT_MS deliberately, not just reused:
// STEP_TIMEOUT_MS bounds a simple background-worker IPC round trip
// (CAPTURE_TAB_STATE / END_SESSION — SEND_PAYLOAD has its own,
// SEND_PAYLOAD_TIMEOUT_MS, below), and its timeout is a hard step failure
// that consumes a retry. The vision/OCR pipeline (detectFaces/runOcr) is
// architecturally allowed to just fail open — see dev2/channel-consistency-
// check.js's union-only mergeSensitivityChannels(), which already treats an
// empty vision channel as "nothing to add", never as a mismatch — so a
// timeout here should degrade that ONE channel, not fail the step. It also
// covers a materially different, legitimately slower workload: cold-start
// model/WASM loading and first-run asset fetches (MediaPipe's .tflite model,
// Tesseract's eng.traineddata) rather than a same-origin extension message.
export const VISION_TIMEOUT_MS = 30000;

// Real bug found live: SEND_PAYLOAD was sharing RETRY_CONFIG.STEP_TIMEOUT_MS
// (20000ms) with CAPTURE_TAB_STATE — a fast local screenshot with no
// business ever legitimately approaching 20s. SEND_PAYLOAD is a REAL
// network round trip to the backend, which itself calls an LLM with up to
// a 12s timeout of its own, on top of which transport.js's
// sendToBackendWithRetry() layers its OWN retry/backoff policy — a single
// attempt has its own TIMEOUT_MS=30000 fetch-abort ceiling
// (background/transport.js), and a retryable error (429/502/503/504) adds
// backoffDelayMs() on top (up to ~650/1300/2600ms for the 1st/2nd/3rd
// retry). Sharing STEP_TIMEOUT_MS meant a perfectly healthy, still-working
// request was indistinguishable from a genuinely hung one at the 20s mark
// — surfacing as "No response to SEND_PAYLOAD after 20000ms" on nothing
// more than an ordinarily slow LLM response.
//
// Sized to comfortably clear the REALISTIC worst case, not the full
// pathological one (all 3 retries each independently timing out at their
// own 30s ceiling — that scenario sums to ~2 minutes and represents a
// backend that's genuinely failing, which SHOULD surface as an error
// rather than being silently absorbed into an ever-longer timeout).
// "Realistic worst case" here means: one attempt using its full 30s
// fetch-abort budget before succeeding (a single slow-but-real LLM
// response), OR one fast-failing retryable rejection + backoff (well under
// 3s) + a second attempt also using a good chunk of that 30s budget —
// both land in the 30-33s range. 45000ms clears either with real margin
// left over for message serialization/Chrome IPC overhead on top of the
// network time itself, without masking an actually-stuck request for
// anywhere near the multi-minute pathological case.
export const SEND_PAYLOAD_TIMEOUT_MS = 45000;

// Phase D.1b: demo-mode instrumentation, NOT a feature. When true, the
// background service worker (see demoCapture.js) persists the PRE-redaction
// ORIGINAL screenshot locally via chrome.downloads, purely for producing
// side-by-side before/after proof during a deliberate demo run. This must
// default to false in every shipped build — flip it only for a controlled
// local demo, never leave it on. See extension/tests/test-demo-capture.js
// for the regression test enforcing this default.
export const DEMO_MODE_ENABLED = false;
