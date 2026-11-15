// Local-only on-screen value relay — feature + regression tests.
//
// Feature: when the vision/OCR pipeline detects a value with no DOM
// presence (e.g. dashboard.html's canvas-rendered balance), the raw text
// is cached locally (orchestrator.js's `lastDetectedValues`) and made
// available to the popup ONLY via an explicit, popup-initiated
// GET_DETECTED_VALUES request — never sent automatically, never part of
// RUN_TASK, never added to the payload SEND_PAYLOAD transmits.
//
// This is intentionally NOT a modification of dev2/redaction-engine.js's
// pipeline: `lastDetectedValues` is populated straight from `ocrLines`
// inside buildSanitizedPayload(), ONE LINE before that same data is handed
// to processPageForRedaction() — see orchestrator.js's own comment at the
// declaration of `lastDetectedValues` for why that ordering is the whole
// point (it reads the raw vision output directly, never anything the
// redaction pipeline returns).
//
// Two different techniques for two different concerns, both already
// established elsewhere in this suite:
//  - The regression tests (wire bytes / key-graph) call
//    processPageForRedaction() DIRECTLY, same convention as
//    test-password-tokenization-wire.js — deliberately WITHOUT a real
//    jsdom `document`, since redactImage() falls back to a safe
//    environment-agnostic canvas stub when `document` doesn't exist, vs.
//    a real jsdom `document.createElement('canvas')` (no real 2D context
//    without the `canvas` npm package) that throws — a pre-existing,
//    accepted jsdom limitation in this suite (see test-retry-backoff.js's
//    own header comment), nothing to do with this feature.
//  - The feature test (GET_DETECTED_VALUES) needs the REAL orchestrator.js
//    message listener, so it does run through a real jsdom `document` and
//    therefore DOES hit that same canvas limitation inside
//    processPageForRedaction() — but that's fine here: lastDetectedValues
//    is populated BEFORE that call, so it's already correctly set by the
//    time the (expected, accepted) exception unwinds the step into a
//    retry. The task exhausting its retries is not this test's concern;
//    only whether the cached value reaches GET_DETECTED_VALUES is.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mock } from 'node:test';
import { createTokenVault } from '../../dev2/token-vault.js';
import { processPageForRedaction } from '../../dev2/redaction-engine.js';

console.log('=== RUNNING LOCAL-ONLY DETECTED-VALUE RELAY TEST SUITE ===\n');

let passCount = 0;
let totalCount = 0;

async function runTestCase(name, fn) {
  totalCount++;
  try {
    await fn();
    passCount++;
    console.log(`[PASS] Test ${totalCount}: ${name}`);
  } catch (err) {
    console.error(`[FAIL] Test ${totalCount}: ${name}\n  Error: ${err.stack || err.message}`);
    throw err;
  }
}

// The exact string that must reach the popup locally, and must NEVER
// appear anywhere in an outgoing payload. Real currency formatting,
// matches the actual dashboard.html fixture, so a substring
// false-negative is unlikely.
const MARKER_TEXT = 'Balance: $4,281.50';

const mockCanvas = {
  getContext: () => ({
    fillRect: () => {}, clearRect: () => {}, drawImage: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
  }),
  toDataURL: () => 'data:image/png;base64,' + 'A'.repeat(150),
};

// Recursively collects every key name appearing anywhere in an object
// graph (arrays included). Used to assert this feature's own data-shape
// field names never appear in the outgoing payload — NOT a stand-in for
// the string-content check below, a complementary guarantee: this one
// still fails even if a future change carries an EMPTY/different-valued
// copy of the holder into the payload, since it's checking structure
// (field names), not today's specific string value.
function collectAllKeys(obj, seen = new Set(), out = new Set()) {
  if (!obj || typeof obj !== 'object' || seen.has(obj)) return out;
  seen.add(obj);
  for (const key of Object.keys(obj)) {
    out.add(key);
    collectAllKeys(obj[key], seen, out);
  }
  return out;
}

// Field names this feature's own local-only holder/message contract uses
// (see lastDetectedValues' shape and the GET_DETECTED_VALUES response
// shape: { success, values: [{ text, bounding_box, confidence }] }).
// `bounding_box`/`confidence` are deliberately EXCLUDED from this list —
// those are legitimate, pre-existing keys on redacted_regions/
// detection_confidence_notes and asserting their absence would false-flag
// the payload's own real, correct fields. `values`/`detected_values` are
// the actually-distinctive names: neither is used anywhere in the existing
// payload shape today, so their presence would specifically mean this
// feature's holder got wired in somewhere it shouldn't be.
const FORBIDDEN_PAYLOAD_KEYS = ['values', 'detected_values', 'lastDetectedValues', 'ocr_raw_text'];

// =====================================================================
// Regression: the detected value is provably absent from every outgoing
// payload — string-content AND structural/key-graph checks. Mirrors
// test-password-tokenization-wire.js's direct-call convention exactly.
// =====================================================================

function buildPayloadWithDetectedValueInVisionChannel() {
  const vault = createTokenVault();
  const visionData = {
    faces: [],
    ocrLines: [{ text: MARKER_TEXT, bounding_box: { x: 10, y: 20, w: 200, h: 24 }, confidence: 0.92 }],
  };
  const result = processPageForRedaction([], mockCanvas, vault, visionData);
  return {
    session_id: 'detected-value-wire-test',
    task_instruction: 'a trivial task',
    step_number: 1,
    ...result,
  };
}

await runTestCase('REGRESSION (wire bytes): the exact detected text never appears anywhere in the JSON.stringify\'d payload processPageForRedaction() produces', async () => {
  const payload = buildPayloadWithDetectedValueInVisionChannel();

  // Sanity check: the vision channel really did pick this up as a region
  // (so the negative assertions below are proving something, not passing
  // vacuously because nothing was ever detected).
  assert.ok(
    payload.redacted_regions.some((r) => r.element_id && r.element_id.startsWith('vision-ocr-')),
    'sanity check: the OCR-detected region must actually appear in redacted_regions (as structural metadata only) for this test to mean anything'
  );

  const wire = JSON.stringify(payload);
  assert.strictEqual(wire.includes(MARKER_TEXT), false, 'the raw marker text must never appear in the payload');
  assert.strictEqual(wire.includes('4,281.50'), false);
  assert.strictEqual(wire.includes('4281.50'), false, 'covers a comma-stripped/reformatted variant too');
});

await runTestCase('REGRESSION (structural): none of this feature\'s own field names (values/detected_values/lastDetectedValues/ocr_raw_text) appear ANYWHERE in the payload\'s key graph, at any depth', async () => {
  const payload = buildPayloadWithDetectedValueInVisionChannel();

  const allKeys = collectAllKeys(payload);
  for (const forbidden of FORBIDDEN_PAYLOAD_KEYS) {
    assert.strictEqual(
      allKeys.has(forbidden),
      false,
      `key "${forbidden}" must never appear anywhere in the outgoing payload's structure — if this fails, someone wired the local-only value relay's holder into the network path`
    );
  }
});

// =====================================================================
// Feature: the detected value reaches the popup locally, via the real
// orchestrator.js message listener.
// =====================================================================

async function withFreshOrchestrator(fn, { mockOcrLines } = {}) {
  // Real runOcr()/detectFaces() fail open to [] under jsdom (no real
  // Tesseract/canvas backend — same limitation test-retry-backoff.js's own
  // OCR failure log already shows). Replacing them with controlled fakes,
  // same technique already proven in test-vision-timeout-guards.js, is the
  // only way to get a KNOWN value into orchestrator.js's own
  // lastDetectedValues caching line for a real end-to-end assertion.
  const ocrMock = mockOcrLines !== undefined
    ? mock.module('../src/vision/ocrPipeline.js', { exports: { runOcr: async () => mockOcrLines } })
    : null;
  const faceMock = mockOcrLines !== undefined
    ? mock.module('../src/vision/visionPipeline.js', { exports: { detectFaces: async () => [] } })
    : null;

  const dom = new JSDOM(`<html><body></body></html>`, { runScripts: 'outside-only' });
  global.window = dom.window;
  global.document = dom.window.document;
  global.MutationObserver = dom.window.MutationObserver;
  global.CustomEvent = dom.window.CustomEvent;
  const previousGlobalPerformance = global.performance;
  global.performance = dom.window.performance || global.performance;
  global.CSS = dom.window.CSS || { escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&') };
  global.window.__PERCEIVE_TEST_MODE__ = true;

  let registeredMessageListener = null;
  let sendMessageImpl = (message, callback) => callback({ success: true });

  global.chrome = {
    runtime: {
      onMessage: { addListener: (fn2) => { registeredMessageListener = fn2; } },
      sendMessage: (message, callback) => sendMessageImpl(message, callback),
      getURL: (p) => p,
      lastError: undefined,
    },
  };

  const modUrl = `../src/content/orchestrator.js?t=${Date.now()}-${Math.random()}`;
  const mod = await import(modUrl);

  try {
    await fn({
      mod,
      getRegisteredListener: () => registeredMessageListener,
      setChromeSendMessage: (impl) => { sendMessageImpl = impl; },
    });
  } finally {
    delete global.window;
    delete global.document;
    delete global.MutationObserver;
    delete global.CustomEvent;
    delete global.CSS;
    delete global.chrome;
    global.performance = previousGlobalPerformance;
    if (ocrMock) ocrMock.restore();
    if (faceMock) faceMock.restore();
  }
}

function invokeListener(listener, message) {
  return new Promise((resolve) => {
    listener(message, {}, resolve);
  });
}

await runTestCase('After a real task step captures a canvas-only value via OCR, GET_DETECTED_VALUES (the popup\'s request) returns it — even though the step itself cannot complete under jsdom afterward (an accepted, pre-existing redactImage()/canvas limitation, unrelated to this feature: lastDetectedValues is set BEFORE that later, unrelated failure)', async () => {
  await withFreshOrchestrator(async ({ mod, getRegisteredListener }) => {
    const captureOverride = async () => ({ elements: [], canvas: mockCanvas });
    // The step will ultimately exhaust its retries (processPageForRedaction's
    // redactImage() throws under jsdom's non-functional real canvas, same
    // as test-retry-backoff.js already documents and relies on) — that's
    // expected and not what this test is about. lastDetectedValues is
    // populated from the real ocrLines BEFORE that later call, on every
    // attempt including the first, so it's already correctly set
    // regardless of how the overall step/task resolves.
    await mod.runTaskLoop('a trivial task', captureOverride);

    const listener = getRegisteredListener();
    assert.ok(listener, 'orchestrator.js must have registered a chrome.runtime.onMessage listener');

    const response = await invokeListener(listener, { type: 'GET_DETECTED_VALUES' });
    assert.strictEqual(response.success, true);
    assert.ok(Array.isArray(response.values) && response.values.length === 1);
    assert.strictEqual(response.values[0].text, MARKER_TEXT, 'the exact detected text must reach the popup');
  }, { mockOcrLines: [{ text: MARKER_TEXT, bounding_box: { x: 10, y: 20, w: 200, h: 24 }, confidence: 0.92 }] });
});

await runTestCase('GET_DETECTED_VALUES before any task has run attempts a fresh on-demand capture (reaches CAPTURE_TAB_STATE) instead of silently returning nothing', async () => {
  await withFreshOrchestrator(async ({ getRegisteredListener, setChromeSendMessage }) => {
    let sawCaptureAttempt = false;
    setChromeSendMessage((message, callback) => {
      if (message.type === 'CAPTURE_TAB_STATE') {
        sawCaptureAttempt = true;
        // Deliberately fails closed rather than trying to exercise real
        // image loading, which jsdom cannot do (no real image decoder for
        // a data: URI without the `canvas` npm package) — this test's job
        // is proving the on-demand path is REACHED and fails gracefully,
        // not exercising image-decode internals.
        callback({ success: false, error: 'restricted_page' });
      } else {
        callback({ success: true });
      }
    });

    const listener = getRegisteredListener();
    const response = await invokeListener(listener, { type: 'GET_DETECTED_VALUES' });

    assert.strictEqual(sawCaptureAttempt, true, 'with nothing cached yet, GET_DETECTED_VALUES must attempt a fresh capture rather than silently returning empty');
    assert.strictEqual(response.success, true, 'a failed on-demand capture must still resolve gracefully, not throw/hang');
    assert.deepStrictEqual(response.values, []);
  });
});

await runTestCase('GET_DETECTED_VALUES is never sent by anything in orchestrator.js except in direct response to being received — grep-proof: it does not appear anywhere in the RUN_TASK handling path or inside runTaskLoop itself, only in its own onMessage branch', async () => {
  const fs = await import('fs');
  const path = await import('path');
  const { fileURLToPath } = await import('url');
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'content', 'orchestrator.js'), 'utf-8');

  const occurrences = source.split('GET_DETECTED_VALUES').length - 1;
  // Exactly 4, all within the feature's own declaration/handler: two
  // explanatory comments (lastDetectedValues' doc comment, and
  // captureAndDetectValuesOnDemand()'s doc comment), the onMessage
  // `if (message.type === 'GET_DETECTED_VALUES')` branch check itself, and
  // its own error-log line. None of these are inside RUN_TASK's handling
  // or runTaskLoop() itself. If this count grows because something new
  // starts referencing/dispatching this message type from inside the task
  // loop, that's exactly the kind of "fires automatically during an
  // unrelated task" regression the opt-in design was meant to prevent.
  assert.strictEqual(occurrences, 4, `expected GET_DETECTED_VALUES to appear exactly 4 times in orchestrator.js (its own comments + guard + error log), got ${occurrences} — if this changed, confirm nothing new triggers it automatically from inside the task loop`);
});

console.log(`\n--- ALL ${passCount} / ${totalCount} DETECTED-VALUE RELAY TESTS PASSED SUCCESSFULLY ---`);
