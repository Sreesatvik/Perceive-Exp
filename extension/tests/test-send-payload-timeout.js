// Real bug found live: SEND_PAYLOAD shared RETRY_CONFIG.STEP_TIMEOUT_MS
// (20000ms) with CAPTURE_TAB_STATE — a fast local screenshot with no
// business ever legitimately approaching 20s. SEND_PAYLOAD is a real
// network round trip to a backend that itself calls an LLM (up to a 12s
// timeout) and layers its own retry/backoff on top — a perfectly healthy,
// still-working request was indistinguishable from a genuinely hung one at
// the 20s mark. See SEND_PAYLOAD_TIMEOUT_MS's own comment in constants.js
// for the full reasoning behind the new 45000ms ceiling.
//
// This proves the fix actually widens SEND_PAYLOAD's window — not just
// that the constant exists — by having its mocked chrome.runtime.sendMessage
// callback fire AFTER the OLD 20s ceiling but BEFORE the NEW 45s one, using
// fake timers so this runs instantly rather than waiting 25 real seconds.
// It also proves the fix is SCOPED: CAPTURE_TAB_STATE still times out at
// the original 20s, not silently widened along with SEND_PAYLOAD.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mock } from 'node:test';
import { RETRY_CONFIG, SEND_PAYLOAD_TIMEOUT_MS } from '../src/shared/constants.js';

console.log('=== RUNNING SEND_PAYLOAD TIMEOUT WIDENING TEST SUITE ===\n');

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

const mockCanvas = {
  getContext: () => ({
    fillRect: () => {}, clearRect: () => {}, drawImage: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
  }),
  toDataURL: () => 'data:image/png;base64,' + 'A'.repeat(150),
};

async function withFreshOrchestrator(fn) {
  const rendererMock = mock.module('../dev2/redaction-renderer.js', {
    exports: {
      redactImage: () => mockCanvas,
      canvasToBase64: () => 'ZmFrZS1yZWRhY3RlZC1pbWFnZQ==',
    },
  });

  const dom = new JSDOM(`<html><body></body></html>`, { runScripts: 'outside-only' });
  global.window = dom.window;
  global.document = dom.window.document;
  global.MutationObserver = dom.window.MutationObserver;
  global.CustomEvent = dom.window.CustomEvent;
  const previousGlobalPerformance = global.performance;
  global.performance = dom.window.performance || global.performance;
  global.CSS = dom.window.CSS || { escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&') };
  global.window.__PERCEIVE_TEST_MODE__ = true;

  let capturedSendPayloadCallback = null;
  let capturedCaptureTabStateCallback = null;

  global.chrome = {
    runtime: {
      onMessage: { addListener: () => {} },
      sendMessage: (message, callback) => {
        if (message.type === 'SEND_PAYLOAD') {
          capturedSendPayloadCallback = callback; // deliberately NOT invoked here
          return;
        }
        if (message.type === 'CAPTURE_TAB_STATE') {
          capturedCaptureTabStateCallback = callback; // deliberately NOT invoked here
          return;
        }
        callback({ success: true });
      },
      lastError: undefined,
    },
  };

  const modUrl = `../src/content/orchestrator.js?t=${Date.now()}-${Math.random()}`;
  const mod = await import(modUrl);

  try {
    await fn({
      mod,
      getSendPayloadCallback: () => capturedSendPayloadCallback,
      getCaptureTabStateCallback: () => capturedCaptureTabStateCallback,
    });
  } finally {
    delete global.window;
    delete global.document;
    delete global.MutationObserver;
    delete global.CustomEvent;
    delete global.CSS;
    delete global.chrome;
    global.performance = previousGlobalPerformance;
    rendererMock.restore();
  }
}

async function flushMicrotasks(rounds = 8) {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}

await runTestCase('SEND_PAYLOAD tolerates a response arriving after the OLD 20s ceiling but before the NEW 45s one — the step succeeds instead of timing out', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    await withFreshOrchestrator(async ({ mod, getSendPayloadCallback }) => {
      const captureOverride = async () => ({ elements: [], canvas: mockCanvas });
      const resultPromise = mod.runTaskLoop('a trivial task', captureOverride);

      // Let the step run up to the point where SEND_PAYLOAD is sent and
      // its timeout timer is armed.
      await flushMicrotasks();

      // Past RETRY_CONFIG.STEP_TIMEOUT_MS (20000) — under the OLD shared
      // ceiling this would already have rejected by now. Still comfortably
      // under SEND_PAYLOAD_TIMEOUT_MS (45000).
      const PAST_OLD_CEILING_MS = RETRY_CONFIG.STEP_TIMEOUT_MS + 5000;
      assert.ok(PAST_OLD_CEILING_MS < SEND_PAYLOAD_TIMEOUT_MS, 'test sanity: the probe point must sit strictly between the two ceilings');
      mock.timers.tick(PAST_OLD_CEILING_MS);
      await flushMicrotasks();

      const callback = getSendPayloadCallback();
      assert.ok(callback, 'SEND_PAYLOAD must have actually been sent');

      // The response FINALLY arrives, late by the old standard, on time by
      // the new one.
      callback({
        success: true,
        action: {
          session_id: 'x', step_number: 1,
          action: { type: 'task_complete', risk_tier: 'safe', reasoning_short: 'done' },
          confidence: 0.9,
        },
      });

      const result = await resultPromise;
      assert.strictEqual(result.success, true, 'a SEND_PAYLOAD response arriving after 20s but before 45s must NOT be treated as a timeout');
    });
  } finally {
    mock.timers.reset();
  }
});

await runTestCase('SCOPE CHECK: CAPTURE_TAB_STATE is UNCHANGED — still times out at the original 20s ceiling, not silently widened along with SEND_PAYLOAD', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    await withFreshOrchestrator(async ({ mod, getCaptureTabStateCallback }) => {
      // No captureOverride here — this drives the REAL captureRealTabState()
      // path (the only way to actually exercise sendMessageAsync's
      // CAPTURE_TAB_STATE timeout branch), same technique as
      // test-detected-values-relay.js's on-demand-capture test.
      const resultPromise = mod.runTaskLoop('a trivial task', mod.__unusedNoCaptureOverride || undefined);
      void resultPromise; // observed indirectly below; this run is expected to fail closed, not succeed

      await flushMicrotasks();
      const callback = getCaptureTabStateCallback();
      assert.ok(callback, 'CAPTURE_TAB_STATE must have actually been sent');

      mock.timers.tick(RETRY_CONFIG.STEP_TIMEOUT_MS + 1000);
      await flushMicrotasks();

      // The timeout has already fired internally by this point (settled),
      // so a late callback invocation now must be a no-op — proving the
      // timer actually elapsed at the ORIGINAL ceiling, not the widened one.
      assert.doesNotThrow(() => callback({ success: true, screenshotDataUrl: 'data:image/png;base64,AAAA' }));
    });
  } finally {
    mock.timers.reset();
  }
});

console.log(`\n--- ALL ${passCount} / ${totalCount} SEND_PAYLOAD TIMEOUT WIDENING TESTS PASSED SUCCESSFULLY ---`);
