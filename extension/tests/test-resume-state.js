// Mid-task navigation resume — background storage + orchestrator wiring.
//
// The content script running orchestrator.js's task loop is destroyed when
// a click action navigates the page. This tests the fix: the background
// service worker (transport.js) holds a small, in-memory, one-shot,
// TTL-bounded record per tabId (resumeStateByTab), stashed right after a
// successful click and consumed by the freshly-injected content script on
// the new page's own startup check.
//
// Split into two halves, matching the two files actually changed:
//  - transport.js's STASH_RESUME_STATE/GET_RESUME_STATE handlers, tested
//    directly via the same mocked chrome.runtime.onMessage.addListener
//    capture convention as test-transport-face-detection.js.
//  - orchestrator.js's send-after-click and startup-check wiring, tested
//    via the same withFreshOrchestrator jsdom harness convention as
//    test-retry-backoff.js / test-detected-values-relay.js.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mock } from 'node:test';

console.log('=== RUNNING MID-TASK NAVIGATION RESUME TEST SUITE ===\n');

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

// =====================================================================
// transport.js: STASH_RESUME_STATE / GET_RESUME_STATE
// =====================================================================

function makeTransportHarness() {
  let registeredMessageListener = null;
  let registeredTabRemovedListener = null;

  global.chrome = {
    runtime: {
      onMessage: { addListener: (fn) => { registeredMessageListener = fn; } },
      getURL: (p) => `chrome-extension://fake-id/${p}`,
      lastError: undefined,
    },
    storage: { local: { get: async () => ({ backendApiKey: 'test-key' }) } },
    tabs: { onRemoved: { addListener: (fn) => { registeredTabRemovedListener = fn; } } },
    offscreen: {
      hasDocument: async () => true,
      createDocument: async () => {},
    },
  };
  global.fetch = async () => { throw new Error('unused in this test'); };

  return {
    getListener: () => registeredMessageListener,
    getTabRemovedListener: () => registeredTabRemovedListener,
    teardown: () => { delete global.chrome; delete global.fetch; },
  };
}

function invoke(listener, message, sender = { tab: { id: 1 }, frameId: 0 }) {
  return new Promise((resolve) => { listener(message, sender, resolve); });
}

await runTestCase('STASH_RESUME_STATE then GET_RESUME_STATE (same tab): returns exactly what was stashed', async () => {
  const harness = makeTransportHarness();
  try {
    await import(`../src/background/transport.js?t=${Date.now()}-${Math.random()}`);
    const listener = harness.getListener();
    assert.ok(listener, 'transport.js must register a chrome.runtime.onMessage listener');

    const stashRes = await invoke(listener, {
      type: 'STASH_RESUME_STATE',
      sessionId: 'sess-123',
      taskInstruction: 'log in with [PASSWORD_1], then go to profile',
      backendStepNumber: 2,
      stepNumber: 3,
    }, { tab: { id: 42 }, frameId: 0 });
    assert.strictEqual(stashRes.success, true);

    const getRes = await invoke(listener, { type: 'GET_RESUME_STATE' }, { tab: { id: 42 }, frameId: 0 });
    assert.strictEqual(getRes.success, true);
    assert.ok(getRes.resumeState, 'expected a resume record for tab 42');
    assert.strictEqual(getRes.resumeState.sessionId, 'sess-123');
    assert.strictEqual(getRes.resumeState.taskInstruction, 'log in with [PASSWORD_1], then go to profile');
    assert.strictEqual(getRes.resumeState.backendStepNumber, 2);
    assert.strictEqual(getRes.resumeState.stepNumber, 3);
  } finally {
    harness.teardown();
  }
});

await runTestCase('GET_RESUME_STATE for a tab with nothing stashed returns null, not an error', async () => {
  const harness = makeTransportHarness();
  try {
    await import(`../src/background/transport.js?t=${Date.now()}-${Math.random()}`);
    const listener = harness.getListener();

    const getRes = await invoke(listener, { type: 'GET_RESUME_STATE' }, { tab: { id: 999 }, frameId: 0 });
    assert.strictEqual(getRes.success, true);
    assert.strictEqual(getRes.resumeState, null);
  } finally {
    harness.teardown();
  }
});

await runTestCase('One-shot: a SECOND GET_RESUME_STATE for the same tab returns null — a stale record must never resurface on an unrelated later navigation', async () => {
  const harness = makeTransportHarness();
  try {
    await import(`../src/background/transport.js?t=${Date.now()}-${Math.random()}`);
    const listener = harness.getListener();
    const sender = { tab: { id: 7 }, frameId: 0 };

    await invoke(listener, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1 }, sender);

    const first = await invoke(listener, { type: 'GET_RESUME_STATE' }, sender);
    assert.ok(first.resumeState, 'first read must return the stashed record');

    const second = await invoke(listener, { type: 'GET_RESUME_STATE' }, sender);
    assert.strictEqual(second.resumeState, null, 'second read for the same tab must be null — the record was already consumed');
  } finally {
    harness.teardown();
  }
});

await runTestCase('TTL: a record older than the resume window is treated as gone, not returned', async () => {
  mock.timers.enable({ apis: ['Date'] });
  const harness = makeTransportHarness();
  try {
    await import(`../src/background/transport.js?t=${Date.now()}-${Math.random()}`);
    const listener = harness.getListener();
    const sender = { tab: { id: 55 }, frameId: 0 };

    await invoke(listener, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1 }, sender);

    // 30 minutes + 1 second — past dev2/session-vault-manager.js's
    // DEFAULT_SESSION_TTL_MS-matching window transport.js reuses.
    mock.timers.tick(30 * 60 * 1000 + 1000);

    const res = await invoke(listener, { type: 'GET_RESUME_STATE' }, sender);
    assert.strictEqual(res.resumeState, null, 'an expired record must not be returned even though it technically still exists in the Map');
  } finally {
    harness.teardown();
    mock.timers.reset();
  }
});

await runTestCase('Tab close cleans up its resume state: a stash for a since-closed tab is never returned to a NEW tab that happens to reuse the same id', async () => {
  const harness = makeTransportHarness();
  try {
    await import(`../src/background/transport.js?t=${Date.now()}-${Math.random()}`);
    const listener = harness.getListener();
    const sender = { tab: { id: 88 }, frameId: 0 };

    await invoke(listener, { type: 'STASH_RESUME_STATE', sessionId: 's', taskInstruction: 't', backendStepNumber: 1, stepNumber: 1 }, sender);

    const tabRemovedListener = harness.getTabRemovedListener();
    assert.ok(tabRemovedListener, 'transport.js must register a chrome.tabs.onRemoved listener');
    tabRemovedListener(88);

    const res = await invoke(listener, { type: 'GET_RESUME_STATE' }, sender);
    assert.strictEqual(res.resumeState, null, 'closing the tab must clear its resume record');
  } finally {
    harness.teardown();
  }
});

// =====================================================================
// orchestrator.js: send-after-click, and startup resume check
// =====================================================================

async function withFreshOrchestrator(fn, { chromeSendMessageImpl } = {}) {
  // Under a real jsdom `document`, dev2/redaction-renderer.js's
  // redactImage() creates a REAL document.createElement('canvas') whose
  // getContext('2d') is non-functional without the `canvas` npm package —
  // canvasToBase64() then throws on a null toDataURL() result, aborting
  // buildSanitizedPayload() before a step can ever reach the click/
  // STASH_RESUME_STATE code this file is actually testing (a pre-existing,
  // accepted jsdom limitation — see test-retry-backoff.js's own header
  // comment). Mocking only these two leaf rendering functions — NOT
  // redaction-engine.js's classification/tokenization logic itself — lets
  // a step complete for real while sidestepping just the part jsdom can't
  // support.
  // NOTE: orchestrator.js imports dev2 modules from extension/dev2/ (the
  // Chrome-packaging-required synced copy), NOT the top-level dev2/ — so
  // this specifier must resolve to extension/dev2/redaction-renderer.js,
  // matching what orchestrator.js's own import chain actually resolves to.
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

  const sentMessages = [];
  let registeredMessageListener = null;

  global.chrome = {
    runtime: {
      onMessage: { addListener: (fn2) => { registeredMessageListener = fn2; } },
      sendMessage: (message, callback) => {
        sentMessages.push(message);
        const impl = chromeSendMessageImpl || (() => ({ success: true }));
        const response = impl(message);
        if (callback) callback(response);
      },
    },
  };

  const modUrl = `../src/content/orchestrator.js?t=${Date.now()}-${Math.random()}`;
  const mod = await import(modUrl);

  try {
    await fn({ mod, sentMessages, getRegisteredListener: () => registeredMessageListener });
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

const mockCanvas = {
  getContext: () => ({
    fillRect: () => {}, clearRect: () => {}, drawImage: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
  }),
  toDataURL: () => 'data:image/png;base64,' + 'A'.repeat(150),
};

await runTestCase('A successful CLICK action sends STASH_RESUME_STATE with the tokenized instruction/session/step numbers — a successful "type" action does not', async () => {
  await withFreshOrchestrator(async ({ mod, sentMessages }) => {
    window.__mockBackendResponse = (stepNumber) => ({
      action: stepNumber === 1
        ? { type: 'click', target_element_id: 'link-1', risk_tier: 'safe', reasoning_short: 'go' }
        : { type: 'task_complete', risk_tier: 'safe', reasoning_short: 'done' },
    });
    // executeAction() needs a real target for 'click' to report success —
    // domIndex.js's findAgentElementResilient() falls back to
    // document.getElementById when no data-ext-id tag matches.
    const link = document.createElement('a');
    link.id = 'link-1';
    link.href = '#';
    // jsdom has no real layout engine — getBoundingClientRect() defaults
    // to an all-zero rect, which actionExecutor.js's visibility check
    // would read as element_not_interactable. Same mocking technique as
    // test-viewport-integration.js.
    link.getBoundingClientRect = () => ({ x: 10, y: 10, width: 100, height: 20, left: 10, top: 10, right: 110, bottom: 30 });
    document.body.appendChild(link);

    const captureOverride = async () => ({ elements: [link], canvas: mockCanvas });
    await mod.runTaskLoop('log in with password \'testpass123\'', captureOverride);

    const stash = sentMessages.find((m) => m.type === 'STASH_RESUME_STATE');
    assert.ok(stash, 'expected a STASH_RESUME_STATE message after the successful click action');
    assert.strictEqual(typeof stash.sessionId, 'string');
    assert.strictEqual(typeof stash.taskInstruction, 'string');
    assert.strictEqual(stash.taskInstruction.includes('testpass123'), false, 'the stashed instruction must be the TOKENIZED one, never the raw password');
    assert.strictEqual(stash.backendStepNumber, 1);
    assert.strictEqual(stash.stepNumber, 1);
    assert.deepStrictEqual(stash.pendingTierTwoValues, [], 'an instruction with only a Tier 1 (password) value must carry forward nothing at all — not even an empty-looking placeholder for it');

    delete window.__mockBackendResponse;
  });
});

await runTestCase('REGRESSION: a Tier 1 (password) token is NEVER included in pendingTierTwoValues, even when it is just as "unconsumed" as a Tier 2 (phone) token sitting right next to it in the same instruction', async () => {
  await withFreshOrchestrator(async ({ mod, sentMessages }) => {
    window.__mockBackendResponse = (stepNumber) => ({
      action: stepNumber === 1
        ? { type: 'click', target_element_id: 'link-1', risk_tier: 'safe', reasoning_short: 'go' }
        : { type: 'task_complete', risk_tier: 'safe', reasoning_short: 'done' },
    });
    const link = document.createElement('a');
    link.id = 'link-1';
    link.href = '#';
    link.getBoundingClientRect = () => ({ x: 10, y: 10, width: 100, height: 20, left: 10, top: 10, right: 110, bottom: 30 });
    document.body.appendChild(link);

    const captureOverride = async () => ({ elements: [link], canvas: mockCanvas });
    // Deliberately contrived: BOTH a Tier 1 credential and a Tier 2 phone
    // number in the same instruction, both equally "still unconsumed" by
    // the time of the click (neither has been typed yet) — the only thing
    // that may ever distinguish them is tier, never how "pending" they are.
    await mod.runTaskLoop("log in with password 'SuperSecret123!', then update phone to 9876543210", captureOverride);

    const stash = sentMessages.find((m) => m.type === 'STASH_RESUME_STATE');
    assert.ok(stash, 'expected a STASH_RESUME_STATE message after the successful click action');

    // Sanity check: the tokenized instruction really does contain BOTH
    // token types — otherwise the negative assertion below would pass
    // vacuously because the password was never tokenized into this string
    // at all, not because tiering correctly excluded it.
    assert.match(stash.taskInstruction, /\[PASSWORD_[a-z0-9]+\]/, 'sanity check: a PASSWORD token must actually be present in the persisted instruction');
    assert.match(stash.taskInstruction, /\[PHONE_[a-z0-9]+\]/, 'sanity check: a PHONE token must actually be present in the persisted instruction');

    assert.strictEqual(stash.taskInstruction.includes('SuperSecret123!'), false, 'the raw password must never appear in the persisted instruction');
    assert.strictEqual(stash.taskInstruction.includes('9876543210'), false, 'the raw phone number must never appear in the persisted instruction — only its resolved value in pendingTierTwoValues, never the instruction text itself');

    assert.strictEqual(stash.pendingTierTwoValues.length, 1, 'exactly one pending value — the phone number — must be carried forward');
    assert.strictEqual(stash.pendingTierTwoValues[0].type, 'PHONE');
    assert.strictEqual(stash.pendingTierTwoValues[0].value, '9876543210');
    assert.ok(
      stash.pendingTierTwoValues[0].token.startsWith('[PHONE_'),
      `expected a PHONE token, got: ${stash.pendingTierTwoValues[0].token}`
    );

    // The actual regression assertion: no entry anywhere in
    // pendingTierTwoValues may carry the raw password value, a PASSWORD
    // token, or a PASSWORD type — under any field, at any position.
    for (const entry of stash.pendingTierTwoValues) {
      assert.notStrictEqual(entry.type, 'PASSWORD');
      assert.notStrictEqual(entry.value, 'SuperSecret123!');
      assert.ok(!entry.token.startsWith('[PASSWORD_'), `a PASSWORD-typed token must never appear in pendingTierTwoValues, found: ${entry.token}`);
    }

    delete window.__mockBackendResponse;
  });
});

await runTestCase('runTaskLoop(instruction, captureOverride, resumeState): reuses the persisted session_id, requests backendStepNumber+1 (not a restart at 1), and sends the instruction through UNCHANGED (skipTokenization)', async () => {
  const resumeState = {
    sessionId: 'resumed-session-id',
    taskInstruction: 'go to profile and update phone to [PHONE_1]', // already tokenized
    backendStepNumber: 1,
    stepNumber: 1,
  };

  await withFreshOrchestrator(async ({ mod, sentMessages }) => {
    const captureOverride = async () => ({ elements: [], canvas: mockCanvas });
    const result = await mod.runTaskLoop(resumeState.taskInstruction, captureOverride, resumeState);
    assert.strictEqual(result.success, true);

    const sendPayloadMsgs = sentMessages.filter((m) => m.type === 'SEND_PAYLOAD');
    assert.ok(sendPayloadMsgs.length > 0, 'the resumed task must have actually run a step');
    assert.strictEqual(sendPayloadMsgs[0].payload.session_id, 'resumed-session-id', 'the resumed run must reuse the persisted session_id, not mint a fresh one');
    assert.strictEqual(sendPayloadMsgs[0].payload.step_number, 2, 'the resumed run must request backendStepNumber+1, not restart at 1 (the server would reject a duplicate/out-of-order step)');
    assert.strictEqual(
      sendPayloadMsgs[0].payload.task_instruction,
      resumeState.taskInstruction,
      'the resumed instruction must be sent through UNCHANGED (skipTokenization) — re-tokenizing already-tokenized text risks a false missing-credential gate'
    );
  }, {
    chromeSendMessageImpl: (message) => {
      if (message.type === 'SEND_PAYLOAD') {
        // transport.js's SEND_PAYLOAD handler responds with
        // { success, action } where `action` is actually the FULL parsed
        // server response ({ session_id, step_number, action: {...},
        // confidence }) — orchestrator.js's `actionResponse = bgResponse.action`
        // then reads `actionResponse.action.type`. Matching that exact
        // shape here, not the single-nested one it'd be easy to assume.
        return {
          success: true,
          action: {
            session_id: message.payload.session_id,
            step_number: message.payload.step_number,
            action: { type: 'task_complete', risk_tier: 'safe', reasoning_short: 'done' },
            confidence: 0.9,
          },
        };
      }
      return { success: true };
    },
  });
});

await runTestCase('End-to-end: a resumed run with a restored PHONE pendingTierTwoValue actually resolves [PHONE_...] back to the real number and types it — the exact failure this whole fix addresses (previously: unresolvable_token, every retry, max_retries_exceeded)', async () => {
  const PHONE_TOKEN = '[PHONE_dzzd9bilk9]';
  const resumeState = {
    sessionId: 'resumed-session-id',
    taskInstruction: `update phone to ${PHONE_TOKEN}`,
    backendStepNumber: 1,
    stepNumber: 1,
    pendingTierTwoValues: [{ token: PHONE_TOKEN, value: '9876543210', type: 'PHONE' }],
  };

  await withFreshOrchestrator(async ({ mod }) => {
    const phoneInput = document.createElement('input');
    phoneInput.id = 'phone-input';
    phoneInput.type = 'tel';
    phoneInput.getBoundingClientRect = () => ({ x: 10, y: 10, width: 100, height: 20, left: 10, top: 10, right: 110, bottom: 30 });
    document.body.appendChild(phoneInput);

    window.__mockBackendResponse = (stepNumber) => ({
      action: stepNumber === 2
        ? { type: 'type', target_element_id: 'phone-input', value: PHONE_TOKEN, risk_tier: 'safe', reasoning_short: 'enter phone' }
        : { type: 'task_complete', risk_tier: 'safe', reasoning_short: 'done' },
    });

    const captureOverride = async () => ({ elements: [phoneInput], canvas: mockCanvas });
    const result = await mod.runTaskLoop(resumeState.taskInstruction, captureOverride, resumeState);

    assert.strictEqual(result.success, true, 'the resumed task must complete successfully, not exhaust retries on unresolvable_token');
    assert.strictEqual(phoneInput.value, '9876543210', 'the real phone number must actually have been typed into the field — proves restoreToken() rehydrated the vault correctly, not just that no error was thrown');

    delete window.__mockBackendResponse;
  });
});

await runTestCase('Startup mechanism: on module load, orchestrator.js asks background for resume state, and — when one is found — actually invokes the task loop with it (observable via the CAPTURE_TAB_STATE message it sends, carrying the resumed session_id/step_number), without waiting for RUN_TASK', async () => {
  const resumeRecord = {
    sessionId: 'resumed-session-id',
    taskInstruction: 'go to profile and update phone to [PHONE_1]',
    backendStepNumber: 1,
    stepNumber: 1,
  };

  await withFreshOrchestrator(async ({ sentMessages }) => {
    // The startup path calls the REAL captureRealTabState() (not
    // injectable via captureOverride — see the previous test for that
    // half), which this harness cannot carry through a full successful
    // capture under jsdom (no real image decoder — same limitation
    // documented in test-detected-values-relay.js). That's fine here:
    // this test's job is proving the startup path was REACHED and called
    // runTaskLoop with the right resume params, not that a full step
    // completes — the CAPTURE_TAB_STATE message captureOnce() sends
    // (BEFORE any image loading happens) already carries sessionId/
    // stepNumber, which is exactly the signal needed.
    await new Promise((r) => setTimeout(r, 50));

    const getReq = sentMessages.find((m) => m.type === 'GET_RESUME_STATE');
    assert.ok(getReq, 'orchestrator.js must ask background for resume state on its own startup, unconditionally');

    const captureReq = sentMessages.find((m) => m.type === 'CAPTURE_TAB_STATE');
    assert.ok(captureReq, 'finding a resume record must actually invoke the task loop, reaching its first capture attempt, not just log something');
    assert.strictEqual(captureReq.sessionId, 'resumed-session-id', 'the invoked task loop must be using the persisted session_id');
    assert.strictEqual(captureReq.stepNumber, 2, 'the invoked task loop must be requesting backendStepNumber+1');
  }, {
    chromeSendMessageImpl: (message) => {
      if (message.type === 'GET_RESUME_STATE') return { success: true, resumeState: resumeRecord };
      if (message.type === 'CAPTURE_TAB_STATE') return { success: false, error: 'restricted_page' };
      return { success: true };
    },
  });
});

await runTestCase('On startup with no resume state available, orchestrator.js does not auto-run any task', async () => {
  await withFreshOrchestrator(async ({ sentMessages }) => {
    await new Promise((r) => setTimeout(r, 50));

    const getReq = sentMessages.find((m) => m.type === 'GET_RESUME_STATE');
    assert.ok(getReq, 'the startup check itself must still fire');

    const sendPayloadMsgs = sentMessages.filter((m) => m.type === 'SEND_PAYLOAD');
    assert.strictEqual(sendPayloadMsgs.length, 0, 'with nothing to resume, no task should run automatically');
  }, {
    chromeSendMessageImpl: (message) => {
      if (message.type === 'GET_RESUME_STATE') return { success: true, resumeState: null };
      return { success: true };
    },
  });
});

console.log(`\n--- ALL ${passCount} / ${totalCount} MID-TASK NAVIGATION RESUME TESTS PASSED SUCCESSFULLY ---`);
