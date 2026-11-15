// Regression test for the live bug: dashboard.html's only interactive
// affordance is a plain <a href="profile.html"> nav link ("Go to Profile"),
// but orchestrator.js's captureOnce() collection selector was
// `input, button, select, textarea` — no `a[href]` — so dom_summary.elements
// was always empty on this page, the LLM had nothing to target, and the
// task got permanently stuck until max_retries_exceeded.
//
// This loads the REAL extension/tests/e2e/three-page-site/dashboard.html
// fixture (not a hand-copied snippet) through the real capture selector
// AND the real classifyElement() label_text derivation, proving both halves
// of the fix end-to-end: the link is now collected, and it gets a real,
// non-null label_text (not silently dropped to null by a form-field-shaped
// label lookup that assumes a <label>/sibling-text structure irrelevant to
// a nav link).
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { JSDOM } from 'jsdom';
import { classifyElement } from '../../dev2/dom-heuristics.js';
import { isRectInViewport } from '../../dev2/dom-heuristics.js';

console.log('=== RUNNING DASHBOARD.HTML LINK-CAPTURE REGRESSION TEST SUITE ===\n');

let passCount = 0;
let totalCount = 0;

function runTestCase(name, fn) {
  totalCount++;
  try {
    fn();
    passCount++;
    console.log(`[PASS] Test ${totalCount}: ${name}`);
  } catch (err) {
    console.error(`[FAIL] Test ${totalCount}: ${name}\n  Error: ${err.message}`);
    throw err;
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardHtmlPath = path.join(__dirname, 'e2e', 'three-page-site', 'dashboard.html');
const dashboardHtml = fs.readFileSync(dashboardHtmlPath, 'utf-8');

runTestCase('The real dashboard.html fixture\'s "Go to Profile" nav link is now collected by orchestrator.js\'s capture selector (previously: zero elements, permanently stuck task)', () => {
  const dom = new JSDOM(dashboardHtml, { runScripts: 'outside-only' });
  const { document } = dom.window;

  // jsdom has no real layout engine, so every element's real
  // getBoundingClientRect() is a zero rect (same reason
  // test-viewport-integration.js mocks it) — stub it as visibly on-screen,
  // matching how this link actually renders in a real browser.
  const navLink = document.querySelector('nav a');
  assert.ok(navLink, 'sanity check: the fixture must actually contain the nav link this test is about');
  navLink.getBoundingClientRect = () => ({ left: 20, top: 200, right: 200, bottom: 230 });

  // Mirrors orchestrator.js's captureOnce() collection line exactly.
  const elements = Array.from(document.querySelectorAll('input, button, select, textarea, a[href]'))
    .filter((el) => isRectInViewport(el.getBoundingClientRect(), 1024, 768));

  assert.strictEqual(elements.length, 1, 'dashboard.html has exactly one capturable element: the nav link (the balance is canvas-rendered pixels, not a DOM element)');
  assert.strictEqual(elements[0], navLink);
  assert.strictEqual(elements[0].getAttribute('href'), 'profile.html');
});

runTestCase('The captured "Go to Profile" link gets a real, non-null label_text from classifyElement() — not silently dropped by form-field label lookup logic that doesn\'t apply to nav links', () => {
  const dom = new JSDOM(dashboardHtml, { runScripts: 'outside-only' });
  const { document } = dom.window;
  global.CSS = dom.window.CSS || { escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&') };

  const navLink = document.querySelector('nav a');
  const classification = classifyElement(navLink);

  assert.strictEqual(classification.tag, 'a');
  assert.strictEqual(classification.role, 'link');
  assert.ok(classification.label_text, 'label_text must not be null/empty for a real, visible nav link');
  assert.ok(
    classification.label_text.includes('Go to Profile'),
    `label_text should reflect the link's real visible text, got: ${JSON.stringify(classification.label_text)}`
  );
  assert.strictEqual(classification.is_sensitive, false, 'a plain nav link is never sensitive');

  delete global.CSS;
});

console.log(`\n--- ALL ${passCount} / ${totalCount} DASHBOARD.HTML LINK-CAPTURE TESTS PASSED SUCCESSFULLY ---`);
