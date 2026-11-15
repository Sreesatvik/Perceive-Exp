// Live perception overlay: rendering, toggle, coordinate handling, privacy.
import assert from 'assert';
import { JSDOM } from 'jsdom';
import { mock } from 'node:test';
import { createOverlay, toOverlayItems, scrollShift, OVERLAY_HOST_ID, RESULT_TTL_MS } from '../src/content/overlay/overlay.js';
import { mountPanel } from '../src/content/panel/panel.js';

console.log('=== RUNNING VISION OVERLAY TEST SUITE ===\n');
let n = 0;
async function t(name, fn) {
  n++;
  try { await fn(); console.log(`[PASS] Test ${n}: ${name}`); }
  catch (e) { console.error(`[FAIL] Test ${n}: ${name}\n  ${e.stack || e.message}`); throw e; }
}
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));

function setup() {
  const dom = new JSDOM('<!DOCTYPE html><html><body><a id="link" href="#x">link</a></body></html>', { url: 'https://example.com/a', pretendToBeVisual: true });
  const win = dom.window;
  const view = { x: 0, y: 0 };
  Object.defineProperty(win, 'innerWidth', { value: 1000, configurable: true, writable: true });
  Object.defineProperty(win, 'innerHeight', { value: 800, configurable: true, writable: true });
  Object.defineProperty(win, 'scrollX', { get: () => view.x, configurable: true });
  Object.defineProperty(win, 'scrollY', { get: () => view.y, configurable: true });
  const overlay = createOverlay({ win });
  const boxes = () => Array.from(overlay.host.shadowRoot.querySelectorAll('.box'));
  const shiftEl = () => overlay.host.shadowRoot.querySelector('.shift');
  return { win, overlay, view, boxes, shiftEl };
}

const RESULT = {
  dom_summary: { elements: [{ element_id: 'email-field', sensitivity_type: 'EMAIL' }] },
  redacted_regions: [
    { element_id: 'email-field', bounding_box: { x: 100, y: 200, w: 150, h: 30 }, sensitivity_tier: 1, semantic_token: '[EMAIL_ab12]', reason: 'email pattern' },
    { element_id: 'vision-face-1', bounding_box: { x: 400, y: 50, w: 80, h: 90 }, sensitivity_tier: 1, sensitivity_type: 'FACE', reason: 'detected as face by vision model' },
    { element_id: 'vision-ocr-2', bounding_box: { x: 10, y: 500, w: 200, h: 20 }, sensitivity_tier: 2, sensitivity_type: 'PHONE', reason: 'phone in on-screen text (OCR)' },
  ],
  detection_confidence_notes: [
    { element_id: 'email-field', confidence: 0.98, method: 'dom_heuristic' },
    { element_id: 'vision-face-1', confidence: 0.94, method: 'vision_model' },
    { element_id: 'vision-ocr-2', confidence: 0.91, method: 'ocr_regex' },
  ],
};

await t('creates one shadow-DOM host; repeated creation returns the same instance (no duplicates)', async () => {
  const { win, overlay } = setup();
  assert.strictEqual(createOverlay({ win }), overlay);
  overlay.setEnabled(true);
  overlay.setEnabled(true);
  assert.strictEqual(win.document.querySelectorAll(`#${OVERLAY_HOST_ID}`).length, 1);
  assert.ok(overlay.host.shadowRoot);
});

await t('toggle: OFF renders nothing and stays hidden; ON shows; OFF again clears the DOM', async () => {
  const { overlay, boxes } = setup();
  overlay.update(RESULT);
  assert.strictEqual(boxes().length, 0, 'nothing rendered while disabled');
  assert.strictEqual(overlay.host.style.display, 'none');
  overlay.setEnabled(true);
  assert.strictEqual(boxes().length, 3);
  assert.strictEqual(overlay.host.style.display, 'block');
  overlay.setEnabled(false);
  assert.strictEqual(boxes().length, 0);
  assert.strictEqual(overlay.host.style.display, 'none');
});

await t('renders each region at its box with "TYPE · confidence"', async () => {
  const { overlay, boxes } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT);
  const b = boxes();
  assert.deepStrictEqual(b.map((x) => [x.style.left, x.style.top, x.style.width, x.style.height]),
    [['100px', '200px', '150px', '30px'], ['400px', '50px', '80px', '90px'], ['10px', '500px', '200px', '20px']]);
  assert.deepStrictEqual(b.map((x) => x.querySelector('.tag').textContent), ['EMAIL · 0.98', 'FACE · 0.94', 'PHONE · 0.91']);
  assert.ok(b[1].classList.contains('face'));
  assert.ok(b[2].classList.contains('t2'));
});

await t('PRIVACY: hostile fields (raw text, label, token, reason) never reach the DOM', async () => {
  const { overlay } = setup();
  overlay.setEnabled(true);
  const SECRETS = ['hunter2-P@ss', '4111 1111 1111 1111', 'jane.doe@corp.com', '9876543210', '123412341234', '[EMAIL_ab12]', 'email pattern'];
  overlay.update({
    dom_summary: { elements: [{ element_id: 'a', sensitivity_type: '<img src=x onerror=alert(1)>', label_text: 'jane.doe@corp.com' }] },
    redacted_regions: [
      { element_id: 'a', bounding_box: { x: 1, y: 30, w: 50, h: 20 }, sensitivity_tier: 1, semantic_token: '[EMAIL_ab12]', reason: 'email pattern', text: 'hunter2-P@ss', raw: '4111 1111 1111 1111', value: '9876543210', label_text: 'jane.doe@corp.com' },
      { element_id: 'b', bounding_box: { x: 5, y: 60, w: 50, h: 20 }, sensitivity_tier: 2, sensitivity_type: 'jane.doe@corp.com', text: '123412341234' },
    ],
    detection_confidence_notes: [{ element_id: 'a', confidence: 0.5, method: 'ocr_regex', text: 'hunter2-P@ss' }],
  });
  const html = overlay.host.shadowRoot.innerHTML;
  for (const s of SECRETS) assert.ok(!html.includes(s), `overlay leaked "${s}"`);
  assert.ok(!html.includes('onerror'), 'non-allow-listed category must not be echoed');
  assert.ok(overlay.host.shadowRoot.querySelector('.tag').textContent.startsWith('SENSITIVE'));
  assert.strictEqual(overlay.host.shadowRoot.querySelectorAll('img').length, 0);
});

await t('toOverlayItems: allow-listed categories only, confidence clamped, bad boxes dropped', async () => {
  const items = toOverlayItems([
    { element_id: 'x', bounding_box: { x: 0, y: 0, w: 10, h: 10 }, sensitivity_type: 'PASSWORD', sensitivity_tier: 1 },
    { element_id: 'y', bounding_box: { x: 0, y: 0, w: 0, h: 10 }, sensitivity_type: 'EMAIL' },
    { element_id: 'z', bounding_box: { x: NaN, y: 0, w: 5, h: 5 }, sensitivity_type: 'EMAIL' },
    { element_id: 'q' },
    null,
  ], [{ element_id: 'x', confidence: 7 }], []);
  assert.strictEqual(items.length, 1);
  assert.deepStrictEqual([items[0].type, items[0].confidence], ['PASSWORD', 1]);
  assert.deepStrictEqual(toOverlayItems(undefined, undefined, undefined), []);
});

await t('coordinates: scrollShift math, and boxes follow the page when scrolled after capture', async () => {
  assert.deepStrictEqual(scrollShift({ scrollX: 0, scrollY: 100 }, { scrollX: 0, scrollY: 340 }), { dx: 0, dy: -240 });
  const { overlay, view, shiftEl, win } = setup();
  overlay.setEnabled(true);
  view.y = 100;
  overlay.update(RESULT, { scrollX: 0, scrollY: 100, vw: 1000, vh: 800 });
  assert.strictEqual(shiftEl().style.transform, 'translate(0px, 0px)');
  view.y = 340;
  win.dispatchEvent(new win.Event('scroll'));
  await tick();
  assert.strictEqual(shiftEl().style.transform, 'translate(0px, -240px)');
  view.x = 30;
  win.dispatchEvent(new win.Event('scroll'));
  await tick();
  assert.strictEqual(shiftEl().style.transform, 'translate(-30px, -240px)');
});

await t('stale: resize/zoom (viewport changed) clears the boxes', async () => {
  const { overlay, boxes, win } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT, { scrollX: 0, scrollY: 0, vw: 1000, vh: 800 });
  assert.strictEqual(boxes().length, 3);
  win.innerWidth = 700;
  win.dispatchEvent(new win.Event('resize'));
  await tick();
  assert.strictEqual(boxes().length, 0);
  assert.strictEqual(overlay.hasResult(), false);
});

await t('stale: SPA navigation (URL changed) clears the boxes', async () => {
  const { overlay, boxes, win } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT, { scrollX: 0, scrollY: 0, vw: 1000, vh: 800 });
  win.history.pushState({}, '', '/b');
  win.dispatchEvent(new win.Event('popstate'));
  await tick();
  assert.strictEqual(boxes().length, 0);
});

await t('stale: a new result replaces the old one; an empty result clears; results expire', async () => {
  const { overlay, boxes } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT);
  overlay.update({ redacted_regions: [RESULT.redacted_regions[1]], detection_confidence_notes: RESULT.detection_confidence_notes });
  assert.strictEqual(boxes().length, 1);
  overlay.update({ redacted_regions: [], detection_confidence_notes: [] });
  assert.strictEqual(boxes().length, 0);

  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    overlay.update(RESULT);
    assert.strictEqual(boxes().length, 3);
    mock.timers.tick(RESULT_TTL_MS + 1);
    assert.strictEqual(boxes().length, 0, 'expired result must be cleared');
  } finally { mock.timers.reset(); }
});

await t('never intercepts pointer events (host, layer and every box)', async () => {
  const { overlay, boxes } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT);
  assert.strictEqual(overlay.host.style.pointerEvents, 'none');
  const css = overlay.host.shadowRoot.querySelector('style').textContent;
  assert.match(css, /\.layer \{[^}]*pointer-events: none/);
  assert.match(css, /\.layer \* \{[^}]*pointer-events: none !important/);
  assert.ok(boxes().length > 0);
});

await t('page stays interactive: overlay adds no listeners that block clicks, and leaves page DOM untouched', async () => {
  const { win, overlay } = setup();
  const before = win.document.body.innerHTML;
  overlay.setEnabled(true);
  overlay.update(RESULT);
  assert.strictEqual(win.document.body.innerHTML, before, 'host lives on <html>, page body unchanged');
  let clicked = 0;
  win.document.getElementById('link').addEventListener('click', (e) => { clicked++; e.preventDefault(); });
  win.document.getElementById('link').click();
  assert.strictEqual(clicked, 1);
});

await t('suspendForCapture hides the overlay for the screenshot; resume restores it', async () => {
  const { overlay } = setup();
  overlay.setEnabled(true);
  await overlay.suspendForCapture();
  assert.strictEqual(overlay.host.style.visibility, 'hidden');
  overlay.resumeAfterCapture();
  assert.strictEqual(overlay.host.style.visibility, '');
});

await t('no render loop while idle: with no events, nothing re-renders', async () => {
  const { overlay, shiftEl } = setup();
  overlay.setEnabled(true);
  overlay.update(RESULT);
  const first = shiftEl().firstChild;
  await tick(80);
  assert.strictEqual(shiftEl().firstChild, first, 'DOM nodes untouched without a new result');
});

await t('panel toggle: button flips "Vision Overlay: OFF/ON", drives the overlay, and persists', async () => {
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', { pretendToBeVisual: true });
  const win = dom.window;
  Object.defineProperty(win, 'innerWidth', { value: 1000, configurable: true });
  Object.defineProperty(win, 'innerHeight', { value: 800, configurable: true });
  const data = {};
  const store = { get: async (k) => ({ [k]: data[k] }), set: async (o) => Object.assign(data, o) };
  const calls = [];
  const overlay = { setEnabled: (v) => calls.push(v) };
  const panel = mountPanel({ runTask: () => {}, overlay, win, chromeApi: {}, store });
  await panel.ready;
  const btn = panel.host.shadowRoot.querySelector('.overlay-btn');
  assert.strictEqual(btn.textContent, 'Vision Overlay: OFF');
  btn.click();
  assert.strictEqual(btn.textContent, 'Vision Overlay: ON');
  assert.strictEqual(btn.getAttribute('aria-pressed'), 'true');
  assert.strictEqual(calls[calls.length - 1], true);
  await tick(5);
  assert.strictEqual(Object.values(data)[0].overlay, true);
  btn.click();
  assert.strictEqual(calls[calls.length - 1], false);
});

console.log(`\n${n}/${n} passed`);
process.exit(0);
