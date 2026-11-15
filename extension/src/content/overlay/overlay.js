// Live perception overlay: draws boxes for what the existing local vision /
// redaction pass ALREADY found. It runs no OCR, no face detection and takes
// no screenshot — it renders `redacted_regions` + `detection_confidence_notes`
// as produced by processPageForRedaction().
//
// PRIVACY: only safe metadata ever reaches the DOM — an allow-listed category
// name and a clamped confidence number. Raw OCR text, label text, semantic
// tokens, "reason" strings and anything else on a region are never read, so
// they cannot be rendered even by mistake (see toOverlayItems()).
//
// COORDINATES: DOM boxes come from getBoundingClientRect() and vision boxes
// from a canvas that orchestrator.js sizes to innerWidth x innerHeight (the
// screenshot is scaled onto it, which already absorbs devicePixelRatio and
// page zoom). Both are therefore in viewport CSS pixels AT CAPTURE TIME, so
// no extra transform is needed beyond compensating for scrolling since then.

export const OVERLAY_HOST_ID = 'perceive-vision-overlay-host';
export const RESULT_TTL_MS = 60_000;

// The only strings the overlay will ever print as a category.
const SAFE_TYPES = new Set(['FACE', 'PASSWORD', 'CARD_NUMBER', 'EMAIL', 'NAME', 'AMOUNT', 'PHONE', 'AADHAAR', 'OTP', 'IFSC']);

const finite = (v) => typeof v === 'number' && Number.isFinite(v);

/**
 * Pure: redaction output -> [{ x, y, w, h, type, confidence, tier }] with
 * nothing but safe metadata. Regions without a usable box are dropped.
 */
export function toOverlayItems(regions, notes, summaryElements) {
  const conf = new Map();
  for (const n of Array.isArray(notes) ? notes : []) {
    if (n && typeof n.element_id === 'string' && finite(n.confidence)) conf.set(n.element_id, n.confidence);
  }
  const summaryType = new Map();
  for (const e of Array.isArray(summaryElements) ? summaryElements : []) {
    if (e && typeof e.element_id === 'string') summaryType.set(e.element_id, e.sensitivity_type);
  }

  const items = [];
  for (const r of Array.isArray(regions) ? regions : []) {
    const b = r && r.bounding_box;
    if (!b || !finite(b.x) || !finite(b.y) || !finite(b.w) || !finite(b.h) || b.w <= 0 || b.h <= 0) continue;
    const rawType = r.sensitivity_type || summaryType.get(r.element_id);
    const c = conf.get(r.element_id);
    items.push({
      x: b.x, y: b.y, w: b.w, h: b.h,
      type: SAFE_TYPES.has(rawType) ? rawType : 'SENSITIVE',
      confidence: finite(c) ? Math.min(1, Math.max(0, c)) : null,
      tier: r.sensitivity_tier === 1 ? 1 : 2,
    });
  }
  return items;
}

/** Pure: how far the captured boxes must shift to stay glued to the page. */
export function scrollShift(captured, now) {
  return { dx: captured.scrollX - now.scrollX, dy: captured.scrollY - now.scrollY };
}

const CSS = `
:host { all: initial; }
.layer { position: fixed; inset: 0; pointer-events: none; overflow: hidden; }
.layer * { pointer-events: none !important; box-sizing: border-box; }
.shift { position: absolute; left: 0; top: 0; width: 0; height: 0; will-change: transform; }
.box { position: absolute; border: 2px solid #ef4444; background: rgba(239,68,68,.10); border-radius: 2px; }
.box.t2 { border-color: #f59e0b; background: rgba(245,158,11,.10); }
.box.face { border-color: #a855f7; background: rgba(168,85,247,.12); }
.tag { position: absolute; left: -2px; top: -18px; padding: 1px 5px; font: 600 11px/16px ui-monospace, Menlo, Consolas, monospace;
  color: #fff; background: #ef4444; border-radius: 3px; white-space: nowrap; }
.t2 .tag { background: #b45309; }
.face .tag { background: #7e22ce; }
.box.top .tag { top: 0; }
`;

const viewportOf = (win) => ({ scrollX: win.scrollX || 0, scrollY: win.scrollY || 0, vw: win.innerWidth, vh: win.innerHeight });

/**
 * One overlay per content-script context (idempotent). Renders only on
 * update()/scroll/toggle events — there is no animation or polling loop.
 */
export function createOverlay({ win = window } = {}) {
  if (win.__perceiveOverlay) return win.__perceiveOverlay;

  const doc = win.document;
  const host = doc.createElement('div');
  host.id = OVERLAY_HOST_ID;
  const root = host.attachShadow({ mode: 'open' });
  root.innerHTML = `<style>${CSS}</style><div class="layer"><div class="shift"></div></div>`;
  const shift = root.querySelector('.shift');
  Object.assign(host.style, { all: 'initial', position: 'fixed', inset: '0', zIndex: '2147483646', pointerEvents: 'none', display: 'none' });

  let enabled = false;
  let last = null; // { items, captured: {scrollX, scrollY, vw, vh}, url }
  let ttl = null;
  let raf = 0;

  const clear = () => {
    last = null;
    clearTimeout(ttl);
    ttl = null;
    shift.replaceChildren();
    shift.style.transform = '';
  };

  const applyShift = () => {
    raf = 0;
    if (!last) return;
    const now = viewportOf(win);
    // Resized/zoomed: box geometry no longer matches the page. Drop it
    // rather than draw boxes in the wrong place; the next step re-fills it.
    if (now.vw !== last.captured.vw || now.vh !== last.captured.vh || win.location.href !== last.url) return clear();
    const { dx, dy } = scrollShift(last.captured, now);
    shift.style.transform = `translate(${dx}px, ${dy}px)`;
  };
  const schedule = () => { if (!raf && last) raf = win.requestAnimationFrame ? win.requestAnimationFrame(applyShift) : (applyShift(), 1); };

  const render = () => {
    const frag = doc.createDocumentFragment();
    for (const it of last.items) {
      const box = doc.createElement('div');
      box.className = `box${it.tier === 2 ? ' t2' : ''}${it.type === 'FACE' ? ' face' : ''}${it.y < 20 ? ' top' : ''}`;
      Object.assign(box.style, { left: `${it.x}px`, top: `${it.y}px`, width: `${it.w}px`, height: `${it.h}px` });
      const tag = doc.createElement('span');
      tag.className = 'tag';
      tag.textContent = it.confidence === null ? it.type : `${it.type} · ${it.confidence.toFixed(2)}`; // textContent: never parsed as HTML
      box.appendChild(tag);
      frag.appendChild(box);
    }
    shift.replaceChildren(frag);
    applyShift();
  };

  const onEvent = () => schedule();
  const listen = (on) => {
    const fn = on ? 'addEventListener' : 'removeEventListener';
    win[fn]('scroll', onEvent, { passive: true, capture: true });
    win[fn]('resize', onEvent);
    win[fn]('popstate', onEvent);
    win[fn]('hashchange', onEvent);
    if (win.navigation && win.navigation[fn]) win.navigation[fn]('currententrychange', onEvent); // SPA pushState
  };

  const attach = () => { if (!host.isConnected) (doc.documentElement || doc).appendChild(host); };

  const api = {
    host,
    isEnabled: () => enabled,
    hasResult: () => last !== null,
    setEnabled(on) {
      on = !!on;
      if (on === enabled) return;
      enabled = on;
      if (on) {
        attach();
        host.style.display = 'block';
        listen(true);
        if (last) render();
      } else {
        listen(false);
        host.style.display = 'none';
        shift.replaceChildren(); // keep `last` cheap to re-show, but nothing rendered while off
      }
    },
    /**
     * @param {{ redacted_regions, detection_confidence_notes, dom_summary }} result processPageForRedaction() output
     * @param {{scrollX, scrollY, vw, vh}} [captured] viewport at capture time
     */
    update(result, captured = viewportOf(win)) {
      clear();
      const items = toOverlayItems(result && result.redacted_regions, result && result.detection_confidence_notes, result && result.dom_summary && result.dom_summary.elements);
      if (!items.length) return;
      last = { items, captured, url: win.location.href };
      ttl = setTimeout(clear, RESULT_TTL_MS); // stale results don't linger
      if (enabled) render();
    },
    clear,
    // The overlay must not appear in the screenshot fed to vision.
    async suspendForCapture() {
      if (!enabled) return;
      host.style.visibility = 'hidden';
      await new Promise((resolve) => { // let the hide paint; never hang in a background tab
        const t = setTimeout(resolve, 100);
        if (win.requestAnimationFrame) win.requestAnimationFrame(() => win.requestAnimationFrame(() => { clearTimeout(t); resolve(); }));
      });
    },
    resumeAfterCapture() { host.style.visibility = ''; },
  };
  win.__perceiveOverlay = api;
  return api;
}
