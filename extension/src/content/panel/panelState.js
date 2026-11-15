// Persisted geometry/open state for the in-page panel. Pure logic + an
// injected `store` ({ get(key) -> Promise<obj>, set(obj) -> Promise }) so it
// is unit-testable without a browser.
export const STATE_KEY = 'perceivePanelState';
export const MIN_WIDTH = 260;
export const MIN_HEIGHT = 200;
export const DEFAULT_STATE = { x: null, y: null, width: 340, height: 380, open: false, minimized: false, overlay: false, macros: false };

const num = (v, fallback) => (Number.isFinite(v) ? v : fallback);

// Keeps the panel fully reachable: size within [min, viewport - margin],
// position within the viewport so the header can never be dragged offscreen.
export function clampState(s, vw, vh) {
  const width = Math.min(Math.max(num(s.width, DEFAULT_STATE.width), MIN_WIDTH), Math.max(MIN_WIDTH, vw - 16));
  const height = Math.min(Math.max(num(s.height, DEFAULT_STATE.height), MIN_HEIGHT), Math.max(MIN_HEIGHT, vh - 16));
  const x = Math.min(Math.max(num(s.x, vw - width - 16), 0), Math.max(0, vw - width));
  const y = Math.min(Math.max(num(s.y, 16), 0), Math.max(0, vh - 40)); // header row always on screen
  return { x, y, width, height, open: !!s.open, minimized: !!s.minimized, overlay: !!s.overlay, macros: !!s.macros };
}

export async function loadState(store) {
  try {
    const got = store ? await store.get(STATE_KEY) : null;
    return { ...DEFAULT_STATE, ...((got && got[STATE_KEY]) || {}) };
  } catch (_e) {
    return { ...DEFAULT_STATE };
  }
}

export async function saveState(store, state) {
  try {
    if (store) await store.set({ [STATE_KEY]: state });
  } catch (_e) {
    // persistence is a convenience, never a requirement
  }
}

// chrome.storage.session lives for the browser session; the background
// worker opens it to content scripts via setAccessLevel (see transport.js).
export function sessionStore(chromeApi = globalThis.chrome) {
  return chromeApi && chromeApi.storage && chromeApi.storage.session ? chromeApi.storage.session : null;
}
