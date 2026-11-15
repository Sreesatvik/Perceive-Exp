// Page title / main heading / visible status banner text, forwarded to the
// LLM as `page_status_text` (untrusted DATA). Text a human could not see
// (display:none, opacity 0, tiny, off-screen) is left out — a classic place
// to hide prompt-injection text — and anything PII-shaped drops the whole
// field. Moved out of orchestrator.js unchanged in behavior (plus the hidden-
// text checks in visibility.js) so it can be tested directly.
import { detectPII } from '../../dev2/pii-patterns.js';
import { isElementVisible } from './visibility.js';

export function extractPageStatusText(doc = (typeof document !== 'undefined' ? document : null), win = (typeof window !== 'undefined' ? window : null)) {
  if (!doc || !win) return null;
  const isVisible = (el) => isElementVisible(el, win);

  const parts = [];
  if (doc.title) parts.push(doc.title.trim());

  const heading = doc.querySelector('h1, h2');
  if (heading && isVisible(heading) && heading.textContent) parts.push(heading.textContent.trim());

  // Real bug found live (2nd pass): the first version of this selector
  // only matched ARIA roles / a fixed class list (.success/.confirmation/
  // etc). The actual test fixture's confirmation banner is
  // `<div id="status" style="display:none">Phone number updated.</div>`,
  // toggled to display:block on click — matching NEITHER role NOR class,
  // so page_status_text was silently always empty and this whole fix did
  // nothing. Broadened to also match common id/class SUBSTRING
  // conventions (status/message/confirm/success/error/alert/notice), and
  // — critically — now requires the element to actually be VISIBLE
  // (display != none, visibility != hidden, non-zero box) before its text
  // counts, since querySelector finds a hidden element just fine and this
  // must never report "updated" before the update actually happened.
  const STATUS_SELECTOR =
    '[role="status"], [role="alert"], [aria-live], ' +
    '[id*="status" i], [id*="message" i], [id*="confirm" i], [id*="success" i], [id*="error" i], [id*="alert" i], [id*="notice" i], ' +
    '[class*="status"], [class*="message"], [class*="confirm"], [class*="success"], [class*="error"], [class*="alert"], [class*="notice"]';
  const statusEl = Array.from(doc.querySelectorAll(STATUS_SELECTOR))
    .find((el) => isVisible(el) && el.textContent && el.textContent.trim());
  if (statusEl) parts.push(statusEl.textContent.trim());

  const combined = parts.filter(Boolean).join(' | ').slice(0, 300);
  if (!combined) return null;

  // Defense in depth: never forward this if it happens to contain
  // anything PII-shaped (e.g. a raw credential leaking into a heading on
  // some unexpected page) — drop the whole field rather than partially
  // redact free text we don't control the shape of.
  if (detectPII(combined).length > 0) return null;

  return combined;
}

