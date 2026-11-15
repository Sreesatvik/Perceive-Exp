// "Would a human plausibly see this text?" — used to keep visually hidden
// webpage text (a classic prompt-injection hiding place) out of what we
// forward to the LLM as page status text. Hidden text is still treated as
// untrusted DATA wherever it does get through; this only removes text no user
// could have read. Style-only on purpose: jsdom (used by our tests) computes
// no layout, so rect-based checks would always report "hidden" there.
export function isElementVisible(el, win = window) {
  if (!el) return false;
  
  // Traverse ancestors to check for hidden parents (since jsdom lacks layout/offsetParent)
  let current = el;
  while (current && current.nodeType === 1) {
    const parentStyle = win.getComputedStyle(current);
    if (parentStyle.display === 'none' || parentStyle.visibility === 'hidden') return false;
    const parentOpacity = parseFloat(parentStyle.opacity);
    if (Number.isFinite(parentOpacity) && parentOpacity <= 0.05) return false;
    current = current.parentNode;
  }

  const style = win.getComputedStyle(el);
  // Only a resolved px value is trusted (Chrome always resolves computed sizes
  // to px; unresolved units like "2em" must not be misread as tiny).
  const fontSize = /px\s*$/.test(style.fontSize) ? parseFloat(style.fontSize) : NaN;
  if (Number.isFinite(fontSize) && fontSize < 4) return false;                 // tiny text
  if ((style.position === 'absolute' || style.position === 'fixed')) {         // shoved off-screen
    const left = parseFloat(style.left);
    const top = parseFloat(style.top);
    if ((Number.isFinite(left) && left <= -1000) || (Number.isFinite(top) && top <= -1000)) return false;
  }
  const indent = parseFloat(style.textIndent);
  if (Number.isFinite(indent) && indent <= -1000) return false;                // text-indent: -9999px
  return true;
}
