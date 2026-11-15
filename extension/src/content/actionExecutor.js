import { findAgentElementResilient } from './domIndex.js';
import { selectNativeOption, selectCustomOption } from './dropdown.js';

// Same safe value rule for every value-carrying action: a bracketed value is
// a semantic token and MUST resolve through the vault; a failed resolve is
// an error, never a fall-through to typing the literal token text.
function resolveActionValue(value, resolveToken, targetId) {
    const v = value || '';
    if (v.startsWith('[') && v.endsWith(']')) {
        const resolved = resolveToken(v);
        if (!resolved) {
            console.warn('[ActionExecutor] Failed to resolve token:', v, '| target:', targetId);
            return { error: 'unresolvable_token' };
        }
        return { value: resolved };
    }
    return { value: v };
}

/**
 * Executes a validated action on the real DOM.
 * @param {Object} action — validated server response action
 * @param {Function} resolveToken — Dev 2's vault.resolveToken, bound and passed in
 * @returns {Promise<Object>} — { success: boolean, error?: string, domChanged?: boolean }
 */
export async function executeAction(action, resolveToken, perceivedElement = null) {
    console.log(`[ActionExecutor] Executing action: ${action.type}`);

    if (action.type === 'task_complete' || action.type === 'task_failed') {
        return { success: true, domChanged: false };
    }

    if (action.type === 'wait') {
        const delay = parseInt(action.value, 10) || 1000;
        await new Promise(r => setTimeout(r, delay));
        return { success: true, domChanged: false };
    }

    // For click, type, scroll, we need a target element. Phase 5.1: a
    // direct lookup miss or tag+label mismatch (both signs of an SPA
    // re-render that dropped our data-ext-id tag) triggers a re-index
    // attempt before giving up — see domIndex.js.
    let targetElement = null;
    if (action.target_element_id) {
        const lookup = findAgentElementResilient(action.target_element_id, perceivedElement);
        targetElement = lookup.element;
        if (lookup.reindexed) {
            console.log(`[ActionExecutor] Re-indexed stale target '${action.target_element_id}' after DOM mutation`);
        }
    }

    if (!targetElement && ['click', 'type', 'scroll', 'select_custom'].includes(action.type)) {
        return { success: false, error: 'target_element_not_found' };
    }

    // Visibility check
    if (targetElement) {
        const rect = targetElement.getBoundingClientRect();
        const isVisible = (rect.width > 0 && rect.height > 0) &&
                          window.getComputedStyle(targetElement).visibility !== 'hidden';
        if (!isVisible || targetElement.disabled) {
            return { success: false, error: 'element_not_interactable' };
        }
    }

    try {
        switch (action.type) {
            case 'click':
                console.log('[ActionExecutor] Clicking element:', targetElement, 'tag:', targetElement.tagName, 'type:', targetElement.type, 'id:', targetElement.id);

                // TEMPORARILY DISABLED for real-site testing — this preventDefault()
                // blocks genuine form submission, which is needed to verify the
                // agent's task_complete claims are actually true on a real site.
                // RESTORE this block before running in the sandbox/test-harness
                // context, where real navigation would wipe test state.
                //
                // if (targetElement.type === 'submit' || targetElement.tagName === 'BUTTON') {
                //     const form = targetElement.closest('form');
                //     if (form) {
                //         const handler = (e) => e.preventDefault();
                //         form.addEventListener('submit', handler, { once: true });
                //     }
                // }

                targetElement.click();
                return { success: true, domChanged: true };
            case 'type': {
                const r = resolveActionValue(action.value, resolveToken, action.target_element_id);
                if (r.error) return { success: false, error: r.error };

                // A native <select> can't be typed into: `.value = 'Hyderabad'`
                // silently selects nothing. Route to option matching instead.
                if (targetElement.tagName === 'SELECT') {
                    return await selectNativeOption(targetElement, r.value);
                }

                // Set value and dispatch synthetic events so SPA frameworks pick it up
                targetElement.value = r.value;
                targetElement.dispatchEvent(new Event('input', { bubbles: true }));
                targetElement.dispatchEvent(new Event('change', { bubbles: true }));

                return { success: true, domChanged: true };
            }

            case 'select_custom': {
                const r = resolveActionValue(action.value, resolveToken, action.target_element_id);
                if (r.error) return { success: false, error: r.error };
                return targetElement.tagName === 'SELECT'
                    ? await selectNativeOption(targetElement, r.value)
                    : await selectCustomOption(targetElement, r.value);
            }

            case 'scroll':
                targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                return { success: true, domChanged: false };

            case 'ask_user_confirmation':
                // Will be handled by the orchestrator calling confirmationUI.js
                return { success: true, domChanged: false };

            default:
                return { success: false, error: 'unknown_action_type' };
        }
    } catch (error) {
        console.error(`[ActionExecutor] Error executing ${action.type}:`, error);
        return { success: false, error: error.message };
    }
}