// Background-side handlers for macro messages from content scripts.
//
// Trust rules enforced here (not by callers):
//   * only THIS extension's content scripts in a TOP-LEVEL http(s) tab may use
//     macros: sender.id must be our extension id and sender.tab must exist;
//   * the origin is derived from the browser-provided `sender` and is NEVER
//     read from the message, so a page/script cannot ask for another origin's
//     macros or file a macro under a different origin;
//   * every handler returns a plain object and never throws.

import { isValidOrigin } from '../macro/schema.js';

export const MACRO_MESSAGE_TYPES = new Set([
  'MACRO_GET_KEY', 'MACRO_LOOKUP', 'MACRO_GET', 'MACRO_PUT', 'MACRO_RECORD_RESULT', 'MACRO_LIST', 'MACRO_DELETE', 'MACRO_CLEAR',
]);

const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The origin of the tab that sent this message, from browser-supplied fields only. */
export function senderOrigin(sender, extensionId) {
  try {
    if (!sender || sender.id !== extensionId) return null;                    // not from our own extension
    if (!sender.tab || sender.frameId !== 0) return null;                      // content script in a top-level frame only
    const url = new URL(sender.tab.url || sender.url || '');
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return isValidOrigin(url.origin) ? url.origin : null;
  } catch (_e) {
    return null;
  }
}

export async function handleMacroMessage({ store, sender, message, extensionId }) {
  try {
    if (!store) return { ok: false, error: 'unavailable' };
    const origin = senderOrigin(sender, extensionId);
    if (!origin) return { ok: false, error: 'forbidden_sender' };

    switch (message.type) {
      case 'MACRO_GET_KEY':
        return { ok: true, key: await store.getKey() };

      case 'MACRO_LOOKUP': {
        if (!HEX64.test(String(message.task_fp))) return { ok: false, error: 'bad_request' };
        const r = await store.lookup(origin, message.task_fp);
        return { ok: true, macro: r.macro, dropped: r.dropped || 0 };
      }

      case 'MACRO_GET': {
        if (!UUID.test(String(message.macro_id))) return { ok: false, error: 'bad_request' };
        return { ok: true, macro: await store.getById(origin, message.macro_id) };   // active + this origin only
      }

      case 'MACRO_PUT':
        return await store.put(origin, message.body);                          // origin overwritten inside put()

      case 'MACRO_RECORD_RESULT':
        if (!UUID.test(String(message.macro_id))) return { ok: false, error: 'bad_request' };
        return await store.recordResult(origin, message.macro_id, { success: message.success === true, hard: message.hard === true });

      case 'MACRO_LIST':
        return { ok: true, ...(await store.list(origin)) };

      case 'MACRO_DELETE':
        if (!UUID.test(String(message.macro_id))) return { ok: false, error: 'bad_request' };
        return await store.delete(origin, message.macro_id);

      case 'MACRO_CLEAR':
        return await store.clearOrigin(origin);                                // this origin only

      default:
        return { ok: false, error: 'unknown_message' };
    }
  } catch (_e) {
    return { ok: false, error: 'internal_error' };
  }
}
