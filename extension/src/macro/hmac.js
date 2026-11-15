// Keyed hashing for macros (WebCrypto HMAC-SHA256). Names, task text and
// form context are stored ONLY as these keyed hashes, so a copy of the macro
// store reveals neither labels (which can contain personal data) nor the task.
// The key is a per-install random secret held by the background worker.

const enc = new TextEncoder();
const HEX = '0123456789abcdef';

export const toHex = (buf) => {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += HEX[b[i] >> 4] + HEX[b[i] & 15];
  return s;
};

export function randomKeyHex(bytes = 32) {
  const b = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(b);
  return toHex(b);
}

export function randomUuid() {
  return globalThis.crypto.randomUUID();
}

const keyCache = new Map(); // hex -> CryptoKey

async function importKey(keyHex) {
  if (typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex)) throw new Error('bad_macro_key');
  if (!keyCache.has(keyHex)) {
    const raw = new Uint8Array(keyHex.match(/../g).map((h) => parseInt(h, 16)));
    keyCache.set(keyHex, await globalThis.crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']));
  }
  return keyCache.get(keyHex);
}

/** @returns {Promise<string>} 64 hex chars */
export async function hmacHex(keyHex, text) {
  const key = await importKey(keyHex);
  return toHex(await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(String(text))));
}
