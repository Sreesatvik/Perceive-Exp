// Durable macro storage (chrome.storage.local, owned by the background worker).
//
// Why .local: macros are a deliberate cross-session feature. That is safe only
// because a macro holds no secrets and no plain labels/task text (see
// macro/schema.js) — contrast dev2/origin-sensitivity-profile.js, which is
// session-scoped on purpose because it stores label text.
//
// Guarantees
//   * origin isolation: one storage key per origin; lookups never cross origins;
//   * bounded: macros/origin, origins, bytes/macro, 90-day unused TTL;
//   * atomic writes: one storage.set per change; a failed write (quota etc.)
//     leaves existing macros untouched and is reported, never thrown;
//   * corruption-safe: every macro is schema-validated and integrity-checked
//     (HMAC) on read; bad entries are dropped and reported, never executed;
//   * serialized: mutations run one at a time (no lost updates).

import { validateMacro, validateCandidateBody, canonicalJson, macroBody, isValidOrigin, LIMITS, SCHEMA_VERSION } from '../macro/schema.js';
import { hmacHex, randomKeyHex, randomUuid } from '../macro/hmac.js';

const KEY_KEY = 'perceive.macro.key.v1';
const INDEX_KEY = 'perceive.macro.index.v1';
const originKey = (origin) => `perceive.macro.v1.${origin}`;

/** Adapter over chrome.storage.local (or any {get,set,remove} for tests). */
export function chromeLocalAdapter(chromeApi = globalThis.chrome) {
  const area = chromeApi && chromeApi.storage && chromeApi.storage.local;
  if (!area) return null;
  return { get: (k) => area.get(k), set: (o) => area.set(o), remove: (k) => area.remove(k) };
}

export function createMacroStore({ storage, now = () => Date.now() } = {}) {
  if (!storage) throw new Error('macro storage unavailable');

  let chain = Promise.resolve();
  const serialize = (fn) => { const run = chain.then(fn, fn); chain = run.catch(() => {}); return run; };

  let keyPromise = null;
  function getKey() {
    if (!keyPromise) {
      keyPromise = (async () => {
        const got = await storage.get(KEY_KEY);
        if (typeof got[KEY_KEY] === 'string' && /^[0-9a-f]{64}$/.test(got[KEY_KEY])) return got[KEY_KEY];
        const fresh = randomKeyHex();
        await storage.set({ [KEY_KEY]: fresh });
        return fresh;
      })().catch((e) => { keyPromise = null; throw e; });
    }
    return keyPromise;
  }

  const stamp = (m) => (m.last_used_at ?? m.created_at);

  /** Reads + validates one origin's macros. Returns valid ones and what was dropped. */
  async function readOrigin(origin) {
    const key = await getKey();
    const raw = (await storage.get(originKey(origin)))[originKey(origin)];
    const out = { macros: [], dropped: { corrupt: 0, unsupported_version: 0, expired: 0, invalid: 0 }, structurallyBad: false };
    if (raw === undefined) return out;
    if (!raw || typeof raw !== 'object' || raw.v !== 1 || !Array.isArray(raw.macros)) { out.structurallyBad = true; return out; }
    for (const m of raw.macros) {
      const v = validateMacro(m);
      if (!v.ok) { out.dropped[v.reason === 'unsupported_version' ? 'unsupported_version' : 'invalid']++; continue; }
      if (m.origin !== origin) { out.dropped.invalid++; continue; }               // a macro filed under the wrong origin
      const expect = await hmacHex(key, canonicalJson(macroBody(m)));
      if (expect !== m.integrity) { out.dropped.corrupt++; continue; }
      if (now() - stamp(m) > LIMITS.UNUSED_TTL_MS) { out.dropped.expired++; continue; }
      out.macros.push(m);
    }
    return out;
  }

  const totalDropped = (d) => d.corrupt + d.unsupported_version + d.expired + d.invalid;

  async function writeOrigin(origin, macros, { touch = true } = {}) {
    const idx = (await storage.get(INDEX_KEY))[INDEX_KEY];
    const origins = idx && typeof idx === 'object' && idx.origins && typeof idx.origins === 'object' ? { ...idx.origins } : {};
    const evictedOrigins = [];
    if (macros.length) {
      if (touch || !(origin in origins)) origins[origin] = now();
      // Global origin cap: evict the least-recently-touched OTHER origins.
      const others = Object.keys(origins).filter((o) => o !== origin).sort((a, b) => origins[a] - origins[b]);
      while (Object.keys(origins).length > LIMITS.MAX_ORIGINS && others.length) { const o = others.shift(); delete origins[o]; evictedOrigins.push(o); }
    } else {
      delete origins[origin];
    }
    const payload = { [INDEX_KEY]: { v: 1, origins } };
    if (macros.length) payload[originKey(origin)] = { v: 1, macros };
    try {
      await storage.set(payload);                                     // ONE atomic write
      if (!macros.length) await storage.remove(originKey(origin));
      if (evictedOrigins.length) await storage.remove(evictedOrigins.map(originKey));
      return { ok: true };
    } catch (e) {
      const msg = String((e && e.message) || e);
      return { ok: false, error: /quota/i.test(msg) ? 'storage_quota' : 'storage_error' };
    }
  }

  const summary = (m) => ({ macro_id: m.macro_id, steps: m.steps.length, created_at: m.created_at, last_used_at: m.last_used_at, status: m.status, stats: { ...m.stats } });

  return {
    getKey,

    /** Active macro for (origin, task fingerprint), or null. Self-heals corrupt entries. */
    lookup: (origin, taskFp) => serialize(async () => {
      if (!isValidOrigin(origin) || !/^[0-9a-f]{64}$/.test(String(taskFp))) return { macro: null, dropped: 0, error: 'bad_request' };
      const { macros, dropped, structurallyBad } = await readOrigin(origin);
      if (structurallyBad) { await writeOrigin(origin, []); return { macro: null, dropped: 1, error: 'corrupt_store' }; }
      const dropCount = totalDropped(dropped);
      if (dropCount) await writeOrigin(origin, macros, { touch: false });   // purge what we refused to use
      const hit = macros.find((m) => m.task_fp === taskFp && m.status === 'active') || null;
      return { macro: hit, dropped: dropCount, dropped_by_reason: dropped };
    }),

    /** One active macro by id (origin-scoped, validated + integrity-checked). */
    getById: (origin, macroId) => serialize(async () => {
      if (!isValidOrigin(origin)) return null;
      const { macros } = await readOrigin(origin);
      return macros.find((m) => m.macro_id === macroId && m.status === 'active') || null;
    }),

    /** Summaries only (no steps) — for UI. */
    list: (origin) => serialize(async () => {
      if (!isValidOrigin(origin)) return { macros: [] };
      const { macros } = await readOrigin(origin);
      return { macros: macros.map(summary) };
    }),

    /**
     * Validates and stores a candidate. The origin is supplied by the CALLER
     * (the background derives it from the message sender) — never from the body.
     */
    put: (origin, body) => serialize(async () => {
      if (!isValidOrigin(origin)) return { ok: false, error: 'bad_origin' };
      if (!body || typeof body !== 'object') return { ok: false, error: 'invalid' };
      const candidate = { ...body, origin };                          // the sender's origin always wins
      const v = validateCandidateBody(candidate);
      if (!v.ok) return { ok: false, error: v.reason };
      const key = await getKey();
      const { macros } = await readOrigin(origin);
      const core = { macro_id: randomUuid(), schema_version: SCHEMA_VERSION, origin, task_fp: candidate.task_fp, created_at: now(), steps: candidate.steps };
      const macro = { ...core, last_used_at: null, status: 'active', stats: { replays: 0, successes: 0, consecutive_failures: 0 }, integrity: await hmacHex(key, canonicalJson(macroBody(core))) };
      const final = validateMacro(macro);
      if (!final.ok) return { ok: false, error: final.reason };
      // One macro per (origin, task): a re-save replaces the old one.
      const next = macros.filter((m) => m.task_fp !== macro.task_fp);
      next.push(macro);
      while (next.length > LIMITS.MAX_MACROS_PER_ORIGIN) next.splice(pickVictim(next, macro.macro_id), 1);
      const w = await writeOrigin(origin, next);
      return w.ok ? { ok: true, macro_id: macro.macro_id } : w;
    }),

    delete: (origin, macroId) => serialize(async () => {
      if (!isValidOrigin(origin)) return { ok: false, error: 'bad_origin' };
      const { macros } = await readOrigin(origin);
      const next = macros.filter((m) => m.macro_id !== macroId);
      if (next.length === macros.length) return { ok: true, removed: 0 };
      const w = await writeOrigin(origin, next, { touch: false });
      return w.ok ? { ok: true, removed: 1 } : w;
    }),

    clearOrigin: (origin) => serialize(async () => (isValidOrigin(origin) ? writeOrigin(origin, []) : { ok: false, error: 'bad_origin' })),

    clearAll: () => serialize(async () => {
      const idx = (await storage.get(INDEX_KEY))[INDEX_KEY];
      const origins = idx && idx.origins && typeof idx.origins === 'object' ? Object.keys(idx.origins).filter(isValidOrigin) : [];
      try { await storage.remove([INDEX_KEY, ...origins.map(originKey)]); return { ok: true, cleared: origins.length }; }
      catch (_e) { return { ok: false, error: 'storage_error' }; }
    }),

    /**
     * Replay outcome bookkeeping. A hard failure (policy rejection) or
     * QUARANTINE_AFTER_FAILURES consecutive failures quarantines the macro.
     */
    recordResult: (origin, macroId, { success, hard = false }) => serialize(async () => {
      if (!isValidOrigin(origin)) return { ok: false, error: 'bad_origin' };
      const { macros } = await readOrigin(origin);
      const m = macros.find((x) => x.macro_id === macroId);
      if (!m) return { ok: false, error: 'not_found' };
      m.stats.replays += 1;
      m.last_used_at = now();
      if (success) { m.stats.successes += 1; m.stats.consecutive_failures = 0; }
      else {
        m.stats.consecutive_failures += 1;
        if (hard || m.stats.consecutive_failures >= LIMITS.QUARANTINE_AFTER_FAILURES) m.status = 'quarantined';
      }
      const w = await writeOrigin(origin, macros, { touch: false });
      return w.ok ? { ok: true, status: m.status } : w;
    }),
  };

  /** Index of the macro to evict: a quarantined one first, else the least recently used. Never the one just saved. */
  function pickVictim(list, keepId) {
    let best = -1;
    for (let i = 0; i < list.length; i++) {
      if (list[i].macro_id === keepId) continue;
      if (best === -1) { best = i; continue; }
      const a = list[i], b = list[best];
      const aq = a.status === 'quarantined', bq = b.status === 'quarantined';
      if (aq !== bq ? aq : stamp(a) < stamp(b)) best = i;
    }
    return best;
  }
}
