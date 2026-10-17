// Tiny in-memory TTL cache. Lives as long as the Worker isolate (or the stdio process); safe to lose at any time.
/** @template V @param {{ ttlMs?: number, now?: () => number }} [o] */
export function createTtlCache({ ttlMs = 300_000, now = Date.now } = {}) {
  /** @type {Map<string, {v: V, exp: number}>} */
  const m = new Map();
  return {
    /** @param {string} k @returns {V|undefined} */
    get(k) { const e = m.get(k); if (!e) return undefined; if (now() >= e.exp) { m.delete(k); return undefined; } return e.v; },
    /** @param {string} k @param {V} v */
    set(k, v) { m.set(k, { v, exp: now() + ttlMs }); },
    /** @param {string} k */
    delete(k) { m.delete(k); },
    clear() { m.clear(); },
  };
}
