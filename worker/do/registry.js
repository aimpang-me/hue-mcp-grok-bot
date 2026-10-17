// Ops of the shared Durable Object instances, which hold no user data:
// - "bridge:<sha256 of bridge id>", one per bridge: the shared bridge key, who holds it, the per-day sign-in cap, and the per-day
//   Hue call budget of everyone on that bridge (one household), with a block of the global quota reserved in advance.
// - "global": the shared-app call counter.
import { LIMITS } from "../limits.js";

/** @typedef {import("../user-do.js").UserDO} DO */

/** A claim is a LEASE (`lease:<uid>` = { exp }, LIMITS.leaseTtlMs): it counts as a holder until bridgeConfirm moves it into `users`
 * (called once the user record is written) or the sweep / the next claim drops it. So a crash after the claim frees itself. */
const LEASE = "lease:";
/** @param {string} uid */
const leaseKey = (uid) => LEASE + uid;
/** Live (unexpired) leases; expired ones are deleted on the spot (lazy expiry, in case no alarm has run yet). @param {DO} d @returns {Promise<string[]>} */
async function liveLeases(d) {
  /** @type {string[]} */ const live = [];
  /** @type {string[]} */ const dead = [];
  for (const [k, v] of await d.storage.list({ prefix: LEASE })) (v.exp > d.now() ? live : dead).push(k);
  await d.deleteKeys(dead);
  return live.map((k) => k.slice(LEASE.length));
}

/** Start a sign-in on this bridge: count it against the daily cap and lease a holder slot. Returns the stored key, if any.
 * @param {DO} d @param {{ uid: string }} a */
export function bridgeClaim(d, { uid }) {
  return d.serial(async () => {
    await liveLeases(d);
    if (!(await d.bump("bl", d.num("BRIDGE_LOGINS_PER_DAY", LIMITS.bridgeLoginsPerDay))).ok) return /** @type {const} */ ({ limited: true });
    const exp = d.now() + LIMITS.leaseTtlMs;
    await d.storage.put(leaseKey(uid), { exp }); await d.wake(exp);
    return { key: /** @type {string|null} */ ((await d.storage.get("key")) ?? null) };
  });
}

/** The user record is written: turn the lease into a permanent holder. Idempotent. Refused ({ ok: false }) when the lease already expired:
 * the key may have been returned to the bridge meanwhile, so the sign-in must fail rather than become a holder of a dead key.
 * @param {DO} d @param {{ uid: string }} a */
export function bridgeConfirm(d, { uid }) {
  return d.serial(async () => {
    const users = (await d.storage.get("users")) ?? [];
    if (users.includes(uid)) return { ok: true };
    if (!(await liveLeases(d)).includes(uid)) return { ok: false };
    await Promise.all([d.storage.put("users", [...users, uid]), d.storage.delete(leaseKey(uid))]); // one atomic write
    return { ok: true };
  });
}

/** A sign-in failed before it was confirmed: drop just its lease. Unlike release this never returns or deletes the key (a failed pairing says nothing about the key on the bridge).
 * @param {DO} d @param {{ uid: string }} a */
export function bridgeAbandon(d, { uid }) { return d.serial(async () => { await d.storage.delete(leaseKey(uid)); return { ok: true }; }); }

/** Store a freshly paired key, but only if the registry still holds `expect` (the key this sign-in saw when it claimed, or null).
 * Compare-and-set: when two first sign-ins on one bridge race, the first put wins and the loser gets `{ ok: false, key }` back,
 * so it can remove its own duplicate from the bridge and use the winner's key instead of silently overwriting it.
 * @param {DO} d @param {{ uid: string, key: string, expect: string|null }} a */
export function bridgePut(d, { key, expect }) {
  return d.serial(async () => {
    const cur = (await d.storage.get("key")) ?? null;
    if (cur !== (expect ?? null)) return { ok: false, key: cur };
    await d.storage.put("key", key);
    return { ok: true, key };
  });
}

/** Drop one holder (confirmed or leased); returns the key only when nobody holds it any more (caller then removes it from the bridge).
 * @param {DO} d @param {{ uid: string }} a */
export function bridgeRelease(d, { uid }) {
  return d.serial(async () => {
    await d.storage.delete(leaseKey(uid));
    const users = ((await d.storage.get("users")) ?? []).filter((/** @type {string} */ u) => u !== uid);
    if (users.length || (await liveLeases(d)).length) { await d.storage.put("users", users); return { key: null }; }
    const key = (await d.storage.get("key")) ?? null;
    await d.storage.delete(["key", "users"]);
    return { key };
  });
}

/** Take one Hue call from today's budget for this bridge, and from the shared-app budget. The bridge reserves global quota in blocks
 * of LIMITS.quotaBlock, so the global counter sees one request per block instead of one per call. Unused reservations lapse with the day.
 * @param {DO} d @returns {Promise<{ ok: boolean, reason?: "bridge" | "global" }>} */
export function bridgeCall(d) {
  return d.serial(async () => {
    const day = d.day(), usedKey = `bc:${day}`, leftKey = `bq:${day}`;
    const used = (await d.storage.get(usedKey)) ?? 0;
    if (used >= d.num("DAILY_HUE_CALLS", LIMITS.bridgeDailyCalls)) return { ok: false, reason: /** @type {const} */ ("bridge") };
    let left = (await d.storage.get(leftKey)) ?? 0;
    if (!left) left = (await d.peer("global", { op: "quotaBlock", n: LIMITS.quotaBlock })).granted;
    if (!left) return { ok: false, reason: /** @type {const} */ ("global") };
    await d.storage.put({ [usedKey]: used + 1, [leftKey]: left - 1 });
    await d.wake(d.dayEnd());
    return { ok: true };
  });
}

/** Global instance: grant up to `n` calls of today's shared-app budget (Hue allows 50,000 per day; we cap lower for headroom).
 * @param {DO} d @param {{ n: number }} a */
export function quotaBlock(d, { n }) {
  return d.serial(async () => {
    const cap = d.num("GLOBAL_DAILY_CALLS", LIMITS.globalDailyCalls), used = (await d.storage.get(`gq:${d.day()}`)) ?? 0;
    const granted = Math.max(0, Math.min(n, cap - used));
    if (granted) await d.bump("gq", cap, granted);
    return { granted };
  });
}

/** Global instance: are new sign-ins still welcome (less than LIMITS.newLoginsUntil of today's budget handed out)? @param {DO} d */
export async function capacity(d) {
  const used = (await d.storage.get(`gq:${d.day()}`)) ?? 0;
  return { ok: used < d.num("GLOBAL_DAILY_CALLS", LIMITS.globalDailyCalls) * LIMITS.newLoginsUntil };
}
