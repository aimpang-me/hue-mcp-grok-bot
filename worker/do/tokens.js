// MCP code/token lifecycle inside a user's Durable Object: mint and redeem codes (single use, PKCE), rotate refresh tokens, validate
// access tokens. Only sha256(token) is stored; every record carries its own `exp` so the cleanup alarm (worker/sweep.js) can drop it.
// Writes that belong together are issued without an await between them, which Durable Objects commit atomically.
import { rand, sha256Hex, sha256b64url, safeEqual, hit, handleOf } from "../util.js";
import { LIMITS, MIN } from "../limits.js";

/** @typedef {import("../user-do.js").UserDO} DO */
/** @typedef {import("../do-client.js").CodeGrant & { grant: string, born: number }} Grant */

/** Mint a one-time authorization code for a new sign-in. @param {DO} d @param {string} handle @param {import("../do-client.js").CodeGrant} code */
export async function mintCode(d, handle, code) {
  const secret = rand(), now = d.now(), exp = now + LIMITS.codeTtlMs;
  await d.storage.put(`code:${await sha256Hex(`${handle}.${secret}`)}`, { ...code, grant: rand(12), born: now, exp });
  await d.wake(exp); // if nobody redeems this code, the alarm cleans up and frees the bridge key
  return `${handle}.${secret}`;
}

/** Mint an access + refresh token pair for a grant, bound to its client and audience. It is written in one atomic step together with
 * the `extra` records and the deletion of `drop`. Neither token outlives the grant's absolute lifetime (`born` + LIMITS.grantMaxMs),
 * so refreshing cannot keep a sign-in alive forever.
 * @param {DO} d @param {Grant} g @param {string} handle @param {Record<string, unknown>} [extra] @param {string[]} [drop] */
async function issue(d, { grant, cid, resource, born }, handle, extra = {}, drop = []) {
  const at = rand(), rt = rand(), now = d.now(), end = born + LIMITS.grantMaxMs, rec = { grant, cid, resource, born };
  const atExp = Math.min(now + LIMITS.accessTtlMs, end), rtExp = Math.min(now + LIMITS.refreshTtlMs, end);
  const [atKey, rtKey] = [`at:${await sha256Hex(`${handle}.${at}`)}`, `rt:${await sha256Hex(`${handle}.${rt}`)}`];
  await Promise.all([d.storage.put({ [atKey]: { ...rec, exp: atExp }, [rtKey]: { ...rec, exp: rtExp }, ...extra }), ...(drop.length ? [d.storage.delete(drop)] : [])]);
  await d.wake(atExp);
  return { access_token: `${handle}.${at}`, refresh_token: `${handle}.${rt}`, expires_in: Math.max(0, Math.floor((atExp - now) / 1000)), token_type: /** @type {const} */ ("Bearer"), resource };
}

/** Kill every token of a grant (kept as long as its refresh tokens could live). @param {DO} d @param {string} grant */
const revokeGrant = (d, grant) => d.storage.put(`grant:${grant}`, { revoked: true, exp: d.now() + LIMITS.refreshTtlMs });

/** Redeem an authorization code (single use, PKCE S256, bound to client + redirect_uri + audience). Presenting a code a second time
 * is treated as theft: everything issued from it is revoked. @param {DO} d @param {import("../do-client.js").Ops["redeem"][0]} a */
export function redeem(d, a) {
  return d.serial(async () => {
    if (await d.storage.get("disabled")) return { error: "invalid_grant" };
    const key = `code:${await sha256Hex(a.code)}`, rec = await d.storage.get(key);
    if (rec?.used) { await revokeGrant(d, rec.grant); return { error: "invalid_grant" }; }
    await d.storage.delete(key); // single use even if validation below fails
    // redirect_uri must match when it was part of the authorize request; when the client left it out there, it may leave it out here too (RFC 6749 4.1.3).
    const ruriOk = rec?.ruriSent === false ? !a.ruri || a.ruri === rec.ruri : rec?.ruri === a.ruri;
    if (!rec || rec.exp < d.now() || rec.cid !== a.cid || !ruriOk) return { error: "invalid_grant" };
    if (!a.verifier || !safeEqual(await sha256b64url(a.verifier), rec.chal)) return { error: "invalid_grant" };
    // /token only checks that the asked resource is THIS origin's /mcp; this compares it with the audience the code was issued for (differs across origins).
    if (a.resource && a.resource !== rec.resource) return { error: "invalid_target" };
    return issue(d, rec, handleOf(a.code), { [key]: { used: true, grant: rec.grant, exp: d.now() + LIMITS.refreshTtlMs } }); // marker: reuse revokes the grant
  });
}

/** Rotate an MCP refresh token. Re-use of an already-rotated token revokes the whole grant. @param {DO} d @param {import("../do-client.js").Ops["refresh"][0]} a */
export function refreshMcp(d, a) {
  return d.serial(async () => {
    if (await d.storage.get("disabled")) return { error: "invalid_grant" };
    const h = await sha256Hex(a.token), key = `rt:${h}`, rec = await d.storage.get(key);
    const used = await d.storage.get(`used:${h}`);
    if (used) { await revokeGrant(d, used.grant); return { error: "invalid_grant" }; }
    if (!rec || rec.exp < d.now() || rec.cid !== a.cid) return { error: "invalid_grant" }; // bound to the client it was issued to
    if ((await d.storage.get(`grant:${rec.grant}`))?.revoked) return { error: "invalid_grant" };
    if (a.resource && a.resource !== rec.resource) return { error: "invalid_target" }; // same cross-origin case as redeem
    return issue(d, rec, handleOf(a.token), { [`used:${h}`]: { grant: rec.grant, exp: rec.exp } }, [key]);
  });
}

/** A live, unrevoked access or refresh token record for this token, or null. @param {DO} d @param {string} token @param {("at"|"rt")[]} kinds */
export async function liveToken(d, token, kinds) {
  const h = await sha256Hex(token);
  for (const kind of kinds) {
    const rec = await d.storage.get(`${kind}:${h}`);
    if (rec && rec.exp > d.now() && !(await d.storage.get(`grant:${rec.grant}`))?.revoked) return rec;
  }
  return null;
}

/** Validate an MCP access token for this audience and apply the per-sign-in rate limit (keyed by grant, so refreshing does not reset it).
 * @param {DO} d @param {{ token: string, resource: string }} a */
export async function authz(d, { token, resource }) {
  if (await d.storage.get("disabled")) return { ok: false };
  const rec = await liveToken(d, token, ["at"]);
  if (!rec || rec.resource !== resource) return { ok: false };
  const r = hit(d.win, `grant:${rec.grant}`, d.num("RATE_PER_MIN", LIMITS.ratePerMin), MIN, d.now());
  return r.ok ? { ok: true } : { ok: false, limited: true, retryAfter: r.retryAfter };
}
