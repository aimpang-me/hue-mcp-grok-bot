// The single way code in this Worker talks to a Durable Object: one JSON op in, one JSON result out, with a typed contract.
// One class (worker/user-do.js) serves three kinds of instance: a user (named by user id), a bridge registry ("bridge:<hash>")
// and the shared counters ("global"). The comment on each op says which instance it is for.

/** @typedef {{ access_token: string, refresh_token: string, expires_in: number, token_type: "Bearer", resource: string }} TokenPair */
/** @typedef {{ cid: string, ruri: string, ruriSent: boolean, chal: string, resource: string }} CodeGrant cid is sha256(client_id) */
/** @typedef {{ error: string }} Failure */

/** Every op: name -> [arguments, result].
 * @typedef {{
 *   connect: [{ uid: string, handle: string, hue: import("../server/transport-remote.js").Tokens, code: CodeGrant }, { code: string } | { code?: undefined, error: string }],
 *   hue: [{ method: string, path: string, body?: unknown }, { status: number, text: string }],
 *   disconnect: [{ token: string }, { ok: boolean }],
 *   redeem: [{ code: string, verifier: string, cid: string, ruri: string, resource?: string }, TokenPair | Failure],
 *   refresh: [{ token: string, cid: string, resource?: string }, TokenPair | Failure],
 *   authz: [{ token: string, resource: string }, { ok: boolean, limited?: boolean, retryAfter?: number }],
 *   capacity: [{}, { ok: boolean }],
 *   quotaBlock: [{ n: number }, { granted: number }],
 *   bridgeClaim: [{ uid: string }, { limited: true, key?: undefined } | { limited?: undefined, key: string|null }],
 *   bridgePut: [{ uid: string, key: string, expect: string|null }, { ok: boolean, key: string|null }],
 *   bridgeConfirm: [{ uid: string }, { ok: boolean }],
 *   bridgeAbandon: [{ uid: string }, { ok: boolean }],
 *   bridgeRelease: [{ uid: string }, { key: string|null }],
 *   bridgeCall: [{}, { ok: boolean, reason?: "bridge" | "global" }],
 * }} Ops */
/** @typedef {<K extends keyof Ops>(name: string, payload: { op: K } & Ops[K][0]) => Promise<Ops[K][1]>} CallDO */
/** @typedef {{ idFromName: (n: string) => unknown, get: (id: any) => { fetch: (r: Request) => Promise<Response> } }} Namespace */

/** @template {keyof Ops} K @param {Namespace} ns @param {string} name @param {{ op: K } & Ops[K][0]} payload @returns {Promise<Ops[K][1]>} */
export async function callDO(ns, name, payload) {
  const res = await ns.get(ns.idFromName(name)).fetch(new Request("https://do/op", { method: "POST", body: JSON.stringify(payload) }));
  return res.json();
}
