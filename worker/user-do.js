// One Durable Object per user (name = user id). It is the ONLY place that holds that user's Hue tokens and bridge app key,
// refreshes the rotating Hue refresh token, and issues and validates that user's MCP codes and tokens.
// Why a Durable Object: Hue refresh tokens rotate, so two concurrent refreshes burn the token and lock the user out. A Durable Object
// is single-threaded per id, so serialising here is exact. Within it, awaits on fetch can interleave requests, so the refresh is also
// single-flight (one transport per sign-in, see server/transport-remote.js) and security steps run through the `serial` mutex below.
// The same class also runs the shared "bridge:<hash>" and "global" instances (worker/do/registry.js).
import { remoteTransport, pairRemote, bridgeIdOf, currentBridgeId, keyWorks, unpairRemote, refreshTokens, HUE_CLOUD } from "../server/transport-remote.js";
import { RESOURCE_PATH, METHODS } from "../server/guards.js";
import { sha256Hex, hit, localBase } from "./util.js";
import * as registry from "./do/registry.js";
import * as tokens from "./do/tokens.js";
import { LIMITS, MIN, envNum } from "./limits.js";
import { callDO } from "./do-client.js";
import { expiryOf, AUTH_RECORD } from "./sweep.js";

/** The subset of Durable Object storage this class uses.
 * @typedef {{ get: { (k: string): Promise<any>, (k: string[]): Promise<Map<string, any>> }, put: { (k: string, v: any): Promise<void>, (entries: Record<string, any>): Promise<void> },
 *   delete: { (k: string): Promise<boolean>, (k: string[]): Promise<number> }, list: (opts?: { prefix?: string }) => Promise<Map<string, any>>,
 *   getAlarm: () => Promise<number|null>, setAlarm: (at: number) => Promise<void>, deleteAlarm: () => Promise<void>, deleteAll: () => Promise<void> }} Storage */
/** @typedef {import("./do-client.js").Ops} Ops */

/** The records that make up a user's Hue connection (removed together on a failed link). */
const CONNECTION_KEYS = ["hue", "appKey", "bridge", "uid"];
/** Durable Object storage takes at most 128 keys per batch call. */
const BATCH = 128;

/** @param {number} status @param {string} description */
const hueError = (status, description) => ({ status, text: JSON.stringify({ errors: [{ description }] }) });
/** Replace exact secrets in a string (no pattern matching, so ids and data stay intact). @param {string} s @param {Array<string|undefined>} secrets */
function scrub(s, secrets) { for (const x of secrets) if (x) s = s.split(x).join("[REDACTED]"); return s; }

export class UserDO {
  /** @param {{ storage: Storage }} state @param {import("./index.js").Env} env @param {{ fetchImpl?: typeof fetch, now?: () => number }} [opts] */
  constructor(state, env, opts = {}) {
    this.storage = state.storage; this.env = env;
    /** @type {typeof fetch} */ this.f = opts.fetchImpl ?? ((u, i) => fetch(u, i));
    this.now = opts.now ?? Date.now;
    /** In-memory per-minute windows (reset on eviction; the daily caps are in storage). @type {Map<string, {w: number, n: number}>} */ this.win = new Map();
    /** @type {Promise<any>} */ this.chain = Promise.resolve();
    /** @type {string|undefined} */ this.appKey = undefined;
    /** @type {import("../server/hue.js").Transport|undefined} */ this.transport = undefined;
  }
  /** Run security-critical read-modify-write steps one at a time. @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  serial(fn) { const r = this.chain.then(fn, fn); this.chain = r.catch(() => {}); return r; }
  /** @param {string} k @param {number} d */
  num(k, d) { return envNum(this.env, k, d); }
  /** Call another Durable Object by name (the shared "global" counter, a "bridge:<hash>" registry). @type {import("./do-client.js").CallDO} */
  peer(name, payload) { return callDO(this.env.USER_DO, name, payload); }
  /** Today's UTC date, the suffix of every per-day counter key. */
  day() { return new Date(this.now()).toISOString().slice(0, 10); }
  /** When today's counters can be swept. */
  dayEnd() { return /** @type {number} */ (expiryOf(`bc:${this.day()}`, 0)); }
  /** Make sure the cleanup alarm fires no later than `at`. @param {number} at */
  async wake(at) { const cur = await this.storage.getAlarm(); if (cur === null || at < cur) await this.storage.setAlarm(at); }
  /** Add `by` to today's counter `<prefix>:<day>` unless that would pass `cap`. Call inside serial().
   * @param {string} prefix @param {number} cap @param {number} [by] */
  async bump(prefix, cap, by = 1) {
    const key = `${prefix}:${this.day()}`, n = (await this.storage.get(key)) ?? 0;
    if (n + by > cap) return { ok: false };
    await this.storage.put(key, n + by); await this.wake(this.dayEnd());
    return { ok: true };
  }
  /** Delete keys in batches. @param {string[]} keys */
  async deleteKeys(keys) { for (let i = 0; i < keys.length; i += BATCH) await this.storage.delete(keys.slice(i, i + BATCH)); }
  get base() { return localBase(this.env.HUE_CLOUD_BASE) ?? HUE_CLOUD; }

  /** @param {Request} req */
  async fetch(req) {
    /** @type {any} */ let m; try { m = await req.json(); } catch { return Response.json({ error: "bad_request" }, { status: 400 }); }
    /** @type {{ [K in keyof Ops]: (a: Ops[K][0]) => Promise<Ops[K][1]> }} */
    const ops = {
      connect: (a) => this.connect(a), hue: (a) => this.hue(a), disconnect: (a) => this.disconnect(a),
      redeem: (a) => tokens.redeem(this, a), refresh: (a) => tokens.refreshMcp(this, a), authz: (a) => tokens.authz(this, a),
      capacity: () => registry.capacity(this), quotaBlock: (a) => registry.quotaBlock(this, a),
      bridgeClaim: (a) => registry.bridgeClaim(this, a), bridgePut: (a) => registry.bridgePut(this, a), bridgeConfirm: (a) => registry.bridgeConfirm(this, a),
      bridgeAbandon: (a) => registry.bridgeAbandon(this, a), bridgeRelease: (a) => registry.bridgeRelease(this, a), bridgeCall: () => registry.bridgeCall(this),
    };
    const op = typeof m?.op === "string" && Object.hasOwn(ops, m.op) ? /** @type {keyof Ops} */ (m.op) : undefined;
    if (!op) return Response.json({ error: "bad_op" }, { status: 400 });
    return Response.json(await /** @type {(a: unknown) => Promise<unknown>} */ (ops[op])(m));
  }

  /** First Hue login for this user: store Hue tokens, link the bridge, mint an MCP auth code. @param {Ops["connect"][0]} a @returns {Promise<Ops["connect"][1]>} */
  async connect({ hue, code, uid, handle }) {
    if (await this.storage.get("hue")) return { error: "already_connected" }; // a user id is created per login; never overwrite another login's record
    let link;
    try { link = await this.linkBridge(hue.access_token, uid); }
    catch { return { error: "pair_failed" }; }
    if (link.limited) return { error: "too_many_logins" };
    const { appKey, bridge } = link;
    await this.storage.put({ hue, appKey, uid, bridge });
    this.appKey = appKey;
    // The user record exists now: the registry lease becomes a permanent holder. Refused = the lease lapsed and the key may be gone: undo the sign-in.
    if (!(await this.peer(bridge, { op: "bridgeConfirm", uid })).ok) {
      await this.storage.delete(CONNECTION_KEYS); this.appKey = undefined;
      return { error: "pair_failed" };
    }
    return { code: await tokens.mintCode(this, handle, code) };
  }

  /** Get this account's bridge key: reuse the one already paired for this bridge (a bridge only holds ~40 keys), else pair once.
   * The bridge must be identified (from the cloud config, or failing that from CLIPv2 with a freshly paired key); otherwise the
   * sign-in fails, because every sign-in has to count against its bridge's daily caps. Any key this sign-in pairs and does not
   * end up storing is removed from the bridge again, on every path, including errors.
   * @param {string} accessToken @param {string} uid @returns {Promise<{ limited: true } | { limited?: false, appKey: string, bridge: string }>} */
  async linkBridge(accessToken, uid) {
    const c = { accessToken, fetch: this.f, base: this.base };
    /** @type {string|undefined} a key this sign-in created on the bridge that nothing holds yet */ let paired;
    const dropPaired = async () => { if (paired) await unpairRemote({ ...c, appKey: paired }).catch(() => false); paired = undefined; };
    try {
      let bridgeId = await bridgeIdOf(c);
      if (!bridgeId) {
        paired = await pairRemote(c);
        bridgeId = await currentBridgeId({ ...c, appKey: paired }).catch(() => undefined);
        if (!bridgeId) throw new Error("Could not identify the bridge");
      }
      const bridge = `bridge:${await sha256Hex(bridgeId)}`, claim = await this.peer(bridge, { op: "bridgeClaim", uid });
      if (claim.limited) { await dropPaired(); return { limited: true }; }
      try {
        if (claim.key && claim.key !== paired && (await keyWorks({ ...c, appKey: claim.key }))) { await dropPaired(); return { appKey: claim.key, bridge }; }
        paired ??= await pairRemote(c);
        const put = await this.peer(bridge, { op: "bridgePut", uid, key: paired, expect: claim.key });
        if (put.ok) { const appKey = paired; paired = undefined; return { appKey, bridge }; }
        // Another sign-in on this bridge stored its key first: remove our duplicate from the bridge, then share theirs.
        await dropPaired();
        if (!put.key) throw new Error("bridge key changed during sign-in");
        return { appKey: put.key, bridge };
      } catch (e) { await this.peer(bridge, { op: "bridgeAbandon", uid }); throw e; }
    } catch (e) { await dropPaired(); throw e; }
  }

  /** The Hue token store for this sign-in. Writes are serialised with revokeAll and refused once disconnected, so a Hue refresh that
   * finishes after a disconnect cannot write tokens back into a wiped record. @returns {import("../server/transport-remote.js").TokenStore} */
  tokenStore() {
    return {
      get: async () => (await this.storage.get("hue")) ?? null,
      set: (t) => this.serial(async () => {
        if (await this.storage.get("disabled")) throw new Error("This sign-in was disconnected; connect again");
        await this.storage.put("hue", t);
      }),
    };
  }

  /** One Hue cloud call for this user: only /resource paths, the per-resource change cap, then the bridge's and the shared daily budgets.
   * @param {Ops["hue"][0]} a @returns {Promise<Ops["hue"][1]>} */
  async hue({ method, path, body }) {
    const m = RESOURCE_PATH.exec(path);
    if (!METHODS.includes(method) || !m) return hueError(400, "Only GET, PUT, POST or DELETE on /resource paths can be called");
    if (await this.storage.get("disabled")) return hueError(401, "This sign-in was disconnected; connect again");
    const rec = await this.storage.get(["hue", "appKey", "bridge"]), hueTokens = rec.get("hue"), bridge = rec.get("bridge");
    const appKey = (this.appKey ??= rec.get("appKey"));
    if (!hueTokens || !appKey || !bridge) return hueError(401, "Hue account not connected for this user");
    if (method !== "GET") {
      const cap = this.num("LIGHT_CAP_PER_MIN", LIMITS.lightCapPerMin), what = m[1] ? `${m[1]}${m[2] ? ` ${m[2]}` : ""}` : "this resource";
      if (!hit(this.win, `light:${m[1] ?? "*"}:${m[2] ?? "*"}`, cap, MIN, this.now()).ok) return hueError(429, `Too many changes to ${what} (limit ${cap}/min); wait a minute`);
    }
    const charge = await this.peer(bridge, { op: "bridgeCall" });
    if (!charge.ok) {
      return hueError(429, charge.reason === "global"
        ? "This free lights connector has used its daily share of Hue's cloud quota. It resets at 00:00 UTC; please try again later."
        : "Daily Hue call budget for your bridge is used up; it resets at 00:00 UTC");
    }
    const secrets = [appKey, hueTokens.access_token, hueTokens.refresh_token, this.env.HUE_CLIENT_SECRET];
    this.transport ??= remoteTransport({ appKey, clientId: this.env.HUE_CLIENT_ID, clientSecret: this.env.HUE_CLIENT_SECRET, tokens: this.tokenStore(), now: this.now, fetch: this.f, base: this.base });
    /** Also scrub tokens a refresh during this call may have stored. @param {string} s */
    const clean = async (s) => { const now = await this.storage.get("hue"); return scrub(s, [...secrets, now?.access_token, now?.refresh_token]); };
    try {
      const res = await this.transport(method, path, body);
      return { status: res.status, text: res.status < 400 ? scrub(res.text, secrets) : await clean(res.text) };
    } catch (e) {
      return hueError(502, await clean(e instanceof Error ? e.message : "Hue request failed"));
    }
  }

  /** Cleanup alarm: delete expired records; when a user's last sign-in record is gone (never redeemed, or its refresh token lapsed),
   * treat the sign-in as abandoned and free its bridge key. Reschedules itself for the next expiry. */
  alarm() { return this.serial(() => this.sweep()); }
  async sweep() {
    const now = this.now(), dead = [];
    let next = Infinity, authLive = 0;
    for (const [k, v] of await this.storage.list()) {
      const exp = expiryOf(k, v);
      if (exp === null) continue;
      if (exp <= now) dead.push(k);
      else { next = Math.min(next, exp); if (AUTH_RECORD.test(k) && !v.used) authLive++; } // a redeemed-code marker is not a live sign-in
    }
    await this.deleteKeys(dead);
    if (!authLive && (await this.storage.get("hue"))) { await this.revokeAll(); return; }
    if (next < Infinity) await this.storage.setAlarm(next);
  }

  /** User-initiated disconnect, authorised by holding a live, unrevoked MCP access or refresh token. @param {Ops["disconnect"][0]} a */
  disconnect({ token }) {
    return this.serial(async () => ((await tokens.liveToken(this, token, ["at", "rt"])) ? this.revokeAll() : { ok: false }));
  }

  /** Drop everything for this user and free their bridge key when no other sign-in uses it. Best effort on the Hue side; the wipe always happens.
   * Call inside serial(). */
  async revokeAll() {
    const rec = await this.storage.get(["uid", "bridge", "appKey", "hue"]), uid = rec.get("uid"), bridge = rec.get("bridge"), hue = rec.get("hue");
    try {
      const last = bridge ? (await this.peer(bridge, { op: "bridgeRelease", uid })).key : null;
      if (last && hue) {
        let t = hue;
        if (t.expires_at - this.now() < 60_000) t = await refreshTokens({ clientId: this.env.HUE_CLIENT_ID, clientSecret: this.env.HUE_CLIENT_SECRET, fetch: this.f, base: this.base, now: this.now }, t.refresh_token);
        const c = { accessToken: t.access_token, appKey: last, fetch: this.f, base: this.base };
        // bridge 0 is whichever bridge the account lists first; only delete the key if that is still the bridge it was paired with
        if (`bridge:${await sha256Hex((await currentBridgeId(c)) ?? "")}` === bridge) await unpairRemote(c);
      }
    } catch { /* Hue unreachable: the key stays on the bridge; the user can remove it in the Hue app. The local wipe continues. */ }
    await this.storage.deleteAll();
    await this.storage.put("disabled", true);
    await this.storage.deleteAlarm();
    this.appKey = undefined; this.transport = undefined;
    return { ok: true };
  }
}
