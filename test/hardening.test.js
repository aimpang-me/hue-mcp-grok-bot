// Audience binding, browser-bound login, code-reuse revocation, record cleanup, bridge lifecycle, budgets and abuse guards.
import test from "node:test";
import assert from "node:assert/strict";
import { ORIGIN, RURI, harness, approve, pkce, register, login, rpc } from "./support/harness.js";
import { UserDO } from "../worker/user-do.js";
import { sha256Hex } from "../worker/util.js";

const DAY = 24 * 3600_000;
const form = (o) => new URLSearchParams(o);
const uidOf = (t) => t.split(".")[0];
const post = (h, path, o) => h.req(path, { method: "POST", body: form(o) });
const dop = async (h, uid, payload) => (await h.env.USER_DO.get(uid).fetch(new Request("https://do/op", { method: "POST", body: JSON.stringify(payload) }))).json();
/** Authorize up to the Hue redirect; returns what the browser would hold. */
async function startAuth(h, extra = {}, headers = {}) {
  const { client_id } = await register(h), { verifier, challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256", state: "cs", ...extra });
  const { r } = await approve(h, q, { headers });
  return { r, client_id, verifier, state: r.headers.get("location") && new URL(r.headers.get("location")).searchParams.get("state"), cookie: r.headers.get("set-cookie")?.split(";")[0] };
}

// ---------- resource audience ----------
test("audience: tokens are always bound to this server's /mcp; a mismatched resource at /token is invalid_target", async () => {
  const h = harness(); const a = await login(h, "alice");
  assert.equal(a.resource, `${ORIGIN}/mcp`, "bound even when the client sent no resource");
  const s = await startAuth(h, { resource: `${ORIGIN}/mcp` });
  const cb = await h.req(`/oauth/callback?code=CODE-bob&state=${s.state}`, { headers: { cookie: s.cookie } });
  const code = new URL(cb.headers.get("location")).searchParams.get("code");
  const bad = await post(h, "/token", { grant_type: "authorization_code", code, client_id: s.client_id, redirect_uri: RURI, code_verifier: s.verifier, resource: "https://evil.example/mcp" });
  assert.equal(bad.status, 400); assert.equal((await bad.json()).error, "invalid_target");
});
test("audience: a token minted for this resource is refused when presented to a different resource/origin", async () => {
  const h = harness(); const a = await login(h, "alice");
  const other = await h.w.fetch(new Request("https://other.example/mcp", { method: "POST", headers: { authorization: `Bearer ${a.access_token}` }, body: "{}" }), h.env);
  assert.equal(other.status, 401);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200);
  const r = await post(h, "/token", { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c, resource: "https://evil.example/mcp" });
  assert.equal((await r.json()).error, "invalid_target");
});

// ---------- login bound to the browser ----------
test("session: approving sets an HttpOnly SameSite login cookie; only that browser can finish, and a replayed callback creates nobody", async () => {
  const h = harness(); const s = await startAuth(h);
  const sc = s.r.headers.get("set-cookie"); assert.match(sc, /hue_login=/); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Lax/); assert.match(sc, /Secure/); assert.match(sc, /Path=\/oauth\/callback/);
  const none = await h.req(`/oauth/callback?code=CODE-eve&state=${s.state}`);
  assert.equal(none.status, 400, "no cookie: someone else's browser finished the login");
  const forged = s.cookie.replace(/.$/, (c) => (c === "A" ? "B" : "A"));
  for (const cookie of ["hue_login=not-the-one", forged]) assert.equal((await h.req(`/oauth/callback?code=CODE-eve&state=${s.state}`, { headers: { cookie } })).status, 400);
  assert.equal((await h.req(`/oauth/callback?code=CODE-eve&state=other-nonce`, { headers: { cookie: s.cookie } })).status, 400, "state must match the cookie");
  assert.equal([...h.stores.keys()].filter((k) => /^[0-9a-f]{32}$/.test(k)).length, 0, "no user was created");
  const ok = await h.req(`/oauth/callback?code=CODE-alice&state=${s.state}`, { headers: { cookie: s.cookie } });
  assert.equal(ok.status, 302); assert.match(ok.headers.get("set-cookie"), /Max-Age=0/, "cookie cleared after use");
  const users = () => [...h.stores.keys()].filter((k) => /^[0-9a-f]{32}$/.test(k)).length;
  const replay = await h.req(`/oauth/callback?code=CODE-alice&state=${s.state}`, { headers: { cookie: s.cookie } });
  assert.equal(new URL(replay.headers.get("location")).searchParams.get("error"), "access_denied", "Hue refuses the used code");
  assert.equal(users(), 1, "the replay created no second user");
  h.advance(11 * 60_000);
  const late = await startAuth(h); h.advance(11 * 60_000);
  assert.equal((await h.req(`/oauth/callback?code=CODE-bob&state=${late.state}`, { headers: { cookie: late.cookie } })).status, 400, "login cookie expires");
});

// ---------- code reuse revokes ----------
test("code reuse: redeeming a code twice revokes every token already issued from it", async () => {
  const h = harness(); const a = await login(h, "alice");
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200);
  const again = await post(h, "/token", { grant_type: "authorization_code", code: a.code, client_id: a.c, redirect_uri: RURI, code_verifier: a.verifier });
  assert.equal((await again.json()).error, "invalid_grant");
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 401, "access token from the first redemption is dead");
  const rf = await post(h, "/token", { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c });
  assert.equal((await rf.json()).error, "invalid_grant");
});

// ---------- cleanup and orphaned bridge keys ----------
const recordKeys = (h, uid) => [...h.stores.get(uid).keys()].filter((k) => /^(at|rt|used|code|grant):/.test(k));
test("cleanup: an alarm is scheduled and removes expired tokens, used: markers, grants and unredeemed codes", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token);
  await post(h, "/token", { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c }); // leaves a used: marker
  assert.ok(h.alarms.get(uid) > h.now(), "alarm scheduled");
  assert.ok(recordKeys(h, uid).some((k) => k.startsWith("used:")));
  h.advance(2 * 3600_000); await h.runAlarms();
  assert.ok(!recordKeys(h, uid).some((k) => k.startsWith("at:")), "expired access tokens swept");
  assert.ok(h.alarms.get(uid) > h.now(), "rescheduled for the refresh-token expiry");
  assert.ok(recordKeys(h, uid).some((k) => k.startsWith("rt:")), "live refresh token kept");
  // an unredeemed code
  const s = await startAuth(h); await h.req(`/oauth/callback?code=CODE-carol&state=${s.state}`, { headers: { cookie: s.cookie } });
  const carol = [...h.stores.keys()].find((k) => /^[0-9a-f]{32}$/.test(k) && k !== uid);
  assert.ok(recordKeys(h, carol).some((k) => k.startsWith("code:")));
  h.advance(11 * 60_000); await h.runAlarms();
  assert.deepEqual([...h.stores.get(carol).keys()], ["disabled"], "orphaned sign-in with only an expired code is wiped (only the tombstone remains)");
});
test("cleanup: day counters in the global/bridge registries expire", async () => {
  const h = harness(); const a = await login(h, "alice"); await rpc(h, a.access_token, "list_rooms"); // a Hue call charges the global counter
  assert.ok([...h.stores.get("global").keys()].some((k) => k.startsWith("gq:")));
  h.advance(3 * DAY); await h.runAlarms();
  assert.ok(![...(h.stores.get("global")?.keys() ?? [])].some((k) => k.startsWith("gq:")));
});
test("orphan: when the last sign-in for a bridge expires unused, its key is removed from the bridge and the registry entry freed", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token);
  h.advance(31 * DAY); await h.runAlarms();
  assert.deepEqual(h.cloud.deleted, ["KEY-alice"]);
  assert.equal(h.stores.get(uid)?.has("hue") ?? false, false);
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:"));
  assert.ok(!h.stores.get(bk).has("key") && !h.stores.get(bk).has("users"));
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 401);
});
test("orphan: an expired sign-in does NOT remove a key another live sign-in on the same bridge still uses", async () => {
  const h = harness(); h.cloud.setBridge(() => "BR-shared");
  const a = await login(h, "alice"); h.advance(20 * DAY); const b = await login(h, "alice");
  h.advance(15 * DAY); await h.runAlarms();
  assert.deepEqual(h.cloud.deleted, [], "key still in use");
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:"));
  assert.deepEqual(h.stores.get(bk).get("users"), [uidOf(b.access_token)]);
  void a;
});

// ---------- abuse guards ----------
test("abuse: well-shaped but unsigned/forged ids never instantiate a Durable Object", async () => {
  const h = harness(); const a = await login(h, "alice"); const before = h.stores.size;
  const fake = "ab".repeat(16), [, tag, sec] = a.access_token.split(".");
  for (const t of [`${fake}.${tag}.${sec}`, `${fake}.AAAA.${sec}`, `${fake}.x`, `${uidOf(a.access_token)}.AAAA.${sec}`]) {
    assert.equal((await rpc(h, t, "list_rooms")).status, 401, t);
    await post(h, "/revoke", { token: t });
    await post(h, "/token", { grant_type: "refresh_token", refresh_token: t, client_id: a.c });
    await post(h, "/token", { grant_type: "authorization_code", code: t, client_id: a.c, redirect_uri: RURI, code_verifier: "x" });
  }
  assert.equal(h.stores.has(fake), false); assert.equal(h.stores.size, before);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200, "the real token still works");
});
test("abuse: approving consent stores nothing and creates no Durable Object until a Hue sign-in succeeds", async () => {
  const h = harness(), before = h.stores.size;
  for (let i = 0; i < 8; i++) assert.equal((await startAuth(h, {}, { "cf-connecting-ip": `198.51.100.${i}` })).r.status, 302);
  assert.equal(h.kvPuts.length, 0);
  assert.deepEqual([...h.stores.keys()].slice(before).filter((k) => k !== "global"), [], "only the shared capacity counter was asked");
});
test("abuse: approving consent is rate-limited per client IP; other clients are unaffected", async () => {
  const h = harness(); const hdr = { "cf-connecting-ip": "203.0.113.7" }; const rs = [];
  for (let i = 0; i < 15; i++) rs.push((await startAuth(h, {}, hdr)).r.status);
  assert.ok(rs.includes(429)); assert.equal(rs.filter((c) => c === 302).length, 10);
  assert.equal((await startAuth(h, {}, { "cf-connecting-ip": "198.51.100.9" })).r.status, 302, "other clients unaffected");
});
test("abuse: the client's state is capped so the login cookie stays small", async () => {
  const h = harness(), { client_id } = await register(h), { challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256", state: "s".repeat(513) });
  assert.equal((await h.req(`/authorize?${q}`)).status, 400);
});

// ---------- multi-bridge: deterministic first bridge, safe unpair ----------
test("multi-bridge: the account's first bridge (bridge 0) is used; disconnect never deletes the key on a different bridge", async () => {
  const h = harness(); const a = await login(h, "alice");
  h.cloud.setBridge(() => "BR-reordered"); // account's bridge order changed since sign-in
  await post(h, "/revoke", { token: a.refresh_token });
  assert.deepEqual(h.cloud.deleted, [], "did not unpair against a different bridge");
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 401, "local wipe still happened");
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:"));
  assert.ok(!h.stores.get(bk).has("users"), "registry freed");
});

// ---------- refresh binding, body limits, budgets, bridge identification, disconnect ----------
test("refresh: a refresh record without a client binding is refused", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token), st = h.stores.get(uid);
  const k = [...st.keys()].find((x) => x.startsWith("rt:")); st.set(k, { ...st.get(k), cid: undefined });
  const r = await post(h, "/token", { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c });
  assert.equal((await r.json()).error, "invalid_grant");
});
test("bodies: oversized /mcp, /token, /register, /revoke payloads are refused without parsing", async () => {
  const h = harness(); const a = await login(h, "alice"), big = "x".repeat(70_000);
  const r = await h.req("/mcp", { method: "POST", headers: { authorization: `Bearer ${a.access_token}` }, body: big });
  assert.equal(r.status, 413);
  assert.equal((await h.req("/register", { method: "POST", body: big })).status, 400);
  assert.equal((await post(h, "/token", { grant_type: "refresh_token", refresh_token: big, client_id: a.c })).status, 401, "body dropped, so no client");
  assert.equal((await post(h, "/revoke", { token: big })).status, 200);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200, "nothing was revoked by the oversized request");
});
test("daily budget: concurrent calls cannot overshoot the per-bridge cap (the budget is taken atomically)", async () => {
  const h = harness({ DAILY_HUE_CALLS: "5" }); const a = await login(h, "alice");
  const hueCalls = () => h.cloud.calls.filter((c) => c.path.startsWith("/route/clip/v2")).length, before = hueCalls();
  await Promise.all(Array.from({ length: 12 }, () => rpc(h, a.access_token, "list_rooms")));
  assert.equal(hueCalls() - before, 5, "exactly the budget, never more");
});
test("daily budget: it is per bridge, so more sign-ins on one bridge do not add budget", async () => {
  const h = harness({ DAILY_HUE_CALLS: "4" }); const a = await login(h, "alice"), b = await login(h, "alice");
  const ok = async (t) => !(await (await rpc(h, t, "list_lights")).json()).result.isError;
  const results = [];
  for (let i = 0; i < 4; i++) results.push(await ok(a.access_token), await ok(b.access_token));
  assert.equal(results.filter(Boolean).length, 4, "two sign-ins share the bridge's 4 calls");
});
test("daily budget: a call refused by the shared quota is not charged to the bridge", async () => {
  const h = harness({ GLOBAL_DAILY_CALLS: "1" }); const a = await login(h, "alice");
  await rpc(h, a.access_token, "list_lights"); await rpc(h, a.access_token, "list_lights"); await rpc(h, a.access_token, "list_lights");
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:")), st = h.stores.get(bk), k = [...st.keys()].find((x) => x.startsWith("bc:"));
  assert.equal(st.get(k), 1);
});
test("sign-in: when the cloud config does not name the bridge, CLIPv2 identifies it and the bridge's caps still apply", async () => {
  const h = harness({ BRIDGE_LOGINS_PER_DAY: "1" }); h.cloud.setConfigNamesBridge(false);
  const a = await login(h, "alice");
  assert.ok(!(await (await rpc(h, a.access_token, "list_rooms")).json()).result.isError);
  assert.ok([...h.stores.keys()].some((k) => k.startsWith("bridge:")), "registered under its bridge");
  await assert.rejects(() => login(h, "alice"), /302|status/, "second sign-in today hits the per-bridge cap");
  assert.deepEqual(h.cloud.deleted, ["KEY-alice~1"], "the key paired to identify the bridge was removed again");
});
test("sign-in: a bridge that cannot be identified at all is refused, and the key paired to look is removed", async () => {
  const h = harness(); h.cloud.setConfigNamesBridge(false); h.cloud.setBridge(() => "");
  await assert.rejects(() => login(h, "alice"), /302|status/);
  assert.deepEqual(h.cloud.deleted, ["KEY-alice"]);
  assert.equal([...h.stores.keys()].filter((k) => k.startsWith("bridge:")).length, 0);
});
test("sign-in: a key paired during the bridge lookup is removed again when a later step fails", async () => {
  const h = harness(); h.cloud.setConfigNamesBridge(false);
  await login(h, "alice"); // stores KEY-alice for the bridge
  h.cloud.setFailKey("KEY-alice"); // checking the stored key now fails with a 503 (not a clear "dead key")
  await assert.rejects(() => login(h, "alice"), /302|status/);
  assert.deepEqual(h.cloud.pairs, ["alice", "alice"]);
  assert.deepEqual(h.cloud.deleted, ["KEY-alice~1"], "the second sign-in's own key did not stay on the bridge");
});
test("disconnect: an expired or revoked token cannot disconnect anyone", async () => {
  const h = harness(); const a = await login(h, "alice"), st = h.stores.get(uidOf(a.access_token));
  h.advance(2 * 3600_000); // access token expired (1 h), refresh token still live
  assert.equal((await post(h, "/revoke", { token: a.access_token })).status, 200);
  assert.ok(st.has("hue"), "expired access token did nothing");
  const grant = [...st.values()].find((v) => v?.grant)?.grant; st.set(`grant:${grant}`, { revoked: true, exp: h.now() + DAY });
  await post(h, "/revoke", { token: a.refresh_token });
  assert.ok(st.has("hue"), "a token of a revoked grant did nothing");
});
test("rate limit: refreshing does not reset the per-sign-in window", async () => {
  const h = harness({ RATE_PER_MIN: "3" }); let t = await login(h, "alice");
  for (let i = 0; i < 3; i++) assert.equal((await rpc(h, t.access_token, "list_rooms")).status, 200);
  const r = await post(h, "/token", { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.c }); t = { ...t, ...(await r.json()) };
  assert.equal((await rpc(h, t.access_token, "list_rooms")).status, 429);
});
test("hue op: the Durable Object itself refuses anything but /resource paths, even if a caller skips the tool check", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token), before = h.cloud.calls.length;
  for (const path of ["/resource/../../bridge/0/config", "/bridge/0/config", "/resource/light?x=1", "/resource/light/ABCDEFGH"]) {
    assert.equal((await dop(h, uid, { op: "hue", method: "GET", path })).status, 400, path);
  }
  assert.equal((await dop(h, uid, { op: "hue", method: "PATCH", path: "/resource/light" })).status, 400);
  assert.equal(h.cloud.calls.length, before, "nothing reached Hue");
});
test("hue op: Hue error text never carries the user's bridge key or Hue tokens", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token);
  const st = h.stores.get(uid), key = st.get("appKey"), acc = st.get("hue").access_token;
  h.cloud.setEcho(true);
  const res = await dop(h, uid, { op: "hue", method: "GET", path: "/resource/light" });
  assert.equal(res.status, 500); assert.match(res.text, /\[REDACTED\]/);
  assert.ok(!res.text.includes(key) && !res.text.includes(acc), res.text);
});

// ---------- revoke and storage races ----------
test("revoke: a valid user handle with a wrong secret disconnects nothing", async () => {
  const h = harness(); const a = await login(h, "alice"), b = await login(h, "bob");
  const handle = (t) => t.split(".").slice(0, 2).join(".");
  for (const t of [`${handle(a.refresh_token)}.wrong-secret`, `${handle(a.access_token)}.wrong-secret`, `${handle(a.access_token)}.`, handle(a.access_token), `${handle(b.refresh_token)}.${a.refresh_token.split(".")[2]}`]) {
    assert.equal((await post(h, "/revoke", { token: t })).status, 200, "always 200 (RFC 7009)");
  }
  assert.deepEqual(h.cloud.deleted, [], "no bridge key was unpaired");
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200, "alice is still connected");
  assert.equal((await rpc(h, b.access_token, "list_rooms")).status, 200, "so is bob");
  assert.equal((await post(h, "/revoke", { token: a.refresh_token })).status, 200);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 401, "the real token does disconnect");
});

/** A UserDO whose storage answers slowly, so that without serial() concurrent read-modify-write steps interleave. */
function slowDO() {
  const m = new Map(), tick = () => new Promise((r) => setTimeout(r, 2)), clone = (v) => structuredClone(v);
  const storage = {
    get: async (k) => (await tick(), Array.isArray(k) ? new Map(k.filter((x) => m.has(x)).map((x) => [x, clone(m.get(x))])) : clone(m.get(k))),
    put: async (k, v) => { await tick(); for (const [x, y] of typeof k === "string" ? [[k, v]] : Object.entries(k)) m.set(x, clone(y)); },
    delete: async (k) => (await tick(), Array.isArray(k) ? k.filter((x) => m.delete(x)).length : m.delete(k)),
    list: async () => (await tick(), new Map([...m].map(([k, v]) => [k, clone(v)]))), getAlarm: async () => null, setAlarm: async () => {}, deleteAlarm: async () => {},
  };
  const d = new UserDO({ storage }, {}, { now: () => 1_800_000_000_000 });
  return { m, op: async (payload) => (await d.fetch(new Request("https://do/op", { method: "POST", body: JSON.stringify(payload) }))).json() };
}
test("serial(): concurrent refreshes of one MCP refresh token under slow storage let exactly one win (fails if serial() is a no-op)", async () => {
  const { m, op } = slowDO(), token = "uid.tag.secret";
  m.set(`rt:${await sha256Hex(token)}`, { grant: "g1", cid: "c1", resource: `${ORIGIN}/mcp`, born: 1_800_000_000_000, exp: 1_900_000_000_000 });
  const rs = await Promise.all([1, 2, 3, 4].map(() => op({ op: "refresh", token, cid: "c1" })));
  assert.equal(rs.filter((r) => r.access_token).length, 1, JSON.stringify(rs));
  assert.equal([...m.keys()].filter((k) => k.startsWith("rt:")).length, 1, "one new refresh token, not one per caller");
});

// The route only checks that the requested resource is THIS origin's /mcp; the Durable Object is the one that compares it with the audience the code/token was issued for.
test("audience: a code or refresh token issued for one origin is refused at another origin, even when it asks for that origin's own /mcp", async () => {
  const OTHER = "https://other.example";
  const tokenAt = (h, o) => h.w.fetch(new Request(`${OTHER}/token`, { method: "POST", body: form(o) }), h.env);
  const h = harness(); const c = (await register(h)).client_id, { verifier, challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id: c, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256" });
  const { r: hu } = await approve(h, q);
  const cb = await h.req(`/oauth/callback?code=CODE-bob&state=${new URL(hu.headers.get("location")).searchParams.get("state")}`, { headers: { cookie: hu.headers.get("set-cookie").split(";")[0] } });
  const code = new URL(cb.headers.get("location")).searchParams.get("code");
  const bad = await tokenAt(h, { grant_type: "authorization_code", code, client_id: c, redirect_uri: RURI, code_verifier: verifier, resource: `${OTHER}/mcp` });
  assert.equal((await bad.json()).error, "invalid_target");
  const a = await login(h, "alice"); // refresh token issued for ORIGIN
  const rf = await tokenAt(h, { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c, resource: `${OTHER}/mcp` });
  assert.equal((await rf.json()).error, "invalid_target");
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200, "the original tokens are untouched");
});
