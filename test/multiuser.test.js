import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { NOTICES } from "../worker/consent.js";
import { CS, SIGN, ORIGIN, RURI, fakeCloud, harness, approve, pkce, register, login, rpc, out } from "./support/harness.js";
import { b64url, sha256Hex } from "../worker/util.js";
const post = (h, path, o) => h.req(path, { method: "POST", body: new URLSearchParams(o) });

// ---------- discovery + registration ----------
test("discovery: 401 carries resource_metadata; PRM and AS metadata advertise S256 PKCE + registration", async () => {
  const h = harness();
  const r = await h.req("/mcp", { method: "POST", body: "{}" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate"), /resource_metadata="https:\/\/w\.example\/\.well-known\/oauth-protected-resource"/);
  const prm = await (await h.req("/.well-known/oauth-protected-resource")).json();
  assert.deepEqual(prm.authorization_servers, [ORIGIN]);
  const as = await (await h.req("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  for (const k of ["authorization_endpoint", "token_endpoint", "registration_endpoint"]) assert.ok(as[k].startsWith(ORIGIN));
});
test("register: public client, safe redirect URIs only, stateless client_id can't be forged", async () => {
  const h = harness();
  const ok = await register(h, [RURI, "http://localhost:8787/callback", "cursor://anysphere.cursor-mcp/oauth/callback"]);
  assert.equal(ok.r.status, 201); assert.ok(ok.client_id); assert.equal(ok.client_secret, undefined);
  for (const bad of [["javascript:alert(1)"], ["http://evil.example/cb"], ["https://a.example/cb#frag"], []]) assert.equal((await register(h, bad)).r.status, 400);
  const forged = ok.client_id.split(".")[0] + ".AAAA";
  assert.equal((await h.req(`/authorize?response_type=code&client_id=${forged}&redirect_uri=${encodeURIComponent(RURI)}`)).status, 400);
});

// ---------- the sign-in flow ----------
test("authorize: consent page shows the Signify + light-sensitivity + privacy notices BEFORE Hue sign-in; no session until confirmed", async () => {
  const h = harness(); const { client_id } = await register(h), { challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256" });
  const r = await h.req(`/authorize?${q}`), body = await r.text();
  assert.equal(r.status, 200); assert.match(r.headers.get("content-type"), /html/);
  assert.match(body, /Not a Signify product/); assert.match(body, /seizures/); assert.match(body, /no log or analytics/); assert.match(body, /bridge key/i, "privacy text mentions the bridge key");
  assert.equal(NOTICES.signify.startsWith("Not a Signify product"), true);
  assert.equal(h.kvPuts.length, 0, "viewing the consent page stores nothing");
  assert.match(body, /client\.example/, "shows the redirect host");
  assert.match(r.headers.get("content-security-policy"), /frame-ancestors 'none'/); assert.equal(r.headers.get("x-frame-options"), "DENY");
});
test("authorize: PKCE S256 is mandatory; unknown redirect_uri is never redirected to", async () => {
  const h = harness(); const { client_id } = await register(h);
  const bad = await h.req(`/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&code_challenge=x&code_challenge_method=S256`);
  assert.equal(bad.status, 400); assert.equal(bad.headers.get("location"), null);
  const noPkce = await h.req(`/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(RURI)}`);
  assert.equal(noPkce.status, 400); assert.equal(noPkce.headers.get("location"), null, "no redirect to the client before consent"); assert.match(await noPkce.text(), /invalid_request/);
});
test("full flow: login yields per-user MCP tokens; Hue tokens/app key never leave the Durable Object", async () => {
  const h = harness(); const a = await login(h, "alice");
  assert.equal(a.token_type, "Bearer"); assert.ok(a.access_token.includes(".") && a.refresh_token);
  const r = await out(await rpc(h, a.access_token, "list_rooms"));
  assert.ok(!r.err, r.text); assert.match(r.text, /Kitchen/);
  assert.ok(!JSON.stringify([a, r]).match(/ACC-alice|REF-alice|KEY-alice/));
});
test("storage: the user's Durable Object holds only hashes of MCP tokens; HUE_CLIENT_SECRET never reaches an MCP response", async () => {
  const h = harness(); const a = await login(h, "alice");
  const uid = a.access_token.split(".")[0], stored = JSON.stringify([...h.stores.get(uid)]);
  for (const t of [a.access_token, a.refresh_token]) {
    assert.ok(stored.includes(await sha256Hex(t)), "the hash of the token is stored");
    assert.ok(!stored.includes(t.split(".").pop()), "the raw token secret is not");
  }
  assert.ok(!stored.includes(CS), "the app's client secret is never stored per user either");
  // every kind of MCP response: success, tool error, bad path, unknown tool, unauthenticated, token endpoint
  const seen = [JSON.stringify(a), a.tok.status];
  for (const [name, args] of [["list_rooms", {}], ["set_room", { room: "garage", on: true }], ["hue_api", { method: "GET", path: "../x" }], ["nope", {}], ["set_light", { light: "Lamp 1", brightness: 500 }]])
    seen.push(await (await rpc(h, a.access_token, name, args)).text());
  seen.push(await (await h.req("/mcp", { method: "POST", body: "{}" })).text());
  seen.push(await (await post(h, "/token", { grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c })).text());
  assert.ok(!JSON.stringify(seen).includes(CS));
});
test("storage: an upstream error that echoes HUE_CLIENT_SECRET or the signing secret is scrubbed from the MCP tool result", async () => {
  const cloud = fakeCloud(), f = cloud.f;
  const h = harness({}, { ...cloud, f: async (u, i) => (new URL(u).pathname.startsWith("/route/clip/v2") && i?.method === "PUT"
    ? new Response(JSON.stringify({ errors: [{ description: `denied for ${CS} signed ${SIGN}` }] }), { status: 400 }) : f(u, i)) });
  const a = await login(h, "alice");
  const r = await out(await rpc(h, a.access_token, "set_room", { room: "kitchen", on: true }));
  assert.ok(r.err && /denied for/.test(r.text) && !r.text.includes(CS) && !r.text.includes(SIGN), r.text);
});
/** Run /authorize + the simulated Hue login for `client`, stopping at the redirect: returns an unredeemed MCP code and its verifier. */
async function pendingCode(h, client, redirectUri = RURI) {
  const { verifier, challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id: client, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256" });
  const { r: hu } = await approve(h, q);
  const cb = await h.req(`/oauth/callback?code=CODE-bob&state=${new URL(hu.headers.get("location")).searchParams.get("state")}`, { headers: { cookie: hu.headers.get("set-cookie").split(";")[0] } });
  return { code: new URL(cb.headers.get("location")).searchParams.get("code"), verifier };
}
const redeemWith = (h, o) => post(h, "/token", { grant_type: "authorization_code", ...o });
const OTHER_RURI = "https://client.example/other";
test("code: redeem is bound to the client_id, the redirect_uri and the PKCE verifier; each failed attempt burns the code", async () => {
  const h = harness();
  const c1 = (await register(h, [RURI, OTHER_RURI])).client_id, c2 = (await register(h)).client_id;
  // control: the right parameters work once
  const ok = await pendingCode(h, c1);
  assert.equal((await redeemWith(h, { code: ok.code, client_id: c1, redirect_uri: RURI, code_verifier: ok.verifier })).status, 200);
  const cases = [
    ["another registered client_id", (p) => ({ client_id: c2, redirect_uri: RURI, code_verifier: p.verifier })],
    ["another (registered) redirect_uri", (p) => ({ client_id: c1, redirect_uri: OTHER_RURI, code_verifier: p.verifier })],
    ["a missing redirect_uri", (p) => ({ client_id: c1, code_verifier: p.verifier })],
    ["a wrong verifier", () => ({ client_id: c1, redirect_uri: RURI, code_verifier: "wrong" })],
    ["no verifier", () => ({ client_id: c1, redirect_uri: RURI })],
  ];
  for (const [label, args] of cases) {
    const p = await pendingCode(h, c1);
    const bad = await redeemWith(h, { code: p.code, ...args(p) });
    assert.equal(bad.status, 400, label); assert.equal((await bad.json()).error, "invalid_grant", label);
    const retry = await redeemWith(h, { code: p.code, client_id: c1, redirect_uri: RURI, code_verifier: p.verifier });
    assert.equal(retry.status, 400, `${label}: the code is burnt, even with the right parameters afterwards`);
  }
});
test("removed setup routes: no admin/oauth-start, admin token in a query string does nothing", async () => {
  const h = harness();
  for (const p of ["/oauth/start?admin=x", "/admin/pair?admin=x", "/admin/anything"]) assert.equal((await h.req(p)).status, 404);
});
test("SIGNUPS=closed stops new sign-ins but existing users keep working", async () => {
  const h = harness(); const a = await login(h, "alice");
  h.env.SIGNUPS = "closed";
  const { client_id } = await register(h);
  assert.equal((await h.req(`/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(RURI)}&code_challenge=x&code_challenge_method=S256`)).status, 503);
  assert.ok(!(await out(await rpc(h, a.access_token, "list_rooms"))).err);
});

// ---------- isolation ----------
test("ISOLATION: user A and B each see and change only their own lights", async () => {
  const h = harness(); const a = await login(h, "alice"), b = await login(h, "bob");
  assert.match((await out(await rpc(h, a.access_token, "list_lights"))).text, /light-alice-1/);
  const lb = (await out(await rpc(h, b.access_token, "list_lights"))).text;
  assert.match(lb, /light-bob-1/); assert.ok(!lb.includes("alice"));
  // same name resolves to each user's OWN room id (name cache is per user)
  await rpc(h, a.access_token, "set_room", { room: "kitchen", on: true });
  await rpc(h, b.access_token, "set_room", { room: "kitchen", on: false });
  const puts = h.cloud.calls.filter((c) => c.method === "PUT" && c.path.startsWith("/route"));
  assert.deepEqual(puts.map((p) => [p.path.split("/").pop(), p.hdr["hue-application-key"], p.hdr.authorization]), [["grouplight-alice", "KEY-alice", "Bearer ACC-alice"], ["grouplight-bob", "KEY-bob", "Bearer ACC-bob"]]);
  // hue_api cannot be pointed at another user's ids' credentials: another user's id with my creds is rejected by the bridge, not served
  const x = await out(await rpc(h, a.access_token, "hue_api", { method: "GET", path: "resource/light/../../../bob" }));
  assert.ok(x.err);
});
test("ISOLATION: forged / cross-wired MCP tokens never authorise", async () => {
  const h = harness(); const a = await login(h, "alice"), b = await login(h, "bob");
  const split = (t) => [t.slice(0, 32), t.slice(33)], [ua, sa] = split(a.access_token), [ub, sb] = split(b.access_token); // token = <uid>.<tag>.<secret>
  for (const bad of [`${ua}.${sb}`, `${ub}.${sa}`, `${ua}.`, `${ua}`, "nodot", `${"0".repeat(32)}.${sa}`, `../x.${sa}`, a.refresh_token]) assert.equal((await rpc(h, bad, "list_rooms")).status, 401, bad);
  assert.equal((await h.req("/mcp", { method: "POST", body: "{}" })).status, 401);
  // a refresh token is not an access token and vice versa
  assert.equal((await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: a.access_token, client_id: a.c }) })).status, 400);
});

// ---------- MCP token lifecycle ----------
test("refresh: rotates, old refresh token re-use revokes the grant, access tokens expire", async () => {
  const h = harness(); const a = await login(h, "alice");
  const rf = (t) => h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: t, client_id: a.c }) });
  const r1 = await rf(a.refresh_token); assert.equal(r1.status, 200); const n = await r1.json();
  assert.ok(!(await out(await rpc(h, n.access_token, "list_rooms"))).err);
  assert.equal((await rf(a.refresh_token)).status, 400); // replay of the rotated token ...
  assert.equal((await rpc(h, n.access_token, "list_rooms")).status, 401); // ... kills the whole grant
  assert.equal((await rf(n.refresh_token)).status, 400);
  const h2 = harness(); const b = await login(h2, "bob"); h2.advance(3600_000 + 1000);
  assert.equal((await rpc(h2, b.access_token, "list_rooms")).status, 401);
});

// ---------- Hue token refresh race ----------
test("RACE: many concurrent tool calls on an expired Hue token cause exactly ONE Hue refresh and the rotated token is stored", async () => {
  const cloud = fakeCloud(); cloud.setDelay(15);
  const h = harness({}, cloud); const a = await login(h, "alice");
  h.advance(8 * 24 * 3600_000); // Hue access token (7d) now expired; MCP token would be too, so mint a fresh MCP token
  const r1 = await (await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c }) })).json();
  const res = await Promise.all(Array.from({ length: 8 }, (_, i) => rpc(h, r1.access_token, i % 2 ? "list_rooms" : "list_lights").then(out)));
  assert.ok(res.every((x) => !x.err), JSON.stringify(res));
  assert.deepEqual(cloud.refreshed, ["REF-alice-0"]);
  // and a later call after another expiry uses the ROTATED token, never the burnt one
  h.advance(8 * 24 * 3600_000);
  const r2 = await (await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: r1.refresh_token, client_id: a.c }) })).json();
  assert.ok(!(await out(await rpc(h, r2.access_token, "list_rooms"))).err);
  assert.deepEqual(cloud.refreshed, ["REF-alice-0", "REF-alice-1"]);
});
test("RACE: two different users refreshing at once do not interfere", async () => {
  const cloud = fakeCloud(); cloud.setDelay(10);
  const h = harness({}, cloud); const a = await login(h, "alice"), b = await login(h, "bob");
  h.advance(8 * 24 * 3600_000);
  const fresh = async (x) => (await (await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: x.refresh_token, client_id: x.c }) })).json()).access_token;
  const [ta, tb] = [await fresh(a), await fresh(b)];
  const rs = await Promise.all([rpc(h, ta, "list_rooms"), rpc(h, tb, "list_rooms"), rpc(h, ta, "list_lights"), rpc(h, tb, "list_lights")].map((p) => p.then(out)));
  assert.ok(rs.every((x) => !x.err));
  assert.deepEqual([...cloud.refreshed].sort(), ["REF-alice-0", "REF-bob-0"]);
});

// ---------- limits ----------
test("rate limit: per sign-in, 429 + Retry-After; other users unaffected; refreshing does not reset it; window resets", async () => {
  const h = harness({ RATE_PER_MIN: "3" }); const a = await login(h, "alice"), b = await login(h, "bob");
  for (let i = 0; i < 3; i++) assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200);
  const lim = await rpc(h, a.access_token, "list_rooms");
  assert.equal(lim.status, 429); assert.ok(Number(lim.headers.get("retry-after")) >= 1);
  assert.equal((await rpc(h, b.access_token, "list_rooms")).status, 200);
  const a2 = await (await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c }) })).json();
  assert.equal((await rpc(h, a2.access_token, "list_rooms")).status, 429, "a refreshed token shares its sign-in's window");
  h.advance(61_000);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 200);
});
test("per-light cap: >N state changes to one light per minute are refused; other lights and users unaffected", async () => {
  const h = harness({ LIGHT_CAP_PER_MIN: "2" }); const a = await login(h, "alice"), b = await login(h, "bob");
  const set = async (t, light, on) => out(await rpc(h, t, "set_light", { light, on }));
  assert.ok(!(await set(a.access_token, "light-alice-1", true)).err); assert.ok(!(await set(a.access_token, "light-alice-1", false)).err);
  const third = await set(a.access_token, "light-alice-1", true);
  assert.ok(third.err); assert.match(third.text, /Too many changes/);
  assert.ok(!(await set(a.access_token, "light-alice-2", true)).err);
  assert.ok(!(await set(b.access_token, "light-bob-1", true)).err);
  assert.ok(!(await out(await rpc(h, a.access_token, "list_lights"))).err, "reads are not capped by the change cap");
  h.advance(61_000); assert.ok(!(await set(a.access_token, "light-alice-1", true)).err);
});
test("quota: per-user daily budget stops a heavy user without touching others", async () => {
  const h = harness({ DAILY_HUE_CALLS: "3" }); const a = await login(h, "alice"), b = await login(h, "bob");
  for (let i = 0; i < 3; i++) assert.ok(!(await out(await rpc(h, a.access_token, "list_lights"))).err);
  const r = await out(await rpc(h, a.access_token, "list_lights")); assert.ok(r.err); assert.match(r.text, /daily/i);
  assert.ok(!(await out(await rpc(h, b.access_token, "list_lights"))).err);
  h.advance(24 * 3600_000); const a2 = await (await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: a.refresh_token, client_id: a.c }) })).json();
  assert.ok(!(await out(await rpc(h, a2.access_token, "list_lights"))).err, "budget resets next UTC day");
});
test("quota: shared-app total is capped; new sign-ins are paused at 90% and calls at 100%", async () => {
  const h = harness({ GLOBAL_DAILY_CALLS: "10" }); const a = await login(h, "alice");
  const cloudCalls0 = h.cloud.calls.length;
  for (let i = 0; i < 9; i++) assert.ok(!(await out(await rpc(h, a.access_token, "list_lights"))).err);
  const { client_id } = await register(h);
  const q = `/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(RURI)}&code_challenge=x&code_challenge_method=S256`;
  h.advance(61_000); // the capacity answer is cached for a minute per isolate
  assert.equal((await h.req(q)).status, 503, "at >=90% no new users");
  assert.ok(!(await out(await rpc(h, a.access_token, "list_lights"))).err); // 10th
  const over = await out(await rpc(h, a.access_token, "list_lights")); assert.ok(over.err); assert.match(over.text, /daily share/);
  assert.equal(h.cloud.calls.length - cloudCalls0, 10, "no Hue call is made once the shared budget is spent");
  h.advance(24 * 3600_000); assert.equal((await h.req(q)).status, 200);
});

/** Every file under dir (relative to repo root), recursive. */
const walk = (dir) => readdirSync(new URL(`../${dir}/`, import.meta.url), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`]));

// ---------- privacy ----------
test("no logging: worker sources contain no console.* and wrangler template turns observability off", () => {
  for (const f of walk("worker")) assert.ok(!/console\.\w+\(/.test(readFileSync(new URL(`../${f}`, import.meta.url), "utf8")), f);
  assert.match(readFileSync(new URL("../wrangler.toml.example", import.meta.url), "utf8"), /\[observability\]\s*enabled = false/);
});

// ---------- quota, bridge keys, registration ----------
const form = (o) => new URLSearchParams(o);
const refreshWith = (h, rt, cid) => h.req("/token", { method: "POST", body: form({ grant_type: "refresh_token", refresh_token: rt, client_id: cid }) });
test("register: non-Latin1 client_name does not crash and the client works end to end", async () => {
  const h = harness();
  const r = await h.req("/register", { method: "POST", body: JSON.stringify({ redirect_uris: [RURI], client_name: "日本 ✨ клиент" }) });
  assert.equal(r.status, 201); const { client_id } = await r.json();
  assert.match(client_id, /^[A-Za-z0-9_.-]+$/, "url-safe id");
  const a = await login(h, "alice", { client: client_id }); assert.equal(a.tok.status, 200);
  assert.match(await (await h.req(`/authorize?${form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: "x", code_challenge_method: "S256" })}`)).text(), /日本/);
});
test("refresh token is bound to its client: another registered client cannot redeem it", async () => {
  const h = harness(); const a = await login(h, "alice"); const other = (await register(h, [RURI, "https://other.example/cb"])).client_id;
  assert.equal((await refreshWith(h, a.refresh_token, other)).status, 400);
  assert.equal((await refreshWith(h, a.refresh_token, a.c)).status, 200, "the right client still can (a mismatch must not burn the token)");
});
test("quota: calls refused by the user's own caps do not consume the shared-app budget", async () => {
  const h = harness({ GLOBAL_DAILY_CALLS: "100", DAILY_HUE_CALLS: "2", LIGHT_CAP_PER_MIN: "1" }); const a = await login(h, "alice");
  const used = async () => { const g = h.stores.get("global"); return [...(g?.entries() ?? [])].filter(([k]) => k.startsWith("gq:")).reduce((n, [, v]) => n + v, 0); };
  await out(await rpc(h, a.access_token, "list_lights")); await out(await rpc(h, a.access_token, "list_lights"));
  const before = await used(); assert.ok(before > 0, "the bridge reserved a block of the shared quota");
  for (let i = 0; i < 5; i++) await out(await rpc(h, a.access_token, "list_lights")); // all over the daily cap
  assert.equal(await used(), before);
});
test("bridge key: signing in again with the same Hue account/bridge reuses the stored key instead of pairing a new slot", async () => {
  const h = harness(); const a = await login(h, "alice"), a2 = await login(h, "alice"), a3 = await login(h, "alice");
  assert.deepEqual(h.cloud.pairs, ["alice"], "one pairing only");
  for (const t of [a, a2, a3]) assert.ok(!(await out(await rpc(h, t.access_token, "list_rooms"))).err);
  assert.notEqual(a.access_token.split(".")[0], a2.access_token.split(".")[0], "still a distinct user id per sign-in");
});
test("bridge key: a revoked/stale stored key is replaced by a fresh pairing", async () => {
  const h = harness(); await login(h, "alice");
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:")); const m = h.stores.get(bk);
  m.set("key", "KEY-stale"); // key got removed from the bridge whitelist behind our back
  const a2 = await login(h, "alice");
  assert.equal(h.cloud.pairs.length, 2); assert.ok(!(await out(await rpc(h, a2.access_token, "list_rooms"))).err);
});
test("bridge: different bridges never share a key; sign-ins per bridge per day are capped", async () => {
  const h = harness({ BRIDGE_LOGINS_PER_DAY: "2" }); await login(h, "alice"); await login(h, "bob");
  assert.deepEqual(h.cloud.pairs, ["alice", "bob"]);
  await login(h, "alice"); // 2nd sign-in for bridge BR-alice today: allowed
  await assert.rejects(() => login(h, "alice"), /302|status/); // 3rd: callback answers 429 page, no code issued
  const { client_id } = await register(h), { challenge } = await pkce();
  const { r: hu } = await approve(h, form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256" }));
  const cb = await h.req(`/oauth/callback?code=CODE-alice&state=${new URL(hu.headers.get("location")).searchParams.get("state")}`, { headers: { cookie: hu.headers.get("set-cookie").split(";")[0] } });
  assert.equal(cb.status, 429); assert.equal(cb.headers.get("location"), null);
  h.advance(24 * 3600_000); assert.ok((await login(h, "alice")).access_token, "resets next UTC day");
});
test("disconnect: POST /revoke (RFC 7009) with a valid token kills all tokens, releases the bridge key and is advertised", async () => {
  const h = harness(); const a = await login(h, "alice"), b = await login(h, "bob");
  const as = await (await h.req("/.well-known/oauth-authorization-server")).json();
  assert.equal(as.revocation_endpoint, `${ORIGIN}/revoke`);
  const bad = await h.req("/revoke", { method: "POST", body: form({ token: `${a.access_token.split(".")[0]}.nope`, client_id: a.c }) });
  assert.equal(bad.status, 200, "RFC 7009: unknown tokens still 200"); assert.ok(!(await h.req("/mcp", { method: "POST", body: "{}" })).ok);
  assert.ok(!(await out(await rpc(h, a.access_token, "list_rooms"))).err, "invalid token revoked nothing");
  const r = await h.req("/revoke", { method: "POST", body: form({ token: a.refresh_token, client_id: a.c }) });
  assert.equal(r.status, 200);
  assert.equal((await rpc(h, a.access_token, "list_rooms")).status, 401);
  assert.equal((await refreshWith(h, a.refresh_token, a.c)).status, 400);
  assert.deepEqual(h.cloud.deleted, ["KEY-alice"], "last holder gone: key removed from the bridge whitelist");
  assert.ok(!(await out(await rpc(h, b.access_token, "list_rooms"))).err, "other user untouched");
  const store = h.stores.get(a.access_token.split(".")[0]); assert.equal(store.has("hue") || store.has("appKey"), false, "Hue tokens and key wiped");
});
test("disconnect: a shared bridge key is only removed from the bridge when its last holder disconnects", async () => {
  const h = harness(); const a = await login(h, "alice"), a2 = await login(h, "alice");
  await h.req("/revoke", { method: "POST", body: form({ token: a.access_token, client_id: a.c }) });
  assert.deepEqual(h.cloud.deleted, []); assert.ok(!(await out(await rpc(h, a2.access_token, "list_rooms"))).err, "second sign-in keeps working");
  await h.req("/revoke", { method: "POST", body: form({ token: a2.access_token, client_id: a2.c }) });
  assert.deepEqual(h.cloud.deleted, ["KEY-alice"]);
});
test("errors: pairing failure page does not echo upstream details", async () => {
  const cloud = fakeCloud(); const f = cloud.f; cloud.f = async (u, i) => (new URL(u).pathname === "/bridge" ? new Response(JSON.stringify([{ error: { description: "SECRET-UPSTREAM-DETAIL" } }])) : f(u, i));
  const h = harness({}, { ...cloud, f: cloud.f }); const { client_id } = await register(h), { challenge } = await pkce();
  const { r: hu } = await approve(h, form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256" }));
  const cb = await h.req(`/oauth/callback?code=CODE-zed&state=${new URL(hu.headers.get("location")).searchParams.get("state")}`, { headers: { cookie: hu.headers.get("set-cookie").split(";")[0] } });
  assert.equal(cb.status, 502); const t = await cb.text(); assert.ok(!/SECRET-UPSTREAM|HTTP \d{3}/.test(t), t);
});
test("bridge key: a transient Hue error while verifying the stored key fails the sign-in instead of pairing a new slot", async () => {
  const cloud = fakeCloud(), f = cloud.f; let down = false;
  const h = harness({}, { ...cloud, f: async (u, i) => (down && new URL(u).pathname === "/route/clip/v2/resource/bridge" ? new Response("{}", { status: 503 }) : f(u, i)) });
  await login(h, "alice");
  assert.equal(cloud.pairs.length, 1);
  down = true; // the stored-key check now gets a 503 (not a 403)
  const failed = await login(h, "alice").then(() => null, (e) => e);
  assert.ok(failed?.name === "AssertionError" && failed.actual === 502 && failed.expected === 302, `sign-in must end in the pair_failed page (502), got ${failed?.message}`);
  assert.equal(cloud.pairs.length, 1, "no second slot was paired");
  assert.deepEqual(cloud.deleted, [], "the stored key was not discarded either");
  down = false; assert.equal((await login(h, "alice")).tok.status, 200, "once Hue answers again the stored key is reused");
  assert.equal(cloud.pairs.length, 1);
});
