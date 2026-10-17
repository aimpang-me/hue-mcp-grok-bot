// Consent page wording, pre-consent errors, redirect_uri rules at /token, grant lifetime, and the bridge-key and disconnect races.
import test from "node:test";
import assert from "node:assert/strict";
import { RURI, harness, approve, pkce, register, login, rpc, out } from "./support/harness.js";

const DAY = 24 * 3600_000;
const form = (o) => new URLSearchParams(o);
const uidOf = (t) => t.split(".")[0];
const post = (h, path, o) => h.req(path, { method: "POST", body: form(o) });
const dop = async (h, uid, payload) => (await h.env.USER_DO.get(uid).fetch(new Request("https://do/op", { method: "POST", body: JSON.stringify(payload) }))).json();

test("authorize: errors before consent show a page and never redirect, even to a registered redirect_uri", async () => {
  const h = harness(); const { client_id } = await register(h), { challenge } = await pkce();
  for (const [bad, e] of [[{ response_type: "token" }, "unsupported_response_type"], [{ code_challenge_method: "plain" }, "invalid_request"], [{ resource: "https://evil.example/mcp" }, "invalid_target"]]) {
    const q = form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256", state: "s", ...bad });
    for (const r of [await h.req(`/authorize?${q}`), await h.req("/authorize", { method: "POST", body: q })]) {
      assert.equal(r.status, 400, e); assert.equal(r.headers.get("location"), null, e); assert.match(await r.text(), new RegExp(e));
    }
  }
});

test("consent: leads with where the result goes and labels the registered name as a claim", async () => {
  const h = harness();
  const reg = await h.req("/register", { method: "POST", body: JSON.stringify({ redirect_uris: [RURI], client_name: "Official Hue App" }) });
  const { client_id } = await reg.json(), { challenge } = await pkce();
  const html = await (await h.req(`/authorize?${form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256" })}`)).text();
  const host = html.indexOf("<b>client.example</b>"), claim = html.indexOf("Claimed app name: Official Hue App");
  assert.ok(host > 0 && claim > host, "redirect host comes first, the name is labelled as claimed");
  assert.match(html, /<h1>Connect your lights<\/h1>/);
  const app = await (await h.req("/register", { method: "POST", body: JSON.stringify({ redirect_uris: ["myapp://cb"], client_name: "X" }) })).json();
  const appHtml = await (await h.req(`/authorize?${form({ response_type: "code", client_id: app.client_id, redirect_uri: "myapp://cb", code_challenge: challenge, code_challenge_method: "S256" })}`)).text();
  assert.match(appHtml, /an app on this device \(myapp: link\)/); assert.match(appHtml, /any app installed on your device/);
});

test("discovery: resource_name does not lead with the Hue brand", async () => {
  const j = await (await harness().req("/.well-known/oauth-protected-resource")).json();
  assert.ok(!j.resource_name.startsWith("Hue"), j.resource_name);
});

/** Authorize (optionally without redirect_uri), finish the simulated Hue login, return the MCP code and PKCE verifier. */
async function codeFor(h, x, { sendRuri }) {
  const { client_id } = await register(h), { verifier, challenge } = await pkce();
  const q = form({ response_type: "code", client_id, code_challenge: challenge, code_challenge_method: "S256", state: "cs", ...(sendRuri ? { redirect_uri: RURI } : {}) });
  const { r } = await approve(h, q);
  const cookie = r.headers.get("set-cookie")?.split(";")[0], state = new URL(r.headers.get("location")).searchParams.get("state");
  const cb = await h.req(`/oauth/callback?code=CODE-${x}&state=${state}`, { headers: { cookie } });
  const back = new URL(cb.headers.get("location"));
  assert.equal(back.origin + back.pathname, RURI);
  return { client_id, verifier, code: back.searchParams.get("code") };
}

test("token: a client that omitted redirect_uri at authorize may omit it at /token; a different one is still refused", async () => {
  const h = harness();
  const a = await codeFor(h, "alice", { sendRuri: false });
  assert.equal((await post(h, "/token", { grant_type: "authorization_code", code: a.code, client_id: a.client_id, code_verifier: a.verifier })).status, 200);
  const b = await codeFor(h, "bob", { sendRuri: false });
  const wrong = await post(h, "/token", { grant_type: "authorization_code", code: b.code, client_id: b.client_id, code_verifier: b.verifier, redirect_uri: "https://client.example/other" });
  assert.equal((await wrong.json()).error, "invalid_grant");
  const c = await codeFor(h, "carol", { sendRuri: true }); // sent at authorize: still required at /token
  assert.equal((await (await post(h, "/token", { grant_type: "authorization_code", code: c.code, client_id: c.client_id, code_verifier: c.verifier })).json()).error, "invalid_grant");
});

test("refresh: a grant has an absolute lifetime of 180 days however often it is refreshed", async () => {
  const h = harness(); let t = await login(h, "alice");
  for (let d = 29; d <= 174; d += 29) {
    h.advance(29 * DAY);
    const r = await post(h, "/token", { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.c });
    assert.equal(r.status, 200, `refresh on day ${d}`); t = { ...t, ...(await r.json()) };
  }
  h.advance(7 * DAY); // day 181: the last refresh token's own 30 days are not up, but the grant is
  const late = await post(h, "/token", { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.c });
  assert.equal((await late.json()).error, "invalid_grant");
});

test("bridge key: two first sign-ins racing on one bridge leave exactly one key on it, shared by both", async () => {
  const h = harness(); h.cloud.setBridge(() => "BR-shared"); h.cloud.setPairDelay(20);
  const [a, b] = await Promise.all([login(h, "alice"), login(h, "alice")]);
  assert.equal(h.cloud.pairs.length, 2, "both paired: the race happened");
  const bk = [...h.stores.keys()].find((k) => k.startsWith("bridge:")), kept = h.stores.get(bk).get("key");
  const made = ["KEY-alice", "KEY-alice~1"];
  assert.deepEqual(h.cloud.deleted, made.filter((k) => k !== kept), "the losing key was removed from the bridge");
  for (const s of [a, b]) {
    assert.equal(h.stores.get(uidOf(s.access_token)).get("appKey"), kept);
    assert.ok(!(await out(await rpc(h, s.access_token, "list_rooms"))).err);
  }
});

test("disconnect: a Hue refresh that finishes after revoke cannot write tokens back, and the DO refuses calls", async () => {
  const h = harness(); const a = await login(h, "alice"), uid = uidOf(a.access_token), store = h.stores.get(uid);
  // 30 min left: inside the Hue call's 1 h refresh window, outside revoke's 60 s one, so only the call refreshes.
  store.set("hue", { ...store.get("hue"), expires_at: h.now() + 30 * 60_000 });
  h.cloud.setDelay(60); // the refresh is slow, so the revoke lands while it is in flight
  const call = rpc(h, a.access_token, "list_rooms");
  while (!h.cloud.refreshed.length) await new Promise((r) => setTimeout(r, 1));
  await post(h, "/revoke", { token: a.refresh_token });
  await call;
  assert.deepEqual([...store.keys()], ["disabled"], "nothing written back after the wipe");
  assert.equal((await dop(h, uid, { op: "hue", method: "GET", path: "/resource/light" })).status, 401);
});
