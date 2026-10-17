// Consent must be a POST with a token bound to the browser and the request; scheme allowlist, nosniff, Hue-denied redirect, rate limits on /register, /token, /revoke.
import test from "node:test";
import assert from "node:assert/strict";
import { RURI, harness, approve, pkce, register } from "./support/harness.js";
import { signClient } from "../worker/clients.js";
import { SIGN } from "./support/harness.js";

const form = (o) => new URLSearchParams(o);
async function params(h, extra = {}) {
  const { client_id } = await register(h), { challenge } = await pkce();
  return form({ response_type: "code", client_id, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256", state: "cs", ...extra });
}
const sessPuts = (h) => h.kvPuts.length; // the login keeps no server-side state at all

// ---------- consent: POST + browser-bound token ----------
test("consent: GET never approves, even with confirm=1 (no session, no Hue redirect)", async () => {
  const h = harness(), q = await params(h);
  for (const extra of ["", "&confirm=1", "&confirm=1&consent=x"]) {
    const r = await h.req(`/authorize?${q}${extra}`);
    assert.equal(r.status, 200); assert.equal(r.headers.get("location"), null); assert.match(r.headers.get("content-type"), /html/);
  }
  assert.equal(sessPuts(h), 0);
});
test("consent: the page is a POST form with a token, and a POST from the same browser proceeds to Hue", async () => {
  const h = harness(), q = await params(h);
  const a = await approve(h, q);
  assert.match(a.html, /<form method="post" action="\/authorize"/); assert.ok(a.fields.get("consent"), "token present");
  assert.ok(a.cookie, "consent cookie set");
  assert.equal(a.r.status, 302); assert.match(a.r.headers.get("location"), /^https:\/\/api\.meethue\.com\/v2\/oauth2\/authorize/);
  assert.match(a.r.headers.get("set-cookie"), /hue_login=/, "the login travels in a cookie");
  assert.equal(sessPuts(h), 0);
});
test("consent: POST without token, with a wrong token, or without the cookie is refused and writes nothing", async () => {
  const h = harness(), q = await params(h);
  const none = await approve(h, q, { tweak: (f) => f.delete("consent") });
  const bad = await approve(h, q, { tweak: (f) => f.set("consent", f.get("consent").slice(0, -2) + "xx") });
  const page = await h.req(`/authorize?${q}`), html = await page.text();
  const tok = /name="consent" value="([^"]+)"/.exec(html)[1], f = new URLSearchParams(q); f.set("consent", tok);
  const noCookie = await h.req("/authorize", { method: "POST", body: f });
  const otherCookie = await h.req("/authorize", { method: "POST", headers: { cookie: "hue_consent=attacker" }, body: f });
  for (const r of [none.r, bad.r, noCookie, otherCookie]) { assert.equal(r.status, 403); assert.equal(r.headers.get("location"), null); }
  assert.equal(sessPuts(h), 0);
});
test("consent: the token is bound to the request it was shown for (changed redirect/challenge/state is refused)", async () => {
  const h = harness(), q = await params(h);
  for (const [k, v] of [["state", "other"], ["code_challenge", "AAAA"], ["redirect_uri", "https://client.example/other"]]) {
    const a = await approve(h, q, { tweak: (f) => f.set(k, v) });
    assert.ok([400, 403].includes(a.r.status), k); assert.equal(a.r.headers.get("location"), null);
  }
  assert.equal(sessPuts(h), 0);
});
test("consent: approving clears the consent cookie, and the token expires", async () => {
  const h = harness(), q = await params(h);
  const a = await approve(h, q); assert.equal(a.r.status, 302);
  assert.match(a.r.headers.get("set-cookie"), /hue_consent=; Path=\/authorize; HttpOnly; Max-Age=0/, "the browser drops its consent cookie");
  const page = await h.req(`/authorize?${q}`), cookie = page.headers.get("set-cookie").split(";")[0];
  const tok = /name="consent" value="([^"]+)"/.exec(await page.text())[1], f = new URLSearchParams(q); f.set("consent", tok);
  h.advance(11 * 60_000);
  assert.equal((await h.req("/authorize", { method: "POST", headers: { cookie }, body: f })).status, 403, "expired");
});
test("consent: a POST to /authorize with confirm=1 in the query or body and no token does nothing", async () => {
  const h = harness(), q = await params(h, { confirm: "1" });
  const r = await h.req(`/authorize?${q}`, { method: "POST", body: q });
  assert.equal(r.status, 403); assert.equal(sessPuts(h), 0);
});
test("consent: cookie is HttpOnly, SameSite and scoped to /authorize; page may post only to itself", async () => {
  const h = harness(), q = await params(h), r = await h.req(`/authorize?${q}`);
  const c = r.headers.get("set-cookie"); assert.match(c, /HttpOnly/); assert.match(c, /SameSite=(Strict|Lax)/); assert.match(c, /Path=\/authorize/);
  assert.match(r.headers.get("content-security-policy"), /form-action 'self'/);
});

// ---------- redirect_uri scheme allowlist ----------
test("redirect_uri: dangerous and non-allowlisted schemes are rejected at registration and at /authorize", async () => {
  const h = harness();
  for (const bad of ["javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,x", "vbscript:x", "file:///etc/passwd", "blob:https://a.example/x", "about:blank", "ftp://a.example/cb", "ws://a.example/cb", "http://a.example/cb", " javascript:alert(1)", "java\tscript:alert(1)"])
    assert.equal((await register(h, [bad])).r.status, 400, bad);
  // a signed client id carrying a bad URI (e.g. issued by an older version) is still never redirected to
  for (const bad of ["javascript:alert(1)", "data:text/html,x"]) {
    const cid = await signClient(SIGN, { n: "x", r: [bad] }), { challenge } = await pkce();
    const r = await h.req(`/authorize?${form({ response_type: "code", client_id: cid, redirect_uri: bad, code_challenge: challenge, code_challenge_method: "S256" })}`);
    assert.equal(r.status, 400); assert.equal(r.headers.get("location"), null);
  }
  assert.equal((await register(h, ["cursor://anysphere.cursor-mcp/oauth/callback", "http://127.0.0.1:9/cb"])).r.status, 201);
});

// ---------- nosniff ----------
test("headers: every response carries X-Content-Type-Options: nosniff", async () => {
  const h = harness(), q = await params(h), a = await approve(h, q);
  const rs = [await h.req("/nope"), await h.req("/.well-known/oauth-authorization-server"), await h.req(`/authorize?${q}`), a.r,
    await h.req("/mcp", { method: "POST", body: "{}" }), await h.req("/token", { method: "POST", body: "" }), await h.req("/revoke", { method: "POST", body: "" }),
    await h.req("/register", { method: "POST", body: "{}" }), await h.req("/mcp", { method: "OPTIONS" }),
    await h.req(`/authorize?response_type=code&client_id=${q.get("client_id")}&redirect_uri=${encodeURIComponent(RURI)}`)];
  for (const r of rs) assert.equal(r.headers.get("x-content-type-options"), "nosniff", `${r.status} ${r.headers.get("location") ?? ""}`);
});

// ---------- Hue denies ----------
test("callback: when Hue reports an error the browser is sent back to the client with error + state, and the login cookie is cleared", async () => {
  const h = harness(), q = await params(h), a = await approve(h, q);
  const state = new URL(a.r.headers.get("location")).searchParams.get("state");
  const cb = await h.req(`/oauth/callback?error=access_denied&state=${state}`, { headers: { cookie: a.r.headers.get("set-cookie").split(";")[0] } });
  assert.equal(cb.status, 302);
  const back = new URL(cb.headers.get("location"));
  assert.equal(back.origin + back.pathname, RURI); assert.equal(back.searchParams.get("error"), "access_denied"); assert.equal(back.searchParams.get("state"), "cs"); assert.equal(back.searchParams.get("code"), null);
  assert.equal(cb.headers.get("x-content-type-options"), "nosniff");
  assert.match(cb.headers.get("set-cookie"), /hue_login=; Path=\/oauth\/callback; HttpOnly; Max-Age=0/);
  assert.equal([...h.stores.keys()].filter((k) => /^[0-9a-f]{32}$/.test(k)).length, 0, "no user was created");
});
test("callback: an error from Hue without the binding cookie is not redirected anywhere", async () => {
  const h = harness(), q = await params(h), a = await approve(h, q);
  const state = new URL(a.r.headers.get("location")).searchParams.get("state");
  const cb = await h.req(`/oauth/callback?error=access_denied&state=${state}`);
  assert.equal(cb.status, 400); assert.equal(cb.headers.get("location"), null);
});

// ---------- rate limits ----------
test("rate limit: /register, /token and /revoke answer 429 + retry-after per client IP, other IPs unaffected, window resets", async () => {
  for (const [path, env, mk] of [
    ["/register", { REGISTER_PER_MIN: "3" }, () => ({ method: "POST", body: JSON.stringify({ redirect_uris: [RURI] }) })],
    ["/token", { TOKEN_PER_MIN: "3" }, () => ({ method: "POST", body: form({ grant_type: "refresh_token", refresh_token: "x", client_id: "x" }) })],
    ["/revoke", { REVOKE_PER_MIN: "3" }, () => ({ method: "POST", body: form({ token: "x" }) })],
  ]) {
    const h = harness(env), ip = { "cf-connecting-ip": "203.0.113.7" }, codes = [];
    for (let i = 0; i < 6; i++) codes.push((await h.req(path, { ...mk(), headers: ip })).status);
    assert.deepEqual(codes.map((c) => c === 429), [false, false, false, true, true, true], path);
    const limited = await h.req(path, { ...mk(), headers: ip }); assert.ok(Number(limited.headers.get("retry-after")) >= 1); assert.equal(limited.headers.get("x-content-type-options"), "nosniff");
    assert.notEqual((await h.req(path, { ...mk(), headers: { "cf-connecting-ip": "198.51.100.9" } })).status, 429, "other IP");
    h.advance(61_000); assert.notEqual((await h.req(path, { ...mk(), headers: ip })).status, 429, "next window");
  }
});
test("rate limit: default limits leave normal use alone (a full login is never limited)", async () => {
  const h = harness(); for (let i = 0; i < 3; i++) assert.equal((await register(h)).r.status, 201);
});
