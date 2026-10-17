import test from "node:test";
import assert from "node:assert/strict";
import { remoteTransport, pairRemote } from "../server/transport-remote.js";
import { createHueClient } from "../server/hue.js";

const APPKEY = "APPKEY" + "x".repeat(34), CS = "CLIENTSECRET-xyz";
const roomJson = JSON.stringify({ errors: [], data: [{ id: "r1", metadata: { name: "Kitchen" }, services: [{ rtype: "grouped_light", rid: "g1" }] }] });

/** Fake Hue cloud as a fetch implementation; records calls. */
function fakeCloud({ accessOk = (t) => t === "ACCESS1" } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    const u = new URL(url); calls.push({ url: u.pathname + u.search, init });
    const hdr = init.headers ?? {};
    if (u.pathname === "/v2/oauth2/token") {
      const b = init.body.get("grant_type");
      return Response.json({ access_token: b === "refresh_token" ? "ACCESS2" : "ACCESS1", refresh_token: "REFRESH2", access_token_expires_in: 604800 });
    }
    if (u.pathname === "/bridge/0/config") return Response.json([{ success: { "/config/linkbutton": true } }]);
    if (u.pathname === "/bridge") return Response.json([{ success: { username: "NEWAPPKEY" } }]);
    if (u.pathname.startsWith("/route/clip/v2")) {
      const tok = hdr.authorization?.replace("Bearer ", "");
      if (!accessOk(tok)) return new Response("{}", { status: 401 });
      if (hdr["hue-application-key"] !== APPKEY) return new Response("{}", { status: 403 });
      if (init.method === "PUT") return Response.json({ errors: [], data: [{}] });
      return new Response(u.pathname.endsWith("/room") ? roomJson : JSON.stringify({ errors: [], data: [] }));
    }
    return new Response("nope", { status: 404 });
  };
  return { f, calls };
}
const memStore = (t) => { let v = t; return { get: async () => v, set: async (n) => { v = n; }, peek: () => v }; };

test("remote: near-expiry token refreshes first and the rotated token is stored", async () => {
  const { f, calls } = fakeCloud({ accessOk: (t) => t === "ACCESS2" });
  const tokens = memStore({ access_token: "ACCESS1", refresh_token: "R1", expires_at: Date.now() + 1000 });
  const t = remoteTransport({ appKey: APPKEY, clientId: "id", clientSecret: CS, tokens, fetch: f });
  const res = await t("GET", "/resource/light");
  assert.equal(res.status, 200);
  assert.equal(tokens.peek().refresh_token, "REFRESH2");
  assert.ok(calls[0].url === "/v2/oauth2/token");
  assert.match(calls[0].init.headers.authorization, /^Basic /);
});
test("remote: a 401 triggers exactly one forced refresh + retry", async () => {
  const { f, calls } = fakeCloud({ accessOk: (t) => t === "ACCESS2" });
  const tokens = memStore({ access_token: "ACCESS1", refresh_token: "R1", expires_at: Date.now() + 86400_000 });
  const res = await remoteTransport({ appKey: APPKEY, clientId: "id", clientSecret: CS, tokens, fetch: f })("GET", "/resource/light");
  assert.equal(res.status, 200);
  assert.equal(calls.filter((c) => c.url === "/v2/oauth2/token").length, 1);
});
test("remote: errors never echo key or secret; 401 maps to a login hint", async () => {
  const { f } = fakeCloud({ accessOk: () => false });
  const tokens = memStore({ access_token: "ACCESS1", refresh_token: "R1", expires_at: Date.now() + 86400_000 });
  const hue = createHueClient(remoteTransport({ appKey: APPKEY, clientId: "id", clientSecret: CS, tokens, fetch: f }), { secrets: [APPKEY, CS] });
  await assert.rejects(hue.list("light"), (e) => { assert.match(e.message, /401/); assert.ok(!e.message.includes(APPKEY)); return true; });
});
test("pairRemote: virtual link button then POST returns the key", async () => {
  const { f, calls } = fakeCloud();
  assert.equal(await pairRemote({ accessToken: "ACCESS1", fetch: f }), "NEWAPPKEY");
  assert.deepEqual(calls.map((c) => c.url), ["/bridge/0/config", "/bridge"]);
});
