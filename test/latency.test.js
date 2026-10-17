// Latency work: fewer Philips cloud round trips per tool call. Tests assert call counts at the transport/fetch boundary.
import test from "node:test";
import assert from "node:assert/strict";
import { createTools } from "../server/tools.js";
import { createHueClient } from "../server/hue.js";
import { createTtlCache } from "../server/cache.js";
import { remoteTransport } from "../server/transport-remote.js";

const APPKEY = "APPKEY0123456789", CS = "CLIENTSECRET0123";
const room = (id, name, gl) => ({ id, metadata: { name }, services: [{ rtype: "grouped_light", rid: gl }] });

/** Fake CLIP transport with mutable world state; records every call. */
function fakeBridge(world) {
  const calls = [];
  const transport = async (method, path, body) => {
    calls.push(`${method} ${path}`);
    const m = /^\/resource\/(\w+)(?:\/([\w-]+))?$/.exec(path);
    if (method === "GET") return { status: 200, text: JSON.stringify({ errors: [], data: world[m[1]] ?? [] }) };
    const exists = (world[m[1]] ?? []).some((x) => x.id === m[2]) || m[1] === "grouped_light" && world.glIds?.includes(m[2]);
    if (!exists) return { status: 404, text: JSON.stringify({ errors: [{ description: "resource not found" }] }) };
    return { status: 200, text: JSON.stringify({ errors: [], data: [{}] }) };
  };
  return { calls, transport };
}
const mk = (world, opts = {}) => {
  const b = fakeBridge(world);
  const tools = createTools(createHueClient(b.transport), { key: APPKEY, ...opts });
  return { ...b, tools };
};
const text = (r) => JSON.parse(r.content[0].text);

// Name->id cache: after the first (cold) call, repeats resolve from the cache and cost exactly one Hue call.
const CACHE_CASES = [
  { name: "set_room: cold = list room + PUT (no grouped_light list); repeat = ONE call", world: () => ({ room: [room("r1", "Kitchen", "g1")], glIds: ["g1"] }),
    first: ["set_room", { room: "kitchen", on: false }], cold: ["GET /resource/room", "PUT /resource/grouped_light/g1"],
    repeat: ["set_room", { room: "kitchen", brightness: 30, color: "#ff8800" }], warm: ["PUT /resource/grouped_light/g1"] },
  { name: "dim_room shares the room cache with set_room", world: () => ({ room: [room("r1", "Kitchen", "g1")], glIds: ["g1"] }),
    first: ["set_room", { room: "kitchen", on: true }], cold: ["GET /resource/room", "PUT /resource/grouped_light/g1"],
    repeat: ["dim_room", { room: "the kitchen" }], warm: ["PUT /resource/grouped_light/g1"] },
  { name: "set_light: repeat resolves from cache", world: () => ({ light: [{ id: "l1", metadata: { name: "Desk lamp" } }] }),
    first: ["set_light", { light: "desk", on: true }], cold: ["GET /resource/light", "PUT /resource/light/l1"],
    repeat: ["set_light", { light: "desk", brightness: 50 }], warm: ["PUT /resource/light/l1"], id: "l1" },
];
test("cache: after one cold call, repeats of set_room, dim_room and set_light resolve names from the cache (ONE Hue call)", async () => {
  for (const c of CACHE_CASES) {
    const { tools, calls } = mk(c.world());
    assert.ok(!(await tools.callTool(...c.first)).isError, c.name);
    assert.deepEqual(calls, c.cold, c.name);
    calls.length = 0;
    const r = await tools.callTool(...c.repeat);
    assert.ok(!r.isError, c.name);
    if (c.id) assert.equal(text(r).id, c.id, c.name);
    assert.deepEqual(calls, c.warm, c.name);
  }
});
test("cache TTL: entry expires after ttl and is refetched", async () => {
  let t = 0;
  const cache = createTtlCache({ ttlMs: 300_000, now: () => t });
  const { tools, calls } = mk({ room: [room("r1", "Kitchen", "g1")], glIds: ["g1"] }, { cache });
  await tools.callTool("set_room", { room: "kitchen", on: true });
  t = 299_000; calls.length = 0;
  await tools.callTool("set_room", { room: "kitchen", on: true });
  assert.equal(calls.length, 1);
  t = 301_000; calls.length = 0;
  await tools.callTool("set_room", { room: "kitchen", on: true });
  assert.deepEqual(calls, ["GET /resource/room", "PUT /resource/grouped_light/g1"]);
});
test("stale id: 404 on PUT invalidates cache, re-resolves and retries exactly once", async () => {
  const w = { room: [room("r1", "Kitchen", "g1")], glIds: ["g1"] };
  const { tools, calls } = mk(w);
  await tools.callTool("set_room", { room: "kitchen", on: true });
  w.room = [room("r1", "Kitchen", "g2")]; w.glIds = ["g2"]; // bridge re-created the group
  calls.length = 0;
  const r = await tools.callTool("set_room", { room: "kitchen", on: false });
  assert.ok(!r.isError, JSON.stringify(r));
  assert.deepEqual(calls, ["PUT /resource/grouped_light/g1", "GET /resource/room", "PUT /resource/grouped_light/g2"]);
});
test("stale id: if the retry also 404s the error surfaces (no loop)", async () => {
  const w = { room: [room("r1", "Kitchen", "g1")], glIds: [] };
  const { tools, calls } = mk(w);
  const r = await tools.callTool("set_room", { room: "kitchen", on: true });
  assert.ok(r.isError); assert.match(r.content[0].text, /404/);
  assert.equal(calls.filter((c) => c.startsWith("PUT")).length, 1); // fresh fetch => no retry
  calls.length = 0;
  await tools.callTool("set_room", { room: "kitchen", on: true }); // cached now -> PUT 404 -> refetch -> PUT 404 -> stop
  assert.equal(calls.length, 3);
});
test("renamed/new room: cached miss triggers one refetch before failing", async () => {
  const w = { room: [room("r1", "Kitchen", "g1")], glIds: ["g1", "g9"] };
  const { tools, calls } = mk(w);
  await tools.callTool("set_room", { room: "kitchen", on: true });
  w.room.push(room("r9", "Garage", "g9"));
  calls.length = 0;
  const r = await tools.callTool("set_room", { room: "garage", on: true });
  assert.ok(!r.isError, JSON.stringify(r));
  assert.deepEqual(calls, ["GET /resource/room", "PUT /resource/grouped_light/g9"]);
  calls.length = 0;
  assert.ok((await tools.callTool("set_room", { room: "nonexistent", on: true })).isError);
  assert.equal(calls.length, 1); // exactly one refetch, then clear error
});
test("validation errors make no cloud call at all after warm cache", async () => {
  const { tools, calls } = mk({ room: [room("r1", "Kitchen", "g1")], glIds: ["g1"] });
  await tools.callTool("set_room", { room: "kitchen", on: true });
  calls.length = 0;
  assert.ok((await tools.callTool("set_room", { room: "kitchen" })).isError);
  assert.equal(calls.length, 0);
});
test("list_rooms is never served from cache (live state)", async () => {
  const { tools, calls } = mk({ room: [room("r1", "Kitchen", "g1")], grouped_light: [{ id: "g1", on: { on: true } }] });
  await tools.callTool("list_rooms", {}); await tools.callTool("list_rooms", {});
  assert.equal(calls.filter((c) => c === "GET /resource/room").length, 2);
});

// ---- token reuse within one sign-in ----
const T = (o = {}) => ({ access_token: "ACCESS1", refresh_token: "R1", expires_at: Date.now() + 86400_000, ...o });
function cloud({ accessOk = (t) => t === "ACCESS1" } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    const u = new URL(url); calls.push(u.pathname);
    if (u.pathname === "/v2/oauth2/token") return Response.json({ access_token: "ACCESS2", refresh_token: "R2", access_token_expires_in: 604800 });
    const tok = init.headers?.authorization?.replace("Bearer ", "");
    if (!accessOk(tok)) return new Response("{}", { status: 401 });
    return Response.json({ errors: [], data: [] });
  };
  return { f, calls };
}
function countingStore(v) { let reads = 0; return { get: async () => (reads++, v), set: async (n) => { v = n; }, reads: () => reads, peek: () => v, poke: (n) => { v = n; } }; }
const tr = (o) => remoteTransport({ appKey: APPKEY, clientId: "id", clientSecret: CS, ...o });

test("token cache: one transport reuses a valid access token without re-reading the store", async () => {
  const { f } = cloud(); const store = countingStore(T()); const t = tr({ tokens: store, fetch: f });
  for (let i = 0; i < 3; i++) await t("GET", "/resource/light");
  assert.equal(store.reads(), 1);
});
test("token cache: near expiry it re-reads the store first and adopts a token that was already rotated there", async () => {
  let clock = Date.now();
  const { f, calls } = cloud({ accessOk: (x) => x === "ACCESS1" || x === "ACCESS9" });
  const store = countingStore(T({ expires_at: clock + 2 * 3600_000 })), t = tr({ tokens: store, fetch: f, now: () => clock });
  await t("GET", "/resource/light"); // remembered, 2 h left
  clock += 90 * 60_000; // 30 min left: inside the 1 h refresh window
  store.poke(T({ access_token: "ACCESS9", refresh_token: "R9", expires_at: clock + 86400_000 }));
  calls.length = 0;
  assert.equal((await t("GET", "/resource/light")).status, 200);
  assert.ok(!calls.includes("/v2/oauth2/token"), "must not burn a refresh token that was already rotated");
});
test("token cache: on a 401 it adopts a newer stored token without refreshing", async () => {
  let ok = "ACCESS1";
  const { f, calls } = cloud({ accessOk: (x) => x === ok });
  const store = countingStore(T()), t = tr({ tokens: store, fetch: f });
  assert.equal((await t("GET", "/resource/light")).status, 200);
  ok = "ACCESS9"; store.poke(T({ access_token: "ACCESS9", refresh_token: "R9" })); calls.length = 0;
  assert.equal((await t("GET", "/resource/light")).status, 200);
  assert.ok(!calls.includes("/v2/oauth2/token"));
});
test("token cache: concurrent calls near expiry share a single refresh", async () => {
  const { f, calls } = cloud({ accessOk: (x) => x === "ACCESS2" });
  const store = countingStore(T({ expires_at: Date.now() + 1000 })), t = tr({ tokens: store, fetch: f });
  await Promise.all([1, 2, 3].map(() => t("GET", "/resource/light")));
  assert.equal(calls.filter((c) => c === "/v2/oauth2/token").length, 1);
});
