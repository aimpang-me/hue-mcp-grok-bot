import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createHue } from "../server/transport-local.js";
import { createTools } from "../server/tools.js";
import { createHueClient } from "../server/hue.js";
import { createHandler } from "../server/rpc.js";
import { startMock, KEY } from "./mock-bridge.js";

async function setup(t) {
  const mock = await startMock();
  t.after(() => mock.close());
  const tools = createTools(createHue({ ip: "127.0.0.1", key: KEY, scheme: "http", port: mock.port }), { key: KEY });
  const call = async (name, args) => { const r = await tools.callTool(name, args); return { r, text: r.content[0].text, json: r.isError ? null : JSON.parse(r.content[0].text) }; };
  return { mock, call };
}

test("list_rooms joins grouped_light state", async (t) => {
  const { call } = await setup(t);
  const { json } = await call("list_rooms", {});
  assert.deepEqual(json.find((r) => r.name === "Kitchen"), { id: "r1", name: "Kitchen", groupedLightId: "g1", on: true, brightness: 80 });
});
test("list_lights", async (t) => {
  const { call } = await setup(t);
  const { json } = await call("list_lights", {});
  assert.equal(json.length, 2);
  assert.equal(json[1].mirek, 300);
});
test("set_light by fuzzy name sends PUT to the right light", async (t) => {
  const { call, mock } = await setup(t);
  await call("set_light", { light: "desk", on: true, brightness: 40, });
  assert.deepEqual(mock.puts[0], { type: "light", id: "l2", body: { dimming: { brightness: 40 }, on: { on: true } } });
});
test("set_light kelvin is wired through to mirek", async (t) => {
  const { call, mock } = await setup(t);
  await call("set_light", { light: "l1", kelvin: 2700 });
  assert.deepEqual(mock.puts[0].body, { color_temperature: { mirek: 370 } });
});
test("unknown tool names are reported by name", async (t) => {
  const { call } = await setup(t);
  const { r, text } = await call("nope", {});
  assert.ok(r.isError); assert.equal(text, "Unknown tool: nope");
});
test("dim_room: 'dim the kitchen' defaults to 20%, explicit brightness honoured", async (t) => {
  const { call, mock } = await setup(t);
  await call("dim_room", { room: "the kitchen" });
  await call("dim_room", { room: "kitchen", brightness: 5 });
  assert.equal(mock.puts[0].id, "g1");
  assert.equal(mock.puts[0].body.dimming.brightness, 20);
  assert.equal(mock.puts[1].body.dimming.brightness, 5);
});
test("list_scenes shows room names and filters", async (t) => {
  const { call } = await setup(t);
  assert.equal((await call("list_scenes", {})).json.length, 3);
  assert.deepEqual((await call("list_scenes", { room: "bedroom" })).json, [{ id: "s2", name: "Relax", room: "Bedroom" }]);
});
test("activate_scene disambiguates by room, errors when ambiguous", async (t) => {
  const { call, mock } = await setup(t);
  const amb = await call("activate_scene", { scene: "relax" });
  assert.ok(amb.r.isError && /ambiguous/.test(amb.text));
  await call("activate_scene", { scene: "relax", room: "bedroom" });
  assert.deepEqual(mock.puts[0], { type: "scene", id: "s2", body: { recall: { action: "active" } } });
});
test("redaction: key never appears in error output, bad key gives clean message", async (t) => {
  const mock = await startMock(); t.after(() => mock.close());
  const bad = createTools(createHue({ ip: "127.0.0.1", key: "wrongkey", scheme: "http", port: mock.port }), { key: "wrongkey" });
  const r = await bad.callTool("list_rooms", {});
  assert.ok(r.isError && /rejected the app key/.test(r.content[0].text));
  assert.ok(!r.content[0].text.includes("wrongkey"));
  // bridge error body echoing the key must be scrubbed
  const good = createTools(createHue({ ip: "127.0.0.1", key: KEY, scheme: "http", port: mock.port }), { key: KEY });
  const r2 = await good.callTool("list_lights", {}); assert.ok(!r2.isError);
  const hue = createHue({ ip: "127.0.0.1", key: KEY, scheme: "http", port: mock.port });
  await assert.rejects(hue.list("bogus-type!"), (e) => { assert.ok(!e.message.includes(KEY)); return true; });
});

test("protocol smoke: initialize, tools/list, tools/call via handler", async (t) => {
  const { mock } = await setup(t);
  const h = createHandler(createTools(createHue({ ip: "127.0.0.1", key: KEY, scheme: "http", port: mock.port }), { key: KEY }));
  const init = await h({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  assert.equal(init.result.serverInfo.name, "hue-mcp");
  assert.equal(await h({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  const list = await h({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.deepEqual(list.result.tools.map((x) => x.name).sort(), ["activate_scene", "dim_room", "hue_api", "list_lights", "list_rooms", "list_scenes", "set_light", "set_room"]);
  const call = await h({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_rooms", arguments: {} } });
  assert.equal(JSON.parse(call.result.content[0].text).length, 3);
});

test("stdio e2e: real child process, env-only config, key never on stdout/stderr", async (t) => {
  const mock = await startMock(); t.after(() => mock.close());
  // index.js always uses https; a missing-env run proves env-only config and exit behaviour.
  const idx = fileURLToPath(new URL("../server/index.js", import.meta.url));
  const env = { ...process.env }; delete env.HUE_BRIDGE_IP; delete env.HUE_APP_KEY;
  const p = spawn(process.execPath, [idx], { env });
  let err = ""; p.stderr.on("data", (c) => (err += c));
  const code = await new Promise((r) => p.on("exit", r));
  assert.equal(code, 1); assert.match(err, /HUE_BRIDGE_IP and HUE_APP_KEY/);
  // With env set, server answers initialize over stdio (bridge not contacted).
  const q = spawn(process.execPath, [idx], { env: { ...process.env, HUE_BRIDGE_IP: "127.0.0.1", HUE_APP_KEY: KEY } });
  let all = ""; q.stderr.on("data", (c) => (all += c));
  const rl = createInterface({ input: q.stdout });
  const line = new Promise((r) => rl.once("line", r));
  q.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
  const resp = JSON.parse(await line);
  assert.equal(resp.result.serverInfo.name, "hue-mcp");
  // unreachable bridge (https to a mock http port is refused/fails) -> error text, key redacted
  const line2 = new Promise((r) => rl.once("line", r));
  q.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_rooms", arguments: {} } }) + "\n");
  const out2 = await line2;
  assert.ok(!out2.includes(KEY) && !all.includes(KEY));
  q.kill();
});

test("hue_api: raw GET/PUT pass through; bad paths and verbs are rejected", async (t) => {
  const { call, mock } = await setup(t);
  assert.equal((await call("hue_api", { method: "GET", path: "resource/light" })).json.length, 2);
  await call("hue_api", { method: "PUT", path: "resource/light/abcd1234", body: { on: { on: true } } });
  assert.deepEqual(mock.puts[0], { type: "light", id: "abcd1234", body: { on: { on: true } } });
  assert.ok((await call("hue_api", { method: "GET", path: "../config" })).r.isError);
  assert.ok((await call("hue_api", { method: "PATCH", path: "resource/light" })).r.isError);
});

// ---- hue_api guard: assert at the transport boundary, so a rejected call provably never leaves the process ----
function recordingTools() {
  const sent = [];
  const hue = createHueClient(async (method, path, body) => { sent.push([method, path, body]); return { status: 200, text: JSON.stringify({ errors: [], data: [{ ok: true }] }) }; });
  return { sent, call: (args) => createTools(hue).callTool("hue_api", args) };
}
const ID = "0a1b2c3d-1111-2222-3333-444455556666";
test("hue_api: only GET/PUT/POST/DELETE on /resource[/type[/id]] reach the bridge (exact method and path forwarded)", async () => {
  const { sent, call } = recordingTools();
  for (const [args, want] of [
    [{ method: "GET", path: "resource" }, ["GET", "/resource", undefined]],
    [{ method: "get", path: "/resource/zone" }, ["GET", "/resource/zone", undefined]],
    [{ method: "GET", path: "clip/v2/resource/light" }, ["GET", "/resource/light", undefined]],
    [{ method: "PUT", path: `resource/light/${ID}`, body: { on: { on: true } } }, ["PUT", `/resource/light/${ID}`, { on: { on: true } }]],
    [{ method: "DELETE", path: `resource/scene/${ID}` }, ["DELETE", `/resource/scene/${ID}`, undefined]],
  ]) { sent.length = 0; assert.ok(!(await call(args)).isError, JSON.stringify(args)); assert.deepEqual(sent, [want]); }
});
test("hue_api: path traversal, other roots, loose ids and bad verbs are refused with no bridge call", async () => {
  const { sent, call } = recordingTools();
  for (const args of [
    { method: "GET", path: "../config" }, { method: "GET", path: "resource/../config" }, { method: "GET", path: "config" },
    { method: "GET", path: `resource/light/${ID}/../../config` }, { method: "GET", path: `resource/light/${ID}/extra` },
    { method: "GET", path: "foo/resource" }, { method: "GET", path: "resource/Light" }, { method: "GET", path: "resource/light/short" },
    { method: "GET", path: "resource/light/ZZZZZZZZ" }, { method: "GET", path: "resource?x=1" },
    // bad verbs WITH a body and a valid path, so only the verb check can refuse them
    { method: "PATCH", path: "resource/light", body: {} }, { method: "TRACE", path: "resource", body: {} }, { method: "HEAD", path: "resource" }, { method: "", path: "resource", body: {} },
    { method: "PUT", path: `resource/light/${ID}` }, { method: "POST", path: "resource/scene" }, // body required
  ]) { const r = await call(args); assert.ok(r.isError, JSON.stringify(args)); }
  assert.deepEqual(sent, [], "nothing was forwarded");
});

// ---- redaction, one layer at a time: each test fails only when ITS layer is neutered ----
const SECRET = "app-key-0123456"; // < 32 chars: only exact-match redaction can remove it (the key-shaped fallback cannot)
test("redaction in callTool: a tool error that carries the key is scrubbed even when the client layer did not", async () => {
  const leaky = { list: async () => { throw new Error(`boom ${SECRET}`); }, put: async () => { throw new Error(`boom ${SECRET}`); } };
  const r = await createTools(leaky, { key: SECRET }).callTool("list_lights", {});
  assert.ok(r.isError && r.content[0].text.includes("boom") && !r.content[0].text.includes(SECRET), r.content[0].text);
});
test("redaction in hue.js: transport failures, 429 and API error bodies are scrubbed before they leave the client", async () => {
  const mk = (t) => createHueClient(t, { secrets: [SECRET] });
  const echo = (status) => async () => ({ status, text: JSON.stringify({ errors: [{ description: `echo ${SECRET}` }] }) });
  for (const [label, t] of [["transport throws", async () => { throw new Error(`down ${SECRET}`); }], ["HTTP 429", echo(429)], ["HTTP 500", echo(500)], ["errors with 200", echo(200)]]) {
    await assert.rejects(mk(t).request("GET", "/resource/light"), (e) => { assert.ok(e.message.length > 5 && !e.message.includes(SECRET), `${label}: ${e.message}`); return true; });
  }
});
