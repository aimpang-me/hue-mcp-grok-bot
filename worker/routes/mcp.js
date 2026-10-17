// The MCP resource: bearer-authenticated JSON-RPC, executed against the caller's own Hue bridge.
import { createHandler } from "../../server/rpc.js";
import { createTools } from "../../server/tools.js";
import { createHueClient } from "../../server/hue.js";
import { CORS, text, json, readBody } from "../http.js";
import { audience, verifiedUid } from "../util.js";

/** @param {import("../index.js").Ctx} c */
export async function mcp({ req, env, origin, callDO, cacheFor }) {
  const challenge = { "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"` };
  const m = /^Bearer (.+)$/.exec(req.headers.get("authorization") ?? ""), token = m?.[1] ?? "", uid = await verifiedUid(env.SIGNING_SECRET, token);
  if (!uid) return json({ error: "unauthorized" }, 401, challenge);
  const a = await callDO(uid, { op: "authz", token, resource: audience(origin) });
  if (a.limited) return json({ error: "rate_limited" }, 429, { "retry-after": String(a.retryAfter) });
  if (!a.ok) return json({ error: "unauthorized" }, 401, challenge);
  if (req.method !== "POST") return text("POST JSON-RPC only", 405, "text/plain", CORS);
  const hue = createHueClient(async (method, path, body) => callDO(uid, { op: "hue", method, path, body }), { secrets: [env.HUE_CLIENT_SECRET, env.SIGNING_SECRET] });
  const handle = createHandler(createTools(hue, { cache: cacheFor(uid) }));
  const raw = await readBody(req); if (raw === null) return json({ error: "payload_too_large" }, 413);
  let msg; try { msg = JSON.parse(raw); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const res = await handle(msg);
  return res ? json(res) : new Response(null, { status: 202, headers: CORS });
}
