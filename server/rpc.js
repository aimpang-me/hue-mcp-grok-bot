// Minimal JSON-RPC 2.0 over newline-delimited stdio, MCP subset: initialize, ping, tools/list, tools/call.
import { isRecord } from "./guards.js";

const SUPPORTED = ["2025-06-18", "2025-03-26", "2024-11-05"];

/** @param {unknown} id @param {number} code @param {string} message */
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });

/** @param {ReturnType<typeof import("./tools.js").createTools>} toolset */
export function createHandler({ toolList, callTool }) {
  /** Handle one parsed message. Returns a response, or null for notifications. @param {unknown} msg */
  return async function handle(msg) {
    if (!isRecord(msg) || typeof msg.method !== "string") return err(isRecord(msg) ? (msg.id ?? null) : null, -32600, "Invalid Request");
    const { id, method } = msg;
    if (id === undefined) return null; // notification
    const params = isRecord(msg.params) ? msg.params : {};
    const ok = (/** @type {object} */ result) => ({ jsonrpc: "2.0", id, result });
    switch (method) {
      case "initialize": {
        const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
        return ok({
          protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[0],
          capabilities: { tools: {} },
          serverInfo: { name: "hue-mcp", version: "0.1.0" },
        });
      }
      case "ping": return ok({});
      case "tools/list": return ok({ tools: toolList });
      case "tools/call":
        if (typeof params.name !== "string") return err(id, -32602, "tools/call requires params.name");
        return ok(await callTool(params.name, params.arguments));
      default: return err(id, -32601, `Method not found: ${method}`);
    }
  };
}

/**
 * Wire stdin lines to a handler; requests run concurrently.
 * @param {(msg: unknown) => Promise<object | null>} handle
 */
export function serve(handle, input = process.stdin, write = (/** @type {string} */ s) => process.stdout.write(s)) {
  let buf = "";
  input.setEncoding("utf8");
  input.on("data", (/** @type {string} */ chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      /** @type {unknown} */
      let msg;
      try { msg = JSON.parse(line); } catch { write(JSON.stringify(err(null, -32700, "Parse error")) + "\n"); continue; }
      handle(msg)
        .catch((e) => err(isRecord(msg) ? (msg.id ?? null) : null, -32603, e instanceof Error ? e.message : "Internal error"))
        .then((res) => res && write(JSON.stringify(res) + "\n"));
    }
  });
}
