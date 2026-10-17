// Transport C: direct LAN, for local testing only (the hosted connector never uses it). The bridge serves a self-signed certificate,
// so TLS verification is disabled ONLY via an https.Agent attached to requests to the configured bridge host. No global
// NODE_TLS_REJECT_UNAUTHORIZED; no other host is ever contacted. Use it only on a network you trust (see docs/DEVELOPING.md).
import https from "node:https";
import http from "node:http";
import { createHueClient } from "./hue.js";

/** @param {{ ip: string, key: string, scheme?: "https"|"http", port?: number, timeoutMs?: number }} cfg @returns {import("./hue.js").Transport} */
export function localTransport({ ip, key, scheme = "https", port, timeoutMs = 8000 }) {
  const agent = scheme === "https" ? new https.Agent({ rejectUnauthorized: false }) : undefined;
  const lib = scheme === "https" ? https : http;
  return (method, path, body) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = lib.request({
      host: ip, port, method, path: `/clip/v2${path}`, agent, timeout: timeoutMs,
      headers: { "hue-application-key": key, accept: "application/json", ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}) },
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: data }));
    });
    req.on("timeout", () => req.destroy(new Error(`Timed out talking to bridge at ${ip}`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** A LAN Hue client: the transport above wrapped with error redaction of the key. @param {Parameters<typeof localTransport>[0]} cfg */
export const createHue = (cfg) => createHueClient(localTransport(cfg), { secrets: [cfg.key] });
