// Hue client = tool-facing API on top of a pluggable transport.
// A transport is `(method, path, body?) => Promise<{status: number, text: string}>` where path is relative to
// the CLIPv2 root (e.g. "/resource/light"). Transports: local LAN (C) and Philips remote cloud (A).
import { redact } from "./redact.js";

/** @typedef {(method: string, path: string, body?: unknown) => Promise<{status: number, text: string}>} Transport */

/**
 * @param {Transport} transport
 * @param {{ secrets?: Array<string|undefined> }} [opts] strings scrubbed from every error
 */
export function createHueClient(transport, { secrets = [] } = {}) {
  /** @param {string} method @param {string} path @param {unknown} [body] @returns {Promise<any>} */
  async function request(method, path, body) {
    let res;
    try { res = await transport(method, path, body); }
    catch (e) { throw new Error(redact(`Bridge request failed: ${e instanceof Error ? e.message : String(e)}`, ...secrets)); }
    let json;
    try { json = res.text ? JSON.parse(res.text) : {}; } catch { throw new Error(redact(`Bridge returned non-JSON (HTTP ${res.status})`, ...secrets)); }
    const errs = Array.isArray(json.errors) ? json.errors.map((/** @type {{description?: string}} */ e) => e.description).filter(Boolean) : [];
    if (res.status === 401) throw new Error("Unauthorized (HTTP 401): cloud token missing/expired. Disconnect and reconnect the lights connector.");
    if (res.status === 403) throw new Error("Bridge rejected the app key (HTTP 403). Disconnect and reconnect the lights connector (local server: see docs/DEVELOPING.md).");
    if (res.status === 429) throw new Error(redact(errs.length ? `Rate limit (HTTP 429): ${errs.join("; ")}` : "Hue rate limit hit (HTTP 429); try again later.", ...secrets));
    if (res.status >= 400 || errs.length) throw Object.assign(new Error(redact(`Hue API ${method} ${path}: HTTP ${res.status}${errs.length ? " - " + errs.join("; ") : ""}`, ...secrets)), { status: res.status });
    return json;
  }
  return {
    request,
    /** @param {string} type */
    list: async (type) => (await request("GET", `/resource/${type}`)).data ?? [],
    /** @param {string} type @param {string} id @param {object} body */
    put: (type, id, body) => request("PUT", `/resource/${type}/${id}`, body),
  };
}
