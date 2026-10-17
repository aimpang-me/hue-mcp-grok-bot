// Stateless dynamic client registration (RFC 7591): client_id = HMAC-signed blob of the registered metadata, so open registration stores nothing and can't be spammed.
import { b64url, unb64url, hmac, safeEqual } from "./util.js";

// Allowlist: https, http only for loopback, or an app custom scheme that is not on the deny list of schemes a browser would execute or fetch.
const BAD_SCHEMES = new Set(["javascript", "data", "file", "vbscript", "blob", "about", "ftp", "ws", "wss", "mailto", "tel", "sms", "view-source", "chrome", "chrome-extension", "resource", "jar", "filesystem", "intent"]);
/** Acceptable redirect URI: https, http loopback, or an app custom scheme. No fragments. @param {unknown} u */
export function okRedirect(u) {
  if (typeof u !== "string" || u.length > 300 || u.includes("#") || !/^[a-z][a-z0-9+.-]*:/.test(u)) return false; // no leading space/control chars, lowercase scheme as written
  try {
    const p = new URL(u);
    if (BAD_SCHEMES.has(p.protocol.slice(0, -1))) return false;
    if (p.protocol === "https:") return true;
    if (p.protocol === "http:") return ["localhost", "127.0.0.1", "[::1]"].includes(p.hostname);
    return /^[a-z][a-z0-9+.-]*:$/.test(p.protocol);
  } catch { return false; }
}

/** @param {string} secret @param {{n: string, r: string[]}} c */
export async function signClient(secret, c) { const b = b64url(new TextEncoder().encode(JSON.stringify(c))); return `${b}.${await hmac(secret, "client:" + b)}`; }
/** @param {string|undefined} secret @param {string} id @returns {Promise<{n: string, r: string[]}|null>} */
export async function readClient(secret, id) {
  const [b, sig] = id.split("."); if (!b || !sig || !secret) return null;
  if (!safeEqual(sig, await hmac(secret, "client:" + b))) return null;
  try { return JSON.parse(new TextDecoder().decode(unb64url(b))); } catch { return null; }
}
