// Small shared helpers for the multi-user Worker (Web Crypto only; runs in workerd and Node 20).
const enc = new TextEncoder();

/** @param {Uint8Array} b */
export const b64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
/** @param {string} s */
export const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
/** @param {number} [n] random bytes as base64url */
export const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
/** 128-bit random user id, 32 hex chars. */
export const newUserId = () => [...crypto.getRandomValues(new Uint8Array(16))].map((x) => x.toString(16).padStart(2, "0")).join("");
export const USER_ID_RE = /^[0-9a-f]{32}$/;
/** @param {string} s */
export async function sha256Hex(s) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
/** @param {string} s */
export async function sha256b64url(s) { return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))); }

/** Constant-time string compare. @param {string} a @param {string} b */
export function safeEqual(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
}
/** @param {string} secret */
const hmacKey = (secret) => crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
/** @param {string} secret @param {string} data */
export async function hmac(secret, data) { return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(data)))); }

/** Test hook: HUE_CLOUD_BASE is honoured ONLY for loopback http URLs, so a stray var can never redirect real tokens off Philips. @param {string|undefined} v */
export const localBase = (v) => (v && /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(v) ? v : undefined);

/** Fixed-window counter. @param {Map<string, {w: number, n: number}>} m @param {string} key @param {number} limit @param {number} windowMs @param {number} now
 * @returns {{ok: boolean, retryAfter: number}} */
export function hit(m, key, limit, windowMs, now) {
  const w = Math.floor(now / windowMs), e = m.get(key);
  if (!e || e.w !== w) { if (m.size > 5000) for (const [k, v] of m) if (v.w !== w) m.delete(k); m.set(key, { w, n: 1 }); return { ok: limit >= 1, retryAfter: 0 }; }
  if (e.n >= limit) return { ok: false, retryAfter: Math.max(1, Math.ceil(((w + 1) * windowMs - now) / 1000)) };
  e.n++; return { ok: true, retryAfter: 0 };
}

/** The MCP resource (audience) this server protects. Every issued token is bound to it. @param {string} origin */
export const audience = (origin) => `${origin}/mcp`;

// Tokens and codes are `<uid>.<tag>.<secret>`. The tag is an HMAC of the uid, so a request carrying an id this server never issued
// is rejected in the Worker and can never make the platform create a Durable Object for it.
/** @param {string} signingSecret @param {string} uid */
const uidTag = async (signingSecret, uid) => (await hmac(signingSecret, "uid:" + uid)).slice(0, 22);
/** `<uid>.<tag>` for a freshly minted user id. @param {string} signingSecret @param {string} uid */
export async function mintHandle(signingSecret, uid) { return `${uid}.${await uidTag(signingSecret, uid)}`; }
/** The `<uid>.<tag>` prefix of a token. @param {string} token */
export const handleOf = (token) => token.split(".").slice(0, 2).join(".");
/** The user id inside a token, only if its tag verifies; otherwise null. @param {string|undefined} signingSecret @param {string} token @returns {Promise<string|null>} */
export async function verifiedUid(signingSecret, token) {
  const [uid, tag] = token.split(".");
  if (!signingSecret || !USER_ID_RE.test(uid) || !tag) return null;
  return safeEqual(tag, await uidTag(signingSecret, uid)) ? uid : null;
}
/** The one audience a token may name (RFC 8707): this server's /mcp, also accepted as the bare origin. Null for anything else. @param {string} origin @param {string} asked */
export const canonicalResource = (origin, asked) => (asked === origin || asked === audience(origin) ? audience(origin) : null);
