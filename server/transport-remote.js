// Transport A: Philips Hue Remote API (cloud). Works anywhere with fetch (Node 18+, Cloudflare Workers).
//   https://api.meethue.com/route/clip/v2/...   headers: Authorization: Bearer <access>, hue-application-key
// Tokens: access ~7 days, refresh ~112 days (rotating). `tokens` is a store the host provides (Durable Object storage in the Worker).
export const HUE_CLOUD = "https://api.meethue.com";

/** @typedef {{ access_token: string, refresh_token: string, expires_at: number }} Tokens */
/** @typedef {{ get: () => Promise<Tokens|null>, set: (t: Tokens) => Promise<void> }} TokenStore */

/** Exchange an auth code or refresh token. @param {{clientId: string, clientSecret: string, fetch?: typeof fetch, base?: string, now?: () => number}} c @param {URLSearchParams} form @param {string} path @returns {Promise<Tokens>} */
async function tokenCall({ clientId, clientSecret, fetch: f = fetch, base = HUE_CLOUD, now = Date.now }, form, path) {
  const res = await f(`${base}${path}`, {
    method: "POST",
    headers: { authorization: "Basic " + btoa(`${clientId}:${clientSecret}`), "content-type": "application/x-www-form-urlencoded" },
    body: form,
  });
  const j = /** @type {any} */ (await res.json().catch(() => ({})));
  if (!res.ok || !j.access_token) throw new Error(`Hue OAuth token call failed (HTTP ${res.status})`);
  const ttl = Number(j.access_token_expires_in ?? j.expires_in ?? 604800);
  return { access_token: j.access_token, refresh_token: j.refresh_token, expires_at: now() + ttl * 1000 };
}

/** @param {Parameters<typeof tokenCall>[0]} c @param {string} code @param {string} [redirectUri] */
export const exchangeCode = (c, code, redirectUri) =>
  tokenCall(c, new URLSearchParams({ grant_type: "authorization_code", code, ...(redirectUri ? { redirect_uri: redirectUri } : {}) }), "/v2/oauth2/token");
/** @param {Parameters<typeof tokenCall>[0]} c @param {string} refresh */
export const refreshTokens = (c, refresh) =>
  tokenCall(c, new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh }), "/v2/oauth2/token");

/**
 * A transport bound to one sign-in. The host keeps it for as long as that sign-in is live: it remembers the current Hue tokens, so
 * a warm instance skips the store read, and it refreshes at most once at a time. The remembered token is only trusted outside the
 * refresh-skew window; near expiry or on a 401 it re-reads the store first and adopts a token that was already rotated there, and
 * refreshes only if the stored token is still the stale one.
 * @param {{ appKey: string, clientId: string, clientSecret: string, tokens: TokenStore, fetch?: typeof fetch, base?: string, skewMs?: number, now?: () => number }} cfg
 * @returns {import("./hue.js").Transport}
 */
export function remoteTransport(cfg) {
  const { appKey, tokens, fetch: f = fetch, base = HUE_CLOUD, skewMs = 3600_000, now = Date.now } = cfg;
  /** @type {Tokens|null} */ let current = null;
  /** @type {Promise<Tokens>|null} */ let refreshing = null;
  const fresh = (/** @type {Tokens} */ t) => t.expires_at - now() >= skewMs;
  /** Refresh from the stored refresh token (single-flight). @param {Tokens} t @returns {Promise<Tokens>} */
  function rotate(t) {
    refreshing ??= (async () => {
      try { const n = await refreshTokens(cfg, t.refresh_token); await tokens.set(n); current = n; return n; }
      finally { refreshing = null; }
    })();
    return refreshing;
  }
  async function access() {
    if (current && fresh(current)) return current.access_token;
    if (refreshing) return (await refreshing).access_token;
    let t = await tokens.get();
    if (!t) throw new Error("No Hue cloud login for this account; sign in again.");
    if (!fresh(t)) t = await rotate(t); else current = t;
    return t.access_token;
  }
  return async (method, path, body) => {
    /** @param {string} bearer */
    const go = (bearer) => f(`${base}/route/clip/v2${path}`, {
      method,
      headers: { authorization: `Bearer ${bearer}`, "hue-application-key": appKey, accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const used = await access();
    let res = await go(used);
    if (res.status === 401) { // token revoked or rotated early: adopt a newer stored token, else one forced refresh
      current = null;
      const t = await tokens.get();
      if (t) {
        const next = t.access_token !== used && fresh(t) ? (current = t) : await rotate(t);
        res = await go(next.access_token);
      }
    }
    return { status: res.status, text: await res.text() };
  };
}

/**
 * One-time remote creation of a bridge app key ("username") without touching the LAN:
 * PUT /bridge/0/config {linkbutton:true} (virtual button press, ~30 s window), then POST /bridge {devicetype}.
 * Returns the key; callers must store it as a secret and never display it.
 * @param {{ accessToken: string, devicetype?: string, fetch?: typeof fetch, base?: string }} c
 */
export async function pairRemote({ accessToken, devicetype = "hue-mcp#remote", fetch: f = fetch, base = HUE_CLOUD }) {
  const h = { authorization: `Bearer ${accessToken}`, "content-type": "application/json" };
  const a = await f(`${base}/bridge/0/config`, { method: "PUT", headers: h, body: JSON.stringify({ linkbutton: true }) });
  if (!a.ok) throw new Error("Remote link-button step failed");
  const b = await f(`${base}/bridge`, { method: "POST", headers: h, body: JSON.stringify({ devicetype }) });
  const j = /** @type {any} */ (await b.json().catch(() => null));
  const key = j?.[0]?.success?.username;
  if (typeof key !== "string") throw new Error("Remote pairing did not return a key");
  return key;
}

/** Stable id of the account's (first) bridge, or undefined if the cloud doesn't say. @param {{ accessToken: string, fetch?: typeof fetch, base?: string }} c */
export async function bridgeIdOf({ accessToken, fetch: f = fetch, base = HUE_CLOUD }) {
  const r = await f(`${base}/bridge/0/config`, { headers: { authorization: `Bearer ${accessToken}` } });
  const j = /** @type {any} */ (r.ok ? await r.json().catch(() => null) : null);
  return typeof j?.bridgeid === "string" && j.bridgeid ? j.bridgeid : undefined;
}
/** The bridge id from CLIPv2 (`resource/bridge`, field `bridge_id`), for when the cloud's config call does not name it. Needs an app key.
 * @param {{ accessToken: string, appKey: string, fetch?: typeof fetch, base?: string }} c @returns {Promise<string|undefined>} */
export async function bridgeIdV2({ accessToken, appKey, fetch: f = fetch, base = HUE_CLOUD }) {
  const r = await f(`${base}/route/clip/v2/resource/bridge`, { headers: { authorization: `Bearer ${accessToken}`, "hue-application-key": appKey } });
  const j = /** @type {any} */ (r.ok ? await r.json().catch(() => null) : null);
  const id = j?.data?.[0]?.bridge_id;
  return typeof id === "string" && id ? id : undefined;
}
/** The account's bridge id from either source. @param {{ accessToken: string, appKey: string, fetch?: typeof fetch, base?: string }} c */
export const currentBridgeId = async (c) => (await bridgeIdOf(c)) ?? (await bridgeIdV2(c));
/** Is this stored app key dead? Only a definite 401/403 says so; anything else (5xx, 429) throws so a blip never burns a new bridge slot. @param {{ accessToken: string, appKey: string, fetch?: typeof fetch, base?: string }} c */
export async function keyWorks({ accessToken, appKey, fetch: f = fetch, base = HUE_CLOUD }) {
  const r = await f(`${base}/route/clip/v2/resource/bridge`, { headers: { authorization: `Bearer ${accessToken}`, "hue-application-key": appKey } });
  if (r.ok) return true;
  if (r.status === 401 || r.status === 403) return false;
  throw new Error("Could not verify the stored bridge key");
}
/** Remove an app key from the bridge whitelist (frees a slot; a bridge holds ~40). Best effort. @param {{ accessToken: string, appKey: string, fetch?: typeof fetch, base?: string }} c */
export async function unpairRemote({ accessToken, appKey, fetch: f = fetch, base = HUE_CLOUD }) {
  const r = await f(`${base}/bridge/0/config/whitelist/${encodeURIComponent(appKey)}`, { method: "DELETE", headers: { authorization: `Bearer ${accessToken}` } });
  return r.ok;
}
