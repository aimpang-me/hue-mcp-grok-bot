// Cloudflare Worker: multi-user, free MCP connector for Philips Hue lights. Design and security model: docs/DESIGN.md.
// The Worker is its own OAuth 2.1 authorization server for MCP clients (RFC 9728 + RFC 8414 + RFC 7591 + PKCE) and delegates
// the actual login to Hue's OAuth (one shared Hue developer app). Every user's data lives in their own Durable Object.
// This file only wires the context and the route table; each route lives in worker/routes/*.js.
import { createTtlCache } from "../server/cache.js";
import { HUE_CLOUD } from "../server/transport-remote.js";
import { localBase } from "./util.js";
import { callDO } from "./do-client.js";
import { CORS, SNIFF, text } from "./http.js";
import { MIN } from "./limits.js";
import { protectedResource, authServer } from "./routes/discovery.js";
import { register } from "./routes/register.js";
import { showConsent, approve } from "./routes/authorize.js";
import { callback } from "./routes/callback.js";
import { token } from "./routes/token.js";
import { revoke } from "./routes/revoke.js";
import { mcp } from "./routes/mcp.js";
export { UserDO } from "./user-do.js";

/** Secrets (wrangler secret put) and optional vars; the full list with defaults is in docs/SELF-HOST.md.
 * @typedef {{ HUE_CLIENT_ID: string, HUE_CLIENT_SECRET: string, HUE_APP_ID: string, SIGNING_SECRET: string, USER_DO: import("./do-client.js").Namespace,
 *   SIGNUPS?: string, HUE_CLOUD_BASE?: string, RATE_PER_MIN?: string, LIGHT_CAP_PER_MIN?: string, DAILY_HUE_CALLS?: string, GLOBAL_DAILY_CALLS?: string,
 *   BRIDGE_LOGINS_PER_DAY?: string, AUTHORIZE_PER_MIN?: string, REGISTER_PER_MIN?: string, TOKEN_PER_MIN?: string, REVOKE_PER_MIN?: string }} Env */
/** @typedef {{ req: Request, env: Env, url: URL, origin: string, base: string, devBase: boolean, fetchImpl: typeof fetch, now: () => number,
 *   callDO: import("./do-client.js").CallDO, hasCapacity: () => Promise<boolean>, windows: Map<string, {w: number, n: number}>,
 *   cacheFor: (uid: string) => ReturnType<typeof createTtlCache<any[]>> }} Ctx */

/** path -> method (or "*") -> handler. Anything else is 404. @type {Record<string, Record<string, (c: Ctx) => Promise<Response>|Response>>} */
const ROUTES = {
  "/.well-known/oauth-protected-resource": { "*": protectedResource },
  "/.well-known/oauth-protected-resource/mcp": { "*": protectedResource },
  "/.well-known/oauth-authorization-server": { "*": authServer },
  "/.well-known/oauth-authorization-server/mcp": { "*": authServer },
  "/register": { POST: register },
  "/authorize": { GET: showConsent, POST: approve },
  "/oauth/callback": { "*": callback },
  "/token": { POST: token },
  "/revoke": { POST: revoke },
  "/mcp": { "*": mcp },
};

/** @param {{ fetchImpl?: typeof fetch, base?: string, now?: () => number }} [o] */
export function createWorker({ fetchImpl = (u, i) => fetch(u, i), base: fixedBase, now = Date.now } = {}) {
  // Isolate-wide, PER USER: name->id caches (5 min). Keyed by user id so one user's light ids can never resolve for another.
  /** @type {Map<string, ReturnType<typeof createTtlCache<any[]>>>} */ const caches = new Map();
  /** @param {string} uid */
  const cacheFor = (uid) => {
    let c = caches.get(uid);
    if (!c) { if (caches.size >= 200) caches.delete(/** @type {string} */ (caches.keys().next().value)); c = createTtlCache(); caches.set(uid, c); }
    return c;
  };
  /** Isolate-local per-client-IP windows for the pre-auth endpoints. @type {Map<string, {w: number, n: number}>} */
  const windows = new Map();
  // Whether new sign-ins are welcome, asked of the shared "global" counter at most once a minute per isolate, so loading the
  // consent page many times cannot crowd that one Durable Object.
  let capacity = { ok: true, at: -Infinity };
  return {
    /** @param {Request} req @param {Env} env */
    async fetch(req, env) {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...CORS, ...SNIFF } });
      const url = new URL(req.url), route = Object.hasOwn(ROUTES, url.pathname) ? ROUTES[url.pathname] : undefined, handler = route?.[req.method] ?? route?.["*"];
      if (!handler) return text("not found", 404);
      const base = fixedBase ?? localBase(env.HUE_CLOUD_BASE) ?? HUE_CLOUD;
      /** @type {import("./do-client.js").CallDO} */
      const toDO = (name, payload) => callDO(env.USER_DO, name, payload);
      const hasCapacity = async () => {
        if (now() - capacity.at >= MIN) capacity = { ok: (await toDO("global", { op: "capacity" })).ok, at: now() };
        return capacity.ok;
      };
      return handler({ req, env, url, origin: url.origin, base, devBase: base !== HUE_CLOUD, fetchImpl, now, callDO: toDO, hasCapacity, cacheFor, windows });
    },
  };
}
export default createWorker();
