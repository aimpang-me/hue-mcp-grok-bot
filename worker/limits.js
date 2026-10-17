// Every tunable number in one place, plus the two helpers that apply them: env overrides and per-client-IP windows.
import { hit } from "./util.js";
import { json } from "./http.js";

/** One minute and one day in ms. */
export const MIN = 60_000, DAY = 24 * 3600_000;

export const LIMITS = {
  globalDailyCalls: 45000, // all users of the shared Hue developer app together (Hue allows 50,000 per day)
  newLoginsUntil: 0.9, // new sign-ins pause once this share of the global budget is used
  quotaBlock: 10, // calls a bridge reserves from the global budget at a time, so the global counter is not hit on every call
  bridgeDailyCalls: 3000, // per bridge (one household) per day, whatever the number of sign-ins on it
  bridgeLoginsPerDay: 10,
  ratePerMin: 60, // per sign-in (grant)
  lightCapPerMin: 20, // state changes per resource
  authorizePerMinPerIp: 10, registerPerMinPerIp: 20, tokenPerMinPerIp: 60, revokePerMinPerIp: 30,
  loginTtlMs: 600_000, // consent page and Hue sign-in round trip
  codeTtlMs: 600_000, leaseTtlMs: 600_000,
  accessTtlMs: 3600_000, refreshTtlMs: 30 * DAY, grantMaxMs: 180 * DAY,
  maxStateLen: 512, // the client's `state` travels in the login cookie (as do the redirect URI, at most 300, and the PKCE challenge, at most 128)
};

/** A positive number from env, else the default (so a typo or a negative value never disables a limit).
 * @param {Record<string, unknown>} env @param {string} name @param {number} dflt */
export function envNum(env, name, dflt) { const v = Number(env[name]); return Number.isFinite(v) && v > 0 ? v : dflt; }

/** Count one request against this client IP's per-minute window. Returns seconds to wait when over the limit, else 0.
 * The windows live in the isolate's memory: they slow bursts down, while the daily caps in Durable Objects are the hard bounds.
 * @param {Pick<import("./index.js").Ctx, "req" | "windows" | "now">} c @param {string} name @param {number} limit */
export function overLimit({ req, windows, now }, name, limit) {
  const w = hit(windows, `${name}:${req.headers.get("cf-connecting-ip") ?? "unknown"}`, limit, MIN, now());
  return w.ok ? 0 : w.retryAfter;
}

/** overLimit for the JSON endpoints: a 429 response, or null when the request may go on.
 * @param {import("./index.js").Ctx} c @param {string} name @param {string} envName @param {number} dflt @returns {Response|null} */
export function limited(c, name, envName, dflt) {
  const retry = overLimit(c, name, envNum(c.env, envName, dflt));
  return retry ? json({ error: "rate_limited" }, 429, { "retry-after": String(retry) }) : null;
}
