// Authorization endpoint. GET shows the consent page with the required notices; the POST from that page approves and sends the
// browser to Hue's own sign-in. Until the user approves, nothing is redirected to the client, even to a registered redirect URI.
import { text, redirect, readBody, HTML_SECURITY } from "../http.js";
import { readClient, okRedirect } from "../clients.js";
import { consentPage, redirectLabel } from "../consent.js";
import { canonicalResource, audience, sha256Hex } from "../util.js";
import { newConsent, checkConsent, consentFields, clearConsent, newLogin } from "../session.js";
import { LIMITS, envNum, overLimit } from "../limits.js";

/** Checks shared by both steps: the client and redirect URI, or the error page to show.
 * @param {import("../index.js").Ctx} c @param {URLSearchParams} q @returns {Promise<{ error: Response } | { error?: undefined, client: { n: string, r: string[] }, ruri: string }>} */
async function check(c, q) {
  const client = await readClient(c.env.SIGNING_SECRET, q.get("client_id") ?? "");
  const ruri = q.get("redirect_uri") ?? (client?.r.length === 1 ? client.r[0] : "");
  if (!client || !okRedirect(ruri) || !client.r.includes(ruri)) return { error: text("Unknown client or redirect_uri", 400) };
  /** @param {string} e */
  const fail = (e) => ({ error: text(`This sign-in request is invalid (${e}). Go back to the app and start the connection again.`, 400) });
  if (q.get("response_type") !== "code") return fail("unsupported_response_type");
  if (!q.get("code_challenge") || q.get("code_challenge_method") !== "S256" || (q.get("code_challenge") ?? "").length > 128) return fail("invalid_request"); // RFC 7636: at most 128 characters
  if ((q.get("state") ?? "").length > LIMITS.maxStateLen) return fail("invalid_request");
  const asked = q.get("resource");
  if (asked && !canonicalResource(c.origin, asked)) return fail("invalid_target");
  if (c.env.SIGNUPS === "closed") return { error: text("This lights connector is not accepting new connections right now.", 503) };
  return { client, ruri };
}

/** Per-client-IP window, then the shared capacity check. Null when the request may go on. @param {import("../index.js").Ctx} c @param {string} name @param {number} limit */
async function admit(c, name, limit) {
  const retry = overLimit(c, name, limit);
  if (retry) return text("Too many sign-in attempts from your network. Please wait a minute.", 429, "text/plain", { "retry-after": String(retry) });
  if (!(await c.hasCapacity())) return text("This free lights connector is at capacity for today (shared Hue quota). Please try again tomorrow, or self-host your own copy: see the README.", 503);
  return null;
}

/** GET: the consent page. @param {import("../index.js").Ctx} c */
export async function showConsent(c) {
  const q = c.url.searchParams, v = await check(c, q);
  if (v.error) return v.error;
  const busy = await admit(c, "authz-view", envNum(c.env, "AUTHORIZE_PER_MIN", LIMITS.authorizePerMinPerIp) * 3); // viewing is cheaper than approving
  if (busy) return busy;
  const { cookie, token } = await newConsent(c.env.SIGNING_SECRET, q, c.now(), c.origin);
  const page = consentPage(v.client.n, redirectLabel(v.ruri), [...consentFields(q), ["consent", token]]);
  return text(page, 200, "text/html; charset=utf-8", { ...HTML_SECURITY, "set-cookie": cookie });
}

/** POST from the consent page: approve, remember the request in the login cookie, go to Hue sign-in. @param {import("../index.js").Ctx} c */
export async function approve(c) {
  const body = await readBody(c.req);
  if (body === null) return text("request too large", 413);
  const q = new URLSearchParams(body), v = await check(c, q);
  if (v.error) return v.error;
  const busy = await admit(c, "authz", envNum(c.env, "AUTHORIZE_PER_MIN", LIMITS.authorizePerMinPerIp));
  if (busy) return busy;
  if (!(await checkConsent(c.env.SIGNING_SECRET, c.req.headers.get("cookie"), q.get("consent") ?? "", q, c.now()))) {
    return text("This approval is invalid or expired. Go back to the app and start the connection again.", 403);
  }
  const login = await newLogin(c.env.SIGNING_SECRET, {
    cid: await sha256Hex(q.get("client_id") ?? ""), ruri: v.ruri, ruriSent: q.has("redirect_uri"),
    chal: q.get("code_challenge") ?? "", state: q.get("state") ?? undefined, resource: audience(c.origin),
  }, c.now(), c.origin);
  const { env, base, origin, devBase } = c;
  const dest = `${base}/v2/oauth2/authorize?client_id=${encodeURIComponent(env.HUE_CLIENT_ID)}&response_type=code&state=${login.nonce}&appid=${encodeURIComponent(env.HUE_APP_ID)}&deviceid=hue-mcp&devicename=hue-mcp${devBase ? `&redirect_uri=${encodeURIComponent(`${origin}/oauth/callback`)}` : ""}`;
  return redirect(dest, [login.cookie, clearConsent]);
}
