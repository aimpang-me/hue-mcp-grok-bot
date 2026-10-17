// Browser-bound login without server-side state. Two short-lived HttpOnly cookies carry the login between its steps, so nothing is
// stored until a Hue sign-in succeeds (and nothing can be filled up by approving the consent page in a loop):
// - hue_consent (Path=/authorize) comes with the consent page. Approving is a POST carrying a token whose MAC covers this cookie and the
//   exact authorize request, so only the browser that was shown the page can approve it, and the page cannot be re-pointed.
// - hue_login (Path=/oauth/callback) is set by the approving POST: a signed copy of the request (client id hash, redirect URI, PKCE
//   challenge, client state, audience) and a random nonce that is also the `state` sent to Hue. The callback accepts only a matching,
//   unexpired cookie, so only the browser that started the login can finish it (no login CSRF or session fixation).
// Replaying an approval needs that browser's cookies and only leads to another Hue sign-in page; Hue codes are single use.
import { rand, hmac, safeEqual, b64url, unb64url } from "./util.js";
import { LIMITS } from "./limits.js";

const CONSENT = "hue_consent", LOGIN = "hue_login", TTL_S = LIMITS.loginTtlMs / 1000;

/** A cookie's value from a Cookie header, or "". @param {string|null} header @param {string} name */
export const cookieOf = (header, name) => new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(header ?? "")?.[1] ?? "";
/** @param {string} name @param {string} value @param {string} path @param {"Strict"|"Lax"} sameSite @param {string} origin */
const cookie = (name, value, path, sameSite, origin) => `${name}=${value}; Path=${path}; HttpOnly; SameSite=${sameSite}; Max-Age=${TTL_S}${origin.startsWith("https:") ? "; Secure" : ""}`;
export const clearConsent = `${CONSENT}=; Path=/authorize; HttpOnly; Max-Age=0`;
export const clearLogin = `${LOGIN}=; Path=/oauth/callback; HttpOnly; Max-Age=0`;

const FIELDS = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "resource"];
/** The request fields consent is bound to, in a fixed order. @param {URLSearchParams} q @returns {[string, string][]} */
export const consentFields = (q) => FIELDS.flatMap((k) => (q.has(k) ? [/** @type {[string, string]} */ ([k, q.get(k) ?? ""])] : []));
/** @param {string} secret @param {string} nonce @param {number} exp @param {string} browser @param {URLSearchParams} q */
const consentMac = (secret, nonce, exp, browser, q) => hmac(secret, `consent:${nonce}.${exp}.${browser}.${JSON.stringify(consentFields(q))}`);

/** Consent for this request: the Set-Cookie value and the token for the form. @param {string} secret @param {URLSearchParams} q @param {number} now @param {string} origin */
export async function newConsent(secret, q, now, origin) {
  const browser = rand(16), nonce = rand(18), exp = now + LIMITS.loginTtlMs;
  return { cookie: cookie(CONSENT, browser, "/authorize", "Strict", origin), token: `${nonce}.${exp}.${await consentMac(secret, nonce, exp, browser, q)}` };
}
/** Is this a valid, unexpired approval from the browser that was shown the page, for exactly this request?
 * @param {string} secret @param {string|null} cookieHeader @param {string} token @param {URLSearchParams} q @param {number} now */
export async function checkConsent(secret, cookieHeader, token, q, now) {
  const [nonce, exp, mac] = token.split("."), browser = cookieOf(cookieHeader, CONSENT);
  if (!secret || !nonce || !mac || !browser || !(Number(exp) > now)) return false;
  return safeEqual(mac, await consentMac(secret, nonce, Number(exp), browser, q));
}

/** @typedef {{ cid: string, ruri: string, ruriSent: boolean, chal: string, state?: string, resource: string }} LoginRequest cid is sha256(client_id) */
/** @typedef {LoginRequest & { n: string, exp: number }} Login */

/** Start a login: the nonce to send to Hue as `state` and the Set-Cookie value that remembers the request.
 * @param {string} secret @param {LoginRequest} req @param {number} now @param {string} origin */
export async function newLogin(secret, req, now, origin) {
  const n = rand(18), body = b64url(new TextEncoder().encode(JSON.stringify({ ...req, n, exp: now + LIMITS.loginTtlMs })));
  return { nonce: n, cookie: cookie(LOGIN, `${body}.${await hmac(secret, `login:${body}`)}`, "/oauth/callback", "Lax", origin) };
}
/** The login this browser started, if its cookie is genuine, unexpired and matches the `state` Hue sent back; else null.
 * @param {string} secret @param {string|null} cookieHeader @param {string} nonce @param {number} now @returns {Promise<Login|null>} */
export async function readLogin(secret, cookieHeader, nonce, now) {
  const [body, mac] = cookieOf(cookieHeader, LOGIN).split(".");
  if (!secret || !body || !mac || !nonce || !safeEqual(mac, await hmac(secret, `login:${body}`))) return null;
  /** @type {Login} */ const s = JSON.parse(new TextDecoder().decode(unb64url(body)));
  return s.exp > now && safeEqual(s.n, nonce) ? s : null;
}
