// Shared test harness: fake Hue cloud, in-memory Durable Objects (with alarms), and a full OAuth login driver. HUE_KV is a
// write-recording KV namespace the Worker must never use: tests assert it stays empty, which proves the login stores nothing.
import assert from "node:assert/strict";
import { createWorker } from "../../worker/index.js";
import { UserDO } from "../../worker/user-do.js";
import { b64url } from "../../worker/util.js";

export const CS = "CLIENTSECRET-xyz", SIGN = "signing-secret-abc";
export const ORIGIN = "https://w.example", RURI = "https://client.example/cb";

let codeSeq = 0;
/** Fake Hue cloud with per-user data: code CODE-x (or CODE-x~n, codes are single use) -> tokens ACC-x/REF-x-n, bridge key KEY-x (KEY-x~n for the n-th extra pairing),
 * room "Kitchen" id room-x, lights light-x-1/2. */
export function fakeCloud() {
  const calls = [], refreshed = [], pairs = [], deleted = [], usedCodes = new Set(); const valid = new Map(); // access -> user
  let bridgeOf = (/** @type {string} */ u) => `BR-${u}`, configNamesBridge = true; // false: GET /bridge/0/config omits bridgeid (CLIPv2 still has it)
  let delay = 0, pairDelay = 0, echo = false, failKey = ""; // failKey: CLIPv2 answers 503 to this app key // echo: CLIPv2 errors repeat the credentials they were sent (to test scrubbing)
  const f = async (url, init = {}) => {
    const u = new URL(url), hdr = init.headers ?? {}; calls.push({ path: u.pathname, method: init.method ?? "GET", hdr, body: init.body });
    if (u.pathname === "/v2/oauth2/token") {
      const g = init.body.get("grant_type");
      if (g === "authorization_code") {
        const c = init.body.get("code"); if (usedCodes.has(c)) return new Response("{}", { status: 400 }); // Hue codes are single use
        usedCodes.add(c); const x = c.replace("CODE-", "").split("~")[0]; // CODE-<user>[~<n>]
        valid.set(`ACC-${x}`, x); return Response.json({ access_token: `ACC-${x}`, refresh_token: `REF-${x}-0`, access_token_expires_in: 604800 });
      }
      const m = /^REF-(.+)-(\d+)$/.exec(init.body.get("refresh_token")); refreshed.push(m[0]);
      if (delay) await new Promise((r) => setTimeout(r, delay));
      if (!m || Number(m[2]) !== refreshed.filter((r) => r.startsWith(`REF-${m[1]}-`)).length - 1) return new Response("{}", { status: 400 }); // rotating: a stale refresh token is dead
      const n = Number(m[2]) + 1; valid.set(`ACC-${m[1]}-${n}`, m[1]);
      return Response.json({ access_token: `ACC-${m[1]}-${n}`, refresh_token: `REF-${m[1]}-${n}`, access_token_expires_in: 604800 });
    }
    const user = valid.get(hdr.authorization?.replace("Bearer ", ""));
    if (!user) return new Response("{}", { status: 401 });
    if (u.pathname === "/bridge/0/config") return init.method === "PUT" ? Response.json([{ success: {} }]) : Response.json(configNamesBridge ? { bridgeid: bridgeOf(user) } : {});
    if (u.pathname.startsWith("/bridge/0/config/whitelist/") && init.method === "DELETE") { deleted.push(u.pathname.split("/").pop()); return Response.json([{ success: "deleted" }]); }
    if (u.pathname === "/bridge") {
      const n = pairs.filter((p) => p === user).length; pairs.push(user);
      if (pairDelay) await new Promise((r) => setTimeout(r, pairDelay));
      return Response.json([{ success: { username: n ? `KEY-${user}~${n}` : `KEY-${user}` } }]);
    }
    if (u.pathname.startsWith("/route/clip/v2")) {
      const key = hdr["hue-application-key"] ?? "";
      if (failKey && key === failKey) return new Response("{}", { status: 503 });
      if (echo) return Response.json({ errors: [{ description: `bad request with key ${key} and ${hdr.authorization}` }] }, { status: 500 });
      if (key !== `KEY-${user}` && !key.startsWith(`KEY-${user}~`)) return new Response("{}", { status: 403 });
      if (init.method === "PUT") return Response.json({ errors: [], data: [{}] });
      const t = u.pathname.split("/").pop();
      const data = t === "bridge" ? [{ id: `b-${user}`, bridge_id: bridgeOf(user) }] : t === "room" ? [{ id: `room-${user}`, metadata: { name: "Kitchen" }, services: [{ rtype: "grouped_light", rid: `grouplight-${user}` }] }]
        : t === "light" ? [1, 2].map((n) => ({ id: `light-${user}-${n}`, metadata: { name: `Lamp ${n}` } })) : [];
      return Response.json({ errors: [], data });
    }
    return new Response("nope", { status: 404 });
  };
  return { f, calls, refreshed, pairs, deleted, setDelay: (d) => (delay = d), setPairDelay: (d) => (pairDelay = d), setBridge: (fn) => (bridgeOf = fn), setConfigNamesBridge: (v) => (configNamesBridge = v), setEcho: (v) => (echo = v), setFailKey: (k) => (failKey = k) };
}

export function harness(extraEnv = {}, cloud = fakeCloud()) {
  let t = 1_800_000_000_000; const kv = new Map(), kvExp = new Map(), kvPuts = [], dos = new Map(), stores = new Map(), alarms = new Map();
  const now = () => t;
  const makeStorage = (id, m) => ({
    get: async (k) => (Array.isArray(k) ? new Map(k.filter((x) => m.has(x)).map((x) => [x, structuredClone(m.get(x))])) : structuredClone(m.get(k))),
    put: async (k, v) => { for (const [x, y] of typeof k === "string" ? [[k, v]] : Object.entries(k)) m.set(x, structuredClone(y)); },
    delete: async (k) => (Array.isArray(k) ? k.filter((x) => m.delete(x)).length : m.delete(k)),
    list: async ({ prefix = "" } = {}) => new Map([...m].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k, structuredClone(v)])),
    getAlarm: async () => alarms.get(id) ?? null, setAlarm: async (at) => void alarms.set(id, at), deleteAlarm: async () => void alarms.delete(id),
    deleteAll: async () => { m.clear(); alarms.delete(id); },
  });
  const ns = {
    idFromName: (n) => n,
    get: (id) => ({ fetch: (req) => {
      if (!dos.has(id)) { const m = new Map(); stores.set(id, m); dos.set(id, new UserDO({ storage: makeStorage(id, m) }, env, { fetchImpl: cloud.f, now })); }
      return dos.get(id).fetch(req);
    } }),
  };
  const live = (k) => kv.has(k) && !(kvExp.get(k) <= t);
  const env = { HUE_CLIENT_ID: "cid", HUE_CLIENT_SECRET: CS, HUE_APP_ID: "aid", SIGNING_SECRET: SIGN, USER_DO: ns, ...extraEnv,
    HUE_KV: { get: async (k) => (live(k) ? kv.get(k) : null), put: async (k, v, o) => { kvPuts.push(k); kv.set(k, v); if (o?.expirationTtl) kvExp.set(k, t + o.expirationTtl * 1000); }, delete: async (k) => void kv.delete(k) } };
  const w = createWorker({ fetchImpl: cloud.f, now });
  const req = (path, init) => w.fetch(new Request(ORIGIN + path, init), env);
  /** Fire every Durable Object alarm that is due, like the platform would. */
  const runAlarms = async () => { for (const [id, at] of [...alarms]) if (at <= t) { alarms.delete(id); await dos.get(id)?.alarm(); } };
  return { w, env, req, cloud, stores, kv, kvPuts, alarms, runAlarms, advance: (ms) => (t += ms), now };
}
export const pkce = async () => { const verifier = b64url(crypto.getRandomValues(new Uint8Array(32))); return { verifier, challenge: b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)))) }; };
export async function register(h, uris = [RURI]) {
  const r = await h.req("/register", { method: "POST", body: JSON.stringify({ redirect_uris: uris, client_name: "Test Client" }) });
  return { r, ...(await r.json()) };
}
/** What a browser does on the consent page: GET it, keep its cookie, POST the form it shows. `tweak` edits the form fields before the POST. */
export async function approve(h, q, { headers = {}, tweak } = {}) {
  const page = await h.req(`/authorize?${q}`, { headers });
  const html = await page.text(), cookie = page.headers.get("set-cookie")?.split(";")[0];
  const fields = new URLSearchParams();
  for (const m of html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)) fields.set(m[1], m[2].replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)));
  tweak?.(fields);
  const r = await h.req("/authorize", { method: "POST", headers: { ...headers, ...(cookie ? { cookie } : {}), "content-type": "application/x-www-form-urlencoded" }, body: fields });
  return { page, html, cookie, fields, r };
}
/** Whole flow for user `x`: register -> authorize (consent) -> Hue login (simulated) -> callback -> token. */
export async function login(h, x, { client } = {}) {
  const c = client ?? (await register(h)).client_id, { verifier, challenge } = await pkce();
  const q = new URLSearchParams({ response_type: "code", client_id: c, redirect_uri: RURI, code_challenge: challenge, code_challenge_method: "S256", state: "cs" });
  const { page: consent, r: hueRedirect } = await approve(h, q);
  assert.equal(consent.status, 200);
  assert.equal(hueRedirect.status, 302);
  const hueUrl = new URL(hueRedirect.headers.get("location"));
  assert.equal(hueUrl.origin + hueUrl.pathname, "https://api.meethue.com/v2/oauth2/authorize");
  const cookie = hueRedirect.headers.get("set-cookie")?.split(";")[0]; // the browser keeps it and sends it back to the callback
  const cb = await h.req(`/oauth/callback?code=CODE-${x}~${++codeSeq}&state=${hueUrl.searchParams.get("state")}`, cookie ? { headers: { cookie } } : {});
  assert.equal(cb.status, 302);
  const back = new URL(cb.headers.get("location"));
  assert.equal(back.searchParams.get("state"), "cs");
  const code = back.searchParams.get("code");
  const tok = await h.req("/token", { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: c, redirect_uri: RURI, code_verifier: verifier }) });
  return { c, code, verifier, tok, cookie, ...(tok.status === 200 ? await tok.json() : {}) };
}
export const rpc = (h, token, name, args = {}) => h.req("/mcp", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
export const out = async (r) => { const j = await r.json(); return j.result ? { err: !!j.result.isError, text: j.result.content[0].text } : j; };

