// Hue sign-in callback: checks the login cookie, creates a NEW user, links the bridge, then returns an MCP auth code to the client.
import { text, redirectBack } from "../http.js";
import { readLogin, clearLogin } from "../session.js";
import { exchangeCode } from "../../server/transport-remote.js";
import { newUserId, mintHandle } from "../util.js";

const CLEAR = { "set-cookie": clearLogin };

/** @param {import("../index.js").Ctx} c */
export async function callback({ req, env, url, origin, base, devBase, fetchImpl, now, callDO }) {
  const code = url.searchParams.get("code") ?? "";
  const s = await readLogin(env.SIGNING_SECRET, req.headers.get("cookie"), url.searchParams.get("state") ?? "", now());
  if (!s || (!code && !url.searchParams.has("error"))) return text("bad or expired login session", 400);
  /** @param {Record<string, string>} params */
  const back = (params) => redirectBack(s.ruri, s.state, params, [clearLogin]);
  if (!code) return back({ error: "access_denied", error_description: "Hue sign-in was cancelled or denied" }); // Hue sent the user back with an error
  let hue;
  try { hue = await exchangeCode({ clientId: env.HUE_CLIENT_ID, clientSecret: env.HUE_CLIENT_SECRET, fetch: fetchImpl, base, now }, code, devBase ? `${origin}/oauth/callback` : undefined); }
  catch { return back({ error: "access_denied", error_description: "Hue sign-in could not be completed" }); }
  const uid = newUserId(), handle = await mintHandle(env.SIGNING_SECRET, uid);
  const r = await callDO(uid, { op: "connect", uid, handle, hue, code: { cid: s.cid, ruri: s.ruri, ruriSent: s.ruriSent, chal: s.chal, resource: s.resource } });
  if ("error" in r && r.error === "too_many_logins") return text("Too many sign-ins for this bridge today. Please try again tomorrow.", 429, "text/plain", CLEAR);
  if (!r.code) return text("Signed in to Hue, but we could not link your bridge. Make sure your bridge is online and has remote access, then try again.", 502, "text/plain", CLEAR);
  return back({ code: r.code });
}
