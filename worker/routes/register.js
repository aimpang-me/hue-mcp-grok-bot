// RFC 7591 dynamic client registration (public clients only). Stores nothing: the client id is a signed blob.
import { LIMITS, limited } from "../limits.js";
import { json, oerr, readBody } from "../http.js";
import { okRedirect, signClient } from "../clients.js";

/** @param {import("../index.js").Ctx} c */
export async function register(c) {
  const lim = limited(c, "register", "REGISTER_PER_MIN", LIMITS.registerPerMinPerIp);
  if (lim) return lim;
  const { req, env } = c;
  /** @type {any} */ let b; try { b = JSON.parse((await readBody(req)) ?? ""); } catch { return oerr("invalid_client_metadata"); }
  const uris = b?.redirect_uris;
  if (!Array.isArray(uris) || !uris.length || uris.length > 5 || !uris.every(okRedirect)) return oerr("invalid_redirect_uri", 400, "redirect_uris must be 1-5 https, loopback http or app-scheme URIs");
  const name = typeof b.client_name === "string" ? b.client_name.slice(0, 80) : "MCP client";
  const client_id = await signClient(env.SIGNING_SECRET, { n: name, r: uris });
  return json({ client_id, client_name: name, redirect_uris: uris, grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }, 201);
}
