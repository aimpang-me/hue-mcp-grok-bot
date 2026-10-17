// Token endpoint: authorization_code and refresh_token grants. The user's Durable Object does the real work.
import { LIMITS, limited } from "../limits.js";
import { json, oerr, readBody } from "../http.js";
import { readClient } from "../clients.js";
import { canonicalResource, verifiedUid, sha256Hex } from "../util.js";

/** @param {import("../index.js").Ctx} c */
export async function token(c) {
  const lim = limited(c, "token", "TOKEN_PER_MIN", LIMITS.tokenPerMinPerIp);
  if (lim) return lim;
  const { req, env, origin, callDO } = c;
  const f = new URLSearchParams((await readBody(req)) ?? ""), grant = f.get("grant_type"), clientId = f.get("client_id") ?? "";
  if (!(await readClient(env.SIGNING_SECRET, clientId))) return oerr("invalid_client", 401);
  if (grant !== "authorization_code" && grant !== "refresh_token") return oerr("unsupported_grant_type");
  const tok = f.get(grant === "refresh_token" ? "refresh_token" : "code") ?? "", uid = await verifiedUid(env.SIGNING_SECRET, tok);
  if (!uid) return oerr("invalid_grant");
  const asked = f.get("resource"), resource = asked ? canonicalResource(origin, asked) ?? undefined : undefined; // RFC 8707: the audience the client wants
  if (asked && !resource) return oerr("invalid_target");
  const cid = await sha256Hex(clientId); // codes and tokens are bound to the hash of the client id
  const r = grant === "authorization_code"
    ? await callDO(uid, { op: "redeem", code: tok, verifier: f.get("code_verifier") ?? "", cid, ruri: f.get("redirect_uri") ?? "", resource })
    : await callDO(uid, { op: "refresh", token: tok, cid, resource });
  return "error" in r ? oerr(r.error) : json(r);
}
