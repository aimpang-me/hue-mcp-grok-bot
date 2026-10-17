// RFC 7009 revocation = user-facing "disconnect": wipes Hue tokens + bridge key for the sign-in that owns this token. Always 200.
import { LIMITS, limited } from "../limits.js";
import { json, readBody } from "../http.js";
import { verifiedUid } from "../util.js";

/** @param {import("../index.js").Ctx} c */
export async function revoke(c) {
  const lim = limited(c, "revoke", "REVOKE_PER_MIN", LIMITS.revokePerMinPerIp);
  if (lim) return lim;
  const { req, env, callDO } = c;
  const token = new URLSearchParams((await readBody(req)) ?? "").get("token") ?? "", uid = await verifiedUid(env.SIGNING_SECRET, token);
  if (uid) await callDO(uid, { op: "disconnect", token });
  return json({});
}
