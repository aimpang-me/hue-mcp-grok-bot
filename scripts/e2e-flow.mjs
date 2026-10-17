// @ts-nocheck
// E2E driver (used by e2e-wrangler.sh): MCP client side of the OAuth flow against a running worker + mock cloud. Exits 1 on any failure.
const W = process.env.WORKER, M = process.env.MOCK;
let bad = 0; const chk = (n, ok, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"} ${n}${ok ? "" : " " + extra}`); if (!ok) bad = 1; };
const b64 = (b) => Buffer.from(b).toString("base64url");
const nofollow = (u, i = {}) => fetch(u, { redirect: "manual", ...i });
async function login(user) {
  await fetch(`${M}/__login?user=${user}`);
  const reg = await (await fetch(`${W}/register`, { method: "POST", body: JSON.stringify({ redirect_uris: ["http://localhost:8787/callback"], client_name: "e2e" }) })).json();
  const verifier = b64(crypto.getRandomValues(new Uint8Array(32))), challenge = b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://localhost:8787/callback", code_challenge: challenge, code_challenge_method: "S256", state: "s1" });
  const page = await fetch(`${W}/authorize?${q}`), consent = await page.text(), consentCookie = page.headers.get("set-cookie").split(";")[0];
  chk(`${user}: consent shows notices`, /Not a Signify product/.test(consent) && /seizures/.test(consent));
  const fields = new URLSearchParams(); for (const m of consent.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)) fields.set(m[1], m[2].replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)));
  const approve = (cookie) => nofollow(`${W}/authorize`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: fields });
  chk(`${user}: GET confirm=1 does not approve`, (await nofollow(`${W}/authorize?${q}&confirm=1`)).status === 200);
  chk(`${user}: POST without the consent cookie is refused`, (await approve("")).status === 403);
  let r = await approve(consentCookie); // sets the hue_login cookie that binds the login to this browser
  chk(`${user}: callback without the cookie is refused`, (await nofollow((await nofollow(r.headers.get("location"))).headers.get("location"))).status === 400);
  chk(`${user}: approving clears the consent cookie`, /hue_consent=;[^,]*Max-Age=0/.test(r.headers.get("set-cookie") ?? ""));
  const page2 = await fetch(`${W}/authorize?${q}`), c2 = (await page2.text()), consentCookie2 = page2.headers.get("set-cookie").split(";")[0];
  for (const m of c2.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)) fields.set(m[1], m[2].replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)));
  r = await approve(consentCookie2); const cookie2 = r.headers.get("set-cookie").split(";")[0];
  r = await nofollow(r.headers.get("location")); // Hue authorize (mock) -> worker callback
  r = await nofollow(r.headers.get("location"), { headers: { cookie: cookie2 } }); const back = new URL(r.headers.get("location"));
  chk(`${user}: callback redirects to client with code+state`, back.origin === "http://localhost:8787" && back.searchParams.get("state") === "s1" && !!back.searchParams.get("code"));
  const t = await (await fetch(`${W}/token`, { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", code: back.searchParams.get("code"), client_id: reg.client_id, redirect_uri: "http://localhost:8787/callback", code_verifier: verifier }) })).json();
  return { ...t, code: back.searchParams.get("code"), cid: reg.client_id, verifier };
}
const call = async (tok, name, args = {}) => (await (await fetch(`${W}/mcp`, { method: "POST", headers: { authorization: `Bearer ${tok}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) })).text());
const u401 = await fetch(`${W}/mcp`, { method: "POST", body: "{}" });
chk("mcp without token: 401 + resource_metadata", u401.status === 401 && /resource_metadata=/.test(u401.headers.get("www-authenticate") ?? ""));
const prm = await (await fetch(`${W}/.well-known/oauth-protected-resource`)).json();
chk("PRM names an authorization server", prm.authorization_servers?.length === 1);
const a = await login("alice"), b = await login("bob");
chk("alice/bob got distinct tokens", a.access_token && b.access_token && a.access_token !== b.access_token);
const ra = await call(a.access_token, "list_rooms"), rb = await call(b.access_token, "list_rooms");
chk("alice sees her room only", ra.includes("Kitchen") && !ra.includes("bob") && rb.includes("Kitchen") && !rb.includes("alice"));
await call(a.access_token, "dim_room", { room: "kitchen", brightness: 30 }); await call(b.access_token, "dim_room", { room: "kitchen", brightness: 60 });
chk("secrets/keys not in tool output", !/KEY-|ACC-|REF-/.test(ra + rb));
chk("removed setup routes 404", (await fetch(`${W}/admin/pair?admin=x`)).status === 404 && (await fetch(`${W}/oauth/start?admin=x`)).status === 404);
chk("cross-wired token 401", (await fetch(`${W}/mcp`, { method: "POST", headers: { authorization: `Bearer ${a.access_token.split(".")[0]}.${b.access_token.slice(33)}` }, body: "{}" })).status === 401);
chk("forged well-shaped id: 401", (await fetch(`${W}/mcp`, { method: "POST", headers: { authorization: `Bearer ${"ab".repeat(16)}.AAAA.xyz` }, body: "{}" })).status === 401);
const rv = await fetch(`${W}/revoke`, { method: "POST", body: new URLSearchParams({ token: a.refresh_token }) });
chk("disconnect: /revoke 200, token dead, other user alive", rv.status === 200 && (await fetch(`${W}/mcp`, { method: "POST", headers: { authorization: `Bearer ${a.access_token}` }, body: "{}" })).status === 401 && (await call(b.access_token, "list_rooms")).includes("Kitchen"));
const reuse = await (await fetch(`${W}/token`, { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", code: b.code, client_id: b.cid, redirect_uri: "http://localhost:8787/callback", code_verifier: b.verifier }) })).json();
chk("code reuse: invalid_grant and bob's token revoked", reuse.error === "invalid_grant" && (await fetch(`${W}/mcp`, { method: "POST", headers: { authorization: `Bearer ${b.access_token}` }, body: "{}" })).status === 401);
process.exit(bad);
