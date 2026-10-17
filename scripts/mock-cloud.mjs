// @ts-nocheck
// Local stand-in for api.meethue.com, for `wrangler dev` end-to-end proof. Test use only; fake data, no secrets.
// Multi-user: GET /__login?user=alice sets who "signs in" next; authorize then returns CODE-alice. Each user has own tokens, bridge key, room, lights.
import http from "node:http";
const PORT = Number(process.env.PORT ?? 8799);
let nextUser = "alice"; const valid = new Map(), linked = new Set();
http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
    const send = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    console.log(req.method, u.pathname); // mock only; contains no user data
    if (u.pathname === "/__login") { nextUser = u.searchParams.get("user"); return send(200, {}); }
    if (u.pathname === "/v2/oauth2/authorize") { const r = new URL(u.searchParams.get("redirect_uri")); r.searchParams.set("code", `CODE-${nextUser}`); r.searchParams.set("state", u.searchParams.get("state")); res.writeHead(302, { location: r.href }); return res.end(); }
    if (u.pathname === "/v2/oauth2/token") {
      const p = new URLSearchParams(body); const x = (p.get("code") ?? "CODE-" + (p.get("refresh_token") ?? "").split("-")[1]).replace("CODE-", "");
      valid.set(`ACC-${x}`, x); return send(200, { access_token: `ACC-${x}`, refresh_token: `REF-${x}-0`, access_token_expires_in: 604800 });
    }
    const user = valid.get((req.headers.authorization ?? "").replace("Bearer ", ""));
    if (!user) return send(401, {});
    if (u.pathname.startsWith("/bridge/0/config/whitelist/") && req.method === "DELETE") { console.log("UNPAIR", user); return send(200, [{ success: "deleted" }]); }
    if (u.pathname === "/bridge/0/config" && req.method === "GET") return send(200, { bridgeid: `BR-${user}` });
    if (u.pathname === "/bridge/0/config") { linked.add(user); return send(200, [{ success: { "/config/linkbutton": true } }]); }
    if (u.pathname === "/bridge") return linked.has(user) ? send(200, [{ success: { username: `KEY-${user}` } }]) : send(200, [{ error: { type: 101 } }]);
    if (u.pathname.startsWith("/route/clip/v2")) {
      if (req.headers["hue-application-key"] !== `KEY-${user}`) return send(403, {});
      const t = u.pathname.split("/").pop();
      if (req.method === "PUT") { console.log("PUT", u.pathname, "as", user, body); return send(200, { errors: [], data: [{}] }); }
      const room = { id: `room-${user}`, metadata: { name: "Kitchen" }, services: [{ rtype: "grouped_light", rid: `grouplight-${user}` }] };
      return send(200, { errors: [], data: t === "room" ? [room] : t === "grouped_light" ? [{ id: `grouplight-${user}`, on: { on: true }, dimming: { brightness: 80 } }] : [] });
    }
    send(404, {});
  });
}).listen(PORT, "127.0.0.1", () => console.log("mock cloud on", PORT));
