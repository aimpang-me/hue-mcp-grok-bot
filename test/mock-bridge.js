import http from "node:http";

export const KEY = "k".repeat(8) + "SECRETKEY0123456789abcdefghijklmnop";
export function makeState() {
  return {
    room: [
      { id: "r1", metadata: { name: "Kitchen" }, services: [{ rtype: "grouped_light", rid: "g1" }] },
      { id: "r2", metadata: { name: "Living Room" }, services: [{ rtype: "grouped_light", rid: "g2" }] },
      { id: "r3", metadata: { name: "Bedroom" }, services: [{ rtype: "grouped_light", rid: "g3" }] },
    ],
    grouped_light: [
      { id: "g1", on: { on: true }, dimming: { brightness: 80 } },
      { id: "g2", on: { on: false }, dimming: { brightness: 10 } },
      { id: "g3", on: { on: false }, dimming: { brightness: 10 } },
    ],
    light: [
      { id: "l1", metadata: { name: "Kitchen Ceiling" }, on: { on: true }, dimming: { brightness: 80 } },
      { id: "l2", metadata: { name: "Desk Lamp" }, on: { on: false }, dimming: { brightness: 50 }, color_temperature: { mirek: 300 } },
    ],
    scene: [
      { id: "s1", metadata: { name: "Relax" }, group: { rid: "r2" } },
      { id: "s2", metadata: { name: "Relax" }, group: { rid: "r3" } },
      { id: "s3", metadata: { name: "Bright" }, group: { rid: "r1" } },
    ],
  };
}

/** Start a plain-http mock of /clip/v2. Records PUTs. */
export async function startMock(state = makeState()) {
  /** @type {Array<{type: string, id: string, body: any}>} */
  const puts = [];
  const server = http.createServer((req, res) => {
    const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (req.headers["hue-application-key"] !== KEY) return send(403, { errors: [{ description: "unauthorized user" }] });
    const m = /^\/clip\/v2\/resource\/(\w+)(?:\/([\w-]+))?$/.exec(req.url ?? "");
    if (!m) return send(404, { errors: [{ description: `leaked ${KEY} in error` }] });
    const [, type, id] = m;
    if (req.method === "GET") return send(200, { errors: [], data: state[type] ?? [] });
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { puts.push({ type, id, body: JSON.parse(data) }); send(200, { errors: [], data: [{ rid: id, rtype: type }] }); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  return { port, puts, state, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
