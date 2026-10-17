import { isRecord, RESOURCE_PATH, METHODS } from "./guards.js";
import { redact } from "./redact.js";
import { fuzzyFind } from "./match.js";
import { createTtlCache } from "./cache.js";
import { toXY, clampMirek, kelvinToMirek } from "./color.js";

const lightProps = {
  on: { type: "boolean", description: "Turn on/off" },
  brightness: { type: "number", minimum: 0, maximum: 100, description: "Percent 0-100 (0 = off)" },
  color: { type: "string", description: "Colour name (red, warm... see list) or hex like #ff8800" },
  mirek: { type: "number", minimum: 153, maximum: 500, description: "Colour temperature in mireds (153 cool .. 500 warm)" },
  kelvin: { type: "number", minimum: 2000, maximum: 6500, description: "Colour temperature in kelvin (alternative to mirek)" },
};

/** @type {Array<{name: string, description: string, inputSchema: object}>} */
export const toolList = [
  { name: "list_rooms", description: "List Hue rooms with on/off, brightness and the grouped_light id.", inputSchema: { type: "object", properties: {} } },
  { name: "list_lights", description: "List individual lights with state (on, brightness, colour/temperature).", inputSchema: { type: "object", properties: {} } },
  { name: "set_light", description: "Set one light by (fuzzy) name or id: on/off, brightness 0-100, colour, or colour temperature.", inputSchema: { type: "object", properties: { light: { type: "string", description: "Light name or id" }, ...lightProps }, required: ["light"] } },
  { name: "set_room", description: "Set all lights in a room (grouped_light) by fuzzy room name.", inputSchema: { type: "object", properties: { room: { type: "string" }, ...lightProps }, required: ["room"] } },
  { name: "list_scenes", description: "List scenes with the room each belongs to.", inputSchema: { type: "object", properties: { room: { type: "string", description: "Optional room filter" } } } },
  { name: "activate_scene", description: "Activate a scene by name (optionally within a room) or id.", inputSchema: { type: "object", properties: { scene: { type: "string" }, room: { type: "string" } }, required: ["scene"] } },
  { name: "hue_api", description: "Raw CLIPv2 call for anything the other tools don't cover (zones, motion/temperature sensors, effects, creating or editing scenes). path like 'resource/zone' or 'resource/light/<id>'. PUT, POST and DELETE change the user's bridge, and DELETE permanently removes things such as scenes, automations or devices: confirm with the user before using them. Entertainment streaming is not supported.", inputSchema: { type: "object", properties: { method: { type: "string", enum: ["GET", "PUT", "POST", "DELETE"] }, path: { type: "string" }, body: { type: "object" } }, required: ["method", "path"] } },
  { name: "dim_room", description: "Name-based shortcut, e.g. 'dim the kitchen': room name + brightness (default 20%).", inputSchema: { type: "object", properties: { room: { type: "string" }, brightness: { type: "number", minimum: 0, maximum: 100 } }, required: ["room"] } },
];

/** @param {unknown} v @param {string} name @param {number} min @param {number} max */
function num(v, name, min, max) {
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) throw new Error(`${name} must be a number between ${min} and ${max}`);
  return v;
}

/** Build a CLIPv2 state body from tool args. @param {Record<string, unknown>} a */
export function buildState(a) {
  /** @type {Record<string, any>} */
  const body = {};
  if (a.color !== undefined && (a.mirek !== undefined || a.kelvin !== undefined)) throw new Error("Give either color or color temperature, not both");
  if (a.brightness !== undefined) {
    const b = num(a.brightness, "brightness", 0, 100);
    if (b === 0) body.on = { on: false };
    else { body.dimming = { brightness: b }; if (a.on === undefined) body.on = { on: true }; }
  }
  if (a.on !== undefined) {
    if (typeof a.on !== "boolean") throw new Error("on must be boolean");
    if (!(body.on && body.on.on === false)) body.on = { on: a.on };
  }
  if (a.color !== undefined) {
    if (typeof a.color !== "string") throw new Error("color must be a string");
    body.color = { xy: toXY(a.color) };
    if (!body.on && a.on === undefined) body.on = { on: true };
  }
  if (a.kelvin !== undefined) body.color_temperature = { mirek: clampMirek(kelvinToMirek(num(a.kelvin, "kelvin", 2000, 6500))) };
  if (a.mirek !== undefined) body.color_temperature = { mirek: clampMirek(num(a.mirek, "mirek", 153, 500)) };
  if (!Object.keys(body).length) throw new Error("Nothing to set: give on, brightness, color, mirek or kelvin");
  return body;
}

/** @param {any} l */
const lightView = (l) => ({
  id: l.id, name: l.metadata?.name, on: l.on?.on, brightness: l.dimming?.brightness,
  mirek: l.color_temperature?.mirek, xy: l.color?.xy, reachable: l.status ? l.status === "connected" : undefined,
});

/** A room's id, name and the id of its grouped_light service (which carries the room's on/brightness). @param {any} r */
const roomView = (r) => ({ id: r.id, name: r.metadata?.name ?? "", groupedLightId: /** @type {string|undefined} */ ((r.services ?? []).find((/** @type {any} */ s) => s.rtype === "grouped_light")?.rid) });

/**
 * @param {ReturnType<typeof import("./hue.js").createHueClient>} hue
 * @param {{ key?: string, cache?: ReturnType<typeof createTtlCache<any[]>> }} [opts] cache: name->id index (default 5 min TTL, per createTools; the Worker passes an isolate-wide one)
 */
export function createTools(hue, { key, cache = /** @type {ReturnType<typeof createTtlCache<any[]>>} */ (createTtlCache()) } = {}) {
  /** Cached name->id index for `type`; `fresh` skips the cache. Only ids/names are cached, never live state.
   * @param {string} type @param {boolean} [fresh] @returns {Promise<{items: any[], cached: boolean}>} */
  async function index(type, fresh = false) {
    const hit = fresh ? undefined : cache.get(type);
    if (hit) return { items: hit, cached: true };
    const items = (await hue.list(type)).map(type === "room" ? roomView : (/** @type {any} */ l) => ({ id: l.id, name: l.metadata?.name ?? "" }));
    cache.set(type, items);
    return { items, cached: false };
  }
  /** Resolve from the index; a miss or a stale-id failure on a CACHED index is retried once against a fresh fetch.
   * @template T @param {string} type @param {(items: any[]) => any} pick @param {(target: any) => Promise<T>} act @returns {Promise<{target: any, out: T}>} */
  async function resolveAndAct(type, pick, act) {
    let { items, cached } = await index(type);
    let target;
    try { target = pick(items); }
    catch (e) { if (!cached) throw e; ({ items, cached } = await index(type, true)); target = pick(items); }
    try { return { target, out: await act(target) }; }
    catch (e) {
      if (!cached || /** @type {any} */ (e)?.status !== 404) throw e;
      cache.delete(type); ({ items } = await index(type, true));
      target = pick(items);
      return { target, out: await act(target) };
    }
  }
  /** Rooms joined with their grouped_light state. @returns {Promise<Array<{id: string, name: string, groupedLightId?: string, on?: boolean, brightness?: number}>>} */
  async function rooms() {
    const [rs, gls] = await Promise.all([hue.list("room"), hue.list("grouped_light")]);
    return rs.map((/** @type {any} */ r) => {
      const room = roomView(r), gl = gls.find((/** @type {any} */ g) => g.id === room.groupedLightId);
      return { ...room, on: gl?.on?.on, brightness: gl?.dimming?.brightness };
    });
  }
  /** @param {Record<string, unknown>} a */
  async function setRoom(a) {
    const body = buildState(a); // validate before any cloud call
    const { target } = await resolveAndAct("room", (items) => {
      const r = fuzzyFind(String(a.room ?? ""), items, "room");
      if (!r.groupedLightId) throw new Error(`Room "${r.name}" has no grouped_light service`);
      return r;
    }, (r) => hue.put("grouped_light", String(r.groupedLightId), body));
    return { room: target.name, applied: body };
  }

  /** @type {Record<string, (a: Record<string, unknown>) => Promise<unknown>>} */
  const impl = {
    list_rooms: () => rooms(),
    list_lights: async () => (await hue.list("light")).map(lightView),
    async set_light(a) {
      const body = buildState(a);
      const q = String(a.light ?? "");
      const { target } = await resolveAndAct("light", (lights) => lights.find((/** @type {{id: string}} */ l) => l.id === q) ?? fuzzyFind(q, lights, "light"),
        (t) => hue.put("light", t.id, body));
      return { light: target.name, id: target.id, applied: body };
    },
    set_room: setRoom,
    async list_scenes(a) {
      const [scenes, rs] = await Promise.all([hue.list("scene"), index("room", true).then((x) => x.items)]);
      let out = scenes.map((/** @type {any} */ s) => ({ id: s.id, name: s.metadata?.name, room: rs.find((/** @type {any} */ r) => r.id === s.group?.rid)?.name, roomId: s.group?.rid }));
      if (a.room) { const r = fuzzyFind(String(a.room), rs, "room"); out = out.filter((/** @type {any} */ s) => s.roomId === r.id); }
      return out.map((/** @type {any} */ x) => { const { roomId, ...rest } = x; return rest; });
    },
    async activate_scene(a) {
      const [scenes, rs] = await Promise.all([hue.list("scene"), index("room", true).then((x) => x.items)]);
      /** @type {Array<{id: string, name: string, groupId?: string}>} */
      let pool = scenes.map((/** @type {any} */ s) => ({ id: s.id, name: s.metadata?.name ?? "", groupId: s.group?.rid }));
      const q = String(a.scene ?? "");
      let target = pool.find((/** @type {{id: string}} */ s) => s.id === q);
      if (!target) {
        if (a.room) { const r = fuzzyFind(String(a.room), rs, "room"); pool = pool.filter((/** @type {any} */ s) => s.groupId === r.id); }
        target = fuzzyFind(q, pool, "scene");
      }
      await hue.put("scene", target.id, { recall: { action: "active" } });
      return { activated: target.name, id: target.id, room: rs.find((/** @type {any} */ r) => r.id === target.groupId)?.name };
    },
    async hue_api(a) {
      const method = String(a.method ?? "GET").toUpperCase();
      const path = "/" + String(a.path ?? "").replace(/^\/+/, "").replace(/^clip\/v2\//, "");
      if (!METHODS.includes(method)) throw new Error("method must be GET, PUT, POST or DELETE");
      if (!RESOURCE_PATH.test(path)) throw new Error("path must look like resource, resource/<type> or resource/<type>/<id>");
      if (method !== "GET" && a.body === undefined && method !== "DELETE") throw new Error("body required for PUT/POST");
      return (await hue.request(method, path, a.body)).data ?? [];
    },
    dim_room: (a) => setRoom({ room: a.room, brightness: a.brightness === undefined ? 20 : a.brightness }),
  };

  /** @param {string} name @param {unknown} args */
  async function callTool(name, args) {
    const fn = impl[name];
    if (!fn) return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
    try {
      const out = await fn(isRecord(args) ? args : {});
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: redact(e instanceof Error ? e.message : "Unknown error", key) }] };
    }
  }
  return { toolList, callTool };
}
