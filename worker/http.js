// Response helpers shared by every route.
export const SNIFF = { "x-content-type-options": "nosniff" };
export const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type, mcp-protocol-version, mcp-session-id", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-expose-headers": "www-authenticate" };
export const HTML_SECURITY = { "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self' https://api.meethue.com", "x-frame-options": "DENY", "referrer-policy": "no-referrer" };

/** @param {string} body @param {number} [status] @param {string} [type] @param {Record<string, string>} [extra] */
export const text = (body, status = 200, type = "text/plain", extra = {}) => new Response(body, { status, headers: { "content-type": type, "cache-control": "no-store", ...SNIFF, ...extra } });
/** @param {unknown} o @param {number} [status] @param {Record<string, string>} [extra] */
export const json = (o, status = 200, extra = {}) => text(JSON.stringify(o), status, "application/json", { ...CORS, ...extra });
/** An OAuth error body. @param {string} error @param {number} [status] @param {string} [description] */
export const oerr = (error, status = 400, description = "") => json({ error, ...(description ? { error_description: description } : {}) }, status);
/** HTML-escape. @param {string} s */
export const esc = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** 302 that may set several cookies. @param {string} to @param {string[]} [cookies] */
export function redirect(to, cookies = []) {
  const h = new Headers({ location: to, "cache-control": "no-store", ...SNIFF });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(null, { status: 302, headers: h });
}
/** Send the browser back to the client's redirect URI with these params and the client's own `state`.
 * @param {string} ruri @param {string|undefined} state @param {Record<string, string>} params @param {string[]} [cookies] */
export function redirectBack(ruri, state, params, cookies = []) {
  const r = new URL(ruri);
  for (const [k, v] of Object.entries(params)) r.searchParams.set(k, v);
  if (state) r.searchParams.set("state", state);
  return redirect(r.href, cookies);
}

/** Request body as text, or null when it is larger than `max` bytes. Reads at most `max` + one chunk, so a huge body is never buffered.
 * @param {Request} req @param {number} [max] */
export async function readBody(req, max = 65536) {
  if (Number(req.headers.get("content-length") ?? 0) > max) return null;
  if (!req.body) return "";
  const reader = req.body.getReader(), parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) { await reader.cancel(); return null; }
    parts.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const p of parts) { all.set(p, at); at += p.byteLength; }
  return new TextDecoder().decode(all);
}
