// Scrub the app key (and anything key-shaped) from any string that could reach a log, tool result or error.
const KEYISH = /\b[A-Za-z0-9_-]{32,}\b/g;

/** @param {unknown} text @param {...(string|undefined)} secrets */
export function redact(text, ...secrets) {
  let s = typeof text === "string" ? text : String(text);
  for (const sec of secrets) if (sec) s = s.split(sec).join("[REDACTED]");
  return s.replace(/(hue-application-key["']?\s*[:=]\s*["']?)[^\s"',]+/gi, "$1[REDACTED]").replace(KEYISH, "[REDACTED]");
}
