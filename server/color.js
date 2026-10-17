// Colour helpers: names/hex -> CIE xy (Hue wide gamut), mireds <-> kelvin.

/** @type {Record<string, string>} */
export const NAMED = {
  red: "#ff0000", orange: "#ff8000", yellow: "#ffff00", lime: "#80ff00", green: "#00ff00", teal: "#00ffa0",
  cyan: "#00ffff", blue: "#0000ff", purple: "#8000ff", violet: "#8f00ff", magenta: "#ff00ff", pink: "#ff69b4", white: "#ffffff",
};

/** @param {string} input @returns {[number, number, number]} 0-255 rgb */
export function parseColor(input) {
  const raw = String(input).trim().toLowerCase();
  const hex = NAMED[raw] ?? raw;
  const m = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/.exec(hex);
  if (!m) throw new Error(`Unknown colour "${input}". Use a name (${Object.keys(NAMED).join(", ")}) or hex like #ff8800.`);
  let h = m[1];
  if (h.length === 3) h = [...h].map((c) => c + c).join("");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}

/** Hue's documented RGB -> xy conversion (gamma-corrected, wide gamut D65). @param {string} input */
export function toXY(input) {
  const [r, g, b] = parseColor(input).map((c) => {
    const v = c / 255;
    return v > 0.04045 ? ((v + 0.055) / 1.055) ** 2.4 : v / 12.92;
  });
  const X = r * 0.664511 + g * 0.154324 + b * 0.162028;
  const Y = r * 0.283881 + g * 0.668433 + b * 0.047685;
  const Z = r * 0.000088 + g * 0.07231 + b * 0.986039;
  const sum = X + Y + Z;
  if (sum === 0) return { x: 0.3127, y: 0.329 };
  const round = (/** @type {number} */ n) => Math.round(n * 10000) / 10000;
  return { x: round(X / sum), y: round(Y / sum) };
}

export const MIREK_MIN = 153, MIREK_MAX = 500;
/** @param {number} k */
export const kelvinToMirek = (k) => Math.round(1_000_000 / k);
/** @param {number} m */
export const clampMirek = (m) => Math.min(MIREK_MAX, Math.max(MIREK_MIN, Math.round(m)));
