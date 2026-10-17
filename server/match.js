// Fuzzy name matching for rooms/lights/scenes.
/** @param {string} s */
const norm = (s) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9 ]/g, " ").replace(/\b(the|room)\b/g, " ").replace(/\s+/g, " ").trim();

/** @param {string} a @param {string} b */
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

/**
 * Score tiers: exact 0, prefix 1, substring 2, typo 3. Returns the single best item,
 * throws with candidates when nothing matches or the best tier is a tie.
 * @template {{name: string}} T
 * @param {string} query
 * @param {T[]} items
 * @param {string} [kind]
 * @returns {T}
 */
export function fuzzyFind(query, items, kind = "item") {
  const q = norm(query);
  if (!q) throw new Error(`Empty ${kind} name.`);
  const scored = items.map((it) => {
    const n = norm(it.name);
    let tier = 99;
    if (n === q) tier = 0;
    else if (n.startsWith(q) || q.startsWith(n) && n) tier = 1;
    else if (n.includes(q) || q.includes(n) && n) tier = 2;
    else if (lev(n, q) <= Math.max(1, Math.floor(Math.max(n.length, q.length) / 4))) tier = 3;
    return { it, tier };
  }).filter((s) => s.tier < 99).sort((a, b) => a.tier - b.tier);
  const names = items.map((i) => i.name).join(", ") || "none";
  if (!scored.length) throw new Error(`No ${kind} matches "${query}". Available: ${names}`);
  const best = scored.filter((s) => s.tier === scored[0].tier);
  if (best.length > 1) throw new Error(`"${query}" is ambiguous for ${kind}: ${best.map((b) => b.it.name).join(", ")}`);
  return best[0].it;
}
