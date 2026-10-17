// Pre-ship leak scan over every file git would ship (tracked + untracked, minus ignored): local paths, emails, long hex secrets,
// LAN IPs, token-looking literals, account/KV ids. Words specific to the maintainer (names, handles, private tool names) live in the
// gitignored file `.leakscan.local`, one case-insensitive regex per line, so the public repo never spells them out.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, existsSync } from "node:fs";

const root = new URL("../", import.meta.url).pathname;
/** Files that would ship: git's list in a checkout, a directory walk in an unpacked `git archive` (no .git there). */
function shippable() {
  try { return execFileSync("git", ["ls-files", "-co", "--exclude-standard"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); }
  catch {
    /** @param {string} d @returns {string[]} */
    const walk = (d) => readdirSync(root + d, { withFileTypes: true }).flatMap((e) => e.name === "node_modules" || e.name === ".git" ? [] : e.isDirectory() ? walk(`${d}${e.name}/`) : [d + e.name]);
    return walk("");
  }
}
const files = shippable();
const j = (...p) => p.join("");
const LOCAL = root + ".leakscan.local";
/** @type {[string, RegExp][]} */
const PRIVATE = existsSync(LOCAL) ? readFileSync(LOCAL, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => ["private word (.leakscan.local)", new RegExp(l, "i")]) : [];
const RULES = [
  ...PRIVATE,
  ["chat platform id", /\b\d{17,20}\b/],
  ["local path", new RegExp(`(${j("/ho", "me/")}|${j("/Us", "ers/")}|/mnt/[a-z]/|[A-Z]:\\\\${j("Us", "ers")})`)],
  ["email address", /[\w.+-]+@[\w-]+\.[a-z]{2,}/i],
  ["long hex (key/id)", /\b[0-9a-fA-F]{32,}\b/],
  ["private LAN ip", /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b/],
  ["token-looking literal", /\b(sk-|ghp_|xox[bp]-|AKIA)[A-Za-z0-9_-]{10,}/],
  ["wrangler account/kv id", /\b(account_id|kv_id)\s*=\s*"[0-9a-f]{20,}"|^id\s*=\s*"(?!REPLACE_ME)[0-9a-f]{20,}"/m],
];
test("leak scan: nothing personal, secret-shaped or machine-specific in the shippable tree", () => {
  assert.ok(files.length > 10, "file list looks wrong");
  const hits = [];
  for (const f of files) {
    if (/\.(png|jpg|ico)$/.test(f)) continue;
    const s = readFileSync(root + f, "utf8");
    for (const [name, re] of RULES) { const m = re.exec(s); if (m) hits.push(`${f}: ${name}`); }
  }
  assert.deepEqual(hits, []);
});
test("leak scan: secrets files and local wrangler config are ignored by git", () => {
  for (const f of [".secrets.local", ".leakscan.local", "wrangler.toml", ".dev.vars"]) assert.ok(!files.includes(f), f);
});
test("leak scan: common secret and bundle file names are ignored by git", { skip: !existsSync(root + ".git") && "no .git (unpacked archive)" }, () => {
  for (const f of [".env.local", "key.pem", "deploy.bundle", "worker.tgz", "debug.log", ".secrets.prod", ".DS_Store"]) {
    assert.doesNotThrow(() => execFileSync("git", ["check-ignore", "-q", f], { cwd: root }), `${f} should be gitignored`);
  }
});
