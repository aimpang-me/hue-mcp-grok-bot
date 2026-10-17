#!/usr/bin/env node
// LAN pairing helper (transport C). Run on your own PC while on the bridge's network:
//   node scripts/pair.mjs <bridge-ip>        (or set HUE_BRIDGE_IP)
// Press the bridge's round link button first (or within 30 s of starting). The new key is printed ONLY to this terminal.
// With --set-env (Windows only) it persists HUE_BRIDGE_IP / HUE_APP_KEY as user env vars via setx and does not print the key.
import https from "node:https";
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
const setEnv = args.includes("--set-env");
const ip = args.find((a) => !a.startsWith("--")) ?? process.env.HUE_BRIDGE_IP;
if (!ip) { console.error("usage: node scripts/pair.mjs <bridge-ip> [--set-env]"); process.exit(2); }
if (setEnv && process.platform !== "win32") { console.error("--set-env only works on Windows (it uses setx). Run without it and store the key yourself."); process.exit(2); }

// Self-signed bridge cert: TLS verification is disabled for this one bridge host only.
const agent = new https.Agent({ rejectUnauthorized: false });
const post = () => new Promise((resolve, reject) => {
  const body = JSON.stringify({ devicetype: "hue-mcp#local-pc", generate_clientkey: true });
  const req = https.request({ host: ip, path: "/api", method: "POST", agent, timeout: 8000, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
    (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve(JSON.parse(d)); } catch { reject(new Error("non-JSON reply")); } }); });
  req.on("error", reject); req.on("timeout", () => req.destroy(new Error("timeout")));
  req.end(body);
});

console.log(`Press the link button on the Hue bridge (${ip}) now. Waiting up to 60 s...`);
for (let i = 0; i < 30; i++) {
  const r = await post().catch((e) => { console.error("request failed:", e.message); process.exit(1); });
  const ok = r?.[0]?.success?.username;
  if (ok) {
    const saved = setEnv && [["HUE_BRIDGE_IP", ip], ["HUE_APP_KEY", ok]].every(([k, v]) => spawnSync("setx", [k, v], { stdio: "ignore" }).status === 0);
    if (saved) {
      console.log("Paired. HUE_BRIDGE_IP and HUE_APP_KEY saved as user env vars (key not shown). Restart your terminal/app.");
    } else {
      if (setEnv) console.error("Saving with setx failed, so the key is shown below instead.");
      console.log("Paired. Keep this secret; do not paste it into chat or commit it.");
      console.log(`HUE_BRIDGE_IP=${ip}`);
      console.log(`HUE_APP_KEY=${ok}`);
      console.log(`PowerShell:  setx HUE_BRIDGE_IP ${ip}; setx HUE_APP_KEY <the key above>`);
    }
    process.exit(0);
  }
  if (r?.[0]?.error?.type !== 101) { console.error("Bridge said:", r?.[0]?.error?.description ?? "unexpected reply"); process.exit(1); }
  await new Promise((s) => setTimeout(s, 2000));
}
console.error("Timed out: link button was not pressed.");
process.exit(1);
