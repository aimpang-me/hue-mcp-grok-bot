// Bridge-slot leases: a claim is a 10-minute lease, confirmed when the user record is written, and freed by the sweep if never confirmed.
import test from "node:test";
import assert from "node:assert/strict";
import { harness, login } from "./support/harness.js";

const MINUTE = 60_000;
const bridgeStore = (h) => h.stores.get([...h.stores.keys()].find((k) => k.startsWith("bridge:")));
const holders = (h) => { const m = bridgeStore(h); return [...(m?.get("users") ?? []), ...[...(m?.keys() ?? [])].filter((k) => k.startsWith("lease:"))]; };
const dop = async (h, name, payload) => (await h.env.USER_DO.get(name).fetch(new Request("https://do/op", { method: "POST", body: JSON.stringify(payload) }))).json();
/** Simulate a process dying right after the claim: every later registry call from this sign-in throws, so neither confirm nor release runs. */
function crashAfterClaim(h) {
  const ns = h.env.USER_DO, get = ns.get; let armed = true;
  ns.get = (id) => { const d = get(id); return { fetch: (req) => (armed && String(id).startsWith("bridge:") ? req.clone().json().then((m) => { if (["bridgePut", "bridgeConfirm", "bridgeRelease", "bridgeAbandon"].includes(m.op)) throw new Error("crash"); return d.fetch(req); }) : d.fetch(req)) }; };
  return () => { armed = false; };
}

test("lease: normal flow leaves a confirmed holder and no lease record behind", async () => {
  const h = harness(); const a = await login(h, "alice");
  assert.equal(holders(h).length, 1); assert.deepEqual(holders(h), [a.access_token.split(".")[0]]);
  assert.ok(![...bridgeStore(h).keys()].some((k) => k.startsWith("lease:")));
});

test("lease: a crash between claim and user-record write leaks nothing; the slot frees itself after the lease expires", async () => {
  const h = harness(); const stop = crashAfterClaim(h);
  await assert.rejects(() => login(h, "alice"));
  stop();
  assert.equal(holders(h).length, 1, "within the lease the claim still counts as a holder");
  h.advance(11 * MINUTE); await h.runAlarms();
  assert.deepEqual(holders(h), [], "expired unconfirmed lease swept by the alarm");
  const b = await login(h, "alice"); assert.ok(b.access_token, "bridge usable again");
  assert.deepEqual(holders(h), [b.access_token.split(".")[0]]);
});

test("lease: expiry is also enforced lazily on the next claim when no alarm has run", async () => {
  const h = harness(); const stop = crashAfterClaim(h);
  await assert.rejects(() => login(h, "alice")); stop();
  h.advance(11 * MINUTE);
  const b = await login(h, "alice");
  assert.deepEqual(holders(h), [b.access_token.split(".")[0]], "stale lease gone, only the confirmed holder remains");
});

test("lease: a live lease protects the key from a release by another holder; once expired, the last release returns the key", async () => {
  const h = harness(); h.cloud.setBridge(() => "BR-shared");
  await dop(h, "bridge:x", { op: "bridgeClaim", uid: "u1" }); await dop(h, "bridge:x", { op: "bridgePut", uid: "u1", key: "K" });
  await dop(h, "bridge:x", { op: "bridgeConfirm", uid: "u1" });
  await dop(h, "bridge:x", { op: "bridgeClaim", uid: "u2" }); // pending, unconfirmed
  assert.deepEqual(await dop(h, "bridge:x", { op: "bridgeRelease", uid: "u1" }), { key: null }, "u2 is mid sign-in and may be using the key");
  h.advance(11 * MINUTE);
  assert.deepEqual(await dop(h, "bridge:x", { op: "bridgeRelease", uid: "u2" }), { key: "K" });
});

test("lease: the per-bridge daily cap still counts leaked claims", async () => {
  const h = harness({ BRIDGE_LOGINS_PER_DAY: "2" }); const stop = crashAfterClaim(h);
  await assert.rejects(() => login(h, "alice")); await assert.rejects(() => login(h, "alice")); stop();
  h.advance(11 * MINUTE); await h.runAlarms();
  await assert.rejects(() => login(h, "alice"), /302|status/, "cap holds even though both leases expired");
  h.advance(24 * 3600_000); assert.ok((await login(h, "alice")).access_token, "resets next UTC day");
});

test("lease: confirming is idempotent", async () => {
  const h = harness();
  await dop(h, "bridge:y", { op: "bridgeClaim", uid: "u1" });
  assert.deepEqual(await dop(h, "bridge:y", { op: "bridgeConfirm", uid: "u1" }), { ok: true });
  assert.deepEqual(await dop(h, "bridge:y", { op: "bridgeConfirm", uid: "u1" }), { ok: true });
  assert.deepEqual(h.stores.get("bridge:y").get("users"), ["u1"]);
});

// Races between claim / confirm / release / sweep.
test("lease: a late confirm after the lease expired and the key was returned is refused, not resurrected as a keyless holder", async () => {
  const h = harness();
  await dop(h, "bridge:z", { op: "bridgeClaim", uid: "u1" }); await dop(h, "bridge:z", { op: "bridgePut", uid: "u1", key: "K" });
  h.advance(11 * MINUTE);
  assert.deepEqual(await dop(h, "bridge:z", { op: "bridgeConfirm", uid: "u1" }), { ok: false }, "expired lease cannot be confirmed (even before any sweep)");
  assert.deepEqual(h.stores.get("bridge:z").get("users") ?? [], []);
});

test("lease: a failed sign-in drops only its own lease and never returns or deletes the shared key", async () => {
  const h = harness();
  await dop(h, "bridge:w", { op: "bridgeClaim", uid: "u1" }); await dop(h, "bridge:w", { op: "bridgePut", uid: "u1", key: "K" });
  assert.deepEqual(await dop(h, "bridge:w", { op: "bridgeAbandon", uid: "u1" }), { ok: true });
  const m = h.stores.get("bridge:w");
  assert.equal(m.get("key"), "K", "key stays registered: nobody unpaired it on the bridge");
  assert.ok(![...m.keys()].some((k) => k.startsWith("lease:")));
});

test("lease: if the registry refuses to confirm, the sign-in fails and leaves no user record", async () => {
  const h = harness(); const ns = h.env.USER_DO, get = ns.get;
  ns.get = (id) => { const d = get(id); return { fetch: (req) => String(id).startsWith("bridge:") ? req.clone().json().then((m) => m.op === "bridgeConfirm" ? Response.json({ ok: false }) : d.fetch(req)) : d.fetch(req) }; };
  await assert.rejects(() => login(h, "alice"));
  assert.ok(![...h.stores].some(([id, m]) => !id.startsWith("bridge:") && id !== "global" && m.has("hue")), "no half-written user");
});

test("lease: concurrent claims cannot exceed the daily cap", async () => {
  const h = harness({ BRIDGE_LOGINS_PER_DAY: "3" });
  const r = await Promise.all([1, 2, 3, 4, 5, 6].map((i) => dop(h, "bridge:c", { op: "bridgeClaim", uid: `u${i}` })));
  assert.equal(r.filter((x) => x.limited).length, 3);
  assert.equal([...h.stores.get("bridge:c").keys()].filter((k) => k.startsWith("lease:")).length, 3);
});

test("lease: claim, confirm and release racing on one registry end consistent", async () => {
  const h = harness();
  await dop(h, "bridge:r", { op: "bridgeClaim", uid: "u1" }); await dop(h, "bridge:r", { op: "bridgePut", uid: "u1", key: "K" });
  const [, rel] = await Promise.all([dop(h, "bridge:r", { op: "bridgeConfirm", uid: "u1" }), dop(h, "bridge:r", { op: "bridgeRelease", uid: "u1" })]);
  const m = h.stores.get("bridge:r");
  assert.deepEqual(rel, { key: "K" }, "confirm ran first, release second: last holder gone, key returned once");
  assert.equal(m.get("key"), undefined); assert.deepEqual(m.get("users") ?? [], []);
});
