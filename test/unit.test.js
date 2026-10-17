import test from "node:test";
import assert from "node:assert/strict";
import { toXY, parseColor, kelvinToMirek, clampMirek } from "../server/color.js";
import { fuzzyFind } from "../server/match.js";
import { redact } from "../server/redact.js";
import { buildState } from "../server/tools.js";

test("color: primaries, white, black fallback, #rgb shorthand, unknown colour error, gamma midtone", () => {
  const near = (c, x, y) => assert.ok(Math.abs(c.x - x) < 0.01 && Math.abs(c.y - y) < 0.01, JSON.stringify(c));
  near(toXY("red"), 0.7006, 0.2993); near(toXY("#00ff00"), 0.1724, 0.7468); near(toXY("blue"), 0.1355, 0.0399);
  near(toXY("#fff"), 0.3227, 0.329);
  // gamma midtone: chromatic, so the sRGB->linear curve changes the x/y ratio (a grey would hide it). Hand-computed from the Hue formula.
  assert.deepEqual(toXY("#ff8000"), { x: 0.6112, y: 0.375 });
  assert.deepEqual(toXY("#8040c0"), { x: 0.2688, y: 0.137 });
  assert.deepEqual(toXY("#000000"), { x: 0.3127, y: 0.329 });
  assert.deepEqual(parseColor("#f80"), [255, 136, 0]);
  assert.throws(() => toXY("blurple"), /Unknown colour/);
});
test("mireds: kelvin conversion and clamping", () => {
  assert.equal(kelvinToMirek(2700), 370);
  assert.equal(clampMirek(100), 153);
  assert.equal(clampMirek(900), 500);
});

const rooms = [{ name: "Kitchen" }, { name: "Living Room" }, { name: "Bedroom" }, { name: "Bathroom" }];
test("fuzzy: exact, case, 'the', prefix, substring, typo", () => {
  assert.equal(fuzzyFind("kitchen", rooms).name, "Kitchen");
  assert.equal(fuzzyFind("the kitchen", rooms).name, "Kitchen");
  assert.equal(fuzzyFind("living", rooms).name, "Living Room");
  assert.equal(fuzzyFind("bedrom", rooms).name, "Bedroom");
  assert.equal(fuzzyFind("bed", rooms).name, "Bedroom");
});
test("fuzzy: ambiguous and missing list candidates", () => {
  assert.throws(() => fuzzyFind("bath", [{ name: "Bathroom" }, { name: "Bath Closet" }], "room"), /ambiguous.*Bathroom.*Bath Closet/);
  assert.throws(() => fuzzyFind("garage", rooms, "room"), /No room matches.*Kitchen/);
});

test("redact: removes exact key, header echo and key-shaped tokens", () => {
  const key = "abcDEF123_secret-key";
  assert.equal(redact(`oops ${key} here`, key), "oops [REDACTED] here");
  assert.ok(!redact('{"hue-application-key": "short"}').includes("short"));
  assert.ok(!redact("tok " + "A".repeat(40)).includes("AAAA"));
});

test("buildState: brightness/colour/mirek mapping and validation", () => {
  assert.deepEqual(buildState({ brightness: 30 }), { dimming: { brightness: 30 }, on: { on: true } });
  assert.deepEqual(buildState({ brightness: 0 }), { on: { on: false } });
  assert.deepEqual(buildState({ on: false }), { on: { on: false } });
  assert.deepEqual(buildState({ mirek: 200 }), { color_temperature: { mirek: 200 } });
  assert.throws(() => buildState({ mirek: 1000 }), /between 153 and 500/);
  assert.ok(buildState({ color: "red" }).color.xy);
  assert.throws(() => buildState({}), /Nothing to set/);
  assert.throws(() => buildState({ brightness: 101 }), /between 0 and 100/);
  assert.throws(() => buildState({ color: "red", mirek: 300 }), /either color or/);
});
