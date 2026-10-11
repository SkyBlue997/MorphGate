// The page behaviour summary (docs/impl/phase2-spec.md §12.8, D-48), checked
// against testdata/phase2/samples/telemetry/behavior/.
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BehaviorCollector, MAX_HISTOGRAM_COUNT } from "../src/behavior";
import { XorShift32 } from "./xorshift";

const BEHAVIOR = new URL("../../../testdata/phase2/samples/telemetry/behavior/", import.meta.url);

/** The §12.8 schema as the Edge decodes it (unknown fields dropped). */
function checkSummary(s: Record<string, unknown>): boolean {
  const b = (v: unknown): boolean => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 31;
  const counts = (v: unknown, n: number): boolean =>
    Array.isArray(v) && v.length === n && v.every((c) => typeof c === "number" && Number.isInteger(c) && c >= 0 && c <= 65_535);
  const bit = (v: unknown): boolean => v === 0 || v === 1;
  const obj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (s["v"] !== 1 || new TextEncoder().encode(JSON.stringify(s)).length > 2048) return false;
  const { ptr, keys, scroll, touch, focus, vis, form } = s;
  if (ptr !== undefined && !(obj(ptr) && counts(ptr["speed"], 16) && counts(ptr["curv"], 16) && b(ptr["pauses"]))) return false;
  if (keys !== undefined && !(obj(keys) && counts(keys["iki"], 16))) return false;
  if (scroll !== undefined && !(obj(scroll) && b(scroll["dist"]) && counts(scroll["speed"], 8))) return false;
  if (touch !== undefined && !(obj(touch) && bit(touch["area_var"]) && bit(touch["pressure_var"]))) return false;
  if (focus !== undefined && !b(focus)) return false;
  if (vis !== undefined && !b(vis)) return false;
  if (form !== undefined && !(obj(form) && b(form["fill_ms"]) && b(form["paste"]))) return false;
  return true;
}

describe("behaviour summary schema (§12.8)", () => {
  it("the test checker agrees with the shared samples", () => {
    for (const dir of ["valid", "invalid"]) {
      for (const name of readdirSync(new URL(`${dir}/`, BEHAVIOR).pathname)) {
        const s = JSON.parse(readFileSync(new URL(`${dir}/${name}`, BEHAVIOR), "utf8"));
        expect(checkSummary(s), `${dir}/${name}`).toBe(dir === "valid");
      }
    }
  });

  it("an empty collector already produces a valid summary", () => {
    const s = new BehaviorCollector().summary();
    expect(checkSummary(s as unknown as Record<string, unknown>)).toBe(true);
    expect(Object.keys(s)).toEqual(["v", "ptr", "keys", "scroll", "touch", "focus", "vis", "form"]);
  });

  it("keeps aggregates only: no coordinates, key values or form content", () => {
    const c = new BehaviorCollector();
    c.observe({ type: "pointermove", timeStamp: 0, clientX: 123.25, clientY: 456.75, pointerType: "mouse" });
    c.observe({ type: "pointermove", timeStamp: 20, clientX: 223.25, clientY: 456.75, pointerType: "mouse" });
    c.observe({ type: "pointermove", timeStamp: 900, clientX: 223.25, clientY: 556.75, pointerType: "mouse" });
    c.observe({ type: "keydown", timeStamp: 1000, key: "secret-value" } as never);
    c.observe({ type: "keydown", timeStamp: 1130 });
    c.observe({ type: "keydown", timeStamp: 1131, repeat: true });
    c.observe({ type: "input", timeStamp: 2000 });
    c.observe({ type: "input", timeStamp: 6000 });
    c.observe({ type: "paste" });
    c.observe({ type: "scroll", timeStamp: 0 }, 0);
    c.observe({ type: "scroll", timeStamp: 100 }, 400);
    c.observe({ type: "pointerdown", pointerType: "touch", width: 10, height: 10, pressure: 0.5 });
    c.observe({ type: "pointerup", pointerType: "touch", width: 12, height: 10, pressure: 0.2 });
    c.observe({ type: "blur" });
    c.observe({ type: "hidden" });
    const s = c.summary();
    const text = JSON.stringify(s);
    expect(text).not.toMatch(/secret|123\.25|456\.75/);
    expect(s.ptr.speed.reduce((a, b) => a + b, 0)).toBe(2);
    expect(s.ptr.pauses).toBe(1); // one gap above 500 ms
    expect(s.ptr.curv.reduce((a, b) => a + b, 0)).toBe(1); // one 90-degree turn: bucket 7
    expect(s.ptr.curv[7]).toBe(1);
    expect(s.keys.iki[8]).toBe(1); // 130 ms; the auto-repeat is not counted
    expect(s.scroll).toEqual({ dist: 9, speed: [0, 0, 0, 0, 0, 0, 0, 1] });
    expect(s.touch).toEqual({ area_var: 1, pressure_var: 1 });
    expect(s.form).toEqual({ fill_ms: 12, paste: 1 });
    expect([s.focus, s.vis]).toEqual([1, 1]);
  });

  it("stays within the schema on 10,000 xorshift events (§2.4)", () => {
    const rng = new XorShift32(0xbe4a);
    const c = new BehaviorCollector();
    const types = ["pointermove", "pointerdown", "pointerup", "keydown", "scroll", "blur", "hidden", "input", "paste", "other"];
    for (let n = 0; n < 10_000; n++) {
      c.observe(
        {
          type: rng.pick(types),
          timeStamp: rng.below(10_000_000) / 10,
          clientX: rng.pick([rng.below(4000) - 1000, Number.NaN, Infinity]),
          clientY: rng.below(4000) - 1000,
          pointerType: rng.pick(["mouse", "touch", "pen", ""]),
          pressure: rng.below(100) / 99,
          width: rng.below(50),
          height: rng.below(50),
          repeat: rng.below(5) === 0,
        },
        rng.below(100_000),
      );
      if (n % 1000 === 0) expect(checkSummary(c.summary() as unknown as Record<string, unknown>)).toBe(true);
    }
    const s = c.summary();
    expect(checkSummary(s as unknown as Record<string, unknown>)).toBe(true);
    expect(Math.max(...s.ptr.speed)).toBeLessThanOrEqual(MAX_HISTOGRAM_COUNT);
  });
});
