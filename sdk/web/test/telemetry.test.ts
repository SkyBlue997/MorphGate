// Telemetry budgets and /__mg/t batching (docs/impl/phase2-spec.md §7.5, §7.6, §9.4, §12.8),
// checked against testdata/phase2/samples/telemetry/.
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  MAX_REPORTS,
  TELEMETRY_BUDGET_BYTES,
  batchReports,
  encodeReports,
  encodeSubmissionTelemetry,
  reportPath,
  utf8Bytes,
  type IxTelemetry,
  type Report,
} from "../src/telemetry";
import { XorShift32 } from "./xorshift";

const SAMPLES = new URL("../../../testdata/phase2/samples/telemetry/", import.meta.url);
/** One JSON text per file; the trailing newline is not part of it. */
const sample = (path: string): string => readFileSync(new URL(path, SAMPLES), "utf8").replace(/\n$/, "");
const files = (dir: string): string[] => readdirSync(new URL(dir, SAMPLES).pathname).filter((f) => f.endsWith(".json"));

const IX: IxTelemetry = JSON.parse(sample("t/valid/hold.json")).ix;

describe("t: encodeSubmissionTelemetry (§7.5, §7.6)", () => {
  it("reproduces the valid samples byte for byte (key order env, auto, ix)", () => {
    for (const name of files("t/valid")) {
      if (name === "unknown-fields-dropped.json") continue;
      const text = sample(`t/valid/${name}`);
      const t = JSON.parse(text);
      expect(encodeSubmissionTelemetry({ env: t.env, auto: t.auto, ix: t.ix }), name).toBe(text);
      expect(utf8Bytes(text)).toBeLessThanOrEqual(TELEMETRY_BUDGET_BYTES);
    }
  });

  it("drops ix.pre, ix.page, env and auto, in that order, to fit", () => {
    const t = JSON.parse(sample("t/valid/hold.json"));
    const full = encodeSubmissionTelemetry(t)!;
    const size = utf8Bytes(full);
    const dropped = (budget: number): Record<string, unknown> => JSON.parse(encodeSubmissionTelemetry(t, budget)!);
    expect(dropped(size)).toEqual(t);
    const noPre = dropped(size - 1);
    expect(noPre.ix).not.toHaveProperty("pre");
    expect(noPre.ix).toHaveProperty("page");
    expect(noPre).toHaveProperty("env");
    const noPage = dropped(utf8Bytes(JSON.stringify(noPre)) - 1);
    expect(noPage.ix).not.toHaveProperty("page");
    expect(noPage.ix).toHaveProperty("hold");
    const noEnv = dropped(utf8Bytes(JSON.stringify(noPage)) - 1);
    expect(noEnv).not.toHaveProperty("env");
    expect(noEnv).toHaveProperty("auto");
    const noAuto = dropped(utf8Bytes(JSON.stringify(noEnv)) - 1);
    expect(Object.keys(noAuto)).toEqual(["ix"]);
    // Still over: nothing is submitted.
    expect(encodeSubmissionTelemetry(t, utf8Bytes(JSON.stringify(noAuto)) - 1)).toBeNull();
    // The input is not modified.
    expect(t.ix.pre).toBeDefined();
  });

  it("a realistic t with the full env summary stays within 2 KB", () => {
    const t = JSON.parse(sample("t/valid/hold.json"));
    expect(utf8Bytes(encodeSubmissionTelemetry({ ...t, ix: IX })!)).toBeLessThanOrEqual(2048);
  });
});

describe("/__mg/t reports (§9.4)", () => {
  it("valid sample bodies come out of batchReports unchanged", () => {
    for (const name of files("report/valid")) {
      if (name === "unknown-report-field-dropped.json") continue;
      const body = JSON.parse(sample(`report/valid/${name}`));
      const batches = batchReports(body.reports);
      expect(batches, name).toHaveLength(1);
      expect(encodeReports(batches[0]!), name).toBe(sample(`report/valid/${name}`));
    }
  });

  it("splits what one request may not carry: 9 reports, two upstream_challenge or cache_hit", () => {
    for (const name of ["nine-reports.json", "two-upstream-challenge.json", "two-cache-hit.json"]) {
      const body = JSON.parse(sample(`report/invalid/${name}`));
      const batches = batchReports(body.reports);
      for (const batch of batches) {
        expect(batch.length).toBeLessThanOrEqual(MAX_REPORTS);
        expect(batch.filter((r) => r.kind === "cache_hit").length).toBeLessThanOrEqual(1);
        expect(batch.filter((r) => r.kind === "upstream_challenge").length).toBeLessThanOrEqual(1);
      }
    }
    // Two upstream reports of the same scope and path merge their counts.
    const merged = batchReports([
      { kind: "upstream_challenge", scope: "protected_fetch", path: "/a", count: 99 },
      { kind: "upstream_challenge", scope: "protected_fetch", path: "/a", count: 5 },
    ]);
    expect(merged).toEqual([[{ kind: "upstream_challenge", scope: "protected_fetch", path: "/a", count: 100 }]]);
  });

  it("reportPath: a page path without query, at most 512 bytes", () => {
    expect(reportPath("/articles")).toBe("/articles");
    expect(reportPath("/a?b")).toBeNull();
    expect(reportPath("a")).toBeNull();
    expect(reportPath(`/${"a".repeat(511)}`)).not.toBeNull();
    expect(reportPath(`/${"a".repeat(512)}`)).toBeNull();
    expect(reportPath(`/${"验".repeat(171)}`)).toBeNull(); // 513 bytes
  });

  it("batching keeps its invariants on 10,000 xorshift report lists (§2.4)", () => {
    const rng = new XorShift32(0x7e1e);
    const kinds: Report[] = [
      { kind: "cache_hit", path: "/__mg/c" },
      { kind: "sw_intercept", path: "/__mg/v" },
      { kind: "key_unavailable", reason: "no_idb" },
      { kind: "behavior", page: "/", summary: { v: 1 } },
    ];
    for (let n = 0; n < 10_000; n++) {
      const list: Report[] = [];
      for (let i = rng.below(20); i > 0; i--) {
        list.push(
          rng.below(3) === 0
            ? { kind: "upstream_challenge", scope: rng.pick(["navigation", "protected_fetch", "mg_endpoint"] as const), path: rng.pick(["/a", "/b"]), count: 1 + rng.below(100) }
            : rng.pick(kinds),
        );
      }
      const batches = batchReports(list);
      for (const batch of batches) {
        expect(batch.length).toBeGreaterThan(0);
        expect(batch.length).toBeLessThanOrEqual(MAX_REPORTS);
        expect(batch.filter((r) => r.kind === "cache_hit").length).toBeLessThanOrEqual(1);
        expect(batch.filter((r) => r.kind === "upstream_challenge").length).toBeLessThanOrEqual(1);
        for (const r of batch) if (r.kind === "upstream_challenge") expect(r.count >= 1 && r.count <= 100).toBe(true);
      }
      const nonUpstream = list.filter((r) => r.kind !== "upstream_challenge").length;
      expect(batches.flat().filter((r) => r.kind !== "upstream_challenge")).toHaveLength(nonUpstream);
    }
  });
});
