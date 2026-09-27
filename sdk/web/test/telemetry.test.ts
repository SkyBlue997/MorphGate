import { describe, expect, it } from "vitest";
import { collectAutomation } from "../src/automation";
import { collectEnv } from "../src/env";
import {
  checkBudget,
  fitToBudget,
  payloadBytes,
  TELEMETRY_BUDGET_BYTES,
  type TelemetryPayload,
} from "../src/telemetry";

function base(): TelemetryPayload {
  return { v: 1, kind: "page", ts: 1790000000, build: "b0" };
}

describe("telemetry budget", () => {
  it("is 2 KB", () => {
    expect(TELEMETRY_BUDGET_BYTES).toBe(2048);
  });

  it("accepts a realistic page payload with env and automation summaries", () => {
    const env = collectEnv({
      navigator: {
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        languages: ["zh-CN", "zh", "en-US", "en"],
        hardwareConcurrency: 8,
        deviceMemory: 8,
        maxTouchPoints: 0,
        cookieEnabled: true,
        userAgentData: {
          brands: [
            { brand: "Chromium", version: "140" },
            { brand: "Google Chrome", version: "140" },
            { brand: "Not=A?Brand", version: "24" },
          ],
          mobile: false,
          platform: "Windows",
        },
      },
      screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1032, colorDepth: 24 },
      innerWidth: 1903,
      innerHeight: 961,
      devicePixelRatio: 1,
      timeZone: () => "Asia/Shanghai",
      timezoneOffset: () => -480,
    });
    const payload: TelemetryPayload = { ...base(), env, automation: collectAutomation({ navigator: { webdriver: false } }) };
    const result = checkBudget(payload);
    expect(result.ok).toBe(true);
    expect(result.bytes).toBeLessThan(TELEMETRY_BUDGET_BYTES);
  });

  it("counts UTF-8 bytes, not UTF-16 code units", () => {
    const payload: TelemetryPayload = { ...base(), features: {} };
    const ascii = payloadBytes(payload);
    // Three CJK characters: 3 code units, 9 UTF-8 bytes.
    const withCjk: TelemetryPayload = { ...payload, build: "b0中文字" };
    expect(payloadBytes(withCjk) - ascii).toBe(9);
  });

  it("reports how far over budget a payload is", () => {
    const features: Record<string, number> = {};
    for (let i = 0; i < 300; i++) features[`f${i}`] = i;
    const result = checkBudget({ ...base(), features });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.overBy).toBe(result.bytes - TELEMETRY_BUDGET_BYTES);
  });

  it("fits by dropping optional sections in order, keeping the core fields", () => {
    const features: Record<string, number> = {};
    for (let i = 0; i < 300; i++) features[`f${i}`] = i;
    const payload: TelemetryPayload = {
      ...base(),
      kind: "upstream_challenge",
      upstream: { scope: "mg_endpoint", count: 1 },
      features,
      automation: { v: 1, webdriver: null },
    };
    const fitted = fitToBudget(payload);
    expect(fitted).not.toBeNull();
    expect(fitted).toMatchObject({ kind: "upstream_challenge", upstream: { scope: "mg_endpoint", count: 1 } });
    expect(fitted?.features).toBeUndefined();
    expect(fitted?.automation).toEqual({ v: 1, webdriver: null });
    // The input object is not mutated.
    expect(payload.features).toBe(features);
  });

  it("returns null when even the core payload cannot fit", () => {
    expect(fitToBudget({ ...base(), build: "x".repeat(TELEMETRY_BUDGET_BYTES) })).toBeNull();
  });
});
