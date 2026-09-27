import { describe, expect, it } from "vitest";
import { collectAutomation } from "../src/automation";
import { collectEnv, type EnvSource } from "../src/env";

describe("collectEnv", () => {
  it("summarises and coarsens the environment", () => {
    const env = collectEnv({
      navigator: {
        userAgent: "UA",
        languages: ["zh-CN", "en-US", "en", "fr"],
        hardwareConcurrency: 128,
        deviceMemory: 4,
        maxTouchPoints: 5,
        cookieEnabled: true,
      },
      screen: { width: 390, height: 844, availWidth: 390, availHeight: 797, colorDepth: 24 },
      innerWidth: 389,
      innerHeight: 664,
      devicePixelRatio: 2.625,
      matchMedia: (q) => ({ matches: q === "(pointer: coarse)" }),
      localStorage: {},
      sessionStorage: null,
      timeZone: () => "Asia/Hong_Kong",
      timezoneOffset: () => -480,
    });
    expect(env).toMatchObject({
      v: 1,
      ua: { userAgent: "UA", brands: null, mobile: null, platform: null },
      languages: ["zh-CN", "en-US", "en"],
      timeZone: "Asia/Hong_Kong",
      utcOffsetMin: 480,
      screen: { width: 390, height: 844, availWidth: 390, availHeight: 800, colorDepth: 24 },
      viewport: { width: 390, height: 660 },
      dpr: 2.75,
      cores: 64,
      memoryGb: 4,
      touch: { maxTouchPoints: 5, coarsePointer: true },
      storage: { cookies: true, local: true, session: false, indexedDb: null },
      graphics: null,
    });
  });

  it("carries no high-entropy fingerprint fields", () => {
    const keys = JSON.stringify(collectEnv({})).toLowerCase();
    for (const banned of ["canvas", "audio", "webglrenderer", "renderer", "vendor", "fonts", "plugins"]) {
      expect(keys).not.toContain(banned);
    }
  });

  it("never throws, mapping throwing getters to null or false", () => {
    const hostile: EnvSource = {
      get navigator(): never {
        throw new Error("boom");
      },
      get localStorage(): never {
        throw new DOMException("denied", "SecurityError");
      },
      timeZone: () => {
        throw new Error("no Intl");
      },
    };
    const env = collectEnv(hostile);
    expect(env.ua).toEqual({ userAgent: null, brands: null, mobile: null, platform: null });
    expect(env.languages).toBeNull();
    expect(env.timeZone).toBeNull();
    expect(env.storage.local).toBe(false);
    expect(env.storage.cookies).toBeNull();
  });

  it("truncates oversized strings", () => {
    const env = collectEnv({ navigator: { userAgent: "x".repeat(10_000), languages: ["y".repeat(100)] } });
    expect(env.ua.userAgent).toHaveLength(256);
    expect(env.languages?.[0]).toHaveLength(35);
  });
});

describe("collectAutomation", () => {
  it("reports the standard navigator.webdriver flag", () => {
    expect(collectAutomation({ navigator: { webdriver: true } })).toEqual({ v: 1, webdriver: true });
    expect(collectAutomation({ navigator: { webdriver: false } })).toEqual({ v: 1, webdriver: false });
  });

  it("reports null when the flag is missing, not boolean, or throws", () => {
    expect(collectAutomation({ navigator: {} }).webdriver).toBeNull();
    expect(collectAutomation({}).webdriver).toBeNull();
    expect(collectAutomation({ navigator: { webdriver: "true" } }).webdriver).toBeNull();
    const throwing = {
      navigator: {
        get webdriver(): never {
          throw new Error("trap");
        },
      },
    };
    expect(collectAutomation(throwing).webdriver).toBeNull();
  });
});
