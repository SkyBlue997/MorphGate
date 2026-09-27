import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { DEFAULT_PATH_PREFIX, endpointPath, normalizePathPrefix, parseConfig } from "../src/index";

describe("parseConfig (script data attributes)", () => {
  it("defaults to /__mg/ when no attributes are set", () => {
    expect(parseConfig({})).toEqual({ pathPrefix: DEFAULT_PATH_PREFIX, site: null, debug: false });
    expect(DEFAULT_PATH_PREFIX).toBe("/__mg/");
  });

  it("reads data-mg-path-prefix, data-mg-site and data-mg-debug", () => {
    expect(parseConfig({ mgPathPrefix: "/x7k/", mgSite: "blog-prod", mgDebug: "true" })).toEqual({
      pathPrefix: "/x7k/",
      site: "blog-prod",
      debug: true,
    });
  });

  it("ignores invalid site ids", () => {
    expect(parseConfig({ mgSite: "a b" }).site).toBeNull();
    expect(parseConfig({ mgSite: "" }).site).toBeNull();
  });
});

describe("normalizePathPrefix", () => {
  it("adds the trailing slash and keeps nested first-party paths", () => {
    expect(normalizePathPrefix("/__mg")).toBe("/__mg/");
    expect(normalizePathPrefix(" /a/b ")).toBe("/a/b/");
  });

  it("falls back to the default for anything that is not a same-origin path", () => {
    for (const bad of ["", "__mg/", "//evil.example/", "https://evil.example/__mg/", "/../", "/a/./b/", "/a b/", "/a?x=1/", `/${"a".repeat(80)}/`]) {
      expect(normalizePathPrefix(bad)).toBe(DEFAULT_PATH_PREFIX);
    }
  });

  it("builds endpoint paths under the prefix", () => {
    const config = parseConfig({ mgPathPrefix: "/x7k" });
    expect(endpointPath(config, "c")).toBe("/x7k/c");
    expect(endpointPath(config, "c/renew")).toBe("/x7k/c/renew");
  });
});

describe("bootstrap", () => {
  // Node 26 exposes experimental Web Storage globals that warn on access; the
  // browser snapshot probes them, so stub them for this suite.
  beforeAll(() => {
    vi.stubGlobal("localStorage", undefined);
    vi.stubGlobal("sessionStorage", undefined);
  });
  afterAll(() => {
    vi.unstubAllGlobals();
  });

  function fakeDocument(dataset: Record<string, string>): Document {
    return { currentScript: { dataset }, querySelector: () => null } as unknown as Document;
  }

  it("exposes a frozen, non-writable window.MorphGate once", async () => {
    const { bootstrap, SDK_VERSION } = await import("../src/index");
    const win = {} as Window;
    const api = bootstrap(fakeDocument({ mgPathPrefix: "/p" }), win);
    expect(api).not.toBeNull();
    expect(api?.version).toBe(SDK_VERSION);
    expect(api?.config.pathPrefix).toBe("/p/");
    expect(win.MorphGate).toBe(api);
    expect(Object.isFrozen(api)).toBe(true);
    // A second inclusion returns the first instance instead of re-initialising.
    expect(bootstrap(fakeDocument({ mgPathPrefix: "/other/" }), win)).toBe(api);
    const snapshot = api?.snapshot();
    expect(snapshot?.automation.v).toBe(1);
    expect(snapshot?.env.v).toBe(1);
  });

  it("returns null instead of throwing when the host page is hostile", async () => {
    const { bootstrap } = await import("../src/index");
    const doc = {
      get currentScript(): never {
        throw new Error("boom");
      },
    } as unknown as Document;
    expect(bootstrap(doc, {} as Window)).toBeNull();
  });
});
