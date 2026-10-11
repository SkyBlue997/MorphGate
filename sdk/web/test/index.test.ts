// window.MorphGate and the page bootstrap (docs/impl/phase2-spec.md §12.1, §12.5, §12.8, §9.4).
import { describe, expect, it } from "vitest";
import { bootstrap, type MorphGateApi } from "../src/index";
import { REPORT_QUEUE_KEY } from "../src/runtime";
import { FakeClock, memoryStorage, until } from "./fakes";

interface Page {
  win: Window;
  api: MorphGateApi | null;
  posts: { url: string; body: string; keepalive: boolean; headers: Headers }[];
  assigned: string[];
  docListeners: Map<string, ((e: unknown) => void)[]>;
  setHidden: () => void;
  selectors: string[];
  session: ReturnType<typeof memoryStorage>;
}

function page(options: { path?: string; dataset?: Record<string, string>; cookie?: string; currentScript?: boolean; queued?: unknown[] } = {}): Page {
  const clock = new FakeClock();
  const posts: Page["posts"] = [];
  const assigned: string[] = [];
  const docListeners = new Map<string, ((e: unknown) => void)[]>();
  const selectors: string[] = [];
  const session = memoryStorage();
  if (options.queued) session.setItem(REPORT_QUEUE_KEY, JSON.stringify(options.queued));
  let visibility = "visible";
  const path = options.path ?? "/articles";
  const doc = {
    currentScript: options.currentScript === false ? null : { dataset: options.dataset ?? {} },
    querySelector: (selector: string) => {
      selectors.push(selector);
      return { dataset: options.dataset ?? {} };
    },
    getElementById: () => null,
    readyState: "complete",
    cookie: options.cookie ?? "",
    get visibilityState() {
      return visibility;
    },
    addEventListener: (type: string, l: (e: unknown) => void) => void docListeners.set(type, [...(docListeners.get(type) ?? []), l]),
  } as unknown as Document;
  const win = {
    location: {
      href: `https://example.test${path}`,
      origin: "https://example.test",
      host: "example.test",
      pathname: path,
      search: "",
      assign: (u: string) => void assigned.push(u),
      replace: (u: string) => void assigned.push(u),
    },
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      posts.push({ url: String(input), body: String(init?.body ?? ""), keepalive: init?.keepalive === true, headers: new Headers(init?.headers) });
      return new Response(null, { status: 204 });
    },
    sessionStorage: session,
    localStorage: memoryStorage(),
    crypto: globalThis.crypto,
    navigator: {},
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    addEventListener: () => undefined,
    scrollY: 0,
  } as unknown as Window;
  const api = bootstrap(doc, win, "https://example.test/__mg/s/mg.js");
  const setHidden = (): void => {
    visibility = "hidden";
    for (const l of docListeners.get("visibilitychange") ?? []) l({});
  };
  return { win, api, posts, assigned, docListeners, setHidden, selectors, session };
}

describe("window.MorphGate (§12.1)", () => {
  it("keeps the seven Phase 1 members and adds ready, proofHeader and onBeforeNavigate", async () => {
    const { api } = page();
    expect(Object.keys(api!).sort()).toEqual(
      ["version", "config", "snapshot", "classifyResponse", "verifyUrl", "verify", "fetch", "ready", "proofHeader", "onBeforeNavigate"].sort(),
    );
    expect(Object.isFrozen(api)).toBe(true);
    await expect(api!.ready()).resolves.toBeUndefined();
    expect(api!.ready()).toBe(api!.ready());
    await expect(api!.proofHeader("GET", "/x")).resolves.toBeNull(); // no key-bound clearance
    expect(api!.config).toMatchObject({ proof: true, refresh: true, behavior: false });
  });

  it("runs onBeforeNavigate before verify() leaves the page", () => {
    const { api, assigned } = page();
    const order: string[] = [];
    api!.onBeforeNavigate(() => order.push(`cb:${assigned.length}`));
    api!.onBeforeNavigate(() => {
      throw new Error("a broken site callback");
    });
    expect(api!.verify()).toBe(true);
    expect(order).toEqual(["cb:0"]);
    expect(assigned).toEqual(["/__mg/v?ret=%2Farticles"]);
  });

  it("finds its tag by the stable alias when currentScript is null", () => {
    const { selectors } = page({ currentScript: false });
    expect(selectors[0]).toContain('script[src$="/__mg/s/mg.js"]');
  });
});

describe("background work on site pages", () => {
  it("reports a Service Worker that answers /__mg/ paths with a site page (§9.4 sw_intercept)", async () => {
    const { posts } = page({ path: "/__mg/v" });
    await until(() => posts.length === 1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ v: 1, reports: [{ kind: "sw_intercept", path: "/__mg/v" }] });
    const ordinary = page({ path: "/articles" });
    await new Promise((r) => setTimeout(r, 10));
    expect(ordinary.posts).toHaveLength(0);
  });

  it("sends the reports the previous page queued, with keepalive", async () => {
    const report = { kind: "upstream_challenge", scope: "protected_fetch", path: "/articles", count: 1 };
    const { posts, session } = page({ queued: [report] });
    await until(() => posts.length === 1);
    expect(posts[0]!.keepalive).toBe(true);
    expect(JSON.parse(posts[0]!.body).reports).toEqual([report]);
    expect(session.getItem(REPORT_QUEUE_KEY)).toBeNull();
  });

  it("collects nothing without data-mg-telemetry=\"behavior\"", async () => {
    const { posts, setHidden, docListeners } = page();
    expect(docListeners.has("pointermove")).toBe(false);
    setHidden();
    await new Promise((r) => setTimeout(r, 10));
    expect(posts).toHaveLength(0);
  });

  it("with data-mg-telemetry=\"behavior\": one summary per page, sent with keepalive when hidden (§12.8)", async () => {
    const { posts, setHidden, docListeners } = page({ dataset: { mgTelemetry: "behavior" } });
    for (const l of docListeners.get("pointermove") ?? []) {
      l({ type: "pointermove", timeStamp: 0, clientX: 1, clientY: 1 });
      l({ type: "pointermove", timeStamp: 16, clientX: 30, clientY: 1 });
    }
    setHidden();
    setHidden();
    await until(() => posts.length === 1);
    await new Promise((r) => setTimeout(r, 10));
    expect(posts).toHaveLength(1);
    expect(posts[0]!.keepalive).toBe(true);
    expect(posts[0]!.url).toBe("/__mg/t");
    const report = JSON.parse(posts[0]!.body).reports[0];
    expect(report.kind).toBe("behavior");
    expect(report.page).toBe("/articles");
    expect(report.summary.v).toBe(1);
    expect(report.summary.ptr.speed.reduce((a: number, b: number) => a + b, 0)).toBe(1);
    expect(posts[0]!.headers.get("mg-proof")).toBeNull(); // no key-bound clearance: unsigned
  });
});
