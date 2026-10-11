// Turnstile loading and fallback with a fake `turnstile` object (docs/impl/phase2-spec.md §8.3, D-52, D-70).
// Nothing here reaches Cloudflare.
import { afterEach, describe, expect, it } from "vitest";
import {
  TS_LOAD_TIMEOUT_MS,
  TURNSTILE_API_URL,
  TurnstileWidget,
  tsErrorClass,
  type TsFallback,
  type TurnstileApi,
  type TurnstileHost,
  type TurnstileRenderParams,
} from "../src/turnstile";
import { FakeClock, settle } from "./fakes";

const lastOf = <T>(items: readonly T[]): T => items[items.length - 1] as T;

const PARAMS = { sitekey: "0x4AAAAAAAtest", action: "login", cdata: "c".repeat(43), lang: "zh-cn" };

class FakeTurnstile implements TurnstileApi {
  rendered: { container: unknown; params: TurnstileRenderParams }[] = [];
  removed: string[] = [];
  resets: string[] = [];
  render(container: unknown, params: TurnstileRenderParams): string {
    this.rendered.push({ container, params });
    return `w${this.rendered.length}`;
  }
  remove(id: string): void {
    this.removed.push(id);
  }
  reset(id: string): void {
    this.resets.push(id);
  }
  get last(): TurnstileRenderParams {
    return lastOf(this.rendered)!.params;
  }
}

function host(mode: "ok" | "error" | "hang" | "preloaded" = "ok") {
  const clock = new FakeClock();
  const api = new FakeTurnstile();
  let loaded = mode === "preloaded";
  const scripts: { src: string; nonce: string | null }[] = [];
  const h: TurnstileHost = {
    api: () => (loaded ? api : null),
    loadScript: (src, nonce, onLoad, onError) => {
      scripts.push({ src, nonce });
      if (mode === "ok") {
        loaded = true;
        queueMicrotask(onLoad);
      } else if (mode === "error") {
        queueMicrotask(onError);
      }
    },
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
  };
  return { h, api, clock, scripts };
}

function callbacks() {
  const tokens: string[] = [];
  const fallbacks: TsFallback[] = [];
  return { tokens, fallbacks, cb: { token: (t: string) => void tokens.push(t), fallback: (r: TsFallback) => void fallbacks.push(r) } };
}

afterEach(() => TurnstileWidget.resetForTests());

describe("Turnstile loading and rendering (§8.3)", () => {
  it("adds the nonce'd api.js once and renders explicitly with the §8.3 parameters", async () => {
    const { h, api, scripts } = host();
    const { tokens, fallbacks, cb } = callbacks();
    const container = { id: "mg-turnstile" };
    await new TurnstileWidget(h, "n0nce").start(container, 320, PARAMS, cb);
    expect(scripts).toEqual([{ src: TURNSTILE_API_URL, nonce: "n0nce" }]);
    expect(TURNSTILE_API_URL).toBe("https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit");
    expect(api.rendered[0]!.container).toBe(container);
    const p = api.last;
    expect({ ...p, callback: 0, "error-callback": 0, "unsupported-callback": 0, "expired-callback": 0 }).toEqual({
      sitekey: PARAMS.sitekey,
      action: "login",
      cData: PARAMS.cdata,
      language: "zh-cn",
      appearance: "interaction-only",
      execution: "render",
      "response-field": false,
      theme: "auto",
      retry: "auto",
      "refresh-expired": "auto",
      callback: 0,
      "error-callback": 0,
      "unsupported-callback": 0,
      "expired-callback": 0,
    });
    p.callback("tok-1");
    expect(tokens).toEqual(["tok-1"]);
    p["expired-callback"]();
    expect(fallbacks).toEqual([]);
    // A second widget on the page does not load api.js again.
    await new TurnstileWidget(h, "n0nce").start(container, 320, PARAMS, cb);
    expect(scripts).toHaveLength(1);
  });

  it("uses size compact in a container narrower than 300 px", async () => {
    const { h, api } = host("preloaded");
    await new TurnstileWidget(h, null).start({}, 299, PARAMS, callbacks().cb);
    expect(api.last.size).toBe("compact");
    await new TurnstileWidget(h, null).start({}, 300, PARAMS, callbacks().cb);
    expect(api.last.size).toBeUndefined();
  });

  it("falls back with ts_load_timeout when api.js is not ready within 5 s or fails to load", async () => {
    const slow = host("hang");
    const a = callbacks();
    const started = new TurnstileWidget(slow.h, null).start({}, 320, PARAMS, a.cb);
    await slow.clock.advance(TS_LOAD_TIMEOUT_MS - 1);
    expect(a.fallbacks).toEqual([]);
    await slow.clock.advance(1);
    await started;
    expect(a.fallbacks).toEqual(["ts_load_timeout"]);
    TurnstileWidget.resetForTests();
    const broken = host("error");
    const b = callbacks();
    await new TurnstileWidget(broken.h, null).start({}, 320, PARAMS, b.cb);
    expect(b.fallbacks).toEqual(["ts_load_timeout"]);
  });

  it("unsupported-callback falls back with ts_unsupported, once", async () => {
    const { h, api } = host("preloaded");
    const { fallbacks, tokens, cb } = callbacks();
    await new TurnstileWidget(h, null).start({}, 320, PARAMS, cb);
    api.last["unsupported-callback"]();
    api.last["unsupported-callback"]();
    api.last.callback("late");
    expect(fallbacks).toEqual(["ts_unsupported"]);
    expect(tokens).toEqual([]);
    expect(api.removed).toEqual(["w1"]);
  });

  it.each(["110100", "110200", "110999", "400020", "400070", 200100])("error %s is a configuration problem: ts_config at once", async (code) => {
    const { h, api } = host("preloaded");
    const { fallbacks, cb } = callbacks();
    await new TurnstileWidget(h, null).start({}, 320, PARAMS, cb);
    expect(api.last["error-callback"](code)).toBe(true);
    expect(fallbacks).toEqual(["ts_config"]);
    expect(api.resets).toEqual([]);
  });

  it.each(["110600", "110620", "200500", "300010", "300030", "600010", "106010"])("error %s: one reset, then ts_error", async (code) => {
    const { h, api } = host("preloaded");
    const { fallbacks, cb } = callbacks();
    await new TurnstileWidget(h, null).start({}, 320, PARAMS, cb);
    api.last["error-callback"](code);
    expect(api.resets).toEqual(["w1"]);
    expect(fallbacks).toEqual([]);
    api.last["error-callback"](code);
    expect(fallbacks).toEqual(["ts_error"]);
  });

  it("tsErrorClass", () => {
    expect(tsErrorClass("110600")).toBe("retry");
    expect(tsErrorClass("110620")).toBe("retry");
    expect(tsErrorClass("110100")).toBe("config");
    expect(tsErrorClass(400020)).toBe("config");
    expect(tsErrorClass("200100")).toBe("config");
    expect(tsErrorClass("x")).toBe("retry");
  });

  it("a removed widget never reports again", async () => {
    const { h, api } = host("preloaded");
    const { fallbacks, tokens, cb } = callbacks();
    const w = new TurnstileWidget(h, null);
    await w.start({}, 320, PARAMS, cb);
    w.remove();
    api.last.callback("t");
    api.last["error-callback"]("110100");
    await settle();
    expect(tokens).toEqual([]);
    expect(fallbacks).toEqual([]);
  });
});
