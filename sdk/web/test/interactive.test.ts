// The interactive control (docs/impl/phase2-spec.md §12.6, §7.4–§7.6, §8.3, D-41, D-65),
// driven with a minimal fake DOM, a fake clock and a scripted network (§12.10).
import { afterEach, describe, expect, it } from "vitest";
import {
  A11Y_SLOW_FIRST_MS,
  A11Y_SLOW_REPEAT_MS,
  HOLD_TOO_LONG_MS,
  InteractiveControl,
  RELOAD_DELAY_MS,
  RENEW_AFTER_MS,
  SUBMIT_TIMEOUT_MS,
  parseIx,
  type ControlDeps,
  type ControlElement,
  type InputEvent,
  type IxParams,
} from "../src/interactive";
import { COPY } from "../src/copy";
import type { EcP256PublicJwk } from "../src/crypto";
import { renewMessage, submissionMessage } from "../src/sig";
import type { PowListener } from "../src/powv2";
import { TurnstileWidget, type TurnstileRenderParams } from "../src/turnstile";
import { FakeEnv, T0, json, settle, until } from "./fakes";
import { es256Verify } from "./proofref";

const lastOf = <T>(items: readonly T[]): T => items[items.length - 1] as T;

const ZH = COPY.zh;
const C1 = "AAECAwQFBgcICQoLDA0ODw";
const C2 = "BBECAwQFBgcICQoLDA0ODw";
const C3 = "CCECAwQFBgcICQoLDA0ODw";

function rawIx(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    providers: ["self_hold", "pow_a11y"],
    hold_ms: 1500,
    offset: [-3, 5],
    min_ms: 1750,
    a11y_min_ms: 2000,
    pow: { alg: "sha256-hashcash-v2", k: 2, bits: 4, a11y_bits: 5 },
    attempt: 1,
    now_ms: T0,
    exp_ms: T0 + 600_000,
    bound: true,
    a11y_first: false,
    a11y_quota: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fake DOM

type Listener = (event: InputEvent) => void;

class FakeEl implements ControlElement {
  readonly attrs = new Map<string, string>();
  readonly listeners = new Map<string, Listener[]>();
  readonly children: FakeEl[] = [];
  readonly styleProps = new Map<string, string>();
  readonly writes: string[] = [];
  private text = "";
  style = { setProperty: (n: string, v: string) => void this.styleProps.set(n, v) };

  constructor(
    readonly id: string,
    private readonly dom: FakeDom,
  ) {}

  get textContent(): string {
    return this.text;
  }
  set textContent(value: string | null) {
    this.text = value ?? "";
    this.writes.push(this.text);
  }
  setAttribute(n: string, v: string): void {
    this.attrs.set(n, v);
  }
  removeAttribute(n: string): void {
    this.attrs.delete(n);
  }
  getAttribute(n: string): string | null {
    return this.attrs.get(n) ?? null;
  }
  addEventListener(type: string, l: (event: never) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), l as Listener]);
  }
  dispatch(type: string, event: InputEvent = {}): void {
    for (const l of this.listeners.get(type) ?? []) l({ type, isTrusted: true, ...event });
  }
  focus(): void {
    this.dom.active = this;
  }
  contains(other: unknown): boolean {
    return other === this || this.children.some((c) => c.contains(other));
  }
  getBoundingClientRect(): { left: number; top: number; width: number; height: number } {
    return { left: 100, top: 100, width: 200, height: 50 };
  }
}

class FakeDom {
  active: unknown = null;
  readonly body = new FakeEl("body", this);
  readonly el = {
    root: new FakeEl("mg-challenge", this),
    ix: new FakeEl("mg-ix", this),
    hold: new FakeEl("mg-hold", this),
    holdLabel: new FakeEl("label", this),
    fill: new FakeEl("fill", this),
    altSingle: new FakeEl("mg-alt-single", this),
    altPow: new FakeEl("mg-alt-pow", this),
    progress: new FakeEl("mg-progress", this),
    turnstile: new FakeEl("mg-turnstile", this),
    status: new FakeEl("mg-status", this),
    retry: new FakeEl("mg-retry", this),
  };
  readonly doc = new Map<string, Listener[]>();
  readonly win = new Map<string, (() => void)[]>();

  constructor() {
    this.el.hold.children.push(this.el.holdLabel, this.el.fill);
    this.el.ix.setAttribute("hidden", "");
    this.el.progress.setAttribute("hidden", "");
    this.el.turnstile.setAttribute("hidden", "");
    this.el.retry.setAttribute("hidden", "");
  }

  /** Inside the hold button's rect: the progress layer (a child) is what is under the pointer. */
  elementFromPoint = (x: number, y: number): unknown => (x >= 100 && x <= 300 && y >= 100 && y <= 150 ? this.el.fill : this.body);

  document(type: string, event: InputEvent = {}): void {
    for (const l of this.doc.get(type) ?? []) l({ type, isTrusted: true, ...event });
  }

  window(type: string): void {
    for (const l of this.win.get(type) ?? []) l();
  }

  get statusWrites(): string[] {
    return this.el.status.writes;
  }
}

// ---------------------------------------------------------------------------
// Harness

interface PowJob {
  bits: number;
  k: number;
  start: number[];
  listener: PowListener;
  stopped: boolean;
  prefix: Uint8Array;
}

interface Harness {
  fake: FakeEnv;
  dom: FakeDom;
  ctl: InteractiveControl;
  pows: PowJob[];
  posts: () => { url: string; body: Record<string, unknown> }[];
  finishPow: () => void;
  ts: { rendered: TurnstileRenderParams[]; removed: string[] };
}

async function harness(options: { ix?: Record<string, unknown>; subtle?: SubtleCrypto | null; lang?: "zh" | "en"; handler?: FakeEnv["handler"]; withTurnstile?: boolean } = {}): Promise<Harness> {
  const fake = new FakeEnv({ path: "/__mg/v?ret=%2Faccount", ...(options.subtle !== undefined ? { subtle: options.subtle } : {}) });
  const dom = new FakeDom();
  const rt = fake.runtime();
  const pows: PowJob[] = [];
  const ts = { rendered: [] as TurnstileRenderParams[], removed: [] as string[] };
  let tsLoaded = false;
  const api = {
    render: (_c: unknown, p: TurnstileRenderParams) => {
      ts.rendered.push(p);
      return `w${ts.rendered.length}`;
    },
    remove: (id: string) => void ts.removed.push(id),
    reset: () => undefined,
  };
  fake.handler =
    options.handler ??
    ((call) => {
      const path = new URL(call.url).pathname;
      if (path === "/__mg/c/renew") return json(200, { v: 2, challenge: C2, ix: rawIx({ now_ms: fake.clock.t, exp_ms: fake.clock.t + 600_000 }) });
      if (path === "/__mg/c") {
        fake.bindClearance();
        return json(200, { ok: true, ret: "/account", v: 2, now_ms: fake.clock.t });
      }
      return new Response(null, { status: 204 });
    });
  const ix = parseIx(rawIx(options.ix))!;
  expect(ix).not.toBeNull();
  const deps: ControlDeps = {
    dom: {
      ...dom.el,
      elementFromPoint: dom.elementFromPoint,
      onWindow: (type, l) => void dom.win.set(type, [...(dom.win.get(type) ?? []), l]),
      onDocument: (type, l) => void dom.doc.set(type, [...(dom.doc.get(type) ?? []), l as Listener]),
      requestFrame: null,
    },
    rt,
    page: { c: C1, ix, ret: "/account", rid: "rid-1", lang: options.lang ?? "zh", build: "0123456789abcdef" },
    startPow: (prefix, bits, k, start, listener) => {
      const job: PowJob = { bits, k, start, listener, stopped: false, prefix };
      pows.push(job);
      return {
        worker: true,
        stop: () => {
          job.stopped = true;
        },
      };
    },
    turnstileHost:
      options.withTurnstile === false
        ? null
        : {
            api: () => (tsLoaded ? api : null),
            loadScript: (_s, _n, onLoad) => {
              tsLoaded = true;
              queueMicrotask(onLoad);
            },
            setTimeout: fake.clock.setTimeout,
            clearTimeout: fake.clock.clearTimeout,
          },
    nonce: "n",
    collect: () => ({ env: null, auto: { v: 1, webdriver: false } }),
    abortController: null,
  };
  const ctl = new InteractiveControl(deps);
  await ctl.start();
  await settle();
  const finishPow = (): void => {
    const job = lastOf(pows.filter((p) => !p.stopped))!;
    const counters = Array.from({ length: job.k }, (_, i) => i + 7);
    counters.forEach((c, i) => job.listener.part(i, c));
    job.listener.done(counters);
  };
  const posts = () =>
    fake.calls
      .filter((c) => new URL(c.url).pathname === "/__mg/c")
      .map((c) => ({ url: c.url, body: JSON.parse(c.body as string) as Record<string, unknown> }));
  return { fake, dom, ctl, pows, posts, finishPow, ts };
}

const down = (h: Harness, e: InputEvent = {}): void =>
  h.dom.el.hold.dispatch("pointerdown", { isPrimary: true, pointerId: 1, pointerType: "mouse", button: 0, clientX: 200, clientY: 125, pressure: 0.5, ...e });
const up = (h: Harness, e: InputEvent = {}): void =>
  h.dom.document("pointerup", { pointerId: 1, pointerType: "mouse", clientX: 201, clientY: 126, ...e });
const click = (h: Harness, e: InputEvent = {}): void => h.dom.el.hold.dispatch("click", { detail: 1, ...e });
const tIx = (body: Record<string, unknown>): Record<string, unknown> => JSON.parse(body["t"] as string).ix;

afterEach(() => TurnstileWidget.resetForTests());

describe("parseIx (§7.2)", () => {
  it("accepts the spec's example and rejects anything that cannot drive the control", () => {
    const ok = parseIx(rawIx({ turnstile: { sitekey: "0x4AAA", action: "login", cdata: "c".repeat(43), lang: "zh-cn" } }));
    expect(ok).toMatchObject({ providers: ["self_hold", "pow_a11y"], holdMs: 1500, offset: [-3, 5], k: 2, bits: 4, a11yBits: 5 });
    expect(ok?.turnstile?.sitekey).toBe("0x4AAA");
    expect(parseIx(JSON.stringify(rawIx()))).not.toBeNull();
    expect(parseIx(rawIx({ a11y_min_ms: undefined }))?.a11yMinMs).toBe(0);
    for (const bad of [
      { v: 2 },
      { providers: [] },
      { providers: ["self_hold", "self_hold"] },
      { providers: ["slider"] },
      { pow: { alg: "sha256-hashcash-v1", k: 1, bits: 4, a11y_bits: 4 } },
      { pow: { alg: "sha256-hashcash-v2", k: 9, bits: 4, a11y_bits: 4 } },
      { hold_ms: -1 },
      { offset: [1] },
      { now_ms: "1" },
    ]) {
      expect(parseIx(rawIx(bad))).toBeNull();
    }
    expect(parseIx("{")).toBeNull();
    expect(parseIx(null)).toBeNull();
    // A malformed turnstile member is dropped, not fatal.
    expect(parseIx(rawIx({ turnstile: { sitekey: "<x>" } }))?.turnstile).toBeNull();
  });
});

describe("start", () => {
  it("shows the control, clears #mg-status, offsets the button by margin only, keeps focus where it is", async () => {
    const h = await harness();
    expect(h.dom.el.ix.getAttribute("hidden")).toBeNull();
    expect(h.dom.el.root.getAttribute("data-mg-phase")).toBe("ix");
    expect(h.dom.statusWrites).toEqual([""]);
    expect([...h.dom.el.hold.styleProps]).toEqual([["margin", "5px 3px -5px -3px"]]);
    expect(h.dom.active).toBeNull();
    expect(h.pows).toHaveLength(1); // a bound C: the self_hold PoW starts at once
    expect(h.pows[0]).toMatchObject({ bits: 4, k: 2, start: [0, 0] });
  });

  it("without WebCrypto the control says so, with the request ID", async () => {
    const h = await harness({ subtle: null });
    expect(h.ctl.state).toBe("BROKEN");
    expect(lastOf(h.dom.statusWrites)).toBe(`${ZH.unsupported} · ${ZH.requestId}rid-1`);
    click(h);
    expect(h.ctl.state).toBe("BROKEN");
  });
});

describe("pointer hold (D-65, WCAG 2.5.2)", () => {
  it("submits on release inside after hold_ms, then navigates with location.replace", async () => {
    const h = await harness();
    const before: string[] = [];
    h.ctl["deps"].rt.onBeforeNavigate(() => before.push("cb"));
    down(h);
    expect(h.ctl.state).toBe("HOLDING");
    await h.fake.clock.advance(1500);
    expect(h.dom.statusWrites.slice(1)).toEqual([ZH.keepHolding, ZH.letGo]);
    up(h);
    click(h); // the click of the same press is ignored
    expect(h.ctl.state).toBe("FINISHING");
    h.finishPow();
    await h.fake.clock.advance(1750 + 100);
    await until(() => h.fake.navigations.length === 1);
    const [post] = h.posts();
    expect(post!.body).toMatchObject({ v: 2, type: "interactive", c: C1, p: "self_hold", pp: "", pow: { counters: [7, 8] }, ret: "/account", build: "0123456789abcdef" });
    const ix = tIx(post!.body);
    expect(ix).toMatchObject({ v: 1, mode: "hold", modality: "mouse", locale: "zh-CN", ks: "local", trusted: 3, fallback: null });
    expect((ix["hold"] as { ms: number }).ms).toBe(1500);
    expect(ix["single"]).toBeUndefined();
    // The signature covers the body as sent.
    const b = post!.body as { c: string; type: string; p: string; pp: string; t: string; ret: string; ts: number; build: string; jwk: EcP256PublicJwk; sig: string };
    const msg = submissionMessage({ c: b.c, type: b.type, p: b.p, pp: b.pp, t: b.t, counters: [7, 8], ret: b.ret, ts: b.ts, build: b.build });
    expect(await es256Verify(b.jwk, msg, b.sig)).toBe(true);
    expect(h.dom.statusWrites.slice(-3)).toEqual([ZH.finishing, ZH.verifying, ZH.verified]);
    expect(before).toEqual(["cb"]);
    expect(h.fake.navigations).toEqual(["replace /account"]);
  });

  it("never submits before receipt + min_ms + 100 ms", async () => {
    const h = await harness();
    h.finishPow();
    down(h);
    await h.fake.clock.advance(1500);
    up(h);
    await settle();
    expect(h.posts()).toHaveLength(0);
    await h.fake.clock.advance(349);
    expect(h.posts()).toHaveLength(0);
    await h.fake.clock.advance(1);
    await until(() => h.posts().length === 1);
  });

  it("aborts without submitting: release outside, pointer leaves, blur, hidden page", async () => {
    const aborts: ((h: Harness) => void)[] = [
      (h) => up(h, { clientX: 10, clientY: 10 }),
      (h) => h.dom.document("pointermove", { pointerId: 1, clientX: 400, clientY: 125 }),
      (h) => h.dom.window("blur"),
      (h) => h.fake.setVisible(false),
    ];
    for (const abort of aborts) {
      const h = await harness();
      h.finishPow();
      down(h);
      await h.fake.clock.advance(1600);
      abort(h);
      expect(h.ctl.state).toBe("READY");
      expect(lastOf(h.dom.statusWrites)).toBe(ZH.holdLonger);
      expect(h.dom.el.hold.getAttribute("data-mg-fill")).toBe("0");
      up(h);
      await h.fake.clock.advance(5_000);
      expect(h.posts()).toHaveLength(0);
    }
  });

  it("moving over the progress layer stays inside", async () => {
    const h = await harness();
    down(h);
    h.dom.document("pointermove", { pointerId: 1, clientX: 290, clientY: 140 });
    expect(h.ctl.state).toBe("HOLDING");
  });

  it("pointercancel without movement suggests clicking and counts the cancel", async () => {
    const h = await harness();
    down(h, { pointerType: "touch" });
    h.dom.document("pointercancel", { pointerId: 1 });
    expect(h.ctl.state).toBe("READY");
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.cantHold);
    down(h, { pointerType: "touch" });
    await h.fake.clock.advance(1500);
    up(h, { pointerType: "touch" });
    h.finishPow();
    await h.fake.clock.advance(2000);
    await until(() => h.posts().length === 1);
    const ix = tIx(h.posts()[0]!.body);
    expect(ix["modality"]).toBe("touch");
    expect((ix["hold"] as { cancels: number }).cancels).toBe(1);
  });

  it("ignores non-primary pointers and secondary mouse buttons", async () => {
    const h = await harness();
    down(h, { isPrimary: false });
    down(h, { button: 2 });
    expect(h.ctl.state).toBe("READY");
    h.dom.el.hold.dispatch("contextmenu", { preventDefault: () => h.dom.statusWrites.push("prevented") });
    expect(lastOf(h.dom.statusWrites)).toBe("prevented");
  });

  it("a hold released after 28 s returns to READY with the click hint, and its click is ignored", async () => {
    const h = await harness();
    h.finishPow();
    down(h);
    await h.fake.clock.advance(HOLD_TOO_LONG_MS + 1);
    up(h);
    click(h);
    expect(h.ctl.state).toBe("READY");
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.tooLong);
    await h.fake.clock.advance(5_000);
    expect(h.posts()).toHaveLength(0);
  });

  it("an early release followed by no click asks to hold longer", async () => {
    const h = await harness();
    down(h);
    await h.fake.clock.advance(300);
    up(h);
    await h.fake.clock.advance(0);
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.holdLonger);
    expect(h.ctl.state).toBe("READY");
  });
});

describe("single activation (D-65) and click classification", () => {
  it("a screen-reader style press, release and click enters WAITING and completes without a second press", async () => {
    const h = await harness();
    down(h, { pointerType: "touch" });
    up(h, { pointerType: "touch" });
    click(h, { detail: 0 });
    expect(h.ctl.state).toBe("WAITING");
    expect(h.dom.el.hold.getAttribute("aria-disabled")).toBe("true");
    h.finishPow();
    await h.fake.clock.advance(1500);
    await h.fake.clock.advance(400);
    await until(() => h.posts().length === 1);
    const ix = tIx(h.posts()[0]!.body);
    expect(ix).toMatchObject({ mode: "single", modality: "touch" });
    expect(ix["hold"]).toBeUndefined();
    expect((ix["single"] as { wait_ms: number }).wait_ms).toBeGreaterThanOrEqual(1500);
    // One status write per transition: no "hold longer" for the short press.
    expect(h.dom.statusWrites.slice(1, 3)).toEqual([ZH.keepHolding, ZH.singleWait]);
  });

  it("keyboard: Enter's auto-repeat produces one WAITING", async () => {
    const h = await harness();
    h.dom.el.hold.dispatch("keydown", { key: "Enter" });
    click(h, { detail: 0 });
    h.dom.el.hold.dispatch("keydown", { key: "Enter", repeat: true });
    click(h, { detail: 0 });
    click(h, { detail: 0 });
    expect(h.dom.statusWrites.filter((w) => w === ZH.singleWait)).toHaveLength(1);
    h.finishPow();
    await h.fake.clock.advance(2_000);
    await until(() => h.posts().length === 1);
    expect(tIx(h.posts()[0]!.body)).toMatchObject({ mode: "single", modality: "keyboard" });
  });

  it("an auto-repeated Enter on 'Use press and hold instead' does not start a single activation", async () => {
    const h = await harness();
    h.dom.el.altPow.dispatch("click", {});
    h.dom.el.hold.dispatch("keydown", { key: "Enter" });
    click(h, { detail: 0 });
    expect(h.ctl.state).toBe("READY");
    h.dom.el.hold.dispatch("keydown", { key: "Enter", repeat: true });
    click(h, { detail: 0 });
    expect(h.ctl.state).toBe("READY");
    h.dom.el.hold.dispatch("keydown", { key: "Enter" });
    click(h, { detail: 0 });
    expect(h.ctl.state).toBe("WAITING");
  });

  it("#mg-alt-single moves focus to #mg-hold, renames it and starts waiting", async () => {
    const h = await harness();
    h.dom.el.altSingle.dispatch("click", { detail: 0 });
    expect(h.dom.active).toBe(h.dom.el.hold);
    expect(h.dom.el.holdLabel.textContent).toBe(ZH.singleLabel);
    expect(h.ctl.state).toBe("WAITING");
  });

  it("an untrusted activation is never submitted", async () => {
    const h = await harness();
    click(h, { isTrusted: false, detail: 0 });
    h.finishPow();
    await h.fake.clock.advance(3_000);
    expect(h.posts()).toHaveLength(0);
    expect(h.ctl.state).toBe("READY");
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.failed);
  });
});

describe("pow_a11y", () => {
  it("shows determinate progress, announces slowness at 10 s then at most every 30 s, and submits pow_a11y", async () => {
    const h = await harness();
    h.dom.el.altPow.dispatch("click", {});
    expect(h.ctl.state).toBe("POW_ONLY");
    expect(h.dom.el.progress.getAttribute("hidden")).toBeNull();
    expect(h.dom.el.progress.getAttribute("aria-valuemax")).toBe("2");
    expect(h.dom.el.progress.getAttribute("aria-valuenow")).toBe("0");
    expect(h.dom.el.altPow.getAttribute("aria-disabled")).toBe("true");
    expect(h.dom.el.holdLabel.textContent).toBe(ZH.backToHold);
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.a11yWait);
    // Restarted at the a11y difficulty.
    expect(lastOf(h.pows)!.bits).toBe(5);
    expect(h.pows[0]!.stopped).toBe(true);
    await h.fake.clock.advance(A11Y_SLOW_FIRST_MS);
    expect(h.dom.statusWrites.filter((w) => w === ZH.a11ySlow)).toHaveLength(1);
    await h.fake.clock.advance(A11Y_SLOW_REPEAT_MS - 1);
    expect(h.dom.statusWrites.filter((w) => w === ZH.a11ySlow)).toHaveLength(1);
    await h.fake.clock.advance(1);
    expect(h.dom.statusWrites.filter((w) => w === ZH.a11ySlow)).toHaveLength(2);
    const job = lastOf(h.pows)!;
    job.listener.part(0, 7);
    expect(h.dom.el.progress.getAttribute("aria-valuenow")).toBe("1");
    expect(h.dom.el.progress.styleProps.get("--mg-p")).toBe("0.5");
    job.listener.part(1, 8);
    job.listener.done([7, 8]);
    await until(() => h.posts().length === 1);
    const body = h.posts()[0]!.body;
    expect(body["p"]).toBe("pow_a11y");
    expect(tIx(body)).toMatchObject({ mode: "pow_only" });
  });

  it("'Use press and hold instead' returns to READY with the self_hold difficulty", async () => {
    const h = await harness();
    h.dom.el.altPow.dispatch("click", {});
    click(h);
    expect(h.ctl.state).toBe("READY");
    expect(h.dom.el.holdLabel.textContent).toBe(ZH.holdLabel);
    expect(h.dom.el.progress.getAttribute("hidden")).toBe("");
    expect(h.dom.el.altPow.getAttribute("aria-disabled")).toBeNull();
    expect(lastOf(h.pows)!.bits).toBe(4);
  });

  it("a11y_first enters POW_ONLY after binding; a11y_quota disables the automatic path", async () => {
    const first = await harness({ ix: { providers: ["pow_a11y", "self_hold"], a11y_first: true } });
    expect(first.ctl.state).toBe("POW_ONLY");
    expect(lastOf(first.dom.statusWrites)).toBe(ZH.a11yWait);
    const quota = await harness({ ix: { a11y_quota: true } });
    expect(quota.dom.el.ix.getAttribute("data-mg-a11y-quota")).toBe("1");
    expect(quota.dom.el.altPow.getAttribute("aria-disabled")).toBe("true");
    quota.dom.el.altPow.dispatch("click", {});
    expect(quota.ctl.state).toBe("READY");
  });
});

describe("binding and renewal (D-41, §7.4)", () => {
  it("renews an unbound C before the PoW, signs it, and accepts input meanwhile", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const fake0: { t?: number } = {};
    const h = await harness({
      ix: { bound: false },
      handler: async (call) => {
        const path = new URL(call.url).pathname;
        if (path === "/__mg/c/renew") {
          await gate;
          return json(200, { v: 2, challenge: C2, ix: rawIx({ now_ms: fake0.t ?? T0 }) });
        }
        return json(200, { ok: true, ret: "/account" });
      },
    });
    expect(h.pows).toHaveLength(0);
    const [renew] = h.fake.callsTo("/__mg/c/renew");
    const body = JSON.parse(renew!.body as string);
    expect(Object.keys(body)).toEqual(["v", "c", "jwk", "ts", "sig"]);
    expect(body.c).toBe(C1);
    expect(await es256Verify(body.jwk, renewMessage(C1, body.ts), body.sig)).toBe(true);
    down(h); // input during binding: progress as usual
    expect(h.ctl.state).toBe("HOLDING");
    release();
    await until(() => h.pows.length === 1);
    expect(h.ctl.currentC).toBe(C2);
    expect(h.dom.statusWrites.slice(1)).toEqual([ZH.keepHolding]); // renewal writes nothing
  });

  it("a binding renewal lost on the network keeps the old C", async () => {
    const h = await harness({
      ix: { bound: false },
      handler: () => {
        throw new TypeError("network");
      },
    });
    await until(() => h.pows.length === 1);
    expect(h.ctl.currentC).toBe(C1);
  });

  it("renews after iat + 480 s while READY and swaps the C, without touching #mg-status", async () => {
    const h = await harness();
    const writes = h.dom.statusWrites.length;
    await h.fake.clock.advance(RENEW_AFTER_MS);
    await until(() => h.fake.callsTo("/__mg/c/renew").length === 1);
    await until(() => h.ctl.currentC === C2);
    expect(h.dom.statusWrites).toHaveLength(writes);
    expect(lastOf(h.pows)!.prefix).not.toEqual(h.pows[0]!.prefix);
  });

  it.each([
    ["403 without a C", () => json(403, { v: 2, error: "mg_challenge_failed", retry: true }, { "mg-error": "mg_challenge_failed" })],
    ["404 (schema 1 Edge)", () => new Response("nf", { status: 404 })],
  ])("%s reloads", async (_name, answer) => {
    const h = await harness({ handler: (call) => (new URL(call.url).pathname === "/__mg/c/renew" ? answer() : new Response("")) });
    await h.fake.clock.advance(RENEW_AFTER_MS);
    await until(() => h.fake.navigations.length === 1);
    expect(h.fake.navigations).toEqual([`replace ${h.fake.location.href}`]);
  });

  it("Cloudflare's challenge on a renewal never reloads: report, stop renewing, keep the C", async () => {
    const h = await harness({
      ix: { bound: false },
      handler: (call) =>
        new URL(call.url).pathname === "/__mg/t"
          ? new Response(null, { status: 204 })
          : new Response("<html>", { status: 403, headers: { "cf-mitigated": "challenge" } }),
    });
    await until(() => h.pows.length === 1);
    expect(h.ctl.currentC).toBe(C1);
    await until(() => h.fake.callsTo("/__mg/t").length === 1);
    expect(JSON.parse(h.fake.callsTo("/__mg/t")[0]!.body as string).reports).toEqual([
      { kind: "upstream_challenge", scope: "mg_endpoint", path: "/__mg/v", count: 1 },
    ]);
    await h.fake.clock.advance(RENEW_AFTER_MS);
    await settle();
    expect(h.fake.callsTo("/__mg/c/renew")).toHaveLength(1);
    expect(h.fake.navigations).toEqual([]);
  });

  it("429 waits Retry-After, retries once, then reloads", async () => {
    const h = await harness({
      handler: () => new Response("{}", { status: 429, headers: { "retry-after": "7", "mg-error": "mg_rate_limited", "content-type": "application/json" } }),
    });
    await h.fake.clock.advance(RENEW_AFTER_MS);
    await until(() => h.fake.callsTo("/__mg/c/renew").length === 1);
    await h.fake.clock.advance(6_999);
    expect(h.fake.callsTo("/__mg/c/renew")).toHaveLength(1);
    await h.fake.clock.advance(1);
    await until(() => h.fake.callsTo("/__mg/c/renew").length === 2);
    await until(() => h.fake.navigations.length === 1);
  });

  it("a page coming back after iat + 480 s renews before accepting input", async () => {
    const h = await harness();
    h.fake.setVisible(false);
    h.fake.clock.t += RENEW_AFTER_MS + 1;
    h.fake.setVisible(true);
    down(h);
    expect(h.ctl.state).toBe("READY");
    await until(() => h.ctl.currentC === C2);
    down(h);
    expect(h.ctl.state).toBe("HOLDING");
  });
});

describe("submission outcomes (§12.6)", () => {
  async function submitWith(answer: (fake: FakeEnv) => Response | Promise<Response>): Promise<Harness> {
    let fakeRef!: FakeEnv;
    const h = await harness({
      handler: (call) => (new URL(call.url).pathname === "/__mg/c" ? answer(fakeRef) : json(200, { challenge: C3, ix: rawIx() })),
    });
    fakeRef = h.fake;
    h.dom.el.hold.focus();
    click(h, { detail: 0 });
    h.finishPow();
    await h.fake.clock.advance(1900);
    await until(() => h.posts().length === 1);
    await settle();
    return h;
  }

  it("403 with a new C resets the control in place: status, focus, new C, new PoW", async () => {
    const h = await submitWith(() =>
      json(403, { v: 2, error: "mg_challenge_failed", retry: true, type: "interactive", challenge: C3, ix: rawIx({ attempt: 2 }) }, { "mg-error": "mg_challenge_failed" }),
    );
    expect(h.ctl.state).toBe("READY");
    expect(h.ctl.currentC).toBe(C3);
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.failed);
    expect(h.dom.active).toBe(h.dom.el.hold);
    expect(h.dom.el.hold.getAttribute("aria-disabled")).toBeNull();
    // A second attempt submits the new C, never the old one.
    click(h, { detail: 0 });
    h.finishPow();
    await h.fake.clock.advance(1900);
    await until(() => h.posts().length === 2);
    expect(h.posts().map((p) => p.body["c"])).toEqual([C1, C3]);
  });

  it("403 with an unbound new C binds it first", async () => {
    const h = await submitWith(() =>
      json(403, { v: 2, error: "mg_challenge_failed", retry: true, type: "interactive", challenge: C3, ix: rawIx({ bound: false }) }, { "mg-error": "mg_challenge_failed" }),
    );
    await until(() => h.fake.callsTo("/__mg/c/renew").length === 1);
    expect(JSON.parse(h.fake.callsTo("/__mg/c/renew")[0]!.body as string).c).toBe(C3);
  });

  it("403 without a C reloads", async () => {
    const h = await submitWith(() => json(403, { v: 2, error: "mg_challenge_failed", retry: true }, { "mg-error": "mg_challenge_failed" }));
    expect(h.fake.navigations).toEqual([`replace ${h.fake.location.href}`]);
  });

  it("429: 'try again later', wait Retry-After, 'you can try again now', then reload; focus stays", async () => {
    const h = await submitWith(() => new Response("{}", { status: 429, headers: { "retry-after": "20", "mg-error": "mg_rate_limited", "content-type": "application/json" } }));
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.later);
    expect(h.dom.active).toBe(h.dom.el.hold);
    await h.fake.clock.advance(20_000);
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.retryNow);
    expect(h.fake.navigations).toEqual([]);
    await h.fake.clock.advance(RELOAD_DELAY_MS);
    expect(h.fake.navigations).toEqual([`replace ${h.fake.location.href}`]);
  });

  it("no answer in 15 s or a network error: 'connection problem', then reload; the C is never resent", async () => {
    const slow = await submitWith(() => new Promise<Response>(() => undefined));
    await slow.fake.clock.advance(SUBMIT_TIMEOUT_MS);
    expect(lastOf(slow.dom.statusWrites)).toBe(ZH.network);
    await slow.fake.clock.advance(RELOAD_DELAY_MS);
    expect(slow.fake.navigations).toHaveLength(1);
    expect(slow.posts()).toHaveLength(1);

    const broken = await submitWith(() => {
      throw new TypeError("network");
    });
    expect(lastOf(broken.dom.statusWrites)).toBe(ZH.network);
    await broken.fake.clock.advance(RELOAD_DELAY_MS);
    expect(broken.fake.navigations).toHaveLength(1);
  });

  it("200 without __Host-mg_st: cookies are blocked, no navigation", async () => {
    const h = await submitWith(() => json(200, { ok: true, ret: "/account" }));
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.cookies);
    expect(h.fake.navigations).toEqual([]);
  });

  it("English pages use the English copy", async () => {
    const h = await harness({ lang: "en" });
    click(h, { detail: 0 });
    expect(lastOf(h.dom.statusWrites)).toBe(COPY.en.singleWait);
  });
});

describe("Turnstile in the control (§8.3)", () => {
  const ts = { sitekey: "0x4AAA", action: "login", cdata: "c".repeat(43), lang: "zh-cn" };

  it("Turnstile first: EXTERNAL, token submits p=turnstile with pp=token", async () => {
    const h = await harness({ ix: { providers: ["turnstile", "self_hold", "pow_a11y"], turnstile: ts } });
    await settle();
    expect(h.ctl.state).toBe("EXTERNAL");
    expect(lastOf(h.dom.statusWrites)).toBe(ZH.external);
    expect(h.dom.el.holdLabel.textContent).toBe(ZH.backToHold);
    expect(h.dom.el.turnstile.getAttribute("hidden")).toBeNull();
    await until(() => h.ts.rendered.length === 1);
    expect(h.ts.rendered[0]!.cData).toBe(ts.cdata);
    h.finishPow();
    h.ts.rendered[0]!.callback("tok");
    await h.fake.clock.advance(2_000);
    await until(() => h.posts().length === 1);
    expect(h.posts()[0]!.body).toMatchObject({ p: "turnstile", pp: "tok" });
    expect(tIx(h.posts()[0]!.body)).toMatchObject({ mode: "external" });
  });

  it("an error falls back to the next provider and the reason is reported", async () => {
    const h = await harness({ ix: { providers: ["turnstile", "self_hold", "pow_a11y"], turnstile: ts } });
    await until(() => h.ts.rendered.length === 1);
    h.ts.rendered[0]!["error-callback"]("110100");
    expect(h.ctl.state).toBe("READY");
    expect(h.dom.el.turnstile.getAttribute("hidden")).toBe("");
    expect(h.ts.removed).toEqual(["w1"]);
    click(h, { detail: 0 });
    h.finishPow();
    await h.fake.clock.advance(2_000);
    await until(() => h.posts().length === 1);
    expect(h.posts()[0]!.body["p"]).toBe("self_hold");
    expect(tIx(h.posts()[0]!.body)["fallback"]).toBe("ts_config");
  });

  it("'Use press and hold instead' leaves Turnstile without consuming anything", async () => {
    const h = await harness({ ix: { providers: ["turnstile", "self_hold", "pow_a11y"], turnstile: ts } });
    await until(() => h.ts.rendered.length === 1);
    click(h);
    expect(h.ctl.state).toBe("READY");
    expect(h.posts()).toHaveLength(0);
  });

  it("a renewal re-renders the widget with the new cData", async () => {
    const h = await harness({ ix: { providers: ["turnstile", "self_hold", "pow_a11y"], turnstile: ts } });
    await until(() => h.ts.rendered.length === 1);
    h.fake.handler = () =>
      json(200, { v: 2, challenge: C2, ix: rawIx({ providers: ["turnstile", "self_hold", "pow_a11y"], turnstile: { ...ts, cdata: "d".repeat(43) }, now_ms: h.fake.clock.t }) });
    await h.fake.clock.advance(RENEW_AFTER_MS);
    await until(() => h.ts.rendered.length === 2);
    expect(h.ts.removed).toContain("w1");
    expect(h.ts.rendered[1]!.cData).toBe("d".repeat(43));
  });
});

describe("telemetry shape (§7.6)", () => {
  it("hold telemetry stays within the decoder's bounds", async () => {
    const h = await harness();
    for (let i = 0; i < 20; i++) h.dom.document("pointermove", { clientX: 10 + i * 9, clientY: 20 + i * 5 });
    h.dom.el.hold.dispatch("pointerenter", {});
    down(h);
    h.dom.document("pointermove", { pointerId: 1, clientX: 203, clientY: 126, pressure: 0.6 });
    await h.fake.clock.advance(1600);
    up(h);
    const ix = h.ctl.telemetry() as unknown as Record<string, Record<string, unknown>>;
    const bucket = (v: unknown): boolean => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 31;
    for (const k of ["moves", "path_px", "speed_mean", "speed_sd", "dir_changes", "render_to_input_ms", "to_target_ms"]) expect(bucket(ix["pre"]![k]), k).toBe(true);
    expect(ix["pre"]!["moves"]).toBe(5); // 20 moves -> bucket 5
    expect(ix["pre"]!["straight"]).toBe(1);
    const hold = ix["hold"]!;
    expect(hold["ms"]).toBe(1600);
    expect(hold["offset"]).toEqual([0, 0.0]);
    expect(hold["pressure"]).toBe(0.5);
    expect(hold["pressure_var"]).toBe(1);
    expect(Number.isInteger((ix as unknown as { act_ms: number }).act_ms / 100)).toBe(true);
    expect((ix as unknown as { sv: string }).sv).toMatch(/^[0-9A-Za-z.+-]{1,16}$/);
  });
});

void (null as unknown as IxParams);
