/**
 * The interactive control on challenge page template v2
 * (docs/impl/phase2-spec.md §12.6, §7.2–§7.6, §8.3, D-41, D-65).
 *
 * States:
 *
 *   READY ──primary pointerdown on #mg-hold──> HOLDING ──pointerup inside, held >= hold_ms──> FINISHING ──pow──> SUBMITTING
 *   HOLDING ──early pointerup / pointercancel / pointer leaves / blur / hidden──> READY   (a status message, not a failure)
 *   READY ──click on #mg-hold (keyboard, screen reader, short press) or #mg-alt-single──> WAITING ──hold_ms, pow──> SUBMITTING
 *   READY ──#mg-alt-pow, or ix.a11y_first after binding──> POW_ONLY ──pow──> SUBMITTING
 *   READY (Turnstile first) ──> EXTERNAL ──token──> SUBMITTING;  errors -> next provider (§8.3)
 *   SUBMITTING ──200──> DONE (location.replace(ret)) | 403 + new C ──> READY (rebinding an unbound C first)
 *   SUBMITTING ──403 without C / 429 / no answer in 15 s / network error──> RELOAD
 *
 * Binding (D-41) is not a UI state: an unbound C (`ix.bound = false`) is
 * renewed once before anything else, input is accepted meanwhile, and the
 * PoW starts when the renewal returns (with the old C if the network
 * failed). Renewal (§7.4) happens after `iat + 480 s` in READY or EXTERNAL,
 * before a PoW starts on a C with less than 120 s left, and before input
 * when a hidden page comes back after `iat + 480 s`. No renewal outcome
 * writes `#mg-status`.
 *
 * Accessibility (§12.6, WCAG 2.1.1, 2.5.2, 4.1.3): every visible state text
 * is written to `#mg-status` once per transition; the control's nodes are
 * never replaced; busy states use `aria-disabled` and ignore activation, so
 * focus is never on a disabled or hidden element; focus moves only when
 * `#mg-alt-single` hands it to `#mg-hold`.
 *
 * Every browser dependency comes through `ControlDeps`, so the state machine
 * runs under vitest with a minimal fake DOM and a fake clock.
 */

import { COPY, type CopyKey, type Lang } from "./copy";
import type { SessionKey } from "./keystore";
import { logBucket, roundToStep } from "./behavior";
import { POW_ALG_V2, powPrefixV2, subPuzzleBits, type PowListener, type PowRun } from "./powv2";
import type { Runtime } from "./runtime";
import { signedRenew, signedSubmission } from "./submit";
import {
  encodeSubmissionTelemetry,
  type Fallback,
  type IxMode,
  type IxTelemetry,
  type Modality,
  type SubmissionTelemetry,
} from "./telemetry";
import { TurnstileWidget, type TsFallback, type TurnstileHost } from "./turnstile";
import { detectUpstreamChallenge, isSealedChallengeToken, isJsonContentType, retryAfterOf } from "./transport";
import { SDK_VERSION } from "./version";
import type { AutomationSummary } from "./automation";
import type { EnvSummary } from "./env";

export type Provider = "self_hold" | "pow_a11y" | "turnstile";
export type ControlState =
  | "READY"
  | "HOLDING"
  | "FINISHING"
  | "WAITING"
  | "POW_ONLY"
  | "EXTERNAL"
  | "SUBMITTING"
  | "DONE"
  | "RELOAD"
  | "BROKEN";

export const RENEW_AFTER_MS = 480_000;
export const MIN_LIFETIME_FOR_POW_MS = 120_000;
export const SUBMIT_TIMEOUT_MS = 15_000;
export const HOLD_TOO_LONG_MS = 28_000;
export const SUBMIT_MARGIN_MS = 100;
export const A11Y_SLOW_FIRST_MS = 10_000;
export const A11Y_SLOW_REPEAT_MS = 30_000;
/** Pause before reloading after a status that should be heard. */
export const RELOAD_DELAY_MS = 1_500;
/** Below this displacement a cancelled hold counts as "the system took the press" (§12.6). */
export const CANCEL_STILL_PX = 4;
export const FILL_STEPS = 4;

// ---------------------------------------------------------------------------
// ix (§7.2)

export interface IxParams {
  providers: Provider[];
  holdMs: number;
  offset: [number, number];
  minMs: number;
  a11yMinMs: number;
  k: number;
  bits: number;
  a11yBits: number;
  attempt: number;
  nowMs: number;
  expMs: number;
  bound: boolean;
  a11yFirst: boolean;
  a11yQuota: boolean;
  turnstile: { sitekey: string; action: string; cdata: string; lang: string } | null;
}

const PROVIDERS: readonly Provider[] = ["self_hold", "pow_a11y", "turnstile"];

function int(value: unknown, min: number, max: number): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max ? value : null;
}

/** Validate the plain parameters; null when they cannot drive the control. Never throws. */
export function parseIx(raw: unknown): IxParams | null {
  try {
    const value = typeof raw === "string" ? (JSON.parse(raw) as unknown) : raw;
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const ix = value as Record<string, unknown>;
    if (ix["v"] !== 1) return null;
    const providers = ix["providers"];
    if (!Array.isArray(providers) || providers.length === 0 || providers.length > 3) return null;
    if (!providers.every((p) => (PROVIDERS as readonly unknown[]).includes(p))) return null;
    if (new Set(providers).size !== providers.length) return null;
    const pow = ix["pow"] as Record<string, unknown> | undefined;
    if (typeof pow !== "object" || pow === null || pow["alg"] !== POW_ALG_V2) return null;
    const offset = ix["offset"];
    const holdMs = int(ix["hold_ms"], 0, 60_000);
    const minMs = int(ix["min_ms"], 0, 600_000);
    const a11yMinMs = ix["a11y_min_ms"] === undefined ? 0 : int(ix["a11y_min_ms"], 0, 600_000);
    const k = int(pow["k"], 1, 8);
    const bits = int(pow["bits"], 0, 32);
    const a11yBits = int(pow["a11y_bits"], 0, 32);
    const attempt = int(ix["attempt"], 0, 1_000_000);
    const nowMs = int(ix["now_ms"], 1, Number.MAX_SAFE_INTEGER);
    const expMs = int(ix["exp_ms"], 1, Number.MAX_SAFE_INTEGER);
    if (
      holdMs === null || minMs === null || a11yMinMs === null || k === null || bits === null ||
      a11yBits === null || attempt === null || nowMs === null || expMs === null ||
      !Array.isArray(offset) || offset.length !== 2
    ) {
      return null;
    }
    const ox = int(offset[0], -64, 64);
    const oy = int(offset[1], -64, 64);
    if (ox === null || oy === null) return null;
    const bool = (name: string): boolean => ix[name] === true;
    let turnstile: IxParams["turnstile"] = null;
    const ts = ix["turnstile"];
    if (typeof ts === "object" && ts !== null) {
      const t = ts as Record<string, unknown>;
      const { sitekey, action, cdata, lang } = t;
      if (
        typeof sitekey === "string" && /^[0-9A-Za-z_-]{1,64}$/.test(sitekey) &&
        typeof action === "string" && /^[0-9A-Za-z_-]{0,32}$/.test(action) &&
        typeof cdata === "string" && /^[0-9A-Za-z_-]{1,255}$/.test(cdata) &&
        (lang === "zh-cn" || lang === "en")
      ) {
        turnstile = { sitekey, action, cdata, lang };
      }
    }
    return {
      providers: providers as Provider[],
      holdMs,
      offset: [ox, oy],
      minMs,
      a11yMinMs,
      k,
      bits,
      a11yBits,
      attempt,
      nowMs,
      expMs,
      bound: bool("bound"),
      a11yFirst: bool("a11y_first"),
      a11yQuota: bool("a11y_quota"),
      turnstile,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// DOM surface

/** The parts of an element the control uses; the real DOM satisfies it. */
export interface ControlElement {
  textContent: string | null;
  setAttribute(name: string, value: string): void;
  removeAttribute(name: string): void;
  getAttribute(name: string): string | null;
  addEventListener(type: string, listener: (event: never) => void): void;
  focus?(): void;
  contains?(other: unknown): boolean;
  getBoundingClientRect?(): { left: number; top: number; width: number; height: number };
  style?: { setProperty(name: string, value: string): void };
}

export interface ControlDom {
  root: ControlElement;
  ix: ControlElement;
  hold: ControlElement;
  /** The text label inside `#mg-hold` (its accessible name). */
  holdLabel: ControlElement;
  altSingle: ControlElement;
  altPow: ControlElement;
  progress: ControlElement;
  turnstile: ControlElement;
  status: ControlElement;
  retry: ControlElement | null;
  elementFromPoint(x: number, y: number): unknown;
  /** window / document listeners. */
  onWindow(type: "blur" | "focus", listener: () => void): void;
  onDocument(type: string, listener: (event: never) => void): void;
  requestFrame: ((callback: (t: number) => void) => unknown) | null;
}

/** Fields of pointer, mouse and keyboard events the control reads. */
export interface InputEvent {
  type?: string;
  isTrusted?: boolean;
  isPrimary?: boolean;
  pointerId?: number;
  pointerType?: string;
  button?: number;
  clientX?: number;
  clientY?: number;
  pressure?: number;
  width?: number;
  height?: number;
  detail?: number;
  key?: string;
  repeat?: boolean;
  target?: unknown;
  preventDefault?(): void;
}

export interface ControlPage {
  c: string;
  ix: IxParams;
  ret: string;
  rid: string;
  lang: Lang;
  build: string;
}

export interface ControlDeps {
  dom: ControlDom;
  rt: Runtime;
  page: ControlPage;
  /** `runPowV2` with the page's Worker wiring. */
  startPow(prefix: Uint8Array, bits: number, k: number, start: number[], listener: PowListener): PowRun;
  turnstileHost: TurnstileHost | null;
  nonce: string | null;
  collect(): { env: EnvSummary | null; auto: AutomationSummary | null };
  /** Whether the AbortController exists (fetch timeout). */
  abortController?: (() => AbortController) | null;
}

// ---------------------------------------------------------------------------
// Telemetry accumulators

class Stats {
  n = 0;
  mean = 0;
  m2 = 0;
  add(x: number): void {
    this.n += 1;
    const d = x - this.mean;
    this.mean += d / this.n;
    this.m2 += d * (x - this.mean);
  }
  sd(): number {
    return this.n > 1 ? Math.sqrt(this.m2 / (this.n - 1)) : 0;
  }
}

const tenths = (v: number, lo: number, hi: number): number => roundToStep(Math.min(hi, Math.max(lo, v)), 0.1);
const ms10 = (v: number): number => Math.min(60_000, Math.max(0, Math.round(v / 10) * 10));
const ms100 = (v: number): number => Math.min(600_000, Math.max(0, Math.round(v / 100) * 100));
const bucket = (v: number): number => logBucket(Math.max(0, v));

// ---------------------------------------------------------------------------
// The control

export class InteractiveControl {
  state: ControlState = "READY";
  provider: Provider = "self_hold";
  c: string;
  ix: IxParams;
  private key: SessionKey | null = null;
  private receivedAt = 0;
  private binding = false;
  private renewing = false;
  private renewDue = false;
  private inputBlocked = false;
  private renewTimer: unknown = null;
  private timers: unknown[] = [];
  private readonly copy: (typeof COPY)[Lang];
  // PoW
  private pow: PowRun | null = null;
  private powBits = -1;
  private powPrefix: Uint8Array = new Uint8Array(0);
  private counters: (number | null)[] = [];
  private powDone = false;
  private powStartedAt: number | null = null;
  private powMs = 0;
  private powWorker = true;
  // Activation
  private mode: IxMode = "hold";
  private activatedAt: number | null = null;
  private waitElapsed = false;
  private externalToken: string | null = null;
  private fallback: Fallback | null = null;
  private widget: TurnstileWidget | null = null;
  private submitTimer: unknown = null;
  // Hold
  private holdPointer: number | null = null;
  private holdStart = 0;
  private holdLetGoTimer: unknown = null;
  private suppressClick = false;
  private shortMessage: unknown = null;
  private holdStats = { x: 0, y: 0, jitter: 0, moves: 0, pressure: 0, pressureVar: false, contact: -1, contactVar: false, offset: [0, 0] as [number, number], ms: 0 };
  private cancels = 0;
  private fillStep = 0;
  // Telemetry
  private readonly renderedAt: number;
  private firstInputAt: number | null = null;
  private lastModality: Modality = "none";
  private trustedEvents = 0;
  private inputEvents = 0;
  private pre = { moves: 0, path: 0, x0: Number.NaN, y0: Number.NaN, x: Number.NaN, y: Number.NaN, t: 0, dx: 0, dy: 0, dirChanges: 0, speed: new Stats(), enterAt: null as number | null };
  private hides = 0;
  private hidesDuring = 0;
  private blurs = 0;
  private frames = new Stats();
  private lastFrame: number | null = null;
  private slowTimer: unknown = null;
  private keyRepeat = false;
  private renewBlocked = false;

  constructor(private readonly deps: ControlDeps) {
    this.c = deps.page.c;
    this.ix = deps.page.ix;
    this.copy = COPY[deps.page.lang];
    this.renderedAt = deps.rt.env.now();
  }

  private get now(): number {
    return this.deps.rt.env.now();
  }

  private after(ms: number, callback: () => void): unknown {
    const handle = this.deps.rt.env.setTimeout(() => {
      this.timers = this.timers.filter((t) => t !== handle);
      try {
        callback();
      } catch {
        // The control keeps running.
      }
    }, Math.max(0, ms));
    this.timers.push(handle);
    return handle;
  }

  private cancel(handle: unknown): null {
    if (handle !== null && handle !== undefined) this.deps.rt.env.clearTimeout(handle);
    return null;
  }

  private say(key: CopyKey, suffix = ""): void {
    this.deps.dom.status.textContent = this.copy[key] + suffix;
  }

  private label(text: string): void {
    this.deps.dom.holdLabel.textContent = text;
  }

  private busy(element: ControlElement, busy: boolean): void {
    if (busy) element.setAttribute("aria-disabled", "true");
    else element.removeAttribute("aria-disabled");
  }

  private fill(step: number): void {
    this.fillStep = step;
    this.deps.dom.hold.setAttribute("data-mg-fill", String(step));
  }

  // ------------------------------------------------------------------ start

  /** Show the control and begin (binding renewal, then PoW). Never rejects. */
  async start(): Promise<void> {
    const { dom, rt } = this.deps;
    try {
      dom.root.setAttribute("data-mg-phase", "ix");
      dom.ix.removeAttribute("hidden");
      dom.status.textContent = "";
      const [ox, oy] = this.ix.offset;
      dom.hold.style?.setProperty("margin", `${oy}px ${-ox}px ${-oy}px ${ox}px`);
      this.listen();
      if (rt.env.subtle === null) {
        this.broken();
        return;
      }
      this.key = await rt.keys.ensure(rt.clearanceValid());
      if (this.key === null) {
        this.broken();
        return;
      }
      this.load(this.c, this.ix);
    } catch {
      this.broken();
    }
  }

  private broken(): void {
    this.state = "BROKEN";
    this.busy(this.deps.dom.hold, true);
    this.say("unsupported", ` · ${this.copy.requestId}${this.deps.page.rid}`);
  }

  /** Put a (new) C in place: bind it first when unbound, else start its PoW. */
  private load(c: string, ix: IxParams): void {
    this.c = c;
    this.ix = ix;
    this.receivedAt = this.now;
    this.stopPow();
    this.counters = Array.from({ length: ix.k }, () => null);
    this.powPrefix = powPrefixV2(c);
    this.powDone = false;
    this.externalToken = null;
    this.renewDue = false;
    this.renewTimer = this.cancel(this.renewTimer);
    this.renewTimer = this.after(RENEW_AFTER_MS, () => {
      this.renewTimer = null;
      this.renewDue = true;
      this.maybeRenew();
    });
    this.deps.dom.ix.setAttribute("data-mg-a11y-quota", ix.a11yQuota ? "1" : "0");
    this.busy(this.deps.dom.altPow, ix.a11yQuota || this.state === "POW_ONLY");
    if (!ix.bound) {
      this.binding = true;
      void this.renew(true);
    } else {
      this.bound();
    }
  }

  /** The C is bound (or binding failed on the network): start working. */
  private bound(): void {
    this.binding = false;
    const first = this.ix.providers[0];
    if (this.state === "READY") {
      if (first === "pow_a11y" && this.ix.a11yFirst && !this.ix.a11yQuota && this.activatedAt === null) {
        this.enterPowOnly();
        return;
      }
      if (first === "turnstile" && this.ix.turnstile !== null && this.deps.turnstileHost !== null && this.fallback === null) {
        this.enterExternal();
        return;
      }
    }
    if (this.state === "EXTERNAL") this.renderTurnstile();
    this.startPow();
  }

  // ------------------------------------------------------------------ PoW

  private stopPow(): void {
    if (this.pow !== null) {
      this.pow.stop();
      if (this.powStartedAt !== null) this.powMs += this.now - this.powStartedAt;
      this.powStartedAt = null;
    }
    this.pow = null;
    this.powBits = -1;
  }

  private bitsFor(provider: Provider): number {
    return provider === "pow_a11y" ? this.ix.a11yBits : this.ix.bits;
  }

  /** (Re)start the PoW at the current provider's difficulty, keeping solved sub-puzzles that still qualify. */
  private startPow(keepShortLived = false): void {
    if (this.binding || this.renewing) return;
    const bits = this.bitsFor(this.provider);
    if (this.pow !== null && this.powBits === bits) return;
    if (this.powDone && this.powBits === bits) return;
    if (!keepShortLived && this.ix.expMs - this.serverNow() < MIN_LIFETIME_FOR_POW_MS) {
      void this.renew(false);
      return;
    }
    this.stopPow();
    const start = this.counters.map((counter, i) => {
      if (counter === null) return 0;
      return subPuzzleBits(this.powPrefix, i, counter) >= bits ? counter : counter + 1;
    });
    this.counters = this.counters.map(() => null);
    this.powDone = false;
    this.powBits = bits;
    this.powStartedAt = this.now;
    const prefix = this.powPrefix;
    let run: PowRun | null = null;
    run = this.deps.startPow(prefix, bits, this.ix.k, start, {
      part: (i, counter) => {
        if (this.pow !== run && run !== null) return;
        this.counters[i] = counter;
        this.progress();
      },
      done: (counters) => {
        if (this.pow !== run && run !== null) return;
        this.counters = counters.slice();
        this.powDone = true;
        this.powWorker = run?.worker ?? this.powWorker;
        if (this.powStartedAt !== null) this.powMs += this.now - this.powStartedAt;
        this.powStartedAt = null;
        this.progress();
        this.maybeSubmit();
      },
      error: () => {
        if (this.pow !== run && run !== null) return;
        this.reload("network");
      },
    });
    if (!this.powDone) this.pow = run;
    else this.pow = null;
  }

  private progress(): void {
    const done = this.counters.filter((c) => c !== null).length;
    this.deps.dom.progress.setAttribute("aria-valuenow", String(done));
    // The bar's width (template v2: `.mg-bar { transform: scaleX(var(--mg-p)) }`); CSSOM, so CSP allows it.
    this.deps.dom.progress.style?.setProperty("--mg-p", String(done / this.ix.k));
  }

  // ------------------------------------------------------------------ time

  private serverNow(): number {
    return this.ix.nowMs + (this.now - this.receivedAt);
  }

  private maybeRenew(): void {
    if (!this.renewDue || this.renewing || this.binding) return;
    if (this.state === "READY" || this.state === "EXTERNAL") void this.renew(false);
  }

  // ------------------------------------------------------------------ renew (§7.4)

  /**
   * POST /__mg/c/renew. `forBinding`: the first renewal of an unbound C.
   * 200 swaps in the new C; 403 with a C swaps it in (binding it first when
   * unbound); 403 without a C, 404 or an exhausted 429 reloads; a network
   * failure keeps the old C. Never touches `#mg-status`.
   */
  private async renew(forBinding: boolean, retried = false): Promise<void> {
    const { rt } = this.deps;
    const key = this.key;
    const subtle = rt.env.subtle;
    if (key === null || subtle === null) return;
    const keepOld = (): void => {
      this.renewing = false;
      this.inputBlocked = false;
      if (forBinding) this.bound();
      else this.startPow(true);
    };
    if (this.renewBlocked) {
      keepOld();
      return;
    }
    this.renewing = true;
    this.renewDue = false;
    let response: Response;
    const url = rt.endpoint("c/renew");
    try {
      const body = await signedRenew(subtle, key, this.c, this.now);
      response = await rt.env.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
    } catch {
      keepOld();
      return;
    }
    rt.observe(response, url);
    if (detectUpstreamChallenge(response) !== null) {
      // A background request never reloads on Cloudflare's challenge: report it, stop
      // background work and renewals, and carry on with the C in hand (§12.5).
      const path = rt.pagePath();
      if (path !== null) void rt.sendReports([{ kind: "upstream_challenge", scope: "mg_endpoint", path, count: 1 }]);
      rt.backgroundStopped = true;
      this.renewBlocked = true;
      keepOld();
      return;
    }
    const answer = await this.readAnswer(response);
    this.renewing = false;
    this.inputBlocked = false;
    if (response.status === 200 && answer.c !== null && answer.ix !== null) {
      this.swap(answer.c, answer.ix);
      return;
    }
    if (response.status === 403 && answer.c !== null && answer.ix !== null) {
      this.swap(answer.c, answer.ix);
      return;
    }
    if (response.status === 429 && !retried) {
      this.after(retryAfterOf(response) * 1000, () => void this.renew(forBinding, true));
      this.renewing = true;
      return;
    }
    this.reload(null);
  }

  /** A new C from a renewal or a failure: keep the UI state, restart the work. */
  private swap(c: string, ix: IxParams): void {
    const external = this.state === "EXTERNAL";
    if (external) this.widget?.remove();
    this.load(c, ix);
  }

  private async readAnswer(response: Response): Promise<{ c: string | null; ix: IxParams | null; ret: string | null; ok: boolean; type: string | null }> {
    const out = { c: null as string | null, ix: null as IxParams | null, ret: null as string | null, ok: false, type: null as string | null };
    try {
      if (!isJsonContentType(response.headers.get("content-type"))) return out;
      const body = (await response.json()) as Record<string, unknown>;
      if (typeof body !== "object" || body === null) return out;
      this.deps.rt.clock.fromNowMs(body["now_ms"]);
      out.ok = body["ok"] === true;
      if (typeof body["ret"] === "string") out.ret = body["ret"];
      const c = body["challenge"];
      if (isSealedChallengeToken(c) && /^[A-Za-z0-9_-]+$/.test(c) && c.length <= 1024) {
        out.c = c;
        out.type = typeof body["type"] === "string" ? body["type"] : null;
        out.ix = parseIx(body["ix"]);
        if (out.type !== null && out.type !== "interactive") out.ix = null;
      }
    } catch {
      // Not JSON: no C.
    }
    return out;
  }

  // ------------------------------------------------------------------ input

  private listen(): void {
    const { dom } = this.deps;
    const on = (el: ControlElement, type: string, f: (e: InputEvent) => void): void =>
      el.addEventListener(type, ((e: InputEvent) => {
        try {
          f(e);
        } catch {
          // Never throw into the page.
        }
      }) as (event: never) => void);
    on(dom.hold, "pointerdown", (e) => this.pointerDown(e));
    on(dom.hold, "pointerenter", () => {
      if (this.pre.enterAt === null) this.pre.enterAt = this.now;
    });
    on(dom.hold, "contextmenu", (e) => e.preventDefault?.());
    on(dom.hold, "click", (e) => this.holdClick(e));
    on(dom.hold, "keydown", (e) => this.input(e, "keyboard"));
    on(dom.altSingle, "keydown", (e) => this.input(e, "keyboard"));
    on(dom.altPow, "keydown", (e) => this.input(e, "keyboard"));
    on(dom.altSingle, "click", (e) => this.altSingle(e));
    on(dom.altPow, "click", (e) => this.altPow(e));
    const doc = (type: string, f: (e: InputEvent) => void): void =>
      dom.onDocument(type, ((e: InputEvent) => {
        try {
          f(e);
        } catch {
          // Never throw into the page.
        }
      }) as (event: never) => void);
    doc("pointermove", (e) => this.pointerMove(e));
    doc("pointerup", (e) => this.pointerUp(e));
    doc("pointercancel", (e) => this.pointerCancel(e));
    dom.onWindow("blur", () => {
      this.blurs += 1;
      if (this.state === "HOLDING") this.abortHold("holdLonger");
    });
    this.deps.rt.env.onVisibility(() => this.visibility());
  }

  private visibility(): void {
    if (this.deps.rt.env.visible()) {
      if (this.now - this.receivedAt >= RENEW_AFTER_MS && (this.state === "READY" || this.state === "EXTERNAL") && !this.renewing && !this.binding) {
        this.inputBlocked = true;
        void this.renew(false);
      }
      return;
    }
    this.hides += 1;
    if (this.state === "HOLDING" || this.state === "WAITING" || this.state === "POW_ONLY") this.hidesDuring += 1;
    if (this.state === "HOLDING") this.abortHold("holdLonger");
  }

  /** Bookkeeping for every input event on the control. */
  private input(e: InputEvent, modality: Modality): void {
    if (e.type === "keydown") this.keyRepeat = e.repeat === true;
    else if (e.type !== "click") this.keyRepeat = false;
    this.inputEvents += 1;
    if (e.isTrusted === true) this.trustedEvents += 1;
    if (this.firstInputAt === null) this.firstInputAt = this.now;
    this.lastModality = modality;
  }

  private pointerModality(e: InputEvent): Modality {
    return e.pointerType === "touch" ? "touch" : e.pointerType === "pen" ? "pen" : "mouse";
  }

  private inside(e: InputEvent): boolean {
    const { dom } = this.deps;
    if (typeof e.clientX !== "number" || typeof e.clientY !== "number") return false;
    const at = dom.elementFromPoint(e.clientX, e.clientY);
    return at !== null && at !== undefined && dom.hold.contains?.(at) === true;
  }

  private pointerDown(e: InputEvent): void {
    this.input(e, this.pointerModality(e));
    if (this.state !== "READY" || this.inputBlocked) return;
    if (e.isPrimary === false) return;
    if ((e.pointerType ?? "mouse") === "mouse" && (e.button ?? 0) !== 0) return;
    this.shortMessage = this.cancel(this.shortMessage);
    this.suppressClick = false;
    this.state = "HOLDING";
    this.holdPointer = e.pointerId ?? 0;
    this.holdStart = this.now;
    if (this.activatedAt === null) this.activatedAt = this.now;
    const rect = this.deps.dom.hold.getBoundingClientRect?.();
    const x = e.clientX ?? 0;
    const y = e.clientY ?? 0;
    const offset: [number, number] =
      rect && rect.width > 0 && rect.height > 0
        ? [((x - rect.left) / rect.width) * 2 - 1, ((y - rect.top) / rect.height) * 2 - 1]
        : [0, 0];
    this.holdStats = {
      x,
      y,
      jitter: 0,
      moves: 0,
      pressure: typeof e.pressure === "number" ? e.pressure : 0,
      pressureVar: false,
      contact: typeof e.width === "number" && typeof e.height === "number" ? e.width * e.height : -1,
      contactVar: false,
      offset,
      ms: 0,
    };
    this.say("keepHolding");
    this.animateFill(this.ix.holdMs);
    this.holdLetGoTimer = this.after(this.ix.holdMs, () => {
      this.holdLetGoTimer = null;
      if (this.state === "HOLDING") this.say("letGo");
    });
    this.frame();
  }

  private pointerMove(e: InputEvent): void {
    if (this.state === "HOLDING" && (e.pointerId ?? 0) === this.holdPointer) {
      const s = this.holdStats;
      s.moves += 1;
      if (typeof e.clientX === "number" && typeof e.clientY === "number") {
        s.jitter = Math.max(s.jitter, Math.hypot(e.clientX - s.x, e.clientY - s.y));
      }
      if (typeof e.pressure === "number" && Math.abs(e.pressure - s.pressure) > 0.01) s.pressureVar = true;
      if (typeof e.width === "number" && typeof e.height === "number" && s.contact >= 0 && Math.abs(e.width * e.height - s.contact) > 0.5) {
        s.contactVar = true;
      }
      if (!this.inside(e)) this.abortHold("holdLonger");
      return;
    }
    if (this.activatedAt !== null || typeof e.clientX !== "number" || typeof e.clientY !== "number") return;
    // Movement before the first press (`ix.pre`): aggregates only.
    const p = this.pre;
    const t = this.now;
    if (this.firstInputAt === null) this.firstInputAt = t;
    if (Number.isNaN(p.x)) {
      p.x0 = e.clientX;
      p.y0 = e.clientY;
    } else {
      const dx = e.clientX - p.x;
      const dy = e.clientY - p.y;
      const d = Math.hypot(dx, dy);
      p.path += d;
      const dt = t - p.t;
      if (dt > 0 && d > 0) p.speed.add((d * 1000) / dt);
      if (d > 0 && (p.dx !== 0 || p.dy !== 0) && p.dx * dx + p.dy * dy < 0) p.dirChanges += 1;
      if (d > 0) {
        p.dx = dx;
        p.dy = dy;
      }
    }
    p.moves += 1;
    p.x = e.clientX;
    p.y = e.clientY;
    p.t = t;
  }

  private pointerUp(e: InputEvent): void {
    if (this.state !== "HOLDING" || (e.pointerId ?? 0) !== this.holdPointer) return;
    this.input(e, this.pointerModality(e));
    const held = this.now - this.holdStart;
    if (!this.inside(e)) {
      this.abortHold("holdLonger");
      return;
    }
    if (held > HOLD_TOO_LONG_MS) {
      this.suppressClick = true;
      this.abortHold("tooLong");
      return;
    }
    if (held >= this.ix.holdMs) {
      this.suppressClick = true;
      this.holdStats.ms = held;
      this.mode = "hold";
      this.state = "FINISHING";
      this.holdPointer = null;
      this.holdLetGoTimer = this.cancel(this.holdLetGoTimer);
      this.busy(this.deps.dom.hold, true);
      if (!this.powDone) this.say("finishing");
      this.maybeSubmit();
      return;
    }
    // Early release on the control: a click follows (short press -> single
    // activation). The "hold longer" text is written only if none does.
    this.abortHold(null);
    this.shortMessage = this.after(0, () => {
      this.shortMessage = null;
      this.say("holdLonger");
    });
  }

  private pointerCancel(e: InputEvent): void {
    if (this.state !== "HOLDING" || (e.pointerId ?? 0) !== this.holdPointer) return;
    this.cancels = Math.min(15, this.cancels + 1);
    this.abortHold(this.holdStats.jitter < CANCEL_STILL_PX ? "cantHold" : "holdLonger");
  }

  /** HOLDING -> READY; not a failure. */
  private abortHold(message: CopyKey | null): void {
    if (this.state !== "HOLDING") return;
    this.state = "READY";
    this.holdPointer = null;
    this.holdLetGoTimer = this.cancel(this.holdLetGoTimer);
    this.fill(0);
    this.deps.dom.hold.removeAttribute("data-mg-active");
    if (message !== null) this.say(message);
    this.maybeRenew();
  }

  private holdClick(e: InputEvent): void {
    this.input(e, this.lastModality);
    if (this.suppressClick) {
      this.suppressClick = false;
      return;
    }
    // A click synthesized by a held key's auto-repeat never activates anything.
    if (e.detail === 0 && this.keyRepeat) return;
    if (this.state === "POW_ONLY" || this.state === "EXTERNAL") {
      this.backToHold();
      return;
    }
    if (this.state !== "READY" || this.inputBlocked) return;
    this.shortMessage = this.cancel(this.shortMessage);
    this.enterWaiting();
  }

  private altSingle(e: InputEvent): void {
    this.input(e, this.lastModality === "none" ? "keyboard" : this.lastModality);
    if (this.state !== "READY" || this.inputBlocked) return;
    this.deps.dom.hold.focus?.();
    this.label(this.copy.singleLabel);
    this.enterWaiting();
  }

  private altPow(e: InputEvent): void {
    this.input(e, this.lastModality);
    if (this.ix.a11yQuota || this.inputBlocked) return;
    if (this.state !== "READY" && this.state !== "EXTERNAL") return;
    if (this.state === "EXTERNAL") this.leaveExternal();
    this.enterPowOnly();
  }

  // ------------------------------------------------------------------ modes

  private animateFill(durationMs: number): void {
    this.fill(0);
    this.deps.dom.hold.setAttribute("data-mg-active", "1");
    const step = durationMs / FILL_STEPS;
    for (let i = 1; i <= FILL_STEPS; i++) {
      const at = this.state;
      this.after(step * i, () => {
        if (this.state === at || (at === "HOLDING" && this.state === "FINISHING")) this.fill(Math.max(this.fillStep, i));
      });
    }
  }

  private enterWaiting(): void {
    this.state = "WAITING";
    this.mode = "single";
    if (this.activatedAt === null) this.activatedAt = this.now;
    const startedAt = this.now;
    this.waitElapsed = false;
    this.busy(this.deps.dom.hold, true);
    this.say("singleWait");
    this.animateFill(this.ix.holdMs);
    this.frame();
    this.after(this.ix.holdMs, () => {
      if (this.state !== "WAITING") return;
      this.waitElapsed = true;
      this.holdStats.ms = this.now - startedAt;
      this.maybeSubmit();
    });
  }

  private enterPowOnly(): void {
    const { dom } = this.deps;
    this.state = "POW_ONLY";
    this.mode = "pow_only";
    this.provider = "pow_a11y";
    if (this.activatedAt === null) this.activatedAt = this.now;
    this.busy(dom.altPow, true);
    this.busy(dom.hold, false);
    this.label(this.copy.backToHold);
    dom.progress.setAttribute("aria-valuemin", "0");
    dom.progress.setAttribute("aria-valuemax", String(this.ix.k));
    dom.progress.removeAttribute("hidden");
    this.say("a11yWait");
    this.frame();
    const powOnlyAt = this.now;
    this.progress();
    const slow = (first: boolean): void => {
      this.slowTimer = this.after(first ? A11Y_SLOW_FIRST_MS : A11Y_SLOW_REPEAT_MS, () => {
        if (this.state !== "POW_ONLY" || this.now - powOnlyAt < A11Y_SLOW_FIRST_MS) return;
        this.say("a11ySlow");
        slow(false);
      });
    };
    slow(true);
    this.startPow();
    this.maybeSubmit();
  }

  /** "Use press and hold instead" from POW_ONLY or EXTERNAL. */
  private backToHold(): void {
    const { dom } = this.deps;
    if (this.state === "EXTERNAL") this.leaveExternal();
    this.slowTimer = this.cancel(this.slowTimer);
    this.state = "READY";
    this.provider = "self_hold";
    this.mode = "hold";
    dom.progress.setAttribute("hidden", "");
    this.busy(dom.altPow, this.ix.a11yQuota);
    this.busy(dom.hold, false);
    this.label(this.copy.holdLabel);
    dom.status.textContent = "";
    this.startPow();
    this.maybeRenew();
  }

  private enterExternal(): void {
    this.state = "EXTERNAL";
    this.provider = "turnstile";
    this.mode = "external";
    this.label(this.copy.backToHold);
    this.say("external");
    this.renderTurnstile();
    this.startPow();
  }

  private renderTurnstile(): void {
    const { dom } = this.deps;
    const host = this.deps.turnstileHost;
    const params = this.ix.turnstile;
    if (host === null || params === null || this.binding) return;
    this.widget?.remove();
    const widget = new TurnstileWidget(host, this.deps.nonce);
    this.widget = widget;
    dom.turnstile.removeAttribute("hidden");
    const width = dom.turnstile.getBoundingClientRect?.().width ?? 0;
    void widget.start(dom.turnstile, width, params, {
      token: (token) => {
        if (this.widget !== widget || this.state !== "EXTERNAL") return;
        this.externalToken = token;
        if (this.activatedAt === null) this.activatedAt = this.now;
        this.maybeSubmit();
      },
      fallback: (reason: TsFallback) => {
        if (this.widget !== widget || this.state !== "EXTERNAL") return;
        this.fallback = reason;
        this.leaveExternal();
        const providers = this.ix.providers;
        const next = providers[providers.indexOf("turnstile") + 1] ?? providers.find((p) => p !== "turnstile");
        if (next === "pow_a11y" && !this.ix.a11yQuota) {
          this.state = "READY";
          this.enterPowOnly();
        } else {
          this.backToHold();
        }
      },
    });
  }

  private leaveExternal(): void {
    this.widget?.remove();
    this.widget = null;
    this.externalToken = null;
    this.deps.dom.turnstile.setAttribute("hidden", "");
  }

  // ------------------------------------------------------------------ submit

  private ready(): boolean {
    switch (this.state) {
      case "FINISHING":
      case "POW_ONLY":
        return this.powDone;
      case "WAITING":
        return this.powDone && this.waitElapsed;
      case "EXTERNAL":
        return this.powDone && this.externalToken !== null;
      default:
        return false;
    }
  }

  private maybeSubmit(): void {
    if (!this.ready() || this.submitTimer !== null) return;
    const floor = this.mode === "pow_only" ? this.ix.a11yMinMs : this.ix.minMs;
    const earliest = this.receivedAt + floor + SUBMIT_MARGIN_MS;
    const wait = earliest - this.now;
    const go = (): void => {
      this.submitTimer = null;
      if (this.ready()) void this.submit();
    };
    if (wait > 0) this.submitTimer = this.after(wait, go);
    else go();
  }

  private trustedBucket(): number {
    if (this.inputEvents === 0 || this.trustedEvents === 0) return 0;
    if (this.trustedEvents >= this.inputEvents) return 3;
    return this.trustedEvents / this.inputEvents < 0.5 ? 1 : 2;
  }

  /** The `t.ix` summary of this attempt (§7.6). */
  telemetry(): IxTelemetry {
    const mode = this.mode;
    const modality: Modality = this.lastModality;
    const ix: IxTelemetry = {
      v: 1,
      mode,
      modality,
      locale: this.deps.page.lang === "zh" ? "zh-CN" : "en",
      ks: this.deps.rt.keys.kind,
      sv: SDK_VERSION,
      fallback: this.fallback,
      trusted: this.trustedBucket(),
      act_ms: ms100(this.activatedAt === null ? 0 : this.now - this.activatedAt),
    };
    if (mode === "hold") {
      const p = this.pre;
      const straight = p.path > 0 ? Math.hypot(p.x - p.x0, p.y - p.y0) / p.path : 0;
      ix.pre = {
        moves: bucket(p.moves),
        path_px: bucket(p.path),
        straight: tenths(straight, 0, 1),
        speed_mean: bucket(p.speed.mean),
        speed_sd: bucket(p.speed.sd()),
        dir_changes: bucket(p.dirChanges),
        render_to_input_ms: bucket(this.firstInputAt === null ? 0 : this.firstInputAt - this.renderedAt),
        to_target_ms: bucket(p.enterAt === null ? 0 : this.holdStart - p.enterAt),
      };
      const s = this.holdStats;
      ix.hold = {
        ms: ms10(s.ms),
        offset: [tenths(s.offset[0], -1, 1), tenths(s.offset[1], -1, 1)],
        jitter_px: bucket(s.jitter),
        moves: bucket(s.moves),
        cancels: this.cancels,
        pressure: tenths(s.pressure, 0, 1),
        pressure_var: s.pressureVar ? 1 : 0,
        contact_var: s.contactVar ? 1 : 0,
      };
    } else if (mode === "single") {
      ix.single = { wait_ms: ms10(this.holdStats.ms) };
    }
    ix.page = {
      vis: bucket(this.hides),
      vis_during: Math.min(15, this.hidesDuring),
      focus: bucket(this.blurs),
      frame_mean: bucket(this.frames.mean),
      frame_sd: bucket(this.frames.sd()),
    };
    ix.pow = { ms: bucket(this.powMs), worker: this.powWorker, impl: "js" };
    return ix;
  }

  /** Measure frame intervals while the control is busy (`page.frame_*`). */
  private frame(): void {
    const raf = this.deps.dom.requestFrame;
    if (raf === null) return;
    const busy = (): boolean => this.state === "HOLDING" || this.state === "WAITING" || this.state === "POW_ONLY" || this.state === "FINISHING";
    const tick = (t: number): void => {
      if (this.lastFrame !== null && t > this.lastFrame) this.frames.add(t - this.lastFrame);
      this.lastFrame = t;
      if (busy() && this.frames.n < 600) raf(tick);
      else this.lastFrame = null;
    };
    try {
      raf(tick);
    } catch {
      // No frames, no frame statistics.
    }
  }

  private async submit(): Promise<void> {
    const { rt, dom, page } = this.deps;
    const key = this.key;
    const subtle = rt.env.subtle;
    if (key === null || subtle === null) return;
    const mode = this.mode;
    const ix = this.telemetry();
    if ((mode === "hold" || mode === "single") && ix.trusted === 0) {
      // A scripted activation would only fail on the Edge (`ic.no_trusted_input`).
      this.resetToReady();
      this.say("failed");
      return;
    }
    const { env, auto } = this.deps.collect();
    const telemetry: SubmissionTelemetry = { env, auto, ix };
    const t = encodeSubmissionTelemetry(telemetry);
    if (t === null) {
      this.resetToReady();
      this.say("failed");
      dom.retry?.removeAttribute("hidden");
      return;
    }
    this.state = "SUBMITTING";
    this.slowTimer = this.cancel(this.slowTimer);
    this.renewTimer = this.cancel(this.renewTimer);
    this.busy(dom.hold, true);
    this.say("verifying");
    const p: Provider = mode === "pow_only" ? "pow_a11y" : mode === "external" ? "turnstile" : "self_hold";
    const c = this.c;
    const url = rt.endpoint("c");
    let response: Response | null = null;
    try {
      const body = await signedSubmission(subtle, key, {
        type: "interactive",
        c,
        p,
        pp: p === "turnstile" ? (this.externalToken ?? "") : "",
        t,
        counters: this.counters.map((x) => x ?? 0),
        ret: page.ret,
        ts: this.now,
        build: page.build,
      });
      // The C is spent from here on: it is never sent again.
      this.c = "";
      const controller = this.deps.abortController?.() ?? null;
      const timeout = new Promise<null>((resolve) =>
        this.after(SUBMIT_TIMEOUT_MS, () => {
          controller?.abort();
          resolve(null);
        }),
      );
      response = await Promise.race([
        rt.env.fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          credentials: "same-origin",
          ...(controller ? { signal: controller.signal } : {}),
        }),
        timeout,
      ]);
    } catch {
      response = null;
    }
    if (this.state !== "SUBMITTING") return;
    if (response === null) {
      this.reload("network");
      return;
    }
    rt.observe(response, url);
    if (response.status === 200) {
      const answer = await this.readAnswer(response);
      if (!answer.ok) {
        this.reload("network");
        return;
      }
      if (rt.status() === null) {
        this.state = "DONE";
        this.say("cookies");
        return;
      }
      this.state = "DONE";
      this.say("verified");
      rt.beforeNavigate();
      rt.env.location.replace(answer.ret !== null && answer.ret.startsWith("/") && !answer.ret.startsWith("//") ? answer.ret : page.ret);
      return;
    }
    if (response.status === 429) {
      this.state = "RELOAD";
      this.say("later");
      const wait = retryAfterOf(response) * 1000;
      this.after(wait, () => {
        this.say("retryNow");
        this.after(RELOAD_DELAY_MS, () => this.reloadNow());
      });
      return;
    }
    if (response.status === 403) {
      const answer = await this.readAnswer(response);
      if (answer.c !== null && answer.ix !== null) {
        this.resetToReady();
        this.say("failed");
        this.load(answer.c, answer.ix);
        return;
      }
      this.reload(null);
      return;
    }
    this.reload("network");
  }

  /** Back to READY with the self_hold provider after a failure or a refused submission. */
  private resetToReady(): void {
    const { dom } = this.deps;
    this.leaveExternal();
    this.slowTimer = this.cancel(this.slowTimer);
    this.submitTimer = this.cancel(this.submitTimer);
    this.state = "READY";
    this.provider = "self_hold";
    this.mode = "hold";
    this.activatedAt = null;
    this.fallback = null;
    this.fill(0);
    dom.hold.removeAttribute("data-mg-active");
    dom.progress.setAttribute("hidden", "");
    this.busy(dom.hold, false);
    this.label(this.copy.holdLabel);
  }

  private reload(message: CopyKey | null): void {
    if (this.state === "RELOAD" || this.state === "DONE") return;
    this.state = "RELOAD";
    this.busy(this.deps.dom.hold, true);
    if (message !== null) {
      this.say(message);
      this.after(RELOAD_DELAY_MS, () => this.reloadNow());
    } else {
      this.reloadNow();
    }
  }

  private reloadNow(): void {
    const { rt } = this.deps;
    try {
      rt.env.location.replace(rt.env.location.href);
    } catch {
      this.deps.dom.retry?.removeAttribute("hidden");
    }
  }

  /** Test hook: the C currently in use ("" once submitted). */
  get currentC(): string {
    return this.c;
  }

}
