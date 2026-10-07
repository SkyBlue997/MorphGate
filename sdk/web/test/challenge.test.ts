// Challenge page client (docs/impl/phase1-spec.md §10.3, §11.3, §11.5).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collectAutomation } from "../src/automation";
import {
  CHALLENGE_TIMEOUT_MS,
  MAX_SUBMIT_BODY_BYTES,
  MESSAGES,
  RETRY_KEY_PREFIX,
  UNKNOWN_BUILD,
  WORKER_ACK_TIMEOUT_MS,
  buildIdFromScriptSrc,
  buildSubmitForm,
  claimAutoRetry,
  encodeSubmission,
  formBodyBytes,
  isValidRet,
  pickLanguage,
  readChallengePage,
  runChallenge,
  selfTest,
  startChallenge,
  submitForm,
  type ChallengeDeps,
  type ChallengeOutcome,
  type ChallengePage,
  type ChallengeView,
  type FormDom,
  type Phase,
  type PowWorkerHandle,
  type RetryStorage,
  type StatusKey,
} from "../src/challenge";
import { collectEnv, type EnvSummary } from "../src/env";
import { handlePowMessage, isPowPrefix, powPrefix, type PowRequest } from "../src/pow";
import { XorShift32 } from "./xorshift";

// kat.json: c "AAECAwQ" at 4 bits is first solved by counter 4.
const C = "AAECAwQ";
const BITS = 4;
const COUNTER = 4;
const RET = "/account/login?next=%2Fcart";
const SCRIPT_SRC = "https://example.test/__mg/s/mg.0123456789abcdef.js";

// ---------------------------------------------------------------------------
// Fakes

const last = <T>(items: readonly T[]): T | undefined => items[items.length - 1];

class FakeElement {
  readonly attributes = new Map<string, string>();
  readonly children: FakeElement[] = [];
  submitted = 0;
  textContent = "";

  constructor(readonly tag: string) {}

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  hasAttribute(name: string): boolean {
    return this.attributes.has(name);
  }

  removeAttribute(name: string): void {
    this.attributes.delete(name);
  }

  appendChild(child: FakeElement): FakeElement {
    this.children.push(child);
    return child;
  }

  submit(): void {
    this.submitted += 1;
  }
}

function fakeFormDom(): { dom: FormDom; body: FakeElement } {
  const body = new FakeElement("body");
  const dom: FormDom = { createElement: (tag: string) => new FakeElement(tag), body };
  return { dom, body };
}

class FakeView implements ChallengeView {
  readonly statuses: StatusKey[] = [];
  readonly phases: Phase[] = [];
  retryHref: string | null = null;

  setStatus(key: StatusKey): void {
    this.statuses.push(key);
  }

  setPhase(phase: Phase): void {
    this.phases.push(phase);
  }

  showRetry(href: string): void {
    this.retryHref = href;
  }
}

type WorkerMode = "real" | "silent" | "ack-only" | "error-event" | "err-reply" | "bad-ok";

/** A Worker stand-in; "real" runs the actual handler in a microtask. */
class FakeWorker implements PowWorkerHandle {
  readonly posted: PowRequest[] = [];
  terminated = false;
  private onMessage: ((data: unknown) => void) | null = null;
  private onError: (() => void) | null = null;

  constructor(private readonly mode: WorkerMode) {}

  listen(onMessage: (data: unknown) => void, onError: () => void): void {
    this.onMessage = onMessage;
    this.onError = onError;
  }

  postMessage(request: PowRequest): void {
    this.posted.push(request);
    queueMicrotask(() => {
      if (this.terminated) return;
      const reply = (data: unknown): void => this.onMessage?.(data);
      switch (this.mode) {
        case "real":
          handlePowMessage(request, reply);
          break;
        case "ack-only":
          reply({ t: "mg-pow-ack" });
          break;
        case "error-event":
          this.onError?.();
          break;
        case "err-reply":
          reply({ t: "mg-pow-ack" });
          reply({ t: "mg-pow-err" });
          break;
        case "bad-ok":
          reply({ t: "mg-pow-ok", counter: COUNTER + 1 }); // does not solve the PoW
          break;
        case "silent":
          break;
      }
    });
  }

  terminate(): void {
    this.terminated = true;
  }
}

class MemoryStorage implements RetryStorage {
  readonly items = new Map<string, string>();

  getItem(key: string): string | null {
    return this.items.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
}

const SAMPLE_ENV: EnvSummary = collectEnv({
  navigator: {
    userAgent: "Mozilla/5.0 (Macintosh) Test/1.0",
    languages: ["zh-CN", "en"],
    userAgentData: { brands: [{ brand: "Chromium", version: "131" }], mobile: false, platform: "macOS" },
  },
  timeZone: () => "Asia/Shanghai",
  timezoneOffset: () => -480,
});

interface Harness {
  deps: ChallengeDeps;
  view: FakeView;
  body: FakeElement;
  workers: FakeWorker[];
  storage: MemoryStorage;
  submittedAt: number[];
}

function harness(options: { page?: Partial<ChallengePage>; worker?: WorkerMode | "throw" | "none"; deps?: Partial<ChallengeDeps> } = {}): Harness {
  const view = new FakeView();
  const { dom, body } = fakeFormDom();
  const workers: FakeWorker[] = [];
  const storage = new MemoryStorage();
  const submittedAt: number[] = [];
  const original = body.appendChild.bind(body);
  body.appendChild = (child: FakeElement): FakeElement => {
    const submit = child.submit.bind(child);
    child.submit = (): void => {
      submittedAt.push(Date.now());
      submit();
    };
    return original(child);
  };
  const mode = options.worker ?? "real";
  const deps: ChallengeDeps = {
    page: { state: "challenge", c: C, type: "pow", bits: BITS, ret: RET, prefix: "/__mg/", ...options.page },
    view,
    scriptSrc: SCRIPT_SRC,
    createWorker:
      mode === "none"
        ? null
        : (url) => {
            expect(url).toBe(SCRIPT_SRC);
            if (mode === "throw") throw new DOMException("blocked by CSP", "SecurityError");
            const worker = new FakeWorker(mode);
            workers.push(worker);
            return worker;
          },
    formDom: dom,
    storage: () => storage,
    collect: () => ({ env: SAMPLE_ENV, auto: collectAutomation({ navigator: { webdriver: false } }) }),
    webCryptoDigest: null,
    timers: {
      setTimeout: (callback, ms) => setTimeout(callback, ms),
      clearTimeout: (handle) => clearTimeout(handle as number),
    },
    now: () => Date.now(),
    ...options.deps,
  };
  return { deps, view, body, workers, storage, submittedAt };
}

/** Drive fake timers until the flow settles. */
async function drive(promise: Promise<ChallengeOutcome>): Promise<ChallengeOutcome> {
  let outcome: ChallengeOutcome | undefined;
  void promise.then((value) => {
    outcome = value;
  });
  for (let i = 0; i < 2_000 && outcome === undefined; i++) await vi.advanceTimersByTimeAsync(50);
  if (outcome === undefined) throw new Error("challenge flow did not settle");
  return outcome;
}

/** The single form the flow submitted, and its parsed `mg` JSON. */
function submitted(h: Harness): { form: FakeElement; json: string; body: Record<string, unknown> } {
  expect(h.body.children).toHaveLength(1);
  const form = h.body.children[0]!;
  expect(form.submitted).toBe(1);
  expect(form.children).toHaveLength(1);
  const json = form.children[0]!.getAttribute("value") ?? "";
  return { form, json, body: JSON.parse(json) as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Strict JSON inspection: JSON.parse silently keeps the last duplicate key, so
// the "no duplicate keys, nesting <= 16" contract (§10.3) needs its own scanner.

function jsonNesting(text: string): number {
  let i = 0;
  const skip = (): void => {
    while (i < text.length && " \t\r\n".includes(text[i]!)) i++;
  };
  const expectChar = (ch: string): void => {
    skip();
    if (text[i] !== ch) throw new Error(`expected ${ch} at ${i}`);
    i++;
  };
  const string = (): string => {
    skip();
    const start = i;
    if (text[i] !== '"') throw new Error(`expected string at ${i}`);
    for (i++; text[i] !== '"'; i++) {
      if (i >= text.length) throw new Error("unterminated string");
      if (text[i] === "\\") i++;
    }
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const value = (): number => {
    skip();
    const ch = text[i];
    if (ch === "{" || ch === "[") {
      const close = ch === "{" ? "}" : "]";
      const keys = new Set<string>();
      let deepest = 0;
      i++;
      skip();
      if (text[i] === close) {
        i++;
        return 1;
      }
      for (;;) {
        if (close === "}") {
          const key = string();
          if (keys.has(key)) throw new Error(`duplicate key "${key}"`);
          keys.add(key);
          expectChar(":");
        }
        deepest = Math.max(deepest, value());
        skip();
        const sep = text[i++];
        if (sep === close) return deepest + 1;
        if (sep !== ",") throw new Error(`expected , or ${close}`);
      }
    }
    if (ch === '"') {
      string();
      return 0;
    }
    const literal = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    if (literal === null) throw new Error(`unexpected token at ${i}`);
    i += literal[0].length;
    return 0;
  };
  const depth = value();
  skip();
  if (i !== text.length) throw new Error("trailing data");
  return depth;
}

// ---------------------------------------------------------------------------

describe("readChallengePage", () => {
  function element(attributes: Record<string, string>): FakeElement {
    const el = new FakeElement("main");
    for (const [name, value] of Object.entries(attributes)) el.setAttribute(name, value);
    return el;
  }

  const VALID = {
    "data-mg-state": "challenge",
    "data-mg-c": C,
    "data-mg-type": "pow",
    "data-mg-pow-bits": "16",
    "data-mg-ret": RET,
    "data-mg-rid": "0123456789abcdef0123456789abcdef",
    "data-mg-prefix": "/__mg/",
  };

  it("reads a rendered challenge page", () => {
    expect(readChallengePage(element(VALID))).toEqual({
      state: "challenge",
      c: C,
      type: "pow",
      bits: 16,
      ret: RET,
      prefix: "/__mg/",
    });
    expect(readChallengePage(element({ ...VALID, "data-mg-type": "invisible", "data-mg-state": "failed" }))).toMatchObject({
      state: "failed",
      type: "invisible",
    });
  });

  it("maps a failed page without a new C to c = null", () => {
    expect(readChallengePage(element({ ...VALID, "data-mg-state": "failed", "data-mg-c": "" })).c).toBeNull();
  });

  it("rejects malformed values field by field", () => {
    const page = (overrides: Record<string, string>): ChallengePage => readChallengePage(element({ ...VALID, ...overrides }));
    expect(page({ "data-mg-state": "solved" }).state).toBe("failed");
    expect(page({ "data-mg-c": "a".repeat(1025) }).c).toBeNull();
    expect(page({ "data-mg-c": "a".repeat(1024) }).c).toBe("a".repeat(1024));
    expect(page({ "data-mg-c": "AAEC+/w=" }).c).toBeNull(); // standard base64, not base64url
    expect(page({ "data-mg-type": "interactive" }).type).toBeNull();
    for (const bits of ["33", "-1", "1.5", "", " 8", "0x10", "100"]) expect(page({ "data-mg-pow-bits": bits }).bits).toBeNull();
    expect(page({ "data-mg-pow-bits": "0" }).bits).toBe(0);
    expect(page({ "data-mg-pow-bits": "32" }).bits).toBe(32);
    expect(page({ "data-mg-ret": "//evil.example/" }).ret).toBeNull();
    expect(page({ "data-mg-prefix": "//evil.example/" }).prefix).toBe("/__mg/");
  });

  it("treats missing attributes and throwing getters as absent", () => {
    expect(readChallengePage(element({}))).toEqual({ state: "failed", c: null, type: null, bits: null, ret: null, prefix: "/__mg/" });
    const hostile = {
      getAttribute(): never {
        throw new Error("boom");
      },
    };
    expect(readChallengePage(hostile)).toEqual({ state: "failed", c: null, type: null, bits: null, ret: null, prefix: "/__mg/" });
  });

  it("never throws on 10,000 xorshift attribute sets (§2.4)", () => {
    const rng = new XorShift32(0x11c3);
    const names = Object.keys(VALID);
    for (let i = 0; i < 10_000; i++) {
      const attributes: Record<string, string> = { ...VALID };
      for (const name of names) if (rng.below(2) === 0) attributes[name] = rng.string(rng.below(3) === 0 ? 1100 : 24);
      const page = readChallengePage(element(attributes));
      if (page.c !== null) expect(page.c).toMatch(/^[A-Za-z0-9_-]{1,1024}$/);
      if (page.ret !== null) expect(isValidRet(page.ret)).toBe(true);
      if (page.bits !== null) expect(page.bits >= 0 && page.bits <= 32).toBe(true);
      expect(page.prefix.startsWith("/") && !page.prefix.startsWith("//")).toBe(true);
    }
  });
});

describe("isValidRet (§6.4 client subset)", () => {
  it("accepts the kat.json ret cases and ordinary paths", () => {
    for (const ret of ["/", "/account/login?next=%2Fcart", "/a/b;c?x=1&y=2", "/验证"]) expect(isValidRet(ret)).toBe(true);
  });

  it("rejects anything that is not a same-site path", () => {
    for (const ret of ["", "a", "//evil.example", "/\\evil.example", "https://evil.example/", "/a\\b", "/a#b", "/a\nb", "/a\u007fb", "/a\tb", `/${"a".repeat(512)}`]) {
      expect(isValidRet(ret), JSON.stringify(ret)).toBe(false);
    }
    for (const ret of ["/__mg", "/__mg/c", "/__mg/c?x=1", "/__mg?x"]) expect(isValidRet(ret), ret).toBe(false);
    expect(isValidRet("/__mgx/c")).toBe(true);
    expect(isValidRet("/a?next=/__mg/c")).toBe(true); // only the path counts
    expect(isValidRet(`/${"a".repeat(511)}`)).toBe(true); // exactly 512 bytes
    expect(isValidRet(`/${"验".repeat(170)}a`)).toBe(true); // 1 + 510 + 1 = 512 bytes
    expect(isValidRet(`/${"验".repeat(171)}`)).toBe(false); // 514 bytes
  });

  it("never rejects a ret the Edge accepts: lookalikes of /__mg are ordinary paths", () => {
    // mg_core::paths::is_reserved is case-sensitive and only claims /__mg and /__mg/...
    // (core/src/paths.rs `lookalikes_are_not_reserved`). The Edge issues challenges
    // with these as `ret`; rejecting them here would leave the visitor with no way
    // to pass the challenge for that page.
    for (const ret of ["/__MG/c", "/__Mg", "/__MG/c?x=1", "/__mg%2Fc", "/x/__mg/c", "/__mgx/c", "/__mg_/"]) {
      expect(isValidRet(ret), ret).toBe(true);
    }
  });
});

describe("buildIdFromScriptSrc", () => {
  it("takes the content hash from mg.<hex16>.js", () => {
    expect(buildIdFromScriptSrc(SCRIPT_SRC)).toBe("0123456789abcdef");
    expect(buildIdFromScriptSrc("/__mg/s/mg.0123456789abcdef.js?v=1")).toBe("0123456789abcdef");
  });

  it("falls back to the all-zero build id", () => {
    for (const src of [null, "", "/dist/mg.js", "/__mg/s/mg.0123456789ABCDEF.js", "/__mg/s/mg.0123456789abcdef0.js", "/__mg/s/xmg.0123456789abcdef.jsx"]) {
      expect(buildIdFromScriptSrc(src)).toBe(UNKNOWN_BUILD);
    }
    expect(UNKNOWN_BUILD).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("encodeSubmission (§10.3)", () => {
  const base = { type: "pow" as const, c: C, counter: COUNTER, ret: RET, ts: 1790000000123, build: "0123456789abcdef" };

  it("has the spec's shape and key order", () => {
    const auto = collectAutomation({ navigator: { webdriver: false } });
    const json = encodeSubmission({ ...base, env: SAMPLE_ENV, auto });
    expect(json).not.toBeNull();
    const body = JSON.parse(json!) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["v", "type", "c", "pow", "ret", "ts", "build", "env", "auto"]);
    expect(body).toEqual({
      v: 1,
      type: "pow",
      c: C,
      pow: { counters: [COUNTER] },
      ret: RET,
      ts: 1790000000123,
      build: "0123456789abcdef",
      env: SAMPLE_ENV,
      auto: { v: 1, webdriver: false },
    });
  });

  it("has no duplicate keys and nests at most 16 levels", () => {
    const json = encodeSubmission({ ...base, env: SAMPLE_ENV, auto: collectAutomation({ navigator: { webdriver: true } }) })!;
    const depth = jsonNesting(json);
    expect(depth).toBeLessThanOrEqual(16);
    expect(depth).toBe(5); // body -> env -> ua -> brands (array) -> brand object
  });

  it("omits env and auto when absent", () => {
    const body = JSON.parse(encodeSubmission({ ...base, env: null, auto: null })!) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["v", "type", "c", "pow", "ret", "ts", "build"]);
  });

  it("keeps the urlencoded body within 8 KiB by dropping env, then auto", () => {
    const huge = (text: string): EnvSummary => ({ ...SAMPLE_ENV, timeZone: text.repeat(4000) });
    const auto = collectAutomation({ navigator: { webdriver: false } });
    const withoutEnv = JSON.parse(encodeSubmission({ ...base, env: huge("验"), auto })!) as Record<string, unknown>;
    expect(withoutEnv["env"]).toBeUndefined();
    expect(withoutEnv["auto"]).toEqual(auto);
    // A C far beyond the protocol limit cannot fit at all.
    expect(encodeSubmission({ ...base, c: "A".repeat(9000) })).toBeNull();
  });

  it("stays within the limit for the largest valid C and ret with any env (xorshift)", () => {
    const rng = new XorShift32(0xb0d7);
    for (let i = 0; i < 300; i++) {
      const env: EnvSummary = {
        ...SAMPLE_ENV,
        ua: { ...SAMPLE_ENV.ua, userAgent: rng.string(256), platform: rng.string(64) },
        languages: [rng.string(35), rng.string(35), rng.string(35)],
      };
      const json = encodeSubmission({ ...base, c: "A".repeat(1024), ret: `/${"验".repeat(170)}`, env });
      expect(json).not.toBeNull();
      expect(formBodyBytes(json!)).toBeLessThanOrEqual(MAX_SUBMIT_BODY_BYTES);
    }
  });

  it("measures the body exactly as the form serializer encodes it", () => {
    expect(formBodyBytes('{"a":"b c"}')).toBe("mg=%7B%22a%22%3A%22b+c%22%7D".length);
    expect(formBodyBytes("验")).toBe("mg=%E9%AA%8C".length);
  });
});

describe("submission form (§11.3 step 4)", () => {
  it("builds a hidden POST form whose only field is mg", () => {
    const { dom } = fakeFormDom();
    const form = buildSubmitForm(dom, "/__mg/c", '{"v":1}') as unknown as FakeElement;
    expect(form.tag).toBe("form");
    expect(Object.fromEntries(form.attributes)).toEqual({
      method: "POST",
      action: "/__mg/c",
      enctype: "application/x-www-form-urlencoded",
      "accept-charset": "UTF-8",
      hidden: "",
    });
    expect(form.children).toHaveLength(1);
    const field = form.children[0]!;
    expect(field.tag).toBe("input");
    expect(Object.fromEntries(field.attributes)).toEqual({ type: "hidden", name: "mg", value: '{"v":1}' });
    expect(form.submitted).toBe(0);
  });

  it("attaches the form to the body before submitting", () => {
    const { dom, body } = fakeFormDom();
    submitForm(dom, "/x7/c", "{}");
    expect(body.children).toHaveLength(1);
    expect(body.children[0]!.submitted).toBe(1);
    expect(body.children[0]!.getAttribute("action")).toBe("/x7/c");
  });

  it("throws (for the flow to catch) when there is no body", () => {
    const dom: FormDom = { createElement: (tag: string) => new FakeElement(tag), body: null };
    expect(() => submitForm(dom, "/__mg/c", "{}")).toThrow();
  });
});

describe("claimAutoRetry (§11.3 step 5)", () => {
  it("allows exactly one automatic retry per ret", () => {
    const storage = new MemoryStorage();
    expect(claimAutoRetry(() => storage, RET)).toBe(true);
    expect(storage.items.get(`${RETRY_KEY_PREFIX}${RET}`)).toBe("1");
    expect(claimAutoRetry(() => storage, RET)).toBe(false);
    expect(claimAutoRetry(() => storage, "/other")).toBe(true);
  });

  it("refuses when storage is missing, throws, or does not persist", () => {
    expect(claimAutoRetry(() => null, RET)).toBe(false);
    expect(
      claimAutoRetry(() => {
        throw new DOMException("denied", "SecurityError");
      }, RET),
    ).toBe(false);
    const throwing: RetryStorage = {
      getItem: () => null,
      setItem: () => {
        throw new DOMException("full", "QuotaExceededError");
      },
    };
    expect(claimAutoRetry(() => throwing, RET)).toBe(false);
    const forgetful: RetryStorage = { getItem: () => null, setItem: () => undefined };
    expect(claimAutoRetry(() => forgetful, RET)).toBe(false);
  });
});

describe("selfTest (§11.4)", () => {
  it("passes against Node's WebCrypto and without WebCrypto", async () => {
    const subtle = globalThis.crypto.subtle;
    expect(await selfTest((data) => subtle.digest("SHA-256", data))).toBe(true);
    expect(await selfTest(null)).toBe(true);
  });

  it("fails when WebCrypto disagrees", async () => {
    expect(await selfTest(async () => new ArrayBuffer(32))).toBe(false);
  });

  it("does not treat a throwing WebCrypto as a mismatch", async () => {
    expect(
      await selfTest(async () => {
        throw new DOMException("not allowed", "NotSupportedError");
      }),
    ).toBe(true);
  });
});

describe("runChallenge (§11.3)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function expectSubmitted(h: Harness, outcome: ChallengeOutcome): void {
    expect(outcome).toEqual({ kind: "submitted", counter: COUNTER });
    const { form, body } = submitted(h);
    expect(form.getAttribute("action")).toBe("/__mg/c");
    expect(body["pow"]).toEqual({ counters: [COUNTER] });
    expect(body["c"]).toBe(C);
    expect(body["ret"]).toBe(RET);
    expect(body["type"]).toBe("pow");
    expect(body["build"]).toBe("0123456789abcdef");
    expect(last(h.view.statuses)).toBe("returning");
    expect(h.view.retryHref).toBeNull();
    for (const worker of h.workers) expect(worker.terminated).toBe(true);
  }

  it("solves in the Worker and submits the form", async () => {
    const h = harness();
    const outcome = await drive(runChallenge(h.deps));
    expectSubmitted(h, outcome);
    expect(h.view.statuses).toEqual(["verifying", "returning"]);
    expect(h.view.phases).toEqual(["work"]);
    expect(h.workers).toHaveLength(1);
    const request = h.workers[0]!.posted[0]!;
    expect(request.t).toBe("mg-pow");
    expect(request.bits).toBe(BITS);
    expect(isPowPrefix(request.prefix)).toBe(true);
    expect(request.prefix).toEqual(powPrefix(C));
  });

  it("falls back to main-thread slices when the Worker cannot be created", async () => {
    const h = harness({ worker: "throw" });
    expectSubmitted(h, await drive(runChallenge(h.deps)));
    expect(h.workers).toHaveLength(0);
  });

  it("falls back when Workers are unavailable or the script URL is unknown", async () => {
    const none = harness({ worker: "none" });
    expectSubmitted(none, await drive(runChallenge(none.deps)));
    const noSrc = harness({ deps: { scriptSrc: null } });
    noSrc.deps.createWorker = () => {
      throw new Error("must not be called without a script URL");
    };
    const outcome = await drive(runChallenge(noSrc.deps));
    expect(outcome).toEqual({ kind: "submitted", counter: COUNTER });
    expect(submitted(noSrc).body["build"]).toBe(UNKNOWN_BUILD);
  });

  it("slices the main-thread search into 50,000-hash chunks with setTimeout(0) between them (§11.3 step 2)", async () => {
    // First solutions computed independently with Node's SHA-256: "mg-slice-2" at 16 bits is
    // 49348 (inside slice 1), "mg-slice-1" at 18 bits is 138709 (inside slice 3: 100000..149999).
    for (const [c, bits, counter, slices] of [
      ["mg-slice-2", 16, 49_348, 1],
      ["mg-slice-1", 18, 138_709, 3],
    ] as const) {
      const zeroDelay: number[] = [];
      const h = harness({
        page: { c, bits },
        worker: "none",
        deps: {
          timers: {
            setTimeout: (callback, ms) => {
              if (ms === 0) zeroDelay.push(Date.now());
              return setTimeout(callback, ms);
            },
            clearTimeout: (handle) => clearTimeout(handle as number),
          },
        },
      });
      expect(await drive(runChallenge(h.deps))).toEqual({ kind: "submitted", counter });
      expect(zeroDelay, c).toHaveLength(slices);
      expect(submitted(h).body["pow"]).toEqual({ counters: [counter] });
    }
  });

  it("falls back after 2 s when the Worker never answers", async () => {
    const h = harness({ worker: "silent" });
    const started = Date.now();
    expectSubmitted(h, await drive(runChallenge(h.deps)));
    expect(h.submittedAt[0]! - started).toBeGreaterThanOrEqual(WORKER_ACK_TIMEOUT_MS);
  });

  it("does not fall back while an acknowledged Worker is busy, and gives up at 60 s", async () => {
    const h = harness({ worker: "ack-only" });
    const started = Date.now();
    const outcome = await drive(runChallenge(h.deps));
    expect(outcome).toEqual({ kind: "retry", reason: "timeout" });
    expect(Date.now() - started).toBeGreaterThanOrEqual(CHALLENGE_TIMEOUT_MS);
    expect(h.body.children).toHaveLength(0);
    expect(h.workers).toHaveLength(1);
    expect(h.workers[0]!.terminated).toBe(true);
    expect(last(h.view.statuses)).toBe("timeout");
    expect(last(h.view.phases)).toBe("retry");
    expect(h.view.retryHref).toBe(RET);
  });

  for (const mode of ["error-event", "err-reply", "bad-ok"] as const) {
    it(`falls back to the main thread on a Worker ${mode}`, async () => {
      const h = harness({ worker: mode });
      expectSubmitted(h, await drive(runChallenge(h.deps)));
      expect(h.workers).toHaveLength(1);
    });
  }

  it("retries a failed page with a new C once per ret", async () => {
    const h = harness({ page: { state: "failed" } });
    expectSubmitted(h, await drive(runChallenge(h.deps)));
    expect(h.view.statuses[0]).toBe("retrying");
    expect(h.storage.items.get(`mg_retry:${RET}`)).toBe("1");

    const again = harness({ page: { state: "failed" }, deps: { storage: () => h.storage } });
    const outcome = await drive(runChallenge(again.deps));
    expect(outcome).toEqual({ kind: "retry", reason: "auto_retry_used" });
    expect(again.workers).toHaveLength(0);
    expect(again.body.children).toHaveLength(0);
    expect(again.view.statuses).toEqual(["failed"]);
    expect(again.view.retryHref).toBe(RET);
  });

  it("shows the retry link instead of auto-retrying when storage is unusable", async () => {
    const h = harness({
      page: { state: "failed" },
      deps: {
        storage: () => {
          throw new DOMException("denied", "SecurityError");
        },
      },
    });
    expect(await drive(runChallenge(h.deps))).toEqual({ kind: "retry", reason: "auto_retry_used" });
    expect(h.workers).toHaveLength(0);
  });

  it("shows the retry link for a failed page without a new C", async () => {
    const h = harness({ page: { state: "failed", c: null } });
    expect(await drive(runChallenge(h.deps))).toEqual({ kind: "retry", reason: "no_challenge" });
    expect(h.view.statuses).toEqual(["failed"]);
    expect(h.view.retryHref).toBe(RET);
    expect(h.storage.items.size).toBe(0);
  });

  it("never links to an invalid ret", async () => {
    const h = harness({ page: { ret: null } });
    expect(await drive(runChallenge(h.deps))).toEqual({ kind: "retry", reason: "no_challenge" });
    expect(h.view.retryHref).toBe("/");
  });

  it("does not start when the SHA-256 self-test fails", async () => {
    const h = harness({ deps: { webCryptoDigest: async () => new ArrayBuffer(32) } });
    expect(await drive(runChallenge(h.deps))).toEqual({ kind: "retry", reason: "self_test" });
    expect(h.workers).toHaveLength(0);
    expect(h.body.children).toHaveLength(0);
    expect(last(h.view.statuses)).toBe("failed");
  });

  it("turns any exception into the failed status and retry link", async () => {
    const throwing = harness({
      deps: {
        collect: () => {
          throw new Error("boom");
        },
      },
    });
    expect(await drive(runChallenge(throwing.deps))).toEqual({ kind: "retry", reason: "error" });
    expect(last(throwing.view.statuses)).toBe("failed");
    expect(throwing.view.retryHref).toBe(RET);

    const noBody = harness();
    noBody.deps.formDom = { createElement: (tag: string) => new FakeElement(tag), body: null };
    expect(await drive(runChallenge(noBody.deps))).toEqual({ kind: "retry", reason: "error" });

    const brokenView = harness();
    brokenView.deps.view = {
      setStatus: () => {
        throw new Error("detached");
      },
      setPhase: () => undefined,
      showRetry: () => {
        throw new Error("detached");
      },
    };
    expect(await drive(runChallenge(brokenView.deps))).toEqual({ kind: "retry", reason: "error" });
  });

  it("submits the invisible type with the page's difficulty", async () => {
    const h = harness({ page: { type: "invisible" } });
    await drive(runChallenge(h.deps));
    expect(submitted(h).body["type"]).toBe("invisible");
  });
});

describe("language and messages", () => {
  it("follows <html lang>", () => {
    expect(pickLanguage("zh-CN")).toBe("zh");
    expect(pickLanguage("ZH")).toBe("zh");
    expect(pickLanguage("en")).toBe("en");
    expect(pickLanguage("")).toBe("en");
    expect(pickLanguage(null)).toBe("en");
  });

  it("has every status in both languages, with the spec's failure wording", () => {
    expect(Object.keys(MESSAGES.zh).sort()).toEqual(Object.keys(MESSAGES.en).sort());
    expect(MESSAGES.zh.failed).toBe("验证失败，请重试");
  });
});

describe("startChallenge (browser wiring)", () => {
  beforeEach(() => {
    // Node 26 exposes experimental Web Storage globals that warn on access; env collection probes them.
    vi.stubGlobal("localStorage", undefined);
    vi.stubGlobal("sessionStorage", undefined);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function fakeDocument(lang: string, attributes: Record<string, string>): { doc: Document; root: FakeElement; status: FakeElement; retry: FakeElement; body: FakeElement } {
    const root = new FakeElement("main");
    for (const [name, value] of Object.entries(attributes)) root.setAttribute(name, value);
    const status = new FakeElement("p");
    const retry = new FakeElement("a");
    retry.setAttribute("href", "/placeholder");
    retry.setAttribute("hidden", "");
    const body = new FakeElement("body");
    const html = new FakeElement("html");
    html.setAttribute("lang", lang);
    const byId: Record<string, FakeElement> = { "mg-challenge": root, "mg-status": status, "mg-retry": retry };
    const doc = {
      documentElement: html,
      body,
      getElementById: (id: string) => byId[id] ?? null,
      createElement: (tag: string) => new FakeElement(tag),
    } as unknown as Document;
    return { doc, root, status, retry, body };
  }

  it("runs the real flow end to end on a challenge page (main-thread PoW, real timers)", async () => {
    const page = fakeDocument("en", {
      "data-mg-state": "challenge",
      "data-mg-c": C,
      "data-mg-type": "pow",
      "data-mg-pow-bits": String(BITS),
      "data-mg-ret": RET,
      "data-mg-prefix": "/__mg/",
    });
    const outcome = await startChallenge(page.doc, SCRIPT_SRC);
    expect(outcome).toEqual({ kind: "submitted", counter: COUNTER });
    expect(page.root.getAttribute("data-mg-phase")).toBe("work");
    expect(page.status.textContent).toBe(MESSAGES.en.returning);
    const form = page.body.children[0]!;
    expect(form.submitted).toBe(1);
    const body = JSON.parse(form.children[0]!.getAttribute("value")!) as Record<string, unknown>;
    expect(body["pow"]).toEqual({ counters: [COUNTER] });
    expect(body["build"]).toBe("0123456789abcdef");
    // Idempotent: a second SDK copy on the page does nothing.
    expect(startChallenge(page.doc, SCRIPT_SRC)).toBeNull();
  });

  it("shows the Chinese failure text and the retry link on a failed page without C", async () => {
    const page = fakeDocument("zh-CN", { "data-mg-state": "failed", "data-mg-c": "", "data-mg-ret": RET });
    expect(await startChallenge(page.doc, SCRIPT_SRC)).toEqual({ kind: "retry", reason: "no_challenge" });
    expect(page.status.textContent).toBe("验证失败，请重试");
    expect(page.retry.hasAttribute("hidden")).toBe(false);
    expect(page.retry.getAttribute("href")).toBe(RET);
    expect(page.root.getAttribute("data-mg-phase")).toBe("retry");
  });

  it("does nothing on pages without #mg-challenge", () => {
    const doc = { getElementById: () => null } as unknown as Document;
    expect(startChallenge(doc, SCRIPT_SRC)).toBeNull();
  });
});
