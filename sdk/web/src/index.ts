/**
 * MorphGate Web SDK entry point (bundled to dist/mg.js as an IIFE and
 * published as dist/sdk/mg.<hex16>.js; docs/impl/phase2-spec.md §12).
 *
 * The same file runs in two contexts:
 *
 * - In a document it bootstraps the SDK (configuration from its own
 *   `data-mg-*` attributes, a read-only `window.MorphGate`), and on the
 *   Edge's challenge page (`#mg-challenge`) runs the challenge flow
 *   (`challenge.ts`; the interactive control on template v2 pages).
 * - In a Worker started from the same URL (`self instanceof
 *   WorkerGlobalScope`) it only installs the PoW handlers (`worker.ts`). One
 *   cacheable file; CSP needs only `worker-src 'self'`.
 *
 * Site pages include it before their own scripts (D-39):
 *   <script data-cfasync="false" src="/__mg/s/mg.js" defer></script>
 * and never assume that `window.MorphGate` exists (§12.1):
 *   const mgFetch = (...a) => (window.MorphGate?.fetch ?? window.fetch)(...a);
 *
 * On site pages the SDK attaches `MG-Proof` to `MorphGate.fetch` requests
 * once the clearance is key-bound, recovers from challenges and missing
 * proofs (§12.5), refreshes a key-bound clearance before it expires, and
 * reports through `/__mg/t` (§9.4; the behaviour summary only with
 * `data-mg-telemetry="behavior"`). No exception reaches the page.
 */

import { collectAutomation, type AutomationSummary } from "./automation";
import { BehaviorCollector, type BehaviorEvent } from "./behavior";
import { startChallenge } from "./challenge";
import { parseConfig, type MgConfig } from "./config";
import { collectEnv, type EnvSummary } from "./env";
import { MgFetch } from "./fetch";
import { isWorkerScope } from "./pow";
import { Refresher } from "./refresh";
import { Runtime, type RuntimeEnv } from "./runtime";
import { classifyResponse } from "./transport";
import { startVerify, verifyUrl, type VerifyMin } from "./verify";
import { BUILD_MANIFEST_VERSION, SDK_VERSION } from "./version";
import { installWorker, type SdkWorkerScope } from "./worker";

export { DEFAULT_PATH_PREFIX, endpointPath, normalizePathPrefix, parseConfig } from "./config";
export type { MgConfig, MgEndpoint } from "./config";
export { VERIFY_GUARD_MS, VERIFY_KEY_PREFIX, isMgChallenge, startVerify, verifyUrl } from "./verify";
export type { VerifyDeps, VerifyLocation } from "./verify";
export { SDK_VERSION } from "./version";

/** The behaviour summary is pre-signed this often while the page is visible (§12.8). */
export const BEHAVIOR_PRESIGN_MS = 20_000;

export interface Snapshot {
  env: EnvSummary;
  automation: AutomationSummary;
}

export interface MorphGateApi {
  readonly version: string;
  readonly config: Readonly<MgConfig>;
  snapshot(): Snapshot;
  classifyResponse: typeof classifyResponse;
  /** `/__mg/v?ret=<ret>`, by default for the current page (I-39). */
  verifyUrl(ret?: string): string;
  /** Send the page to the verify entry (once per path per minute); true when it navigates. */
  verify(): boolean;
  /** `fetch` with `MG-Proof` and challenge recovery (§12.5). */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** Resolves once the key store is initialised; never rejects (§12.1). */
  ready(): Promise<void>;
  /** `MG-Proof` for XHR / axios interceptors, or null (§12.1, §12.5 step 1). */
  proofHeader(method: string, url: string | URL): Promise<string | null>;
  /** Called synchronously (50 ms budget) before the SDK navigates away (§12.1). */
  onBeforeNavigate(callback: () => void): void;
}

declare global {
  interface Window {
    MorphGate?: MorphGateApi;
  }
}

/**
 * Locate our own <script> tag: currentScript while executing, else by
 * attribute or by the stable alias `/__mg/s/mg.js` (§12.1).
 */
function findOwnScript(doc: Document): HTMLOrSVGScriptElement | null {
  const current = doc.currentScript;
  if (current !== null && current !== undefined) return current;
  return doc.querySelector<HTMLScriptElement>(
    'script[data-mg-path-prefix], script[data-mg-site], script[src$="/__mg/s/mg.js"]',
  );
}

/** The browser behind `RuntimeEnv`; every accessor tolerates a hostile or partial window. */
export function browserEnv(win: Window, doc: Document): RuntimeEnv {
  const crypto = ((): Crypto | null => {
    try {
      return win.crypto ?? null;
    } catch {
      return null;
    }
  })();
  let subtle: SubtleCrypto | null = null;
  try {
    subtle = crypto?.subtle ?? null;
  } catch {
    subtle = null;
  }
  let locks: RuntimeEnv["locks"] = null;
  try {
    const l = (win.navigator as { locks?: { request?: unknown } } | undefined)?.locks;
    if (l && typeof l.request === "function") {
      locks = { request: (name, cb) => (l as LockManager).request(name, cb) };
    }
  } catch {
    locks = null;
  }
  return {
    get location() {
      return win.location;
    },
    fetch: (input, init) => win.fetch(input, init),
    cookie: () => doc.cookie,
    sessionStorage: () => win.sessionStorage,
    localStorage: () => win.localStorage,
    indexedDB: () => win.indexedDB ?? null,
    subtle,
    randomBytes: (n) => crypto!.getRandomValues(new Uint8Array(n)),
    locks,
    setTimeout: (callback, ms) => win.setTimeout(callback, ms),
    clearTimeout: (handle) => win.clearTimeout(handle as number),
    now: () => Date.now(),
    visible: () => doc.visibilityState !== "hidden",
    onVisibility: (callback) => doc.addEventListener("visibilitychange", callback),
  };
}

/** The behaviour summary (§12.8): collect, pre-sign, send once when the page is first hidden. */
function startBehavior(rt: Runtime, doc: Document, win: Window): void {
  const collector = new BehaviorCollector();
  const observe = (event: Event): void => collector.observe(event as unknown as BehaviorEvent);
  for (const type of ["pointermove", "pointerdown", "pointerup", "keydown", "input", "paste"]) {
    doc.addEventListener(type, observe, { passive: true, capture: true });
  }
  win.addEventListener("scroll", (e) => collector.observe({ type: "scroll", timeStamp: e.timeStamp }, win.scrollY), {
    passive: true,
  });
  win.addEventListener("blur", () => collector.observe({ type: "blur" }));
  let proof: string | null = null;
  let sent = false;
  const presign = (): void => {
    if (sent || !rt.env.visible()) return;
    if (rt.boundClearance()) {
      void rt.proofFor("POST", rt.endpoint("t"), true).then((p) => {
        proof = p;
      });
    }
    rt.env.setTimeout(presign, BEHAVIOR_PRESIGN_MS);
  };
  presign();
  rt.env.onVisibility(() => {
    if (rt.env.visible()) {
      presign();
      return;
    }
    collector.observe({ type: "hidden" });
    const page = rt.pagePath();
    if (sent || page === null) return;
    sent = true;
    void rt.sendReports([{ kind: "behavior", page, summary: { ...collector.summary() } }], true, proof);
  });
}

/** The runtime of the instance this script created, shared with the challenge flow. */
let pageRuntime: Runtime | null = null;

/**
 * Initialise the SDK once per page. Returns the existing instance when the
 * script is included twice. Never throws into the host page.
 */
export function bootstrap(doc: Document = document, win: Window = window, scriptSrc: string | null = null): MorphGateApi | null {
  try {
    if (win.MorphGate) return win.MorphGate;
    const script = findOwnScript(doc);
    const config = Object.freeze(parseConfig(script?.dataset ?? {}));
    const rt = new Runtime(config, browserEnv(win, doc), scriptSrc);
    pageRuntime = rt;
    const verify = (min?: VerifyMin): boolean =>
      startVerify(
        config,
        {
          location: win.location,
          storage: () => win.sessionStorage,
          now: () => Date.now(),
          beforeNavigate: () => rt.beforeNavigate(),
        },
        min,
      );
    const timers = {
      setTimeout: (callback: () => void, ms: number) => win.setTimeout(callback, ms),
      clearTimeout: (handle: unknown) => win.clearTimeout(handle as number),
    };
    const mgFetch = new MgFetch({
      rt,
      inPlace: BUILD_MANIFEST_VERSION >= 2,
      solve: {
        createWorker:
          typeof Worker === "function"
            ? (url) => {
                const worker = new Worker(url);
                return {
                  listen(onMessage, onError) {
                    worker.onmessage = (event) => onMessage(event.data);
                    worker.onmessageerror = () => onError();
                    worker.onerror = (event) => {
                      event.preventDefault();
                      onError();
                    };
                  },
                  postMessage: (message) => worker.postMessage(message),
                  terminate: () => worker.terminate(),
                };
              }
            : null,
        scriptSrc,
        timers,
        now: () => Date.now(),
      },
      collect: () => ({ env: collectEnv(), auto: collectAutomation() }),
      verify,
    });
    let ready: Promise<void> | null = null;
    const api: MorphGateApi = Object.freeze({
      version: SDK_VERSION,
      config,
      snapshot: (): Snapshot => ({ env: collectEnv(), automation: collectAutomation() }),
      classifyResponse,
      verifyUrl: (ret?: string): string => verifyUrl(config, ret ?? win.location.pathname + win.location.search),
      verify: (): boolean => verify(),
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => mgFetch.fetch(input, init),
      ready: (): Promise<void> => (ready ??= rt.keys.init().then(() => undefined, () => undefined)),
      proofHeader: (method: string, url: string | URL): Promise<string | null> => mgFetch.proofHeader(method, url),
      onBeforeNavigate: (callback: () => void): void => rt.onBeforeNavigate(callback),
    });
    Object.defineProperty(win, "MorphGate", { value: api, configurable: false, writable: false, enumerable: false });
    startBackground(rt, doc, win);
    if (config.debug) console.debug("[morphgate]", SDK_VERSION, config, api.snapshot());
    return api;
  } catch {
    // SDK failure must not affect the page; the server sees "signals missing".
    return null;
  }
}

/** Refresh, queued reports, the Service Worker check and the behaviour summary. Never throws. */
function startBackground(rt: Runtime, doc: Document, win: Window): void {
  try {
    if (typeof win.location?.pathname !== "string") return;
    if (rt.boundClearance()) void rt.keys.init();
    rt.flushQueuedReports();
    new Refresher(rt).start();
    if (rt.config.behavior) startBehavior(rt, doc, win);
    const checkIntercept = (): void => {
      const path = rt.pagePath();
      if (path !== null && path.startsWith(rt.config.pathPrefix) && doc.getElementById("mg-challenge") === null) {
        rt.reportOnce("sw_intercept", { kind: "sw_intercept", path });
      }
    };
    if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", checkIntercept, { once: true });
    else checkIntercept();
  } catch {
    // Background work is optional.
  }
}

/**
 * URL of the executing script, the Worker script for the PoW. Must be read
 * synchronously: `document.currentScript` is null once execution yields.
 */
function currentScriptSrc(doc: Document): string | null {
  try {
    const script = doc.currentScript;
    return script instanceof HTMLScriptElement && script.src !== "" ? script.src : null;
  } catch {
    return null;
  }
}

/** Run the challenge flow when this is a challenge page (after parsing, if needed). */
function startChallengeWhenReady(doc: Document, scriptSrc: string | null, win: Window): void {
  try {
    const run = (): void => {
      void startChallenge(doc, scriptSrc, pageRuntime ?? runtimeFor(doc, win, scriptSrc));
    };
    if (doc.getElementById("mg-challenge") !== null || doc.readyState !== "loading") {
      run();
      return;
    }
    doc.addEventListener("DOMContentLoaded", run, { once: true });
  } catch {
    // Never throw into the page.
  }
}

/** A runtime for the challenge page (its own key store view; the challenge page has no site code). */
function runtimeFor(doc: Document, win: Window, scriptSrc: string | null): Runtime {
  const script = findOwnScript(doc);
  return new Runtime(Object.freeze(parseConfig(script?.dataset ?? {})), browserEnv(win, doc), scriptSrc);
}

if (isWorkerScope(globalThis)) {
  installWorker(globalThis as unknown as SdkWorkerScope);
} else if (typeof document !== "undefined" && typeof window !== "undefined") {
  const scriptSrc = currentScriptSrc(document);
  bootstrap(document, window, scriptSrc);
  startChallengeWhenReady(document, scriptSrc, window);
}
