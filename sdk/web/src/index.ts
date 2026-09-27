/**
 * MorphGate Web SDK entry point (bundled to dist/mg.js as an IIFE and
 * published as dist/sdk/mg.<hex16>.js, docs/impl/phase1-spec.md §11).
 *
 * The same file runs in two contexts:
 *
 * - In a document it bootstraps the SDK (configuration from its own
 *   `data-mg-*` attributes, a read-only `window.MorphGate`) and, on the
 *   Edge's challenge page (`#mg-challenge`), runs the challenge flow
 *   (`challenge.ts`).
 * - In a Worker started by that flow from the same URL
 *   (`self instanceof WorkerGlobalScope`) it only installs the PoW message
 *   handler (`pow.ts`). One cacheable file; CSP needs only `worker-src 'self'`.
 *
 * The Edge serves it first-party, e.g.
 *   <script data-cfasync="false" src="/__mg/s/mg.<hex16>.js" nonce="…" data-mg-path-prefix="/__mg/"></script>
 * `data-cfasync="false"` (before `src`) keeps Cloudflare Rocket Loader away.
 *
 * Phase 1 sends exactly one request: the challenge form submission. Session
 * keys, MG-Proof, telemetry uploads and fetch wrapping land in Phase 2.
 */

import { collectAutomation, type AutomationSummary } from "./automation";
import { startChallenge } from "./challenge";
import { parseConfig, type MgConfig } from "./config";
import { collectEnv, type EnvSummary } from "./env";
import { installPowWorker, isWorkerScope, type PowWorkerScope } from "./pow";
import { classifyResponse } from "./transport";

export { DEFAULT_PATH_PREFIX, endpointPath, normalizePathPrefix, parseConfig } from "./config";
export type { MgConfig, MgEndpoint } from "./config";

export const SDK_VERSION = "0.1.0-phase1";

export interface Snapshot {
  env: EnvSummary;
  automation: AutomationSummary;
}

export interface MorphGateApi {
  readonly version: string;
  readonly config: Readonly<MgConfig>;
  snapshot(): Snapshot;
  classifyResponse: typeof classifyResponse;
}

declare global {
  interface Window {
    MorphGate?: MorphGateApi;
  }
}

/** Locate our own <script> tag: currentScript while executing, else by attribute. */
function findOwnScript(doc: Document): HTMLOrSVGScriptElement | null {
  const current = doc.currentScript;
  if (current !== null) return current;
  return doc.querySelector<HTMLScriptElement>("script[data-mg-path-prefix], script[data-mg-site]");
}

/**
 * Initialise the SDK once per page. Returns the existing instance when the
 * script is included twice. Never throws into the host page.
 */
export function bootstrap(doc: Document = document, win: Window = window): MorphGateApi | null {
  try {
    if (win.MorphGate) return win.MorphGate;
    const script = findOwnScript(doc);
    const config = Object.freeze(parseConfig(script?.dataset ?? {}));
    const api: MorphGateApi = Object.freeze({
      version: SDK_VERSION,
      config,
      snapshot: (): Snapshot => ({ env: collectEnv(), automation: collectAutomation() }),
      classifyResponse,
    });
    Object.defineProperty(win, "MorphGate", { value: api, configurable: false, writable: false, enumerable: false });
    if (config.debug) console.debug("[morphgate]", SDK_VERSION, config, api.snapshot());
    return api;
  } catch {
    // SDK failure must not affect the page; the server sees "signals missing".
    return null;
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
function startChallengeWhenReady(doc: Document, scriptSrc: string | null): void {
  try {
    if (doc.getElementById("mg-challenge") !== null || doc.readyState !== "loading") {
      void startChallenge(doc, scriptSrc);
      return;
    }
    doc.addEventListener("DOMContentLoaded", () => void startChallenge(doc, scriptSrc), { once: true });
  } catch {
    // Never throw into the page.
  }
}

if (isWorkerScope(globalThis)) {
  installPowWorker(globalThis as unknown as PowWorkerScope);
} else if (typeof document !== "undefined" && typeof window !== "undefined") {
  const scriptSrc = currentScriptSrc(document);
  bootstrap();
  startChallengeWhenReady(document, scriptSrc);
}
