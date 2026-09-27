/**
 * MorphGate Web SDK entry point (bundled to dist/mg.js as an IIFE).
 *
 * The Edge injects the SDK as a first-party script, e.g.
 *   <script data-cfasync="false" src="/__mg/s/{build}.js" data-mg-path-prefix="/__mg/" nonce="..."></script>
 * `data-cfasync="false"` keeps Cloudflare Rocket Loader away from it; the
 * data attributes carry configuration.
 *
 * Phase 0 bootstrap: read configuration, take env/automation snapshots on
 * demand, expose a small read-only `window.MorphGate` object for debugging.
 * No network requests and no key generation happen yet; the challenge flow,
 * session keys in IndexedDB, MG-Proof and telemetry uploads land in Phase 2.
 */

import { collectAutomation, type AutomationSummary } from "./automation";
import { collectEnv, type EnvSummary } from "./env";
import { classifyResponse } from "./transport";

export const SDK_VERSION = "0.0.0-phase0";
export const DEFAULT_PATH_PREFIX = "/__mg/";
const MAX_PREFIX_LENGTH = 64;
const SITE_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9._~-]+$/;

export interface MgConfig {
  /** First-party path prefix for MorphGate endpoints; always starts and ends with "/". */
  pathPrefix: string;
  /** Site id from data-mg-site; informational, the Edge knows the site from the Host. */
  site: string | null;
  /** data-mg-debug="true" logs snapshots to the console. */
  debug: boolean;
}

/** Endpoints under the prefix (docs/02 §3, docs/04 §9). */
export type MgEndpoint = "c" | "c/renew" | "r" | "t";

/**
 * Normalise a configured prefix. Only same-origin absolute paths are accepted
 * ("/__mg/", "/x7/mg"), so a tampered attribute cannot point the SDK at a
 * third-party host ("//evil.example/") or escape with dot segments.
 */
export function normalizePathPrefix(raw: string | undefined): string {
  if (raw === undefined) return DEFAULT_PATH_PREFIX;
  const value = raw.trim();
  if (value.length === 0 || value.length > MAX_PREFIX_LENGTH || !value.startsWith("/")) {
    return DEFAULT_PATH_PREFIX;
  }
  const segments = value.slice(1).replace(/\/$/, "").split("/");
  const valid = segments.every(
    (segment) => PATH_SEGMENT_PATTERN.test(segment) && segment !== "." && segment !== "..",
  );
  return valid ? `/${segments.join("/")}/` : DEFAULT_PATH_PREFIX;
}

/** Build the configuration from a script element's dataset (data-mg-* attributes). */
export function parseConfig(dataset: Readonly<Record<string, string | undefined>>): MgConfig {
  const site = dataset["mgSite"]?.trim();
  return {
    pathPrefix: normalizePathPrefix(dataset["mgPathPrefix"]),
    site: site !== undefined && SITE_ID_PATTERN.test(site) ? site : null,
    debug: dataset["mgDebug"] === "true",
  };
}

export function endpointPath(config: MgConfig, endpoint: MgEndpoint): string {
  return `${config.pathPrefix}${endpoint}`;
}

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

if (typeof document !== "undefined" && typeof window !== "undefined") {
  bootstrap();
}
