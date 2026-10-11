/**
 * Script-tag configuration: the `data-mg-*` attributes on the SDK's own
 * <script> element (docs/impl/phase2-spec.md §12.1), and the first-party
 * endpoint prefix.
 *
 * Kept separate from the entry point so the challenge flow can share
 * `normalizePathPrefix` without an import cycle.
 */

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
  /** data-mg-proof: "auto" (default) attaches MG-Proof to same-origin `MorphGate.fetch` requests. */
  proof: boolean;
  /** data-mg-refresh: "auto" (default) refreshes a key-bound clearance before it expires. */
  refresh: boolean;
  /** data-mg-telemetry="behavior" turns on the behaviour summary (off by default, D-48). */
  behavior: boolean;
}

/** Endpoints under the prefix (§11.1; `v` is the verify entry, I-39). */
export type MgEndpoint = "c" | "c/renew" | "r" | "t" | "v";

/**
 * Normalise a configured prefix. Only same-origin absolute paths are accepted
 * ("/__mg/", "/x7/mg"), so a tampered attribute cannot point the SDK at a
 * third-party host ("//evil.example/") or escape with dot segments.
 */
export function normalizePathPrefix(raw: string | null | undefined): string {
  if (raw === undefined || raw === null) return DEFAULT_PATH_PREFIX;
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
    proof: dataset["mgProof"]?.trim() !== "off",
    refresh: dataset["mgRefresh"]?.trim() !== "off",
    behavior: dataset["mgTelemetry"]?.trim() === "behavior",
  };
}

export function endpointPath(config: Pick<MgConfig, "pathPrefix">, endpoint: MgEndpoint): string {
  return `${config.pathPrefix}${endpoint}`;
}
