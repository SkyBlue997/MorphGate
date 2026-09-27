/**
 * Environment summary (docs/04 §7, module `env`).
 *
 * Privacy-minimised by design: only values the browser already exposes to
 * every site, coarsened where they would otherwise add entropy. Deliberately
 * NOT collected: canvas / WebGL / audio render hashes, WebGL renderer and
 * vendor strings, font or plugin lists, media devices, battery, high-entropy
 * UA Client Hints. The server does all consistency reasoning; the SDK only
 * reports what it saw.
 *
 * Every probe is individually guarded: a throwing getter yields `null` for
 * that field and never breaks the page (docs/04 §7 "稳健").
 */

import { clamp, roundToStep } from "./behavior";

export const ENV_SCHEMA_VERSION = 1;

export interface UaSummary {
  /** navigator.userAgent, truncated; the server compares it with the User-Agent header. */
  userAgent: string | null;
  /** Low-entropy UA Client Hints (navigator.userAgentData), when the browser has them. */
  brands: Array<{ brand: string; version: string }> | null;
  mobile: boolean | null;
  platform: string | null;
}

export interface EnvSummary {
  v: typeof ENV_SCHEMA_VERSION;
  ua: UaSummary;
  /** First few entries of navigator.languages. */
  languages: string[] | null;
  /** IANA time zone name, e.g. "Asia/Shanghai". */
  timeZone: string | null;
  /** Minutes east of UTC (the negation of Date#getTimezoneOffset). */
  utcOffsetMin: number | null;
  /** Screen size in CSS px; available area rounded to 10 px. */
  screen: { width: number; height: number; availWidth: number; availHeight: number; colorDepth: number } | null;
  /** Viewport rounded to 10 px so window resizing does not create unique values. */
  viewport: { width: number; height: number } | null;
  /** devicePixelRatio rounded to 0.25. */
  dpr: number | null;
  /** navigator.hardwareConcurrency, capped at 64. */
  cores: number | null;
  /** navigator.deviceMemory (already coarse, Chromium only). */
  memoryGb: number | null;
  touch: { maxTouchPoints: number | null; coarsePointer: boolean | null };
  /** Whether each storage API is reachable (not whether it holds anything). */
  storage: { cookies: boolean | null; local: boolean | null; session: boolean | null; indexedDb: boolean | null };
  /**
   * Graphics stack family (e.g. "webgl2" / "webgpu" availability, never the
   * renderer string). Reserved; collected from Phase 2.
   */
  graphics: null;
}

/** The subset of browser globals the collector reads. Injected in tests. */
export interface EnvSource {
  navigator?: {
    userAgent?: string;
    languages?: readonly string[];
    hardwareConcurrency?: number;
    deviceMemory?: number;
    maxTouchPoints?: number;
    cookieEnabled?: boolean;
    userAgentData?: {
      brands?: ReadonlyArray<{ brand: string; version: string }>;
      mobile?: boolean;
      platform?: string;
    };
  };
  screen?: { width?: number; height?: number; availWidth?: number; availHeight?: number; colorDepth?: number };
  innerWidth?: number;
  innerHeight?: number;
  devicePixelRatio?: number;
  matchMedia?: (query: string) => { matches: boolean };
  localStorage?: unknown;
  sessionStorage?: unknown;
  indexedDB?: unknown;
  /** Resolved IANA zone; defaults to Intl. */
  timeZone?: () => string | undefined;
  /** Date#getTimezoneOffset; defaults to the current date. */
  timezoneOffset?: () => number;
}

const MAX_UA_LENGTH = 256;
const MAX_LANGUAGES = 3;
const MAX_LANGUAGE_TAG_LENGTH = 35;
const MAX_BRANDS = 4;
const MAX_BRAND_TEXT = 64;

/** Run a probe, mapping exceptions and undefined to null. */
function probe<T>(read: () => T | undefined | null): T | null {
  try {
    const value = read();
    return value === undefined ? null : value;
  } catch {
    return null;
  }
}

function finite(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function bool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

/**
 * True when `value` contains an unpaired UTF-16 surrogate (no UTF-8 encoding).
 * A loop rather than a lookbehind regex: lookbehind is a syntax error in
 * Safari before 16.4 and would stop the whole bundle from parsing.
 */
function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0xd800 || code > 0xdfff) continue;
    if (code >= 0xdc00) return true; // trailing surrogate without a leading one
    const next = value.charCodeAt(i + 1); // NaN past the end
    if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
    i++; // skip the pair's trailing half
  }
  return false;
}

/**
 * At most `max` UTF-16 code units of a string, never ending inside a surrogate
 * pair; `undefined` for non-strings and for strings that are not well-formed
 * Unicode. `JSON.stringify` writes a lone surrogate as a `\udXXX` escape,
 * which strict parsers (the Edge's serde_json) reject, failing the whole
 * challenge submission (phase1-spec §10.3: the body is UTF-8). Such a value is
 * dropped rather than rewritten, so a truncated `userAgent` stays a prefix of
 * the User-Agent header (§10.3 step 8).
 */
function truncate(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  let out = value.slice(0, max);
  if (out.length < value.length) {
    const last = out.charCodeAt(out.length - 1);
    if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1);
  }
  return hasLoneSurrogate(out) ? undefined : out;
}

/** Reads the real browser globals; property access itself is deferred to the probes. */
export function browserEnvSource(): EnvSource {
  const g = globalThis as unknown as Record<string, unknown>;
  const source: EnvSource = {
    timeZone: () => Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: () => new Date().getTimezoneOffset(),
  };
  // Storage getters can throw (sandboxed iframes, blocked cookies), so they are
  // wrapped as lazy getters instead of being read here.
  for (const key of ["navigator", "screen", "innerWidth", "innerHeight", "devicePixelRatio", "localStorage", "sessionStorage", "indexedDB"] as const) {
    Object.defineProperty(source, key, { enumerable: true, get: () => g[key] });
  }
  if (typeof g["matchMedia"] === "function") {
    const matchMedia = g["matchMedia"] as (query: string) => { matches: boolean };
    source.matchMedia = (query) => matchMedia.call(globalThis, query);
  }
  return source;
}

function storageReachable(read: () => unknown): boolean | null {
  try {
    const value = read();
    if (value === undefined) return null;
    return value !== null;
  } catch {
    return false;
  }
}

function collectUa(source: EnvSource): UaSummary {
  const nav = probe(() => source.navigator);
  const uaData = probe(() => nav?.userAgentData);
  const brands = probe(() => {
    const list = uaData?.brands;
    if (!Array.isArray(list)) return undefined;
    return list.slice(0, MAX_BRANDS).map((b: { brand: unknown; version: unknown }) => ({
      brand: truncate(b.brand, MAX_BRAND_TEXT) ?? "",
      version: truncate(b.version, MAX_BRAND_TEXT) ?? "",
    }));
  });
  return {
    userAgent: probe(() => truncate(nav?.userAgent, MAX_UA_LENGTH)),
    brands,
    mobile: probe(() => bool(uaData?.mobile)),
    platform: probe(() => truncate(uaData?.platform, MAX_BRAND_TEXT)),
  };
}

/** Collect the environment summary. Never throws. */
export function collectEnv(source: EnvSource = browserEnvSource()): EnvSummary {
  const nav = probe(() => source.navigator);
  return {
    v: ENV_SCHEMA_VERSION,
    ua: collectUa(source),
    languages: probe(() => {
      const list = nav?.languages;
      if (!Array.isArray(list)) return undefined;
      return list
        .slice(0, MAX_LANGUAGES)
        .map((tag) => truncate(tag, MAX_LANGUAGE_TAG_LENGTH))
        .filter((tag): tag is string => tag !== undefined);
    }),
    timeZone: probe(() => truncate(source.timeZone?.(), 64)),
    utcOffsetMin: probe(() => {
      const offset = finite(source.timezoneOffset?.());
      return offset === undefined ? undefined : 0 - offset;
    }),
    screen: probe(() => {
      const s = source.screen;
      const width = finite(s?.width);
      const height = finite(s?.height);
      if (width === undefined || height === undefined) return undefined;
      return {
        width,
        height,
        availWidth: roundToStep(finite(s?.availWidth) ?? width, 10),
        availHeight: roundToStep(finite(s?.availHeight) ?? height, 10),
        colorDepth: finite(s?.colorDepth) ?? 0,
      };
    }),
    viewport: probe(() => {
      const width = finite(source.innerWidth);
      const height = finite(source.innerHeight);
      if (width === undefined || height === undefined) return undefined;
      return { width: roundToStep(width, 10), height: roundToStep(height, 10) };
    }),
    dpr: probe(() => {
      const dpr = finite(source.devicePixelRatio);
      return dpr === undefined ? undefined : roundToStep(dpr, 0.25);
    }),
    cores: probe(() => {
      const cores = finite(nav?.hardwareConcurrency);
      return cores === undefined ? undefined : clamp(Math.round(cores), 0, 64);
    }),
    memoryGb: probe(() => finite(nav?.deviceMemory)),
    touch: {
      maxTouchPoints: probe(() => {
        const points = finite(nav?.maxTouchPoints);
        return points === undefined ? undefined : clamp(Math.round(points), 0, 32);
      }),
      coarsePointer: probe(() => bool(source.matchMedia?.("(pointer: coarse)").matches)),
    },
    storage: {
      cookies: probe(() => bool(nav?.cookieEnabled)),
      local: storageReachable(() => source.localStorage),
      session: storageReachable(() => source.sessionStorage),
      indexedDb: storageReachable(() => source.indexedDB),
    },
    graphics: null,
  };
}
