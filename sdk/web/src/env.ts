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

function truncate(value: unknown, max: number): string | undefined {
  return typeof value === "string" ? value.slice(0, max) : undefined;
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
        .filter((tag): tag is string => typeof tag === "string")
        .map((tag) => tag.slice(0, MAX_LANGUAGE_TAG_LENGTH));
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
