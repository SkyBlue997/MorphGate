/**
 * The verify entry for challenged fetches (docs/impl/phase1-spec.md §10.5,
 * I-39; docs/impl/phase2-spec.md D-57, D-58).
 *
 * When a fetch gets a JSON challenge the SDK does not solve in place, the
 * page navigates to `/__mg/v?ret=<its own path>`: the Edge serves the
 * challenge page there, and the solved challenge returns to the page with a
 * clearance the fetch's route accepts. An interactive JSON challenge adds
 * `&min=interactive`, so the Edge issues an interactive challenge even when
 * the page's own route asks for less (D-58).
 *
 * One navigation per page path per `VERIFY_GUARD_MS` (sessionStorage
 * `mg_verify:<ret>`), so a fetch that is challenged again right after the
 * return cannot loop the visitor through the challenge. Without storage
 * the guard cannot hold, so the page stays put. The `onBeforeNavigate`
 * callbacks run first (§12.1).
 */

import { endpointPath, type MgConfig } from "./config";
import { isValidRet, type RetryStorage } from "./challenge";
import { classifyFetched } from "./transport";

export const VERIFY_KEY_PREFIX = "mg_verify:";
export const VERIFY_GUARD_MS = 60_000;

export interface VerifyLocation {
  readonly pathname: string;
  readonly search: string;
  assign(url: string): void;
}

export interface VerifyDeps {
  location: VerifyLocation;
  /** Accessor, because merely reading `sessionStorage` can throw. */
  storage: () => RetryStorage | null;
  now: () => number;
  /** Runs the page's `onBeforeNavigate` callbacks (§12.1). */
  beforeNavigate?: () => void;
}

/** `min` of `/__mg/v`: only `interactive` exists (D-58). */
export type VerifyMin = "interactive";

/** `/__mg/v?ret=<ret>[&min=interactive]`; without a valid `ret` the Edge's `fallback_ret` applies. */
export function verifyUrl(config: Pick<MgConfig, "pathPrefix">, ret: string | null, min?: VerifyMin): string {
  const base = endpointPath(config, "v");
  const params: string[] = [];
  if (ret !== null && isValidRet(ret)) params.push(`ret=${encodeURIComponent(ret)}`);
  if (min === "interactive") params.push("min=interactive");
  return params.length > 0 ? `${base}?${params.join("&")}` : base;
}

/**
 * Send the page to the verify entry with its own path. False when the guard
 * holds (a navigation for this path within `VERIFY_GUARD_MS`) or storage is
 * unavailable. Never throws.
 */
export function startVerify(config: Pick<MgConfig, "pathPrefix">, deps: VerifyDeps, min?: VerifyMin): boolean {
  try {
    const ret = deps.location.pathname + deps.location.search;
    const store = deps.storage();
    if (store === null || store === undefined) return false;
    const key = VERIFY_KEY_PREFIX + ret;
    const now = deps.now();
    const last = Number(store.getItem(key) ?? Number.NaN);
    if (Number.isFinite(last) && last <= now && now - last < VERIFY_GUARD_MS) return false;
    store.setItem(key, String(now));
    if (store.getItem(key) !== String(now)) return false;
    deps.beforeNavigate?.();
    deps.location.assign(verifyUrl(config, ret, min));
    return true;
  } catch {
    return false;
  }
}

/**
 * True when `response` is the Edge's JSON challenge (403, JSON,
 * `MG-Challenge`, `error: mg_challenge`). Reads a clone, so the caller's
 * body is untouched.
 */
export async function isMgChallenge(response: Response): Promise<boolean> {
  const c = await classifyFetched(response);
  return c.kind === "mg" && c.result.kind === "mg_challenge";
}
