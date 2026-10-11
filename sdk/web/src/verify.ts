/**
 * The verify entry for challenged fetches (docs/impl/phase1-spec.md §10.5,
 * I-39).
 *
 * In Phase 1 a script cannot solve the Edge's JSON challenge in place. When
 * a fetch gets one, the page navigates to `/__mg/v?ret=<its own path>`: the
 * Edge serves the challenge page there, and the solved form returns to the
 * page with a `pow` clearance that the fetch's route accepts.
 *
 * One navigation per page path per `VERIFY_GUARD_MS` (sessionStorage
 * `mg_verify:<ret>`), so a fetch that is challenged again right after the
 * return cannot loop the visitor through the challenge. Without storage
 * the guard cannot hold, so the page stays put.
 */

import { endpointPath, type MgConfig } from "./config";
import { isValidRet, type RetryStorage } from "./challenge";
import { classifyResponse } from "./transport";

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
}

/** `/__mg/v?ret=<ret>`; without a valid `ret` the Edge's `fallback_ret` applies. */
export function verifyUrl(config: Pick<MgConfig, "pathPrefix">, ret: string | null): string {
  const base = endpointPath(config, "v");
  return ret !== null && isValidRet(ret) ? `${base}?ret=${encodeURIComponent(ret)}` : base;
}

/**
 * Send the page to the verify entry with its own path. False when the guard
 * holds (a navigation for this path within `VERIFY_GUARD_MS`) or storage is
 * unavailable. Never throws.
 */
export function startVerify(config: Pick<MgConfig, "pathPrefix">, deps: VerifyDeps): boolean {
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
    deps.location.assign(verifyUrl(config, ret));
    return true;
  } catch {
    return false;
  }
}

/**
 * True when `response` is the Edge's JSON challenge (403, JSON,
 * `error: mg_challenge`). Reads a clone, so the caller's body is untouched.
 */
export async function isMgChallenge(response: Response): Promise<boolean> {
  try {
    if (response.status !== 403) return false;
    const text = await response.clone().text();
    const c = classifyResponse(response, text);
    return c.kind === "mg" && c.result.kind === "mg_challenge";
  } catch {
    return false;
  }
}
