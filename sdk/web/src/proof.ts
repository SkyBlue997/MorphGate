/**
 * `MG-Proof` (docs/impl/phase2-spec.md §6.7, §12.5, D-40), the clearance
 * status cookie `__Host-mg_st` (§6.8) and the client clock skew (§12.5).
 *
 * MG-Proof is a compact JWS, ES256:
 *   header  {"alg":"ES256","typ":"mg-proof+jwt","jwk":{"kty":"EC","crv":"P-256","x","y"}}
 *   payload {"htm","htu","iat","jti"}
 * - `htm` is the method string the browser actually sends: fetch upper-cases
 *   only DELETE, GET, HEAD, OPTIONS, POST and PUT (case-insensitively);
 *   any other method (`patch`) goes out as written, and is signed as written;
 * - `htu` is `https://<host><path>` without query and fragment; above 2048
 *   bytes no proof is attached;
 * - `iat` is the estimated server time in seconds, `floor((Date.now() + skew) / 1000)`;
 * - `jti` is 16 random bytes (22 base64url characters).
 * The protected header is cached per key (`SessionKey.proofHeader`), so a
 * request costs one payload and one signature.
 */

import { base64UrlEncode } from "./crypto";
import type { SessionKey } from "./keystore";
import { es256Sign } from "./sig";

export const STATUS_COOKIE = "__Host-mg_st";
export const MAX_HTU_BYTES = 2048;
export const SKEW_KEY = "mg_skew";
const NORMALIZED_METHODS = ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"];
const STATUS_PATTERN = /^(\d{1,12})\.(\d{1,12})\.([01])$/;

/** `<iat>.<exp>.<b>` of `__Host-mg_st`: Unix seconds, and whether the clearance is key-bound. */
export interface ClearanceStatus {
  iat: number;
  exp: number;
  bound: boolean;
}

/** Read `__Host-mg_st` from a `document.cookie` string; null when absent or malformed. */
export function parseStatusCookie(cookie: string | null | undefined): ClearanceStatus | null {
  if (typeof cookie !== "string") return null;
  for (const part of cookie.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0 || part.slice(0, eq).trim() !== STATUS_COOKIE) continue;
    const m = STATUS_PATTERN.exec(part.slice(eq + 1).trim());
    if (m === null) return null;
    const iat = Number(m[1]);
    const exp = Number(m[2]);
    return exp > iat ? { iat, exp, bound: m[3] === "1" } : null;
  }
  return null;
}

/** The status cookie names a clearance that has not expired at `nowS` (server seconds). */
export function statusValid(status: ClearanceStatus | null, nowS: number): status is ClearanceStatus {
  return status !== null && status.exp > nowS;
}

/** The method string fetch sends for `method` (Fetch "normalize a method"). */
export function wireMethod(method: string): string {
  const upper = method.toUpperCase();
  return NORMALIZED_METHODS.includes(upper) ? upper : method;
}

/** `https://<host><path>` for a request URL; null above 2048 bytes. */
export function proofHtu(url: URL): string | null {
  const htu = `https://${url.host}${url.pathname}`;
  return new TextEncoder().encode(htu).byteLength <= MAX_HTU_BYTES ? htu : null;
}

export interface ProofInput {
  method: string;
  htu: string;
  iat: number;
  jti: Uint8Array;
}

/** The compact JWS for `input`, signed with `key`. */
export async function buildProof(subtle: SubtleCrypto, key: SessionKey, input: ProofInput): Promise<string> {
  const payload = JSON.stringify({ htm: input.method, htu: input.htu, iat: input.iat, jti: base64UrlEncode(input.jti) });
  const signingInput = `${key.proofHeader}.${base64UrlEncode(new TextEncoder().encode(payload))}`;
  const sig = await es256Sign(subtle, key.privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${sig}`;
}

export interface SkewStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * Estimated `server time - Date.now()` in ms. Updated from the `now_ms` of
 * any MorphGate JSON answer, or from the `Date` header of any same-origin
 * response (second resolution, enough for the ±30 s proof window), and kept
 * in sessionStorage `mg_skew` across page loads.
 */
export class Clock {
  skewMs = 0;

  constructor(
    private readonly now: () => number,
    private readonly storage: () => SkewStorage | null,
  ) {
    try {
      const saved = Number(this.storage()?.getItem(SKEW_KEY) ?? Number.NaN);
      if (Number.isSafeInteger(saved) && Math.abs(saved) < 86_400_000 * 366) this.skewMs = saved;
    } catch {
      // No storage: start at 0.
    }
  }

  serverNowMs(): number {
    return this.now() + this.skewMs;
  }

  serverNowS(): number {
    return Math.floor(this.serverNowMs() / 1000);
  }

  private set(skew: number): void {
    this.skewMs = Math.round(skew);
    try {
      this.storage()?.setItem(SKEW_KEY, String(this.skewMs));
    } catch {
      // Keep it for this page only.
    }
  }

  /** From an Edge `now_ms`; returns the previous estimate's error in ms. */
  fromNowMs(nowMs: unknown): number {
    if (typeof nowMs !== "number" || !Number.isSafeInteger(nowMs) || nowMs <= 0) return 0;
    const error = nowMs - this.serverNowMs();
    this.set(nowMs - this.now());
    return error;
  }

  /** From a `Date` header: adopted only when the estimate falls outside that second (plus latency). */
  fromDateHeader(value: string | null): void {
    if (value === null) return;
    const dateMs = Date.parse(value);
    if (!Number.isFinite(dateMs)) return;
    const estimate = this.serverNowMs();
    if (estimate < dateMs - 1000 || estimate > dateMs + 2000) this.set(dateMs + 500 - this.now());
  }
}
