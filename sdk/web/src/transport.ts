/**
 * Response classification for the SDK transport layer
 * (docs/impl/phase2-spec.md §11.2, §12.5).
 *
 * Two kinds of "challenge" can come back from a protected request when the
 * site sits behind Cloudflare, and they must never be confused:
 *
 * - an upstream Cloudflare challenge page, marked with `cf-mitigated: challenge`
 *   (the only documented value): reload plus a report, never a MorphGate
 *   failure (docs/04 §7);
 * - a MorphGate JSON answer (§11.2). Only a 403 or 429 that carries
 *   `MG-Error` or `MG-Challenge` is one: the Edge strips `MG-*` from origin
 *   responses, so an origin cannot make the SDK solve or navigate with a
 *   look-alike body (S-22).
 *
 * Pure functions over Response-like objects; `fetch.ts` acts on the result.
 */

/** Challenge types a server may ask the SDK to run (mirrors proto ChallengeType). */
export const CHALLENGE_TYPES = ["invisible", "pow", "interactive", "attestation", "step_up"] as const;
export type ChallengeType = (typeof CHALLENGE_TYPES)[number];

/** Sealed challenges are opaque tokens; cap their size so a hostile body cannot bloat memory. */
export const MAX_SEALED_CHALLENGE_LENGTH = 4096;
const SEALED_CHALLENGE_PATTERN = /^[A-Za-z0-9._~+/=-]+$/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export const UPSTREAM_CHALLENGE = "upstream_challenge" as const;

/** Minimal structural view of a fetch Response, so tests and XHR adapters can supply their own. */
export interface ResponseLike {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
}

/** The `pow` member of a non-interactive JSON challenge: `{alg, bits}` (`k` for v2). */
export interface PowSpec {
  alg: string;
  bits: number;
  k?: number;
}

interface Extras {
  requestId?: string;
  nowMs?: number;
}

export type MgJsonResult =
  | ({
      kind: "mg_challenge";
      type: ChallengeType;
      challenge: string;
      retry: boolean;
      pow?: PowSpec;
      /** Interactive: the plain parameters (§7.2), validated by the control. */
      ix?: Record<string, unknown>;
      ret?: string;
    } & Extras)
  /** `challenge` is the fresh C, absent when the Edge attaches none (phase1-spec §10.3). */
  | ({
      kind: "mg_challenge_failed";
      challenge?: string;
      type?: ChallengeType;
      pow?: PowSpec;
      ix?: Record<string, unknown>;
      retry: boolean;
    } & Extras)
  /** With a `pow` C bound to the proof's key when the Edge offers in-place recovery (§9.1). */
  | ({ kind: "mg_proof_required"; challenge?: string; pow?: PowSpec; ret?: string } & Extras)
  | ({ kind: "mg_blocked" } & Extras)
  | ({ kind: "mg_rate_limited"; retryAfter?: number } & Extras)
  | ({ kind: "mg_refresh_denied" } & Extras)
  | ({ kind: "mg_bad_request" } & Extras)
  | ({ kind: "mg_too_early" } & Extras)
  | ({ kind: "agent_scope_denied" } & Extras)
  | { kind: "not_mg"; reason: string };

export type Classification =
  | { kind: typeof UPSTREAM_CHALLENGE }
  | { kind: "mg"; result: Exclude<MgJsonResult, { kind: "not_mg" }> }
  | { kind: "rate_limited"; retryAfterSeconds?: number }
  | { kind: "too_early" }
  | { kind: "pass" };

/**
 * Detect Cloudflare's challenge marker. Header lookup through `Headers.get`
 * is case-insensitive; the value comparison is too, to be lenient.
 */
export function detectUpstreamChallenge(response: ResponseLike): typeof UPSTREAM_CHALLENGE | null {
  const value = response.headers.get("cf-mitigated");
  return value !== null && value.trim().toLowerCase() === "challenge" ? UPSTREAM_CHALLENGE : null;
}

/** The response carries `MG-Error` or `MG-Challenge`, which only the Edge can set (§11.2). */
export function hasMgHeader(response: ResponseLike): boolean {
  return response.headers.get("mg-error") !== null || response.headers.get("mg-challenge") !== null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isChallengeType(value: unknown): value is ChallengeType {
  return typeof value === "string" && (CHALLENGE_TYPES as readonly string[]).includes(value);
}

export function isSealedChallengeToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_SEALED_CHALLENGE_LENGTH &&
    SEALED_CHALLENGE_PATTERN.test(value)
  );
}

function extras(body: Record<string, unknown>): Extras {
  const out: Extras = {};
  const id = body["request_id"];
  if (typeof id === "string" && REQUEST_ID_PATTERN.test(id)) out.requestId = id;
  const now = body["now_ms"];
  if (typeof now === "number" && Number.isSafeInteger(now) && now > 0) out.nowMs = now;
  return out;
}

function powSpec(value: unknown): { pow?: PowSpec } {
  if (!isRecord(value)) return {};
  const { alg, bits, k } = value;
  if (typeof alg !== "string" || typeof bits !== "number" || !Number.isInteger(bits) || bits < 0 || bits > 32) return {};
  const spec: PowSpec = { alg, bits };
  if (typeof k === "number" && Number.isInteger(k) && k >= 1 && k <= 8) spec.k = k;
  return { pow: spec };
}

/** Optional members of a challenge-carrying body: `pow`, `ix`, `ret`. */
function challengeExtras(body: Record<string, unknown>): { pow?: PowSpec; ix?: Record<string, unknown>; ret?: string } {
  const out: { pow?: PowSpec; ix?: Record<string, unknown>; ret?: string } = powSpec(body["pow"]);
  if (isRecord(body["ix"])) out.ix = body["ix"];
  const ret = body["ret"];
  if (typeof ret === "string" && ret.length <= 2048) out.ret = ret;
  return out;
}

/**
 * Parse a MorphGate JSON error body. Accepts either the raw text or an
 * already-parsed value. Anything that does not match the documented shapes
 * is `not_mg`, so an origin API's own 403 bodies are left alone.
 */
export function parseMgJson(input: unknown): MgJsonResult {
  let body: unknown = input;
  if (typeof input === "string") {
    try {
      body = JSON.parse(input);
    } catch {
      return { kind: "not_mg", reason: "invalid_json" };
    }
  }
  if (!isRecord(body)) return { kind: "not_mg", reason: "not_an_object" };

  const error = body["error"];
  const retry = body["retry"] === true;
  switch (error) {
    case "mg_challenge": {
      const type = body["type"];
      const challenge = body["challenge"];
      if (!isChallengeType(type)) return { kind: "not_mg", reason: "unknown_challenge_type" };
      if (!isSealedChallengeToken(challenge)) return { kind: "not_mg", reason: "bad_challenge" };
      return { kind: "mg_challenge", type, challenge, retry, ...challengeExtras(body), ...extras(body) };
    }
    case "mg_challenge_failed": {
      const challenge = body["challenge"];
      if (challenge === undefined) return { kind: "mg_challenge_failed", retry, ...extras(body) };
      if (!isSealedChallengeToken(challenge)) return { kind: "not_mg", reason: "bad_challenge" };
      const type = body["type"];
      return {
        kind: "mg_challenge_failed",
        challenge,
        retry,
        ...(isChallengeType(type) ? { type } : {}),
        ...challengeExtras(body),
        ...extras(body),
      };
    }
    case "mg_proof_required": {
      const challenge = body["challenge"];
      const base = { kind: "mg_proof_required" as const, ...extras(body) };
      if (body["type"] === "pow" && isSealedChallengeToken(challenge)) {
        const { pow, ret } = challengeExtras(body);
        return { ...base, challenge, ...(pow ? { pow } : {}), ...(ret !== undefined ? { ret } : {}) };
      }
      return base;
    }
    case "mg_rate_limited": {
      const after = body["retry_after"];
      return {
        kind: "mg_rate_limited",
        ...(typeof after === "number" && Number.isInteger(after) && after >= 0 && after < 86_400 ? { retryAfter: after } : {}),
        ...extras(body),
      };
    }
    case "mg_blocked":
    case "mg_refresh_denied":
    case "mg_bad_request":
    case "mg_too_early":
    case "agent_scope_denied":
      return { kind: error, ...extras(body) };
    default:
      return { kind: "not_mg", reason: "unknown_error_code" };
  }
}

export function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(";")[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

/** Parse Retry-After as delta-seconds; HTTP-date values are ignored. */
function retryAfterSeconds(value: string | null): { retryAfterSeconds?: number } {
  if (value === null || !/^\d{1,9}$/.test(value.trim())) return {};
  return { retryAfterSeconds: Number(value.trim()) };
}

/** Retry-After in seconds, default `fallback`, capped at one hour. */
export function retryAfterOf(response: ResponseLike, fallback = 5): number {
  return Math.min(3600, retryAfterSeconds(response.headers.get("retry-after")).retryAfterSeconds ?? fallback);
}

/** The body is worth reading: a 403 / 429 from the Edge with a JSON body. */
export function isMgAnswer(response: ResponseLike): boolean {
  return (
    (response.status === 403 || response.status === 429) &&
    hasMgHeader(response) &&
    isJsonContentType(response.headers.get("content-type"))
  );
}

/**
 * Classify a completed response. `bodyText` is optional because callers only
 * need to read the body for the Edge's JSON 403s; the upstream-challenge
 * check wins over everything else since a Cloudflare page never carries a
 * MorphGate body. A 403 or 429 without `MG-Error` / `MG-Challenge` is the
 * origin's and passes through untouched.
 */
export function classifyResponse(response: ResponseLike, bodyText?: string): Classification {
  if (detectUpstreamChallenge(response) !== null) return { kind: UPSTREAM_CHALLENGE };
  if (response.status === 425) return { kind: "too_early" };
  if ((response.status !== 403 && response.status !== 429) || !hasMgHeader(response)) return { kind: "pass" };
  if (response.status === 429) {
    return { kind: "rate_limited", ...retryAfterSeconds(response.headers.get("retry-after")) };
  }
  if (bodyText !== undefined && isJsonContentType(response.headers.get("content-type"))) {
    const result = parseMgJson(bodyText);
    if (result.kind !== "not_mg") return { kind: "mg", result };
  }
  return { kind: "pass" };
}

/** Read and classify `response` without consuming its body. Never rejects. */
export async function classifyFetched(response: Response): Promise<Classification> {
  try {
    const text = isMgAnswer(response) && response.status === 403 ? await response.clone().text() : undefined;
    return classifyResponse(response, text);
  } catch {
    return { kind: "pass" };
  }
}
