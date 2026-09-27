/**
 * Response classification for the SDK transport layer.
 *
 * Two kinds of "challenge" can come back from a protected request when the
 * site sits behind Cloudflare, and they must never be confused:
 *
 * - an upstream Cloudflare challenge page, marked with `cf-mitigated: challenge`
 *   (the only documented value). The SDK treats it as "upstream challenged":
 *   top-level reload plus telemetry, never a MorphGate failure (docs/04 §7);
 * - a MorphGate JSON challenge / error body (docs/04 §9).
 *
 * Phase 0 is classification only: pure functions over Response-like objects,
 * no fetch wrapping, no retries, no navigation. Phase 2 adds the fetch/XHR
 * wrapper that attaches MG-Proof and acts on these results.
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

export type MgJsonResult =
  | { kind: "mg_challenge"; type: ChallengeType; challenge: string; retry: boolean }
  | { kind: "mg_challenge_failed"; challenge: string; retry: boolean; requestId?: string }
  | { kind: "mg_proof_required" }
  | { kind: "mg_blocked"; requestId?: string }
  | { kind: "agent_scope_denied"; requestId?: string }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isChallengeType(value: unknown): value is ChallengeType {
  return typeof value === "string" && (CHALLENGE_TYPES as readonly string[]).includes(value);
}

function isSealedChallenge(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_SEALED_CHALLENGE_LENGTH &&
    SEALED_CHALLENGE_PATTERN.test(value)
  );
}

function optionalRequestId(body: Record<string, unknown>): { requestId?: string } {
  const id = body["request_id"];
  return typeof id === "string" && REQUEST_ID_PATTERN.test(id) ? { requestId: id } : {};
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
      if (!isSealedChallenge(challenge)) return { kind: "not_mg", reason: "bad_challenge" };
      return { kind: "mg_challenge", type, challenge, retry };
    }
    case "mg_challenge_failed": {
      const challenge = body["challenge"];
      if (!isSealedChallenge(challenge)) return { kind: "not_mg", reason: "bad_challenge" };
      return { kind: "mg_challenge_failed", challenge, retry, ...optionalRequestId(body) };
    }
    case "mg_proof_required":
      return { kind: "mg_proof_required" };
    case "mg_blocked":
      return { kind: "mg_blocked", ...optionalRequestId(body) };
    case "agent_scope_denied":
      return { kind: "agent_scope_denied", ...optionalRequestId(body) };
    default:
      return { kind: "not_mg", reason: "unknown_error_code" };
  }
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(";")[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

/** Parse Retry-After as delta-seconds; HTTP-date values are ignored in Phase 0. */
function retryAfterSeconds(value: string | null): { retryAfterSeconds?: number } {
  if (value === null || !/^\d{1,9}$/.test(value.trim())) return {};
  return { retryAfterSeconds: Number(value.trim()) };
}

/**
 * Classify a completed response. `bodyText` is optional because callers only
 * need to read the body for JSON 403s; the upstream-challenge check wins over
 * everything else since a Cloudflare page never carries a MorphGate body.
 */
export function classifyResponse(response: ResponseLike, bodyText?: string): Classification {
  if (detectUpstreamChallenge(response) !== null) return { kind: UPSTREAM_CHALLENGE };
  if (response.status === 429) {
    return { kind: "rate_limited", ...retryAfterSeconds(response.headers.get("retry-after")) };
  }
  if (response.status === 425) return { kind: "too_early" };
  if (response.status === 403 && bodyText !== undefined && isJsonContentType(response.headers.get("content-type"))) {
    const result = parseMgJson(bodyText);
    if (result.kind !== "not_mg") return { kind: "mg", result };
  }
  return { kind: "pass" };
}
