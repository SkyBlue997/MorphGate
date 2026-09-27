import { describe, expect, it } from "vitest";
import {
  classifyResponse,
  detectUpstreamChallenge,
  MAX_SEALED_CHALLENGE_LENGTH,
  parseMgJson,
  UPSTREAM_CHALLENGE,
} from "../src/transport";

const SEALED = "v1.AbC_-dEf.123~xyz";

function response(status: number, headers: Record<string, string> = {}): Response {
  return new Response(null, { status, headers });
}

describe("detectUpstreamChallenge (cf-mitigated)", () => {
  it("recognises Cloudflare's challenge marker regardless of header case", () => {
    expect(detectUpstreamChallenge(response(403, { "cf-mitigated": "challenge" }))).toBe(UPSTREAM_CHALLENGE);
    expect(detectUpstreamChallenge(response(403, { "CF-Mitigated": "Challenge" }))).toBe(UPSTREAM_CHALLENGE);
    expect(detectUpstreamChallenge(response(200, { "cf-mitigated": " challenge " }))).toBe(UPSTREAM_CHALLENGE);
  });

  it("ignores absent or other values", () => {
    expect(detectUpstreamChallenge(response(403))).toBeNull();
    expect(detectUpstreamChallenge(response(403, { "cf-mitigated": "block" }))).toBeNull();
    expect(detectUpstreamChallenge(response(403, { "x-cf-mitigated": "challenge" }))).toBeNull();
  });
});

describe("parseMgJson", () => {
  it("parses a MorphGate JSON challenge", () => {
    const body = JSON.stringify({ error: "mg_challenge", type: "pow", challenge: SEALED, retry: true });
    expect(parseMgJson(body)).toEqual({ kind: "mg_challenge", type: "pow", challenge: SEALED, retry: true });
  });

  it("parses failure bodies with a fresh challenge and request id", () => {
    const body = { error: "mg_challenge_failed", retry: true, request_id: "req-01:ab", challenge: SEALED };
    expect(parseMgJson(body)).toEqual({
      kind: "mg_challenge_failed",
      challenge: SEALED,
      retry: true,
      requestId: "req-01:ab",
    });
  });

  it("parses the other documented error codes", () => {
    expect(parseMgJson('{"error":"mg_proof_required"}')).toEqual({ kind: "mg_proof_required" });
    expect(parseMgJson('{"error":"mg_blocked","request_id":"r1"}')).toEqual({ kind: "mg_blocked", requestId: "r1" });
    expect(parseMgJson('{"error":"agent_scope_denied"}')).toEqual({ kind: "agent_scope_denied" });
  });

  it("drops request ids that are not plain tokens", () => {
    expect(parseMgJson({ error: "mg_blocked", request_id: "<script>" })).toEqual({ kind: "mg_blocked" });
  });

  it("treats malformed or foreign bodies as not_mg", () => {
    expect(parseMgJson("not json").kind).toBe("not_mg");
    expect(parseMgJson("[1,2]").kind).toBe("not_mg");
    expect(parseMgJson("null").kind).toBe("not_mg");
    expect(parseMgJson({ error: "forbidden" }).kind).toBe("not_mg");
    expect(parseMgJson({ error: "mg_challenge", type: "slider", challenge: SEALED })).toEqual({
      kind: "not_mg",
      reason: "unknown_challenge_type",
    });
    expect(parseMgJson({ error: "mg_challenge", type: "pow" })).toEqual({ kind: "not_mg", reason: "bad_challenge" });
    expect(parseMgJson({ error: "mg_challenge", type: "pow", challenge: "has space" }).kind).toBe("not_mg");
    expect(
      parseMgJson({ error: "mg_challenge", type: "pow", challenge: "a".repeat(MAX_SEALED_CHALLENGE_LENGTH + 1) }).kind,
    ).toBe("not_mg");
    expect(parseMgJson({ error: "mg_challenge_failed", retry: true }).kind).toBe("not_mg");
  });

  it("defaults retry to false unless it is literally true", () => {
    const result = parseMgJson({ error: "mg_challenge", type: "invisible", challenge: SEALED, retry: "yes" });
    expect(result).toMatchObject({ kind: "mg_challenge", retry: false });
  });
});

describe("classifyResponse", () => {
  const challengeBody = JSON.stringify({ error: "mg_challenge", type: "interactive", challenge: SEALED, retry: true });

  it("prefers the upstream challenge over any body", () => {
    const res = response(403, { "cf-mitigated": "challenge", "content-type": "application/json" });
    expect(classifyResponse(res, challengeBody)).toEqual({ kind: UPSTREAM_CHALLENGE });
  });

  it("classifies MorphGate JSON challenges on 403 JSON responses only", () => {
    const res = response(403, { "content-type": "application/json; charset=utf-8" });
    expect(classifyResponse(res, challengeBody)).toEqual({
      kind: "mg",
      result: { kind: "mg_challenge", type: "interactive", challenge: SEALED, retry: true },
    });
    expect(classifyResponse(response(403, { "content-type": "text/html" }), challengeBody)).toEqual({ kind: "pass" });
    expect(classifyResponse(response(200, { "content-type": "application/json" }), challengeBody)).toEqual({
      kind: "pass",
    });
    expect(classifyResponse(response(403, { "content-type": "application/json" }))).toEqual({ kind: "pass" });
  });

  it("leaves an origin's own 403 JSON alone", () => {
    const res = response(403, { "content-type": "application/problem+json" });
    expect(classifyResponse(res, '{"error":"forbidden"}')).toEqual({ kind: "pass" });
  });

  it("maps 429 with Retry-After and 425 Too Early", () => {
    expect(classifyResponse(response(429, { "retry-after": "30" }))).toEqual({
      kind: "rate_limited",
      retryAfterSeconds: 30,
    });
    expect(classifyResponse(response(429, { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" }))).toEqual({
      kind: "rate_limited",
    });
    expect(classifyResponse(response(425))).toEqual({ kind: "too_early" });
  });
});
