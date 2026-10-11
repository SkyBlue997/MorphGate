import { describe, expect, it } from "vitest";
import {
  classifyFetched,
  classifyResponse,
  isMgAnswer,
  detectUpstreamChallenge,
  MAX_SEALED_CHALLENGE_LENGTH,
  parseMgJson,
  UPSTREAM_CHALLENGE,
} from "../src/transport";
import { XorShift32 } from "./xorshift";

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
    expect(parseMgJson({ error: "mg_challenge_failed", retry: true, challenge: "has space" })).toEqual({
      kind: "not_mg",
      reason: "bad_challenge",
    });
  });

  it("parses a failure body without a fresh challenge (phase1-spec §10.3 omits it when there is no new C)", () => {
    expect(parseMgJson({ error: "mg_challenge_failed", retry: true, request_id: "r1" })).toEqual({
      kind: "mg_challenge_failed",
      retry: true,
      requestId: "r1",
    });
  });

  it("defaults retry to false unless it is literally true", () => {
    const result = parseMgJson({ error: "mg_challenge", type: "invisible", challenge: SEALED, retry: "yes" });
    expect(result).toMatchObject({ kind: "mg_challenge", retry: false });
  });
});

describe("parseMgJson: Phase 2 catalog (phase2-spec §11.2)", () => {
  it("keeps pow, ix, ret, request_id and now_ms of a challenge", () => {
    const body = {
      v: 2,
      error: "mg_challenge",
      type: "pow",
      challenge: SEALED,
      pow: { alg: "sha256-hashcash-v1", bits: 16 },
      ret: "/a?b=1",
      retry: true,
      request_id: "r1",
      now_ms: 1790000000123,
    };
    expect(parseMgJson(body)).toEqual({
      kind: "mg_challenge",
      type: "pow",
      challenge: SEALED,
      retry: true,
      pow: { alg: "sha256-hashcash-v1", bits: 16 },
      ret: "/a?b=1",
      requestId: "r1",
      nowMs: 1790000000123,
    });
    const ix = { v: 1, providers: ["self_hold", "pow_a11y"] };
    expect(parseMgJson({ error: "mg_challenge", type: "interactive", challenge: SEALED, ix })).toMatchObject({ ix });
  });

  it("parses mg_proof_required with and without the in-place recovery C", () => {
    expect(parseMgJson({ v: 2, error: "mg_proof_required", now_ms: 5, request_id: "r" })).toEqual({
      kind: "mg_proof_required",
      nowMs: 5,
      requestId: "r",
    });
    expect(
      parseMgJson({ error: "mg_proof_required", type: "pow", challenge: SEALED, pow: { alg: "sha256-hashcash-v1", bits: 12 }, ret: "/x" }),
    ).toEqual({ kind: "mg_proof_required", challenge: SEALED, pow: { alg: "sha256-hashcash-v1", bits: 12 }, ret: "/x" });
    // A C of another type is not an in-place recovery.
    expect(parseMgJson({ error: "mg_proof_required", type: "interactive", challenge: SEALED })).toEqual({
      kind: "mg_proof_required",
    });
  });

  it("parses the remaining error codes", () => {
    expect(parseMgJson({ error: "mg_rate_limited", retry_after: 30 })).toEqual({ kind: "mg_rate_limited", retryAfter: 30 });
    expect(parseMgJson({ error: "mg_refresh_denied", request_id: "r" })).toEqual({ kind: "mg_refresh_denied", requestId: "r" });
    expect(parseMgJson({ error: "mg_bad_request" })).toEqual({ kind: "mg_bad_request" });
    expect(parseMgJson({ error: "mg_too_early" })).toEqual({ kind: "mg_too_early" });
  });

  it("drops out-of-range pow specs and now_ms", () => {
    const r = parseMgJson({ error: "mg_challenge", type: "pow", challenge: SEALED, pow: { alg: "x", bits: 40 }, now_ms: -1 });
    expect(r).toEqual({ kind: "mg_challenge", type: "pow", challenge: SEALED, retry: false });
  });
});

describe("classifyResponse", () => {
  const challengeBody = JSON.stringify({ error: "mg_challenge", type: "interactive", challenge: SEALED, retry: true });
  const edgeJson = { "content-type": "application/json; charset=utf-8", "mg-challenge": "interactive" };

  it("prefers the upstream challenge over any body", () => {
    const res = response(403, { "cf-mitigated": "challenge", ...edgeJson });
    expect(classifyResponse(res, challengeBody)).toEqual({ kind: UPSTREAM_CHALLENGE });
  });

  it("classifies the Edge's JSON answers: 403, JSON, MG-Challenge or MG-Error", () => {
    expect(classifyResponse(response(403, edgeJson), challengeBody)).toEqual({
      kind: "mg",
      result: { kind: "mg_challenge", type: "interactive", challenge: SEALED, retry: true },
    });
    const blocked = response(403, { "content-type": "application/json", "mg-error": "mg_blocked" });
    expect(classifyResponse(blocked, '{"error":"mg_blocked"}')).toEqual({ kind: "mg", result: { kind: "mg_blocked" } });
    expect(classifyResponse(response(403, { "mg-challenge": "pow", "content-type": "text/html" }), challengeBody)).toEqual({
      kind: "pass",
    });
    expect(classifyResponse(response(200, edgeJson), challengeBody)).toEqual({ kind: "pass" });
    expect(classifyResponse(response(403, edgeJson))).toEqual({ kind: "pass" });
  });

  it("leaves an origin's own 403 and 429 alone, even with a look-alike body (S-22)", () => {
    expect(classifyResponse(response(403, { "content-type": "application/json" }), challengeBody)).toEqual({ kind: "pass" });
    expect(classifyResponse(response(403, { "content-type": "application/problem+json" }), '{"error":"forbidden"}')).toEqual({
      kind: "pass",
    });
    expect(classifyResponse(response(429, { "retry-after": "30" }))).toEqual({ kind: "pass" });
  });

  it("maps the Edge's 429 with Retry-After and 425 Too Early", () => {
    expect(classifyResponse(response(429, { "retry-after": "30", "mg-error": "mg_rate_limited" }))).toEqual({
      kind: "rate_limited",
      retryAfterSeconds: 30,
    });
    expect(
      classifyResponse(response(429, { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT", "mg-error": "mg_rate_limited" })),
    ).toEqual({ kind: "rate_limited" });
    expect(classifyResponse(response(425))).toEqual({ kind: "too_early" });
  });

  it("classifyFetched reads a clone and isMgAnswer gates the read", async () => {
    const r = new Response(challengeBody, { status: 403, headers: edgeJson });
    expect(isMgAnswer(r)).toBe(true);
    expect((await classifyFetched(r)).kind).toBe("mg");
    expect(await r.text()).toBe(challengeBody);
    expect(isMgAnswer(new Response("x", { status: 403, headers: { "content-type": "application/json" } }))).toBe(false);
  });
});

describe("random input never throws (phase1-spec §2.4)", () => {
  it("parseMgJson over 10,000 xorshift bodies", () => {
    const rng = new XorShift32(0x7a45);
    const errors = ["mg_challenge", "mg_challenge_failed", "mg_blocked", "mg_proof_required", "agent_scope_denied", "mg_rate_limited", "mg_refresh_denied", "other"];
    for (let i = 0; i < 10_000; i++) {
      const shaped = {
        error: rng.pick(errors),
        type: rng.pick(["pow", "invisible", "interactive", rng.string(8), 7, null]),
        challenge: rng.pick([SEALED, rng.string(40), undefined, 42, null]),
        retry: rng.pick([true, false, "true", undefined]),
        request_id: rng.pick([rng.string(20), "r1", undefined, {}]),
        pow: rng.pick([{ alg: "sha256-hashcash-v1", bits: rng.below(40) }, { alg: rng.string(4), bits: "8" }, null, undefined]),
        ix: rng.pick([{ v: 1 }, [], "x", undefined]),
        ret: rng.pick(["/", rng.string(30), 1, undefined]),
        now_ms: rng.pick([1790000000000, -1, 1.5, "1", undefined]),
        retry_after: rng.pick([30, -1, 1e9, "3", undefined]),
      };
      const input: unknown = rng.pick([shaped, JSON.stringify(shaped), rng.string(64), rng.string(8), null, [], 3]);
      const result = parseMgJson(input);
      expect(typeof result.kind).toBe("string");
      if (result.kind === "mg_challenge_failed" && result.challenge !== undefined) expect(result.challenge.length).toBeGreaterThan(0);
    }
  });
});
