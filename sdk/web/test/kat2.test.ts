// Phase 2 known-answer vectors (docs/impl/phase2-spec.md §6.3–§6.7, §6.11, §12.10),
// read straight from testdata/phase2/kat.json: PoW v2, JWK thumbprints, ES256
// (verified with WebCrypto), submission and renew messages, ui_params, and
// MG-Proof (a reference verifier of the §6.7 rules agrees with every vector,
// and the proofs the SDK builds pass it).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { jwkThumbprint, type EcP256PublicJwk } from "../src/crypto";
import { proofHeaderB64, type SessionKey } from "../src/keystore";
import { buildProof, proofHtu, wireMethod } from "../src/proof";
import { PowSolverV2, powDigestV2, powPrefixV2, verifyPowV2 } from "../src/powv2";
import { leadingZeroBits, toHex } from "../src/sha256";
import { renewMessage, submissionMessage } from "../src/sig";
import { signedRenew, signedSubmission } from "../src/submit";
import { uiParams } from "../src/ui";
import { b64urlDecode, cloudflareView, es256Verify, referenceVerify } from "./proofref";

const lastOf = <T>(items: readonly T[]): T => items[items.length - 1] as T;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;
const KAT: Json = JSON.parse(readFileSync(new URL("../../../testdata/phase2/kat.json", import.meta.url), "utf8"));
const subtle = globalThis.crypto.subtle;

const hex = (h: string): Uint8Array<ArrayBuffer> => Uint8Array.from((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));

describe("kat.json pow_v2 (§6.4)", () => {
  for (const c of KAT.pow_v2.cases) {
    it(`${c.c} d=${c.d} k=${c.k}`, () => {
      const prefix = powPrefixV2(c.c);
      expect(toHex(prefix)).toBe(c.prefix_hex);
      for (const p of c.sub_puzzles) {
        expect(toHex(powDigestV2(prefix, p.i, p.counter))).toBe(p.digest_hex);
        expect(leadingZeroBits(powDigestV2(prefix, p.i, p.counter))).toBe(p.leading_zero_bits);
        const solver = new PowSolverV2(prefix, c.d, p.i);
        expect(toHex(solver.digest(p.counter))).toBe(p.digest_hex);
        // The search from 0 finds the canonical counter.
        expect(solver.search(0, p.counter + 1)).toBe(p.counter);
      }
      expect(verifyPowV2(prefix, c.d, c.counters)).toBe(true);
      expect(verifyPowV2(prefix, c.d + 32, c.counters)).toBe(false);
      const counters = c.counters as number[];
      const lastCounter = lastOf(counters);
      // The canonical counter is the smallest: one less never solves the last sub-puzzle.
      expect(verifyPowV2(prefix, c.d, counters.slice(0, -1).concat([lastCounter - 1]))).toBe(false);
    });
  }
});

describe("kat.json jwk_thumbprint (§6.5)", () => {
  it("RFC 7638 §3.1 example", async () => {
    const ex = KAT.jwk_thumbprint.rfc7638_example;
    const jwk = JSON.parse(ex.canonical_json);
    expect(await jwkThumbprint(jwk, subtle)).toBe(ex.thumbprint);
  });
  for (const c of KAT.jwk_thumbprint.cases) {
    it(c.name, async () => {
      expect(await jwkThumbprint(c.jwk, subtle)).toBe(c.thumbprint);
    });
  }
  it("test_keys carry their thumbprints", async () => {
    for (const k of KAT.test_keys.keys) expect(await jwkThumbprint(k.jwk, subtle)).toBe(k.jkt);
  });
});

describe("kat.json es256 (§6.5), verified with WebCrypto", () => {
  for (const c of KAT.es256.cases) {
    it(c.name, async () => {
      expect(await es256Verify(c.jwk, hex(c.msg_hex), c.sig_b64url)).toBe(c.valid);
    });
  }
});

describe("kat.json submission_message and renew_message (§6.6)", () => {
  for (const c of KAT.submission_message.cases) {
    it(c.name, async () => {
      const f = c.fields;
      const message = submissionMessage({ ...f, counters: f.counters });
      expect(toHex(message)).toBe(c.message_hex);
      expect(f.counters.join(",")).toBe(c.counters_text);
      expect(await es256Verify(c.jwk, message, c.sig_b64url)).toBe(true);
    });
  }
  for (const c of KAT.renew_message.cases) {
    it(c.name, async () => {
      const message = renewMessage(c.c, c.ts);
      expect(toHex(message)).toBe(c.message_hex);
      expect(await es256Verify(c.jwk, message, c.sig_b64url)).toBe(true);
    });
  }
  it("rejects fields that do not fit lp() or u64", () => {
    const base = { c: "c", type: "pow", p: "", pp: "", t: "", counters: [1], ret: "/", ts: 0, build: "0".repeat(16) };
    expect(() => submissionMessage({ ...base, ret: "/" + "a".repeat(65_535) })).toThrow(RangeError);
    expect(() => submissionMessage({ ...base, ts: -1 })).toThrow(RangeError);
    expect(() => renewMessage("c", 2 ** 53)).toThrow(RangeError);
  });
});

describe("kat.json ui_params (§6.3)", () => {
  for (const c of KAT.ui_params.cases) {
    it(`ui_seed ${c.ui_seed}`, () => {
      expect(uiParams(BigInt(c.ui_seed))).toEqual({
        requiredHoldMs: c.required_hold_ms,
        offsetXPx: c.offset_x_px,
        offsetYPx: c.offset_y_px,
      });
    });
  }
});

// ---------------------------------------------------------------------------
// MG-Proof: a reference verifier of §6.7, checked against every vector

describe("kat.json mg_proof (§6.7): the reference verifier agrees with every vector", () => {
  for (const c of KAT.mg_proof.cases) {
    it(`${c.name} -> ${c.expect}`, async () => {
      expect(await referenceVerify(c.mg_proof, c.request)).toBe(c.expect);
    });
  }
  it("cloudflareView matches the Rust helper on the vector paths", () => {
    expect(cloudflareView("/api/v1/../save")).toBe("/api/save");
    expect(cloudflareView("/api%2fsave")).toBe("/api%2Fsave");
    expect(cloudflareView("/a//b/./c/..")).toBe("/a/b/");
  });
});

// ---------------------------------------------------------------------------
// Proofs and signatures the SDK builds

async function sdkKey(): Promise<SessionKey> {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const raw = await subtle.exportKey("jwk", pair.publicKey);
  const jwk: EcP256PublicJwk = { kty: "EC", crv: "P-256", x: raw.x!, y: raw.y! };
  return { privateKey: pair.privateKey, jwk, jkt: await jwkThumbprint(jwk, subtle), createdMs: 0, proofHeader: proofHeaderB64(jwk) };
}

describe("MG-Proof built by the SDK (§12.5) passes the §6.7 rules", () => {
  const now = 1_790_000_000;
  const jti = Uint8Array.from({ length: 16 }, (_, n) => n);

  it.each([
    ["POST", "https://example.com/api/save?draft=1#top", "POST", "/api/save"],
    ["patch", "https://example.com/api/save", "patch", "/api/save"],
    ["delete", "https://Example.COM/api/x", "DELETE", "/api/x"],
    ["GET", "https://example.com/caf%C3%A9", "GET", "/caf%C3%A9"],
  ])("%s %s", async (method, url, wire, path) => {
    const key = await sdkKey();
    const htu = proofHtu(new URL(url));
    expect(htu).not.toBeNull();
    expect(htu).not.toMatch(/[?#]/);
    expect(wireMethod(method)).toBe(wire);
    const proof = await buildProof(subtle, key, { method: wireMethod(method), htu: htu!, iat: now, jti });
    const req = { method: wire, scheme: "https", host: "example.com", path, now_s: now, expected_jkt: key.jkt };
    expect(await referenceVerify(proof, req)).toBe("valid");
    expect(await referenceVerify(proof, { ...req, expected_jkt: null })).toBe("proof.unbound");
    expect(await referenceVerify(proof, { ...req, now_s: now + 31 })).toBe("proof.iat");
    // The protected header has exactly the three members, the JWK exactly four.
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(proof.split(".")[0]!)!));
    expect(Object.keys(header)).toEqual(["alg", "typ", "jwk"]);
    expect(Object.keys(header.jwk)).toEqual(["kty", "crv", "x", "y"]);
    expect(proof.length).toBeLessThanOrEqual(4096);
  });

  it("no proof for an htu above 2048 bytes", () => {
    expect(proofHtu(new URL(`https://example.com/${"a".repeat(2100)}`))).toBeNull();
    expect(proofHtu(new URL(`https://example.com/${"a".repeat(2000)}`))).not.toBeNull();
  });

  it("v2 submissions and renew bodies verify against their messages", async () => {
    const key = await sdkKey();
    const fields = { type: "interactive", c: "AAEC", p: "self_hold", pp: "", t: '{"ix":{}}', counters: [1, 2], ret: "/r", ts: 1790000000123, build: "0123456789abcdef" };
    const body = await signedSubmission(subtle, key, fields);
    expect(Object.keys(body)).toEqual(["v", "type", "c", "p", "pp", "t", "pow", "ret", "ts", "build", "jwk", "sig"]);
    expect(body.sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(await es256Verify(body.jwk, submissionMessage(fields), body.sig)).toBe(true);
    const renew = await signedRenew(subtle, key, "AAEC", 1790000480000);
    expect(Object.keys(renew)).toEqual(["v", "c", "jwk", "ts", "sig"]);
    expect(await es256Verify(renew.jwk, renewMessage("AAEC", 1790000480000), renew.sig)).toBe(true);
  });
});
