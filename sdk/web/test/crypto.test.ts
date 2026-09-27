import { describe, expect, it } from "vitest";
import {
  base64UrlEncode,
  exportPublicJwk,
  generateSessionKey,
  jwkThumbprint,
  sessionKeyThumbprint,
  thumbprintInput,
} from "../src/crypto";

// RFC 7638 §3.1 example key and its published thumbprint.
const RFC7638_JWK = {
  kty: "RSA",
  n:
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
    "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
    "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
  alg: "RS256",
  kid: "2011-04-29",
};
const RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// RFC 8037 Appendix A.3: Ed25519 (OKP) thumbprint.
const RFC8037_JWK = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
const RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

describe("jwkThumbprint (RFC 7638)", () => {
  it("matches the RFC 7638 §3.1 example", async () => {
    await expect(jwkThumbprint(RFC7638_JWK)).resolves.toBe(RFC7638_THUMBPRINT);
  });

  it("builds the canonical input with only required members in lexicographic order", () => {
    expect(thumbprintInput(RFC7638_JWK)).toBe(`{"e":"AQAB","kty":"RSA","n":"${RFC7638_JWK.n}"}`);
  });

  it("matches the RFC 8037 A.3 OKP example", async () => {
    expect(thumbprintInput(RFC8037_JWK)).toBe(
      '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
    );
    await expect(jwkThumbprint(RFC8037_JWK)).resolves.toBe(RFC8037_THUMBPRINT);
  });

  it("orders EC members crv, kty, x, y and ignores optional members", async () => {
    const ec = { y: "yyy", x: "xxx", kty: "EC", crv: "P-256", use: "sig", key_ops: ["verify"], ext: true };
    expect(thumbprintInput(ec)).toBe('{"crv":"P-256","kty":"EC","x":"xxx","y":"yyy"}');
    const bare = { kty: "EC", crv: "P-256", x: "xxx", y: "yyy" };
    await expect(jwkThumbprint(ec)).resolves.toBe(await jwkThumbprint(bare));
  });

  it("rejects keys with missing members or unknown kty", async () => {
    expect(() => thumbprintInput({ kty: "EC", crv: "P-256", x: "xxx" })).toThrow(/"y"/);
    expect(() => thumbprintInput({ kty: "XYZ" })).toThrow(/unsupported/);
    await expect(jwkThumbprint({ kty: "RSA", n: "abc" })).rejects.toThrow(/"e"/);
  });
});

describe("base64UrlEncode", () => {
  it("uses the URL-safe alphabet without padding", () => {
    expect(base64UrlEncode(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(base64UrlEncode(new Uint8Array([]))).toBe("");
    expect(base64UrlEncode(new TextEncoder().encode("any carnal pleas"))).toBe("YW55IGNhcm5hbCBwbGVhcw");
  });
});

describe("session key (WebCrypto ECDSA P-256)", () => {
  it("generates a non-extractable private key", async () => {
    const pair = await generateSessionKey();
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toMatchObject({ name: "ECDSA", namedCurve: "P-256" });
    expect(pair.privateKey.usages).toEqual(["sign"]);
    await expect(crypto.subtle.exportKey("jwk", pair.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
  });

  it("exports a minimal public JWK whose thumbprint is a 43-char base64url string", async () => {
    const pair = await generateSessionKey();
    const jwk = await exportPublicJwk(pair.publicKey);
    expect(Object.keys(jwk).sort()).toEqual(["crv", "kty", "x", "y"]);
    const jkt = await sessionKeyThumbprint(pair);
    expect(jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jkt).toBe(await jwkThumbprint(jwk));
  });

  it("signatures from the private key verify against the exported public JWK", async () => {
    const pair = await generateSessionKey();
    const jwk = await exportPublicJwk(pair.publicKey);
    const imported = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, [
      "verify",
    ]);
    const data = new TextEncoder().encode("mg-phase0");
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data);
    await expect(
      crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, imported, signature, data),
    ).resolves.toBe(true);
  });

  it("gives distinct thumbprints for distinct keys", async () => {
    const [a, b] = await Promise.all([generateSessionKey(), generateSessionKey()]);
    expect(await sessionKeyThumbprint(a)).not.toBe(await sessionKeyThumbprint(b));
  });
});
