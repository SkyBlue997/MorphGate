/**
 * Session-key crypto for the Web SDK.
 *
 * The session key is an ECDSA P-256 key pair generated with WebCrypto and
 * `extractable: false`, so page scripts (including injected ones) can use the
 * private key to sign but can never export it. Clearance tokens bind to the
 * key through `cnf.jkt`, the RFC 7638 JWK thumbprint of the public key
 * (docs/04 §5, §6.1).
 *
 * Phase 0: key generation, public JWK export and thumbprints (real, tested).
 * Phase 2: IndexedDB persistence of the CryptoKeyPair, MG-Proof (compact JWS,
 * ES256) and submission signatures.
 */

/** Public JWK members the SDK and Edge work with. Extra members are ignored by thumbprints. */
export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  k?: string;
  [member: string]: unknown;
}

/** An exported P-256 public key in the shape the Edge expects inside MG-Proof headers. */
export type EcP256PublicJwk = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
};

export const SESSION_KEY_ALGORITHM: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };

/**
 * Required members per key type, already in the lexicographic order RFC 7638
 * §3.3 demands. OKP comes from RFC 8037 §2.
 */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  OKP: ["crv", "kty", "x"],
};

function defaultSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    // Only secure contexts (https, localhost) expose SubtleCrypto.
    throw new Error("WebCrypto SubtleCrypto is unavailable (insecure context?)");
  }
  return subtle;
}

/** base64url without padding (RFC 7515 §2). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Canonical JSON input of the RFC 7638 thumbprint: only the required members,
 * sorted, no whitespace. Values must be strings; JSON.stringify gives the
 * RFC-mandated escaping for them.
 */
export function thumbprintInput(jwk: Jwk): string {
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) throw new Error(`unsupported JWK kty for thumbprint: ${String(jwk.kty)}`);
  const parts = members.map((name) => {
    const value = jwk[name];
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`JWK is missing required member "${name}" for kty ${jwk.kty}`);
    }
    return `${JSON.stringify(name)}:${JSON.stringify(value)}`;
  });
  return `{${parts.join(",")}}`;
}

/** RFC 7638 JWK thumbprint with SHA-256, base64url-encoded (43 characters). */
export async function jwkThumbprint(jwk: Jwk, subtle: SubtleCrypto = defaultSubtle()): Promise<string> {
  const input = new TextEncoder().encode(thumbprintInput(jwk));
  const digest = await subtle.digest("SHA-256", input);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Generate a fresh session key pair. The private key is non-extractable; the
 * public key is always exportable per the WebCrypto spec.
 */
export async function generateSessionKey(subtle: SubtleCrypto = defaultSubtle()): Promise<CryptoKeyPair> {
  return subtle.generateKey(SESSION_KEY_ALGORITHM, false, ["sign", "verify"]);
}

/** Export the public half as a minimal EC JWK (drops `ext`, `key_ops`). */
export async function exportPublicJwk(
  publicKey: CryptoKey,
  subtle: SubtleCrypto = defaultSubtle(),
): Promise<EcP256PublicJwk> {
  const jwk = await subtle.exportKey("jwk", publicKey);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("session public key is not an EC P-256 JWK");
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/** Convenience: the `cnf.jkt` value for a session key pair. */
export async function sessionKeyThumbprint(
  keyPair: CryptoKeyPair,
  subtle: SubtleCrypto = defaultSubtle(),
): Promise<string> {
  return jwkThumbprint(await exportPublicJwk(keyPair.publicKey, subtle), subtle);
}
