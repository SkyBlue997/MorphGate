// A reference verifier of the MG-Proof rules (docs/impl/phase2-spec.md §6.7),
// for tests only: kat2.test.ts checks it against every kat.json vector, and
// the other suites check the proofs the SDK builds with it.
import { jwkThumbprint, type EcP256PublicJwk } from "../src/crypto";

const subtle = globalThis.crypto.subtle;

export function b64urlDecode(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  try {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** ES256 verification of a 64-byte r || s with WebCrypto (DER and other lengths: false). */
export async function es256Verify(jwk: EcP256PublicJwk, msg: Uint8Array<ArrayBuffer>, sigB64: string): Promise<boolean> {
  const sig = b64urlDecode(sigB64);
  if (sig === null || sig.length !== 64) return false;
  try {
    const key = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "verify",
    ]);
    return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, msg);
  } catch {
    return false;
  }
}

/** JSON.parse that rejects duplicate object keys at any depth (serde's behaviour). */
function strictParse(text: string): unknown {
  let i = 0;
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i]!)) i++;
  };
  const str = (): string => {
    const start = i;
    i++;
    while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const value = (): void => {
    ws();
    const ch = text[i];
    if (ch === "{") {
      i++;
      const keys = new Set<string>();
      ws();
      if (text[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        ws();
        const key = str();
        if (keys.has(key)) throw new Error(`duplicate key ${key}`);
        keys.add(key);
        ws();
        i++; // :
        value();
        ws();
        if (text[i++] === "}") return;
      }
    } else if (ch === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return;
      }
      for (;;) {
        value();
        ws();
        if (text[i++] === "]") return;
      }
    } else if (ch === '"') {
      str();
    } else {
      while (i < text.length && !",}] \t\n\r".includes(text[i]!)) i++;
    }
  };
  const parsed = JSON.parse(text) as unknown;
  value();
  return parsed;
}

function exactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const own = Object.keys(value).sort();
  return own.length === keys.length && own.every((k, n) => k === [...keys].sort()[n]);
}

/** mg_core::paths::cloudflare_view. */
export function cloudflareView(path: string): string {
  if (!/[%.\\]/.test(path) && !path.includes("//")) return path;
  const decoded = path.replace(/%([0-9A-Fa-f]{2})/g, (m, h: string) => {
    const ch = String.fromCharCode(parseInt(h, 16));
    return /[A-Za-z0-9\-._~]/.test(ch) ? ch : `%${h.toUpperCase()}`;
  });
  const merged = decoded.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  if (!merged.startsWith("/")) return merged;
  const out: string[] = [];
  let trailing = false;
  for (const segment of merged.slice(1).split("/")) {
    trailing = segment === "." || segment === "..";
    if (segment === ".") continue;
    if (segment === "..") out.pop();
    else out.push(segment);
  }
  let result = `/${out.join("/")}`;
  if (trailing && !result.endsWith("/")) result += "/";
  return result;
}

const normHost = (h: string): string => h.toLowerCase().replace(/\.$/, "");

interface ProofRequest {
  method: string;
  scheme: string;
  host: string;
  path: string;
  now_s: number;
  expected_jkt: string | null;
}

export async function referenceVerify(header: string, req: ProofRequest): Promise<string> {
  const malformed = "proof.malformed";
  if (new TextEncoder().encode(header).length > 4096) return malformed;
  const parts = header.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return malformed;
  const [h64, p64, s64] = parts as [string, string, string];
  const hBytes = b64urlDecode(h64);
  const pBytes = b64urlDecode(p64);
  const sig = b64urlDecode(s64);
  if (hBytes === null || pBytes === null || sig === null) return malformed;
  let h: unknown;
  let p: unknown;
  try {
    h = strictParse(new TextDecoder("utf-8", { fatal: true }).decode(hBytes));
    p = strictParse(new TextDecoder("utf-8", { fatal: true }).decode(pBytes));
  } catch {
    return malformed;
  }
  if (!exactKeys(h, ["alg", "typ", "jwk"]) || h["alg"] !== "ES256" || h["typ"] !== "mg-proof+jwt") return malformed;
  const jwk = h["jwk"];
  if (!exactKeys(jwk, ["kty", "crv", "x", "y"]) || jwk["kty"] !== "EC" || jwk["crv"] !== "P-256") return malformed;
  for (const c of ["x", "y"]) {
    const v = jwk[c];
    if (typeof v !== "string" || b64urlDecode(v)?.length !== 32 || v.length !== 43) return malformed;
  }
  if (!exactKeys(p, ["htm", "htu", "iat", "jti"])) return malformed;
  const { htm, htu, iat, jti } = p;
  if (typeof htm !== "string" || new TextEncoder().encode(htm).length > 32) return malformed;
  if (typeof htu !== "string" || new TextEncoder().encode(htu).length > 2048) return malformed;
  if (typeof iat !== "number" || !Number.isInteger(iat)) return malformed;
  if (typeof jti !== "string" || jti.length !== 22 || b64urlDecode(jti)?.length !== 16) return malformed;
  if (req.expected_jkt === null) return "proof.unbound";
  const pub = jwk as unknown as EcP256PublicJwk;
  if ((await jwkThumbprint(pub, subtle)) !== req.expected_jkt) return "proof.jkt";
  if (htm !== req.method) return "proof.htm";
  const m = /^https:\/\/([^/?#]*)([^?#]*)/.exec(htu);
  if (m === null || req.scheme !== "https") return "proof.htu";
  const authority = m[1]!;
  if (authority.includes("@") || normHost(authority) !== normHost(req.host)) return "proof.htu";
  if (cloudflareView(m[2]!) !== cloudflareView(req.path)) return "proof.htu";
  if (iat < req.now_s - 30 || iat > req.now_s + 5) return "proof.iat";
  if (!(await es256Verify(pub, new TextEncoder().encode(`${h64}.${p64}`), s64))) return "proof.sig";
  return "valid";
}

