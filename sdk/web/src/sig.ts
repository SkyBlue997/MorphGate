/**
 * Signed messages of the session key (docs/impl/phase2-spec.md §6.5, §6.6)
 * and ES256 over WebCrypto.
 *
 *   lp(x) = u16be(len(x)) || x        (x <= 65535 bytes; strings as UTF-8)
 *   H(x)  = SHA-256(x)
 *   submission (mg-sub-v2):
 *     "mg-sub-v2" || 0x00 || lp(c) || lp(type) || lp(p) || lp(H(pp)) || lp(H(t))
 *       || lp(counters) || lp(ret) || u64be(ts) || lp(build)
 *   renew (mg-renew-v1):
 *     "mg-renew-v1" || 0x00 || lp(c) || u64be(ts)
 *
 * `counters` is the decimal counters joined by ",". `pp` and `t` are hashed
 * as the UTF-8 bytes of the string fields the body carries, so both sides
 * hash the same bytes without any JSON canonicalization.
 *
 * Signatures are the 64-byte IEEE P1363 `r || s` WebCrypto produces, sent
 * as unpadded base64url (86 characters).
 */

import { base64UrlEncode } from "./crypto";
import { sha256 } from "./sha256";

const ENCODER = new TextEncoder();
export const ES256: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

export interface SubmissionFields {
  c: string;
  type: string;
  p: string;
  pp: string;
  t: string;
  counters: readonly number[];
  ret: string;
  ts: number;
  build: string;
}

class ByteWriter {
  private readonly parts: Uint8Array[] = [];
  private length = 0;

  raw(bytes: Uint8Array): this {
    this.parts.push(bytes);
    this.length += bytes.length;
    return this;
  }

  /** u16be(len) || bytes; throws above 65535 bytes. */
  lp(value: string | Uint8Array): this {
    const bytes = typeof value === "string" ? ENCODER.encode(value) : value;
    if (bytes.length > 0xffff) throw new RangeError("lp: longer than 65535 bytes");
    return this.raw(Uint8Array.of(bytes.length >>> 8, bytes.length & 0xff)).raw(bytes);
  }

  /** Big-endian u64 of a safe non-negative integer. */
  u64(value: number): this {
    if (!Number.isSafeInteger(value) || value < 0) throw new RangeError("u64: not a safe non-negative integer");
    const out = new Uint8Array(8);
    const high = Math.floor(value / 0x1_0000_0000);
    const low = value >>> 0;
    for (let b = 0; b < 4; b++) {
      out[b] = high >>> (24 - 8 * b);
      out[4 + b] = low >>> (24 - 8 * b);
    }
    return this.raw(out);
  }

  label(name: string): this {
    return this.raw(ENCODER.encode(name)).raw(Uint8Array.of(0));
  }

  bytes(): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(this.length);
    let at = 0;
    for (const part of this.parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }
}

/** The bytes the submission signature covers (§6.6). Throws on out-of-range fields. */
export function submissionMessage(f: SubmissionFields): Uint8Array<ArrayBuffer> {
  return new ByteWriter()
    .label("mg-sub-v2")
    .lp(f.c)
    .lp(f.type)
    .lp(f.p)
    .lp(sha256(ENCODER.encode(f.pp)))
    .lp(sha256(ENCODER.encode(f.t)))
    .lp(f.counters.join(","))
    .lp(f.ret)
    .u64(f.ts)
    .lp(f.build)
    .bytes();
}

/** The bytes the renew signature covers (§6.6). */
export function renewMessage(c: string, ts: number): Uint8Array<ArrayBuffer> {
  return new ByteWriter().label("mg-renew-v1").lp(c).u64(ts).bytes();
}

/** ES256 over `data`: the 64-byte r || s as unpadded base64url. */
export async function es256Sign(subtle: SubtleCrypto, key: CryptoKey, data: Uint8Array<ArrayBuffer>): Promise<string> {
  const signature = new Uint8Array(await subtle.sign(ES256, key, data));
  if (signature.length !== 64) throw new Error("ES256: unexpected signature length");
  return base64UrlEncode(signature);
}
