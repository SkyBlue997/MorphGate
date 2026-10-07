/**
 * Pure TypeScript SHA-256 (FIPS 180-4) for the challenge proof of work
 * (docs/impl/phase1-spec.md §11.4).
 *
 * Why not WebCrypto: `crypto.subtle.digest` is one asynchronous call per
 * hash, which makes a hashcash search over millions of counters an order of
 * magnitude slower than a synchronous loop (spec D-12). WebCrypto is still
 * used once per challenge, as a start-up self-test (`challenge.ts`).
 *
 * The compression function takes a round range so the PoW search (`pow.ts`)
 * can reuse a precomputed midstate: its single 64-byte block has fixed words
 * 0..9 (the challenge prefix), so rounds 0..9 are identical for every counter.
 *
 * Arithmetic is on signed 32-bit integers (`| 0`); words live in Int32Array
 * and are reinterpreted as unsigned only when serialised to bytes.
 */

export const DIGEST_BYTES = 32;
export const BLOCK_BYTES = 64;

/** Round constants (FIPS 180-4 §4.2.2). Values above 2^31 wrap to int32 on store. */
const K = Int32Array.of(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
);

/** Initial hash value H(0) (FIPS 180-4 §5.3.3). Treat as read-only. */
export const SHA256_IV: Readonly<Int32Array> = Int32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);

/**
 * Run compression rounds `from..to-1` on the working variables in `state`
 * (a..h) and write the resulting working variables to `out`; the caller adds
 * the chaining value. `w[0..15]` must hold the block and `from <= 16`: message
 * schedule words 16.. are computed inside the round loop and stored in `w`
 * (fusing the two loops roughly doubles throughput in V8). `state` and `out`
 * may be the same array.
 */
export function runRounds(state: Readonly<Int32Array>, w: Int32Array, from: number, to: number, out: Int32Array): void {
  let a = state[0]!;
  let b = state[1]!;
  let c = state[2]!;
  let d = state[3]!;
  let e = state[4]!;
  let f = state[5]!;
  let g = state[6]!;
  let h = state[7]!;
  for (let i = from; i < to; i++) {
    let wi: number;
    if (i < 16) {
      wi = w[i]!;
    } else {
      const x = w[i - 15]!;
      const y = w[i - 2]!;
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      wi = (s1 + w[i - 7]! + s0 + w[i - 16]!) | 0;
      w[i] = wi;
    }
    const t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[i]! + wi) | 0;
    const t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  out[0] = a;
  out[1] = b;
  out[2] = c;
  out[3] = d;
  out[4] = e;
  out[5] = f;
  out[6] = g;
  out[7] = h;
}

/** Read a big-endian 32-bit word; bytes past the end read as zero. */
export function readWordBE(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) << 24) | ((bytes[offset + 1] ?? 0) << 16) | ((bytes[offset + 2] ?? 0) << 8) | (bytes[offset + 3] ?? 0);
}

/** Serialise eight state words as the 32-byte big-endian digest. */
export function wordsToBytes(words: Readonly<Int32Array>): Uint8Array {
  const out = new Uint8Array(DIGEST_BYTES);
  for (let i = 0; i < 8; i++) {
    const word = words[i]!;
    out[4 * i] = word >>> 24;
    out[4 * i + 1] = word >>> 16;
    out[4 * i + 2] = word >>> 8;
    out[4 * i + 3] = word;
  }
  return out;
}

/** SHA-256 of `data`. */
export function sha256(data: Uint8Array): Uint8Array {
  const length = data.length;
  // Message, 0x80, zero padding, 64-bit big-endian bit length (FIPS 180-4 §5.1.1).
  const padded = new Uint8Array(Math.ceil((length + 9) / BLOCK_BYTES) * BLOCK_BYTES);
  padded.set(data);
  padded[length] = 0x80;
  const bitsHigh = Math.floor(length / 0x2000_0000); // length * 8 / 2^32
  const bitsLow = (length << 3) >>> 0;
  const end = padded.length;
  padded[end - 8] = bitsHigh >>> 24;
  padded[end - 7] = bitsHigh >>> 16;
  padded[end - 6] = bitsHigh >>> 8;
  padded[end - 5] = bitsHigh;
  padded[end - 4] = bitsLow >>> 24;
  padded[end - 3] = bitsLow >>> 16;
  padded[end - 2] = bitsLow >>> 8;
  padded[end - 1] = bitsLow;

  const hash = Int32Array.from(SHA256_IV);
  const w = new Int32Array(64);
  const vars = new Int32Array(8);
  for (let block = 0; block < end; block += BLOCK_BYTES) {
    for (let i = 0; i < 16; i++) w[i] = readWordBE(padded, block + 4 * i);
    runRounds(hash, w, 0, 64, vars);
    for (let i = 0; i < 8; i++) hash[i] = (hash[i]! + vars[i]!) | 0;
  }
  return wordsToBytes(hash);
}

/** Number of leading zero bits of a byte string (all bits when it is all zero). */
export function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte !== 0) return bits + Math.clz32(byte) - 24;
    bits += 8;
  }
  return bits;
}

/** Lower-case hex encoding. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Constant-structure byte comparison (the values compared here are not secret). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
