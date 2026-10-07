/**
 * Hashcash proof of work for sealed challenges and the Worker protocol that
 * runs it (docs/impl/phase1-spec.md §6.3, §11.3, §11.4).
 *
 *   prefix = "mg-pow-v1" || 0x00 || SHA-256(C as ASCII)          (42 bytes)
 *   digest = SHA-256(prefix || u64be(counter))
 *   solved iff leading_zero_bits(digest) >= bits,  0 <= bits <= 32
 *
 * The message is 50 bytes, so with padding it is exactly one 64-byte block:
 * words 0..9 are the first 40 prefix bytes, word 10 holds the last two
 * prefix bytes and the counter's top 16 bits, words 11..12 the rest of the
 * counter and the 0x80 pad byte, words 13..15 the zero pad and the bit length
 * (400). `PowSolver` fills the fixed words once, precomputes the state after
 * rounds 0..9 (they only read words 0..9), and per counter only rewrites
 * words 10..12 and runs rounds 10..63: one compression per attempt.
 *
 * The counter search starts at 0 and never exceeds 2^53 - 1 (the protocol's
 * `counter < 2^53`, a JS safe integer), so the first solution is canonical
 * and matches `testdata/phase1/kat.json`.
 *
 * Worker protocol (the SDK bundle doubles as the Worker script):
 *   main -> worker  {t: "mg-pow", prefix: Uint8Array(42), bits}
 *   worker -> main  {t: "mg-pow-ack"}                 immediately, for a valid request
 *                   {t: "mg-pow-ok", counter} | {t: "mg-pow-err"}
 * The ack lets the page tell a live-but-busy Worker from a dead one inside
 * its 2 s fallback window without cutting the search short (README).
 */

import { SHA256_IV, leadingZeroBits, readWordBE, runRounds, sha256, wordsToBytes } from "./sha256";

export const POW_ALG = "sha256-hashcash-v1";
export const POW_LABEL = "mg-pow-v1";
export const POW_PREFIX_BYTES = 42;
export const MAX_POW_BITS = 32;
/** Largest counter the protocol accepts: 2^53 - 1. */
export const MAX_POW_COUNTER = Number.MAX_SAFE_INTEGER;
/** Hashes per main-thread slice when no Worker is available (§11.3). */
export const MAIN_THREAD_SLICE = 50_000;

const MESSAGE_BYTES = POW_PREFIX_BYTES + 8;
const TWO_POW_32 = 0x1_0000_0000;
const LABEL_BYTES = new TextEncoder().encode(POW_LABEL);

export function isValidPowBits(bits: unknown): bits is number {
  return typeof bits === "number" && Number.isInteger(bits) && bits >= 0 && bits <= MAX_POW_BITS;
}

export function isValidCounter(counter: unknown): counter is number {
  return typeof counter === "number" && Number.isSafeInteger(counter) && counter >= 0;
}

/** True for a 42-byte prefix that starts with "mg-pow-v1" || 0x00. */
export function isPowPrefix(prefix: Uint8Array): boolean {
  if (prefix.length !== POW_PREFIX_BYTES) return false;
  for (let i = 0; i < LABEL_BYTES.length; i++) {
    if (prefix[i] !== LABEL_BYTES[i]) return false;
  }
  return prefix[LABEL_BYTES.length] === 0;
}

/** The 42-byte PoW prefix for a sealed challenge `c`. */
export function powPrefix(c: string): Uint8Array {
  const prefix = new Uint8Array(POW_PREFIX_BYTES);
  prefix.set(LABEL_BYTES, 0);
  prefix[LABEL_BYTES.length] = 0;
  prefix.set(sha256(new TextEncoder().encode(c)), LABEL_BYTES.length + 1);
  return prefix;
}

/** prefix || u64be(counter): the 50-byte hashed message. */
export function powMessage(prefix: Uint8Array, counter: number): Uint8Array<ArrayBuffer> {
  if (!isValidCounter(counter)) throw new RangeError("powMessage: counter must be a safe non-negative integer");
  const message = new Uint8Array(MESSAGE_BYTES);
  message.set(prefix.subarray(0, POW_PREFIX_BYTES), 0);
  const high = Math.floor(counter / TWO_POW_32);
  const low = counter >>> 0;
  const at = POW_PREFIX_BYTES;
  message[at] = high >>> 24;
  message[at + 1] = high >>> 16;
  message[at + 2] = high >>> 8;
  message[at + 3] = high;
  message[at + 4] = low >>> 24;
  message[at + 5] = low >>> 16;
  message[at + 6] = low >>> 8;
  message[at + 7] = low;
  return message;
}

/** Reference digest via the generic SHA-256 (verification and tests, not the search loop). */
export function powDigest(prefix: Uint8Array, counter: number): Uint8Array {
  return sha256(powMessage(prefix, counter));
}

/** Check a claimed solution with the generic SHA-256 path. */
export function verifyPow(prefix: Uint8Array, bits: number, counter: unknown): boolean {
  if (!isPowPrefix(prefix) || !isValidPowBits(bits) || !isValidCounter(counter)) return false;
  return leadingZeroBits(powDigest(prefix, counter)) >= bits;
}

/** Midstate-based search over one prefix and difficulty. */
export class PowSolver {
  readonly bits: number;
  private readonly w = new Int32Array(64);
  private readonly midstate = new Int32Array(8);
  private readonly vars = new Int32Array(8);
  /** Prefix bytes 40..41 in the top half of word 10. */
  private readonly word10High: number;

  constructor(prefix: Uint8Array, bits: number) {
    if (!isPowPrefix(prefix)) throw new RangeError("PowSolver: not a mg-pow-v1 prefix");
    if (!isValidPowBits(bits)) throw new RangeError("PowSolver: bits must be an integer in 0..32");
    this.bits = bits;
    const w = this.w;
    for (let i = 0; i < 10; i++) w[i] = readWordBE(prefix, 4 * i);
    this.word10High = (prefix[40]! << 24) | (prefix[41]! << 16);
    w[13] = 0;
    w[14] = 0;
    w[15] = MESSAGE_BYTES * 8;
    runRounds(SHA256_IV, w, 0, 10, this.midstate);
  }

  /** Load `counter` into words 10..12 and leave rounds 10..63 in `vars`. */
  private run(counter: number): void {
    const w = this.w;
    const high = Math.floor(counter / TWO_POW_32);
    const low = counter >>> 0;
    w[10] = this.word10High | (high >>> 16);
    w[11] = (high << 16) | (low >>> 16);
    w[12] = (low << 16) | 0x8000;
    runRounds(this.midstate, w, 10, 64, this.vars);
  }

  /** Full digest for one counter through the search path (self-test and tests). */
  digest(counter: number): Uint8Array {
    if (!isValidCounter(counter)) throw new RangeError("PowSolver.digest: counter must be a safe non-negative integer");
    this.run(counter);
    const words = new Int32Array(8);
    for (let i = 0; i < 8; i++) words[i] = (SHA256_IV[i]! + this.vars[i]!) | 0;
    return wordsToBytes(words);
  }

  /**
   * Try counters `start .. start + count - 1` (clamped to 2^53 - 1) in order
   * and return the first solution, or -1. Only the first digest word is
   * needed because `bits <= 32`.
   */
  search(start: number, count: number): number {
    // `count` may be 2^53 (the whole range), which is an exact but not a "safe" integer.
    if (!isValidCounter(start) || !Number.isInteger(count) || count <= 0) return -1;
    const end = start + Math.min(count, MAX_POW_COUNTER - start + 1);
    const iv0 = SHA256_IV[0]!;
    const bits = this.bits;
    const vars = this.vars;
    for (let counter = start; counter < end; counter++) {
      this.run(counter);
      if (Math.clz32((iv0 + vars[0]!) | 0) >= bits) return counter;
    }
    return -1;
  }
}

/** Main thread -> Worker. */
export interface PowRequest {
  t: "mg-pow";
  prefix: Uint8Array;
  bits: number;
}

/** Worker -> main thread. */
export type PowReply = { t: "mg-pow-ack" } | { t: "mg-pow-ok"; counter: number } | { t: "mg-pow-err" };

function isUint8Array(value: unknown): value is Uint8Array {
  // Structured clone creates the array in the Worker's realm, so no instanceof.
  return Object.prototype.toString.call(value) === "[object Uint8Array]";
}

/** Validate an incoming Worker message; anything else is null. Never throws. */
export function parsePowRequest(data: unknown): PowRequest | null {
  try {
    if (typeof data !== "object" || data === null) return null;
    const record = data as Record<string, unknown>;
    if (record["t"] !== "mg-pow") return null;
    const prefix = record["prefix"];
    const bits = record["bits"];
    if (!isUint8Array(prefix) || !isPowPrefix(prefix) || !isValidPowBits(bits)) return null;
    return { t: "mg-pow", prefix: Uint8Array.from(prefix), bits };
  } catch {
    return null;
  }
}

/** Parse a Worker reply; unknown shapes are null. Never throws. */
export function parsePowReply(data: unknown): PowReply | null {
  try {
    if (typeof data !== "object" || data === null) return null;
    const record = data as Record<string, unknown>;
    switch (record["t"]) {
      case "mg-pow-ack":
        return { t: "mg-pow-ack" };
      case "mg-pow-err":
        return { t: "mg-pow-err" };
      case "mg-pow-ok": {
        const counter = record["counter"];
        return isValidCounter(counter) ? { t: "mg-pow-ok", counter } : null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * The Worker's message handler: ack a valid request, search from 0, reply
 * with the first solution. `limit` bounds the search (tests); the page stops
 * a long search by terminating the Worker. Never throws.
 */
export function handlePowMessage(data: unknown, post: (reply: PowReply) => void, limit = MAX_POW_COUNTER + 1): void {
  const request = parsePowRequest(data);
  if (request === null) {
    post({ t: "mg-pow-err" });
    return;
  }
  post({ t: "mg-pow-ack" });
  let counter = -1;
  try {
    counter = new PowSolver(request.prefix, request.bits).search(0, limit);
  } catch {
    counter = -1;
  }
  post(counter >= 0 ? { t: "mg-pow-ok", counter } : { t: "mg-pow-err" });
}

/** The parts of a DedicatedWorkerGlobalScope the handler needs. */
export interface PowWorkerScope {
  addEventListener(type: "message" | "messageerror", listener: (event: { data?: unknown }) => void): void;
  postMessage(message: PowReply): void;
}

/** Install the PoW handler in a Worker (the only thing the SDK does there). */
export function installPowWorker(scope: PowWorkerScope): void {
  const post = (reply: PowReply): void => scope.postMessage(reply);
  scope.addEventListener("message", (event) => handlePowMessage(event.data, post));
  scope.addEventListener("messageerror", () => post({ t: "mg-pow-err" }));
}

/**
 * True when running as a Worker: `self instanceof WorkerGlobalScope` (§11.3).
 * Never throws.
 */
export function isWorkerScope(scope: unknown = globalThis): boolean {
  try {
    const ctor = (scope as { WorkerGlobalScope?: unknown }).WorkerGlobalScope;
    return typeof ctor === "function" && scope instanceof (ctor as abstract new () => unknown);
  } catch {
    return false;
  }
}
