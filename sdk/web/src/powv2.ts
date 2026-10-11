/**
 * PoW v2 for interactive challenges (`sha256-hashcash-v2`,
 * docs/impl/phase2-spec.md §6.4, D-43) and the runner that solves it in a
 * Worker or, failing that, in short main-thread slices (§12.6).
 *
 *   prefix2  = "mg-pow-v2" || 0x00 || SHA-256(C as ASCII)          (42 bytes)
 *   digest_i = SHA-256(prefix2 || u8(i) || u64be(counter_i)),  i = 0 .. k-1
 *   solved  <=> every leading_zero_bits(digest_i) >= d and counter_i < 2^53
 *
 * The 51-byte message pads to one 64-byte block: words 0..9 are the first 40
 * prefix bytes (rounds 0..9 are precomputed once per prefix), word 10 holds
 * the last two prefix bytes, `i` and the counter's top byte, words 11..12 the
 * remaining seven counter bytes and the 0x80 pad byte, word 15 the bit length
 * (408). The search for each sub-puzzle starts at 0 by default, so the first
 * solution is the canonical one of `testdata/phase2/kat.json`.
 *
 * Worker protocol v2 (the SDK bundle doubles as the Worker script):
 *
 *   page   -> worker  {t: "mg-pow2", prefix: Uint8Array(42), bits, k, sv, start?: number[k]}
 *   worker -> page    {t: "mg-pow2-ack", sv}                 at once, for a valid request
 *                     {t: "mg-pow2-part", i, counter}        after each sub-puzzle
 *                     {t: "mg-pow2-ok", counters} | {t: "mg-pow2-err"}
 *
 * `start` (an addition to §12.6) gives the first counter to try per
 * sub-puzzle, so a switch of difficulty keeps the sub-puzzles already solved
 * and continues the others (§12.6 "PoW 的时机").
 */

import { SHA256_IV, leadingZeroBits, readWordBE, runRounds, sha256, wordsToBytes } from "./sha256";
import { MAX_POW_COUNTER, isValidCounter, isValidPowBits } from "./pow";

export const POW_ALG_V2 = "sha256-hashcash-v2";
export const POW_LABEL_V2 = "mg-pow-v2";
export const MAX_POW_K = 8;
export const POW_PREFIX_V2_BYTES = 42;
/** The page waits this long for the Worker's acknowledgement (§12.6). */
export const POW2_ACK_TIMEOUT_MS = 2_000;
/** Longest main-thread slice (§12.6). */
export const MAIN_SLICE_MS = 8;
/** Hashes between clock reads inside a main-thread slice. */
const SLICE_CHUNK = 1_024;
/** Upper bound of hashes per slice, should the clock stand still. */
const SLICE_MAX_HASHES = 65_536;

const MESSAGE_BYTES = POW_PREFIX_V2_BYTES + 9;
const TWO_POW_32 = 0x1_0000_0000;
const LABEL_BYTES = new TextEncoder().encode(POW_LABEL_V2);

export function isValidK(k: unknown): k is number {
  return typeof k === "number" && Number.isInteger(k) && k >= 1 && k <= MAX_POW_K;
}

/** True for a 42-byte prefix that starts with "mg-pow-v2" || 0x00. */
export function isPowPrefixV2(prefix: Uint8Array): boolean {
  if (prefix.length !== POW_PREFIX_V2_BYTES) return false;
  for (let i = 0; i < LABEL_BYTES.length; i++) {
    if (prefix[i] !== LABEL_BYTES[i]) return false;
  }
  return prefix[LABEL_BYTES.length] === 0;
}

/** The 42-byte v2 prefix of a sealed challenge `c`. */
export function powPrefixV2(c: string): Uint8Array {
  const prefix = new Uint8Array(POW_PREFIX_V2_BYTES);
  prefix.set(LABEL_BYTES, 0);
  prefix.set(sha256(new TextEncoder().encode(c)), LABEL_BYTES.length + 1);
  return prefix;
}

/** prefix2 || u8(i) || u64be(counter): the 51-byte message of sub-puzzle `i`. */
export function powMessageV2(prefix: Uint8Array, i: number, counter: number): Uint8Array {
  if (!isValidCounter(counter)) throw new RangeError("powMessageV2: counter must be a safe non-negative integer");
  const message = new Uint8Array(MESSAGE_BYTES);
  message.set(prefix.subarray(0, POW_PREFIX_V2_BYTES), 0);
  message[POW_PREFIX_V2_BYTES] = i & 0xff;
  const high = Math.floor(counter / TWO_POW_32);
  const low = counter >>> 0;
  const at = POW_PREFIX_V2_BYTES + 1;
  for (let b = 0; b < 4; b++) {
    message[at + b] = high >>> (24 - 8 * b);
    message[at + 4 + b] = low >>> (24 - 8 * b);
  }
  return message;
}

/** Reference digest of sub-puzzle `i` via the generic SHA-256. */
export function powDigestV2(prefix: Uint8Array, i: number, counter: number): Uint8Array {
  return sha256(powMessageV2(prefix, i, counter));
}

/** Leading zero bits of sub-puzzle `i`'s digest, or -1 for an invalid counter. */
export function subPuzzleBits(prefix: Uint8Array, i: number, counter: unknown): number {
  if (!isValidCounter(counter)) return -1;
  return leadingZeroBits(powDigestV2(prefix, i, counter));
}

/** Check a claimed v2 solution (1..8 counters) with the generic SHA-256 path. */
export function verifyPowV2(prefix: Uint8Array, bits: number, counters: readonly unknown[]): boolean {
  if (!isPowPrefixV2(prefix) || !isValidPowBits(bits) || !isValidK(counters.length)) return false;
  return counters.every((counter, i) => subPuzzleBits(prefix, i, counter) >= bits);
}

/** Midstate-based search for one sub-puzzle of one prefix and difficulty. */
export class PowSolverV2 {
  private readonly w = new Int32Array(64);
  private readonly midstate = new Int32Array(8);
  private readonly vars = new Int32Array(8);
  /** Prefix bytes 40..41 and `i` in the top three bytes of word 10. */
  private readonly word10High: number;

  constructor(
    prefix: Uint8Array,
    readonly bits: number,
    readonly index: number,
  ) {
    if (!isPowPrefixV2(prefix)) throw new RangeError("PowSolverV2: not a mg-pow-v2 prefix");
    if (!isValidPowBits(bits)) throw new RangeError("PowSolverV2: bits must be an integer in 0..32");
    if (!Number.isInteger(index) || index < 0 || index >= MAX_POW_K) throw new RangeError("PowSolverV2: bad index");
    const w = this.w;
    for (let j = 0; j < 10; j++) w[j] = readWordBE(prefix, 4 * j);
    this.word10High = (prefix[40]! << 24) | (prefix[41]! << 16) | (index << 8);
    w[15] = MESSAGE_BYTES * 8;
    runRounds(SHA256_IV, w, 0, 10, this.midstate);
  }

  private run(counter: number): void {
    const w = this.w;
    const high = Math.floor(counter / TWO_POW_32);
    const low = counter >>> 0;
    w[10] = this.word10High | (high >>> 24);
    w[11] = (high << 8) | (low >>> 24);
    w[12] = (low << 8) | 0x80;
    runRounds(this.midstate, w, 10, 64, this.vars);
  }

  /** Full digest for one counter through the search path (tests). */
  digest(counter: number): Uint8Array {
    if (!isValidCounter(counter)) throw new RangeError("PowSolverV2.digest: bad counter");
    this.run(counter);
    const words = new Int32Array(8);
    for (let j = 0; j < 8; j++) words[j] = (SHA256_IV[j]! + this.vars[j]!) | 0;
    return wordsToBytes(words);
  }

  /** First solving counter in `start .. start + count - 1` (clamped to 2^53 - 1), or -1. */
  search(start: number, count: number): number {
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

// ---------------------------------------------------------------------------
// Worker protocol v2

export interface Pow2Request {
  t: "mg-pow2";
  prefix: Uint8Array;
  bits: number;
  k: number;
  sv: string;
  start?: number[];
}

export type Pow2Reply =
  | { t: "mg-pow2-ack"; sv: string }
  | { t: "mg-pow2-part"; i: number; counter: number }
  | { t: "mg-pow2-ok"; counters: number[] }
  | { t: "mg-pow2-err" };

function isUint8Array(value: unknown): value is Uint8Array {
  // Structured clone creates the array in the Worker's realm, so no instanceof.
  return Object.prototype.toString.call(value) === "[object Uint8Array]";
}

function record(data: unknown): Record<string, unknown> | null {
  return typeof data === "object" && data !== null ? (data as Record<string, unknown>) : null;
}

/** Validate a v2 request; anything else is null. Never throws. */
export function parsePow2Request(data: unknown): Pow2Request | null {
  try {
    const r = record(data);
    if (r === null || r["t"] !== "mg-pow2") return null;
    const { prefix, bits, k, sv, start } = r;
    if (!isUint8Array(prefix) || !isPowPrefixV2(prefix) || !isValidPowBits(bits) || !isValidK(k)) return null;
    if (typeof sv !== "string" || sv.length > 32) return null;
    const request: Pow2Request = { t: "mg-pow2", prefix: Uint8Array.from(prefix), bits, k, sv };
    if (start !== undefined) {
      if (!Array.isArray(start) || start.length !== k || !start.every(isValidCounter)) return null;
      request.start = start.slice() as number[];
    }
    return request;
  } catch {
    return null;
  }
}

/** Parse a v2 Worker reply; unknown shapes are null. Never throws. */
export function parsePow2Reply(data: unknown): Pow2Reply | null {
  try {
    const r = record(data);
    if (r === null) return null;
    switch (r["t"]) {
      case "mg-pow2-ack":
        return typeof r["sv"] === "string" ? { t: "mg-pow2-ack", sv: r["sv"] } : null;
      case "mg-pow2-part": {
        const { i, counter } = r;
        return typeof i === "number" && Number.isInteger(i) && i >= 0 && i < MAX_POW_K && isValidCounter(counter)
          ? { t: "mg-pow2-part", i, counter }
          : null;
      }
      case "mg-pow2-ok": {
        const counters = r["counters"];
        return Array.isArray(counters) && isValidK(counters.length) && counters.every(isValidCounter)
          ? { t: "mg-pow2-ok", counters: counters.slice() as number[] }
          : null;
      }
      case "mg-pow2-err":
        return { t: "mg-pow2-err" };
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * The Worker's v2 handler: acknowledge with its own `sv` at once, solve the
 * sub-puzzles in order and report each. `limit` bounds each search (tests).
 * Never throws.
 */
export function handlePow2Message(
  data: unknown,
  post: (reply: Pow2Reply) => void,
  sv: string,
  limit = MAX_POW_COUNTER + 1,
): void {
  const request = parsePow2Request(data);
  if (request === null) {
    post({ t: "mg-pow2-err" });
    return;
  }
  post({ t: "mg-pow2-ack", sv });
  const counters: number[] = [];
  try {
    for (let i = 0; i < request.k; i++) {
      const counter = new PowSolverV2(request.prefix, request.bits, i).search(request.start?.[i] ?? 0, limit);
      if (counter < 0) {
        post({ t: "mg-pow2-err" });
        return;
      }
      counters.push(counter);
      post({ t: "mg-pow2-part", i, counter });
    }
  } catch {
    post({ t: "mg-pow2-err" });
    return;
  }
  post({ t: "mg-pow2-ok", counters });
}

// ---------------------------------------------------------------------------
// Runner (page side)

/** A Worker running this SDK file. */
export interface PowWorkerPort {
  listen(onMessage: (data: unknown) => void, onError: () => void): void;
  postMessage(message: unknown): void;
  terminate(): void;
}

export interface RunnerTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface PowRunnerDeps {
  /** Null when Workers are unavailable; may throw (CSP, SecurityError). */
  createWorker: ((url: string) => PowWorkerPort) | null;
  /** The executing script's URL, the Worker script. */
  workerUrl: string | null;
  /** `<prefix>s/mg.js?sv=<SDK_VERSION>`: one rebuild after a version mismatch (§12.6). */
  rebuildUrl: string;
  sv: string;
  timers: RunnerTimers;
  now: () => number;
  /** `scheduler.yield()` when available; else a zero timeout is used. */
  yieldNow?: (() => Promise<void>) | null;
}

export interface PowListener {
  /** Sub-puzzle `i` solved (verified with the generic SHA-256). */
  part(i: number, counter: number): void;
  done(counters: number[]): void;
  /** The search failed everywhere (no solution below 2^53, or a broken solver). */
  error(): void;
}

export interface PowRun {
  stop(): void;
  /** True while (or after) a Worker solved; false once on the main thread. */
  readonly worker: boolean;
}

/**
 * Solve `k` sub-puzzles of `prefix` at `bits`, starting each at `start[i]`
 * (default 0). Worker first: an acknowledgement must arrive within 2 s; a
 * Worker that reports another SDK version is replaced once by
 * `rebuildUrl`; after that, or on any Worker failure, the remaining
 * sub-puzzles run on the main thread in slices of at most 8 ms. Parts the
 * Worker reports are re-verified before they count.
 */
export function runPowV2(
  deps: PowRunnerDeps,
  prefix: Uint8Array,
  bits: number,
  k: number,
  start: readonly number[],
  listener: PowListener,
): PowRun {
  const counters: (number | null)[] = Array.from({ length: k }, () => null);
  const next = Array.from({ length: k }, (_, i) => start[i] ?? 0);
  let stopped = false;
  let finished = false;
  let port: PowWorkerPort | null = null;
  let ackTimer: unknown = null;
  let rebuilt = false;
  let onMain = false;
  const run = {
    worker: true,
    stop: () => {
      stopped = true;
      killWorker();
    },
  };

  const clearAck = (): void => {
    if (ackTimer !== null) deps.timers.clearTimeout(ackTimer);
    ackTimer = null;
  };
  const killWorker = (): void => {
    clearAck();
    const p = port;
    port = null;
    if (p !== null) {
      try {
        p.terminate();
      } catch {
        // Already gone.
      }
    }
  };
  const finish = (ok: boolean): void => {
    if (finished || stopped) return;
    finished = true;
    killWorker();
    if (ok) listener.done(counters as number[]);
    else listener.error();
  };
  const accept = (i: number, counter: number): boolean => {
    if (counters[i] !== null) return true;
    if (subPuzzleBits(prefix, i, counter) < bits) return false;
    counters[i] = counter;
    try {
      listener.part(i, counter);
    } catch {
      // A listener bug must not stop the search.
    }
    return true;
  };
  const allDone = (): boolean => counters.every((c) => c !== null);

  const mainThread = (): void => {
    if (onMain || stopped || finished) return;
    onMain = true;
    run.worker = false;
    killWorker();
    const solvers = new Map<number, PowSolverV2>();
    const slice = (): void => {
      if (stopped || finished) return;
      try {
        const t0 = deps.now();
        let hashed = 0;
        for (;;) {
          const i = counters.findIndex((c) => c === null);
          if (i < 0) {
            finish(true);
            return;
          }
          let solver = solvers.get(i);
          if (solver === undefined) {
            solver = new PowSolverV2(prefix, bits, i);
            solvers.set(i, solver);
          }
          const from = next[i]!;
          if (from > MAX_POW_COUNTER) {
            finish(false);
            return;
          }
          const found = solver.search(from, SLICE_CHUNK);
          hashed += SLICE_CHUNK;
          if (found >= 0) {
            accept(i, found);
          } else {
            next[i] = from + SLICE_CHUNK;
          }
          if (deps.now() - t0 >= MAIN_SLICE_MS || hashed >= SLICE_MAX_HASHES) break;
        }
      } catch {
        finish(false);
        return;
      }
      schedule();
    };
    const schedule = (): void => {
      const y = deps.yieldNow;
      if (y) {
        y().then(slice, () => deps.timers.setTimeout(slice, 0));
      } else {
        deps.timers.setTimeout(slice, 0);
      }
    };
    schedule();
  };

  const startWorker = (url: string): void => {
    if (deps.createWorker === null) {
      mainThread();
      return;
    }
    try {
      const p = deps.createWorker(url);
      port = p;
      p.listen(
        (data) => {
          if (port !== p || stopped || finished || onMain) return;
          clearAck();
          const reply = parsePow2Reply(data);
          if (reply === null || reply.t === "mg-pow2-err") {
            mainThread();
            return;
          }
          if (reply.t === "mg-pow2-ack") {
            if (reply.sv === deps.sv) return;
            killWorker();
            if (rebuilt) {
              mainThread();
            } else {
              rebuilt = true;
              startWorker(deps.rebuildUrl);
            }
            return;
          }
          if (reply.t === "mg-pow2-part") {
            if (reply.i >= k || !accept(reply.i, reply.counter)) mainThread();
            return;
          }
          reply.counters.forEach((counter, i) => {
            if (i < k) accept(i, counter);
          });
          if (allDone()) finish(true);
          else mainThread();
        },
        () => {
          if (port === p) mainThread();
        },
      );
      ackTimer = deps.timers.setTimeout(() => {
        ackTimer = null;
        if (port === p) mainThread();
      }, POW2_ACK_TIMEOUT_MS);
      const request: Pow2Request = { t: "mg-pow2", prefix, bits, k, sv: deps.sv, start: next.slice() };
      p.postMessage(request);
    } catch {
      mainThread();
    }
  };

  if (deps.workerUrl === null) mainThread();
  else startWorker(deps.workerUrl);
  return run;
}
