// Hashcash PoW and the Worker protocol (docs/impl/phase1-spec.md §6.3, §11.3, §11.4, §11.5).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  MAX_POW_COUNTER,
  POW_ALG,
  POW_PREFIX_BYTES,
  PowSolver,
  handlePowMessage,
  installPowWorker,
  isPowPrefix,
  isWorkerScope,
  parsePowReply,
  parsePowRequest,
  powDigest,
  powMessage,
  powPrefix,
  verifyPow,
  type PowReply,
  type PowWorkerScope,
} from "../src/pow";
import { leadingZeroBits, toHex } from "../src/sha256";
import { XorShift32 } from "./xorshift";

interface PowCase {
  c: string;
  bits: number;
  first_counter: number;
  digest_hex: string;
  leading_zero_bits: number;
  prefix_hex: string;
}

/** The shared known-answer vectors, read straight from testdata/phase1/kat.json (§16). */
function loadPowCases(): PowCase[] {
  const kat: unknown = JSON.parse(readFileSync(new URL("../../../testdata/phase1/kat.json", import.meta.url), "utf8"));
  const cases = (kat as { pow?: { cases?: unknown } }).pow?.cases;
  if (!Array.isArray(cases) || cases.length === 0) throw new Error("kat.json: pow.cases missing");
  return cases.map((raw: Record<string, unknown>, index) => {
    const { c, bits, first_counter, digest_hex, leading_zero_bits, prefix_hex } = raw;
    if (
      typeof c !== "string" ||
      typeof bits !== "number" ||
      typeof first_counter !== "number" ||
      typeof digest_hex !== "string" ||
      typeof leading_zero_bits !== "number" ||
      typeof prefix_hex !== "string"
    ) {
      throw new Error(`kat.json: malformed pow case ${index}`);
    }
    return { c, bits, first_counter, digest_hex, leading_zero_bits, prefix_hex };
  });
}

const POW_CASES = loadPowCases();

function collect(data: unknown, limit?: number): PowReply[] {
  const replies: PowReply[] = [];
  handlePowMessage(data, (reply) => replies.push(reply), limit);
  return replies;
}

describe("kat.json pow cases (§11.5)", () => {
  it("covers every case in the file", () => {
    expect(POW_CASES.length).toBeGreaterThanOrEqual(5);
  });

  for (const vector of POW_CASES) {
    describe(`c=${vector.c} bits=${vector.bits}`, () => {
      const prefix = powPrefix(vector.c);

      it("derives the 42-byte prefix", () => {
        expect(prefix.length).toBe(POW_PREFIX_BYTES);
        expect(toHex(prefix)).toBe(vector.prefix_hex);
        expect(isPowPrefix(prefix)).toBe(true);
      });

      it("finds exactly first_counter, searching from 0", () => {
        expect(new PowSolver(prefix, vector.bits).search(0, 1_000_000)).toBe(vector.first_counter);
      });

      it("reproduces digest_hex on both the generic and the midstate path", () => {
        expect(toHex(powDigest(prefix, vector.first_counter))).toBe(vector.digest_hex);
        expect(toHex(new PowSolver(prefix, vector.bits).digest(vector.first_counter))).toBe(vector.digest_hex);
        expect(leadingZeroBits(powDigest(prefix, vector.first_counter))).toBe(vector.leading_zero_bits);
      });

      it("verifies the solution and rejects every earlier counter", () => {
        expect(verifyPow(prefix, vector.bits, vector.first_counter)).toBe(true);
        for (let counter = 0; counter < Math.min(vector.first_counter, 2_000); counter++) {
          expect(verifyPow(prefix, vector.bits, counter)).toBe(false);
        }
      });

      it("is what the Worker handler replies", () => {
        expect(collect({ t: "mg-pow", prefix, bits: vector.bits })).toEqual([
          { t: "mg-pow-ack" },
          { t: "mg-pow-ok", counter: vector.first_counter },
        ]);
      });
    });
  }
});

describe("PowSolver", () => {
  const prefix = powPrefix("mg-test-c-1");

  it("matches the generic digest for counters around the 32-bit and 53-bit edges", () => {
    const solver = new PowSolver(prefix, 0);
    const rng = new XorShift32(0xc0ffee);
    const counters = [0, 1, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000, 0x1_0000_0001, 0x1234_5678_9abc, MAX_POW_COUNTER - 1, MAX_POW_COUNTER];
    for (let i = 0; i < 50; i++) counters.push(rng.next() * 0x20_0000 + rng.below(0x20_0000));
    for (const counter of counters) {
      expect(toHex(solver.digest(counter)), `counter ${counter}`).toBe(toHex(powDigest(prefix, counter)));
    }
  });

  it("encodes the counter as u64 big-endian after the prefix", () => {
    const message = powMessage(prefix, 0x0102_0304_0506);
    expect(message.length).toBe(50);
    expect(toHex(message.subarray(0, 42))).toBe(toHex(prefix));
    expect(toHex(message.subarray(42))).toBe("0000010203040506");
  });

  it("returns counter 0 for zero difficulty", () => {
    expect(new PowSolver(prefix, 0).search(0, 1)).toBe(0);
  });

  it("searches only inside the requested window", () => {
    const solver = new PowSolver(prefix, 8); // first solution is 387 (kat.json)
    expect(solver.search(0, 387)).toBe(-1);
    expect(solver.search(387, 1)).toBe(387);
    expect(solver.search(388, 1)).toBe(-1);
  });

  it("accepts the whole counter range as the window size", () => {
    expect(new PowSolver(prefix, 8).search(0, MAX_POW_COUNTER + 1)).toBe(387);
  });

  it("never tries a counter beyond 2^53 - 1", () => {
    const solver = new PowSolver(prefix, 0);
    expect(solver.search(MAX_POW_COUNTER, 50_000)).toBe(MAX_POW_COUNTER);
    expect(solver.search(MAX_POW_COUNTER + 1, 1)).toBe(-1);
  });

  it("rejects invalid inputs", () => {
    expect(() => new PowSolver(new Uint8Array(42), 8)).toThrow(RangeError); // wrong label
    expect(() => new PowSolver(prefix.subarray(0, 41), 8)).toThrow(RangeError);
    for (const bits of [-1, 33, 1.5, Number.NaN]) {
      expect(() => new PowSolver(prefix, bits)).toThrow(RangeError);
    }
    const solver = new PowSolver(prefix, 8);
    expect(solver.search(-1, 10)).toBe(-1);
    expect(solver.search(0.5, 10)).toBe(-1);
    expect(solver.search(0, 0)).toBe(-1);
    expect(() => solver.digest(-1)).toThrow(RangeError);
    expect(() => powMessage(prefix, 2 ** 53)).toThrow(RangeError);
  });

  it("verifyPow rejects malformed claims", () => {
    expect(verifyPow(prefix, 8, 387)).toBe(true);
    for (const counter of [-1, 387.5, "387", null, 2 ** 53, Number.POSITIVE_INFINITY]) {
      expect(verifyPow(prefix, 8, counter)).toBe(false);
    }
    expect(verifyPow(prefix, 33, 387)).toBe(false);
    expect(verifyPow(new Uint8Array(42), 0, 0)).toBe(false);
  });

  it("names the algorithm as the Edge does", () => {
    expect(POW_ALG).toBe("sha256-hashcash-v1");
  });
});

describe("Worker message handler (§11.3)", () => {
  const prefix = powPrefix("AAECAwQ");

  it("acks, then replies with the counter", () => {
    expect(collect({ t: "mg-pow", prefix, bits: 4 })).toEqual([{ t: "mg-pow-ack" }, { t: "mg-pow-ok", counter: 4 }]);
  });

  it("replies mg-pow-err without an ack to malformed requests", () => {
    const bad: unknown[] = [
      null,
      undefined,
      "mg-pow",
      42,
      [],
      {},
      { t: "mg-pow-ok", prefix, bits: 4 },
      { t: "mg-pow", prefix: Array.from(prefix), bits: 4 }, // plain array, not Uint8Array
      { t: "mg-pow", prefix: prefix.subarray(0, 41), bits: 4 },
      { t: "mg-pow", prefix: new Uint8Array(42), bits: 4 }, // not a mg-pow-v1 prefix
      { t: "mg-pow", prefix: new Uint16Array(42), bits: 4 },
      { t: "mg-pow", prefix, bits: 33 },
      { t: "mg-pow", prefix, bits: -1 },
      { t: "mg-pow", prefix, bits: 2.5 },
      { t: "mg-pow", prefix, bits: "4" },
      { t: "mg-pow", prefix },
    ];
    for (const message of bad) expect(collect(message)).toEqual([{ t: "mg-pow-err" }]);
  });

  it("survives hostile message objects", () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("boom");
        },
      },
    );
    expect(collect(hostile)).toEqual([{ t: "mg-pow-err" }]);
  });

  it("replies mg-pow-err when the search window is exhausted", () => {
    expect(collect({ t: "mg-pow", prefix: powPrefix("mg-test-c-1"), bits: 8 }, 100)).toEqual([
      { t: "mg-pow-ack" },
      { t: "mg-pow-err" },
    ]);
  });

  it("copies the prefix so later mutation by the sender cannot change the search", () => {
    const own = powPrefix("AAECAwQ");
    const request = parsePowRequest({ t: "mg-pow", prefix: own, bits: 4 });
    own.fill(0);
    expect(request !== null && isPowPrefix(request.prefix)).toBe(true);
  });

  it("installPowWorker wires message and messageerror events", () => {
    const listeners = new Map<string, (event: { data?: unknown }) => void>();
    const posted: PowReply[] = [];
    const scope: PowWorkerScope = {
      addEventListener: (type, listener) => listeners.set(type, listener),
      postMessage: (message) => posted.push(message),
    };
    installPowWorker(scope);
    listeners.get("message")?.({ data: { t: "mg-pow", prefix, bits: 4 } });
    listeners.get("messageerror")?.({});
    expect(posted).toEqual([{ t: "mg-pow-ack" }, { t: "mg-pow-ok", counter: 4 }, { t: "mg-pow-err" }]);
  });

  it("parsePowReply accepts only the protocol's replies", () => {
    expect(parsePowReply({ t: "mg-pow-ack" })).toEqual({ t: "mg-pow-ack" });
    expect(parsePowReply({ t: "mg-pow-err" })).toEqual({ t: "mg-pow-err" });
    expect(parsePowReply({ t: "mg-pow-ok", counter: 7 })).toEqual({ t: "mg-pow-ok", counter: 7 });
    for (const reply of [null, {}, { t: "mg-pow-ok" }, { t: "mg-pow-ok", counter: -1 }, { t: "mg-pow-ok", counter: 2 ** 53 }, { t: "other" }]) {
      expect(parsePowReply(reply)).toBeNull();
    }
  });
});

describe("isWorkerScope", () => {
  it("is true only for an instance of WorkerGlobalScope", () => {
    class WorkerGlobalScope {}
    const scope = Object.assign(new WorkerGlobalScope(), { WorkerGlobalScope });
    expect(isWorkerScope(scope)).toBe(true);
    expect(isWorkerScope({ WorkerGlobalScope })).toBe(false);
    expect(isWorkerScope({})).toBe(false);
    expect(isWorkerScope(globalThis)).toBe(false); // vitest runs in Node, not a Worker
  });

  it("never throws", () => {
    const hostile = {
      get WorkerGlobalScope(): never {
        throw new Error("boom");
      },
    };
    expect(isWorkerScope(hostile)).toBe(false);
  });
});

describe("random input never throws (§2.4)", () => {
  it("parsePowRequest / handlePowMessage / parsePowReply over 10,000 xorshift inputs", () => {
    const rng = new XorShift32(20260928);
    const label = powPrefix("x");
    for (let i = 0; i < 10_000; i++) {
      // Mostly near-valid shapes, so the validation branches are all exercised.
      const bytes = rng.below(3) === 0 ? Uint8Array.from(label, (b, j) => (j < 10 ? b : rng.next() & 0xff)) : rng.bytes(rng.below(50));
      const message: unknown = rng.pick([
        { t: "mg-pow", prefix: bytes, bits: rng.below(40) - 4 },
        { t: rng.string(8), prefix: bytes, bits: rng.below(33) },
        { t: "mg-pow", prefix: rng.string(42), bits: rng.below(33) },
        rng.string(16),
        rng.below(1000),
        null,
        [bytes],
      ]);
      const replies = collect(message, 64);
      expect(replies.length === 1 || replies.length === 2).toBe(true);
      expect(parsePowReply(message)).toBeNull();
      expect(() => parsePowReply({ t: rng.pick(["mg-pow-ok", "mg-pow-ack", "mg-pow-err", rng.string(10)]), counter: rng.next() - 2 ** 31 })).not.toThrow();
    }
  });
});
