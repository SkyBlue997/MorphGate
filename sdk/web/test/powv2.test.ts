// PoW v2 Worker protocol and runner (docs/impl/phase2-spec.md §6.4, §12.6, §12.10 "PoW 协议").
import { describe, expect, it } from "vitest";
import {
  MAX_POW_K,
  POW2_ACK_TIMEOUT_MS,
  handlePow2Message,
  parsePow2Reply,
  parsePow2Request,
  powPrefixV2,
  runPowV2,
  subPuzzleBits,
  verifyPowV2,
  type Pow2Reply,
  type PowListener,
  type PowRunnerDeps,
  type PowWorkerPort,
} from "../src/powv2";
import { powPrefix } from "../src/pow";
import { installWorker } from "../src/worker";
import { XorShift32 } from "./xorshift";

const C = "mg-test-c-2";
const PREFIX = powPrefixV2(C);
// kat.json pow_v2: mg-test-c-2 at d = 12, k = 4.
const KAT_COUNTERS = [2946, 14020, 17969, 2810];

class FakeClock {
  t = 0;
  private queue: { at: number; f: () => void; id: number }[] = [];
  private nextId = 1;
  setTimeout = (f: () => void, ms: number): unknown => {
    const id = this.nextId++;
    this.queue.push({ at: this.t + ms, f, id });
    return id;
  };
  clearTimeout = (id: unknown): void => {
    this.queue = this.queue.filter((e) => e.id !== id);
  };
  /** Run due timers (in order) up to `ms` from now. */
  advance(ms: number): void {
    const end = this.t + ms;
    for (;;) {
      this.queue.sort((a, b) => a.at - b.at);
      const next = this.queue[0];
      if (next === undefined || next.at > end) break;
      this.queue.shift();
      this.t = Math.max(this.t, next.at);
      next.f();
    }
    this.t = end;
  }
  /** Run only the next due timer. */
  step(): void {
    this.queue.sort((a, b) => a.at - b.at);
    const next = this.queue.shift();
    if (next === undefined) return;
    this.t = Math.max(this.t, next.at);
    next.f();
  }
  get pending(): number {
    return this.queue.length;
  }
}

class FakeWorker implements PowWorkerPort {
  posted: unknown[] = [];
  terminated = false;
  onMessage: (data: unknown) => void = () => undefined;
  onError: () => void = () => undefined;
  constructor(readonly url: string) {}
  listen(onMessage: (data: unknown) => void, onError: () => void): void {
    this.onMessage = onMessage;
    this.onError = onError;
  }
  postMessage(message: unknown): void {
    this.posted.push(message);
  }
  terminate(): void {
    this.terminated = true;
  }
  reply(message: Pow2Reply): void {
    this.onMessage(message);
  }
}

function setup(createWorker: PowRunnerDeps["createWorker"] = null) {
  const clock = new FakeClock();
  const deps: PowRunnerDeps = {
    createWorker,
    workerUrl: "https://example.test/__mg/s/mg.0123456789abcdef.js",
    rebuildUrl: "/__mg/s/mg.js?sv=0.2.0-preview.1",
    sv: "0.2.0-preview.1",
    timers: clock,
    now: () => clock.t,
    yieldNow: null,
  };
  const events: string[] = [];
  let result: number[] | null = null;
  const listener: PowListener = {
    part: (i, counter) => void events.push(`part ${i} ${counter}`),
    done: (counters) => {
      result = counters;
      events.push("done");
    },
    error: () => void events.push("error"),
  };
  return { clock, deps, events, listener, result: () => result };
}

describe("worker protocol v2", () => {
  it("acks with its own sv, reports every part, then ok", () => {
    const replies: Pow2Reply[] = [];
    handlePow2Message({ t: "mg-pow2", prefix: PREFIX, bits: 12, k: 4, sv: "x" }, (r) => replies.push(r), "9.9.9");
    expect(replies[0]).toEqual({ t: "mg-pow2-ack", sv: "9.9.9" });
    expect(replies.slice(1, 5)).toEqual(KAT_COUNTERS.map((counter, i) => ({ t: "mg-pow2-part", i, counter })));
    expect(replies[5]).toEqual({ t: "mg-pow2-ok", counters: KAT_COUNTERS });
  });

  it("starts each sub-puzzle at start[i]", () => {
    const replies: Pow2Reply[] = [];
    handlePow2Message({ t: "mg-pow2", prefix: PREFIX, bits: 12, k: 4, sv: "x", start: [2946, 14020, 0, 2811] }, (r) => replies.push(r), "s");
    const ok = replies[replies.length - 1] as { counters: number[] };
    expect(ok.counters.slice(0, 3)).toEqual([2946, 14020, 17969]);
    expect(ok.counters[3]).toBeGreaterThan(2811);
    expect(verifyPowV2(PREFIX, 12, ok.counters)).toBe(true);
  });

  it("answers mg-pow2-err to anything malformed, and err when the search is bounded out", () => {
    for (const bad of [
      null,
      { t: "mg-pow2", prefix: powPrefix(C), bits: 8, k: 1, sv: "" }, // a v1 prefix
      { t: "mg-pow2", prefix: PREFIX, bits: 33, k: 1, sv: "" },
      { t: "mg-pow2", prefix: PREFIX, bits: 8, k: 0, sv: "" },
      { t: "mg-pow2", prefix: PREFIX, bits: 8, k: MAX_POW_K + 1, sv: "" },
      { t: "mg-pow2", prefix: PREFIX, bits: 8, k: 2, sv: "", start: [0] },
      { t: "mg-pow2", prefix: PREFIX, bits: 8, k: 1, sv: 7 },
    ]) {
      const replies: Pow2Reply[] = [];
      handlePow2Message(bad, (r) => replies.push(r), "s");
      expect(replies).toEqual([{ t: "mg-pow2-err" }]);
    }
    const replies: Pow2Reply[] = [];
    handlePow2Message({ t: "mg-pow2", prefix: PREFIX, bits: 32, k: 1, sv: "" }, (r) => replies.push(r), "s", 10);
    expect(replies).toEqual([{ t: "mg-pow2-ack", sv: "s" }, { t: "mg-pow2-err" }]);
  });

  it("the Worker entry dispatches v1 and v2 messages", () => {
    const listeners: ((e: { data?: unknown }) => void)[] = [];
    const posted: unknown[] = [];
    installWorker({ addEventListener: (_t, l) => void listeners.push(l), postMessage: (m) => void posted.push(m) }, "1.0.0");
    listeners[0]!({ data: { t: "mg-pow2", prefix: PREFIX, bits: 4, k: 1, sv: "1.0.0" } });
    expect(posted[0]).toEqual({ t: "mg-pow2-ack", sv: "1.0.0" });
    listeners[0]!({ data: { t: "mg-pow", prefix: powPrefix("AAECAwQ"), bits: 4 } });
    expect(posted).toContainEqual({ t: "mg-pow-ok", counter: 4 });
  });

  it("parsers never throw on 10,000 xorshift messages (§2.4)", () => {
    const rng = new XorShift32(0x5a17);
    for (let n = 0; n < 10_000; n++) {
      const msg = {
        t: rng.pick(["mg-pow2", "mg-pow2-ack", "mg-pow2-part", "mg-pow2-ok", "mg-pow2-err", rng.string(6)]),
        prefix: rng.pick([PREFIX, rng.bytes(42), rng.bytes(rng.below(60)), "x"]),
        bits: rng.pick([rng.below(40), -1, "8", 1.5]),
        k: rng.pick([rng.below(10), "2", null]),
        sv: rng.pick([rng.string(8), rng.string(40), 3]),
        start: rng.pick([undefined, [0], [rng.below(5), -1], "x"]),
        i: rng.pick([rng.below(10), -1, "0"]),
        counter: rng.pick([rng.below(1000), -1, 2 ** 53, 1.5]),
        counters: rng.pick([[1], [], Array(9).fill(0), [1, "2"], null]),
      };
      const request = parsePow2Request(msg);
      if (request !== null) expect(request.k).toBeGreaterThanOrEqual(1);
      parsePow2Reply(msg);
    }
  });
});

describe("runPowV2", () => {
  it("uses the Worker: ack, parts (verified), ok", () => {
    const workers: FakeWorker[] = [];
    const s = setup((url) => {
      const w = new FakeWorker(url);
      workers.push(w);
      return w;
    });
    const run = runPowV2(s.deps, PREFIX, 12, 4, [], s.listener);
    const w = workers[0]!;
    expect(w.url).toBe(s.deps.workerUrl);
    expect(w.posted[0]).toMatchObject({ t: "mg-pow2", bits: 12, k: 4, sv: s.deps.sv, start: [0, 0, 0, 0] });
    w.reply({ t: "mg-pow2-ack", sv: s.deps.sv });
    s.clock.advance(POW2_ACK_TIMEOUT_MS * 3);
    KAT_COUNTERS.forEach((counter, i) => w.reply({ t: "mg-pow2-part", i, counter }));
    w.reply({ t: "mg-pow2-ok", counters: KAT_COUNTERS });
    expect(s.result()).toEqual(KAT_COUNTERS);
    expect(s.events.filter((e) => e.startsWith("part"))).toHaveLength(4);
    expect(run.worker).toBe(true);
    expect(w.terminated).toBe(true);
  });

  it("falls back to the main thread without an ack within 2 s, keeping verified parts", () => {
    const workers: FakeWorker[] = [];
    const s = setup((url) => {
      const w = new FakeWorker(url);
      workers.push(w);
      return w;
    });
    const run = runPowV2(s.deps, PREFIX, 12, 4, [], s.listener);
    s.clock.advance(POW2_ACK_TIMEOUT_MS - 1);
    expect(workers[0]!.terminated).toBe(false);
    s.clock.advance(1);
    expect(workers[0]!.terminated).toBe(true);
    expect(run.worker).toBe(false);
    for (let n = 0; n < 200 && s.result() === null; n++) s.clock.advance(1);
    expect(s.result()).toEqual(KAT_COUNTERS);
    // A late Worker message changes nothing.
    workers[0]!.reply({ t: "mg-pow2-part", i: 0, counter: 1 });
    expect(s.events.filter((e) => e === "done")).toHaveLength(1);
  });

  it("rebuilds the Worker once from rebuildUrl when its sv differs, then uses the main thread", () => {
    const workers: FakeWorker[] = [];
    const s = setup((url) => {
      const w = new FakeWorker(url);
      workers.push(w);
      return w;
    });
    runPowV2(s.deps, PREFIX, 4, 1, [], s.listener);
    workers[0]!.reply({ t: "mg-pow2-ack", sv: "0.1.0" });
    expect(workers[0]!.terminated).toBe(true);
    expect(workers[1]!.url).toBe(s.deps.rebuildUrl);
    workers[1]!.reply({ t: "mg-pow2-ack", sv: "0.1.0" });
    expect(workers[1]!.terminated).toBe(true);
    expect(workers).toHaveLength(2);
    for (let n = 0; n < 50 && s.result() === null; n++) s.clock.advance(1);
    expect(s.result()).not.toBeNull();
    expect(verifyPowV2(PREFIX, 4, s.result()!)).toBe(true);
  });

  it("a rebuilt Worker with the right sv is used", () => {
    const workers: FakeWorker[] = [];
    const s = setup((url) => {
      const w = new FakeWorker(url);
      workers.push(w);
      return w;
    });
    runPowV2(s.deps, PREFIX, 12, 4, [], s.listener);
    workers[0]!.reply({ t: "mg-pow2-ack", sv: "old" });
    workers[1]!.reply({ t: "mg-pow2-ack", sv: s.deps.sv });
    workers[1]!.reply({ t: "mg-pow2-ok", counters: KAT_COUNTERS });
    expect(s.result()).toEqual(KAT_COUNTERS);
  });

  it("mg-pow2-err, a wrong part, a Worker error or a throwing constructor fall back", () => {
    const cases: ((w: FakeWorker) => void)[] = [
      (w) => w.reply({ t: "mg-pow2-err" }),
      (w) => {
        w.reply({ t: "mg-pow2-ack", sv: "0.2.0-preview.1" });
        w.reply({ t: "mg-pow2-part", i: 0, counter: 1 }); // does not solve sub-puzzle 0
      },
      (w) => w.onError(),
    ];
    for (const act of cases) {
      const workers: FakeWorker[] = [];
      const s = setup((url) => {
        const w = new FakeWorker(url);
        workers.push(w);
        return w;
      });
      const run = runPowV2(s.deps, PREFIX, 12, 4, [], s.listener);
      act(workers[0]!);
      expect(run.worker).toBe(false);
      for (let n = 0; n < 200 && s.result() === null; n++) s.clock.advance(1);
      expect(s.result()).toEqual(KAT_COUNTERS);
    }
    const s = setup(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    runPowV2(s.deps, PREFIX, 4, 2, [], s.listener);
    for (let n = 0; n < 50 && s.result() === null; n++) s.clock.advance(1);
    expect(verifyPowV2(PREFIX, 4, s.result()!)).toBe(true);
  });

  it("main-thread slices last at most 8 ms and stop when stopped", () => {
    const s = setup(null);
    let reads = 0;
    // Each clock read advances 1 ms: a slice ends after about 8 chunks.
    s.deps.now = () => s.clock.t + reads++;
    const run = runPowV2(s.deps, PREFIX, 24, 8, [], s.listener);
    s.clock.step();
    const afterOne = reads;
    expect(afterOne).toBeGreaterThan(1);
    expect(afterOne).toBeLessThanOrEqual(10);
    expect(s.clock.pending).toBe(1); // the next slice is queued, the page got control back
    run.stop();
    s.clock.step();
    expect(s.clock.pending).toBe(0);
    expect(s.events).not.toContain("done");
  });

  it("start[] keeps solved sub-puzzles that satisfy the new difficulty (provider switch)", () => {
    const solved = KAT_COUNTERS;
    // Raise the difficulty to 14 bits: keep those with >= 14 leading zeros, continue the others.
    const start = solved.map((c, i) => (subPuzzleBits(PREFIX, i, c) >= 14 ? c : c + 1));
    const s = setup(null);
    runPowV2(s.deps, PREFIX, 14, 4, start, s.listener);
    for (let n = 0; n < 2_000 && s.result() === null; n++) s.clock.advance(1);
    const out = s.result()!;
    expect(verifyPowV2(PREFIX, 14, out)).toBe(true);
    solved.forEach((c, i) => {
      if (subPuzzleBits(PREFIX, i, c) >= 14) expect(out[i]).toBe(c);
      else expect(out[i]).toBeGreaterThan(c);
    });
  });
});
