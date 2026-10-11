// MorphGate.fetch (docs/impl/phase2-spec.md §12.5; §12.10 "transport").
import { describe, expect, it } from "vitest";
import { MgFetch, tooHardInPlace, replayableBody, type FetchDeps } from "../src/fetch";
import { CF_GUARD_PREFIX } from "../src/fetch";
import { REPORT_QUEUE_KEY } from "../src/runtime";
import type { VerifyMin } from "../src/verify";
import { FakeEnv, ORIGIN, fakeLocks, json, redirectedResponse, settle, until, type FakeEnvOptions } from "./fakes";
import { referenceVerify } from "./proofref";

const C = "AAECAwQ"; // v1, 4 bits: counter 4 (phase1 kat.json)
const MG = { "mg-challenge": "pow" };
const challenge = (type = "pow", extra: Record<string, unknown> = {}): Response =>
  json(403, { v: 2, error: "mg_challenge", type, challenge: C, pow: { alg: "sha256-hashcash-v1", bits: 4 }, ret: "/page", retry: true, request_id: "r1", ...extra }, { "mg-challenge": type });

function setup(options: FakeEnvOptions & { inPlace?: boolean } = {}) {
  const fake = new FakeEnv(options);
  const rt = fake.runtime();
  const verified: (VerifyMin | undefined)[] = [];
  const deps: FetchDeps = {
    rt,
    inPlace: options.inPlace ?? false,
    solve: {
      createWorker: null,
      scriptSrc: null,
      timers: { setTimeout: (f, ms) => globalThis.setTimeout(f, ms), clearTimeout: (h) => globalThis.clearTimeout(h as number) },
      now: () => Date.now(),
    },
    collect: () => ({ env: null, auto: { v: 1, webdriver: false } }),
    verify: (min) => {
      verified.push(min);
      return true;
    },
  };
  return { fake, rt, mg: new MgFetch(deps), verified };
}

describe("MG-Proof on MorphGate.fetch (§12.5 step 1)", () => {
  it("attaches a valid proof to same-origin requests with a key-bound clearance", async () => {
    const { fake, rt, mg } = setup();
    fake.bindClearance();
    await rt.keys.ensure(true);
    await mg.fetch("/api/save?x=1", { method: "POST", body: "a" });
    const proof = fake.calls[0]!.headers.get("mg-proof");
    expect(proof).not.toBeNull();
    const req = { method: "POST", scheme: "https", host: "example.test", path: "/api/save", now_s: Math.floor(fake.clock.t / 1000), expected_jkt: rt.keys.current()!.jkt };
    expect(await referenceVerify(proof!, req)).toBe("valid");
    // `patch` is sent (and signed) as written; `delete` is upper-cased by fetch.
    await mg.fetch("/api/x", { method: "patch" });
    expect(await referenceVerify(fake.calls[1]!.headers.get("mg-proof")!, { ...req, method: "patch", path: "/api/x" })).toBe("valid");
    // Existing headers are kept.
    await mg.fetch(new Request(`${ORIGIN}/api/y`, { headers: { "x-site": "1" } }));
    expect(fake.calls[2]!.headers.get("x-site")).toBe("1");
    expect(fake.calls[2]!.headers.get("mg-proof")).not.toBeNull();
  });

  it("no proof cross-origin, with data-mg-proof=off, without a bound clearance or a persisted key", async () => {
    const a = setup();
    a.fake.bindClearance();
    await a.rt.keys.ensure(true);
    await a.mg.fetch("https://other.example/api");
    expect(a.fake.calls[0]!.headers.get("mg-proof")).toBeNull();

    const off = setup({ config: { proof: false } });
    off.fake.bindClearance();
    await off.rt.keys.ensure(true);
    await off.mg.fetch("/api");
    expect(off.fake.calls[0]!.headers.get("mg-proof")).toBeNull();
    expect(await off.mg.proofHeader("GET", "/api")).toBeNull();

    const unbound = setup();
    unbound.fake.bindClearance(1800, false);
    await unbound.rt.keys.ensure(true);
    await unbound.mg.fetch("/api");
    expect(unbound.fake.calls[0]!.headers.get("mg-proof")).toBeNull();

    const expired = setup();
    expired.fake.bindClearance(60, true, 120);
    await expired.mg.fetch("/api");
    expect(expired.fake.calls[0]!.headers.get("mg-proof")).toBeNull();

    const memory = setup({ local: null });
    memory.fake.bindClearance();
    await memory.rt.keys.ensure(true);
    expect(memory.rt.keys.kind).toBe("memory");
    await memory.mg.fetch("/api");
    expect(memory.fake.calls[0]!.headers.get("mg-proof")).toBeNull();
  });

  it("proofHeader() serves XHR and axios interceptors", async () => {
    const { fake, rt, mg } = setup();
    fake.bindClearance();
    await rt.keys.ensure(true);
    const proof = await mg.proofHeader("PUT", `${ORIGIN}/api/z`);
    expect(proof?.split(".")).toHaveLength(3);
    expect(await mg.proofHeader(7, "/x")).toBeNull();
  });
});

describe("response handling (§12.5 step 3)", () => {
  it("returns any 403 / 429 without MG-Error or MG-Challenge untouched", async () => {
    const { fake, mg, verified } = setup();
    const body = { error: "mg_challenge", type: "pow", challenge: C, retry: true };
    fake.handler = () => json(403, body);
    const r = await mg.fetch("/api");
    expect(r.status).toBe(403);
    expect(await r.json()).toEqual(body);
    expect(verified).toEqual([]);
    fake.handler = () => new Response("slow down", { status: 429 });
    expect((await mg.fetch("/api")).status).toBe(429);
    expect(fake.calls).toHaveLength(2);
  });

  it("interactive JSON challenges go to the verify entry with min=interactive", async () => {
    const { fake, mg, verified } = setup({ inPlace: true });
    fake.handler = () => challenge("interactive", { ix: { v: 1 } });
    expect((await mg.fetch("/api")).status).toBe(403);
    expect(verified).toEqual(["interactive"]);
  });

  it("a v1 build sends pow / invisible challenges to the verify entry (stage 1)", async () => {
    const { fake, mg, verified } = setup({ inPlace: false });
    fake.handler = () => challenge("pow");
    await mg.fetch("/api");
    expect(verified).toEqual([undefined]);
    expect(fake.callsTo("/__mg/c")).toHaveLength(0);
  });

  it("solves in place, submits v2 JSON to /__mg/c and retries the request once", async () => {
    const { fake, rt, mg, verified } = setup({ inPlace: true });
    let served = 0;
    fake.handler = (call) => {
      const path = new URL(call.url).pathname;
      if (path === "/__mg/c") return json(200, { ok: true, ret: "/page", v: 2, now_ms: fake.clock.t });
      return served++ === 0 ? challenge("pow") : new Response("saved", { status: 201 });
    };
    const r = await mg.fetch("/api/save", { method: "POST", body: "draft" });
    expect(r.status).toBe(201);
    expect(verified).toEqual([]);
    const submit = fake.callsTo("/__mg/c");
    expect(submit).toHaveLength(1);
    expect(submit[0]!.headers.get("content-type")).toBe("application/json");
    const body = JSON.parse(submit[0]!.body as string);
    expect(body).toMatchObject({ v: 2, type: "pow", c: C, p: "", pp: "", pow: { counters: [4] }, ret: "/page" });
    expect(body.jwk.kty).toBe("EC");
    expect(body.sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(JSON.parse(body.t)).toEqual({ auto: { v: 1, webdriver: false } });
    expect(rt.keys.current()).not.toBeNull();
    const api = fake.callsTo("/api/save");
    expect(api).toHaveLength(2);
    expect(api[1]!.body).toBe("draft");
  });

  it("does not retry a stream body; does not solve above 24 bits", async () => {
    const stream = setup({ inPlace: true });
    stream.fake.handler = (call) =>
      new URL(call.url).pathname === "/__mg/c" ? json(200, { ok: true }) : challenge("pow");
    const body = new ReadableStream({ start: (c) => c.close() });
    const r = await stream.mg.fetch("/api", { method: "POST", body, duplex: "half" } as RequestInit);
    expect(r.status).toBe(403);
    expect(stream.fake.callsTo("/api")).toHaveLength(1);
    expect(stream.fake.callsTo("/__mg/c")).toHaveLength(1);

    const hard = setup({ inPlace: true });
    hard.fake.handler = () => challenge("pow", { pow: { alg: "sha256-hashcash-v1", bits: 25 } });
    await hard.mg.fetch("/api");
    expect(hard.verified).toEqual([undefined]);
    expect(hard.fake.callsTo("/__mg/c")).toHaveLength(0);
  });

  it("five concurrent challenged requests share one submission", async () => {
    const { fake, mg } = setup({ inPlace: true, locks: fakeLocks() });
    const seen = new Map<string, number>();
    fake.handler = (call) => {
      const path = new URL(call.url).pathname;
      if (path === "/__mg/c") return json(200, { ok: true });
      const n = seen.get(path) ?? 0;
      seen.set(path, n + 1);
      return n === 0 ? challenge("pow") : new Response("ok", { status: 200 });
    };
    const results = await Promise.all([1, 2, 3, 4, 5].map((i) => mg.fetch(`/api/${i}`)));
    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(fake.callsTo("/__mg/c")).toHaveLength(1);
  });

  it("another tab's fresh clearance (re-read under the lock) skips the solve", async () => {
    const locks = fakeLocks();
    const { fake, mg } = setup({ inPlace: true, locks });
    // Another tab holds "mg-solve" and earns a clearance meanwhile.
    let release!: () => void;
    void locks.request("mg-solve", () => new Promise<void>((r) => (release = r)));
    let n = 0;
    fake.handler = () => (n++ === 0 ? challenge("pow") : new Response("ok", { status: 200 }));
    const pending = mg.fetch("/api");
    await settle();
    expect(locks.names).toEqual(["mg-solve", "mg-solve"]);
    fake.bindClearance(1800, false);
    release();
    expect((await pending).status).toBe(200);
    expect(fake.callsTo("/__mg/c")).toHaveLength(0);
  });

  it("tooHardInPlace and replayableBody", () => {
    expect(tooHardInPlace({ alg: "sha256-hashcash-v1", bits: 24 })).toBe(false);
    expect(tooHardInPlace({ alg: "sha256-hashcash-v1", bits: 25 })).toBe(true);
    expect(tooHardInPlace({ alg: "sha256-hashcash-v2", bits: 25, k: 8 })).toBe(false);
    expect(tooHardInPlace({ alg: "sha256-hashcash-v2", bits: 26, k: 8 })).toBe(true);
    expect(tooHardInPlace(undefined)).toBe(true);
    expect(replayableBody("/x", { body: "s" })).toBe(true);
    expect(replayableBody("/x", { body: new URLSearchParams("a=1") })).toBe(true);
    expect(replayableBody("/x", { body: new Blob(["x"]) })).toBe(true);
    expect(replayableBody("/x", { body: new ArrayBuffer(2) })).toBe(true);
    expect(replayableBody("/x", { body: new FormData() })).toBe(true);
    expect(replayableBody("/x", { body: new ReadableStream() })).toBe(false);
    expect(replayableBody(new Request(`${ORIGIN}/x`, { method: "POST", body: "b" }))).toBe(false);
    expect(replayableBody(new Request(`${ORIGIN}/x`))).toBe(true);
  });
});

describe("cf-mitigated (§12.5)", () => {
  const upstream = (): Response => new Response("<html>", { status: 403, headers: { "cf-mitigated": "challenge" } });

  it("queues a report, calls onBeforeNavigate and reloads once per path per minute", async () => {
    const { fake, rt, mg } = setup({ path: "/articles" });
    const order: string[] = [];
    rt.onBeforeNavigate(() => order.push("before"));
    fake.handler = upstream;
    await mg.fetch("/api");
    expect(fake.navigations).toEqual([`assign ${ORIGIN}/articles`]);
    expect(order).toEqual(["before"]);
    const queued = JSON.parse(fake.session!.getItem(REPORT_QUEUE_KEY)!);
    expect(queued).toEqual([{ kind: "upstream_challenge", scope: "protected_fetch", path: "/articles", count: 1 }]);
    expect(fake.session!.getItem(`${CF_GUARD_PREFIX}/articles`)).toBe(String(fake.clock.t));
    // Within 60 s: no second reload; the report goes out now.
    fake.handler = (call) => (new URL(call.url).pathname === "/__mg/t" ? new Response(null, { status: 204 }) : upstream());
    await mg.fetch("/api");
    await settle();
    expect(fake.navigations).toHaveLength(1);
    expect(fake.callsTo("/__mg/t")).toHaveLength(1);
    // The next page load flushes the queue with keepalive.
    rt.flushQueuedReports();
    await until(() => fake.callsTo("/__mg/t").length === 2);
    expect(fake.callsTo("/__mg/t")[1]!.keepalive).toBe(true);
    expect(fake.session!.getItem(REPORT_QUEUE_KEY)).toBeNull();
  });

  it("without sessionStorage: no reload, report only", async () => {
    const { fake, mg } = setup({ session: null });
    fake.handler = (call) => (new URL(call.url).pathname === "/__mg/t" ? new Response(null, { status: 204 }) : upstream());
    await mg.fetch("/api");
    await until(() => fake.callsTo("/__mg/t").length === 1);
    expect(fake.navigations).toEqual([]);
    expect(JSON.parse(fake.callsTo("/__mg/t")[0]!.body as string)).toEqual({
      v: 1,
      reports: [{ kind: "upstream_challenge", scope: "protected_fetch", path: "/page", count: 1 }],
    });
  });
});

describe("mg_proof_required (§12.5, §9.1)", () => {
  const required = (extra: Record<string, unknown> = {}, nowMs?: number): Response =>
    json(403, { v: 2, error: "mg_proof_required", now_ms: nowMs ?? 0, request_id: "r", ...extra }, { "mg-error": "mg_proof_required" });

  it("step 1: a clock more than 5 s off is corrected and the request retried with a new proof", async () => {
    const { fake, rt, mg, verified } = setup();
    fake.bindClearance();
    await rt.keys.ensure(true);
    const serverNow = fake.clock.t + 40_000;
    let n = 0;
    fake.handler = () => (n++ === 0 ? required({}, serverNow) : new Response("ok"));
    expect((await mg.fetch("/api", { method: "POST", body: "x" })).status).toBe(200);
    expect(verified).toEqual([]);
    const [first, second] = fake.callsTo("/api");
    const iat = (proof: string): number => JSON.parse(atob(proof.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).iat;
    expect(iat(second!.headers.get("mg-proof")!) - iat(first!.headers.get("mg-proof")!)).toBe(40);
  });

  it("step 2: an attached pow C is solved in place and the request retried", async () => {
    const { fake, rt, mg } = setup({ inPlace: true });
    fake.bindClearance();
    await rt.keys.ensure(true);
    let n = 0;
    fake.handler = (call) => {
      if (new URL(call.url).pathname === "/__mg/c") return json(200, { ok: true });
      return n++ === 0
        ? required({ type: "pow", challenge: C, pow: { alg: "sha256-hashcash-v1", bits: 4 }, ret: "/page" }, fake.clock.t)
        : new Response("ok");
    };
    expect((await mg.fetch("/api")).status).toBe(200);
    const sub = JSON.parse(fake.callsTo("/__mg/c")[0]!.body as string);
    // Signed with the same key the proof used: the C is bound to it.
    expect(sub.jwk).toEqual(rt.keys.current()!.jwk);
  });

  it("step 3: a key only in memory returns the answer and reports key_unavailable once", async () => {
    const { fake, mg, verified } = setup({ local: null });
    fake.handler = (call) => (new URL(call.url).pathname === "/__mg/t" ? new Response(null, { status: 204 }) : required({}, fake.clock.t));
    expect((await mg.fetch("/api")).status).toBe(403);
    await mg.fetch("/api");
    await until(() => fake.callsTo("/__mg/t").length === 1);
    await settle();
    expect(fake.callsTo("/__mg/t")).toHaveLength(1);
    expect(JSON.parse(fake.callsTo("/__mg/t")[0]!.body as string).reports).toEqual([{ kind: "key_unavailable", reason: "no_storage" }]);
    expect(verified).toEqual([]);
    const none = setup({ subtle: null });
    none.fake.handler = (call) => (new URL(call.url).pathname === "/__mg/t" ? new Response(null, { status: 204 }) : required());
    await none.mg.fetch("/api");
    await until(() => none.fake.callsTo("/__mg/t").length === 1);
    expect(JSON.parse(none.fake.callsTo("/__mg/t")[0]!.body as string).reports[0].reason).toBe("no_webcrypto");
  });

  it("step 4: otherwise the verify entry", async () => {
    const { fake, rt, mg, verified } = setup();
    await rt.keys.ensure(true);
    fake.handler = () => required({}, fake.clock.t);
    await mg.fetch("/api");
    expect(verified).toEqual([undefined]);
  });

  it("a redirected GET is re-requested once at response.url with a new proof", async () => {
    const { fake, rt, mg } = setup();
    fake.bindClearance();
    await rt.keys.ensure(true);
    let n = 0;
    fake.handler = (call) => {
      if (n++ === 0) return redirectedResponse(required({}, fake.clock.t), `${ORIGIN}/api/v2/list`);
      return new Response(new URL(call.url).pathname);
    };
    const r = await mg.fetch("/api/list");
    expect(await r.text()).toBe("/api/v2/list");
    const second = fake.calls[1]!;
    const req = { method: "GET", scheme: "https", host: "example.test", path: "/api/v2/list", now_s: Math.floor(fake.clock.t / 1000), expected_jkt: rt.keys.current()!.jkt };
    expect(await referenceVerify(second.headers.get("mg-proof")!, req)).toBe("valid");
    // Other methods are not re-sent to the redirect target.
    const post = setup();
    post.fake.bindClearance();
    await post.rt.keys.ensure(true);
    post.fake.handler = () => redirectedResponse(required({}, post.fake.clock.t), `${ORIGIN}/elsewhere`);
    await post.mg.fetch("/api", { method: "POST", body: "x" });
    expect(post.fake.callsTo("/elsewhere")).toHaveLength(0);
  });
});

describe("clock (§12.5)", () => {
  it("learns the skew from now_ms and from a same-origin Date header, and keeps it in sessionStorage", async () => {
    const { fake, rt, mg } = setup();
    fake.handler = () => new Response("ok", { headers: { date: new Date(fake.clock.t + 120_000).toUTCString() } });
    await mg.fetch("/api");
    expect(Math.abs(rt.clock.skewMs - 120_000)).toBeLessThanOrEqual(1_500);
    expect(Number(fake.session!.getItem("mg_skew"))).toBe(rt.clock.skewMs);
    expect(rt.clock.fromNowMs(fake.clock.t - 3_000)).toBeLessThan(0);
    expect(rt.clock.skewMs).toBe(-3_000);
    expect(new FakeEnv({ session: fake.session }).runtime().clock.skewMs).toBe(-3_000);
  });
});

void MG;
