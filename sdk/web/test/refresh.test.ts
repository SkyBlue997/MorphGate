// Silent clearance refresh (docs/impl/phase2-spec.md §12.5 "刷新", §9.3; §12.10 "刷新定时器").
import { describe, expect, it } from "vitest";
import { REFRESH_DENIED_PREFIX, REFRESH_RETRY_MS, Refresher, refreshAtS } from "../src/refresh";
import { FakeEnv, fakeLocks, json, settle, until, type FakeEnvOptions } from "./fakes";
import { referenceVerify } from "./proofref";

describe("refreshAtS", () => {
  it("is iat + 0.8 (exp - iat), not before exp - 600 s, not after exp - 60 s", () => {
    expect(refreshAtS({ iat: 0, exp: 1800, bound: true })).toBe(1440);
    expect(refreshAtS({ iat: 0, exp: 7200, bound: true })).toBe(6600); // 5760 is before exp - 600
    expect(refreshAtS({ iat: 0, exp: 200, bound: true })).toBe(140); // 160 is after exp - 60
    expect(refreshAtS({ iat: 0, exp: 3000, bound: true })).toBe(2400);
  });
});

async function setup(options: FakeEnvOptions = {}) {
  const fake = new FakeEnv(options);
  const rt = fake.runtime();
  fake.bindClearance(1800);
  await rt.keys.ensure(true);
  const refresher = new Refresher(rt);
  return { fake, rt, refresher };
}

const nowS = (fake: FakeEnv): number => Math.floor(fake.clock.t / 1000);

describe("Refresher", () => {
  it("refreshes at the scheduled time with MG-Proof and reschedules from the new cookie", async () => {
    const { fake, rt, refresher } = await setup();
    fake.handler = () => {
      fake.bindClearance(1800);
      return json(200, { v: 2, ok: true, iat: nowS(fake), exp: nowS(fake) + 1800, now_ms: fake.clock.t });
    };
    refresher.start();
    await fake.clock.advance(1440 * 1000 - 1);
    expect(fake.callsTo("/__mg/r")).toHaveLength(0);
    await fake.clock.advance(1);
    await until(() => fake.callsTo("/__mg/r").length === 1);
    const call = fake.callsTo("/__mg/r")[0]!;
    expect(call.method).toBe("POST");
    expect(call.body).toBe('{"v":2}');
    const req = { method: "POST", scheme: "https", host: "example.test", path: "/__mg/r", now_s: nowS(fake), expected_jkt: rt.keys.current()!.jkt };
    expect(await referenceVerify(call.headers.get("mg-proof")!, req)).toBe("valid");
    await settle();
    expect(fake.clock.pending).toBe(1); // the next refresh is armed
    await fake.clock.advance(1440 * 1000);
    await until(() => fake.callsTo("/__mg/r").length === 2);
  });

  it("does nothing for an unbound clearance, with data-mg-refresh=off, or while hidden", async () => {
    const a = await setup();
    a.fake.bindClearance(1800, false);
    a.refresher.start();
    expect(a.fake.clock.pending).toBe(0);

    const off = await setup({ config: { refresh: false } });
    off.refresher.start();
    expect(off.fake.clock.pending).toBe(0);

    const hidden = await setup();
    hidden.fake.visibility = false;
    hidden.refresher.start();
    expect(hidden.fake.clock.pending).toBe(0);
    // Becoming visible after the refresh time checks at once.
    hidden.fake.handler = () => json(200, { ok: true });
    hidden.fake.clock.t += 1500 * 1000;
    hidden.fake.setVisible(true);
    await hidden.fake.clock.advance(0);
    await until(() => hidden.fake.callsTo("/__mg/r").length === 1);
  });

  it("pauses while hidden", async () => {
    const { fake, refresher } = await setup();
    refresher.start();
    expect(fake.clock.pending).toBe(1);
    fake.setVisible(false);
    expect(fake.clock.pending).toBe(0);
  });

  it("mg_refresh_denied marks that exp and never tries it again", async () => {
    const { fake, refresher } = await setup();
    fake.handler = () => json(403, { v: 2, error: "mg_refresh_denied", request_id: "r" }, { "mg-error": "mg_refresh_denied" });
    const exp = fake.cookie.match(/mg_st=\d+\.(\d+)/)![1]!;
    expect(await refresher.attempt(Number(exp))).toBe("denied");
    expect(fake.session!.getItem(REFRESH_DENIED_PREFIX + exp)).toBe("1");
    refresher.schedule();
    expect(fake.clock.pending).toBe(0);
  });

  it("mg_blocked and an upstream challenge stop background work for the page", async () => {
    const blocked = await setup();
    blocked.fake.handler = () => json(403, { v: 2, error: "mg_blocked" }, { "mg-error": "mg_blocked" });
    const exp = Number(blocked.fake.cookie.match(/mg_st=\d+\.(\d+)/)![1]);
    expect(await blocked.refresher.attempt(exp)).toBe("blocked");
    expect(blocked.rt.backgroundStopped).toBe(true);

    const cf = await setup();
    cf.fake.handler = (call) =>
      new URL(call.url).pathname === "/__mg/t" ? new Response(null, { status: 204 }) : new Response("<html>", { status: 403, headers: { "cf-mitigated": "challenge" } });
    expect(await cf.refresher.attempt(exp)).toBe("stopped");
    expect(cf.fake.navigations).toEqual([]); // background requests never reload
    expect(cf.rt.backgroundStopped).toBe(true);
  });

  it("retries a network failure after 30 s, at most 3 times", async () => {
    const { fake, refresher } = await setup();
    fake.handler = () => {
      throw new TypeError("network");
    };
    const exp = Number(fake.cookie.match(/mg_st=\d+\.(\d+)/)![1]);
    fake.clock.t += 1500 * 1000;
    expect(await refresher.attempt(exp)).toBe("retry");
    for (let i = 0; i < 5; i++) await fake.clock.advance(REFRESH_RETRY_MS + 60_000);
    await settle();
    expect(fake.callsTo("/__mg/r")).toHaveLength(4);
  });

  it("another tab's refresh (a new exp under the lock) ends the attempt", async () => {
    const locks = fakeLocks();
    const { fake, refresher } = await setup({ locks });
    const exp = Number(fake.cookie.match(/mg_st=\d+\.(\d+)/)![1]);
    fake.bindClearance(3600); // another tab refreshed
    expect(await refresher.attempt(exp)).toBe("skipped");
    expect(locks.names.filter((n) => n === "mg-refresh")).toHaveLength(1);
    expect(fake.callsTo("/__mg/r")).toHaveLength(0);
  });

  it("an Edge without /__mg/r (404) stops refreshing", async () => {
    const { fake, refresher } = await setup();
    fake.handler = () => new Response("not found", { status: 404 });
    const exp = Number(fake.cookie.match(/mg_st=\d+\.(\d+)/)![1]);
    expect(await refresher.attempt(exp)).toBe("denied");
    expect(await refresher.attempt(exp)).toBe("skipped");
  });
});
