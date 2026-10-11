// Runtime pieces: the status cookie, methods, reports (docs/impl/phase2-spec.md §6.8, §9.4, §12.5).
import { describe, expect, it } from "vitest";
import { parseStatusCookie, statusValid, wireMethod } from "../src/proof";
import { FakeEnv, settle, until } from "./fakes";
import { XorShift32 } from "./xorshift";

describe("__Host-mg_st (§6.8)", () => {
  it("parses <iat>.<exp>.<b> among other cookies", () => {
    expect(parseStatusCookie("a=1; __Host-mg_st=1790000000.1790001800.1; b=2")).toEqual({ iat: 1790000000, exp: 1790001800, bound: true });
    expect(parseStatusCookie("__Host-mg_st=1.2.0")).toEqual({ iat: 1, exp: 2, bound: false });
    for (const bad of ["", "__Host-mg_st=", "__Host-mg_st=1.2", "__Host-mg_st=1.2.2", "__Host-mg_st=2.1.1", "__host-mg_st=1.2.1", "__Host-mg_st=a.b.1", "x__Host-mg_st=1.2.1"]) {
      expect(parseStatusCookie(bad), bad).toBeNull();
    }
    expect(statusValid({ iat: 1, exp: 10, bound: true }, 9)).toBe(true);
    expect(statusValid({ iat: 1, exp: 10, bound: true }, 10)).toBe(false);
    expect(statusValid(null, 0)).toBe(false);
  });

  it("never throws on 10,000 xorshift cookie strings (§2.4)", () => {
    const rng = new XorShift32(0xc00c);
    for (let i = 0; i < 10_000; i++) {
      const value = rng.pick([`${rng.below(1e9)}.${rng.below(1e9)}.${rng.below(3)}`, rng.string(30)]);
      const s = parseStatusCookie(`${rng.string(10)}; __Host-mg_st=${value}; ${rng.string(10)}`);
      if (s !== null) expect(s.exp).toBeGreaterThan(s.iat);
    }
  });
});

describe("wireMethod (§6.7 htm)", () => {
  it("upper-cases only the six methods fetch normalizes", () => {
    for (const m of ["delete", "get", "head", "options", "post", "put", "Post"]) expect(wireMethod(m)).toBe(m.toUpperCase());
    expect(wireMethod("patch")).toBe("patch");
    expect(wireMethod("PATCH")).toBe("PATCH");
    expect(wireMethod("Purge")).toBe("Purge");
  });
});

describe("reports (§9.4)", () => {
  it("cache_hit is reported once per page for the Edge's own endpoints, never for /__mg/s/", async () => {
    const fake = new FakeEnv();
    const rt = fake.runtime();
    fake.handler = () => new Response(null, { status: 204 });
    const hit = new Response("{}", { headers: { "cf-cache-status": "HIT" } });
    rt.observe(hit, "/__mg/s/mg.js");
    rt.observe(hit, "https://other.example/__mg/c");
    await settle();
    expect(fake.callsTo("/__mg/t")).toHaveLength(0);
    rt.observe(hit, "/__mg/c/renew");
    rt.observe(hit, "/__mg/c");
    await until(() => fake.callsTo("/__mg/t").length === 1);
    await settle();
    expect(fake.callsTo("/__mg/t")).toHaveLength(1);
    expect(JSON.parse(fake.callsTo("/__mg/t")[0]!.body as string).reports).toEqual([{ kind: "cache_hit", path: "/__mg/c/renew" }]);
  });

  it("an Edge without /__mg/t (404) ends reporting for the page; a block stops background work", async () => {
    const fake = new FakeEnv();
    const rt = fake.runtime();
    fake.handler = () => new Response("nf", { status: 404 });
    await rt.sendReports([{ kind: "sw_intercept", path: "/__mg/v" }]);
    await rt.sendReports([{ kind: "sw_intercept", path: "/__mg/v" }]);
    expect(fake.callsTo("/__mg/t")).toHaveLength(1);
    rt.backgroundStopped = true;
    const other = new FakeEnv().runtime();
    other.backgroundStopped = true;
    await other.sendReports([{ kind: "sw_intercept", path: "/x" }]);
  });

  it("signs reports when the clearance is key-bound", async () => {
    const fake = new FakeEnv();
    const rt = fake.runtime();
    fake.bindClearance();
    await rt.keys.ensure(true);
    fake.handler = () => new Response(null, { status: 204 });
    await rt.sendReports([{ kind: "key_unavailable", reason: "no_idb" }]);
    expect(fake.callsTo("/__mg/t")[0]!.headers.get("mg-proof")?.split(".")).toHaveLength(3);
  });
});
