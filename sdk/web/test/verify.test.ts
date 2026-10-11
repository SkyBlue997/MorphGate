import { describe, expect, it } from "vitest";
import { VERIFY_GUARD_MS, VERIFY_KEY_PREFIX, isMgChallenge, startVerify, verifyUrl, type VerifyDeps } from "../src/verify";

const CONFIG = { pathPrefix: "/__mg/" };

function memory(): Map<string, string> & { getItem(k: string): string | null; setItem(k: string, v: string): void } {
  const m = new Map<string, string>() as Map<string, string> & {
    getItem(k: string): string | null;
    setItem(k: string, v: string): void;
  };
  m.getItem = (k) => m.get(k) ?? null;
  m.setItem = (k, v) => void m.set(k, v);
  return m;
}

function deps(pathname: string, search: string, store: ReturnType<typeof memory> | null, now: number) {
  const assigned: string[] = [];
  const d: VerifyDeps = {
    location: { pathname, search, assign: (url) => void assigned.push(url) },
    storage: () => store,
    now: () => now,
  };
  return { d, assigned };
}

describe("verifyUrl", () => {
  it("encodes the page path and query as one ret parameter", () => {
    expect(verifyUrl(CONFIG, "/posts/7?x=1&y=%20")).toBe("/__mg/v?ret=%2Fposts%2F7%3Fx%3D1%26y%3D%2520");
    expect(verifyUrl({ pathPrefix: "/x7/" }, "/")).toBe("/x7/v?ret=%2F");
  });

  it("leaves out a ret the Edge would refuse", () => {
    for (const ret of ["//evil.example/", "https://evil.example/", "/__mg/c", "/a#b", `/${"a".repeat(512)}`, null]) {
      expect(verifyUrl(CONFIG, ret)).toBe("/__mg/v");
    }
  });
});

describe("startVerify", () => {
  it("navigates once per path per guard window", () => {
    const store = memory();
    const first = deps("/posts/7", "?x=1", store, 1_000_000);
    expect(startVerify(CONFIG, first.d)).toBe(true);
    expect(first.assigned).toEqual(["/__mg/v?ret=%2Fposts%2F7%3Fx%3D1"]);
    expect(store.getItem(`${VERIFY_KEY_PREFIX}/posts/7?x=1`)).toBe("1000000");

    // Challenged again right after the return: no loop.
    const again = deps("/posts/7", "?x=1", store, 1_000_000 + VERIFY_GUARD_MS - 1);
    expect(startVerify(CONFIG, again.d)).toBe(false);
    expect(again.assigned).toEqual([]);
    // Another page, or the same one later, may go.
    expect(startVerify(CONFIG, deps("/other", "", store, 1_000_001).d)).toBe(true);
    expect(startVerify(CONFIG, deps("/posts/7", "?x=1", store, 1_000_000 + VERIFY_GUARD_MS).d)).toBe(true);
    // A record from the future (clock change) does not block forever.
    store.setItem(`${VERIFY_KEY_PREFIX}/f`, String(9_000_000));
    expect(startVerify(CONFIG, deps("/f", "", store, 1_000_000).d)).toBe(true);
  });

  it("stays put without storage and never throws", () => {
    const none = deps("/a", "", null, 1);
    expect(startVerify(CONFIG, none.d)).toBe(false);
    expect(none.assigned).toEqual([]);
    const throwing: VerifyDeps = {
      location: { pathname: "/a", search: "", assign: () => undefined },
      storage: () => {
        throw new Error("SecurityError");
      },
      now: () => 1,
    };
    expect(startVerify(CONFIG, throwing)).toBe(false);
  });
});

describe("isMgChallenge", () => {
  const json = { "content-type": "application/json" };
  const challenge = JSON.stringify({ error: "mg_challenge", type: "pow", challenge: "v1.abc", retry: true });

  it("recognises the Edge's JSON challenge and leaves the body readable", async () => {
    const r = new Response(challenge, { status: 403, headers: json });
    expect(await isMgChallenge(r)).toBe(true);
    expect(await r.text()).toBe(challenge);
  });

  it("ignores everything else", async () => {
    const blocked = JSON.stringify({ error: "mg_blocked", request_id: "x" });
    expect(await isMgChallenge(new Response(blocked, { status: 403, headers: json }))).toBe(false);
    expect(await isMgChallenge(new Response(challenge, { status: 200, headers: json }))).toBe(false);
    expect(await isMgChallenge(new Response(challenge, { status: 403 }))).toBe(false);
    expect(await isMgChallenge(new Response("<html>", { status: 403, headers: { "content-type": "text/html" } }))).toBe(false);
    expect(
      await isMgChallenge(new Response(challenge, { status: 403, headers: { ...json, "cf-mitigated": "challenge" } })),
    ).toBe(false);
  });
});
