// Non-interactive challenges on template v2 pages (docs/impl/phase2-spec.md §12.1 `challenge`,
// §7.5, §2.1): v2 submissions signed with the session key; v1 on template v1 pages or without WebCrypto.
import { describe, expect, it } from "vitest";
import {
  MAX_SUBMIT_BODY_BYTES,
  encodeSubmissionV2,
  formBodyBytes,
  runChallenge,
  type ChallengeDeps,
  type ChallengePage,
  type FormDom,
} from "../src/challenge";
import type { EnvSummary } from "../src/env";
import { submissionMessage } from "../src/sig";
import { FakeEnv } from "./fakes";
import { es256Verify } from "./proofref";

const C = "AAECAwQ"; // 4 bits: counter 4

class El {
  attrs = new Map<string, string>();
  children: El[] = [];
  submitted = 0;
  setAttribute(n: string, v: string): void {
    this.attrs.set(n, v);
  }
  appendChild(c: El): El {
    this.children.push(c);
    return c;
  }
  submit(): void {
    this.submitted += 1;
  }
}

async function run(page: Partial<ChallengePage>, signer: Exclude<ChallengeDeps["signer"], undefined>): Promise<Record<string, unknown>> {
  const body = new El();
  const dom = { createElement: () => new El(), body } as unknown as FormDom;
  const deps: ChallengeDeps = {
    page: { state: "challenge", c: C, type: "pow", bits: 4, ret: "/account", prefix: "/__mg/", ix: "", ...page },
    view: { setStatus: () => undefined, setPhase: () => undefined, showRetry: () => undefined },
    scriptSrc: "https://example.test/__mg/s/mg.0123456789abcdef.js",
    createWorker: null,
    formDom: dom,
    storage: () => null,
    collect: () => ({ env: { v: 1 } as unknown as EnvSummary, auto: { v: 1, webdriver: false } }),
    webCryptoDigest: null,
    timers: { setTimeout: (f, ms) => globalThis.setTimeout(f, ms), clearTimeout: (h) => globalThis.clearTimeout(h as number) },
    now: () => Date.now(),
    signer,
  };
  const outcome = await runChallenge(deps);
  expect(outcome).toEqual({ kind: "submitted", counter: 4 });
  const form = body.children[0]!;
  expect(form.submitted).toBe(1);
  expect(form.attrs.get("action")).toBe("/__mg/c");
  return JSON.parse(form.children[0]!.attrs.get("value")!);
}

async function signer(): Promise<NonNullable<ChallengeDeps["signer"]>> {
  const fake = new FakeEnv();
  const rt = fake.runtime();
  const key = (await rt.keys.ensure(false))!;
  return async () => ({ subtle: globalThis.crypto.subtle, key });
}

describe("template v2 pages", () => {
  it("send a v2 submission: env / auto inside t, jwk and a valid signature", async () => {
    const body = await run({}, await signer());
    expect(Object.keys(body)).toEqual(["v", "type", "c", "p", "pp", "t", "pow", "ret", "ts", "build", "jwk", "sig"]);
    expect(body).toMatchObject({ v: 2, type: "pow", c: C, p: "", pp: "", pow: { counters: [4] }, ret: "/account", build: "0123456789abcdef" });
    expect(JSON.parse(body["t"] as string)).toEqual({ env: { v: 1 }, auto: { v: 1, webdriver: false } });
    const b = body as { c: string; type: string; p: string; pp: string; t: string; ret: string; ts: number; build: string; jwk: never; sig: string };
    const msg = submissionMessage({ c: b.c, type: b.type, p: b.p, pp: b.pp, t: b.t, counters: [4], ret: b.ret, ts: b.ts, build: b.build });
    expect(await es256Verify(b.jwk, msg, b.sig)).toBe(true);
  });

  it("fall back to v1 without WebCrypto (no signer)", async () => {
    const body = await run({}, async () => null);
    expect(body["v"]).toBe(1);
    expect(body).not.toHaveProperty("jwk");
  });

  it("template v1 pages keep sending v1, even with a key", async () => {
    let asked = false;
    const s = await signer();
    const body = await run({ ix: null }, async () => {
      asked = true;
      return s();
    });
    expect(body["v"]).toBe(1);
    expect(asked).toBe(false);
  });

  it("an interactive page without the control is not solved as a pow page", async () => {
    const deps = {
      page: { state: "challenge", c: C, type: "interactive", bits: 4, ret: "/a", prefix: "/__mg/", ix: "{}" },
      view: { setStatus: () => undefined, setPhase: () => undefined, showRetry: () => undefined },
    } as unknown as ChallengeDeps;
    expect(await runChallenge({ ...deps, webCryptoDigest: null } as ChallengeDeps)).toMatchObject({ kind: "retry" });
  });

  it("encodeSubmissionV2 drops env, then auto, to stay within the 8 KiB form body", async () => {
    const s = await (await signer())();
    // Quotes fit the 2 KB t budget but expand twelvefold in the urlencoded form body.
    const big = { v: 1, pad: '"'.repeat(700) } as unknown as EnvSummary;
    const json = (await encodeSubmissionV2(s!.subtle, s!.key, {
      type: "pow",
      c: C,
      counter: 4,
      ret: "/a",
      ts: 1,
      build: "0".repeat(16),
      env: big,
      auto: { v: 1, webdriver: false },
    }))!;
    expect(formBodyBytes(json)).toBeLessThanOrEqual(MAX_SUBMIT_BODY_BYTES);
    expect(JSON.parse(JSON.parse(json).t)).toEqual({ auto: { v: 1, webdriver: false } });
  });
});
