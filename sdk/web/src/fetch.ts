/**
 * `MorphGate.fetch` (docs/impl/phase2-spec.md §12.5, D-40, D-57, D-58).
 *
 * 1. Same-origin requests get `MG-Proof` when `data-mg-proof` is on, a
 *    persisted session key exists and `__Host-mg_st` shows an unexpired,
 *    key-bound clearance (`Runtime.proofFor`).
 * 2. The native fetch runs. A redirect carries the same proof to its target,
 *    where `htu` no longer matches: a final `mg_proof_required` with
 *    `response.redirected` on a GET / HEAD is re-requested once at
 *    `response.url` with a new proof.
 * 3. Only a 403 / 429 with `MG-Error` or `MG-Challenge` is the Edge's (§11.2):
 *    - `cf-mitigated: challenge`: queue an `upstream_challenge` report for
 *      the next page load and reload the page, once per path per 60 s
 *      (sessionStorage `mg_cfm:<path>`); without storage, report only;
 *    - `mg_challenge` `invisible` / `pow`: solve in place (a v2 build only,
 *      `BUILD_MANIFEST_VERSION = 2`, §2.1): refuse above v1 24 bits or
 *      v2 `k · 2^bits > 2^28`; one solve per page at a time (shared promise),
 *      across tabs through `navigator.locks.request("mg-solve")` with a
 *      re-read of `__Host-mg_st`; Worker PoW; JSON `POST /__mg/c` (v2, or v1
 *      without WebCrypto); then the original request once more when its body
 *      can be replayed. In a v1 build: the verify entry, as in Phase 1;
 *    - `mg_challenge` `interactive`: the verify entry with `min=interactive`;
 *    - `mg_proof_required`: (1) a clock off by more than 5 s against the
 *      answer's `now_ms` is corrected and the request retried once; (2) an
 *      attached `pow` C is solved in place and the request retried; (3) a
 *      key that lives only in memory (or no WebCrypto) returns the answer
 *      and reports `key_unavailable` once; (4) otherwise the verify entry.
 *    - anything else, 429 included, is returned as it is.
 * The response handed back is always a real response: the original, or
 * the retry's.
 */

import type { AutomationSummary } from "./automation";
import { buildIdFromScriptSrc, isValidRet, solvePow, type SolveDeps } from "./challenge";
import type { EnvSummary } from "./env";
import { powPrefix } from "./pow";
import { POW_ALG_V2 } from "./powv2";
import { statusValid, type ClearanceStatus } from "./proof";
import type { Runtime } from "./runtime";
import { safeStorage } from "./runtime";
import { signedSubmission } from "./submit";
import { encodeSubmissionTelemetry } from "./telemetry";
import { classifyFetched, UPSTREAM_CHALLENGE, type PowSpec } from "./transport";
import type { VerifyMin } from "./verify";

export const CF_GUARD_PREFIX = "mg_cfm:";
export const CF_GUARD_MS = 60_000;
/** v1: above this many bits the SDK does not solve in place (§12.5). */
export const MAX_IN_PLACE_BITS_V1 = 24;
/** v2: above k · 2^bits = 2^28 the SDK does not solve in place. */
export const MAX_IN_PLACE_WORK_V2 = 2 ** 28;
export const IN_PLACE_DEADLINE_MS = 60_000;
export const SKEW_RETRY_MS = 5_000;

export interface FetchDeps {
  rt: Runtime;
  /** In-place solving (§12.5) is on only in a manifest v2 build (§2.1). */
  inPlace: boolean;
  solve: SolveDeps;
  collect: () => { env: EnvSummary | null; auto: AutomationSummary | null };
  /** Navigate to the verify entry (guarded, after `onBeforeNavigate`); true when it navigates. */
  verify: (min?: VerifyMin) => boolean;
}

interface InPlaceChallenge {
  type: "invisible" | "pow";
  c: string;
  pow?: PowSpec | undefined;
  ret?: string | undefined;
}

type SolveOutcome = "solved" | "verify" | "failed";

function isRequest(value: unknown): value is Request {
  return typeof Request !== "undefined" && value instanceof Request;
}

/** Too much work for an in-place solve: the verify entry is used instead. */
export function tooHardInPlace(pow: PowSpec | undefined): boolean {
  if (pow === undefined) return true;
  if (pow.alg === POW_ALG_V2) return (pow.k ?? 1) * 2 ** pow.bits > MAX_IN_PLACE_WORK_V2;
  return pow.bits > MAX_IN_PLACE_BITS_V1;
}

/** The body of `init` / `input` can be sent again (§12.5): anything but a stream. */
export function replayableBody(input: RequestInfo | URL, init?: RequestInit): boolean {
  const body = init?.body;
  if (body !== undefined && body !== null) {
    return !(typeof ReadableStream !== "undefined" && body instanceof ReadableStream);
  }
  if (isRequest(input)) return input.body === null;
  return true;
}

export class MgFetch {
  private solving: Promise<SolveOutcome> | null = null;

  constructor(private readonly deps: FetchDeps) {}

  /** `MorphGate.proofHeader(method, url)`: the §12.5 step 1 rules. Never rejects. */
  proofHeader(method: unknown, url: unknown): Promise<string | null> {
    if (typeof method !== "string" || (typeof url !== "string" && !(url instanceof URL))) return Promise.resolve(null);
    return this.deps.rt.proofFor(method, url);
  }

  /** `MorphGate.fetch`. Rejects only where the native fetch would. */
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const { rt } = this.deps;
    let method = "GET";
    let url: URL | null = null;
    try {
      method = init?.method ?? (isRequest(input) ? input.method : "GET");
      url = new URL(isRequest(input) ? input.url : String(input), rt.env.location.href);
    } catch {
      return rt.env.fetch(input, init);
    }
    const sameOrigin = url.origin === rt.env.location.origin;
    const replayable = replayableBody(input, init);
    const upper = method.toUpperCase();
    const safeMethod = upper === "GET" || upper === "HEAD";

    let sent = await this.send(input, init, method, url, sameOrigin);
    let solved = false;
    let skewRetried = false;
    let redirectRetried = false;
    for (let round = 0; round < 4; round++) {
      const { response, proof } = sent;
      let cls;
      try {
        cls = await classifyFetched(response);
      } catch {
        return response;
      }
      if (cls.kind === UPSTREAM_CHALLENGE) {
        if (sameOrigin) this.upstreamChallenge();
        return response;
      }
      if (cls.kind !== "mg" || !sameOrigin) return response;
      const r = cls.result;
      const clockError = r.nowMs !== undefined ? rt.clock.fromNowMs(r.nowMs) : 0;
      if (r.kind === "mg_challenge") {
        if (r.type === "interactive") {
          this.deps.verify("interactive");
          return response;
        }
        if ((r.type === "invisible" || r.type === "pow") && this.deps.inPlace && !solved) {
          const outcome = await this.solveShared({ type: r.type, c: r.challenge, pow: r.pow, ret: r.ret });
          if (outcome === "verify") {
            this.deps.verify();
            return response;
          }
          if (outcome === "failed" || !replayable) return response;
          solved = true;
          sent = await this.send(input, init, method, url, sameOrigin);
          continue;
        }
        this.deps.verify();
        return response;
      }
      if (r.kind !== "mg_proof_required") return response;
      if (response.redirected && safeMethod && !redirectRetried) {
        redirectRetried = true;
        try {
          const target = new URL(response.url);
          if (target.origin === rt.env.location.origin) {
            const { body: _body, ...rest } = init ?? {};
            sent = await this.send(target.href, { ...rest, method }, method, target, true, isRequest(input) ? input.headers : undefined);
            continue;
          }
        } catch {
          return response;
        }
      }
      if (proof && Math.abs(clockError) > SKEW_RETRY_MS && !skewRetried && replayable) {
        skewRetried = true;
        sent = await this.send(input, init, method, url, sameOrigin);
        continue;
      }
      if (r.challenge !== undefined && this.deps.inPlace && !solved) {
        const outcome = await this.solveShared({ type: "pow", c: r.challenge, pow: r.pow, ret: r.ret });
        if (outcome === "solved" && replayable) {
          solved = true;
          sent = await this.send(input, init, method, url, sameOrigin);
          continue;
        }
        if (outcome === "failed") return response;
      }
      await rt.keys.init();
      const kind = rt.keys.kind;
      if (kind === "memory" || kind === "none") {
        rt.reportOnce("key_unavailable", {
          kind: "key_unavailable",
          reason: kind === "memory" ? "no_storage" : "no_webcrypto",
        });
        return response;
      }
      this.deps.verify();
      return response;
    }
    return sent.response;
  }

  /** The native fetch with a fresh proof when one applies. */
  private async send(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    method: string,
    url: URL,
    sameOrigin: boolean,
    baseHeaders?: Headers,
  ): Promise<{ response: Response; proof: boolean }> {
    const { rt } = this.deps;
    const proof = sameOrigin ? await rt.proofFor(method, url) : null;
    let finalInit = init;
    if (proof !== null) {
      const headers = new Headers(init?.headers ?? baseHeaders ?? (isRequest(input) ? input.headers : undefined));
      headers.set("MG-Proof", proof);
      finalInit = { ...init, headers };
    }
    const response = await rt.env.fetch(input, finalInit);
    if (sameOrigin) rt.observe(response, url);
    return { response, proof: proof !== null };
  }

  /**
   * `cf-mitigated: challenge` on a site request: queue the report for the
   * next page load, then reload once per path per minute; without
   * sessionStorage, report now and stay.
   */
  private upstreamChallenge(): void {
    const { rt } = this.deps;
    const path = rt.pagePath();
    if (path === null) return;
    const report = { kind: "upstream_challenge" as const, scope: "protected_fetch" as const, path, count: 1 };
    const store = safeStorage(rt.env.sessionStorage);
    let guarded = true;
    if (store !== null) {
      try {
        const key = CF_GUARD_PREFIX + path;
        const now = rt.env.now();
        const last = Number(store.getItem(key) ?? Number.NaN);
        if (!(Number.isFinite(last) && last <= now && now - last < CF_GUARD_MS)) {
          store.setItem(key, String(now));
          guarded = store.getItem(key) !== String(now);
        }
      } catch {
        guarded = true;
      }
    }
    if (guarded || !rt.queueReport(report)) {
      void rt.sendReports([report]);
      return;
    }
    rt.beforeNavigate();
    try {
      rt.env.location.assign(rt.env.location.href);
    } catch {
      // Stay on the page.
    }
  }

  /** One in-place solve per page at a time; concurrent callers share it. */
  private solveShared(challenge: InPlaceChallenge): Promise<SolveOutcome> {
    if (this.solving !== null) return this.solving;
    const statusAtChallenge = this.deps.rt.status();
    const run = async (): Promise<SolveOutcome> => {
      const locks = this.deps.rt.env.locks;
      if (locks === null) return this.solveInPlace(challenge, statusAtChallenge);
      return locks.request("mg-solve", () => this.solveInPlace(challenge, statusAtChallenge));
    };
    const promise = run()
      .catch((): SolveOutcome => "failed")
      .finally(() => {
        if (this.solving === promise) this.solving = null;
      });
    this.solving = promise;
    return promise;
  }

  private async solveInPlace(challenge: InPlaceChallenge, before: ClearanceStatus | null): Promise<SolveOutcome> {
    const { rt } = this.deps;
    // Another tab may have earned a clearance while this one waited for the lock.
    const now = rt.status();
    if (statusValid(now, rt.clock.serverNowS()) && (before === null || now.iat > before.iat)) return "solved";
    if (tooHardInPlace(challenge.pow) || challenge.pow?.alg === POW_ALG_V2) return "verify";
    const ret = challenge.ret;
    if (ret === undefined || !isValidRet(ret)) return "verify";
    const bits = challenge.pow!.bits;
    const startedAt = this.deps.solve.now();
    const counter = await solvePow(this.deps.solve, powPrefix(challenge.c), bits, startedAt + IN_PLACE_DEADLINE_MS);
    if (typeof counter !== "number") return "failed";
    const { env, auto } = this.deps.collect();
    const build = buildIdFromScriptSrc(rt.scriptSrc);
    const subtle = rt.env.subtle;
    const key = subtle === null ? null : await rt.keys.ensure(rt.clearanceValid());
    let body: string;
    if (subtle !== null && key !== null) {
      const t = encodeSubmissionTelemetry({ env, auto }) ?? "";
      const submission = await signedSubmission(subtle, key, {
        type: challenge.type,
        c: challenge.c,
        p: "",
        pp: "",
        t,
        counters: [counter],
        ret,
        ts: rt.env.now(),
        build,
      });
      body = JSON.stringify(submission);
    } else {
      body = JSON.stringify({ v: 1, type: challenge.type, c: challenge.c, pow: { counters: [counter] }, ret, ts: Math.floor(rt.env.now()), build, ...(env ? { env } : {}), ...(auto ? { auto } : {}) });
    }
    const url = rt.endpoint("c");
    const response = await rt.env.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      credentials: "same-origin",
    });
    rt.observe(response, url);
    if (response.status !== 200) return "failed";
    try {
      const answer = (await response.clone().json()) as { ok?: unknown; now_ms?: unknown };
      rt.clock.fromNowMs(answer.now_ms);
      return answer.ok === true ? "solved" : "failed";
    } catch {
      return "failed";
    }
  }
}
