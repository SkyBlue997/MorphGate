/**
 * Silent clearance refresh, `POST /__mg/r` (docs/impl/phase2-spec.md §12.5,
 * §9.3, D-47).
 *
 * Runs when `data-mg-refresh` is `auto` and `__Host-mg_st` shows a
 * key-bound clearance (`b = 1`):
 *
 * - while the page is visible, a timer fires at `iat + 0.8 · (exp − iat)`
 *   server time, but not before `exp − 600 s` and not after `exp − 60 s`;
 *   hidden pages pause, and a page that becomes visible checks at once;
 * - one refresh across tabs: `navigator.locks.request("mg-refresh")`, then
 *   `__Host-mg_st` is read again and an `exp` that changed (another tab
 *   refreshed) ends the attempt;
 * - the request carries `MG-Proof`; a network failure retries after 30 s, at
 *   most 3 times; a page attempts at most once per minute;
 * - `mg_refresh_denied` writes sessionStorage `mg_rd:<exp>` and that `exp` is
 *   never tried again; `mg_blocked` or an upstream challenge stops refresh
 *   and reports for the page.
 */

import type { ClearanceStatus } from "./proof";
import { safeStorage, type Runtime } from "./runtime";
import { classifyFetched, retryAfterOf, UPSTREAM_CHALLENGE } from "./transport";

export const REFRESH_DENIED_PREFIX = "mg_rd:";
export const REFRESH_RETRY_MS = 30_000;
export const REFRESH_MAX_RETRIES = 3;
export const REFRESH_MIN_INTERVAL_MS = 60_000;

/** When to refresh, in server seconds (§12.5). */
export function refreshAtS(status: ClearanceStatus): number {
  const at = status.iat + 0.8 * (status.exp - status.iat);
  return Math.floor(Math.min(status.exp - 60, Math.max(status.exp - 600, at)));
}

export type RefreshResult = "ok" | "denied" | "blocked" | "skipped" | "retry" | "stopped";

export class Refresher {
  private timer: unknown = null;
  private lastAttemptMs = Number.NEGATIVE_INFINITY;
  private failures = 0;
  private stopped = false;
  private running = false;
  private deniedExp: number | null = null;

  constructor(private readonly rt: Runtime) {}

  /** Arm the timer and the visibility listener. */
  start(): void {
    if (!this.rt.config.refresh) return;
    this.rt.env.onVisibility(() => this.schedule());
    this.schedule();
  }

  private clear(): void {
    if (this.timer !== null) this.rt.env.clearTimeout(this.timer);
    this.timer = null;
  }

  private denied(exp: number): boolean {
    if (this.deniedExp === exp) return true;
    try {
      const store = safeStorage(this.rt.env.sessionStorage);
      return store !== null && store.getItem(REFRESH_DENIED_PREFIX + exp) !== null;
    } catch {
      return false;
    }
  }

  /** (Re)arm the timer from the current status cookie. */
  schedule(delayOverrideMs?: number): void {
    this.clear();
    if (this.stopped || this.rt.backgroundStopped || !this.rt.env.visible()) return;
    const status = this.rt.status();
    const nowS = this.rt.clock.serverNowS();
    if (status === null || !status.bound || status.exp <= nowS || this.denied(status.exp)) return;
    let delay = delayOverrideMs ?? refreshAtS(status) * 1000 - this.rt.clock.serverNowMs();
    const sinceLast = this.rt.env.now() - this.lastAttemptMs;
    if (sinceLast < REFRESH_MIN_INTERVAL_MS) delay = Math.max(delay, REFRESH_MIN_INTERVAL_MS - sinceLast);
    this.timer = this.rt.env.setTimeout(() => {
      this.timer = null;
      void this.attempt(status.exp);
    }, Math.max(0, Math.min(delay, 2_147_000_000)));
  }

  /** One refresh attempt for the clearance that expires at `exp`. Never rejects. */
  async attempt(exp: number): Promise<RefreshResult> {
    if (this.running || this.stopped || this.rt.backgroundStopped) return "skipped";
    this.running = true;
    try {
      const locks = this.rt.env.locks;
      const result = locks !== null ? await locks.request("mg-refresh", () => this.refresh(exp)) : await this.refresh(exp);
      if (result === "retry") {
        this.failures += 1;
        if (this.failures <= REFRESH_MAX_RETRIES) this.schedule(REFRESH_RETRY_MS);
      } else {
        this.failures = 0;
        if (result === "ok" || result === "skipped") this.schedule();
      }
      return result;
    } catch {
      return "skipped";
    } finally {
      this.running = false;
    }
  }

  private async refresh(exp: number): Promise<RefreshResult> {
    const rt = this.rt;
    const status = rt.status();
    if (status === null || status.exp !== exp || !status.bound) return "skipped";
    if (status.exp <= rt.clock.serverNowS()) return "skipped";
    this.lastAttemptMs = rt.env.now();
    const url = rt.endpoint("r");
    const proof = await rt.proofFor("POST", url, true);
    if (proof === null) return "stopped";
    let response: Response;
    try {
      response = await rt.env.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "mg-proof": proof },
        body: '{"v":2}',
        credentials: "same-origin",
      });
    } catch {
      return "retry";
    }
    rt.observe(response, url);
    const cls = await classifyFetched(response);
    if (cls.kind === UPSTREAM_CHALLENGE) {
      const path = rt.pagePath();
      if (path !== null) void rt.sendReports([{ kind: "upstream_challenge", scope: "mg_endpoint", path, count: 1 }]);
      rt.backgroundStopped = true;
      return "stopped";
    }
    if (response.status === 200) {
      try {
        const body = (await response.json()) as { ok?: unknown; now_ms?: unknown };
        rt.clock.fromNowMs(body.now_ms);
        return body.ok === true ? "ok" : "skipped";
      } catch {
        return "skipped";
      }
    }
    if (cls.kind === "rate_limited") {
      this.schedule(Math.max(REFRESH_RETRY_MS, retryAfterOf(response) * 1000));
      return "denied";
    }
    if (cls.kind === "mg") {
      if (cls.result.nowMs !== undefined) rt.clock.fromNowMs(cls.result.nowMs);
      if (cls.result.kind === "mg_blocked") {
        rt.backgroundStopped = true;
        return "blocked";
      }
      if (cls.result.kind === "mg_refresh_denied") {
        this.deniedExp = exp;
        try {
          safeStorage(rt.env.sessionStorage)?.setItem(REFRESH_DENIED_PREFIX + exp, "1");
        } catch {
          // `deniedExp` still holds for this page.
        }
        return "denied";
      }
    }
    // 404 (an Edge without the endpoint), 5xx and the rest: stop for this page.
    this.stopped = response.status === 404 || response.status === 405;
    return response.status >= 500 ? "retry" : "denied";
  }
}
