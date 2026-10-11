/**
 * The SDK's per-page runtime (docs/impl/phase2-spec.md §12.1, §12.4,
 * §12.5, §9.4): configuration, the session key store, the clock, proofs,
 * `onBeforeNavigate`, and the `/__mg/t` reporter with its off-page queue.
 *
 * Every browser dependency comes through `RuntimeEnv`, so the fetch
 * wrapper, refresh and the interactive control are tested with fakes.
 */

import { endpointPath, type MgConfig } from "./config";
import { KeyStore, type KeyStoreKind, type LockManagerLike, type SessionKey, type StorageLike } from "./keystore";
import { buildProof, Clock, parseStatusCookie, proofHtu, statusValid, wireMethod, type ClearanceStatus } from "./proof";
import { batchReports, encodeReports, reportPath, type Report } from "./telemetry";
import { detectUpstreamChallenge } from "./transport";

export const REPORT_QUEUE_KEY = "mg_tq";
export const NAVIGATE_BUDGET_MS = 50;

export interface RuntimeLocation {
  readonly href: string;
  readonly origin: string;
  readonly host: string;
  readonly pathname: string;
  readonly search: string;
  assign(url: string): void;
  replace(url: string): void;
}

export interface RuntimeEnv {
  location: RuntimeLocation;
  /** The page's native fetch. */
  fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  /** `document.cookie`; may throw. */
  cookie: () => string;
  /** Accessors: merely reading them can throw. */
  sessionStorage: () => StorageLike | null;
  localStorage: () => StorageLike | null;
  indexedDB: () => IDBFactory | null;
  subtle: SubtleCrypto | null;
  randomBytes: (n: number) => Uint8Array;
  locks: LockManagerLike | null;
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  now(): number;
  /** `document.visibilityState === "visible"`. */
  visible(): boolean;
  /** Subscribe to `visibilitychange`. */
  onVisibility(callback: () => void): void;
}

/** Wrap a storage accessor so that any throw reads as "no storage". */
export function safeStorage(get: () => StorageLike | null | undefined): StorageLike | null {
  try {
    return get() ?? null;
  } catch {
    return null;
  }
}

export class Runtime {
  readonly keys: KeyStore;
  readonly clock: Clock;
  /** `mg_blocked` or an upstream challenge on a background request stops refresh and reports (§12.5). */
  backgroundStopped = false;
  private readonly navigateCallbacks: (() => void)[] = [];
  private reportsDisabled = false;
  private readonly sentOnce = new Set<string>();

  constructor(
    readonly config: Readonly<MgConfig>,
    readonly env: RuntimeEnv,
    readonly scriptSrc: string | null,
  ) {
    this.keys = new KeyStore({
      subtle: env.subtle,
      indexedDB: env.indexedDB,
      localStorage: () => safeStorage(env.localStorage),
      locks: env.locks,
      setTimeout: (cb, ms) => env.setTimeout(cb, ms),
      now: () => env.now(),
    });
    this.clock = new Clock(
      () => env.now(),
      () => safeStorage(env.sessionStorage),
    );
  }

  get keyStoreKind(): KeyStoreKind {
    return this.keys.kind;
  }

  endpoint(name: Parameters<typeof endpointPath>[1]): string {
    return endpointPath(this.config, name);
  }

  /** `__Host-mg_st`, or null. */
  status(): ClearanceStatus | null {
    try {
      return parseStatusCookie(this.env.cookie());
    } catch {
      return null;
    }
  }

  /** A clearance cookie that has not expired by the estimated server clock. */
  clearanceValid(): boolean {
    return statusValid(this.status(), this.clock.serverNowS());
  }

  /** A key-bound clearance that has not expired: proofs can pass (§12.5 step 1). */
  boundClearance(): boolean {
    const status = this.status();
    return statusValid(status, this.clock.serverNowS()) && status.bound;
  }

  /** Register an `onBeforeNavigate` callback (§12.1). */
  onBeforeNavigate(callback: unknown): void {
    if (typeof callback === "function" && this.navigateCallbacks.length < 32) {
      this.navigateCallbacks.push(callback as () => void);
    }
  }

  /** Run the callbacks synchronously before the SDK leaves the page; stop once 50 ms are spent. */
  beforeNavigate(): void {
    const start = this.env.now();
    for (const callback of this.navigateCallbacks) {
      if (this.env.now() - start > NAVIGATE_BUDGET_MS) break;
      try {
        callback();
      } catch {
        // A site callback must not keep the visitor on the page.
      }
    }
  }

  /**
   * The key for a proof: only a persisted one (IndexedDB or localStorage; a
   * key that lives in memory signs no proofs, §12.4). A lost key (storage
   * cleared) is silently replaced; the proof then fails with `proof.jkt` and
   * the §12.5 recovery binds the clearance to the new key.
   */
  async proofKey(): Promise<SessionKey | null> {
    await this.keys.init();
    if (this.keys.kind !== "idb" && this.keys.kind !== "local") return null;
    return this.keys.ensure(true);
  }

  /**
   * `MG-Proof` for `method` and `url` when §12.5 step 1 allows one: same
   * origin, `data-mg-proof` on, a persisted key, and a key-bound clearance
   * that has not expired. `force` skips the clearance check (the SDK's own
   * endpoints, whose proofs are optional). Never rejects.
   */
  async proofFor(method: string, url: string | URL, force = false): Promise<string | null> {
    try {
      if (!this.config.proof && !force) return null;
      const target = new URL(String(url), this.env.location.href);
      if (target.origin !== this.env.location.origin) return null;
      if (!force && !this.boundClearance()) return null;
      const htu = proofHtu(target);
      const subtle = this.env.subtle;
      if (htu === null || subtle === null) return null;
      const key = await this.proofKey();
      if (key === null) return null;
      return await buildProof(subtle, key, {
        method: wireMethod(method),
        htu,
        iat: this.clock.serverNowS(),
        jti: this.env.randomBytes(16),
      });
    } catch {
      return null;
    }
  }

  /**
   * Bookkeeping on any response the SDK sees: the clock from a same-origin
   * `Date` header (§12.5), and a `cache_hit` report when Cloudflare served
   * one of the Edge's own endpoints from cache (§9.4).
   */
  observe(response: Response, url: string | URL): void {
    try {
      const target = new URL(String(url), this.env.location.href);
      if (target.origin !== this.env.location.origin) return;
      this.clock.fromDateHeader(response.headers.get("date"));
      const prefix = this.config.pathPrefix;
      const path = target.pathname;
      if (path.startsWith(prefix) && !path.startsWith(`${prefix}s/`)) {
        if ((response.headers.get("cf-cache-status") ?? "").trim().toUpperCase() === "HIT") {
          this.reportOnce(`cache_hit`, { kind: "cache_hit", path });
        }
      }
    } catch {
      // Bookkeeping only.
    }
  }

  /** Send `report` at most once per page per `key`. */
  reportOnce(key: string, report: Report): void {
    if (this.sentOnce.has(key)) return;
    this.sentOnce.add(key);
    void this.sendReports([report]);
  }

  /**
   * POST `/__mg/t` (§9.4) with `MG-Proof` when the key and clearance allow
   * (else the Edge counts the report as unsigned). A 404 (an Edge without the
   * endpoint) or a block ends reporting for this page. Never rejects.
   */
  async sendReports(reports: readonly Report[], keepalive = false, presigned?: string | null): Promise<void> {
    if (this.reportsDisabled || this.backgroundStopped || reports.length === 0) return;
    const url = this.endpoint("t");
    for (const batch of batchReports(reports)) {
      try {
        const headers: Record<string, string> = { "content-type": "application/json" };
        // A pre-signed proof keeps the request synchronous for a page that is being hidden (§12.8).
        const proof =
          presigned !== undefined ? presigned : this.boundClearance() ? await this.proofFor("POST", url, true) : null;
        if (proof !== null) headers["mg-proof"] = proof;
        const response = await this.env.fetch(url, {
          method: "POST",
          headers,
          body: encodeReports(batch),
          credentials: "same-origin",
          keepalive,
        });
        this.observe(response, url);
        if (detectUpstreamChallenge(response) !== null) {
          this.backgroundStopped = true;
          return;
        }
        if (response.status === 404 || response.status === 405) {
          this.reportsDisabled = true;
          return;
        }
      } catch {
        return;
      }
    }
  }

  /** Queue `report` in sessionStorage for the next page load (§12.5); false without storage. */
  queueReport(report: Report): boolean {
    const store = safeStorage(this.env.sessionStorage);
    if (store === null) return false;
    try {
      const raw = store.getItem(REPORT_QUEUE_KEY);
      const queue = raw === null ? [] : (JSON.parse(raw) as unknown);
      const list = Array.isArray(queue) ? (queue as Report[]).slice(-7) : [];
      list.push(report);
      store.setItem(REPORT_QUEUE_KEY, JSON.stringify(list));
      return store.getItem(REPORT_QUEUE_KEY) !== null;
    } catch {
      return false;
    }
  }

  /** Send the queued reports with keepalive (page load). */
  flushQueuedReports(): void {
    const store = safeStorage(this.env.sessionStorage);
    if (store === null) return;
    try {
      const raw = store.getItem(REPORT_QUEUE_KEY);
      if (raw === null) return;
      store.removeItem(REPORT_QUEUE_KEY);
      const queue = JSON.parse(raw) as unknown;
      if (!Array.isArray(queue)) return;
      const reports = (queue as unknown[]).filter(
        (r): r is Report => typeof r === "object" && r !== null && typeof (r as Report).kind === "string",
      );
      void this.sendReports(reports.slice(0, 8), true);
    } catch {
      // A malformed queue is dropped.
    }
  }

  /** The page path for reports, or null. */
  pagePath(): string | null {
    return reportPath(this.env.location.pathname);
  }
}
