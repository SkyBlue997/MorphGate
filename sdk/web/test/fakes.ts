/**
 * Shared fakes for the Phase 2 suites: a deterministic clock with timers, an
 * in-memory Web Storage, and a `RuntimeEnv` whose fetch is scripted per test
 * (docs/impl/phase2-spec.md §12.10: injectable DOM, clock and network).
 */
import { parseConfig, type MgConfig } from "../src/config";
import type { LockManagerLike, StorageLike } from "../src/keystore";
import { Runtime, type RuntimeEnv } from "../src/runtime";

export const ORIGIN = "https://example.test";
export const T0 = 1_790_000_000_000;

export class FakeClock {
  t = T0;
  private queue: { at: number; f: () => void; id: number }[] = [];
  private nextId = 1;
  setTimeout = (f: () => void, ms: number): unknown => {
    const id = this.nextId++;
    this.queue.push({ at: this.t + Math.max(0, ms), f, id });
    return id;
  };
  clearTimeout = (id: unknown): void => {
    this.queue = this.queue.filter((e) => e.id !== id);
  };
  /** Run due timers in order up to `ms` from now; settles promises between timers. */
  async advance(ms: number): Promise<void> {
    const end = this.t + ms;
    for (let guard = 0; guard < 100_000; guard++) {
      await settle();
      this.queue.sort((a, b) => a.at - b.at || a.id - b.id);
      const next = this.queue[0];
      if (next === undefined || next.at > end) break;
      this.queue.shift();
      this.t = Math.max(this.t, next.at);
      next.f();
    }
    this.t = end;
    await settle();
  }
  get pending(): number {
    return this.queue.length;
  }
}

/** Let pending promise callbacks and WebCrypto jobs run (a few real macrotask turns). */
export async function settle(turns = 3): Promise<void> {
  for (let i = 0; i < turns; i++) await new Promise<void>((r) => globalThis.setTimeout(r, 0));
}

/** Wait (in real time, at most `ms`) until `cond()` holds. */
export async function until(cond: () => boolean, ms = 3_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("until: condition not met in time");
    await new Promise<void>((r) => globalThis.setTimeout(r, 1));
  }
}

export function memoryStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, String(v)),
    removeItem: (k) => void map.delete(k),
  };
}

export interface FetchCall {
  url: string;
  method: string;
  headers: Headers;
  body: unknown;
  keepalive: boolean;
}

export type Handler = (call: FetchCall) => Response | Promise<Response>;

export interface FakeEnvOptions {
  cookie?: string;
  session?: StorageLike | null;
  local?: StorageLike | null;
  subtle?: SubtleCrypto | null;
  locks?: LockManagerLike | null;
  path?: string;
  config?: Partial<MgConfig>;
}

export class FakeEnv {
  readonly clock = new FakeClock();
  cookie: string;
  session: StorageLike | null;
  local: StorageLike | null;
  calls: FetchCall[] = [];
  handler: Handler = () => new Response("ok", { status: 200 });
  navigations: string[] = [];
  visibility = true;
  private visibilityListeners: (() => void)[] = [];
  readonly env: RuntimeEnv;
  location: { href: string; origin: string; host: string; pathname: string; search: string; assign(u: string): void; replace(u: string): void };

  constructor(readonly options: FakeEnvOptions = {}) {
    this.cookie = options.cookie ?? "";
    this.session = options.session === undefined ? memoryStorage() : options.session;
    this.local = options.local === undefined ? memoryStorage() : options.local;
    const path = options.path ?? "/page";
    this.location = {
      href: `${ORIGIN}${path}`,
      origin: ORIGIN,
      host: "example.test",
      pathname: path.split("?")[0]!,
      search: path.includes("?") ? `?${path.split("?")[1]}` : "",
      assign: (u) => void this.navigations.push(`assign ${u}`),
      replace: (u) => void this.navigations.push(`replace ${u}`),
    };
    let counter = 0;
    this.env = {
      location: this.location,
      fetch: async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        const call: FetchCall = {
          url: new URL(url, ORIGIN).href,
          method: init?.method ?? (input instanceof Request ? input.method : "GET"),
          headers: new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)),
          body: init?.body,
          keepalive: init?.keepalive === true,
        };
        this.calls.push(call);
        return this.handler(call);
      },
      cookie: () => this.cookie,
      sessionStorage: () => this.session,
      localStorage: () => this.local,
      indexedDB: () => null,
      subtle: options.subtle === undefined ? globalThis.crypto.subtle : options.subtle,
      randomBytes: (n) => Uint8Array.from({ length: n }, () => (counter++ * 37) & 0xff),
      locks: options.locks ?? null,
      setTimeout: this.clock.setTimeout,
      clearTimeout: this.clock.clearTimeout,
      now: () => this.clock.t,
      visible: () => this.visibility,
      onVisibility: (cb) => void this.visibilityListeners.push(cb),
    };
  }

  setVisible(visible: boolean): void {
    this.visibility = visible;
    for (const l of this.visibilityListeners) l();
  }

  runtime(scriptSrc: string | null = `${ORIGIN}/__mg/s/mg.0123456789abcdef.js`): Runtime {
    return new Runtime(Object.freeze({ ...parseConfig({}), ...this.options.config }), this.env, scriptSrc);
  }

  /** A bound, unexpired `__Host-mg_st` relative to the clock. */
  bindClearance(lifetimeS = 1800, bound = true, issuedAgoS = 0): void {
    const iat = Math.floor(this.clock.t / 1000) - issuedAgoS;
    this.cookie = `a=1; __Host-mg_st=${iat}.${iat + lifetimeS}.${bound ? 1 : 0}; b=2`;
  }

  callsTo(path: string): FetchCall[] {
    return this.calls.filter((c) => new URL(c.url).pathname === path);
  }
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

/** A Node Response with `redirected` / `url` set (both are read-only on real responses). */
export function redirectedResponse(response: Response, url: string): Response {
  Object.defineProperty(response, "redirected", { value: true });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

/** `navigator.locks` with one holder per name at a time. */
export function fakeLocks(): LockManagerLike & { names: string[] } {
  const tails = new Map<string, Promise<unknown>>();
  const names: string[] = [];
  return {
    names,
    request<T>(name: string, cb: () => Promise<T>): Promise<T> {
      names.push(name);
      const prev = tails.get(name) ?? Promise.resolve();
      const run = prev.then(cb, cb);
      tails.set(name, run.catch(() => undefined));
      return run;
    },
  };
}
