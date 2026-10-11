// Session key storage (docs/impl/phase2-spec.md §12.4, D-45; §12.10 "密钥存储").
import { describe, expect, it } from "vitest";
import {
  IDB_KEY,
  IDB_TIMEOUT_MS,
  KEY_MAX_AGE_MS,
  KeyStore,
  LOCAL_KEY,
  ROTATE_MIN_AGE_MS,
  needsRotation,
  type KeyStoreDeps,
  type StorageLike,
} from "../src/keystore";

const subtle = globalThis.crypto.subtle;

// ---------------------------------------------------------------------------
// A minimal IndexedDB: one database, readwrite transactions run one at a time.

interface FakeRequest {
  result: unknown;
  error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
  onupgradeneeded?: (() => void) | null;
  onblocked?: (() => void) | null;
}

class FakeIdb {
  data = new Map<string, unknown>();
  stores = new Set<string>();
  mode: "ok" | "hang" | "blocked" | "error" = "ok";
  /** The next readwrite `get` misses the stored value (a lost race), so `add` hits ConstraintError. */
  missNextGet = false;
  opens = 0;
  private tail: Promise<void> = Promise.resolve();

  open(): FakeRequest {
    this.opens += 1;
    const req: FakeRequest = { result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null };
    queueMicrotask(() => {
      if (this.mode === "hang") return;
      if (this.mode === "blocked") return req.onblocked?.();
      if (this.mode === "error") {
        req.error = new DOMException("denied", "SecurityError");
        return req.onerror?.();
      }
      req.result = this.db();
      if (!this.stores.has("keys")) req.onupgradeneeded?.();
      req.onsuccess?.();
    });
    return req;
  }

  private db(): unknown {
    return {
      objectStoreNames: { contains: (n: string) => this.stores.has(n) },
      createObjectStore: (n: string) => void this.stores.add(n),
      transaction: (_store: string, mode: string) => this.transaction(mode),
    };
  }

  private transaction(mode: string): unknown {
    let pending = 0;
    let failed = false;
    let release!: () => void;
    const previous = this.tail;
    const done = new Promise<void>((r) => (release = r));
    if (mode === "readwrite") this.tail = previous.then(() => done);
    const ready = mode === "readwrite" ? previous : Promise.resolve();
    const tx = {
      error: null as unknown,
      oncomplete: null as (() => void) | null,
      onerror: null as (() => void) | null,
      onabort: null as (() => void) | null,
      objectStore: () => store,
    };
    const finish = (): void => {
      queueMicrotask(() => {
        if (pending > 0 || failed) return;
        tx.oncomplete?.();
        release();
      });
    };
    const request = (op: () => unknown): FakeRequest => {
      const req: FakeRequest = { result: undefined, error: null, onsuccess: null, onerror: null };
      pending += 1;
      void ready.then(() => {
        if (failed) return;
        try {
          req.result = op();
          req.onsuccess?.();
        } catch (error) {
          failed = true;
          req.error = error;
          tx.error = error;
          req.onerror?.();
          tx.onerror?.();
          release();
          return;
        }
        pending -= 1;
        finish();
      });
      return req;
    };
    const store = {
      get: (k: string) =>
        request(() => {
          if (mode === "readwrite" && this.missNextGet) {
            this.missNextGet = false;
            return undefined;
          }
          return this.data.get(k);
        }),
      put: (v: unknown, k: string) => request(() => void this.data.set(k, v)),
      add: (v: unknown, k: string) =>
        request(() => {
          if (this.data.has(k)) throw new DOMException("exists", "ConstraintError");
          this.data.set(k, v);
        }),
      delete: (k: string) => request(() => void this.data.delete(k)),
    };
    return tx;
  }
}

class FakeTimers {
  private queue: { at: number; f: () => void }[] = [];
  t = 1_790_000_000_000;
  setTimeout = (f: () => void, ms: number): unknown => {
    const e = { at: this.t + ms, f };
    this.queue.push(e);
    return e;
  };
  advance(ms: number): void {
    this.t += ms;
    const due = this.queue.filter((e) => e.at <= this.t);
    this.queue = this.queue.filter((e) => e.at > this.t);
    for (const e of due) e.f();
  }
}

function memoryStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return { map, getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, v), removeItem: (k) => void map.delete(k) };
}

function deps(idb: FakeIdb | null, local: StorageLike | null, timers = new FakeTimers()): KeyStoreDeps & { timers: FakeTimers } {
  return {
    timers,
    subtle,
    indexedDB: () => idb as unknown as IDBFactory | null,
    localStorage: () => local,
    locks: null,
    setTimeout: timers.setTimeout,
    now: () => timers.t,
  };
}

describe("needsRotation (§12.4)", () => {
  it("rotates at 7 days, or without a valid clearance once the key is 10 minutes old", () => {
    const now = 10 * KEY_MAX_AGE_MS;
    expect(needsRotation(now - 1, now, true)).toBe(false);
    expect(needsRotation(now - KEY_MAX_AGE_MS + 1, now, true)).toBe(false);
    expect(needsRotation(now - KEY_MAX_AGE_MS, now, true)).toBe(true);
    expect(needsRotation(now - ROTATE_MIN_AGE_MS + 1, now, false)).toBe(false);
    expect(needsRotation(now - ROTATE_MIN_AGE_MS, now, false)).toBe(true);
    expect(needsRotation(now + 1, now, true)).toBe(true); // created in the future: a broken clock
    expect(needsRotation(Number.NaN, now, true)).toBe(true);
  });
});

describe("KeyStore tiers", () => {
  it("IndexedDB: generates a non-extractable key on first need and finds it again", async () => {
    const idb = new FakeIdb();
    const a = new KeyStore(deps(idb, memoryStorage()));
    await a.init();
    expect(a.kind).toBe("idb");
    expect(a.current()).toBeNull(); // init never generates
    const key = await a.ensure(true);
    expect(key).not.toBeNull();
    expect(key!.privateKey.extractable).toBe(false);
    expect(key!.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = idb.data.get(IDB_KEY) as { created_ms: number };
    expect(stored.created_ms).toBe(key!.createdMs);
    const b = new KeyStore(deps(idb, memoryStorage()));
    await b.init();
    expect(b.current()?.jkt).toBe(key!.jkt);
    expect(await b.ensure(true)).toBe(b.current());
  });

  it("two tabs generating at once end up with the same key", async () => {
    const idb = new FakeIdb();
    const [a, b] = [new KeyStore(deps(idb, null)), new KeyStore(deps(idb, null))];
    const [ka, kb] = await Promise.all([a.ensure(false), b.ensure(false)]);
    expect(ka!.jkt).toBe(kb!.jkt);
  });

  it("ConstraintError: the stored key is re-read and used", async () => {
    const idb = new FakeIdb();
    const first = await new KeyStore(deps(idb, null)).ensure(true);
    idb.missNextGet = true;
    // A second tab's readwrite get misses the key (a race); its add then fails.
    const other = new KeyStore(deps(idb, null));
    const timers = (other as unknown as { deps: { timers: FakeTimers } }).deps.timers;
    timers.t += KEY_MAX_AGE_MS; // even a rotation attempt ends with the stored key
    const key = await other.ensure(true);
    expect(key!.jkt).toBe(first!.jkt);
  });

  it("an IndexedDB that does not answer within 1.5 s falls back to localStorage", async () => {
    const idb = new FakeIdb();
    idb.mode = "hang";
    const local = memoryStorage();
    const d = deps(idb, local);
    const store = new KeyStore(d);
    const init = store.init();
    await Promise.resolve();
    d.timers.advance(IDB_TIMEOUT_MS);
    await init;
    expect(store.kind).toBe("local");
    const key = await store.ensure(true);
    expect(key).not.toBeNull();
    const saved = JSON.parse(local.map.get(LOCAL_KEY)!);
    expect(saved).toMatchObject({ v: 1, created_ms: key!.createdMs });
    expect(saved.jwk.d).toEqual(expect.any(String));
    // Another tab reads the same key from localStorage.
    const again = new KeyStore(deps(null, local));
    await again.init();
    expect(again.kind).toBe("local");
    expect(again.current()?.jkt).toBe(key!.jkt);
  });

  it("onblocked and open errors count as unavailable", async () => {
    for (const mode of ["blocked", "error"] as const) {
      const idb = new FakeIdb();
      idb.mode = mode;
      const store = new KeyStore(deps(idb, memoryStorage()));
      await store.init();
      expect(store.kind).toBe("local");
    }
  });

  it("without any storage the key lives in memory; without WebCrypto there is none", async () => {
    const throwing = {
      getItem(): string | null {
        throw new DOMException("denied", "SecurityError");
      },
      setItem(): void {
        throw new DOMException("denied", "SecurityError");
      },
      removeItem(): void {},
    };
    const mem = new KeyStore(deps(null, throwing));
    await mem.init();
    expect(mem.kind).toBe("memory");
    const key = await mem.ensure(true);
    expect(key).not.toBeNull();
    expect(await mem.ensure(true)).toBe(key);

    const none = new KeyStore({ ...deps(null, null), subtle: null });
    await none.init();
    expect(none.kind).toBe("none");
    expect(await none.ensure(true)).toBeNull();
  });

  it("rotates a 7-day-old key, and an old key when the clearance is gone", async () => {
    const idb = new FakeIdb();
    const d = deps(idb, null);
    const store = new KeyStore(d);
    const k1 = await store.ensure(true);
    d.timers.t += ROTATE_MIN_AGE_MS - 1;
    expect((await store.ensure(false))!.jkt).toBe(k1!.jkt); // too young to rotate
    d.timers.t += 1;
    const k2 = await store.ensure(false);
    expect(k2!.jkt).not.toBe(k1!.jkt);
    expect((idb.data.get(IDB_KEY) as { created_ms: number }).created_ms).toBe(k2!.createdMs);
    d.timers.t += KEY_MAX_AGE_MS;
    const k3 = await store.ensure(true);
    expect(k3!.jkt).not.toBe(k2!.jkt);
  });

  it("a malformed localStorage entry is replaced", async () => {
    const local = memoryStorage();
    local.map.set(LOCAL_KEY, "{not json");
    const store = new KeyStore(deps(null, local));
    await store.init();
    expect(store.current()).toBeNull();
    expect(await store.ensure(true)).not.toBeNull();
    expect(JSON.parse(local.map.get(LOCAL_KEY)!).v).toBe(1);
  });
});
