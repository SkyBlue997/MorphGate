/**
 * Session key storage (docs/impl/phase2-spec.md §12.4, D-45).
 *
 * | Tier     | Where                                                          | `ks`     |
 * |----------|----------------------------------------------------------------|----------|
 * | IndexedDB| database `mg-v1`, store `keys`, key `session`:                 | `idb`    |
 * |          | `{pair: CryptoKeyPair, created_ms}`, private key not extractable |        |
 * | 1        | localStorage `mg_sk_v1`: an extractable key as JWK (all tabs)  | `local`  |
 * | 2        | memory only; the SDK then attaches no `MG-Proof`               | `memory` |
 * | —        | no WebCrypto                                                   | `none`   |
 *
 * Every IndexedDB operation has a 1.5 s timeout; a timeout or `onblocked`
 * makes the tier unavailable for the rest of the page. A key is generated
 * when first needed (the challenge page, or the first request that needs a
 * proof), outside the transaction (WebCrypto is asynchronous, an IndexedDB
 * transaction is not), then stored in one readwrite transaction that first
 * reads the stored key and keeps it when it exists and needs no rotation:
 * readwrite transactions on one store run one at a time, so two tabs end
 * up with the same key. `navigator.locks.request("mg-key")` wraps the whole
 * step when available.
 *
 * Rotation: a key is replaced when it is 7 days old, or when there is no
 * valid clearance (`__Host-mg_st` missing or expired) and the key is at
 * least `ROTATE_MIN_AGE_MS` old. The public key travels with every proof, so
 * an unrotated key would be a long-term identifier across sessions. The
 * minimum age (an addition to §12.4) keeps two challenge pages opened
 * together from replacing each other's fresh key.
 */

import { base64UrlEncode, exportPublicJwk, jwkThumbprint, SESSION_KEY_ALGORITHM, type EcP256PublicJwk } from "./crypto";

export type KeyStoreKind = "idb" | "local" | "memory" | "none";

export const IDB_NAME = "mg-v1";
export const IDB_STORE = "keys";
export const IDB_KEY = "session";
export const LOCAL_KEY = "mg_sk_v1";
export const IDB_TIMEOUT_MS = 1_500;
export const KEY_MAX_AGE_MS = 7 * 86_400_000;
export const ROTATE_MIN_AGE_MS = 600_000;

export interface SessionKey {
  readonly privateKey: CryptoKey;
  readonly jwk: EcP256PublicJwk;
  /** RFC 7638 thumbprint (`cnf.jkt`). */
  readonly jkt: string;
  readonly createdMs: number;
  /** base64url of the MG-Proof protected header, cached per key (§12.5). */
  readonly proofHeader: string;
}

export interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface KeyStoreDeps {
  subtle: SubtleCrypto | null;
  /** Accessors: merely reading `indexedDB` / `localStorage` can throw. */
  indexedDB: () => IDBFactory | null;
  localStorage: () => StorageLike | null;
  locks: LockManagerLike | null;
  setTimeout(callback: () => void, ms: number): unknown;
  now(): number;
}

interface StoredValue {
  pair: CryptoKeyPair;
  created_ms: number;
}

/** True when `key` must be replaced before use. */
export function needsRotation(createdMs: number, nowMs: number, clearanceValid: boolean): boolean {
  const age = nowMs - createdMs;
  if (!(age >= 0) || age >= KEY_MAX_AGE_MS) return true;
  return !clearanceValid && age >= ROTATE_MIN_AGE_MS;
}

/** The MG-Proof protected header (§6.7): exactly alg, typ and the four-member JWK. */
export function proofHeaderB64(jwk: EcP256PublicJwk): string {
  const header = { alg: "ES256", typ: "mg-proof+jwt", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } };
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
}

function isStoredValue(value: unknown): value is StoredValue {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Partial<StoredValue>;
  return (
    typeof v.created_ms === "number" &&
    Number.isFinite(v.created_ms) &&
    typeof v.pair === "object" &&
    v.pair !== null &&
    typeof v.pair.privateKey === "object" &&
    typeof v.pair.publicKey === "object"
  );
}

class Unavailable extends Error {}

export class KeyStore {
  kind: KeyStoreKind = "none";
  private key: SessionKey | null = null;
  private initPromise: Promise<void> | null = null;
  private db: IDBDatabase | null = null;

  constructor(private readonly deps: KeyStoreDeps) {}

  /** Pick the tier and load a stored key. Memoized; never rejects. */
  init(): Promise<void> {
    if (this.initPromise === null) this.initPromise = this.doInit().catch(() => undefined);
    return this.initPromise;
  }

  /** The loaded key, without generating one. */
  current(): SessionKey | null {
    return this.key;
  }

  /**
   * The key to use now, generated or rotated as needed (null for `none`, or
   * when generation fails). `clearanceValid`: `__Host-mg_st` exists and has
   * not expired. Never rejects.
   */
  async ensure(clearanceValid: boolean): Promise<SessionKey | null> {
    try {
      await this.init();
      if (this.kind === "none") return null;
      const now = this.deps.now();
      if (this.key !== null && !needsRotation(this.key.createdMs, now, clearanceValid)) return this.key;
      const locks = this.deps.locks;
      const step = (): Promise<SessionKey | null> => this.generateAndStore(clearanceValid);
      this.key = locks !== null ? await locks.request("mg-key", step) : await step();
      return this.key;
    } catch {
      return null;
    }
  }

  private async doInit(): Promise<void> {
    const subtle = this.deps.subtle;
    if (subtle === null) {
      this.kind = "none";
      return;
    }
    try {
      this.db = await this.openDb();
      this.kind = "idb";
      const stored = await this.idbRequest<unknown>((store) => store.get(IDB_KEY), "readonly");
      if (isStoredValue(stored)) this.key = await this.describe(stored.pair, stored.created_ms);
      return;
    } catch {
      this.db = null;
    }
    const local = this.localStorage();
    if (local !== null) {
      this.kind = "local";
      this.key = await this.readLocal(local);
      return;
    }
    this.kind = "memory";
  }

  private localStorage(): StorageLike | null {
    try {
      const store = this.deps.localStorage();
      if (store === null || store === undefined) return null;
      const probe = `${LOCAL_KEY}_probe`;
      store.setItem(probe, "1");
      const ok = store.getItem(probe) === "1";
      store.removeItem(probe);
      return ok ? store : null;
    } catch {
      return null;
    }
  }

  private withTimeout<T>(executor: (resolve: (v: T) => void, reject: (e: unknown) => void) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let done = false;
      const settle = (f: () => void): void => {
        if (!done) {
          done = true;
          f();
        }
      };
      this.deps.setTimeout(() => settle(() => reject(new Unavailable("timeout"))), IDB_TIMEOUT_MS);
      try {
        executor(
          (v) => settle(() => resolve(v)),
          (e) => settle(() => reject(e)),
        );
      } catch (error) {
        settle(() => reject(error));
      }
    });
  }

  private openDb(): Promise<IDBDatabase> {
    const factory = this.deps.indexedDB();
    if (factory === null || factory === undefined) return Promise.reject(new Unavailable("no indexedDB"));
    return this.withTimeout<IDBDatabase>((resolve, reject) => {
      const request = factory.open(IDB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE);
      };
      request.onblocked = () => reject(new Unavailable("blocked"));
      request.onerror = () => reject(request.error ?? new Unavailable("open"));
      request.onsuccess = () => resolve(request.result);
    });
  }

  /** One request in its own transaction, resolved when the transaction completes. */
  private idbRequest<T>(make: (store: IDBObjectStore) => IDBRequest, mode: IDBTransactionMode): Promise<T> {
    const db = this.db;
    if (db === null) return Promise.reject(new Unavailable("no db"));
    return this.withTimeout<T>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, mode);
      const request = make(tx.objectStore(IDB_STORE));
      tx.oncomplete = () => resolve(request.result as T);
      tx.onerror = () => reject(tx.error ?? request.error ?? new Unavailable("tx"));
      tx.onabort = () => reject(tx.error ?? new Unavailable("abort"));
    });
  }

  private async describe(pair: CryptoKeyPair, createdMs: number): Promise<SessionKey> {
    const subtle = this.deps.subtle!;
    const jwk = await exportPublicJwk(pair.publicKey, subtle);
    return {
      privateKey: pair.privateKey,
      jwk,
      jkt: await jwkThumbprint(jwk, subtle),
      createdMs,
      proofHeader: proofHeaderB64(jwk),
    };
  }

  private async generateAndStore(clearanceValid: boolean): Promise<SessionKey | null> {
    const subtle = this.deps.subtle!;
    if (this.kind === "idb") {
      try {
        const pair = await subtle.generateKey(SESSION_KEY_ALGORITHM, false, ["sign", "verify"]);
        const fresh: StoredValue = { pair, created_ms: this.deps.now() };
        const kept = await this.idbStoreUnlessCurrent(fresh, clearanceValid);
        return await this.describe(kept.pair, kept.created_ms);
      } catch {
        // IndexedDB failed now: continue with localStorage, then memory.
        this.db = null;
        const local = this.localStorage();
        this.kind = local !== null ? "local" : "memory";
      }
    }
    if (this.kind === "local") {
      const local = this.localStorage();
      if (local !== null) {
        try {
          return await this.storeLocal(local, clearanceValid);
        } catch {
          this.kind = "memory";
        }
      } else {
        this.kind = "memory";
      }
    }
    const pair = await subtle.generateKey(SESSION_KEY_ALGORITHM, false, ["sign", "verify"]);
    return this.describe(pair, this.deps.now());
  }

  /**
   * In one readwrite transaction: keep the stored key when it needs no
   * rotation, else store `fresh`. A `ConstraintError` (another writer won)
   * re-reads and uses the stored key.
   */
  private async idbStoreUnlessCurrent(fresh: StoredValue, clearanceValid: boolean): Promise<StoredValue> {
    const db = this.db;
    if (db === null) throw new Unavailable("no db");
    try {
      return await this.withTimeout<StoredValue>((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, "readwrite");
        const store = tx.objectStore(IDB_STORE);
        let result: StoredValue = fresh;
        const get = store.get(IDB_KEY);
        get.onsuccess = () => {
          const stored: unknown = get.result;
          if (isStoredValue(stored) && !needsRotation(stored.created_ms, this.deps.now(), clearanceValid)) {
            result = stored;
            return;
          }
          if (stored !== undefined) store.delete(IDB_KEY);
          store.add(fresh, IDB_KEY);
        };
        tx.oncomplete = () => resolve(result);
        tx.onerror = () => reject(tx.error ?? new Unavailable("tx"));
        tx.onabort = () => reject(tx.error ?? new Unavailable("abort"));
      });
    } catch (error) {
      if ((error as { name?: unknown } | null)?.name !== "ConstraintError") throw error;
      const stored = await this.idbRequest<unknown>((store) => store.get(IDB_KEY), "readonly");
      if (!isStoredValue(stored)) throw error;
      return stored;
    }
  }

  private async readLocal(store: StorageLike): Promise<SessionKey | null> {
    try {
      const raw = store.getItem(LOCAL_KEY);
      if (raw === null) return null;
      const value = JSON.parse(raw) as { v?: unknown; created_ms?: unknown; jwk?: unknown };
      if (value.v !== 1 || typeof value.created_ms !== "number" || typeof value.jwk !== "object" || value.jwk === null) {
        return null;
      }
      const subtle = this.deps.subtle!;
      const jwk = value.jwk as JsonWebKey;
      const privateKey = await subtle.importKey("jwk", jwk, SESSION_KEY_ALGORITHM, false, ["sign"]);
      if (typeof jwk.x !== "string" || typeof jwk.y !== "string") return null;
      const publicJwk: JsonWebKey = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
      const publicKey = await subtle.importKey(
        "jwk",
        publicJwk,
        SESSION_KEY_ALGORITHM,
        true,
        ["verify"],
      );
      return await this.describe({ privateKey, publicKey }, value.created_ms);
    } catch {
      return null;
    }
  }

  /** Generate an extractable key, store it unless a current one is there, re-read what is stored. */
  private async storeLocal(store: StorageLike, clearanceValid: boolean): Promise<SessionKey | null> {
    const existing = await this.readLocal(store);
    const now = this.deps.now();
    if (existing !== null && !needsRotation(existing.createdMs, now, clearanceValid)) return existing;
    const subtle = this.deps.subtle!;
    const pair = await subtle.generateKey(SESSION_KEY_ALGORITHM, true, ["sign", "verify"]);
    const jwk = await subtle.exportKey("jwk", pair.privateKey);
    store.setItem(LOCAL_KEY, JSON.stringify({ v: 1, created_ms: now, jwk }));
    // Another tab may have written in between: use whatever is stored now.
    return (await this.readLocal(store)) ?? (await this.describe(pair, now));
  }
}
