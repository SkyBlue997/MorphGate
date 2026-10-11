/**
 * Challenge page client (docs/impl/phase1-spec.md §10.2, §10.3, §11.2, §11.3;
 * docs/impl/phase2-spec.md §12.1, §12.3, §7.5).
 *
 * Template v2 pages (`#mg-challenge` carries `data-mg-ix`) send v2
 * submissions, signed with the session key; an interactive challenge there
 * runs the control of `interactive.ts`. On template v1 pages, or without
 * WebCrypto, the non-interactive flow sends the Phase 1 v1 submission.
 *
 * The Edge answers a navigation that needs a challenge with a 403 page
 * rendered from `templates/challenge.html`. Its `<main id="mg-challenge">`
 * carries the sealed challenge C, its type, the PoW difficulty and the return
 * path as data attributes; this module:
 *
 *   1. self-tests the pure-JS SHA-256 (against a known answer and, when
 *      available, WebCrypto) and refuses to run on a mismatch;
 *   2. solves the PoW in a Worker started from this very script URL, falling
 *      back to 50,000-hash main-thread slices when the Worker cannot be
 *      created, errors, or does not answer within 2 s; gives up after 60 s;
 *   3. collects the env / automation summaries;
 *   4. submits `mg=<JSON>` as a real form navigation to `<prefix>c`, so the
 *      browser follows the Edge's 303 back to `ret` with the new
 *      `__Host-mg_clr` cookie (spec D-11);
 *   5. on a `failed` page with a fresh C, retries automatically at most once
 *      per `ret` (sessionStorage `mg_retry:<ret>`), otherwise shows the retry
 *      link.
 *
 * Nothing here throws into the page: every failure ends in the "verification
 * failed, please retry" status and a visible retry link. The Edge re-checks
 * everything (C, binding, PoW, `ret`), so client-side validation only keeps
 * the page from doing pointless work or linking somewhere odd.
 *
 * Every browser dependency (DOM, Worker, storage, timers, WebCrypto) is
 * injected through `ChallengeDeps`, so the whole flow is unit-tested with
 * fakes; `startChallenge` wires the real ones.
 */

import { collectAutomation, type AutomationSummary } from "./automation";
import { endpointPath, normalizePathPrefix } from "./config";
import { collectEnv, type EnvSummary } from "./env";
import {
  MAIN_THREAD_SLICE,
  MAX_POW_COUNTER,
  PowSolver,
  isValidPowBits,
  parsePowReply,
  powMessage,
  powPrefix,
  verifyPow,
  type PowRequest,
} from "./pow";
import { bytesEqual, sha256, toHex } from "./sha256";
import { langOf } from "./copy";
import { InteractiveControl, parseIx, type ControlElement } from "./interactive";
import { runPowV2, type Pow2Request } from "./powv2";
import type { Runtime } from "./runtime";
import type { TurnstileApi } from "./turnstile";
import { SDK_VERSION } from "./version";
import type { SessionKey } from "./keystore";
import { signedSubmission } from "./submit";
import { encodeSubmissionTelemetry } from "./telemetry";

export const SUBMISSION_VERSION = 1;
/** The Edge's body limit for POST /__mg/c (§10.3); measured on the urlencoded form body. */
export const MAX_SUBMIT_BODY_BYTES = 8192;
/** Sealed challenges are base64url without padding, at most 1024 characters (§6.2). */
export const MAX_SEALED_CHALLENGE_CHARS = 1024;
export const MAX_RET_BYTES = 512;
export const WORKER_ACK_TIMEOUT_MS = 2_000;
export const CHALLENGE_TIMEOUT_MS = 60_000;
/** `build` when the script URL does not carry a content hash (e.g. a dev copy of dist/mg.js). */
export const UNKNOWN_BUILD = "0000000000000000";
export const RETRY_KEY_PREFIX = "mg_retry:";

const SEALED_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]+$/;
const POW_BITS_PATTERN = /^\d{1,2}$/;
const BUILD_FROM_SCRIPT_SRC = /\/mg\.([0-9a-f]{16})\.js(?:[?#]|$)/;

// ---------------------------------------------------------------------------
// Page data

export type ChallengeState = "challenge" | "failed";
export type SubmitType = "invisible" | "pow";
export type PageType = SubmitType | "interactive";

/** The validated contents of `#mg-challenge`'s data attributes. */
export interface ChallengePage {
  /** Anything other than "challenge" is treated as "failed" (bounded retries). */
  state: ChallengeState;
  /** Sealed challenge; null when absent or malformed. */
  c: string | null;
  type: PageType | null;
  bits: number | null;
  /** Template v2: the raw `data-mg-ix` (empty on non-interactive pages); null on template v1. */
  ix: string | null;
  /** Return path; null when it fails the §6.4 checks. */
  ret: string | null;
  /** Endpoint prefix, normalised to a same-origin path ("/__mg/"). */
  prefix: string;
}

export interface AttributeReader {
  getAttribute(name: string): string | null;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export function isSealedChallenge(value: string): boolean {
  return value.length > 0 && value.length <= MAX_SEALED_CHALLENGE_CHARS && SEALED_CHALLENGE_PATTERN.test(value);
}

/**
 * The client-side subset of the §6.4 `ret` rules: starts with "/", not "//",
 * no backslash, control character or "#", at most 512 UTF-8 bytes, and the
 * path is not literally `/__mg` or under `/__mg/`. The Edge's
 * `mg_core::paths::is_reserved` also catches encoded and normalised spellings
 * and stays authoritative; this check only keeps the page from retrying or
 * linking into MorphGate's own endpoints.
 *
 * It must never be stricter than the Edge: a `ret` the Edge accepts but the
 * page rejects is a challenge the visitor can never pass. So the reserved
 * check is case-sensitive, exactly like `is_reserved`'s raw-path rule
 * (`/__MG/c` is an ordinary origin path).
 */
export function isValidRet(ret: string): boolean {
  if (!ret.startsWith("/") || ret.startsWith("//")) return false;
  for (let i = 0; i < ret.length; i++) {
    const code = ret.charCodeAt(i);
    if (code < 0x20 || code === 0x7f || code === 0x5c || code === 0x23) return false;
  }
  const path = ret.split("?", 1)[0] ?? "";
  if (path === "/__mg" || path.startsWith("/__mg/")) return false;
  return utf8Length(ret) <= MAX_RET_BYTES;
}

function parseBits(raw: string | null): number | null {
  if (raw === null || !POW_BITS_PATTERN.test(raw)) return null;
  const bits = Number(raw);
  return isValidPowBits(bits) ? bits : null;
}

/** Read and validate `#mg-challenge`. Never throws. */
export function readChallengePage(root: AttributeReader): ChallengePage {
  const read = (name: string): string | null => {
    try {
      const value = root.getAttribute(name);
      return typeof value === "string" ? value : null;
    } catch {
      return null;
    }
  };
  const c = read("data-mg-c") ?? "";
  const type = read("data-mg-type");
  const ret = read("data-mg-ret");
  return {
    state: read("data-mg-state") === "challenge" ? "challenge" : "failed",
    c: isSealedChallenge(c) ? c : null,
    type: type === "invisible" || type === "pow" || type === "interactive" ? type : null,
    bits: parseBits(read("data-mg-pow-bits")),
    ix: read("data-mg-ix"),
    ret: ret !== null && isValidRet(ret) ? ret : null,
    prefix: normalizePathPrefix(read("data-mg-prefix")),
  };
}

/** The SDK build id is the content hash in the script's own file name, `mg.<hex16>.js`. */
export function buildIdFromScriptSrc(src: string | null): string {
  if (src === null) return UNKNOWN_BUILD;
  return BUILD_FROM_SCRIPT_SRC.exec(src)?.[1] ?? UNKNOWN_BUILD;
}

// ---------------------------------------------------------------------------
// Submission (§10.3)

export interface Submission {
  v: typeof SUBMISSION_VERSION;
  type: SubmitType;
  c: string;
  pow: { counters: [number] };
  ret: string;
  /** Client clock in ms; a feature only. */
  ts: number;
  build: string;
  env?: EnvSummary;
  auto?: AutomationSummary;
}

export interface SubmissionInput {
  type: SubmitType;
  c: string;
  counter: number;
  ret: string;
  ts: number;
  build: string;
  env?: EnvSummary | null;
  auto?: AutomationSummary | null;
}

/** Byte length of the urlencoded body `mg=<json>` the form navigation sends. */
export function formBodyBytes(json: string): number {
  // Same application/x-www-form-urlencoded serializer as form submission; the
  // output is ASCII, so characters are bytes.
  return new URLSearchParams([["mg", json]]).toString().length;
}

/**
 * Serialise the submission with the spec's key order. If the urlencoded body
 * would exceed the Edge's 8 KiB limit, `env` and then `auto` are dropped (both
 * are optional for the Edge); null when even the minimal body does not fit.
 */
export function encodeSubmission(input: SubmissionInput): string | null {
  const submission: Submission = {
    v: SUBMISSION_VERSION,
    type: input.type,
    c: input.c,
    pow: { counters: [input.counter] },
    ret: input.ret,
    ts: Math.floor(input.ts),
    build: input.build,
  };
  if (input.env) submission.env = input.env;
  if (input.auto) submission.auto = input.auto;
  for (const drop of [null, "env", "auto"] as const) {
    if (drop !== null) delete submission[drop];
    const json = JSON.stringify(submission);
    if (formBodyBytes(json) <= MAX_SUBMIT_BODY_BYTES) return json;
  }
  return null;
}

/**
 * The v2 submission of a non-interactive challenge on a template v2 page
 * (phase2-spec §7.5): `env` and `auto` travel inside the `t` string, `jwk`
 * and `sig` bind the clearance to the session key. Over the 8 KiB form
 * limit (or the 2 KB `t` budget), `env` and then `auto` are dropped; null
 * when even that does not fit.
 */
export async function encodeSubmissionV2(subtle: SubtleCrypto, key: SessionKey, input: SubmissionInput): Promise<string | null> {
  const attempts: { env: EnvSummary | null; auto: AutomationSummary | null }[] = [
    { env: input.env ?? null, auto: input.auto ?? null },
    { env: null, auto: input.auto ?? null },
    { env: null, auto: null },
  ];
  for (const { env, auto } of attempts) {
    const t = encodeSubmissionTelemetry({ env, auto });
    if (t === null) continue;
    const body = await signedSubmission(subtle, key, {
      type: input.type,
      c: input.c,
      p: "",
      pp: "",
      t,
      counters: [input.counter],
      ret: input.ret,
      ts: input.ts,
      build: input.build,
    });
    const json = JSON.stringify(body);
    if (formBodyBytes(json) <= MAX_SUBMIT_BODY_BYTES) return json;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Form navigation (§11.3 step 4)

export interface FormFieldLike {
  setAttribute(name: string, value: string): void;
}

export interface FormLike extends FormFieldLike {
  appendChild(child: FormFieldLike): unknown;
  submit(): void;
}

/**
 * The minimal DOM the submission needs. The real `Document` provides it at
 * runtime (see `browserFormDom`); tests pass fakes.
 */
export interface FormDom {
  createElement(tag: "form"): FormLike;
  createElement(tag: "input"): FormFieldLike;
  readonly body: { appendChild(child: FormLike): unknown } | null;
}

/** A hidden POST form to `action` whose only field is `mg` = `json`. */
export function buildSubmitForm(dom: FormDom, action: string, json: string): FormLike {
  const form = dom.createElement("form");
  form.setAttribute("method", "POST");
  form.setAttribute("action", action);
  form.setAttribute("enctype", "application/x-www-form-urlencoded");
  form.setAttribute("accept-charset", "UTF-8");
  form.setAttribute("hidden", "");
  const field = dom.createElement("input");
  field.setAttribute("type", "hidden");
  field.setAttribute("name", "mg");
  field.setAttribute("value", json);
  form.appendChild(field);
  return form;
}

/** Attach the form (browsers only submit connected forms) and navigate. */
export function submitForm(dom: FormDom, action: string, json: string): void {
  const form = buildSubmitForm(dom, action, json);
  const body = dom.body;
  if (body === null) throw new Error("challenge: document has no body");
  body.appendChild(form);
  form.submit();
}

// ---------------------------------------------------------------------------
// View

export type StatusKey = "verifying" | "retrying" | "returning" | "failed" | "timeout";
export type Language = "zh" | "en";

export const MESSAGES: Readonly<Record<Language, Readonly<Record<StatusKey, string>>>> = {
  zh: {
    verifying: "正在验证，请稍候…",
    retrying: "验证未通过，正在重试…",
    returning: "验证完成，正在返回…",
    failed: "验证失败，请重试",
    timeout: "验证时间过长，请重试",
  },
  en: {
    verifying: "Verifying your browser…",
    retrying: "Verification did not pass. Retrying…",
    returning: "Verified. Returning to the page…",
    failed: "Verification failed. Please try again.",
    timeout: "Verification is taking too long. Please try again.",
  },
};

/** The page language the Edge chose (`<html lang>`): zh-* or en. */
export function pickLanguage(lang: string | null | undefined): Language {
  return typeof lang === "string" && lang.trim().toLowerCase().startsWith("zh") ? "zh" : "en";
}

export type Phase = "work" | "retry";

export interface ChallengeView {
  setStatus(key: StatusKey): void;
  /** Mirrored to `data-mg-phase` on `#mg-challenge` (the template's spinner keys on it). */
  setPhase(phase: Phase): void;
  /** Reveal `#mg-retry`, pointing at `href`. */
  showRetry(href: string): void;
}

// ---------------------------------------------------------------------------
// Flow

/** A Worker running this SDK in its PoW mode. */
export interface PowWorkerHandle {
  listen(onMessage: (data: unknown) => void, onError: () => void): void;
  postMessage(message: PowRequest | Pow2Request): void;
  terminate(): void;
}

export interface RetryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export interface Timers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ChallengeDeps {
  page: ChallengePage;
  view: ChallengeView;
  /** This script's URL: the Worker script and the source of the build id. */
  scriptSrc: string | null;
  /** Null when Workers are unavailable. May throw (CSP, SecurityError). */
  createWorker: ((url: string) => PowWorkerHandle) | null;
  formDom: FormDom;
  /** Accessor, because merely reading `sessionStorage` can throw. */
  storage: () => RetryStorage | null;
  collect: () => { env: EnvSummary | null; auto: AutomationSummary | null };
  /** `crypto.subtle.digest("SHA-256", …)`, or null when WebCrypto is unavailable. */
  webCryptoDigest: ((data: Uint8Array<ArrayBuffer>) => Promise<ArrayBuffer>) | null;
  timers: Timers;
  now: () => number;
  /**
   * The session key for a v2 submission (template v2 pages), or null when
   * WebCrypto or a key is unavailable: the page then sends v1.
   */
  signer?: (() => Promise<{ subtle: SubtleCrypto; key: SessionKey } | null>) | null;
}

/** What a PoW search needs from the page. */
export type SolveDeps = Pick<ChallengeDeps, "createWorker" | "scriptSrc" | "timers" | "now">;

export type RetryReason = "no_challenge" | "auto_retry_used" | "self_test" | "timeout" | "error";

export type ChallengeOutcome = { kind: "submitted"; counter: number } | { kind: "retry"; reason: RetryReason };

const ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SELF_TEST_C = "mg-self-test";
/** Above 2^32, so the self-test covers the counter's high word too. */
const SELF_TEST_COUNTER = 0x1_2345_6789;

/**
 * Start-up self-test (§11.4): the generic SHA-256 must reproduce a known
 * answer, the midstate search path must agree with it, and WebCrypto (when
 * present and working) must agree too. A missing or throwing WebCrypto is not
 * a mismatch: there is nothing to compare, and the known answer still holds.
 */
export async function selfTest(webCryptoDigest: ChallengeDeps["webCryptoDigest"]): Promise<boolean> {
  try {
    if (toHex(sha256(new TextEncoder().encode("abc"))) !== ABC_SHA256) return false;
    const prefix = powPrefix(SELF_TEST_C);
    const message = powMessage(prefix, SELF_TEST_COUNTER);
    const reference = sha256(message);
    if (!bytesEqual(new PowSolver(prefix, 0).digest(SELF_TEST_COUNTER), reference)) return false;
    if (webCryptoDigest === null) return true;
    let native: Uint8Array;
    try {
      native = new Uint8Array(await webCryptoDigest(message));
    } catch {
      return true;
    }
    return bytesEqual(native, reference);
  } catch {
    return false;
  }
}

/**
 * Record the one automatic retry for `ret`. False (no auto-retry) when it was
 * already used or storage is unavailable: without a record, "at most once"
 * cannot be guaranteed.
 */
export function claimAutoRetry(storage: () => RetryStorage | null, ret: string): boolean {
  try {
    const store = storage();
    if (store === null || store === undefined) return false;
    const key = RETRY_KEY_PREFIX + ret;
    if (store.getItem(key) !== null) return false;
    store.setItem(key, "1");
    return store.getItem(key) === "1";
  } catch {
    return false;
  }
}

type SolveResult = number | "timeout" | "error";

/**
 * Find the first solving counter: Worker first, main-thread slices as the
 * fallback, `deadline` (ms, `deps.now()` clock) for both. Resolves, never
 * rejects; always stops the Worker and pending slices before resolving.
 */
export function solvePow(deps: SolveDeps, prefix: Uint8Array, bits: number, deadline: number): Promise<SolveResult> {
  let solver: PowSolver;
  try {
    solver = new PowSolver(prefix, bits);
  } catch {
    return Promise.resolve("error");
  }
  return new Promise((resolve) => {
    const { timers } = deps;
    let settled = false;
    let fallbackStarted = false;
    let worker: PowWorkerHandle | null = null;
    let ackTimer: unknown = null;
    let sliceTimer: unknown = null;
    let deadlineTimer: unknown = null;

    const clearAckTimer = (): void => {
      if (ackTimer !== null) timers.clearTimeout(ackTimer);
      ackTimer = null;
    };
    const stopWorker = (): void => {
      clearAckTimer();
      const running = worker;
      worker = null;
      if (running !== null) {
        try {
          running.terminate();
        } catch {
          // Already gone.
        }
      }
    };
    const finish = (result: SolveResult): void => {
      if (settled) return;
      settled = true;
      if (deadlineTimer !== null) timers.clearTimeout(deadlineTimer);
      if (sliceTimer !== null) timers.clearTimeout(sliceTimer);
      stopWorker();
      resolve(result);
    };
    const fallback = (): void => {
      if (settled || fallbackStarted) return;
      fallbackStarted = true;
      stopWorker();
      let next = 0;
      const slice = (): void => {
        sliceTimer = null;
        if (settled) return;
        try {
          const found = solver.search(next, MAIN_THREAD_SLICE);
          if (found >= 0) {
            finish(found);
            return;
          }
          next += MAIN_THREAD_SLICE;
          if (next > MAX_POW_COUNTER) {
            finish("error");
            return;
          }
          sliceTimer = timers.setTimeout(slice, 0);
        } catch {
          finish("error");
        }
      };
      sliceTimer = timers.setTimeout(slice, 0);
    };
    const onWorkerMessage = (data: unknown): void => {
      if (settled || fallbackStarted) return;
      clearAckTimer(); // any reply proves the Worker is alive
      const reply = parsePowReply(data);
      if (reply?.t === "mg-pow-ack") return;
      if (reply?.t === "mg-pow-ok" && verifyPow(prefix, bits, reply.counter)) {
        finish(reply.counter);
        return;
      }
      fallback();
    };

    deadlineTimer = timers.setTimeout(() => finish("timeout"), Math.max(0, deadline - deps.now()));
    if (deps.createWorker === null || deps.scriptSrc === null) {
      fallback();
      return;
    }
    try {
      const handle = deps.createWorker(deps.scriptSrc);
      worker = handle;
      handle.listen(onWorkerMessage, () => {
        if (!settled) fallback();
      });
      ackTimer = timers.setTimeout(() => {
        ackTimer = null;
        fallback();
      }, WORKER_ACK_TIMEOUT_MS);
      handle.postMessage({ t: "mg-pow", prefix, bits });
    } catch {
      fallback();
    }
  });
}

function giveUp(deps: ChallengeDeps, status: StatusKey, reason: RetryReason): ChallengeOutcome {
  try {
    deps.view.setPhase("retry");
    deps.view.setStatus(status);
    deps.view.showRetry(deps.page.ret ?? "/");
  } catch {
    // Nothing more can be shown; the page stays as the Edge rendered it.
  }
  return { kind: "retry", reason };
}

/** Run the challenge described by `deps.page` (§11.3). Never rejects. */
export async function runChallenge(deps: ChallengeDeps): Promise<ChallengeOutcome> {
  try {
    const { page, view } = deps;
    const startedAt = deps.now();
    const { c, type, bits, ret } = page;
    if (c === null || type === null || bits === null || ret === null) {
      return giveUp(deps, "failed", "no_challenge");
    }
    if (page.state === "failed") {
      if (!claimAutoRetry(deps.storage, ret)) return giveUp(deps, "failed", "auto_retry_used");
      view.setStatus("retrying");
    } else {
      view.setStatus("verifying");
    }
    view.setPhase("work");

    if (!(await selfTest(deps.webCryptoDigest))) return giveUp(deps, "failed", "self_test");

    if (type === "interactive") return giveUp(deps, "failed", "no_challenge");
    const result = await solvePow(deps, powPrefix(c), bits, startedAt + CHALLENGE_TIMEOUT_MS);
    if (result === "timeout") return giveUp(deps, "timeout", "timeout");
    if (result === "error") return giveUp(deps, "failed", "error");

    const { env, auto } = deps.collect();
    const build = buildIdFromScriptSrc(deps.scriptSrc);
    const signer = page.ix !== null && deps.signer ? await deps.signer() : null;
    const json =
      signer !== null
        ? await encodeSubmissionV2(signer.subtle, signer.key, { type, c, counter: result, ret, ts: deps.now(), build, env, auto })
        : encodeSubmission({ type, c, counter: result, ret, ts: deps.now(), build, env, auto });
    if (json === null) return giveUp(deps, "failed", "error");
    view.setStatus("returning");
    submitForm(deps.formDom, endpointPath({ pathPrefix: page.prefix }, "c"), json);
    return { kind: "submitted", counter: result };
  } catch {
    return giveUp(deps, "failed", "error");
  }
}

// ---------------------------------------------------------------------------
// Browser wiring

function domView(doc: Document, root: Element): ChallengeView {
  const messages = MESSAGES[pickLanguage(doc.documentElement.getAttribute("lang"))];
  return {
    setStatus(key) {
      const status = doc.getElementById("mg-status");
      if (status !== null) status.textContent = messages[key];
    },
    setPhase(phase) {
      root.setAttribute("data-mg-phase", phase);
    },
    showRetry(href) {
      const retry = doc.getElementById("mg-retry");
      if (retry === null) return;
      retry.setAttribute("href", href);
      retry.removeAttribute("hidden");
    },
  };
}

function browserWorkerFactory(): ChallengeDeps["createWorker"] {
  if (typeof Worker !== "function") return null;
  return (url) => {
    const worker = new Worker(url);
    return {
      listen(onMessage, onError) {
        worker.onmessage = (event) => onMessage(event.data);
        worker.onmessageerror = () => onError();
        worker.onerror = (event) => {
          event.preventDefault();
          onError();
        };
      },
      postMessage: (request) => worker.postMessage(request),
      terminate: () => worker.terminate(),
    };
  };
}

function browserWebCryptoDigest(): ChallengeDeps["webCryptoDigest"] {
  try {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined || typeof subtle.digest !== "function") return null;
    return (data) => subtle.digest("SHA-256", data);
  } catch {
    return null;
  }
}

/**
 * The real `Document` as a `FormDom`. TypeScript's DOM types declare
 * `appendChild<T extends Node>`, which a structural fake cannot satisfy, so the
 * view is narrowed here, at the one place the real document is used.
 */
function browserFormDom(doc: Document): FormDom {
  return doc as unknown as FormDom;
}

/**
 * Run the challenge flow if this page is a challenge page. Idempotent: a
 * second SDK copy on the same page finds `data-mg-phase` already set.
 * Returns null when there is nothing to do.
 */
/** The SDK `<script>`'s CSP nonce (Turnstile's api.js needs it, phase2-spec §8.3). */
function scriptNonce(doc: Document): string | null {
  try {
    const script = doc.querySelector<HTMLScriptElement>("script[nonce][src]");
    return script?.nonce || script?.getAttribute("nonce") || null;
  } catch {
    return null;
  }
}

function browserTimers(): Timers {
  return {
    // Wrapped: calling a detached `setTimeout` with another `this` throws "Illegal invocation".
    setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms),
    clearTimeout: (handle) => globalThis.clearTimeout(handle as number),
  };
}

/** The interactive control on a template v2 page (phase2-spec §12.6). */
function startInteractive(doc: Document, root: Element, page: ChallengePage, rt: Runtime, scriptSrc: string | null): Promise<void> {
  const ix = parseIx(page.ix ?? "");
  const get = (id: string): HTMLElement => {
    const element = doc.getElementById(id);
    if (element === null) throw new Error(`challenge: #${id} missing`);
    return element;
  };
  if (ix === null || page.c === null || page.ret === null) throw new Error("challenge: no interactive challenge");
  const hold = get("mg-hold");
  const timers = browserTimers();
  const sched = (globalThis as { scheduler?: { yield?: () => Promise<void> } }).scheduler;
  const yieldNow = typeof sched?.yield === "function" ? () => sched.yield!() : null;
  const createWorker = browserWorkerFactory();
  const control = new InteractiveControl({
    dom: {
      root: root as unknown as ControlElement,
      ix: get("mg-ix") as unknown as ControlElement,
      hold: hold as unknown as ControlElement,
      holdLabel: (hold.querySelector(".mg-label") ?? hold) as unknown as ControlElement,
      altSingle: get("mg-alt-single") as unknown as ControlElement,
      altPow: get("mg-alt-pow") as unknown as ControlElement,
      progress: get("mg-progress") as unknown as ControlElement,
      turnstile: get("mg-turnstile") as unknown as ControlElement,
      status: get("mg-status") as unknown as ControlElement,
      retry: doc.getElementById("mg-retry") as unknown as ControlElement | null,
      elementFromPoint: (x, y) => doc.elementFromPoint(x, y),
      onWindow: (type, listener) => globalThis.addEventListener(type, listener),
      onDocument: (type, listener) => doc.addEventListener(type, listener as unknown as EventListener, { passive: true }),
      requestFrame: typeof requestAnimationFrame === "function" ? (callback) => requestAnimationFrame(callback) : null,
    },
    rt,
    page: {
      c: page.c,
      ix,
      ret: page.ret,
      rid: root.getAttribute("data-mg-rid") ?? "",
      lang: langOf(doc.documentElement.getAttribute("lang")),
      build: buildIdFromScriptSrc(scriptSrc),
    },
    startPow: (prefix, bits, k, start, listener) =>
      runPowV2(
        {
          createWorker,
          workerUrl: scriptSrc,
          rebuildUrl: `${page.prefix}s/mg.js?sv=${encodeURIComponent(SDK_VERSION)}`,
          sv: SDK_VERSION,
          timers,
          now: () => Date.now(),
          yieldNow,
        },
        prefix,
        bits,
        k,
        start,
        listener,
      ),
    turnstileHost: {
      api: () => {
        const api = (globalThis as { turnstile?: TurnstileApi }).turnstile;
        return api && typeof api.render === "function" ? api : null;
      },
      loadScript: (src, nonce, onLoad, onError) => {
        const script = doc.createElement("script");
        if (nonce !== null) script.nonce = nonce;
        script.async = true;
        script.onload = onLoad;
        script.onerror = onError;
        script.src = src;
        (doc.head ?? doc.body)?.appendChild(script);
      },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
    },
    nonce: scriptNonce(doc),
    collect: () => ({ env: collectEnv(), auto: collectAutomation() }),
    abortController: typeof AbortController === "function" ? () => new AbortController() : null,
  });
  return control.start();
}

/**
 * Run the challenge flow if this is a challenge page. Idempotent: a second
 * SDK copy on the same page finds `data-mg-phase` already set. Returns null
 * when there is nothing to do. `rt` (the page runtime) signs v2
 * submissions and runs the interactive control on template v2 pages.
 */
export function startChallenge(
  doc: Document,
  scriptSrc: string | null,
  rt: Runtime | null = null,
): Promise<ChallengeOutcome | void> | null {
  try {
    const root = doc.getElementById("mg-challenge");
    if (root === null || root.hasAttribute("data-mg-phase")) return null;
    root.setAttribute("data-mg-phase", "start");
    const page = readChallengePage(root);
    if (page.type === "interactive" && page.ix !== null && rt !== null) {
      return startInteractive(doc, root, page, rt, scriptSrc).catch(() => {
        giveUp({ page, view: domView(doc, root) } as ChallengeDeps, "failed", "error");
      });
    }
    return runChallenge({
      page,
      view: domView(doc, root),
      scriptSrc,
      createWorker: browserWorkerFactory(),
      formDom: browserFormDom(doc),
      storage: () => globalThis.sessionStorage,
      collect: () => ({ env: collectEnv(), auto: collectAutomation() }),
      webCryptoDigest: browserWebCryptoDigest(),
      timers: browserTimers(),
      now: () => Date.now(),
      signer:
        rt === null
          ? null
          : async () => {
              const subtle = rt.env.subtle;
              if (subtle === null) return null;
              const key = await rt.keys.ensure(rt.clearanceValid());
              return key === null ? null : { subtle, key };
            },
    });
  } catch {
    // Wiring failed before the flow could take over: at least offer the retry link.
    try {
      doc.getElementById("mg-retry")?.removeAttribute("hidden");
    } catch {
      // Nothing more can be done without throwing into the page.
    }
    return null;
  }
}
