/**
 * Telemetry payload shape and the 2 KB budget (docs/04 §7, docs/09).
 *
 * Budget: a serialized payload (UTF-8 JSON) must fit in 2048 bytes. The Edge
 * enforces the same limit and rejects larger bodies, so the SDK checks before
 * sending and drops optional sections instead of truncating fields.
 *
 * Phase 0: types, serialization and budget checks. Phase 2: batching,
 * session-key signatures over the payload hash, and POST /__mg/t.
 */

import type { AutomationSummary } from "./automation";
import type { EnvSummary } from "./env";

export const TELEMETRY_SCHEMA_VERSION = 1;
export const TELEMETRY_BUDGET_BYTES = 2048;

export type TelemetryKind = "page" | "challenge" | "upstream_challenge";

/** Where an upstream (Cloudflare) challenge was observed; never a full URL. */
export type UpstreamChallengeScope = "mg_endpoint" | "protected_fetch" | "navigation";

export interface TelemetryPayload {
  v: typeof TELEMETRY_SCHEMA_VERSION;
  kind: TelemetryKind;
  /** Client clock in whole seconds; the server records its own receive time too. */
  ts: number;
  /** SDK build identifier, so the server can decode per-build encodings (Phase 5). */
  build: string;
  env?: EnvSummary;
  automation?: AutomationSummary;
  upstream?: { scope: UpstreamChallengeScope; count: number };
  /** Quantized interaction features (Phase 2); keys are short feature ids. */
  features?: Record<string, number>;
}

export type BudgetCheck =
  | { ok: true; bytes: number }
  | { ok: false; bytes: number; overBy: number };

export function encodePayload(payload: TelemetryPayload): string {
  return JSON.stringify(payload);
}

/** UTF-8 byte length of the serialized payload (not the UTF-16 string length). */
export function payloadBytes(payload: TelemetryPayload): number {
  return new TextEncoder().encode(encodePayload(payload)).byteLength;
}

export function checkBudget(payload: TelemetryPayload, budget = TELEMETRY_BUDGET_BYTES): BudgetCheck {
  const bytes = payloadBytes(payload);
  return bytes <= budget ? { ok: true, bytes } : { ok: false, bytes, overBy: bytes - budget };
}

/**
 * Sections dropped, in order, when a payload is over budget. The core
 * identity of the report (v, kind, ts, build, upstream) is never dropped.
 */
const DROP_ORDER = ["features", "env", "automation"] as const;

/**
 * Return a copy of `payload` that fits the budget by dropping optional
 * sections, or `null` if even the minimal payload is too large (the caller
 * then sends nothing: missing telemetry is treated as "signal missing").
 */
export function fitToBudget(payload: TelemetryPayload, budget = TELEMETRY_BUDGET_BYTES): TelemetryPayload | null {
  const candidate: TelemetryPayload = { ...payload };
  if (checkBudget(candidate, budget).ok) return candidate;
  for (const section of DROP_ORDER) {
    delete candidate[section];
    if (checkBudget(candidate, budget).ok) return candidate;
  }
  return null;
}
