/**
 * Telemetry payloads and their 2 KB budgets (docs/impl/phase2-spec.md
 * §7.5, §7.6, §9.4, §12.8).
 *
 * - `t` of a `/__mg/c` v2 submission: a JSON object with `env`, `auto`
 *   (the Phase 1 summaries) and `ix` (§7.6), serialized to a string of at
 *   most 2048 UTF-8 bytes. Over budget, `ix.pre`, `ix.page`, `env` and
 *   `auto` are dropped in that order; still over, nothing is submitted.
 * - `/__mg/t` reports (§9.4): at most 8 per request, at most one
 *   `upstream_challenge` and one `cache_hit`.
 *
 * Only quantized summaries leave the page: no raw coordinates, trajectories,
 * key values or cross-site identifiers (docs/09 §10).
 */

import type { AutomationSummary } from "./automation";
import type { EnvSummary } from "./env";

export const TELEMETRY_SCHEMA_VERSION = 1;
export const TELEMETRY_BUDGET_BYTES = 2048;
export const MAX_REPORTS = 8;
export const MAX_REPORT_PATH_BYTES = 512;

export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).byteLength;
}

// ---------------------------------------------------------------------------
// t.ix (§7.6)

export type IxMode = "hold" | "single" | "pow_only" | "external";
export type Modality = "mouse" | "touch" | "pen" | "keyboard" | "mixed" | "none";
export type KeyStoreTag = "idb" | "local" | "memory" | "none";
export type Fallback = "ts_unsupported" | "ts_load_timeout" | "ts_error" | "ts_config";

export interface IxPre {
  moves: number;
  path_px: number;
  straight: number;
  speed_mean: number;
  speed_sd: number;
  dir_changes: number;
  render_to_input_ms: number;
  to_target_ms: number;
}

export interface IxHold {
  ms: number;
  offset: [number, number];
  jitter_px: number;
  moves: number;
  cancels: number;
  pressure: number;
  pressure_var: 0 | 1;
  contact_var: 0 | 1;
}

export interface IxPage {
  vis: number;
  vis_during: number;
  focus: number;
  frame_mean: number;
  frame_sd: number;
}

export interface IxTelemetry {
  v: 1;
  mode: IxMode;
  modality: Modality;
  locale: "zh-CN" | "en";
  ks: KeyStoreTag;
  sv: string;
  fallback: Fallback | null;
  trusted: number;
  act_ms: number;
  pre?: IxPre;
  hold?: IxHold;
  single?: { wait_ms: number };
  page?: IxPage;
  pow?: { ms: number; worker: boolean; impl: "js" | "wasm" };
}

export interface SubmissionTelemetry {
  env?: EnvSummary | null;
  auto?: AutomationSummary | null;
  ix?: IxTelemetry | null;
}

/**
 * Serialize `t` within the budget, dropping `ix.pre`, `ix.page`, `env`,
 * `auto` in that order; null when even that does not fit (§7.6).
 */
export function encodeSubmissionTelemetry(input: SubmissionTelemetry, budget = TELEMETRY_BUDGET_BYTES): string | null {
  const t: { env?: EnvSummary; auto?: AutomationSummary; ix?: IxTelemetry } = {};
  if (input.env) t.env = input.env;
  if (input.auto) t.auto = input.auto;
  if (input.ix) t.ix = { ...input.ix };
  const steps: (() => void)[] = [
    () => undefined,
    () => void (t.ix && delete t.ix.pre),
    () => void (t.ix && delete t.ix.page),
    () => void delete t.env,
    () => void delete t.auto,
  ];
  for (const step of steps) {
    step();
    const text = JSON.stringify(t);
    if (utf8Bytes(text) <= budget) return text;
  }
  return null;
}

// ---------------------------------------------------------------------------
// /__mg/t reports (§9.4)

export type UpstreamChallengeScope = "navigation" | "protected_fetch" | "mg_endpoint";

export type Report =
  | { kind: "upstream_challenge"; scope: UpstreamChallengeScope; path: string; count: number }
  | { kind: "cache_hit"; path: string }
  | { kind: "behavior"; page: string; summary: Record<string, unknown> }
  | { kind: "sw_intercept"; path: string }
  | { kind: "key_unavailable"; reason: "no_idb" | "no_storage" | "no_webcrypto" };

/** A page path for a report: no query or fragment, at most 512 UTF-8 bytes; null otherwise. */
export function reportPath(pathname: string): string | null {
  return pathname.startsWith("/") && !/[?#]/.test(pathname) && utf8Bytes(pathname) <= MAX_REPORT_PATH_BYTES
    ? pathname
    : null;
}

/**
 * Split reports into request bodies that satisfy §9.4: at most 8 reports,
 * at most one `upstream_challenge` (counts of the same scope and path are
 * merged, capped at 100) and one `cache_hit` per body.
 */
export function batchReports(reports: readonly Report[]): Report[][] {
  const merged: Report[] = [];
  for (const report of reports) {
    if (report.kind === "upstream_challenge") {
      const same = merged.find(
        (r): r is Extract<Report, { kind: "upstream_challenge" }> =>
          r.kind === "upstream_challenge" && r.scope === report.scope && r.path === report.path,
      );
      if (same !== undefined) {
        same.count = Math.min(100, same.count + report.count);
        continue;
      }
      merged.push({ ...report, count: Math.max(1, Math.min(100, report.count)) });
    } else {
      merged.push(report);
    }
  }
  const batches: Report[][] = [];
  for (const report of merged) {
    const limited = report.kind === "upstream_challenge" || report.kind === "cache_hit";
    let batch = batches.find(
      (b) => b.length < MAX_REPORTS && !(limited && b.some((r) => r.kind === report.kind)),
    );
    if (batch === undefined) {
      batch = [];
      batches.push(batch);
    }
    batch.push(report);
  }
  return batches;
}

export function encodeReports(reports: readonly Report[]): string {
  return JSON.stringify({ v: 1, reports });
}
