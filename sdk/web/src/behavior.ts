/**
 * Quantization helpers for behaviour and environment summaries.
 *
 * Everything the SDK reports is coarsened on the client before it leaves the
 * page (docs/04 §7: "端上计算摘要"), so the server only ever sees buckets,
 * never raw trajectories or exact timings. These functions are pure and
 * deterministic so the Edge can reproduce the same bucket boundaries.
 *
 * Phase 0 ships the helpers only. Pointer / keyboard / scroll / touch
 * collectors that feed them arrive with the interactive challenge in Phase 2.
 */

/** Upper bound for log buckets; 2^31 ms is ~24 days, far beyond any metric we keep. */
export const MAX_LOG_BUCKET = 31;

/**
 * Logarithmic bucket index of `value` for an integer `base` >= 2.
 *
 * Bucket 0 holds everything below 1 (including negatives and NaN); bucket
 * `b >= 1` holds `base^(b-1) <= value < base^b`. With base 2: 1 -> 1,
 * 2..3 -> 2, 4..7 -> 3, and so on. The loop multiplies instead of calling
 * Math.log so boundaries are exact (Math.log(1000)/Math.log(10) is not 3).
 */
export function logBucket(value: number, base = 2, maxBucket = MAX_LOG_BUCKET): number {
  if (!Number.isInteger(base) || base < 2) {
    throw new RangeError(`logBucket: base must be an integer >= 2, got ${base}`);
  }
  if (!Number.isInteger(maxBucket) || maxBucket < 1) {
    throw new RangeError(`logBucket: maxBucket must be an integer >= 1, got ${maxBucket}`);
  }
  if (Number.isNaN(value) || value < 1) return 0;
  let bucket = 0;
  let threshold = 1;
  while (threshold <= value && bucket < maxBucket) {
    threshold *= base;
    bucket += 1;
  }
  return bucket;
}

/** Smallest value that falls into `bucket` (inverse of {@link logBucket}). */
export function bucketLowerBound(bucket: number, base = 2): number {
  if (!Number.isInteger(bucket) || bucket < 0) {
    throw new RangeError(`bucketLowerBound: bucket must be a non-negative integer, got ${bucket}`);
  }
  return bucket === 0 ? 0 : base ** (bucket - 1);
}

/** Number of decimal digits in a finite step such as 0.25 or 10. */
function decimalsOf(step: number): number {
  const text = String(step);
  const exp = text.indexOf("e-");
  if (exp >= 0) return Number(text.slice(exp + 2));
  const dot = text.indexOf(".");
  return dot < 0 ? 0 : text.length - dot - 1;
}

/**
 * Round `value` to the nearest multiple of `step`; ties follow Math.round
 * (towards +Infinity). The result is cleaned of binary
 * floating-point noise, so roundToStep(0.3, 0.1) is 0.3, not 0.30000000000000004.
 * Non-finite values are returned unchanged so callers can decide how to encode them.
 */
export function roundToStep(value: number, step: number): number {
  if (!Number.isFinite(step) || step <= 0) {
    throw new RangeError(`roundToStep: step must be a positive finite number, got ${step}`);
  }
  if (!Number.isFinite(value)) return value;
  const rounded = Math.round(value / step) * step;
  const cleaned = Number(rounded.toFixed(Math.min(20, decimalsOf(step))));
  // Normalise -0 so JSON output is stable.
  return cleaned === 0 ? 0 : cleaned;
}

/** Clamp `value` into [min, max]; NaN collapses to `min`. */
export function clamp(value: number, min: number, max: number): number {
  if (min > max) throw new RangeError(`clamp: min ${min} > max ${max}`);
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

/**
 * Sparse log-bucket histogram: bucket index -> count. Used for distributions
 * such as "pointer moves before press" where only the shape matters.
 */
export function logHistogram(values: readonly number[], base = 2): Record<number, number> {
  const histogram: Record<number, number> = {};
  for (const value of values) {
    const bucket = logBucket(value, base);
    histogram[bucket] = (histogram[bucket] ?? 0) + 1;
  }
  return histogram;
}
