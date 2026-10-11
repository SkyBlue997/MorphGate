/**
 * Quantization helpers for behaviour and environment summaries, and the
 * page behaviour summary of docs/impl/phase2-spec.md §12.8 (off unless the
 * SDK tag carries `data-mg-telemetry="behavior"`, D-48).
 *
 * Everything the SDK reports is coarsened on the client before it leaves the
 * page (docs/04 §7: "端上计算摘要"), so the server only ever sees buckets,
 * never raw trajectories or exact timings. The quantizers are pure and
 * deterministic so the Edge can reproduce the same bucket boundaries.
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

// ---------------------------------------------------------------------------
// Page behaviour summary (§12.8)

export const MAX_HISTOGRAM_COUNT = 65_535;
/** A gap between pointer moves longer than this counts as a pause. */
export const PAUSE_MS = 500;

/** `v = 1` summary: `b` values are `logBucket`s, arrays are counts per bucket. */
export interface BehaviorSummary {
  v: 1;
  ptr: { speed: number[]; curv: number[]; pauses: number };
  keys: { iki: number[] };
  scroll: { dist: number; speed: number[] };
  touch: { area_var: 0 | 1; pressure_var: 0 | 1 };
  focus: number;
  vis: number;
  form: { fill_ms: number; paste: number };
}

/** The event fields the collector reads; nothing else (no targets, key values or coordinates kept). */
export interface BehaviorEvent {
  type: string;
  timeStamp?: number;
  clientX?: number;
  clientY?: number;
  pointerType?: string;
  pressure?: number;
  width?: number;
  height?: number;
  repeat?: boolean;
}

function bump(histogram: number[], value: number): void {
  const bucket = Math.min(histogram.length - 1, logBucket(value));
  histogram[bucket] = Math.min(MAX_HISTOGRAM_COUNT, (histogram[bucket] ?? 0) + 1);
}

/**
 * Accumulates the §12.8 summary from page events. It keeps only running
 * aggregates: the previous pointer sample (to measure the next segment) and
 * counters, never a trajectory, a key value or form content.
 */
export class BehaviorCollector {
  private readonly speed = new Array<number>(16).fill(0);
  private readonly curv = new Array<number>(16).fill(0);
  private readonly iki = new Array<number>(16).fill(0);
  private readonly scrollSpeed = new Array<number>(8).fill(0);
  private pauses = 0;
  private scrollDist = 0;
  private lastScrollY: number | null = null;
  private lastScrollT = 0;
  private lastPtr: { x: number; y: number; t: number; dx: number; dy: number } | null = null;
  private lastKeyT: number | null = null;
  private touchArea: number | null = null;
  private touchPressure: number | null = null;
  private areaVar: 0 | 1 = 0;
  private pressureVar: 0 | 1 = 0;
  private blurs = 0;
  private hides = 0;
  private formFirst: number | null = null;
  private formLast = 0;
  private pastes = 0;

  /** Feed one event. `scrollY` is read by the caller for scroll events. Never throws. */
  observe(event: BehaviorEvent, scrollY?: number): void {
    try {
      const t = event.timeStamp ?? 0;
      switch (event.type) {
        case "pointermove":
          this.pointer(event, t);
          break;
        case "pointerdown":
        case "pointerup":
          if (event.pointerType === "touch") this.touch(event);
          break;
        case "keydown":
          if (!event.repeat) {
            if (this.lastKeyT !== null) bump(this.iki, t - this.lastKeyT);
            this.lastKeyT = t;
          }
          break;
        case "scroll":
          if (typeof scrollY === "number" && Number.isFinite(scrollY)) {
            if (this.lastScrollY !== null) {
              const d = Math.abs(scrollY - this.lastScrollY);
              this.scrollDist += d;
              const dt = t - this.lastScrollT;
              if (dt > 0 && d > 0) bump(this.scrollSpeed, (d * 1000) / dt);
            }
            this.lastScrollY = scrollY;
            this.lastScrollT = t;
          }
          break;
        case "blur":
          this.blurs += 1;
          break;
        case "hidden":
          this.hides += 1;
          break;
        case "input":
          if (this.formFirst === null) this.formFirst = t;
          this.formLast = t;
          break;
        case "paste":
          this.pastes += 1;
          break;
        default:
          break;
      }
    } catch {
      // Collection never affects the page.
    }
  }

  private pointer(event: BehaviorEvent, t: number): void {
    const x = event.clientX;
    const y = event.clientY;
    if (typeof x !== "number" || typeof y !== "number") return;
    if (event.pointerType === "touch") this.touch(event);
    const last = this.lastPtr;
    if (last !== null) {
      const dx = x - last.x;
      const dy = y - last.y;
      const dt = t - last.t;
      if (dt > PAUSE_MS) this.pauses += 1;
      const dist = Math.hypot(dx, dy);
      if (dt > 0 && dist > 0) bump(this.speed, (dist * 1000) / dt);
      if (dist > 0 && (last.dx !== 0 || last.dy !== 0)) {
        const angle = Math.abs(Math.atan2(last.dx * dy - last.dy * dx, last.dx * dx + last.dy * dy));
        bump(this.curv, (angle * 180) / Math.PI);
      }
      this.lastPtr = { x, y, t, dx: dist > 0 ? dx : last.dx, dy: dist > 0 ? dy : last.dy };
    } else {
      this.lastPtr = { x, y, t, dx: 0, dy: 0 };
    }
  }

  private touch(event: BehaviorEvent): void {
    if (typeof event.width === "number" && typeof event.height === "number") {
      const area = event.width * event.height;
      if (this.touchArea !== null && Math.abs(area - this.touchArea) > 0.5) this.areaVar = 1;
      this.touchArea = area;
    }
    if (typeof event.pressure === "number") {
      if (this.touchPressure !== null && Math.abs(event.pressure - this.touchPressure) > 0.01) this.pressureVar = 1;
      this.touchPressure = event.pressure;
    }
  }

  summary(): BehaviorSummary {
    return {
      v: 1,
      ptr: { speed: this.speed.slice(), curv: this.curv.slice(), pauses: logBucket(this.pauses) },
      keys: { iki: this.iki.slice() },
      scroll: { dist: logBucket(this.scrollDist), speed: this.scrollSpeed.slice() },
      touch: { area_var: this.areaVar, pressure_var: this.pressureVar },
      focus: logBucket(this.blurs),
      vis: logBucket(this.hides),
      form: { fill_ms: this.formFirst === null ? 0 : logBucket(this.formLast - this.formFirst), paste: logBucket(this.pastes) },
    };
  }
}
