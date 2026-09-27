import { describe, expect, it } from "vitest";
import { bucketLowerBound, clamp, logBucket, logHistogram, MAX_LOG_BUCKET, roundToStep } from "../src/behavior";

describe("logBucket", () => {
  it("puts values below 1, negatives and NaN into bucket 0", () => {
    expect(logBucket(0)).toBe(0);
    expect(logBucket(0.999)).toBe(0);
    expect(logBucket(-5)).toBe(0);
    expect(logBucket(Number.NaN)).toBe(0);
  });

  it("uses exact power-of-base boundaries", () => {
    expect([1, 2, 3, 4, 7, 8, 1023, 1024].map((v) => logBucket(v))).toEqual([1, 2, 2, 3, 3, 4, 10, 11]);
    // Math.log(1000) / Math.log(10) is 2.9999999999999996; the loop must not be fooled.
    expect(logBucket(999, 10)).toBe(3);
    expect(logBucket(1000, 10)).toBe(4);
  });

  it("caps at maxBucket, including Infinity", () => {
    expect(logBucket(Number.POSITIVE_INFINITY)).toBe(MAX_LOG_BUCKET);
    expect(logBucket(1e12, 2, 8)).toBe(8);
  });

  it("round-trips with bucketLowerBound", () => {
    for (let bucket = 1; bucket <= 20; bucket++) {
      const lower = bucketLowerBound(bucket);
      expect(logBucket(lower)).toBe(bucket);
      expect(logBucket(lower * 2 - 1)).toBe(bucket);
    }
    expect(bucketLowerBound(0)).toBe(0);
  });

  it("rejects invalid bases", () => {
    expect(() => logBucket(10, 1)).toThrow(RangeError);
    expect(() => logBucket(10, 2.5)).toThrow(RangeError);
    expect(() => logBucket(10, 2, 0)).toThrow(RangeError);
  });
});

describe("roundToStep", () => {
  it("quantizes hold durations to 10 ms", () => {
    expect(roundToStep(1234, 10)).toBe(1230);
    expect(roundToStep(1235, 10)).toBe(1240);
    expect(roundToStep(4, 10)).toBe(0);
  });

  it("removes binary floating-point noise for fractional steps", () => {
    expect(roundToStep(0.3, 0.1)).toBe(0.3);
    expect(roundToStep(0.7, 0.1)).toBe(0.7);
    expect(roundToStep(2.63, 0.25)).toBe(2.75);
    expect(roundToStep(1.1, 0.25)).toBe(1);
    expect(roundToStep(0.0003, 1e-4)).toBe(0.0003);
  });

  it("never returns negative zero", () => {
    expect(Object.is(roundToStep(-0.2, 1), 0)).toBe(true);
  });

  it("passes non-finite values through and rejects bad steps", () => {
    expect(roundToStep(Number.NaN, 10)).toBeNaN();
    expect(roundToStep(Number.POSITIVE_INFINITY, 10)).toBe(Number.POSITIVE_INFINITY);
    expect(() => roundToStep(1, 0)).toThrow(RangeError);
    expect(() => roundToStep(1, -1)).toThrow(RangeError);
    expect(() => roundToStep(1, Number.NaN)).toThrow(RangeError);
  });
});

describe("clamp and logHistogram", () => {
  it("clamps and maps NaN to min", () => {
    expect(clamp(5, 0, 3)).toBe(3);
    expect(clamp(-1, 0, 3)).toBe(0);
    expect(clamp(Number.NaN, 1, 3)).toBe(1);
    expect(() => clamp(1, 3, 0)).toThrow(RangeError);
  });

  it("counts values per log bucket", () => {
    expect(logHistogram([0, 1, 2, 3, 5, 6, 7, 100])).toEqual({ 0: 1, 1: 1, 2: 2, 3: 3, 7: 1 });
    expect(logHistogram([])).toEqual({});
  });
});
