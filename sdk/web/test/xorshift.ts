/**
 * Deterministic xorshift32 generator for the "random input never throws"
 * tests (docs/impl/phase1-spec.md §2.4 item 3): fixed seed, reproducible.
 */
export class XorShift32 {
  private state: number;

  constructor(seed: number) {
    this.state = seed | 0 || 0x9e3779b9;
  }

  next(): number {
    let x = this.state;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x;
    return x >>> 0;
  }

  /** Integer in [0, n). */
  below(n: number): number {
    return this.next() % n;
  }

  bytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = this.next() & 0xff;
    return out;
  }

  /** A string mixing ASCII, HTML/URL metacharacters, controls, CJK and lone surrogates. */
  string(maxLength: number): string {
    const alphabet = ['a', 'Z', '0', '9', '-', '_', '/', '\\', '#', '?', '%', '=', '&', '"', "'", '<', '>', '{', '}', ' ', '\n', '\u0000', '\u007f', '验', '证', '\ud800', '\udfff', '.', ':'];
    const length = this.below(maxLength + 1);
    let out = "";
    for (let i = 0; i < length; i++) {
      out += this.below(4) === 0 ? String.fromCharCode(this.below(0x10000)) : alphabet[this.below(alphabet.length)];
    }
    return out;
  }

  pick<T>(items: readonly T[]): T {
    return items[this.below(items.length)] as T;
  }
}
