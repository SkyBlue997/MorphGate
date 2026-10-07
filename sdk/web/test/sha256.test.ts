// Pure-JS SHA-256 (docs/impl/phase1-spec.md §11.4, §11.5).
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bytesEqual, leadingZeroBits, sha256, toHex } from "../src/sha256";
import { XorShift32 } from "./xorshift";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

// FIPS 180-2 Appendix B and the NIST CSRC example values for SHA-256.
const NIST_VECTORS: ReadonlyArray<{ name: string; input: Uint8Array; hex: string }> = [
  { name: "empty", input: new Uint8Array(0), hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { name: "abc (one block)", input: utf8("abc"), hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  {
    name: "448-bit message (two blocks)",
    input: utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    hex: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  },
  {
    name: "896-bit message",
    input: utf8(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
    hex: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  },
  {
    name: "one million 'a'",
    input: new Uint8Array(1_000_000).fill(0x61),
    hex: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  },
];

describe("sha256 (§11.5 NIST vectors)", () => {
  for (const vector of NIST_VECTORS) {
    it(vector.name, () => {
      expect(toHex(sha256(vector.input))).toBe(vector.hex);
    });
  }

  it("agrees with Node's SHA-256 across every padding boundary", () => {
    // 55/56 bytes: the length field just fits / spills into a second block; 63-65: block edges.
    const rng = new XorShift32(0x5a17);
    for (let length = 0; length <= 200; length++) {
      const input = rng.bytes(length);
      expect(toHex(sha256(input)), `length ${length}`).toBe(createHash("sha256").update(input).digest("hex"));
    }
  });

  it("does not mutate its input", () => {
    const input = utf8("mg-pow-v1");
    const copy = input.slice();
    sha256(input);
    expect(bytesEqual(input, copy)).toBe(true);
  });
});

describe("leadingZeroBits", () => {
  it("counts across byte boundaries", () => {
    expect(leadingZeroBits(Uint8Array.of(0x80))).toBe(0);
    expect(leadingZeroBits(Uint8Array.of(0x01))).toBe(7);
    expect(leadingZeroBits(Uint8Array.of(0x00, 0x00, 0x1d))).toBe(19);
    expect(leadingZeroBits(Uint8Array.of(0x00, 0x0f))).toBe(12);
    expect(leadingZeroBits(new Uint8Array(4))).toBe(32);
    expect(leadingZeroBits(new Uint8Array(0))).toBe(0);
  });
});

describe("helpers", () => {
  it("toHex is lower-case and zero-padded", () => {
    expect(toHex(Uint8Array.of(0x00, 0x0a, 0xff))).toBe("000aff");
  });

  it("bytesEqual compares length and content", () => {
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).toBe(false);
  });
});
