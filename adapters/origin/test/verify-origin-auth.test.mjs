// The reference origin check against kat.json origin_auth (spec I-38), the
// same vectors the Edge's signer is tested with.
// Run from the repo root: node --test adapters/origin/test/verify-origin-auth.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  MAX_SKEW_S,
  loadOriginKeys,
  originAuthMessage,
  verifyOriginAuth,
} from "../verify-origin-auth.mjs";

const phase1 = new URL("../../../testdata/phase1/", import.meta.url);
const read = (rel) => readFileSync(new URL(rel, phase1), "utf8");
const kat = JSON.parse(read("kat.json")).origin_auth;
const keys = loadOriginKeys(read(kat.key_file));
const rotated = loadOriginKeys(read("keys/origin-keys.rotated.json"));

const input = (c, over = {}) => ({
  value: c.header,
  method: c.method,
  target: c.target,
  header: (name) => c.headers[name],
  keys,
  now: c.t,
  ...over,
});

describe("MG-Origin-Auth reference check", () => {
  it("matches the known answers", () => {
    assert.ok(kat.cases.length >= 2);
    for (const c of kat.cases) {
      const msg = originAuthMessage(String(c.t), c.method, c.target, (n) => c.headers[n]);
      assert.equal(msg.toString("latin1"), c.message);
      assert.equal(verifyOriginAuth(input(c)), true, c.target);
    }
  });

  it("accepts either value of a rotated file", () => {
    const c = kat.cases[0];
    // origin-keys.rotated.json keeps the KAT key as values[1].
    assert.equal(verifyOriginAuth(input(c, { keys: rotated })), true);
    assert.equal(verifyOriginAuth(input(c, { keys: rotated.slice(0, 1) })), false);
  });

  it("rejects stale, altered, forged and malformed values", () => {
    const c = kat.cases[0];
    assert.equal(verifyOriginAuth(input(c, { now: c.t + MAX_SKEW_S })), true);
    assert.equal(verifyOriginAuth(input(c, { now: c.t + MAX_SKEW_S + 1 })), false);
    assert.equal(verifyOriginAuth(input(c, { now: c.t - MAX_SKEW_S - 1 })), false);
    assert.equal(verifyOriginAuth(input(c, { method: "POST" })), false);
    assert.equal(verifyOriginAuth(input(c, { target: "/members/home" })), false);
    const ip = (name) => (name === "mg-client-ip" ? "198.51.100.1" : c.headers[name]);
    assert.equal(verifyOriginAuth(input(c, { header: ip })), false);
    const dropped = (name) => (name === "mg-session" ? undefined : c.headers[name]);
    assert.equal(verifyOriginAuth(input(c, { header: dropped })), false);
    const repeated = (name) => (name === "mg-client-ip" ? ["a", "b"] : c.headers[name]);
    assert.equal(verifyOriginAuth(input(c, { header: repeated })), false);
    assert.equal(verifyOriginAuth(input(c, { keys: [Buffer.alloc(32)] })), false);
    const sig = c.header.split("sig=")[1];
    for (const value of [
      undefined,
      "",
      ["a"],
      c.header.replace("v1;", "v2;"),
      c.header + "=",
      c.header.replace(`t=${c.t}`, `t=+${c.t}`),
      `v1;t=${c.t};sig=${sig.slice(1)}`,
      `v1;t=${c.t};sig=${sig.slice(1)}*`,
    ]) {
      assert.equal(verifyOriginAuth(input(c, { value })), false, String(value));
    }
  });

  it("refuses key files that are not mg-origin-keys", () => {
    assert.throws(() => loadOriginKeys(read("keys/upstream-keys.json")), /mg-origin-keys/);
    assert.throws(
      () => loadOriginKeys('{"v":1,"kind":"mg-origin-keys","values":[]}'),
      /1-2/,
    );
  });
});
