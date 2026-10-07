// dist/sdk/ assembly (docs/impl/phase1-spec.md §10.4, §11.1, §11.5). Runs in a
// temp directory, so it does not depend on a prior `pnpm run build`.
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SDK_FILE_PATTERN, buildDist, type SdkManifest } from "../scripts/build-dist.mjs";

const TEMPLATE = readFileSync(new URL("../templates/challenge.html", import.meta.url));
const BUNDLE = new TextEncoder().encode('(()=>{"use strict";var mg=1})();\n');
/** The Edge serves only names matching this under /__mg/s/ (§10.4). */
const EDGE_FILE_NAME = /^[A-Za-z0-9._-]{1,64}$/;

const sha256 = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

let dir = "";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mg-sdk-dist-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("buildDist", () => {
  it("writes the bundle, template and a manifest whose hashes match the files", () => {
    const manifest = buildDist({ bundle: BUNDLE, template: TEMPLATE }, dir);
    const build = sha256(BUNDLE).slice(0, 16);

    expect(manifest).toEqual({
      v: 1,
      build,
      sdk: `mg.${build}.js`,
      files: { [`mg.${build}.js`]: sha256(BUNDLE) },
      templates: { "challenge.html": sha256(TEMPLATE) },
    });
    expect(readdirSync(dir).sort()).toEqual(["challenge.html", "manifest.json", `mg.${build}.js`].sort());

    // Files on disk hash to what the manifest says; the SDK copy is byte-identical to dist/mg.js.
    const sdkBytes = readFileSync(join(dir, manifest.sdk));
    expect(sha256(sdkBytes)).toBe(manifest.files[manifest.sdk]);
    expect(new Uint8Array(sdkBytes)).toEqual(BUNDLE);
    expect(sha256(readFileSync(join(dir, "challenge.html")))).toBe(manifest.templates["challenge.html"]);

    // manifest.json on disk is the returned manifest, keys in the spec's order.
    const text = readFileSync(join(dir, "manifest.json"), "utf8");
    expect(text.endsWith("}\n")).toBe(true);
    const onDisk = JSON.parse(text) as SdkManifest;
    expect(onDisk).toEqual(manifest);
    expect(Object.keys(onDisk)).toEqual(["v", "build", "sdk", "files", "templates"]);
  });

  it("names the SDK so the Edge can serve it", () => {
    const manifest = buildDist({ bundle: BUNDLE, template: TEMPLATE }, dir);
    expect(manifest.build).toMatch(/^[0-9a-f]{16}$/);
    expect(manifest.sdk).toMatch(SDK_FILE_PATTERN);
    for (const name of Object.keys(manifest.files)) expect(name).toMatch(EDGE_FILE_NAME);
    // The template is read by the Edge, never served.
    expect(Object.keys(manifest.files)).not.toContain("challenge.html");
  });

  it("is deterministic and follows the bundle's content", () => {
    const first = buildDist({ bundle: BUNDLE, template: TEMPLATE }, dir);
    expect(buildDist({ bundle: BUNDLE, template: TEMPLATE }, dir)).toEqual(first);
    const other = buildDist({ bundle: "(()=>{})();", template: new TextDecoder().decode(TEMPLATE) }, dir);
    expect(other.build).not.toBe(first.build);
    expect(other.build).toBe(sha256(new TextEncoder().encode("(()=>{})();")).slice(0, 16));
  });

  it("removes stale content-hashed builds but leaves other files alone", () => {
    writeFileSync(join(dir, "mg.aaaaaaaaaaaaaaaa.js"), "stale");
    writeFileSync(join(dir, "notes.txt"), "keep");
    const manifest = buildDist({ bundle: BUNDLE, template: TEMPLATE }, dir);
    expect(existsSync(join(dir, "mg.aaaaaaaaaaaaaaaa.js"))).toBe(false);
    expect(existsSync(join(dir, "notes.txt"))).toBe(true);
    expect(readdirSync(dir).filter((name) => SDK_FILE_PATTERN.test(name))).toEqual([manifest.sdk]);
  });

  it("creates a missing output directory", () => {
    const nested = join(dir, "a", "sdk");
    const manifest = buildDist({ bundle: BUNDLE, template: TEMPLATE }, nested);
    expect(existsSync(join(nested, manifest.sdk))).toBe(true);
  });

  it("refuses a template that breaks the contract, writing nothing", () => {
    const bad = new TextDecoder().decode(TEMPLATE).replace('nonce="{{nonce}}"', "");
    expect(() => buildDist({ bundle: BUNDLE, template: bad }, dir)).toThrow(/template contract/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it("refuses an empty bundle", () => {
    expect(() => buildDist({ bundle: new Uint8Array(0), template: TEMPLATE }, dir)).toThrow(/empty/);
    expect(readdirSync(dir)).toEqual([]);
  });
});
