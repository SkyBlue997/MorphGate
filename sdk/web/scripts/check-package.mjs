#!/usr/bin/env node
// Verify the actual npm archive and an offline consumer installation.
// Packing ignores lifecycle scripts to avoid recursively invoking prepack.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { SDK_FILE_PATTERN, validateTemplate } from "./build-dist.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(root, "dist/sdk/manifest.json"), "utf8"));
assert.equal(manifest.v, 1);
assert.match(manifest.sdk, SDK_FILE_PATTERN);
assert.equal(manifest.sdk, `mg.${manifest.build}.js`);
assert.deepEqual(Object.keys(manifest.files), [manifest.sdk]);
assert.deepEqual(Object.keys(manifest.templates), ["challenge.html"]);
assert.deepEqual(pkg.dependencies ?? {}, {}, "the asset package must have no runtime dependencies");
assert.equal(pkg.license, "Apache-2.0");
assert.equal(pkg.private, undefined);
assert.deepEqual(readFileSync(join(root, "LICENSE")), readFileSync(join(root, "../../LICENSE")));

const assets = ["manifest.json", "challenge.html", manifest.sdk].sort();
assert.deepEqual(readdirSync(join(root, "dist/sdk")).sort(), assets, "unexpected SDK output");
const expectedFiles = ["package.json", "README.md", "LICENSE", "NOTICE", ...assets.map((p) => `dist/sdk/${p}`)].sort();
const temp = mkdtempSync(join(tmpdir(), "morphgate-npm-check-"));

function npm(args, cwd) {
  const result = spawnSync("npm", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, NPM_CONFIG_LOGS_MAX: "0" },
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `npm ${args[0]} failed: ${result.stderr}`);
  return result.stdout;
}

try {
  const [packed] = JSON.parse(npm(["pack", "--ignore-scripts", "--json", "--pack-destination", temp], root));
  assert.equal(packed.name, pkg.name);
  assert.equal(packed.version, pkg.version);
  assert.deepEqual(packed.files.map((f) => f.path).sort(), expectedFiles, "unexpected npm archive contents");
  assert.deepEqual(packed.bundled, [], "do not bundle development dependencies");
  writeFileSync(join(temp, "package.json"), JSON.stringify({ name: "morphgate-asset-consumer", version: "0.0.0", private: true }));
  npm(["install", "--ignore-scripts", "--offline", "--no-audit", "--no-fund", join(temp, packed.filename)], temp);
  const installed = join(temp, "node_modules", pkg.name);
  for (const name of expectedFiles) {
    assert.deepEqual(readFileSync(join(installed, name)), readFileSync(join(root, name)), `installed ${name} differs`);
  }
  for (const [name, hash] of Object.entries({ ...manifest.files, ...manifest.templates })) {
    assert.equal(createHash("sha256").update(readFileSync(join(installed, "dist/sdk", name))).digest("hex"), hash);
  }
  assert.deepEqual(validateTemplate(readFileSync(join(installed, "dist/sdk/challenge.html"))), []);
  console.log(`npm package verified: ${pkg.name}@${pkg.version}; ${expectedFiles.length} files; offline install and asset hashes passed`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
