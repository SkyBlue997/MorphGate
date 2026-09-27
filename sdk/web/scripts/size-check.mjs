#!/usr/bin/env node
// Enforce the Web SDK size budget: gzip(dist/mg.js) <= 30 KB (docs/04 §7).
// The SDK is served first-party to visitors on slow cross-border links, so the
// budget is a release gate, not a guideline.
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const BUDGET_BYTES = 30720;
const bundlePath = fileURLToPath(new URL("../dist/mg.js", import.meta.url));

let source;
try {
  source = readFileSync(bundlePath);
} catch (error) {
  console.error(`size-check: cannot read ${bundlePath} (run "pnpm run build" first): ${error.message}`);
  process.exit(1);
}

const gzipBytes = gzipSync(source, { level: 9 }).byteLength;
const percent = ((gzipBytes / BUDGET_BYTES) * 100).toFixed(1);
console.log(`dist/mg.js: ${source.byteLength} bytes raw, ${gzipBytes} bytes gzip (${percent}% of ${BUDGET_BYTES} byte budget)`);

if (gzipBytes > BUDGET_BYTES) {
  console.error(`size-check: FAIL, gzip size exceeds budget by ${gzipBytes - BUDGET_BYTES} bytes`);
  process.exit(1);
}
