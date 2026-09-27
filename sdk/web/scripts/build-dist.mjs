#!/usr/bin/env node
// Assemble the Edge's SDK directory, dist/sdk/ (docs/impl/phase1-spec.md §11.1):
//
//   mg.<hex16>.js   byte-identical to dist/mg.js; hex16 = first 16 hex chars of its SHA-256
//   challenge.html  the challenge page template (§11.2), validated here
//   manifest.json   {"v":1,"build","sdk","files":{name: sha256},"templates":{"challenge.html": sha256}}
//
// The Edge serves only the `files` names under /__mg/s/ and reads `templates`
// itself; it re-checks the hashes and the template rules when it loads the
// directory. `buildDist` is a pure-input function (in-memory bundle and
// template, output directory) so vitest can exercise it in a temp directory
// without a prior build; running this file as a script builds from
// dist/mg.js and templates/challenge.html (the `build` npm script does this
// right after esbuild).
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const MANIFEST_VERSION = 1;
export const TEMPLATE_NAME = "challenge.html";
export const MANIFEST_NAME = "manifest.json";
export const MAX_TEMPLATE_BYTES = 32 * 1024;
/** Content-hashed SDK file names. */
export const SDK_FILE_PATTERN = /^mg\.[0-9a-f]{16}\.js$/;
/** Exactly these placeholders, each at least once (§11.2). */
export const TEMPLATE_PLACEHOLDERS = Object.freeze([
  "lang",
  "nonce",
  "sdk_src",
  "prefix",
  "c",
  "type",
  "pow_bits",
  "ret",
  "request_id",
  "state",
]);

/** `data-mg-*` attributes of <main id="mg-challenge"> and the placeholder each must hold. */
const MAIN_ATTRIBUTES = Object.freeze({
  "data-mg-state": "{{state}}",
  "data-mg-c": "{{c}}",
  "data-mg-type": "{{type}}",
  "data-mg-pow-bits": "{{pow_bits}}",
  "data-mg-ret": "{{ret}}",
  "data-mg-rid": "{{request_id}}",
  "data-mg-prefix": "{{prefix}}",
});

const TAG_PATTERN = /<([A-Za-z][A-Za-z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
const ATTRIBUTE_PATTERN = /([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
/** ATTRIBUTE_PATTERN with match indices (`d`), to locate quoted values. */
const ATTRIBUTE_SPANS = new RegExp(ATTRIBUTE_PATTERN.source, "gd");
const PLACEHOLDER_PATTERN = /\{\{([^{}]*)\}\}/g;
const COMMENT_PATTERN = /<!--[\s\S]*?(?:-->|$)/g;
/** A <script> or <style> start tag, its raw-text content, and the end tag. */
const RAW_TEXT_PATTERN = /(<(script|style)\b(?:[^>"']|"[^"]*"|'[^']*')*>)([\s\S]*?)(?:<\/\2\s*>|$)/gi;

function toBytes(value) {
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (value instanceof Uint8Array) return value;
  throw new TypeError("expected a string or Uint8Array");
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Tags in document order with their attributes as ordered [name, value] pairs (names lower-cased). */
function parseTags(html) {
  const tags = [];
  for (const match of html.matchAll(TAG_PATTERN)) {
    const attributes = [];
    for (const attr of (match[2] ?? "").matchAll(ATTRIBUTE_PATTERN)) {
      attributes.push([attr[1].toLowerCase(), attr[2] ?? attr[3] ?? attr[4] ?? ""]);
    }
    tags.push({ name: match[1].toLowerCase(), attributes, get: (name) => attributes.find(([n]) => n === name)?.[1] });
  }
  return tags;
}

/**
 * Placeholders outside the contexts where the Edge's substitution is safe.
 * The Edge escapes `& < > " '` and substitutes plain text (§11.2), which makes
 * a value inert only inside a quoted attribute value or ordinary text. In an
 * unquoted attribute value, an attribute or tag name, <script> / <style>
 * content or a comment, a value such as ret = "/a/;alert(1)//" or
 * "/x onmouseover=y" would become script or markup.
 */
function placeholderContextErrors(html) {
  const errors = [];
  const forbidden = []; // [start, end, where]
  for (const m of html.matchAll(COMMENT_PATTERN)) forbidden.push([m.index, m.index + m[0].length, "inside an HTML comment"]);
  for (const m of html.matchAll(RAW_TEXT_PATTERN)) {
    const start = m.index + m[1].length;
    forbidden.push([start, start + m[3].length, `inside <${m[2].toLowerCase()}> content`]);
  }
  const tags = []; // [start, end, name, quoted value spans]
  for (const m of html.matchAll(TAG_PATTERN)) {
    const offset = m.index + 1 + m[1].length;
    const quoted = [];
    for (const attr of (m[2] ?? "").matchAll(ATTRIBUTE_SPANS)) {
      const span = attr.indices[2] ?? attr.indices[3];
      if (span !== undefined) quoted.push([offset + span[0], offset + span[1]]);
    }
    tags.push([m.index, m.index + m[0].length, m[1].toLowerCase(), quoted]);
  }
  const within = (start, end) => ([s, e]) => start >= s && end <= e;
  for (const p of html.matchAll(PLACEHOLDER_PATTERN)) {
    const start = p.index;
    const end = start + p[0].length;
    const region = forbidden.find(within(start, end));
    if (region !== undefined) {
      errors.push(`{{${p[1]}}} ${region[2]}`);
      continue;
    }
    const tag = tags.find(within(start, end));
    if (tag !== undefined) {
      if (!tag[3].some(within(start, end))) errors.push(`{{${p[1]}}} outside a quoted attribute value in <${tag[2]}>`);
    } else if (/<\/?$/.test(html.slice(Math.max(0, start - 2), start))) {
      errors.push(`{{${p[1]}}} as a tag name`);
    }
  }
  return errors;
}

function startsExternal(value) {
  const v = value.trim();
  return v.startsWith("//") || v.startsWith("\\\\") || v.startsWith("/\\") || v.startsWith("\\/");
}

/**
 * Check the template contract (§11.2). Returns the list of violations, empty
 * when the template is valid. The Edge performs the same checks on load.
 */
export function validateTemplate(template) {
  const errors = [];
  const bytes = toBytes(template);
  if (bytes.byteLength > MAX_TEMPLATE_BYTES) errors.push(`larger than ${MAX_TEMPLATE_BYTES} bytes (${bytes.byteLength})`);
  let html;
  try {
    html = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return [...errors, "not valid UTF-8"];
  }

  if (!/^<!doctype html>/i.test(html)) errors.push("must start with <!doctype html>");

  // Placeholders: exactly the known set, each at least once, no stray braces.
  const seen = new Set();
  for (const match of html.matchAll(PLACEHOLDER_PATTERN)) {
    if (TEMPLATE_PLACEHOLDERS.includes(match[1])) seen.add(match[1]);
    else errors.push(`unknown placeholder {{${match[1]}}}`);
  }
  for (const name of TEMPLATE_PLACEHOLDERS) {
    if (!seen.has(name)) errors.push(`placeholder {{${name}}} missing`);
  }
  const rest = html.replace(PLACEHOLDER_PATTERN, "");
  if (rest.includes("{{") || rest.includes("}}")) errors.push("stray {{ or }} outside a placeholder");
  errors.push(...placeholderContextErrors(html));

  // External resources: no absolute or protocol-relative URLs anywhere.
  if (/https?:/i.test(html)) errors.push("contains an http: or https: URL");
  if (/@import/i.test(html)) errors.push("contains a CSS @import");
  if (/url\(\s*["']?\s*(?:\/\/|\\\\|\/\\)/i.test(html)) errors.push("contains a protocol-relative CSS url()");

  const tags = parseTags(html);
  for (const tag of tags) {
    for (const [name, value] of tag.attributes) {
      if (startsExternal(value)) errors.push(`<${tag.name} ${name}> is a protocol-relative URL`);
      // CSP allows only nonce'd <script>/<style>: inline handlers and style attributes would be blocked.
      if (name.startsWith("on")) errors.push(`<${tag.name}> has an inline event handler (${name})`);
      if (name === "style") errors.push(`<${tag.name}> has a style attribute (blocked by the nonce-only CSP)`);
    }
    if ((tag.name === "script" || tag.name === "style") && tag.get("nonce") !== "{{nonce}}") {
      errors.push(`<${tag.name}> without nonce="{{nonce}}"`);
    }
  }

  // Required structure.
  const find = (name, predicate = () => true) => tags.filter((t) => t.name === name && predicate(t));
  if (find("html", (t) => t.get("lang") === "{{lang}}").length !== 1) errors.push('needs <html lang="{{lang}}">');
  if (find("meta", (t) => t.get("charset")?.toLowerCase() === "utf-8").length !== 1) errors.push('needs <meta charset="utf-8">');
  if (find("meta", (t) => t.get("name") === "robots" && t.get("content") === "noindex").length !== 1) {
    errors.push('needs <meta name="robots" content="noindex">');
  }
  if (find("meta", (t) => t.get("name") === "viewport" && t.get("content") === "width=device-width, initial-scale=1").length !== 1) {
    errors.push('needs <meta name="viewport" content="width=device-width, initial-scale=1">');
  }
  const title = /<title>([^<]*)<\/title>/i.exec(html);
  if (title === null || title[1].trim() === "") errors.push("needs a non-empty <title>");
  if (find("style").length === 0) errors.push("needs an inline <style>");

  const main = find("main", (t) => t.get("id") === "mg-challenge");
  if (main.length !== 1) {
    errors.push('needs exactly one <main id="mg-challenge">');
  } else {
    for (const [name, value] of Object.entries(MAIN_ATTRIBUTES)) {
      if (main[0].get(name) !== value) errors.push(`<main id="mg-challenge"> needs ${name}="${value}"`);
    }
  }
  if (find("p", (t) => t.get("id") === "mg-status" && t.get("role") === "status" && t.get("aria-live") === "polite").length !== 1) {
    errors.push('needs <p id="mg-status" role="status" aria-live="polite">');
  }
  if (find("a", (t) => t.get("id") === "mg-retry" && t.get("href") === "{{ret}}" && t.get("hidden") !== undefined).length !== 1) {
    errors.push('needs <a id="mg-retry" href="{{ret}}" hidden>');
  }
  if (find("noscript").length === 0) errors.push("needs a <noscript> message");
  if (!html.replace(/<[^>]*>/g, "").includes("{{request_id}}")) errors.push("{{request_id}} must appear in the page text");

  // The SDK script: nonce'd, Rocket Loader opt-out before src, path prefix.
  const external = find("script", (t) => t.get("src") !== undefined);
  if (external.length !== 1 || external[0].get("src") !== "{{sdk_src}}") {
    errors.push('needs exactly one external <script>, src="{{sdk_src}}"');
  } else {
    const names = external[0].attributes.map(([n]) => n);
    const cfasync = names.indexOf("data-cfasync");
    if (external[0].get("data-cfasync") !== "false" || cfasync < 0 || cfasync > names.indexOf("src")) {
      errors.push('the SDK <script> needs data-cfasync="false" before src');
    }
    if (external[0].get("data-mg-path-prefix") !== "{{prefix}}") errors.push('the SDK <script> needs data-mg-path-prefix="{{prefix}}"');
  }
  return errors;
}

/**
 * Write the SDK directory into `outDir` and return the manifest. Throws when
 * the template violates §11.2 or the bundle is empty. Stale content-hashed
 * builds in `outDir` are removed after the new manifest is written, so the
 * directory holds exactly what the manifest lists.
 */
export function buildDist({ bundle, template }, outDir) {
  const bundleBytes = toBytes(bundle);
  const templateBytes = toBytes(template);
  if (bundleBytes.byteLength === 0) throw new Error("buildDist: empty SDK bundle");
  const errors = validateTemplate(templateBytes);
  if (errors.length > 0) {
    throw new Error(`buildDist: ${TEMPLATE_NAME} violates the template contract (spec §11.2):\n- ${errors.join("\n- ")}`);
  }

  const bundleHash = sha256Hex(bundleBytes);
  const build = bundleHash.slice(0, 16);
  const sdk = `mg.${build}.js`;
  const manifest = {
    v: MANIFEST_VERSION,
    build,
    sdk,
    files: { [sdk]: bundleHash },
    templates: { [TEMPLATE_NAME]: sha256Hex(templateBytes) },
  };

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, sdk), bundleBytes);
  writeFileSync(join(outDir, TEMPLATE_NAME), templateBytes);
  writeFileSync(join(outDir, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const name of readdirSync(outDir)) {
    if (SDK_FILE_PATTERN.test(name) && name !== sdk) rmSync(join(outDir, name));
  }
  return manifest;
}

function main() {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const bundlePath = join(root, "dist", "mg.js");
  let bundle;
  try {
    bundle = readFileSync(bundlePath);
  } catch (error) {
    console.error(`build-dist: cannot read ${bundlePath} (run esbuild first): ${error.message}`);
    process.exit(1);
  }
  const template = readFileSync(join(root, "templates", TEMPLATE_NAME));
  const outDir = join(root, "dist", "sdk");
  rmSync(outDir, { recursive: true, force: true });
  try {
    const manifest = buildDist({ bundle, template }, outDir);
    console.log(`dist/sdk: ${manifest.sdk}, ${TEMPLATE_NAME}, ${MANIFEST_NAME} (build ${manifest.build})`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

/** True when run as `node scripts/build-dist.mjs`, false when imported (vitest). */
function invokedDirectly() {
  try {
    const invoked = process.argv[1];
    return invoked !== undefined && realpathSync(resolve(invoked)) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main();
