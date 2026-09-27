// Challenge page template contract (docs/impl/phase1-spec.md §10.2, §11.2, §11.5).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MAX_TEMPLATE_BYTES, TEMPLATE_PLACEHOLDERS, validateTemplate } from "../scripts/build-dist.mjs";
import { XorShift32 } from "./xorshift";

const TEMPLATE_BYTES = readFileSync(new URL("../templates/challenge.html", import.meta.url));
const TEMPLATE = new TextDecoder("utf-8", { fatal: true }).decode(TEMPLATE_BYTES);

const SPEC_PLACEHOLDERS = ["lang", "nonce", "sdk_src", "prefix", "c", "type", "pow_bits", "ret", "request_id", "state"];

/** Every start tag of `name`, as raw text. */
function tags(html: string, name: string): string[] {
  return [...html.matchAll(new RegExp(`<${name}\\b(?:[^>"']|"[^"]*"|'[^']*')*>`, "gi"))].map((m) => m[0]);
}

/** What the Edge does (§11.2): HTML-attribute escaping, then plain text substitution. */
function render(template: string, values: Record<string, string>): string {
  const escape = (value: string): string =>
    value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  return template.replace(/\{\{([a-z_]+)\}\}/g, (_, name: string) => escape(values[name] ?? ""));
}

describe("templates/challenge.html (§11.2)", () => {
  it("passes the build's validator", () => {
    expect(validateTemplate(TEMPLATE_BYTES)).toEqual([]);
  });

  it("is UTF-8 and at most 32 KiB", () => {
    expect(TEMPLATE_BYTES.byteLength).toBeLessThanOrEqual(32 * 1024);
    expect(MAX_TEMPLATE_BYTES).toBe(32 * 1024);
  });

  it("uses exactly the ten placeholders, each at least once", () => {
    expect([...TEMPLATE_PLACEHOLDERS].sort()).toEqual([...SPEC_PLACEHOLDERS].sort());
    const used = new Set([...TEMPLATE.matchAll(/\{\{([^{}]*)\}\}/g)].map((m) => m[1]));
    expect([...used].sort()).toEqual([...SPEC_PLACEHOLDERS].sort());
    expect(TEMPLATE.replace(/\{\{[a-z_]+\}\}/g, "")).not.toMatch(/\{\{|\}\}/);
  });

  it("puts nonce=\"{{nonce}}\" on every <script> and <style>", () => {
    const scriptsAndStyles = [...tags(TEMPLATE, "script"), ...tags(TEMPLATE, "style")];
    expect(scriptsAndStyles.length).toBeGreaterThanOrEqual(2);
    for (const tag of scriptsAndStyles) expect(tag).toContain('nonce="{{nonce}}"');
  });

  it("loads the SDK with data-cfasync=\"false\" before src and the path prefix", () => {
    const scripts = tags(TEMPLATE, "script");
    expect(scripts).toHaveLength(1);
    const script = scripts[0]!;
    expect(script.indexOf('data-cfasync="false"')).toBeGreaterThan(0);
    expect(script.indexOf('data-cfasync="false"')).toBeLessThan(script.indexOf('src="{{sdk_src}}"'));
    expect(script).toContain('data-mg-path-prefix="{{prefix}}"');
  });

  it("references no external resource and nothing CSP would block", () => {
    expect(TEMPLATE).not.toMatch(/https?:/i);
    expect(TEMPLATE).not.toMatch(/=\s*["']?\s*\/\//);
    expect(TEMPLATE).not.toMatch(/url\(|@import/i);
    expect(TEMPLATE).not.toMatch(/\son[a-z]+\s*=/i); // inline handlers
    expect(TEMPLATE).not.toMatch(/\sstyle\s*=/i); // style attributes
  });

  it("carries the required structure", () => {
    expect(TEMPLATE).toMatch(/^<!doctype html>/i);
    expect(TEMPLATE).toContain('<html lang="{{lang}}">');
    expect(TEMPLATE).toContain('<meta charset="utf-8">');
    expect(TEMPLATE).toContain('<meta name="robots" content="noindex">');
    expect(TEMPLATE).toContain('<meta name="viewport" content="width=device-width, initial-scale=1">');
    const main = tags(TEMPLATE, "main");
    expect(main).toHaveLength(1);
    for (const attribute of [
      'id="mg-challenge"',
      'data-mg-state="{{state}}"',
      'data-mg-c="{{c}}"',
      'data-mg-type="{{type}}"',
      'data-mg-pow-bits="{{pow_bits}}"',
      'data-mg-ret="{{ret}}"',
      'data-mg-rid="{{request_id}}"',
      'data-mg-prefix="{{prefix}}"',
    ]) {
      expect(main[0]).toContain(attribute);
    }
    expect(TEMPLATE).toMatch(/<p id="mg-status" role="status" aria-live="polite">/);
    expect(TEMPLATE).toMatch(/<a id="mg-retry" href="\{\{ret\}\}" hidden>/);
    expect(TEMPLATE).toMatch(/<noscript>[\s\S]+<\/noscript>/);
    expect(TEMPLATE.replace(/<[^>]*>/g, "")).toContain("{{request_id}}");
  });

  it("ships both languages, selected by <html lang>, and respects reduced motion", () => {
    expect(TEMPLATE).toMatch(/lang="zh-CN">[^<]*[一-鿿]/);
    expect(TEMPLATE).toMatch(/lang="en">[A-Za-z]/);
    expect(TEMPLATE).toContain('html[lang|="zh"] [lang="en"]');
    expect(TEMPLATE).toContain('html:not([lang|="zh"]) [lang|="zh"]');
    expect(TEMPLATE).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{\s*\.spin \{ animation: none; \}/);
  });

  it("stays well-formed when the Edge renders hostile values", () => {
    const hostile = `"><script>alert(1)</script><a href='//evil'>`;
    const values: Record<string, string> = Object.fromEntries(SPEC_PLACEHOLDERS.map((name) => [name, hostile]));
    const html = render(TEMPLATE, values);
    expect(html).not.toMatch(/\{\{|\}\}/);
    expect(tags(html, "script")).toHaveLength(1);
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("href='//evil'");
    // A realistic rendering keeps every placeholder slot filled.
    const real = render(TEMPLATE, {
      lang: "zh-CN",
      nonce: "q83vEjRWeJq83vEjRWeJqw==",
      sdk_src: "/__mg/s/mg.0123456789abcdef.js",
      prefix: "/__mg/",
      c: "AAECAwQ",
      type: "pow",
      pow_bits: "16",
      ret: "/account/login?next=%2Fcart&x=1",
      request_id: "0123456789abcdef0123456789abcdef",
      state: "challenge",
    });
    expect(real).toContain('data-mg-ret="/account/login?next=%2Fcart&amp;x=1"');
    expect(real).toContain('<script data-cfasync="false" src="/__mg/s/mg.0123456789abcdef.js" nonce="q83vEjRWeJq83vEjRWeJqw=="');
  });
});

describe("validateTemplate rejects contract violations", () => {
  const cases: ReadonlyArray<[string, (t: string) => string, RegExp]> = [
    ["a missing placeholder", (t) => t.replace(/\{\{state\}\}/g, "challenge"), /\{\{state\}\} missing/],
    ["an unknown placeholder", (t) => t.replace("<noscript>", "<noscript>{{user}}"), /unknown placeholder \{\{user\}\}/],
    ["stray braces", (t) => t.replace("<noscript>", "<noscript>{{"), /stray/],
    ["a <script> without nonce", (t) => t.replace("</body>", '<script nonce="x">1</script></body>'), /<script> without nonce/],
    ["a <style> without nonce", (t) => t.replace("</head>", "<style>p{}</style></head>"), /<style> without nonce/],
    ["an https URL", (t) => t.replace("<noscript>", "<noscript>https://example.com/"), /http: or https:/],
    ["a protocol-relative src", (t) => t.replace('src="{{sdk_src}}"', 'src="//cdn.example/mg.js"'), /protocol-relative/],
    ["a protocol-relative CSS url()", (t) => t.replace("* { box-sizing", ".x { background: url(//cdn.example/x.png) }\n* { box-sizing"), /url\(\)/],
    ["a CSS @import", (t) => t.replace("* { box-sizing", '@import "/x.css";\n* { box-sizing'), /@import/],
    ["data-cfasync after src", (t) => t.replace('<script data-cfasync="false" src="{{sdk_src}}"', '<script src="{{sdk_src}}" data-cfasync="false"'), /data-cfasync="false" before src/],
    ["a second external script", (t) => t.replace("</body>", '<script nonce="{{nonce}}" src="/x.js"></script></body>'), /exactly one external <script>/],
    ["an inline event handler", (t) => t.replace('<a id="mg-retry"', '<a onclick="x()" id="mg-retry"'), /inline event handler/],
    ["a style attribute", (t) => t.replace('<p class="rid">', '<p class="rid" style="color:red">'), /style attribute/],
    ["a missing main data attribute", (t) => t.replace('data-mg-type="{{type}}"', 'data-mg-kind="{{type}}"'), /data-mg-type/],
    ["a missing retry link", (t) => t.replace('id="mg-retry"', 'id="retry"'), /mg-retry/],
    ["a missing status region", (t) => t.replace('aria-live="polite"', ""), /mg-status/],
    ["a missing noscript", (t) => t.replace(/<noscript>[\s\S]*<\/noscript>/, ""), /noscript/],
    ["no doctype", (t) => t.replace("<!doctype html>", ""), /doctype/],
    ["no robots meta", (t) => t.replace('<meta name="robots" content="noindex">', ""), /robots/],
    ["an empty title", (t) => t.replace(/<title>[^<]*<\/title>/, "<title> </title>"), /title/],
    ["request_id only in attributes", (t) => t.replace("<code>{{request_id}}</code>", "<code></code>"), /request_id/],
    ["more than 32 KiB", (t) => t.replace("</body>", `<p>${"x".repeat(32 * 1024)}</p></body>`), /larger than/],
    // The Edge's escaping (& < > " ') only makes a value inert inside a quoted
    // attribute value or ordinary text; anywhere else a value such as ret
    // "/a/;alert(1)//" or "/x onmouseover=y" becomes markup or script.
    ["a placeholder in an unquoted attribute value", (t) => t.replace('data-mg-rid="{{request_id}}"', "data-mg-rid={{request_id}}"), /outside a quoted attribute value/],
    ["a placeholder as an attribute name", (t) => t.replace('<p class="rid">', '<p class="rid" {{ret}}>'), /outside a quoted attribute value/],
    ["a placeholder in inline script", (t) => t.replace("</body>", '<script nonce="{{nonce}}">var r = {{ret}};</script></body>'), /inside <script>/],
    ["a placeholder in the stylesheet", (t) => t.replace("* { box-sizing", ".x::after { content: \"{{request_id}}\" }\n* { box-sizing"), /inside <style>/],
    ["a placeholder in a comment", (t) => t.replace("<noscript>", "<!-- {{ret}} --><noscript>"), /inside an HTML comment/],
    ["a placeholder as a tag name", (t) => t.replace("<noscript>", "<{{ret}}><noscript>"), /as a tag name/],
  ];

  for (const [name, mutate, message] of cases) {
    it(name, () => {
      const mutated = mutate(TEMPLATE);
      expect(mutated).not.toBe(TEMPLATE);
      const errors = validateTemplate(mutated);
      expect(errors.join("\n")).toMatch(message);
    });
  }

  it("accepts placeholders in single-quoted attribute values and in plain text", () => {
    const variant = TEMPLATE.replace('data-mg-rid="{{request_id}}"', "data-mg-rid='{{request_id}}'").replace(
      "<noscript>",
      "<p>{{request_id}}</p><noscript>",
    );
    expect(validateTemplate(variant)).toEqual([]);
  });

  it("invalid UTF-8", () => {
    const bytes = new Uint8Array(TEMPLATE_BYTES.byteLength + 1);
    bytes.set(TEMPLATE_BYTES);
    bytes[bytes.length - 1] = 0xff;
    expect(validateTemplate(bytes)).toContain("not valid UTF-8");
  });

  it("never throws on 10,000 xorshift inputs (§2.4)", () => {
    const rng = new XorShift32(0x7e3a);
    for (let i = 0; i < 10_000; i++) {
      let input: string | Uint8Array;
      switch (rng.below(3)) {
        case 0:
          input = rng.bytes(rng.below(512));
          break;
        case 1:
          input = rng.string(256);
          break;
        default: {
          // Local edits of the real template exercise the structural checks.
          const at = rng.below(TEMPLATE.length);
          input = TEMPLATE.slice(0, at) + rng.string(8) + TEMPLATE.slice(at + rng.below(16));
        }
      }
      expect(Array.isArray(validateTemplate(input))).toBe(true);
    }
  });
});
