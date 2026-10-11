// Challenge page template v2 (docs/impl/phase2-spec.md §12.3, §12.7, §2.4 items 11-12).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TEMPLATE_PLACEHOLDERS_V2, V2_ELEMENTS, validateTemplate } from "../scripts/build-dist.mjs";
import { XorShift32 } from "./xorshift";

const BYTES = readFileSync(new URL("../templates/challenge.v2.html", import.meta.url));
const T = new TextDecoder("utf-8", { fatal: true }).decode(BYTES);
const V1 = readFileSync(new URL("../templates/challenge.html", import.meta.url), "utf8");
const STYLE = /<style nonce="\{\{nonce\}\}">([\s\S]*?)<\/style>/.exec(T)![1]!;

/** The declarations of the CSS rule whose selector list is exactly `selector`. */
function rule(selector: string, css = STYLE): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`(?:^|[}\\n])\\s*${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  if (m === null) throw new Error(`no rule for ${selector}`);
  return m[1]!;
}

/** The body of an @media block. */
function media(query: string): string {
  const at = STYLE.indexOf(`@media ${query}`);
  if (at < 0) throw new Error(`no @media ${query}`);
  let depth = 0;
  const open = STYLE.indexOf("{", at);
  for (let i = open; i < STYLE.length; i++) {
    if (STYLE[i] === "{") depth++;
    if (STYLE[i] === "}" && --depth === 0) return STYLE.slice(open + 1, i);
  }
  throw new Error("unbalanced");
}

function render(values: Record<string, string>): string {
  const escape = (v: string): string =>
    v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  return T.replace(/\{\{([a-z_]+)\}\}/g, (_, n: string) => escape(values[n] ?? ""));
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}
const contrast = (a: string, b: string): number => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
};
function tokens(block: string): Record<string, string> {
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1]!, m[2]!]));
}

describe("templates/challenge.v2.html: contract (§12.3)", () => {
  it("passes the v2 validator, and only that one", () => {
    expect(validateTemplate(BYTES, 2)).toEqual([]);
    expect(validateTemplate(BYTES, 1).join("\n")).toMatch(/unknown placeholder \{\{ix\}\}/);
    // The v1 template lacks the v2 structure.
    expect(validateTemplate(V1, 2).join("\n")).toMatch(/\{\{ix\}\} missing/);
    expect(validateTemplate(BYTES, 3)).toEqual(["unknown template version 3"]);
  });

  it("uses the 13 placeholders: {{ix}} once in data-mg-ix, the links only in href", () => {
    expect([...TEMPLATE_PLACEHOLDERS_V2].sort()).toEqual(
      ["lang", "nonce", "sdk_src", "prefix", "c", "type", "pow_bits", "ret", "request_id", "state", "ix", "help_href", "privacy_href"].sort(),
    );
    expect(T.match(/\{\{ix\}\}/g)).toHaveLength(1);
    expect(T).toContain('data-mg-ix="{{ix}}"');
    expect(T.match(/\{\{help_href\}\}/g)).toEqual(['{{help_href}}']);
    expect(T).toContain('<a id="mg-help" href="{{help_href}}">');
    expect(T).toContain('<a id="mg-privacy" href="{{privacy_href}}">');
  });

  it("has every new element once, with its attributes, in place", () => {
    for (const { id } of V2_ELEMENTS) expect(T.match(new RegExp(`id="${id}"`, "g")), id).toHaveLength(1);
    expect(T).toMatch(/<div id="mg-ix" hidden>/);
    expect(T).toMatch(/<button id="mg-hold" type="button" aria-describedby="mg-purpose">/);
    expect(T).toMatch(/<div id="mg-progress" role="progressbar" aria-labelledby="mg-purpose" hidden>/);
    // #mg-status stays in the initial markup (a live region must exist before it speaks).
    expect(T).toMatch(/<p id="mg-status" role="status" aria-live="polite">/);
    // The hold button: a text label and an aria-hidden progress layer that ignores the pointer.
    const hold = /<button id="mg-hold"[^>]*>([\s\S]*?)<\/button>/.exec(T)![1]!;
    expect(hold).toMatch(/<span class="mg-fill" aria-hidden="true"><\/span>/);
    expect(hold).toMatch(/<span class="mg-label">.*按住以验证.*Press and hold to verify/);
    expect(rule(".mg-fill")).toMatch(/pointer-events:\s*none/);
  });

  it("carries the §12.7 copy in both languages", () => {
    for (const text of [
      "为防止自动化滥用，请按住或点击“按住以验证”按钮完成验证。",
      "To protect this site from automated abuse, press and hold, or click, the “Press and hold to verify” button.",
      "无法按住？改为按一下",
      "Can't press and hold? Press once instead",
      "改用自动验证（较慢）",
      "Verify automatically (slower)",
      "页面没有响应？请更新浏览器或换用其他浏览器 · 请求 ID：",
      "Page not responding? Please update your browser or use another one · Request ID: ",
      "此页面需要启用 JavaScript 完成验证。请求 ID：",
      "JavaScript is required to complete this check. Request ID: ",
      "排查问题",
      "Troubleshoot",
      "隐私说明",
      "Privacy",
    ]) {
      expect(T, text).toContain(text);
    }
    expect(T.replace(/<[^>]*>/g, "")).not.toMatch(/机器人|可疑|已被拦截|robot|suspicious|blocked/i);
  });

  it("references no third party: no URL at all, Turnstile only at runtime", () => {
    expect(T).not.toMatch(/https?:|\/\/[a-z]/i);
    expect(T).not.toContain("challenges.cloudflare.com");
    expect(T).not.toMatch(/url\(|@import/i);
  });

  it("stays well-formed when the Edge renders hostile values", () => {
    const hostile = `"><script>alert(1)</script><a href='//evil'>`;
    const html = render(Object.fromEntries(TEMPLATE_PLACEHOLDERS_V2.map((n) => [n, hostile])));
    expect(html).not.toContain("<script>alert");
    expect(html.match(/<script\b/g)).toHaveLength(1);
    const ix = JSON.stringify({ v: 1, providers: ["self_hold", "pow_a11y"], ret: "/a?b=<c>&d" });
    const real = render({ ix, help_href: "/help", privacy_href: "/privacy", type: "interactive" });
    expect(real).toContain(`data-mg-ix="${ix.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")}"`);
    expect(real).toContain('<a id="mg-help" href="/help">');
  });
});

describe("templates/challenge.v2.html: style rules (§12.3), one test each", () => {
  it("every control is at least 24 x 24 CSS px, #mg-hold at least 44 x 44", () => {
    expect(rule("button, a")).toMatch(/min-width:\s*24px;\s*min-height:\s*24px/);
    const hold = rule("#mg-hold");
    expect(hold).toMatch(/min-width:\s*44px/);
    expect(hold).toMatch(/min-height:\s*44px/);
  });

  it("every control has a visible :focus-visible ring", () => {
    expect(rule("button:focus-visible, a:focus-visible")).toMatch(/outline:\s*3px solid/);
  });

  it("touch-action, the callout and user-select are set on #mg-hold only", () => {
    const hold = rule("#mg-hold");
    for (const decl of ["touch-action: none", "-webkit-touch-callout: none", "-webkit-user-select: none", "user-select: none"]) {
      expect(hold).toContain(decl);
      expect(STYLE.match(new RegExp(`(^|[^-])${decl}`, "g")), decl).toHaveLength(1);
    }
  });

  it("prefers-reduced-motion: the progress is stepped, nothing animates", () => {
    const reduced = media("(prefers-reduced-motion: reduce)");
    expect(rule(".mg-fill, .mg-bar", reduced)).toMatch(/transition:\s*none/);
    expect(rule(".spin", reduced)).toMatch(/animation:\s*none/);
  });

  it("forced-colors: the progress uses Highlight and the control a system-colour border", () => {
    const forced = media("(forced-colors: active)");
    expect(rule(".mg-fill, .mg-bar", forced)).toMatch(/background:\s*Highlight/);
    expect(rule("#mg-hold", forced)).toMatch(/border:\s*2px solid ButtonText/);
  });

  it("the button is offset only by margin, with 16 px on both sides, no fixed height, and wraps at 320 px", () => {
    expect(rule(".mg-row")).toMatch(/padding:\s*8px 16px/);
    const hold = rule("#mg-hold");
    expect(hold).not.toMatch(/(^|[^-])height:/);
    expect(hold).not.toMatch(/transform|left:|top:/);
    expect(rule("button")).toMatch(/max-width:\s*100%/);
    expect(rule("button")).toMatch(/white-space:\s*normal/);
    expect(rule("body")).toMatch(/padding:\s*16px/);
  });

  it("text meets AAA contrast (7:1) in both schemes; red is never used", () => {
    const light = tokens(rule(":root"));
    const dark = tokens(media("(prefers-color-scheme: dark)"));
    for (const t of [light, dark]) {
      for (const [fg, bg] of [
        ["fg", "bg"],
        ["fg", "card"],
        ["muted", "card"],
        ["muted", "bg"],
        ["accent", "card"],
        ["on-accent", "accent"],
        ["fg", "hold"],
        ["fg", "fill"],
      ] as const) {
        expect(contrast(t[fg]!, t[bg]!), `${fg} on ${bg}`).toBeGreaterThanOrEqual(7);
      }
    }
    expect(STYLE).not.toMatch(/\bred\b|#f00\b|#ff0000/i);
  });

  it("#mg-stuck appears after 10 s without the SDK, without motion, and the SDK hides it", () => {
    expect(rule("#mg-stuck")).toMatch(/visibility:\s*hidden;\s*animation:\s*mg-reveal 0s 10s forwards/);
    expect(STYLE).toContain("@keyframes mg-reveal { to { visibility: visible; } }");
    expect(rule("[data-mg-phase] #mg-stuck")).toMatch(/display:\s*none/);
  });

  it("interactive pages start with an empty status and no spinner", () => {
    expect(rule('[data-mg-type="interactive"] .spin, [data-mg-type="interactive"] .lead, [data-mg-type="interactive"] .mg-wait')).toMatch(
      /display:\s*none/,
    );
    expect(T).toMatch(/<p id="mg-status"[^>]*><span class="mg-wait">/);
  });
});

describe("validateTemplate v2 rejects contract violations", () => {
  const cases: ReadonlyArray<[string, (t: string) => string, RegExp]> = [
    ["{{ix}} twice", (t) => t.replace('<div id="mg-turnstile" hidden>', '<div id="mg-turnstile" hidden data-x="{{ix}}">'), /\{\{ix\}\} must appear exactly once/],
    ["{{ix}} on another attribute", (t) => t.replace('data-mg-ix="{{ix}}"', 'data-mg-ixx="{{ix}}"'), /data-mg-ix="\{\{ix\}\}"/],
    ["{{help_href}} in text", (t) => t.replace("<noscript>", "<noscript>{{help_href}}"), /help_href.*quoted href/],
    ["{{privacy_href}} in another attribute", (t) => t.replace('<div id="mg-turnstile" hidden>', '<div id="mg-turnstile" hidden title="{{privacy_href}}">'), /privacy_href.*quoted href/],
    ["{{help_href}} inside a longer href", (t) => t.replace('href="{{help_href}}"', 'href="/x{{help_href}}"'), /help_href.*quoted href/],
    ...V2_ELEMENTS.map(
      ({ id }): [string, (t: string) => string, RegExp] => [
        `no #${id}`,
        (t) => t.replace(`id="${id}"`, `id="${id}-x"`),
        new RegExp(`id "${id}" must appear exactly once`),
      ],
    ),
    ["a duplicate id", (t) => t.replace("<noscript>", '<p id="mg-stuck">x</p><noscript>'), /id "mg-stuck" must appear exactly once \(found 2\)/],
    ["#mg-hold not a button", (t) => t.replace(/<button id="mg-hold"([^>]*)>([\s\S]*?)<\/button>/, '<div id="mg-hold"$1>$2</div>'), /<button id="mg-hold"/],
    ["#mg-hold without aria-describedby", (t) => t.replace(' aria-describedby="mg-purpose"', ""), /<button id="mg-hold"/],
    ["#mg-ix not hidden", (t) => t.replace('<div id="mg-ix" hidden>', '<div id="mg-ix">'), /<div id="mg-ix" hidden>/],
    ["#mg-progress without its role", (t) => t.replace('role="progressbar" ', ""), /mg-progress/],
    ["#mg-alt-pow outside #mg-ix", (t) => t.replace(/<button id="mg-alt-pow"[\s\S]*?<\/button>/, "").replace("<noscript>", '<button id="mg-alt-pow" type="button">x</button><noscript>'), /#mg-alt-pow must be inside #mg-ix/],
    ["#mg-stuck outside <main>", (t) => t.replace(/<p id="mg-stuck">[\s\S]*?<\/p>/, "").replace("</main>", '</main><p id="mg-stuck">x</p>'), /#mg-stuck must be inside <main/],
    ["#mg-hold without a progress layer", (t) => t.replace('<span class="mg-fill" aria-hidden="true"></span>', ""), /aria-hidden="true" progress layer/],
    ["#mg-hold without a label", (t) => t.replace(/<span class="mg-label">[\s\S]*?<\/span><\/span><\/button>/, "</button>"), /text label/],
    ["an external URL", (t) => t.replace("<noscript>", "<noscript>https://challenges.cloudflare.com/turnstile/v0/api.js"), /http: or https:/],
  ];
  for (const [name, mutate, message] of cases) {
    it(name, () => {
      const mutated = mutate(T);
      expect(mutated).not.toBe(T);
      expect(validateTemplate(mutated, 2).join("\n")).toMatch(message);
    });
  }

  it("never throws on 10,000 xorshift edits (§2.4)", () => {
    const rng = new XorShift32(0x2b2b);
    for (let i = 0; i < 10_000; i++) {
      const at = rng.below(T.length);
      const input = rng.below(4) === 0 ? rng.string(300) : T.slice(0, at) + rng.string(8) + T.slice(at + rng.below(24));
      expect(Array.isArray(validateTemplate(input, 2))).toBe(true);
    }
  });
});
