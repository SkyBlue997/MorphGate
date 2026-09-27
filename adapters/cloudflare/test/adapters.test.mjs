// Offline checks for the Cloudflare templates. Nothing here talks to Cloudflare.
// Run from the repo root: node --test adapters/cloudflare/test/adapters.test.mjs
// (Node >= 22.18 imports the Worker's .ts directly; older Node skips those cases.)
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { afterEach, describe, it } from "node:test";

const root = new URL("../", import.meta.url);
const readJson = (name) => JSON.parse(readFileSync(new URL(name, root), "utf8"));

// Brief B2 Tier 0: header -> Cloudflare rules field. Numeric fields must go through to_string().
const TIER0 = {
  "x-mg-cf-tls-version": "cf.tls_version",
  "x-mg-cf-tls-cipher": "cf.tls_cipher",
  "x-mg-cf-tls-ciphers-sha1": "cf.tls_ciphers_sha1",
  "x-mg-cf-tls-ext-sha1": "cf.tls_client_extensions_sha1",
  "x-mg-cf-tls-hello-len": "to_string(cf.tls_client_hello_length)",
  "x-mg-cf-tls-random": "cf.tls_client_random",
  "x-mg-cf-http-version": "http.request.version",
  "x-mg-cf-rtt": "to_string(cf.timings.client_tcp_rtt_msec)",
  "x-mg-cf-quic-rtt": "to_string(cf.timings.client_quic_rtt_msec)",
  "x-mg-cf-asn": "to_string(ip.src.asnum)",
  "x-mg-cf-vbot": "to_string(cf.client.bot)",
  "x-mg-cf-vbot-cat": "cf.verified_bot_category",
  "x-mg-cf-hdr-names": 'join(http.request.headers.names, ",")',
};
const TIER1 = ["x-mg-cf-priority", "x-mg-cf-accept-encoding", "x-mg-cf-as-org", "x-mg-cf-t1"];
const MG_PREFIX_EXPR = 'starts_with(http.request.uri.path, "/__mg/")';

function assertRulesetShape(ruleset, phase) {
  assert.equal(ruleset.kind, "zone");
  assert.equal(ruleset.phase, phase);
  assert.ok(Array.isArray(ruleset.rules) && ruleset.rules.length === 1);
  const [rule] = ruleset.rules;
  for (const field of ["ref", "description", "expression", "action"]) {
    assert.equal(typeof rule[field], "string", `rule.${field}`);
  }
  // mgctl only manages rules whose ref starts with "mg_" (docs/08 §2.3).
  assert.match(rule.ref, /^mg_[a-z0-9_]+$/);
  assert.equal(rule.enabled, true);
  return rule;
}

describe("transform-rule.request-headers.json", () => {
  const rule = assertRulesetShape(readJson("transform-rule.request-headers.json"), "http_request_late_transform");
  const headers = rule.action_parameters.headers;

  it("is a single rewrite rule", () => {
    assert.equal(rule.action, "rewrite");
  });

  it("sets exactly the Tier 0 headers from dynamic expressions", () => {
    const set = Object.fromEntries(
      Object.entries(headers)
        .filter(([, op]) => op.operation === "set")
        .map(([name, op]) => [name, op.expression]),
    );
    assert.deepEqual(set, TIER0);
  });

  it("removes client-sent Tier 1 names so only a Snippet or Worker can set them", () => {
    const removed = Object.entries(headers)
      .filter(([, op]) => op.operation === "remove")
      .map(([name]) => name);
    assert.deepEqual(removed.sort(), [...TIER1].sort());
  });

  it("uses header names Cloudflare accepts", () => {
    for (const name of Object.keys(headers)) {
      assert.match(name, /^[a-z0-9_-]+$/, `${name}: only [A-Za-z0-9_-], lowercase by convention`);
      assert.ok(!name.startsWith("cf-") && !name.startsWith("x-cf-"), `${name}: cf-/x-cf- names cannot be set`);
      assert.ok(name.startsWith("x-mg-cf-"), `${name}: MorphGate owns the x-mg-cf- namespace`);
    }
  });

  it("flags the ciphers field spelling for verification", () => {
    assert.match(rule.description, /cf\.tls_client_ciphers_sha1/);
  });
});

describe("cache-rule.bypass-mg.json", () => {
  const rule = assertRulesetShape(readJson("cache-rule.bypass-mg.json"), "http_request_cache_settings");

  it("bypasses cache for the MorphGate prefix except SDK builds, and says it must be last", () => {
    assert.equal(rule.action, "set_cache_settings");
    assert.deepEqual(rule.action_parameters, { cache: false });
    // Content-hashed builds under /__mg/s/ are immutable and may be edge-cached (docs/08 §2.6).
    assert.equal(rule.expression, `${MG_PREFIX_EXPR} and not starts_with(http.request.uri.path, "/__mg/s/")`);
    assert.match(rule.description, /LAST/);
  });
});

// Skip rules (docs/08 §2.7). Default: never skip http_ratelimit, so the one Free
// rate limiting rule can keep blocking POST /__mg/ floods (reconciliation D12).
function assertSkipRule(file, wantPhases) {
  const rule = assertRulesetShape(readJson(file), "http_request_firewall_custom");
  assert.equal(rule.ref, "mg_skip_mg_paths");
  assert.equal(rule.action, "skip");
  assert.equal(rule.expression, MG_PREFIX_EXPR);
  const allowedPhases = ["http_ratelimit", "http_request_sbfm", "http_request_firewall_managed"];
  const allowedProducts = ["zoneLockdown", "uaBlock", "bic", "hot", "securityLevel", "rateLimit", "waf"];
  assert.deepEqual([...rule.action_parameters.phases].sort(), wantPhases);
  assert.deepEqual([...rule.action_parameters.products].sort(), ["bic", "securityLevel"]);
  for (const p of rule.action_parameters.phases) assert.ok(allowedPhases.includes(p));
  for (const p of rule.action_parameters.products) assert.ok(allowedProducts.includes(p), `${p} (case-sensitive)`);
  return rule;
}

describe("waf-skip.mg.json", () => {
  it("skips SBFM, BIC and Security Level for the MorphGate prefix, never rate limiting", () => {
    const rule = assertSkipRule("waf-skip.mg.json", ["http_request_sbfm"]);
    assert.ok(!rule.action_parameters.phases.includes("http_ratelimit"), "the /__mg/ flood rule must keep applying");
    assert.ok(!rule.action_parameters.products.includes("rateLimit"));
    assert.match(rule.description, /does not skip http_ratelimit/i);
  });
});

describe("waf-skip.mg.no-flood-limit.json", () => {
  it("is the default rule plus http_ratelimit, and says it is only for zones without a flood rule", () => {
    const variant = assertSkipRule("waf-skip.mg.no-flood-limit.json", ["http_ratelimit", "http_request_sbfm"]);
    const base = readJson("waf-skip.mg.json").rules[0];
    // Same rule identity, so mgctl manages exactly one of the two on a zone.
    assert.equal(variant.ref, base.ref);
    assert.equal(variant.expression, base.expression);
    assert.match(readJson("waf-skip.mg.no-flood-limit.json").description, /ONLY for zones with NO rate limiting rule/);
    assert.match(variant.description, /without a \/__mg\/ flood rate limiting rule/);
  });
});

describe("template inventory", () => {
  it("tests every Rulesets template in this directory", () => {
    const files = readdirSync(root).filter((f) => f.endsWith(".json")).sort();
    assert.deepEqual(files, [
      "cache-rule.bypass-mg.json",
      "transform-rule.request-headers.json",
      "waf-skip.mg.json",
      "waf-skip.mg.no-flood-limit.json",
    ]);
  });
});

// --- Tier 1 forwarders: run the real Snippet and Worker code against a stubbed fetch ---

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function captureFetch() {
  const seen = [];
  globalThis.fetch = async (request) => {
    seen.push(request);
    return new Response("ok");
  };
  return seen;
}

function incoming(cf, init = {}) {
  const request = new Request("https://example.com/__mg/c", {
    method: "POST",
    body: '{"c":"x"}',
    headers: {
      "content-type": "application/json",
      "x-real-ip": "203.0.113.7",
      // Client-supplied spoofs that must never survive:
      "x-mg-cf-priority": "spoofed",
      "x-mg-cf-as-org": "spoofed",
      "x-mg-cf-t1": "spoofed",
    },
    ...init,
  });
  if (cf !== undefined) Object.defineProperty(request, "cf", { value: cf });
  return request;
}

async function loadForwarders() {
  const forwarders = [["snippet", (await import("../snippet/mg-signals.js")).default]];
  try {
    forwarders.push(["worker", (await import("../worker/src/index.ts")).default]);
  } catch (error) {
    if (error?.code !== "ERR_UNKNOWN_FILE_EXTENSION") throw error;
    console.warn("skipping Worker checks: this Node cannot import .ts (needs >= 22.18)");
  }
  return forwarders;
}

for (const [source, handler] of await loadForwarders()) {
  describe(`Tier 1 ${source}`, () => {
    it("sets the Tier 1 headers from request.cf and keeps the body and x-real-ip", async () => {
      const seen = captureFetch();
      await handler.fetch(
        incoming({
          requestPriority: "weight=256;exclusive=1;group=0;group-weight=0",
          clientAcceptEncoding: "gzip, deflate, br, zstd",
          asOrganization: "Example Networks, Inc.",
        }),
      );
      assert.equal(seen.length, 1);
      const out = seen[0];
      assert.equal(out.headers.get("x-mg-cf-priority"), "weight=256;exclusive=1;group=0;group-weight=0");
      assert.equal(out.headers.get("x-mg-cf-accept-encoding"), "gzip, deflate, br, zstd");
      assert.equal(out.headers.get("x-mg-cf-as-org"), "Example%20Networks%2C%20Inc.");
      assert.equal(out.headers.get("x-mg-cf-t1"), source);
      assert.equal(out.headers.get("x-real-ip"), "203.0.113.7");
      assert.equal(out.method, "POST");
      assert.equal(await out.text(), '{"c":"x"}');
    });

    it("deletes spoofed headers when Cloudflare has no value", async () => {
      const seen = captureFetch();
      await handler.fetch(incoming({}));
      const out = seen[0];
      assert.equal(out.headers.get("x-mg-cf-priority"), null);
      assert.equal(out.headers.get("x-mg-cf-as-org"), null);
      assert.equal(out.headers.get("x-mg-cf-t1"), source);
    });

    it("percent-encodes non-ASCII organisations and drops unusable values", async () => {
      const seen = captureFetch();
      await handler.fetch(
        incoming({ asOrganization: "中国电信", requestPriority: "x".repeat(300), clientAcceptEncoding: "bad\u0000value" }),
      );
      const out = seen[0];
      assert.equal(out.headers.get("x-mg-cf-as-org"), encodeURIComponent("中国电信"));
      assert.equal(decodeURIComponent(out.headers.get("x-mg-cf-as-org")), "中国电信");
      assert.equal(out.headers.get("x-mg-cf-priority"), null);
      assert.equal(out.headers.get("x-mg-cf-accept-encoding"), null);
    });

    it("sends no Tier 1 values without request.cf (the Edge records them as MISSING)", async () => {
      const seen = captureFetch();
      await handler.fetch(incoming(undefined, { method: "GET", body: undefined }));
      assert.equal(seen[0].headers.get("x-mg-cf-as-org"), null);
      assert.equal(seen[0].headers.get("x-mg-cf-t1"), source);
    });
  });
}

describe("snippet size", () => {
  it("stays far below the 32 KB Snippet package limit", () => {
    const bytes = readFileSync(new URL("snippet/mg-signals.js", root)).byteLength;
    assert.ok(bytes < 4096, `snippet is ${bytes} bytes`);
  });
});
