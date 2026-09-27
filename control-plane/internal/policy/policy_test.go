package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

var fixedNow = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func newTestCompiler(t *testing.T, opts Options) *Compiler {
	t.Helper()
	if opts.Now == nil {
		opts.Now = func() time.Time { return fixedNow }
	}
	c, err := NewCompiler(opts)
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	return c
}

// checkSource parses and checks YAML given inline.
func checkSource(t *testing.T, opts Options, src string) ([]*CheckedRule, Diagnostics) {
	t.Helper()
	rules, diags := Parse("test.yaml", []byte(src))
	checked, ds := newTestCompiler(t, opts).Check(rules)
	return checked, append(diags, ds...)
}

func checkFiles(t *testing.T, files ...string) ([]*CheckedRule, Diagnostics) {
	t.Helper()
	var rules []*Rule
	var diags Diagnostics
	for _, f := range files {
		rs, ds := ParseFile(f)
		rules = append(rules, rs...)
		diags = append(diags, ds...)
	}
	checked, ds := newTestCompiler(t, Options{}).Check(rules)
	return checked, append(diags, ds...)
}

func diagStrings(ds Diagnostics) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.String()
	}
	return out
}

func requireDiag(t *testing.T, ds Diagnostics, want string) {
	t.Helper()
	for _, s := range diagStrings(ds) {
		if strings.Contains(s, want) {
			return
		}
	}
	t.Errorf("no diagnostic contains %q; got:\n  %s", want, strings.Join(diagStrings(ds), "\n  "))
}

func TestValidTestdata(t *testing.T) {
	files, err := filepath.Glob("../../testdata/policies/valid/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no valid testdata: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			checked, diags := checkFiles(t, f)
			if len(diags) != 0 {
				t.Fatalf("unexpected diagnostics:\n  %s", strings.Join(diagStrings(diags), "\n  "))
			}
			if len(checked) == 0 {
				t.Fatal("no rules compiled")
			}
		})
	}
}

func TestInvalidTestdata(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"non-bool-expr.yaml", []string{
			`non-bool-expr.yaml:4:11: error: rule "returns-int": expr: expression must evaluate to bool, got int`,
		}},
		{"unknown-field.yaml", []string{
			`unknown-field.yaml:6:5: error: rule "typo-in-mode": unknown field "mdoe"`,
		}},
		{"bad-phase.yaml", []string{
			`bad-phase.yaml:3:12: error: rule "wrong-phase": phase: "botting" is not one of identity, protocol, rate_limit, bot, custom, default`,
		}},
		{"temporary-without-expiry.yaml", []string{
			`temporary-without-expiry.yaml:4:5: error: rule "forgot-expiry": expires_at: required when ` + "`temporary: true`",
		}},
		{"undeclared-field.yaml", []string{
			`undeclared-field.yaml:4:27: error: rule "misspelled-field": expr: undefined field 'verfied'`,
		}},
		{"bad-values.yaml", []string{
			`rule "Bad_ID": id: must match`,
			`:4:15: error: rule "Bad_ID": priority: must be a decimal integer, got "high"`,
			`rule "Bad_ID": action: "destroy" is not one of`,
			`rule "Bad_ID": mode: "shadow" is not one of`,
			`rule "Bad_ID": rollout: must be between 0 and 100, got 150`,
			`rule "Bad_ID": locked: must be true or false, got "yes"`,
			`rule "Bad_ID": expires_at: must be an RFC 3339 timestamp`,
			`rule "missing-required": phase: required field is missing`,
			`rule "missing-required": action: required field is missing`,
			`rule "bad-challenge-type": params.type: "captcha" is not one of`,
			`:20:26: error: rule "bad-literals": expr: ip_in: invalid CIDR "10.0.0.0/33"`,
			`rule "bad-literals": expr: list() takes a string literal name`,
			`rule "bad-literals": expr: glob() pattern must be a string literal`,
			`:22:5: error: rule "bad-literals": id: duplicate rule id (first defined at`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			_, diags := checkFiles(t, filepath.Join("../../testdata/policies/invalid", tc.file))
			if !diags.HasErrors() {
				t.Fatal("expected errors, got none")
			}
			for _, w := range tc.want {
				requireDiag(t, diags, w)
			}
		})
	}
}

func TestParseStructure(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"empty file", "", "empty policy file"},
		{"comment only", "# nothing\n", "empty policy file"},
		{"top level list", "- id: x\n", "top level must be a mapping"},
		{"unknown top level key", "policies: []\nversion: 2\n", `unknown top-level field "version"`},
		{"missing policies", "rules: []\n", "missing `policies` list"},
		{"policies not a list", "policies: {id: x}\n", "`policies` must be a list"},
		{"entry not a mapping", "policies:\n  - just-a-string\n", "each policy must be a mapping"},
		{"multiple documents", "policies: []\n---\npolicies: []\n", "multiple YAML documents"},
		{"syntax error", "policies:\n  - id: [x\n", "invalid YAML"},
		{"anchors", "policies:\n  - &a {id: x, phase: bot, expr: 'true', action: log}\n  - *a\n", "anchors, aliases and merge keys"},
		{"duplicate field", "policies:\n  - id: x\n    phase: bot\n    phase: custom\n    expr: 'true'\n    action: log\n", `rule "x": phase: duplicate field`},
		{"nested params", "policies:\n  - {id: x, phase: bot, expr: 'true', action: log, params: {a: {b: c}}}\n", "params.a: must be a scalar value, not a mapping"},
		{"bad param key", "policies:\n  - {id: x, phase: bot, expr: 'true', action: log, params: {Bad-Key: 1}}\n", `key "Bad-Key" must match`},
		{"null expr", "policies:\n  - {id: x, phase: bot, expr: , action: log}\n", `rule "x": expr: must not be empty`},
		{"list as action", "policies:\n  - {id: x, phase: bot, expr: 'true', action: [block]}\n", "action: must be a scalar value, not a list"},
		{"quoted rollout", "policies:\n  - {id: x, phase: bot, expr: 'true', action: log, rollout: '50'}\n", `rollout: must be a decimal integer, got "50"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := checkSource(t, Options{}, tc.src)
			if !diags.HasErrors() {
				t.Fatalf("expected an error containing %q, got %v", tc.want, diagStrings(diags))
			}
			requireDiag(t, diags, tc.want)
		})
	}
}

func TestDefaultsAndFields(t *testing.T) {
	src := `policies:
  - id: minimal
    phase: bot
    expr: risk.score > 90
    action: block
  - id: full
    phase: custom
    priority: -3
    expr: req.path == "/x"
    action: challenge
    params: { type: pow, difficulty: 18 }
    mode: dry_run
    rollout: 5
    temporary: true
    expires_at: 2027-01-02T03:04:05+08:00
    locked: true
    owner: me
    description: d
`
	checked, diags := checkSource(t, Options{}, src)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diagStrings(diags))
	}
	min, full := checked[0], checked[1]
	if min.Mode != "enforce" || min.Rollout != 100 || min.Priority != 0 || min.Locked || min.Temporary {
		t.Errorf("defaults not applied: %+v", min.Rule)
	}
	want := time.Date(2027, 1, 1, 19, 4, 5, 0, time.UTC)
	if full.ExpiresAt == nil || !full.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, want %v", full.ExpiresAt, want)
	}
	if full.Priority != -3 || full.Mode != "dry_run" || full.Rollout != 5 || !full.Locked ||
		full.Owner != "me" || full.Description != "d" ||
		!reflect.DeepEqual(full.Params, map[string]string{"type": "pow", "difficulty": "18"}) {
		t.Errorf("fields not parsed: %+v", full.Rule)
	}
}

func TestExprPositions(t *testing.T) {
	cases := []struct {
		name, expr, want string
	}{
		{"plain", "expr: risk.scor > 1", `test.yaml:4:15: error: rule "p": expr: undefined field 'scor'`},
		{"double quoted", `expr: "risk.scor > 1"`, `test.yaml:4:16: error: rule "p": expr: undefined field 'scor'`},
		{"block", "expr: >\n      risk.score > 1\n      && nope", `test.yaml:5: error: rule "p": expr: undeclared reference to 'nope'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "policies:\n  - id: p\n    phase: bot\n    " + tc.expr + "\n    action: log\n"
			_, diags := checkSource(t, Options{}, src)
			requireDiag(t, diags, tc.want)
			if tc.name == "block" {
				requireDiag(t, diags, "(at expr 1:")
			}
		})
	}
}

func TestSemanticWarnings(t *testing.T) {
	src := `policies:
  - {id: old, phase: bot, expr: 'true', action: log, temporary: true, expires_at: 2020-01-01T00:00:00Z}
  - {id: zero, phase: bot, expr: 'true', action: log, rollout: 0}
`
	_, diags := checkSource(t, Options{}, src)
	if diags.HasErrors() {
		t.Fatalf("unexpected errors: %v", diagStrings(diags))
	}
	requireDiag(t, diags, `warning: rule "old": expires_at: rule expired at 2020-01-01T00:00:00Z`)
	requireDiag(t, diags, `warning: rule "zero": rollout: rollout 0 means the rule never applies`)
}

// rulesWithDiags returns the ids of the rules that have a diagnostic containing sub.
func rulesWithDiags(ds Diagnostics, sub string) []string {
	var ids []string
	for _, d := range ds {
		if strings.Contains(d.String(), sub) && !slices.Contains(ids, d.RuleID) {
			ids = append(ids, d.RuleID)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestMissingFieldWarnings(t *testing.T) {
	const rules = `policies:
  - {id: ja4, phase: bot, expr: 'tls.ja4.value == "x"', action: log}
  - {id: tls-version, phase: bot, expr: 'tls.version == "TLSv1.0"', action: log}
  - {id: order, phase: bot, expr: 'size(http.header_order) == 0', action: log}
  - {id: edge, phase: bot, expr: 'edge_tls.hello_len > 0 && edge_tls.ext_sha1 != ""', action: log}
  - {id: vbot-cat, phase: bot, expr: 'identity.crawler.cf_vbot_cat == "Search Engine Crawler"', action: tag}
  - {id: ja4-guarded, phase: bot, expr: 'has(tls.ja4) && tls.ja4.value == "x"', action: log}
  - {id: ja4-guard-after, phase: bot, expr: 'tls.ja4.value == "x" && has(tls.ja4.value)', action: log}
  - {id: order-negated-guard, phase: bot, expr: '!has(http.header_order) || size(http.header_order) == 0', action: log}
  - {id: docs-fallback, phase: bot, expr: 'has(tls.ja4) ? tls.ja4.value in list("bad_ja4") : edge_tls.ciphers_sha1 in list("bad_cf_ciphers")', action: log}
  - {id: wrong-guard, phase: bot, expr: 'has(tls.ja4) && tls.version == "TLSv1.0"', action: log}
  - {id: has-only, phase: bot, expr: '!has(tls.ja4)', action: log}
`
	missing := "is always MISSING under the"

	t.Run("no profile: no check", func(t *testing.T) {
		_, diags := checkSource(t, Options{}, rules)
		if len(diags) != 0 {
			t.Fatalf("diagnostics without a profile: %v", diagStrings(diags))
		}
	})

	t.Run("declared cloudflare", func(t *testing.T) {
		_, diags := checkSource(t, Options{}, "profile: cloudflare\n"+rules)
		if diags.HasErrors() {
			t.Fatalf("errors: %v", diagStrings(diags))
		}
		want := []string{"ja4", "order", "tls-version", "wrong-guard"}
		if got := rulesWithDiags(diags, missing); !slices.Equal(got, want) {
			t.Errorf("warned rules = %v, want %v\n  %s", got, want, strings.Join(diagStrings(diags), "\n  "))
		}
		requireDiag(t, diags, `test.yaml:3:34: warning: rule "ja4": expr: tls.ja4.value is always MISSING under the cloudflare profile`)
		requireDiag(t, diags, `guard them with has(tls.ja4)`)
		requireDiag(t, diags, `rule "order": expr: http.header_order is always MISSING under the cloudflare profile (Cloudflare does not preserve header order); comparisons on it evaluate to unknown, guard them with has(http.header_order)`)
		for _, d := range diags {
			if d.Severity != SeverityWarning {
				t.Errorf("not a warning: %s", d)
			}
		}
	})

	t.Run("declared direct_tls", func(t *testing.T) {
		_, diags := checkSource(t, Options{}, "profile: direct_tls\n"+rules)
		want := []string{"docs-fallback", "edge", "vbot-cat"}
		if got := rulesWithDiags(diags, missing); !slices.Equal(got, want) {
			t.Errorf("warned rules = %v, want %v\n  %s", got, want, strings.Join(diagStrings(diags), "\n  "))
		}
		requireDiag(t, diags, `rule "edge": expr: edge_tls.ext_sha1 is always MISSING under the direct_tls profile`)
		requireDiag(t, diags, `rule "edge": expr: edge_tls.hello_len is always MISSING under the direct_tls profile`)
		requireDiag(t, diags, `rule "vbot-cat": expr: identity.crawler.cf_vbot_cat is always MISSING under the direct_tls profile`)
	})

	t.Run("compiler default applies to files without profile", func(t *testing.T) {
		_, diags := checkSource(t, Options{Profile: "cloudflare"}, rules)
		if got := rulesWithDiags(diags, missing); len(got) != 4 {
			t.Errorf("warned rules = %v", got)
		}
		_, diags = checkSource(t, Options{Profile: "cloudflare"}, "profile: direct_tls\n"+rules)
		requireDiag(t, diags, `test.yaml:1:1: error: profile: file declares profile "direct_tls" but the check was requested for "cloudflare"`)
		if n := len(diags.Errors()); n != 1 {
			t.Errorf("want the conflict reported once per file, got %d errors", n)
		}
	})

	t.Run("profile values", func(t *testing.T) {
		_, diags := checkSource(t, Options{}, "profile: cloudfront\n"+rules)
		if diags.HasErrors() {
			t.Fatalf("errors: %v", diagStrings(diags))
		}
		requireDiag(t, diags, `test.yaml:1:10: warning: profile: no field-availability table for profile "cloudfront" yet`)
		if got := rulesWithDiags(diags, missing); len(got) != 0 {
			t.Errorf("unchecked profile produced MISSING warnings for %v", got)
		}
		for src, want := range map[string]string{
			"profile: akamai\n" + rules:                          `test.yaml:1:10: error: profile: "akamai" is not one of direct_tls, cloudflare, proxy_protocol,`,
			"profile:\n" + rules:                                 `test.yaml:1:9: error: profile: must be a non-empty string`,
			"profile: [cloudflare]\n" + rules:                    `error: profile: must be a non-empty string`,
			"profile: cloudflare\nprofile: direct_tls\n" + rules: "test.yaml:2:1: error: duplicate key `profile`",
		} {
			_, diags := checkSource(t, Options{}, src)
			requireDiag(t, diags, want)
		}
	})

	t.Run("compiler options", func(t *testing.T) {
		if _, err := NewCompiler(Options{Profile: "akamai"}); err == nil || !strings.Contains(err.Error(), `unknown upstream profile "akamai"`) {
			t.Errorf("unknown profile: err = %v", err)
		}
		if _, err := NewCompiler(Options{Profile: "cloudfront"}); err == nil || !strings.Contains(err.Error(), "no field-availability table") {
			t.Errorf("unchecked profile: err = %v", err)
		}
	})
}

func TestCloudflareVerifiedBotWarning(t *testing.T) {
	src := `policies:
  - {id: vbot-allow, phase: identity, expr: 'identity.crawler.cf_vbot', action: allow}
  - {id: vbot-block, phase: identity, expr: '!identity.crawler.cf_vbot && req.headers["user-agent"].contains("Googlebot")', action: block}
  - {id: vbot-cat-allow, phase: identity, expr: 'identity.crawler.cf_vbot_cat == "Search Engine Crawler"', action: allow}
  - {id: vbot-guard-only, phase: identity, expr: 'has(identity.crawler.cf_vbot) && route.name == "feed"', action: allow}
  - {id: negated-verification, phase: identity, expr: 'identity.crawler.cf_vbot && !identity.crawler.verified', action: allow}
  - {id: verification-in-or, phase: identity, expr: 'identity.crawler.verified || identity.crawler.cf_vbot', action: allow}
  - {id: corroborated, phase: identity, expr: 'identity.crawler.cf_vbot && identity.crawler.verified', action: allow}
  - {id: corroborated-eq, phase: identity, expr: 'identity.crawler.verified == true && identity.crawler.cf_vbot_cat != ""', action: allow}
  - {id: class-decides, phase: identity, expr: 'risk.class == "IMPERSONATOR" && !identity.crawler.cf_vbot', action: block}
  - {id: class-decides-reversed, phase: identity, expr: '"VERIFIED_CRAWLER" == risk.class && identity.crawler.cf_vbot', action: allow}
  - {id: not-allow-or-block, phase: identity, expr: 'identity.crawler.cf_vbot', action: tag}
`
	want := []string{"negated-verification", "vbot-allow", "vbot-block", "vbot-cat-allow", "vbot-guard-only", "verification-in-or"}
	for _, opts := range []Options{{}, {Profile: "cloudflare"}} {
		_, diags := checkSource(t, opts, src)
		if diags.HasErrors() {
			t.Fatalf("errors: %v", diagStrings(diags))
		}
		if got := rulesWithDiags(diags, "Cloudflare corroboration only"); !slices.Equal(got, want) {
			t.Errorf("profile %q: warned rules = %v, want %v\n  %s", opts.Profile, got, want, strings.Join(diagStrings(diags), "\n  "))
		}
	}
	_, diags := checkSource(t, Options{}, src)
	requireDiag(t, diags, `test.yaml:2:46: warning: rule "vbot-allow": expr: allow decision depends on identity.crawler.cf_vbot, which is Cloudflare corroboration only; add identity.crawler.verified or a risk.class == "..." check as a top-level && condition`)
	requireDiag(t, diags, `rule "vbot-block": expr: block decision depends on identity.crawler.cf_vbot, which`)
	requireDiag(t, diags, `rule "vbot-cat-allow": expr: allow decision depends on identity.crawler.cf_vbot_cat, which`)
}

func TestContextFieldNames(t *testing.T) {
	ok := `policies:
  - {id: f, phase: bot, expr: 'edge_tls.ext_sha1 != "" && upstream.auth_method == "loopback" && identity.crawler.cf_vbot_cat != ""', action: log}
`
	if _, diags := checkSource(t, Options{}, ok); len(diags) != 0 {
		t.Errorf("docs/06 §2 fields rejected: %v", diagStrings(diags))
	}
	for field, want := range map[string]string{
		"edge_tls.extensions_sha1": "undefined field 'extensions_sha1'",
		"http.h2_fp":               "undefined field 'h2_fp'",
	} {
		src := "policies:\n  - {id: f, phase: bot, expr: '" + field + ` != ""', action: log}` + "\n"
		_, diags := checkSource(t, Options{}, src)
		requireDiag(t, diags, want)
	}
}

func TestCostLimit(t *testing.T) {
	src := `policies:
  - {id: big, phase: identity, expr: 'ip_in(net.ip, list("owner_cidrs"))', action: allow}
`
	checked, diags := checkSource(t, Options{}, src)
	if diags.HasErrors() {
		t.Fatalf("default budget rejected a named-list lookup: %v", diagStrings(diags))
	}
	if c := checked[0].Cost; c.Max < MaxNamedListEntries || c.Min == 0 {
		t.Errorf("cost %+v does not account for the named list", c)
	}
	_, diags = checkSource(t, Options{MaxCost: 1000}, src)
	requireDiag(t, diags, `rule "big": expr: estimated worst-case cost`)
}

// TestReferencedLists: CheckedRule.Lists names every list("...") the
// expression uses, sorted and unique (docs/impl/phase1-spec.md §8.2).
func TestReferencedLists(t *testing.T) {
	src := `policies:
  - {id: l, phase: bot, expr: 'ip_in(net.ip, list("zeta")) || req.host in list("alpha") || ip_in(net.ip, list("zeta"))', action: log}
  - {id: n, phase: bot, expr: 'net.tor', action: log}
`
	checked, diags := checkSource(t, Options{}, src)
	if diags.HasErrors() || len(checked) != 2 {
		t.Fatalf("unexpected diagnostics: %v", diagStrings(diags))
	}
	if got := checked[0].Lists; !slices.Equal(got, []string{"alpha", "zeta"}) {
		t.Errorf("Lists = %q, want [alpha zeta]", got)
	}
	if got := checked[1].Lists; len(got) != 0 {
		t.Errorf("Lists = %q, want none", got)
	}
}

func TestReferencedFields(t *testing.T) {
	src := `policies:
  - {id: f, phase: bot, expr: 'tls.ja4.value != "" && "x" in labels && rate["a"] > 0.5 && [1].all(v, v > 0)', action: log}
  - {id: g, phase: bot, expr: 'has(tls.ja4) && has(identity.crawler.cf_vbot) && net.tor', action: log}
`
	checked, diags := checkSource(t, Options{}, src)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diagStrings(diags))
	}
	for i, want := range [][]string{
		{"labels", "rate", "tls.ja4.value"},
		{"identity.crawler.cf_vbot", "net.tor", "tls.ja4"}, // has() tests are listed too
	} {
		if !slices.Equal(checked[i].Fields, want) {
			t.Errorf("%s: fields = %v, want %v", checked[i].ID, checked[i].Fields, want)
		}
	}
}

func TestDocsExamplesEvaluate(t *testing.T) {
	checked, diags := checkFiles(t, "../../testdata/policies/valid/docs06-examples.yaml")
	if diags.HasErrors() {
		t.Fatalf("diagnostics: %v", diagStrings(diags))
	}
	byID := map[string]*CheckedRule{}
	for _, cr := range checked {
		byID[cr.ID] = cr
	}
	ev, err := NewEvaluator(map[string][]string{"owner_cidrs": {"203.0.113.0/24", "2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	staging := func(mut func(*Input)) *Input {
		in := &Input{
			Net:   Net{IP: "198.51.100.7"},
			Risk:  Risk{Class: "AUTOMATION_LIKELY", Score: 10},
			Route: Route{Env: "staging", Name: "home"},
		}
		if mut != nil {
			mut(in)
		}
		return in
	}
	cases := []struct {
		rule string
		in   *Input
		want bool
	}{
		{"test-env-default-deny", staging(nil), true},
		{"test-env-default-deny", staging(func(in *Input) { in.Net.IP = "203.0.113.9" }), false},
		{"test-env-default-deny", staging(func(in *Input) { in.Net.IP = "::ffff:203.0.113.9" }), false},
		{"test-env-default-deny", staging(func(in *Input) { in.Risk.Class = "AUTHORIZED_AGENT" }), false},
		{"test-env-default-deny", staging(func(in *Input) { in.Route.Env = "production" }), false},
		// Phase 0 has(): an empty IP counts as unavailable, so the rule does not need the list.
		{"test-env-default-deny", staging(func(in *Input) { in.Net.IP = "" }), true},
		{"block-impersonators", staging(func(in *Input) { in.Risk.Class = "IMPERSONATOR" }), true},
		{"block-impersonators", staging(nil), false},
		{"deny-ai-training-crawlers", staging(func(in *Input) {
			in.Identity.Crawler = Crawler{Verified: true, Purpose: "ai_training"}
		}), true},
		{"deny-ai-training-crawlers", staging(func(in *Input) {
			in.Identity.Crawler = Crawler{Verified: false, Purpose: "ai_training"}
		}), false},
		{"scanner-block", staging(func(in *Input) { in.Labels = []string{"delegated", "scanner"} }), true},
		{"scanner-block", staging(nil), false},
		{"login-require-proof", staging(func(in *Input) { in.Route.Name = "login" }), true},
		{"login-require-proof", staging(func(in *Input) { in.Route.Name = "login"; in.Identity.Proof.Valid = true }), false},
		{"login-high-risk", staging(func(in *Input) { in.Route.Name = "login"; in.Risk.Score = 60 }), true},
		{"login-high-risk", staging(func(in *Input) { in.Route.Name = "login"; in.Risk.Score = 59 }), false},
	}
	for _, tc := range cases {
		got, err := ev.Eval(byID[tc.rule], tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s on %+v = %v, want %v", tc.rule, tc.in, got, tc.want)
		}
	}

	// A missing named list is an evaluation error, never a silent false.
	noLists, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noLists.Eval(byID["test-env-default-deny"], staging(nil)); err == nil {
		t.Error("expected an error for an unknown named list")
	}
}

func TestHasFallbackEvaluates(t *testing.T) {
	checked, diags := checkFiles(t, "../../testdata/policies/valid/cloudflare-site.yaml")
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diagStrings(diags))
	}
	var rule *CheckedRule
	for _, cr := range checked {
		if cr.ID == "bad-tls-fingerprints" {
			rule = cr
		}
		if cr.Profile != "cloudflare" {
			t.Errorf("%s: profile = %q, want cloudflare", cr.ID, cr.Profile)
		}
	}
	ev, err := NewEvaluator(map[string][]string{"bad_ja4": {"t13d_bad"}, "bad_cf_ciphers": {"cf_bad"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{"cloudflare, bad cipher list", Input{EdgeTLS: EdgeTLS{CiphersSHA1: "cf_bad"}}, true},
		{"cloudflare, fine cipher list", Input{EdgeTLS: EdgeTLS{CiphersSHA1: "cf_ok"}}, false},
		{"direct_tls, bad JA4", Input{TLS: TLS{JA4: JA4{Value: "t13d_bad", Source: "self", Authenticated: true}}}, true},
		{"direct_tls, JA4 wins over edge_tls", Input{TLS: TLS{JA4: JA4{Value: "t13d_ok"}}, EdgeTLS: EdgeTLS{CiphersSHA1: "cf_bad"}}, false},
	}
	for _, tc := range cases {
		got, err := ev.Eval(rule, &tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}

func TestProtoMapping(t *testing.T) {
	for _, a := range Actions {
		if ActionEnum(a) == morphgatev1.Action_ACTION_UNSPECIFIED {
			t.Errorf("action %q has no morphgate.v1.Action value", a)
		}
	}
	for _, c := range ChallengeTypes {
		if ChallengeTypeEnum(c) == morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED {
			t.Errorf("challenge type %q has no morphgate.v1.ChallengeType value", c)
		}
	}
	if len(Actions) != len(morphgatev1.Action_name)-1 {
		t.Errorf("policy actions %v do not cover morphgate.v1.Action", Actions)
	}

	checked, diags := checkFiles(t, "../../testdata/policies/valid/all-fields.yaml")
	if diags.HasErrors() {
		t.Fatalf("diagnostics: %v", diagStrings(diags))
	}
	for _, cr := range checked {
		pb := cr.Proto()
		if pb.GetId() != cr.ID || pb.GetIrVersion() != 0 || len(pb.GetExprIr()) != 0 ||
			pb.GetAction() != ActionEnum(cr.Action) || pb.GetRolloutPercent() != uint32(cr.Rollout) {
			t.Errorf("proto mismatch for %s: %v", cr.ID, pb)
		}
		if cr.ID == "maintenance-window-tarpit" && pb.GetExpiresAtMs() != time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli() {
			t.Errorf("expires_at_ms = %d", pb.GetExpiresAtMs())
		}
	}
}

func TestNamespacesMatchDocs(t *testing.T) {
	want := []string{"req", "net", "upstream", "tls", "http", "edge_tls", "identity", "risk", "route", "rate", "labels"}
	if got := Namespaces(); !slices.Equal(got, want) {
		t.Errorf("Namespaces() = %v, want %v", got, want)
	}
}

func TestParseFileErrors(t *testing.T) {
	_, diags := ParseFile(filepath.Join(t.TempDir(), "missing.yaml"))
	if !diags.HasErrors() {
		t.Error("missing file did not produce an error")
	}
	big := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(big, make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, diags = ParseFile(big)
	requireDiag(t, diags, "larger than 1 MiB")
}
