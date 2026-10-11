package sitecfg

import (
	"slices"
	"strings"
	"testing"
)

const phase2YAML = "../../testdata/sites/golden/site-phase2.yaml"

func warningsOf(ds []Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Severity == SeverityWarning {
			out = append(out, d.String())
		}
	}
	return out
}

func mutate(t *testing.T, base, old, new string) []Diagnostic {
	t.Helper()
	y := read(t, base)
	if !strings.Contains(y, old) {
		t.Fatalf("test bug: %q not in %s", old, base)
	}
	_, diags := Parse("site.yaml", []byte(strings.Replace(y, old, new, 1)))
	return diags
}

func containsAny(list []string, sub string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(s, sub) })
}

func TestPhase2SiteValues(t *testing.T) {
	s, diags, err := Load(phase2YAML)
	if err != nil || HasErrors(diags) {
		t.Fatalf("%v %v", err, diags)
	}
	if s.SchemaVersion() != 2 || !slices.Contains(s.Phase2Keys, "providers") || !slices.Contains(s.Phase2Keys, "challenge.interactive") ||
		!slices.Contains(s.Phase2Keys, "environments[production].rate_limits[1].on_exceed.type") {
		t.Errorf("Phase 2 keys %v", s.Phase2Keys)
	}
	ix := s.Challenge.Interactive
	if !ix.Enabled || ix.PowBits != (PowBits{13, 15, 17, 19}) || ix.PowK != 6 || ix.A11yBits != 18 || ix.EscalateAfter != 3 ||
		ix.ScoringMode != "enforce" || ix.TPass != 0.4 || ix.TBlock != 0.8 || ix.MinPowMS != 250 || ix.A11yMinMS != 2500 ||
		ix.Issue != (Rate{40, 600, 25}) || ix.Renew != (Rate{20, 300, 8}) || ix.A11yIssue != (A11yIssue{5, 100, 1800}) {
		t.Errorf("interactive %+v", ix)
	}
	p := s.Providers[0]
	if p.ID != "turnstile" || !p.Enabled || p.Sitekey != "0x4AAAAAAAkat-test-sitekey" || !slices.Equal(p.Routes, []string{"login", "signup"}) ||
		p.Selection != "escalate_after_fail" || p.Mode != "shadow" || p.TimeoutMS != 3500 || p.Fallback != "self_hold" || !slices.Equal(p.DenyCountries, []string{"CN"}) {
		t.Errorf("provider %+v", p)
	}
	routes := s.Environments[0].Routes
	if routes[0].MinLevel != "interactive" || routes[1].Proof != "off" || routes[2].Proof != "required" || routes[2].MinLevel != "invisible" || routes[3].Proof != "off" {
		t.Errorf("routes %+v", routes)
	}
	// Two expected warnings: the enforce reminder and the privacy notice.
	if w := warningsOf(diags); len(w) != 2 || !containsAny(w, "t_pass must be above") || !containsAny(w, "privacy notice") {
		t.Errorf("warnings %v", w)
	}
	// Provider defaults.
	y := strings.Replace(read(t, phase2YAML), `    enabled: true
    sitekey: 0x4AAAAAAAkat-test-sitekey
    hostnames: [example.com, www.example.com]
    routes: [login, signup]
    selection: escalate_after_fail
    mode: shadow
    timeout_ms: 3500
    fallback: self_hold
    deny_countries: [CN]
`, "    sitekey: k\n    hostnames: [example.com]\n", 1)
	s, diags = Parse("x.yaml", []byte(y))
	if HasErrors(diags) {
		t.Fatal(diags)
	}
	want := Provider{ID: "turnstile", Enabled: true, Sitekey: "k", Hostnames: []string{"example.com"}, Selection: "escalate_after_fail",
		Mode: "shadow", TimeoutMS: 4000, Fallback: "self_hold"}
	if got := s.Providers[0]; got.ID != want.ID || got.Enabled != want.Enabled || got.Selection != want.Selection || got.Mode != want.Mode ||
		got.TimeoutMS != want.TimeoutMS || got.Fallback != want.Fallback || len(got.Routes) != 0 || len(got.DenyCountries) != 0 {
		t.Errorf("provider defaults %+v", got)
	}
}

// §10.2 and §8.2 validation: every error has a counterexample.
func TestPhase2ValidationRules(t *testing.T) {
	cases := []mutation{
		// clearance.
		{"ttl_interactive_s low", phase2YAML, "ttl_interactive_s: 2400", "ttl_interactive_s: 299", "clearance.ttl_interactive_s: must be between 300 and 7200"},
		{"ttl_interactive_s high", phase2YAML, "ttl_interactive_s: 2400", "ttl_interactive_s: 7201", "clearance.ttl_interactive_s: must be between 300 and 7200"},
		{"ttl_interactive_a11y_s high", phase2YAML, "ttl_interactive_a11y_s: 600", "ttl_interactive_a11y_s: 3601", "must be between 300 and 3600"},
		{"ttl_interactive_ext_s low", phase2YAML, "ttl_interactive_ext_s: 1500", "ttl_interactive_ext_s: 200", "must be between 300 and 7200"},
		{"refresh not bool", phase2YAML, "refresh: true", "refresh: 1", "clearance.refresh: must be true or false"},
		{"refresh_max_interactive_s low", phase2YAML, "refresh_max_interactive_s: 10800", "refresh_max_interactive_s: 899", "must be between 900 and 86400"},
		{"refresh_max_ext_s high", phase2YAML, "refresh_max_ext_s: 5400", "refresh_max_ext_s: 86401", "must be between 900 and 86400"},
		{"refresh_max_pow_s high", phase2YAML, "refresh_max_pow_s: 1800", "refresh_max_pow_s: 86401", "must be between 0 and 86400"},
		// challenge.
		{"default_lang", phase2YAML, "default_lang: en", "default_lang: de", `"de" is not one of zh-CN, en`},
		{"help_path off-site", phase2YAML, "help_path: /help/verification", "help_path: //evil.example", "challenge.help_path"},
		{"help_path reserved", phase2YAML, "help_path: /help/verification", "help_path: /__mg/v", "reserved /__mg/ namespace"},
		{"privacy_path relative", phase2YAML, "privacy_path: /privacy?section=verification", "privacy_path: privacy", "challenge.privacy_path: \"privacy\" must start with /"},
		{"privacy_path fragment", phase2YAML, "privacy_path: /privacy?section=verification", "privacy_path: '/privacy#x'", `must not contain \ or #`},
		{"interactive unknown key", phase2YAML, "    pow_k: 6", "    pow_k: 6\n    k: 6", `challenge.interactive: unknown key "k"`},
		{"pow_bits 23", phase2YAML, "very_high: 19}\n    pow_k", "very_high: 23}\n    pow_k", "challenge.interactive.pow_bits.very_high: must be between 8 and 22"},
		{"pow_bits 7", phase2YAML, "{low: 13,", "{low: 7,", "challenge.interactive.pow_bits.low: must be between 8 and 22"},
		{"pow_bits decreasing", phase2YAML, "{low: 13, medium: 15,", "{low: 16, medium: 15,", "must not decrease with the risk band"},
		{"pow_k 0", phase2YAML, "pow_k: 6", "pow_k: 0", "pow_k: must be between 1 and 8"},
		{"pow_k 9", phase2YAML, "pow_k: 6", "pow_k: 9", "pow_k: must be between 1 and 8"},
		{"a11y_bits 11", phase2YAML, "a11y_bits: 18", "a11y_bits: 11", "a11y_bits: must be between 12 and 24"},
		{"a11y_bits 25", phase2YAML, "a11y_bits: 18", "a11y_bits: 25", "a11y_bits: must be between 12 and 24"},
		{"escalate_after 0", phase2YAML, "escalate_after: 3", "escalate_after: 0", "escalate_after: must be between 1 and 5"},
		{"escalate_after 6", phase2YAML, "escalate_after: 3", "escalate_after: 6", "escalate_after: must be between 1 and 5"},
		{"scoring mode unknown", phase2YAML, "{mode: enforce, t_pass: 0.4, t_block: 0.8}", "{mode: block}", `"block" is not one of shadow, enforce`},
		{"scoring mode missing", phase2YAML, "{mode: enforce, t_pass: 0.4, t_block: 0.8}", "{t_pass: 0.4}", "scoring.mode: required"},
		{"enforce without thresholds", phase2YAML, "{mode: enforce, t_pass: 0.4, t_block: 0.8}", "{mode: enforce}", "mode enforce requires t_pass and t_block"},
		{"enforce t_pass 0", phase2YAML, "t_pass: 0.4,", "t_pass: 0,", "need 0 < t_pass < t_block <= 1"},
		{"enforce t_pass = t_block", phase2YAML, "t_pass: 0.4,", "t_pass: 0.8,", "need 0 < t_pass < t_block <= 1"},
		{"enforce t_block > 1", phase2YAML, "t_block: 0.8}", "t_block: 1.2}", "t_block: must be between 0 and 1"},
		{"shadow with thresholds", phase2YAML, "{mode: enforce, t_pass: 0.4, t_block: 0.8}", "{mode: shadow, t_pass: 0.4}", "t_pass: only with mode: enforce"},
		{"min_pow_ms high", phase2YAML, "min_pow_ms: 250", "min_pow_ms: 5001", "min_pow_ms: must be between 0 and 5000"},
		{"a11y_min_ms high", phase2YAML, "a11y_min_ms: 2500", "a11y_min_ms: 10001", "a11y_min_ms: must be between 0 and 10000"},
		{"issue rate syntax", phase2YAML, "issue: {rate: 40/10m", "issue: {rate: 40 per 10m", "is not <n>/<duration>"},
		{"issue burst 0", phase2YAML, "burst: 25}", "burst: 0}", "challenge.interactive.issue.burst: must be between 1 and 100000"},
		{"issue unknown key", phase2YAML, "issue: {rate: 40/10m, burst: 25}", "issue: {rate: 40/10m, burst: 25, scope: ip}", `challenge.interactive.issue: unknown key "scope"`},
		{"renew gcra", phase2YAML, "renew: {rate: 20/5m, burst: 8}", "renew: {rate: 1/24h, burst: 100}", "challenge.interactive.renew: 1 per 86400 s with burst 100 is not a valid GCRA limiter"},
		{"renew ipp gcra", phase2YAML, "renew: {rate: 20/5m, burst: 8}", "renew: {rate: 400000/1s, burst: 8}", "challenge.interactive.renew (ipp, 4x)"},
		{"a11y per_ipp below per_ip", phase2YAML, "per_ip: 5, per_ipp: 100", "per_ip: 5, per_ipp: 4", "per_ipp 4 must be at least per_ip 5"},
		{"a11y per_ip 0", phase2YAML, "per_ip: 5,", "per_ip: 0,", "a11y_issue.per_ip: must be between 1 and 100000"},
		{"a11y period 0", phase2YAML, "period_s: 1800}", "period_s: 0}", "a11y_issue.period_s: must be between 1 and 86400"},
		// events.
		{"telemetry_behavior not bool", phase2YAML, "telemetry_behavior: true", "telemetry_behavior: yes", "events.telemetry_behavior: must be true or false"},
		{"scanner bait relative", phase2YAML, `"/old-admin/**"`, `"old-admin/**"`, "must start with /"},
		{"scanner bait wildcards", phase2YAML, `"/old-admin/**"`, `"/*/?/**/x*/y?"`, "5 wildcards, at most 4"},
		{"scanner bait duplicate", phase2YAML, `"/old-admin/**"`, `"/.env*"`, `duplicate entry "/.env*"`},
		{"scanner baits unknown key", phase2YAML, "{builtin: false,", "{builtins: false,", `events.scanner_baits: unknown key "builtins"`},
		// routes.
		{"proof unknown", phase2YAML, "proof: required", "proof: optional", `"optional" is not one of off, required`},
		{"min_level unknown", phase2YAML, "min_level: invisible", "min_level: attestation", `"attestation" is not one of invisible, pow, interactive`},
		{"proof with never_challenge", phase2YAML, "        proof: required\n", "        proof: required\n        never_challenge: true\n", "proof required contradicts never_challenge"},
		{"min_level with never_challenge", phase2YAML, "        min_level: invisible\n", "        min_level: invisible\n        never_challenge: true\n", "min_level: contradicts never_challenge"},
		// providers (§8.2).
		{"two providers", phase2YAML, "providers:\n", "providers:\n  - {id: turnstile, sitekey: k, hostnames: [example.com]}\n", "providers: 2 entries, at most 1"},
		{"provider self_hold", phase2YAML, "  - id: turnstile", "  - id: self_hold", `"self_hold" is built in`},
		{"provider tencent", phase2YAML, "  - id: turnstile", "  - id: tencent", `"tencent" is not available in Phase 2`},
		{"provider sitekey", phase2YAML, "sitekey: 0x4AAAAAAAkat-test-sitekey", "sitekey: 'bad key'", `"bad key" does not match`},
		{"provider sitekey long", phase2YAML, "sitekey: 0x4AAAAAAAkat-test-sitekey", "sitekey: " + strings.Repeat("a", 65), "does not match"},
		{"provider no sitekey", phase2YAML, "    sitekey: 0x4AAAAAAAkat-test-sitekey\n", "", "providers[0].sitekey: required"},
		{"provider hostnames empty", phase2YAML, "hostnames: [example.com, www.example.com]\n    routes", "hostnames: []\n    routes", "must list at least one host name"},
		{"provider hostname not a site host", phase2YAML, "hostnames: [example.com, www.example.com]\n    routes", "hostnames: [example.com, shop.example.net]\n    routes", `"shop.example.net" is not one of the site's hosts`},
		{"provider unknown route", phase2YAML, "routes: [login, signup]", "routes: [login, checkout]", `no route "checkout" in any environment`},
		{"provider selection", phase2YAML, "selection: escalate_after_fail", "selection: always", `"always" is not one of first, escalate_after_fail`},
		{"provider mode", phase2YAML, "    mode: shadow\n    timeout_ms", "    mode: monitor\n    timeout_ms", `"monitor" is not one of shadow, enforce`},
		{"provider timeout low", phase2YAML, "timeout_ms: 3500", "timeout_ms: 999", "timeout_ms: must be between 1000 and 5000"},
		{"provider timeout high", phase2YAML, "timeout_ms: 3500", "timeout_ms: 5001", "timeout_ms: must be between 1000 and 5000"},
		{"provider fail_closed", phase2YAML, "fallback: self_hold", "fallback: fail_closed", "the only fallback is self_hold"},
		{"provider fail open", phase2YAML, "fallback: self_hold", "fallback: fail_open_with_signal", "fail-open is never allowed (D-51)"},
		{"provider lower-case country", phase2YAML, "deny_countries: [CN]", "deny_countries: [cn]", `"cn" is not an upper-case ISO 3166-1 alpha-2 code`},
		{"provider duplicate country", phase2YAML, "deny_countries: [CN]", "deny_countries: [CN, CN]", `duplicate entry "CN"`},
		{"provider secret in yaml", phase2YAML, "    fallback: self_hold\n", "    fallback: self_hold\n    secret_refs: [x]\n", `unknown key "secret_refs"`},
		{"provider allowed_countries", phase2YAML, "    fallback: self_hold\n", "    fallback: self_hold\n    allowed_countries: [US]\n", `unknown key "allowed_countries"`},
		{"providers not a list", phase2YAML, "providers:\n  - id: turnstile", "providers: turnstile\nold_providers:\n  - id: turnstile", "providers: must be a list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := errorsOf(mutate(t, tc.base, tc.old, tc.new))
			if !containsAny(errs, tc.want) {
				t.Errorf("want an error containing %q, got:\n%s", tc.want, strings.Join(errs, "\n"))
			}
		})
	}
}

// §10.2 warnings (and §4.2): each one fires in its situation and not otherwise.
func TestPhase2Warnings(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"min_level interactive while disabled", "    enabled: true\n    pow_bits", "    enabled: false\n    pow_bits", "min_level: interactive while challenge.interactive.enabled is false"},
		{"interactive limiter while disabled", "    enabled: true\n    pow_bits", "    enabled: false\n    pow_bits", "on_exceed type interactive while challenge.interactive.enabled is false"},
		{"proof on a web route with POST", "        channel: api\n        sensitivity: medium\n        proof: required", "        sensitivity: medium\n        proof: required", "form posts must be sent with MorphGate.fetch"},
		{"min_level interactive on a POST-only route", "        methods: [GET]\n        sensitivity: critical", "        methods: [POST]\n        sensitivity: critical", "min_level: interactive on a route with POST but not GET"},
		{"interactive limiter on POST-only routes", "        methods: [GET, HEAD]\n        sensitivity: high", "        methods: [POST]\n        sensitivity: high", "interactive challenge on routes with POST but not GET only"},
		{"deny_countries without a country source", "  location_headers: true\n", "  location_headers: false\n", "the country is always unknown, so Turnstile is never selected"},
	}
	_, base := Parse("site.yaml", []byte(read(t, phase2YAML)))
	baseWarnings := warningsOf(base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if containsAny(baseWarnings, tc.want) {
				t.Fatalf("the golden site already warns %q", tc.want)
			}
			diags := mutate(t, phase2YAML, tc.old, tc.new)
			if HasErrors(diags) {
				t.Fatalf("errors: %v", errorsOf(diags))
			}
			if w := warningsOf(diags); !containsAny(w, tc.want) {
				t.Errorf("want a warning containing %q, got:\n%s", tc.want, strings.Join(w, "\n"))
			}
		})
	}
	// Safe methods only: no MorphGate.fetch warning for a GET / HEAD web route.
	diags := mutate(t, phase2YAML, "        channel: api\n        sensitivity: medium\n        proof: required", "        methods: [GET, HEAD]\n        sensitivity: medium\n        proof: required")
	if containsAny(warningsOf(diags), "MorphGate.fetch") {
		t.Error("a GET / HEAD route needs no MorphGate.fetch warning")
	}
	// A geoip-country artifact is a country source too.
	diags = mutate(t, phase2YAML, "  location_headers: true\n", "  location_headers: false\n")
	if !containsAny(warningsOf(diags), "country is always unknown") {
		t.Fatal("no warning without a country source")
	}
	diags = mutate(t, phase2YAML, "    deny_countries: [CN]\n", "    deny_countries: []\n")
	if containsAny(warningsOf(diags), "country is always unknown") {
		t.Error("empty deny_countries needs no country source")
	}
}
