package sitecfg

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	fullYAML    = "../../testdata/sites/valid/full.yaml"
	minimalYAML = "../../testdata/sites/valid/minimal.yaml"
	invalidDir  = "../../testdata/sites/invalid"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func errorsOf(ds []Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Severity == SeverityError {
			out = append(out, d.String())
		}
	}
	return out
}

func TestValidFixtures(t *testing.T) {
	for _, f := range []string{fullYAML, minimalYAML} {
		s, diags, err := Load(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(diags) != 0 {
			t.Errorf("%s: unexpected diagnostics:\n%v", f, diags)
		}
		if s.File != f || s.Dir != filepath.Dir(f) || !bytes.Equal(s.Raw, []byte(read(t, f))) {
			t.Errorf("%s: File %q Dir %q", f, s.File, s.Dir)
		}
	}
}

// §8.3: every optional section takes the documented default.
func TestMinimalSiteDefaults(t *testing.T) {
	s, diags, err := Load(minimalYAML)
	if err != nil || HasErrors(diags) {
		t.Fatalf("%v %v", err, diags)
	}
	want := &Site{
		Version: 1, ID: "shop", Profile: "direct_tls", Hosts: []string{"shop.example.test"},
		AllowedListeners: []string{"public-tls"}, MonitorOnly: true,
		Token:     Token{ActiveKID: "shop-t-20260927"},
		Clearance: Clearance{TTLInvisibleS: 1800, TTLPowS: 1800, SessionMaxS: 86400, CTPShadow: true},
		Challenge: Challenge{TTLS: 120, PowBits: PowBits{14, 16, 18, 20}, FallbackRet: "/", MaxFailures: 5,
			FailureWindowS: 600, Submit: Rate{30, 60, 10}, Issue: Issue{60, 600, 3600}},
		Scoring: Scoring{ThetaC: 0.4, Kappa: 0, Z0: map[string]float64{"low": -2.197, "medium": -1.735, "high": -1.386, "critical": -1.099},
			FamilyModes: map[string]string{"edge_tls": "shadow"}, Weights: map[string]float64{}, HMin: -4.0, RulesetVersion: "v1"},
		Crawlers:      Crawlers{DefaultAction: "allow", Purposes: map[string]string{}},
		Events:        Events{AllowSampleRate: 0.1, AccessLog: true, Stream: true},
		OriginHeaders: OriginHeaders{Scores: true, Reasons: false, Session: true},
		Environments: []Environment{{
			Name: "production", Hosts: []string{"shop.example.test"},
			Routes: []Route{{Name: "default", Paths: []string{"/**"}, Channel: "web", Sensitivity: "low", Implicit: true}},
		}},
	}
	s.File, s.Dir, s.Raw = "", "", nil
	if !reflect.DeepEqual(s, want) {
		t.Errorf("minimal site:\n got %+v\nwant %+v", s, want)
	}
}

func TestFullSiteValues(t *testing.T) {
	s, _, _ := Load(fullYAML)
	prod := s.Environments[0]
	if s.NotBefore == nil || s.NotBefore.Unix() != 1790812800 {
		t.Errorf("not_before %v", s.NotBefore)
	}
	if s.Cloudflare == nil || s.Cloudflare.Zone != "example.com" || !s.Cloudflare.LocationHeaders || s.Cloudflare.OriginMode != "tunnel" {
		t.Errorf("cloudflare %+v", s.Cloudflare)
	}
	login, reset := prod.Routes[0], prod.Routes[1]
	if !login.RequireClearance || !login.FailClosed || reset.RequireClearance || reset.FailClosed || !reset.RedactPath {
		t.Errorf("require_clearance / fail_closed default to sensitivity == critical: login %+v reset %+v", login, reset)
	}
	if last := prod.Routes[len(prod.Routes)-1]; !last.Implicit || last.Name != "default" {
		t.Errorf("default route not appended: %+v", last)
	}
	l := prod.RateLimits[2]
	if l.Rate != (Rate{5, 900, 1}) || l.Scope != "global" || l.Mode != "dry_run" || l.OnExceed.Type != "pow" {
		t.Errorf("reset-challenge limiter %+v (burst defaults to 1, 5/15m = 5 per 900 s)", l)
	}
	if prod.AutomationAllowlistOnly || !s.Environments[1].AutomationAllowlistOnly {
		t.Error("automation_allowlist_only defaults to false for production only")
	}
	if s.Scoring.Weights["http.ua_library"] != 2.5 || s.Scoring.FamilyModes["edge_tls"] != "shadow" {
		t.Errorf("scoring %+v", s.Scoring)
	}
	if len(s.Artifacts) != 4 || s.Artifacts[0].Name != "cloudflare-ips" || !filepath.IsAbs(s.Artifacts[0].Path) && !strings.HasPrefix(s.Artifacts[0].Path, "../") {
		t.Errorf("artifacts %+v", s.Artifacts)
	}
	if s.Crawlers.Purposes["ai_training"] != "block" || len(s.ListFiles) != 1 || s.ListFiles[0].Name != "bad_ja4" {
		t.Errorf("crawlers %+v list files %+v", s.Crawlers, s.ListFiles)
	}
}

func TestExplicitCatchAllRouteIsKept(t *testing.T) {
	y := strings.Replace(read(t, minimalYAML), "    hosts: [shop.example.test]\n", `    hosts: [shop.example.test]
    routes:
      - name: everything
        paths: ["/**"]
        sensitivity: medium
`, 1)
	s, diags := Parse("x.yaml", []byte(y))
	if HasErrors(diags) {
		t.Fatal(diags)
	}
	if r := s.Environments[0].Routes; len(r) != 1 || r[0].Name != "everything" {
		t.Errorf("routes %+v: a paths == [\"/**\"] route replaces the implicit default", r)
	}
	// A catch-all limited to some methods is not a catch-all: default is appended.
	y = strings.Replace(y, `paths: ["/**"]`, `paths: ["/**"]
        methods: [POST]`, 1)
	s, _ = Parse("x.yaml", []byte(y))
	if r := s.Environments[0].Routes; len(r) != 2 || r[1].Name != "default" {
		t.Errorf("routes %+v", r)
	}
}

type mutation struct {
	name string
	base string // fullYAML or minimalYAML
	old  string
	new  string
	want string // substring of an error
}

// §8.2 validation table: every row has at least one counterexample, plus the
// structural rules (unknown keys, types, YAML features).
func TestValidationRules(t *testing.T) {
	cases := []mutation{
		// Environments and hosts.
		{"env host outside site", fullYAML, "hosts: [staging.example.com]", "hosts: [staging.example.com, other.example.com]", `"other.example.com" is not one of the site's hosts`},
		{"site host in no env", fullYAML, "hosts: [staging.example.com]\n    policies", "hosts: [www.example.com]\n    policies", `site host "staging.example.com" belongs to no environment`},
		{"host in two envs", fullYAML, "hosts: [staging.example.com]", "hosts: [staging.example.com, example.com]", `"example.com" already belongs to environment production`},
		{"env without hosts", minimalYAML, "    hosts: [shop.example.test]", "    hosts: []", "must list at least one host"},
		{"duplicate env", minimalYAML, "  - name: production\n    hosts: [shop.example.test]", "  - name: production\n    hosts: [shop.example.test]\n  - name: production\n    hosts: [shop.example.test]", `duplicate environment "production"`},
		{"unknown env name", minimalYAML, "name: production", "name: prod", `"prod" is not one of production, staging, test, dev`},
		{"no environments", minimalYAML, "environments:\n  - name: production\n    hosts: [shop.example.test]", "environments: []", "must list at least one environment"},
		// Routes.
		{"duplicate route", fullYAML, "- name: reset", "- name: login", `duplicate route name "login"`},
		{"bad route name", fullYAML, "- name: reset", "- name: Reset", `"Reset" does not match`},
		{"no paths", fullYAML, `paths: ["/api/**"]`, `paths: []`, "0 patterns, want 1-16"},
		{"17 paths", fullYAML, `paths: ["/api/**"]`, `paths: [/a, /b, /c, /d, /e, /f, /g, /h, /i, /j, /k, /l, /m, /n, /o, /p, /q]`, "17 patterns, want 1-16"},
		{"relative path", fullYAML, `"/account/reset/**"`, `"account/reset/**"`, "must start with /"},
		{"space in path", fullYAML, `"/account/reset/**"`, `"/account/re set"`, "visible ASCII"},
		{"non-ASCII path", fullYAML, `"/account/reset/**"`, `"/café"`, "visible ASCII"},
		{"long path", fullYAML, `"/account/reset/**"`, `"/` + strings.Repeat("a", 128) + `"`, "at most 128"},
		{"5 wildcards", fullYAML, `"/account/reset/**"`, `"/*/?/**/x*/y?"`, "5 wildcards, at most 4"},
		{"lower-case method", fullYAML, "methods: [GET, POST]", "methods: [get]", `"get" is not an upper-case HTTP method`},
		{"duplicate method", fullYAML, "methods: [GET, POST]", "methods: [GET, GET]", `duplicate entry "GET"`},
		{"route host outside env", fullYAML, "        redact_path: true", "        redact_path: true\n        hosts: [staging.example.com]", `"staging.example.com" is not a host of this environment`},
		{"reserved default name", fullYAML, "- name: reset", "- name: default", `the name "default" is reserved`},
		{"missing sensitivity", fullYAML, "        sensitivity: high\n", "", "sensitivity: required"},
		{"bad sensitivity", fullYAML, "sensitivity: high", "sensitivity: severe", `"severe" is not one of low, medium, high, critical`},
		{"bad channel", fullYAML, "channel: api", "channel: grpc", `"grpc" is not one of web, api, mobile`},
		// Rate limiters.
		{"bad limiter id", fullYAML, "id: api-per-prefix", "id: Api", `"Api" does not match`},
		{"reserved limiter id", fullYAML, "id: api-per-prefix", "id: mg.c.submit", `"mg." prefix is reserved`},
		{"duplicate limiter", fullYAML, "id: api-per-prefix", "id: login-per-ip", `duplicate limiter id "login-per-ip"`},
		// Ruling I-23: limiter ids are unique across environments too.
		{"limiter id in two envs", fullYAML, "    automation_allowlist_only: true", "    automation_allowlist_only: true\n    rate_limits:\n      - {id: login-per-ip, key: [ip], rate: 5/1m, on_exceed: {action: block}}", `limiter id "login-per-ip" is already used by environments[production]; limiter ids are unique across the site`},
		{"rate zero", fullYAML, "rate: 20/1m", "rate: 0/1m", "request count must be between 1"},
		{"period zero", fullYAML, "rate: 20/1m", "rate: 20/0m", "duration must be at least 1"},
		{"period too long", fullYAML, "rate: 20/1m", "rate: 20/25h", "at most 86400 s"},
		{"bad rate syntax", fullYAML, "rate: 20/1m", "rate: 20 per minute", "is not <n>/<duration>"},
		{"days unit", fullYAML, "rate: 20/1m", "rate: 20/1d", "is not <n>/<duration>"},
		{"burst zero", fullYAML, "burst: 5", "burst: 0", "burst: must be between 1 and 100000"},
		{"burst too high", fullYAML, "burst: 5", "burst: 100001", "burst: must be between 1 and 100000"},
		{"gcra dvt over 7 days", fullYAML, "rate: 20/1m\n        burst: 5", "rate: 1/24h\n        burst: 10", "not a valid GCRA limiter"},
		{"gcra interval zero", fullYAML, "rate: 20/1m", "rate: 2000000/1s", "not a valid GCRA limiter"},
		{"signal weight zero", fullYAML, "weight: 1.5", "weight: 0", "must be greater than 0"},
		// signal_weight is a float32 on the wire: 1e-50 would arrive as 0, which the Edge rejects.
		{"signal weight underflows float32", fullYAML, "weight: 1.5", "weight: 1e-50", "must be greater than 0"},
		{"signal weight high", fullYAML, "weight: 1.5", "weight: 2.5", "must be between 0 and 2"},
		{"signal without weight", fullYAML, "{action: signal, weight: 1.5}", "{action: signal}", "weight: required"},
		{"interactive limiter", fullYAML, "type: pow}", "type: interactive}", `"interactive" is not one of invisible, pow`},
		{"type on block", fullYAML, "{action: challenge, type: pow}", "{action: block, type: pow}", `unknown key "type"`},
		{"bad on_exceed", fullYAML, "{action: signal, weight: 1.5}", "{action: tarpit}", `"tarpit" is not one of signal, challenge, rate_limit, block`},
		{"retry after too long", fullYAML, "retry_after_s: 60}", "retry_after_s: 86401}", "retry_after_s: must be between 0 and 86400"},
		{"asn without geoip", fullYAML, "key: [ip]\n        rate: 20/1m", "key: [asn]\n        rate: 20/1m", "the asn dimension needs artifacts.geoip_asn"},
		{"unknown dimension", fullYAML, "key: [ip]\n        rate: 20/1m", "key: [user]\n        rate: 20/1m", `"user" is not one of ip, ip_prefix, asn, session, route`},
		{"empty key", fullYAML, "key: [ip]\n        rate: 20/1m", "key: []\n        rate: 20/1m", "must list at least one dimension"},
		{"unknown route", fullYAML, "routes: [login]", "routes: [signin]", `no route "signin" in this environment`},
		{"bad scope", fullYAML, "scope: local", "scope: cluster", `"cluster" is not one of global, local`},
		{"bad mode", fullYAML, "mode: dry_run", "mode: shadow", `"shadow" is not one of enforce, dry_run`},
		// challenge.
		{"ttl too short", fullYAML, "ttl_s: 120", "ttl_s: 9", "challenge.ttl_s: must be between 10 and 120"},
		{"ttl too long", fullYAML, "ttl_s: 120", "ttl_s: 121", "challenge.ttl_s: must be between 10 and 120"},
		{"pow bits low", fullYAML, "low: 14,", "low: 7,", "challenge.pow_bits.low: must be between 8 and 24"},
		{"pow bits high", fullYAML, "very_high: 20}", "very_high: 25}", "challenge.pow_bits.very_high: must be between 8 and 24"},
		{"fallback off-site", fullYAML, "fallback_ret: /", "fallback_ret: //evil.example", "must not start with //"},
		{"fallback backslash", fullYAML, "fallback_ret: /", `fallback_ret: /\evil`, `must not start with // or /\`},
		{"fallback fragment", fullYAML, "fallback_ret: /", "fallback_ret: '/a#b'", `must not contain \ or #`},
		{"fallback reserved", fullYAML, "fallback_ret: /", "fallback_ret: /__mg/c", "reserved /__mg/ namespace"},
		{"fallback reserved encoded", fullYAML, "fallback_ret: /", "fallback_ret: /%5F%5Fmg/c?x=1", "reserved /__mg/ namespace"},
		{"fallback relative", fullYAML, "fallback_ret: /", "fallback_ret: home", "must start with /"},
		{"max failures zero", fullYAML, "max_failures: 5", "max_failures: 0", "challenge.max_failures: must be between 1 and 1000"},
		{"max failures high", fullYAML, "max_failures: 5", "max_failures: 1001", "challenge.max_failures: must be between 1 and 1000"},
		{"failure window short", fullYAML, "failure_window_s: 600", "failure_window_s: 59", "challenge.failure_window_s: must be between 60 and 86400"},
		{"submit gcra", fullYAML, "submit: {rate: 30, period_s: 60, burst: 10}", "submit: {rate: 1, period_s: 86400, burst: 100000}", "challenge.submit: 1 per 86400 s with burst 100000 is not a valid GCRA limiter"},
		{"submit period", fullYAML, "submit: {rate: 30, period_s: 60, burst: 10}", "submit: {rate: 30, period_s: 0, burst: 10}", "challenge.submit.period_s: must be between 1 and 86400"},
		{"issue zero", fullYAML, "per_ipp: 60", "per_ipp: 0", "challenge.issue.per_ipp: must be between 1 and 100000"},
		{"issue unknown key", fullYAML, "per_ipp: 60", "per_ip: 60", `unknown key "per_ip"`},
		// clearance.
		{"ttl invisible short", fullYAML, "ttl_invisible_s: 1800", "ttl_invisible_s: 59", "clearance.ttl_invisible_s: must be between 60 and 86400"},
		{"ttl pow long", fullYAML, "ttl_pow_s: 1800", "ttl_pow_s: 86401", "clearance.ttl_pow_s: must be between 60 and 86400"},
		{"session shorter than ttl", fullYAML, "session_max_s: 86400", "session_max_s: 600", "shorter than a clearance TTL"},
		{"session over 30 days", fullYAML, "session_max_s: 86400", "session_max_s: 2592001", "clearance.session_max_s: must be between 60 and 2592000"},
		// Token and other.
		{"bad active kid", fullYAML, "active_kid: blog-t-20260927", "active_kid: Blog_T", `"Blog_T" does not match`},
		{"verify kid repeats active", fullYAML, "verify_kids: []", "verify_kids: [blog-t-20260927]", `duplicate entry "blog-t-20260927"`},
		{"too many kids", fullYAML, "verify_kids: []", "verify_kids: [a1, a2, a3]", "4 key ids, but token.keys.json holds at most 3"},
		{"missing token", minimalYAML, "token:\n  active_kid: shop-t-20260927\n", "", "token: required"},
		// Top level and sections.
		{"unknown top-level key", minimalYAML, "version: 1", "version: 1\nsite_name: x", `site: unknown key "site_name"`},
		{"unknown nested key", fullYAML, "ttl_s: 120", "ttl_s: 120\n  ttl: 5", `challenge: unknown key "ttl"`},
		{"version 2", minimalYAML, "version: 1", "version: 2", "version: must be 1"},
		{"version string", minimalYAML, "version: 1", `version: "1"`, "version: must be an integer"},
		{"missing site", minimalYAML, "site: shop\n", "", "site: required"},
		{"bad site id", minimalYAML, "site: shop", "site: Shop!", `"Shop!" does not match`},
		{"unknown profile", minimalYAML, "profile: direct_tls", "profile: akamai", `"akamai" is not one of cloudflare, direct_tls`},
		{"cloudflare section missing", minimalYAML, "profile: direct_tls", "profile: cloudflare", "cloudflare: required with profile cloudflare"},
		{"cloudflare section with direct_tls", fullYAML, "profile: cloudflare", "profile: direct_tls", "cloudflare: only allowed with profile cloudflare"},
		{"cloudflare zone missing", fullYAML, "  zone: example.com\n", "", "cloudflare.zone: required"},
		{"bad origin mode", fullYAML, "origin_mode: tunnel", "origin_mode: direct", `"direct" is not one of tunnel, aop`},
		{"upper-case host", minimalYAML, "hosts: [shop.example.test]\nallowed", "hosts: [Shop.example.test]\nallowed", "is not a lower-case host name"},
		{"host with port", minimalYAML, "hosts: [shop.example.test]\nallowed", "hosts: [shop.example.test:8443]\nallowed", "is not a lower-case host name"},
		{"host trailing dot", minimalYAML, "hosts: [shop.example.test]\nallowed", "hosts: [shop.example.test.]\nallowed", "is not a lower-case host name"},
		{"duplicate host", fullYAML, "hosts: [example.com, www.example.com, staging", "hosts: [example.com, example.com, www.example.com, staging", `duplicate entry "example.com"`},
		{"no listeners", minimalYAML, "allowed_listeners: [public-tls]", "allowed_listeners: []", "must list at least one listener"},
		{"bad listener", minimalYAML, "allowed_listeners: [public-tls]", "allowed_listeners: [public_tls]", `"public_tls" does not match`},
		{"monitor_only string", fullYAML, "monitor_only: true", "monitor_only: yes", "monitor_only: must be true or false"},
		{"bad not_before", fullYAML, `not_before: "2026-10-01T00:00:00Z"`, `not_before: "tomorrow"`, "not_before: must be an RFC 3339 timestamp"},
		// The Edge rejects a negative not_before_ms (edge-core bundle validation).
		{"not_before before 1970", fullYAML, `not_before: "2026-10-01T00:00:00Z"`, `not_before: "1969-12-31T23:59:59Z"`, "not_before: must not be before 1970"},
		{"bad list name", fullYAML, "owner_cidrs: [", "Owner: [", "list name does not match"},
		{"long list entry", fullYAML, "owner_cidrs: [203.0.113.0/24", "owner_cidrs: [" + strings.Repeat("x", 257), "entry is 257 bytes, at most 256"},
		{"list and list file clash", fullYAML, "bad_ja4: lists/bad-ja4.txt", "owner_cidrs: lists/bad-ja4.txt", "a list with this name is also defined in lists"},
		{"unknown artifact", fullYAML, "tor_exits:", "tor_exit_nodes:", `artifacts: unknown key "tor_exit_nodes"`},
		{"unknown weight", fullYAML, "weights: {http.ua_library: 2.5}", "weights: {http.ua: 2.5}", `"http.ua" is not a Phase 1 detector signal id`},
		{"weight negative", fullYAML, "weights: {http.ua_library: 2.5}", "weights: {http.ua_library: -1}", "must be between 0 and 10"},
		{"bad family mode", fullYAML, "family_modes: {edge_tls: shadow}", "family_modes: {edge_tls: loud}", `"loud" is not one of active, shadow, off`},
		{"unknown family", fullYAML, "family_modes: {edge_tls: shadow}", "family_modes: {ja4: shadow}", `scoring.family_modes: unknown key "ja4"`},
		{"theta high", fullYAML, "theta_c: 0.4", "theta_c: 1.5", "scoring.theta_c: must be between 0 and 1"},
		{"z0 NaN", fullYAML, "low: -2.197", "low: .nan", "must be a finite decimal number"},
		{"h_min positive", fullYAML, "h_min: -4.0", "h_min: 1", "scoring.h_min: must be between -20 and 0"},
		{"bad ruleset", fullYAML, "ruleset_version: v1", "ruleset_version: 'v 1'", "does not match"},
		{"bad crawler purpose", fullYAML, "purposes: {ai_training: block}", "purposes: {scraping: block}", `crawlers.purposes: unknown key "scraping"`},
		{"bad crawler action", fullYAML, "default_action: allow", "default_action: challenge", `"challenge" is not one of allow, block`},
		{"sample rate", fullYAML, "allow_sample_rate: 0.1", "allow_sample_rate: 2", "events.allow_sample_rate: must be between 0 and 1"},
		{"origin header type", fullYAML, "reasons: false", "reasons: 0", "origin_headers.reasons: must be true or false"},
		{"anchor", minimalYAML, "token:\n  active_kid: shop-t-20260927", "token: &t\n  active_kid: shop-t-20260927", "anchors, aliases and merge keys are not supported"},
		{"two documents", minimalYAML, "version: 1", "version: 1\n---\nversion: 1", "multiple YAML documents"},
		{"duplicate key", minimalYAML, "site: shop", "site: shop\nsite: shop", `duplicate key "site"`},
		{"invalid yaml", minimalYAML, "site: shop", "site: [shop", "invalid YAML"},
		{"not a mapping", minimalYAML, read(t, minimalYAML), "- a\n- b\n", "must be a mapping"},
		{"empty file", minimalYAML, read(t, minimalYAML), "", "empty site file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := read(t, tc.base)
			if !strings.Contains(base, tc.old) {
				t.Fatalf("test bug: %q not in %s", tc.old, tc.base)
			}
			y := strings.Replace(base, tc.old, tc.new, 1)
			_, diags := Parse("site.yaml", []byte(y))
			errs := errorsOf(diags)
			found := false
			for _, e := range errs {
				found = found || strings.Contains(e, tc.want)
			}
			if !found {
				t.Errorf("want an error containing %q, got:\n%s", tc.want, strings.Join(errs, "\n"))
			}
		})
	}
}

func TestRouteAndLimiterCountLimits(t *testing.T) {
	var routes, limiters strings.Builder
	for i := range 64 {
		fmt.Fprintf(&routes, "      - {name: r%d, paths: [\"/r%d\"], sensitivity: low}\n", i, i)
		fmt.Fprintf(&limiters, "      - {id: l%d, key: [ip], rate: 10/s, on_exceed: {action: block}}\n", i)
	}
	base := read(t, minimalYAML)
	// Ruling I-24: 64 declared routes plus the implicit default (65 in the
	// bundle, what the Edge accepts); a 65th declared route is an error.
	y := base + "    routes:\n" + routes.String()
	s, diags := Parse("x.yaml", []byte(y))
	if HasErrors(diags) {
		t.Fatalf("64 routes + default: %v", errorsOf(diags))
	}
	if r := s.Environments[0].Routes; len(r) != 65 || !r[64].Implicit || r[64].Name != "default" {
		t.Errorf("64 declared routes: %d routes, last %+v", len(r), r[len(r)-1])
	}
	y = base + "    routes:\n" + routes.String() + "      - {name: r64, paths: [\"/r64\"], sensitivity: low}\n"
	if _, diags := Parse("x.yaml", []byte(y)); !strings.Contains(strings.Join(errorsOf(diags), "\n"), "65 declared routes, at most 64 (plus the implicit default)") {
		t.Errorf("65 declared routes: %v", errorsOf(diags))
	}
	// 64 declared routes of which one is the catch-all: no default appended.
	catchAll := strings.Replace(routes.String(), `{name: r0, paths: ["/r0"]`, `{name: r0, paths: ["/**"]`, 1)
	s, diags = Parse("x.yaml", []byte(base+"    routes:\n"+catchAll))
	if HasErrors(diags) || len(s.Environments[0].Routes) != 64 {
		t.Errorf("64 routes with a catch-all: %v", errorsOf(diags))
	}
	y = base + "    rate_limits:\n" + limiters.String() + "      - {id: l64, key: [ip], rate: 10/s, on_exceed: {action: block}}\n"
	if _, diags := Parse("x.yaml", []byte(y)); !strings.Contains(strings.Join(errorsOf(diags), "\n"), "65 limiters, at most 64") {
		t.Errorf("65 limiters: %v", errorsOf(diags))
	}
	y = base + "    rate_limits:\n" + limiters.String()
	if _, diags := Parse("x.yaml", []byte(y)); HasErrors(diags) {
		t.Errorf("64 limiters: %v", errorsOf(diags))
	}
	entries := strings.Repeat("a,", MaxListEntries) + "a"
	y = strings.Replace(base, "token:", "lists: {big: ["+entries+"]}\ntoken:", 1)
	if _, diags := Parse("x.yaml", []byte(y)); !strings.Contains(strings.Join(errorsOf(diags), "\n"), "10001 entries, at most 10000") {
		t.Errorf("10001 list entries: %v", errorsOf(diags))
	}
}

// TestLimiterIDsUniqueSiteWide: ruling I-23. The Valkey key of a limiter,
// mg:rl:{site}:{limiter}:{kh}, has no environment part, so an id may appear
// in one environment only; distinct ids across environments are fine.
func TestLimiterIDsUniqueSiteWide(t *testing.T) {
	two := func(prodID, stagingID string) string {
		return fmt.Sprintf(`version: 1
site: shop
profile: direct_tls
hosts: [shop.example.test, staging.example.test]
allowed_listeners: [public-tls]
token:
  active_kid: shop-t-20260927
environments:
  - name: production
    hosts: [shop.example.test]
    rate_limits:
      - {id: %s, key: [ip], rate: 20/1m, on_exceed: {action: block}}
  - name: staging
    hosts: [staging.example.test]
    rate_limits:
      - {id: other, key: [ip], rate: 20/1m, on_exceed: {action: block}}
      - {id: %s, key: [ip], rate: 200/1m, on_exceed: {action: block}}
`, prodID, stagingID)
	}
	s, diags := Parse("x.yaml", []byte(two("login-per-ip", "staging-login-per-ip")))
	if HasErrors(diags) || len(s.Environments[1].RateLimits) != 2 {
		t.Fatalf("distinct ids: %v", errorsOf(diags))
	}
	_, diags = Parse("x.yaml", []byte(two("login-per-ip", "login-per-ip")))
	errs := errorsOf(diags)
	want := `x.yaml:17:14: error: environments[staging].rate_limits[1].id: limiter id "login-per-ip" is already used by environments[production]`
	if len(errs) != 1 || !strings.HasPrefix(errs[0], want) {
		t.Errorf("same id in two environments: %v, want one error starting %q", errs, want)
	}
}

func TestDiagnosticPositionsAndWarnings(t *testing.T) {
	y := strings.Replace(read(t, fullYAML), "ttl_s: 120", "ttl_s: 121", 1)
	_, diags := Parse("site.yaml", []byte(y))
	if len(diags) != 1 || diags[0].Line != 27 || diags[0].Col != 10 || diags[0].File != "site.yaml" ||
		diags[0].String() != "site.yaml:27:10: error: challenge.ttl_s: must be between 10 and 120, got 121" {
		t.Errorf("diagnostics %v", diags)
	}
	// Warnings are not errors.
	y = strings.Replace(read(t, fullYAML), "key: [ip_prefix, route]", "key: [session]", 1)
	y = strings.Replace(y, `"/api/**"]`, `"/api/**", "/__mg/x"]`, 1)
	_, diags = Parse("site.yaml", []byte(y))
	if HasErrors(diags) || len(diags) != 2 {
		t.Errorf("want two warnings, got %v", diags)
	}
}

func TestParseRate(t *testing.T) {
	for spec, want := range map[string][2]uint32{
		"20/1m": {20, 60}, "5/15m": {5, 900}, "600/1m": {600, 60}, "10/s": {10, 1}, "1/24h": {1, 86400}, "3/h": {3, 3600},
	} {
		r, p, err := ParseRate(spec)
		if err != nil || r != want[0] || p != want[1] {
			t.Errorf("ParseRate(%q) = %d, %d, %v", spec, r, p, err)
		}
	}
	for _, spec := range []string{"", "20", "20/", "/1m", "20/1", "-1/1m", "20/1.5m", "4294967296/1s", "1/86401s", "1/1441m"} {
		if _, _, err := ParseRate(spec); err == nil {
			t.Errorf("ParseRate(%q) accepted", spec)
		}
	}
}

func TestGCRAValid(t *testing.T) {
	for _, tc := range []struct {
		r  Rate
		ok bool
	}{
		{Rate{30, 60, 10}, true},
		{Rate{1, 86400, 7}, true},
		{Rate{1, 86400, 8}, false}, // 8 days
		{Rate{1_000_000, 1, 1}, true},
		{Rate{1_000_001, 1, 1}, false}, // interval rounds to 0
		{Rate{0, 1, 1}, false},
		{Rate{1, 0, 1}, false},
		{Rate{1, 1, 0}, false},
	} {
		if got := GCRAValid(tc.r); got != tc.ok {
			t.Errorf("GCRAValid(%+v) = %v", tc.r, got)
		}
	}
}

// Invalid fixture files carry the expected error on their first line.
func TestInvalidFixtures(t *testing.T) {
	entries, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		n++
		data := read(t, filepath.Join(invalidDir, e.Name()))
		first, _, _ := strings.Cut(data, "\n")
		want, ok := strings.CutPrefix(first, "# want: ")
		if !ok {
			t.Errorf("%s: first line must be `# want: <error substring>`", e.Name())
			continue
		}
		_, diags := Parse(e.Name(), []byte(data))
		if !strings.Contains(strings.Join(errorsOf(diags), "\n"), want) {
			t.Errorf("%s: want an error containing %q, got %v", e.Name(), want, errorsOf(diags))
		}
	}
	if n == 0 {
		t.Error("no invalid fixtures")
	}
}

func TestValidateRetAndReservedPaths(t *testing.T) {
	for _, ret := range []string{"/", "/account/login?next=%2F", "/a/b?c=d&e=f", "/%7Euser/", "/__mgx", "/x/__mg/c", "/__MG/c"} {
		if err := ValidateRet(ret); err != nil {
			t.Errorf("ValidateRet(%q) = %v", ret, err)
		}
	}
	for _, ret := range []string{"", "a", "//x", `/\x`, `/a\b`, "/a#b", "/a\x00", "/a\x7f", "/" + strings.Repeat("a", 512), "/__mg", "/__mg/c?x", "/%5F%5Fmg/c", "//__mg/c", "/./__mg/c"} {
		if err := ValidateRet(ret); err == nil {
			t.Errorf("ValidateRet(%q) accepted", ret)
		}
	}
	// The mg_core::paths test vectors.
	for _, p := range []string{"/__mg", "/__mg/", "/__mg/healthz", "/__mg/c", "//__mg/c", "///__mg/healthz", "/%5F%5Fmg/c", "/%5f%5fmg/c",
		"/_%5Fmg/", "/%5F%5F%6D%67/c", "/./__mg/c", "/%2e/__mg/c", "/x/../__mg/c", "/x/%2E%2E/__mg/c", `/\__mg/c`, "/__mg/./healthz",
		"/__mg/..%2F..%2Fadmin", "/a//../__mg/x", "/__mg//../x", "/__mg/%2e%2e"} {
		if !IsReserved(p) {
			t.Errorf("IsReserved(%q) = false", p)
		}
	}
	for _, p := range []string{"/__mg%2Fc", "/__MG/c", "/x/__mg/c", "/__mgx/c", "/%5F%5Fmgx", "/__mg_/", "/a/b/../c", "/%7Euser/", "/assets//app.js", "*", ""} {
		if IsReserved(p) {
			t.Errorf("IsReserved(%q) = true", p)
		}
	}
	if got := cloudflareView("/a//b/./c/../%7E%41%2f"); got != "/a/b/~A%2F" {
		t.Errorf("cloudflareView = %q", got)
	}
	if got := rfc3986View("/a//b/./c/../%7E%41%2f"); got != "/a//b/~A%2F" {
		t.Errorf("rfc3986View = %q", got)
	}
	for in, want := range map[string]string{"/a/b/..": "/a/", "/..": "/", "/%zz/%4": "/%zz/%4", "/caf%C3%A9": "/caf%C3%A9"} {
		if got := cloudflareView(in); got != want {
			t.Errorf("cloudflareView(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: no error")
	}
	big := filepath.Join(t.TempDir(), "big.yaml")
	os.WriteFile(big, bytes.Repeat([]byte("#"), MaxFileSize+1), 0o600)
	if _, _, err := Load(big); err == nil {
		t.Error("oversized file: no error")
	}
}

type xorshift uint64

func (x *xorshift) next() uint64 {
	*x ^= *x << 13
	*x ^= *x >> 7
	*x ^= *x << 17
	return uint64(*x)
}

// §2.4 item 3: ≥ 10,000 deterministic random variations of a valid site
// return diagnostics, never panic.
func TestParserNeverPanics(t *testing.T) {
	seed := []byte(read(t, fullYAML))
	tokens := [][]byte{[]byte("&a "), []byte("*a"), []byte("{"), []byte("["), []byte(": "), []byte("\n  - "), []byte("!!binary "), []byte("~"), []byte("0x1f"), []byte("<<: "), []byte("\t")}
	x := xorshift(0x2545f4914f6cdd1d)
	for i := 0; i < 10_000; i++ {
		b := bytes.Clone(seed)
		for range 1 + x.next()%3 {
			if len(b) == 0 {
				break
			}
			j := int(x.next() % uint64(len(b)))
			switch x.next() % 4 {
			case 0:
				b[j] = byte(x.next())
			case 1:
				b = append(b[:j:j], append(bytes.Clone(tokens[x.next()%uint64(len(tokens))]), b[j:]...)...)
			case 2:
				k := min(len(b), j+int(x.next()%40))
				b = append(b[:j:j], b[k:]...)
			default:
				b = b[:j]
			}
		}
		s, diags := Parse("fuzz.yaml", b)
		if s == nil && !HasErrors(diags) {
			t.Fatalf("nil site without an error for input %q", b)
		}
	}
}
