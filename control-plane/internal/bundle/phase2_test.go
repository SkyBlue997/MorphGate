package bundle

import (
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
)

const (
	goldenPhase2YAML = goldenDir + "/site-phase2.yaml"
	tokenAnchor      = "token:\n  active_kid: shop-t-20260927\n"
	envAnchor        = "    hosts: [shop.example.test]\n"
)

// minimalWith returns minimal.yaml with extra top-level YAML after token:
// and extra lines after the environment's hosts.
func minimalWith(t *testing.T, top, env string) string {
	t.Helper()
	y, err := os.ReadFile(minimalYAML)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(y), tokenAnchor, tokenAnchor+top, 1)
	return strings.Replace(s, envAnchor, envAnchor+env, 1)
}

func buildYAML(t *testing.T, y string, files map[string]string) *BuildResult {
	t.Helper()
	res, err := Build(loadSite(t, writeSite(t, y, files)), BuildOptions{Version: 1, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func warningsContain(res *BuildResult, sub string) bool {
	return slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, sub) })
}

// §3.2, §10.2: any Phase 2 key or value makes schema_version 2, even when it
// repeats a default; without one the bundle is schema_version 1 with every
// Phase 2 field unset.
func TestSchemaVersionDecision(t *testing.T) {
	routes := "    routes:\n      - {name: api, paths: [\"/api/**\"], sensitivity: medium%s}\n"
	cases := []struct {
		name, top, env string
		want           uint32
	}{
		{"phase 1 only", "", "", 1},
		{"phase 1 sections", "clearance: {ttl_pow_s: 600}\nchallenge: {ttl_s: 60}\nevents: {stream: false}\n", "", 1},
		{"route proof off", "", strings.Replace(routes, "%s", ", proof: off", 1), 2},
		{"route proof required", "", strings.Replace(routes, "%s", ", proof: required", 1), 2},
		{"route min_level", "", strings.Replace(routes, "%s", ", min_level: pow", 1), 2},
		{"clearance refresh false", "clearance: {refresh: false}\n", "", 2},
		{"clearance ttl_interactive_s", "clearance: {ttl_interactive_s: 1800}\n", "", 2},
		{"challenge default_lang", "challenge: {default_lang: zh-CN}\n", "", 2},
		{"challenge help_path", "challenge: {help_path: /help}\n", "", 2},
		{"challenge interactive empty", "challenge: {interactive: {}}\n", "", 2},
		{"events telemetry_behavior false", "events: {telemetry_behavior: false}\n", "", 2},
		{"events scanner_baits", "events: {scanner_baits: {builtin: true}}\n", "", 2},
		{"providers", "providers: [{id: turnstile, sitekey: abc, hostnames: [shop.example.test]}]\n", "", 2},
		{"interactive limiter", "", "    rate_limits:\n      - {id: l, key: [ip], rate: 5/1m, on_exceed: {action: challenge, type: interactive}}\n", 2},
		{"pow limiter", "", "    rate_limits:\n      - {id: l, key: [ip], rate: 5/1m, on_exceed: {action: challenge, type: pow}}\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := buildYAML(t, minimalWith(t, tc.top, tc.env), nil)
			sb := res.Bundle
			if sb.SchemaVersion != tc.want {
				t.Fatalf("schema_version %d, want %d", sb.SchemaVersion, tc.want)
			}
			if err := CheckSchema(sb); err != nil {
				t.Fatalf("CheckSchema: %v", err)
			}
			if tc.want == 1 && (sb.Challenge.Interactive != nil || sb.Challenge.DefaultLang != "" || sb.Clearance.TtlInteractiveS != 0 ||
				sb.Clearance.RefreshMaxPowS != 0 || sb.Events.ScannerBaitsBuiltin || len(sb.Providers) != 0) {
				t.Errorf("schema_version 1 with Phase 2 fields set: %v", sb)
			}
			if tc.want == 2 && (sb.Challenge.Interactive == nil || sb.Challenge.DefaultLang == "" || sb.Clearance.TtlInteractiveS == 0) {
				t.Errorf("schema_version 2 without explicit defaults: %v", sb)
			}
		})
	}
}

// §3.2: the builder writes every Phase 2 default explicitly.
func TestPhase2Defaults(t *testing.T) {
	res := buildYAML(t, minimalWith(t, "clearance: {ttl_pow_s: 50000}\nevents: {telemetry_behavior: false}\n", ""), nil)
	sb := res.Bundle
	ix := sb.Challenge.Interactive
	want := &morphgatev1.InteractiveConfig{
		Enabled: false, PowBits: &morphgatev1.ChallengeConfig_PowBits{Low: 14, Medium: 16, High: 18, VeryHigh: 19},
		PowK: 8, A11YBits: 17, EscalateAfter: 2, ScoringMode: "shadow", MinPowMs: 0, A11YMinMs: 2000,
		IssueRate: 30, IssuePeriodS: 600, IssueBurst: 20, RenewRate: 30, RenewPeriodS: 600, RenewBurst: 10,
		A11YIssuePerIp: 6, A11YIssuePerIpp: 120, A11YIssuePeriodS: 3600,
	}
	if !proto.Equal(ix, want) {
		t.Errorf("interactive defaults:\n got %v\nwant %v", ix, want)
	}
	if c := sb.Challenge; c.DefaultLang != "zh-CN" || c.HelpPath != "/" || c.PrivacyPath != "/" {
		t.Errorf("challenge defaults %v", c)
	}
	cl := sb.Clearance
	// refresh_max_pow_s defaults to 2 x ttl_pow_s, capped to its 86400 s range.
	if cl.TtlInteractiveS != 1800 || cl.TtlInteractiveA11YS != 900 || cl.TtlInteractiveExtS != 1800 || cl.Refresh ||
		cl.RefreshMaxInteractiveS != 14400 || cl.RefreshMaxExtS != 7200 || cl.RefreshMaxPowS != 86400 {
		t.Errorf("clearance defaults %v", cl)
	}
	if ev := sb.Events; ev.TelemetryBehavior || !ev.ScannerBaitsBuiltin || len(ev.ScannerBaits) != 0 {
		t.Errorf("events defaults %v", ev)
	}
	r := sb.Environments[0].Routes[0]
	if r.Proof != morphgatev1.ProofMode_PROOF_MODE_OFF || r.MinLevel != morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED {
		t.Errorf("default route %v", r)
	}
	res = buildYAML(t, minimalWith(t, "clearance: {ttl_pow_s: 900, refresh: true}\n", ""), nil)
	if got := res.Bundle.Clearance.RefreshMaxPowS; got != 1800 {
		t.Errorf("refresh_max_pow_s = %d, want 2 x ttl_pow_s = 1800", got)
	}
}

// The golden Phase 2 site maps every key onto the bundle.
func TestPhase2Mapping(t *testing.T) {
	res, err := Build(loadSite(t, goldenPhase2YAML), BuildOptions{Version: 1790000000, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	sb := res.Bundle
	if sb.SchemaVersion != 2 {
		t.Fatalf("schema_version %d", sb.SchemaVersion)
	}
	ix := sb.Challenge.Interactive
	if !ix.Enabled || ix.PowBits.Low != 13 || ix.PowBits.VeryHigh != 19 || ix.PowK != 6 || ix.A11YBits != 18 || ix.EscalateAfter != 3 ||
		ix.ScoringMode != "enforce" || ix.TPass != 0.4 || ix.TBlock != 0.8 || ix.MinPowMs != 250 || ix.A11YMinMs != 2500 ||
		ix.IssueRate != 40 || ix.IssuePeriodS != 600 || ix.IssueBurst != 25 || ix.RenewRate != 20 || ix.RenewPeriodS != 300 || ix.RenewBurst != 8 ||
		ix.A11YIssuePerIp != 5 || ix.A11YIssuePerIpp != 100 || ix.A11YIssuePeriodS != 1800 {
		t.Errorf("interactive %v", ix)
	}
	if c := sb.Challenge; c.DefaultLang != "en" || c.HelpPath != "/help/verification" || c.PrivacyPath != "/privacy?section=verification" {
		t.Errorf("challenge %v", c)
	}
	cl := sb.Clearance
	if cl.TtlPowS != 1200 || cl.TtlInteractiveS != 2400 || cl.TtlInteractiveA11YS != 600 || cl.TtlInteractiveExtS != 1500 || !cl.Refresh ||
		cl.RefreshMaxInteractiveS != 10800 || cl.RefreshMaxExtS != 5400 || cl.RefreshMaxPowS != 1800 {
		t.Errorf("clearance %v", cl)
	}
	if ev := sb.Events; !ev.TelemetryBehavior || ev.ScannerBaitsBuiltin || !slices.Equal(ev.ScannerBaits, []string{"/wp-login.php", "/.env*", "/old-admin/**"}) {
		t.Errorf("events %v", ev)
	}
	want := &morphgatev1.ProviderConfig{Id: "turnstile", Enabled: true, Sitekey: "0x4AAAAAAAkat-test-sitekey",
		DeniedCountries: []string{"CN"}, RouteIds: []string{"login", "signup"}, TimeoutMs: 3500, Fallback: "self_hold",
		Mode: "shadow", Hostnames: []string{"example.com", "www.example.com"}, Selection: "escalate_after_fail"}
	if len(sb.Providers) != 1 || !proto.Equal(sb.Providers[0], want) {
		t.Errorf("providers %v", sb.Providers)
	}
	routes := sb.Environments[0].Routes
	levels := map[string]morphgatev1.ChallengeType{}
	proofs := map[string]morphgatev1.ProofMode{}
	for _, r := range routes {
		levels[r.Id], proofs[r.Id] = r.MinLevel, r.Proof
	}
	if levels["login"] != morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE || levels["signup"] != morphgatev1.ChallengeType_CHALLENGE_TYPE_POW ||
		levels["api"] != morphgatev1.ChallengeType_CHALLENGE_TYPE_INVISIBLE || levels["default"] != morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED {
		t.Errorf("min_level %v", levels)
	}
	if proofs["api"] != morphgatev1.ProofMode_PROOF_MODE_REQUIRED || proofs["signup"] != morphgatev1.ProofMode_PROOF_MODE_OFF {
		t.Errorf("proof %v", proofs)
	}
	l := sb.Environments[0].RateLimits[1]
	if l.Id != "signup-per-ip" || l.ChallengeType != morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE || l.OnExceed != "challenge" {
		t.Errorf("interactive limiter %v", l)
	}
	sum := Summarize(sb, res.Bytes, nil, nil)
	if sum.SchemaVersion != 2 || sum.Phase2 == nil || !slices.Equal(sum.Phase2.ProofRequired, []string{"production/api"}) ||
		sum.Phase2.MinLevels["production/login"] != "interactive" || sum.Phase2.Providers[0].Sitekey != want.Sitekey {
		t.Errorf("summary %+v", sum.Phase2)
	}
	if s1 := Summarize(&morphgatev1.SiteBundle{SchemaVersion: 1}, nil, nil, nil); s1.Phase2 != nil {
		t.Error("a schema_version 1 summary has no Phase 2 part")
	}
}

// Rules that read Phase 2 policy fields make the bundle schema_version 2;
// identity.proof.valid alone (a Phase 1 field) keeps schema_version 1 with a
// warning, because the D-66 Edge never evaluates proofs there.
func TestPhase2RuleFields(t *testing.T) {
	build := func(rule string) *BuildResult {
		y := minimalWith(t, "", "    policies: [p.yaml]\n")
		return buildYAML(t, y, map[string]string{"p.yaml": "policies:\n  - " + rule + "\n"})
	}
	res := build(`{id: nav, phase: bot, expr: '!http.navigation && risk.score > 50', action: challenge, params: {type: pow}}`)
	if res.Bundle.SchemaVersion != 2 || !warningsContain(res, `rule "nav" reads http.navigation, a Phase 2 policy field`) {
		t.Errorf("navigation rule: schema_version %d, warnings %v", res.Bundle.SchemaVersion, res.Warnings)
	}
	res = build(`{id: bound, phase: bot, expr: 'identity.token.bound', action: log}`)
	if res.Bundle.SchemaVersion != 2 {
		t.Errorf("identity.token.bound rule: schema_version %d", res.Bundle.SchemaVersion)
	}
	res = build(`{id: proof, phase: bot, expr: '!identity.proof.valid', action: challenge, params: {type: pow}}`)
	if res.Bundle.SchemaVersion != 1 || !warningsContain(res, "identity.proof.* is always MISSING in a schema_version 1 bundle (D-66)") {
		t.Errorf("proof rule: schema_version %d, warnings %v", res.Bundle.SchemaVersion, res.Warnings)
	}
	// With a Phase 2 key the same rule is evaluated: no warning.
	y := minimalWith(t, "", "    policies: [p.yaml]\n    routes:\n      - {name: api, paths: [\"/api/**\"], sensitivity: medium, proof: required, channel: api}\n")
	res = buildYAML(t, y, map[string]string{"p.yaml": "policies:\n  - {id: proof, phase: bot, expr: '!identity.proof.valid', action: challenge, params: {type: pow}}\n"})
	if res.Bundle.SchemaVersion != 2 || warningsContain(res, "always MISSING") {
		t.Errorf("proof rule with proof route: schema_version %d, warnings %v", res.Bundle.SchemaVersion, res.Warnings)
	}
	// A disabled rule never enters the bundle and decides nothing.
	res = build(`{id: nav-off, phase: bot, expr: 'http.navigation', action: log, mode: disabled}`)
	if res.Bundle.SchemaVersion != 1 {
		t.Errorf("disabled rule: schema_version %d", res.Bundle.SchemaVersion)
	}
	// An allow rule on http.navigation fails the build (§4.2).
	y = minimalWith(t, "", "    policies: [p.yaml]\n")
	_, err := Build(loadSite(t, writeSite(t, y, map[string]string{"p.yaml": "policies:\n  - {id: nav-allow, phase: bot, expr: 'http.navigation', action: allow}\n"})), BuildOptions{Version: 1, Now: buildTime})
	if err == nil || !strings.Contains(err.Error(), "an allow rule must not depend on http.navigation") {
		t.Errorf("allow on http.navigation: %v", err)
	}
	// Interactive rules warn only while interactive is disabled (D-08).
	rule := "policies:\n  - {id: ix, phase: bot, expr: 'risk.score > 50', action: challenge, params: {type: interactive}}\n"
	res = buildYAML(t, minimalWith(t, "", "    policies: [p.yaml]\n"), map[string]string{"p.yaml": rule})
	if !warningsContain(res, "runs as pow while challenge.interactive.enabled is false") {
		t.Errorf("warnings %v", res.Warnings)
	}
	res = buildYAML(t, minimalWith(t, "challenge: {interactive: {enabled: true}}\n", "    policies: [p.yaml]\n"), map[string]string{"p.yaml": rule})
	if warningsContain(res, "runs as pow") {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func goldenBuilt(t *testing.T, yaml string) *morphgatev1.SiteBundle {
	t.Helper()
	res, err := Build(loadSite(t, goldenDir+"/"+yaml), BuildOptions{Version: 1790000000, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(res.Bundle); err != nil {
		t.Fatal(err)
	}
	return res.Bundle
}

// §3.2 (D-66) and §10.2 / §8.2: one counterexample per schema rule.
func TestCheckSchemaCounterexamples(t *testing.T) {
	v1 := goldenBuilt(t, "site-rules.yaml")
	v2 := goldenBuilt(t, "site-phase2.yaml")
	route := func(sb *morphgatev1.SiteBundle) *morphgatev1.Route { return sb.Environments[0].Routes[0] }
	cases := []struct {
		name   string
		base   *morphgatev1.SiteBundle
		mutate func(*morphgatev1.SiteBundle)
		want   string
	}{
		{"schema 0", v1, func(sb *morphgatev1.SiteBundle) { sb.SchemaVersion = 0 }, "schema_version 0 is neither 1 nor 2"},
		{"schema 3", v2, func(sb *morphgatev1.SiteBundle) { sb.SchemaVersion = 3 }, "schema_version 3 is neither 1 nor 2"},
		// schema_version 1: every Phase 2 field zero.
		{"v1 route proof", v1, func(sb *morphgatev1.SiteBundle) { route(sb).Proof = morphgatev1.ProofMode_PROOF_MODE_REQUIRED }, "proof and min_level must be unset"},
		{"v1 route min_level", v1, func(sb *morphgatev1.SiteBundle) {
			route(sb).MinLevel = morphgatev1.ChallengeType_CHALLENGE_TYPE_POW
		}, "proof and min_level must be unset"},
		{"v1 interactive", v1, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive = &morphgatev1.InteractiveConfig{} }, "challenge.interactive, default_lang"},
		{"v1 default_lang", v1, func(sb *morphgatev1.SiteBundle) { sb.Challenge.DefaultLang = "en" }, "challenge.interactive, default_lang"},
		{"v1 help_path", v1, func(sb *morphgatev1.SiteBundle) { sb.Challenge.HelpPath = "/" }, "challenge.interactive, default_lang"},
		{"v1 privacy_path", v1, func(sb *morphgatev1.SiteBundle) { sb.Challenge.PrivacyPath = "/" }, "challenge.interactive, default_lang"},
		{"v1 ttl_interactive_s", v1, func(sb *morphgatev1.SiteBundle) { sb.Clearance.TtlInteractiveS = 1800 }, "Phase 2 clearance fields"},
		{"v1 refresh", v1, func(sb *morphgatev1.SiteBundle) { sb.Clearance.Refresh = true }, "Phase 2 clearance fields"},
		{"v1 refresh_max_pow_s", v1, func(sb *morphgatev1.SiteBundle) { sb.Clearance.RefreshMaxPowS = 1 }, "Phase 2 clearance fields"},
		{"v1 telemetry_behavior", v1, func(sb *morphgatev1.SiteBundle) { sb.Events.TelemetryBehavior = true }, "events.telemetry_behavior"},
		{"v1 scanner_baits_builtin", v1, func(sb *morphgatev1.SiteBundle) { sb.Events.ScannerBaitsBuiltin = true }, "events.telemetry_behavior"},
		{"v1 scanner_baits", v1, func(sb *morphgatev1.SiteBundle) { sb.Events.ScannerBaits = []string{"/x"} }, "events.telemetry_behavior"},
		{"v1 providers", v1, func(sb *morphgatev1.SiteBundle) { sb.Providers = v2.Providers }, "providers must be unset"},
		{"v1 interactive limiter", v1, func(sb *morphgatev1.SiteBundle) {
			sb.Environments[0].RateLimits[0].ChallengeType = morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE
		}, "challenge_type INTERACTIVE needs schema_version 2"},
		// schema_version 2: required messages and ranges.
		{"v2 no interactive", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive = nil }, "needs the challenge, challenge.interactive, clearance and events"},
		{"v2 no clearance", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance = nil }, "needs the challenge"},
		{"v2 no events", v2, func(sb *morphgatev1.SiteBundle) { sb.Events = nil }, "needs the challenge"},
		{"v2 no challenge", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge = nil }, "needs the challenge"},
		{"v2 default_lang", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.DefaultLang = "fr" }, `default_lang "fr"`},
		{"v2 default_lang empty", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.DefaultLang = "" }, `default_lang ""`},
		{"v2 help_path", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.HelpPath = "//evil.example" }, "challenge.help_path"},
		{"v2 privacy_path", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.PrivacyPath = "" }, "challenge.privacy_path"},
		{"v2 pow_bits missing", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowBits = nil }, "pow_bits missing"},
		{"v2 pow_bits 23", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowBits.VeryHigh = 23 }, "pow_bits.very_high 23 outside 8..22"},
		{"v2 pow_bits 7", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowBits.Low = 7 }, "pow_bits.low 7 outside 8..22"},
		{"v2 pow_bits decrease", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowBits.High = 14 }, "decrease with the risk band"},
		{"v2 pow_k 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowK = 0 }, "pow_k 0 outside 1..8"},
		{"v2 pow_k 9", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.PowK = 9 }, "pow_k 9 outside 1..8"},
		{"v2 a11y_bits 11", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YBits = 11 }, "a11y_bits 11 outside 12..24"},
		{"v2 a11y_bits 25", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YBits = 25 }, "a11y_bits 25 outside 12..24"},
		{"v2 escalate_after 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.EscalateAfter = 0 }, "escalate_after 0 outside 1..5"},
		{"v2 escalate_after 6", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.EscalateAfter = 6 }, "escalate_after 6 outside 1..5"},
		{"v2 scoring mode", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.ScoringMode = "" }, `scoring_mode ""`},
		{"v2 enforce t_pass 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.TPass = 0 }, "enforce needs 0 < t_pass < t_block <= 1"},
		{"v2 enforce t_pass >= t_block", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.TPass = 0.8 }, "enforce needs 0 < t_pass < t_block <= 1"},
		{"v2 enforce t_block > 1", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.TBlock = 1.5 }, "enforce needs 0 < t_pass < t_block <= 1"},
		{"v2 shadow with thresholds", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.ScoringMode = "shadow" }, "t_pass and t_block are enforce only"},
		{"v2 min_pow_ms", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.MinPowMs = 5001 }, "min_pow_ms 5001 outside 0..5000"},
		{"v2 a11y_min_ms", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YMinMs = 10001 }, "a11y_min_ms 10001 outside 0..10000"},
		{"v2 issue rate 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.IssueRate = 0 }, "challenge.interactive issue: 0 per 600 s"},
		{"v2 issue period 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.IssuePeriodS = 0 }, "issue period_s 0 outside 1..86400"},
		{"v2 renew burst 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.RenewBurst = 0 }, "renew burst 0 outside 1..100000"},
		{"v2 renew ipp gcra", v2, func(sb *morphgatev1.SiteBundle) {
			sb.Challenge.Interactive.RenewRate, sb.Challenge.Interactive.RenewPeriodS = 400_000, 1
		}, "renew (ipp, 4x)"},
		{"v2 a11y per_ip 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YIssuePerIp = 0 }, "a11y_issue_per_ip 0 outside"},
		{"v2 a11y per_ipp < per_ip", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YIssuePerIpp = 4 }, "a11y_issue_per_ipp 4 below a11y_issue_per_ip 5"},
		{"v2 a11y period 0", v2, func(sb *morphgatev1.SiteBundle) { sb.Challenge.Interactive.A11YIssuePeriodS = 0 }, "a11y_issue_period_s 0 outside"},
		{"v2 ttl_interactive_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.TtlInteractiveS = 299 }, "ttl_interactive_s 299 outside 300..7200"},
		{"v2 ttl_interactive_a11y_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.TtlInteractiveA11YS = 3601 }, "ttl_interactive_a11y_s 3601 outside 300..3600"},
		{"v2 ttl_interactive_ext_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.TtlInteractiveExtS = 7201 }, "ttl_interactive_ext_s 7201 outside 300..7200"},
		{"v2 refresh_max_interactive_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.RefreshMaxInteractiveS = 899 }, "refresh_max_interactive_s 899 outside 900..86400"},
		{"v2 refresh_max_ext_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.RefreshMaxExtS = 86401 }, "refresh_max_ext_s 86401 outside 900..86400"},
		{"v2 refresh_max_pow_s", v2, func(sb *morphgatev1.SiteBundle) { sb.Clearance.RefreshMaxPowS = 86401 }, "refresh_max_pow_s 86401 outside 0..86400"},
		{"v2 65 scanner baits", v2, func(sb *morphgatev1.SiteBundle) {
			sb.Events.ScannerBaits = slices.Repeat([]string{"/x"}, 65)
		}, "65 patterns, at most 64"},
		{"v2 bad scanner bait", v2, func(sb *morphgatev1.SiteBundle) { sb.Events.ScannerBaits = []string{"x"} }, `scanner_baits "x": must start with /`},
		{"v2 unknown proof mode", v2, func(sb *morphgatev1.SiteBundle) { route(sb).Proof = 7 }, "unknown proof mode 7"},
		{"v2 min_level attestation", v2, func(sb *morphgatev1.SiteBundle) {
			route(sb).MinLevel = morphgatev1.ChallengeType_CHALLENGE_TYPE_ATTESTATION
		}, "is not invisible, pow or interactive"},
		{"v2 proof with never_challenge", v2, func(sb *morphgatev1.SiteBundle) {
			r := sb.Environments[0].Routes[2] // api: proof required
			r.NeverChallenge = true
		}, "contradict never_challenge"},
		// §8.2 providers.
		{"v2 two providers", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers = append(sb.Providers, sb.Providers[0]) }, "2 entries, at most 1"},
		{"v2 provider id", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Id = "tencent" }, `provider id "tencent" is not turnstile`},
		{"v2 provider sitekey", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Sitekey = "a b" }, `sitekey "a b" does not match`},
		{"v2 provider no hostnames", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Hostnames = nil }, "hostnames empty"},
		{"v2 provider foreign hostname", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Hostnames = []string{"evil.example"} }, `hostname "evil.example" is not a site host`},
		{"v2 provider unknown route", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].RouteIds = []string{"nope"} }, `route "nope" does not exist`},
		{"v2 provider timeout", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].TimeoutMs = 999 }, "timeout_ms 999 outside 1000..5000"},
		{"v2 provider fail_closed", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Fallback = "fail_closed" }, `fallback "fail_closed" is not self_hold (D-51)`},
		{"v2 provider fail open", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Fallback = "fail_open_with_signal" }, "is not self_hold (D-51)"},
		{"v2 provider mode", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Mode = "" }, `mode "" is not shadow or enforce`},
		{"v2 provider selection", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].Selection = "always" }, `selection "always"`},
		{"v2 provider country", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].DeniedCountries = []string{"cn"} }, `denied country "cn"`},
		{"v2 provider secret_refs", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].SecretRefs = []string{"x"} }, "secret_refs and allowed_countries must be empty"},
		{"v2 provider allowed_countries", v2, func(sb *morphgatev1.SiteBundle) { sb.Providers[0].AllowedCountries = []string{"US"} }, "secret_refs and allowed_countries must be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := proto.Clone(tc.base).(*morphgatev1.SiteBundle)
			tc.mutate(sb)
			err := CheckSchema(sb)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CheckSchema = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// An interactive limiter is fine under schema_version 2.
	sb := proto.Clone(v2).(*morphgatev1.SiteBundle)
	if sb.Environments[0].RateLimits[1].ChallengeType != morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE || CheckSchema(sb) != nil {
		t.Error("schema_version 2 accepts challenge_type INTERACTIVE")
	}
}

// Verify (bundle verify / publish) and the signed golden file apply the
// schema rules too: a correctly signed bundle that breaks them is rejected.
func TestVerifyAppliesSchemaRules(t *testing.T) {
	k, pub := ownerTestKey(t)
	file, err := os.ReadFile(goldenDir + "/golden-phase2.bundle")
	if err != nil {
		t.Fatal(err)
	}
	_, sb, err := VerifyFile(file, []*keys.OwnerPublicKey{pub})
	if err != nil || sb.SchemaVersion != 2 {
		t.Fatalf("golden-phase2.bundle: %v (schema_version %d)", err, sb.GetSchemaVersion())
	}
	sb.Providers[0].Fallback = "fail_closed"
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(data, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, []*keys.OwnerPublicKey{pub}); err == nil || !strings.Contains(err.Error(), "D-51") {
		t.Errorf("Verify = %v", err)
	}
}
