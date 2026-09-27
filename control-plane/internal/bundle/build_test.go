package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/sitecfg"
)

// §8.3 and "defaults and proto3": a minimal site YAML yields every optional
// message, fully populated with the documented defaults.
func TestBuildMinimalSiteDefaults(t *testing.T) {
	site := loadSite(t, minimalYAML)
	res, err := Build(site, BuildOptions{Version: 7, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	sb := res.Bundle
	want := &morphgatev1.SiteBundle{
		SiteId: "shop", Version: 7, CreatedAtMs: buildTime.UnixMilli(), SchemaVersion: 1,
		Upstream: &morphgatev1.UpstreamProfile{Kind: morphgatev1.UpstreamProfileKind_UPSTREAM_PROFILE_KIND_DIRECT_TLS,
			ExpectedMask: 1<<1 | 1<<2 | 1<<3 | 1<<8 | 1<<7},
		Environments: []*morphgatev1.Environment{{
			Name:  "production",
			Hosts: []string{"shop.example.test"},
			Routes: []*morphgatev1.Route{{Id: "default", Name: "default", Paths: []string{"/**"},
				Channel: morphgatev1.Channel_CHANNEL_WEB, Sensitivity: morphgatev1.RouteSensitivity_ROUTE_SENSITIVITY_LOW}},
		}},
		TokenKeyIds:      []string{"shop-t-20260927"},
		MonitorOnly:      true,
		Hosts:            []string{"shop.example.test"},
		AllowedListeners: []string{"public-tls"},
		Challenge: &morphgatev1.ChallengeConfig{TtlS: 120, PowBits: &morphgatev1.ChallengeConfig_PowBits{Low: 14, Medium: 16, High: 18, VeryHigh: 20},
			FallbackRet: "/", MaxFailures: 5, FailureWindowS: 600, SubmitRate: 30, SubmitPeriodS: 60, SubmitBurst: 10,
			IssuePerIpp: 60, IssuePerAsn: 600, IssuePeriodS: 3600},
		Clearance: &morphgatev1.ClearanceConfig{TtlInvisibleS: 1800, TtlPowS: 1800, SessionMaxS: 86400, CtpShadow: true},
		Scoring: &morphgatev1.ScoringConfig{ThetaC: 0.4, Kappa: 0, HMin: -4, RulesetVersion: "v1",
			Z0:          map[string]float32{"low": -2.197, "medium": -1.735, "high": -1.386, "critical": -1.099},
			FamilyModes: map[string]string{"edge_tls": "shadow"}, Weights: map[string]float32{}},
		CrawlerPolicy: &morphgatev1.CrawlerPolicy{DefaultAction: "allow", Purposes: map[string]string{}},
		Events:        &morphgatev1.EventConfig{AllowSampleRate: 0.1, AccessLog: true, Stream: true},
		OriginHeaders: &morphgatev1.OriginHeaderConfig{Scores: true, Reasons: false, Session: true},
		Lists:         map[string]*morphgatev1.NamedList{},
		SourceDigest:  hexSHA(site.Raw),
	}
	if !proto.Equal(sb, want) {
		t.Errorf("minimal bundle:\n got %v\nwant %v", sb, want)
	}
	// Proto3 cannot tell "unset" from zero: the messages must be present on
	// the wire even where every value is the default.
	var decoded morphgatev1.SiteBundle
	if err := proto.Unmarshal(res.Bytes, &decoded); err != nil {
		t.Fatal(err)
	}
	for name, present := range map[string]bool{
		"challenge": decoded.Challenge != nil, "clearance": decoded.Clearance != nil, "scoring": decoded.Scoring != nil,
		"crawler_policy": decoded.CrawlerPolicy != nil, "events": decoded.Events != nil, "origin_headers": decoded.OriginHeaders != nil,
		"pow_bits": decoded.GetChallenge().GetPowBits() != nil, "upstream": decoded.Upstream != nil,
	} {
		if !present {
			t.Errorf("%s is missing on the wire", name)
		}
	}
	if decoded.Cloudflare != nil {
		t.Error("cloudflare set for a direct_tls site")
	}
	// Version defaults to the build time.
	res2, err := Build(site, BuildOptions{Now: buildTime})
	if err != nil || res2.Bundle.Version != uint64(buildTime.Unix()) {
		t.Errorf("default version %d, %v", res2.Bundle.Version, err)
	}
}

func hexSHA(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ruleIDs(env *morphgatev1.Environment) []string {
	var ids []string
	for _, r := range env.Rules {
		ids = append(ids, r.Id)
	}
	return ids
}

// §8.3 / §5.4: rules filtered (disabled, expired) and ordered by phase,
// priority descending, id; routes, limiters, lists and artifacts mapped.
func TestBuildFullSite(t *testing.T) {
	withLowering(t, nil)
	site := loadSite(t, fullYAML)
	res, err := Build(site, BuildOptions{Version: 1790000000, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	sb := res.Bundle
	prod, staging := sb.Environments[0], sb.Environments[1]
	wantOrder := []string{"owner-networks-allow", "block-impersonators", "bad-cf-ciphers", "scanner-block",
		"login-rate-signal", "login-high-risk", "legacy-browser-tag"}
	if got := ruleIDs(prod); !slices.Equal(got, wantOrder) {
		t.Errorf("production rules %v, want %v (disabled rule dropped, phase / priority / id order)", got, wantOrder)
	}
	if got := ruleIDs(staging); !slices.Equal(got, []string{"test-env-default-deny"}) || !staging.Rules[0].Locked {
		t.Errorf("staging rules %v", got)
	}
	for _, r := range prod.Rules {
		if r.IrVersion != 1 || len(r.ExprIr) == 0 || r.ExprSource == "" {
			t.Errorf("rule %s without IR", r.Id)
		}
	}
	if r := prod.Rules[6]; r.Action != morphgatev1.Action_ACTION_TAG || r.Params["label"] != "legacy_browser" {
		t.Errorf("tag rule %v", r)
	}
	// Routes: declaration order, default appended, defaults of require_clearance / fail_closed.
	var names []string
	for _, r := range prod.Routes {
		names = append(names, r.Id)
		if r.Id != r.Name {
			t.Errorf("route id %q != name %q", r.Id, r.Name)
		}
	}
	if !slices.Equal(names, []string{"login", "reset", "api", "default"}) {
		t.Errorf("routes %v", names)
	}
	login := prod.Routes[0]
	if !login.RequireClearance || !login.FailClosed || login.Sensitivity != morphgatev1.RouteSensitivity_ROUTE_SENSITIVITY_CRITICAL ||
		!slices.Equal(login.Methods, []string{"GET", "POST"}) || login.PathGlob != "" {
		t.Errorf("login route %v", login)
	}
	if reset := prod.Routes[1]; !reset.RedactPath || reset.RequireClearance || reset.FailClosed {
		t.Errorf("reset route %v", reset)
	}
	if api := prod.Routes[2]; api.Channel != morphgatev1.Channel_CHANNEL_API {
		t.Errorf("api route %v", api)
	}
	// Limiters.
	rl := prod.RateLimits
	if len(rl) != 3 || rl[0].Algorithm != "gcra" || rl[0].RetryAfterS != 60 || rl[0].OnExceed != "rate_limit" ||
		!slices.Equal(rl[0].RouteIds, []string{"login"}) || rl[0].RouteId != "" || rl[0].Rate != 20 || rl[0].PeriodS != 60 || rl[0].Burst != 5 {
		t.Errorf("limiter 0 %v", rl[0])
	}
	if rl[1].SignalWeight != 1.5 || rl[1].Scope != "local" || !slices.Equal(rl[1].Key, []string{"ip_prefix", "route"}) {
		t.Errorf("limiter 1 %v", rl[1])
	}
	if rl[2].ChallengeType != morphgatev1.ChallengeType_CHALLENGE_TYPE_POW || rl[2].Mode != "dry_run" || rl[2].PeriodS != 900 || rl[2].Burst != 1 {
		t.Errorf("limiter 2 %v", rl[2])
	}
	// Lists: inline and file entries (comments and blanks dropped).
	if got := sb.Lists["bad_ja4"].GetEntries(); !slices.Equal(got, []string{"0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef"}) {
		t.Errorf("bad_ja4 %v", got)
	}
	if got := sb.Lists["owner_cidrs"].GetEntries(); !slices.Equal(got, []string{"203.0.113.0/24", "2001:db8::/32"}) {
		t.Errorf("owner_cidrs %v", got)
	}
	// Artifacts in §12.1 order, content-addressed.
	var artNames []string
	for _, a := range sb.Artifacts {
		artNames = append(artNames, a.Name)
		src, ok := res.Artifacts[a.Sha256]
		data, err := os.ReadFile(src)
		if !ok || err != nil || hexSHA(data) != a.Sha256 || uint64(len(data)) != a.Size || a.Uri != "artifacts/"+a.Sha256 {
			t.Errorf("artifact %v: source %q %v", a, src, err)
		}
	}
	if !slices.Equal(artNames, []string{"cloudflare-ips", "crawler-registry", "datacenter-asns", "tor-exits"}) {
		t.Errorf("artifact order %v", artNames)
	}
	if sb.Artifacts[0].Version != "2026-09-27T10:00:00Z" || sb.Artifacts[1].Version != "2026-09-27T10:00:00Z" || sb.Artifacts[2].Version != "" {
		t.Errorf("artifact versions %v", sb.Artifacts)
	}
	// Site-level settings.
	if sb.NotBeforeMs != 1790812800000 || sb.Cloudflare.GetZone() != "example.com" || !sb.Cloudflare.GetLocationHeaders() ||
		!slices.Equal(sb.Cloudflare.GetOwnerZones(), []string{"example.com"}) || sb.Upstream.ExpectedMask != 1<<1|1<<3|1<<9|1<<8|1<<7|1<<10 {
		t.Errorf("site settings: not_before %d cloudflare %v upstream %v", sb.NotBeforeMs, sb.Cloudflare, sb.Upstream)
	}
	if sb.Scoring.Weights["http.ua_library"] != 2.5 || sb.CrawlerPolicy.Purposes["ai_training"] != "block" {
		t.Errorf("scoring %v crawlers %v", sb.Scoring, sb.CrawlerPolicy)
	}
	// source_digest: YAML, policy files, list files.
	read := func(p string) []byte { b, _ := os.ReadFile(p); return b }
	want := hexSHA(site.Raw, read(sitesDir+"/valid/policies/production.yaml"), read(sitesDir+"/valid/policies/staging.yaml"),
		read(sitesDir+"/valid/lists/bad-ja4.txt"))
	if sb.SourceDigest != want {
		t.Errorf("source_digest %s, want %s", sb.SourceDigest, want)
	}
	// Determinism: same inputs and version, same bytes.
	for range 3 {
		again, err := Build(loadSite(t, fullYAML), BuildOptions{Version: 1790000000, Now: buildTime})
		if err != nil || !bytes.Equal(again.Bytes, res.Bytes) {
			t.Fatal("two builds with the same inputs differ")
		}
	}
}

func TestBuildLowerCasesPatternsForCaseInsensitivePaths(t *testing.T) {
	y := strings.Replace(mustRead(t, minimalYAML), "    hosts: [shop.example.test]\n", `    hosts: [shop.example.test]
    routes:
      - {name: login, paths: ["/Account/Login", "/API/**"], sensitivity: critical}
`, 1) + "case_insensitive_paths: true\n"
	res, err := Build(loadSite(t, writeSite(t, y, nil)), BuildOptions{Version: 1, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Bundle.Environments[0].Routes[0].Paths; !slices.Equal(got, []string{"/account/login", "/api/**"}) || !res.Bundle.CaseInsensitivePaths {
		t.Errorf("paths %v", got)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// §8.3: a rule without IR fails the build ("policy IR unavailable"), so no
// builder ever produces a bundle the Edge cannot load.
func TestBuildFailsWithoutPolicyIR(t *testing.T) {
	site := loadSite(t, fullYAML)
	if _, err := Build(site, BuildOptions{Version: 1, Now: buildTime}); err != nil {
		t.Fatalf("with the real compiler: %v", err)
	}
	old := ruleProto
	t.Cleanup(func() { ruleProto = old })
	ruleProto = func(cr *policy.CheckedRule) *morphgatev1.CompiledRule {
		pb := cr.Proto()
		pb.IrVersion, pb.ExprIr = 0, nil
		return pb
	}
	if _, err := Build(site, BuildOptions{Version: 1, Now: buildTime}); err == nil || !strings.Contains(err.Error(), "policy IR unavailable") {
		t.Errorf("ir_version 0: %v", err)
	}
	ruleProto = func(cr *policy.CheckedRule) *morphgatev1.CompiledRule {
		pb := cr.Proto()
		pb.IrVersion, pb.ExprIr = 1, nil
		return pb
	}
	if _, err := Build(site, BuildOptions{Version: 1, Now: buildTime}); err == nil || !strings.Contains(err.Error(), "policy IR unavailable") {
		t.Errorf("empty expr_ir: %v", err)
	}
	// A site without rules builds either way.
	if _, err := Build(loadSite(t, minimalYAML), BuildOptions{Version: 1, Now: buildTime}); err != nil {
		t.Errorf("site without rules: %v", err)
	}
}

// The real compiler (WP-G1): every bundled rule carries IR with max_steps.
func TestBuildWithCompilerIR(t *testing.T) {
	res, err := Build(loadSite(t, fullYAML), BuildOptions{Version: 1, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range res.Bundle.Environments {
		for _, r := range env.Rules {
			var pe morphgatev1.PolicyExpr
			if err := proto.Unmarshal(r.ExprIr, &pe); err != nil || pe.IrVersion != 1 || pe.MaxSteps == 0 || pe.MaxSteps > MaxSteps {
				t.Errorf("rule %s: IR %v %v", r.Id, &pe, err)
			}
		}
	}
}

const policyHeader = `version: 1
site: shop
profile: direct_tls
hosts: [shop.example.test]
allowed_listeners: [public-tls]
token: {active_kid: shop-t-20260927}
lists:
  ips: [192.0.2.0/24, "2001:db8::1"]
  words: [alpha, beta]
environments:
  - name: production
    hosts: [shop.example.test]
    policies: [p.yaml]
    rate_limits:
      - {id: per-ip, key: [ip], rate: 10/s, on_exceed: {action: block}}
`

func buildPolicy(t *testing.T, policyYAML string, lower func(*policy.CheckedRule) *morphgatev1.PolicyExpr) (*BuildResult, error) {
	t.Helper()
	withLowering(t, lower)
	return Build(loadSite(t, writeSite(t, policyHeader, map[string]string{"p.yaml": policyYAML})), BuildOptions{Version: 1, Now: buildTime})
}

// §8.2 "策略" row and the Phase 1 parameter restrictions of §3.2.
func TestBuildPolicyRules(t *testing.T) {
	rule := func(body string) string { return "policies:\n  - id: r1\n    phase: bot\n" + body }
	for _, tc := range []struct {
		name, policy, want string
		lower              func(*policy.CheckedRule) *morphgatev1.PolicyExpr
	}{
		{"tarpit", rule("    expr: risk.score > 50\n    action: tarpit\n"), "tarpit is not available in Phase 1", nil},
		{"unknown param", rule("    expr: risk.score > 50\n    action: block\n    params: {delay_ms: 5}\n"), "params.delay_ms is not a Phase 1 parameter", nil},
		{"param for another action", rule("    expr: risk.score > 50\n    action: block\n    params: {label: x}\n"), "params.label does not apply to action block", nil},
		{"tag without label", rule("    expr: risk.score > 50\n    action: tag\n"), "a tag rule needs params.label", nil},
		{"bad label", rule("    expr: risk.score > 50\n    action: tag\n    params: {label: Bad Label}\n"), "a tag rule needs params.label", nil},
		{"attestation", rule("    expr: risk.score > 50\n    action: challenge\n    params: {type: attestation}\n"), `params.type "attestation" is not available in Phase 1`, nil},
		{"retry after", rule("    expr: risk.score > 50\n    action: rate_limit\n    params: {retry_after_s: \"0\"}\n"), "params.retry_after_s", nil},
		{"bad limiter", rule("    expr: risk.score > 50\n    action: rate_limit\n    params: {limiter: Bad}\n"), `params.limiter "Bad" does not match`, nil},
		{"undefined list", rule("    expr: req.path in list(\"nope\")\n    action: block\n"), `list("nope") is not defined in lists or list_files`, nil},
		{"policy compile error", rule("    expr: risk.scor > 50\n    action: block\n"), "p.yaml:", nil},
		{"profile mismatch", "profile: cloudflare\n" + rule("    expr: risk.score > 50\n    action: block\n"), `file declares profile "cloudflare"`, nil},
		{"IR list undefined", rule("    expr: risk.score > 50\n    action: block\n"), `policy IR uses list "ghost"`,
			func(*policy.CheckedRule) *morphgatev1.PolicyExpr {
				return &morphgatev1.PolicyExpr{IrVersion: 1, Root: inList(field("req.path"), namedList("ghost")), MaxSteps: 3}
			}},
		{"ip_in over non-IP list", rule("    expr: has(net.ip) && ip_in(net.ip, list(\"words\"))\n    action: block\n"), `list "words" is used with ip_in() but entry "alpha"`, nil},
		{"step bound", rule("    expr: risk.score > 50\n    action: block\n"), "exceeds the evaluation step bound: 100001 > 100000",
			func(*policy.CheckedRule) *morphgatev1.PolicyExpr {
				return &morphgatev1.PolicyExpr{IrVersion: 1, Root: lit(true), MaxSteps: 100_001}
			}},
		{"IR version", rule("    expr: risk.score > 50\n    action: block\n"), "policy IR has ir_version 2",
			func(*policy.CheckedRule) *morphgatev1.PolicyExpr {
				return &morphgatev1.PolicyExpr{IrVersion: 2, Root: lit(true), MaxSteps: 1}
			}},
		{"missing policy file", "", "no such file", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.policy == "" {
				withLowering(t, nil)
				_, err = Build(loadSite(t, writeSite(t, policyHeader, nil)), BuildOptions{Version: 1, Now: buildTime})
			} else {
				_, err = buildPolicy(t, tc.policy, tc.lower)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestBuildPolicyWarningsAndFilters(t *testing.T) {
	res, err := buildPolicy(t, `policies:
  - {id: a-interactive, phase: bot, expr: risk.score > 50, action: challenge, params: {type: interactive}}
  - {id: b-ip, phase: identity, expr: 'has(net.ip) && ip_in(net.ip, list("ips"))', action: allow}
  - {id: c-disabled, phase: bot, expr: risk.score > 90, action: block, mode: disabled}
  - {id: d-expired, phase: bot, expr: risk.score > 91, action: block, temporary: true, expires_at: 2026-09-27T10:00:00Z}
  - {id: e-later, phase: bot, expr: risk.score > 92, action: block, temporary: true, expires_at: 2026-09-27T10:00:01Z}
  - {id: f-limit, phase: rate_limit, expr: '"per-ip" in rate', action: rate_limit, params: {limiter: other, retry_after_s: "5"}}
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(res.Bundle.Environments[0]); !slices.Equal(got, []string{"b-ip", "f-limit", "a-interactive", "e-later"}) {
		t.Errorf("rules %v (disabled dropped, expiry at build time is expired)", got)
	}
	all := strings.Join(res.Warnings, "\n")
	// The D-08 warning comes from the compiler (WP-G1) or, failing that, the builder.
	for _, w := range []string{"(D-08)", `params.limiter "other" is not a rate limiter`} {
		if !strings.Contains(all, w) {
			t.Errorf("missing warning %q in:\n%s", w, all)
		}
	}
}

func TestBuildListFiles(t *testing.T) {
	y := strings.Replace(policyHeader, "lists:", "list_files: {bad: bad.txt}\nlists:", 1)
	withLowering(t, nil)
	res, err := Build(loadSite(t, writeSite(t, y, map[string]string{"p.yaml": "policies: []\n", "bad.txt": "# c\n\n a \nb # x\n"})), BuildOptions{Version: 1, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Bundle.Lists["bad"].GetEntries(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("list file entries %v", got)
	}
	for name, content := range map[string]string{
		"long entry": strings.Repeat("x", 257) + "\n",
		"too many":   strings.Repeat("x\n", sitecfg.MaxListEntries+1),
		"not utf-8":  "\xff\xfe\n",
	} {
		_, err := Build(loadSite(t, writeSite(t, y, map[string]string{"p.yaml": "policies: []\n", "bad.txt": content})), BuildOptions{Version: 1, Now: buildTime})
		if err == nil || !strings.Contains(err.Error(), "list_files.bad") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Build(loadSite(t, writeSite(t, y, map[string]string{"p.yaml": "policies: []\n"})), BuildOptions{Version: 1, Now: buildTime}); err == nil {
		t.Error("missing list file accepted")
	}
}

func TestBuildRejectsOversizedBundle(t *testing.T) {
	entry := strings.Repeat("y", 250) + "\n"
	files := map[string]string{}
	var listFiles []string
	for i := range 4 {
		name := "l" + string(rune('a'+i))
		files[name+".txt"] = strings.Repeat(entry, sitecfg.MaxListEntries)
		listFiles = append(listFiles, name+": "+name+".txt")
	}
	y := strings.Replace(mustRead(t, minimalYAML), "token:", "list_files: {"+strings.Join(listFiles, ", ")+"}\ntoken:", 1)
	if _, err := Build(loadSite(t, writeSite(t, y, files)), BuildOptions{Version: 1, Now: buildTime}); err == nil || !strings.Contains(err.Error(), "at most 8388608") {
		t.Errorf("oversized bundle: %v", err)
	}
}

// §2.4 item 3: random site variations never panic the builder.
func TestBuildNeverPanics(t *testing.T) {
	withLowering(t, nil)
	seed := []byte(mustRead(t, fullYAML))
	x := xorshift(0xdeadbeefcafef00d)
	for i := 0; i < 2000; i++ {
		s, diags := sitecfg.Parse(fullYAML, x.mutate(seed))
		if s == nil || sitecfg.HasErrors(diags) {
			continue
		}
		_, _ = Build(s, BuildOptions{Version: 1, Now: buildTime})
	}
}

// §2.4 item 3: ≥ 10,000 random policy IR inputs never panic the IR backstop.
func TestCheckIRNeverPanics(t *testing.T) {
	b := &builder{lists: map[string][]string{"ips": {"192.0.2.0/24", "2001:db8::1"}, "words": {"alpha"}}}
	seed, err := proto.Marshal(&morphgatev1.PolicyExpr{IrVersion: 1, MaxSteps: 9,
		Root: or(ipIn(field("net.ip"), namedList("ips")), inList(field("req.path"), namedList("words")), lit(true))})
	if err != nil {
		t.Fatal(err)
	}
	if !b.checkIR("seed", seed) || len(b.problems) != 0 {
		t.Fatalf("seed IR rejected: %v", b.problems)
	}
	x := xorshift(0x94d049bb133111eb)
	for i := 0; i < 10_000; i++ {
		b.checkIR("fuzz", x.mutate(seed))
	}
}
