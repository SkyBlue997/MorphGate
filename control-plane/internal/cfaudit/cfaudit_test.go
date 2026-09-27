package cfaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/intelsync"
)

const (
	scenarioRoot = "../../testdata/cloudflare"
	testToken    = "cf-audit-test-token"
	// The x-mg-upstream-key value of the green fixture; it must never be
	// printed.
	fixtureUpstreamKey = "Zml4dHVyZS11cHN0cmVhbS1rZXktbm90LXNlY3JldCE"
)

var auditNow = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

// fakeCF serves a fixture scenario (see testdata/cloudflare/README.md).
type fakeCF struct {
	t    *testing.T
	dirs []string // scenario first, then its base
	mu   sync.Mutex
	reqs []*http.Request
}

func scenarioDirs(t *testing.T, scenario string) []string {
	t.Helper()
	dir := filepath.Join(scenarioRoot, scenario)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenario %s: %v", scenario, err)
	}
	dirs := []string{dir}
	if b, err := os.ReadFile(filepath.Join(dir, "base")); err == nil {
		dirs = append(dirs, filepath.Join(scenarioRoot, strings.TrimSpace(string(b))))
	}
	return dirs
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		f.t.Errorf("audit sent %s %s: it must be read-only", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/client/v4/")
	if rel == "zones" && r.URL.Query().Get("name") == "" {
		f.t.Errorf("zone lookup without name")
	}
	for _, dir := range f.dirs {
		for _, st := range []int{403, 404} {
			if b, err := os.ReadFile(filepath.Join(dir, "api", fmt.Sprintf("%s.%d.json", rel, st))); err == nil {
				w.WriteHeader(st)
				_, _ = w.Write(b)
				return
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "api", rel+".json")); err == nil {
			_, _ = w.Write(b)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"Could not route"}],"messages":[],"result":null}`))
}

type auditRun struct {
	code   int
	stdout string
	stderr string
	rep    *Report
	fake   *fakeCF
}

func (r *auditRun) status(id string) Status {
	for _, c := range r.rep.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func (r *auditRun) detail(id string) string {
	for _, c := range r.rep.Checks {
		if c.ID == id {
			return c.Detail
		}
	}
	return ""
}

func siteFile(t *testing.T, scenario string) string {
	for _, d := range scenarioDirs(t, scenario) {
		if p := filepath.Join(d, "site.yaml"); fileExists(p) {
			return p
		}
	}
	t.Fatalf("no site.yaml for %s", scenario)
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// audit runs `mgctl cf audit --json` against a scenario.
func audit(t *testing.T, scenario string, args ...string) *auditRun {
	t.Helper()
	fake := &fakeCF{t: t, dirs: scenarioDirs(t, scenario)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	var out, errb bytes.Buffer
	vars := map[string]string{"CLOUDFLARE_API_TOKEN": testToken, "MGCTL_CF_API_BASE": srv.URL + "/client/v4"}
	env := cli.Env{
		Stdout: &out, Stderr: &errb, Now: func() time.Time { return auditNow },
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		Getenv: func(k string) string { return vars[k] },
		Audit:  func(cli.AuditEvent) error { t.Error("cf audit must not write the audit log"); return nil },
	}
	full := append([]string{"--site-config", siteFile(t, scenario), "--json"}, args...)
	code := RunCLI(full, env)
	run := &auditRun{code: code, stdout: out.String(), stderr: errb.String(), fake: fake}
	if out.Len() > 0 {
		run.rep = &Report{}
		if err := json.Unmarshal(out.Bytes(), run.rep); err != nil {
			t.Fatalf("stdout is not a JSON report: %v\n%s", err, out.String())
		}
	}
	for _, s := range []string{run.stdout, run.stderr} {
		if strings.Contains(s, fixtureUpstreamKey) || strings.Contains(s, testToken) {
			t.Errorf("output leaks a secret:\n%s", s)
		}
	}
	return run
}

// freshCFIPs writes a valid Cloudflare IP artifact with a state file whose
// last success is age before auditNow.
func freshCFIPs(t *testing.T, age time.Duration) string {
	t.Helper()
	dir := t.TempDir()
	art := filepath.Join(dir, "cloudflare-ips.json")
	data, err := os.ReadFile("../../../testdata/phase1/artifacts/cloudflare-ips.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art, data, 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ := intelsync.EncodeCanonical(intelsync.SyncState{V: 1, LastSuccess: auditNow.Add(-age).Format(time.RFC3339), ETag: "38f79d050aa027e3be3865e495dcc9bc"})
	if err := os.WriteFile(intelsync.StatePath(art), st, 0o644); err != nil {
		t.Fatal(err)
	}
	return art
}

// fakeVM answers instant queries: the first matching substring decides the
// sample value ("" = empty result).
func fakeVM(t *testing.T, values map[string]string, status int) (string, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("VictoriaMetrics path %s", r.URL.Path)
		}
		q := r.URL.Query().Get("query")
		mu.Lock()
		queries = append(queries, q)
		mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		result := `[]`
		for k, v := range values {
			if strings.Contains(q, k) && v != "" {
				result = fmt.Sprintf(`[{"metric":{},"value":[1790589600,%q]}]`, v)
			}
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":%s}}`, result)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &queries
}

// §14.3 "all green": a Pro zone behind a healthy Tunnel, with runtime
// metrics and a fresh IP snapshot, passes every check once Precursor is
// acknowledged.
func TestAuditGreenTunnel(t *testing.T) {
	vm, queries := fakeVM(t, map[string]string{"mg_requests_total": "1000"}, 0)
	prom := filepath.Join(t.TempDir(), "cf-audit.prom")
	r := audit(t, "green", "--ack", "precursor=off in the dashboard, checked 2026-09-28",
		"--cf-ips", freshCFIPs(t, 3*time.Hour), "--vm-url", vm, "--metrics-textfile", prom)
	if r.code != cli.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	want := map[string]Status{
		"origin_protection": StatusPass, "ssl_mode": StatusSkip, "aop_cert_expiry": StatusSkip,
		"remove_visitor_ip_headers": StatusPass, "visitor_location_headers": StatusPass,
		"transform_rule_signals": StatusPass, "pseudo_ipv4": StatusPass, "zero_rtt": StatusPass,
		"bot_fight_mode": StatusSkip, "sbfm_skip": StatusPass, "skip_rule_order": StatusPass,
		"cache_bypass_mg": StatusPass, "ttl_override_trap": StatusPass, "cf_challenge_overlap": StatusPass,
		"rocket_loader": StatusPass, "ai_bot_policy": StatusPass, "precursor": StatusPass,
		"runtime_metrics": StatusPass, "ip_snapshot_age": StatusPass, "optional_rules": StatusPass,
		"always_use_https": StatusPass,
	}
	if len(r.rep.Checks) != 21 {
		t.Fatalf("%d checks, want 21", len(r.rep.Checks))
	}
	for i, c := range r.rep.Checks {
		if c.N != i+1 {
			t.Errorf("check %d has n=%d", i+1, c.N)
		}
		if c.Status != want[c.ID] {
			t.Errorf("%s = %s (%s), want %s", c.ID, c.Status, c.Detail, want[c.ID])
		}
	}
	if r.rep.Zone != "example.com" || r.rep.Plan != "pro" || r.rep.Errors != 0 {
		t.Errorf("report header %+v", r.rep)
	}
	if d := r.detail("transform_rule_signals"); !strings.Contains(d, "x-mg-upstream-key set by mg_upstream_key_v1 (value not shown)") {
		t.Errorf("transform detail: %s", d)
	}
	if !strings.Contains(r.detail("precursor"), "acknowledged: off in the dashboard") {
		t.Errorf("precursor: %s", r.detail("precursor"))
	}
	for _, q := range *queries {
		if strings.Contains(q, "site=") && !strings.Contains(q, `site="blog"`) {
			t.Errorf("query not scoped to the site: %s", q)
		}
	}
	prometheus, err := os.ReadFile(prom)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prometheus)
	if strings.Count(text, "mg_cf_audit_failed_checks{zone=\"example.com\",check=") != 21 ||
		strings.Contains(text, "} 1\n") ||
		!strings.Contains(text, "mg_cf_audit_last_run_timestamp_seconds{zone=\"example.com\"} 1790589600\n") {
		t.Errorf("textfile:\n%s", text)
	}
	for _, req := range r.fake.reqs {
		if req.Header.Get("User-Agent") != "morphgate-dev-tooling" {
			t.Errorf("User-Agent %q", req.Header.Get("User-Agent"))
		}
	}
}

// A Free zone behind zone-level AOP; Rocket Loader is on but the SDK
// template opts out.
func TestAuditGreenFreeAOP(t *testing.T) {
	sdk := filepath.Join(scenarioRoot, "green-free-aop", "sdk")
	r := audit(t, "green-free-aop", "--sdk-dir", sdk, "--ack", "precursor=off")
	if r.code != cli.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	want := map[string]Status{
		"origin_protection": StatusPass, "ssl_mode": StatusPass, "aop_cert_expiry": StatusPass,
		"transform_rule_signals": StatusPass, "bot_fight_mode": StatusPass, "sbfm_skip": StatusSkip,
		"skip_rule_order": StatusPass, "rocket_loader": StatusPass, "runtime_metrics": StatusSkip,
		"ip_snapshot_age": StatusSkip, "optional_rules": StatusPass, "always_use_https": StatusPass,
		"visitor_location_headers": StatusPass,
	}
	for id, st := range want {
		if got := r.status(id); got != st {
			t.Errorf("%s = %s (%s), want %s", id, got, r.detail(id), st)
		}
	}
	if !strings.Contains(r.detail("origin_protection"), "zone-level AOP enabled with 1 active certificate") {
		t.Errorf("origin: %s", r.detail("origin_protection"))
	}
	if !strings.Contains(r.detail("always_use_https"), "HSTS unknown") {
		t.Errorf("https: %s", r.detail("always_use_https"))
	}
	// 404 entry point = no rate limiting rules.
	if !strings.Contains(r.detail("optional_rules"), "no /__mg/ flood") {
		t.Errorf("optional_rules: %s", r.detail("optional_rules"))
	}
	// Without --sdk-dir Rocket Loader cannot be cleared.
	r = audit(t, "green-free-aop")
	if r.status("rocket_loader") != StatusWarn || r.status("precursor") != StatusManual || r.code != cli.ExitOK {
		t.Errorf("rocket_loader %s, precursor %s, exit %d", r.status("rocket_loader"), r.status("precursor"), r.code)
	}
}

// §14.3: each error-level check fails on its own misconfiguration, and the
// exit code is 1.
func TestAuditErrorChecksFail(t *testing.T) {
	cases := []struct {
		scenario, check, detail string
	}{
		{"tunnel-down", "origin_protection", `status "down"`},
		{"aop-global-only", "origin_protection", "only global AOP"},
		{"aop-host-partial", "origin_protection", "AOP is not enabled for www.example.org"},
		{"ssl-flexible", "ssl_mode", "ssl = flexible"},
		{"remove-ip-headers", "remove_visitor_ip_headers", "CF-Connecting-IP never reaches the Edge"},
		{"transform-incomplete", "transform_rule_signals", "x-mg-cf-rtt missing"},
		{"transform-incomplete", "transform_rule_signals", `x-mg-cf-vbot = "http.request.headers[\"x-client-bot\"][0]"`},
		{"transform-incomplete", "transform_rule_signals", "x-mg-cf-t1 must be removed"},
		{"transform-incomplete", "transform_rule_signals", "rule owner-asn-override also changes x-mg-cf-asn"},
		{"transform-hosts", "transform_rule_signals", "does not cover www.example.org"},
		{"transform-missing", "transform_rule_signals", "no enabled mg_signals_v* rule"},
		{"upstream-key-placeholder", "transform_rule_signals", "still holds the template placeholder"},
		{"pseudo-overwrite", "pseudo_ipv4", "pseudo_ipv4_overwrite is false"},
		{"bfm-on", "bot_fight_mode", "Bot Fight Mode is on"},
		{"sbfm-block", "sbfm_skip", "Definitely Automated must be Allow"},
		{"sbfm-no-skip", "sbfm_skip", "no mg_skip_mg_paths rule skips http_request_sbfm"},
		{"cache-bypass-not-last", "cache_bypass_mg", "rule 2 of 3; rules after it (api-no-cache)"},
		{"cache-missing", "cache_bypass_mg", "no cache rules"},
		{"ttl-trap", "ttl_override_trap", "html-cache"},
		{"https-off", "always_use_https", "always_use_https = off"},
	}
	for _, tc := range cases {
		t.Run(tc.scenario+"/"+tc.check, func(t *testing.T) {
			r := audit(t, tc.scenario)
			if r.code != cli.ExitFailed {
				t.Errorf("exit %d, want %d", r.code, cli.ExitFailed)
			}
			if r.status(tc.check) != StatusFail {
				t.Errorf("%s = %s (%s), want fail", tc.check, r.status(tc.check), r.detail(tc.check))
			}
			if !strings.Contains(r.detail(tc.check), tc.detail) {
				t.Errorf("%s detail %q lacks %q", tc.check, r.detail(tc.check), tc.detail)
			}
			if r.rep.Errors < 1 {
				t.Errorf("errors = %d", r.rep.Errors)
			}
		})
	}
}

// Findings that come with the error scenarios but are warnings.
func TestAuditWarnings(t *testing.T) {
	r := audit(t, "sbfm-block")
	if r.status("skip_rule_order") != StatusWarn ||
		!strings.Contains(r.detail("skip_rule_order"), "geo-challenge run before mg_skip_mg_paths") ||
		!strings.Contains(r.detail("skip_rule_order"), "disabling the /__mg/ flood rule(s) mg_flood_mg_paths") {
		t.Errorf("skip_rule_order: %s %s", r.status("skip_rule_order"), r.detail("skip_rule_order"))
	}
	if r.status("optional_rules") != StatusWarn {
		t.Errorf("optional_rules: %s", r.status("optional_rules"))
	}

	r = audit(t, "warnings")
	if r.code != cli.ExitOK {
		t.Errorf("warnings only: exit %d", r.code)
	}
	want := map[string]string{
		"cf_challenge_overlap":     "login-challenge (/account/login)",
		"ai_bot_policy":            "ai_bots_protection=only_on_ad_pages",
		"zero_rtt":                 "0rtt = on",
		"rocket_loader":            "pass --sdk-dir",
		"visitor_location_headers": "not available on this plan",
	}
	for id, d := range want {
		if r.status(id) != StatusWarn || !strings.Contains(r.detail(id), d) {
			t.Errorf("%s = %s %q, want warn with %q", id, r.status(id), r.detail(id), d)
		}
	}
	// A challenge rule that excludes /__mg/ and the routes with `and not
	// starts_with(...)` (docs/08 §2.7) does not overlap them; a negated
	// conjunction still matches /__mg/ on other hosts.
	if d := r.detail("cf_challenge_overlap"); strings.Contains(d, "wp-challenge") || !strings.Contains(d, "other-hosts-challenge (/__mg)") {
		t.Errorf("cf_challenge_overlap: %s", d)
	}

	r = audit(t, "aop-per-hostname", "--ack", "precursor=off")
	if r.status("origin_protection") != StatusPass || !strings.Contains(r.detail("origin_protection"), "per-hostname AOP enabled for all 2 host(s)") {
		t.Errorf("per-hostname: %s", r.detail("origin_protection"))
	}
	if r.status("aop_cert_expiry") != StatusWarn || !strings.Contains(r.detail("aop_cert_expiry"), "www.example.org expires 2026-10-10T00:00:00Z (11 days left)") {
		t.Errorf("expiry: %s %s", r.status("aop_cert_expiry"), r.detail("aop_cert_expiry"))
	}
}

// §14.3: permission errors make the affected checks manual; --strict turns
// error-level manual checks into failures.
func TestAuditForbiddenIsManual(t *testing.T) {
	r := audit(t, "forbidden")
	manual := []string{"origin_protection", "remove_visitor_ip_headers", "visitor_location_headers", "sbfm_skip",
		"skip_rule_order", "cf_challenge_overlap", "ai_bot_policy", "optional_rules", "precursor"}
	for _, id := range manual {
		if r.status(id) != StatusManual {
			t.Errorf("%s = %s (%s), want manual", id, r.status(id), r.detail(id))
		}
	}
	if !strings.Contains(r.detail("ai_bot_policy"), `"Bot Management Read"`) ||
		!strings.Contains(r.detail("origin_protection"), "Cloudflare Tunnel Read") {
		t.Errorf("permission hints: %s / %s", r.detail("ai_bot_policy"), r.detail("origin_protection"))
	}
	if r.status("cache_bypass_mg") != StatusPass || r.code != cli.ExitOK || r.rep.Errors != 0 {
		t.Errorf("readable checks or exit wrong: %s exit %d errors %d", r.status("cache_bypass_mg"), r.code, r.rep.Errors)
	}
	r = audit(t, "forbidden", "--strict")
	if r.code != cli.ExitFailed || r.rep.Errors != 3 {
		t.Errorf("--strict: exit %d, errors %d (want 3 error-level manual checks)", r.code, r.rep.Errors)
	}
	// --ack confirms a manual check.
	r = audit(t, "forbidden", "--strict", "--ack", "origin_protection=tunnel healthy in the dashboard",
		"--ack", "remove_visitor_ip_headers=off", "--ack", "sbfm_skip=groups allow")
	if r.code != cli.ExitOK || r.status("origin_protection") != StatusPass {
		t.Errorf("acked: exit %d, origin %s", r.code, r.status("origin_protection"))
	}
}

// --ack ttl_override_trap:<ref>=<note> accepts one reviewed cache rule.
func TestAuditTTLAckByRef(t *testing.T) {
	r := audit(t, "ttl-trap", "--ack", "ttl_override_trap:html-cache=HTML never carries challenges on this host")
	if r.status("ttl_override_trap") != StatusPass || !strings.Contains(r.detail("ttl_override_trap"), "html-cache (acknowledged") {
		t.Errorf("%s %s", r.status("ttl_override_trap"), r.detail("ttl_override_trap"))
	}
	if r.code != cli.ExitOK {
		t.Errorf("exit %d", r.code)
	}
	// A plain ack does not clear a failing check.
	r = audit(t, "ttl-trap", "--ack", "ttl_override_trap=whatever")
	if r.status("ttl_override_trap") != StatusFail || !strings.Contains(r.stderr, "had no effect") {
		t.Errorf("plain ack: %s, stderr %q", r.status("ttl_override_trap"), r.stderr)
	}
}

// Check 18 against a fake VictoriaMetrics.
func TestAuditRuntimeMetrics(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]string
		status int
		want   Status
		detail string
	}{
		{"zero", map[string]string{"mg_requests_total": "5000"}, 0, StatusPass, "worst signal missing rate 0.00%"},
		{"foreign worker", map[string]string{"mg_cf_foreign_worker_total": "3"}, 0, StatusFail, "mg_cf_foreign_worker_total"},
		{"missing ip", map[string]string{"mg_cf_connecting_ip_missing_total": "1"}, 0, StatusFail, "mg_cf_connecting_ip_missing_total"},
		{"bad secret", map[string]string{"bad_secret_header": "12"}, 0, StatusFail, "bad_secret_header"},
		{"missing rate", map[string]string{"mg_upstream_signal_missing_total": "50", "mg_requests_total": "1000"}, 0, StatusWarn, "5.00%"},
		// No request samples at all: the zeros prove nothing (wrong --vm-url,
		// or the Edge is not scraped), so the check cannot pass.
		{"no traffic", map[string]string{}, 0, StatusWarn, "no mg_requests_total samples in 24 h"},
		{"vm down", nil, 500, StatusFail, "VictoriaMetrics query failed"},
		// NaN compares false with 0: it must not read as "no increase".
		{"nan", map[string]string{"mg_cf_foreign_worker_total": "NaN", "mg_requests_total": "1000"}, 0, StatusFail, "not a finite number"},
		{"nan rate", map[string]string{"mg_upstream_signal_missing_total": "NaN", "mg_requests_total": "1000"}, 0, StatusFail, "not a finite number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vm, queries := fakeVM(t, tc.values, tc.status)
			r := audit(t, "green", "--vm-url", vm)
			if r.status("runtime_metrics") != tc.want || !strings.Contains(r.detail("runtime_metrics"), tc.detail) {
				t.Errorf("%s %q, want %s with %q", r.status("runtime_metrics"), r.detail("runtime_metrics"), tc.want, tc.detail)
			}
			// The client-controlled hdr-names signal never counts (§9.3).
			for _, q := range *queries {
				if strings.Contains(q, "mg_upstream_signal_missing_total") && !strings.Contains(q, `signal!="hdr-names"`) {
					t.Errorf("missing-rate query includes hdr-names: %s", q)
				}
			}
		})
	}
}

// Check 19: the snapshot's state file dates the last successful sync.
func TestAuditIPSnapshotAge(t *testing.T) {
	r := audit(t, "green", "--cf-ips", freshCFIPs(t, 72*time.Hour))
	if r.status("ip_snapshot_age") != StatusWarn || !strings.Contains(r.detail("ip_snapshot_age"), "72h0m0s ago") {
		t.Errorf("stale: %s %s", r.status("ip_snapshot_age"), r.detail("ip_snapshot_age"))
	}
	art := freshCFIPs(t, time.Hour)
	if err := os.Remove(intelsync.StatePath(art)); err != nil {
		t.Fatal(err)
	}
	r = audit(t, "green", "--cf-ips", art)
	if r.status("ip_snapshot_age") != StatusWarn || !strings.Contains(r.detail("ip_snapshot_age"), "no sync state") {
		t.Errorf("no state: %s %s", r.status("ip_snapshot_age"), r.detail("ip_snapshot_age"))
	}
	bad := filepath.Join(t.TempDir(), "cf.json")
	if err := os.WriteFile(bad, []byte(`{"v":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r = audit(t, "green", "--cf-ips", bad)
	if r.status("ip_snapshot_age") != StatusWarn || !strings.Contains(r.detail("ip_snapshot_age"), "not a valid artifact") {
		t.Errorf("invalid artifact: %s %s", r.status("ip_snapshot_age"), r.detail("ip_snapshot_age"))
	}
	// The artifact is read with the §12.1 size limit: an endless file (a
	// wrong path such as a device) ends the read instead of exhausting memory.
	if fileExists("/dev/zero") {
		r = audit(t, "green", "--cf-ips", "/dev/zero")
		if r.status("ip_snapshot_age") != StatusWarn || !strings.Contains(r.detail("ip_snapshot_age"), "larger than") {
			t.Errorf("endless file: %s %s", r.status("ip_snapshot_age"), r.detail("ip_snapshot_age"))
		}
	}
}

// §14.3 check 13 with stacked cache rules: settings of every matching rule
// combine (docs/08 §2.6), so a TTL override in one rule and "Eligible for
// cache" in another make the same trap as one rule with both.
func TestAuditTTLStackedRules(t *testing.T) {
	r := audit(t, "ttl-trap-stacked")
	d := r.detail("ttl_override_trap")
	if r.status("ttl_override_trap") != StatusFail || !strings.Contains(d, "default-ttl") || !strings.Contains(d, "blog-eligible") {
		t.Errorf("stacked: %s %s", r.status("ttl_override_trap"), d)
	}
	if strings.Contains(d, "static-assets") || strings.Contains(d, "images-ttl") {
		t.Errorf("static-only rules reported: %s", d)
	}
	if r.code != cli.ExitFailed {
		t.Errorf("exit %d", r.code)
	}
	// The override rule is the one to acknowledge.
	r = audit(t, "ttl-trap-stacked", "--ack", "ttl_override_trap:default-ttl=blog pages never carry challenges")
	if r.status("ttl_override_trap") != StatusPass || r.code != cli.ExitOK {
		t.Errorf("acked: %s %s exit %d", r.status("ttl_override_trap"), r.detail("ttl_override_trap"), r.code)
	}
}

func TestAuditCLIErrors(t *testing.T) {
	var out, errb bytes.Buffer
	vars := map[string]string{"CLOUDFLARE_API_TOKEN": testToken}
	env := cli.Env{Stdout: &out, Stderr: &errb, Now: func() time.Time { return auditNow }, Getenv: func(k string) string { return vars[k] }}
	site := siteFile(t, "green")
	cases := []struct {
		args   []string
		code   int
		errHas string
	}{
		{nil, cli.ExitUsage, "--site-config is required"},
		{[]string{"--site-config", site, "extra"}, cli.ExitUsage, "unexpected arguments"},
		{[]string{"--site-config", site, "--ack", "nope=x"}, cli.ExitUsage, `unknown check "nope"`},
		{[]string{"--site-config", site, "--ack", "precursor="}, cli.ExitUsage, "want <check>=<note>"},
		{[]string{"--site-config", site, "--ack", "ssl_mode:r1=x"}, cli.ExitUsage, "only ttl_override_trap"},
		{[]string{"--site-config", site, "--vm-url", "ftp://vm"}, cli.ExitUsage, "--vm-url"},
		{[]string{"--site-config", filepath.Join(t.TempDir(), "none.yaml")}, cli.ExitFailed, "no such file"},
	}
	for _, tc := range cases {
		out.Reset()
		errb.Reset()
		if code := RunCLI(tc.args, env); code != tc.code || !strings.Contains(errb.String(), tc.errHas) {
			t.Errorf("%v: exit %d, stderr %q; want %d with %q", tc.args, code, errb.String(), tc.code, tc.errHas)
		}
	}
	// No token.
	delete(vars, "CLOUDFLARE_API_TOKEN")
	errb.Reset()
	if code := RunCLI([]string{"--site-config", site}, env); code != cli.ExitUsage || !strings.Contains(errb.String(), "CLOUDFLARE_API_TOKEN") {
		t.Errorf("no token: %d %s", code, errb.String())
	}
	// A plain-http API base off loopback is refused before any request.
	vars["CLOUDFLARE_API_TOKEN"] = testToken
	vars["MGCTL_CF_API_BASE"] = "http://api.example.com/client/v4"
	errb.Reset()
	if code := RunCLI([]string{"--site-config", site}, env); code != cli.ExitUsage || !strings.Contains(errb.String(), "loopback") {
		t.Errorf("http base: %d %s", code, errb.String())
	}
	// Unknown zone.
	r := audit(t, "zone-missing")
	if r.code != cli.ExitFailed || !strings.Contains(r.stderr, "zone not found") {
		t.Errorf("zone missing: %d %s", r.code, r.stderr)
	}
	// Unreachable API.
	vars["MGCTL_CF_API_BASE"] = "http://127.0.0.1:1/client/v4"
	errb.Reset()
	if code := RunCLI([]string{"--site-config", site}, env); code != cli.ExitInternal {
		t.Errorf("unreachable API: exit %d %s", code, errb.String())
	}
}

// Without --json the report is a table with a summary line.
func TestAuditTable(t *testing.T) {
	fake := &fakeCF{t: t, dirs: scenarioDirs(t, "https-off")}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	var out, errb bytes.Buffer
	vars := map[string]string{"CLOUDFLARE_API_TOKEN": testToken, "MGCTL_CF_API_BASE": srv.URL + "/client/v4"}
	env := cli.Env{Stdout: &out, Stderr: &errb, Now: func() time.Time { return auditNow }, Getenv: func(k string) string { return vars[k] }}
	if code := RunCLI([]string{"--site-config", siteFile(t, "https-off")}, env); code != cli.ExitFailed {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"site blog, zone example.com (plan pro, origin tunnel)", "#   ID", "21  always_use_https", "fail", "1 error-level failure(s)"} {
		if !strings.Contains(s, want) {
			t.Errorf("table lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, fixtureUpstreamKey) {
		t.Error("table leaks the upstream key")
	}
}

func TestLoadSite(t *testing.T) {
	good := string(mustRead(t, siteFile(t, "green")))
	s, err := ParseSite("site.yaml", []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if s.Site != "blog" || s.Cloudflare.OriginMode != "tunnel" || len(s.Hosts) != 2 || len(s.routePaths()) != 3 {
		t.Errorf("site %+v", s)
	}
	bad := map[string]string{
		"direct_tls":       strings.Replace(good, "profile: cloudflare", "profile: direct_tls", 1),
		"no cloudflare":    good[:strings.Index(good, "cloudflare:\n")] + "token: {}\n",
		"bad origin mode":  strings.Replace(good, "origin_mode: tunnel", "origin_mode: vpn", 1),
		"bad host":         strings.Replace(good, "www.example.com]", "www.example.com/x]", 1),
		"tunnel id alone":  strings.Replace(good, "  account_id: 01a7362d577a6c3019a474fd6f485823\n", "", 1),
		"bad tunnel id":    strings.Replace(good, "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", "../../etc", 1),
		"bad site id":      strings.Replace(good, "site: blog", "site: Blog!", 1),
		"no hosts":         strings.Replace(good, "hosts: [example.com, www.example.com]\nallowed", "hosts: []\nallowed", 1),
		"zone without dot": strings.Replace(good, "zone: example.com", "zone: localhost", 1),
		"empty":            "",
	}
	for name, y := range bad {
		if _, err := ParseSite("site.yaml", []byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unknown keys are ignored (the audit reads only what it needs).
	if _, err := ParseSite("site.yaml", []byte(good+"future_key: 1\n")); err != nil {
		t.Errorf("unknown key: %v", err)
	}
	// origin_mode defaults to tunnel.
	s, err = ParseSite("site.yaml", []byte(strings.Replace(good, "  origin_mode: tunnel\n", "", 1)))
	if err != nil || s.Cloudflare.OriginMode != "tunnel" {
		t.Errorf("default origin mode: %v %v", s, err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
