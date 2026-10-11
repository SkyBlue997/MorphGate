package mgctl

import (
	"encoding/json"
	"strings"
	"testing"

	"morphgate/control-plane/internal/bundle"
)

const phase2Site = sitesDir + "/golden/site-phase2.yaml"

// Phase 2 spec §16: site check / bundle build accept the §10.2 keys and
// write schema_version 2; bundle verify lists the interactive configuration,
// the providers, the proof-required and min_level routes, help_path and
// privacy_path, and the §7.8 reminder for scoring mode enforce.
func TestBundleWorkflowPhase2(t *testing.T) {
	e := newTestEnv(t)
	e.must("keys", "gen", "--kid", "owner-2026", "--out-dir", e.path("keys"), "--insecure-test-key")
	pub := e.path("keys/owner-2026.pub")

	code, out, errs := e.run("site", "check", "--site-config", phase2Site)
	if code != 0 || !strings.HasPrefix(out, "ok: site blog (cloudflare)") || !strings.Contains(errs, "t_pass must be above") {
		t.Fatalf("site check: %d %q %q", code, out, errs)
	}
	e.must("bundle", "build", "--site-config", phase2Site, "--out-dir", e.path("build"), "--version", "1790000000")
	e.must("bundle", "sign", "--in", e.path("build/blog.sitebundle.pb"), "--key", e.path("keys/owner-2026.key.age"), "--out", e.path("blog.bundle"))
	out = e.must("bundle", "verify", "--in", e.path("blog.bundle"), "--pub", pub)
	for _, want := range []string{
		"schema_version 2\n",
		"interactive enabled true  pow_bits 13/15/17/19 x 6  a11y_bits 18  escalate_after 3  scoring enforce (t_pass 0.4, t_block 0.8)  min_pow_ms 250  a11y_min_ms 2500\n",
		"provider turnstile enabled true  sitekey 0x4AAAAAAAkat-test-sitekey  hostnames example.com,www.example.com  routes login,signup  selection escalate_after_fail  mode shadow  timeout_ms 3500  fallback self_hold  deny_countries CN\n",
		"proof required production/api\n",
		"min_level production/api=invisible,production/login=interactive,production/signup=pow\n",
		"help_path /help/verification  privacy_path /privacy?section=verification  default_lang en  refresh true  telemetry_behavior true\n",
		"reminder: interactive scoring is enforce",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}
	var sum bundle.Summary
	if err := json.Unmarshal([]byte(e.must("bundle", "verify", "--in", e.path("blog.bundle"), "--pub", pub, "--json")), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.SchemaVersion != 2 || sum.Phase2 == nil || sum.Phase2.Interactive.PowK != 6 || len(sum.Phase2.Providers) != 1 {
		t.Errorf("json summary %+v", sum)
	}
	// The committed golden bundle verifies with the Phase 1 owner test key.
	out = e.must("bundle", "verify", "--in", sitesDir+"/golden/golden-phase2.bundle", "--pub", phase1Keys+"/owner-test.pub")
	if !strings.Contains(out, "schema_version 2") {
		t.Errorf("golden-phase2.bundle: %q", out)
	}
	// Phase 1 bundles print schema_version 1 and no Phase 2 lines.
	out = e.must("bundle", "verify", "--in", sitesDir+"/golden/golden-rules.bundle", "--pub", phase1Keys+"/owner-test.pub")
	if !strings.Contains(out, "schema_version 1\n") || strings.Contains(out, "interactive enabled") || strings.Contains(out, "reminder:") {
		t.Errorf("golden-rules.bundle: %q", out)
	}
}
