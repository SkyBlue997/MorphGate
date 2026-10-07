package intelsync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morphgate/control-plane/internal/cli"
)

// Ruling I-27: `cf ips sync` and `crawler sync` confirm that the audit log is
// usable before they fetch or write anything. An unusable log (AuditReady
// fails, or no log at all) exits 3 with no request sent, no artifact, state
// or metrics file written and an existing artifact left as it was.
func TestSyncsCheckTheAuditLogFirst(t *testing.T) {
	broken := map[string]func(*testEnv){
		"log not usable": func(te *testEnv) {
			te.env.AuditReady = func() error { return errors.New("read-only file system") }
		},
		"no log": func(te *testEnv) { te.env.Audit = nil },
	}
	for name, breakLog := range broken {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			prev := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
			out := filepath.Join(dir, "cloudflare-ips.json")
			if err := os.WriteFile(out, prev, 0o644); err != nil {
				t.Fatal(err)
			}
			fn := newFakeNet(t)
			fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.added.json"))
			te := newTestEnv(syncTime, fn.client())
			breakLog(te)
			if code := runCFIPs(t, te, "--out", out, "--metrics-textfile", filepath.Join(dir, "cf.prom"), "--accept-change"); code != cli.ExitInternal {
				t.Errorf("cf ips sync: exit %d, want %d: %s", code, cli.ExitInternal, te.errb)
			}
			if !strings.Contains(te.errb.String(), "audit log") {
				t.Errorf("cf ips sync: stderr %q does not name the audit log", te.errb)
			}
			if fn.hitCount(cfIPsHostPath) != 0 {
				t.Error("cf ips sync fetched the ranges although the audit log was unusable")
			}

			fn = crawlerFakeNet(t)
			te = newTestEnv(syncTime, fn.client())
			breakLog(te)
			if code := runCrawler(t, te, "--registry", crawlerSource, "--out", filepath.Join(dir, "crawler-registry.json")); code != cli.ExitInternal {
				t.Errorf("crawler sync: exit %d, want %d: %s", code, cli.ExitInternal, te.errb)
			}
			if !strings.Contains(te.errb.String(), "audit log") {
				t.Errorf("crawler sync: stderr %q does not name the audit log", te.errb)
			}
			for _, hp := range []string{googleRanges, gptbotRanges, archiveRanges, archiveExtra} {
				if fn.hitCount(hp) != 0 {
					t.Errorf("crawler sync fetched %s although the audit log was unusable", hp)
				}
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "cloudflare-ips.json" {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Errorf("files written although the audit log was unusable: %v", names)
			}
			if got := mustRead(t, out); string(got) != string(prev) {
				t.Error("the existing artifact was changed")
			}
			if len(te.audits) != 0 {
				t.Errorf("audit records: %v", te.audits)
			}
		})
	}
}

// The preflight runs once per sync and lets a usable log through: the syncs
// write and audit as before.
func TestSyncsAuditPreflightPasses(t *testing.T) {
	dir := t.TempDir()
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	te := newTestEnv(syncTime, fn.client())
	checks := 0
	te.env.AuditReady = func() error { checks++; return nil }
	if code := runCFIPs(t, te, "--out", filepath.Join(dir, "cloudflare-ips.json")); code != cli.ExitOK {
		t.Fatalf("cf ips sync: exit %d: %s", code, te.errb)
	}
	fn = crawlerFakeNet(t)
	te2 := newTestEnv(syncTime, fn.client())
	te2.env.AuditReady = te.env.AuditReady
	if code := runCrawler(t, te2, "--registry", crawlerSource, "--out", filepath.Join(dir, "crawler-registry.json")); code != cli.ExitOK {
		t.Fatalf("crawler sync: exit %d: %s", code, te2.errb)
	}
	if checks != 2 || len(te.audits) != 1 || len(te2.audits) != 1 {
		t.Errorf("%d preflight checks, audits %v / %v", checks, te.audits, te2.audits)
	}
}
