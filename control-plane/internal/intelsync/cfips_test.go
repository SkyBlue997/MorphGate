package intelsync

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
)

var syncTime = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

const cfIPsHostPath = "api.cloudflare.com/client/v4/ips"

// §12.0 / §12.2: the shared valid sample loads, every invalid sample fails.
func TestCloudflareIPsSamples(t *testing.T) {
	good := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
	a, err := ParseCloudflareIPs(good)
	if err != nil {
		t.Fatalf("valid sample rejected: %v", err)
	}
	if len(a.IPv4CIDRs) != 15 || len(a.IPv6CIDRs) != 7 {
		t.Errorf("counts %d/%d", len(a.IPv4CIDRs), len(a.IPv6CIDRs))
	}
	enc, err := a.Encode()
	if err != nil || !bytes.Equal(enc, good) {
		t.Errorf("re-encoding the sample changed its bytes:\n%s", enc)
	}
	for _, f := range mustGlob(t, filepath.Join(phase1Artifacts, "invalid", "cloudflare-ips.*.json")) {
		if _, err := ParseCloudflareIPs(mustRead(t, f)); err == nil {
			t.Errorf("%s: accepted, want rejection", filepath.Base(f))
		}
	}
}

func TestCloudflareIPsValidation(t *testing.T) {
	base := func() *CloudflareIPs {
		a, err := ParseCloudflareIPs(mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json")))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	cases := map[string]func(a *CloudflareIPs){
		"v2":               func(a *CloudflareIPs) { a.V = 2 },
		"http source":      func(a *CloudflareIPs) { a.Source = "http://api.cloudflare.com/client/v4/ips" },
		"bad fetched_at":   func(a *CloudflareIPs) { a.FetchedAt = "2026-09-27 10:00" },
		"empty etag":       func(a *CloudflareIPs) { a.ETag = "" },
		"etag with space":  func(a *CloudflareIPs) { a.ETag = "a b" },
		"v6 in v4 list":    func(a *CloudflareIPs) { a.IPv4CIDRs[0] = "2400:cb00::/32" },
		"v4 in v6 list":    func(a *CloudflareIPs) { a.IPv6CIDRs[0] = "173.245.48.0/20" },
		"too many v6":      func(a *CloudflareIPs) { a.IPv6CIDRs = append(a.IPv6CIDRs, make([]string, 30)...) },
		"too few v6":       func(a *CloudflareIPs) { a.IPv6CIDRs = a.IPv6CIDRs[:1] },
		"non-canonical v6": func(a *CloudflareIPs) { a.IPv6CIDRs[0] = "2400:CB00::/32" },
		"link-local v4":    func(a *CloudflareIPs) { a.IPv4CIDRs[0] = "169.254.0.0/16" },
		"multicast v6":     func(a *CloudflareIPs) { a.IPv6CIDRs[0] = "ff00::/16" },
	}
	for name, mut := range cases {
		a := base()
		mut(a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseCloudflareIPs([]byte(`{"v":1,"kind":"mg-cloudflare-ips","extra":1}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field: %v", err)
	}
	good := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
	if _, err := ParseCloudflareIPs(append(append([]byte(nil), good...), []byte("{}")...)); err == nil {
		t.Error("trailing data accepted")
	}
}

func runCFIPs(t *testing.T, te *testEnv, args ...string) int {
	t.Helper()
	return RunCFIPs(append([]string{"sync"}, args...), te.env)
}

// §12.0: for the sample API response and fetched_at, `cf ips sync` writes the
// shared sample byte for byte; §14.4: it records state and metrics.
func TestCFIPsSyncWritesSampleBytes(t *testing.T) {
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	dir := t.TempDir()
	out := filepath.Join(dir, "cloudflare-ips.json")
	prom := filepath.Join(dir, "cf.prom")
	te := newTestEnv(syncTime, fn.client())

	if code := runCFIPs(t, te, "--out", out, "--metrics-textfile", prom); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, te.errb)
	}
	want := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
	if got := mustRead(t, out); !bytes.Equal(got, want) {
		t.Errorf("artifact differs from testdata/phase1/artifacts/cloudflare-ips.json:\n%s", got)
	}
	st, last, err := ReadSyncState(StatePath(out))
	if err != nil || st.ETag != "38f79d050aa027e3be3865e495dcc9bc" || !last.Equal(syncTime) {
		t.Errorf("state = %+v, %v, %v", st, last, err)
	}
	if got := string(mustRead(t, prom)); !strings.Contains(got, "\nmg_cf_ips_sync_timestamp_seconds 1790503200\n") ||
		!strings.Contains(got, "# TYPE mg_cf_ips_sync_timestamp_seconds gauge") {
		t.Errorf("textfile:\n%s", got)
	}
	if len(te.audits) != 1 || te.audits[0].Action != "cf.ips.sync" || te.audits[0].ResourceID != "cloudflare-ips" {
		t.Errorf("audits = %+v", te.audits)
	}
	if fn.uas[0] != UserAgent {
		t.Errorf("User-Agent %q", fn.uas[0])
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("artifact mode: %v %v", st.Mode(), err)
	}
}

// §14.4: the same etag leaves the artifact untouched but still records the
// success (state + metrics); nothing is audited.
func TestCFIPsSyncUnchangedEtag(t *testing.T) {
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	dir := t.TempDir()
	out := filepath.Join(dir, "cloudflare-ips.json")
	te := newTestEnv(syncTime, fn.client())
	if code := runCFIPs(t, te, "--out", out); code != cli.ExitOK {
		t.Fatalf("first sync: %d %s", code, te.errb)
	}
	first := mustRead(t, out)

	later := syncTime.Add(24 * time.Hour)
	te2 := newTestEnv(later, fn.client())
	prom := filepath.Join(dir, "cf.prom")
	if code := runCFIPs(t, te2, "--out", out, "--metrics-textfile", prom); code != cli.ExitOK {
		t.Fatalf("second sync: %d %s", code, te2.errb)
	}
	if !bytes.Equal(mustRead(t, out), first) {
		t.Error("artifact rewritten although the etag did not change")
	}
	if !strings.Contains(te2.out.String(), "unchanged") {
		t.Errorf("stdout: %s", te2.out)
	}
	if len(te2.audits) != 0 {
		t.Errorf("unchanged sync audited: %+v", te2.audits)
	}
	if _, last, err := ReadSyncState(StatePath(out)); err != nil || !last.Equal(later) {
		t.Errorf("state not refreshed: %v %v", last, err)
	}
	if !strings.Contains(string(mustRead(t, prom)), "mg_cf_ips_sync_timestamp_seconds 1790589600") {
		t.Error("metrics not refreshed")
	}
}

// A new etag with a small change is written and audited; one over 30% needs
// --accept-change.
func TestCFIPsSyncChangeProtection(t *testing.T) {
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	dir := t.TempDir()
	out := filepath.Join(dir, "cloudflare-ips.json")
	if code := runCFIPs(t, newTestEnv(syncTime, fn.client()), "--out", out); code != cli.ExitOK {
		t.Fatal("seed sync failed")
	}
	orig := mustRead(t, out)

	// +1 IPv4 range (15 -> 16) is accepted.
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.added.json"))
	te := newTestEnv(syncTime.Add(time.Hour), fn.client())
	if code := runCFIPs(t, te, "--out", out); code != cli.ExitOK {
		t.Fatalf("small change: %d %s", code, te.errb)
	}
	a, err := ParseCloudflareIPs(mustRead(t, out))
	if err != nil || len(a.IPv4CIDRs) != 16 {
		t.Fatalf("after small change: %v %v", a, err)
	}
	if len(te.audits) != 1 {
		t.Errorf("change not audited")
	} else if d, ok := te.audits[0].Diff.(cfIPsDiff); !ok || d.PreviousIPv4 != 15 || d.IPv4 != 16 {
		t.Errorf("diff = %+v", te.audits[0].Diff)
	}

	// 16 -> 5 IPv4 ranges is refused and leaves the file alone.
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.shrunk.json"))
	before := mustRead(t, out)
	te = newTestEnv(syncTime.Add(2*time.Hour), fn.client())
	if code := runCFIPs(t, te, "--out", out); code != cli.ExitFailed {
		t.Fatalf("big change: exit %d, want %d", code, cli.ExitFailed)
	}
	if !strings.Contains(te.errb.String(), "--accept-change") {
		t.Errorf("stderr: %s", te.errb)
	}
	if !bytes.Equal(mustRead(t, out), before) {
		t.Error("refused change modified the artifact")
	}
	if _, last, _ := ReadSyncState(StatePath(out)); !last.Equal(syncTime.Add(time.Hour)) {
		t.Error("a refused sync must not record success")
	}

	// --accept-change writes it.
	te = newTestEnv(syncTime.Add(3*time.Hour), fn.client())
	if code := runCFIPs(t, te, "--out", out, "--accept-change"); code != cli.ExitOK {
		t.Fatalf("accept-change: %d %s", code, te.errb)
	}
	if a, _ := ParseCloudflareIPs(mustRead(t, out)); a == nil || len(a.IPv4CIDRs) != 5 {
		t.Error("accept-change did not write the new ranges")
	}

	// An explicit --previous is used for the comparison.
	prev := filepath.Join(dir, "previous.json")
	if err := os.WriteFile(prev, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.json")
	te = newTestEnv(syncTime.Add(4*time.Hour), fn.client())
	if code := runCFIPs(t, te, "--out", other, "--previous", prev); code != cli.ExitFailed {
		t.Errorf("--previous not honoured: exit %d", code)
	}
}

// Invalid ranges or a failed API response never produce an artifact.
func TestCFIPsSyncRejectsBadResponses(t *testing.T) {
	cases := map[string]struct {
		fixture string
		status  int
		code    int
		errHas  string
	}{
		"host bits":     {"api-ips.host-bits.json", 200, cli.ExitFailed, "host bits"},
		"private":       {"api-ips.private.json", 200, cli.ExitFailed, "private"},
		"success=false": {"api-ips.failure.json", 200, cli.ExitFailed, "success is not true"},
		"http 500":      {"api-ips.json", 500, cli.ExitInternal, "HTTP 500"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fn := newFakeNet(t)
			fn.set(cfIPsHostPath, fakeResp{status: tc.status, body: mustRead(t, filepath.Join(intelFixtures, "cloudflare", tc.fixture))})
			out := filepath.Join(t.TempDir(), "cloudflare-ips.json")
			te := newTestEnv(syncTime, fn.client())
			if code := runCFIPs(t, te, "--out", out); code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, te.errb)
			}
			if !strings.Contains(te.errb.String(), tc.errHas) {
				t.Errorf("stderr %q lacks %q", te.errb, tc.errHas)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Error("artifact written")
			}
			if _, err := os.Stat(StatePath(out)); !errors.Is(err, os.ErrNotExist) {
				t.Error("state written for a failed sync")
			}
		})
	}
}

func TestCFIPsFlags(t *testing.T) {
	te := newTestEnv(syncTime, http.DefaultClient)
	cases := []struct {
		args   []string
		errHas string
	}{
		{[]string{}, "--out is required"},
		{[]string{"--out", "x", "--url", "http://api.cloudflare.com/client/v4/ips"}, "https"},
		{[]string{"--out", "x", "extra"}, "unexpected arguments"},
		{[]string{"--nope"}, "flag provided but not defined"},
	}
	for _, tc := range cases {
		te.errb.Reset()
		if code := runCFIPs(t, te, tc.args...); code != cli.ExitUsage {
			t.Errorf("%v: exit %d", tc.args, code)
		}
		if !strings.Contains(te.errb.String(), tc.errHas) {
			t.Errorf("%v: stderr %q lacks %q", tc.args, te.errb, tc.errHas)
		}
	}
	if code := RunCFIPs(nil, te.env); code != cli.ExitUsage {
		t.Errorf("no subcommand: %d", code)
	}
	// --audit-log is accepted (the dispatcher binds env.Audit to it).
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	te = newTestEnv(syncTime, fn.client())
	if code := runCFIPs(t, te, "--out", filepath.Join(t.TempDir(), "c.json"), "--audit-log", "/dev/null"); code != cli.ExitOK {
		t.Errorf("--audit-log: exit %d %s", code, te.errb)
	}
}

// A failing audit append is exit 3 (§14.1), after the artifact was written.
func TestCFIPsAuditFailure(t *testing.T) {
	fn := newFakeNet(t)
	fn.setFile(cfIPsHostPath, filepath.Join(intelFixtures, "cloudflare/api-ips.json"))
	te := newTestEnv(syncTime, fn.client())
	te.env.Audit = func(cli.AuditEvent) error { return errors.New("disk full") }
	if code := runCFIPs(t, te, "--out", filepath.Join(t.TempDir(), "c.json")); code != cli.ExitInternal {
		t.Errorf("exit %d, want %d", code, cli.ExitInternal)
	}
}

// Redirects are limited to three https hops.
func TestFetchRedirects(t *testing.T) {
	fn := newFakeNet(t)
	fn.set("a.example.net/1", fakeResp{status: 302, location: "https://b.example.net/2"})
	fn.set("b.example.net/2", fakeResp{status: 301, location: "https://c.example.net/3"})
	fn.set("c.example.net/3", fakeResp{status: 307, location: "https://d.example.net/4"})
	fn.set("d.example.net/4", fakeResp{body: []byte("ok")})
	fn.set("e.example.net/5", fakeResp{status: 302, location: "https://a.example.net/1"})
	fn.set("f.example.net/6", fakeResp{status: 302, location: "http://d.example.net/4"})
	fc := fetchConfig{client: fn.client(), timeout: 5 * time.Second}
	if b, err := fc.fetch(context.Background(), "https://a.example.net/1", "*/*", 100); err != nil || string(b) != "ok" {
		t.Errorf("3 redirects: %q %v", b, err)
	}
	if _, err := fc.fetch(context.Background(), "https://e.example.net/5", "*/*", 100); err == nil || !strings.Contains(err.Error(), "more than 3 redirects") {
		t.Errorf("4 redirects: %v", err)
	}
	if _, err := fc.fetch(context.Background(), "https://f.example.net/6", "*/*", 100); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("https -> http: %v", err)
	}
	if fn.hitCount("d.example.net/4") != 1 {
		t.Error("the http redirect target must not be requested over https either")
	}
	if _, err := fc.fetch(context.Background(), "http://d.example.net/4", "*/*", 100); err == nil {
		t.Error("http URL accepted")
	}
	if _, err := fc.fetch(context.Background(), "https://user:pw@d.example.net/4", "*/*", 100); err == nil || strings.Contains(err.Error(), "pw") {
		t.Errorf("credentials in URL: %v", err)
	}
}

func TestFetchLimits(t *testing.T) {
	fn := newFakeNet(t)
	fn.set("big.example.net/x", fakeResp{body: bytes.Repeat([]byte("a"), 1001)})
	fn.set("slow.example.net/x", fakeResp{body: []byte("late"), delay: 2 * time.Second})
	fn.set("gone.example.net/x", fakeResp{status: 404})
	fc := fetchConfig{client: fn.client(), timeout: 300 * time.Millisecond}
	if _, err := fc.fetch(context.Background(), "https://big.example.net/x", "*/*", 1000); !errors.Is(err, errTooLarge) {
		t.Errorf("oversized: %v", err)
	}
	if b, err := fc.fetch(context.Background(), "https://big.example.net/x", "*/*", 1001); err != nil || len(b) != 1001 {
		t.Errorf("at the limit: %v", err)
	}
	start := time.Now()
	if _, err := fc.fetch(context.Background(), "https://slow.example.net/x", "*/*", 1000); err == nil {
		t.Error("timeout not applied")
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Error("timeout took too long")
	}
	if _, err := fc.fetch(context.Background(), "https://gone.example.net/x", "*/*", 1000); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("404: %v", err)
	}
}
