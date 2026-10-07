package mgctl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"morphgate/control-plane/internal/audit"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
)

const (
	sitesDir   = "../../testdata/sites"
	goldenSite = sitesDir + "/golden/site.yaml"
	fullSite   = sitesDir + "/valid/full.yaml"
	phase1Keys = "../../../testdata/phase1/keys"
)

var cliNow = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

// testEnv runs mgctl commands in a temporary workspace with a passphrase
// file, work factor 10 and a private audit log. MGCTL_PASSPHRASE_FILE is
// always set so no test ever prompts on a terminal.
type testEnv struct {
	t     *testing.T
	dir   string
	vars  map[string]string
	audit cli.AuditFunc // nil: the real audit log
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	pass := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(pass, []byte("test passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testEnv{t: t, dir: dir, vars: map[string]string{
		keys.EnvPassphraseFile: pass,
		keys.EnvWorkFactor:     "10",
		audit.EnvAuditLog:      filepath.Join(dir, "state", "audit.jsonl"),
		"HOME":                 dir,
	}}
}

func (e *testEnv) path(p string) string { return filepath.Join(e.dir, p) }

func (e *testEnv) run(args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	code := RunEnv(args, cli.Env{
		Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(""),
		Now:    func() time.Time { return cliNow },
		Getenv: func(k string) string { return e.vars[k] },
		Audit:  e.audit,
	})
	return code, out.String(), errb.String()
}

// must runs a command that has to succeed.
func (e *testEnv) must(args ...string) string {
	e.t.Helper()
	code, out, errs := e.run(args...)
	if code != cli.ExitOK {
		e.t.Fatalf("mgctl %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

func (e *testEnv) expect(code int, stderrHas string, args ...string) {
	e.t.Helper()
	got, out, errs := e.run(args...)
	if got != code || !strings.Contains(errs, stderrHas) {
		e.t.Errorf("mgctl %s: exit %d (want %d), stderr %q (want %q), stdout %q", strings.Join(args, " "), got, code, errs, stderrHas, out)
	}
}

func (e *testEnv) records() []audit.Record {
	e.t.Helper()
	data, err := os.ReadFile(e.vars[audit.EnvAuditLog])
	if err != nil {
		return nil
	}
	var out []audit.Record
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (e *testEnv) lastRecord() audit.Record {
	e.t.Helper()
	rs := e.records()
	if len(rs) == 0 {
		e.t.Fatal("no audit records")
	}
	return rs[len(rs)-1]
}

func (e *testEnv) export(in string) []byte {
	e.t.Helper()
	return []byte(e.must("keys", "export", "--in", in))
}

// withRand makes key generation read a fixed byte stream.
func withRand(t *testing.T, b []byte) {
	old := randReader
	randReader = bytes.NewReader(b)
	t.Cleanup(func() { randReader = old })
}

// §12.6: owner key generation, work-factor guard, no overwrite, audit diff.
func TestKeysGen(t *testing.T) {
	e := newTestEnv(t)
	e.expect(cli.ExitUsage, "need --insecure-test-key", "keys", "gen", "--kid", "owner-2026", "--out-dir", e.path("keys"))
	if _, err := os.Stat(e.path("keys")); !os.IsNotExist(err) {
		t.Error("a refused keys gen created files")
	}
	_, out, errs := e.run("keys", "gen", "--kid", "owner-2026", "--out-dir", e.path("keys"), "--insecure-test-key")
	if !strings.Contains(errs, "WARNING: --insecure-test-key") || !strings.Contains(out, "owner-2026.pub") {
		t.Errorf("stdout %q stderr %q", out, errs)
	}
	for p, mode := range map[string]os.FileMode{e.path("keys/owner-2026.key.age"): 0o600, e.path("keys/owner-2026.pub"): 0o644} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v", p, err)
		}
	}
	k, err := keys.LoadOwnerKey(e.path("keys/owner-2026.key.age"), []byte("test passphrase"))
	if err != nil || k.KID != "owner-2026" || !k.CreatedAt.Equal(cliNow) {
		t.Fatalf("generated key: %v %v", k, err)
	}
	rec := e.lastRecord()
	var diff map[string]any
	json.Unmarshal(rec.Diff, &diff)
	if rec.Action != "keys.gen" || rec.ResourceType != "owner_key" || rec.ResourceID != "owner-2026" ||
		diff["work_factor"] != float64(10) || diff["insecure_test_key"] != true {
		t.Errorf("audit record %+v diff %v", rec, diff)
	}
	if bytes.Contains(rec.Diff, []byte(hex.EncodeToString(k.Private.Seed()))) {
		t.Error("the audit diff contains key material")
	}
	e.expect(cli.ExitFailed, "already exists", "keys", "gen", "--kid", "owner-2026", "--out-dir", e.path("keys"), "--insecure-test-key")
	e.expect(cli.ExitUsage, "--kid is required", "keys", "gen", "--out-dir", e.path("keys"))
	e.expect(cli.ExitUsage, "does not match", "keys", "gen", "--kid", "Owner", "--out-dir", e.path("keys"), "--insecure-test-key")
	e.expect(cli.ExitUsage, "unexpected argument", "keys", "gen", "--kid", "a", "--out-dir", "x", "extra")
	e.vars[keys.EnvWorkFactor] = "9"
	e.expect(cli.ExitUsage, "between 10 and 22", "keys", "gen", "--kid", "x", "--out-dir", e.path("k2"), "--insecure-test-key")
}

// §12.7, §17: site keys, rotation in place, export to stdout and to a file.
func TestSiteKeysAndExport(t *testing.T) {
	e := newTestEnv(t)
	e.must("site", "keys", "gen", "--site", "blog", "--out-dir", e.path("blog"), "--date", "20260927", "--insecure-test-key")
	token, seal := e.path("blog/token.keys.json.age"), e.path("blog/seal.root.json.age")
	info, err := keys.Inspect(e.export(token))
	if err != nil || info.Site != "blog" || info.IDs[0] != "blog-t-20260927" {
		t.Fatalf("token keys %+v %v", info, err)
	}
	if rec := e.lastRecord(); rec.Action != "keys.export" || !strings.Contains(string(rec.Diff), `"target":"pipe"`) || strings.Contains(string(rec.Diff), `"key"`) {
		t.Errorf("export record %+v %s", rec, rec.Diff)
	}
	e.expect(cli.ExitFailed, "already exists", "site", "keys", "gen", "--site", "blog", "--out-dir", e.path("blog"), "--insecure-test-key")

	if out := e.must("site", "keys", "rotate-token", "--site", "blog", "--file", token, "--date", "20260928", "--insecure-test-key"); out != "blog-t-20260928\n" {
		t.Errorf("rotate-token printed %q", out)
	}
	if info, _ := keys.Inspect(e.export(token)); strings.Join(info.IDs, ",") != "blog-t-20260928,blog-t-20260927" {
		t.Errorf("after rotation %v", info.IDs)
	}
	e.expect(cli.ExitFailed, `belongs to site "blog", not "shop"`, "site", "keys", "rotate-token", "--site", "shop", "--file", token, "--insecure-test-key")
	e.expect(cli.ExitFailed, "want mg-site-token-keys", "site", "keys", "rotate-token", "--site", "blog", "--file", seal, "--insecure-test-key")

	for _, step := range []struct{ step, want string }{
		{"add", "blog-r-20260927,blog-r-20261027"},
		{"promote", "blog-r-20261027,blog-r-20260927"},
		{"retire", "blog-r-20261027"},
	} {
		e.must("site", "keys", "rotate-seal", "--site", "blog", "--file", seal, "--step", step.step, "--date", "20261027", "--insecure-test-key")
		if info, _ := keys.Inspect(e.export(seal)); strings.Join(info.IDs, ",") != step.want {
			t.Errorf("after %s: %v, want %s", step.step, info.IDs, step.want)
		}
		if rec := e.records(); rec[len(rec)-2].Action != "site_keys.rotate_seal" {
			t.Errorf("no rotate_seal record before the export")
		}
	}
	e.expect(cli.ExitFailed, "no second root to retire", "site", "keys", "rotate-seal", "--site", "blog", "--file", seal, "--step", "retire", "--insecure-test-key")
	e.expect(cli.ExitUsage, `--step "swap"`, "site", "keys", "rotate-seal", "--site", "blog", "--file", seal, "--step", "swap")

	// Export to a 0600 file, never over an existing one.
	e.must("keys", "export", "--in", seal, "--out", e.path("seal.root.json"))
	if st, err := os.Stat(e.path("seal.root.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("exported file: %v", err)
	}
	e.expect(cli.ExitFailed, "already exists", "keys", "export", "--in", seal, "--out", e.path("seal.root.json"))
	if rec := e.lastRecord(); rec.Action != "keys.export" || !strings.Contains(string(rec.Diff), `"target":"file"`) {
		t.Errorf("file export record %s", rec.Diff)
	}
	// Wrong passphrase.
	os.WriteFile(e.vars[keys.EnvPassphraseFile], []byte("wrong\n"), 0o600)
	e.expect(cli.ExitFailed, "cannot decrypt", "keys", "export", "--in", token)
	e.expect(cli.ExitFailed, "cannot decrypt", "site", "keys", "rotate-token", "--site", "blog", "--file", token, "--insecure-test-key")
}

// §14.1 verdict key equals kat.json entity_key for the kat pseudonymisation key.
func TestPseudoKeyAndVerdictKey(t *testing.T) {
	e := newTestEnv(t)
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i) // kat.json entity_key.k_pseudo_hex
	}
	withRand(t, seq)
	e.must("keys", "gen-pseudo", "--out", e.path("pseudo.key.json.age"), "--insecure-test-key")
	fixture, _ := os.ReadFile(phase1Keys + "/pseudo.key.json")
	if got := e.export(e.path("pseudo.key.json.age")); !bytes.Equal(got, fixture) {
		t.Errorf("gen-pseudo plaintext differs from the shared fixture:\n%s", got)
	}
	count := len(e.records())
	for _, tc := range []struct{ site, typ, value, want string }{
		{"blog", "ip", "203.0.113.7", "mg:v:blog:ip:083956bb9c00bbcfdac40338c45b515a"},
		{"all", "prefix", "203.0.113.0/24", "mg:v:all:prefix:66e68905fcd729e0729795701f890bff"},
		{"blog", "ip", "2001:db8::1", "mg:v:blog:ip:3b645483868f3dcc072bef9eebc3dda5"},
		{"blog", "asn", "64500", "mg:v:blog:asn:64500"},
	} {
		out := e.must("verdict", "key", "--pseudo-key", e.path("pseudo.key.json.age"), "--site", tc.site, "--type", tc.typ, "--value", tc.value)
		if out != tc.want+"\n" {
			t.Errorf("verdict key %s %s %s = %q, want %q", tc.site, tc.typ, tc.value, out, tc.want)
		}
	}
	if len(e.records()) != count {
		t.Error("verdict key wrote audit records (it is read-only)")
	}
	e.expect(cli.ExitFailed, "not an IP address", "verdict", "key", "--pseudo-key", e.path("pseudo.key.json.age"), "--site", "blog", "--type", "ip", "--value", "nope")
	e.expect(cli.ExitUsage, "expected a subcommand: key", "verdict", "keys")
	e.expect(cli.ExitFailed, "already exists", "keys", "gen-pseudo", "--out", e.path("pseudo.key.json.age"), "--insecure-test-key")
}

func TestUpstreamKeys(t *testing.T) {
	e := newTestEnv(t)
	out := e.must("keys", "gen-upstream", "--out", e.path("up.json.age"), "--insecure-test-key")
	first := strings.TrimSpace(out)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(first) {
		t.Fatalf("value %q", out)
	}
	e.expect(cli.ExitFailed, "already exists", "keys", "gen-upstream", "--out", e.path("up.json.age"), "--insecure-test-key")
	second := strings.TrimSpace(e.must("keys", "gen-upstream", "--out", e.path("up.json.age"), "--rotate", "--insecure-test-key"))
	plain := e.export(e.path("up.json.age"))
	var f struct{ Values []string }
	json.Unmarshal(plain, &f)
	if len(f.Values) != 2 || f.Values[0] != second || f.Values[1] != first {
		t.Errorf("after rotation %v (want [%s %s])", f.Values, second, first)
	}
	third := strings.TrimSpace(e.must("keys", "gen-upstream", "--out", e.path("up.json.age"), "--rotate", "--insecure-test-key"))
	json.Unmarshal(e.export(e.path("up.json.age")), &f)
	if len(f.Values) != 2 || f.Values[0] != third || f.Values[1] != second {
		t.Errorf("keeps two values: %v", f.Values)
	}
	for _, r := range e.records() {
		if bytes.Contains(r.Diff, []byte(first)) || bytes.Contains(r.Diff, []byte(second)) {
			t.Errorf("audit record %s contains a secret value", r.Action)
		}
	}
	e.expect(cli.ExitFailed, "--rotate", "keys", "gen-upstream", "--out", e.path("missing.age"), "--rotate", "--insecure-test-key")
	// Owner signing keys are never exported.
	e.must("keys", "gen", "--kid", "o", "--out-dir", e.path("k"), "--insecure-test-key")
	e.expect(cli.ExitFailed, "never exported", "keys", "export", "--in", e.path("k/o.key.age"))
}

// The bundle workflow of §17: build -> sign -> verify -> publish, audited.
func TestBundleWorkflow(t *testing.T) {
	e := newTestEnv(t)
	e.must("keys", "gen", "--kid", "owner-2026", "--out-dir", e.path("keys"), "--insecure-test-key")
	pub := e.path("keys/owner-2026.pub")

	if out := e.must("site", "check", "--site-config", goldenSite); !strings.HasPrefix(out, "ok: site blog (cloudflare): 2 environment(s), 0 rule(s)") {
		t.Errorf("site check: %q", out)
	}
	out := e.must("bundle", "build", "--site-config", goldenSite, "--out-dir", e.path("build"), "--version", "1790000000")
	if !strings.Contains(out, "built blog version 1790000000") {
		t.Errorf("build: %q", out)
	}
	for _, f := range []string{"build/blog.sitebundle.pb", "build/blog.sitebundle.json"} {
		if _, err := os.Stat(e.path(f)); err != nil {
			t.Error(err)
		}
	}
	js, _ := os.ReadFile(e.path("build/blog.sitebundle.json"))
	if !bytes.Contains(js, []byte(`"siteId"`)) {
		t.Errorf("protojson output %s", js)
	}
	e.must("bundle", "sign", "--in", e.path("build/blog.sitebundle.pb"), "--key", e.path("keys/owner-2026.key.age"), "--out", e.path("blog.bundle"))
	if rec := e.lastRecord(); rec.Action != "bundle.sign" || rec.ResourceID != "blog@1790000000" || rec.Site != "blog" ||
		!strings.Contains(string(rec.Diff), `"monitor_only":true`) || !strings.Contains(string(rec.Diff), `"rules":0`) {
		t.Errorf("sign record %+v %s", rec, rec.Diff)
	}
	out = e.must("bundle", "verify", "--in", e.path("blog.bundle"), "--pub", pub, "--site", "blog")
	if !strings.Contains(out, "ok: signature by owner-2026 verifies") || !strings.Contains(out, "env production") {
		t.Errorf("verify: %q", out)
	}
	var sum map[string]any
	if err := json.Unmarshal([]byte(e.must("bundle", "verify", "--in", e.path("blog.bundle"), "--pub", pub, "--json")), &sum); err != nil || sum["site"] != "blog" {
		t.Errorf("verify --json: %v %v", sum, err)
	}
	e.expect(cli.ExitFailed, `not "shop"`, "bundle", "verify", "--in", e.path("blog.bundle"), "--pub", pub, "--site", "shop")
	e.expect(cli.ExitFailed, "untrusted key id", "bundle", "verify", "--in", e.path("blog.bundle"), "--pub", phase1Keys+"/owner-test.pub")
	e.expect(cli.ExitUsage, "at least one --pub", "bundle", "verify", "--in", e.path("blog.bundle"))
	// §14.1: an unreadable or invalid key file is invalid input (1), not a usage error.
	e.expect(cli.ExitFailed, "no such file", "bundle", "verify", "--in", e.path("blog.bundle"), "--pub", e.path("missing.pub"))
	e.expect(cli.ExitFailed, "public_key", "bundle", "verify", "--in", e.path("blog.bundle"), "--pub", phase1Keys+"/invalid/owner-test.pub.short-key.json")

	publish := []string{"bundle", "publish", "--in", e.path("blog.bundle"), "--artifacts", e.path("build/artifacts"), "--dest", e.path("srv"), "--pub", pub}
	e.expect(cli.ExitUsage, "--confirm <site> is required", publish...)
	e.expect(cli.ExitFailed, "--confirm does not match", append(publish, "--confirm", "shop")...)
	e.must(append(publish, "--confirm", "blog", "--metrics-textfile", e.path("metrics/mg_bundle.prom"))...)
	if prom, _ := os.ReadFile(e.path("metrics/mg_bundle.prom")); !strings.Contains(string(prom), `mg_bundle_published_version{site="blog"} 1790000000`) {
		t.Errorf("textfile %q", prom)
	}
	if rec := e.lastRecord(); rec.Action != "bundle.publish" || rec.ConfirmText != "blog" || !strings.Contains(string(rec.Diff), `"previous_version":0`) {
		t.Errorf("publish record %+v %s", rec, rec.Diff)
	}
	e.expect(cli.ExitFailed, "not newer", append(publish, "--confirm", "blog")...)

	// audit verify: every write above is in the chain.
	out = e.must("audit", "verify")
	if !strings.Contains(out, "3 record(s)") {
		t.Errorf("audit verify: %q", out)
	}
	logPath := e.vars[audit.EnvAuditLog]
	data, _ := os.ReadFile(logPath)
	i := bytes.LastIndex(data, []byte(`"rules":0`))
	data[i+len(`"rules":`)] = '9'
	os.WriteFile(logPath, data, 0o600)
	e.expect(cli.ExitFailed, "line 2:", "audit", "verify")
	e.expect(cli.ExitFailed, "no audit log", "audit", "verify", "--audit-log", e.path("nope.jsonl"))
}

// With policy IR (WP-G1), a site with rules builds end to end.
func TestBundleBuildWithRules(t *testing.T) {
	e := newTestEnv(t)
	e.must("bundle", "build", "--site-config", fullSite, "--out-dir", e.path("b"), "--version", "7")
	entries, _ := os.ReadDir(e.path("b/artifacts"))
	if len(entries) != 4 {
		t.Errorf("copied artifacts %v", entries)
	}
	e.expect(cli.ExitFailed, "is invalid", "site", "check", "--site-config", sitesDir+"/invalid/challenge-ttl.yaml")
	e.expect(cli.ExitFailed, "", "site", "check", "--site-config", e.path("missing.yaml"))
}

// §14.1: an audit log that cannot be used fails write commands with exit
// code 3 before anything is written; a failed append after the write also
// exits 3.
func TestAuditFailureExitsThree(t *testing.T) {
	e := newTestEnv(t)
	os.WriteFile(e.path("file"), nil, 0o600)
	e.vars[audit.EnvAuditLog] = e.path("file/audit.jsonl")
	e.expect(cli.ExitInternal, "audit log", "keys", "gen", "--kid", "k", "--out-dir", e.path("keys"), "--insecure-test-key")
	if _, err := os.Stat(e.path("keys/k.key.age")); !os.IsNotExist(err) {
		t.Error("a key was written although the audit log was unusable")
	}
	delete(e.vars, audit.EnvAuditLog)
	delete(e.vars, "HOME")
	e.expect(cli.ExitInternal, "cannot place the audit log", "keys", "gen-pseudo", "--out", e.path("p.age"), "--insecure-test-key")

	e2 := newTestEnv(t)
	e2.audit = func(cli.AuditEvent) error { return errors.New("disk full") }
	e2.expect(cli.ExitInternal, "audit record could not be written: disk full", "keys", "gen-pseudo", "--out", e2.path("p.age"), "--insecure-test-key")
}

// failingTransport fails every request and remembers that one was tried: the
// syncs below must not reach it (they stop at the audit check), and even if
// they did, nothing would leave the process.
type failingTransport struct{ tried *int }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	*f.tried++
	return nil, errors.New("no network in tests")
}

// Ruling I-27: the dispatcher binds the audit log check to the intelligence
// syncs of internal/intelsync too, so `cf ips sync` and `crawler sync` with
// an unusable audit log exit 3 before they fetch or write anything.
func TestSyncWriteCommandsCheckAuditLogFirst(t *testing.T) {
	e := newTestEnv(t)
	if err := os.WriteFile(e.path("file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.vars[audit.EnvAuditLog] = e.path("file/audit.jsonl") // below a regular file
	source := e.path("crawler-source.yaml")
	if err := os.WriteFile(source, []byte(`version: 1
operators:
  - id: examplebot
    name: Example bot
    purpose: search
    ua_tokens: [ExampleBot]
    verify:
      mode: ip_ranges
      ip_ranges:
        - url: https://127.0.0.1:9/examplebot.json
          format: prefixes_json
`), 0o600); err != nil {
		t.Fatal(err)
	}
	tried := 0
	for _, args := range [][]string{
		{"cf", "ips", "sync", "--out", e.path("out/cloudflare-ips.json"), "--url", "https://127.0.0.1:9/ips", "--metrics-textfile", e.path("out/cf.prom")},
		{"crawler", "sync", "--registry", source, "--out", e.path("out/crawler-registry.json")},
	} {
		if err := os.MkdirAll(e.path("out"), 0o700); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := RunEnv(args, cli.Env{
			Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(""),
			Now:    func() time.Time { return cliNow },
			Getenv: func(k string) string { return e.vars[k] },
			HTTP:   &http.Client{Transport: failingTransport{&tried}},
		})
		if code != cli.ExitInternal || !strings.Contains(errb.String(), "audit log") {
			t.Errorf("mgctl %s: exit %d, stderr %q; want exit 3 naming the audit log", strings.Join(args, " "), code, errb.String())
		}
		if entries, _ := os.ReadDir(e.path("out")); len(entries) != 0 {
			t.Errorf("mgctl %s wrote %d file(s) although the audit log was unusable", strings.Join(args, " "), len(entries))
		}
	}
	if tried != 0 {
		t.Errorf("%d request(s) attempted although the audit log was unusable", tried)
	}
}

// Ruling I-27 with a log that exists and reads fine but cannot be appended
// to (a read-only file): the preflight must catch it, not the append after
// the key, artifact, state file or textfile was written.
func TestReadOnlyAuditLogFailsBeforeAnyWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not bind root")
	}
	e := newTestEnv(t)
	e.must("keys", "gen-pseudo", "--out", e.path("first.age"), "--insecure-test-key")
	logPath := e.vars[audit.EnvAuditLog]
	if err := os.Chmod(logPath, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })
	if err := os.MkdirAll(e.path("out"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := e.path("crawler-source.yaml")
	if err := os.WriteFile(source, []byte(`version: 1
operators:
  - id: examplebot
    name: Example bot
    purpose: search
    ua_tokens: [ExampleBot]
    verify:
      mode: ip_ranges
      ip_ranges:
        - url: https://127.0.0.1:9/examplebot.json
          format: prefixes_json
`), 0o600); err != nil {
		t.Fatal(err)
	}
	tried := 0
	for _, args := range [][]string{
		{"keys", "gen-pseudo", "--out", e.path("out/p.age"), "--insecure-test-key"},
		{"cf", "ips", "sync", "--out", e.path("out/cloudflare-ips.json"), "--url", "https://127.0.0.1:9/ips", "--metrics-textfile", e.path("out/cf.prom")},
		{"crawler", "sync", "--registry", source, "--out", e.path("out/crawler-registry.json")},
	} {
		var out, errb bytes.Buffer
		code := RunEnv(args, cli.Env{
			Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(""),
			Now:    func() time.Time { return cliNow },
			Getenv: func(k string) string { return e.vars[k] },
			HTTP:   &http.Client{Transport: failingTransport{&tried}},
		})
		if code != cli.ExitInternal || !strings.Contains(errb.String(), "audit log") || strings.Contains(errb.String(), "the change was made") {
			t.Errorf("mgctl %s: exit %d, stderr %q; want exit 3 from the audit log check, before any change", strings.Join(args, " "), code, errb.String())
		}
		if entries, _ := os.ReadDir(e.path("out")); len(entries) != 0 {
			t.Errorf("mgctl %s wrote %d file(s) although the audit log was read-only", strings.Join(args, " "), len(entries))
		}
	}
	if tried != 0 {
		t.Errorf("%d request(s) attempted although the audit log was read-only", tried)
	}
	if n, _, err := audit.Verify(logPath); err != nil || n != 1 {
		t.Errorf("audit log after the refused commands: %d records, %v", n, err)
	}
}

func TestAuditLogFlagPlacement(t *testing.T) {
	for _, args := range [][]string{
		{"--audit-log", "LOG", "keys", "gen-pseudo", "--out", "OUT", "--insecure-test-key"},
		{"keys", "gen-pseudo", "--audit-log=LOG", "--out", "OUT", "--insecure-test-key"},
		{"keys", "gen-pseudo", "--out", "OUT", "--insecure-test-key", "-audit-log", "LOG"},
	} {
		e := newTestEnv(t)
		for i := range args {
			args[i] = strings.NewReplacer("LOG", e.path("custom/log.jsonl"), "OUT", e.path("p.age")).Replace(args[i])
		}
		e.must(args...)
		if n, _, err := audit.Verify(e.path("custom/log.jsonl")); err != nil || n != 1 {
			t.Errorf("%v: %d %v", args, n, err)
		}
		if _, err := os.Stat(e.vars[audit.EnvAuditLog]); !os.IsNotExist(err) {
			t.Errorf("%v: the default log was written", args)
		}
	}
	e := newTestEnv(t)
	e.expect(cli.ExitUsage, "flag needs an argument: --audit-log", "keys", "gen-pseudo", "--audit-log")
}

func TestExtractAuditLog(t *testing.T) {
	rest, p, err := extractAuditLog([]string{"a", "--audit-log", "x", "b", "--", "--audit-log", "y"})
	if err != nil || p != "x" || strings.Join(rest, " ") != "a b -- --audit-log y" {
		t.Errorf("%v %q %v", rest, p, err)
	}
	if _, _, err := extractAuditLog([]string{"--audit-log="}); err == nil {
		t.Error("empty value accepted")
	}
}

// The help text names every §14.1 command.
func TestUsageListsAllCommands(t *testing.T) {
	_, out, _ := run("help")
	for _, c := range []string{"keys gen ", "keys gen-pseudo", "keys gen-upstream", "keys export", "site keys gen", "site keys rotate-token",
		"site keys rotate-seal", "verdict key", "site check", "bundle build", "bundle sign", "bundle verify", "bundle publish",
		"audit verify", "cf audit", "cf ips sync", "crawler sync", "--audit-log", "MGCTL_PASSPHRASE_FILE", "MGCTL_AGE_WORK_FACTOR"} {
		if !strings.Contains(out, c) {
			t.Errorf("usage lacks %q", c)
		}
	}
}

func TestDispatchErrors(t *testing.T) {
	e := newTestEnv(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"keys"}, "expected a subcommand"},
		{[]string{"keys", "rotate"}, `unknown subcommand "rotate"`},
		{[]string{"site"}, "expected a subcommand: check | keys"},
		{[]string{"site", "keys"}, "expected a subcommand: gen | rotate-token | rotate-seal"},
		{[]string{"site", "keys", "drop"}, `unknown subcommand "drop"`},
		{[]string{"site", "lint"}, `unknown subcommand "lint"`},
		{[]string{"bundle"}, "expected a subcommand: build | sign | verify | publish"},
		{[]string{"bundle", "push"}, `unknown subcommand "push"`},
		{[]string{"audit"}, "expected a subcommand: verify"},
		{[]string{"bundle", "build", "--site-config", "x"}, "--out-dir is required"},
		{[]string{"site", "keys", "gen", "--site", "Blog", "--out-dir", "x"}, "does not match"},
		{[]string{"site", "keys", "gen", "--site", "blog", "--out-dir", "x", "--date", "2026-09-27"}, "is not YYYYMMDD"},
	} {
		e.expect(cli.ExitUsage, tc.want, tc.args...)
	}
	e.expect(cli.ExitFailed, "not a schema_version 1 SiteBundle", "bundle", "sign", "--in", phase1Keys+"/owner-test.pub", "--key", "k", "--out", e.path("o"))

}
