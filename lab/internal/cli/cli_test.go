package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"morphgate/lab/internal/guard"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

func runWith(opts []guard.Option, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, opts)
	return code, out.String(), errb.String()
}

func TestCheck(t *testing.T) {
	res := staticResolver{
		"app.test":  {netip.MustParseAddr("127.0.0.1")},
		"evil.test": {netip.MustParseAddr("93.184.216.34")},
	}
	opts := []guard.Option{guard.WithResolver(res)}
	cases := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"check", "http://localhost:8080/"}, ExitOK, "allow  http://localhost:8080/"},
		{[]string{"check", "http://2130706433/"}, ExitOK, "allow  http://127.0.0.1/"},
		{[]string{"check", "http://localhost.evil.com/"}, ExitDenied, `host "localhost.evil.com" is not in the lab allowlist`},
		{[]string{"check", "http://localhost@evil.com/"}, ExitDenied, "userinfo"},
		{[]string{"check", "-resolve", "http://app.test/"}, ExitOK, "resolves to [127.0.0.1]"},
		{[]string{"check", "-resolve", "http://evil.test/"}, ExitDenied, "resolved to 93.184.216.34"},
		{[]string{"check"}, ExitUsage, ""},
		{[]string{"check", "-config", "missing.yaml", "http://localhost/"}, ExitUsage, ""},
		{[]string{"nope"}, ExitUsage, ""},
		{nil, ExitUsage, ""},
	}
	for _, tc := range cases {
		code, out, errOut := runWith(opts, tc.args...)
		if code != tc.code || !strings.Contains(out, tc.out) {
			t.Errorf("mglab %v = %d\nstdout: %s\nstderr: %s\nwant %d and %q", tc.args, code, out, errOut, tc.code, tc.out)
		}
	}
}

func TestCheckWithConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lab.yaml")
	os.WriteFile(p, []byte("allow_hosts: [origin]\nallow_cidrs: [\"::1/128\"]\n"), 0o600)
	if code, out, _ := runWith(nil, "check", "-config", p, "http://origin:8081/"); code != ExitOK {
		t.Errorf("configured host denied: %s", out)
	}
	if code, out, _ := runWith(nil, "check", "-config", p, "http://localhost/"); code != ExitDenied {
		t.Errorf("host outside config allowed: %s", out)
	}
	if code, out, _ := runWith(nil, "check", "-config", p, "http://127.0.0.1/"); code != ExitDenied {
		t.Errorf("IPv4 loopback allowed without a CIDR: %s", out)
	}
}

func TestReplay(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	scenario := filepath.Join(dir, "s.yaml")
	os.WriteFile(scenario, []byte("name: t\nrequests:\n  - {method: GET, path: /a, expect_status: 200}\n  - {method: GET, path: /b}\n"), 0o600)

	code, out, errOut := runWith(nil, "replay", "-rps", "50", "-base", srv.URL, scenario)
	if code != ExitOK || hits.Load() != 2 {
		t.Fatalf("replay = %d, hits %d\n%s\n%s", code, hits.Load(), out, errOut)
	}

	// Denied base: nothing is sent.
	code, _, errOut = runWith(nil, "replay", "-base", "http://example.com", scenario)
	if code != ExitDenied || !strings.Contains(errOut, "not in the lab allowlist") || hits.Load() != 2 {
		t.Errorf("denied base: code %d, hits %d, stderr %s", code, hits.Load(), errOut)
	}

	// Rate cap cannot be raised past the hard maximum.
	if code, _, errOut = runWith(nil, "replay", "-rps", "500", "-base", srv.URL, scenario); code != ExitUsage ||
		!strings.Contains(errOut, "hard maximum") {
		t.Errorf("-rps 500: code %d, stderr %s", code, errOut)
	}

	// Expectation mismatch is a failure.
	os.WriteFile(scenario, []byte("name: t\nrequests:\n  - {method: GET, path: /a, expect_status: 204}\n"), 0o600)
	if code, _, _ = runWith(nil, "replay", "-rps", "50", "-base", srv.URL, scenario); code != ExitDenied {
		t.Errorf("mismatch exit = %d, want %d", code, ExitDenied)
	}
}

// -map-host lets replay reach a loopback server under a *.test name (the
// Edge picks the site by Host); -var fills the scenario's variables.
func TestReplayMapHostAndVars(t *testing.T) {
	var gotHost, gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		gotPath.Store(r.URL.Path)
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	dir := t.TempDir()
	scenario := filepath.Join(dir, "s.yaml")
	os.WriteFile(scenario, []byte("name: t\nvars: {run: manual, id: ~}\nrequests:\n  - {method: GET, path: '/x/${run}/${id}', expect_status: 200}\n"), 0o600)
	base := "http://site.lab.test:" + port

	code, out, errOut := runWith(nil, "replay", "-rps", "50", "-map-host", "site.lab.test=127.0.0.1",
		"-var", "run=r7", "-var", "id=9", "-base", base, scenario)
	if code != ExitOK {
		t.Fatalf("replay = %d\n%s\n%s", code, out, errOut)
	}
	if gotHost.Load() != "site.lab.test:"+port || gotPath.Load() != "/x/r7/9" {
		t.Errorf("server saw Host %v path %v", gotHost.Load(), gotPath.Load())
	}

	usage := []struct {
		args []string
		want string
	}{
		{[]string{"-var", "id=1", "-var", "id=2"}, "-var id given twice"},
		{[]string{"-var", "noequals"}, "want name=value"},
		{[]string{"-var", "other=1", "-var", "id=1"}, `variable "other" is not declared`},
		{[]string{"-var", "run=x"}, `variable "id" has no default`},
		{[]string{"-var", "id=a b"}, "whitespace"},
		{[]string{"-map-host", "evil.com=127.0.0.1", "-var", "id=1"}, `-map-host evil.com: host "evil.com" is not in the lab allowlist`},
		{[]string{"-map-host", "site.lab.test=169.254.169.254", "-var", "id=1"}, "never a lab target"},
		{[]string{"-map-host", "site.lab.test", "-var", "id=1"}, "want name=address"},
	}
	for _, tc := range usage {
		args := append(append([]string{"replay", "-rps", "50"}, tc.args...), "-base", base, scenario)
		if code, _, errOut := runWith(nil, args...); code != ExitUsage || !strings.Contains(errOut, tc.want) {
			t.Errorf("mglab %v = %d, stderr %q; want usage error %q", tc.args, code, errOut, tc.want)
		}
	}

	// A mapping to an address the allowlist does not admit for the name is
	// refused at connect time: nothing is sent.
	before := gotPath.Load()
	code, _, errOut = runWith(nil, "replay", "-rps", "50", "-map-host", "site.lab.test=93.184.216.34",
		"-var", "id=1", "-base", base, scenario)
	if code != ExitDenied || !strings.Contains(errOut, "may only use loopback or private") || gotPath.Load() != before {
		t.Errorf("public mapping: code %d, stderr %s", code, errOut)
	}
}

func TestCheckMapHost(t *testing.T) {
	code, out, _ := runWith(nil, "check", "-map-host", "site.lab.test=127.0.0.1", "-resolve", "http://site.lab.test:8080/")
	if code != ExitOK || !strings.Contains(out, "resolves to [127.0.0.1]") {
		t.Errorf("check -map-host = %d\n%s", code, out)
	}
	code, out, _ = runWith(nil, "check", "-map-host", "site.lab.test=10.9.8.7", "-map-host", "site.lab.test=8.8.8.8", "-resolve", "http://site.lab.test/")
	if code != ExitDenied || !strings.Contains(out, "resolved to 8.8.8.8") {
		t.Errorf("check with a public mapping = %d\n%s", code, out)
	}
}

func TestEvents(t *testing.T) {
	sample := "../events/testdata/phase1-run.jsonl"
	cases := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"impersonator", "-site", "lab", "-impersonators", "/lab/impersonator/sample/", "-crawlers", "/lab/crawler/sample/",
			"-want-settled", "13", "-want-verified", "6", sample}, ExitOK, "PASS  impersonators: 13/13 settled requests classified impersonator (100.0%)"},
		{[]string{"impersonator", "-impersonators", "/lab/impersonator/sample/", "-want-settled", "14", sample}, ExitDenied, "FAIL  13 settled impersonator requests, want 14"},
		{[]string{"clearance", "-site", "lab", "-protected", "/lab/members/sample/", "-want-feedback", "3", sample}, ExitOK, "PASS  clearance: 4 challenge submission(s) (0 succeeded), 3 feedback event(s), 0 passed; 5 request(s) to the protected route, 0 forwarded"},
		{[]string{"clearance", "-protected", "/lab/impersonator/sample/", sample}, ExitDenied, "protected request answered 200"},
		{[]string{"impersonator", sample}, ExitUsage, ""},
		{[]string{"clearance", "-protected", "/x/", "-want-feedback", "-1", sample}, ExitUsage, ""},
		{[]string{"impersonator", "-impersonators", "/x/", "missing.jsonl"}, ExitUsage, ""},
		{[]string{"impersonator", "-impersonators", "/x/"}, ExitUsage, ""},
		{[]string{"other"}, ExitUsage, ""},
		{nil, ExitUsage, ""},
	}
	for _, tc := range cases {
		code, out, errOut := runWith(nil, append([]string{"events"}, tc.args...)...)
		if code != tc.code || !strings.Contains(out, tc.out) {
			t.Errorf("mglab events %v = %d\nstdout: %s\nstderr: %s\nwant %d and %q", tc.args, code, out, errOut, tc.code, tc.out)
		}
	}

	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	os.WriteFile(bad, []byte("{\"kind\":\"access\"}\nnot json\n"), 0o600)
	if code, _, errOut := runWith(nil, "events", "clearance", "-protected", "/x/", bad); code != ExitUsage || !strings.Contains(errOut, "line 2") {
		t.Errorf("malformed event file: code %d, stderr %s", code, errOut)
	}
}
