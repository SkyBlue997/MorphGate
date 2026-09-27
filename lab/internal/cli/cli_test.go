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
