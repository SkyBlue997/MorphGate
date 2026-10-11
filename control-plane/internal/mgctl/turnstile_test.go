package mgctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
)

const (
	tsAccount = "0123456789abcdef0123456789abcdef"
	tsSitekey = "0x4AAAAAAAkat-test-sitekey"
	tsToken   = "cf-turnstile-edit-token-0001"
	tsSecret1 = "0x4AAAAAAAkat-test-secret-current-00000000"
	tsSecret2 = "0x4AAAAAAAkat-test-secret-rotated-1111111"
	tsSecret3 = "0x4AAAAAAAkat-test-secret-rotated-2222222"
)

// tsAPI is a loopback stand-in for the Turnstile widget API; every rotation
// hands out the next secret.
type tsAPI struct {
	mu      sync.Mutex
	secrets []string
	bodies  []string // rotate_secret request bodies
	auth    []string
	fail    bool
}

func (a *tsAPI) current() string { return a.secrets[0] }

func newTSAPI(t *testing.T, e *testEnv) *tsAPI {
	t.Helper()
	a := &tsAPI{secrets: []string{tsSecret1, tsSecret2, tsSecret3}}
	base := "/client/v4/accounts/" + tsAccount + "/challenges/widgets"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.auth = append(a.auth, r.Header.Get("Authorization")+" | "+r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		if a.fail {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10001,"message":"internal"}]}`)
			return
		}
		widget := map[string]any{"sitekey": tsSitekey, "name": "blog", "mode": "managed", "domains": []string{"example.com"}, "modified_on": "2026-09-02T00:00:00Z"}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			result := []any{widget}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]int{"total_count": 1}})
			return
		case r.Method == http.MethodGet && r.URL.Path == base+"/"+tsSitekey:
		case r.Method == http.MethodPost && r.URL.Path == base+"/"+tsSitekey+"/rotate_secret":
			a.bodies = append(a.bodies, string(body))
			a.secrets = a.secrets[1:]
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":7003,"message":"no route"}]}`)
			return
		}
		widget["secret"] = a.current()
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": widget})
	}))
	t.Cleanup(srv.Close)
	e.vars[EnvCFAPIBase] = srv.URL + "/client/v4"
	if err := keys.EncryptFile(e.path("cf-token.age"), []byte(tsToken+"\n"), []byte("test passphrase"), 10); err != nil {
		t.Fatal(err)
	}
	return a
}

func readKeysFile(t *testing.T, path string) *keys.TurnstileKeys {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %v, want 0600", path, st.Mode().Perm())
	}
	k, err := keys.ReadTurnstileKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Phase 2 spec §8.7, §16: import, rotate (invalidate_immediately always
// explicit), drop-previous, and audit records without secrets.
func TestTurnstileSecretLifecycle(t *testing.T) {
	e := newTestEnv(t)
	api := newTSAPI(t, e)
	tok := e.path("cf-token.age")
	keysFile := e.path("blog-turnstile.json")

	out := e.must("turnstile", "widgets", "--account", tsAccount, "--cf-token-file", tok)
	if !strings.Contains(out, tsSitekey) || strings.Contains(out, tsSecret1) {
		t.Errorf("widgets output %q", out)
	}

	out = e.must("turnstile", "secret", "import", "--account", tsAccount, "--sitekey", tsSitekey, "--site", "blog", "--out", keysFile, "--cf-token-file", tok)
	if strings.Contains(out, tsSecret1) {
		t.Error("import printed the secret")
	}
	if k := readKeysFile(t, keysFile); k.Site != "blog" || len(k.Values) != 1 || k.Values[0] != tsSecret1 {
		t.Errorf("imported %v", k.Values)
	}
	// The written bytes are the canonical form of the shared samples.
	data, _ := os.ReadFile(keysFile)
	sample, err := os.ReadFile("../../../testdata/phase2/samples/keys/valid/one-value.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(sample) {
		t.Errorf("import wrote\n%s\nwant the bytes of valid/one-value.json\n%s", data, sample)
	}
	if r := e.lastRecord(); r.Action != "turnstile.secret.import" || r.Site != "blog" || r.ResourceID != tsSitekey {
		t.Errorf("audit %+v", r)
	}
	// Never overwritten.
	e.expect(cli.ExitFailed, "already exists", "turnstile", "secret", "import", "--account", tsAccount, "--sitekey", tsSitekey, "--site", "blog", "--out", keysFile, "--cf-token-file", tok)

	e.must("turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile, "--cf-token-file", tok)
	if k := readKeysFile(t, keysFile); len(k.Values) != 2 || k.Values[0] != tsSecret2 || k.Values[1] != tsSecret1 {
		t.Errorf("after rotate: %d values", len(k.Values))
	}
	if r := e.lastRecord(); r.Action != "turnstile.secret.rotate" || !strings.Contains(string(r.Diff), `"invalidate_immediately":false`) {
		t.Errorf("audit %+v %s", r, r.Diff)
	}

	e.must("turnstile", "secret", "drop-previous", "--keys", keysFile)
	if k := readKeysFile(t, keysFile); len(k.Values) != 1 || k.Values[0] != tsSecret2 {
		t.Errorf("after drop-previous: %d values", len(k.Values))
	}
	if r := e.lastRecord(); r.Action != "turnstile.secret.drop_previous" || r.Site != "blog" {
		t.Errorf("audit %+v", r)
	}
	n := len(e.records())
	out = e.must("turnstile", "secret", "drop-previous", "--keys", keysFile)
	if !strings.Contains(out, "nothing to do") || len(e.records()) != n {
		t.Errorf("second drop-previous: %q", out)
	}

	e.must("turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile, "--invalidate-immediately", "--cf-token-file", tok)
	if k := readKeysFile(t, keysFile); len(k.Values) != 1 || k.Values[0] != tsSecret3 {
		t.Errorf("after rotate --invalidate-immediately: %d values", len(k.Values))
	}
	if want := []string{`{"invalidate_immediately":false}`, `{"invalidate_immediately":true}`}; strings.Join(api.bodies, ",") != strings.Join(want, ",") {
		t.Errorf("rotate bodies %v, want %v", api.bodies, want)
	}
	for _, a := range api.auth {
		if a != "Bearer "+tsToken+" | morphgate-dev-tooling" {
			t.Errorf("request headers %q", a)
		}
	}

	// No secret or token in the audit log.
	log, err := os.ReadFile(e.vars["MGCTL_AUDIT_LOG"])
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{tsSecret1, tsSecret2, tsSecret3, tsToken, "kat-test-secret"} {
		if strings.Contains(string(log), s) {
			t.Errorf("the audit log contains %q", s)
		}
	}
	e.must("audit", "verify")
}

func TestTurnstileRotateRefusals(t *testing.T) {
	e := newTestEnv(t)
	api := newTSAPI(t, e)
	tok := e.path("cf-token.age")
	keysFile := e.path("k.json")
	// The file's current value is not the widget's current secret: nothing rotates.
	stale, _ := (&keys.TurnstileKeys{Site: "blog", Values: []string{"0x4AAAAAAAstale"}}).Marshal()
	if err := os.WriteFile(keysFile, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	e.expect(cli.ExitFailed, "is not the current secret of widget", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile, "--cf-token-file", tok)
	if len(api.bodies) != 0 {
		t.Error("rotated despite a stale keys file")
	}
	// API errors.
	good, _ := (&keys.TurnstileKeys{Site: "blog", Values: []string{tsSecret1}}).Marshal()
	if err := os.WriteFile(keysFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	api.fail = true
	e.expect(cli.ExitFailed, "HTTP 500", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile, "--cf-token-file", tok)
	api.fail = false
	// Invalid files, flags and token.
	e.expect(cli.ExitFailed, "no such file", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", e.path("missing.json"), "--cf-token-file", tok)
	e.expect(cli.ExitUsage, "--cf-token-file is required", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile)
	e.expect(cli.ExitUsage, "invalid sitekey", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", "a/b", "--keys", keysFile, "--cf-token-file", tok)
	e.expect(cli.ExitUsage, "--site", "turnstile", "secret", "import", "--account", tsAccount, "--sitekey", tsSitekey, "--site", "Blog!", "--out", e.path("n.json"), "--cf-token-file", tok)
	e.expect(cli.ExitFailed, "--cf-token-file", "turnstile", "widgets", "--account", tsAccount, "--cf-token-file", keysFile)
	e.expect(cli.ExitUsage, "expected a subcommand", "turnstile")
	e.expect(cli.ExitUsage, "unknown subcommand", "turnstile", "secret", "renew")
	if err := os.WriteFile(keysFile, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.expect(cli.ExitFailed, "missing member", "turnstile", "secret", "drop-previous", "--keys", keysFile)
	// An http base URL off loopback is refused before any request.
	e.vars[EnvCFAPIBase] = "http://api.example.com/client/v4"
	e.expect(cli.ExitFailed, "http is only allowed for loopback", "turnstile", "widgets", "--account", tsAccount, "--cf-token-file", tok)
}

// I-27: an unusable audit log stops the rotation before Cloudflare changes.
func TestTurnstileAuditPreflight(t *testing.T) {
	e := newTestEnv(t)
	api := newTSAPI(t, e)
	keysFile := e.path("k.json")
	good, _ := (&keys.TurnstileKeys{Site: "blog", Values: []string{tsSecret1}}).Marshal()
	if err := os.WriteFile(keysFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path("file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.vars["MGCTL_AUDIT_LOG"] = e.path("file/audit.jsonl") // below a regular file
	e.expect(cli.ExitInternal, "audit log", "turnstile", "secret", "rotate", "--account", tsAccount, "--sitekey", tsSitekey, "--keys", keysFile, "--cf-token-file", e.path("cf-token.age"))
	e.expect(cli.ExitInternal, "audit log", "turnstile", "secret", "import", "--account", tsAccount, "--sitekey", tsSitekey, "--site", "blog", "--out", e.path("n.json"), "--cf-token-file", e.path("cf-token.age"))
	if len(api.bodies) != 0 || len(api.auth) != 0 {
		t.Error("the API was called without a usable audit log")
	}
	if _, err := os.Stat(e.path("n.json")); !os.IsNotExist(err) {
		t.Error("import wrote a file without a usable audit log")
	}
}
