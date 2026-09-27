package cfapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "test-token-not-a-secret"

// fakeAPI answers with a fixed status and body per path and records requests.
type fakeAPI struct {
	routes map[string]struct {
		status int
		body   string
	}
	reqs []*http.Request
}

func newFake(t *testing.T) (*fakeAPI, *Client) {
	t.Helper()
	f := &fakeAPI{routes: map[string]struct {
		status int
		body   string
	}{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reqs = append(f.reqs, r)
		rt, ok := f.routes[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"Could not route"}],"result":null}`))
			return
		}
		w.WriteHeader(rt.status)
		_, _ = w.Write([]byte(rt.body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/client/v4", testToken, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *fakeAPI) set(path string, status int, body string) {
	f.routes["/client/v4"+path] = struct {
		status int
		body   string
	}{status, body}
}

func TestNewBaseURL(t *testing.T) {
	for _, base := range []string{"", "https://api.cloudflare.com/client/v4", "http://127.0.0.1:8080", "http://[::1]:1/x", "http://localhost:9"} {
		if _, err := New(base, "t", nil); err != nil {
			t.Errorf("%q: %v", base, err)
		}
	}
	for _, base := range []string{"http://api.cloudflare.com/client/v4", "ftp://x", "https://u:p@api.cloudflare.com", "https://x/?q=1", "not a url", "http://10.0.0.1"} {
		if _, err := New(base, "t", nil); err == nil {
			t.Errorf("%q accepted", base)
		}
	}
	if _, err := New("", "", nil); err == nil {
		t.Error("empty token accepted")
	}
}

func TestGetSendsAuthAndDecodes(t *testing.T) {
	f, c := newFake(t)
	f.set("/zones", 200, `{"success":true,"errors":[],"messages":[],"result":[
		{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com","status":"active","plan":{"id":"p","name":"Pro Website","legacy_id":"pro"},"account":{"id":"acc1"}},
		{"id":"ffff","name":"example.com.cn"}]}`)
	z, err := c.FindZone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if z.ID != "023e105f4ecef8ad9ca31a8372d0c353" || z.Plan.LegacyID != "pro" || z.Account.ID != "acc1" {
		t.Errorf("zone = %+v", z)
	}
	r := f.reqs[0]
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+testToken ||
		r.Header.Get("User-Agent") != UserAgent || r.URL.Query().Get("name") != "example.com" {
		t.Errorf("request %s %s %v", r.Method, r.URL, r.Header)
	}
}

func TestErrors(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	f.set("/zones/z1/settings/ssl", 403, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}],"result":null}`)
	_, err := c.Setting(ctx, "z1", "ssl")
	if !IsForbidden(err) || IsNotFound(err) {
		t.Errorf("403: %v", err)
	}
	if !strings.Contains(err.Error(), "9109") || strings.Contains(err.Error(), testToken) {
		t.Errorf("403 message: %v", err)
	}
	f.set("/zones/z1/settings/0rtt", 200, `{"success":false,"errors":[{"code":1000,"message":"boom"}]}`)
	if _, err := c.Setting(ctx, "z1", "0rtt"); err == nil || IsForbidden(err) {
		t.Errorf("success=false: %v", err)
	}
	f.set("/zones/z1/settings/pseudo_ipv4", 500, `<html>`)
	if _, err := c.Setting(ctx, "z1", "pseudo_ipv4"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("500: %v", err)
	}
	f.set("/zones/z1/settings/rocket_loader", 200, `not json`)
	if _, err := c.Setting(ctx, "z1", "rocket_loader"); err == nil {
		t.Error("invalid JSON accepted")
	}
	f.set("/zones/z1/settings/always_use_https", 200, `{"success":true,"result":null}`)
	if _, err := c.Setting(ctx, "z1", "always_use_https"); err == nil {
		t.Error("null result accepted")
	}
	f.set("/zones/z1/settings/big", 200, `{"success":true,"result":{"id":"big","value":"`+strings.Repeat("a", maxResponseSize)+`"}}`)
	if _, err := c.Setting(ctx, "z1", "big"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized: %v", err)
	}
	f.set("/zones", 200, `{"success":true,"result":[]}`)
	if _, err := c.FindZone(ctx, "example.com"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("no zone: %v", err)
	}
}

// Path segments come from the site YAML; anything but a plain name is
// refused before a request is made.
func TestPathSegmentsAreChecked(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	bad := []string{"", "..", "a/b", "a?b", "a%2fb", "x y", "a#b"}
	for _, s := range bad {
		if _, err := c.Setting(ctx, "z1", s); err == nil {
			t.Errorf("setting %q accepted", s)
		}
		if _, err := c.AOPHostname(ctx, s, "example.com"); err == nil {
			t.Errorf("zone id %q accepted", s)
		}
		if _, err := c.Tunnel(ctx, "acc", s); err == nil {
			t.Errorf("tunnel id %q accepted", s)
		}
	}
	if len(f.reqs) != 0 {
		t.Errorf("%d requests sent for invalid segments", len(f.reqs))
	}
}

func TestEntrypointRuleset(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	rs, err := c.EntrypointRuleset(ctx, "z1", PhaseCacheSettings)
	if err != nil || !rs.Missing || len(rs.Rules) != 0 {
		t.Errorf("404 entry point: %+v %v", rs, err)
	}
	f.set("/zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint", 200, `{"success":true,"result":{"id":"r1","phase":"http_request_firewall_custom","rules":[
		{"id":"a","ref":"mg_skip_mg_paths","expression":"true","action":"skip","action_parameters":{"phases":["http_request_sbfm"]},"enabled":false},
		{"id":"b","expression":"true","action":"block"}]}}`)
	rs, err = c.EntrypointRuleset(ctx, "z1", PhaseFirewallCustom)
	if err != nil || rs.Missing || len(rs.Rules) != 2 {
		t.Fatalf("%+v %v", rs, err)
	}
	if rs.Rules[0].IsEnabled() || !rs.Rules[1].IsEnabled() || rs.Rules[1].Name() != "b" || rs.Rules[0].Name() != "mg_skip_mg_paths" {
		t.Errorf("rules %+v", rs.Rules)
	}
	var p struct{ Phases []string }
	if err := rs.Rules[0].Params(&p); err != nil || len(p.Phases) != 1 {
		t.Errorf("params %v %v", p, err)
	}
	f.set("/zones/z1/rulesets/phases/http_ratelimit/entrypoint", 403, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	if _, err := c.EntrypointRuleset(ctx, "z1", PhaseRateLimit); !IsForbidden(err) {
		t.Errorf("403 entry point: %v", err)
	}
}

func TestBotManagementAndAOP(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	f.set("/zones/z1/bot_management", 200, `{"success":true,"result":{"fight_mode":false,"ai_bots_protection":"block","sbfm_definitely_automated":"allow"}}`)
	b, err := c.BotManagement(ctx, "z1")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := b.Bool("fight_mode"); !ok || v {
		t.Error("fight_mode")
	}
	if v, ok := b.String("ai_bots_protection"); !ok || v != "block" {
		t.Error("ai_bots_protection")
	}
	if _, ok := b.Bool("ai_bots_protection"); ok {
		t.Error("string read as bool")
	}
	if _, ok := b.String("sbfm_likely_automated"); ok {
		t.Error("absent field present")
	}
	h, err := c.AOPHostname(ctx, "z1", "www.example.com")
	if h != nil || err != nil {
		t.Errorf("absent per-hostname AOP: %v %v", h, err)
	}
	f.set("/zones/z1/origin_tls_client_auth/hostnames/www.example.com", 200, `{"success":true,"result":{"hostname":"www.example.com","cert_id":"c1","enabled":true,"status":"active","expires_on":"2027-01-01T00:00:00Z"}}`)
	h, err = c.AOPHostname(ctx, "z1", "www.example.com")
	if err != nil || h == nil || h.Enabled == nil || !*h.Enabled || h.CertID != "c1" {
		t.Errorf("per-hostname AOP: %+v %v", h, err)
	}
}

// The client never follows redirects, so the bearer token cannot leak to
// another host.
func TestNoRedirects(t *testing.T) {
	leaked := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer other.Close()
	redirect := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusFound))
	defer redirect.Close()
	c, err := New(redirect.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Setting(context.Background(), "z1", "ssl"); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Errorf("redirect: %v", err)
	}
	if leaked {
		t.Error("token sent to the redirect target")
	}
}

// §2.4 item 3: the response decoder never panics on random input.
func TestRandomResponses(t *testing.T) {
	seed := []byte(`{"success":true,"errors":[{"code":1,"message":"m"}],"result":{"managed_request_headers":[{"id":"add_visitor_location_headers","enabled":true}],"fight_mode":false,"rules":[{"ref":"x","enabled":true,"action_parameters":{"a":1}}]}}`)
	x := uint64(0x2545f4914f6cdd1d)
	next := func() uint64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
	for i := 0; i < 12000; i++ {
		b := append([]byte(nil), seed...)
		for n := 1 + next()%4; n > 0; n-- {
			b[next()%uint64(len(b))] = byte(next())
		}
		if next()%3 == 0 {
			b = b[:next()%uint64(len(b))]
		}
		status := []int{200, 403, 404, 500}[next()%4]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", b, r)
				}
			}()
			var mh ManagedHeaders
			_ = decodeResponse("/p", status, b, &mh)
			bm := &BotManagement{}
			if decodeResponse("/p", status, b, &bm.Fields) == nil {
				bm.Bool("fight_mode")
				bm.String("ai_bots_protection")
			}
			var rs Ruleset
			if decodeResponse("/p", status, b, &rs) == nil {
				for _, r := range rs.Rules {
					var p map[string]any
					_ = r.Params(&p)
					_ = r.IsEnabled()
				}
			}
		}()
	}
}
