package replay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"morphgate/lab/internal/guard"
)

type seen struct {
	method, uri, body, ua, custom string
}

func recordingServer(t *testing.T) (*httptest.Server, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{r.Method, r.RequestURI, string(b), r.UserAgent(), r.Header.Get("X-Demo")})
		mu.Unlock()
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/escape":
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
		default:
			io.WriteString(w, "ok")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seen {
		mu.Lock()
		defer mu.Unlock()
		return append([]seen(nil), got...)
	}
}

func fastGuard(t *testing.T) *guard.Guard {
	t.Helper()
	cfg := guard.DefaultConfig()
	cfg.RateRPS = guard.MaxRateRPS
	g, err := guard.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRunSendsExactlyTheScenario(t *testing.T) {
	srv, received := recordingServer(t)
	s := &Scenario{Name: "demo", Requests: []Request{
		{Method: "GET", Path: "/", ExpectStatus: 200},
		{Method: "POST", Path: "/login?next=%2Fhome", Headers: map[string]string{"Content-Type": "application/json", "X-Demo": "1"}, Body: `{"user":"demo"}`},
		{Method: "GET", Path: "/missing", ExpectStatus: 200},
		{Method: "GET", Path: "/ua", Headers: map[string]string{"User-Agent": "recorded-browser/1.0"}},
	}}
	var out bytes.Buffer
	sum, err := Run(context.Background(), fastGuard(t), s, srv.URL+"/", &out)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	if sum.Sent != 4 || sum.Failed != 0 || sum.Mismatched != 1 || sum.OK() {
		t.Errorf("summary = %+v", sum)
	}
	want := []seen{
		{"GET", "/", "", DefaultUserAgent, ""},
		{"POST", "/login?next=%2Fhome", `{"user":"demo"}`, DefaultUserAgent, "1"},
		{"GET", "/missing", "", DefaultUserAgent, ""},
		{"GET", "/ua", "", "recorded-browser/1.0", ""},
	}
	got := received()
	if len(got) != len(want) {
		t.Fatalf("server saw %d requests, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !strings.Contains(out.String(), "404") || !strings.Contains(out.String(), "(expected 200)") {
		t.Errorf("output lacks status report:\n%s", out.String())
	}
}

func TestRunKeepsCookies(t *testing.T) {
	var sawCookie bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
		case "/me":
			c, err := r.Cookie("sid")
			sawCookie = err == nil && c.Value == "abc"
		}
	}))
	defer srv.Close()
	s := &Scenario{Name: "session", Requests: []Request{{Method: "POST", Path: "/login"}, {Method: "GET", Path: "/me"}}}
	if _, err := Run(context.Background(), fastGuard(t), s, srv.URL, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !sawCookie {
		t.Error("session cookie from /login was not sent to /me")
	}
}

func TestRunBasePath(t *testing.T) {
	srv, received := recordingServer(t)
	s := &Scenario{Name: "prefixed", Requests: []Request{{Method: "GET", Path: "/x"}}}
	if _, err := Run(context.Background(), fastGuard(t), s, srv.URL+"/app/", io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := received(); len(got) != 1 || got[0].uri != "/app/x" {
		t.Errorf("got %+v, want /app/x", got)
	}
}

func TestRunRefusesDisallowedBase(t *testing.T) {
	s := &Scenario{Name: "evil", BaseURL: "http://example.com", Requests: []Request{{Method: "GET", Path: "/"}}}
	_, err := Run(context.Background(), fastGuard(t), s, "", io.Discard)
	if !errors.Is(err, guard.ErrDenied) {
		t.Fatalf("Run = %v, want ErrDenied", err)
	}
	if _, err := Run(context.Background(), fastGuard(t), &Scenario{Name: "x", Requests: s.Requests}, "", io.Discard); err == nil {
		t.Error("missing base URL accepted")
	}
}

func TestRunAbortsOnDeniedRedirect(t *testing.T) {
	srv, received := recordingServer(t)
	s := &Scenario{Name: "escape", Requests: []Request{
		{Method: "GET", Path: "/escape"},
		{Method: "GET", Path: "/never-sent"},
	}}
	var out bytes.Buffer
	_, err := Run(context.Background(), fastGuard(t), s, srv.URL, &out)
	if !errors.Is(err, guard.ErrDenied) {
		t.Fatalf("Run = %v, want ErrDenied", err)
	}
	if got := received(); len(got) != 1 {
		t.Errorf("server saw %d requests after a denied redirect, want 1", len(got))
	}
	if !strings.Contains(out.String(), "DENIED") {
		t.Errorf("output does not report the denial:\n%s", out.String())
	}
}

func TestRunCountsTransportErrors(t *testing.T) {
	srv, _ := recordingServer(t)
	url := srv.URL
	srv.Close() // connection refused from now on
	s := &Scenario{Name: "down", Requests: []Request{{Method: "GET", Path: "/"}, {Method: "GET", Path: "/2"}}}
	sum, err := Run(context.Background(), fastGuard(t), s, url, io.Discard)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Failed != 2 || sum.OK() {
		t.Errorf("summary = %+v, want 2 failures", sum)
	}
}

func TestValidate(t *testing.T) {
	ok := Request{Method: "GET", Path: "/"}
	cases := []struct {
		name string
		mut  func(*Scenario)
		want string
	}{
		{"no name", func(s *Scenario) { s.Name = "" }, "name is required"},
		{"no requests", func(s *Scenario) { s.Requests = nil }, "requests is empty"},
		{"too many", func(s *Scenario) { s.Requests = make([]Request, MaxRequests+1) }, "exceed the limit"},
		{"bad method", func(s *Scenario) { s.Requests[0].Method = "TRACE" }, `method "TRACE"`},
		{"lower-case method", func(s *Scenario) { s.Requests[0].Method = "get" }, `method "get"`},
		{"absolute URL", func(s *Scenario) { s.Requests[0].Path = "http://evil.com/x" }, "must start with a single '/'"},
		{"scheme-relative", func(s *Scenario) { s.Requests[0].Path = "//evil.com/x" }, "must start with a single '/'"},
		{"relative", func(s *Scenario) { s.Requests[0].Path = "x" }, "must start with a single '/'"},
		{"backslash", func(s *Scenario) { s.Requests[0].Path = `/\evil.com` }, `must not contain '\'`},
		{"fragment", func(s *Scenario) { s.Requests[0].Path = "/#x" }, "must not contain"},
		{"space", func(s *Scenario) { s.Requests[0].Path = "/a b" }, "whitespace"},
		{"host header", func(s *Scenario) { s.Requests[0].Headers = map[string]string{"host": "evil.com"} }, "managed by the client"},
		{"transfer-encoding", func(s *Scenario) {
			s.Requests[0].Headers = map[string]string{"Transfer-Encoding": "chunked"}
		}, "managed by the client"},
		{"header injection", func(s *Scenario) { s.Requests[0].Headers = map[string]string{"X-A": "1\r\nHost: evil"} }, "CR, LF or NUL"},
		{"bad header name", func(s *Scenario) { s.Requests[0].Headers = map[string]string{"X A": "1"} }, "invalid header name"},
		{"huge body", func(s *Scenario) { s.Requests[0].Body = strings.Repeat("a", MaxBodyBytes+1) }, "body larger"},
		{"bad expect", func(s *Scenario) { s.Requests[0].ExpectStatus = 42 }, "expect_status 42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scenario{Name: "v", Requests: []Request{ok}}
			tc.mut(s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	s, err := Load("../../testdata/scenarios/edge-smoke.yaml")
	if err != nil {
		t.Fatalf("Load sample: %v", err)
	}
	if s.Name != "edge-smoke" || len(s.Requests) != 3 || s.Requests[0].ExpectStatus != 200 {
		t.Errorf("unexpected scenario: %+v", s)
	}

	p := filepath.Join(t.TempDir(), "typo.yaml")
	os.WriteFile(p, []byte("name: x\nrequests:\n  - method: GET\n    path: /\n    payload: fuzz\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "field payload not found") {
		t.Errorf("unknown field accepted: %v", err)
	}
}

func TestLoadLabOriginScenario(t *testing.T) {
	s, err := Load("../../testdata/scenarios/lab-origin.yaml")
	if err != nil {
		t.Fatalf("Load lab-origin: %v", err)
	}
	if s.Name != "lab-origin" || s.BaseURL != "http://origin.lab.test:8081" || len(s.Requests) != 2 {
		t.Errorf("unexpected scenario: %+v", s)
	}
}
