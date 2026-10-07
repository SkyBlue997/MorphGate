package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
		// Two spellings of one header: which value is sent would depend on
		// map iteration order.
		{"duplicate header", func(s *Scenario) {
			s.Requests[0].Headers = map[string]string{"User-Agent": "a", "user-agent": "b"}
		}, `header "User-Agent" is set twice`},
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

	// A YAML merge whose override spells the header differently keeps both
	// keys; the request that would be sent is not determined, so it is an
	// error rather than a coin toss.
	merged := "name: x\nrequests:\n  - method: GET\n    path: /\n    headers: &h {User-Agent: a}\n" +
		"  - method: GET\n    path: /\n    headers: {<<: *h, user-agent: b}\n"
	if _, err := Parse([]byte(merged)); err == nil || !strings.Contains(err.Error(), "is set twice") {
		t.Errorf("case-variant header override accepted: %v", err)
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

func strp(s string) *string { return &s }

func TestVariables(t *testing.T) {
	srv, received := recordingServer(t)
	s := &Scenario{
		Name: "vars",
		Vars: map[string]*string{"run": strp("default-run"), "id": nil},
		Requests: []Request{
			{Method: "POST", Path: "/r/${run}/${id}?q=${id}", Headers: map[string]string{"X-Demo": "run=${run}"}, Body: `{"id":"${id}","lit":"$${run}"}`},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// A required variable must be given.
	if _, err := Run(context.Background(), fastGuard(t), s, srv.URL, io.Discard); err == nil || !strings.Contains(err.Error(), `variable "id" has no default`) {
		t.Fatalf("Run without id = %v", err)
	}
	rs, err := s.Resolve(map[string]string{"id": "42"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(s.Requests[0].Path) == len(rs.Requests[0].Path) || s.Requests[0].Path != "/r/${run}/${id}?q=${id}" {
		t.Error("Resolve changed the template")
	}
	if _, err := Run(context.Background(), fastGuard(t), rs, srv.URL, io.Discard); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := received()
	want := seen{"POST", "/r/default-run/42?q=42", `{"id":"42","lit":"${run}"}`, DefaultUserAgent, "run=default-run"}
	if len(got) != 1 || got[0] != want {
		t.Errorf("server saw %+v, want %+v", got, want)
	}
	if _, err := rs.Resolve(map[string]string{"id": "1"}); err == nil {
		t.Error("a resolved scenario accepted new values")
	}
}

func TestVariableErrors(t *testing.T) {
	base := func() *Scenario {
		return &Scenario{Name: "v", Vars: map[string]*string{"p": strp("x")}, Requests: []Request{{Method: "GET", Path: "/${p}"}}}
	}
	validate := []struct {
		name string
		mut  func(*Scenario)
		want string
	}{
		{"undeclared", func(s *Scenario) { s.Requests[0].Path = "/${q}" }, `variable "q" is not declared`},
		{"unterminated", func(s *Scenario) { s.Requests[0].Path = "/${p" }, "unterminated ${"},
		{"bad reference", func(s *Scenario) { s.Requests[0].Body = "${1x}" }, "invalid variable reference"},
		{"bad name", func(s *Scenario) { s.Vars["1x"] = strp("") }, `invalid variable name "1x"`},
		{"bad default", func(s *Scenario) { s.Vars["p"] = strp("a\nb") }, "CR, LF or NUL"},
		{"header", func(s *Scenario) { s.Requests[0].Headers = map[string]string{"X-A": "${nope}"} }, `header "X-A"`},
		{"too many", func(s *Scenario) {
			for i := 0; i <= MaxVars; i++ {
				s.Vars[fmt.Sprintf("v%d", i)] = strp("")
			}
		}, "vars exceed the limit"},
	}
	for _, tc := range validate {
		s := base()
		tc.mut(s)
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate = %v, want %q", tc.name, err, tc.want)
		}
	}

	resolve := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"unknown override", map[string]string{"q": "1"}, `variable "q" is not declared`},
		{"CR in value", map[string]string{"p": "a\rb"}, "CR, LF or NUL"},
		{"too long", map[string]string{"p": strings.Repeat("a", MaxVarBytes+1)}, "longer than"},
		// A value may not turn the path into another host or a bad path.
		{"scheme-relative", map[string]string{"p": "/evil.com/x"}, "must start with a single '/'"},
		{"space", map[string]string{"p": "a b"}, "whitespace"},
		{"fragment", map[string]string{"p": "a#b"}, "must not contain"},
	}
	for _, tc := range resolve {
		if _, err := base().Resolve(tc.values); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Resolve = %v, want %q", tc.name, err, tc.want)
		}
	}
	// A value is inserted as text: a "${" inside it is not expanded again.
	rs, err := base().Resolve(map[string]string{"p": "${p}"})
	if err != nil || rs.Requests[0].Path != "/${p}" {
		t.Errorf("Resolve with ${p} value = %+v, %v", rs, err)
	}
}

func TestDelay(t *testing.T) {
	srv, received := recordingServer(t)
	s := &Scenario{Name: "delay", Requests: []Request{{Method: "GET", Path: "/a"}, {Method: "GET", Path: "/b", DelayMS: 150}}}
	start := time.Now()
	if _, err := Run(context.Background(), fastGuard(t), s, srv.URL, io.Discard); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Errorf("replay took %s, want >= 150ms", el)
	}
	if len(received()) != 2 {
		t.Errorf("server saw %d requests", len(received()))
	}

	// Cancelling during a delay stops the replay before the request.
	s = &Scenario{Name: "cancel", Requests: []Request{{Method: "GET", Path: "/c", DelayMS: MaxDelayMS}}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Run(ctx, fastGuard(t), s, srv.URL, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run = %v, want DeadlineExceeded", err)
	}
	if len(received()) != 2 {
		t.Errorf("a cancelled request was sent")
	}
}

func TestExpectations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Add("Cache-Control", "private")
			w.Header().Add("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<main id="mg-challenge" data-mg-state="challenge">`)
		case "/cookie":
			w.Header().Add("Set-Cookie", "other=1; Path=/")
			w.Header().Add("Set-Cookie", "__Host-mg_clr=secret-token; Path=/; Secure; HttpOnly")
		case "/bad-cookie":
			// A value net/http's cookie parser drops, under another spelling
			// of the name: still a Set-Cookie of that cookie.
			w.Header().Add("Set-Cookie", `__host-MG_CLR=a"b; Path=/`)
		case "/redirect":
			// The cookie is set on the hop, not on the final response.
			w.Header().Add("Set-Cookie", "__Host-mg_clr=x; Path=/; Secure")
			http.Redirect(w, r, "/landing", http.StatusSeeOther)
		case "/landing":
			io.WriteString(w, "landed")
		case "/submit":
			// A redirect to a page that also answers 403: only the hop
			// shows that a redirect happened.
			http.Redirect(w, r, "/page", http.StatusSeeOther)
		}
	}))
	defer srv.Close()

	cases := []struct {
		name string
		req  Request
		want []string // substrings of the mismatch note; nil = all met
	}{
		{"all met", Request{Path: "/page", ExpectStatusIn: []int{403, 429},
			ExpectHeader:       map[string]string{"Content-Type": "text/html", "cache-control": "no-store", "Date": ""},
			ExpectHeaderAbsent: []string{"Location", "MG-Challenge"}, ExpectCookieAbsent: []string{"__Host-mg_clr"},
			ExpectBodyContains: `data-mg-state="challenge"`}, nil},
		{"status", Request{Path: "/page", ExpectStatus: 200}, []string{"expected 200"}},
		{"status in", Request{Path: "/page", ExpectStatusIn: []int{200, 303}}, []string{"expected one of 200, 303"}},
		{"header missing", Request{Path: "/page", ExpectHeader: map[string]string{"MG-Challenge": ""}}, []string{"header MG-Challenge missing"}},
		{"header value", Request{Path: "/page", ExpectHeader: map[string]string{"Content-Type": "json"}}, []string{`header Content-Type does not contain "json"`}},
		{"header present", Request{Path: "/page", ExpectHeaderAbsent: []string{"content-type"}}, []string{"header content-type present"}},
		{"body", Request{Path: "/page", ExpectBodyContains: "failed"}, []string{`body does not contain "failed"`}},
		{"cookie", Request{Path: "/cookie", ExpectCookieAbsent: []string{"__Host-mg_clr"}}, []string{"Set-Cookie __Host-mg_clr received"}},
		{"cookie other name", Request{Path: "/cookie", ExpectCookieAbsent: []string{"session"}}, nil},
		{"malformed cookie", Request{Path: "/bad-cookie", ExpectCookieAbsent: []string{"__Host-mg_clr"}}, []string{"Set-Cookie __Host-mg_clr received"}},
		{"cookie on a redirect hop", Request{Path: "/redirect", ExpectStatus: 200, ExpectBodyContains: "landed",
			ExpectCookieAbsent: []string{"__Host-mg_clr"}}, []string{"Set-Cookie __Host-mg_clr received"}},
		{"several", Request{Path: "/page", ExpectStatus: 200, ExpectBodyContains: "nope"}, []string{"expected 200", `body does not contain "nope"`}},
		// expect_header_absent covers every hop, so "no Location" means no
		// redirect was followed even when the final answer is the expected
		// 403 page.
		{"header on a redirect hop", Request{Path: "/submit", ExpectStatus: 403, ExpectBodyContains: `data-mg-state="challenge"`,
			ExpectHeaderAbsent: []string{"Location"}}, []string{"(after 303)", "header Location present on the 303 redirect"}},
		{"redirect without absent expectation", Request{Path: "/submit", ExpectStatus: 403}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Method = "GET"
			var out bytes.Buffer
			sum, err := Run(context.Background(), fastGuard(t), &Scenario{Name: tc.name, Requests: []Request{tc.req}}, srv.URL, &out)
			if err != nil {
				t.Fatal(err)
			}
			if (sum.Mismatched == 0) != (tc.want == nil) {
				t.Fatalf("mismatched = %d\n%s", sum.Mismatched, out.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
			if strings.Contains(out.String(), "secret-token") {
				t.Errorf("a cookie value was printed:\n%s", out.String())
			}
		})
	}
}

func TestExpectationValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Request)
		want string
	}{
		{"both status forms", func(r *Request) { r.ExpectStatus, r.ExpectStatusIn = 403, []int{403} }, "not both"},
		{"empty status list", func(r *Request) { r.ExpectStatusIn = []int{} }, "must list 1-"},
		{"bad status in list", func(r *Request) { r.ExpectStatusIn = []int{403, 99} }, "99 is not an HTTP status"},
		{"bad header name", func(r *Request) { r.ExpectHeader = map[string]string{"X Y": ""} }, "invalid header name"},
		{"header value CR", func(r *Request) { r.ExpectHeader = map[string]string{"X-Y": "a\rb"} }, "CR, LF or NUL"},
		{"bad absent header", func(r *Request) { r.ExpectHeaderAbsent = []string{"a:b"} }, "invalid header name"},
		{"bad cookie name", func(r *Request) { r.ExpectCookieAbsent = []string{"a;b"} }, "invalid cookie name"},
		{"too many", func(r *Request) { r.ExpectHeaderAbsent = make([]string, MaxExpectations+1) }, "at most"},
		{"long body expectation", func(r *Request) { r.ExpectBodyContains = strings.Repeat("a", MaxVarBytes+1) }, "longer than"},
		{"negative delay", func(r *Request) { r.DelayMS = -1 }, "delay_ms -1"},
		{"long delay", func(r *Request) { r.DelayMS = MaxDelayMS + 1 }, "delay_ms 10001"},
		{"long path", func(r *Request) { r.Path = "/" + strings.Repeat("a", MaxPathBytes) }, "path longer than"},
	}
	for _, tc := range cases {
		s := &Scenario{Name: "v", Requests: []Request{{Method: "GET", Path: "/"}}}
		tc.mut(&s.Requests[0])
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestSetCookieName(t *testing.T) {
	for in, want := range map[string]string{
		"__Host-mg_clr=v4.local.x; Path=/; Secure": "__Host-mg_clr",
		"  a = b":        "a",
		"flag; Secure":   "flag",
		"":               "",
		"=value":         "",
		"n=v=w; Path=/x": "n",
	} {
		if got := setCookieName(in); got != want {
			t.Errorf("setCookieName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The Phase 1 scenarios (spec §15 WP-L1) load, declare "run", resolve with a
// run id, and send requests only to origin-form paths of one host.
func TestPhase1Scenarios(t *testing.T) {
	for _, tc := range []struct {
		file     string
		requests int
		prefixes []string
	}{
		{"phase1-impersonator.yaml", 26, []string{"/lab/impersonator/r1/", "/lab/crawler/r1/"}},
		{"phase1-nonjs-clearance.yaml", 9, []string{"/lab/members/r1/", "/__mg/c"}},
	} {
		s, err := Load("../../testdata/scenarios/" + tc.file)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if len(s.Requests) != tc.requests || s.Vars["run"] == nil {
			t.Fatalf("%s: %d requests, vars %v", tc.file, len(s.Requests), s.Vars)
		}
		rs, err := s.Resolve(map[string]string{"run": "r1"})
		if err != nil {
			t.Fatalf("%s: Resolve: %v", tc.file, err)
		}
		for i, r := range rs.Requests {
			if !slices.ContainsFunc(tc.prefixes, func(p string) bool { return strings.HasPrefix(r.Path, p) }) {
				t.Errorf("%s: requests[%d] path %q outside %v", tc.file, i, r.Path, tc.prefixes)
			}
			if r.Headers["CF-Connecting-IP"] == "" || r.ExpectStatus == 0 {
				t.Errorf("%s: requests[%d] lacks CF-Connecting-IP or expect_status", tc.file, i)
			}
			if strings.Contains(r.Path+r.Body, "${") {
				t.Errorf("%s: requests[%d] still has a variable", tc.file, i)
			}
			// Every challenge submission and protected page must show that
			// no clearance was issued and no redirect happened (§15 WP-L1).
			if strings.HasPrefix(r.Path, "/__mg/c") || strings.HasPrefix(r.Path, "/lab/members/") {
				if !slices.Contains(r.ExpectCookieAbsent, "__Host-mg_clr") || !slices.Contains(r.ExpectHeaderAbsent, "Location") {
					t.Errorf("%s: requests[%d] (%s) does not forbid __Host-mg_clr and Location", tc.file, i, r.Name)
				}
			}
		}
	}
}

// xorshift is the deterministic generator of the random-input tests
// (docs/impl/phase1-spec.md §2.4 item 3).
type xorshift uint64

func (x *xorshift) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift(v)
	return v
}

// mutate splices template and YAML tokens into seed, truncates it or
// replaces it with noise.
func (x *xorshift) mutate(seed string) string {
	tokens := []string{"${", "$${", "}", "${run}", "${x}", "$", "{", "\n", ": ", "- ", "~", "'", `"`, "\x00", "/", "//", "#", " ", "&a", "*a", "<<: *a", "vars:", "delay_ms: 99999", "expect_status_in: []"}
	switch x.next() % 4 {
	case 0:
		b := make([]byte, x.next()%128)
		for i := range b {
			b[i] = byte(x.next())
		}
		return string(b)
	case 1:
		if seed == "" {
			return ""
		}
		return seed[:x.next()%uint64(len(seed))]
	default:
		out := seed
		for n := x.next()%4 + 1; n > 0; n-- {
			i := 0
			if len(out) > 0 {
				i = int(x.next() % uint64(len(out)))
			}
			out = out[:i] + tokens[x.next()%uint64(len(tokens))] + out[i:]
		}
		return out
	}
}

// Parse, Resolve and substitute return errors, never panic, on arbitrary
// input.
func TestRandomScenariosDoNotPanic(t *testing.T) {
	seed := "name: r\nvars: {run: manual, id: ~}\nrequests:\n  - method: GET\n    path: /a/${run}/${id}\n    headers: {X-A: '${run}'}\n    body: '$${x}'\n    delay_ms: 5\n    expect_status_in: [403]\n    expect_cookie_absent: [c]\n"
	x := xorshift(0x9e3779b97f4a7c15)
	parsed, resolved := 0, 0
	for i := 0; i < 10000; i++ {
		_, _ = substitute(x.mutate("/p/${run}"), map[string]string{"run": "r"})
		_ = setCookieName(x.mutate("__Host-mg_clr=v; Path=/"))
		s, err := Parse([]byte(x.mutate(seed)))
		if err != nil {
			continue
		}
		parsed++
		vals := map[string]string{"id": "7"}
		if x.next()%2 == 0 {
			vals["id"] = x.mutate("7")
		}
		if x.next()%3 == 0 {
			vals["run"] = x.mutate("r1")
		}
		if _, err := s.Resolve(vals); err == nil {
			resolved++
		}
	}
	// The mutations must also produce valid scenarios, or Resolve is untested.
	if parsed < 100 || resolved < 50 {
		t.Errorf("only %d of 10000 inputs parsed and %d resolved", parsed, resolved)
	}
}
