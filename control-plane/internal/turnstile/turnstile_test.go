package turnstile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	testToken   = "cf-test-token-0123456789"
	testAccount = "0123456789abcdef0123456789abcdef"
	testSitekey = "0x4AAAAAAAkat-test-sitekey"
	oldSecret   = "0x4AAAAAAAkat-test-secret-current-00000000"
	newSecret   = "0x4AAAAAAAkat-test-secret-rotated-0000000"
)

type request struct {
	Method, Path, Query, Auth, UA, ContentType, Body string
}

// fakeAPI is a loopback stand-in for the documented Turnstile widget API.
type fakeAPI struct {
	mu       sync.Mutex
	requests []request
	widgets  int    // listed widgets
	secret   string // current secret
	status   int    // non-zero: answer every request with this status
	raw      string // non-empty: answer every request with this body
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"),
			r.Header.Get("User-Agent"), r.Header.Get("Content-Type"), string(body)})
		w.Header().Set("Content-Type", "application/json")
		if f.status != 0 {
			w.WriteHeader(f.status)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
			return
		}
		if f.raw != "" {
			fmt.Fprint(w, f.raw)
			return
		}
		base := "/client/v4/accounts/" + testAccount + "/challenges/widgets"
		widget := func(secret string) map[string]any {
			m := map[string]any{"sitekey": testSitekey, "name": "blog", "mode": "managed", "domains": []string{"example.com"},
				"created_on": "2026-09-01T00:00:00Z", "modified_on": "2026-09-02T00:00:00Z"}
			if secret != "" {
				m["secret"] = secret
			}
			return m
		}
		var result any
		var info any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			page := r.URL.Query().Get("page")
			var ws []any
			start := 0
			if page == "2" {
				start = 100
			}
			for i := start; i < min(f.widgets, start+100); i++ {
				m := widget("leaked-in-listing")
				m["sitekey"] = fmt.Sprintf("0x4AAAAAAAw%04d", i)
				ws = append(ws, m)
			}
			result = ws
			info = map[string]int{"page": 1, "per_page": 100, "count": len(ws), "total_count": f.widgets}
		case r.Method == http.MethodGet && r.URL.Path == base+"/"+testSitekey:
			result = widget(f.secret)
		case r.Method == http.MethodPost && r.URL.Path == base+"/"+testSitekey+"/rotate_secret":
			f.secret = newSecret
			result = widget(f.secret)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":7003,"message":"No route"}]}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result, "result_info": info})
	})
}

func newFake(t *testing.T) (*fakeAPI, *Client) {
	t.Helper()
	f := &fakeAPI{secret: oldSecret, widgets: 3}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/client/v4", testToken, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func checkCommon(t *testing.T, r request) {
	t.Helper()
	if r.Auth != "Bearer "+testToken || r.UA != UserAgent {
		t.Errorf("headers: auth %q, user agent %q", r.Auth, r.UA)
	}
}

// Phase 2 spec §8.7, §16: rotate_secret always sends invalidate_immediately
// explicitly, false included.
func TestRotateSecretSendsInvalidateImmediatelyExplicitly(t *testing.T) {
	for _, invalidate := range []bool{false, true} {
		f, c := newFake(t)
		w, err := c.RotateSecret(context.Background(), testAccount, testSitekey, invalidate)
		if err != nil {
			t.Fatal(err)
		}
		if w.Secret != newSecret {
			t.Errorf("secret not returned")
		}
		if len(f.requests) != 1 {
			t.Fatalf("%d requests", len(f.requests))
		}
		r := f.requests[0]
		checkCommon(t, r)
		want := fmt.Sprintf(`{"invalidate_immediately":%v}`, invalidate)
		if r.Method != http.MethodPost || r.Path != "/client/v4/accounts/"+testAccount+"/challenges/widgets/"+testSitekey+"/rotate_secret" ||
			r.Body != want || r.ContentType != "application/json" {
			t.Errorf("request %+v, want body %s", r, want)
		}
	}
}

func TestWidgetAndListing(t *testing.T) {
	f, c := newFake(t)
	w, err := c.Widget(context.Background(), testAccount, testSitekey)
	if err != nil || w.Secret != oldSecret || w.Sitekey != testSitekey {
		t.Fatalf("widget %v, %v", w, err)
	}
	if r := f.requests[0]; r.Method != http.MethodGet || r.Body != "" || r.Path != "/client/v4/accounts/"+testAccount+"/challenges/widgets/"+testSitekey {
		t.Errorf("request %+v", r)
	}
	for _, s := range []string{w.String(), fmt.Sprintf("%v", *w), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", *w)} {
		if strings.Contains(s, oldSecret) {
			t.Errorf("formatting shows the secret: %s", s)
		}
	}
	// Two pages; secrets in a listing are dropped.
	f.widgets = 150
	f.requests = nil
	ws, err := c.Widgets(context.Background(), testAccount)
	if err != nil || len(ws) != 150 {
		t.Fatalf("%d widgets, %v", len(ws), err)
	}
	for _, w := range ws {
		if w.Secret != "" {
			t.Fatal("listing kept a secret")
		}
	}
	if len(f.requests) != 2 || f.requests[0].Query != "page=1&per_page=100" || f.requests[1].Query != "page=2&per_page=100" {
		t.Errorf("requests %+v", f.requests)
	}
	checkCommon(t, f.requests[1])
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	f.status = http.StatusForbidden
	_, err := c.RotateSecret(ctx, testAccount, testSitekey, false)
	var ae *APIError
	if !asAPIError(err, &ae) || ae.Status != 403 || !strings.Contains(err.Error(), "10000 Authentication error") {
		t.Errorf("403: %v", err)
	}
	f.status = 0
	for _, raw := range []string{
		`not json`,
		`{"success":true,"result":null}`,
		`{"success":false,"errors":[{"code":1,"message":"x"}]}`,
		`{"success":true,"result":{"sitekey":"0x4AAAAAAAother","secret":"` + oldSecret + `"}}`,
		`{"success":true,"result":{"sitekey":"` + testSitekey + `","secret":""}}`,
		`{"success":true,"result":{"sitekey":"` + testSitekey + `","secret":"has space ` + oldSecret + `"}}`,
	} {
		f.raw = raw
		_, err := c.Widget(ctx, testAccount, testSitekey)
		if err == nil {
			t.Errorf("accepted %s", raw)
			continue
		}
		if strings.Contains(err.Error(), oldSecret) || strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaks a secret: %v", err)
		}
	}
	// Inputs never change the request path.
	for _, bad := range [][2]string{{"../x", testSitekey}, {testAccount, "a/b"}, {testAccount, "a b"}, {"", testSitekey}} {
		if _, err := c.Widget(ctx, bad[0], bad[1]); err == nil {
			t.Errorf("accepted account %q sitekey %q", bad[0], bad[1])
		}
	}
}

func asAPIError(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}

func TestNewRules(t *testing.T) {
	for _, base := range []string{"http://api.example.com/client/v4", "ftp://127.0.0.1/", "https://user:pw@api.example.com", "https://api.example.com/?x=1", "://"} {
		if _, err := New(base, testToken, nil); err == nil {
			t.Errorf("accepted base %q", base)
		}
	}
	for _, tok := range []string{"", "a b", "tok\n"} {
		if _, err := New("", tok, nil); err == nil {
			t.Errorf("accepted token %q", tok)
		}
	}
	if c, err := New("", testToken, nil); err != nil || c.base.String() != DefaultBaseURL {
		t.Errorf("default base: %v", err)
	}
	if _, err := New("http://[::1]:8080/client/v4", testToken, nil); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

// The bearer token never follows a redirect.
func TestNoRedirects(t *testing.T) {
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotAuth = r.Header.Get("Authorization") }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(srv.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Widgets(context.Background(), testAccount); err == nil {
		t.Error("a redirect was accepted")
	}
	if gotAuth != "" {
		t.Error("the token followed the redirect")
	}
}
