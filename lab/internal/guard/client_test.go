package guard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestServer serves:
//
//	/ok                    200 "ok"
//	/to?u=<url>            302 to <url>
//	/chain?n=<k>           302 to /chain?n=<k-1>, and 200 at n=0
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("/to", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound)
	})
	mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 {
			io.WriteString(w, "end")
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/chain?n=%d", n-1), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// strictResolver fails the test on any lookup: the test server is an IP
// literal, so any DNS lookup means a disallowed host got too far.
type strictResolver struct{ t *testing.T }

func (r strictResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.t.Errorf("unexpected DNS lookup for %q", host)
	return nil, errors.New("no DNS in this test")
}

func fastGuard(t *testing.T) *Guard {
	cfg := DefaultConfig()
	cfg.RateRPS = MaxRateRPS
	return mustGuard(t, cfg, WithResolver(strictResolver{t}))
}

func get(t *testing.T, c *http.Client, url string) (string, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestClientAllowedRequest(t *testing.T) {
	srv := newTestServer(t)
	body, err := get(t, fastGuard(t).Client(), srv.URL+"/ok")
	if err != nil || body != "ok" {
		t.Fatalf("GET /ok = %q, %v", body, err)
	}
}

func TestClientRefusesDisallowedURL(t *testing.T) {
	c := fastGuard(t).Client()
	for _, u := range []string{"http://example.com/", "http://localhost@example.com/", "ftp://127.0.0.1/"} {
		if _, err := get(t, c, u); !errors.Is(err, ErrDenied) {
			t.Errorf("GET %s = %v, want ErrDenied", u, err)
		}
	}
}

func TestClientRedirects(t *testing.T) {
	srv := newTestServer(t)
	c := fastGuard(t).Client()
	cases := []struct {
		name   string
		path   string
		want   string // body on success
		denied bool
	}{
		{"same host", "/to?u=/ok", "ok", false},
		{"absolute allowed", "/to?u=" + srv.URL + "/ok", "ok", false},
		{"numeric trick to loopback", "/to?u=" + strings.Replace(srv.URL, "127.0.0.1", "2130706433", 1) + "/ok", "ok", false},
		{"external host", "/to?u=http://example.com/", "", true},
		{"allowed name as subdomain", "/to?u=http://localhost.evil.com/", "", true},
		{"userinfo", "/to?u=http://localhost@example.com/", "", true},
		{"metadata", "/to?u=http://169.254.169.254/", "", true},
		{"scheme change", "/to?u=file:///etc/passwd", "", true},
		{"five redirects", "/chain?n=5", "end", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := get(t, c, srv.URL+tc.path)
			if tc.denied {
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("got body %q err %v, want ErrDenied", body, err)
				}
				return
			}
			if err != nil || body != tc.want {
				t.Fatalf("got %q, %v; want %q", body, err, tc.want)
			}
		})
	}

	_, err := get(t, c, srv.URL+"/chain?n=6")
	if err == nil || !strings.Contains(err.Error(), "stopped after 5 redirects") {
		t.Errorf("six redirects: %v, want redirect cap error", err)
	}
}

func TestClientIgnoresProxyEnvironment(t *testing.T) {
	c := fastGuard(t).Client()
	tr := c.Transport.(*guardedTransport).next.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("transport uses a proxy function; the guard must see the real destination")
	}
	if c.Timeout == 0 || tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Error("client without timeouts")
	}
}

func TestClientRateCap(t *testing.T) {
	srv := newTestServer(t)
	cfg := DefaultConfig()
	cfg.RateRPS = 20 // 50 ms spacing
	c := mustGuard(t, cfg).Client()
	start := time.Now()
	for i := 0; i < 4; i++ {
		if _, err := get(t, c, srv.URL+"/ok"); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond {
		t.Errorf("4 requests at 20 rps took %v, want >= 150ms", elapsed)
	}
}
