package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
		body         string // JSON, compared semantically; empty = not checked
	}{
		{"GET", "/healthz", 200, `{"status":"ok"}`},
		{"GET", "/v1/bundles/blog", 404, `{"error":"not_implemented","phase":3}`},
		{"GET", "/v1/bundles/shop-prod", 404, `{"error":"not_implemented","phase":3}`},
		{"POST", "/healthz", 405, ""},
		{"PUT", "/v1/bundles/blog", 405, ""},
		{"GET", "/v1/bundles/", 404, ""},
		{"GET", "/", 404, ""},
	}
	h := Handler()
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if tc.body == "" {
				return
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q", cc)
			}
			var got any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not JSON: %q", rec.Body.String())
			}
			if gb, _ := json.Marshal(got); string(gb) != mustCanon(tc.body) {
				t.Errorf("body = %s, want %s", gb, tc.body)
			}
		})
	}
}

func mustCanon(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestServeGracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, Config{ShutdownTimeout: 2 * time.Second}) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz = %d %s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Error("listener still accepting after shutdown")
	}
}

func TestServeReturnsListenerErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // Serve must report the closed listener instead of blocking.
	if err := Serve(context.Background(), ln, Config{}); err == nil {
		t.Fatal("expected an error from a closed listener")
	}
}
