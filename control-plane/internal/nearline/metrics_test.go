package nearline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetricsText(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sites = []string{"blog", "shop"}
	cfg.Detectors.HighRate.Mode = ModeEnforce
	m := NewMetrics(&cfg)
	m.Entry("blog", KindDecision)
	m.Entry("blog", KindDecision)
	m.ParseError()
	m.Verdict("shop", DetHighRate, ModeEnforce)
	m.Dropped(DetScanner)
	m.Error(OpRead)
	m.SetStatus(1.5, 7, 2)
	m.SetLastBatch(1790000000.25)
	m.SetShares("blog", Shares{Visitor: 0.001, HasVisitor: true})
	text := metricsText(t, m)
	for _, line := range []string{
		"# TYPE mg_nl_entries_total counter",
		`mg_nl_entries_total{site="blog",kind="decision"} 2`,
		`mg_nl_entries_total{site="shop",kind="feedback"} 0`,
		"mg_nl_parse_errors_total 1",
		`mg_nl_verdicts_total{site="shop",detector="high_rate",mode="enforce"} 1`,
		`mg_nl_verdicts_total{site="blog",detector="scanner",mode="shadow"} 0`,
		"# TYPE mg_nl_lag_seconds gauge",
		"mg_nl_lag_seconds 1.5",
		"mg_nl_backlog 7",
		"mg_nl_pending 2",
		`mg_nl_window_dropped_total{detector="scanner"} 1`,
		`mg_nl_window_dropped_total{detector="shared_token"} 0`,
		`mg_nl_errors_total{op="read"} 1`,
		`mg_nl_errors_total{op="verdict"} 0`,
		"mg_nl_last_batch_timestamp_seconds 1.79000000025e+09",
		`mg_nl_interactive_visitor_share{site="blog"} 0.001`,
		"# TYPE mg_nl_interactive_abandon_share gauge",
	} {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("missing %q", line)
		}
	}
	// No share is exported for a site below the denominator.
	if strings.Contains(text, `share{site="shop"}`) || strings.Contains(text, `mg_nl_interactive_abandon_share{`) {
		t.Errorf("unexpected share series:\n%s", text)
	}
	m.SetShares("blog", Shares{})
	if strings.Contains(metricsText(t, m), `mg_nl_interactive_visitor_share{`) {
		t.Error("a share that became unavailable is still exported")
	}

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") || !strings.Contains(string(body), "mg_nl_backlog 7") {
		t.Errorf("GET /metrics: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp, err := http.Get(srv.URL + "/other"); err != nil || resp.StatusCode != 404 {
		t.Errorf("GET /other: %v %v", resp, err)
	}
}

func TestVLSinkRetriesAndDrops(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Sites = []string{"blog"}
	m := NewMetrics(&cfg)
	s, err := NewVLSink(srv.URL, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	ctx := context.Background()
	s.post(ctx, [][]byte{[]byte(`{"kind":"verdict"}`)})
	if calls.Load() != 3 {
		t.Errorf("5xx: %d attempts, want 3", calls.Load())
	}
	expectMetric(t, m, `mg_nl_errors_total{op="vl"} 1`)
	calls.Store(0)
	status.Store(400)
	s.post(ctx, [][]byte{[]byte(`{}`)})
	if calls.Load() != 1 {
		t.Errorf("4xx: %d attempts, want 1 (not retried)", calls.Load())
	}
	calls.Store(0)
	status.Store(204)
	s.post(ctx, [][]byte{[]byte(`{}`)})
	if calls.Load() != 1 {
		t.Errorf("2xx: %d attempts", calls.Load())
	}
	expectMetric(t, m, `mg_nl_errors_total{op="vl"} 2`)
	// A full queue drops instead of blocking.
	for range vlQueue + 5 {
		s.Enqueue([]byte("{}"))
	}
	expectMetric(t, m, `mg_nl_errors_total{op="vl"} 7`)
	// Redirects are not followed.
	redirect := httptest.NewServer(http.RedirectHandler(srv.URL, http.StatusFound))
	defer redirect.Close()
	s2, _ := NewVLSink(redirect.URL, m, nil)
	if err := s2.send(ctx, []byte("{}")); err == nil {
		t.Error("a redirect counted as delivered")
	}
}
