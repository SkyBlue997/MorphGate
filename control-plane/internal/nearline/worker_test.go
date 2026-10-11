package nearline

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is an adjustable clock: real time plus an offset.
type clock struct{ off atomic.Int64 }

func (c *clock) now() time.Time      { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *clock) add(d time.Duration) { c.off.Add(int64(d)) }

func (fx *fixture) worker(cfg *Config, consumer string, vl *VLSink, clk *clock) (*Worker, *Metrics) {
	fx.t.Helper()
	m := NewMetrics(cfg)
	now := time.Now
	if clk != nil {
		now = clk.now
	}
	return NewWorker(cfg, fx.store(fx.connOptions("", ""), consumer), m, nil, vl, now), m
}

func baitFV(site string, ph string) []string {
	return decisionFV(site, time.Now().UnixMilli(), map[string]string{"bt": "1", "ph": ph, "status": "404", "ct": "o"})
}

func metricsText(t *testing.T, m *Metrics) string {
	t.Helper()
	var b bytes.Buffer
	if err := m.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func expectMetric(t *testing.T, m *Metrics, line string) {
	t.Helper()
	if text := metricsText(t, m); !strings.Contains(text, "\n"+line+"\n") {
		t.Fatalf("metrics lack %q:\n%s", line, text)
	}
}

func (fx *fixture) pending() int64 {
	fx.t.Helper()
	arr, err := fx.do("XPENDING", fx.key, "nl").ToArray()
	if err != nil {
		fx.t.Fatal(err)
	}
	n, _ := arr[0].AsInt64()
	return n
}

func TestGroupCreatedAtStreamEnd(t *testing.T) {
	fx := needValkey(t)
	fx.xadd(baitFV(fx.site, "00000000000000a1")...) // before the group: never consumed
	cfg := fx.config()
	w, m := fx.worker(cfg, "w", nil, nil)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 0`)
	fx.xadd(baitFV(fx.site, "00000000000000a2")...)
	if err := w.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 1`)
	if fx.pending() != 0 {
		t.Fatal("entry not acknowledged")
	}
	// A second start keeps the existing group and its position.
	fx.xadd(baitFV(fx.site, "00000000000000a3")...)
	w2, m2 := fx.worker(cfg, "w2", nil, nil)
	if err := w2.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m2, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 1`)
	// The stream disappears (NOGROUP): the worker recreates the group.
	fx.del(fx.key)
	if err := w2.Step(fx.ctx); err == nil {
		t.Fatal("read from a deleted stream succeeded")
	}
	fx.xadd(baitFV(fx.site, "00000000000000a4")...)
	if err := w2.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m2, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 2`)
	expectMetric(t, m2, `mg_nl_errors_total{op="read"} 1`)
}

func TestReclaimAndStaleConsumers(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	cfg.Stream.ReclaimIdleMs = 200 // test only
	fx.do("XGROUP", "CREATE", fx.key, "nl", "$", "MKSTREAM")
	fx.do("XGROUP", "CREATECONSUMER", fx.key, "nl", "gone-idle")
	fx.xadd(baitFV(fx.site, "00000000000000b1")...)
	fx.xadd(baitFV(fx.site, "00000000000000b2")...)
	// An exited process left two delivered, unacknowledged entries.
	if err := fx.do("XREADGROUP", "GROUP", "nl", "gone-busy", "COUNT", "10", "STREAMS", fx.key, ">").Error(); err != nil {
		t.Fatal(err)
	}
	w, m := fx.worker(cfg, "w", nil, nil)
	// Too fresh to claim: Start deletes only the idle consumer.
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	cs, _ := w.store.Consumers(fx.ctx)
	if names := consumerNames(cs); names != "gone-busy,w" {
		t.Fatalf("consumers after Start: %s", names)
	}
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 0`)
	time.Sleep(250 * time.Millisecond)
	if err := w.Reclaim(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 2`)
	expectMetric(t, m, `mg_nl_verdicts_total{site="`+fx.site+`",detector="scanner",mode="shadow"} 1`)
	if fx.pending() != 0 {
		t.Fatal("claimed entries not acknowledged")
	}
	cs, _ = w.store.Consumers(fx.ctx)
	if names := consumerNames(cs); names != "w" {
		t.Fatalf("consumers after reclaim: %s", names)
	}
}

func TestReclaimManyEntries(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	cfg.Stream.ReclaimIdleMs = 1
	cfg.Stream.Batch = 7 // several XAUTOCLAIM pages
	fx.do("XGROUP", "CREATE", fx.key, "nl", "$", "MKSTREAM")
	for range 30 {
		fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), nil)...)
	}
	fx.do("XREADGROUP", "GROUP", "nl", "dead", "STREAMS", fx.key, ">")
	time.Sleep(5 * time.Millisecond)
	w, m := fx.worker(cfg, "w", nil, nil)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 30`)
	if fx.pending() != 0 {
		t.Fatal("pending entries left")
	}
}

func consumerNames(cs []ConsumerInfo) string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name)
	}
	return strings.Join(n, ",")
}

func TestFailedVerdictWriteLeavesBatchPending(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	cfg.Detectors.Scanner.Mode = ModeEnforce
	cfg.Stream.ReclaimIdleMs = 1
	w, m := fx.worker(cfg, "w", nil, nil)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	vkey := "mg:v:" + fx.site + ":ip:" + testIPK(1)
	fx.do("HSET", vkey, "f", "v") // GET inside the script fails: WRONGTYPE
	fx.xadd(baitFV(fx.site, "00000000000000c1")...)
	fx.xadd(baitFV(fx.site, "00000000000000c2")...)
	if err := w.Step(fx.ctx); err == nil {
		t.Fatal("Step succeeded although the verdict write failed")
	}
	if n := fx.pending(); n != 2 {
		t.Fatalf("pending = %d, want 2 (batch not acknowledged)", n)
	}
	expectMetric(t, m, `mg_nl_errors_total{op="verdict"} 1`)
	fx.del(vkey)
	time.Sleep(5 * time.Millisecond)
	if err := w.Reclaim(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if fx.pending() != 0 {
		t.Fatal("redelivered batch not acknowledged")
	}
	// At-least-once: both entries were counted twice.
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 4`)
	var v EntityVerdict
	raw, err := fx.do("GET", vkey).ToString()
	if err != nil || json.Unmarshal([]byte(raw), &v) != nil {
		t.Fatalf("verdict after redelivery: %q %v", raw, err)
	}
	if v.Source != "nearline/scanner" || v.Version != "p2.1" || v.Type != "ip" || v.Key != testIPK(1) ||
		v.Risk != 80 || v.SiteID != fx.site || len(v.Labels) != 1 || v.Labels[0] != "nl_scanner" ||
		len(v.Reasons) != 1 || v.Reasons[0] != "nl.scanner.bait" {
		t.Fatalf("verdict: %+v", v)
	}
	if d := v.ExpiresAtMs - time.Now().UnixMilli(); d < 14*60_000 || d > 15*60_000 {
		t.Fatalf("expires_at_ms - now = %d ms", d)
	}
	if pttl, _ := fx.do("PTTL", vkey).AsInt64(); pttl < 14*60_000 || pttl > 15*60_000 {
		t.Fatalf("PTTL = %d", pttl)
	}
}

// vlServer is a loopback VictoriaLogs stand-in that records lines.
type vlServer struct {
	mu    sync.Mutex
	lines []string
	ua    []string
	srv   *httptest.Server
}

func newVLServer(t *testing.T) *vlServer {
	s := &vlServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path != "/insert/jsonline" || r.URL.RawQuery != vlJSONLineQuery || r.Header.Get("Content-Type") != vlJSONContentType {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.ua = append(s.ua, r.UserAgent())
		for l := range strings.SplitSeq(strings.TrimSuffix(string(body), "\n"), "\n") {
			s.lines = append(s.lines, l)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *vlServer) wait(t *testing.T, n int) []string {
	t.Helper()
	for range 200 {
		s.mu.Lock()
		if len(s.lines) >= n {
			out := append([]string(nil), s.lines...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("VictoriaLogs got fewer than %d lines", n)
	return nil
}

func TestShadowAndEnforceOutputs(t *testing.T) {
	fx := needValkey(t)
	vls := newVLServer(t)
	cfg := fx.config()
	cfg.VerdictEvents.VLMain = vls.srv.URL
	cfg.Detectors.SharedToken.Mode = ModeEnforce
	m0 := NewMetrics(cfg)
	vl, err := NewVLSink(cfg.VerdictEvents.VLMain, m0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(fx.ctx)
	go vl.Run(ctx)
	defer func() { cancel(); <-vl.Done() }()
	w, m := fx.worker(cfg, "w", vl, nil)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	// scanner (shadow): two bait paths from ipk 1.
	fx.xadd(baitFV(fx.site, "00000000000000d1")...)
	fx.xadd(baitFV(fx.site, "00000000000000d2")...)
	// shared_token (enforce): three proof mismatches from two prefixes.
	for i, pfk := range []int{2001, 2002, 2002} {
		fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), map[string]string{
			"sess": "SessA_123", "tk": "1", "pf": "j", "pfk": testIPK(pfk), "ph": "000000000000000" + string(rune('1'+i)),
		})...)
	}
	if err := w.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := fx.do("EXISTS", "mg:v:"+fx.site+":ip:"+testIPK(1)).AsInt64(); n != 0 {
		t.Fatal("shadow verdict was written to Valkey")
	}
	raw, err := fx.do("GET", "mg:v:"+fx.site+":session:SessA_123").ToString()
	if err != nil || !strings.Contains(raw, `"source":"nearline/shared_token"`) || !strings.Contains(raw, `"labels":["nl_shared_token"]`) {
		t.Fatalf("enforce verdict: %q %v", raw, err)
	}
	expectMetric(t, m, `mg_nl_verdicts_total{site="`+fx.site+`",detector="scanner",mode="shadow"} 1`)
	expectMetric(t, m, `mg_nl_verdicts_total{site="`+fx.site+`",detector="shared_token",mode="enforce"} 1`)

	lines := vls.wait(t, 2)
	byDetector := map[string]map[string]any{}
	for _, l := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(l), &obj); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		if !strings.HasPrefix(l, `{"kind":"verdict","site":"`+fx.site+`","ts":`) {
			t.Errorf("envelope order: %s", l)
		}
		if strings.Contains(l, "203.0.113") || strings.Contains(l, "\"ip\":") {
			t.Errorf("line carries an IP: %s", l)
		}
		byDetector[obj["detector"].(string)] = obj
	}
	sc, st := byDetector["scanner"], byDetector["shared_token"]
	if sc == nil || st == nil {
		t.Fatalf("lines: %v", lines)
	}
	if sc["mode"] != "shadow" || sc["written"] != false || sc["type"] != "ip" || sc["key"] != testIPK(1) ||
		sc["source"] != "nearline/scanner" || sc["evidence"].(map[string]any)["bait"] != float64(2) {
		t.Errorf("scanner line: %v", sc)
	}
	if st["mode"] != "enforce" || st["written"] != true || st["type"] != "session" || st["risk"] != float64(85) {
		t.Errorf("shared_token line: %v", st)
	}
	vls.mu.Lock()
	if vls.ua[0] != UserAgent {
		t.Errorf("User-Agent %q", vls.ua[0])
	}
	vls.mu.Unlock()
}

func TestParseErrorsAndOtherSitesAreAcknowledged(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	w, m := fx.worker(cfg, "w", nil, nil)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	fx.xadd("v", "9", "kind", "decision")
	fx.xadd("garbage", "\x00\xff")
	fx.xadd(baitFV("other-site", "00000000000000e1")...)
	fx.xadd(sampleForSite(t, "mg-ev-v1.txt", fx.site)...)
	if err := w.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if fx.pending() != 0 {
		t.Fatal("entries left pending")
	}
	expectMetric(t, m, "mg_nl_parse_errors_total 2")
	expectMetric(t, m, `mg_nl_entries_total{site="`+fx.site+`",kind="decision"} 1`)
	if strings.Contains(metricsText(t, m), "other-site") {
		t.Error("an unconfigured site appears in the metrics")
	}
}

// sampleForSite returns the first entry of a sample file with its site
// replaced.
func sampleForSite(t *testing.T, name, site string) []string {
	fv := readSamples(t, name)[0]
	for i := 0; i+1 < len(fv); i += 2 {
		if fv[i] == "site" {
			fv[i+1] = site
		}
	}
	return fv
}

func TestLagAndBacklog(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	clk := &clock{}
	w, m := fx.worker(cfg, "w", nil, clk)
	if err := w.Start(fx.ctx); err != nil {
		t.Fatal(err)
	}
	status := func() (lag float64, backlog, pending float64) {
		t.Helper()
		if err := w.PollStatus(fx.ctx); err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.lagSeconds, m.backlog, m.pending
	}
	if err := w.Step(fx.ctx); err != nil { // caught up (empty read)
		t.Fatal(err)
	}
	clk.add(time.Hour)
	if lag, b, p := status(); lag != 0 || b != 0 || p != 0 {
		t.Fatalf("idle stream an hour later: lag %v backlog %v pending %v, want 0 0 0", lag, b, p)
	}
	// Three undelivered entries; the poll runs 10 s after they arrived.
	clk.add(-time.Hour)
	for range 3 {
		fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), nil)...)
	}
	clk.add(10 * time.Second)
	lag, b, p := status()
	if b != 3 || p != 0 || lag < 10 || lag > 15 {
		t.Fatalf("backlog: lag %v backlog %v pending %v, want ~10 s, 3, 0", lag, b, p)
	}
	if err := w.Step(fx.ctx); err != nil {
		t.Fatal(err)
	}
	if lag, b, p := status(); lag != 0 || b != 0 || p != 0 {
		t.Fatalf("after catching up: lag %v backlog %v pending %v", lag, b, p)
	}
	// One entry delivered to another consumer and not acknowledged.
	id := fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), nil)...)
	fx.do("XREADGROUP", "GROUP", "nl", "other", "STREAMS", fx.key, ">")
	ms, _ := IDMillis(id)
	clk.off.Store(int64(time.Duration(ms+30_000-time.Now().UnixMilli()) * time.Millisecond))
	lag, b, p = status()
	if b != 0 || p != 1 || lag < 29.5 || lag > 31 {
		t.Fatalf("pending: lag %v backlog %v pending %v, want ~30 s, 0, 1", lag, b, p)
	}
	expectMetric(t, m, "mg_nl_pending 1")
}

func TestServeEndToEnd(t *testing.T) {
	fx := needValkey(t)
	cfg := fx.config()
	if vk.addr.Network == "unix" {
		if !vk.spawned {
			t.Skip("Serve uses database 0 of a unix-socket server; only run on a throwaway server")
		}
		cfg.Valkey.URL = "unix://" + vk.addr.Address
	} else {
		cfg.Valkey.URL = "redis://" + vk.addr.Address + "/9"
	}
	cfg.Valkey.User = vk.user
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(fx.ctx)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, vk.password, nil, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	scrape := func() string {
		resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	// Wait until the group exists (Start ran), then add two bait entries.
	admin := fx
	if vk.addr.Network == "unix" {
		admin = fxOnDB0(t)
	}
	for i := 0; ; i++ {
		if n, _ := admin.do("EXISTS", "mg:ev").AsInt64(); n == 1 {
			break
		}
		if i > 200 {
			t.Fatal("the worker did not create the group")
		}
		time.Sleep(25 * time.Millisecond)
	}
	admin.xadd(baitFV(fx.site, "00000000000000f1")...)
	admin.xadd(baitFV(fx.site, "00000000000000f2")...)
	want := `mg_nl_verdicts_total{site="` + fx.site + `",detector="scanner",mode="shadow"} 1`
	for i := 0; !strings.Contains(scrape(), want); i++ {
		if i > 200 {
			t.Fatalf("no shadow verdict in /metrics:\n%s", scrape())
		}
		time.Sleep(25 * time.Millisecond)
	}
	text := scrape()
	for _, family := range []string{"mg_nl_entries_total", "mg_nl_parse_errors_total", "mg_nl_verdicts_total", "mg_nl_lag_seconds",
		"mg_nl_backlog", "mg_nl_pending", "mg_nl_window_dropped_total", "mg_nl_errors_total", "mg_nl_last_batch_timestamp_seconds",
		"mg_nl_interactive_visitor_share", "mg_nl_interactive_abandon_share"} {
		if !strings.Contains(text, "# TYPE "+family+" ") {
			t.Errorf("/metrics lacks %s", family)
		}
	}
}

// fxOnDB0 is a fixture on database 0 of the throwaway server.
func fxOnDB0(t *testing.T) *fixture {
	o := ConnOptions{Addr: vk.addr}
	c, err := Dial(context.Background(), o, "mg:ev", "nl", "admin0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &fixture{t: t, admin: c.Client(), key: "mg:ev", ctx: context.Background()}
}
