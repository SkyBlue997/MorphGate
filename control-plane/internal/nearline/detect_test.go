package nearline

import (
	"slices"
	"testing"
	"time"
)

// t0 is a minute boundary; tests add whole minutes and seconds to it.
const t0 = int64(1790000040000)

func init() {
	if t0%msPerMinute != 0 {
		panic("t0 must be a minute boundary")
	}
}

func key(n int) Key16 {
	var k Key16
	k[14], k[15] = byte(n>>8), byte(n)
	k[0] = 0xa0
	return k
}

// dec returns a v2 decision entry for the "blog" site: an HTML GET from
// ipk key(1), pfk key(1001), IPv4, no clearance, same-origin.
func dec(ts int64) Entry {
	return Entry{
		Version: 2, Kind: KindDecision, Site: "blog", TS: ts, RID: "r", Route: "default",
		IPK: key(1), HasIPK: true, PFK: key(1001), HasPFK: true, ASN: 64500,
		Action: "allow", Class: "unknown", Status: 200, Method: "GET", PH: 1, HasPH: true,
		CT: 'h', PF: '-', UF: "chrome", Fam: 4,
	}
}

func feedback(ts int64, outcome string) Entry {
	return Entry{Version: 2, Kind: KindFeedback, Site: "blog", TS: ts, RID: "r", Route: "login",
		Outcome: outcome, Type: "interactive", PFK: key(1001), HasPFK: true, IPK: key(1), HasIPK: true}
}

type harness struct {
	t       *testing.T
	p       *Processor
	now     int64
	dropped map[string]int
}

func newHarness(t *testing.T, mut func(*Config)) *harness {
	cfg := DefaultConfig()
	cfg.Version = 1
	cfg.Valkey.URL = "unix:///run/valkey/valkey.sock"
	cfg.Sites = []string{"blog"}
	if mut != nil {
		mut(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, now: t0 + 3600_000, dropped: map[string]int{}}
	h.p = NewProcessor(&cfg, func(d string) { h.dropped[d]++ })
	return h
}

// feed processes es (the clock is an hour ahead of t0, so entry times are
// never clamped) and returns the verdicts.
func (h *harness) feed(es ...Entry) []Verdict {
	var out []Verdict
	for i := range es {
		out = append(out, h.p.Process(&es[i], h.now)...)
	}
	return out
}

func (h *harness) expectNone(what string, vs []Verdict) {
	h.t.Helper()
	if len(vs) != 0 {
		h.t.Fatalf("%s: got %d verdict(s) %+v, want none", what, len(vs), vs[0])
	}
}

func (h *harness) expectOne(what, detector, typ, key string, vs []Verdict) Verdict {
	h.t.Helper()
	if len(vs) != 1 {
		h.t.Fatalf("%s: got %d verdicts, want 1", what, len(vs))
	}
	v := vs[0]
	if v.Detector != detector || v.Type != typ || v.Key != key || v.Site != "blog" || v.Mode != ModeShadow {
		h.t.Fatalf("%s: got %+v, want %s %s %s", what, v, detector, typ, key)
	}
	return v
}

func bait(ts int64, ph uint64) Entry {
	e := dec(ts)
	e.BT, e.PH, e.Status, e.CT = true, ph, 404, 'o'
	return e
}

func TestScannerBaitBoundary(t *testing.T) {
	h := newHarness(t, nil)
	h.expectNone("one bait path", h.feed(bait(t0, 1), bait(t0+1000, 1)))
	v := h.expectOne("second distinct bait path", DetScanner, "ip", key(1).String(), h.feed(bait(t0+2000, 2)))
	if v.Risk != 80 || v.TTL != 15*time.Minute || !slices.Equal(v.Labels, []string{"nl_scanner"}) ||
		!slices.Equal(v.Reasons, []string{"nl.scanner.bait"}) || v.Evidence["bait"] != 2 {
		t.Errorf("verdict: %+v", v)
	}
	if v.VerdictKey() != "mg:v:blog:ip:"+key(1).String() || v.Source() != "nearline/scanner" {
		t.Errorf("key / source: %s %s", v.VerdictKey(), v.Source())
	}
	// Never the scanner label that the matrix blocks on (D-53).
	if slices.Contains(v.Labels, "scanner") {
		t.Error("near-line verdicts must not carry the scanner label")
	}
}

func TestScannerSkipsTokenAndCrossSite(t *testing.T) {
	h := newHarness(t, nil)
	a, b := bait(t0, 1), bait(t0, 2)
	a.TK, b.XS = true, true
	c, d := bait(t0, 3), bait(t0, 4)
	c.XS, d.TK = true, true
	h.expectNone("tk = 1 / xs = 1 entries", h.feed(a, b, c, d))
	h.expectOne("counted entries", DetScanner, "ip", key(1).String(), h.feed(bait(t0, 5), bait(t0, 6)))
}

func TestScannerWindowSlides(t *testing.T) {
	h := newHarness(t, nil)
	h.expectNone("first", h.feed(bait(t0, 1)))
	h.expectNone("10 minutes later (outside the window)", h.feed(bait(t0+10*msPerMinute, 2)))
	h.expectOne("9 minutes after the second", DetScanner, "ip", key(1).String(), h.feed(bait(t0+19*msPerMinute+59_000, 3)))
}

func status(ts int64, ph uint64, code int) Entry {
	e := dec(ts)
	e.PH, e.Status = ph, code
	return e
}

func TestScannerStatusBoundary(t *testing.T) {
	h := newHarness(t, nil)
	var es []Entry
	for i := range 29 {
		es = append(es, status(t0, uint64(100+i), []int{404, 403, 405}[i%3]))
	}
	h.expectNone("29 distinct paths", h.feed(es...))
	h.expectNone("repeat of a path", h.feed(status(t0, 100, 404)))
	v := h.expectOne("30th distinct path", DetScanner, "ip", key(1).String(), h.feed(status(t0, 200, 404)))
	if !slices.Equal(v.Reasons, []string{"nl.scanner.status"}) || v.Evidence["distinct_404"] != 30 {
		t.Errorf("verdict: %+v", v)
	}
}

func TestScannerStatusShareBoundary(t *testing.T) {
	run := func(ok200 int) []Verdict {
		h := newHarness(t, nil)
		var es []Entry
		for range ok200 {
			es = append(es, status(t0, 7, 200))
		}
		for i := range 30 {
			es = append(es, status(t0, uint64(100+i), 404))
		}
		return h.feed(es...)
	}
	// 30 errors of 50 entries = 0.6: verdict; 30 of 51 = 0.588: none.
	if vs := run(20); len(vs) != 1 {
		t.Errorf("share 0.6: %d verdicts, want 1", len(vs))
	}
	if vs := run(21); len(vs) != 0 {
		t.Errorf("share 30/51: %d verdicts, want 0", len(vs))
	}
}

func TestScannerIPv6PrefixWindow(t *testing.T) {
	h := newHarness(t, nil)
	pfx := key(2001)
	mk := func(i int) Entry {
		e := bait(t0, uint64(i))
		e.Fam, e.IPK, e.PFK = 6, key(100+i), pfx // every request from another /64
		return e
	}
	var es []Entry
	for i := range 7 {
		es = append(es, mk(i))
	}
	h.expectNone("7 distinct bait paths across /64s (threshold 2 x 4)", h.feed(es...))
	h.expectOne("8th", DetScanner, "prefix", pfx.String(), h.feed(mk(7)))

	// IPv4 entries never build a prefix window.
	h2 := newHarness(t, nil)
	for i := range 20 {
		e := bait(t0, uint64(i))
		e.IPK = key(100 + i)
		h2.expectNone("IPv4 prefix", h2.feed(e))
	}
}

func TestReportAgainAfterHalfTTL(t *testing.T) {
	h := newHarness(t, nil)
	h.expectOne("first", DetScanner, "ip", key(1).String(), h.feed(bait(t0, 1), bait(t0, 2)))
	h.expectNone("same condition, at once", h.feed(bait(t0, 3)))
	h.now += int64(7*time.Minute/time.Millisecond) + 29_000
	h.expectNone("before half the TTL", h.feed(bait(t0, 4)))
	h.now += 1000
	v := h.expectOne("after half the TTL", DetScanner, "ip", key(1).String(), h.feed(bait(t0, 5)))
	v.Rearm()
	h.expectOne("rearmed after a failed write", DetScanner, "ip", key(1).String(), h.feed(bait(t0, 6)))
}

func TestWindowFullDropsNewKeys(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Windows.MaxKeys = 2 })
	a, b := bait(t0, 1), bait(t0, 1)
	b.IPK = key(2)
	h.expectNone("two keys", h.feed(a, b))
	c1, c2 := bait(t0, 1), bait(t0, 2)
	c1.IPK, c2.IPK = key(3), key(3)
	h.expectNone("third key is dropped", h.feed(c1, c2))
	if h.dropped[DetScanner] != 2 {
		t.Errorf("scanner drops = %d, want 2", h.dropped[DetScanner])
	}
	h.expectOne("existing key still counts", DetScanner, "ip", key(1).String(), h.feed(bait(t0, 9)))
	// Keys that left the window are swept, which makes room again.
	late := t0 + 11*msPerMinute
	d1, d2 := bait(late, 1), bait(late, 2)
	d1.IPK, d2.IPK = key(3), key(3)
	h.expectOne("after the sweep", DetScanner, "ip", key(3).String(), h.feed(d1, d2))
}

func rate(ts int64) Entry {
	e := dec(ts)
	e.CT = 'j'
	return e
}

// feedRate sends perMinute counted entries in each of the given minutes and
// returns the verdicts of the last entry only, checking that no earlier one
// produced any.
func (h *harness) feedRate(minutes []int, perMinute int, mut func(*Entry, int)) []Verdict {
	h.t.Helper()
	var last []Verdict
	n := 0
	for mi, m := range minutes {
		for i := range perMinute {
			e := rate(t0 + int64(m)*msPerMinute + int64(i%60)*1000)
			if mut != nil {
				mut(&e, n)
			}
			n++
			vs := h.feed(e)
			if mi == len(minutes)-1 && i == perMinute-1 {
				last = vs
			} else if len(vs) != 0 {
				h.t.Fatalf("high_rate fired early (minute %d, entry %d): %+v", m, i, vs[0])
			}
		}
	}
	return last
}

func TestHighRateBoundary(t *testing.T) {
	h := newHarness(t, nil)
	v := h.expectOne("600 per minute for 5 minutes", DetHighRate, "ip", key(1).String(), h.feedRate([]int{0, 1, 2, 3, 4}, 600, nil))
	if v.Risk != 75 || !slices.Equal(v.Labels, []string{"nl_high_rate"}) || v.Evidence["min_per_minute"] != uint32(600) {
		t.Errorf("verdict: %+v", v)
	}
	h2 := newHarness(t, nil)
	h2.expectNone("599 in one of the minutes", h2.feedRate([]int{0, 1, 2, 3}, 600, nil))
	h2.expectNone("599 in the fifth", h2.feedRate([]int{4}, 599, nil))
	h3 := newHarness(t, nil)
	h3.expectNone("a gap minute", h3.feedRate([]int{0, 1, 3, 4, 5}, 600, nil))
}

func TestHighRateCountsOnlyHTMLJSONOther(t *testing.T) {
	for name, mut := range map[string]func(*Entry, int){
		"ct = a":  func(e *Entry, _ int) { e.CT = 'a' },
		"no ct":   func(e *Entry, _ int) { e.CT = 0 },
		"tk = 1":  func(e *Entry, _ int) { e.TK = true },
		"xs = 1":  func(e *Entry, _ int) { e.XS = true },
		"no ipk":  func(e *Entry, _ int) { e.HasIPK = false },
		"v1-like": func(e *Entry, _ int) { e.Version = 1 },
	} {
		h := newHarness(t, nil)
		h.expectNone(name, h.feedRate([]int{0, 1, 2, 3, 4}, 600, mut))
	}
	for name, ct := range map[string]byte{"h": 'h', "o": 'o'} {
		h := newHarness(t, nil)
		h.expectOne(name, DetHighRate, "ip", key(1).String(), h.feedRate([]int{0, 1, 2, 3, 4}, 600, func(e *Entry, _ int) { e.CT = ct }))
	}
}

func TestHighRateSharedEgress(t *testing.T) {
	ufs := []string{"chrome", "firefox", "safari"}
	h := newHarness(t, nil)
	h.expectNone("3 UA families", h.feedRate([]int{0, 1, 2, 3, 4}, 600, func(e *Entry, n int) { e.UF = ufs[n%3] }))
	h2 := newHarness(t, nil)
	h2.expectOne("2 UA families", DetHighRate, "ip", key(1).String(),
		h2.feedRate([]int{0, 1, 2, 3, 4}, 600, func(e *Entry, n int) { e.UF = ufs[n%2] }))
	// Three sessions on the same ipk (requests with a clearance are not
	// counted, but they show that several visitors share the address).
	h3 := newHarness(t, nil)
	for i, s := range []string{"s1", "s2", "s3"} {
		e := dec(t0 + int64(i))
		e.TK, e.Sess = true, s
		if i == 0 {
			// The state exists once a counted entry has been seen.
			h3.feed(rate(t0))
		}
		h3.feed(e)
	}
	h3.expectNone("3 sessions", h3.feedRate([]int{0, 1, 2, 3, 4}, 600, nil))
}

func TestHighRateIPv6Prefix(t *testing.T) {
	pfx := key(3001)
	mut := func(e *Entry, n int) { e.Fam, e.PFK, e.IPK = 6, pfx, key(n%4000+10) }
	h := newHarness(t, nil)
	h.expectOne("2400 per minute across /64s", DetHighRate, "prefix", pfx.String(), h.feedRate([]int{0, 1, 2, 3, 4}, 2400, mut))
	h2 := newHarness(t, nil)
	h2.expectNone("2399 in the last minute", h2.feedRate([]int{0, 1, 2, 3}, 2400, mut))
	h2.expectNone("", h2.feedRate([]int{4}, 2399, mut))
}

func mismatch(ts int64, sess string, pfk int) Entry {
	e := dec(ts)
	e.TK, e.PF, e.Sess, e.CT, e.PFK = true, 'j', sess, 'j', key(pfk)
	return e
}

func TestSharedTokenBoundary(t *testing.T) {
	h := newHarness(t, nil)
	h.expectNone("two entries", h.feed(mismatch(t0, "S1", 1), mismatch(t0, "S1", 2)))
	v := h.expectOne("third entry, two prefixes", DetSharedToken, "session", "S1", h.feed(mismatch(t0, "S1", 2)))
	if v.Risk != 85 || v.TTL != time.Hour || !slices.Equal(v.Labels, []string{"nl_shared_token"}) {
		t.Errorf("verdict: %+v", v)
	}
	h2 := newHarness(t, nil)
	h2.expectNone("one prefix", h2.feed(mismatch(t0, "S2", 1), mismatch(t0, "S2", 1), mismatch(t0, "S2", 1)))
	h2.expectOne("second prefix", DetSharedToken, "session", "S2", h2.feed(mismatch(t0, "S2", 9)))
	h3 := newHarness(t, nil)
	ok := mismatch(t0, "S3", 1)
	ok.PF = 'v'
	ok2, ok3 := ok, ok
	ok2.PFK, ok3.PFK = key(2), key(3)
	h3.expectNone("pf = v", h3.feed(ok, ok2, ok3))
	noSess := mismatch(t0, "", 1)
	h3.expectNone("no sess", h3.feed(noSess, noSess, noSess))
}

func TestChallengeAbuseBoundary(t *testing.T) {
	run := func(fails, passes int) []Verdict {
		h := newHarness(t, nil)
		var es []Entry
		for range passes {
			es = append(es, feedback(t0, "pass"))
		}
		for range fails - 1 {
			es = append(es, feedback(t0, "fail"))
		}
		h.expectNone("before the last fail", h.feed(es...))
		return h.feed(feedback(t0, "fail"))
	}
	if vs := run(29, 0); len(vs) != 0 {
		t.Error("29 fails: want no verdict")
	}
	vs := run(30, 0)
	if len(vs) != 1 || vs[0].Detector != DetChallengeAbuse || vs[0].Type != "prefix" || vs[0].Key != key(1001).String() || vs[0].Risk != 70 {
		t.Fatalf("30 fails: %+v", vs)
	}
	if vs := run(30, 3); len(vs) != 1 {
		t.Error("30 fails, 3 passes (9.1%): want a verdict")
	}
	if vs := run(36, 4); len(vs) != 0 {
		t.Error("36 fails, 4 passes (exactly 10%): want none")
	}
	// Other outcomes are not counted; entries without pfk are skipped.
	h := newHarness(t, nil)
	var es []Entry
	for range 40 {
		es = append(es, feedback(t0, "unavailable"), feedback(t0, "renew_rebind"))
		f := feedback(t0, "fail")
		f.HasPFK = false
		es = append(es, f)
	}
	h.expectNone("other outcomes", h.feed(es...))
}

func TestUnknownSiteAndV1Decisions(t *testing.T) {
	h := newHarness(t, nil)
	e := bait(t0, 1)
	e.Site = "other"
	h.expectNone("other site", h.feed(e, e))
	a, b := bait(t0, 1), bait(t0, 2)
	a.Version, b.Version = 1, 1
	h.expectNone("v1 decisions", h.feed(a, b))
}

func TestFutureTimestampsAreClamped(t *testing.T) {
	h := newHarness(t, nil)
	far := h.now + 365*24*3600_000
	h.expectNone("one", h.feed(bait(far, 1)))
	// Clamped to now: a bait now is in the same window.
	h.expectOne("second", DetScanner, "ip", key(1).String(), h.feed(bait(h.now, 2)))
}

func TestModesInVerdicts(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Detectors.Scanner.Mode = ModeEnforce })
	vs := h.feed(bait(t0, 1), bait(t0, 2))
	if len(vs) != 1 || vs[0].Mode != ModeEnforce {
		t.Fatalf("got %+v", vs)
	}
}
