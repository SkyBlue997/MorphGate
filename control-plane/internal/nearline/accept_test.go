package nearline

import (
	"math"
	"testing"
)

func acceptHarness(t *testing.T, minDen, maxPerDay int) *harness {
	return newHarness(t, func(c *Config) {
		c.Acceptance.MinDenominator = minDen
		c.Acceptance.MaxKeysPerDay = maxPerDay
	})
}

func visit(ts int64, ipk int) Entry {
	e := dec(ts)
	e.IPK = key(ipk)
	return e
}

func interactiveC(ts int64, ipk int, dry bool) Entry {
	e := dec(ts)
	e.IPK, e.Action, e.CType, e.Dry, e.CT, e.Status = key(ipk), "challenge", "interactive", dry, 0, 403
	return e
}

func pass(ts int64, ipk int) Entry {
	f := feedback(ts, "pass")
	f.IPK = key(ipk)
	return f
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestVisitorShare(t *testing.T) {
	h := acceptHarness(t, 4, 1000)
	h.feed(visit(t0, 1), visit(t0, 2), visit(t0, 3))
	h.feed(interactiveC(t0, 1, true)) // monitor mode counts for the visitor share
	if s := h.p.Shares("blog", h.now); s.HasVisitor || s.HTMLVisitors != 3 {
		t.Fatalf("3 HTML visitors < 4: %+v", s)
	}
	h.feed(visit(t0+1000, 4), visit(t0+2000, 4))
	s := h.p.Shares("blog", h.now)
	if !s.HasVisitor || !near(s.Visitor, 0.25) {
		t.Fatalf("visitor share: %+v, want 1/4", s)
	}
	// Non-HTML requests and requests without ipk are not visitors.
	a := visit(t0, 5)
	a.CT = 'a'
	b := visit(t0, 6)
	b.HasIPK = false
	h.feed(a, b)
	if s := h.p.Shares("blog", h.now); s.HTMLVisitors != 4 {
		t.Errorf("HTML visitors = %d, want 4", s.HTMLVisitors)
	}
}

func TestAbandonShare(t *testing.T) {
	h := acceptHarness(t, 3, 1000)
	h.now = t0 + 3600_000
	h.feed(
		interactiveC(t0, 1, false), pass(t0+5*msPerMinute, 1), // passed in time
		interactiveC(t0, 2, false), pass(t0+11*msPerMinute, 2), // too late: abandoned
		interactiveC(t0, 3, false), // never passed
		interactiveC(t0, 4, true),  // monitor mode: not served
	)
	s := h.p.Shares("blog", h.now)
	if !s.HasAbandon || s.ServedVisitors != 3 || !near(s.Abandon, 2.0/3) {
		t.Fatalf("abandon share: %+v, want 2/3 of 3", s)
	}
	// A visitor challenged again passes within 10 minutes of the latest C.
	h.feed(interactiveC(t0+20*msPerMinute, 3, false), pass(t0+29*msPerMinute, 3))
	if s := h.p.Shares("blog", h.now); !near(s.Abandon, 1.0/3) {
		t.Fatalf("after visitor 3 passed: %+v", s)
	}
	// A C younger than 10 minutes is undecided: in the denominator only.
	h.feed(interactiveC(h.now-60_000, 5, false))
	if s := h.p.Shares("blog", h.now); s.ServedVisitors != 4 || !near(s.Abandon, 1.0/4) {
		t.Fatalf("undecided visitor: %+v", s)
	}
	if s := h.p.Shares("blog", h.now+10*msPerMinute); !near(s.Abandon, 2.0/4) {
		t.Fatalf("10 minutes later: %+v", s)
	}
}

func TestAbandonPassAcrossMidnight(t *testing.T) {
	h := acceptHarness(t, 1, 1000)
	midnight := (t0/msPerDay + 1) * msPerDay
	h.now = midnight + 3600_000
	h.feed(interactiveC(midnight-2*msPerMinute, 1, false), pass(midnight+3*msPerMinute, 1))
	if s := h.p.Shares("blog", h.now); !s.HasAbandon || s.Abandon != 0 {
		t.Fatalf("pass after midnight: %+v", s)
	}
}

func TestSharesNeedMinDenominator(t *testing.T) {
	h := acceptHarness(t, 2000, 200000)
	for i := range 1999 {
		h.feed(visit(t0, i+1))
	}
	if s := h.p.Shares("blog", h.now); s.HasVisitor {
		t.Fatal("1999 visitors: the share must not be exported")
	}
	h.feed(visit(t0, 5000))
	if s := h.p.Shares("blog", h.now); !s.HasVisitor || s.Visitor != 0 || s.HasAbandon {
		t.Fatalf("2000 visitors: %+v", s)
	}
}

func TestSharesDayOverflowAndWindow(t *testing.T) {
	h := acceptHarness(t, 1, 2)
	day := t0 / msPerDay * msPerDay
	h.now = day + 8*msPerDay + 3600_000
	// Day 8: three visitors overflow the 2-key set; the day is left out.
	h.feed(visit(day+8*msPerDay, 1), visit(day+8*msPerDay, 2), visit(day+8*msPerDay, 3))
	if s := h.p.Shares("blog", h.now); s.HasVisitor {
		t.Fatalf("overflowed day: %+v", s)
	}
	// Day 7 is within the 7-day window, day 1 is not.
	h.feed(visit(day+7*msPerDay, 4), interactiveC(day+7*msPerDay, 4, true), visit(day+1*msPerDay, 5))
	s := h.p.Shares("blog", h.now)
	if !s.HasVisitor || s.HTMLVisitors != 1 || s.Visitor != 1 {
		t.Fatalf("window: %+v", s)
	}
	// The same visitor on two days counts once.
	h.feed(visit(day+6*msPerDay, 4))
	if s := h.p.Shares("blog", h.now); s.HTMLVisitors != 1 {
		t.Fatalf("dedup across days: %+v", s)
	}
	// Seven days later everything has left the window.
	if s := h.p.Shares("blog", h.now+7*msPerDay); s.HasVisitor {
		t.Fatalf("expired: %+v", s)
	}
}
