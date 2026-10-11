package nearline

// Acceptance shares (docs/impl/phase2-spec.md §13.3 "验收比例", §20): per
// site, over the last window_days UTC days, with one deduplicated set of
// ipk per day (at most max_keys_per_day keys; a day that overflows is left
// out of both shares, numerator and denominator alike).
//
//   - visitor share: distinct ipk that got an interactive C (decision entry
//     action = challenge, ctype = interactive), over distinct ipk with a
//     ct = h request. Monitor-mode (dry = 1) challenges count: the owner reads
//     this share from shadow data before turning challenges on.
//   - abandon share: distinct ipk that got an interactive C and did not pass
//     within 10 minutes (no feedback entry with outcome = pass and the same
//     ipk), over distinct ipk that got an interactive C. Only challenges that
//     were actually served (dry = 0) count here, since a monitor-mode
//     "challenge" cannot be passed. An ipk counts as passed when a pass came
//     within 10 minutes after its latest earlier challenge; one whose latest
//     challenge is younger than 10 minutes and not yet passed is in the
//     denominator but not (yet) in the numerator.
//
// A share is not exported while its denominator is below min_denominator.

const (
	msPerDay       = 86_400_000
	passWithinMs   = 10 * msPerMinute
	flagHTML       = 1 << 0 // a ct = h request
	flagChallenged = 1 << 1 // an interactive C, dry or not
	flagServed     = 1 << 2 // an interactive C that was served (dry = 0)
	flagPassed     = 1 << 3 // passed within 10 minutes of a served C
)

type visitor struct {
	flags uint8
	// pendingMs is the time of the latest served C while the visitor has not
	// passed (0: none).
	pendingMs int64
}

type visitorDay struct {
	day      int64
	m        map[Key16]visitor
	overflow bool
}

type acceptance struct {
	cfg  Acceptance
	days []*visitorDay // ordered by day, at most cfg.WindowDays
}

// Shares are the two acceptance shares of a site; a share is exported only
// when its Has flag is set.
type Shares struct {
	Visitor, Abandon       float64
	HasVisitor, HasAbandon bool
	// Denominators, for tests and logs.
	HTMLVisitors, ServedVisitors int
}

func newAcceptance(cfg Acceptance) *acceptance { return &acceptance{cfg: cfg} }

// dayFor returns the set of day d, creating it (and dropping days that left
// the window) when d is new. nil when d is outside the window.
func (a *acceptance) dayFor(d, today int64, create bool) *visitorDay {
	if d > today || d <= today-int64(a.cfg.WindowDays) {
		return nil
	}
	for _, vd := range a.days {
		if vd.day == d {
			return vd
		}
	}
	if !create {
		return nil
	}
	vd := &visitorDay{day: d, m: map[Key16]visitor{}}
	a.days = append(a.days, vd)
	kept := a.days[:0]
	for _, x := range a.days {
		if x.day > today-int64(a.cfg.WindowDays) {
			kept = append(kept, x)
		}
	}
	a.days = kept
	return vd
}

func (a *acceptance) observe(e *Entry, ts, nowMs int64) {
	if !e.HasIPK || e.Version < 2 {
		return
	}
	today := nowMs / msPerDay
	d := ts / msPerDay
	switch e.Kind {
	case KindDecision:
		var add uint8
		if e.CT == 'h' {
			add |= flagHTML
		}
		interactive := e.Action == "challenge" && e.CType == "interactive"
		if interactive {
			add |= flagChallenged
			if !e.Dry {
				add |= flagServed
			}
		}
		if add == 0 {
			return
		}
		vd := a.dayFor(d, today, true)
		if vd == nil || vd.overflow {
			return
		}
		v, ok := vd.m[e.IPK]
		if !ok && len(vd.m) >= a.cfg.MaxKeysPerDay {
			vd.overflow, vd.m = true, nil
			return
		}
		v.flags |= add
		if add&flagServed != 0 && v.flags&flagPassed == 0 {
			v.pendingMs = max(v.pendingMs, ts)
		}
		vd.m[e.IPK] = v
	case KindFeedback:
		if e.Outcome != "pass" {
			return
		}
		// The C may have been served the day before (a pass just after
		// midnight UTC).
		for _, dd := range []int64{d, d - 1} {
			vd := a.dayFor(dd, today, false)
			if vd == nil || vd.overflow {
				continue
			}
			v, ok := vd.m[e.IPK]
			if !ok || v.flags&flagServed == 0 || v.pendingMs == 0 {
				continue
			}
			if dt := ts - v.pendingMs; dt >= 0 && dt <= passWithinMs {
				v.flags |= flagPassed
				v.pendingMs = 0
				vd.m[e.IPK] = v
			}
		}
	}
}

func (a *acceptance) shares(nowMs int64) Shares {
	today := nowMs / msPerDay
	type agg struct {
		flags     uint8
		undecided bool
	}
	union := map[Key16]agg{}
	for _, vd := range a.days {
		if vd.overflow || vd.day <= today-int64(a.cfg.WindowDays) || vd.day > today {
			continue
		}
		for k, v := range vd.m {
			g := union[k]
			g.flags |= v.flags
			if v.flags&flagServed != 0 && v.flags&flagPassed == 0 && v.pendingMs != 0 && nowMs-v.pendingMs < passWithinMs {
				g.undecided = true
			}
			union[k] = g
		}
	}
	var html, challenged, served, abandoned int
	for _, g := range union {
		if g.flags&flagHTML != 0 {
			html++
		}
		if g.flags&flagChallenged != 0 {
			challenged++
		}
		if g.flags&flagServed != 0 {
			served++
			if g.flags&flagPassed == 0 && !g.undecided {
				abandoned++
			}
		}
	}
	s := Shares{HTMLVisitors: html, ServedVisitors: served}
	if html >= a.cfg.MinDenominator {
		s.Visitor, s.HasVisitor = float64(challenged)/float64(html), true
	}
	if served >= a.cfg.MinDenominator {
		s.Abandon, s.HasAbandon = float64(abandoned)/float64(served), true
	}
	return s
}
