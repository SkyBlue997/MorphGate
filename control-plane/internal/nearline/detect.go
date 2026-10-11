package nearline

import (
	"time"
)

// The four v1 detectors (docs/impl/phase2-spec.md §13.3). Detection is best
// effort: windows live in memory and start from zero when the worker
// restarts; at-least-once delivery may count an entry twice.
//
// Readings of the spec that the code fixes:
//   - Windows use the entry's own ts (clamped to the worker's clock), not the
//     arrival time, so a backlog read after a pause is not compressed into a
//     burst. Each key's window ends at the newest minute seen for that key.
//   - scanner "status 404 / 403 / 405 share": entries with one of those
//     statuses divided by all of the entity's counted entries (tk = 0 and
//     xs = 0) in the window.
//   - challenge_abuse "pass ratio": pass / (pass + fail) of the prefix's
//     feedback entries; other outcomes are not counted.
//   - high_rate shared egress: distinct non-empty sess or uf values among all
//     decision entries of that ipk in the window (sess is only set when the
//     request carried a valid clearance, which the counted entries never do).
//   - IPv6 prefix windows multiply the count thresholds (bait_distinct,
//     distinct_404, per_minute, shared_egress) by ipv6_prefix_factor; ratios
//     and the number of minutes stay the same.
//   - v1 decision entries carry none of the v2 fields the decision detectors
//     read (ph, ct, tk, xs, pf), so only feedback entries of v1 are used.
//   - A detector reports a key again only after half its TTL, so a sustained
//     condition refreshes the verdict before it expires without writing it on
//     every entry.

// Window spans (minutes) of spec §13.3. high_rate spans its "minutes".
const (
	scannerSpan        = 10
	sharedTokenSpan    = 10
	challengeAbuseSpan = 10
)

// Verdict is one detector result, before it is written (enforce) or only
// logged (shadow).
type Verdict struct {
	Site     string
	Detector string
	Mode     string
	Type     string // "ip", "prefix" or "session"
	Key      string // ipk / pfk (hex) or the session sub
	Risk     int
	TTL      time.Duration
	Labels   []string
	Reasons  []string
	Evidence map[string]any

	fired *int64 // the state's re-report guard; reset when the write failed
}

// VerdictKey returns mg:v:{site}:{type}:{key}.
func (v *Verdict) VerdictKey() string { return "mg:v:" + v.Site + ":" + v.Type + ":" + v.Key }

// Source returns "nearline/<detector>".
func (v *Verdict) Source() string { return "nearline/" + v.Detector }

type scannerState struct {
	newest int64
	total  ring
	errs   ring
	bait   recentSet[uint64]
	errPH  recentSet[uint64]
	fired  int64
}

type tokenState struct {
	newest   int64
	count    ring
	prefixes recentSet[Key16]
	fired    int64
}

type abuseState struct {
	newest int64
	fails  ring
	passes ring
	fired  int64
}

type rateState struct {
	newest  int64
	counted ring
	sess    recentSet[string]
	uf      recentSet[string]
	fired   int64
}

// siteWindows are the windows of one site.
type siteWindows struct {
	clock        int64 // newest minute seen on this site
	scannerIP    window[Key16, scannerState]
	scannerPfx   window[Key16, scannerState]
	sharedToken  window[string, tokenState]
	abuse        window[Key16, abuseState]
	highRateIP   window[Key16, rateState]
	highRatePfx  window[Key16, rateState]
	acceptance   *acceptance
	lastSweepMin int64
}

// Processor runs the detectors over parsed entries. It is not safe for
// concurrent use; the worker calls it from its consumer loop only.
type Processor struct {
	det     DetectorsConfig
	factor  int
	sites   map[string]*siteWindows
	dropped func(detector string)
}

// NewProcessor returns a processor for cfg's sites. dropped (may be nil) is
// called once per key a full window refuses.
func NewProcessor(cfg *Config, dropped func(detector string)) *Processor {
	p := &Processor{det: cfg.Detectors, factor: cfg.Windows.IPv6PrefixFactor, sites: map[string]*siteWindows{}, dropped: dropped}
	mk := cfg.Windows.MaxKeys
	hr := cfg.Detectors.HighRate.Minutes
	for _, s := range cfg.Sites {
		p.sites[s] = &siteWindows{
			scannerIP:   window[Key16, scannerState]{name: DetScanner, span: scannerSpan, maxKeys: mk, keys: map[Key16]*scannerState{}, newest: func(s *scannerState) int64 { return s.newest }, dropped: dropped},
			scannerPfx:  window[Key16, scannerState]{name: DetScanner, span: scannerSpan, maxKeys: mk, keys: map[Key16]*scannerState{}, newest: func(s *scannerState) int64 { return s.newest }, dropped: dropped},
			sharedToken: window[string, tokenState]{name: DetSharedToken, span: sharedTokenSpan, maxKeys: mk, keys: map[string]*tokenState{}, newest: func(s *tokenState) int64 { return s.newest }, dropped: dropped},
			abuse:       window[Key16, abuseState]{name: DetChallengeAbuse, span: challengeAbuseSpan, maxKeys: mk, keys: map[Key16]*abuseState{}, newest: func(s *abuseState) int64 { return s.newest }, dropped: dropped},
			highRateIP:  window[Key16, rateState]{name: DetHighRate, span: hr, maxKeys: mk, keys: map[Key16]*rateState{}, newest: func(s *rateState) int64 { return s.newest }, dropped: dropped},
			highRatePfx: window[Key16, rateState]{name: DetHighRate, span: hr, maxKeys: mk, keys: map[Key16]*rateState{}, newest: func(s *rateState) int64 { return s.newest }, dropped: dropped},
			acceptance:  newAcceptance(cfg.Acceptance),
		}
	}
	return p
}

// HasSite reports whether site is configured.
func (p *Processor) HasSite(site string) bool { return p.sites[site] != nil }

// Process feeds one entry of a configured site into the windows and returns
// the verdicts it triggers. nowMs is the worker's clock; entry times later
// than it are clamped to it.
func (p *Processor) Process(e *Entry, nowMs int64) []Verdict {
	sw := p.sites[e.Site]
	if sw == nil {
		return nil
	}
	ts := min(e.TS, nowMs)
	minute := minuteOf(ts)
	if minute > sw.clock {
		sw.clock = minute
	}
	if sw.clock > sw.lastSweepMin {
		sw.lastSweepMin = sw.clock
		sw.scannerIP.sweep(sw.clock)
		sw.scannerPfx.sweep(sw.clock)
		sw.sharedToken.sweep(sw.clock)
		sw.abuse.sweep(sw.clock)
		sw.highRateIP.sweep(sw.clock)
		sw.highRatePfx.sweep(sw.clock)
	}
	sw.acceptance.observe(e, ts, nowMs)

	var out []Verdict
	emit := func(v Verdict, fired *int64) {
		if *fired > nowMs {
			return
		}
		*fired = nowMs + int64(v.TTL/time.Millisecond)/2
		v.Site, v.fired = e.Site, fired
		v.Mode = p.det.Mode(v.Detector)
		out = append(out, v)
	}
	switch e.Kind {
	case KindDecision:
		if e.Version < 2 {
			return nil
		}
		if e.HasIPK {
			p.scanner(&sw.scannerIP, e.IPK, "ip", 1, e, minute, emit)
			p.highRate(&sw.highRateIP, e.IPK, "ip", 1, e, minute, emit)
		}
		if e.Fam == 6 && e.HasPFK {
			p.scanner(&sw.scannerPfx, e.PFK, "prefix", p.factor, e, minute, emit)
			p.highRate(&sw.highRatePfx, e.PFK, "prefix", p.factor, e, minute, emit)
		}
		if e.PF == 'j' && e.Sess != "" {
			p.sharedToken(&sw.sharedToken, e, minute, emit)
		}
	case KindFeedback:
		if e.HasPFK && (e.Outcome == "pass" || e.Outcome == "fail") {
			p.challengeAbuse(&sw.abuse, e, minute, emit)
		}
	}
	return out
}

type emitFn func(Verdict, *int64)

func (p *Processor) scanner(w *window[Key16, scannerState], k Key16, typ string, factor int, e *Entry, minute int64, emit emitFn) {
	if e.TK || e.XS {
		return
	}
	c := &p.det.Scanner
	baitN, errN := c.BaitDistinct*factor, c.Distinct404*factor
	s := w.get(k, func() *scannerState {
		return &scannerState{total: newRing(scannerSpan), errs: newRing(scannerSpan),
			bait: newRecentSet[uint64](2 * baitN), errPH: newRecentSet[uint64](2 * errN)}
	})
	if s == nil || !s.total.add(minute) {
		return
	}
	s.newest = max(s.newest, minute)
	if e.Status == 404 || e.Status == 403 || e.Status == 405 {
		s.errs.add(minute)
		if e.HasPH {
			s.errPH.add(e.PH, minute)
		}
	}
	if e.BT && e.HasPH {
		s.bait.add(e.PH, minute)
	}
	cur := s.newest
	bait := s.bait.count(cur, scannerSpan)
	distinct := s.errPH.count(cur, scannerSpan)
	total, errs := s.total.sum(cur), s.errs.sum(cur)
	share := 0.0
	if total > 0 {
		share = float64(errs) / float64(total)
	}
	var reasons []string
	if bait >= baitN {
		reasons = append(reasons, "nl.scanner.bait")
	}
	if distinct >= errN && share >= c.Share404 {
		reasons = append(reasons, "nl.scanner.status")
	}
	if len(reasons) == 0 {
		return
	}
	emit(Verdict{
		Detector: DetScanner, Type: typ, Key: k.String(), Risk: c.Risk, TTL: time.Duration(c.TTL),
		Labels: []string{"nl_scanner"}, Reasons: reasons,
		Evidence: map[string]any{"bait": bait, "distinct_404": distinct, "share_404": round3(share), "entries": total},
	}, &s.fired)
}

func (p *Processor) highRate(w *window[Key16, rateState], k Key16, typ string, factor int, e *Entry, minute int64, emit emitFn) {
	c := &p.det.HighRate
	counted := (e.CT == 'h' || e.CT == 'j' || e.CT == 'o') && !e.TK && !e.XS
	var s *rateState
	if counted {
		s = w.get(k, func() *rateState {
			return &rateState{counted: newRing(c.Minutes),
				sess: newRecentSet[string](c.SharedEgress * factor), uf: newRecentSet[string](c.SharedEgress * factor)}
		})
	} else {
		s = w.lookup(k)
	}
	if s == nil {
		return
	}
	if minute+int64(c.Minutes) <= s.newest {
		return // older than the window
	}
	s.newest = max(s.newest, minute)
	if e.Sess != "" {
		s.sess.add(e.Sess, minute)
	}
	if e.UF != "" {
		s.uf.add(e.UF, minute)
	}
	if !counted || !s.counted.add(minute) {
		return
	}
	cur := s.newest
	need := uint32(min(int64(c.PerMinute)*int64(factor), int64(^uint32(0))))
	low := ^uint32(0)
	for i := 0; i < c.Minutes; i++ {
		n := s.counted.at(cur - int64(i))
		if n < need {
			return
		}
		low = min(low, n)
	}
	egress := c.SharedEgress * factor
	nSess, nUF := s.sess.count(cur, c.Minutes), s.uf.count(cur, c.Minutes)
	if nSess >= egress || nUF >= egress {
		return // shared egress (internet cafe, school, tutoring centre)
	}
	emit(Verdict{
		Detector: DetHighRate, Type: typ, Key: k.String(), Risk: c.Risk, TTL: time.Duration(c.TTL),
		Labels: []string{"nl_high_rate"}, Reasons: []string{"nl.high_rate.sustained"},
		Evidence: map[string]any{"min_per_minute": low, "minutes": c.Minutes, "distinct_sess": nSess, "distinct_uf": nUF},
	}, &s.fired)
}

func (p *Processor) sharedToken(w *window[string, tokenState], e *Entry, minute int64, emit emitFn) {
	c := &p.det.SharedToken
	s := w.get(e.Sess, func() *tokenState {
		return &tokenState{count: newRing(sharedTokenSpan), prefixes: newRecentSet[Key16](2 * c.DistinctPrefix)}
	})
	if s == nil || !s.count.add(minute) {
		return
	}
	s.newest = max(s.newest, minute)
	if e.HasPFK {
		s.prefixes.add(e.PFK, minute)
	}
	cur := s.newest
	n := s.count.sum(cur)
	pfx := s.prefixes.count(cur, sharedTokenSpan)
	if n < uint64(c.ProofMismatch) || pfx < c.DistinctPrefix {
		return
	}
	emit(Verdict{
		Detector: DetSharedToken, Type: "session", Key: e.Sess, Risk: c.Risk, TTL: time.Duration(c.TTL),
		Labels: []string{"nl_shared_token"}, Reasons: []string{"nl.shared_token.proof_mismatch"},
		Evidence: map[string]any{"proof_mismatch": n, "distinct_prefix": pfx},
	}, &s.fired)
}

func (p *Processor) challengeAbuse(w *window[Key16, abuseState], e *Entry, minute int64, emit emitFn) {
	c := &p.det.ChallengeAbuse
	s := w.get(e.PFK, func() *abuseState {
		return &abuseState{fails: newRing(challengeAbuseSpan), passes: newRing(challengeAbuseSpan)}
	})
	if s == nil {
		return
	}
	pass := e.Outcome == "pass"
	if pass {
		if !s.passes.add(minute) {
			return
		}
	} else if !s.fails.add(minute) {
		return
	}
	s.newest = max(s.newest, minute)
	if pass {
		return
	}
	cur := s.newest
	fails, passes := s.fails.sum(cur), s.passes.sum(cur)
	ratio := float64(passes) / float64(passes+fails)
	if fails < uint64(c.Fails) || ratio >= c.MaxPassRatio {
		return
	}
	emit(Verdict{
		Detector: DetChallengeAbuse, Type: "prefix", Key: e.PFK.String(), Risk: c.Risk, TTL: time.Duration(c.TTL),
		Labels: []string{"nl_challenge_abuse"}, Reasons: []string{"nl.challenge_abuse.fails"},
		Evidence: map[string]any{"fails": fails, "passes": passes},
	}, &s.fired)
}

// Rearm lets v's detector report the same key again on its next trigger
// (used when writing v failed).
func (v *Verdict) Rearm() {
	if v.fired != nil {
		*v.fired = 0
	}
}

func round3(f float64) float64 { return float64(int64(f*1000+0.5)) / 1000 }

// Shares returns the acceptance shares of site at nowMs (spec §13.3).
func (p *Processor) Shares(site string, nowMs int64) Shares {
	sw := p.sites[site]
	if sw == nil {
		return Shares{}
	}
	return sw.acceptance.shares(nowMs)
}
