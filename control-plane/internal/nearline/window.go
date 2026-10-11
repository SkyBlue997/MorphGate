package nearline

// In-memory sliding windows of the detectors (docs/impl/phase2-spec.md
// §13.3): 1-minute buckets, per site, at most max_keys keys per window. A
// full window drops new keys and never evicts live ones, so a flood of new
// keys cannot push out the counts that are building up. Keys whose newest
// minute has left the window are swept as the site's clock advances.

const msPerMinute = 60_000

// minuteOf returns the Unix minute of a Unix-ms timestamp.
func minuteOf(ms int64) int64 { return ms / msPerMinute }

// bucket is one minute of a ring.
type bucket struct {
	minute int64
	n      uint32
}

// ring holds per-minute counts for the last len(b) minutes.
type ring struct{ b []bucket }

func newRing(minutes int) ring { return ring{b: make([]bucket, minutes)} }

// add counts one event at minute. It returns false when minute is older
// than the ring's span relative to the newest minute already in that slot.
func (r *ring) add(minute int64) bool {
	i := int(minute % int64(len(r.b)))
	if i < 0 {
		i += len(r.b)
	}
	s := &r.b[i]
	switch {
	case s.minute == minute:
	case s.minute < minute:
		s.minute, s.n = minute, 0
	default:
		return false
	}
	if s.n < ^uint32(0) {
		s.n++
	}
	return true
}

// at returns the count of exactly minute (0 when the slot holds another one).
func (r *ring) at(minute int64) uint32 {
	i := int(minute % int64(len(r.b)))
	if i < 0 {
		i += len(r.b)
	}
	if r.b[i].minute == minute {
		return r.b[i].n
	}
	return 0
}

// sum returns the count of the minutes (cur-len, cur].
func (r *ring) sum(cur int64) uint64 {
	var t uint64
	lo := cur - int64(len(r.b))
	for _, s := range r.b {
		if s.minute > lo && s.minute <= cur {
			t += uint64(s.n)
		}
	}
	return t
}

// recentSet keeps, for up to limit distinct members, the newest minute each
// was seen. When it is full, a new member replaces the member seen longest
// ago. The set therefore always holds the limit most recently seen members,
// which answers "are there at least limit distinct members in the window"
// exactly while its memory stays bounded by the threshold.
type recentSet[K comparable] struct {
	m     map[K]int64
	limit int
}

func newRecentSet[K comparable](limit int) recentSet[K] {
	return recentSet[K]{limit: max(limit, 1)}
}

func (s *recentSet[K]) add(k K, minute int64) {
	if s.m == nil {
		s.m = make(map[K]int64, min(s.limit, 8))
	}
	if old, ok := s.m[k]; ok {
		if minute > old {
			s.m[k] = minute
		}
		return
	}
	if len(s.m) >= s.limit {
		var oldestK K
		oldest := int64(1<<63 - 1)
		for mk, mm := range s.m {
			if mm < oldest {
				oldest, oldestK = mm, mk
			}
		}
		if minute <= oldest {
			return
		}
		delete(s.m, oldestK)
	}
	s.m[k] = minute
}

// count returns the number of members seen in the minutes (cur-span, cur].
func (s *recentSet[K]) count(cur int64, span int) int {
	n := 0
	lo := cur - int64(span)
	for _, mm := range s.m {
		if mm > lo && mm <= cur {
			n++
		}
	}
	return n
}

// window is one detector window of one site: key -> state, bounded.
type window[K comparable, S any] struct {
	name    string // detector label of mg_nl_window_dropped_total
	span    int    // minutes
	maxKeys int
	keys    map[K]*S
	newest  func(*S) int64 // newest minute of a state
	dropped func(detector string)
}

// get returns the state of k, creating it with mk when there is room. It
// returns nil (and counts a drop) when the window is full.
func (w *window[K, S]) get(k K, mk func() *S) *S {
	if s, ok := w.keys[k]; ok {
		return s
	}
	if len(w.keys) >= w.maxKeys {
		if w.dropped != nil {
			w.dropped(w.name)
		}
		return nil
	}
	s := mk()
	w.keys[k] = s
	return s
}

// lookup returns the state of k without creating it.
func (w *window[K, S]) lookup(k K) *S { return w.keys[k] }

// sweep removes the keys whose newest minute is outside (cur-span, cur].
func (w *window[K, S]) sweep(cur int64) {
	lo := cur - int64(w.span)
	for k, s := range w.keys {
		if w.newest(s) <= lo {
			delete(w.keys, k)
		}
	}
}
