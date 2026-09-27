package guard

import (
	"context"
	"sync"
	"time"
)

// limiter is a token bucket with burst 1: requests are spaced at least
// 1/rate apart, process-wide for one Guard. It is deliberately tiny so its
// behaviour is obvious; clock and sleep are injectable for tests.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time // earliest time the next request may start
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
}

func newLimiter(rps float64) *limiter {
	return &limiter{
		interval: time.Duration(float64(time.Second) / rps),
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

// Wait blocks until the caller may send one request, or ctx is done.
func (l *limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.now()
	start := l.next
	if start.Before(now) {
		start = now
	}
	l.next = start.Add(l.interval)
	l.mu.Unlock()

	if d := start.Sub(now); d > 0 {
		if err := l.sleep(ctx, d); err != nil {
			// Give the slot back only if nobody reserved after us.
			l.mu.Lock()
			if l.next.Equal(start.Add(l.interval)) {
				l.next = start
			}
			l.mu.Unlock()
			return err
		}
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
