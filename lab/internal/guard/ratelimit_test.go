package guard

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeClock advances only when the limiter sleeps.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) install(l *limiter) {
	l.now = func() time.Time { return c.now }
	l.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.sleeps = append(c.sleeps, d)
		c.now = c.now.Add(d)
		return nil
	}
}

func TestLimiterSpacing(t *testing.T) {
	l := newLimiter(5)
	clk := &fakeClock{now: time.Unix(1000, 0)}
	clk.install(l)
	for i := 0; i < 4; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []time.Duration{200 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond}
	if len(clk.sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
	}
	for i := range want {
		if clk.sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
		}
	}

	// After an idle period there is no burst beyond one request.
	clk.now = clk.now.Add(10 * time.Second)
	clk.sleeps = nil
	_ = l.Wait(context.Background())
	_ = l.Wait(context.Background())
	if len(clk.sleeps) != 1 || clk.sleeps[0] != 200*time.Millisecond {
		t.Errorf("after idle: sleeps = %v, want one 200ms wait", clk.sleeps)
	}
}

func TestLimiterCancel(t *testing.T) {
	l := newLimiter(1)
	clk := &fakeClock{now: time.Unix(1000, 0)}
	clk.install(l)
	_ = l.Wait(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait on cancelled ctx = %v", err)
	}
	// The cancelled reservation is returned: the next caller waits one
	// interval from the first request, not two.
	_ = l.Wait(context.Background())
	if n := len(clk.sleeps); n != 1 || clk.sleeps[0] != time.Second {
		t.Errorf("sleeps = %v, want [1s]", clk.sleeps)
	}
}

func TestRealSleepHonoursContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("sleepCtx = %v", err)
	}
}
