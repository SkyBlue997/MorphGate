//! Valkey health and the circuit breaker (spec §9.7): after
//! `failure_threshold` consecutive failed round trips the connection is
//! dropped and Valkey is not used for 1 s; each further open period doubles up
//! to 30 s, and recovery is detected with a `PING` probe on a fresh
//! connection.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// Shared between the proxies' handles and the `mg-state` service.
pub(crate) struct Health {
    up: AtomicBool,
    /// Incremented for every new connection; results from an older
    /// connection do not move the breaker.
    generation: AtomicU64,
    consecutive_failures: AtomicU32,
    threshold: u32,
    trips: AtomicU64,
    /// Duration of the current / last open period (for status).
    open_ms: AtomicU64,
    pub tripped: Notify,
}

impl Health {
    pub fn new(threshold: u32) -> Self {
        Self {
            up: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            threshold: threshold.max(1),
            trips: AtomicU64::new(0),
            open_ms: AtomicU64::new(0),
            tripped: Notify::new(),
        }
    }

    /// Valkey may be used (connected, scripts loaded, circuit closed).
    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }

    /// Starts a new connection generation (before publishing the connection).
    pub fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn set_up(&self, generation: u64) {
        if self.generation.load(Ordering::Acquire) == generation {
            self.consecutive_failures.store(0, Ordering::Release);
            self.up.store(true, Ordering::Release);
        }
    }

    pub fn set_down(&self) {
        self.up.store(false, Ordering::Release);
    }

    pub fn success(&self, generation: u64) {
        if self.generation.load(Ordering::Acquire) == generation {
            self.consecutive_failures.store(0, Ordering::Release);
        }
    }

    /// Records a failed round trip; trips the breaker at the threshold.
    pub fn failure(&self, generation: u64) {
        if self.generation.load(Ordering::Acquire) != generation || !self.is_up() {
            return;
        }
        let n = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= self.threshold && self.up.swap(false, Ordering::AcqRel) {
            self.trips.fetch_add(1, Ordering::AcqRel);
            self.tripped.notify_one();
        }
    }

    pub fn set_open_ms(&self, d: Duration) {
        self.open_ms.store(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Acquire)
    }

    pub fn trips(&self) -> u64 {
        self.trips.load(Ordering::Acquire)
    }

    pub fn open_ms(&self) -> u64 {
        self.open_ms.load(Ordering::Acquire)
    }
}

/// Open-period schedule: base, doubling to max. It restarts from the base
/// once the circuit has stayed closed for at least `max`.
#[derive(Debug)]
pub(crate) struct Backoff {
    base: Duration,
    max: Duration,
    next: Duration,
    closed_at: Option<Instant>,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        let max = max.max(base);
        Self {
            base,
            max,
            next: base,
            closed_at: None,
        }
    }

    /// The circuit tripped at `now`: how long to stay open before probing.
    pub fn on_trip(&mut self, now: Instant) -> Duration {
        if let Some(closed) = self.closed_at.take()
            && now.saturating_duration_since(closed) >= self.max
        {
            self.next = self.base;
        }
        self.take()
    }

    /// A probe (or the initial connection) failed: how long until the next.
    pub fn on_probe_failed(&mut self) -> Duration {
        self.take()
    }

    /// The circuit closed (probe or initial connection succeeded).
    pub fn on_close(&mut self, now: Instant) {
        self.closed_at = Some(now);
    }

    fn take(&mut self) -> Duration {
        let d = self.next;
        self.next = (self.next * 2).min(self.max);
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_trips_after_threshold_consecutive_failures() {
        let h = Health::new(5);
        let g = h.next_generation();
        h.set_up(g);
        for _ in 0..4 {
            h.failure(g);
        }
        assert!(h.is_up());
        h.success(g);
        for _ in 0..4 {
            h.failure(g);
        }
        assert!(h.is_up(), "a success resets the count");
        h.failure(g);
        assert!(!h.is_up());
        assert_eq!(h.trips(), 1);
        // Further failures and stale generations do not count again.
        h.failure(g);
        assert_eq!(h.trips(), 1);
        let g2 = h.next_generation();
        h.set_up(g2);
        for _ in 0..10 {
            h.failure(g);
        }
        assert!(h.is_up(), "failures of an old connection are ignored");
    }

    #[test]
    fn open_period_doubles_to_the_cap_and_resets_after_a_healthy_period() {
        let s = Duration::from_secs;
        let mut b = Backoff::new(s(1), s(30));
        let t0 = Instant::now();
        let got: Vec<u64> = (0..7).map(|_| b.on_probe_failed().as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 30, 30]);
        let mut b = Backoff::new(s(1), s(30));
        assert_eq!(b.on_trip(t0), s(1));
        b.on_close(t0);
        assert_eq!(b.on_trip(t0 + s(5)), s(2), "tripped again soon: doubled");
        assert_eq!(b.on_probe_failed(), s(4));
        b.on_close(t0 + s(10));
        assert_eq!(b.on_trip(t0 + s(40)), s(1), "closed for >= 30 s: reset");
    }
}
