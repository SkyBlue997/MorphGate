//! Verdict cache (spec §9.7): results of `MGET mg:v:*` are kept for 2 s,
//! including "no verdict", for at most 50,000 keys. A full cache stops
//! caching new keys (after dropping expired ones) instead of evicting.
//!
//! Dropping expired entries on demand scans the whole cache, so a full cache
//! is scanned at most once per [`SWEEP_MIN_INTERVAL`]: otherwise a client
//! with many addresses (every new IPv6 /64 is a new key) could keep the cache
//! full of live entries and make every request scan all of them under the
//! shard locks.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use super::local::lock;

const SHARDS: usize = 16;
/// On-demand sweeps of a full cache run at most this often (a quarter of the
/// 2 s lifetime: a full cache frees slots at most this much later).
const SWEEP_MIN_INTERVAL: Duration = Duration::from_millis(500);

type Entry = (Option<String>, Instant);

pub(crate) struct VerdictCache {
    shards: Vec<Mutex<HashMap<String, Entry>>>,
    hasher: RandomState,
    len: AtomicUsize,
    capacity: usize,
    ttl: Duration,
    /// Start of the last on-demand sweep.
    last_sweep: Mutex<Option<Instant>>,
    /// Full-cache sweeps started by `put` (for tests and diagnostics).
    on_demand_sweeps: AtomicU64,
}

impl VerdictCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            len: AtomicUsize::new(0),
            capacity,
            ttl,
            last_sweep: Mutex::new(None),
            on_demand_sweeps: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn on_demand_sweeps(&self) -> u64 {
        self.on_demand_sweeps.load(Ordering::Relaxed)
    }

    fn shard(&self, key: &str) -> &Mutex<HashMap<String, Entry>> {
        &self.shards[(self.hasher.hash_one(key) as usize) % SHARDS]
    }

    fn fresh(&self, stored: Instant, now: Instant) -> bool {
        now.saturating_duration_since(stored) < self.ttl
    }

    /// `None`: not cached. `Some(None)`: cached "no verdict".
    pub fn get(&self, key: &str, now: Instant) -> Option<Option<String>> {
        let mut shard = lock(self.shard(key));
        match shard.get(key) {
            Some((v, t)) if self.fresh(*t, now) => Some(v.clone()),
            Some(_) => {
                shard.remove(key);
                self.len.fetch_sub(1, Ordering::AcqRel);
                None
            }
            None => None,
        }
    }

    pub fn put(&self, key: String, value: Option<String>, now: Instant) {
        for attempt in 0..2 {
            {
                let mut shard = lock(self.shard(&key));
                if let Some(e) = shard.get_mut(&key) {
                    *e = (value, now);
                    return;
                }
                let reserved = self
                    .len
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                        (n < self.capacity).then_some(n + 1)
                    })
                    .is_ok();
                if reserved {
                    shard.insert(key, (value, now));
                    return;
                }
            }
            if attempt == 0 && self.sweep_if_due(now) == 0 {
                return;
            }
        }
    }

    /// Sweeps a full cache unless a sweep started less than
    /// [`SWEEP_MIN_INTERVAL`] ago or is running on another thread (the new
    /// key is then simply not cached).
    fn sweep_if_due(&self, now: Instant) -> usize {
        let mut last = match self.last_sweep.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return 0,
        };
        if last.is_some_and(|t| now.saturating_duration_since(t) < SWEEP_MIN_INTERVAL) {
            return 0;
        }
        *last = Some(now);
        drop(last);
        self.on_demand_sweeps.fetch_add(1, Ordering::Relaxed);
        self.sweep(now)
    }

    /// Drops expired entries; returns how many.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut s = lock(shard);
            let before = s.len();
            s.retain(|_, (_, t)| now.saturating_duration_since(*t) < self.ttl);
            let n = before - s.len();
            self.len.fetch_sub(n, Ordering::AcqRel);
            removed += n;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_values_and_absence_for_the_ttl() {
        let c = VerdictCache::new(2, Duration::from_secs(2));
        let t0 = Instant::now();
        assert_eq!(c.get("a", t0), None);
        c.put("a".into(), Some("{}".into()), t0);
        c.put("b".into(), None, t0);
        assert_eq!(c.get("a", t0), Some(Some("{}".into())));
        assert_eq!(c.get("b", t0 + Duration::from_millis(1999)), Some(None));
        // Full: "c" is not cached, nothing live is evicted.
        c.put("c".into(), None, t0 + Duration::from_millis(10));
        assert_eq!(c.get("c", t0 + Duration::from_millis(10)), None);
        assert_eq!(
            c.get("a", t0 + Duration::from_millis(10)),
            Some(Some("{}".into()))
        );
        // After the TTL, entries are gone and slots are reused.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(c.get("a", t1), None);
        c.put("c".into(), None, t1);
        assert_eq!(c.get("c", t1), Some(None));
    }

    /// A full cache of live entries is not rescanned for every new key
    /// (each scan visits all 50,000 entries under the shard locks, which an
    /// attacker with many addresses could trigger on every request); on-demand
    /// sweeps run at most once per `SWEEP_MIN_INTERVAL`.
    #[test]
    fn full_cache_is_not_rescanned_for_every_new_key() {
        let c = VerdictCache::new(2, Duration::from_secs(2));
        let t0 = Instant::now();
        c.put("a".into(), None, t0);
        c.put("b".into(), None, t0);
        let ms = Duration::from_millis;
        for i in 0..100 {
            c.put(format!("new{i}"), None, t0 + ms(10 + i));
        }
        assert_eq!(c.on_demand_sweeps(), 1, "one scan, then rate limited");
        assert_eq!(c.get("a", t0 + ms(200)), Some(None), "live entries stay");
        // After the interval a new key may trigger another scan.
        c.put("later".into(), None, t0 + ms(700));
        assert_eq!(c.on_demand_sweeps(), 2);
        // Once entries expired, a due sweep frees their slots.
        let t1 = t0 + Duration::from_secs(2);
        c.put("fresh".into(), Some("{}".into()), t1);
        assert_eq!(c.get("fresh", t1), Some(Some("{}".into())));
    }
}
