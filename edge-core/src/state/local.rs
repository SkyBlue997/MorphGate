//! Process-local state (spec §9.7 "本地模式"): the bounded GCRA table with
//! per-limiter overflow buckets, and the fixed-capacity TTL replay set that
//! never evicts a live nonce (D-35).
//!
//! Both tables are sharded `Mutex<HashMap>`s with a global entry count, so the
//! configured capacity is exact. No lock is held while another shard is
//! locked, so there is no lock-order deadlock.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mg_core::gcra::{GcraOutcome, GcraParams, MAX_DVT_US, gcra_check};

use super::{LimitCheck, OVERFLOW_DIMS, metrics};

const SHARDS: usize = 16;
/// On-demand sweeps of a full GCRA table run at most this often.
const SWEEP_MIN_INTERVAL_US: u64 = 1_000_000;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding a table lock cannot leave an entry half-written
    // (every update is a single insert / assignment), so the data stays usable.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A [`LimitCheck`] with its keys computed and its parameters clamped.
#[derive(Clone)]
pub(crate) struct PreparedLimit {
    /// `mg:rl:{site}:{limiter}:{kh}`.
    pub key: String,
    /// Local-only key of the limiter's overflow bucket.
    pub overflow_key: String,
    pub params: GcraParams,
    pub cost: u32,
    pub write: bool,
}

impl PreparedLimit {
    pub fn new(check: &LimitCheck, k_pseudo: &[u8; 32]) -> Self {
        let (params, cost) = sanitize(check.params, check.cost);
        Self {
            key: check.key.redis_key(k_pseudo),
            overflow_key: format!(
                "mg:rl:{}:{}:{}",
                check.key.site, check.key.limiter, OVERFLOW_DIMS
            ),
            params,
            cost,
            write: check.write,
        }
    }
}

/// Clamps parameters so that `interval * burst <= MAX_DVT_US` and
/// `cost <= burst + 1`: nothing can overflow in Rust (debug builds panic on
/// overflow) or exceed 2^53 in Lua. Parameters from [`GcraParams::new`] and a
/// cost of 1 are unchanged; a cost above the burst can never pass before or
/// after clamping (only its `retry_after_us` shrinks).
pub(crate) fn sanitize(p: GcraParams, cost: u32) -> (GcraParams, u32) {
    let interval_us = p.interval_us.min(MAX_DVT_US);
    let max_burst = u32::try_from(MAX_DVT_US / interval_us.max(1)).unwrap_or(u32::MAX);
    let burst = p.burst.min(max_burst.max(1));
    let cost = cost.clamp(1, burst.saturating_add(1).max(1));
    (GcraParams { interval_us, burst }, cost)
}

#[derive(Default)]
struct GcraShard {
    /// key -> stored TAT (µs). An entry with TAT <= now is "no state".
    map: HashMap<String, u64>,
}

/// Bounded in-process GCRA state (local limiters and the Valkey fallback).
pub(crate) struct LocalGcra {
    shards: Vec<Mutex<GcraShard>>,
    hasher: RandomState,
    len: AtomicUsize,
    capacity: usize,
    last_sweep_us: AtomicU64,
    /// Overflow buckets, one per (site, limiter); not counted in `capacity`
    /// (bounded by the configured limiters).
    overflow: Mutex<HashMap<String, u64>>,
    /// Serializes all-or-nothing issuance checks (the local equivalent of the
    /// atomic `mg_nonce_issue`).
    issue_lock: Mutex<()>,
}

impl LocalGcra {
    pub fn new(capacity: usize) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            len: AtomicUsize::new(0),
            capacity: capacity.max(1),
            last_sweep_us: AtomicU64::new(0),
            overflow: Mutex::default(),
            issue_lock: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    fn shard(&self, key: &str) -> &Mutex<GcraShard> {
        let h = self.hasher.hash_one(key);
        &self.shards[(h as usize) % SHARDS]
    }

    fn try_reserve(&self) -> bool {
        self.len
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.capacity).then_some(n + 1)
            })
            .is_ok()
    }

    fn is_full(&self) -> bool {
        self.len.load(Ordering::Acquire) >= self.capacity
    }

    /// One GCRA step against the local table. `write` stores the new TAT when
    /// allowed. When the table is full, a key without state is counted in
    /// its limiter's overflow bucket (for checks and writes alike, so a
    /// check-only query sees what a write recorded); live entries are never
    /// evicted.
    pub fn check(&self, lim: &PreparedLimit, write: bool, now_us: u64) -> GcraOutcome {
        if let Some(out) = self.try_check(lim, write, now_us) {
            return out;
        }
        if self.sweep_if_due(now_us) > 0
            && let Some(out) = self.try_check(lim, write, now_us)
        {
            return out;
        }
        metrics::get().overflow("gcra");
        let mut of = lock(&self.overflow);
        let stored = of.get(&lim.overflow_key).copied().filter(|t| *t > now_us);
        let out = gcra_check(&lim.params, stored, now_us, lim.cost);
        if write && let Some(new_tat) = out.new_tat_us {
            of.insert(lim.overflow_key.clone(), new_tat);
        }
        out
    }

    /// `None`: the key has no state and the table is full.
    fn try_check(&self, lim: &PreparedLimit, write: bool, now_us: u64) -> Option<GcraOutcome> {
        let mut shard = lock(self.shard(&lim.key));
        if let Some(tat) = shard.map.get_mut(&lim.key) {
            if *tat > now_us {
                let out = gcra_check(&lim.params, Some(*tat), now_us, lim.cost);
                if write && let Some(new_tat) = out.new_tat_us {
                    *tat = new_tat;
                }
                return Some(out);
            }
            // Stale entry: equivalent to no state. Reuse its slot or drop it.
            let out = gcra_check(&lim.params, None, now_us, lim.cost);
            match (write, out.new_tat_us) {
                (true, Some(new_tat)) => *tat = new_tat,
                _ => {
                    shard.map.remove(&lim.key);
                    self.len.fetch_sub(1, Ordering::AcqRel);
                }
            }
            return Some(out);
        }
        let fresh = gcra_check(&lim.params, None, now_us, lim.cost);
        match (write, fresh.new_tat_us) {
            (true, Some(new_tat)) => {
                if !self.try_reserve() {
                    return None;
                }
                shard.map.insert(lim.key.clone(), new_tat);
                Some(fresh)
            }
            _ => (!self.is_full()).then_some(fresh),
        }
    }

    /// All-or-nothing check of several limiters, as `mg_nonce_issue` does:
    /// every outcome is computed from the current state, and the new TATs
    /// are stored only if all of them allow.
    pub fn check_all_or_nothing(&self, limits: &[PreparedLimit], now_us: u64) -> Vec<GcraOutcome> {
        let _serial = lock(&self.issue_lock);
        let checked: Vec<GcraOutcome> = limits
            .iter()
            .map(|l| self.check(l, false, now_us))
            .collect();
        if checked.iter().all(|o| o.allowed) {
            // Same state (issuance keys are only written under this lock), so
            // the same outcomes; this pass stores them.
            limits.iter().map(|l| self.check(l, true, now_us)).collect()
        } else {
            checked
        }
    }

    fn sweep_if_due(&self, now_us: u64) -> usize {
        let last = self.last_sweep_us.load(Ordering::Acquire);
        // A clock that went backwards (now < last) does not block sweeps.
        let recent = now_us >= last && now_us - last < SWEEP_MIN_INTERVAL_US;
        if recent
            || self
                .last_sweep_us
                .compare_exchange(last, now_us, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return 0;
        }
        self.sweep(now_us)
    }

    /// Removes every entry whose TAT is not after `now_us` ("no state").
    /// Returns the number of removed table entries.
    pub fn sweep(&self, now_us: u64) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut s = lock(shard);
            let before = s.map.len();
            s.map.retain(|_, tat| *tat > now_us);
            let n = before - s.map.len();
            self.len.fetch_sub(n, Ordering::AcqRel);
            removed += n;
        }
        lock(&self.overflow).retain(|_, tat| *tat > now_us);
        removed
    }
}

/// Result of [`NonceSet::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceInsert {
    Inserted,
    /// A live entry exists: the nonce was used before.
    Exists,
    /// The set is full of live entries; the nonce was not recorded.
    Full,
}

#[derive(Default)]
struct NonceShard {
    map: HashMap<Arc<str>, i64>,
    /// Min-heap of (expiry, key); an item is stale when the map holds a
    /// different expiry for the key (or none).
    heap: BinaryHeap<Reverse<(i64, Arc<str>)>>,
}

impl NonceShard {
    fn expire(&mut self, now_ms: i64) -> usize {
        let mut removed = 0;
        while self
            .heap
            .peek()
            .is_some_and(|Reverse((exp, _))| *exp <= now_ms)
        {
            if let Some(Reverse((exp, key))) = self.heap.pop()
                && self.map.get(&key) == Some(&exp)
            {
                self.map.remove(&key);
                removed += 1;
            }
        }
        removed
    }
}

/// Fixed-capacity TTL set of used nonces. Entries expire at their own
/// expiry; a live entry is never evicted; when full, inserts fail.
pub(crate) struct NonceSet {
    shards: Vec<Mutex<NonceShard>>,
    hasher: RandomState,
    len: AtomicUsize,
    capacity: usize,
    /// Latest `now_ms` at which an insert failed (i64::MIN: never).
    last_overflow_ms: AtomicI64,
}

impl NonceSet {
    pub fn new(capacity: usize) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            len: AtomicUsize::new(0),
            capacity: capacity.max(1),
            last_overflow_ms: AtomicI64::new(i64::MIN),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    fn shard(&self, key: &str) -> &Mutex<NonceShard> {
        let h = self.hasher.hash_one(key);
        &self.shards[(h as usize) % SHARDS]
    }

    fn try_reserve(&self) -> bool {
        self.len
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.capacity).then_some(n + 1)
            })
            .is_ok()
    }

    /// Checks and records `key` until `expiry_ms` (raised to `now_ms + 1`).
    pub fn insert(&self, key: &str, expiry_ms: i64, now_ms: i64) -> NonceInsert {
        let expiry_ms = expiry_ms.max(now_ms.saturating_add(1));
        for attempt in 0..2 {
            {
                let mut shard = lock(self.shard(key));
                let removed = shard.expire(now_ms);
                self.len.fetch_sub(removed, Ordering::AcqRel);
                if let Some(exp) = shard.map.get_mut(key) {
                    if *exp > now_ms {
                        return NonceInsert::Exists;
                    }
                    // Unreachable after `expire`, but harmless: reuse the slot.
                    *exp = expiry_ms;
                    let k: Arc<str> = Arc::from(key);
                    shard.heap.push(Reverse((expiry_ms, k)));
                    return NonceInsert::Inserted;
                }
                if self.try_reserve() {
                    let k: Arc<str> = Arc::from(key);
                    shard.map.insert(Arc::clone(&k), expiry_ms);
                    shard.heap.push(Reverse((expiry_ms, k)));
                    return NonceInsert::Inserted;
                }
            }
            // Full: expired entries in other shards may still count; drop them
            // (cheap: only expired heap tops are visited) and retry once.
            if attempt == 0 && self.expire_all(now_ms) == 0 {
                break;
            }
        }
        self.last_overflow_ms.fetch_max(now_ms, Ordering::AcqRel);
        metrics::get().overflow("nonce");
        NonceInsert::Full
    }

    /// Removes expired entries from every shard; returns how many.
    pub fn expire_all(&self, now_ms: i64) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let n = lock(shard).expire(now_ms);
            self.len.fetch_sub(n, Ordering::AcqRel);
            removed += n;
        }
        removed
    }

    /// Latest time an insert failed because the set was full.
    pub fn last_overflow_ms(&self) -> Option<i64> {
        let v = self.last_overflow_ms.load(Ordering::Acquire);
        (v != i64::MIN).then_some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LimiterKey;

    const NOW: u64 = 1_790_000_000_000_000;

    fn limit(
        site: &str,
        limiter: &str,
        dims: &str,
        rate: u32,
        period: u32,
        burst: u32,
    ) -> PreparedLimit {
        PreparedLimit::new(
            &LimitCheck {
                key: LimiterKey::new(site, limiter, dims),
                params: GcraParams::new(rate, period, burst).unwrap(),
                cost: 1,
                write: true,
            },
            &[3u8; 32],
        )
    }

    #[test]
    fn sanitize_keeps_valid_params_and_bounds_invalid_ones() {
        let p = GcraParams::new(10, 1, 3).unwrap();
        assert_eq!(sanitize(p, 1), (p, 1));
        assert_eq!(sanitize(p, 0), (p, 1));
        assert_eq!(sanitize(p, 1000).1, 4);
        let huge = GcraParams {
            interval_us: u64::MAX,
            burst: u32::MAX,
        };
        let (q, c) = sanitize(huge, u32::MAX);
        assert!(q.interval_us.checked_mul(u64::from(q.burst)).unwrap() <= MAX_DVT_US);
        assert!(u64::from(c) <= u64::from(q.burst) + 1);
        // A clamped impossible request stays impossible.
        let p = GcraParams::new(1, 1, 2).unwrap();
        let (q, c) = sanitize(p, 50);
        assert!(!gcra_check(&q, None, NOW, c).allowed);
    }

    #[test]
    fn gcra_matches_core_and_expires_lazily() {
        let t = LocalGcra::new(10);
        let l = limit("s", "l", "ip=1", 10, 1, 3);
        let mut tat = None;
        for _ in 0..3 {
            let a = t.check(&l, true, NOW);
            let b = gcra_check(&l.params, tat, NOW, 1);
            assert_eq!(a, b);
            tat = b.new_tat_us;
        }
        assert!(!t.check(&l, true, NOW).allowed);
        assert_eq!(t.len(), 1);
        // Check-only never creates state.
        let other = limit("s", "l", "ip=2", 10, 1, 3);
        assert!(t.check(&other, false, NOW).allowed);
        assert_eq!(t.len(), 1);
        // Long after the TAT, the entry is "no state" and a check-only drops it.
        assert!(t.check(&l, false, NOW + 10_000_000).allowed);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn full_table_uses_overflow_bucket_and_never_evicts_live_entries() {
        let t = LocalGcra::new(2);
        let a = limit("s", "l", "ip=a", 1, 60, 1);
        let b = limit("s", "l", "ip=b", 1, 60, 1);
        assert!(t.check(&a, true, NOW).allowed);
        assert!(t.check(&b, true, NOW).allowed);
        assert_eq!(t.len(), 2);
        // New keys go to the overflow bucket, which counts them together.
        let c = limit("s", "l", "ip=c", 1, 60, 1);
        let d = limit("s", "l", "ip=d", 1, 60, 1);
        assert!(t.check(&c, true, NOW).allowed);
        assert!(
            !t.check(&d, true, NOW).allowed,
            "overflow bucket shares state"
        );
        // A check-only query of a key without state sees the overflow bucket.
        assert!(!t.check(&c, false, NOW).allowed);
        // Live entries were not evicted.
        assert!(!t.check(&a, true, NOW).allowed);
        assert!(!t.check(&b, true, NOW).allowed);
        assert_eq!(t.len(), 2);
        // Another limiter has its own overflow bucket.
        let e = limit("s", "other", "ip=e", 1, 60, 1);
        assert!(t.check(&e, true, NOW).allowed);
        // Once entries are stale, the next full event sweeps and frees slots.
        let later = NOW + 120_000_000;
        assert!(t.check(&c, true, later).allowed);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn all_or_nothing_writes_only_when_every_quota_allows() {
        let t = LocalGcra::new(10);
        let ipp = limit("s", "mg.clr.issue.ipp", "ip_prefix=p", 1, 60, 1);
        let asn = limit("s", "mg.clr.issue.asn", "asn=1", 1, 60, 2);
        let out = t.check_all_or_nothing(&[ipp.clone(), asn.clone()], NOW);
        assert!(out.iter().all(|o| o.allowed));
        // ipp exhausted: asn must not be consumed.
        let out = t.check_all_or_nothing(&[ipp.clone(), asn.clone()], NOW);
        assert!(!out[0].allowed && out[1].allowed);
        let asn_state = t.check(&asn, false, NOW);
        assert_eq!(
            asn_state.tat_minus_now_us,
            2 * 60_000_000,
            "one consumption only"
        );
    }

    #[test]
    fn nonce_set_never_evicts_live_entries() {
        let s = NonceSet::new(2);
        assert_eq!(s.insert("a", 1_000, 0), NonceInsert::Inserted);
        assert_eq!(s.insert("a", 1_000, 10), NonceInsert::Exists);
        assert_eq!(s.insert("b", 2_000, 10), NonceInsert::Inserted);
        assert_eq!(s.insert("c", 2_000, 20), NonceInsert::Full);
        assert_eq!(s.last_overflow_ms(), Some(20));
        // Both live entries are still there.
        assert_eq!(s.insert("a", 1_000, 30), NonceInsert::Exists);
        assert_eq!(s.insert("b", 2_000, 30), NonceInsert::Exists);
        // After "a" expires, its slot is reused, and "a" is fresh again.
        assert_eq!(s.insert("c", 2_000, 1_000), NonceInsert::Inserted);
        assert_eq!(s.len(), 2);
        assert_eq!(s.insert("b", 2_000, 1_999), NonceInsert::Exists);
        assert_eq!(s.expire_all(5_000), 2);
        assert_eq!(s.len(), 0);
        assert_eq!(s.insert("a", 6_000, 5_000), NonceInsert::Inserted);
    }

    #[test]
    fn concurrent_nonce_inserts_admit_each_nonce_once() {
        let s = Arc::new(NonceSet::new(10_000));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    (0..1000)
                        .filter(|i| s.insert(&format!("n{i}"), 100_000, 1) == NonceInsert::Inserted)
                        .count()
                })
            })
            .collect();
        let total: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(total, 1000);
        assert_eq!(s.len(), 1000);
    }
}
