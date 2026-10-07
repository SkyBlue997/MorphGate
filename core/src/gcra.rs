//! Pure GCRA (generic cell rate algorithm) in integer microseconds.
//!
//! The Edge runs the same arithmetic in two places: in process (local
//! limiters, and the local fallback when Valkey is unavailable) and inside the
//! Valkey Lua script `mg_gcra` (docs/impl/phase1-spec.md §9.7). Both must agree
//! bit for bit; `core/testdata/gcra-cases.json` is the shared case table that
//! this module's tests and the Lua tests (WP-C3) both run.
//!
//! Lua 5.1 numbers are doubles, so every value the script handles must stay
//! below 2^53. [`GcraParams::new`] therefore caps the delay variation
//! tolerance at [`MAX_DVT_US`] (7 days); with present-day Unix time in
//! microseconds (~1.8e15) all intermediate values stay far below 2^53.

/// Largest accepted `interval_us * burst` (7 days in microseconds).
pub const MAX_DVT_US: u64 = 7 * 86_400 * 1_000_000;

/// Parameters of one limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcraParams {
    /// Emission interval: `period_s * 1_000_000 / rate` (floor).
    pub interval_us: u64,
    /// Requests allowed at one instant from a fresh state (>= 1).
    pub burst: u32,
}

impl GcraParams {
    /// `None` if `rate`, `period_s` or `burst` is 0, if the interval rounds
    /// down to 0 (`rate > period_s * 1e6`), or if `interval_us * burst`
    /// exceeds [`MAX_DVT_US`].
    pub fn new(rate: u32, period_s: u32, burst: u32) -> Option<Self> {
        if rate == 0 || period_s == 0 || burst == 0 {
            return None;
        }
        let interval_us = u64::from(period_s) * 1_000_000 / u64::from(rate);
        if interval_us == 0 {
            return None;
        }
        let dvt = interval_us.checked_mul(u64::from(burst))?;
        (dvt <= MAX_DVT_US).then_some(Self { interval_us, burst })
    }

    /// Delay variation tolerance: `interval_us * burst`.
    pub fn dvt_us(&self) -> u64 {
        self.interval_us * u64::from(self.burst)
    }
}

/// Result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcraOutcome {
    pub allowed: bool,
    /// Denied: time until the request would be allowed. Allowed: 0.
    pub retry_after_us: u64,
    /// Allowed: `new_tat - now`. Denied: `tat - now` (the stored state is unchanged).
    pub tat_minus_now_us: u64,
    /// `Some(new_tat)` iff allowed; the caller stores it to consume the request
    /// ("check only" callers drop it).
    pub new_tat_us: Option<u64>,
}

impl GcraOutcome {
    /// Utilization in `[0, 1]`: allowed `min(1, tat_minus_now / dvt)`; denied 1.0.
    pub fn utilization(&self, p: &GcraParams) -> f32 {
        if !self.allowed {
            return 1.0;
        }
        let dvt = p.dvt_us().max(1);
        (self.tat_minus_now_us as f64 / dvt as f64).min(1.0) as f32
    }
}

/// One GCRA step. `stored_tat_us` is the stored theoretical arrival time
/// (`None` = no state); `cost` is the number of requests (Phase 1: always 1;
/// 0 is treated as 1).
///
/// `tat = max(stored, now)`, `new_tat = tat + interval * cost`,
/// `allow_at = new_tat - dvt` (saturating at 0). Denied iff `now < allow_at`.
pub fn gcra_check(
    p: &GcraParams,
    stored_tat_us: Option<u64>,
    now_us: u64,
    cost: u32,
) -> GcraOutcome {
    let cost = u64::from(cost.max(1));
    let tat = stored_tat_us.unwrap_or(0).max(now_us);
    let new_tat = tat.saturating_add(p.interval_us.saturating_mul(cost));
    let allow_at = new_tat.saturating_sub(p.dvt_us());
    if now_us < allow_at {
        GcraOutcome {
            allowed: false,
            retry_after_us: allow_at - now_us,
            tat_minus_now_us: tat - now_us,
            new_tat_us: None,
        }
    } else {
        GcraOutcome {
            allowed: true,
            retry_after_us: 0,
            tat_minus_now_us: new_tat - now_us,
            new_tat_us: Some(new_tat),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CASES: &str = include_str!("../testdata/gcra-cases.json");

    fn opt_u64(v: &Value) -> Option<u64> {
        v.as_u64()
    }

    #[test]
    fn params_table() {
        let doc: Value = serde_json::from_str(CASES).expect("gcra-cases.json");
        let cases = doc["params"].as_array().expect("params");
        assert!(!cases.is_empty());
        for c in cases {
            let got = GcraParams::new(
                c["rate"].as_u64().unwrap() as u32,
                c["period_s"].as_u64().unwrap() as u32,
                c["burst"].as_u64().unwrap() as u32,
            );
            assert_eq!(
                got.map(|p| p.interval_us),
                opt_u64(&c["interval_us"]),
                "{c}"
            );
        }
    }

    #[test]
    fn check_table() {
        let doc: Value = serde_json::from_str(CASES).expect("gcra-cases.json");
        let cases = doc["checks"].as_array().expect("checks");
        assert!(cases.len() >= 10);
        for c in cases {
            let p = GcraParams {
                interval_us: c["interval_us"].as_u64().unwrap(),
                burst: c["burst"].as_u64().unwrap() as u32,
            };
            let out = gcra_check(
                &p,
                opt_u64(&c["stored_tat_us"]),
                c["now_us"].as_u64().unwrap(),
                c["cost"].as_u64().unwrap() as u32,
            );
            let name = c["name"].as_str().unwrap();
            assert_eq!(out.allowed, c["allowed"].as_bool().unwrap(), "{name}");
            assert_eq!(
                out.retry_after_us,
                c["retry_after_us"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                out.tat_minus_now_us,
                c["tat_minus_now_us"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(out.new_tat_us, opt_u64(&c["new_tat_us"]), "{name}");
        }
    }

    #[test]
    fn burst_then_steady_rate() {
        // 10 per second, burst 3: three at once, the fourth waits one interval.
        let p = GcraParams::new(10, 1, 3).unwrap();
        let now = 1_790_000_000_000_000;
        let mut tat = None;
        for _ in 0..3 {
            let o = gcra_check(&p, tat, now, 1);
            assert!(o.allowed);
            tat = o.new_tat_us;
        }
        let denied = gcra_check(&p, tat, now, 1);
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after_us, 100_000);
        assert_eq!(denied.utilization(&p), 1.0);
        let later = gcra_check(&p, tat, now + 100_000, 1);
        assert!(later.allowed);
        assert_eq!(later.utilization(&p), 1.0);
        let fresh = gcra_check(&p, None, now, 1);
        assert!((fresh.utilization(&p) - 1.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn values_stay_below_2_pow_53() {
        let p = GcraParams::new(1, 86_400, 7).unwrap();
        assert_eq!(p.dvt_us(), MAX_DVT_US);
        assert!(GcraParams::new(1, 86_400, 8).is_none());
        let now = 4_102_444_800_000_000; // 2100-01-01
        let o = gcra_check(&p, Some(now + p.dvt_us()), now, 1);
        assert!(now + p.dvt_us() + p.interval_us < 1 << 53);
        assert!(!o.allowed);
    }
}
