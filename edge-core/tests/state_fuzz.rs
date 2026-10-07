//! Deterministic random inputs never panic (spec §2.4 item 3) for the state
//! layer's public entry points: key builders, local GCRA checks with
//! arbitrary parameters, local nonce checks with arbitrary times, config
//! validation, verdict parsing and fault-proxy targets. (Valkey reply parsers
//! are covered by a unit test in `state/valkey.rs`.)

use mg_core::gcra::GcraParams;
use mg_edge_core::state::{
    LimitCheck, LimiterKey, NonceIssue, NonceResult, StateConfig, StateService, dims, kh,
    parse_verdict,
};
use mg_edge_core::testkit::valkey::FaultTarget;

const N: usize = 10_000;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    /// Mostly small / boundary values, sometimes anything.
    fn u64_edgy(&mut self) -> u64 {
        match self.below(6) {
            0 => 0,
            1 => u64::MAX - self.below(3),
            2 => self.below(10),
            3 => 1_790_000_000_000_000 + self.below(1 << 40),
            4 => 1 << self.below(64),
            _ => self.next(),
        }
    }

    fn string(&mut self) -> String {
        const ALPHABET: &[u8] = b"abc:/?#@[]%&=._-~ 0123456789\\\n\x00";
        let len = self.below(40) as usize;
        let mut s: String = (0..len)
            .map(|_| char::from(ALPHABET[self.below(ALPHABET.len() as u64) as usize]))
            .collect();
        if self.below(4) == 0 {
            s.push(char::from_u32(0x80 + self.below(0x2000) as u32).unwrap_or('é'));
        }
        if self.below(3) == 0 {
            let prefix = [
                "redis://",
                "unix://",
                "valkey+unix://",
                "/",
                "rediss://",
                "",
            ][self.below(6) as usize];
            s.insert_str(0, prefix);
        }
        s
    }
}

#[test]
fn key_builders_never_panic() {
    let mut r = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut k = [0u8; 32];
    for _ in 0..N {
        for b in k.iter_mut() {
            *b = r.next() as u8;
        }
        let (a, b, c) = (r.string(), r.string(), r.string());
        let h = kh(&k, &a, &b, &c);
        assert_eq!(h.len(), 32);
        let d = dims(&[(a.as_str(), Some(b.as_str())), (c.as_str(), None)]);
        let key = LimiterKey::new(a, b, d).redis_key(&k);
        assert!(key.starts_with("mg:rl:"));
    }
}

#[test]
fn local_checks_with_arbitrary_parameters_never_panic() {
    let mut r = XorShift(0x0123_4567_89ab_cdef);
    let mut cfg = StateConfig::local([1; 32]);
    cfg.local_limiter_capacity = 64;
    let (_service, h) = StateService::new(cfg);
    for i in 0..N {
        let check = LimitCheck {
            key: LimiterKey::new(
                "s",
                format!("l{}", r.below(4)),
                format!("ip={}", r.below(100)),
            ),
            params: GcraParams {
                interval_us: r.u64_edgy(),
                burst: r.u64_edgy() as u32,
            },
            cost: r.u64_edgy() as u32,
            write: r.below(2) == 0,
        };
        let out = h.local_check(&check, r.u64_edgy());
        assert_eq!(out.allowed, out.new_tat_us.is_some(), "case {i}");
        assert!(
            out.allowed || out.retry_after_us > 0 || check.params.burst == 0,
            "case {i}"
        );
    }
}

#[tokio::test]
async fn local_nonce_checks_with_arbitrary_times_never_panic() {
    let mut r = XorShift(0xdead_beef_cafe_f00d);
    let mut cfg = StateConfig::local([2; 32]);
    cfg.local_nonce_capacity = 256;
    cfg.local_limiter_capacity = 256;
    cfg.local_replay_authoritative = true;
    let (_service, h) = StateService::new(cfg);
    for _ in 0..N {
        let mut nonce = [0u8; 16];
        nonce[0] = r.below(512) as u8;
        nonce[1] = r.below(2) as u8;
        let limits = (0..r.below(3))
            .map(|j| LimitCheck {
                key: LimiterKey::new("s", format!("q{j}"), "x"),
                params: GcraParams {
                    interval_us: r.u64_edgy(),
                    burst: r.u64_edgy() as u32,
                },
                cost: r.u64_edgy() as u32,
                write: true,
            })
            .collect();
        let req = NonceIssue {
            site: "s".into(),
            nonce,
            ttl_ms: r.u64_edgy(),
            limits,
        };
        let now = r.u64_edgy() as i64;
        let iat = r.u64_edgy() as i64;
        match h.nonce_issue(req, now, iat).await {
            NonceResult::Reused => {}
            NonceResult::Fresh { limits } | NonceResult::Unavailable { limits } => {
                assert!(limits.len() <= 2);
            }
        }
    }
}

#[test]
fn config_validation_and_targets_never_panic() {
    let mut r = XorShift(0x5555_aaaa_3333_cccc);
    for _ in 0..N {
        let url = r.string();
        let mut cfg = StateConfig::valkey(url.clone(), [3; 32]);
        cfg.timeout_ms = r.below(3);
        if let Err(e) = cfg.validate() {
            // Errors never echo a URL (it could carry credentials).
            if url.len() > 12 {
                assert!(!e.to_string().contains(&url), "{e}");
            }
        }
        let _ = FaultTarget::parse(&url);
        let _ = parse_verdict(&url);
    }
}
