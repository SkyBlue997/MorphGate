//! Shared helpers for the mg-challenge integration tests: deterministic
//! RNGs (test code only, spec §2.4 item 6), fixture paths and builders for
//! well-formed claims.
#![allow(dead_code)] // each test binary uses a different subset

use mg_challenge::{Rng, RngError};
use mg_core::{ChallengeBind, ChallengeType, PowParams, RiskBand, SealedChallengeClaims};
use std::path::PathBuf;
use std::sync::Mutex;

/// `testdata/phase1/<rel>` (read-only shared fixtures, spec §0.4).
pub fn phase1(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/phase1")
        .join(rel)
}

pub fn read(rel: &str) -> Vec<u8> {
    let path = phase1(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn kat() -> serde_json::Value {
    serde_json::from_slice(&read("kat.json")).expect("kat.json is JSON")
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// xorshift64* behind a mutex: deterministic and never failing.
#[derive(Debug)]
pub struct TestRng(Mutex<u64>);

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self(Mutex::new(seed.max(1)))
    }

    pub fn next_u64(&self) -> u64 {
        let mut s = self.0.lock().unwrap();
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        s.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

impl Rng for TestRng {
    fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
        for b in dst {
            *b = (self.next_u64() >> 56) as u8;
        }
        Ok(())
    }
}

/// An RNG whose every call fails.
#[derive(Debug)]
pub struct FailingRng;

impl Rng for FailingRng {
    fn fill(&self, _dst: &mut [u8]) -> Result<(), RngError> {
        Err(RngError)
    }
}

/// An RNG that succeeds `ok` times, then fails.
#[derive(Debug)]
pub struct FailAfter {
    pub ok: Mutex<u32>,
    pub inner: TestRng,
}

impl FailAfter {
    pub fn new(ok: u32) -> Self {
        Self {
            ok: Mutex::new(ok),
            inner: TestRng::new(99),
        }
    }
}

impl Rng for FailAfter {
    fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
        let mut ok = self.ok.lock().unwrap();
        if *ok == 0 {
            return Err(RngError);
        }
        *ok -= 1;
        self.inner.fill(dst)
    }
}

/// `2026-10-10T00:00:00Z`: the first millisecond of epoch 20736.
pub const DAY_START_MS: i64 = 20_736 * 86_400_000;
/// Midday of the same epoch.
pub const MIDDAY_MS: i64 = DAY_START_MS + 43_200_000;

/// Well-formed Phase 1 `pow` claims for site `blog`, issued at `iat_ms`
/// with a 120 s lifetime and the `uah` / `ipp` / `ipa` bindings of
/// [`bindings`].
pub fn pow_claims(iat_ms: i64) -> SealedChallengeClaims {
    SealedChallengeClaims {
        v: 1,
        kid: mg_challenge::epoch_kid(mg_challenge::epoch_no(iat_ms)),
        nonce: [0x5a; 16],
        site: "blog".into(),
        route_class: "login".into(),
        challenge_type: ChallengeType::Pow,
        providers: vec![],
        risk_band: RiskBand::Medium,
        attempt_no: 0,
        iat_ms,
        exp_ms: iat_ms + 120_000,
        ui_seed: 0,
        pow: Some(PowParams {
            alg: mg_challenge::POW_ALG.into(),
            difficulty: 16,
        }),
        ret_hash: mg_challenge::ret_hash("/account/login").to_vec(),
        bind: ChallengeBind {
            uah: Some(mg_challenge::uah("chrome", 131).to_vec()),
            ipp: Some(mg_challenge::ipp("203.0.113.0/24").to_vec()),
            ipa: mg_challenge::ipa(64500).map(|h| h.to_vec()),
            ..ChallengeBind::default()
        },
    }
}

/// The request bindings matching [`pow_claims`]: Chrome 131 from
/// 203.0.113.0/24 in AS64500.
pub fn bindings() -> mg_challenge::BindInputs {
    mg_challenge::BindInputs {
        uah: mg_challenge::uah("chrome", 131),
        ipp: Some(mg_challenge::ipp("203.0.113.0/24")),
        ipa: mg_challenge::ipa(64500),
        ctp: None,
    }
}

pub fn seal_root(byte: u8) -> mg_challenge::SealRoot {
    mg_challenge::SealRoot::from_bytes([byte; 32])
}

pub fn sealer(site: &str, roots: &[u8]) -> mg_challenge::Sealer {
    let keys = mg_challenge::SealKeys::new(roots.iter().map(|&b| seal_root(b)).collect())
        .expect("1 or 2 roots");
    mg_challenge::Sealer::new(site, keys)
}
