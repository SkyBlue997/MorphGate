//! Claims of the sealed challenge `C` (docs/09 §4, ADR-0005).
//!
//! ```text
//! C  = base64url(prost(SealedChallenge { v, kid, xnonce, ct }))
//! ct = XChaCha20-Poly1305.seal(k_epoch[kid], xnonce, prost(SealedChallengeClaims),
//!                              aad = host || type || kid)
//! ```
//!
//! [`SealedChallengeClaims`] is the native form of
//! `morphgate.v1.SealedChallengeClaims` (`proto/morphgate/v1/challenge.proto`).
//! Only the Edge seals and opens `C`; the SDK never parses it. This module
//! holds no key material and does no cryptography: sealing, opening, the
//! HKDF-derived epoch keys and the nonce `SET NX` are Phase 1 (Edge). What is
//! here are the pure checks on opened claims that need no key, hash or store.
//!
//! The claims deliberately implement neither `Serialize` nor a `Debug` that
//! shows the nonce: their only encoding is the sealed protobuf, and the
//! single-use nonce must never reach a log line.

use crate::challenge::ProviderId;
use crate::enums::ChallengeType;
use crate::values::RiskBand;
use std::fmt;

/// PoW parameters sealed into `C` and re-checked by the server
/// (docs/impl/phase2-spec.md §3.1, §6.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PowParams {
    /// [`SealedChallengeClaims::POW_ALG_V1`] (invisible / pow) or
    /// [`SealedChallengeClaims::POW_ALG_V2`] (interactive).
    pub alg: String,
    /// v1: the single puzzle; v2: every sub-puzzle of `self_hold` (or `turnstile`).
    pub difficulty: u32,
    /// v2 only: number of sub-puzzles, `1..=MAX_POW_K`; v1: 0.
    pub k: u32,
    /// v2 only: every sub-puzzle of `pow_a11y`; v1: 0.
    pub a11y_difficulty: u32,
}

/// Binding hashes sealed into `C` (phases and strengths: docs/04 §5).
///
/// Presence-aware like the protobuf `optional bytes` fields: `None` means not
/// bound; `Some` is checked even when the hash is empty.
///
/// `Debug` shows only which bindings are present: the hashes are short and
/// unsalted (an `ipp` hash of a /24 is reversed by trying every prefix), so
/// printing them would leak the client prefix (spec §2.4 item 5, D-31).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ChallengeBind {
    /// `hash(UA family + major version)`: hard (Phase 1).
    pub uah: Option<Vec<u8>>,
    /// `hash(IP /24 or /48)`: soft (Phase 1). `None` when the client IP is unknown.
    pub ipp: Option<Vec<u8>>,
    /// `bind_hash("jkt", thumbprint)` of the SDK session key the `C` is bound
    /// to (Phase 2 spec D-41): hard. 16 bytes when present.
    pub jkt: Option<Vec<u8>>,
    /// Coarse TLS tuple hash: `cloudflare` only, shadow only.
    pub ctp: Option<Vec<u8>>,
    /// JA4 hash: `direct_tls` only, after the JA4 spike, hard.
    pub tfp: Option<Vec<u8>>,
    /// `hash(ASN)` of the client IP at issuance. Decides the soft `ipp`
    /// result: prefix changed within the same ASN is a risk signal, a changed
    /// (or unknown) ASN needs a new challenge. `None` when the ASN is unknown.
    pub ipa: Option<Vec<u8>>,
}

/// Claims inside a sealed challenge (docs/09 §4.2). Times are Unix epoch
/// milliseconds from the server clock.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChallengeClaims {
    /// Claims format version; anything but [`Self::VERSION`] is rejected.
    pub v: u32,
    /// Epoch key id; must equal the envelope's `kid`.
    pub kid: String,
    /// 128-bit single-use nonce (`mg:n:{site}:{nonce}`).
    pub nonce: [u8; 16],
    /// Site id; must own the request's Host.
    pub site: String,
    /// `[a-z0-9_-]{1,32}`; also the Turnstile `action`.
    pub route_class: String,
    /// `Invisible`, `Pow` or `Interactive`; must match the endpoint.
    pub challenge_type: ChallengeType,
    /// Interactive only: the offered providers, first = default. A submitted
    /// provider outside this set fails (anti-downgrade). Phase 2: non-empty,
    /// unique, contains `pow_a11y`, subset of `{self_hold, pow_a11y, turnstile}`.
    pub providers: Vec<ProviderId>,
    /// Pre-challenge risk band: PoW difficulty and scoring prior.
    pub risk_band: RiskBand,
    /// Interactive only: 1-based attempt number (0 otherwise).
    pub attempt_no: u32,
    pub iat_ms: i64,
    pub exp_ms: i64,
    /// Interactive only: random and non-zero; seeds the hold duration and the
    /// button offset (Phase 2 spec §6.3). 0 otherwise.
    pub ui_seed: u64,
    pub pow: Option<PowParams>,
    /// Hash of the same-site return path (anti open redirect).
    pub ret_hash: Vec<u8>,
    pub bind: ChallengeBind,
    /// Interactive only: renewals so far in this chain,
    /// `0..=MAX_RENEW_NO` (Phase 2 spec D-42). 0 otherwise.
    pub renew_no: u32,
}

/// Why opened claims are unusable. Every variant maps to the same
/// `mg_challenge_failed` answer to the client (docs/09 §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimsError {
    UnsupportedVersion(u32),
    InvalidRouteClass,
    /// Only invisible, PoW and interactive challenges are sealed.
    UnsealableType(ChallengeType),
    /// `providers` empty or duplicated for an interactive challenge, or set for
    /// any other type.
    InvalidProviders,
    /// `attempt_no` 0 for an interactive challenge, or set for any other type.
    InvalidAttempt,
    /// `ui_seed` 0 for an interactive challenge, or set for any other type
    /// (Phase 2 spec §6.2).
    InvalidUiSeed,
    /// `renew_no` above [`SealedChallengeClaims::MAX_RENEW_NO`] for an
    /// interactive challenge, or set for any other type (Phase 2 spec §6.2).
    InvalidRenewNo,
    /// PoW parameters missing or not those of the type: algorithm, `k`,
    /// difficulties (Phase 2 spec §6.2).
    InvalidPow,
    /// `bind.jkt` present but not 16 bytes (Phase 2 spec §6.2).
    InvalidJktBinding,
    /// `exp <= iat`, or a lifetime above the limit for the type.
    InvalidLifetime,
    /// Checked against the host-supplied time.
    Expired,
    /// `iat` lies in the future beyond the allowed clock skew.
    NotYetValid,
    /// The hard `uah` binding is absent.
    MissingUahBinding,
}

impl fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported claims version {v}"),
            Self::InvalidRouteClass => f.write_str("route_class must match [a-z0-9_-]{1,32}"),
            Self::UnsealableType(t) => write!(f, "challenge type {t} is not sealed"),
            Self::InvalidProviders => f.write_str("providers do not fit the challenge type"),
            Self::InvalidAttempt => f.write_str("attempt_no does not fit the challenge type"),
            Self::InvalidUiSeed => f.write_str("ui_seed does not fit the challenge type"),
            Self::InvalidRenewNo => f.write_str("renew_no does not fit the challenge type"),
            Self::InvalidPow => f.write_str("pow parameters do not fit the challenge type"),
            Self::InvalidJktBinding => f.write_str("jkt binding must be 16 bytes"),
            Self::InvalidLifetime => f.write_str("invalid challenge lifetime"),
            Self::Expired => f.write_str("challenge expired"),
            Self::NotYetValid => f.write_str("challenge issued in the future"),
            Self::MissingUahBinding => f.write_str("uah binding missing"),
        }
    }
}

impl std::error::Error for ClaimsError {}

impl SealedChallengeClaims {
    /// The only claims version this build accepts.
    pub const VERSION: u32 = 1;
    /// Maximum `route_class` length.
    pub const MAX_ROUTE_CLASS_LEN: usize = 32;
    /// Invisible / PoW challenges live at most 120 s (docs/04 §4.1).
    pub const MAX_NON_INTERACTIVE_LIFETIME_MS: i64 = 120_000;
    /// Interactive challenges live 600 s and are renewed silently
    /// (docs/09 §4.3; Phase 2 spec D-42, §6.1).
    pub const MAX_INTERACTIVE_LIFETIME_MS: i64 = 10 * 60_000;
    /// Renewals per interactive chain (Phase 2 spec D-42).
    pub const MAX_RENEW_NO: u32 = 6;
    /// Sub-puzzles of the v2 PoW (Phase 2 spec D-43, §6.4).
    pub const MAX_POW_K: u32 = 8;
    /// Leading zero bits of any (sub-)puzzle.
    pub const MAX_POW_DIFFICULTY: u32 = 32;
    /// PoW of invisible / pow challenges (Phase 1 spec §6.3).
    pub const POW_ALG_V1: &'static str = "sha256-hashcash-v1";
    /// PoW of interactive challenges (Phase 2 spec D-43, §6.4).
    pub const POW_ALG_V2: &'static str = "sha256-hashcash-v2";
    /// Length of every binding hash (Phase 1 spec §6.4).
    pub const BIND_HASH_LEN: usize = 16;
    /// Tolerated skew between the Edges' clocks for `iat`.
    pub const MAX_CLOCK_SKEW_MS: i64 = 5_000;

    /// Whether `provider` was offered (anti-downgrade check on submission).
    pub fn offers(&self, provider: ProviderId) -> bool {
        self.providers.contains(&provider)
    }

    /// The default provider (first offered), for interactive challenges.
    pub fn default_provider(&self) -> Option<ProviderId> {
        self.providers.first().copied()
    }

    /// Structural checks from docs/09 §4.2 and the Phase 2 rules of
    /// docs/impl/phase2-spec.md §6.2 that need no key, hash or store, plus
    /// expiry against the host-supplied `now_ms`. Run after opening and
    /// before consuming the nonce; binding values and `ret` are compared by
    /// the caller, and the remaining length checks (`ret`, `uah`, `ipp` and
    /// the other bindings) stay with the sealer, as in Phase 1.
    ///
    /// | type | rules |
    /// |---|---|
    /// | invisible / pow | `providers` empty; `attempt_no`, `ui_seed`, `renew_no` 0; PoW `sha256-hashcash-v1` with `k` and `a11y_difficulty` 0; lifetime <= 120 s |
    /// | interactive | `providers` non-empty, unique, containing `pow_a11y`, within `{self_hold, pow_a11y, turnstile}`; `attempt_no >= 1`; `ui_seed != 0`; `renew_no <= 6`; PoW `sha256-hashcash-v2` with `1 <= k <= 8` and both difficulties <= 32; lifetime <= 600 s |
    /// | both | `bind.uah` present; `bind.jkt` absent or 16 bytes |
    pub fn check(&self, now_ms: i64) -> Result<(), ClaimsError> {
        if self.v != Self::VERSION {
            return Err(ClaimsError::UnsupportedVersion(self.v));
        }
        if !is_valid_route_class(&self.route_class) {
            return Err(ClaimsError::InvalidRouteClass);
        }
        let max_lifetime = match self.challenge_type {
            ChallengeType::Interactive => {
                let mut seen = Vec::with_capacity(self.providers.len());
                for p in &self.providers {
                    let allowed = matches!(
                        p,
                        ProviderId::SelfHold | ProviderId::PowA11y | ProviderId::Turnstile
                    );
                    if !allowed || seen.contains(p) {
                        return Err(ClaimsError::InvalidProviders);
                    }
                    seen.push(*p);
                }
                if !seen.contains(&ProviderId::PowA11y) {
                    return Err(ClaimsError::InvalidProviders);
                }
                if self.attempt_no == 0 {
                    return Err(ClaimsError::InvalidAttempt);
                }
                if self.ui_seed == 0 {
                    return Err(ClaimsError::InvalidUiSeed);
                }
                if self.renew_no > Self::MAX_RENEW_NO {
                    return Err(ClaimsError::InvalidRenewNo);
                }
                let pow_ok = self.pow.as_ref().is_some_and(|p| {
                    p.alg == Self::POW_ALG_V2
                        && (1..=Self::MAX_POW_K).contains(&p.k)
                        && p.difficulty <= Self::MAX_POW_DIFFICULTY
                        && p.a11y_difficulty <= Self::MAX_POW_DIFFICULTY
                });
                if !pow_ok {
                    return Err(ClaimsError::InvalidPow);
                }
                Self::MAX_INTERACTIVE_LIFETIME_MS
            }
            ChallengeType::Invisible | ChallengeType::Pow => {
                if !self.providers.is_empty() {
                    return Err(ClaimsError::InvalidProviders);
                }
                if self.attempt_no != 0 {
                    return Err(ClaimsError::InvalidAttempt);
                }
                if self.ui_seed != 0 {
                    return Err(ClaimsError::InvalidUiSeed);
                }
                if self.renew_no != 0 {
                    return Err(ClaimsError::InvalidRenewNo);
                }
                let pow_ok = self.pow.as_ref().is_some_and(|p| {
                    p.alg == Self::POW_ALG_V1 && p.k == 0 && p.a11y_difficulty == 0
                });
                if !pow_ok {
                    return Err(ClaimsError::InvalidPow);
                }
                Self::MAX_NON_INTERACTIVE_LIFETIME_MS
            }
            other => return Err(ClaimsError::UnsealableType(other)),
        };
        let lifetime = self.exp_ms.saturating_sub(self.iat_ms);
        if lifetime <= 0 || lifetime > max_lifetime {
            return Err(ClaimsError::InvalidLifetime);
        }
        if self.iat_ms > now_ms.saturating_add(Self::MAX_CLOCK_SKEW_MS) {
            return Err(ClaimsError::NotYetValid);
        }
        if now_ms >= self.exp_ms {
            return Err(ClaimsError::Expired);
        }
        if self.bind.uah.is_none() {
            return Err(ClaimsError::MissingUahBinding);
        }
        if self
            .bind
            .jkt
            .as_ref()
            .is_some_and(|h| h.len() != Self::BIND_HASH_LEN)
        {
            return Err(ClaimsError::InvalidJktBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for ChallengeBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// `Some(..)` / `None` without the bytes.
        struct Presence(bool);
        impl fmt::Debug for Presence {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(if self.0 { "Some(..)" } else { "None" })
            }
        }
        let p = |b: &Option<Vec<u8>>| Presence(b.is_some());
        f.debug_struct("ChallengeBind")
            .field("uah", &p(&self.uah))
            .field("ipp", &p(&self.ipp))
            .field("jkt", &p(&self.jkt))
            .field("ctp", &p(&self.ctp))
            .field("tfp", &p(&self.tfp))
            .field("ipa", &p(&self.ipa))
            .finish()
    }
}

impl fmt::Debug for SealedChallengeClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedChallengeClaims")
            .field("v", &self.v)
            .field("kid", &self.kid)
            .field("site", &self.site)
            .field("route_class", &self.route_class)
            .field("challenge_type", &self.challenge_type)
            .field("providers", &self.providers)
            .field("risk_band", &self.risk_band)
            .field("attempt_no", &self.attempt_no)
            .field("iat_ms", &self.iat_ms)
            .field("exp_ms", &self.exp_ms)
            .field("pow", &self.pow)
            .field("renew_no", &self.renew_no)
            .finish_non_exhaustive() // nonce, ui_seed, ret and bindings deliberately omitted
    }
}

/// `[a-z0-9_-]{1,32}`.
fn is_valid_route_class(s: &str) -> bool {
    (1..=SealedChallengeClaims::MAX_ROUTE_CLASS_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000_000;

    /// §2.4 item 5 / D-31: binding hashes never appear in `Debug` output.
    #[test]
    fn challenge_bind_debug_shows_presence_only() {
        let bind = ChallengeBind {
            uah: Some(vec![0xa1; 16]),
            ipp: Some(vec![0xb2; 16]),
            ipa: Some(vec![]),
            ..Default::default()
        };
        let s = format!("{bind:?}");
        assert_eq!(
            s,
            "ChallengeBind { uah: Some(..), ipp: Some(..), jkt: None, ctp: None, tfp: None, ipa: Some(..) }"
        );
        assert!(!s.contains("161") && !s.contains("178"), "{s}");
    }

    fn interactive() -> SealedChallengeClaims {
        SealedChallengeClaims {
            v: SealedChallengeClaims::VERSION,
            kid: "blog-e20360".into(),
            nonce: [0x5a; 16],
            site: "blog".into(),
            route_class: "login".into(),
            challenge_type: ChallengeType::Interactive,
            providers: vec![ProviderId::SelfHold, ProviderId::PowA11y],
            risk_band: RiskBand::High,
            attempt_no: 1,
            iat_ms: NOW - 1_000,
            exp_ms: NOW - 1_000 + 600_000,
            ui_seed: 0xDEAD_BEEF,
            pow: Some(PowParams {
                alg: SealedChallengeClaims::POW_ALG_V2.into(),
                difficulty: 16,
                k: 8,
                a11y_difficulty: 17,
            }),
            ret_hash: vec![1; 32],
            bind: ChallengeBind {
                uah: Some(vec![2; 32]),
                ipp: Some(vec![3; 32]),
                ..ChallengeBind::default()
            },
            renew_no: 0,
        }
    }

    fn pow() -> SealedChallengeClaims {
        SealedChallengeClaims {
            challenge_type: ChallengeType::Pow,
            providers: vec![],
            attempt_no: 0,
            ui_seed: 0,
            exp_ms: NOW + 60_000,
            pow: Some(PowParams {
                alg: SealedChallengeClaims::POW_ALG_V1.into(),
                difficulty: 16,
                ..PowParams::default()
            }),
            ..interactive()
        }
    }

    #[test]
    fn well_formed_claims_pass() {
        assert_eq!(interactive().check(NOW), Ok(()));
        assert_eq!(pow().check(NOW), Ok(()));
        let c = interactive();
        assert_eq!(c.default_provider(), Some(ProviderId::SelfHold));
        assert!(c.offers(ProviderId::PowA11y));
        assert!(
            !c.offers(ProviderId::Turnstile),
            "not offered -> downgrade attempt"
        );
    }

    #[test]
    fn version_and_route_class() {
        let mut c = interactive();
        c.v = 2;
        assert_eq!(c.check(NOW), Err(ClaimsError::UnsupportedVersion(2)));
        for bad in ["", "Login", "a/b", "log in", &"x".repeat(33)] {
            let mut c = interactive();
            c.route_class = bad.into();
            assert_eq!(c.check(NOW), Err(ClaimsError::InvalidRouteClass), "{bad:?}");
        }
        let mut c = interactive();
        c.route_class = "api-v2_login".into();
        assert_eq!(c.check(NOW), Ok(()));
    }

    #[test]
    fn type_specific_fields() {
        let mut c = interactive();
        c.providers.clear();
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidProviders));
        c.providers = vec![ProviderId::Turnstile, ProviderId::Turnstile];
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidProviders));

        let mut c = interactive();
        c.attempt_no = 0;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidAttempt));

        let mut c = pow();
        c.providers = vec![ProviderId::SelfHold];
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidProviders));
        let mut c = pow();
        c.attempt_no = 1;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidAttempt));

        for t in [
            ChallengeType::Unspecified,
            ChallengeType::Attestation,
            ChallengeType::StepUp,
        ] {
            let mut c = pow();
            c.challenge_type = t;
            assert_eq!(c.check(NOW), Err(ClaimsError::UnsealableType(t)));
        }
    }

    /// A named mutation and the error it must produce.
    type Case = (&'static str, ClaimsError, fn(&mut SealedChallengeClaims));

    /// Phase 2 spec §6.2: one counterexample per interactive rule.
    #[test]
    fn interactive_phase2_rules() {
        let cases: [Case; 14] = [
            ("no pow_a11y", ClaimsError::InvalidProviders, |c| {
                c.providers = vec![ProviderId::SelfHold]
            }),
            ("tencent", ClaimsError::InvalidProviders, |c| {
                c.providers.push(ProviderId::Tencent)
            }),
            ("aliyun_v2", ClaimsError::InvalidProviders, |c| {
                c.providers.push(ProviderId::AliyunV2)
            }),
            ("duplicate", ClaimsError::InvalidProviders, |c| {
                c.providers.push(ProviderId::PowA11y)
            }),
            ("ui_seed 0", ClaimsError::InvalidUiSeed, |c| c.ui_seed = 0),
            ("renew_no 7", ClaimsError::InvalidRenewNo, |c| {
                c.renew_no = 7
            }),
            ("no pow", ClaimsError::InvalidPow, |c| c.pow = None),
            ("v1 alg", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().alg = SealedChallengeClaims::POW_ALG_V1.into()
            }),
            ("k 0", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().k = 0
            }),
            ("k 9", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().k = 9
            }),
            ("difficulty 33", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().difficulty = 33
            }),
            ("a11y_difficulty 33", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().a11y_difficulty = 33
            }),
            ("lifetime 600.001 s", ClaimsError::InvalidLifetime, |c| {
                c.exp_ms = c.iat_ms + 600_001
            }),
            ("15-byte jkt", ClaimsError::InvalidJktBinding, |c| {
                c.bind.jkt = Some(vec![7; 15])
            }),
        ];
        for (name, want, mutate) in cases {
            let mut c = interactive();
            mutate(&mut c);
            assert_eq!(c.check(NOW), Err(want), "{name}");
        }
        // Boundaries that pass.
        let passing: [fn(&mut SealedChallengeClaims); 8] = [
            |c| c.providers = vec![ProviderId::PowA11y],
            |c| {
                c.providers = vec![
                    ProviderId::Turnstile,
                    ProviderId::PowA11y,
                    ProviderId::SelfHold,
                ]
            },
            |c| c.renew_no = SealedChallengeClaims::MAX_RENEW_NO,
            |c| c.pow.as_mut().unwrap().k = 1,
            |c| {
                let p = c.pow.as_mut().unwrap();
                p.difficulty = 32;
                p.a11y_difficulty = 32;
            },
            |c| c.exp_ms = c.iat_ms + 600_000,
            |c| c.bind.jkt = Some(vec![7; 16]),
            |c| c.ui_seed = u64::MAX,
        ];
        for (i, mutate) in passing.iter().enumerate() {
            let mut c = interactive();
            mutate(&mut c);
            assert_eq!(c.check(NOW), Ok(()), "{i}");
        }
    }

    /// Phase 2 spec §6.2: one counterexample per invisible / pow rule.
    #[test]
    fn non_interactive_phase2_rules() {
        let cases: [Case; 8] = [
            ("ui_seed", ClaimsError::InvalidUiSeed, |c| c.ui_seed = 1),
            ("renew_no", ClaimsError::InvalidRenewNo, |c| c.renew_no = 1),
            ("no pow", ClaimsError::InvalidPow, |c| c.pow = None),
            ("v2 alg", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().alg = SealedChallengeClaims::POW_ALG_V2.into()
            }),
            ("k", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().k = 1
            }),
            ("a11y_difficulty", ClaimsError::InvalidPow, |c| {
                c.pow.as_mut().unwrap().a11y_difficulty = 1
            }),
            ("lifetime 120.001 s", ClaimsError::InvalidLifetime, |c| {
                c.exp_ms = c.iat_ms + 120_001
            }),
            ("32-byte jkt", ClaimsError::InvalidJktBinding, |c| {
                c.bind.jkt = Some(vec![7; 32])
            }),
        ];
        for ty in [ChallengeType::Invisible, ChallengeType::Pow] {
            for (name, want, mutate) in &cases {
                let mut c = pow();
                c.challenge_type = ty;
                mutate(&mut c);
                assert_eq!(c.check(NOW), Err(want.clone()), "{ty} {name}");
            }
            let mut c = pow();
            c.challenge_type = ty;
            c.exp_ms = c.iat_ms + 120_000;
            c.bind.jkt = Some(vec![7; 16]);
            assert_eq!(c.check(NOW), Ok(()), "{ty}");
        }
    }

    #[test]
    fn lifetimes_and_expiry() {
        let mut c = pow();
        c.exp_ms = c.iat_ms + SealedChallengeClaims::MAX_NON_INTERACTIVE_LIFETIME_MS + 1;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidLifetime));
        c.exp_ms = c.iat_ms;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidLifetime));

        let mut c = interactive();
        c.exp_ms = c.iat_ms + SealedChallengeClaims::MAX_INTERACTIVE_LIFETIME_MS + 1;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidLifetime));

        let c = pow();
        assert_eq!(c.check(c.exp_ms), Err(ClaimsError::Expired));
        assert_eq!(c.check(c.exp_ms - 1), Ok(()));

        let mut c = pow();
        c.iat_ms = NOW + SealedChallengeClaims::MAX_CLOCK_SKEW_MS + 1;
        c.exp_ms = c.iat_ms + 60_000;
        assert_eq!(c.check(NOW), Err(ClaimsError::NotYetValid));

        // Extreme values saturate instead of overflowing.
        let mut c = pow();
        c.iat_ms = i64::MIN;
        c.exp_ms = i64::MAX;
        assert_eq!(c.check(NOW), Err(ClaimsError::InvalidLifetime));
    }

    #[test]
    fn uah_binding_is_required_and_presence_aware() {
        let mut c = interactive();
        c.bind.uah = None;
        assert_eq!(c.check(NOW), Err(ClaimsError::MissingUahBinding));
        // Unknown client IP: no ipp binding, still valid (soft binding).
        let mut c = interactive();
        c.bind.ipp = None;
        assert_eq!(c.check(NOW), Ok(()));
        // Present-but-empty differs from absent.
        let mut a = interactive();
        a.bind.jkt = Some(vec![]);
        assert_ne!(a, interactive());
    }

    #[test]
    fn debug_never_shows_the_nonce() {
        let s = format!("{:?}", interactive());
        assert!(!s.contains("nonce") && !s.contains("90, 90"), "{s}");
        assert!(s.contains("route_class: \"login\""));
    }
}
