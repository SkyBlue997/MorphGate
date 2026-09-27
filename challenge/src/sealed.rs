//! The sealed challenge `C` (spec §6.2, docs/09 §4, ADR-0005).
//!
//! ```text
//! C     = base64url_nopad( prost(SealedChallenge { v: 1, kid, xnonce, ct }) )      len(C) <= 1024
//! ct    = XChaCha20-Poly1305.seal(k_epoch[kid] of roots[0], xnonce,
//!                                 prost(SealedChallengeClaims), aad)
//! aad   = u16be(len(host)) ‖ host ‖ u16be(len(type)) ‖ type ‖ u16be(len(kid)) ‖ kid
//! ```
//!
//! Issuing `C` writes no state; the single-use nonce inside is consumed by
//! the Edge on submission. Opening checks every length before any
//! fixed-size construction and never panics on input.

use crate::b64;
use crate::bind::BIND_HASH_LEN;
use crate::keys::{
    MAX_C_LIFETIME_MS, SealKeys, accepted_epochs, derive_epoch_key, epoch_no, parse_epoch_kid,
};
use crate::pow::{MAX_POW_BITS, POW_ALG};
use crate::rng::{Rng, RngError, random_array};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mg_core::{
    ChallengeBind, ChallengeType, ClaimsError, PowParams, RiskBand, SealedChallengeClaims,
    challenge::ProviderId,
};
use mg_proto::v1::sealed_challenge_claims::{Bind as ProtoBind, Pow as ProtoPow};
use mg_proto::v1::{SealedChallenge, SealedChallengeClaims as ProtoClaims};
use prost::Message;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroizing;

/// Longest accepted `C` (characters of base64url).
pub const MAX_C_LEN: usize = 1024;
/// Longest host name (a DNS name is at most 253 bytes; spec §9.4).
pub const MAX_HOST_LEN: usize = 253;

const ENVELOPE_VERSION: u32 = 1;
const XNONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 16;
/// Derived epoch keys kept per `Sealer`: two epochs × two roots at any time,
/// with room for the seal path.
const CACHE_CAPACITY: usize = 8;

/// Additional data bound to `C`: `u16be(len(host)) ‖ host ‖ u16be(len(type))
/// ‖ type ‖ u16be(len(kid)) ‖ kid`, where `type` is the wire name
/// (`invisible`, `pow`, `interactive`) and `host` the normalized request
/// host (lower-case, no port, no trailing dot; spec §9.4).
///
/// Every part is length-prefixed, so no two `(host, type, kid)` triples
/// share an encoding. Parts longer than 65 535 bytes cannot occur (hosts are
/// at most 253 bytes); their prefix saturates instead of wrapping.
pub fn aad(host: &str, ty: ChallengeType, kid: &str) -> Vec<u8> {
    let ty = ty.as_str();
    let mut out = Vec::with_capacity(6 + host.len() + ty.len() + kid.len());
    for part in [host, ty, kid] {
        let len = u16::try_from(part.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// A fresh 128-bit single-use challenge nonce.
pub fn random_nonce(rng: &dyn Rng) -> Result<[u8; 16], RngError> {
    random_array(rng)
}

/// Seals and opens the challenges of one site.
///
/// Holds the site's seal roots and a small cache of derived epoch keys
/// (`(root index, epoch)`, at most 8 entries, least recently used evicted).
/// Shareable between threads.
pub struct Sealer {
    site: String,
    keys: SealKeys,
    cache: Mutex<Vec<CachedKey>>,
}

struct CachedKey {
    root: usize,
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
}

impl Sealer {
    pub fn new(site_id: &str, keys: SealKeys) -> Self {
        Self {
            site: site_id.to_owned(),
            keys,
            cache: Mutex::new(Vec::with_capacity(CACHE_CAPACITY)),
        }
    }

    /// The site this sealer serves.
    pub fn site_id(&self) -> &str {
        &self.site
    }

    /// Seals `claims` (whose kid must be `epoch_kid(epoch_no(claims.iat_ms))`)
    /// for `host` with `roots[0]`.
    ///
    /// Refuses claims that [`Sealer::open`] would reject: `claims.check` at
    /// `iat_ms` or a lifetime above [`MAX_C_LIFETIME_MS`] for any type
    /// ([`SealError::Invalid`]), another site, a missing or
    /// malformed PoW, `ret` or binding (`uah` and `ipp` are required: no `C`
    /// is issued for an unknown client IP, D-23), or an empty or overlong
    /// host ([`SealError::Shape`]).
    pub fn seal(
        &self,
        claims: &SealedChallengeClaims,
        host: &str,
        rng: &dyn Rng,
    ) -> Result<String, SealError> {
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(SealError::Shape);
        }
        let epoch = parse_epoch_kid(&claims.kid)
            .filter(|&e| e == epoch_no(claims.iat_ms))
            .ok_or(SealError::Kid)?;
        claims.check(claims.iat_ms).map_err(SealError::Invalid)?;
        // The accepted-epoch window (spec §6.1) is sized for this lifetime; a
        // longer-lived C sealed before midnight would become unopenable.
        if claims.exp_ms.saturating_sub(claims.iat_ms) > MAX_C_LIFETIME_MS {
            return Err(SealError::Invalid(ClaimsError::InvalidLifetime));
        }
        if claims.site != self.site || !has_valid_shape(claims) {
            return Err(SealError::Shape);
        }
        let plaintext = Zeroizing::new(to_proto(claims).encode_to_vec());
        let xnonce: [u8; XNONCE_LEN] = random_array(rng).map_err(|_| SealError::Rng)?;
        let key = self.epoch_key(0, epoch);
        let ct = cipher(&key)
            .encrypt(
                &XNonce::from(xnonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad(host, claims.challenge_type, &claims.kid),
                },
            )
            // Only fails for messages beyond the cipher's 256 GiB limit.
            .map_err(|_| SealError::TooLong)?;
        let envelope = SealedChallenge {
            v: ENVELOPE_VERSION,
            kid: claims.kid.clone(),
            xnonce: xnonce.to_vec(),
            ct,
        };
        let c = b64::encode(&envelope.encode_to_vec());
        if c.len() > MAX_C_LEN {
            return Err(SealError::TooLong);
        }
        Ok(c)
    }

    /// Opens `c` submitted for `host` as a `claimed` challenge at `now_ms`
    /// (spec §6.2, steps 1–5 in order; the first failure is returned).
    pub fn open(
        &self,
        c: &str,
        host: &str,
        claimed: ChallengeType,
        now_ms: i64,
    ) -> Result<SealedChallengeClaims, OpenError> {
        // 1. Size, encoding and envelope.
        if c.len() > MAX_C_LEN {
            return Err(OpenError::TooLong);
        }
        let raw = b64::decode(c).ok_or(OpenError::Encoding)?;
        let envelope = SealedChallenge::decode(raw.as_slice()).map_err(|_| OpenError::Envelope)?;
        // prost also accepts unknown, repeated or reordered fields and
        // non-minimal varints. Only the one encoding `seal` writes is a C:
        // the PoW prefix (and in Phase 2 the SDK signature) covers the text
        // of C, so one challenge must not have several accepted spellings.
        if envelope.encoded_len() != raw.len() || envelope.encode_to_vec() != raw {
            return Err(OpenError::Envelope);
        }
        if envelope.v != ENVELOPE_VERSION || envelope.ct.len() < TAG_LEN {
            return Err(OpenError::Envelope);
        }
        let xnonce: [u8; XNONCE_LEN] = envelope
            .xnonce
            .as_slice()
            .try_into()
            .map_err(|_| OpenError::Envelope)?;

        // 2. Epoch.
        let epoch = parse_epoch_kid(&envelope.kid).ok_or(OpenError::Kid)?;
        if !accepted_epochs(now_ms).contains(&epoch) {
            return Err(OpenError::Kid);
        }

        // 3. AEAD under every root, in order. A host that cannot have been
        //    sealed opens under no key.
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(OpenError::Aead);
        }
        let aad = aad(host, claimed, &envelope.kid);
        let nonce = XNonce::from(xnonce);
        let plaintext = (0..self.keys.root_count())
            .find_map(|root| {
                let key = self.epoch_key(root, epoch);
                cipher(&key)
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: &envelope.ct,
                            aad: &aad,
                        },
                    )
                    .ok()
            })
            .map(Zeroizing::new)
            .ok_or(OpenError::Aead)?;

        // 4. Claims: decode, match the envelope and the request, check the shape.
        let proto = ProtoClaims::decode(plaintext.as_slice()).map_err(|_| OpenError::Claims)?;
        let claims = from_proto(proto, |c| {
            c.kid == envelope.kid && c.site == self.site && c.challenge_type == claimed
        })?;
        if !has_valid_shape(&claims) {
            return Err(OpenError::Shape);
        }

        // 5. Structure and expiry.
        claims.check(now_ms).map_err(|e| match e {
            ClaimsError::Expired => OpenError::Expired,
            other => OpenError::Invalid(other),
        })?;
        Ok(claims)
    }

    /// `k_epoch` for `(root, epoch)`, from the cache or freshly derived.
    fn epoch_key(&self, root: usize, epoch: u64) -> Zeroizing<[u8; 32]> {
        // A panic while holding the lock cannot leave the cache inconsistent
        // (entries are only pushed or removed whole), so poisoning is ignored.
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = cache
            .iter()
            .position(|c| c.root == root && c.epoch == epoch)
        {
            let hit = cache.remove(i);
            let key = hit.key.clone();
            cache.push(hit); // most recently used last
            return key;
        }
        let key = Zeroizing::new(derive_epoch_key(
            &self.keys.roots()[root],
            &self.site,
            epoch,
        ));
        if cache.len() >= CACHE_CAPACITY {
            cache.remove(0);
        }
        cache.push(CachedKey {
            root,
            epoch,
            key: key.clone(),
        });
        key
    }

    #[cfg(test)]
    fn cached_entries(&self) -> Vec<(usize, u64)> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.iter().map(|c| (c.root, c.epoch)).collect()
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("site", &self.site)
            .field("roots", &self.keys.root_count())
            .finish_non_exhaustive()
    }
}

/// Why [`Sealer::seal`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("random number generator failed")]
    Rng,
    /// `claims.kid` is not the epoch kid of `claims.iat_ms`.
    #[error("claims kid does not match the epoch of iat")]
    Kid,
    #[error("sealed challenge would exceed 1024 characters")]
    TooLong,
    #[error("claims rejected: {0}")]
    Invalid(ClaimsError),
    /// Another site, missing or malformed PoW / `ret` / binding, or an empty
    /// or overlong host: `open` would reject the result.
    #[error("claims or host do not have the shape of a sealable challenge")]
    Shape,
}

/// Why [`Sealer::open`] rejected a challenge. The client always gets the same
/// answer; [`OpenError::reason_code`] only goes to events.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("challenge longer than 1024 characters")]
    TooLong,
    #[error("challenge is not unpadded base64url")]
    Encoding,
    /// Not a `SealedChallenge` in its canonical encoding, `v != 1`, `xnonce`
    /// not 24 bytes or `ct` shorter than the tag.
    #[error("malformed challenge envelope")]
    Envelope,
    /// Malformed kid or an epoch outside the accepted range.
    #[error("challenge epoch not accepted")]
    Kid,
    #[error("challenge does not open under any key")]
    Aead,
    /// The plaintext is not a `SealedChallengeClaims` this build understands.
    #[error("undecodable challenge claims")]
    Claims,
    /// Length, PoW and binding checks of step 4.
    #[error("challenge claims have the wrong shape")]
    Shape,
    /// Claims kid, site or type differ from the envelope or the request.
    #[error("challenge claims do not match the request")]
    Mismatch,
    #[error("challenge expired")]
    Expired,
    #[error("challenge claims rejected: {0}")]
    Invalid(ClaimsError),
}

impl OpenError {
    /// Internal reason code (spec §6.2): `ic.c_kid`, `ic.c_expired` or
    /// `ic.c_invalid`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Kid => "ic.c_kid",
            Self::Expired => "ic.c_expired",
            Self::TooLong
            | Self::Encoding
            | Self::Envelope
            | Self::Aead
            | Self::Claims
            | Self::Shape
            | Self::Mismatch
            | Self::Invalid(_) => "ic.c_invalid",
        }
    }
}

/// The AEAD keyed with an epoch key. The key is borrowed in place (no
/// unzeroized copy) and the cipher zeroizes its own copy on drop.
fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Step 4 shape checks shared by seal and open: PoW present with the Phase 1
/// algorithm and at most 32 bits, a 16-byte `ret` hash, `uah` and `ipp`
/// bound with 16-byte hashes, every other binding absent or 16 bytes. (The
/// 16-byte nonce is enforced by the native type.)
fn has_valid_shape(c: &SealedChallengeClaims) -> bool {
    let pow_ok = c
        .pow
        .as_ref()
        .is_some_and(|p| p.alg == POW_ALG && p.difficulty <= MAX_POW_BITS);
    let hash = |h: &Option<Vec<u8>>| h.as_ref().is_some_and(|v| v.len() == BIND_HASH_LEN);
    let optional_hash = |h: &Option<Vec<u8>>| h.as_ref().is_none_or(|v| v.len() == BIND_HASH_LEN);
    let b = &c.bind;
    pow_ok
        && c.ret_hash.len() == BIND_HASH_LEN
        && hash(&b.uah)
        && hash(&b.ipp)
        && optional_hash(&b.ipa)
        && optional_hash(&b.ctp)
        && optional_hash(&b.jkt)
        && optional_hash(&b.tfp)
}

fn to_proto(c: &SealedChallengeClaims) -> ProtoClaims {
    ProtoClaims {
        v: c.v,
        kid: c.kid.clone(),
        nonce: c.nonce.to_vec(),
        site: c.site.clone(),
        route_class: c.route_class.clone(),
        r#type: c.challenge_type.to_proto(),
        providers: c.providers.iter().map(|p| p.as_str().to_owned()).collect(),
        risk_band: c.risk_band.as_str().to_owned(),
        attempt_no: c.attempt_no,
        iat: c.iat_ms,
        exp: c.exp_ms,
        ui_seed: c.ui_seed,
        pow: c.pow.as_ref().map(|p| ProtoPow {
            alg: p.alg.clone(),
            difficulty: p.difficulty,
        }),
        ret: c.ret_hash.clone(),
        bind: Some(ProtoBind {
            uah: c.bind.uah.clone(),
            ipp: c.bind.ipp.clone(),
            jkt: c.bind.jkt.clone(),
            ctp: c.bind.ctp.clone(),
            tfp: c.bind.tfp.clone(),
            ipa: c.bind.ipa.clone(),
        }),
    }
}

/// Wire → native, in the order of spec §6.2 step 4: unknown enum numbers,
/// provider ids or risk bands are [`OpenError::Claims`]; then `matches`
/// (kid, site and type against the envelope and the request) or
/// [`OpenError::Mismatch`]; then a nonce that is not 16 bytes is
/// [`OpenError::Shape`] (the remaining shape checks follow in the caller).
fn from_proto(
    p: ProtoClaims,
    matches: impl FnOnce(&Header<'_>) -> bool,
) -> Result<SealedChallengeClaims, OpenError> {
    let challenge_type = ChallengeType::from_proto(p.r#type).ok_or(OpenError::Claims)?;
    let risk_band: RiskBand = p.risk_band.parse().map_err(|_| OpenError::Claims)?;
    let providers = p
        .providers
        .iter()
        .map(|s| s.parse::<ProviderId>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OpenError::Claims)?;
    let header = Header {
        kid: &p.kid,
        site: &p.site,
        challenge_type,
    };
    if !matches(&header) {
        return Err(OpenError::Mismatch);
    }
    let nonce: [u8; NONCE_LEN] = p
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| OpenError::Shape)?;
    let bind = p.bind.unwrap_or_default();
    Ok(SealedChallengeClaims {
        v: p.v,
        kid: p.kid,
        nonce,
        site: p.site,
        route_class: p.route_class,
        challenge_type,
        providers,
        risk_band,
        attempt_no: p.attempt_no,
        iat_ms: p.iat,
        exp_ms: p.exp,
        ui_seed: p.ui_seed,
        pow: p.pow.map(|pow| PowParams {
            alg: pow.alg,
            difficulty: pow.difficulty,
        }),
        ret_hash: p.ret,
        bind: ChallengeBind {
            uah: bind.uah,
            ipp: bind.ipp,
            jkt: bind.jkt,
            ctp: bind.ctp,
            tfp: bind.tfp,
            ipa: bind.ipa,
        },
    })
}

/// The claims fields compared against the envelope and the request.
struct Header<'a> {
    kid: &'a str,
    site: &'a str,
    challenge_type: ChallengeType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{SealRoot, epoch_kid};
    use crate::rng::test_rng::{Failing, XorShift};

    const NOW: i64 = 1_790_596_800_000; // midday of epoch 20724

    fn sealer(site: &str) -> Sealer {
        Sealer::new(
            site,
            SealKeys::new(vec![SealRoot::from_bytes([1; 32])]).unwrap(),
        )
    }

    fn claims() -> SealedChallengeClaims {
        SealedChallengeClaims {
            v: 1,
            kid: epoch_kid(epoch_no(NOW)),
            nonce: [9; 16],
            site: "blog".into(),
            route_class: "login".into(),
            challenge_type: ChallengeType::Pow,
            providers: vec![],
            risk_band: RiskBand::Medium,
            attempt_no: 0,
            iat_ms: NOW,
            exp_ms: NOW + 120_000,
            ui_seed: 0,
            pow: Some(PowParams {
                alg: POW_ALG.into(),
                difficulty: 16,
            }),
            ret_hash: vec![3; 16],
            bind: ChallengeBind {
                uah: Some(vec![4; 16]),
                ipp: Some(vec![5; 16]),
                ..ChallengeBind::default()
            },
        }
    }

    #[test]
    fn round_trip_and_proto_mapping() {
        let s = sealer("blog");
        let mut c = claims();
        c.bind.ipa = Some(vec![6; 16]);
        c.bind.ctp = Some(vec![7; 16]);
        let sealed = s.seal(&c, "example.com", &XorShift::new(1)).unwrap();
        let opened = s
            .open(&sealed, "example.com", ChallengeType::Pow, NOW + 1)
            .unwrap();
        assert_eq!(opened, c);
        assert_eq!(from_proto(to_proto(&c), |_| true).unwrap(), c);
        assert_eq!(
            from_proto(to_proto(&c), |_| false).unwrap_err(),
            OpenError::Mismatch
        );
    }

    #[test]
    fn seal_refuses_what_open_would_reject() {
        let s = sealer("blog");
        let rng = XorShift::new(2);
        let mut c = claims();
        c.kid = epoch_kid(epoch_no(NOW) - 1);
        assert_eq!(s.seal(&c, "example.com", &rng), Err(SealError::Kid));
        let mut c = claims();
        c.exp_ms = c.iat_ms + 120_001;
        assert_eq!(
            s.seal(&c, "example.com", &rng),
            Err(SealError::Invalid(ClaimsError::InvalidLifetime))
        );
        let shapes: [fn(&mut SealedChallengeClaims); 9] = [
            |c| c.site = "shop".into(),
            |c| c.pow = None,
            |c| c.pow.as_mut().unwrap().alg = "sha1".into(),
            |c| c.pow.as_mut().unwrap().difficulty = 33,
            |c| c.ret_hash = vec![3; 15],
            |c| c.bind.ipp = None,
            |c| c.bind.uah = Some(vec![4; 17]),
            |c| c.bind.ipa = Some(vec![]),
            |c| c.bind.tfp = Some(vec![1; 32]),
        ];
        for (i, mutate) in shapes.iter().enumerate() {
            let mut c = claims();
            mutate(&mut c);
            assert_eq!(
                s.seal(&c, "example.com", &rng),
                Err(SealError::Shape),
                "{i}"
            );
        }
        assert_eq!(s.seal(&claims(), "", &rng), Err(SealError::Shape));
        let long_host = "a".repeat(MAX_HOST_LEN + 1);
        assert_eq!(s.seal(&claims(), &long_host, &rng), Err(SealError::Shape));
        assert_eq!(
            s.seal(&claims(), "example.com", &Failing),
            Err(SealError::Rng)
        );
        // A site id long enough to push C over 1024 characters.
        let big = sealer(&"b".repeat(1000));
        let mut c = claims();
        c.site = "b".repeat(1000);
        assert_eq!(big.seal(&c, "example.com", &rng), Err(SealError::TooLong));
    }

    #[test]
    fn epoch_key_cache_is_bounded_lru() {
        let s = sealer("blog");
        let direct = derive_epoch_key(&SealRoot::from_bytes([1; 32]), "blog", 20724);
        assert_eq!(*s.epoch_key(0, 20724), direct);
        assert_eq!(
            *s.epoch_key(0, 20724),
            direct,
            "cache hit returns the same key"
        );
        for e in 0..10 {
            s.epoch_key(0, e);
        }
        let entries = s.cached_entries();
        assert_eq!(entries.len(), CACHE_CAPACITY);
        assert_eq!(entries.last(), Some(&(0, 9)));
        assert!(
            !entries.contains(&(0, 20724)),
            "least recently used evicted"
        );
        s.epoch_key(0, 2);
        assert_eq!(
            s.cached_entries().last(),
            Some(&(0, 2)),
            "hit moves to the back"
        );
    }

    #[test]
    fn aad_is_length_delimited() {
        assert_eq!(
            aad("ab", ChallengeType::Pow, "e1"),
            b"\x00\x02ab\x00\x03pow\x00\x02e1".to_vec()
        );
        assert_ne!(
            aad("a", ChallengeType::Pow, "be1"),
            aad("ab", ChallengeType::Pow, "e1")
        );
        let huge = "h".repeat(70_000);
        assert_eq!(&aad(&huge, ChallengeType::Pow, "e1")[..2], &[0xff, 0xff]);
    }

    #[test]
    fn reason_codes() {
        assert_eq!(OpenError::Kid.reason_code(), "ic.c_kid");
        assert_eq!(OpenError::Expired.reason_code(), "ic.c_expired");
        for e in [
            OpenError::TooLong,
            OpenError::Encoding,
            OpenError::Envelope,
            OpenError::Aead,
            OpenError::Claims,
            OpenError::Shape,
            OpenError::Mismatch,
            OpenError::Invalid(ClaimsError::NotYetValid),
        ] {
            assert_eq!(e.reason_code(), "ic.c_invalid", "{e:?}");
        }
    }

    #[test]
    fn debug_shows_no_key_material() {
        let s = sealer("blog");
        s.epoch_key(0, 1);
        assert_eq!(format!("{s:?}"), "Sealer { site: \"blog\", roots: 1, .. }");
    }
}
