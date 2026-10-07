//! Binding hashes, the return path and binding comparison (spec §6.4).
//!
//! A challenge `C` and a clearance token carry the same bindings, computed
//! from the request that earned them and compared against the request that
//! presents them:
//!
//! | kind  | value                                   | strength |
//! |-------|-----------------------------------------|----------|
//! | `uah` | `family/major` of `mg_core::ua::parse`  | hard |
//! | `ipp` | `Net::prefix_of(ip)` (`/24`, `/48`)     | soft, always bound (D-23) |
//! | `ipa` | ASN in decimal, only when known and ≠ 0 | decides soft vs hard `ipp` |
//! | `ctp` | `version|cipher|ciphers_sha1|bucket`    | shadow, recorded only |
//!
//! `bind_hash(kind, value) = SHA-256("mg-bind-v1" ‖ 0x00 ‖ kind ‖ 0x00 ‖
//! value)[0..16]`. The hashes of small value spaces (an IP prefix, an ASN)
//! are easily reversed, so they are treated like the values themselves and
//! never printed.

use mg_core::{BindResult, ChallengeBind, TokenBind};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

/// Length of every binding hash and of the `ret` hash.
pub const BIND_HASH_LEN: usize = 16;
/// Longest accepted return path.
pub const MAX_RET_LEN: usize = 512;

const BIND_DOMAIN: &[u8] = b"mg-bind-v1";
const RET_DOMAIN: &[u8] = b"mg-ret-v1";
/// `ctp` buckets the ClientHello length by 64 bytes, capped at 31.
const CTP_MAX_BUCKET: u32 = 31;

/// `SHA-256("mg-bind-v1" ‖ 0x00 ‖ kind ‖ 0x00 ‖ value)[0..16]`.
pub fn bind_hash(kind: &str, value: &str) -> [u8; 16] {
    truncated_sha256(&[BIND_DOMAIN, &[0], kind.as_bytes(), &[0], value.as_bytes()])
}

/// `uah`: hash of `family/major`, e.g. `chrome/131`.
pub fn uah(ua_family: &str, ua_major: u32) -> [u8; 16] {
    bind_hash("uah", &format!("{ua_family}/{ua_major}"))
}

/// `ipp`: hash of the IP prefix text (`203.0.113.0/24`, `2001:db8:abcd::/48`).
pub fn ipp(prefix: &str) -> [u8; 16] {
    bind_hash("ipp", prefix)
}

/// `ipa`: hash of the ASN, `None` for 0 (GeoLite2 "not found" is unknown,
/// never `hash("0")`).
pub fn ipa(asn: u32) -> Option<[u8; 16]> {
    (asn != 0).then(|| bind_hash("ipa", &asn.to_string()))
}

/// `ctp`: hash of `version|cipher|ciphers_sha1|min(hello_len / 64, 31)`.
pub fn ctp(version: &str, cipher: &str, ciphers_sha1: &str, hello_len: u32) -> [u8; 16] {
    let bucket = (hello_len / 64).min(CTP_MAX_BUCKET);
    bind_hash(
        "ctp",
        &format!("{version}|{cipher}|{ciphers_sha1}|{bucket}"),
    )
}

/// `SHA-256("mg-ret-v1" ‖ 0x00 ‖ ret)[0..16]`, sealed into `C` so the
/// submitted `ret` cannot be swapped (anti open redirect).
pub fn ret_hash(ret: &str) -> [u8; 16] {
    truncated_sha256(&[RET_DOMAIN, &[0], ret.as_bytes()])
}

/// Checks a return path (spec §6.4): starts with `/` but not `//` or `/\`;
/// no `\`, control character (< 0x20, 0x7f) or `#`; at most 512 bytes; and
/// its path (before `?`) is not in the Edge's `/__mg` namespace by
/// [`mg_core::paths::is_reserved`], the same function that decides `/__mg`
/// ownership at the Edge.
pub fn validate_ret(ret: &str) -> Result<(), RetError> {
    if ret.len() > MAX_RET_LEN {
        return Err(RetError::TooLong);
    }
    if !ret.starts_with('/') {
        return Err(RetError::NotRooted);
    }
    if ret.starts_with("//") || ret.starts_with("/\\") {
        return Err(RetError::SchemeRelative);
    }
    for b in ret.bytes() {
        match b {
            b'\\' => return Err(RetError::Backslash),
            b'#' => return Err(RetError::Fragment),
            0..=0x1f | 0x7f => return Err(RetError::ControlChar),
            _ => {}
        }
    }
    let path = ret.split_once('?').map_or(ret, |(p, _)| p);
    if mg_core::paths::is_reserved(path) {
        return Err(RetError::Reserved);
    }
    Ok(())
}

/// Why a return path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RetError {
    #[error("return path longer than 512 bytes")]
    TooLong,
    #[error("return path does not start with '/'")]
    NotRooted,
    #[error("return path starts with '//' or '/\\'")]
    SchemeRelative,
    #[error("return path contains '\\'")]
    Backslash,
    #[error("return path contains a control character")]
    ControlChar,
    #[error("return path contains '#'")]
    Fragment,
    #[error("return path is in the /__mg namespace")]
    Reserved,
}

/// The bindings of the current request. `ipp` is `None` when the client IP
/// is unknown, `ipa` when the ASN is unknown or 0, `ctp` unless the
/// `cloudflare` shadow inputs are all present.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BindInputs {
    pub uah: [u8; 16],
    pub ipp: Option<[u8; 16]>,
    pub ipa: Option<[u8; 16]>,
    pub ctp: Option<[u8; 16]>,
}

impl fmt::Debug for BindInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Presence only: the hashes identify the client.
        f.debug_struct("BindInputs")
            .field("ipp", &self.ipp.is_some())
            .field("ipa", &self.ipa.is_some())
            .field("ctp", &self.ctp.is_some())
            .finish_non_exhaustive()
    }
}

/// Result of comparing sealed or token bindings with the current request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindCheck {
    pub uah: BindResult,
    pub ipp: BindResult,
    /// Shadow only; `None` unless both sides have a `ctp`.
    pub ctp: Option<BindResult>,
}

impl BindCheck {
    /// `uah` or `ipp` is a hard `Mismatch` (a soft `ipp` result is not).
    pub fn hard_failure(&self) -> bool {
        self.uah == BindResult::Mismatch || self.ipp == BindResult::Mismatch
    }

    /// The per-item results for `identity.token.bind`.
    pub fn token_bind(&self) -> TokenBind {
        TokenBind {
            uah: Some(self.uah),
            ipp: Some(self.ipp),
            ctp: self.ctp,
            ..TokenBind::default()
        }
    }
}

/// Compares the bindings sealed into an opened `C` with the current request
/// (spec §6.4). A sealed hash that is absent or not 16 bytes never matches.
pub fn check_challenge_bind(sealed: &ChallengeBind, current: &BindInputs) -> BindCheck {
    let hash = |h: &Option<Vec<u8>>| h.as_deref().and_then(|v| <[u8; 16]>::try_from(v).ok());
    compare(
        &Bound {
            uah: hash(&sealed.uah),
            ipp: hash(&sealed.ipp),
            ipa: hash(&sealed.ipa),
            ctp: hash(&sealed.ctp),
        },
        current,
    )
}

/// Bindings recorded at issuance, decoded.
pub(crate) struct Bound {
    pub(crate) uah: Option<[u8; 16]>,
    pub(crate) ipp: Option<[u8; 16]>,
    pub(crate) ipa: Option<[u8; 16]>,
    pub(crate) ctp: Option<[u8; 16]>,
}

/// The comparison table of spec §6.4, shared by `C` and clearance tokens:
///
/// * `uah`: equal → match, otherwise mismatch.
/// * `ipp`: equal prefix → match. Otherwise (including an unknown current
///   IP): if `ipa` was bound and the current ASN is known, non-zero and
///   equal → soft mismatch, otherwise mismatch.
/// * `ctp`: compared only when both sides have one; recorded, never
///   enforced.
pub(crate) fn compare(bound: &Bound, current: &BindInputs) -> BindCheck {
    let same = |a: &Option<[u8; 16]>, b: &Option<[u8; 16]>| match (a, b) {
        (Some(a), Some(b)) => bool::from(a.ct_eq(b)),
        _ => false,
    };
    let uah = if same(&bound.uah, &Some(current.uah)) {
        BindResult::Match
    } else {
        BindResult::Mismatch
    };
    let ipp = if bound.ipp.is_none() {
        // Never issued without ipp (D-23); a missing one fails closed.
        BindResult::Mismatch
    } else if same(&bound.ipp, &current.ipp) {
        BindResult::Match
    } else if same(&bound.ipa, &current.ipa) {
        BindResult::SoftMismatch
    } else {
        BindResult::Mismatch
    };
    let ctp = match (bound.ctp, current.ctp) {
        (Some(_), Some(_)) if same(&bound.ctp, &current.ctp) => Some(BindResult::Match),
        (Some(_), Some(_)) => Some(BindResult::Mismatch),
        _ => None,
    };
    BindCheck { uah, ipp, ctp }
}

fn truncated_sha256(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipa_zero_is_unknown() {
        assert_eq!(ipa(0), None);
        assert_eq!(ipa(64500), Some(bind_hash("ipa", "64500")));
        assert_ne!(Some(bind_hash("ipa", "0")), ipa(0));
    }

    #[test]
    fn ctp_buckets_hello_length() {
        let h = |len| ctp("TLSv1.3", "TLS_AES_128_GCM_SHA256", "x", len);
        assert_eq!(h(0), bind_hash("ctp", "TLSv1.3|TLS_AES_128_GCM_SHA256|x|0"));
        assert_eq!(h(63), h(0));
        assert_eq!(
            h(64),
            bind_hash("ctp", "TLSv1.3|TLS_AES_128_GCM_SHA256|x|1")
        );
        assert_eq!(h(31 * 64), h(u32::MAX), "capped at 31");
        assert_ne!(h(30 * 64), h(31 * 64));
    }

    #[test]
    fn debug_hides_hashes() {
        let b = BindInputs {
            uah: [0xab; 16],
            ipp: Some([0xcd; 16]),
            ipa: None,
            ctp: None,
        };
        let s = format!("{b:?}");
        assert_eq!(s, "BindInputs { ipp: true, ipa: false, ctp: false, .. }");
    }

    #[test]
    fn token_bind_mapping() {
        let c = BindCheck {
            uah: BindResult::Match,
            ipp: BindResult::SoftMismatch,
            ctp: None,
        };
        let t = c.token_bind();
        assert_eq!(t.uah, Some(BindResult::Match));
        assert_eq!(t.ipp, Some(BindResult::SoftMismatch));
        assert_eq!((t.ctp, t.jkt, t.tfp), (None, None, None));
        assert!(!c.hard_failure());
    }
}
