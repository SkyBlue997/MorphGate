//! SDK session public keys (docs/impl/phase2-spec.md §6.5): the strict
//! four-member P-256 JWK, its RFC 7638 thumbprint `jkt` (43 characters) and
//! ES256 verification of 64-byte `r || s` signatures through `aws-lc-rs`
//! (`signature::ECDSA_P256_SHA256_FIXED`).
//!
//! * The JWK has **exactly** the members `kty = "EC"`, `crv = "P-256"`, `x`
//!   and `y`; `x` and `y` are unpadded base64url of 32 bytes each. Any other
//!   member (WebCrypto's `ext`, `key_ops`, …) is rejected, as are duplicates.
//! * `jkt = base64url_nopad(SHA-256('{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}'))`.
//! * Whether the point lies on the curve is checked when verifying: an
//!   invalid point fails exactly like an invalid signature.
//! * Signatures are the 64-byte IEEE P1363 `r || s` that WebCrypto produces,
//!   as 86 characters of unpadded base64url. DER is rejected; a high `s` is
//!   accepted (WebCrypto does not normalize it, and the signature is never
//!   used as an identifier).
//!
//! The production path only verifies; it never holds a private key. The
//! public key and its thumbprint identify a browser session, so neither is
//! printed by `Debug` (spec §2.4 item 10).

use crate::b64;
use crate::json::ObjectOnly;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

/// Length of a thumbprint `jkt`: 32 bytes of unpadded base64url.
pub const JKT_LEN: usize = 43;
/// Length of an ES256 signature in unpadded base64url (64 bytes).
pub const ES256_SIG_B64_LEN: usize = 86;
/// Longest JWK text [`SessionKey::from_jwk_json`] reads; a valid one is
/// about 130 bytes.
pub const MAX_JWK_JSON_LEN: usize = 1024;

const COORD_LEN: usize = 32;

/// The JWK object as received (§6.5): exactly these four members, all
/// strings. Embed it in a request body struct and convert it with
/// [`SessionKey::from_jwk`]; the member values are checked there.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jwk(..)")
    }
}

/// Why a JWK was rejected. Never carries the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwkError {
    /// Longer than [`MAX_JWK_JSON_LEN`], not JSON, not an object, a missing,
    /// duplicate, non-string or unknown member.
    #[error("JWK is not a JSON object with exactly kty, crv, x and y")]
    Json,
    #[error("JWK kty is not EC")]
    Kty,
    #[error("JWK crv is not P-256")]
    Crv,
    /// `x` or `y` is not 32 bytes of canonical unpadded base64url.
    #[error("JWK coordinate is not 32 bytes of unpadded base64url")]
    Coordinate,
}

/// A session public key: the uncompressed point `0x04 ‖ x ‖ y` and its
/// thumbprint. Constructing one does not check that the point is on the
/// curve; [`SessionKey::verify_es256`] does.
#[derive(Clone)]
pub struct SessionKey {
    point: [u8; 65],
    jkt: String,
}

impl SessionKey {
    /// Parses a JWK object (§6.5, strict members).
    pub fn from_jwk_json(json: &[u8]) -> Result<Self, JwkError> {
        if json.len() > MAX_JWK_JSON_LEN {
            return Err(JwkError::Json);
        }
        let ObjectOnly(jwk) =
            serde_json::from_slice::<ObjectOnly<Jwk>>(json).map_err(|_| JwkError::Json)?;
        Self::from_jwk(&jwk)
    }

    /// Checks the member values of a parsed [`Jwk`].
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, JwkError> {
        if jwk.kty != "EC" {
            return Err(JwkError::Kty);
        }
        if jwk.crv != "P-256" {
            return Err(JwkError::Crv);
        }
        let x = b64::decode_array::<COORD_LEN>(&jwk.x).ok_or(JwkError::Coordinate)?;
        let y = b64::decode_array::<COORD_LEN>(&jwk.y).ok_or(JwkError::Coordinate)?;
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        Ok(Self {
            point,
            jkt: jwk_thumbprint(&jwk.x, &jwk.y),
        })
    }

    /// The RFC 7638 thumbprint `jkt`, 43 characters.
    pub fn thumbprint(&self) -> &str {
        &self.jkt
    }

    /// Whether the thumbprint equals `jkt`, in constant time.
    pub fn thumbprint_eq(&self, jkt: &str) -> bool {
        jkt_eq(&self.jkt, jkt)
    }

    /// The uncompressed point `0x04 ‖ x ‖ y`.
    pub fn point(&self) -> &[u8; 65] {
        &self.point
    }

    /// Verifies an ES256 signature over `msg`: `sig_b64url` must be 86
    /// characters of unpadded base64url decoding to the 64-byte `r || s`.
    /// False for any malformed signature and for a point not on the curve.
    pub fn verify_es256(&self, msg: &[u8], sig_b64url: &str) -> bool {
        if sig_b64url.len() != ES256_SIG_B64_LEN {
            return false;
        }
        b64::decode_array::<64>(sig_b64url).is_some_and(|sig| self.verify_raw(msg, &sig))
    }

    /// Verifies decoded signature bytes; false unless they are 64 bytes.
    pub(crate) fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        sig.len() == 64
            && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.point)
                .verify(msg, sig)
                .is_ok()
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// The RFC 7638 thumbprint of a P-256 key from the text of its `x` and `y`
/// members: `base64url_nopad(SHA-256('{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}'))`.
/// Only hashes; it neither decodes nor checks the coordinates (`MG-Proof`
/// step 3 compares it before any curve operation). The members are inserted
/// as given, so callers pass base64url text, which needs no JSON escaping.
pub fn jwk_thumbprint(x: &str, y: &str) -> String {
    let mut h = Sha256::new();
    h.update(br#"{"crv":"P-256","kty":"EC","x":""#);
    h.update(x.as_bytes());
    h.update(br#"","y":""#);
    h.update(y.as_bytes());
    h.update(br#""}"#);
    b64::encode(&h.finalize())
}

/// Constant-time comparison of two thumbprints (or any short strings).
pub(crate) fn jkt_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Whether `s` has the shape of a thumbprint: 43 characters of canonical
/// unpadded base64url (32 bytes).
pub fn is_jkt(s: &str) -> bool {
    s.len() == JKT_LEN && b64::decode_array::<32>(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "rrXA79fsqDJ_SXUTgnEyOO__YXLSTtRXSSJhNH9YKH0";
    const Y: &str = "fy_r8gTN8v7j6GHSFRr_lW7pGX4MxTFboW1NVnc6-PA";

    fn json(members: &str) -> Vec<u8> {
        format!("{{{members}}}").into_bytes()
    }

    #[test]
    fn strict_members() {
        let ok = format!(r#""kty":"EC","crv":"P-256","x":"{X}","y":"{Y}""#);
        let key = SessionKey::from_jwk_json(&json(&ok)).unwrap();
        assert_eq!(
            key.thumbprint(),
            "L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc"
        );
        assert!(key.thumbprint_eq("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc"));
        assert!(!key.thumbprint_eq("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOd"));
        assert!(!key.thumbprint_eq(""));
        assert_eq!(key.point()[0], 4);
        // Member order does not matter.
        let reordered = format!(r#""y":"{Y}","x":"{X}","crv":"P-256","kty":"EC""#);
        assert!(SessionKey::from_jwk_json(&json(&reordered)).is_ok());

        let cases: [(String, JwkError); 12] = [
            (format!(r#"{ok},"ext":true"#), JwkError::Json),
            (format!(r#"{ok},"key_ops":["verify"]"#), JwkError::Json),
            (format!(r#"{ok},"x":"{X}""#), JwkError::Json),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{X}""#),
                JwkError::Json,
            ),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{X}","y":null"#),
                JwkError::Json,
            ),
            (
                format!(r#""kty":"RSA","crv":"P-256","x":"{X}","y":"{Y}""#),
                JwkError::Kty,
            ),
            (
                format!(r#""kty":"EC","crv":"P-384","x":"{X}","y":"{Y}""#),
                JwkError::Crv,
            ),
            (
                format!(r#""kty":"ec","crv":"P-256","x":"{X}","y":"{Y}""#),
                JwkError::Kty,
            ),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{}","y":"{Y}""#, &X[..42]),
                JwkError::Coordinate,
            ),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{X}=","y":"{Y}""#),
                JwkError::Coordinate,
            ),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{X}","y":"{}+""#, &Y[..42]),
                JwkError::Coordinate,
            ),
            (
                format!(r#""kty":"EC","crv":"P-256","x":"{X}A","y":"{Y}""#),
                JwkError::Coordinate,
            ),
        ];
        for (members, want) in cases {
            assert_eq!(
                SessionKey::from_jwk_json(&json(&members)).unwrap_err(),
                want,
                "{members}"
            );
        }
        for bad in [&b"[]"[..], b"null", b"", b"{}", b"\"x\""] {
            assert_eq!(SessionKey::from_jwk_json(bad).unwrap_err(), JwkError::Json);
        }
        let mut long = json(&ok);
        long.extend(std::iter::repeat_n(b' ', MAX_JWK_JSON_LEN));
        assert_eq!(
            SessionKey::from_jwk_json(&long).unwrap_err(),
            JwkError::Json
        );
    }

    #[test]
    fn signature_shapes() {
        let ok = format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#);
        let key = SessionKey::from_jwk_json(ok.as_bytes()).unwrap();
        let zero = b64::encode(&[0u8; 64]);
        assert_eq!(zero.len(), ES256_SIG_B64_LEN);
        assert!(!key.verify_es256(b"m", &zero));
        assert!(!key.verify_es256(b"m", ""));
        assert!(!key.verify_es256(b"m", &b64::encode(&[1u8; 63])));
        assert!(!key.verify_es256(b"m", &"A".repeat(ES256_SIG_B64_LEN)));
        assert!(!key.verify_raw(b"m", &[1u8; 72]));
    }

    #[test]
    fn debug_prints_nothing_identifying() {
        let ok = format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#);
        let key = SessionKey::from_jwk_json(ok.as_bytes()).unwrap();
        assert_eq!(format!("{key:?}"), "SessionKey(..)");
        let jwk: Jwk = serde_json::from_str(&ok).unwrap();
        assert_eq!(format!("{jwk:?}"), "Jwk(..)");
    }

    #[test]
    fn thumbprint_shape() {
        assert!(is_jkt("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc"));
        assert!(!is_jkt("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxO"));
        assert!(!is_jkt("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxO="));
        assert!(
            !is_jkt("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOd"),
            "trailing bits"
        );
        assert_eq!(jwk_thumbprint(X, Y).len(), JKT_LEN);
    }
}
