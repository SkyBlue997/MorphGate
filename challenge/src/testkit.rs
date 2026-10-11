//! Test helpers for the Phase 2 client side (docs/impl/phase2-spec.md §17
//! WP-R5): an SDK session key that signs submissions, renewals and
//! `MG-Proof` headers, and the reference v2 PoW solver.
//!
//! Only compiled for this crate's tests and with the `testkit` feature, which
//! the Edge enables for its integration tests (D-59: the interactive
//! integrity checks run in `edge/tests` with these helpers, never in the
//! Validation Lab). Production code never signs: the Edge only verifies.

use crate::b64;
use crate::jwk::{Jwk, SessionKey, jwk_thumbprint};
use crate::sig::{SubmissionFields, renew_message, submission_message};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use sha2::{Digest, Sha256};
use std::fmt;

pub use crate::pow::pow_solve_v2;

/// The order of P-256 minus one, big-endian.
const N_MINUS_1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
];

/// An SDK session key pair (ECDSA P-256) for tests.
pub struct TestSessionKey {
    pair: EcdsaKeyPair,
    x: String,
    y: String,
}

impl TestSessionKey {
    /// The deterministic key of `testdata/phase2/kat.json` `test_keys`:
    /// `d = (SHA-256(label) mod (n − 1)) + 1`, e.g. `mg-phase2-kat-key-0`.
    pub fn from_label(label: &str) -> Self {
        let h: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        let mut d = if h >= N_MINUS_1 {
            sub(&h, &N_MINUS_1)
        } else {
            h
        };
        add_one(&mut d);
        Self::from_scalar(&d)
    }

    /// A fresh random key (OS RNG).
    pub fn generate() -> Self {
        let pair =
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("P-256 key generation");
        Self::from_pair(pair)
    }

    /// A key from its private scalar `d` (big-endian, `1 ≤ d < n`).
    pub fn from_scalar(d: &[u8; 32]) -> Self {
        // RFC 5915 ECPrivateKey without the optional public key, which
        // aws-lc computes: SEQUENCE { 1, OCTET STRING d, [0] prime256v1 }.
        let mut der = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
        der.extend_from_slice(d);
        der.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        let pair = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .expect("valid P-256 private key");
        Self::from_pair(pair)
    }

    fn from_pair(pair: EcdsaKeyPair) -> Self {
        let point = pair.public_key().as_ref().to_vec();
        assert_eq!(point.len(), 65, "uncompressed P-256 point");
        let x = b64::encode(&point[1..33]);
        let y = b64::encode(&point[33..]);
        Self { pair, x, y }
    }

    /// The `x` member (unpadded base64url).
    pub fn x(&self) -> &str {
        &self.x
    }

    /// The `y` member (unpadded base64url).
    pub fn y(&self) -> &str {
        &self.y
    }

    /// The four-member JWK the SDK sends.
    pub fn jwk(&self) -> Jwk {
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }

    /// The JWK as a JSON value, for request bodies.
    pub fn jwk_value(&self) -> serde_json::Value {
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": self.x, "y": self.y})
    }

    /// The JWK as JSON text.
    pub fn jwk_json(&self) -> String {
        self.jwk_value().to_string()
    }

    /// The thumbprint `jkt`.
    pub fn thumbprint(&self) -> String {
        jwk_thumbprint(&self.x, &self.y)
    }

    /// The verifying side of this key.
    pub fn session_key(&self) -> SessionKey {
        SessionKey::from_jwk(&self.jwk()).expect("a generated key has a valid JWK")
    }

    /// An ES256 signature over `msg`: 64-byte `r || s`, unpadded base64url
    /// (randomized, like WebCrypto).
    pub fn sign(&self, msg: &[u8]) -> String {
        b64::encode(self.sign_raw(msg).as_slice())
    }

    /// The 64 raw signature bytes.
    pub fn sign_raw(&self, msg: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), msg)
            .expect("ECDSA signing")
            .as_ref()
            .to_vec()
    }

    /// The `sig` of a `/__mg/c` v2 submission.
    pub fn sign_submission(&self, f: &SubmissionFields<'_>) -> String {
        self.sign(&submission_message(f))
    }

    /// The `sig` of a `/__mg/c/renew` request.
    pub fn sign_renew(&self, c: &str, ts: u64) -> String {
        self.sign(&renew_message(c, ts))
    }

    /// A well-formed `MG-Proof` header value.
    pub fn proof(&self, htm: &str, htu: &str, iat: i64, jti: &[u8; 16]) -> String {
        let header =
            serde_json::json!({"alg": "ES256", "typ": "mg-proof+jwt", "jwk": self.jwk_value()});
        let payload =
            serde_json::json!({"htm": htm, "htu": htu, "iat": iat, "jti": b64::encode(jti)});
        self.sign_jws(&header.to_string(), &payload.to_string())
    }

    /// A compact JWS over arbitrary header and payload JSON text, for
    /// negative tests: `B64(header) "." B64(payload) "." B64(sig)`.
    pub fn sign_jws(&self, header_json: &str, payload_json: &str) -> String {
        let input = format!(
            "{}.{}",
            b64::encode(header_json.as_bytes()),
            b64::encode(payload_json.as_bytes())
        );
        let sig = self.sign(input.as_bytes());
        format!("{input}.{sig}")
    }
}

impl fmt::Debug for TestSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TestSessionKey(..)")
    }
}

/// `a − b` for big-endian 256-bit numbers with `a ≥ b`.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut v = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(v < 0);
        if v < 0 {
            v += 256;
        }
        out[i] = v as u8;
    }
    out
}

/// `d += 1` for a big-endian 256-bit number below `2^256 − 1`.
fn add_one(d: &mut [u8; 32]) {
    for b in d.iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let mut d = [0u8; 32];
        d[31] = 0xff;
        add_one(&mut d);
        assert_eq!((d[30], d[31]), (1, 0));
        assert_eq!(sub(&N_MINUS_1, &N_MINUS_1), [0; 32]);
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut x = [0u8; 32];
        x[30] = 1;
        let y = sub(&x, &one);
        assert_eq!((y[30], y[31]), (0, 0xff));
    }

    #[test]
    fn signs_what_verifies() {
        let k = TestSessionKey::generate();
        let key = k.session_key();
        assert_eq!(key.thumbprint(), k.thumbprint());
        let sig = k.sign(b"hello");
        assert_eq!(sig.len(), crate::jwk::ES256_SIG_B64_LEN);
        assert!(key.verify_es256(b"hello", &sig));
        assert!(!key.verify_es256(b"hellO", &sig));
        assert_eq!(format!("{k:?}"), "TestSessionKey(..)");
    }
}
