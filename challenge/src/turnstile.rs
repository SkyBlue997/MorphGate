//! Turnstile `cData` and the siteverify idempotency key
//! (docs/impl/phase2-spec.md §6.9): an HMAC of the challenge nonce under the
//! epoch binding key, and a UUID-formatted hash of the nonce (with a variant
//! for the retry with the previous secret).
//!
//! ```text
//! k_bind          = derive_bind_epoch_key(root, site_id, epoch of C.kid)     (label "mg-bind-v1")
//! cdata           = base64url_nopad(HMAC-SHA256(k_bind, "mg-ts-cdata-v1" ‖ 0x00 ‖ lp(site_id) ‖ lp(nonce)))
//! idempotency_key = uuid_v4_format(SHA-256("mg-ts-idem-v1" ‖ 0x00 ‖ nonce)[0..16])
//! previous secret : uuid_v4_format(SHA-256("mg-ts-idem-v1" ‖ 0x00 ‖ nonce ‖ 0x01)[0..16])
//! ```
//!
//! Issuing uses `roots[0]`; checking tries every root. Nothing here talks to
//! Cloudflare; the siteverify client is `mg_edge_core::outbound` (WP-C6).

use crate::b64;
use crate::keys::{SealKeys, SealRoot, derive_bind_epoch_key};
use crate::sig::push_lp;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of `cdata`: 32 bytes of unpadded base64url.
pub const CDATA_LEN: usize = 43;

const CDATA_DOMAIN: &[u8] = b"mg-ts-cdata-v1";
const IDEM_DOMAIN: &[u8] = b"mg-ts-idem-v1";

/// The raw HMAC behind `cdata`.
fn cdata_mac(root: &SealRoot, site_id: &str, epoch: u64, nonce: &[u8; 16]) -> [u8; 32] {
    let key = Zeroizing::new(derive_bind_epoch_key(root, site_id, epoch));
    let mut msg = Vec::with_capacity(CDATA_DOMAIN.len() + 1 + 2 + site_id.len() + 2 + 16);
    msg.extend_from_slice(CDATA_DOMAIN);
    msg.push(0);
    push_lp(&mut msg, site_id.as_bytes());
    push_lp(&mut msg, nonce);
    // HMAC accepts keys of any length.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice())
        .expect("HMAC-SHA256 takes a key of any length");
    mac.update(&msg);
    mac.finalize().into_bytes().into()
}

/// The Turnstile `cData` of a challenge (§6.9), 43 characters: the epoch is
/// that of the `C`'s kid, `nonce` its single-use nonce. The Edge issues it
/// with `roots[0]`.
pub fn turnstile_cdata(root: &SealRoot, site_id: &str, epoch: u64, nonce: &[u8; 16]) -> String {
    b64::encode(&cdata_mac(root, site_id, epoch, nonce))
}

/// Whether `cdata` (from a siteverify response) is the `cData` of this
/// challenge under any of the site's roots. Every root is tried and the
/// comparison is constant-time.
pub fn turnstile_cdata_matches(
    keys: &SealKeys,
    site_id: &str,
    epoch: u64,
    nonce: &[u8; 16],
    cdata: &str,
) -> bool {
    let Some(got) = (cdata.len() == CDATA_LEN)
        .then(|| b64::decode_array::<32>(cdata))
        .flatten()
    else {
        return false;
    };
    keys.roots().iter().fold(false, |found, root| {
        let want = cdata_mac(root, site_id, epoch, nonce);
        found | bool::from(want.ct_eq(&got))
    })
}

/// The `idempotency_key` of the siteverify call for a challenge nonce
/// (§6.9, §8.4). `previous_secret` gives the variant for the retry with the
/// previous secret, so Cloudflare does not answer it from the result cached
/// under the first key.
pub fn idempotency_key(nonce: &[u8; 16], previous_secret: bool) -> String {
    let mut h = Sha256::new();
    h.update(IDEM_DOMAIN);
    h.update([0]);
    h.update(nonce);
    if previous_secret {
        h.update([1]);
    }
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    uuid_v4_format(b)
}

/// Sets the version (`0100` in the high bits of byte 6) and variant (`10` in
/// the high bits of byte 8) and prints 8-4-4-4-12 lower-case hex.
fn uuid_v4_format(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_layout() {
        assert_eq!(
            uuid_v4_format([0xff; 16]),
            "ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        assert_eq!(
            uuid_v4_format([0; 16]),
            "00000000-0000-4000-8000-000000000000"
        );
        let k = idempotency_key(&[7; 16], false);
        assert_eq!(k.len(), 36);
        assert_ne!(k, idempotency_key(&[7; 16], true));
    }

    #[test]
    fn cdata_matching() {
        let r1 = SealRoot::from_bytes([1; 32]);
        let r2 = SealRoot::from_bytes([2; 32]);
        let nonce = [9; 16];
        let c1 = turnstile_cdata(&r1, "blog", 5, &nonce);
        let c2 = turnstile_cdata(&r2, "blog", 5, &nonce);
        assert_eq!(c1.len(), CDATA_LEN);
        let both = SealKeys::new(vec![r2.clone(), r1.clone()]).unwrap();
        let only1 = SealKeys::new(vec![r1]).unwrap();
        assert!(turnstile_cdata_matches(&both, "blog", 5, &nonce, &c1));
        assert!(turnstile_cdata_matches(&both, "blog", 5, &nonce, &c2));
        assert!(turnstile_cdata_matches(&only1, "blog", 5, &nonce, &c1));
        assert!(!turnstile_cdata_matches(&only1, "blog", 5, &nonce, &c2));
        assert!(!turnstile_cdata_matches(&only1, "shop", 5, &nonce, &c1));
        assert!(!turnstile_cdata_matches(&only1, "blog", 6, &nonce, &c1));
        assert!(!turnstile_cdata_matches(&only1, "blog", 5, &[8; 16], &c1));
        for bad in ["", "x", &c1[..42], &format!("{c1}A"), &format!("{c1}=")] {
            assert!(
                !turnstile_cdata_matches(&only1, "blog", 5, &nonce, bad),
                "{bad}"
            );
        }
    }
}
