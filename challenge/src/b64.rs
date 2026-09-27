//! Unpadded base64url (RFC 4648 §5), the only binary-to-text encoding used by
//! `C`, clearance tokens and key files (spec §12.0).
//!
//! Decoding is strict: padding, characters outside the URL-safe alphabet and
//! non-zero trailing bits are rejected, so every byte string has exactly one
//! accepted spelling.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

/// Encodes `bytes` as unpadded base64url.
pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded base64url; `None` for anything non-canonical.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Encoded length of `n` bytes without padding.
pub(crate) const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Decodes exactly `N` bytes. The text length is checked first, so oversized
/// input is rejected without decoding it. The intermediate buffer is
/// zeroized, since `N`-byte values are often keys.
pub(crate) fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != encoded_len(N) {
        return None;
    }
    let bytes = Zeroizing::new(decode(s)?);
    bytes.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_round_trip() {
        for n in 0..40 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            let s = encode(&bytes);
            assert_eq!(s.len(), encoded_len(n));
            assert_eq!(decode(&s).as_deref(), Some(bytes.as_slice()));
        }
        let key: [u8; 32] = std::array::from_fn(|i| 0x20 + i as u8);
        let s = encode(&key);
        assert_eq!(s, "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8");
        assert_eq!(decode_array::<32>(&s), Some(key));
    }

    #[test]
    fn rejects_non_canonical_spellings() {
        // Padding, standard alphabet, whitespace, trailing bits.
        for bad in ["AQ==", "AQ=", "+/8", "A Q", "AR", "AQE\n", "é"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        assert_eq!(decode("AQ"), Some(vec![1]));
        // Wrong length for a fixed-size value.
        assert_eq!(decode_array::<16>("AQ"), None);
        assert_eq!(decode_array::<1>("AQ"), Some([1]));
    }
}
