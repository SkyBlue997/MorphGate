//! The OS CSPRNG (§2.4 item 6): request ids, and later the sealed
//! challenge's nonces, clearance token ids and CSP nonces (WP-E1c).
//!
//! Every production random value comes from `getrandom`; a failure is an
//! error the caller turns into a 503 (§9.9), never a panic.

use mg_challenge::{Rng, RngError};

/// [`Rng`] over the operating system's CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(dst).map_err(|_| RngError)
    }
}

/// A request id: 128 random bits as 32 lower-case hex characters (§9.5).
pub fn request_id(rng: &dyn Rng) -> Result<String, RngError> {
    let mut raw = [0u8; 16];
    rng.fill(&mut raw)?;
    Ok(lower_hex(&raw))
}

/// Lower-case hex encoding.
pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Failing;
    impl Rng for Failing {
        fn fill(&self, _dst: &mut [u8]) -> Result<(), RngError> {
            Err(RngError)
        }
    }

    #[test]
    fn request_ids_are_32_lower_hex_and_distinct() {
        let a = request_id(&OsRng).unwrap();
        let b = request_id(&OsRng).unwrap();
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_ne!(a, b);
    }

    #[test]
    fn rng_failure_is_an_error() {
        assert_eq!(request_id(&Failing), Err(RngError));
    }

    #[test]
    fn hex() {
        assert_eq!(lower_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(lower_hex(&[]), "");
    }
}
