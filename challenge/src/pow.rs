//! SHA-256 hashcash proof of work (spec §6.3).
//!
//! ```text
//! prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(C as ASCII)            (42 bytes)
//! digest = SHA-256(prefix ‖ u64be(counter))
//! solved iff leading_zero_bits(digest) >= difficulty
//! ```
//!
//! The Web SDK searches counters in a Worker (WP-W1, same `kat.json`
//! vectors); the Edge only verifies one counter per submission.

use sha2::{Digest, Sha256};

/// Algorithm name sealed into `C` and sent to the client.
pub const POW_ALG: &str = "sha256-hashcash-v1";
/// Largest difficulty the protocol allows (bundles restrict it to 8–24).
pub const MAX_POW_BITS: u32 = 32;
/// Counters must be below 2^53 (a JavaScript safe integer).
pub const MAX_POW_COUNTER: u64 = 1 << 53;

const POW_DOMAIN: &[u8] = b"mg-pow-v1";

/// `"mg-pow-v1" ‖ 0x00 ‖ SHA-256(c)`.
pub fn pow_prefix(c: &str) -> [u8; 42] {
    let mut prefix = [0u8; 42];
    prefix[..POW_DOMAIN.len()].copy_from_slice(POW_DOMAIN);
    // prefix[9] stays 0x00, the separator.
    prefix[POW_DOMAIN.len() + 1..].copy_from_slice(&Sha256::digest(c.as_bytes()));
    prefix
}

/// Number of leading zero bits of a digest (0–256).
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &b in digest {
        if b != 0 {
            return bits + b.leading_zeros();
        }
        bits += 8;
    }
    bits
}

/// Whether `counter` solves `c` at `difficulty`. False for `difficulty > 32`
/// or `counter >= 2^53`.
pub fn pow_verify(c: &str, difficulty: u32, counter: u64) -> bool {
    if difficulty > MAX_POW_BITS || counter >= MAX_POW_COUNTER {
        return false;
    }
    let mut h = prefixed_hasher(c);
    h.update(counter.to_be_bytes());
    leading_zero_bits(&h.finalize().into()) >= difficulty
}

/// Reference solver for tests: the smallest counter below
/// `min(max_iterations, 2^53)` that solves `c`, if any. Never called on a
/// request path.
#[doc(hidden)]
pub fn pow_solve(c: &str, difficulty: u32, max_iterations: u64) -> Option<u64> {
    if difficulty > MAX_POW_BITS {
        return None;
    }
    let base = prefixed_hasher(c);
    (0..max_iterations.min(MAX_POW_COUNTER)).find(|counter| {
        let mut h = base.clone();
        h.update(counter.to_be_bytes());
        leading_zero_bits(&h.finalize().into()) >= difficulty
    })
}

fn prefixed_hasher(c: &str) -> Sha256 {
    let mut h = Sha256::new();
    h.update(pow_prefix(c));
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bit_counts() {
        let mut d = [0u8; 32];
        assert_eq!(leading_zero_bits(&d), 256);
        d[0] = 0x80;
        assert_eq!(leading_zero_bits(&d), 0);
        d[0] = 0x01;
        assert_eq!(leading_zero_bits(&d), 7);
        d[0] = 0;
        d[2] = 0x10;
        assert_eq!(leading_zero_bits(&d), 19);
    }

    #[test]
    fn verify_bounds() {
        // Difficulty 0 accepts any in-range counter.
        assert!(pow_verify("c", 0, 0));
        assert!(pow_verify("c", 0, MAX_POW_COUNTER - 1));
        assert!(!pow_verify("c", 0, MAX_POW_COUNTER));
        assert!(!pow_verify("c", 0, u64::MAX));
        assert!(!pow_verify("c", MAX_POW_BITS + 1, 0));
        assert_eq!(pow_solve("c", MAX_POW_BITS + 1, 10), None);
        assert_eq!(pow_solve("c", 0, 0), None, "no iterations, no answer");
        assert_eq!(pow_solve("c", 0, 1), Some(0));
    }

    #[test]
    fn solve_and_verify_agree() {
        for c in ["a", "b", "AAECAwQ", "mg-test-c-1"] {
            let counter = pow_solve(c, 10, 1 << 16).unwrap();
            assert!(pow_verify(c, 10, counter));
            assert!(
                (0..counter).all(|n| !pow_verify(c, 10, n)),
                "smallest counter"
            );
        }
    }
}
