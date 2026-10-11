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
//!
//! Interactive challenges use v2 (Phase 2 spec §6.4, D-43): `k` sub-puzzles
//! (1–8), each of the same difficulty, so the solve time varies less:
//!
//! ```text
//! prefix2  = "mg-pow-v2" ‖ 0x00 ‖ SHA-256(C as ASCII)            (42 bytes)
//! digest_i = SHA-256(prefix2 ‖ u8(i) ‖ u64be(counter_i)),  i = 0 .. k−1
//! solved iff every leading_zero_bits(digest_i) >= d and counter_i < 2^53
//! ```

use sha2::{Digest, Sha256};

/// Algorithm name sealed into `C` and sent to the client.
pub const POW_ALG: &str = "sha256-hashcash-v1";
/// Largest difficulty the protocol allows (bundles restrict it to 8–24).
pub const MAX_POW_BITS: u32 = 32;
/// Counters must be below 2^53 (a JavaScript safe integer).
pub const MAX_POW_COUNTER: u64 = 1 << 53;

/// Algorithm of the interactive PoW (Phase 2 spec §6.4, D-43).
pub const POW_ALG_V2: &str = "sha256-hashcash-v2";
/// Most sub-puzzles of a v2 PoW.
pub const MAX_POW_K: usize = 8;

const POW_DOMAIN: &[u8] = b"mg-pow-v1";
const POW_V2_DOMAIN: &[u8] = b"mg-pow-v2";

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

/// `"mg-pow-v2" ‖ 0x00 ‖ SHA-256(c)` (Phase 2 spec §6.4).
pub fn pow_prefix_v2(c: &str) -> [u8; 42] {
    let mut prefix = [0u8; 42];
    prefix[..POW_V2_DOMAIN.len()].copy_from_slice(POW_V2_DOMAIN);
    // prefix[9] stays 0x00, the separator.
    prefix[POW_V2_DOMAIN.len() + 1..].copy_from_slice(&Sha256::digest(c.as_bytes()));
    prefix
}

/// `SHA-256(prefix2 ‖ u8(i) ‖ u64be(counter))`: the digest of sub-puzzle `i`
/// of a v2 PoW (a 51-byte message).
pub fn pow_digest_v2(prefix2: &[u8; 42], i: u8, counter: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix2);
    h.update([i]);
    h.update(counter.to_be_bytes());
    h.finalize().into()
}

/// Whether `counters` solve the v2 PoW of `c` at `difficulty` (Phase 2 spec
/// §6.4): `counters[i]` solves sub-puzzle `i` and every counter is below
/// 2^53. False when `counters.len()` is not in `1..=8` or `difficulty > 32`.
/// The caller compares `counters.len()` with the sealed `pow.k` (`ic.pow`)
/// and picks the difficulty by the submitted provider.
pub fn pow_verify_v2(c: &str, difficulty: u32, counters: &[u64]) -> bool {
    if !(1..=MAX_POW_K).contains(&counters.len())
        || difficulty > MAX_POW_BITS
        || counters.iter().any(|&n| n >= MAX_POW_COUNTER)
    {
        return false;
    }
    let prefix = pow_prefix_v2(c);
    counters
        .iter()
        .zip(0u8..)
        .all(|(&counter, i)| leading_zero_bits(&pow_digest_v2(&prefix, i, counter)) >= difficulty)
}

/// Reference solver for tests: for each of the `k` sub-puzzles the smallest
/// counter below `min(max_iterations, 2^53)` (the canonical solution of the
/// known-answer vectors); `None` if a sub-puzzle has none, `k` is not in
/// `1..=8` or `difficulty > 32`. `max_iterations` bounds each sub-puzzle.
/// Never called on a request path.
#[doc(hidden)]
pub fn pow_solve_v2(c: &str, difficulty: u32, k: usize, max_iterations: u64) -> Option<Vec<u64>> {
    if !(1..=MAX_POW_K).contains(&k) || difficulty > MAX_POW_BITS {
        return None;
    }
    let prefix = pow_prefix_v2(c);
    (0..k)
        .zip(0u8..)
        .map(|(_, i)| {
            (0..max_iterations.min(MAX_POW_COUNTER))
                .find(|&n| leading_zero_bits(&pow_digest_v2(&prefix, i, n)) >= difficulty)
        })
        .collect()
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
    fn v2_bounds() {
        assert_eq!(&pow_prefix_v2("c")[..10], b"mg-pow-v2\0");
        assert_eq!(pow_prefix_v2("c")[10..], pow_prefix("c")[10..]);
        assert!(pow_verify_v2("c", 0, &[0]));
        assert!(pow_verify_v2("c", 0, &[0; MAX_POW_K]));
        assert!(!pow_verify_v2("c", 0, &[]), "no counters");
        assert!(!pow_verify_v2("c", 0, &[0; MAX_POW_K + 1]), "k = 9");
        assert!(!pow_verify_v2("c", 0, &[0, MAX_POW_COUNTER]));
        assert!(pow_verify_v2("c", 0, &[0, MAX_POW_COUNTER - 1]));
        assert!(!pow_verify_v2("c", MAX_POW_BITS + 1, &[0]));
        assert_eq!(pow_solve_v2("c", 0, 0, 10), None);
        assert_eq!(pow_solve_v2("c", 0, MAX_POW_K + 1, 10), None);
        assert_eq!(pow_solve_v2("c", MAX_POW_BITS + 1, 1, 10), None);
        assert_eq!(pow_solve_v2("c", 0, 3, 1), Some(vec![0, 0, 0]));
        assert_eq!(pow_solve_v2("c", 8, 2, 0), None);
    }

    #[test]
    fn v2_solve_and_verify_agree() {
        for c in ["a", "mg-test-c-1"] {
            let counters = pow_solve_v2(c, 8, 4, 1 << 16).unwrap();
            assert!(pow_verify_v2(c, 8, &counters));
            let prefix = pow_prefix_v2(c);
            for (i, &n) in counters.iter().enumerate() {
                let i = i as u8;
                assert!((0..n).all(|m| leading_zero_bits(&pow_digest_v2(&prefix, i, m)) < 8));
            }
            // Sub-puzzles are ordered: swapping two different counters fails
            // unless both happen to solve both positions.
            let mut swapped = counters.clone();
            swapped.reverse();
            if swapped != counters {
                let ok = pow_verify_v2(c, 8, &swapped);
                let both = (0..4)
                    .all(|i| leading_zero_bits(&pow_digest_v2(&prefix, i as u8, swapped[i])) >= 8);
                assert_eq!(ok, both);
            }
            // A v1 solution is not a v2 solution of the same C in general.
            assert!(!pow_verify_v2(c, 30, &counters));
        }
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
