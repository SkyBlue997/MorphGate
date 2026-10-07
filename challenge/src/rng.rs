//! Injected randomness (spec §6.7, §2.4 item 6).
//!
//! `mg-challenge` never reads a global RNG: the `xnonce` and `nonce` of a
//! sealed challenge and the `sub` / `jti` of a clearance token come from the
//! caller's [`Rng`]. `mg-edge` implements it over the OS CSPRNG
//! (`getrandom`); deterministic generators exist only in tests.

use std::fmt;

/// The random number generator could not produce bytes. Returned, never
/// panicked on: the Edge answers 503 (spec §9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("random number generator failed")
    }
}

impl std::error::Error for RngError {}

/// Source of cryptographically secure random bytes.
///
/// Production implementations are backed by the OS CSPRNG (mg-edge:
/// getrandom). Deterministic test RNGs exist only under `#[cfg(test)]` or in
/// callers' test code. A failure is returned, never a panic; the Edge answers
/// 503 (spec §9.9).
pub trait Rng: Send + Sync {
    /// Fills all of `dst` with random bytes, or fails without a partial result
    /// being used.
    fn fill(&self, dst: &mut [u8]) -> Result<(), RngError>;
}

/// `N` random bytes from `rng`.
pub(crate) fn random_array<const N: usize>(rng: &dyn Rng) -> Result<[u8; N], RngError> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

/// Deterministic generators for this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_rng {
    use super::{Rng, RngError};
    use std::sync::Mutex;

    /// xorshift64*: deterministic, never fails.
    #[derive(Debug)]
    pub(crate) struct XorShift(Mutex<u64>);

    impl XorShift {
        pub(crate) fn new(seed: u64) -> Self {
            Self(Mutex::new(seed.max(1)))
        }
    }

    impl Rng for XorShift {
        fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
            let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
            for b in dst {
                *s ^= *s << 13;
                *s ^= *s >> 7;
                *s ^= *s << 17;
                *b = (s.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
            }
            Ok(())
        }
    }

    /// Always fails.
    #[derive(Debug)]
    pub(crate) struct Failing;

    impl Rng for Failing {
        fn fill(&self, _dst: &mut [u8]) -> Result<(), RngError> {
            Err(RngError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_rng::{Failing, XorShift};
    use super::*;

    #[test]
    fn random_array_propagates_failure() {
        assert_eq!(random_array::<16>(&Failing), Err(RngError));
        let a = random_array::<16>(&XorShift::new(7)).unwrap();
        let b = random_array::<16>(&XorShift::new(7)).unwrap();
        assert_eq!(a, b, "deterministic for a fixed seed");
        assert_ne!(a, [0; 16]);
        assert_eq!(RngError.to_string(), "random number generator failed");
    }
}
