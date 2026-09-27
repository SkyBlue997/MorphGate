//! Bit set over [`SignalFamily`], used for `availability_mask` / `expected_mask`.
//!
//! Bit `i` corresponds to the family whose protobuf number is `i`. Bit 0
//! (`Unspecified`) and bits above the last known family are never set, so a
//! mask is always a subset of [`FamilyMask::ALL`].
//!
//! The two masks answer different questions:
//!
//! * `expected`: what this upstream profile *can* supply (e.g. behind
//!   Cloudflare the visitor's own TLS handshake is never visible, so `Tls`
//!   is not expected and its absence is neutral);
//! * `available`: what this request actually carried.
//!
//! In the signal-state terms of docs/03 §3.1: a family outside `expected` is
//! `MISSING` (neutral, not counted in confidence at all); [`FamilyMask::absent`]
//! = expected but not available is the `ABSENT` candidate set, which lowers
//! confidence. Neither is ever treated as human evidence. The masks cannot tell
//! an `ABSENT` family from an expected family that is `MISSING` on this request
//! because an upstream-injected header did not arrive (docs/08 §1.4); the Edge
//! records that distinction per signal in [`crate::SignalState`].

use crate::enums::SignalFamily;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A set of [`SignalFamily`] values packed into a `u32` (JSON: the number).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "u32", into = "u32")]
pub struct FamilyMask(u32);

impl FamilyMask {
    /// No family.
    pub const EMPTY: Self = Self(0);

    /// Every known family (bits 1..=10).
    pub const ALL: Self = Self(Self::known_bits());

    const fn known_bits() -> u32 {
        let mut bits = 0;
        let mut i = 0;
        while i < SignalFamily::ALL.len() {
            bits |= Self::bit(SignalFamily::ALL[i]);
            i += 1;
        }
        bits
    }

    /// The bit for `family`; `0` for `Unspecified`, which is never stored.
    pub const fn bit(family: SignalFamily) -> u32 {
        match family {
            SignalFamily::Unspecified => 0,
            f => 1 << f.to_proto(),
        }
    }

    /// Builds a mask from raw bits, silently dropping bit 0 and unknown bits.
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::known_bits())
    }

    /// Raw bits (the protobuf `uint32` value).
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A mask containing exactly `families`.
    pub const fn of(families: &[SignalFamily]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < families.len() {
            bits |= Self::bit(families[i]);
            i += 1;
        }
        Self(bits)
    }

    /// Whether `family` is in the set. Always `false` for `Unspecified`.
    pub const fn contains(self, family: SignalFamily) -> bool {
        let bit = Self::bit(family);
        bit != 0 && self.0 & bit == bit
    }

    /// Adds `family` (no-op for `Unspecified`).
    pub fn insert(&mut self, family: SignalFamily) {
        self.0 |= Self::bit(family);
    }

    /// Removes `family`.
    pub fn remove(&mut self, family: SignalFamily) {
        self.0 &= !Self::bit(family);
    }

    /// Copy of `self` with `family` added.
    #[must_use]
    pub const fn with(self, family: SignalFamily) -> Self {
        Self(self.0 | Self::bit(family))
    }

    /// Set union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set intersection.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Families in `self` that are not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Families the upstream is expected to supply but this request lacks
    /// (`ABSENT` candidates; see the module docs for the `MISSING` caveat).
    pub const fn absent(available: Self, expected: Self) -> Self {
        expected.difference(available)
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of families in the set.
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Iterates the families in protobuf-number order.
    pub fn iter(self) -> impl Iterator<Item = SignalFamily> {
        SignalFamily::ALL
            .iter()
            .copied()
            .filter(move |&f| self.contains(f))
    }
}

impl From<u32> for FamilyMask {
    fn from(bits: u32) -> Self {
        Self::from_bits_truncate(bits)
    }
}

impl From<FamilyMask> for u32 {
    fn from(mask: FamilyMask) -> Self {
        mask.bits()
    }
}

impl FromIterator<SignalFamily> for FamilyMask {
    fn from_iter<I: IntoIterator<Item = SignalFamily>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl Extend<SignalFamily> for FamilyMask {
    fn extend<I: IntoIterator<Item = SignalFamily>>(&mut self, iter: I) {
        for f in iter {
            self.insert(f);
        }
    }
}

impl fmt::Debug for FamilyMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SignalFamily as F;

    #[test]
    fn bit_index_is_proto_number() {
        assert_eq!(FamilyMask::bit(F::Network), 1 << 1);
        assert_eq!(FamilyMask::bit(F::EdgeTls), 1 << 9);
        assert_eq!(FamilyMask::bit(F::External), 1 << 10);
        assert_eq!(FamilyMask::bit(F::Unspecified), 0);
        assert_eq!(FamilyMask::ALL.bits(), 0b111_1111_1110);
        assert_eq!(FamilyMask::ALL.len(), SignalFamily::ALL.len() - 1);
    }

    #[test]
    fn insert_remove_contains() {
        let mut m = FamilyMask::EMPTY;
        m.insert(F::Tls);
        m.insert(F::Http);
        m.insert(F::Unspecified); // ignored
        assert!(m.contains(F::Tls) && m.contains(F::Http));
        assert!(!m.contains(F::Unspecified));
        assert_eq!(m.len(), 2);
        m.remove(F::Tls);
        assert_eq!(m, FamilyMask::of(&[F::Http]));
        assert!(FamilyMask::EMPTY.is_empty());
    }

    #[test]
    fn truncates_invalid_bits() {
        let m = FamilyMask::from_bits_truncate(u32::MAX);
        assert_eq!(m, FamilyMask::ALL);
        assert_eq!(
            FamilyMask::from_bits_truncate(1).bits(),
            0,
            "bit 0 is Unspecified"
        );
        let json: FamilyMask = serde_json::from_str("4294967295").unwrap();
        assert_eq!(json, FamilyMask::ALL);
    }

    #[test]
    fn absent_is_expected_minus_available() {
        // Behind Cloudflare: TLS is not expected (MISSING), EDGE_TLS is.
        let expected = FamilyMask::of(&[F::Network, F::Http, F::EdgeTls]);
        let available = FamilyMask::of(&[F::Network, F::Http, F::Client]);
        let absent = FamilyMask::absent(available, expected);
        assert_eq!(absent, FamilyMask::of(&[F::EdgeTls]));
        // Families outside `expected` are MISSING, never ABSENT.
        assert!(!absent.contains(F::Tls));
    }

    #[test]
    fn set_algebra_and_iteration() {
        let a: FamilyMask = [F::Network, F::Tls].into_iter().collect();
        let b = FamilyMask::of(&[F::Tls, F::Rate]);
        assert_eq!(
            a.union(b).iter().collect::<Vec<_>>(),
            [F::Network, F::Tls, F::Rate]
        );
        assert_eq!(a.intersection(b), FamilyMask::of(&[F::Tls]));
        assert_eq!(a.difference(b), FamilyMask::of(&[F::Network]));
        assert_eq!(format!("{a:?}"), "{Network, Tls}");
    }

    #[test]
    fn serializes_as_plain_number() {
        let m = FamilyMask::of(&[F::Network, F::Http]);
        assert_eq!(serde_json::to_string(&m).unwrap(), "10");
        assert_eq!(serde_json::from_str::<FamilyMask>("10").unwrap(), m);
    }
}
