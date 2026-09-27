//! `IpSet`: a set of IP prefixes with O(log n) membership (spec §7.1).

use std::fmt;
use std::net::IpAddr;

use crate::cidr::{Prefix, mask_v4, mask_v6};
use crate::error::{IntelError, quote};

/// The most entries an [`IpSet`] accepts (spec §7.1).
pub const MAX_IPSET_ENTRIES: usize = 1_000_000;

/// A set of IPv4 and IPv6 prefixes.
///
/// Entries and queries in the IPv4-mapped block (`::ffff:0:0/96`) are
/// normalised to IPv4, so `::ffff:192.0.2.1` and `192.0.2.1` are the same
/// address. Internally the set is two sorted lists of disjoint, non-adjacent
/// inclusive ranges (`u32` for IPv4, `u128` for IPv6); [`IpSet::contains`] is
/// a binary search.
///
/// Every entry must be a canonical network address: `192.0.2.0/24` or a bare
/// address, never `192.0.2.1/24` (spec §12.3, §12.4).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl fmt::Debug for IpSet {
    /// Sizes only: sets can hold a million ranges.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpSet")
            .field("v4_ranges", &self.v4.len())
            .field("v6_ranges", &self.v6.len())
            .finish()
    }
}

impl IpSet {
    /// Builds a set from IP / CIDR strings (used verbatim: no trimming, no
    /// comments). An error names the 1-based index of the first bad entry.
    pub fn parse<'a, I: IntoIterator<Item = &'a str>>(entries: I) -> Result<Self, IntelError> {
        let mut prefixes = Vec::new();
        for (i, entry) in entries.into_iter().enumerate() {
            if i >= MAX_IPSET_ENTRIES {
                return Err(IntelError::TooManyEntries {
                    limit: MAX_IPSET_ENTRIES,
                });
            }
            prefixes.push(parse_entry(i + 1, entry)?);
        }
        Ok(Self::from_prefixes(prefixes))
    }

    /// Builds a set from text: one IP or CIDR per line, `#` starts a comment,
    /// surrounding whitespace and blank lines are ignored (spec §12.4). An
    /// error names the 1-based line number.
    pub fn from_text(text: &str) -> Result<Self, IntelError> {
        let mut prefixes = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let entry = strip_comment(raw);
            if entry.is_empty() {
                continue;
            }
            if prefixes.len() >= MAX_IPSET_ENTRIES {
                return Err(IntelError::TooManyEntries {
                    limit: MAX_IPSET_ENTRIES,
                });
            }
            prefixes.push(parse_entry(i + 1, entry)?);
        }
        Ok(Self::from_prefixes(prefixes))
    }

    /// Builds a set from already validated prefixes.
    pub(crate) fn from_prefixes(prefixes: Vec<Prefix>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for p in prefixes {
            match p {
                Prefix::V4 { addr, len } => v4.push((addr, addr | !mask_v4(len))),
                Prefix::V6 { addr, len } => {
                    let end = addr | !mask_v6(len);
                    // An IPv6 range covering the whole mapped block also
                    // covers every IPv4 address, because queries in that
                    // block are looked up as IPv4. Aligned prefixes shorter
                    // than /96 either contain the block or miss it entirely.
                    if addr <= MAPPED_START && MAPPED_END <= end {
                        v4.push((0, u32::MAX));
                    }
                    v6.push((addr, end));
                }
            }
        }
        Self {
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    /// Whether `ip` (IPv4-mapped addresses as IPv4) is in the set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => lookup(&self.v4, u32::from(a)),
            IpAddr::V6(a) => lookup(&self.v6, u128::from(a)),
        }
    }

    /// The number of disjoint ranges after merging overlapping and adjacent
    /// entries (so two sets with the same addresses have the same length).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// True when the set contains no address.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

const MAPPED_START: u128 = 0xffff_0000_0000;
const MAPPED_END: u128 = 0xffff_ffff_ffff;

fn parse_entry(line: usize, entry: &str) -> Result<Prefix, IntelError> {
    Prefix::parse(entry).map_err(|reason| IntelError::Line {
        line,
        reason: format!("{}: {reason}", quote(entry)),
    })
}

/// The part of a list line before any `#`, without surrounding whitespace.
pub(crate) fn strip_comment(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before, _)| before)
        .trim()
}

/// Sorts and merges overlapping or adjacent inclusive ranges.
fn merge<T: Copy + Ord + Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            // `last.1 + 1 >= start`, written without overflow at the top.
            if last.1 >= start || last.1.succ() == Some(start) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out.shrink_to_fit();
    out
}

fn lookup<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    // First range whose end is >= x; it contains x iff its start is <= x.
    let i = ranges.partition_point(|&(_, end)| end < x);
    ranges.get(i).is_some_and(|&(start, _)| start <= x)
}

trait Step: Sized {
    fn succ(self) -> Option<Self>;
}

impl Step for u32 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl Step for u128 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn set(entries: &[&str]) -> IpSet {
        IpSet::parse(entries.iter().copied()).unwrap()
    }

    /// §7.1: /0 covers the whole family and nothing of the other.
    #[test]
    fn slash_zero() {
        let s = set(&["0.0.0.0/0"]);
        assert!(s.contains(ip("0.0.0.0")));
        assert!(s.contains(ip("255.255.255.255")));
        assert!(s.contains(ip("::ffff:8.8.8.8")));
        assert!(!s.contains(ip("2001:db8::1")));
        assert_eq!(s.len(), 1);

        let s6 = set(&["::/0"]);
        assert!(s6.contains(ip("::")));
        assert!(s6.contains(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
        // ::/0 covers the mapped block, hence every IPv4 address.
        assert!(s6.contains(ip("192.0.2.1")));
    }

    /// §7.1: /32 and /128 match exactly one address.
    #[test]
    fn single_addresses() {
        let s = set(&["192.0.2.7/32", "2001:db8::7/128", "198.51.100.1"]);
        assert!(s.contains(ip("192.0.2.7")));
        assert!(!s.contains(ip("192.0.2.6")));
        assert!(!s.contains(ip("192.0.2.8")));
        assert!(s.contains(ip("2001:db8::7")));
        assert!(!s.contains(ip("2001:db8::6")));
        assert!(!s.contains(ip("2001:db8::8")));
        assert!(s.contains(ip("198.51.100.1")));
        assert_eq!(s.len(), 3);
    }

    /// §7.1: mapped entries and mapped queries are IPv4.
    #[test]
    fn mapped_addresses() {
        let s = set(&["::ffff:192.0.2.0/120"]);
        assert!(s.contains(ip("192.0.2.200")));
        assert!(s.contains(ip("::ffff:192.0.2.200")));
        assert!(!s.contains(ip("192.0.3.0")));
        let s = set(&["192.0.2.0/24"]);
        assert!(s.contains(ip("::ffff:192.0.2.1")));
        // IPv4-compatible (deprecated) addresses are not mapped.
        assert!(!s.contains(ip("::192.0.2.1")));
        // An IPv6 range that only partly overlaps ::/8 but not the mapped
        // block adds no IPv4 addresses.
        let s = set(&["::/97"]);
        assert!(!s.contains(ip("192.0.2.1")));
    }

    /// §7.1: overlapping and adjacent ranges merge; edges stay exact.
    #[test]
    fn merging() {
        let s = set(&[
            "10.0.0.0/25",
            "10.0.0.128/25",
            "10.0.1.0/24",
            "10.0.0.64/26",
            "10.0.3.0/24",
        ]);
        assert_eq!(s.len(), 2);
        assert!(s.contains(ip("10.0.0.0")));
        assert!(s.contains(ip("10.0.1.255")));
        assert!(!s.contains(ip("10.0.2.0")));
        assert!(s.contains(ip("10.0.3.0")));
        assert!(!s.contains(ip("10.0.4.0")));

        // Adjacent at the very top of the address space: no overflow.
        let s = set(&[
            "255.255.255.254/31",
            "255.255.255.0/25",
            "255.255.255.128/25",
        ]);
        assert_eq!(s.len(), 1);
        assert!(s.contains(ip("255.255.255.255")));
        let s = set(&["ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "::/0"]);
        assert_eq!(s.v6.len(), 1);

        // Same content, same set.
        assert_eq!(
            set(&["10.0.0.0/24"]),
            set(&["10.0.0.0/25", "10.0.0.128/25"])
        );
    }

    #[test]
    fn empty() {
        let s = IpSet::from_text("# nothing\n\n   \n").unwrap();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.contains(ip("0.0.0.0")));
        assert!(IpSet::parse(std::iter::empty()).unwrap().is_empty());
    }

    /// §12.4: comments, blank lines, whitespace; errors carry line numbers.
    #[test]
    fn text_format() {
        let s = IpSet::from_text(
            "# head\r\n192.0.2.10  # inline\r\n\t198.51.100.0/28\n\n2001:db8::10\n",
        )
        .unwrap();
        assert!(s.contains(ip("192.0.2.10")));
        assert!(s.contains(ip("198.51.100.15")));
        assert!(!s.contains(ip("198.51.100.16")));
        assert!(s.contains(ip("2001:db8::10")));

        let err = IpSet::from_text("192.0.2.10\n\n# c\n999.1.1.1\n").unwrap_err();
        assert!(matches!(err, IntelError::Line { line: 4, .. }), "{err}");
        let err = IpSet::from_text("198.51.100.1/28\n").unwrap_err();
        assert!(err.to_string().contains("host bits"), "{err}");
        let err = IpSet::parse(["192.0.2.0/24", "x"]).unwrap_err();
        assert!(matches!(err, IntelError::Line { line: 2, .. }), "{err}");
    }

    #[test]
    fn entry_limit() {
        let many = "192.0.2.1\n".repeat(MAX_IPSET_ENTRIES + 1);
        assert!(matches!(
            IpSet::from_text(&many),
            Err(IntelError::TooManyEntries { .. })
        ));
        let exact = "192.0.2.1\n".repeat(MAX_IPSET_ENTRIES);
        assert_eq!(IpSet::from_text(&exact).unwrap().len(), 1);
        let entries = std::iter::repeat_n("192.0.2.1", MAX_IPSET_ENTRIES + 1);
        assert!(matches!(
            IpSet::parse(entries),
            Err(IntelError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn debug_prints_sizes_only() {
        let s = set(&["192.0.2.0/24", "2001:db8::/32"]);
        let d = format!("{s:?}");
        assert!(!d.contains("192"), "{d}");
        assert!(d.contains("v4_ranges: 1"), "{d}");
    }

    /// Randomised cross-check of `contains` against a linear scan of the
    /// input prefixes (deterministic xorshift, §2.4).
    #[test]
    fn matches_linear_scan() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut prefixes = Vec::new();
            for _ in 0..(next() % 20) {
                // Cluster addresses in a small space so ranges overlap.
                let len = (next() % 9) as u8 + 24;
                let addr = (0x0a00_0000 | (next() as u32 & 0x0fff)) & mask_v4(len);
                prefixes.push(Prefix::V4 { addr, len });
                let len6 = (next() % 9) as u8 + 120;
                let addr6 =
                    (0x2001_0db8_u128 << 96 | u128::from(next() as u16 & 0x0fff)) & mask_v6(len6);
                prefixes.push(Prefix::V6 {
                    addr: addr6,
                    len: len6,
                });
            }
            let s = IpSet::from_prefixes(prefixes.clone());
            for _ in 0..200 {
                let a = 0x0a00_0000 | (next() as u32 & 0x1fff);
                let want = prefixes.iter().any(|p| match *p {
                    Prefix::V4 { addr, len } => a & mask_v4(len) == addr,
                    Prefix::V6 { .. } => false,
                });
                assert_eq!(s.contains(IpAddr::V4(a.into())), want);
                let a6 = 0x2001_0db8_u128 << 96 | u128::from(next() as u16 & 0x1fff);
                let want6 = prefixes.iter().any(|p| match *p {
                    Prefix::V6 { addr, len } => a6 & mask_v6(len) == addr,
                    Prefix::V4 { .. } => false,
                });
                assert_eq!(s.contains(IpAddr::V6(a6.into())), want6);
            }
        }
    }
}
