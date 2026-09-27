//! Network prefixes: strict parsing, IPv4-mapped normalisation and the
//! special-purpose ranges that published crawler and Cloudflare ranges must
//! never touch (spec §12.2, §12.3, D-36).

use std::net::{IpAddr, Ipv6Addr};

/// A network prefix with its host bits zero. IPv4-mapped IPv6 prefixes
/// (`::ffff:a.b.c.d/96+n`) are normalised to `V4` with length `n` (spec §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prefix {
    V4 { addr: u32, len: u8 },
    V6 { addr: u128, len: u8 },
}

/// `::ffff:0:0/96`, the IPv4-mapped block.
const MAPPED_BASE: u128 = 0xffff_0000_0000;
const MAPPED_MASK: u128 = !0u128 << 32;

pub(crate) fn mask_v4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

pub(crate) fn mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

impl Prefix {
    /// Parses `addr` or `addr/len`. Rejects host bits, prefix lengths out of
    /// range or written with a sign / leading zeros, zones and surrounding
    /// whitespace. The error is a short reason for the caller to wrap.
    pub(crate) fn parse(s: &str) -> Result<Self, &'static str> {
        let (addr_text, len_text) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = addr_text.parse().map_err(|_| "not an IP address or CIDR")?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len_text {
            None => max,
            Some(l) => parse_len(l, max)?,
        };
        let prefix = match addr {
            IpAddr::V4(a) => {
                let addr = u32::from(a);
                if addr & !mask_v4(len) != 0 {
                    return Err("host bits set (not a canonical network address)");
                }
                Prefix::V4 { addr, len }
            }
            IpAddr::V6(a) => {
                let addr = u128::from(a);
                if addr & !mask_v6(len) != 0 {
                    return Err("host bits set (not a canonical network address)");
                }
                Prefix::V6 { addr, len }
            }
        };
        Ok(prefix.normalized())
    }

    /// Maps prefixes inside `::ffff:0:0/96` to their IPv4 form.
    fn normalized(self) -> Self {
        match self {
            Prefix::V6 { addr, len } if len >= 96 && addr & MAPPED_MASK == MAPPED_BASE => {
                // Truncation keeps exactly the low 32 bits: the IPv4 address.
                let v4 = addr as u32;
                Prefix::V4 {
                    addr: v4,
                    len: len - 96,
                }
            }
            other => other,
        }
    }

    pub(crate) fn len(self) -> u8 {
        match self {
            Prefix::V4 { len, .. } | Prefix::V6 { len, .. } => len,
        }
    }

    pub(crate) fn is_v4(self) -> bool {
        matches!(self, Prefix::V4 { .. })
    }

    /// True when the two prefixes share at least one address. Aligned
    /// prefixes either nest or are disjoint, so this is "one contains the
    /// other".
    pub(crate) fn intersects(self, other: Prefix) -> bool {
        match (self, other) {
            (Prefix::V4 { addr: a, len: la }, Prefix::V4 { addr: b, len: lb }) => {
                (a ^ b) & mask_v4(la.min(lb)) == 0
            }
            (Prefix::V6 { addr: a, len: la }, Prefix::V6 { addr: b, len: lb }) => {
                (a ^ b) & mask_v6(la.min(lb)) == 0
            }
            _ => false,
        }
    }

    /// The first special-purpose range this prefix intersects, if any.
    /// Documentation ranges are skipped when `allow_documentation` is set
    /// (test registries, spec §12.3).
    pub(crate) fn special(self, allow_documentation: bool) -> Option<&'static SpecialRange> {
        SPECIAL_RANGES.iter().find(|r| {
            (!allow_documentation || r.class != SpecialClass::Documentation)
                && self.intersects(r.prefix)
        })
    }
}

/// Parses a prefix length: decimal, no sign, no leading zeros, `<= max`.
fn parse_len(text: &str, max: u8) -> Result<u8, &'static str> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 3
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err("malformed prefix length");
    }
    let len: u8 = text.parse().map_err(|_| "malformed prefix length")?;
    if len > max {
        return Err("prefix length out of range");
    }
    Ok(len)
}

/// Why a range is special.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpecialClass {
    Unspecified,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Cgnat,
    Reserved,
    Documentation,
}

impl SpecialClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SpecialClass::Unspecified => "unspecified",
            SpecialClass::Private => "private",
            SpecialClass::Loopback => "loopback",
            SpecialClass::LinkLocal => "link-local",
            SpecialClass::Multicast => "multicast",
            SpecialClass::Cgnat => "CGNAT",
            SpecialClass::Reserved => "reserved",
            SpecialClass::Documentation => "documentation",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SpecialRange {
    pub(crate) prefix: Prefix,
    pub(crate) text: &'static str,
    pub(crate) class: SpecialClass,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
    Prefix::V4 {
        addr: u32::from_be_bytes([a, b, c, d]),
        len,
    }
}

const fn v6(segments: [u16; 8], len: u8) -> Prefix {
    Prefix::V6 {
        addr: u128::from_be_bytes(
            Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )
            .octets(),
        ),
        len,
    }
}

const fn special(prefix: Prefix, text: &'static str, class: SpecialClass) -> SpecialRange {
    SpecialRange {
        prefix,
        text,
        class,
    }
}

/// Ranges that no published crawler or Cloudflare prefix may intersect
/// (spec §12.2, §12.3). IPv4-mapped prefixes are normalised before the check,
/// so `::ffff:0:0/96` is covered by the IPv4 rows; the IPv6 `::/8` row covers
/// `::`, `::1`, IPv4-compatible and NAT64 (`64:ff9b::/96`) addresses. For
/// IPv6 only global unicast (`2000::/3`) outside `2001::/23` and the
/// documentation blocks passes: the same address space the Go writer
/// (`control-plane/internal/intelsync`, WP-G3) allows, so the reader never
/// accepts a range the writer would have refused on these grounds.
pub(crate) static SPECIAL_RANGES: &[SpecialRange] = &[
    special(v4(0, 0, 0, 0, 8), "0.0.0.0/8", SpecialClass::Unspecified),
    special(v4(10, 0, 0, 0, 8), "10.0.0.0/8", SpecialClass::Private),
    special(v4(100, 64, 0, 0, 10), "100.64.0.0/10", SpecialClass::Cgnat),
    special(v4(127, 0, 0, 0, 8), "127.0.0.0/8", SpecialClass::Loopback),
    special(
        v4(169, 254, 0, 0, 16),
        "169.254.0.0/16",
        SpecialClass::LinkLocal,
    ),
    special(
        v4(172, 16, 0, 0, 12),
        "172.16.0.0/12",
        SpecialClass::Private,
    ),
    special(v4(192, 0, 0, 0, 24), "192.0.0.0/24", SpecialClass::Reserved),
    special(
        v4(192, 0, 2, 0, 24),
        "192.0.2.0/24",
        SpecialClass::Documentation,
    ),
    special(
        v4(192, 168, 0, 0, 16),
        "192.168.0.0/16",
        SpecialClass::Private,
    ),
    special(
        v4(198, 18, 0, 0, 15),
        "198.18.0.0/15",
        SpecialClass::Reserved,
    ),
    special(
        v4(198, 51, 100, 0, 24),
        "198.51.100.0/24",
        SpecialClass::Documentation,
    ),
    special(
        v4(203, 0, 113, 0, 24),
        "203.0.113.0/24",
        SpecialClass::Documentation,
    ),
    special(v4(224, 0, 0, 0, 4), "224.0.0.0/4", SpecialClass::Multicast),
    special(v4(240, 0, 0, 0, 4), "240.0.0.0/4", SpecialClass::Reserved),
    special(
        v6([0, 0, 0, 0, 0, 0, 0, 0], 128),
        "::/128",
        SpecialClass::Unspecified,
    ),
    special(
        v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
        "::1/128",
        SpecialClass::Loopback,
    ),
    special(
        v6([0, 0, 0, 0, 0, 0, 0, 0], 8),
        "::/8",
        SpecialClass::Reserved,
    ),
    special(
        v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
        "100::/64",
        SpecialClass::Reserved,
    ),
    // IETF protocol assignments (Teredo, ORCHID, ...): the IPv6 counterpart
    // of 192.0.0.0/24.
    special(
        v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        "2001::/23",
        SpecialClass::Reserved,
    ),
    special(
        v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        "2001:db8::/32",
        SpecialClass::Documentation,
    ),
    special(
        v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
        "3fff::/20",
        SpecialClass::Documentation,
    ),
    special(
        v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
        "fc00::/7",
        SpecialClass::Private,
    ),
    special(
        v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
        "fe80::/10",
        SpecialClass::LinkLocal,
    ),
    special(
        v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
        "fec0::/10",
        SpecialClass::Reserved,
    ),
    special(
        v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
        "ff00::/8",
        SpecialClass::Multicast,
    ),
    // Everything outside global unicast 2000::/3 is reserved by the IETF
    // (RFC 4291 §2.4, IANA IPv6 address space). Listed last so the specific
    // rows above name the class for ::, ::1, ULA, link-local and multicast.
    special(
        v6([0, 0, 0, 0, 0, 0, 0, 0], 3),
        "::/3",
        SpecialClass::Reserved,
    ),
    special(
        v6([0x4000, 0, 0, 0, 0, 0, 0, 0], 2),
        "4000::/2",
        SpecialClass::Reserved,
    ),
    special(
        v6([0x8000, 0, 0, 0, 0, 0, 0, 0], 1),
        "8000::/1",
        SpecialClass::Reserved,
    ),
];

/// Checks a published prefix against the per-family length floor and the
/// special-range table. Returns a short reason on failure.
pub(crate) fn check_published(
    prefix: Prefix,
    min_v4: u8,
    min_v6: u8,
    allow_documentation: bool,
) -> Result<(), String> {
    let (min, family) = if prefix.is_v4() {
        (min_v4, "IPv4")
    } else {
        (min_v6, "IPv6")
    };
    let mut reasons = Vec::new();
    if prefix.len() < min {
        reasons.push(format!("{family} prefix shorter than /{min}"));
    }
    if let Some(r) = prefix.special(allow_documentation) {
        reasons.push(format!("intersects {} range {}", r.class.as_str(), r.text));
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        Prefix::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parses_addresses_and_prefixes() {
        assert_eq!(p("1.2.3.4"), v4(1, 2, 3, 4, 32));
        assert_eq!(p("1.2.3.0/24"), v4(1, 2, 3, 0, 24));
        assert_eq!(p("0.0.0.0/0"), v4(0, 0, 0, 0, 0));
        assert_eq!(p("::/0"), Prefix::V6 { addr: 0, len: 0 });
        assert_eq!(
            p("2001:db8::/32"),
            v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32)
        );
        assert_eq!(p("2001:db8::1"), v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 128));
    }

    /// §7.1: IPv4-mapped IPv6 entries are normalised to IPv4.
    #[test]
    fn normalises_ipv4_mapped_prefixes() {
        assert_eq!(p("::ffff:1.2.3.4"), v4(1, 2, 3, 4, 32));
        assert_eq!(p("::ffff:1.2.3.0/120"), v4(1, 2, 3, 0, 24));
        assert_eq!(p("::ffff:0:0/96"), v4(0, 0, 0, 0, 0));
        // Shorter than /96: not a mapped prefix, stays IPv6 (even though it
        // contains the mapped block).
        assert!(matches!(p("::/80"), Prefix::V6 { len: 80, .. }));
        assert!(Prefix::parse("::ffff:0:0/95").is_err());
        // IPv4-compatible addresses are not mapped.
        assert!(matches!(p("::1.2.3.4"), Prefix::V6 { len: 128, .. }));
    }

    /// §12.3: canonical network addresses only; strict prefix lengths.
    #[test]
    fn rejects_non_canonical_and_malformed() {
        for bad in [
            "66.249.64.1/27",
            "2001:db8::1/32",
            "1.2.3.4/33",
            "::/129",
            "1.2.3.0/024",
            "1.2.3.0/+24",
            "1.2.3.0/",
            "1.2.3.0/24/1",
            " 1.2.3.4",
            "1.2.3.4 ",
            "01.2.3.4",
            "1.2.3",
            "fe80::1%eth0",
            "",
            "/24",
            "::ffff:1.2.3.4/97",
        ] {
            assert!(Prefix::parse(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn intersection_is_nesting() {
        assert!(p("10.0.0.0/8").intersects(p("10.1.0.0/16")));
        assert!(p("10.1.0.0/16").intersects(p("10.0.0.0/8")));
        assert!(!p("10.0.0.0/8").intersects(p("11.0.0.0/8")));
        assert!(p("0.0.0.0/0").intersects(p("203.0.113.0/24")));
        assert!(!p("0.0.0.0/0").intersects(p("::/0")));
    }

    /// §12.3 / D-36: every special class is detected, documentation only when
    /// not allowed.
    #[test]
    fn special_ranges() {
        let cases = [
            ("0.0.0.0/32", Some(SpecialClass::Unspecified)),
            ("10.1.0.0/16", Some(SpecialClass::Private)),
            ("172.20.0.0/16", Some(SpecialClass::Private)),
            ("192.168.1.0/24", Some(SpecialClass::Private)),
            ("100.100.0.0/16", Some(SpecialClass::Cgnat)),
            ("127.0.0.0/8", Some(SpecialClass::Loopback)),
            ("169.254.0.0/16", Some(SpecialClass::LinkLocal)),
            ("224.0.0.0/24", Some(SpecialClass::Multicast)),
            ("240.0.0.0/16", Some(SpecialClass::Reserved)),
            ("255.255.255.255", Some(SpecialClass::Reserved)),
            ("198.18.0.0/16", Some(SpecialClass::Reserved)),
            ("192.0.2.0/24", Some(SpecialClass::Documentation)),
            ("198.51.100.0/25", Some(SpecialClass::Documentation)),
            ("203.0.113.7", Some(SpecialClass::Documentation)),
            ("::", Some(SpecialClass::Unspecified)),
            ("::1", Some(SpecialClass::Loopback)),
            ("64:ff9b::/96", Some(SpecialClass::Reserved)),
            ("fd00::/8", Some(SpecialClass::Private)),
            ("fe80::/64", Some(SpecialClass::LinkLocal)),
            ("ff02::/16", Some(SpecialClass::Multicast)),
            ("2001:db8:1::/48", Some(SpecialClass::Documentation)),
            // IETF protocol assignments (Teredo, ORCHID, ...) and everything
            // outside global unicast 2000::/3 are reserved.
            ("2001::/32", Some(SpecialClass::Reserved)),
            ("2001:1ff::/32", Some(SpecialClass::Reserved)),
            ("1000::/32", Some(SpecialClass::Reserved)),
            ("4000::/32", Some(SpecialClass::Reserved)),
            ("8000::/32", Some(SpecialClass::Reserved)),
            ("e000::/16", Some(SpecialClass::Reserved)),
            ("fe00::/16", Some(SpecialClass::Reserved)),
            ("2001:200::/32", None),
            ("3fff:1000::/32", None),
            // Too broad ranges that *contain* a special range intersect it.
            ("0.0.0.0/0", Some(SpecialClass::Unspecified)),
            ("64.0.0.0/2", Some(SpecialClass::Cgnat)),
            ("66.249.64.0/27", None),
            ("157.55.39.0/24", None),
            ("2001:4860:4801:10::/64", None),
            ("2400:cb00::/32", None),
        ];
        for (text, want) in cases {
            let got = p(text).special(false).map(|r| r.class);
            assert_eq!(got, want, "{text}");
        }
        assert!(p("192.0.2.0/25").special(true).is_none());
        assert!(p("2001:db8:4860::/48").special(true).is_none());
        assert_eq!(
            p("127.0.0.0/8").special(true).map(|r| r.class),
            Some(SpecialClass::Loopback)
        );
    }

    #[test]
    fn published_prefix_floor() {
        assert!(check_published(p("66.0.0.0/8"), 16, 32, false).is_err());
        assert!(check_published(p("66.249.0.0/16"), 16, 32, false).is_ok());
        assert!(check_published(p("2600::/16"), 16, 32, false).is_err());
        assert!(check_published(p("2600::/32"), 16, 32, false).is_ok());
        // A mapped /112 is an IPv4 /16.
        assert!(check_published(p("::ffff:66.249.0.0/112"), 16, 32, false).is_ok());
        assert!(check_published(p("::ffff:66.0.0.0/104"), 16, 32, false).is_err());
    }
}
