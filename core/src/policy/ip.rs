//! `ip_in` semantics (docs/impl/phase1-spec.md §5.3) and the site's named
//! lists.
//!
//! Parsing follows Go's `net/netip` exactly as used by the reference
//! `ipIn` in `control-plane/internal/policy/funcs.go`, so the Rust evaluator
//! and the Go reference agree on every input: strict dotted-quad IPv4 (no
//! leading zeros), RFC 4291 IPv6 text, CIDR bits without sign or leading
//! zeros, IPv4-mapped addresses and `::ffff:a.b.c.d/n` (n >= 96) prefixes
//! compared as IPv4; a zone makes a subject "not an IP" (`false`) and a list
//! entry invalid (`Error(invalid_argument)`).

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

/// A masked network (address family, network bits, prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpNet {
    V4 { net: u32, bits: u8 },
    V6 { net: u128, bits: u8 },
}

impl IpNet {
    fn v4(addr: Ipv4Addr, bits: u8) -> Self {
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(bits))
        };
        Self::V4 {
            net: u32::from(addr) & mask,
            bits,
        }
    }

    fn v6(addr: Ipv6Addr, bits: u8) -> Self {
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(bits))
        };
        Self::V6 {
            net: u128::from(addr) & mask,
            bits,
        }
    }

    /// Whether `ip` (already canonical: IPv4-mapped addresses unmapped) is
    /// inside the network. Families never cross: `::/0` holds no IPv4 address.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4 { net, bits }, IpAddr::V4(a)) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(bits))
                };
                u32::from(a) & mask == net
            }
            (Self::V6 { net, bits }, IpAddr::V6(a)) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(bits))
                };
                u128::from(a) & mask == net
            }
            _ => false,
        }
    }
}

/// Parses the left-hand side of `ip_in` into a canonical address
/// (IPv4-mapped IPv6 unmapped to IPv4). `None` = not an IP, and `ip_in` is
/// `false` without looking at the list (§5.3). An address with a zone
/// (`fe80::1%eth0`, also `::ffff:a.b.c.d%eth0`) is not an IP here: Go's
/// `ipIn` returns `false` for `addr.Zone() != ""` before parsing the entries,
/// and the std parser rejects zones outright.
pub(crate) fn parse_subject(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Parses one list entry: an address or a CIDR prefix. `None` = invalid
/// (`ip_in` is then `Error(invalid_argument)`).
pub(crate) fn parse_entry(s: &str) -> Option<IpNet> {
    let Some((addr, bits)) = s.rsplit_once('/') else {
        // A single address: zones are rejected by the IpAddr parser.
        return Some(match s.parse::<IpAddr>().ok()?.to_canonical() {
            IpAddr::V4(a) => IpNet::v4(a, 32),
            IpAddr::V6(a) => IpNet::v6(a, 128),
        });
    };
    let bits = parse_bits(bits)?;
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => (bits <= 32).then(|| IpNet::v4(a, bits as u8)),
        IpAddr::V6(a) => {
            if bits > 128 {
                return None;
            }
            match a.to_ipv4_mapped() {
                // ::ffff:a.b.c.d/n is the IPv4 network a.b.c.d/(n-96).
                Some(v4) => bits.checked_sub(96).map(|b| IpNet::v4(v4, b as u8)),
                None => Some(IpNet::v6(a, bits as u8)),
            }
        }
    }
}

/// CIDR length as Go's `ParsePrefix` reads it: decimal digits, no sign, no
/// leading zero (except `0` itself).
fn parse_bits(s: &str) -> Option<u32> {
    if s.is_empty()
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
        || s.len() > 3
    {
        return None;
    }
    s.parse().ok()
}

/// One named list of the site bundle (`list("name")`).
pub struct NamedList {
    entries: Vec<String>,
    /// Parsed on first use by `ip_in`: `None` if any entry is not an IP / CIDR.
    nets: OnceLock<Option<Vec<IpNet>>>,
}

impl NamedList {
    /// The entries, in bundle order.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// The entries as networks, or `None` if any entry is invalid.
    pub(crate) fn nets(&self) -> Option<&[IpNet]> {
        self.nets
            .get_or_init(|| self.entries.iter().map(|e| parse_entry(e)).collect())
            .as_deref()
    }
}

impl Clone for NamedList {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            nets: OnceLock::new(),
        }
    }
}

impl fmt::Debug for NamedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamedList")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// The site's named lists (`SiteBundle.lists`), by name.
#[derive(Debug, Clone, Default)]
pub struct NamedLists {
    lists: BTreeMap<String, NamedList>,
}

impl NamedLists {
    /// Wraps the bundle's lists. Entry-count and entry-length bounds are
    /// checked by the bundle loader (§8.2); IP prefixes are parsed lazily.
    pub fn new(lists: BTreeMap<String, Vec<String>>) -> Self {
        Self {
            lists: lists
                .into_iter()
                .map(|(name, entries)| {
                    (
                        name,
                        NamedList {
                            entries,
                            nets: OnceLock::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Whether a list with this name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.lists.contains_key(name)
    }

    /// The list with this name.
    pub fn get(&self, name: &str) -> Option<&NamedList> {
        self.lists.get(name)
    }

    /// List names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.lists.keys().map(String::as_str)
    }
}

/// The `f64` whose shortest decimal form equals that of `x` (so `0.4f32`
/// becomes `0.4f64`, not `0.4000000059604645`): the value the event JSON shows.
pub(crate) fn canonical_decimal(x: f32) -> f64 {
    if !x.is_finite() {
        return f64::from(x);
    }
    x.to_string().parse().unwrap_or(f64::from(x))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_in(ip: &str, list: &[&str]) -> Result<bool, ()> {
        let Some(subject) = parse_subject(ip) else {
            return Ok(false);
        };
        let nets: Option<Vec<IpNet>> = list.iter().map(|e| parse_entry(e)).collect();
        let nets = nets.ok_or(())?;
        Ok(nets.iter().any(|n| n.contains(subject)))
    }

    /// The table of `funcs_test.go` `TestIPIn`, plus the §5.3 edge cases.
    #[test]
    fn matches_go_reference_table() {
        let cases: &[(&str, &[&str], Result<bool, ()>)] = &[
            ("10.1.2.3", &["10.0.0.0/8"], Ok(true)),
            ("11.1.2.3", &["10.0.0.0/8"], Ok(false)),
            ("192.0.2.1", &["192.0.2.1"], Ok(true)),
            ("192.0.2.2", &["192.0.2.1"], Ok(false)),
            ("::ffff:10.0.0.1", &["10.0.0.0/8"], Ok(true)),
            ("10.0.0.1", &["::ffff:10.0.0.0/104"], Ok(true)),
            ("2001:db8::1", &["2001:db8::/32"], Ok(true)),
            ("2001:db9::1", &["2001:db8::/32"], Ok(false)),
            ("10.0.0.1", &["10.0.0.5/8"], Ok(true)),
            ("10.0.0.1", &[], Ok(false)),
            ("not-an-ip", &["0.0.0.0/0"], Ok(false)),
            ("", &["0.0.0.0/0"], Ok(false)),
            ("10.0.0.1", &["10.0.0.0/8", "bogus"], Err(())),
            ("10.0.0.1", &["10.0.0.0/33"], Err(())),
            ("fe80::1", &["fe80::1%eth0"], Err(())),
            // Invalid entries are errors even after an earlier match.
            ("10.0.0.1", &["10.0.0.1", "300.0.0.0/8"], Err(())),
            // An invalid subject is false before the entries are looked at.
            ("not-an-ip", &["bogus"], Ok(false)),
            // Families never cross.
            ("10.0.0.1", &["::/0"], Ok(false)),
            ("::ffff:10.0.0.1", &["::/0"], Ok(false)),
            ("2001:db8::1", &["0.0.0.0/0"], Ok(false)),
            ("2001:db8::1", &["::/0"], Ok(true)),
            ("10.0.0.1", &["0.0.0.0/0"], Ok(true)),
            // Mapped CIDRs below /96 are invalid.
            ("10.0.0.1", &["::ffff:10.0.0.0/95"], Err(())),
            ("10.0.0.1", &["::ffff:10.0.0.0/96"], Ok(true)),
            ("10.0.0.1", &["::ffff:10.0.0.1"], Ok(true)),
            // Go's ParsePrefix: no sign, no leading zeros, no zone, no empty bits.
            ("10.0.0.1", &["10.0.0.0/08"], Err(())),
            ("10.0.0.1", &["10.0.0.0/+8"], Err(())),
            ("10.0.0.1", &["10.0.0.0/"], Err(())),
            ("10.0.0.1", &["/8"], Err(())),
            ("10.0.0.1", &["10.0.0.0/8/8"], Err(())),
            ("fe80::1", &["fe80::%eth0/64"], Err(())),
            ("10.0.0.1", &["010.0.0.1"], Err(())),
            ("10.0.0.1", &[" 10.0.0.1"], Err(())),
            ("10.0.0.1", &["10.0.0.0/0"], Ok(true)),
            ("10.0.0.1", &["1.2.3.4/000"], Err(())),
            // Subjects: leading zeros and zones are not IPs (§5.3 "不带 zone";
            // Go's ipIn returns false for `addr.Zone() != ""` before it
            // parses the list, so the entries are not validated either).
            ("010.0.0.1", &["0.0.0.0/0"], Ok(false)),
            ("10.0.0.1%eth0", &["0.0.0.0/0"], Ok(false)),
            ("fe80::1%eth0", &["fe80::/10"], Ok(false)),
            ("fe80::1%eth0", &["bogus"], Ok(false)),
            ("fe80::1%", &["bogus"], Ok(false)),
            ("::ffff:10.0.0.1%eth0", &["10.0.0.0/8"], Ok(false)),
            ("::ffff:10.0.0.1%eth0", &["bogus"], Ok(false)),
        ];
        for (ip, list, want) in cases {
            assert_eq!(ip_in(ip, list), *want, "ip_in({ip:?}, {list:?})");
        }
    }

    #[test]
    fn named_lists_parse_lazily_and_report_invalid_entries() {
        let lists = NamedLists::new(BTreeMap::from([
            (
                "owner_cidrs".to_string(),
                vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            ),
            ("ua_words".to_string(), vec!["curl".to_string()]),
        ]));
        assert!(lists.contains("owner_cidrs") && !lists.contains("nope"));
        assert_eq!(
            lists.names().collect::<Vec<_>>(),
            ["owner_cidrs", "ua_words"]
        );
        let owner = lists.get("owner_cidrs").unwrap();
        assert_eq!(owner.nets().map(<[IpNet]>::len), Some(2));
        assert_eq!(lists.get("ua_words").unwrap().nets(), None);
        assert_eq!(format!("{owner:?}"), "NamedList { entries: 2, .. }");
        let cloned = lists.clone();
        assert_eq!(
            cloned.get("owner_cidrs").unwrap().entries(),
            owner.entries()
        );
    }

    #[test]
    fn canonical_decimals() {
        assert_eq!(canonical_decimal(0.4), 0.4);
        assert_eq!(canonical_decimal(0.6), 0.6);
        assert_eq!(canonical_decimal(1.0), 1.0);
        assert_eq!(canonical_decimal(0.0), 0.0);
        assert!(canonical_decimal(f32::NAN).is_nan());
    }

    /// Spec §2.4: deterministic random input never panics.
    #[test]
    fn random_inputs_do_not_panic() {
        let alphabet = b"0123456789abcdef:./%fF";
        let mut state: u64 = 0xdead_beef_cafe_f00d;
        for _ in 0..10_000 {
            let mut s = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for i in 0..(state % 40) {
                s.push(
                    alphabet[((state >> (i % 60)) as usize + i as usize) % alphabet.len()] as char,
                );
            }
            let _ = parse_subject(&s);
            let _ = parse_entry(&s);
        }
    }
}
