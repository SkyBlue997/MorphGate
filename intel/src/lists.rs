//! Plain-text lists (spec §12.4). `tor-exits` is an [`crate::IpSet`] built
//! with [`crate::IpSet::from_text`]; `datacenter-asns` is parsed here.

use std::collections::BTreeSet;

use crate::artifact::ArtifactKind;
use crate::error::{IntelError, check_size, quote};
use crate::ipset::strip_comment;

/// Parses a `datacenter-asns` list: one decimal ASN (1–4294967295) per line,
/// optionally prefixed with `AS` in any case; `#` starts a comment; blank
/// lines are ignored. ASN 0 is invalid. Errors carry the 1-based line number.
/// The 4 MiB artifact limit (§12.1) bounds the input.
pub fn parse_asn_list(text: &str) -> Result<BTreeSet<u32>, IntelError> {
    check_size(
        "datacenter-asns list",
        text.len(),
        ArtifactKind::DatacenterAsns.max_size(),
    )?;
    let mut asns = BTreeSet::new();
    for (i, raw) in text.lines().enumerate() {
        let entry = strip_comment(raw);
        if entry.is_empty() {
            continue;
        }
        let asn = parse_asn(entry).map_err(|reason| IntelError::Line {
            line: i + 1,
            reason: format!("{}: {reason}", quote(entry)),
        })?;
        asns.insert(asn);
    }
    Ok(asns)
}

fn parse_asn(entry: &str) -> Result<u32, &'static str> {
    let digits = match entry.get(..2) {
        Some(p) if p.eq_ignore_ascii_case("as") => &entry[2..],
        _ => entry,
    };
    // Digits only: `u32::from_str` would also accept a leading `+`.
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not a decimal ASN");
    }
    let value: u64 = digits.parse().map_err(|_| "not a decimal ASN")?;
    match u32::try_from(value) {
        Ok(0) => Err("ASN 0 is not a valid ASN"),
        Ok(asn) => Ok(asn),
        Err(_) => Err("ASN out of range (1-4294967295)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §12.4: prefixes, comments, blank lines, range.
    #[test]
    fn asn_list() {
        let set = parse_asn_list("# c\nAS16509\n15169 # inline\n\n  as8075\t\r\nAs1\n4294967295\n")
            .unwrap();
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec![1, 8075, 15169, 16509, 4_294_967_295]
        );
        assert!(parse_asn_list("").unwrap().is_empty());
    }

    #[test]
    fn asn_list_rejects() {
        for (text, line) in [
            ("0\n", 1),
            ("AS0\n", 1),
            ("AS16509\nAS12x\n", 2),
            ("1\n\n4294967296\n", 3),
            ("+15169\n", 1),
            ("-1\n", 1),
            ("AS\n", 1),
            ("AS 15169\n", 1),
            ("ASN15169\n", 1),
            ("15169.0\n", 1),
            ("99999999999\n", 1),
            ("１２３\n", 1),
        ] {
            match parse_asn_list(text) {
                Err(IntelError::Line { line: l, .. }) => assert_eq!(l, line, "{text:?}"),
                other => panic!("{text:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn asn_list_size_limit() {
        let big = "#".repeat(usize::try_from(ArtifactKind::DatacenterAsns.max_size()).unwrap() + 1);
        assert!(matches!(
            parse_asn_list(&big),
            Err(IntelError::TooLarge { .. })
        ));
    }
}
