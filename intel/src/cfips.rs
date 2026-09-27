//! The `cloudflare-ips` artifact (spec §12.2).

use serde::Deserialize;

use crate::artifact::ArtifactKind;
use crate::cidr::{Prefix, check_published};
use crate::error::{IntelError, check_size, quote};
use crate::ipset::IpSet;
use crate::text::is_rfc3339;

/// A validated `cloudflare-ips` artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudflareIps {
    /// Every IPv4 and IPv6 range.
    pub set: IpSet,
    /// When mgctl fetched the ranges (RFC 3339).
    pub fetched_at: String,
    /// The API response's ETag.
    pub etag: String,
}

const KIND: &str = "mg-cloudflare-ips";
const V4_COUNT: std::ops::RangeInclusive<usize> = 5..=64;
const V6_COUNT: std::ops::RangeInclusive<usize> = 2..=32;
const V4_LEN: std::ops::RangeInclusive<u8> = 8..=32;
const V6_LEN: std::ops::RangeInclusive<u8> = 16..=128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    v: u64,
    kind: String,
    source: String,
    fetched_at: String,
    etag: String,
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

/// Parses and validates a `cloudflare-ips` artifact with the same rules as
/// the writer (`mgctl cf ips sync`): `v == 1`, `kind`, 5–64 IPv4 and 2–32
/// IPv6 entries, each a canonical network address of the right family with a
/// prefix length of 8–32 (IPv4) or 16–128 (IPv6), none intersecting a
/// private, loopback, link-local, multicast, unspecified, CGNAT, reserved or
/// documentation range. Unknown fields are rejected (§12.0).
pub fn parse_cloudflare_ips(json: &[u8]) -> Result<CloudflareIps, IntelError> {
    check_size(
        "cloudflare-ips artifact",
        json.len(),
        ArtifactKind::CloudflareIps.max_size(),
    )?;
    let doc: Doc = serde_json::from_slice(json).map_err(|e| IntelError::json(&e))?;
    if doc.v != 1 {
        return Err(IntelError::invalid(format!("unsupported v {}", doc.v)));
    }
    if doc.kind != KIND {
        return Err(IntelError::invalid(format!(
            "kind is {}, want {KIND:?}",
            quote(&doc.kind)
        )));
    }
    if !is_rfc3339(&doc.fetched_at) {
        return Err(IntelError::invalid(format!(
            "fetched_at {} is not RFC 3339",
            quote(&doc.fetched_at)
        )));
    }
    let _ = doc.source; // informational only
    check_count("ipv4_cidrs", doc.ipv4_cidrs.len(), &V4_COUNT)?;
    check_count("ipv6_cidrs", doc.ipv6_cidrs.len(), &V6_COUNT)?;
    let mut prefixes = Vec::with_capacity(doc.ipv4_cidrs.len() + doc.ipv6_cidrs.len());
    for (field, list, want_v4) in [
        ("ipv4_cidrs", &doc.ipv4_cidrs, true),
        ("ipv6_cidrs", &doc.ipv6_cidrs, false),
    ] {
        for (i, entry) in list.iter().enumerate() {
            let fail = |reason: &str| {
                IntelError::invalid(format!("{field}[{i}] {}: {reason}", quote(entry)))
            };
            let prefix = Prefix::parse(entry).map_err(fail)?;
            // The family is judged on the text as well: an IPv4-mapped IPv6
            // entry belongs in neither list.
            if prefix.is_v4() != want_v4 || entry.contains(':') == want_v4 {
                return Err(fail(if want_v4 {
                    "not an IPv4 network"
                } else {
                    "not an IPv6 network"
                }));
            }
            let lens = if want_v4 { &V4_LEN } else { &V6_LEN };
            if !lens.contains(&prefix.len()) {
                return Err(fail(&format!(
                    "prefix length /{} outside {}-{}",
                    prefix.len(),
                    lens.start(),
                    lens.end()
                )));
            }
            check_published(prefix, 0, 0, false).map_err(|r| fail(&r))?;
            prefixes.push(prefix);
        }
    }
    Ok(CloudflareIps {
        set: IpSet::from_prefixes(prefixes),
        fetched_at: doc.fetched_at,
        etag: doc.etag,
    })
}

fn check_count(
    field: &str,
    n: usize,
    range: &std::ops::RangeInclusive<usize>,
) -> Result<(), IntelError> {
    if range.contains(&n) {
        Ok(())
    } else {
        Err(IntelError::invalid(format!(
            "{field} has {n} entries, want {}-{}",
            range.start(),
            range.end()
        )))
    }
}
