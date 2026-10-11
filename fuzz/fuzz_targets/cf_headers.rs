//! Cloudflare's request headers (docs/impl/phase1-spec.md §9.3): every value
//! `parse_cloudflare` returns is valid, and removing the hop-by-hop headers
//! first never changes what it parses (`mg_edge_core::testkit::upstream`).
//!
//! Input: one flag byte (location headers, Tier 1, owner zones, Pseudo IPv4
//! = Overwrite), then `name: value` lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge_core::testkit::upstream::check_upstream_steps;
use mg_edge_core::upstream::CloudflareSite;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let zones = ["example.com".to_owned(), "Example.NET".to_owned()];
    let site = CloudflareSite {
        location_headers: flags & 1 != 0,
        tier1: flags & 2 != 0,
        owner_zones: if flags & 4 != 0 { &zones } else { &[] },
        pseudo_ipv4_overwrite: flags & 8 != 0,
    };
    check_upstream_steps(&header_lines(rest), &site);
});

/// `name: value` lines; a line without a colon or with a non-UTF-8 name is
/// skipped. Values stay raw bytes, as Pingora hands them over.
fn header_lines(data: &[u8]) -> Vec<(&str, &[u8])> {
    data.split(|&b| b == b'\n')
        .filter_map(|line| {
            let colon = line.iter().position(|&b| b == b':')?;
            let name = std::str::from_utf8(&line[..colon]).ok()?;
            let value = &line[colon + 1..];
            Some((name, value.strip_prefix(b" ").unwrap_or(value)))
        })
        .collect()
}
