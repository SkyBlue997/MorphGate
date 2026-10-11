//! The §9.3 header-parsing properties, shared by the fixed-seed random-input
//! test (`tests/upstream_fuzz.rs`) and the coverage-guided fuzz target
//! (`fuzz/fuzz_targets/cf_headers.rs`).

use crate::upstream::{
    CfHeaders, ClientIp, CloudflareSite, FRAMING, connection_listed, hop_by_hop,
    is_upstream_family, parse_cloudflare,
};
use mg_core::IpSource;
use std::collections::HashSet;

/// Parses `headers` as the upstream steps do and asserts every property:
/// each parsed value satisfies its validation rule
/// ([`check_cf_invariants`]); `Connection`-listed names are distinct and
/// lower-case; the hop-by-hop removal (step 3) never removes a trusted name
/// before step 4 parses it; and removing those headers first does not change
/// what step 4 parses. Returns the parsed headers.
pub fn check_upstream_steps(slices: &[(&str, &[u8])], site: &CloudflareSite<'_>) -> CfHeaders {
    let cf = parse_cloudflare(slices, site);
    check_cf_invariants(&cf, site);
    let _ = format!("{cf:?}");
    for (name, _) in slices {
        let _ = is_upstream_family(name);
    }
    let listed = connection_listed(slices);
    let distinct: HashSet<&String> = listed.iter().collect();
    assert_eq!(distinct.len(), listed.len());
    assert!(
        listed
            .iter()
            .all(|n| !n.is_empty() && *n == n.to_ascii_lowercase())
    );
    let hop = hop_by_hop(slices);
    assert_eq!(hop[0], "connection");
    let distinct: HashSet<&String> = hop.iter().collect();
    assert_eq!(distinct.len(), hop.len());
    // Step 3 never removes a trusted name before step 4 parses it, nor a
    // framing field (that would desynchronise the body); every other listed
    // name is removed by step 3 or by step 5.
    assert!(
        hop.iter()
            .all(|n| !is_upstream_family(n) && !FRAMING.contains(&n.as_str()))
    );
    assert!(listed.iter().all(|n| hop.contains(n)
        || is_upstream_family(n)
        || FRAMING.contains(&n.as_str())
        || n == "upgrade"));
    let kept: Vec<(&str, &[u8])> = slices
        .iter()
        .copied()
        .filter(|(n, _)| !hop.iter().any(|h| n.eq_ignore_ascii_case(h)))
        .collect();
    assert_eq!(parse_cloudflare(&kept, site), cf);
    cf
}

/// Every value [`parse_cloudflare`] returns satisfies its §9.3 validation
/// rule; invalid input is reported as missing.
pub fn check_cf_invariants(cf: &CfHeaders, site: &CloudflareSite<'_>) {
    let ascii_in = |s: &str, max: usize, allowed: &dyn Fn(u8) -> bool| {
        !s.is_empty() && s.len() <= max && s.bytes().all(allowed)
    };
    match cf.client_ip {
        ClientIp::Known(ip, source) => {
            assert!(matches!(
                source,
                IpSource::CfConnectingIp | IpSource::CfConnectingIpv6
            ));
            // Mapped addresses are always restored.
            assert_eq!(ip, ip.to_canonical());
            if source == IpSource::CfConnectingIpv6 {
                assert!(site.pseudo_ipv4_overwrite);
            }
        }
        // §9.3 table: missing or invalid → client_ip_header_missing = true.
        ClientIp::Unknown { header_missing } => assert!(header_missing),
    }
    if let Some(ray) = &cf.cf_ray {
        assert!(ascii_in(ray, 64, &|b| b.is_ascii_alphanumeric() || b == b'-'));
    }
    if let Some(tls) = &cf.edge_tls {
        assert_ne!(*tls, mg_core::EdgeTls::default());
        for hash in [&tls.ciphers_sha1, &tls.ext_sha1].into_iter().flatten() {
            assert_eq!(hash.len(), 28, "{hash}");
        }
        if let Some(len) = tls.hello_len {
            assert!((1..=65_535).contains(&len));
        }
        if let Some(v) = &tls.version {
            assert!(v.len() <= 16);
        }
    }
    if let Some(rtt) = cf.rtt_ms {
        assert!((1..=60_000).contains(&rtt));
    }
    if let Some(asn) = cf.upstream_asn {
        assert!(asn >= 1);
    }
    if !site.location_headers {
        assert!(cf.upstream_country.is_none());
        assert!(cf.upstream_region.is_none());
        assert!(cf.upstream_timezone.is_none());
    }
    if let Some(country) = &cf.upstream_country {
        assert_eq!(country.len(), 2);
        assert_ne!(country, "XX");
    }
    if let Some(cat) = &cf.cf_vbot_cat {
        assert!(cat.len() <= 64);
    }
    if let Some(names) = &cf.header_names {
        assert!(!names.is_empty() && names.len() <= 128);
        let distinct: HashSet<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        assert_eq!(distinct.len(), names.len());
        assert!(names.iter().all(|n| !n.is_empty() && n.len() <= 64));
    }
    if let Some(t1) = &cf.tier1 {
        assert!(site.tier1);
        if let Some(org) = &t1.as_org {
            assert!(!org.is_empty() && org.len() <= 256);
            assert!(!org.chars().any(char::is_control));
        }
        if let Some(ae) = &t1.accept_encoding_orig {
            assert!(ascii_in(ae, 256, &|b| (0x20..=0x7e).contains(&b)));
        }
        if let Some(p) = &t1.priority {
            assert!(p.len() <= 128);
        }
    }
    let known = [
        "tls-version",
        "tls-cipher",
        "tls-ciphers-sha1",
        "tls-ext-sha1",
        "tls-hello-len",
        "tls-random",
        "http-version",
        "rtt",
        "quic-rtt",
        "asn",
        "vbot",
        "hdr-names",
    ];
    let distinct: HashSet<&str> = cf.missing_signals.iter().copied().collect();
    assert_eq!(distinct.len(), cf.missing_signals.len());
    assert!(cf.missing_signals.iter().all(|s| known.contains(s)));
}
