//! Deterministic random-input test for the upstream header parsers
//! (docs/impl/phase1-spec.md §2.4 item 3, §9.3; WP-C1): a fixed-seed
//! xorshift generates ≥ 10,000 header lists; nothing panics and every parsed
//! value satisfies its §9.3 validation rule.

use mg_core::IpSource;
use mg_edge_core::upstream::{
    CfHeaders, ClientIp, CloudflareSite, connection_listed, hop_by_hop, is_upstream_family,
    parse_cloudflare, secret_header_ok,
};
use std::collections::HashSet;

const ITERATIONS: usize = 20_000;

/// xorshift64 (Marsaglia), fixed seed: reproducible across runs.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

const NAMES: &[&str] = &[
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ray",
    "cf-visitor",
    "cf-worker",
    "cf-ipcountry",
    "cf-region-code",
    "cf-timezone",
    "x-mg-cf-tls-version",
    "x-mg-cf-tls-cipher",
    "x-mg-cf-tls-ciphers-sha1",
    "x-mg-cf-tls-ext-sha1",
    "x-mg-cf-tls-hello-len",
    "x-mg-cf-tls-random",
    "x-mg-cf-http-version",
    "x-mg-cf-rtt",
    "x-mg-cf-quic-rtt",
    "x-mg-cf-asn",
    "x-mg-cf-vbot",
    "x-mg-cf-vbot-cat",
    "x-mg-cf-hdr-names",
    "x-mg-cf-t1",
    "x-mg-cf-priority",
    "x-mg-cf-accept-encoding",
    "x-mg-cf-as-org",
    "x-mg-upstream-key",
    "connection",
    "upgrade",
    "keep-alive",
    "host",
    "accept",
    "cookie",
    "x-forwarded-for",
    "true-client-ip",
    "forwarded",
];

const VALUES: &[&str] = &[
    "203.0.113.7",
    "::ffff:203.0.113.7",
    "2001:db8::1",
    "[2001:db8::1]:443",
    "8a1b2c3d4e5f6a7b-SJC",
    r#"{"scheme":"http"}"#,
    r#"{"scheme":"https"}"#,
    r#"["http"]"#,
    "example.com",
    "Example.com",
    "HK",
    "T1",
    "XX",
    "Asia/Hong_Kong",
    "TLSv1.3",
    "3zN0vNnT0h1r1TmXnq4B3Ic1S0c=",
    "3zN0vNnT0h1r1TmXnq4B3Ic1S0c",
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "512",
    "65536",
    "0",
    "4294967295",
    "4294967296",
    "HTTP/3",
    "HTTP/2",
    "true",
    "false",
    "Host,Accept,accept",
    "snippet",
    "worker",
    "weight=192;exclusive=0",
    "gzip, br",
    "M%C3%BCnchen",
    "%",
    "%C3",
    "upgrade, mg-client-ip",
    "websocket",
    "",
];

/// A value: a sample, a mutated sample, or random bytes from a biased
/// alphabet (JSON, base64, percent-encoding, separators, non-ASCII).
fn value(rng: &mut XorShift) -> Vec<u8> {
    const ALPHABET: &[u8] =
        b"0123456789abcdefABCDEFxyzXYZ.:,;=/+-_%{}[]\"() \t@&*!~\\\x00\x01\x7f\x80\xc3\xbc\xff";
    match rng.below(4) {
        0 => rng.pick(VALUES).as_bytes().to_vec(),
        1 => {
            let mut v = rng.pick(VALUES).as_bytes().to_vec();
            for _ in 0..=rng.below(3) {
                let op = rng.below(3);
                let at = if v.is_empty() { 0 } else { rng.below(v.len()) };
                let byte = *rng.pick(ALPHABET);
                match op {
                    0 if !v.is_empty() => v[at] = byte,
                    1 if !v.is_empty() => {
                        v.remove(at);
                    }
                    _ => v.insert(at, byte),
                }
            }
            v
        }
        2 => {
            let len = rng.below(300);
            (0..len).map(|_| *rng.pick(ALPHABET)).collect()
        }
        _ => {
            // Long repetitive values near the parsers' length limits.
            let unit = rng.pick(VALUES).as_bytes().to_vec();
            let reps = 1 + rng.below(40);
            let mut v = Vec::new();
            for _ in 0..reps {
                v.extend_from_slice(&unit);
                v.push(b',');
            }
            v
        }
    }
}

/// A name: a known name with random case and `_` / `-` swaps, or random
/// characters.
fn name(rng: &mut XorShift) -> String {
    if rng.chance(5) {
        let len = rng.below(20);
        let chars = "abcXYZ-_:é0 ";
        return (0..len)
            .map(|_| chars.chars().nth(rng.below(chars.chars().count())).unwrap())
            .collect();
    }
    rng.pick(NAMES)
        .chars()
        .map(|c| match (c, rng.below(6)) {
            ('-', 0) => '_',
            (c, 1) => c.to_ascii_uppercase(),
            (c, _) => c,
        })
        .collect()
}

fn check_invariants(cf: &CfHeaders, site: &CloudflareSite<'_>) {
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

#[test]
fn random_headers_never_panic_and_parse_only_valid_values() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let zones = vec!["example.com".to_owned(), "Example.NET".to_owned()];
    let no_zones: Vec<String> = Vec::new();
    let mut known_ips = 0;
    let mut parsed_tls = 0;
    for _ in 0..ITERATIONS {
        let count = rng.below(40);
        let headers: Vec<(String, Vec<u8>)> = (0..count)
            .map(|_| (name(&mut rng), value(&mut rng)))
            .collect();
        let slices: Vec<(&str, &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        let site = CloudflareSite {
            location_headers: rng.chance(2),
            tier1: rng.chance(2),
            owner_zones: if rng.chance(3) { &no_zones } else { &zones },
            pseudo_ipv4_overwrite: rng.chance(2),
        };

        let cf = parse_cloudflare(&slices, &site);
        check_invariants(&cf, &site);
        let _ = format!("{cf:?}");
        known_ips += usize::from(cf.client_ip.ip().is_some());
        parsed_tls += usize::from(cf.edge_tls.is_some());

        for (name, _) in &slices {
            let _ = is_upstream_family(name);
        }
        let listed = connection_listed(&slices);
        let distinct: HashSet<&String> = listed.iter().collect();
        assert_eq!(distinct.len(), listed.len());
        assert!(
            listed
                .iter()
                .all(|n| !n.is_empty() && *n == n.to_ascii_lowercase())
        );
        let hop = hop_by_hop(&slices);
        assert_eq!(hop[0], "connection");
        let distinct: HashSet<&String> = hop.iter().collect();
        assert_eq!(distinct.len(), hop.len());
        // Step 3 never removes a trusted name before step 4 parses it; every
        // listed name is removed by step 3 or by step 5.
        assert!(hop.iter().all(|n| !is_upstream_family(n)));
        assert!(
            listed
                .iter()
                .all(|n| hop.contains(n) || is_upstream_family(n) || n == "upgrade")
        );
        let kept: Vec<(&str, &[u8])> = slices
            .iter()
            .copied()
            .filter(|(n, _)| !hop.iter().any(|h| n.eq_ignore_ascii_case(h)))
            .collect();
        assert_eq!(parse_cloudflare(&kept, &site), cf);

        let accepted = vec![value(&mut rng), value(&mut rng)];
        let presented = slices.first().map(|(_, v)| *v);
        let expected = presented.is_some_and(|p| !p.is_empty() && accepted.iter().any(|a| a == p));
        assert_eq!(secret_header_ok(presented, &accepted), expected);
    }
    // The generator does reach the interesting branches.
    assert!(known_ips > 50, "{known_ips}");
    assert!(parsed_tls > 100, "{parsed_tls}");
}
