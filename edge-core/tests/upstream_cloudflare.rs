//! The `cloudflare` trusted-header table (docs/impl/phase1-spec.md §9.3,
//! §9.3.2; WP-C1): every row valid, invalid and missing; Tier 1 marker on /
//! off; location headers on / off; `CF-Connecting-IP` missing / invalid /
//! mapped; `CF-Worker` owner / foreign / invalid.

use mg_core::{EdgeTls, IpSource};
use mg_edge_core::upstream::{
    CfHeaders, ClientIp, CloudflareSite, Tier1, Tier1Source, WorkerZone, hop_by_hop,
    is_upstream_family, parse_cloudflare,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const CIPHERS_SHA1: &str = "3zN0vNnT0h1r1TmXnq4B3Ic1S0c=";
const EXT_SHA1: &str = "AAECAwQFBgcICQoLDA0ODxAREhM=";
const TLS_RANDOM: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// A request carrying every header of the §9.3 table with a valid value,
/// plus headers the parser must ignore.
const BASE: &[(&str, &str)] = &[
    ("Host", "blog.example.com"),
    ("cf-connecting-ip", "203.0.113.7"),
    ("cf-ray", "8a1b2c3d4e5f6a7b-SJC"),
    ("cf-visitor", r#"{"scheme":"https"}"#),
    ("cf-ipcountry", "HK"),
    ("cf-region", "Hong Kong"),
    ("cf-region-code", "HCW"),
    ("cf-timezone", "Asia/Hong_Kong"),
    ("cf-ipcity", "Hong Kong"),
    ("cf-iplatitude", "22.3"),
    ("x-mg-cf-tls-version", "TLSv1.3"),
    ("x-mg-cf-tls-cipher", "AEAD-AES128-GCM-SHA256"),
    ("x-mg-cf-tls-ciphers-sha1", CIPHERS_SHA1),
    ("x-mg-cf-tls-ext-sha1", EXT_SHA1),
    ("x-mg-cf-tls-hello-len", "512"),
    ("x-mg-cf-tls-random", TLS_RANDOM),
    ("x-mg-cf-http-version", "HTTP/2"),
    ("x-mg-cf-rtt", "23"),
    ("x-mg-cf-quic-rtt", "0"),
    ("x-mg-cf-asn", "64500"),
    ("x-mg-cf-vbot", "false"),
    ("x-mg-cf-vbot-cat", "Search Engine Crawler"),
    (
        "x-mg-cf-hdr-names",
        "Host,User-Agent,Accept,Accept-Language,accept",
    ),
    ("x-mg-cf-t1", "snippet"),
    (
        "x-mg-cf-priority",
        "weight=192;exclusive=0;group=3;group-weight=127",
    ),
    ("x-mg-cf-accept-encoding", "gzip, deflate, br, zstd"),
    ("x-mg-cf-as-org", "Example%20Networks%20Ltd"),
    ("Accept", "text/html"),
];

fn owners() -> Vec<String> {
    vec!["example.com".to_owned(), "example.net".to_owned()]
}

fn site(owner_zones: &[String]) -> CloudflareSite<'_> {
    CloudflareSite {
        location_headers: true,
        tier1: true,
        owner_zones,
        pseudo_ipv4_overwrite: false,
    }
}

/// [`BASE`] with `name` replaced by `value` (removed for `None`; appended
/// when absent).
fn with(name: &str, value: Option<&str>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = BASE
        .iter()
        .filter(|(n, _)| !n.eq_ignore_ascii_case(name))
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    if let Some(value) = value {
        out.push((name.to_owned(), value.to_owned()));
    }
    out
}

fn parse_owned(headers: &[(String, String)], site: &CloudflareSite<'_>) -> CfHeaders {
    let slices: Vec<(&str, &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_bytes()))
        .collect();
    parse_cloudflare(&slices, site)
}

fn parse(headers: &[(&str, &str)], site: &CloudflareSite<'_>) -> CfHeaders {
    let slices: Vec<(&str, &[u8])> = headers.iter().map(|(n, v)| (*n, v.as_bytes())).collect();
    parse_cloudflare(&slices, site)
}

/// Parses [`BASE`] with one header replaced, on the default site.
fn parse_with(name: &str, value: Option<&str>) -> CfHeaders {
    let owners = owners();
    parse_owned(&with(name, value), &site(&owners))
}

#[test]
fn every_valid_row_is_parsed() {
    let owners = owners();
    let cf = parse(BASE, &site(&owners));
    assert_eq!(
        cf.client_ip,
        ClientIp::Known(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpSource::CfConnectingIp
        )
    );
    assert_eq!(cf.worker, WorkerZone::None);
    assert_eq!(cf.cf_ray.as_deref(), Some("8a1b2c3d4e5f6a7b-SJC"));
    assert!(cf.visitor_https);
    assert_eq!(
        cf.edge_tls,
        Some(EdgeTls {
            version: Some("TLSv1.3".into()),
            cipher: Some("AEAD-AES128-GCM-SHA256".into()),
            ciphers_sha1: Some(CIPHERS_SHA1.into()),
            ext_sha1: Some(EXT_SHA1.into()),
            hello_len: Some(512),
        })
    );
    assert_eq!(cf.http_version.as_deref(), Some("HTTP/2"));
    assert_eq!(cf.rtt_ms, Some(23));
    assert_eq!(cf.upstream_asn, Some(64500));
    assert_eq!(cf.upstream_country.as_deref(), Some("HK"));
    assert!(!cf.is_tor());
    assert_eq!(cf.upstream_region.as_deref(), Some("HCW"));
    assert_eq!(cf.upstream_timezone.as_deref(), Some("Asia/Hong_Kong"));
    assert_eq!(cf.cf_vbot, Some(false));
    assert_eq!(cf.cf_vbot_cat.as_deref(), Some("Search Engine Crawler"));
    assert_eq!(
        cf.header_names,
        Some(vec![
            "Host".to_owned(),
            "User-Agent".to_owned(),
            "Accept".to_owned(),
            "Accept-Language".to_owned(),
        ])
    );
    assert_eq!(
        cf.tier1,
        Some(Tier1 {
            source: Tier1Source::Snippet,
            priority: Some("weight=192;exclusive=0;group=3;group-weight=127".into()),
            accept_encoding_orig: Some("gzip, deflate, br, zstd".into()),
            as_org: Some("Example Networks Ltd".into()),
        })
    );
    assert!(cf.missing_signals.is_empty(), "{:?}", cf.missing_signals);
}

/// §9.3: names compare case-insensitively (HTTP field names), values have
/// their optional whitespace trimmed.
#[test]
fn names_are_case_insensitive_and_values_trimmed() {
    let owners = owners();
    let cf = parse(
        &[
            ("CF-Connecting-IP", " 198.51.100.9\t"),
            ("X-MG-CF-ASN", "13335 "),
            ("X-Mg-Cf-Http-Version", "HTTP/1.1"),
        ],
        &site(&owners),
    );
    assert_eq!(
        cf.client_ip.ip(),
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)))
    );
    assert_eq!(cf.upstream_asn, Some(13335));
    assert_eq!(cf.http_version.as_deref(), Some("HTTP/1.1"));
}

/// §9.3 step 4: underscore spellings are never parsed (they are only
/// stripped), so they cannot smuggle a value past Cloudflare's own header.
#[test]
fn underscore_variants_are_never_parsed() {
    let owners = owners();
    let cf = parse(
        &[
            ("CF_Connecting_IP", "192.0.2.1"),
            ("cf_worker", "evil.example"),
            ("x_mg_cf_asn", "64500"),
            ("x-mg-cf_vbot", "true"),
            ("X_MG_CF_T1", "worker"),
            ("x-mg-cf-http_version", "HTTP/2"),
        ],
        &site(&owners),
    );
    assert_eq!(
        cf.client_ip,
        ClientIp::Unknown {
            header_missing: true
        }
    );
    assert_eq!(cf.worker, WorkerZone::None);
    assert_eq!(cf.upstream_asn, None);
    assert_eq!(cf.cf_vbot, None);
    assert_eq!(cf.tier1, None);
    assert_eq!(cf.http_version, None);
    for signal in ["asn", "vbot", "http-version"] {
        assert!(cf.missing_signals.contains(&signal), "{signal}");
    }
}

/// §9.3 step 4: a client-supplied underscore spelling next to Cloudflare's
/// own header neither overrides it nor makes it count as repeated.
#[test]
fn underscore_variants_do_not_shadow_trusted_headers() {
    let owners = owners();
    let cf = parse(
        &[
            ("CF_Connecting_IP", "192.0.2.1"),
            ("cf-connecting-ip", "203.0.113.7"),
            ("cf_worker", "evil.example"),
            ("cf-worker", "example.com"),
            ("x_mg_cf_asn", "1"),
            ("x-mg-cf-asn", "64500"),
        ],
        &site(&owners),
    );
    assert_eq!(
        cf.client_ip,
        ClientIp::Known(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpSource::CfConnectingIp
        )
    );
    assert_eq!(cf.worker, WorkerZone::Owner);
    assert_eq!(cf.upstream_asn, Some(64500));
}

/// §9.3 steps 3–5 as E1a wires them (remove [`hop_by_hop`], parse, strip
/// the families), D-23: a `Connection` field that lists trusted Cloudflare
/// headers cannot hide them from the parser. Otherwise a foreign Worker's
/// `Connection: CF-Worker` would turn the §9.4 step 4 403 into an ordinary
/// request. The listed names still never reach the origin (step 5).
#[test]
fn connection_listing_cannot_hide_trusted_headers() {
    let owners = owners();
    let request = [
        ("Host", "blog.example.com"),
        (
            "Connection",
            "CF-Worker, cf-connecting-ip, X-MG-CF-HTTP-Version, keep-alive",
        ),
        ("cf-worker", "evil.example"),
        ("cf-connecting-ip", "203.0.113.7"),
        ("x-mg-cf-http-version", "HTTP/2"),
        ("Keep-Alive", "timeout=5"),
    ];
    let request: Vec<(&str, &[u8])> = request.iter().map(|(n, v)| (*n, v.as_bytes())).collect();
    let removed = hop_by_hop(&request);
    let after_step3: Vec<(&str, &[u8])> = request
        .iter()
        .copied()
        .filter(|(name, _)| !removed.iter().any(|r| name.eq_ignore_ascii_case(r)))
        .collect();
    let cf = parse_cloudflare(&after_step3, &site(&owners));
    assert_eq!(cf.worker, WorkerZone::Foreign);
    assert_eq!(
        cf.client_ip,
        ClientIp::Known(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpSource::CfConnectingIp
        )
    );
    assert_eq!(cf.http_version.as_deref(), Some("HTTP/2"));
    // Step 5: nothing the client listed (and no family header) is forwarded.
    let forwarded: Vec<&str> = after_step3
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !is_upstream_family(name))
        .collect();
    assert_eq!(forwarded, ["Host"]);
}

/// §9.3 table / §9.5: an absent **or invalid** `cf-connecting-ip` sets
/// `upstream.client_ip_header_missing = true`, which E1b copies from
/// `ClientIp::Unknown::header_missing`.
#[test]
fn unusable_connecting_ip_always_reports_header_missing() {
    let owners = owners();
    let mut overwrite = site(&owners);
    overwrite.pseudo_ipv4_overwrite = true;
    let unknown = ClientIp::Unknown {
        header_missing: true,
    };
    assert_eq!(parse_with("cf-connecting-ip", None).client_ip, unknown);
    assert_eq!(
        parse_with("cf-connecting-ip", Some("203.0.113.7:443")).client_ip,
        unknown
    );
    let repeated = [
        ("cf-connecting-ip", "203.0.113.7"),
        ("cf-connecting-ip", "203.0.113.7"),
    ];
    assert_eq!(parse(&repeated, &site(&owners)).client_ip, unknown);
    let both_bad = [("cf-connecting-ip", "x"), ("cf-connecting-ipv6", "y")];
    assert_eq!(parse(&both_bad, &overwrite).client_ip, unknown);
}

/// §9.3: a trusted header that occurs twice is ambiguous and counts as
/// invalid (missing).
#[test]
fn repeated_trusted_headers_are_invalid() {
    let mut h = with("x-mg-cf-asn", Some("64500"));
    h.push(("X-MG-CF-ASN".into(), "64500".into()));
    let owners = owners();
    let cf = parse_owned(&h, &site(&owners));
    assert_eq!(cf.upstream_asn, None);
    assert_eq!(cf.missing_signals, ["asn"]);

    let mut h = with("cf-connecting-ip", Some("203.0.113.7"));
    h.push(("cf-connecting-ip".into(), "198.51.100.1".into()));
    // Unusable, so `client_ip_header_missing = true` (§9.3 table).
    assert_eq!(
        parse_owned(&h, &site(&owners)).client_ip,
        ClientIp::Unknown {
            header_missing: true
        }
    );
}

// ---- cf-connecting-ip / cf-connecting-ipv6 (§9.3, §9.3.2) ----

#[test]
fn connecting_ip_missing_is_unknown_with_header_missing() {
    let cf = parse_with("cf-connecting-ip", None);
    assert_eq!(
        cf.client_ip,
        ClientIp::Unknown {
            header_missing: true
        }
    );
    assert_eq!(cf.client_ip.ip(), None);
    assert_eq!(cf.client_ip.source(), None);
    // Counted by mg_cf_connecting_ip_missing_total, not as a signal alarm.
    assert!(cf.missing_signals.is_empty());
}

#[test]
fn connecting_ip_invalid_is_unknown() {
    for bad in [
        "",
        "unknown",
        "203.0.113.7:443",
        "[2001:db8::1]",
        "[2001:db8::1]:443",
        "2001:db8::1%eth0",
        "fe80::1%25en0",
        "203.0.113.7, 198.51.100.1",
        "203.0.113.256",
        "010.0.0.1",
        "1.2.3",
        "0x7f.0.0.1",
        "203.0.113.7/32",
        "2001:db8:::1",
        "\u{ff11}.2.3.4",
    ] {
        let cf = parse_with("cf-connecting-ip", Some(bad));
        // §9.3 table: invalid is handled like missing, including
        // `client_ip_header_missing = true`.
        assert_eq!(
            cf.client_ip,
            ClientIp::Unknown {
                header_missing: true
            },
            "{bad:?}"
        );
        assert!(cf.missing_signals.is_empty(), "{bad:?}");
    }
}

#[test]
fn connecting_ip_accepts_v4_v6_and_restores_mapped() {
    let cases = [
        ("192.0.2.1", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        (
            "2001:DB8::7",
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
        ),
        (
            "::ffff:203.0.113.7",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ),
        (
            "::ffff:cb00:7107",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ),
    ];
    for (value, expected) in cases {
        let cf = parse_with("cf-connecting-ip", Some(value));
        assert_eq!(
            cf.client_ip,
            ClientIp::Known(expected, IpSource::CfConnectingIp),
            "{value}"
        );
    }
}

/// §9.3: `cf-connecting-ipv6` is used, first, only under Pseudo IPv4 =
/// Overwrite; otherwise (or when absent / invalid / not IPv6) the Edge falls
/// back to `cf-connecting-ip`.
#[test]
fn connecting_ipv6_only_under_pseudo_ipv4_overwrite() {
    let owners = owners();
    let mut overwrite = site(&owners);
    overwrite.pseudo_ipv4_overwrite = true;
    let real = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 1));
    let pseudo = IpAddr::V4(Ipv4Addr::new(240, 16, 0, 1));

    let h = [
        ("cf-connecting-ip", "240.16.0.1"),
        ("cf-connecting-ipv6", "2001:db8:abcd::1"),
    ];
    assert_eq!(
        parse(&h, &overwrite).client_ip,
        ClientIp::Known(real, IpSource::CfConnectingIpv6)
    );
    assert_eq!(
        parse(&h, &site(&owners)).client_ip,
        ClientIp::Known(pseudo, IpSource::CfConnectingIp)
    );

    for bad in ["240.16.0.1", "[2001:db8::1]", "garbage", ""] {
        let h = [
            ("cf-connecting-ip", "240.16.0.1"),
            ("cf-connecting-ipv6", bad),
        ];
        assert_eq!(
            parse(&h, &overwrite).client_ip,
            ClientIp::Known(pseudo, IpSource::CfConnectingIp),
            "{bad:?}"
        );
    }
    assert_eq!(
        parse(&[("cf-connecting-ip", "192.0.2.1")], &overwrite).client_ip,
        ClientIp::Known(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpSource::CfConnectingIp
        )
    );
    assert_eq!(
        parse(&[("cf-connecting-ipv6", "garbage")], &overwrite).client_ip,
        ClientIp::Unknown {
            header_missing: true
        }
    );
}

/// §2.4 item 5 / D-31: `Debug` output never shows the client address or
/// the TLS client random.
#[test]
fn debug_output_redacts_client_ip_and_tls_random() {
    let cf = parse_with("cf-connecting-ip", Some("203.0.113.7"));
    let debug = format!("{cf:?}");
    assert!(!debug.contains("203.0.113.7"), "{debug}");
    assert!(!debug.contains("203"), "{debug}");
    assert!(!debug.contains(TLS_RANDOM), "{debug}");
    assert!(
        !debug.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"),
        "{debug}"
    );
    assert!(debug.contains("redacted"), "{debug}");

    let v6 = parse_with("cf-connecting-ip", Some("2001:db8::7"));
    let debug = format!("{:?}", v6.client_ip);
    assert!(!debug.contains("2001"), "{debug}");
    assert!(!debug.contains("db8"), "{debug}");
}

// ---- cf-ray, cf-visitor ----

#[test]
fn cf_ray_row() {
    let max = "A".repeat(64);
    assert_eq!(
        parse_with("cf-ray", Some(&max)).cf_ray.as_deref(),
        Some(max.as_str())
    );
    for bad in ["", "8a1b_SJC", "8a1b SJC", "8a1b;SJC", &"a".repeat(65)] {
        assert_eq!(parse_with("cf-ray", Some(bad)).cf_ray, None, "{bad:?}");
    }
    let cf = parse_with("cf-ray", None);
    assert_eq!(cf.cf_ray, None);
    assert!(cf.missing_signals.is_empty());
}

#[test]
fn cf_visitor_row() {
    let http = parse_with("cf-visitor", Some(r#"{"scheme":"http"}"#));
    assert!(!http.visitor_https);
    assert!(parse_with("cf-visitor", Some(r#"{ "scheme" : "https" }"#)).visitor_https);
    // Unknown members are ignored.
    assert!(!parse_with("cf-visitor", Some(r#"{"scheme":"http","x":1}"#)).visitor_https);
    // Missing or invalid: treated as https.
    assert!(parse_with("cf-visitor", None).visitor_https);
    for bad in [
        "http",
        r#"{"scheme":"ftp"}"#,
        r#"{"scheme":1}"#,
        r#"{"Scheme":"http"}"#,
        r#"{"scheme":"http","scheme":"http"}"#,
        r#"["http"]"#,
        r#"{"scheme":"HTTP"}"#,
    ] {
        assert!(parse_with("cf-visitor", Some(bad)).visitor_https, "{bad}");
    }
    // Over 64 bytes, even though it would otherwise say http.
    let long = format!(r#"{{"scheme":"http","pad":"{}"}}"#, "x".repeat(40));
    assert!(long.len() > 64);
    assert!(parse_with("cf-visitor", Some(&long)).visitor_https);
    let exactly_64 = format!(r#"{{"scheme":"http","pad":"{}"}}"#, "x".repeat(64 - 26));
    assert_eq!(exactly_64.len(), 64);
    assert!(!parse_with("cf-visitor", Some(&exactly_64)).visitor_https);
}

// ---- cf-worker (§9.3, §9.3.2, §9.4 step 4) ----

#[test]
fn cf_worker_owner_foreign_invalid() {
    let owners = owners();
    let s = site(&owners);
    let zone = |v: &str| parse(&[("cf-worker", v)], &s).worker;
    assert_eq!(parse(&[], &s).worker, WorkerZone::None);
    assert_eq!(zone("example.com"), WorkerZone::Owner);
    assert_eq!(zone("example.net"), WorkerZone::Owner);
    assert_eq!(zone("evil.example"), WorkerZone::Foreign);
    assert_eq!(zone("sub.example.com"), WorkerZone::Foreign);
    assert_eq!(zone("example.co"), WorkerZone::Foreign);
    // Invalid values are foreign, never "no Worker".
    for bad in [
        "",
        "Example.com",
        "EXAMPLE.COM",
        "example.com.",
        "-example.com",
        "example..com",
        "exa mple.com",
        "example.com:443",
        "exämple.com",
        "example_zone.com",
    ] {
        assert_eq!(zone(bad), WorkerZone::Foreign, "{bad:?}");
    }
    let too_long = format!("{}.com", vec!["a".repeat(63); 4].join("."));
    assert!(too_long.len() > 253);
    assert_eq!(zone(&too_long), WorkerZone::Foreign);
    // Repeated cf-worker, even with owner values.
    assert_eq!(
        parse(
            &[("cf-worker", "example.com"), ("CF-Worker", "example.com")],
            &s
        )
        .worker,
        WorkerZone::Foreign
    );
}

/// §9.4 step 4 / I-4: without owner zones (bootstrap without
/// `bootstrap_owner_zones`) every Worker is foreign; owner zones configured
/// with capitals still match the lower-case header.
#[test]
fn cf_worker_owner_zone_list_edge_cases() {
    let none: Vec<String> = Vec::new();
    assert_eq!(
        parse(&[("cf-worker", "example.com")], &site(&none)).worker,
        WorkerZone::Foreign
    );
    let caps = vec!["Example.COM".to_owned()];
    assert_eq!(
        parse(&[("cf-worker", "example.com")], &site(&caps)).worker,
        WorkerZone::Owner
    );
}

// ---- visitor location headers ----

#[test]
fn location_headers_rows() {
    assert_eq!(
        parse_with("cf-ipcountry", Some("XX")).upstream_country,
        None
    );
    let tor = parse_with("cf-ipcountry", Some("T1"));
    assert_eq!(tor.upstream_country.as_deref(), Some("T1"));
    assert!(tor.is_tor());
    for bad in ["hk", "HKG", "H", "H1", "", "U S"] {
        assert_eq!(
            parse_with("cf-ipcountry", Some(bad)).upstream_country,
            None,
            "{bad:?}"
        );
    }
    let max = "R".repeat(64);
    assert_eq!(
        parse_with("cf-region-code", Some(&max))
            .upstream_region
            .as_deref(),
        Some(max.as_str())
    );
    for bad in [&"R".repeat(65), "", "C\u{1}A", "Zürich"] {
        assert_eq!(
            parse_with("cf-region-code", Some(bad)).upstream_region,
            None,
            "{bad:?}"
        );
    }
    for good in [
        "America/Argentina/Buenos_Aires",
        "Etc/GMT+8",
        "Etc/GMT-14",
        "UTC",
    ] {
        assert_eq!(
            parse_with("cf-timezone", Some(good))
                .upstream_timezone
                .as_deref(),
            Some(good)
        );
    }
    for bad in [
        "Asia/Hong Kong",
        "",
        "Europe/Zürich",
        &"A".repeat(65),
        "a;b",
    ] {
        assert_eq!(
            parse_with("cf-timezone", Some(bad)).upstream_timezone,
            None,
            "{bad:?}"
        );
    }
    // Missing location headers never alarm.
    let cf = parse_with("cf-ipcountry", None);
    assert_eq!(cf.upstream_country, None);
    assert!(cf.missing_signals.is_empty());
}

#[test]
fn location_headers_ignored_unless_confirmed() {
    let owners = owners();
    let mut s = site(&owners);
    s.location_headers = false;
    let cf = parse(BASE, &s);
    assert_eq!(cf.upstream_country, None);
    assert_eq!(cf.upstream_region, None);
    assert_eq!(cf.upstream_timezone, None);
    let tor = parse(&[("cf-ipcountry", "T1")], &s);
    assert!(!tor.is_tor());
    assert!(cf.missing_signals.is_empty());
}

// ---- x-mg-cf-tls-* (EDGE_TLS) ----

/// Invalid values of each TLS header: the field is missing and its signal
/// alarms for an https visitor.
#[test]
fn edge_tls_rows_invalid_and_missing() {
    let cases: &[(&str, &[&str])] = &[
        (
            "x-mg-cf-tls-version",
            &["", "TLSv1.3!", "TLS v1.3", "TLSv1.3-extra-long"],
        ),
        (
            "x-mg-cf-tls-cipher",
            &["", "AES 128", "AES.128", &"C".repeat(65)],
        ),
        (
            "x-mg-cf-tls-ciphers-sha1",
            &[
                "not base64",
                "AAECAwQFBgcICQoLDA0ODxAREg==",
                "AAECAwQFBgcICQoLDA0ODxAREhMU",
                "-__7__v_-__7__v_-__7__v_-_8=",
                "3zN0vNnT0h1r1TmXnq4B3Ic1S0d=",
                "",
            ],
        ),
        (
            "x-mg-cf-tls-ext-sha1",
            &[
                "AAECAwQFBgcICQoLDA0ODxAREhM==",
                "AAECAwQFBgcICQoLDA0ODxAREhM=AAAA",
            ],
        ),
        (
            "x-mg-cf-tls-hello-len",
            &["0", "65536", "-1", "abc", "0512", "5 12", "+512", ""],
        ),
    ];
    for (name, bads) in cases {
        let signal = name.strip_prefix("x-mg-cf-").unwrap();
        for bad in bads.iter().map(Some).chain([None]) {
            let cf = parse_with(name, bad.copied());
            let tls = cf.edge_tls.clone().expect("other TLS fields are valid");
            let field_missing = match *name {
                "x-mg-cf-tls-version" => tls.version.is_none(),
                "x-mg-cf-tls-cipher" => tls.cipher.is_none(),
                "x-mg-cf-tls-ciphers-sha1" => tls.ciphers_sha1.is_none(),
                "x-mg-cf-tls-ext-sha1" => tls.ext_sha1.is_none(),
                _ => tls.hello_len.is_none(),
            };
            assert!(field_missing, "{name}: {bad:?}");
            assert_eq!(cf.missing_signals, [signal], "{name}: {bad:?}");
        }
    }
}

#[test]
fn edge_tls_valid_boundaries() {
    let tls = |name: &str, v: &str| parse_with(name, Some(v)).edge_tls.unwrap();
    assert_eq!(tls("x-mg-cf-tls-hello-len", "1").hello_len, Some(1));
    assert_eq!(
        tls("x-mg-cf-tls-hello-len", "65535").hello_len,
        Some(65_535)
    );
    assert_eq!(
        tls("x-mg-cf-tls-version", "TLSv1.2").version.as_deref(),
        Some("TLSv1.2")
    );
    let v16 = "a.b_c-d0123456789"[..16].to_owned();
    assert_eq!(tls("x-mg-cf-tls-version", &v16).version, Some(v16));
    let c64 = "C_-".repeat(22)[..64].to_owned();
    assert_eq!(tls("x-mg-cf-tls-cipher", &c64).cipher, Some(c64));
    // Unpadded base64 is accepted and stored in canonical padded form.
    assert_eq!(
        tls("x-mg-cf-tls-ciphers-sha1", "3zN0vNnT0h1r1TmXnq4B3Ic1S0c")
            .ciphers_sha1
            .as_deref(),
        Some(CIPHERS_SHA1)
    );
    assert_eq!(
        tls("x-mg-cf-tls-ext-sha1", "+//7//v/+//7//v/+//7//v/+/8=")
            .ext_sha1
            .as_deref(),
        Some("+//7//v/+//7//v/+//7//v/+/8=")
    );
}

/// `x-mg-cf-tls-random` is validated (32 bytes of base64) and alarms when
/// invalid, but its value is never kept.
#[test]
fn tls_random_row() {
    for bad in [
        Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg=="),
        Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8fHw=="),
        Some("not base64 at all"),
        None,
    ] {
        let cf = parse_with("x-mg-cf-tls-random", bad);
        assert_eq!(cf.missing_signals, ["tls-random"], "{bad:?}");
    }
    let cf = parse_with(
        "x-mg-cf-tls-random",
        Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
    );
    assert!(cf.missing_signals.is_empty());
}

/// §9.3: EDGE_TLS headers alarm only for https visitors; `edge_tls` is
/// `None` when no TLS field is valid and `Some` as soon as one is.
#[test]
fn edge_tls_alarms_only_for_https_visitors() {
    let owners = owners();
    let s = site(&owners);
    let http_only = parse(&[("cf-visitor", r#"{"scheme":"http"}"#)], &s);
    assert_eq!(http_only.edge_tls, None);
    assert_eq!(
        http_only.missing_signals,
        ["http-version", "rtt", "asn", "vbot", "hdr-names"]
    );
    // A missing cf-visitor counts as https.
    let nothing = parse(&[], &s);
    assert_eq!(nothing.edge_tls, None);
    assert_eq!(
        nothing.missing_signals,
        [
            "tls-version",
            "tls-cipher",
            "tls-ciphers-sha1",
            "tls-ext-sha1",
            "tls-hello-len",
            "tls-random",
            "http-version",
            "rtt",
            "asn",
            "vbot",
            "hdr-names"
        ]
    );
    let one = parse(&[("x-mg-cf-tls-hello-len", "300")], &s);
    assert_eq!(
        one.edge_tls,
        Some(EdgeTls {
            hello_len: Some(300),
            ..EdgeTls::default()
        })
    );
}

// ---- http version, RTT, ASN, verified bot, header names ----

#[test]
fn http_version_row() {
    for good in ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"] {
        let cf = parse_with("x-mg-cf-http-version", Some(good));
        assert_eq!(cf.http_version.as_deref(), Some(good));
    }
    for bad in [
        None,
        Some(""),
        Some("HTTP/2.0"),
        Some("http/2"),
        Some("h2"),
        Some("HTTP/4"),
    ] {
        let cf = parse_with("x-mg-cf-http-version", bad);
        assert_eq!(cf.http_version, None, "{bad:?}");
        assert_eq!(cf.missing_signals, ["http-version"], "{bad:?}");
    }
}

#[test]
fn rtt_row_uses_quic_for_http3_else_tcp() {
    let owners = owners();
    let s = site(&owners);
    let cf = parse(
        &[
            ("x-mg-cf-http-version", "HTTP/3"),
            ("x-mg-cf-rtt", "0"),
            ("x-mg-cf-quic-rtt", "41"),
        ],
        &s,
    );
    assert_eq!(cf.rtt_ms, Some(41));
    assert!(!cf.missing_signals.contains(&"quic-rtt"));
    assert!(!cf.missing_signals.contains(&"rtt"));

    let cf = parse(
        &[("x-mg-cf-http-version", "HTTP/3"), ("x-mg-cf-rtt", "12")],
        &s,
    );
    assert_eq!(cf.rtt_ms, None);
    assert!(cf.missing_signals.contains(&"quic-rtt"));
    assert!(!cf.missing_signals.contains(&"rtt"));

    let cf = parse(
        &[
            ("x-mg-cf-http-version", "HTTP/1.1"),
            ("x-mg-cf-quic-rtt", "12"),
        ],
        &s,
    );
    assert_eq!(cf.rtt_ms, None);
    assert!(cf.missing_signals.contains(&"rtt"));
    assert!(!cf.missing_signals.contains(&"quic-rtt"));

    // Without a (valid) version the TCP value is used.
    let cf = parse(&[("x-mg-cf-rtt", "60000")], &s);
    assert_eq!(cf.rtt_ms, Some(60_000));

    for bad in ["0", "60001", "-5", "1.5", "012", ""] {
        let cf = parse_with("x-mg-cf-rtt", Some(bad));
        assert_eq!(cf.rtt_ms, None, "{bad:?}");
        assert_eq!(cf.missing_signals, ["rtt"], "{bad:?}");
    }

    // The QUIC value follows the same rule for HTTP/3 visitors.
    let quic = |v: &str| {
        parse(
            &[
                ("x-mg-cf-http-version", "HTTP/3"),
                ("x-mg-cf-rtt", "0"),
                ("x-mg-cf-quic-rtt", v),
            ],
            &s,
        )
    };
    assert_eq!(quic("60000").rtt_ms, Some(60_000));
    for bad in ["0", "60001", "-5", "1.5", "012", ""] {
        let cf = quic(bad);
        assert_eq!(cf.rtt_ms, None, "{bad:?}");
        assert!(cf.missing_signals.contains(&"quic-rtt"), "{bad:?}");
        assert!(!cf.missing_signals.contains(&"rtt"), "{bad:?}");
    }
}

#[test]
fn asn_row() {
    assert_eq!(parse_with("x-mg-cf-asn", Some("1")).upstream_asn, Some(1));
    assert_eq!(
        parse_with("x-mg-cf-asn", Some("4294967295")).upstream_asn,
        Some(u32::MAX)
    );
    for bad in [
        None,
        Some("0"),
        Some("4294967296"),
        Some("AS64500"),
        Some("064500"),
        Some(""),
    ] {
        let cf = parse_with("x-mg-cf-asn", bad);
        assert_eq!(cf.upstream_asn, None, "{bad:?}");
        assert_eq!(cf.missing_signals, ["asn"], "{bad:?}");
    }
}

#[test]
fn vbot_rows() {
    assert_eq!(parse_with("x-mg-cf-vbot", Some("true")).cf_vbot, Some(true));
    for bad in [None, Some("TRUE"), Some("1"), Some("yes"), Some("")] {
        let cf = parse_with("x-mg-cf-vbot", bad);
        assert_eq!(cf.cf_vbot, None, "{bad:?}");
        assert_eq!(cf.missing_signals, ["vbot"], "{bad:?}");
    }
    for good in [
        "Monitoring & Analytics",
        "Page Preview (Social)",
        "AI Crawler",
        "Search Engine Optimization",
        "a/b.c,d_e-f",
    ] {
        assert_eq!(
            parse_with("x-mg-cf-vbot-cat", Some(good))
                .cf_vbot_cat
                .as_deref(),
            Some(good)
        );
    }
    // The category never alarms: it is absent for every non-bot request.
    for bad in [
        None,
        Some("a;b"),
        Some("a\"b"),
        Some(""),
        Some(&*"c".repeat(65)),
    ] {
        let cf = parse_with("x-mg-cf-vbot-cat", bad);
        assert_eq!(cf.cf_vbot_cat, None, "{bad:?}");
        assert!(cf.missing_signals.is_empty(), "{bad:?}");
    }
}

#[test]
fn header_names_row() {
    let names = |v: &str| parse_with("x-mg-cf-hdr-names", Some(v)).header_names;
    assert_eq!(
        names("Accept,accept,ACCEPT,X-Custom_1"),
        Some(vec!["Accept".to_owned(), "X-Custom_1".to_owned()])
    );
    let max: Vec<String> = (0..128).map(|i| format!("h{i}")).collect();
    assert_eq!(names(&max.join(",")), Some(max.clone()));
    let repeated = vec!["a"; 128].join(",");
    assert_eq!(names(&repeated), Some(vec!["a".to_owned()]));
    // Set semantics: the 128 cap is on distinct names. Cloudflare repeats
    // the name of a repeated field (HTTP/2 browsers send every cookie as
    // its own `cookie` field), which must not make the signal MISSING.
    let mut crumbs: Vec<String> = max.clone();
    crumbs.extend((0..200).map(|i| if i % 2 == 0 { "cookie" } else { "H0" }.to_owned()));
    crumbs[127] = "cookie".to_owned();
    let mut expected = max[..127].to_vec();
    expected.push("cookie".to_owned());
    assert_eq!(names(&crumbs.join(",")), Some(expected));
    let item_64 = "n".repeat(64);
    assert_eq!(names(&item_64), Some(vec![item_64.clone()]));

    let too_many = (0..129)
        .map(|i| format!("h{i}"))
        .collect::<Vec<_>>()
        .join(",");
    for bad in [
        "a,,b",
        ",a",
        "a,",
        "a, b",
        "a b",
        "a:b",
        &"n".repeat(65),
        too_many.as_str(),
        "",
    ] {
        let cf = parse_with("x-mg-cf-hdr-names", Some(bad));
        assert_eq!(cf.header_names, None, "{bad:?}");
        assert_eq!(cf.missing_signals, ["hdr-names"], "{bad:?}");
    }
    assert_eq!(
        parse_with("x-mg-cf-hdr-names", None).missing_signals,
        ["hdr-names"]
    );
}

// ---- Tier 1 ----

#[test]
fn tier1_requires_site_flag_and_valid_marker() {
    let owners = owners();
    let mut off = site(&owners);
    off.tier1 = false;
    assert_eq!(parse(BASE, &off).tier1, None);

    for marker in [
        None,
        Some(""),
        Some("Snippet"),
        Some("yes"),
        Some("snippet,worker"),
    ] {
        let cf = parse_with("x-mg-cf-t1", marker);
        assert_eq!(cf.tier1, None, "{marker:?}");
        // Tier 1 never alarms.
        assert!(cf.missing_signals.is_empty(), "{marker:?}");
    }
    let worker = parse_with("x-mg-cf-t1", Some("worker")).tier1.unwrap();
    assert_eq!(worker.source, Tier1Source::Worker);
    assert_eq!(worker.source.as_str(), "worker");
    assert_eq!(Tier1Source::Snippet.as_str(), "snippet");
}

#[test]
fn tier1_fields_invalid_or_missing_are_missing() {
    let t1 = |name: &str, v: Option<&str>| parse_with(name, v).tier1.expect("marker is valid");
    assert_eq!(t1("x-mg-cf-priority", Some("u=0, i")).priority, None);
    assert_eq!(
        t1("x-mg-cf-priority", Some(&"p".repeat(129))).priority,
        None
    );
    assert_eq!(t1("x-mg-cf-priority", None).priority, None);
    let p128 = "w=1;".repeat(32);
    assert_eq!(t1("x-mg-cf-priority", Some(&p128)).priority, Some(p128));

    let ae256 = "gzip, ".repeat(43)[..256].trim_end().to_owned();
    assert_eq!(
        t1("x-mg-cf-accept-encoding", Some(&ae256)).accept_encoding_orig,
        Some(ae256)
    );
    for bad in [&"g".repeat(257), "gzip,\u{1}br", "gzip, ü", ""] {
        assert_eq!(
            t1("x-mg-cf-accept-encoding", Some(bad)).accept_encoding_orig,
            None,
            "{bad:?}"
        );
    }

    assert_eq!(
        t1("x-mg-cf-as-org", Some("M%C3%BCnchen%20AG"))
            .as_org
            .as_deref(),
        Some("München AG")
    );
    for bad in ["%ZZ", "%C3", "a%0Ab", "%FF%FE", "", "a\u{e9}b"] {
        assert_eq!(t1("x-mg-cf-as-org", Some(bad)).as_org, None, "{bad:?}");
    }
    let cf = parse_with("x-mg-cf-as-org", Some("%ZZ"));
    assert!(cf.missing_signals.is_empty());
}

/// Missing values of the rows that never alarm: location headers (only
/// `cf-region-code` feeds `upstream_region`; `cf-region` is ignored) and the
/// Tier 1 values.
#[test]
fn missing_rows_without_alarm() {
    let owners = owners();
    let s = site(&owners);
    let region_name_only = parse(&[("cf-region", "Hong Kong")], &s);
    assert_eq!(region_name_only.upstream_region, None);

    let cf = parse_with("cf-region-code", None);
    assert_eq!(cf.upstream_region, None);
    assert!(cf.missing_signals.is_empty());
    let cf = parse_with("cf-timezone", None);
    assert_eq!(cf.upstream_timezone, None);
    assert!(cf.missing_signals.is_empty());

    let cf = parse_with("x-mg-cf-accept-encoding", None);
    assert_eq!(cf.tier1.as_ref().unwrap().accept_encoding_orig, None);
    assert!(cf.missing_signals.is_empty());
    let cf = parse_with("x-mg-cf-as-org", None);
    assert_eq!(cf.tier1.as_ref().unwrap().as_org, None);
    assert!(cf.missing_signals.is_empty());
}

/// §9.3: a missing `x-mg-cf-rtt` alarms as `rtt` for a TCP visitor.
#[test]
fn rtt_missing_alarms() {
    let cf = parse_with("x-mg-cf-rtt", None);
    assert_eq!(cf.rtt_ms, None);
    assert_eq!(cf.missing_signals, ["rtt"]);
}
