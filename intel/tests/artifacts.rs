//! Artifact parsing and validation against the shared samples in
//! `testdata/phase1/artifacts/` (spec §7.5, §7.7, §12.0, §12.2–§12.4) plus
//! targeted negative cases for every §12.3 rule (D-36).

mod common;

use common::{ip, phase1, read};
use mg_intel::{
    ArtifactKind, CrawlerRegistry, IntelError, IpSet, VerifyMode, parse_asn_list,
    parse_cloudflare_ips, verify_sha256,
};
use serde_json::{Value, json};

fn artifact(name: &str) -> Vec<u8> {
    read(phase1().join("artifacts").join(name))
}

fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

// ---------------------------------------------------------------------------
// Valid samples (§12.0: every reader accepts them)
// ---------------------------------------------------------------------------

/// §12.2: `cloudflare-ips.json` is accepted with its metadata.
#[test]
fn sample_cloudflare_ips_accepted() {
    let cf = parse_cloudflare_ips(&artifact("cloudflare-ips.json")).unwrap();
    assert_eq!(cf.fetched_at, "2026-09-27T10:00:00Z");
    assert_eq!(cf.etag, "38f79d050aa027e3be3865e495dcc9bc");
    for inside in [
        "173.245.48.1",
        "104.16.0.0",
        "104.23.255.255",
        "131.0.75.255",
        "2400:cb00::1",
        "2a06:98c7:ffff::1",
        "::ffff:173.245.48.1",
    ] {
        assert!(cf.set.contains(ip(inside)), "{inside}");
    }
    for outside in ["1.1.1.1", "104.32.0.0", "2400:cb01::1", "127.0.0.1"] {
        assert!(!cf.set.contains(ip(outside)), "{outside}");
    }
}

/// §12.0 / §16: what the Go writer produces loads here. The golden output of
/// WP-G3's `mgctl crawler sync` test (written by Go, never edited by hand)
/// passes every §12.3 check of the Rust reader.
#[test]
fn go_crawler_sync_output_accepted() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../control-plane/testdata/intel/crawler/expected-registry.json");
    let reg = CrawlerRegistry::from_artifact(&read(path)).unwrap();
    assert!(!reg.is_test());
    let ids: Vec<_> = reg.operators().iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, ["googlebot", "gptbot", "archivebot", "rdnsbot"]);
    let g = reg.operator("gptbot").unwrap();
    assert_eq!(g.mode, VerifyMode::IpRanges);
    assert!(g.cidrs.contains(ip("20.171.206.9")));
    assert_eq!(reg.operator("rdnsbot").unwrap().mode, VerifyMode::Rdns);
}

/// §12.3: `crawler-registry.json` is accepted; operators keep file order.
#[test]
fn sample_crawler_registry_accepted() {
    let reg = CrawlerRegistry::from_artifact(&artifact("crawler-registry.json")).unwrap();
    assert!(!reg.is_test());
    assert_eq!(reg.generated_at(), "2026-09-27T10:00:00Z");
    let ids: Vec<_> = reg.operators().iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, ["googlebot", "bingbot", "gptbot"]);

    let g = reg.operator("googlebot").unwrap();
    assert_eq!(g.name, "Googlebot");
    assert_eq!(g.purpose, "search");
    assert_eq!(g.mode, VerifyMode::IpRangesOrRdns);
    assert_eq!(g.rdns_suffixes, [".googlebot.com", ".google.com"]);
    assert!(g.cidrs.contains(ip("66.249.64.63")));
    assert!(!g.cidrs.contains(ip("66.249.64.64")));
    assert!(g.cidrs.contains(ip("2001:4860:4801:10::1")));

    let gpt = reg.operator("gptbot").unwrap();
    assert_eq!(gpt.mode, VerifyMode::IpRanges);
    assert_eq!(gpt.purpose, "ai_training");
    assert!(gpt.rdns_suffixes.is_empty());
    assert!(reg.operator("applebot").is_none());
}

/// §12.3: the `"test": true` registry with documentation ranges loads.
#[test]
fn sample_test_registry_accepted() {
    let reg = CrawlerRegistry::from_artifact(&artifact("crawler-registry.test.json")).unwrap();
    assert!(reg.is_test());
    let g = reg.operator("googlebot").unwrap();
    assert!(g.cidrs.contains(ip("198.51.100.127")));
    assert!(!g.cidrs.contains(ip("198.51.100.128")));
    assert!(g.cidrs.contains(ip("2001:db8:4860::1")));
    assert!(
        reg.operator("gptbot")
            .unwrap()
            .cidrs
            .contains(ip("192.0.2.1"))
    );
}

/// §12.4: both text lists are accepted.
#[test]
fn sample_text_lists_accepted() {
    let asns =
        parse_asn_list(std::str::from_utf8(&artifact("datacenter-asns.txt")).unwrap()).unwrap();
    assert_eq!(asns.into_iter().collect::<Vec<_>>(), [8075, 15169, 16509]);

    let tor = IpSet::from_text(std::str::from_utf8(&artifact("tor-exits.txt")).unwrap()).unwrap();
    assert!(tor.contains(ip("192.0.2.10")));
    assert!(!tor.contains(ip("192.0.2.11")));
    assert!(tor.contains(ip("198.51.100.15")));
    assert!(!tor.contains(ip("198.51.100.16")));
    assert!(tor.contains(ip("2001:db8::10")));
    assert!(tor.contains(ip("::ffff:192.0.2.10")));
}

// ---------------------------------------------------------------------------
// Invalid samples (§12.0: every reader rejects each one)
// ---------------------------------------------------------------------------

/// Expected rejection reason per shared invalid sample, so each file is
/// rejected for the rule it exercises and not by accident.
const INVALID: &[(&str, &str)] = &[
    ("cloudflare-ips.documentation.json", "documentation"),
    ("cloudflare-ips.host-bits.json", "host bits"),
    ("cloudflare-ips.prefix-too-short.json", "prefix length /7"),
    ("cloudflare-ips.private.json", "private"),
    ("cloudflare-ips.too-few-v4.json", "ipv4_cidrs has 4 entries"),
    ("cloudflare-ips.wrong-kind.json", "kind"),
    (
        "crawler-registry.documentation-without-test.json",
        "documentation",
    ),
    (
        "crawler-registry.duplicate-id.json",
        "duplicate operator id",
    ),
    ("crawler-registry.host-bits.json", "host bits"),
    (
        "crawler-registry.ip-ranges-without-cidrs.json",
        "requires cidrs",
    ),
    ("crawler-registry.private.json", "private"),
    (
        "crawler-registry.rdns-without-suffixes.json",
        "requires rdns_suffixes",
    ),
    ("crawler-registry.slash-zero.json", "shorter than /16"),
    ("crawler-registry.test-loopback.json", "loopback"),
    ("crawler-registry.too-broad-v4.json", "shorter than /16"),
    ("crawler-registry.too-broad-v6.json", "shorter than /32"),
    ("crawler-registry.unknown-mode.json", "unknown verify.mode"),
    ("crawler-registry.uppercase-suffix.json", "lower-case"),
    ("datacenter-asns.bad-line.txt", "line 2"),
    ("datacenter-asns.zero.txt", "line 1: \"0\": ASN 0"),
    ("tor-exits.bad-line.txt", "line 2"),
];

fn parse_by_name(name: &str, bytes: &[u8]) -> Result<(), IntelError> {
    let text = || std::str::from_utf8(bytes).expect("text sample is UTF-8");
    if name.starts_with("cloudflare-ips.") {
        parse_cloudflare_ips(bytes).map(drop)
    } else if name.starts_with("crawler-registry.") {
        CrawlerRegistry::from_artifact(bytes).map(drop)
    } else if name.starts_with("datacenter-asns.") {
        parse_asn_list(text()).map(drop)
    } else if name.starts_with("tor-exits.") {
        IpSet::from_text(text()).map(drop)
    } else {
        panic!("no parser for sample {name}");
    }
}

#[test]
fn every_invalid_sample_rejected() {
    let dir = phase1().join("artifacts/invalid");
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let err = parse_by_name(&name, &read(path.clone()))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        if let Some((_, want)) = INVALID.iter().find(|(n, _)| *n == name) {
            let msg = err.to_string();
            assert!(
                msg.contains(want),
                "{name}: {msg:?} does not mention {want:?}"
            );
        } else {
            eprintln!("note: {name} rejected ({err}); add its reason to INVALID");
        }
        seen.push(name);
    }
    for (name, _) in INVALID {
        assert!(seen.iter().any(|s| s == name), "sample {name} is missing");
    }
}

// ---------------------------------------------------------------------------
// §12.3 rules, one by one (D-36)
// ---------------------------------------------------------------------------

fn registry() -> Value {
    serde_json::from_slice(&artifact("crawler-registry.json")).unwrap()
}

fn test_registry() -> Value {
    serde_json::from_slice(&artifact("crawler-registry.test.json")).unwrap()
}

fn reject(v: &Value, want: &str) {
    match CrawlerRegistry::from_artifact(&to_bytes(v)) {
        Ok(_) => panic!("accepted, want rejection mentioning {want:?}"),
        Err(e) => assert!(
            e.to_string().contains(want),
            "{e} does not mention {want:?}"
        ),
    }
}

fn accept(v: &Value) -> CrawlerRegistry {
    CrawlerRegistry::from_artifact(&to_bytes(v)).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn registry_header_rules() {
    let mut v = registry();
    v["v"] = json!(2);
    reject(&v, "unsupported v");
    let mut v = registry();
    v["kind"] = json!("mg-cloudflare-ips");
    reject(&v, "kind");
    let mut v = registry();
    v["generated_at"] = json!("yesterday");
    reject(&v, "generated_at");
    let mut v = registry();
    v["test"] = json!(false);
    assert!(!accept(&v).is_test());
    let mut v = registry();
    v["operators"] = json!([]);
    assert!(accept(&v).operators().is_empty());
}

/// §12.0: readers reject unknown fields at every level, and missing fields.
#[test]
fn registry_rejects_unknown_and_missing_fields() {
    let mut v = registry();
    v["extra"] = json!(1);
    reject(&v, "unknown field");
    let mut v = registry();
    v["operators"][0]["extra"] = json!(1);
    reject(&v, "unknown field");
    let mut v = registry();
    v["operators"][0]["verify"]["extra"] = json!(1);
    reject(&v, "unknown field");
    let mut v = registry();
    v["operators"][0]["sources"][0]["extra"] = json!(1);
    reject(&v, "unknown field");
    let mut v = registry();
    v["operators"][0].as_object_mut().unwrap().remove("sources");
    reject(&v, "missing field");
    let mut v = registry();
    v.as_object_mut().unwrap().remove("generated_at");
    reject(&v, "missing field");
    // Duplicate keys are not silently merged.
    let text = String::from_utf8(artifact("crawler-registry.json")).unwrap();
    let dup = text.replacen("\"v\": 1,", "\"v\": 1, \"v\": 1,", 1);
    assert!(CrawlerRegistry::from_artifact(dup.as_bytes()).is_err());
}

#[test]
fn registry_operator_rules() {
    for bad_id in [
        "",
        "Googlebot",
        "-bot",
        "_bot",
        "bot.x",
        "b ot",
        &"a".repeat(33),
    ] {
        let mut v = registry();
        v["operators"][2]["id"] = json!(bad_id);
        reject(&v, "id must match");
    }
    for good_id in ["a", "0bot", "g-p_t", &"a".repeat(32)] {
        let mut v = registry();
        v["operators"][2]["id"] = json!(good_id);
        accept(&v);
    }
    let mut v = registry();
    v["operators"][0]["purpose"] = json!("scraping");
    reject(&v, "unknown purpose");
    for purpose in mg_intel::PURPOSES {
        let mut v = registry();
        v["operators"][0]["purpose"] = json!(purpose);
        accept(&v);
    }
    let mut v = registry();
    v["operators"][0]["ua_tokens"] = json!([]);
    reject(&v, "0 ua_tokens");
    let mut v = registry();
    v["operators"][0]["ua_tokens"] = json!(vec!["abc"; 9]);
    reject(&v, "9 ua_tokens");
    let mut v = registry();
    v["operators"][0]["ua_tokens"] = json!(["ab"]);
    reject(&v, "3-64 characters");
    let mut v = registry();
    v["operators"][0]["ua_tokens"] = json!(["x".repeat(65)]);
    reject(&v, "3-64 characters");
    let mut v = registry();
    v["operators"][0]["ua_tokens"] = json!(["abc", "é".repeat(64), "12345678"]);
    accept(&v);
}

#[test]
fn registry_verify_rules() {
    for mode in ["rdns", "ip_ranges_or_rdns"] {
        let mut v = registry();
        v["operators"][0]["verify"]["mode"] = json!(mode);
        v["operators"][0]["verify"]["rdns_suffixes"] = json!([]);
        reject(&v, "requires rdns_suffixes");
    }
    let mut v = registry();
    v["operators"][0]["verify"]["rdns_suffixes"] = json!([""]);
    reject(&v, "1-253 bytes");
    let mut v = registry();
    v["operators"][0]["verify"]["rdns_suffixes"] = json!([format!(".{}", "a".repeat(253))]);
    reject(&v, "1-253 bytes");
    let mut v = registry();
    v["operators"][0]["verify"]["rdns_suffixes"] = json!([".Google.com"]);
    reject(&v, "lower-case");
    // rDNS-only operators may publish no ranges.
    let mut v = registry();
    v["operators"][1]["verify"]["mode"] = json!("rdns");
    v["operators"][1]["cidrs"] = json!([]);
    v["operators"][1]["sources"] = json!([]);
    assert_eq!(
        accept(&v).operator("bingbot").unwrap().mode,
        VerifyMode::Rdns
    );
}

/// D-36: CIDR length floors, special ranges, documentation only in tests.
#[test]
fn registry_cidr_rules() {
    let cases: &[(&str, Option<&str>)] = &[
        ("66.249.0.0/16", None),
        ("66.248.0.0/15", Some("shorter than /16")),
        ("2001:4860::/32", None),
        ("2001:4860::/31", Some("shorter than /32")),
        ("::ffff:66.249.64.0/123", None),
        ("::ffff:66.0.0.0/104", Some("shorter than /16")),
        ("66.249.64.7", None),
        ("2001:4860:4801:10::7", None),
        ("66.249.64.1/27", Some("host bits")),
        ("66.249.64.0/033", Some("malformed prefix length")),
        ("66.249.64.0/27 ", Some("malformed prefix length")),
        ("googlebot.com", Some("not an IP address")),
        ("100.64.0.0/16", Some("CGNAT")),
        ("100.127.255.0/24", Some("CGNAT")),
        ("240.0.0.0/16", Some("reserved")),
        ("255.255.255.255", Some("reserved")),
        ("198.18.0.0/16", Some("reserved")),
        ("0.0.0.0/16", Some("unspecified")),
        ("127.0.0.1", Some("loopback")),
        ("169.254.0.0/16", Some("link-local")),
        ("224.0.0.0/16", Some("multicast")),
        ("172.16.0.0/16", Some("private")),
        ("192.168.0.0/16", Some("private")),
        ("192.0.2.0/24", Some("documentation")),
        ("203.0.113.0/24", Some("documentation")),
        ("::1", Some("loopback")),
        ("::", Some("unspecified")),
        ("64:ff9b::/96", Some("reserved")),
        ("fd00::/32", Some("private")),
        ("fe80::/32", Some("link-local")),
        ("ff02::/32", Some("multicast")),
        ("2001:db8::/32", Some("documentation")),
        // Reserved IPv6: IETF protocol assignments (incl. Teredo) and
        // anything outside global unicast 2000::/3 (same as the Go writer).
        ("2001::/32", Some("reserved")),
        ("2001:0:4136::/48", Some("reserved")),
        ("4000::/32", Some("reserved")),
        ("a000::/32", Some("reserved")),
        ("2001:200::/32", None),
        ("::ffff:10.0.0.0/112", Some("private")),
        ("::ffff:127.0.0.0/104", Some("shorter than /16")),
    ];
    for (cidr, want) in cases {
        let mut v = registry();
        v["operators"][0]["cidrs"] = json!([cidr]);
        match want {
            None => {
                accept(&v);
            }
            Some(w) => reject(&v, w),
        }
    }
    // Documentation ranges only with "test": true; other specials never.
    let mut v = test_registry();
    v["operators"][0]["cidrs"] = json!(["203.0.113.0/24", "2001:db8::/32"]);
    accept(&v);
    for cidr in [
        "10.0.0.0/16",
        "127.0.0.0/16",
        "100.64.0.0/16",
        "0.0.0.0/0",
        "fe80::/32",
    ] {
        let mut v = test_registry();
        v["operators"][0]["cidrs"] = json!([cidr]);
        assert!(
            CrawlerRegistry::from_artifact(&to_bytes(&v)).is_err(),
            "{cidr}"
        );
    }
}

#[test]
fn registry_cidr_count_limit() {
    let cidrs = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("20.{}.{}.0/24", i / 256, i % 256))
            .collect()
    };
    let mut v = registry();
    v["operators"][2]["cidrs"] = json!(cidrs(20_000));
    let reg = accept(&v);
    assert!(
        reg.operator("gptbot")
            .unwrap()
            .cidrs
            .contains(ip("20.78.31.1"))
    );
    let mut v = registry();
    v["operators"][2]["cidrs"] = json!(cidrs(20_001));
    reject(&v, "20001 cidrs, limit 20000");
}

#[test]
fn registry_source_rules() {
    let mut v = registry();
    v["operators"][0]["sources"][0]["sha256"] =
        json!("3B5D5C3712955042212316173CCF37BE800A5DD6C01B7C2E8E8A4E6D8B9C4F11");
    reject(&v, "sha256");
    let mut v = registry();
    v["operators"][0]["sources"][0]["sha256"] = json!("3b5d");
    reject(&v, "sha256");
    let mut v = registry();
    v["operators"][0]["sources"][0]["format"] = json!("csv");
    reject(&v, "unknown format");
    let mut v = registry();
    v["operators"][0]["sources"][0]["format"] = json!("cidr_text");
    accept(&v);
    let mut v = registry();
    v["operators"][0]["sources"][0]["fetched_at"] = json!("2026-09-27 10:00:00");
    reject(&v, "fetched_at");
    let mut v = registry();
    v["operators"][0]["sources"][0]["stale"] = json!("no");
    reject(&v, "invalid type");
    let mut v = registry();
    v["operators"][0]["sources"] = json!([]);
    accept(&v);
}

/// Error messages stay short (they end up in the Edge's log) even though
/// serde_json quotes an offending string value or unknown key in full.
#[test]
fn json_errors_are_bounded() {
    type Parse = fn(&[u8]) -> Result<(), IntelError>;
    let huge = "x".repeat(100_000);
    let cases: [(&str, Parse); 3] = [
        ("crawler-registry", |b| {
            CrawlerRegistry::from_artifact(b).map(drop)
        }),
        ("cloudflare-ips", |b| parse_cloudflare_ips(b).map(drop)),
        ("static resolver", |b| {
            mg_intel::StaticResolver::from_json(b).map(drop)
        }),
    ];
    for (what, parse) in cases {
        for doc in [
            format!(r#"{{"v": "{huge}"}}"#),
            format!(r#"{{"{huge}": 1}}"#),
        ] {
            let msg = parse(doc.as_bytes()).unwrap_err().to_string();
            assert!(msg.len() < 1_000, "{what}: {} bytes", msg.len());
        }
    }
}

#[test]
fn registry_size_limit() {
    let mut big = artifact("crawler-registry.json");
    big.resize(
        usize::try_from(ArtifactKind::CrawlerRegistry.max_size()).unwrap() + 1,
        b' ',
    );
    assert!(matches!(
        CrawlerRegistry::from_artifact(&big),
        Err(IntelError::TooLarge { .. })
    ));
}

/// §12.3: UA tokens are case-insensitive substrings; file order wins.
#[test]
fn ua_matching() {
    let reg = CrawlerRegistry::from_artifact(&artifact("crawler-registry.json")).unwrap();
    let m = |ua: &str| reg.match_ua(ua).map(|o| o.id.as_str());
    assert_eq!(
        m("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        Some("googlebot")
    );
    assert_eq!(m("GOOGLEBOT"), Some("googlebot"));
    assert_eq!(m("Mozilla/5.0 (compatible; BingBot/2.0)"), Some("bingbot"));
    assert_eq!(m("gptbot/1.1"), Some("gptbot"));
    // Two claims: the first operator in file order.
    assert_eq!(m("GPTBot bingbot Googlebot"), Some("googlebot"));
    assert_eq!(m("Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"), None);
    assert_eq!(m(""), None);
    assert_eq!(m("Google bot"), None);
    // A long hostile UA is handled (linear-time search).
    let hostile = "g".repeat(8192);
    assert_eq!(m(&hostile), None);
}

// ---------------------------------------------------------------------------
// §12.2 rules
// ---------------------------------------------------------------------------

fn cf() -> Value {
    serde_json::from_slice(&artifact("cloudflare-ips.json")).unwrap()
}

fn cf_reject(v: &Value, want: &str) {
    match parse_cloudflare_ips(&to_bytes(v)) {
        Ok(_) => panic!("accepted, want rejection mentioning {want:?}"),
        Err(e) => assert!(
            e.to_string().contains(want),
            "{e} does not mention {want:?}"
        ),
    }
}

fn v4_list(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("20.{i}.0.0/16")).collect()
}

fn v6_list(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("2400:{:x}::/32", i + 1)).collect()
}

#[test]
fn cloudflare_rules() {
    let mut v = cf();
    v["v"] = json!(2);
    cf_reject(&v, "unsupported v");
    let mut v = cf();
    v["extra"] = json!(true);
    cf_reject(&v, "unknown field");
    let mut v = cf();
    v.as_object_mut().unwrap().remove("etag");
    cf_reject(&v, "missing field");
    let mut v = cf();
    v["fetched_at"] = json!("2026-09-27");
    cf_reject(&v, "fetched_at");

    // Counts: IPv4 5-64, IPv6 2-32.
    for (n4, n6, ok) in [
        (5, 2, true),
        (64, 32, true),
        (4, 2, false),
        (65, 2, false),
        (5, 1, false),
        (5, 33, false),
    ] {
        let mut v = cf();
        v["ipv4_cidrs"] = json!(v4_list(n4));
        v["ipv6_cidrs"] = json!(v6_list(n6));
        assert_eq!(parse_cloudflare_ips(&to_bytes(&v)).is_ok(), ok, "{n4}/{n6}");
    }

    // Family and prefix-length ranges.
    let v4_case = |entry: &str| {
        let mut v = cf();
        v["ipv4_cidrs"][0] = json!(entry);
        v
    };
    let v6_case = |entry: &str| {
        let mut v = cf();
        v["ipv6_cidrs"][0] = json!(entry);
        v
    };
    assert!(parse_cloudflare_ips(&to_bytes(&v4_case("20.0.0.0/8"))).is_ok());
    assert!(parse_cloudflare_ips(&to_bytes(&v4_case("20.1.2.3"))).is_ok());
    cf_reject(&v4_case("20.0.0.0/7"), "prefix length /7");
    cf_reject(&v4_case("2400:cb00::/32"), "not an IPv4 network");
    cf_reject(&v4_case("::ffff:20.0.0.0/112"), "not an IPv4 network");
    cf_reject(&v4_case("100.64.0.0/10"), "CGNAT");
    cf_reject(&v4_case("127.0.0.0/8"), "loopback");
    cf_reject(&v4_case("169.254.0.0/16"), "link-local");
    cf_reject(&v4_case("224.0.0.0/8"), "multicast");
    cf_reject(&v4_case("0.0.0.0/8"), "unspecified");
    cf_reject(&v4_case("203.0.113.0/24"), "documentation");
    assert!(parse_cloudflare_ips(&to_bytes(&v6_case("2400::/16"))).is_ok());
    assert!(parse_cloudflare_ips(&to_bytes(&v6_case("2400:cb00::1"))).is_ok());
    cf_reject(&v6_case("2400::/15"), "prefix length /15");
    cf_reject(&v6_case("173.245.48.0/20"), "not an IPv6 network");
    cf_reject(&v6_case("::ffff:173.245.48.0/116"), "not an IPv6 network");
    cf_reject(&v6_case("fc00::/16"), "private");
    cf_reject(&v6_case("::/16"), "unspecified");
    cf_reject(&v6_case("ff00::/16"), "multicast");
    cf_reject(&v6_case("2001::/32"), "reserved");
    cf_reject(&v6_case("4000::/16"), "reserved");
}

#[test]
fn cloudflare_size_limit() {
    let mut big = artifact("cloudflare-ips.json");
    big.resize(
        usize::try_from(ArtifactKind::CloudflareIps.max_size()).unwrap() + 1,
        b' ',
    );
    assert!(matches!(
        parse_cloudflare_ips(&big),
        Err(IntelError::TooLarge { .. })
    ));
}

/// §7.6 / §9.10: artifacts are content-addressed by SHA-256.
#[test]
fn artifact_hash_verification() {
    let bytes = artifact("cloudflare-ips.json");
    let digest = mg_intel::sha256_hex(&bytes);
    verify_sha256(&bytes, &digest).unwrap();
    let mut tampered = bytes.clone();
    tampered[10] ^= 1;
    assert!(matches!(
        verify_sha256(&tampered, &digest),
        Err(IntelError::HashMismatch { .. })
    ));
    assert!(matches!(
        verify_sha256(&bytes, &digest.to_uppercase()),
        Err(IntelError::MalformedHash)
    ));
}
