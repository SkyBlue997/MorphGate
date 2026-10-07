//! `kh` and the key builders against `testdata/phase1/kat.json`
//! (spec §9.7 "键中的假名化", D-06, D-24; WP-C3 tests in §15).

use std::net::IpAddr;

use mg_core::Net;
use mg_edge_core::state::{
    ENTITY_DOMAIN, LIMITER_DOMAIN, LimiterKey, UNKNOWN_DIM, dims, entity_key, kh, verdict_key,
};
use serde_json::Value;

const KAT: &str = include_str!("../../testdata/phase1/kat.json");

fn kat() -> Value {
    serde_json::from_str(KAT).expect("kat.json")
}

fn k_pseudo(doc: &Value) -> [u8; 32] {
    let hex = doc["entity_key"]["k_pseudo_hex"]
        .as_str()
        .expect("k_pseudo_hex");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("32 bytes")
}

/// §9.7: every `entity_key` case, including the `?` fallback and IPv6 /64.
#[test]
fn kh_matches_kat_entity_key_cases() {
    let doc = kat();
    let k = k_pseudo(&doc);
    let cases = doc["entity_key"]["cases"].as_array().expect("cases");
    assert!(cases.len() >= 9);
    let mut saw_unknown = false;
    let mut saw_v6 = false;
    for c in cases {
        let (domain, typ, value) = (
            c["domain"].as_str().unwrap(),
            c["type"].as_str().unwrap(),
            c["value"].as_str().unwrap(),
        );
        let got = kh(&k, domain, typ, value);
        assert_eq!(got, c["key_hex"].as_str().unwrap(), "{c}");
        assert_eq!(got.len(), 32);
        saw_unknown |= value.ends_with(&format!("={UNKNOWN_DIM}"));
        saw_v6 |= value.contains("::/64");
        if domain == ENTITY_DOMAIN {
            assert_eq!(entity_key(&k, typ, value), got);
        } else {
            assert_eq!(domain, LIMITER_DOMAIN);
            let redis_key = LimiterKey::new("blog", typ, value).redis_key(&k);
            assert_eq!(redis_key, format!("mg:rl:blog:{typ}:{got}"));
        }
    }
    assert!(saw_unknown && saw_v6, "KAT must cover '?' and /64");
}

/// D-24: keys are derived from `Net::entity_of` / `Net::prefix_of`, so an
/// IPv6 client's rotating addresses in one /64 share a key, and an
/// IPv4-mapped address shares the IPv4 key.
#[test]
fn entity_keys_follow_the_ip_entity_kat() {
    let doc = kat();
    let k = k_pseudo(&doc);
    for c in doc["ip_entity"]["cases"].as_array().expect("cases") {
        let ip: IpAddr = c["ip"].as_str().unwrap().parse().unwrap();
        let entity = Net::entity_of(ip);
        let prefix = Net::prefix_of(ip);
        assert_eq!(entity, c["entity"].as_str().unwrap(), "{c}");
        assert_eq!(prefix, c["prefix"].as_str().unwrap(), "{c}");
        assert_eq!(
            entity_key(&k, "ip", &entity),
            kh(&k, ENTITY_DOMAIN, "ip", c["entity"].as_str().unwrap())
        );
    }
    // Composite checks against KAT values: an IPv6 host inside the /64 of
    // the "login-per-ip" case, and the IPv4-mapped form of the v4 case.
    let v6: IpAddr = "2001:db8:abcd:12:a:b:c:d".parse().unwrap();
    let d = dims(&[("ip", Some(&Net::entity_of(v6)))]);
    assert_eq!(
        kh(&k, LIMITER_DOMAIN, "login-per-ip", &d),
        "a98aadec2a93ead3e4a81bcc62d1ea00"
    );
    let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    assert_eq!(
        entity_key(&k, "ip", &Net::entity_of(mapped)),
        "083956bb9c00bbcfdac40338c45b515a"
    );
    let d = dims(&[("ip", None)]);
    assert_eq!(
        kh(&k, LIMITER_DOMAIN, "login-per-ip", &d),
        "fc0088f74ac76001f2bb7e6401b22bd2"
    );
    let d = dims(&[
        ("ip_prefix", Some("203.0.113.0/24")),
        ("route", Some("api")),
    ]);
    assert_eq!(
        kh(&k, LIMITER_DOMAIN, "api-mixed", &d),
        "948f739b69a7af5fc878ab15e026a4b5"
    );
    assert_eq!(
        verdict_key("blog", "ip", &entity_key(&k, "ip", "203.0.113.7")),
        "mg:v:blog:ip:083956bb9c00bbcfdac40338c45b515a"
    );
}

/// Different keys give different outputs (domain separation by the 0x00
/// separators: "a\0bc" and "ab\0c" must differ).
#[test]
fn kh_separates_fields() {
    let k = [9u8; 32];
    assert_ne!(kh(&k, "a", "bc", "d"), kh(&k, "ab", "c", "d"));
    assert_ne!(kh(&k, "a", "b", "cd"), kh(&k, "a", "bc", "d"));
    assert_ne!(kh(&k, "a", "b", "c"), kh(&[8u8; 32], "a", "b", "c"));
}
