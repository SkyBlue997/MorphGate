//! Deterministic random-input tests (spec §2.4 item 3, §7.7): every parser
//! gets at least 10,000 inputs from a fixed-seed xorshift, mostly mutations of
//! the valid samples so the inputs reach deep validation paths. Each input
//! must produce `Ok` or `Err`, never a panic, and every accepted artifact must
//! still satisfy the security invariants of §12.2 / §12.3.

mod common;

use std::net::IpAddr;

use common::{Scripted, XorShift, block_on, intel_testdata, ip, phase1, read};
use mg_intel::{
    CrawlerRegistry, DnsError, GeoDb, IpSet, RdnsJob, StaticResolver, parse_asn_list,
    parse_cloudflare_ips, resolve_rdns, verify_sha256,
};

const N: usize = 10_000;

/// Addresses no accepted registry or Cloudflare artifact may cover.
const NEVER: &[&str] = &[
    "0.0.0.1",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fd00::1",
    "fe80::1",
    "ff02::1",
    "2001::1",
    "4000::1",
    "8000::1",
];

/// Documentation addresses: only a `"test": true` registry may cover them.
const DOCUMENTATION: &[&str] = &["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"];

fn input(rng: &mut XorShift, seeds: &[Vec<u8>]) -> Vec<u8> {
    if rng.below(10) == 0 {
        let len = rng.below(512);
        rng.bytes(len)
    } else {
        let seed = &seeds[rng.below(seeds.len())];
        rng.mutate(seed)
    }
}

fn artifact(name: &str) -> Vec<u8> {
    read(phase1().join("artifacts").join(name))
}

#[test]
fn fuzz_crawler_registry() {
    let seeds = [
        artifact("crawler-registry.json"),
        artifact("crawler-registry.test.json"),
        artifact("invalid/crawler-registry.host-bits.json"),
        artifact("invalid/crawler-registry.slash-zero.json"),
    ];
    let mut rng = XorShift::new(0x5eed_0001);
    let mut accepted = 0;
    for _ in 0..N {
        let bytes = input(&mut rng, &seeds);
        let Ok(reg) = CrawlerRegistry::from_artifact(&bytes) else {
            continue;
        };
        accepted += 1;
        for op in reg.operators() {
            for addr in NEVER {
                assert!(!op.cidrs.contains(ip(addr)), "{} covers {addr}", op.id);
            }
            if !reg.is_test() {
                for addr in DOCUMENTATION {
                    assert!(!op.cidrs.contains(ip(addr)), "{} covers {addr}", op.id);
                }
            }
            assert!((1..=8).contains(&op.ua_tokens.len()));
            assert!(!op.mode.uses_rdns() || !op.rdns_suffixes.is_empty());
        }
        let ua = String::from_utf8_lossy(&rng.bytes(64)).into_owned();
        let _ = reg.match_ua(&ua);
    }
    assert!(accepted > 0, "mutations never produced a valid registry");
}

#[test]
fn fuzz_cloudflare_ips() {
    let seeds = [
        artifact("cloudflare-ips.json"),
        artifact("invalid/cloudflare-ips.private.json"),
    ];
    let mut rng = XorShift::new(0x5eed_0002);
    let mut accepted = 0;
    for _ in 0..N {
        let bytes = input(&mut rng, &seeds);
        let Ok(cf) = parse_cloudflare_ips(&bytes) else {
            continue;
        };
        accepted += 1;
        for addr in NEVER.iter().chain(DOCUMENTATION) {
            assert!(!cf.set.contains(ip(addr)), "covers {addr}");
        }
    }
    assert!(accepted > 0);
}

#[test]
fn fuzz_text_lists() {
    let seeds = [
        artifact("tor-exits.txt"),
        artifact("datacenter-asns.txt"),
        b"::ffff:192.0.2.0/120\n0.0.0.0/0\n::/0\n".to_vec(),
    ];
    let mut rng = XorShift::new(0x5eed_0003);
    for _ in 0..N {
        let bytes = input(&mut rng, &seeds);
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(set) = IpSet::from_text(&text) {
            let v6: [u8; 16] = rng.bytes(16).try_into().unwrap();
            let v4: [u8; 4] = rng.bytes(4).try_into().unwrap();
            let _ = set.contains(IpAddr::from(v6));
            let _ = set.contains(IpAddr::from(v4));
            let _ = set.len();
        }
        if let Ok(asns) = parse_asn_list(&text) {
            assert!(!asns.contains(&0));
        }
        let entries: Vec<&str> = text.split(['\n', ',']).collect();
        let _ = IpSet::parse(entries);
    }
}

#[test]
fn fuzz_static_resolver() {
    let seeds = [
        br#"{"v": 1, "ptr": {"198.51.100.7": ["crawl.googlebot.com."], "2001:db8::7": ["x.test"]}, "a": {"crawl.googlebot.com": ["198.51.100.7", "2001:db8::7"]}}"#.to_vec(),
    ];
    let mut rng = XorShift::new(0x5eed_0004);
    let mut accepted = 0;
    for _ in 0..N {
        let bytes = input(&mut rng, &seeds);
        if let Ok(r) = StaticResolver::from_json(&bytes) {
            accepted += 1;
            let job = RdnsJob::new(ip("198.51.100.7"), "x", vec![".googlebot.com".into()]);
            let _ = block_on(resolve_rdns(&job, &r));
        }
    }
    assert!(accepted > 0);
}

/// Random PTR names and suffixes through the rDNS algorithm.
#[test]
fn fuzz_rdns_names() {
    const ALPHABET: &[u8] = b"abcG.-_.9\xc3\xa9.";
    let mut rng = XorShift::new(0x5eed_0005);
    let name = |rng: &mut XorShift| -> String {
        let len = rng.below(40);
        let bytes: Vec<u8> = (0..len)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    for _ in 0..N {
        let names: Vec<String> = (0..rng.below(8)).map(|_| name(&mut rng)).collect();
        let suffixes: Vec<String> = (0..rng.below(3)).map(|_| name(&mut rng)).collect();
        let mut r = Scripted::default();
        r.ptr.insert(ip("192.0.2.1"), Ok(names.clone()));
        for n in &names {
            let answer = match rng.below(4) {
                0 => Err(DnsError::Timeout),
                1 => Err(DnsError::NoRecords),
                _ => Ok(vec![ip("192.0.2.1")]),
            };
            r.fwd.insert(n.clone(), answer);
        }
        let job = RdnsJob::new(ip("192.0.2.1"), "x", suffixes);
        let _ = block_on(resolve_rdns(&job, &r));
        let forward_queries = r.calls().len() - 1;
        assert!(forward_queries <= 5, "{forward_queries} forward queries");
    }
}

#[test]
fn fuzz_geodb() {
    let dir = intel_testdata().join("mmdb");
    let seeds = [
        read(dir.join("test-asn.mmdb")),
        read(dir.join("test-country.mmdb")),
        read(dir.join("test-city.mmdb")),
    ];
    let probes = [
        "192.0.2.1",
        "198.51.100.200",
        "203.0.113.200",
        "2001:db8::1",
        "8.8.8.8",
        "::",
    ];
    let mut rng = XorShift::new(0x5eed_0006);
    let mut loaded = 0;
    for _ in 0..N {
        let bytes = input(&mut rng, &seeds);
        let as_asn = rng.below(2) == 0;
        let db = if as_asn {
            GeoDb::load(Some(bytes), None)
        } else {
            GeoDb::load(None, Some(bytes))
        };
        if let Ok(db) = db {
            loaded += 1;
            for p in probes {
                let _ = db.lookup(ip(p));
            }
        }
    }
    assert!(loaded > 0, "mutations never produced a loadable database");
}

#[test]
fn fuzz_sha256_expectations() {
    let mut rng = XorShift::new(0x5eed_0007);
    let seed = b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_vec();
    for _ in 0..N {
        let expected =
            String::from_utf8_lossy(&input(&mut rng, std::slice::from_ref(&seed))).into_owned();
        let _ = verify_sha256(b"abc", &expected);
    }
}
