//! Deterministic random inputs never panic the bundle parsers
//! (docs/impl/phase1-spec.md §2.4 item 3: fixed-seed xorshift, >= 10,000
//! inputs per parser, errors instead of panics).

use mg_edge_core::bundle::{OwnerKeys, Source, verify_bundle};
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_PUB, OWNER_TEST_SEED, owner_test_keys, sign_test_bundle,
    sign_test_bytes, test_site_bundle,
};
use mg_proto::v1::{ArtifactRef, NamedList, RateLimit, Route, SiteBundle};

const N: usize = 10_000;

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
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
    fn string(&mut self, alphabet: &[u8], max_len: usize) -> String {
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

fn hosts() -> Vec<String> {
    vec!["example.com".into()]
}

/// Random bytes (N), and random payloads wrapped in a validly signed
/// envelope (N / 10; signing dominates the run time in debug builds) so the
/// inner `SiteBundle` decoder and the bound checks see them too.
#[test]
fn verify_bundle_random_bytes() {
    let keys = owner_test_keys();
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..N {
        let _ = verify_bundle(&rng.bytes(512), &keys, "blog", &hosts());
    }
    for _ in 0..N / 10 {
        let signed = sign_test_bytes(&rng.bytes(512), &OWNER_TEST_SEED, OWNER_TEST_KID);
        let _ = verify_bundle(&signed, &keys, "blog", &hosts());
    }
}

/// Bit flips, truncations and splices of a valid signed bundle: never a
/// panic, and never accepted unless the bytes are unchanged.
#[test]
fn verify_bundle_mutated_envelopes() {
    let keys = owner_test_keys();
    let mut b = test_site_bundle("blog", &["example.com"], 7);
    b.lists.insert(
        "l".into(),
        NamedList {
            entries: vec!["203.0.113.0/24".into()],
        },
    );
    let valid = sign_test_bundle(&b, &OWNER_TEST_SEED, OWNER_TEST_KID);
    verify_bundle(&valid, &keys, "blog", &hosts()).unwrap();
    let mut rng = XorShift(42);
    for _ in 0..N {
        let mut m = valid.clone();
        match rng.below(4) {
            0 => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            1 => m.truncate(rng.below(m.len())),
            2 => {
                let i = rng.below(m.len());
                let extra = rng.bytes(16);
                m.splice(i..i, extra);
            }
            _ => {
                let i = rng.below(m.len());
                let j = (i + rng.below(8)).min(m.len());
                m.drain(i..j);
            }
        }
        let result = verify_bundle(&m, &keys, "blog", &hosts());
        if m != valid {
            // Protobuf tolerates some envelope edits that leave the signed
            // payload and key id intact (e.g. an appended unknown field);
            // anything accepted must carry the original bundle.
            if let Ok(vb) = result {
                assert_eq!(vb.bundle, b, "accepted a modified bundle");
            }
        }
    }
}

/// Validly signed bundles with random field values: the bound checks must
/// return errors, not panic (overflows, NaN, huge counts, odd strings).
/// Signing dominates the run time in debug builds, so this structure-aware
/// pass uses fewer iterations; the byte-level passes above run N each.
#[test]
fn verify_bundle_random_structures() {
    let keys = owner_test_keys();
    let mut rng = XorShift(7);
    let text: &[u8] = b"/*?abcAZ09._-~#\\ \x00\x7f%";
    for _ in 0..N / 4 {
        let mut b: SiteBundle = test_site_bundle("blog", &["example.com"], rng.next());
        b.not_before_ms = rng.next() as i64;
        let env = &mut b.environments[0];
        for _ in 0..rng.below(3) {
            env.routes.push(Route {
                id: rng.string(text, 6),
                name: rng.string(text, 6),
                paths: (0..rng.below(3)).map(|_| rng.string(text, 12)).collect(),
                path_glob: rng.string(text, 4),
                methods: (0..rng.below(2)).map(|_| rng.string(text, 4)).collect(),
                channel: rng.next() as i32 % 5,
                sensitivity: rng.next() as i32 % 6,
                ..Default::default()
            });
        }
        for _ in 0..rng.below(3) {
            env.rate_limits.push(RateLimit {
                id: rng.string(text, 6),
                key: (0..rng.below(3))
                    .map(|_| rng.string(b"ip_prefixasnroute", 8))
                    .collect(),
                algorithm: if rng.below(4) == 0 {
                    rng.string(text, 4)
                } else {
                    "gcra".into()
                },
                rate: rng.next() as u32,
                period_s: rng.next() as u32 % 100_000,
                burst: rng.next() as u32 % 200_000,
                on_exceed: ["signal", "challenge", "rate_limit", "block", "x"][rng.below(5)].into(),
                signal_weight: f32::from_bits(rng.next() as u32),
                challenge_type: rng.next() as i32 % 7,
                route_ids: (0..rng.below(2)).map(|_| rng.string(text, 4)).collect(),
                ..Default::default()
            });
        }
        if let Some(c) = &mut b.challenge {
            c.ttl_s = rng.next() as u32 % 200;
            c.max_failures = rng.next() as u32;
            c.failure_window_s = rng.next() as u32;
            c.issue_per_ipp = rng.next() as u32;
            c.issue_period_s = rng.next() as u32 % 100_000;
            c.fallback_ret = rng.string(text, 10);
        }
        if let Some(c) = &mut b.clearance {
            c.session_max_s = rng.next() as u32;
        }
        if let Some(s) = &mut b.scoring {
            s.theta_c = f32::from_bits(rng.next() as u32);
        }
        if let Some(e) = &mut b.events {
            e.allow_sample_rate = f32::from_bits(rng.next() as u32);
        }
        if rng.below(3) == 0 {
            let sha = rng.string(b"0123456789abcdefg", 64);
            b.artifacts.push(ArtifactRef {
                name: ["geoip-asn", "tor-exits", "x"][rng.below(3)].into(),
                uri: format!("artifacts/{sha}"),
                sha256: sha,
                version: String::new(),
                size: rng.next(),
            });
        }
        let signed = sign_test_bundle(&b, &OWNER_TEST_SEED, OWNER_TEST_KID);
        let _ = verify_bundle(&signed, &keys, "blog", &hosts());
    }
}

/// Owner key files: random bytes and edits of the valid sample.
#[test]
fn owner_key_files() {
    let mut rng = XorShift(0xdead_beef);
    let valid = OWNER_TEST_PUB;
    for i in 0..N {
        let input = if i % 2 == 0 {
            rng.bytes(300)
        } else {
            let mut m = valid.to_vec();
            let at = rng.below(m.len());
            m[at] = rng.next() as u8;
            if rng.below(2) == 0 {
                m.truncate(rng.below(m.len()));
            }
            m
        };
        let _ = OwnerKeys::from_pub_files(&[("fuzz.pub", &input)]);
    }
    OwnerKeys::from_pub_files(&[("owner-test.pub", valid)]).unwrap();
}

/// `bundle_root` strings.
#[test]
fn bundle_roots() {
    let mut rng = XorShift(99);
    let alphabet: &[u8] = b"filehtps:/[]@?#.%0123456789abcdef:-_ \\";
    let prefixes = [
        "",
        "file://",
        "http://",
        "https://",
        "http://127.0.0.1",
        "http://[",
    ];
    for _ in 0..N {
        let s = format!(
            "{}{}",
            prefixes[rng.below(prefixes.len())],
            rng.string(alphabet, 24)
        );
        let _ = Source::parse(&s);
    }
}
