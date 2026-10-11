//! Deterministic random-input test for the upstream header parsers
//! (docs/impl/phase1-spec.md §2.4 item 3, §9.3; WP-C1): a fixed-seed
//! xorshift generates ≥ 10,000 header lists; nothing panics and every parsed
//! value satisfies its §9.3 validation rule.

use mg_edge_core::testkit::upstream::check_upstream_steps;
use mg_edge_core::upstream::{CloudflareSite, secret_header_ok};

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
    "content-length",
    "transfer-encoding",
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
    // Framing fields are listed but never removed (found by cargo-fuzz).
    "keep-alive, transfer-encoding, Content-Length",
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

        let cf = check_upstream_steps(&slices, &site);
        known_ips += usize::from(cf.client_ip.ip().is_some());
        parsed_tls += usize::from(cf.edge_tls.is_some());

        let accepted = vec![value(&mut rng), value(&mut rng)];
        let presented = slices.first().map(|(_, v)| *v);
        let expected = presented.is_some_and(|p| !p.is_empty() && accepted.iter().any(|a| a == p));
        assert_eq!(secret_header_ok(presented, &accepted), expected);
    }
    // The generator does reach the interesting branches.
    assert!(known_ips > 50, "{known_ips}");
    assert!(parsed_tls > 100, "{parsed_tls}");
}
