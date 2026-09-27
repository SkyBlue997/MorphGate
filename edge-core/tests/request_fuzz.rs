//! Deterministic random-input test for the request checks
//! (docs/impl/phase1-spec.md §2.4 item 3, §9.3.1, §9.4; WP-C1): a
//! fixed-seed xorshift generates ≥ 10,000 inputs per function; nothing
//! panics, and accepted inputs satisfy the documented invariants.

use mg_edge_core::request::{
    MAX_HEADER_NAME_BYTES, MAX_HEADER_ORDER, MAX_HOST_BYTES, OversizeKind, Reject,
    check_header_count, check_limits, check_limits_detailed, header_order, resolve_host,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

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

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    fn string(&mut self, alphabet: &[char], max_len: usize) -> String {
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }
}

const HOSTS: &[&str] = &[
    "blog.example.com",
    "Blog.Example.COM.:443",
    "192.0.2.1",
    "[2001:db8::1]:8443",
    "[fe80::1%25eth0]",
    "127.1",
    "xn--bcher-kva.example",
    "localhost",
];

fn host_input(rng: &mut XorShift) -> String {
    let alphabet: Vec<char> = "abcXYZ019.-:[]_%@/ \té".chars().collect();
    match rng.below(3) {
        0 => HOSTS[rng.below(HOSTS.len())].to_owned(),
        1 => {
            let mut s = HOSTS[rng.below(HOSTS.len())].to_owned();
            let at = rng.below(s.len() + 1);
            if s.is_char_boundary(at) {
                s.insert(at, alphabet[rng.below(alphabet.len())]);
            }
            s
        }
        _ => {
            let max = if rng.chance(10) { 300 } else { 24 };
            rng.string(&alphabet, max)
        }
    }
}

#[test]
fn random_limits_input_never_panics() {
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let name_chars: Vec<char> = "aAcCoOkKiIeE-_ZzÉ ".chars().collect();
    let method_chars: Vec<char> = "GETPOSgetpos-_!~ (é\r".chars().collect();
    let mut accepted = 0;
    for _ in 0..ITERATIONS {
        let method = rng.string(&method_chars, 40);
        let path_len = if rng.chance(4) {
            8190 + rng.below(5)
        } else {
            rng.below(64)
        };
        let query_len = if rng.chance(4) {
            8190 + rng.below(5)
        } else {
            rng.below(64)
        };
        let path = "p".repeat(path_len);
        let query = "q".repeat(query_len);
        let headers: Vec<(String, Vec<u8>)> = (0..rng.below(30))
            .map(|_| {
                let name = if rng.chance(3) {
                    ["cookie", "Cookie", "authorization", "x-a", "X-A"][rng.below(5)].to_owned()
                } else if rng.chance(50) {
                    "n".repeat(250 + rng.below(10))
                } else {
                    rng.string(&name_chars, 12)
                };
                let len = if rng.chance(8) {
                    4000 + rng.below(5000)
                } else {
                    rng.below(100)
                };
                (name, vec![b'v'; len])
            })
            .collect();
        let slices: Vec<(&str, &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();

        let detailed = check_limits_detailed(&method, &path, &query, &slices);
        assert_eq!(
            check_limits(&method, &path, &query, &slices),
            detailed.map_err(OversizeKind::reject)
        );
        if detailed.is_ok() {
            accepted += 1;
            assert!(path.len() <= 8192 && query.len() <= 8192);
            assert!(!method.is_empty() && method.len() <= 32);
            assert!(slices.iter().all(|(n, _)| n.len() <= MAX_HEADER_NAME_BYTES));
        }
        let count = rng.below(200);
        assert_eq!(check_header_count(count).is_ok(), count <= 128);
    }
    assert!(accepted > 100, "{accepted}");
}

#[test]
fn random_hosts_never_panic_and_normalize_idempotently() {
    let mut rng = XorShift(0x0123_4567_89ab_cdef);
    let mut accepted = 0;
    for _ in 0..ITERATIONS {
        let a = host_input(&mut rng);
        let b = if rng.chance(2) {
            a.to_ascii_uppercase()
        } else {
            host_input(&mut rng)
        };
        let host = (!rng.chance(4)).then_some(a.as_str());
        let authority = rng.chance(2).then_some(b.as_str());
        let absolute = rng.chance(3).then_some(a.as_str());
        let result = resolve_host(host, authority, absolute);
        match &result {
            Err(reject) => assert_eq!(*reject, Reject::BadHost),
            Ok(h) => {
                accepted += 1;
                // Canonical: lower-case, no port, no trailing dot, bounded.
                assert_eq!(*h, h.to_ascii_lowercase());
                assert!(!h.ends_with('.'));
                if let Some(inner) = h.strip_prefix('[') {
                    let inner = inner.strip_suffix(']').expect("bracketed IPv6");
                    let v6: Ipv6Addr = inner.parse().expect("IPv6 literal");
                    assert_eq!(v6.to_string(), inner);
                } else {
                    assert!(!h.contains(':'));
                    assert!(h.len() <= MAX_HOST_BYTES);
                    if let Ok(ip) = h.parse::<IpAddr>() {
                        assert!(ip.is_ipv4());
                    }
                }
                // Normalizing the result again is the identity, in every slot.
                assert_eq!(resolve_host(Some(h), None, None).as_ref(), Ok(h));
                assert_eq!(resolve_host(None, Some(h), Some(h)).as_ref(), Ok(h));
            }
        }
    }
    assert!(accepted > 1_000, "{accepted}");
}

#[test]
fn random_header_names_order_is_bounded_and_distinct() {
    let mut rng = XorShift(0xdead_beef_cafe_f00d);
    let chars: Vec<char> = "aAbBxX-_1".chars().collect();
    // Each input is a list of up to 200 names, so 10,000 lists suffice.
    for _ in 0..10_000 {
        let owned: Vec<String> = (0..rng.below(200))
            .map(|_| {
                if rng.chance(100) {
                    "n".repeat(250 + rng.below(10))
                } else {
                    rng.string(&chars, 4)
                }
            })
            .collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        let order = header_order(&names);
        assert!(order.len() <= MAX_HEADER_ORDER);
        let distinct: HashSet<String> = order.iter().map(|n| n.to_ascii_lowercase()).collect();
        assert_eq!(distinct.len(), order.len());
        assert!(
            order
                .iter()
                .all(|n| !n.is_empty() && n.len() <= MAX_HEADER_NAME_BYTES)
        );
        // Every entry is an input name, in first-arrival order.
        let mut first = HashMap::new();
        for (pos, name) in names.iter().enumerate() {
            first.entry(*name).or_insert(pos);
        }
        let positions: Vec<usize> = order.iter().map(|entry| first[entry.as_str()]).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]));
    }
}
