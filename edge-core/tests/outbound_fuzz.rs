//! Deterministic random-input tests for the outbound parsers
//! (docs/impl/phase2-spec.md §2.4 item 9; WP-C6): a fixed-seed xorshift
//! generates ≥ 10,000 inputs per function (siteverify response bodies,
//! RFC 3339 timestamps, siteverify URLs); nothing panics and accepted inputs
//! satisfy the documented invariants. The cargo-fuzz target
//! `siteverify_response` follows in WP-E2c.

use mg_edge_core::outbound::{
    MAX_ERROR_CODES, SITEVERIFY_URL, UrlError, parse_rfc3339_ns, parse_siteverify_response,
    validate_siteverify_url,
};
use std::path::PathBuf;

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

    fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        for _ in 0..=self.below(4) {
            let pos = if v.is_empty() { 0 } else { self.below(v.len()) };
            match self.below(5) {
                0 if !v.is_empty() => v[pos] = self.next() as u8,
                1 => v.insert(pos, *self.pick(b"{}[]\",:0123456789tfnul-.TZ+ \\")),
                2 if !v.is_empty() => {
                    v.remove(pos);
                }
                3 => v.truncate(pos),
                _ => {
                    let end = (pos + self.below(16)).min(v.len());
                    let chunk = v[pos..end].to_vec();
                    v.splice(pos..pos, chunk);
                }
            }
        }
        v
    }
}

fn samples() -> Vec<Vec<u8>> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase2/samples/siteverify");
    let mut out = Vec::new();
    for sub in [dir.clone(), dir.join("malformed")] {
        for e in std::fs::read_dir(sub).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json")
                && p.file_name().is_some_and(|n| n != "cases.json")
            {
                out.push(std::fs::read(p).unwrap());
            }
        }
    }
    assert!(out.len() >= 20);
    out
}

#[test]
fn siteverify_response_parser_holds_its_invariants() {
    let seeds = samples();
    let mut rng = XorShift(0x5eed_51e7_e41f_0001);
    let fragments: &[&str] = &[
        "{",
        "}",
        "[",
        "]",
        ",",
        ":",
        "\"success\"",
        "true",
        "false",
        "null",
        "\"error-codes\"",
        "\"internal-error\"",
        "\"challenge_ts\"",
        "\"2026-09-21T14:13:50.000Z\"",
        "\"hostname\"",
        "\"example.com\"",
        "\"action\"",
        "\"cdata\"",
        "\"x\"",
        "1",
        "-0.5e3",
        " ",
    ];
    let mut accepted = 0;
    for i in 0..ITERATIONS {
        let body: Vec<u8> = match i % 3 {
            0 => {
                let seed = &seeds[rng.below(seeds.len())];
                rng.mutate(seed)
            }
            1 => (0..rng.below(64)).map(|_| rng.next() as u8).collect(),
            _ => {
                let mut s = String::from("{");
                for _ in 0..rng.below(24) {
                    let f: &&str = rng.pick(fragments);
                    s.push_str(f);
                }
                s.into_bytes()
            }
        };
        if let Ok(r) = parse_siteverify_response(&body) {
            accepted += 1;
            assert!(body.len() <= 16 * 1024);
            assert!(r.error_codes.len() <= MAX_ERROR_CODES);
            assert!(r.error_codes.iter().all(|c| c.len() <= 64));
            if r.success {
                assert!(r.challenge_ts_ns.is_some());
                assert!(r.hostname.is_some() && r.action.is_some() && r.cdata.is_some());
            }
        }
    }
    assert!(
        accepted > 100,
        "the generator reaches the accepting paths ({accepted})"
    );
}

/// Naive reference: days from 1970-01-01 by counting.
fn reference_days(y: i64, m: i64, d: i64) -> i64 {
    let leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mut days = 0;
    for year in 1970..y {
        days += if leap(year) { 366 } else { 365 };
    }
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    days += months[..(m - 1) as usize].iter().sum::<i64>();
    days + d - 1
}

#[test]
fn rfc3339_parser_matches_a_reference_and_never_panics() {
    let mut rng = XorShift(0x5eed_51e7_e41f_0002);
    for _ in 0..ITERATIONS {
        let y = 1970 + rng.below(130) as i64;
        let m = 1 + rng.below(12) as i64;
        let d = 1 + rng.below(28) as i64;
        let (hh, mm, ss) = (
            rng.below(24) as i64,
            rng.below(60) as i64,
            rng.below(60) as i64,
        );
        let frac_digits = rng.below(10);
        let frac: String = (0..frac_digits)
            .map(|_| char::from(b'0' + rng.below(10) as u8))
            .collect();
        let (oh, om) = (rng.below(24) as i64, rng.below(60) as i64);
        let sign = if rng.below(2) == 0 { '+' } else { '-' };
        let zone = if rng.below(3) == 0 {
            "Z".to_owned()
        } else {
            format!("{sign}{oh:02}:{om:02}")
        };
        let dot = if frac_digits > 0 {
            format!(".{frac}")
        } else {
            String::new()
        };
        let s = format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}{dot}{zone}");
        let mut nanos: i128 = 0;
        if frac_digits > 0 {
            nanos = frac.parse::<i128>().unwrap() * 10i128.pow(9 - frac_digits as u32);
        }
        let offset = if zone == "Z" {
            0
        } else {
            let o = oh * 3600 + om * 60;
            if sign == '+' { o } else { -o }
        };
        let secs = reference_days(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - offset;
        let want = i128::from(secs) * 1_000_000_000 + nanos;
        assert_eq!(parse_rfc3339_ns(&s), Some(want), "{s}");

        // Mutations never panic; whatever parses has the RFC 3339 shape.
        let mutated = String::from_utf8_lossy(&rng.mutate(s.as_bytes())).into_owned();
        if parse_rfc3339_ns(&mutated).is_some() {
            let b = mutated.as_bytes();
            assert!(
                b.len() >= 20 && b[4] == b'-' && b[7] == b'-' && b[13] == b':',
                "{mutated}"
            );
        }
    }
}

#[test]
fn siteverify_url_check_never_widens() {
    let mut rng = XorShift(0x5eed_51e7_e41f_0003);
    let prefixes = [
        "http://127.0.0.1:",
        "http://[::1]:",
        "https://challenges.cloudflare.com/",
        "http://",
        "https://",
        "",
    ];
    let alphabet = b"0123456789abcz/.:-_~@?#[]% AZ";
    for i in 0..ITERATIONS {
        let url = if i % 4 == 0 {
            String::from_utf8_lossy(&rng.mutate(SITEVERIFY_URL.as_bytes())).into_owned()
        } else {
            let mut s = (*rng.pick(&prefixes)).to_owned();
            for _ in 0..rng.below(40) {
                s.push(char::from(*rng.pick(alphabet)));
            }
            s
        };
        match validate_siteverify_url(&url, false) {
            Ok(u) => {
                assert_eq!(u.as_str(), SITEVERIFY_URL);
                assert!(!u.is_override());
            }
            Err(_) => assert_ne!(url, SITEVERIFY_URL),
        }
        match validate_siteverify_url(&url, true) {
            Ok(u) if u.is_override() => {
                assert!(
                    url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:"),
                    "{url}"
                );
                assert!(!url.contains(['?', '#', '@', ' ', '%']), "{url}");
                assert_eq!(
                    validate_siteverify_url(&url, false),
                    Err(UrlError::TestDestinationNotAllowed)
                );
            }
            Ok(u) => assert_eq!(u.as_str(), SITEVERIFY_URL),
            Err(_) => {}
        }
    }
}
