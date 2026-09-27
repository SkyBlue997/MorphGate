//! Crawler verification: the §7.3 state machine, rDNS algorithm, cache and
//! in-flight handling, and `StaticResolver` (spec §7.3, §7.4, §7.7).

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::{Scripted, block_on, ip, phase1, read};
use mg_intel::{
    CacheConfig, CrawlerRegistry, CrawlerStatus, CrawlerVerifier, DnsError, DnsResolver, RdnsJob,
    RdnsOutcome, StaticResolver, VerifyMethod, resolve_rdns,
};
use serde_json::json;

const NOW: i64 = 1_790_503_200_000;

const IPONLY_UA: &str = "Mozilla/5.0 (compatible; IpOnlyBot/1.0)";
const HYBRID_UA: &str = "Mozilla/5.0 (compatible; HybridBot/2.0)";
const DNSONLY_UA: &str = "DnsOnlyBot/3.0 (+https://dnsonly.example.test/bot)";
const BROWSER_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";

/// A test registry (documentation ranges) with one operator per mode.
fn registry() -> Arc<CrawlerRegistry> {
    let source = json!([{
        "url": "https://example.test/ranges.json", "format": "prefixes_json",
        "fetched_at": "2026-09-27T10:00:00Z", "creation_time": "",
        "sha256": "0".repeat(64), "stale": false
    }]);
    let doc = json!({
        "v": 1, "kind": "mg-crawler-registry", "generated_at": "2026-09-27T10:00:00Z",
        "test": true,
        "operators": [
            {"id": "iponly", "name": "IpOnlyBot", "purpose": "ai_training", "ua_tokens": ["IpOnlyBot"],
             "verify": {"mode": "ip_ranges", "rdns_suffixes": []},
             "cidrs": ["192.0.2.0/25"], "sources": source},
            {"id": "hybrid", "name": "HybridBot", "purpose": "search", "ua_tokens": ["HybridBot"],
             "verify": {"mode": "ip_ranges_or_rdns", "rdns_suffixes": [".hybrid.example.test"]},
             "cidrs": ["198.51.100.0/25", "2001:db8:1::/48"], "sources": source},
            {"id": "dnsonly", "name": "DnsOnlyBot", "purpose": "archive", "ua_tokens": ["DnsOnlyBot"],
             "verify": {"mode": "rdns", "rdns_suffixes": [".dnsonly.example.test", "exact.example.test"]},
             "cidrs": [], "sources": []}
        ]
    });
    Arc::new(CrawlerRegistry::from_artifact(&serde_json::to_vec(&doc).unwrap()).unwrap())
}

fn verifier() -> CrawlerVerifier {
    CrawlerVerifier::new(registry(), CacheConfig::default())
}

fn verified(op: &str, purpose: &str, method: VerifyMethod) -> CrawlerStatus {
    CrawlerStatus::Verified {
        operator: op.into(),
        purpose: purpose.into(),
        method,
    }
}

fn failed(op: &str, purpose: &str, method: VerifyMethod) -> CrawlerStatus {
    CrawlerStatus::Failed {
        operator: op.into(),
        purpose: purpose.into(),
        method,
    }
}

fn pending(op: &str, purpose: &str, outside_ranges: bool) -> CrawlerStatus {
    CrawlerStatus::Pending {
        operator: op.into(),
        purpose: purpose.into(),
        outside_ranges,
    }
}

fn unverifiable(op: &str, purpose: &str, reason: &'static str) -> CrawlerStatus {
    CrawlerStatus::Unverifiable {
        operator: op.into(),
        purpose: purpose.into(),
        reason,
    }
}

fn some_ip(s: &str) -> Option<IpAddr> {
    Some(ip(s))
}

// ---------------------------------------------------------------------------
// §7.3 state machine, row by row
// ---------------------------------------------------------------------------

/// Row 1: no operator token in the UA.
#[test]
fn row_not_claimed() {
    let v = verifier();
    assert_eq!(
        v.check(BROWSER_UA, some_ip("192.0.2.1"), NOW),
        (CrawlerStatus::NotClaimed, None)
    );
    assert_eq!(v.check("", None, NOW), (CrawlerStatus::NotClaimed, None));
}

/// Row 2: claimed but the client IP is unknown (05 §3.3: never "impersonator").
#[test]
fn row_no_client_ip() {
    let v = verifier();
    for ua in [IPONLY_UA, HYBRID_UA, DNSONLY_UA] {
        let (status, job) = v.check(ua, None, NOW);
        assert!(job.is_none());
        assert!(
            matches!(
                status,
                CrawlerStatus::Unverifiable {
                    reason: "no_client_ip",
                    ..
                }
            ),
            "{status:?}"
        );
    }
}

/// Row 3: inside the published ranges → verified by IP range (any mode).
#[test]
fn row_inside_ranges() {
    let v = verifier();
    assert_eq!(
        v.check(IPONLY_UA, some_ip("192.0.2.100"), NOW),
        (
            verified("iponly", "ai_training", VerifyMethod::IpRange),
            None
        )
    );
    assert_eq!(
        v.check(HYBRID_UA, some_ip("2001:db8:1::99"), NOW),
        (verified("hybrid", "search", VerifyMethod::IpRange), None)
    );
    // IPv4-mapped client addresses are canonicalised.
    assert_eq!(
        v.check(HYBRID_UA, some_ip("::ffff:198.51.100.3"), NOW),
        (verified("hybrid", "search", VerifyMethod::IpRange), None)
    );
}

/// Row 4 (D-18): `ip_ranges` operator, outside the ranges → failed at once,
/// no DNS job.
#[test]
fn row_ip_ranges_outside_fails_synchronously() {
    let v = verifier();
    for addr in ["192.0.2.128", "203.0.113.9", "2001:db8::1"] {
        assert_eq!(
            v.check(IPONLY_UA, some_ip(addr), NOW),
            (failed("iponly", "ai_training", VerifyMethod::IpRange), None),
            "{addr}"
        );
    }
}

/// Row 6 with `outside_ranges = true` (operator publishes ranges, D-18) and
/// `false` (rDNS-only operator), then row 5 once the result is cached.
#[test]
fn rows_pending_then_cached() {
    let v = verifier();
    let (status, job) = v.check(HYBRID_UA, some_ip("203.0.113.50"), NOW);
    assert_eq!(status, pending("hybrid", "search", true));
    let job = job.expect("first request issues a job");
    assert_eq!(job.ip, ip("203.0.113.50"));
    assert_eq!(job.operator_id, "hybrid");
    assert_eq!(job.suffixes, [".hybrid.example.test"]);

    let (status, job2) = v.check(DNSONLY_UA, some_ip("203.0.113.50"), NOW);
    assert_eq!(status, pending("dnsonly", "archive", false));
    let job2 = job2.expect("a different operator is a different job");

    v.complete(&job, RdnsOutcome::Pass, NOW + 10);
    v.complete(&job2, RdnsOutcome::Fail, NOW + 10);
    assert_eq!(
        v.check(HYBRID_UA, some_ip("203.0.113.50"), NOW + 20),
        (verified("hybrid", "search", VerifyMethod::Rdns), None)
    );
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.50"), NOW + 20),
        (failed("dnsonly", "archive", VerifyMethod::Rdns), None)
    );

    let (_, job3) = v.check(DNSONLY_UA, some_ip("203.0.113.51"), NOW);
    v.complete(&job3.unwrap(), RdnsOutcome::DnsError, NOW);
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.51"), NOW + 1),
        (unverifiable("dnsonly", "archive", "dns_error"), None)
    );
}

/// Cache keys are `(ip, operator)`: one operator's result never answers for
/// another, and the mapped form shares the entry with the plain form.
#[test]
fn cache_key_is_ip_and_operator() {
    let v = verifier();
    let (_, job) = v.check(HYBRID_UA, some_ip("203.0.113.60"), NOW);
    v.complete(&job.unwrap(), RdnsOutcome::Pass, NOW);
    assert!(matches!(
        v.check(DNSONLY_UA, some_ip("203.0.113.60"), NOW).0,
        CrawlerStatus::Pending { .. }
    ));
    assert!(matches!(
        v.check(HYBRID_UA, some_ip("::ffff:203.0.113.60"), NOW).0,
        CrawlerStatus::Verified {
            method: VerifyMethod::Rdns,
            ..
        }
    ));
    assert!(matches!(
        v.check(HYBRID_UA, some_ip("203.0.113.61"), NOW).0,
        CrawlerStatus::Pending { .. }
    ));
}

// ---------------------------------------------------------------------------
// In-flight jobs (§7.3, R2-3)
// ---------------------------------------------------------------------------

#[test]
fn inflight_dedup() {
    let v = verifier();
    let (_, first) = v.check(HYBRID_UA, some_ip("203.0.113.70"), NOW);
    assert!(first.is_some());
    for dt in [0, 1, 4_999] {
        let (status, job) = v.check(HYBRID_UA, some_ip("203.0.113.70"), NOW + dt);
        assert_eq!(status, pending("hybrid", "search", true));
        assert!(job.is_none(), "duplicate job at +{dt} ms");
    }
}

#[test]
fn abandon_allows_immediate_reissue() {
    let v = verifier();
    let (_, job) = v.check(HYBRID_UA, some_ip("203.0.113.71"), NOW);
    v.abandon(&job.unwrap());
    let (status, again) = v.check(HYBRID_UA, some_ip("203.0.113.71"), NOW);
    assert_eq!(status, pending("hybrid", "search", true));
    assert!(again.is_some(), "abandon must release the in-flight mark");
    // Abandon caches nothing.
    v.abandon(&again.unwrap());
    assert!(matches!(
        v.check(HYBRID_UA, some_ip("203.0.113.71"), NOW + 1),
        (CrawlerStatus::Pending { .. }, Some(_))
    ));
}

#[test]
fn inflight_expiry_reissues() {
    let v = verifier();
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.72"), NOW);
    assert!(job.is_some());
    // The job is lost (never completed or abandoned).
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.72"), NOW + 4_999);
    assert!(job.is_none());
    let (status, job) = v.check(DNSONLY_UA, some_ip("203.0.113.72"), NOW + 5_000);
    assert_eq!(status, pending("dnsonly", "archive", false));
    assert!(
        job.is_some(),
        "an expired in-flight mark must not block forever"
    );

    let custom = CrawlerVerifier::new(
        registry(),
        CacheConfig {
            inflight_ttl_ms: 100,
            ..CacheConfig::default()
        },
    );
    assert!(
        custom
            .check(DNSONLY_UA, some_ip("203.0.113.73"), NOW)
            .1
            .is_some()
    );
    assert!(
        custom
            .check(DNSONLY_UA, some_ip("203.0.113.73"), NOW + 99)
            .1
            .is_none()
    );
    assert!(
        custom
            .check(DNSONLY_UA, some_ip("203.0.113.73"), NOW + 100)
            .1
            .is_some()
    );
}

#[test]
fn complete_clears_inflight_and_ignores_unknown_operator() {
    let v = verifier();
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.74"), NOW);
    let job = job.unwrap();
    let stranger = RdnsJob {
        operator_id: "not-in-registry".into(),
        ..job.clone()
    };
    v.complete(&stranger, RdnsOutcome::Pass, NOW);
    v.abandon(&stranger);
    // Still in flight: the unknown operator touched nothing.
    assert!(
        v.check(DNSONLY_UA, some_ip("203.0.113.74"), NOW + 1)
            .1
            .is_none()
    );
    v.complete(&job, RdnsOutcome::Fail, NOW + 2);
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.74"), NOW + 3),
        (failed("dnsonly", "archive", VerifyMethod::Rdns), None)
    );
}

/// The in-flight set is bounded by `capacity`; saturation yields Pending
/// without a job instead of unbounded growth.
#[test]
fn inflight_is_bounded() {
    let v = CrawlerVerifier::new(
        registry(),
        CacheConfig {
            capacity: 2,
            ..CacheConfig::default()
        },
    );
    assert!(v.check(DNSONLY_UA, some_ip("203.0.113.1"), NOW).1.is_some());
    assert!(v.check(DNSONLY_UA, some_ip("203.0.113.2"), NOW).1.is_some());
    let (status, job) = v.check(DNSONLY_UA, some_ip("203.0.113.3"), NOW);
    assert_eq!(status, pending("dnsonly", "archive", false));
    assert!(job.is_none());
    // Expired marks free space.
    assert!(
        v.check(DNSONLY_UA, some_ip("203.0.113.3"), NOW + 5_000)
            .1
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// Cache TTLs and eviction (§7.3)
// ---------------------------------------------------------------------------

#[test]
fn cache_ttls() {
    let v = verifier();
    let cases = [
        ("203.0.113.80", RdnsOutcome::Pass, 24 * 3_600_000),
        ("203.0.113.81", RdnsOutcome::Fail, 3_600_000),
        ("203.0.113.82", RdnsOutcome::DnsError, 300_000),
    ];
    for (addr, outcome, ttl) in cases {
        let (_, job) = v.check(DNSONLY_UA, some_ip(addr), NOW);
        v.complete(&job.unwrap(), outcome, NOW);
        let (status, job) = v.check(DNSONLY_UA, some_ip(addr), NOW + ttl - 1);
        assert!(
            !matches!(status, CrawlerStatus::Pending { .. }),
            "{outcome:?} expired early"
        );
        assert!(job.is_none());
        let (status, job) = v.check(DNSONLY_UA, some_ip(addr), NOW + ttl);
        assert_eq!(
            status,
            pending("dnsonly", "archive", false),
            "{outcome:?} outlived its TTL"
        );
        assert!(job.is_some());
    }
}

#[test]
fn cache_evicts_earliest_expiry_when_full() {
    let v = CrawlerVerifier::new(
        registry(),
        CacheConfig {
            capacity: 3,
            ..CacheConfig::default()
        },
    );
    let finish = |addr: &str, outcome| {
        let (_, job) = v.check(DNSONLY_UA, some_ip(addr), NOW);
        v.complete(&job.expect("job"), outcome, NOW);
    };
    finish("203.0.113.1", RdnsOutcome::Pass); // expires in 24 h
    finish("203.0.113.2", RdnsOutcome::DnsError); // 5 min: evicted first
    finish("203.0.113.3", RdnsOutcome::Fail); // 1 h
    finish("203.0.113.4", RdnsOutcome::Pass); // cache full: evicts .2
    let cached = |addr: &str| {
        !matches!(
            v.check(DNSONLY_UA, some_ip(addr), NOW + 1).0,
            CrawlerStatus::Pending { .. }
        )
    };
    assert!(cached("203.0.113.1"));
    assert!(cached("203.0.113.3"));
    assert!(cached("203.0.113.4"));
    assert!(!cached("203.0.113.2"));
    // Next to go is the Fail entry (1 h), not either Pass.
    finish("203.0.113.5", RdnsOutcome::Pass);
    assert!(!cached("203.0.113.3"));
    assert!(cached("203.0.113.1"));
    assert!(cached("203.0.113.5"));
}

#[test]
fn completing_again_replaces_the_entry() {
    let v = verifier();
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.90"), NOW);
    let job = job.unwrap();
    v.complete(&job, RdnsOutcome::DnsError, NOW);
    v.complete(&job, RdnsOutcome::Pass, NOW + 1);
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.90"), NOW + 400_000),
        (verified("dnsonly", "archive", VerifyMethod::Rdns), None)
    );
}

/// A late, inconclusive job never replaces a live conclusive result: job A
/// outlives its in-flight mark (the Edge's overall deadline, 2 x 2000 ms +
/// 1 s with the §8.1 defaults, equals the default `inflight_ttl_ms`), job B
/// is issued and passes, then A reports its timeout as `DnsError`.
#[test]
fn late_dns_error_does_not_replace_a_live_verdict() {
    let v = verifier();
    for (addr, verdict, want) in [
        (
            "203.0.113.95",
            RdnsOutcome::Pass,
            verified("dnsonly", "archive", VerifyMethod::Rdns),
        ),
        (
            "203.0.113.96",
            RdnsOutcome::Fail,
            failed("dnsonly", "archive", VerifyMethod::Rdns),
        ),
    ] {
        let (_, a) = v.check(DNSONLY_UA, some_ip(addr), NOW);
        let a = a.expect("job A");
        let (_, b) = v.check(DNSONLY_UA, some_ip(addr), NOW + 5_000);
        let b = b.expect("A's mark expired: job B");
        v.complete(&b, verdict, NOW + 5_001);
        v.complete(&a, RdnsOutcome::DnsError, NOW + 5_002);
        assert_eq!(
            v.check(DNSONLY_UA, some_ip(addr), NOW + 5_003),
            (want, None),
            "{verdict:?} replaced by a late DnsError"
        );
    }
    // A late conclusive result still replaces an earlier one (last writer
    // wins), and DnsError is cached when nothing conclusive is live.
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.97"), NOW);
    let job = job.unwrap();
    v.complete(&job, RdnsOutcome::Pass, NOW);
    v.complete(&job, RdnsOutcome::Fail, NOW + 1);
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.97"), NOW + 2).0,
        failed("dnsonly", "archive", VerifyMethod::Rdns)
    );
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.98"), NOW);
    let job = job.unwrap();
    v.complete(&job, RdnsOutcome::Fail, NOW);
    // After the Fail expired (1 h), a DnsError is cached normally.
    v.complete(&job, RdnsOutcome::DnsError, NOW + 3_600_000);
    assert_eq!(
        v.check(DNSONLY_UA, some_ip("203.0.113.98"), NOW + 3_600_001)
            .0,
        unverifiable("dnsonly", "archive", "dns_error")
    );
}

#[test]
fn zero_ttl_caches_nothing_and_config_is_clamped() {
    let v = CrawlerVerifier::new(
        registry(),
        CacheConfig {
            capacity: 0,
            fail_ttl_ms: -5,
            ..CacheConfig::default()
        },
    );
    assert_eq!(v.config().capacity, 1);
    assert_eq!(v.config().fail_ttl_ms, 0);
    let (_, job) = v.check(DNSONLY_UA, some_ip("203.0.113.91"), NOW);
    v.complete(&job.unwrap(), RdnsOutcome::Fail, NOW);
    assert!(
        v.check(DNSONLY_UA, some_ip("203.0.113.91"), NOW)
            .1
            .is_some()
    );
}

/// §2.4 / D-31: no client address in Debug output.
#[test]
fn debug_output_has_no_client_ip() {
    let v = verifier();
    let (status, job) = v.check(DNSONLY_UA, some_ip("203.0.113.99"), NOW);
    let job = job.unwrap();
    for text in [format!("{job:?}"), format!("{v:?}"), format!("{status:?}")] {
        assert!(!text.contains("203.0.113.99"), "{text}");
        assert!(!text.contains("203, 0, 113"), "{text}");
    }
    assert!(format!("{job:?}").contains("dnsonly"));
}

/// The verifier is shared across request threads.
#[test]
fn verifier_is_send_and_sync() {
    fn assert_sync<T: Send + Sync>() {}
    assert_sync::<CrawlerVerifier>();
    assert_sync::<CrawlerRegistry>();
    assert_sync::<StaticResolver>();

    let v = Arc::new(verifier());
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let v = Arc::clone(&v);
            std::thread::spawn(move || {
                let mut jobs = 0;
                for i in 0..200u32 {
                    let addr = IpAddr::from([203, 0, 113, (i % 50) as u8]);
                    if let (_, Some(job)) = v.check(DNSONLY_UA, Some(addr), NOW + i64::from(i)) {
                        jobs += 1;
                        if t % 2 == 0 {
                            v.complete(&job, RdnsOutcome::Fail, NOW);
                        } else {
                            v.abandon(&job);
                        }
                    }
                }
                jobs
            })
        })
        .collect();
    let jobs: i32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(jobs >= 50);
}

// ---------------------------------------------------------------------------
// rDNS algorithm (§7.3)
// ---------------------------------------------------------------------------

fn job(addr: &str, suffixes: &[&str]) -> RdnsJob {
    RdnsJob {
        ip: ip(addr),
        operator_id: "x".into(),
        suffixes: suffixes.iter().map(|s| (*s).to_owned()).collect(),
    }
}

const G: &[&str] = &[".googlebot.com", ".google.com"];

#[test]
fn rdns_pass() {
    let r = Scripted::default()
        .ptr("66.249.66.1", Ok(&["crawl-66-249-66-1.googlebot.com."]))
        .fwd("crawl-66-249-66-1.googlebot.com.", Ok(&["66.249.66.1"]));
    assert_eq!(
        block_on(resolve_rdns(&job("66.249.66.1", G), &r)),
        RdnsOutcome::Pass
    );
    assert_eq!(
        r.calls(),
        ["PTR 66.249.66.1", "A crawl-66-249-66-1.googlebot.com."]
    );
}

#[test]
fn rdns_case_and_trailing_dot_insensitive() {
    let r = Scripted::default()
        .ptr("2001:4860:4801:10::1", Ok(&["Crawl.GoogleBot.COM"]))
        .fwd("crawl.googlebot.com.", Ok(&["2001:4860:4801:10::1"]));
    assert_eq!(
        block_on(resolve_rdns(&job("2001:4860:4801:10::1", G), &r)),
        RdnsOutcome::Pass
    );
}

/// Suffixes match on label boundaries only; a non-dot suffix is a full name.
#[test]
fn rdns_suffix_label_boundary() {
    for name in [
        "evilgooglebot.com.",
        "googlebot.com.",
        "crawl.googlebot.com.evil.test.",
    ] {
        let r = Scripted::default()
            .ptr("203.0.113.9", Ok(&[name]))
            .fwd(name, Ok(&["203.0.113.9"]));
        assert_eq!(
            block_on(resolve_rdns(&job("203.0.113.9", G), &r)),
            RdnsOutcome::Fail,
            "{name}"
        );
        // A non-matching name is never looked up forward.
        assert_eq!(r.calls().len(), 1, "{name}");
    }
    let exact = &["crawler.example.test"];
    let r = Scripted::default()
        .ptr("203.0.113.9", Ok(&["crawler.example.test."]))
        .fwd("crawler.example.test.", Ok(&["203.0.113.9"]));
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", exact), &r)),
        RdnsOutcome::Pass
    );
    let r = Scripted::default()
        .ptr("203.0.113.9", Ok(&["a.crawler.example.test."]))
        .fwd("a.crawler.example.test.", Ok(&["203.0.113.9"]));
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", exact), &r)),
        RdnsOutcome::Fail
    );
}

/// An impersonator controls its own PTR record but not the operator's zone:
/// the forward answer does not contain its address.
#[test]
fn rdns_forward_without_ip_fails() {
    let r = Scripted::default()
        .ptr("203.0.113.9", Ok(&["crawl-1.googlebot.com."]))
        .fwd(
            "crawl-1.googlebot.com.",
            Ok(&["66.249.66.1", "2001:4860::1"]),
        );
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", G), &r)),
        RdnsOutcome::Fail
    );
    let r = Scripted::default()
        .ptr("203.0.113.9", Ok(&["crawl-1.googlebot.com."]))
        .fwd("crawl-1.googlebot.com.", Err(DnsError::NoRecords));
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", G), &r)),
        RdnsOutcome::Fail
    );
}

#[test]
fn rdns_ptr_no_records_or_empty_fails() {
    let r = Scripted::default();
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", G), &r)),
        RdnsOutcome::Fail
    );
    let r = Scripted::default().ptr("203.0.113.9", Ok(&[]));
    assert_eq!(
        block_on(resolve_rdns(&job("203.0.113.9", G), &r)),
        RdnsOutcome::Fail
    );
}

/// Several PTR names: non-matching ones are skipped, the first matching one
/// that resolves back passes; at most 5 names and 5 forward queries.
#[test]
fn rdns_multiple_ptr_names() {
    let r = Scripted::default()
        .ptr(
            "66.249.66.2",
            Ok(&[
                "host.example.test.",
                "a.googlebot.com.",
                "b.google.com.",
                "c.googlebot.com.",
            ]),
        )
        .fwd("a.googlebot.com.", Ok(&["66.249.66.99"]))
        .fwd("b.google.com.", Ok(&["66.249.66.2"]));
    assert_eq!(
        block_on(resolve_rdns(&job("66.249.66.2", G), &r)),
        RdnsOutcome::Pass
    );
    assert_eq!(
        r.calls(),
        ["PTR 66.249.66.2", "A a.googlebot.com.", "A b.google.com."]
    );

    // The sixth name is never considered.
    let names = [
        "n1.googlebot.com.",
        "n2.googlebot.com.",
        "n3.googlebot.com.",
        "n4.googlebot.com.",
        "n5.googlebot.com.",
        "n6.googlebot.com.",
    ];
    let r = Scripted::default()
        .ptr("66.249.66.3", Ok(&names))
        .fwd("n6.googlebot.com.", Ok(&["66.249.66.3"]));
    assert_eq!(
        block_on(resolve_rdns(&job("66.249.66.3", G), &r)),
        RdnsOutcome::Fail
    );
    let calls = r.calls();
    assert_eq!(calls.len(), 1 + 5, "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("n6")));

    // Duplicate names are queried once.
    let r = Scripted::default().ptr("66.249.66.4", Ok(&["d.googlebot.com.", "D.googlebot.com"]));
    assert_eq!(
        block_on(resolve_rdns(&job("66.249.66.4", G), &r)),
        RdnsOutcome::Fail
    );
    assert_eq!(r.calls().len(), 2);
}

/// Timeout and Server errors (PTR or forward) are DnsError, never Fail.
#[test]
fn rdns_errors() {
    for err in [DnsError::Timeout, DnsError::Server("SERVFAIL".into())] {
        let r = Scripted::default().ptr("66.249.66.5", Err(err.clone()));
        assert_eq!(
            block_on(resolve_rdns(&job("66.249.66.5", G), &r)),
            RdnsOutcome::DnsError,
            "PTR {err:?}"
        );
        let r = Scripted::default()
            .ptr("66.249.66.5", Ok(&["a.googlebot.com."]))
            .fwd("a.googlebot.com.", Err(err.clone()));
        assert_eq!(
            block_on(resolve_rdns(&job("66.249.66.5", G), &r)),
            RdnsOutcome::DnsError,
            "forward {err:?}"
        );
        // A conclusive match elsewhere still passes.
        let r = Scripted::default()
            .ptr("66.249.66.5", Ok(&["a.googlebot.com.", "b.googlebot.com."]))
            .fwd("a.googlebot.com.", Err(err.clone()))
            .fwd("b.googlebot.com.", Ok(&["66.249.66.5"]));
        assert_eq!(
            block_on(resolve_rdns(&job("66.249.66.5", G), &r)),
            RdnsOutcome::Pass
        );
    }
}

#[test]
fn rdns_mapped_addresses() {
    let r = Scripted::default()
        .ptr("66.249.66.6", Ok(&["a.googlebot.com."]))
        .fwd("a.googlebot.com.", Ok(&["::ffff:66.249.66.6"]));
    assert_eq!(
        block_on(resolve_rdns(&job("::ffff:66.249.66.6", G), &r)),
        RdnsOutcome::Pass
    );
}

#[test]
fn rdns_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let r = StaticResolver::from_json(br#"{"v": 1}"#).unwrap();
    let j = job("192.0.2.1", G);
    let fut = resolve_rdns(&j, &r);
    assert_send(&fut);
    assert_eq!(block_on(fut), RdnsOutcome::Fail);
}

// ---------------------------------------------------------------------------
// StaticResolver (§7.4) and the whole flow
// ---------------------------------------------------------------------------

const STATIC: &str = r#"{"v": 1,
 "ptr": {"198.51.100.7": ["crawl-198-51-100-7.googlebot.com."], "198.51.100.8": ["host.example.test."],
         "2001:db8::7": ["crawl-v6.googlebot.com"],
         "203.0.113.8": ["crawl-198-51-100-7.googlebot.com."]},
 "a":   {"crawl-198-51-100-7.googlebot.com": ["198.51.100.7"],
         "Crawl-V6.googlebot.com.": ["2001:db8::7", "198.51.100.99"]}}"#;

#[test]
fn static_resolver_answers() {
    let r = StaticResolver::from_json(STATIC.as_bytes()).unwrap();
    assert_eq!(
        block_on(r.reverse(ip("198.51.100.7"))),
        Ok(vec!["crawl-198-51-100-7.googlebot.com.".to_owned()])
    );
    assert_eq!(
        block_on(r.reverse(ip("::ffff:198.51.100.7"))),
        Ok(vec!["crawl-198-51-100-7.googlebot.com.".to_owned()])
    );
    assert_eq!(
        block_on(r.reverse(ip("198.51.100.9"))),
        Err(DnsError::NoRecords)
    );
    for name in [
        "crawl-198-51-100-7.googlebot.com",
        "crawl-198-51-100-7.googlebot.com.",
        "CRAWL-198-51-100-7.GOOGLEBOT.COM.",
    ] {
        assert_eq!(
            block_on(r.forward(name)),
            Ok(vec![ip("198.51.100.7")]),
            "{name}"
        );
    }
    assert_eq!(
        block_on(r.forward("crawl-v6.googlebot.com.")),
        Ok(vec![ip("2001:db8::7"), ip("198.51.100.99")])
    );
    assert_eq!(
        block_on(r.forward("unknown.test")),
        Err(DnsError::NoRecords)
    );
    assert_eq!(block_on(r.forward("")), Err(DnsError::NoRecords));
    assert!(!format!("{r:?}").contains("198.51"));
}

#[test]
fn static_resolver_rejects_bad_tables() {
    for bad in [
        r#"{"v": 2}"#,
        r#"{"ptr": {}}"#,
        r#"{"v": 1, "extra": {}}"#,
        r#"{"v": 1, "ptr": {"not-an-ip": ["a.test"]}}"#,
        r#"{"v": 1, "a": {"a.test": ["999.1.1.1"]}}"#,
        r#"{"v": 1, "a": {"a..test": ["192.0.2.1"]}}"#,
        r#"{"v": 1, "a": {"a.test": "192.0.2.1"}}"#,
        "[]",
        "",
    ] {
        assert!(StaticResolver::from_json(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(StaticResolver::from_json(br#"{"v": 1, "ptr": {}, "a": {}}"#).is_ok());
}

/// End to end with the shared test registry and a static resolver: a real
/// crawler outside the published ranges verifies by rDNS; an impersonator
/// with its own PTR fails (D-22 warm-up request first).
#[test]
fn flow_with_shared_test_registry() {
    let reg = Arc::new(
        CrawlerRegistry::from_artifact(&read(
            phase1().join("artifacts/crawler-registry.test.json"),
        ))
        .unwrap(),
    );
    let v = CrawlerVerifier::new(reg, CacheConfig::default());
    let r = StaticResolver::from_json(STATIC.as_bytes()).unwrap();
    let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

    // Inside the published range (198.51.100.0/25): verified synchronously.
    assert!(matches!(
        v.check(ua, some_ip("198.51.100.7"), NOW),
        (
            CrawlerStatus::Verified {
                method: VerifyMethod::IpRange,
                ..
            },
            None
        )
    ));

    // Outside the range (2001:db8::7 is not in 2001:db8:4860::/48): rDNS.
    let (status, job) = v.check(ua, some_ip("2001:db8::7"), NOW);
    assert_eq!(status, pending("googlebot", "search", true));
    let job = job.unwrap();
    let outcome = block_on(resolve_rdns(&job, &r));
    assert_eq!(outcome, RdnsOutcome::Pass);
    v.complete(&job, outcome, NOW + 5);
    assert_eq!(
        v.check(ua, some_ip("2001:db8::7"), NOW + 6),
        (verified("googlebot", "search", VerifyMethod::Rdns), None)
    );

    // An impersonator outside the ranges whose own PTR record names a real
    // crawler host: the forward lookup does not lead back to it.
    let (status, job) = v.check(ua, some_ip("203.0.113.8"), NOW);
    assert_eq!(status, pending("googlebot", "search", true));
    let job = job.unwrap();
    let outcome = block_on(resolve_rdns(&job, &r));
    assert_eq!(outcome, RdnsOutcome::Fail);
    v.complete(&job, outcome, NOW + 5);
    assert_eq!(
        v.check(ua, some_ip("203.0.113.8"), NOW + 6),
        (failed("googlebot", "search", VerifyMethod::Rdns), None)
    );

    // GPTBot is ip_ranges only: failed at once outside 192.0.2.0/25.
    assert_eq!(
        v.check("GPTBot/1.0", some_ip("192.0.2.200"), NOW),
        (failed("gptbot", "ai_training", VerifyMethod::IpRange), None)
    );
}
