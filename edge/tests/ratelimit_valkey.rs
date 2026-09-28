//! Rate limiting against a real Valkey behind a `FaultProxy`
//! (docs/impl/phase1-spec.md §9.7, §9.8, D-23, D-24; §15 WP-E1b
//! `ratelimit_valkey.rs`): one round trip per request, local fallback and
//! breaker recovery when Valkey goes away, one shared `?` bucket for
//! requests without a client IP, one bucket per IPv6 /64.
//!
//! Skipped (with `SKIPPED: …`) without `valkey-server` or
//! `MG_TEST_VALKEY_URL`, unless `MG_REQUIRE_VALKEY=1`. Limiter ids carry the
//! fixture's random tag, so runs sharing a server never share buckets.

mod common;

use common::policy::limiter;
use common::valkey::Valkey;
use common::{Edge, TestEnv, blog_bundle, cf, get, sign, test_k_pseudo, with_valkey};
use mg_edge_core::state::LimiterKey;
use mg_edge_core::testkit::valkey::FaultMode;
use redis::Commands;

const CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/131.0.0.0 Safari/537.36";

/// Browser headers (a low score, so the limiter is what decides), with
/// `CF-Connecting-IP` when `ip` is given.
fn browser(ip: Option<&str>) -> String {
    let base = format!(
        "User-Agent: {CHROME}\r\nAccept: text/html\r\nAccept-Language: en\r\n\
         Sec-Fetch-Mode: navigate\r\nSec-CH-UA: \"Chromium\";v=\"131\"\r\n"
    );
    match ip {
        Some(ip) => format!("{}{base}", cf(ip)),
        None => format!("CF-Visitor: {{\"scheme\":\"https\"}}\r\n{base}"),
    }
}

/// An enforce bundle with one global `[ip]` limiter: 1 per minute, burst 1.
fn start(env: &TestEnv, vk: &Valkey, limiter_id: &str) -> Edge {
    let mut b = blog_bundle(1);
    b.monitor_only = false;
    b.environments[0].rate_limits = vec![limiter(
        limiter_id,
        &[],
        &["ip"],
        (1, 60, 1),
        "rate_limit",
        30,
    )];
    env.write_lkg("blog", &sign(&b));
    let config = with_valkey(&env.default_config(""), &vk.proxy_url(), 500);
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 10, |v| v == 1.0);
    edge
}

fn status(env: &TestEnv, path: &str, ip: Option<&str>) -> u16 {
    get(env.listen, "example.com", path, &browser(ip)).status
}

#[test]
fn one_round_trip_per_request_and_shared_buckets() {
    let Some(vk) = Valkey::start() else { return };
    let env = TestEnv::new("rl-valkey");
    let id = format!("{}-ip", vk.tag);
    let _edge = start(&env, &vk, &id);
    let mut admin = vk.admin();
    let k = test_k_pseudo();
    let key = |dims: &str| LimiterKey::new("blog", id.as_str(), dims).redis_key(&k);

    // §9.7: a request is one round trip (verdict MGET + EVALSHA mg_gcra).
    let before = vk.round_trips();
    assert_eq!(status(&env, "/a1", Some("198.51.100.70")), 200);
    assert_eq!(vk.round_trips() - before, 1, "one pipeline per request");
    let before = vk.round_trips();
    assert_eq!(status(&env, "/a2", Some("198.51.100.70")), 429);
    assert_eq!(vk.round_trips() - before, 1);
    let exists: bool = admin.exists(key("ip=198.51.100.70")).unwrap();
    assert!(exists, "the bucket lives in Valkey");

    // D-23: every request without a client IP shares the `?` bucket.
    assert_eq!(status(&env, "/u1", None), 200);
    assert_eq!(status(&env, "/u2", None), 429);
    let exists: bool = admin.exists(key("ip=?")).unwrap();
    assert!(exists);

    // D-24: two addresses of one IPv6 /64 share a bucket; another /64 does not.
    assert_eq!(status(&env, "/v1", Some("2001:db8:77:1::a")), 200);
    assert_eq!(status(&env, "/v2", Some("2001:db8:77:1:ffff::b")), 429);
    assert_eq!(status(&env, "/v3", Some("2001:db8:77:2::a")), 200);
    let exists: bool = admin.exists(key("ip=2001:db8:77:1::/64")).unwrap();
    assert!(exists);
}

#[test]
fn outage_falls_back_to_local_and_recovers() {
    let Some(vk) = Valkey::start() else { return };
    let env = TestEnv::new("rl-outage");
    let id = format!("{}-ip", vk.tag);
    let edge = start(&env, &vk, &id);

    vk.set_mode(FaultMode::Refuse);
    // Answered without Valkey; the limiter still holds (local table).
    let started = std::time::Instant::now();
    assert_eq!(status(&env, "/o1", Some("198.51.100.80")), 200);
    assert_eq!(status(&env, "/o2", Some("198.51.100.80")), 429);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // The breaker opens after consecutive failures.
    for i in 0..6 {
        let _ = status(
            &env,
            &format!("/o-fill{i}"),
            Some(&format!("198.51.100.{}", 100 + i)),
        );
    }
    edge.wait_metric("mg_state_mode{mode=\"local\"}", 10, |v| v == 1.0);

    vk.set_mode(FaultMode::Pass);
    edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 20, |v| v == 1.0);
    let before = vk.round_trips();
    assert_eq!(status(&env, "/o3", Some("198.51.100.81")), 200);
    assert!(vk.round_trips() > before, "back on Valkey");
}
