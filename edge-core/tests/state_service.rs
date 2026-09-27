//! `StateService` / `StateHandle` against a real Valkey behind a
//! `FaultProxy` (spec §9.7, §9.1.1, §16; WP-C3 tests in §15): round trips per
//! request type, fallback within `timeout_ms`, circuit breaker and recovery,
//! replay rules, verdict cache, async failure counting, `XADD`.
//!
//! Valkey tests are skipped (with `SKIPPED: …`) without a server; the
//! local-mode tests always run.

use std::time::{Duration, Instant};

use mg_core::gcra::GcraParams;
use mg_edge_core::state::builtin::{ChallengeLimits, ClientDims};
use mg_edge_core::state::{
    BreakerConfig, EVENT_STREAM_KEY, LimitCheck, LimiterKey, NonceIssue, NonceResult, RoundTrip1,
    StateConfig, StateHandle, StateMode, StateService, dims, entity_key, parse_verdict,
    verdict_key,
};
use mg_edge_core::testkit::valkey::{FaultMode, FaultProxy, ValkeyFixture};
use mg_proto::v1::ChallengeConfig;
use redis::aio::MultiplexedConnection;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// `K_pseudo` of `kat.json` (bytes 0x00..0x1f).
const K: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

struct Running {
    handle: StateHandle,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(cfg: StateConfig) -> Self {
        let (service, handle) = StateService::new(cfg);
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(service.run(rx));
        Self { handle, stop, task }
    }

    async fn shutdown(self) {
        self.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("service stops on shutdown")
            .expect("service task");
    }
}

fn valkey_cfg(url: &str) -> StateConfig {
    let mut c = StateConfig::valkey(url, K);
    // Generous for the machine running the tests; fault tests lower it.
    c.timeout_ms = 1_000;
    c.connect_timeout_ms = 1_000;
    c
}

async fn wait_mode(h: &StateHandle, mode: StateMode, within: Duration) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if h.mode() == mode {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.mode() == mode
}

async fn direct(fx: &ValkeyFixture) -> MultiplexedConnection {
    redis::Client::open(fx.url())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

fn check(
    site: &str,
    limiter: &str,
    d: &str,
    rate: u32,
    period: u32,
    burst: u32,
    write: bool,
) -> LimitCheck {
    LimitCheck {
        key: LimiterKey::new(site, limiter, d),
        params: GcraParams::new(rate, period, burst).expect("valid params"),
        cost: 1,
        write,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn verdict_json(site: &str, key: &str) -> String {
    format!(
        r#"{{"type":"ip","key":"{key}","risk":90,"expires_at_ms":{},"source":"owner","version":"1","site_id":"{site}"}}"#,
        now_ms() + 3_600_000
    )
}

/// §9.7 "往返": a normal request needs exactly one round trip (MGET +
/// EVALSHA mg_gcra in one pipeline), `POST /__mg/c` exactly two; cached
/// verdicts need none; after `SCRIPT FLUSH` the scripts are reloaded.
#[tokio::test]
async fn round_trips_per_request_type() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let run = Running::start(valkey_cfg(&proxy.url()));
    let h = &run.handle;
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let ip = "203.0.113.7";
    let ipk = entity_key(&K, "ip", ip);
    let vk_ip = verdict_key(site, "ip", &ipk);
    let vk_prefix = verdict_key(site, "prefix", &entity_key(&K, "prefix", "203.0.113.0/24"));
    let vk_asn = verdict_key(site, "asn", "64500");
    let mut conn = direct(&fx).await;
    let json = verdict_json(site, &ipk);
    redis::cmd("SET")
        .arg(&vk_ip)
        .arg(&json)
        .arg("PX")
        .arg(60_000)
        .exec_async(&mut conn)
        .await
        .unwrap();

    // Normal request.
    let ip_dims = dims(&[("ip", Some(ip))]);
    let base = proxy.round_trips();
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![vk_ip.clone(), vk_prefix.clone(), vk_asn.clone()],
            limits: vec![
                check(site, "global-ip", &ip_dims, 10, 1, 3, true),
                check(site, "global-route", "route=api", 100, 1, 50, true),
            ],
        })
        .await;
    assert_eq!(
        proxy.round_trips() - base,
        1,
        "normal request: one round trip"
    );
    assert_eq!(res.mode, StateMode::Valkey);
    assert_eq!(res.verdicts, vec![Some(json.clone()), None, None]);
    assert_eq!(
        parse_verdict(res.verdicts[0].as_deref().unwrap())
            .unwrap()
            .key,
        ipk
    );
    assert_eq!(res.limits.len(), 2);
    assert!(res.limits.iter().all(|o| o.allowed));
    assert_eq!(res.limits[0].tat_minus_now_us, 100_000);

    // Verdicts (and their absence) are cached for 2 s: no round trip.
    redis::cmd("SET")
        .arg(&vk_asn)
        .arg("changed")
        .arg("PX")
        .arg(60_000)
        .exec_async(&mut conn)
        .await
        .unwrap();
    let base = proxy.round_trips();
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![vk_ip.clone(), vk_prefix.clone(), vk_asn.clone()],
            limits: vec![],
        })
        .await;
    assert_eq!(proxy.round_trips(), base, "served from the verdict cache");
    assert_eq!(res.verdicts, vec![Some(json.clone()), None, None]);

    // POST /__mg/c: round trip 1 (built-in limiters) + round trip 2.
    let builtin = ChallengeLimits::try_from(&ChallengeConfig {
        max_failures: 5,
        failure_window_s: 600,
        submit_rate: 30,
        submit_period_s: 60,
        submit_burst: 10,
        issue_per_ipp: 60,
        issue_per_asn: 600,
        issue_period_s: 3600,
        ..Default::default()
    })
    .unwrap();
    let client = ClientDims {
        ip_entity: Some(ip),
        ip_prefix: Some("203.0.113.0/24"),
        asn: Some(64500),
        asn_available: true,
    };
    let base = proxy.round_trips();
    let rt1 = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![],
            limits: builtin.submit_round_trip(site, &client),
        })
        .await;
    assert_eq!(rt1.mode, StateMode::Valkey);
    assert_eq!(rt1.limits.len(), 5);
    assert!(rt1.limits.iter().all(|o| o.allowed));
    let now = now_ms();
    let rt2 = h
        .nonce_issue(
            NonceIssue {
                site: site.to_owned(),
                nonce: [0x5a; 16],
                ttl_ms: 180_000,
                limits: builtin.issuance(site, &client),
            },
            now,
            now,
        )
        .await;
    assert_eq!(proxy.round_trips() - base, 2, "/__mg/c: two round trips");
    let NonceResult::Fresh { limits } = rt2 else {
        panic!("expected Fresh, got {rt2:?}")
    };
    assert!(limits.len() == 2 && limits.iter().all(|o| o.allowed));
    // Round trip 1 only checked the issuance quotas (write 0): the nonce
    // issuance consumed exactly one unit of each.
    let ipp_interval = 3_600_000_000 / 60;
    assert_eq!(limits[0].tat_minus_now_us, ipp_interval);
    // A failure is recorded asynchronously (fail + fail.prefix, write 1);
    // wait for it so it does not overlap the round trips counted below.
    let fails = builtin.failures(site, &client);
    let fail_key = fails[1].key.redis_key(&K);
    assert!(h.record_failure(fails));
    let end = Instant::now() + Duration::from_secs(5);
    let mut written: Option<String> = None;
    while written.is_none() && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
        written = redis::cmd("GET")
            .arg(&fail_key)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
    assert!(written.is_some(), "mg.c.fail.prefix counted in valkey");
    // Let the proxy forward that reply before the next counted section.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Production calls pass now_us = 0: the stored TAT is on the server clock.
    let (secs, micros): (u64, u64) = redis::cmd("TIME").query_async(&mut conn).await.unwrap();
    let server_now = secs * 1_000_000 + micros;
    let key = LimiterKey::new(site, "global-ip", ip_dims.clone()).redis_key(&K);
    let tat: u64 = redis::cmd("GET")
        .arg(&key)
        .query_async::<String>(&mut conn)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        tat.abs_diff(server_now) < 5_000_000,
        "tat {tat} vs server {server_now}"
    );

    // NOSCRIPT (scripts flushed): reload and retry within the same call.
    // On a server shared with concurrently running tests (MG_TEST_VALKEY_URL)
    // another client may reload the scripts between our FLUSH and EVALSHA
    // (then no NOSCRIPT: 1 round trip); retry until the reload path ran.
    let mut deltas = Vec::new();
    for _ in 0..10 {
        redis::cmd("SCRIPT")
            .arg("FLUSH")
            .exec_async(&mut conn)
            .await
            .unwrap();
        let base = proxy.round_trips();
        let res = h
            .round_trip1(RoundTrip1 {
                verdict_keys: vec![],
                limits: vec![check(site, "after-flush", "route=x", 1000, 1, 1000, true)],
            })
            .await;
        assert_eq!(res.mode, StateMode::Valkey);
        assert!(res.limits[0].allowed);
        deltas.push(proxy.round_trips() - base);
        if deltas.last() == Some(&3) {
            break;
        }
    }
    assert!(
        deltas.iter().all(|d| *d == 1 || *d == 3),
        "round trips per call {deltas:?}"
    );
    assert_eq!(
        deltas.last(),
        Some(&3),
        "NOSCRIPT, SCRIPT LOAD, retry: {deltas:?}"
    );
    run.shutdown().await;
}

/// §9.7 "本地模式与熔断": a blackholed Valkey costs at most `timeout_ms` per
/// request (local fallback), 5 consecutive failures open the circuit (no
/// more waiting), open periods double up to the cap while probes fail, and
/// the Edge returns to Valkey after recovery.
#[tokio::test]
async fn blackhole_fallback_breaker_doubling_and_recovery() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let mut cfg = valkey_cfg(&proxy.url());
    cfg.timeout_ms = 50;
    cfg.connect_timeout_ms = 100;
    cfg.breaker = BreakerConfig {
        failure_threshold: 5,
        base_open_ms: 200,
        max_open_ms: 800,
    };
    let run = Running::start(cfg);
    let h = &run.handle;
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let vk = verdict_key(site, "asn", "64500");
    let mut conn = direct(&fx).await;
    redis::cmd("SET")
        .arg(&vk)
        .arg("{}")
        .arg("PX")
        .arg(60_000)
        .exec_async(&mut conn)
        .await
        .unwrap();

    proxy.set_mode(FaultMode::Blackhole);
    let lim = check(site, "bh", "ip=?", 1, 60, 1, true);
    for i in 0..5 {
        let t = Instant::now();
        let res = h
            .round_trip1(RoundTrip1 {
                verdict_keys: vec![vk.clone()],
                limits: vec![lim.clone()],
            })
            .await;
        let spent = t.elapsed();
        assert!(
            spent < Duration::from_millis(300),
            "request {i} waited {spent:?}"
        );
        assert!(
            spent >= Duration::from_millis(45),
            "request {i} did not wait for valkey"
        );
        assert_eq!(res.mode, StateMode::Local);
        assert_eq!(res.verdicts, vec![None], "no verdicts in local mode");
        // Local GCRA table: burst 1, so only the first passes.
        assert_eq!(res.limits[0].allowed, i == 0, "request {i}");
    }
    // The service records the 5th failure at the same deadline the proxy
    // gave up at; allow it to run.
    let end = Instant::now() + Duration::from_secs(1);
    while h.status().trips == 0 && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let st = h.status();
    assert_eq!(st.trips, 1, "{st:?}");
    assert_eq!(st.mode, StateMode::Local);

    // Circuit open: no waiting at all.
    let t = Instant::now();
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![vk.clone()],
            limits: vec![lim.clone()],
        })
        .await;
    assert!(
        t.elapsed() < Duration::from_millis(40),
        "open circuit waited {:?}",
        t.elapsed()
    );
    assert_eq!(res.mode, StateMode::Local);

    // Probes keep failing: 200 -> 400 -> 800 -> 800 ms.
    let mut seen: Vec<u64> = Vec::new();
    let end = Instant::now() + Duration::from_secs(6);
    while Instant::now() < end {
        let ms = h.status().open_ms;
        if ms != 0 && seen.last() != Some(&ms) {
            seen.push(ms);
        }
        if seen.iter().filter(|m| **m == 800).count() >= 1 && seen.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(seen[..3], [200, 400, 800], "open periods {seen:?}");
    assert!(seen.iter().all(|m| *m <= 800));
    assert_eq!(h.status().trips, 1, "failed probes are not new trips");

    // Recovery: back to Valkey after the next probe.
    proxy.set_mode(FaultMode::Pass);
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![verdict_key(site, "asn", "64501")],
            limits: vec![check(site, "after", "ip=?", 10, 1, 3, true)],
        })
        .await;
    assert_eq!(res.mode, StateMode::Valkey);
    assert!(res.limits[0].allowed);
    run.shutdown().await;
}

/// §9.7 breaker: only request-path round trips within `timeout_ms` prove
/// Valkey healthy. The async failure consumer has a longer budget; a slow
/// success of it must not reset the consecutive-failure count, or a Valkey
/// slower than `timeout_ms` would never trip the breaker while challenge
/// failures keep being recorded (each request would keep paying
/// `timeout_ms` before falling back).
#[tokio::test]
async fn slow_failure_counting_does_not_reset_the_breaker() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let mut cfg = valkey_cfg(&proxy.url());
    cfg.timeout_ms = 30;
    // The failure consumer waits max(timeout_ms, connect_timeout_ms).
    cfg.connect_timeout_ms = 3_000;
    cfg.breaker = BreakerConfig {
        failure_threshold: 5,
        base_open_ms: 10_000,
        max_open_ms: 10_000,
    };
    let run = Running::start(cfg);
    let h = &run.handle;
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let req = || RoundTrip1 {
        verdict_keys: vec![],
        limits: vec![check(site, "slow", "ip=?", 1000, 1, 1000, true)],
    };
    let wait_failures = |n: u32| async move {
        let end = Instant::now() + Duration::from_secs(1);
        while h.status().consecutive_failures < n && Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        h.status().consecutive_failures
    };

    // Round trips now take ~200 ms: every request-path call misses 30 ms.
    proxy.set_latency(Duration::from_millis(100));
    for _ in 0..3 {
        assert_eq!(h.round_trip1(req()).await.mode, StateMode::Local);
    }
    assert_eq!(wait_failures(3).await, 3);

    // A challenge failure is counted in Valkey by the consumer (slowly).
    let fail = check(site, "mg.c.fail", "ip=203.0.113.9", 5, 900, 5, true);
    let key = fail.key.redis_key(&K);
    assert!(h.record_failure(vec![fail]));
    let mut conn = direct(&fx).await;
    let end = Instant::now() + Duration::from_secs(5);
    let mut stored: Option<String> = None;
    while stored.is_none() && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
        stored = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
    assert!(stored.is_some(), "the consumer wrote the failure");
    // Let its (delayed) reply reach the consumer.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        h.status().consecutive_failures,
        3,
        "a success slower than timeout_ms is no proof of health"
    );

    // Two more request-path misses: 5 in a row, the circuit opens.
    for _ in 0..2 {
        assert_eq!(h.round_trip1(req()).await.mode, StateMode::Local);
    }
    let end = Instant::now() + Duration::from_secs(1);
    while h.status().trips == 0 && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(h.status().trips, 1, "{:?}", h.status());
    proxy.set_latency(Duration::ZERO);
    run.shutdown().await;
}

/// Connections reset by the server: the connection manager reconnects; a
/// single failure neither trips the breaker nor loses Valkey mode for long.
/// A refusing server trips the breaker and is probed until it is back.
#[tokio::test]
async fn reset_and_refused_connections() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let mut cfg = valkey_cfg(&proxy.url());
    cfg.timeout_ms = 200;
    cfg.breaker.base_open_ms = 100;
    cfg.breaker.max_open_ms = 400;
    let run = Running::start(cfg);
    let h = &run.handle;
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let req = || RoundTrip1 {
        verdict_keys: vec![],
        limits: vec![check(site, "rst", "ip=?", 1000, 1, 1000, true)],
    };

    proxy.set_mode(FaultMode::ResetExisting);
    let mut modes = Vec::new();
    for _ in 0..10 {
        modes.push(h.round_trip1(req()).await.mode);
        if modes.last() == Some(&StateMode::Valkey) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(modes.last(), Some(&StateMode::Valkey), "{modes:?}");
    assert_eq!(h.status().trips, 0);

    proxy.set_mode(FaultMode::Refuse);
    for _ in 0..5 {
        assert_eq!(h.round_trip1(req()).await.mode, StateMode::Local);
    }
    assert_eq!(h.status().trips, 1);
    proxy.set_mode(FaultMode::Pass);
    assert!(wait_mode(h, StateMode::Valkey, Duration::from_secs(5)).await);
    assert_eq!(h.round_trip1(req()).await.mode, StateMode::Valkey);
    run.shutdown().await;
}

/// §9.7 replay rules with Valkey: a nonce used on one Edge is `Reused` on
/// another (Valkey's `{0}`); the local set answers first on the same Edge;
/// issuance quotas come from Valkey; without a Valkey answer the result is
/// `Unavailable` unless the local set is authoritative.
#[tokio::test]
async fn nonce_issue_across_edges_and_when_valkey_is_down() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let a = Running::start(valkey_cfg(&proxy.url()));
    let b = Running::start(valkey_cfg(&proxy.url()));
    assert!(wait_mode(&a.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    assert!(wait_mode(&b.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let quota = |write| {
        vec![check(
            site,
            "mg.clr.issue.ipp",
            "ip_prefix=203.0.113.0/24",
            1,
            3600,
            1,
            write,
        )]
    };
    let issue = |nonce: u8| NonceIssue {
        site: site.to_owned(),
        nonce: [nonce; 16],
        ttl_ms: 180_000,
        limits: quota(true),
    };
    let now = now_ms();

    let r = a.handle.nonce_issue(issue(1), now, now).await;
    assert!(
        matches!(&r, NonceResult::Fresh { limits } if limits[0].allowed),
        "{r:?}"
    );
    let base = proxy.round_trips();
    assert_eq!(
        a.handle.nonce_issue(issue(1), now, now).await,
        NonceResult::Reused
    );
    assert_eq!(
        proxy.round_trips(),
        base,
        "the local set answers without valkey"
    );
    assert_eq!(
        b.handle.nonce_issue(issue(1), now, now).await,
        NonceResult::Reused,
        "valkey {{0}}"
    );
    // Quota exhausted by the first issuance (burst 1), counted in Valkey.
    let r = b.handle.nonce_issue(issue(2), now, now).await;
    assert!(
        matches!(&r, NonceResult::Fresh { limits } if !limits[0].allowed),
        "{r:?}"
    );

    // Valkey down: no authoritative answer.
    proxy.set_mode(FaultMode::Refuse);
    let r = a.handle.nonce_issue(issue(3), now, now).await;
    assert!(matches!(r, NonceResult::Unavailable { .. }), "{r:?}");
    assert_eq!(
        a.handle.nonce_issue(issue(3), now, now).await,
        NonceResult::Reused
    );
    proxy.set_mode(FaultMode::Pass);
    a.shutdown().await;
    b.shutdown().await;
}

fn local_cfg() -> StateConfig {
    StateConfig::local(K)
}

fn issue(nonce: u8, limits: Vec<LimitCheck>) -> NonceIssue {
    NonceIssue {
        site: "blog".into(),
        nonce: [nonce; 16],
        ttl_ms: 180_000,
        limits,
    }
}

/// D-35, §9.7 rules 3-4 in local mode: the local set is authoritative only
/// with `local_replay_authoritative`, for challenges issued after the
/// process started, and never for a nonce the full set could not record.
#[tokio::test]
async fn local_replay_rules() {
    // Not authoritative: Unavailable, but reuse is still detected.
    let (_s, h) = StateService::new(local_cfg());
    let r = h.nonce_issue(issue(1, vec![]), 2_000_000, 2_000_000).await;
    assert_eq!(r, NonceResult::Unavailable { limits: vec![] });
    assert_eq!(
        h.nonce_issue(issue(1, vec![]), 2_000_001, 2_000_000).await,
        NonceResult::Reused
    );

    // Authoritative, 3 slots, process started at t = 1,000,000 ms.
    let mut cfg = local_cfg();
    cfg.local_replay_authoritative = true;
    cfg.local_nonce_capacity = 3;
    cfg.process_start_ms = 1_000_000;
    let (_s, h) = StateService::new(cfg);
    let now = 2_000_000;
    let fresh = NonceResult::Fresh { limits: vec![] };
    let unavailable = NonceResult::Unavailable { limits: vec![] };
    assert_eq!(h.nonce_issue(issue(2, vec![]), now, 1_500_000).await, fresh);
    assert_eq!(
        h.nonce_issue(issue(3, vec![]), now, 999_999).await,
        unavailable,
        "challenge issued before this process started (graceful upgrade window)"
    );
    assert_eq!(h.nonce_issue(issue(4, vec![]), now, 1_500_000).await, fresh);
    // Full (2, 3, 4 are live): not recorded -> Unavailable; live ones stay.
    assert_eq!(
        h.nonce_issue(issue(5, vec![]), now + 10, 1_500_000).await,
        unavailable
    );
    for n in [2, 3, 4] {
        assert_eq!(
            h.nonce_issue(issue(n, vec![]), now + 20, 1_500_000).await,
            NonceResult::Reused
        );
    }
    // After the entries expired, the set has room again, but nonce 5 (never
    // recorded) must not be judged fresh: its challenge predates the overflow.
    let later = now + 180_000 + 1;
    assert_eq!(
        h.nonce_issue(issue(5, vec![]), later, 1_500_000).await,
        unavailable
    );
    // Challenges issued after the last overflow are judged locally again.
    assert_eq!(
        h.nonce_issue(issue(6, vec![]), later, now + 11).await,
        fresh
    );
}

/// Issuance quotas without Valkey: counted in the local table,
/// all-or-nothing like `mg_nonce_issue`.
#[tokio::test]
async fn local_issuance_quotas_are_all_or_nothing() {
    let mut cfg = local_cfg();
    cfg.local_replay_authoritative = true;
    cfg.process_start_ms = 0;
    let (_s, h) = StateService::new(cfg);
    let quotas = || {
        vec![
            check("blog", "mg.clr.issue.ipp", "ip_prefix=p", 1, 3600, 1, true),
            check("blog", "mg.clr.issue.asn", "asn=1", 1, 3600, 2, true),
        ]
    };
    let now = 2_000_000_000_000;
    let NonceResult::Fresh { limits } = h.nonce_issue(issue(1, quotas()), now, now).await else {
        panic!("fresh expected")
    };
    assert!(limits.iter().all(|o| o.allowed));
    let NonceResult::Fresh { limits } = h.nonce_issue(issue(2, quotas()), now, now).await else {
        panic!("fresh expected")
    };
    assert!(!limits[0].allowed && limits[1].allowed);
    // The asn quota was not consumed by the refused issuance.
    let asn = h.local_check(
        &check("blog", "mg.clr.issue.asn", "asn=1", 1, 3600, 2, false),
        now as u64 * 1000,
    );
    assert!(asn.allowed);
    assert_eq!(asn.tat_minus_now_us, 2 * 3_600_000_000);
}

/// §9.7 "GCRA 表": at capacity, new keys share their limiter's overflow
/// bucket (`dims = "~overflow"`); live entries are never evicted, and the
/// same applies to global limiters falling back to the local table.
#[tokio::test]
async fn local_table_overflow_bucket() {
    let mut cfg = local_cfg();
    cfg.local_limiter_capacity = 2;
    let (_s, h) = StateService::new(cfg);
    let now = 1_790_000_000_000_000u64;
    let lim = |ip: &str| {
        check(
            "blog",
            "login-per-ip",
            &dims(&[("ip", Some(ip))]),
            1,
            60,
            1,
            true,
        )
    };
    assert!(h.local_check(&lim("192.0.2.1"), now).allowed);
    assert!(h.local_check(&lim("192.0.2.2"), now).allowed);
    // Table full: the next two new clients share one overflow bucket.
    assert!(h.local_check(&lim("192.0.2.3"), now).allowed);
    assert!(!h.local_check(&lim("192.0.2.4"), now).allowed);
    // The first two keep their own (live) state.
    assert!(!h.local_check(&lim("192.0.2.1"), now + 1).allowed);
    assert!(!h.local_check(&lim("192.0.2.2"), now + 1).allowed);
    // Another limiter has its own overflow bucket.
    let other = check("blog", "api", "ip=192.0.2.5", 1, 60, 1, true);
    assert!(h.local_check(&other, now).allowed);
    // Round trip 1 in local mode uses the same table (wall clock).
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![],
            limits: vec![lim("192.0.2.6"), lim("192.0.2.7")],
        })
        .await;
    assert_eq!(res.mode, StateMode::Local);
    assert_eq!(res.limits.len(), 2);
}

/// §9.1.1: proxies await the handle inside Pingora's multi-threaded request
/// filters, and `mg-edge` runs the service in a background service: the
/// futures must be `Send` and the handle shareable across threads.
#[test]
fn futures_are_send_and_the_handle_is_shareable() {
    fn send<T: Send>(_: &T) {}
    fn shareable<T: Clone + Send + Sync + 'static>() {}
    shareable::<StateHandle>();
    let (service, h) = StateService::new(local_cfg());
    send(&h.round_trip1(RoundTrip1::default()));
    send(&h.nonce_issue(issue(1, vec![]), 0, 0));
    send(&h.xadd_batch(1, vec![]));
    let (_stop, rx) = watch::channel(false);
    send(&service.run(rx));
}

/// Before `mg-state` is ready (or in local mode) every call answers at once
/// from local state.
#[tokio::test]
async fn not_ready_service_answers_locally_without_waiting() {
    let mut cfg = StateConfig::valkey("redis://127.0.0.1:1/", K);
    cfg.timeout_ms = 1_000;
    let (_service, h) = StateService::new(cfg);
    let t = Instant::now();
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec!["mg:v:blog:asn:1".into()],
            limits: vec![check("blog", "l", "ip=?", 1, 60, 1, true)],
        })
        .await;
    assert!(t.elapsed() < Duration::from_millis(100));
    assert_eq!(res.mode, StateMode::Local);
    assert_eq!(res.verdicts, vec![None]);
    assert!(res.limits[0].allowed);
    let res = h
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![],
            limits: vec![check("blog", "l", "ip=?", 1, 60, 1, true)],
        })
        .await;
    assert!(
        !res.limits[0].allowed,
        "the local table counted the first request"
    );
    assert!(matches!(
        h.xadd_batch(10, vec![vec![("v", "1".into())]]).await,
        Err(mg_edge_core::state::StateError::Unavailable)
    ));
    assert!(h.xadd_batch(10, vec![]).await.is_ok());
}

fn gathered_value(name: &str) -> f64 {
    use prometheus::Encoder;
    let mut out = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&prometheus::gather(), &mut out)
        .unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .find_map(|l| {
            l.strip_prefix(&format!("{name} "))
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap_or(0.0)
}

/// §9.7 "提交失败后": the async failure channel holds 1024 updates; when
/// full, updates are dropped and counted, never blocking the caller.
#[tokio::test]
async fn failure_channel_full_drops_and_counts() {
    let (_service, h) = StateService::new(StateConfig::valkey("redis://127.0.0.1:1/", K));
    let before = gathered_value("mg_state_async_dropped_total");
    let fail = || vec![check("blog", "mg.c.fail", "ip=?", 5, 900, 5, true)];
    for i in 0..1024 {
        assert!(h.record_failure(fail()), "update {i} must be queued");
    }
    let t = Instant::now();
    assert!(!h.record_failure(fail()));
    assert!(!h.record_failure(fail()));
    assert!(t.elapsed() < Duration::from_millis(50), "never blocks");
    assert!(gathered_value("mg_state_async_dropped_total") >= before + 2.0);

    // Local mode applies the update immediately (on the wall clock).
    let (_s, h) = StateService::new(local_cfg());
    let probe = check("blog", "mg.c.fail", "ip=?", 1, 900, 2, false);
    let wall_us = || now_ms() as u64 * 1000;
    assert!(h.local_check(&probe, wall_us()).allowed);
    for _ in 0..2 {
        assert!(h.record_failure(vec![check("blog", "mg.c.fail", "ip=?", 1, 900, 2, true)]));
    }
    assert!(
        !h.local_check(&probe, wall_us()).allowed,
        "two failures consumed the burst"
    );
}

/// An empty failure update records nothing: it is not queued (so it is not
/// "dropped" when the channel is full, and never reaches the consumer, where
/// an instant no-op would look like a healthy Valkey round trip).
#[tokio::test]
async fn empty_failure_updates_are_not_queued() {
    let (_service, h) = StateService::new(StateConfig::valkey("redis://127.0.0.1:1/", K));
    let fail = || vec![check("blog", "mg.c.fail", "ip=?", 5, 900, 5, true)];
    for i in 0..1024 {
        assert!(h.record_failure(fail()), "update {i} must be queued");
    }
    assert!(!h.record_failure(fail()), "channel full");
    assert!(
        h.record_failure(vec![]),
        "nothing to record, nothing dropped"
    );
}

/// With Valkey, failures are counted there by the single consumer.
#[tokio::test]
async fn failures_are_counted_in_valkey() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let run = Running::start(valkey_cfg(fx.url()));
    assert!(wait_mode(&run.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let fail = check(site, "mg.c.fail", "ip=203.0.113.9", 5, 900, 5, true);
    assert!(run.handle.record_failure(vec![fail.clone()]));
    let key = fail.key.redis_key(&K);
    let mut conn = direct(&fx).await;
    let end = Instant::now() + Duration::from_secs(5);
    let mut stored: Option<String> = None;
    while Instant::now() < end && stored.is_none() {
        stored = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stored.is_some(), "failure written to valkey");
    run.shutdown().await;
}

/// §13.6: one pipeline of `XADD mg:ev MAXLEN ~ n *` with fields in order.
#[tokio::test]
async fn xadd_batch_writes_ordered_fields() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let run = Running::start(valkey_cfg(fx.url()));
    assert!(wait_mode(&run.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site().to_owned();
    let entry = |rid: &str| {
        vec![
            ("v", "1".to_owned()),
            ("kind", "decision".to_owned()),
            ("site", site.clone()),
            ("rid", rid.to_owned()),
        ]
    };
    run.handle
        .xadd_batch(10_000, vec![entry("r1"), entry("r2")])
        .await
        .expect("xadd");
    let mut conn = direct(&fx).await;
    let raw: redis::Value = redis::cmd("XRANGE")
        .arg(EVENT_STREAM_KEY)
        .arg("-")
        .arg("+")
        .query_async(&mut conn)
        .await
        .unwrap();
    let redis::Value::Array(items) = raw else {
        panic!("XRANGE reply")
    };
    let mut ours = Vec::new();
    for item in items {
        let redis::Value::Array(parts) = item else {
            continue;
        };
        let Some(redis::Value::Array(fields)) = parts.get(1) else {
            continue;
        };
        let fields: Vec<String> = fields
            .iter()
            .map(|f| match f {
                redis::Value::BulkString(b) => String::from_utf8(b.clone()).unwrap(),
                _ => String::new(),
            })
            .collect();
        if fields.get(5) == Some(&site) {
            ours.push(fields);
        }
    }
    assert_eq!(ours.len(), 2);
    assert_eq!(
        ours[0],
        ["v", "1", "kind", "decision", "site", &site, "rid", "r1"]
    );
    assert_eq!(ours[1][7], "r2");
    run.shutdown().await;
}

/// Invalid verdict values are ignored and counted (§9.7).
#[tokio::test]
async fn invalid_verdicts_are_ignored_and_counted() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let run = Running::start(valkey_cfg(fx.url()));
    assert!(wait_mode(&run.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let bad_json = verdict_key(site, "asn", "1");
    let bad_utf8 = verdict_key(site, "asn", "2");
    let mut conn = direct(&fx).await;
    redis::cmd("SET")
        .arg(&bad_json)
        .arg("{not json")
        .arg("PX")
        .arg(60_000)
        .exec_async(&mut conn)
        .await
        .unwrap();
    redis::cmd("SET")
        .arg(&bad_utf8)
        .arg(&[0xffu8, 0xfe][..])
        .arg("PX")
        .arg(60_000)
        .exec_async(&mut conn)
        .await
        .unwrap();
    let before = gathered_value("mg_verdict_parse_errors_total");
    let res = run
        .handle
        .round_trip1(RoundTrip1 {
            verdict_keys: vec![bad_json, bad_utf8],
            limits: vec![],
        })
        .await;
    assert_eq!(res.mode, StateMode::Valkey);
    assert_eq!(res.verdicts[1], None, "non-UTF-8 value ignored");
    assert!(parse_verdict(res.verdicts[0].as_deref().unwrap()).is_none());
    assert!(gathered_value("mg_verdict_parse_errors_total") >= before + 2.0);
    run.shutdown().await;
}
