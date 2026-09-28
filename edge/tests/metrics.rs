//! The Edge's metrics (docs/impl/phase1-spec.md §13.7; §15 WP-E1d
//! `metrics.rs`): every §13.7 family is served on `metrics_listen` with its
//! labels, and the Edge's added latency never contains the origin
//! connection: with an origin whose connection is artificially delayed,
//! `mg_edge_added_latency_seconds` stays small while
//! `mg_origin_connect_seconds` grows. Loopback only.

mod common;

use common::challenge::browser;
use common::policy::{default_route, field, glob, limiter, route, rule};
use common::{TestEnv, blog_bundle, cf, fixture, free_addr, get, raw, sign, testdata_artifact};
use mg_proto::v1::{Action, RouteSensitivity as S, SiteBundle};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Every §13.7 family with its label names (histograms: without `le`).
const FAMILIES: &[(&str, &[&str])] = &[
    (
        "mg_requests_total",
        &["site", "env", "route", "action", "class"],
    ),
    ("mg_decision_latency_seconds", &["site"]),
    ("mg_edge_added_latency_seconds", &["site"]),
    ("mg_origin_connect_seconds", &["site"]),
    ("mg_challenge_total", &["type", "provider", "result"]),
    (
        "mg_upstream_auth_failures_total",
        &["listener", "profile", "reason"],
    ),
    ("mg_upstream_headers_stripped_total", &["profile"]),
    ("mg_cf_connecting_ip_missing_total", &["site"]),
    ("mg_cf_foreign_worker_total", &["site"]),
    ("mg_upstream_signal_missing_total", &["profile", "signal"]),
    ("mg_token_verify_total", &["result"]),
    ("mg_ratelimit_exceeded_total", &["limiter"]),
    ("mg_crawler_verify_total", &["method", "result"]),
    ("mg_cf_vbot_disagree_total", &["direction"]),
    ("mg_event_dropped_total", &["sink", "class"]),
    ("mg_valkey_rtt_seconds", &[]),
    ("mg_valkey_errors_total", &["op"]),
    ("mg_state_mode", &["mode"]),
    ("mg_config_version", &["site"]),
    ("mg_config_age_seconds", &["site"]),
    ("mg_config_reload_total", &["site", "result"]),
    ("mg_config_fetch_failures_total", &["site"]),
    ("mg_site_state", &["site", "state"]),
    ("mg_site_unavailable_total", &["site"]),
    ("mg_artifact_missing", &["site", "name"]),
    ("mg_protocol_rejected_total", &["listener", "reason"]),
    ("mg_https_redirect_total", &["site"]),
    ("mg_policy_step_limit_total", &["site"]),
    ("mg_state_local_overflow_total", &["table"]),
    ("mg_state_async_dropped_total", &[]),
    ("mg_unknown_host_total", &["listener"]),
    ("mg_listener_rejected_total", &["listener", "site"]),
    ("mg_verdict_parse_errors_total", &[]),
    ("mg_rdns_lookups_total", &["result"]),
    ("mg_cf_ip_filter_active", &["listener"]),
    ("mg_edge_info", &["version", "edge_id"]),
    ("mg_edge_requests_total", &["route", "status"]),
    ("mg_edge_request_duration_seconds", &["route"]),
    ("mg_edge_request_errors_total", &["route"]),
];

/// `name -> every label-name set seen` of the samples in `text` (a
/// histogram is read from its `_count` samples).
fn samples(text: &str) -> BTreeMap<String, Vec<BTreeSet<String>>> {
    let histograms: BTreeSet<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|l| l.strip_suffix(" histogram"))
        .collect();
    let mut out: BTreeMap<String, Vec<BTreeSet<String>>> = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (name, labels) = match line.split_once('{') {
            Some((name, rest)) => (name, rest.split_once('}').map_or("", |(l, _)| l)),
            None => (line.split_whitespace().next().unwrap_or_default(), ""),
        };
        let name = match name.strip_suffix("_count") {
            Some(base) if histograms.contains(base) => base,
            _ if histograms.iter().any(|h| name.starts_with(h)) => continue,
            _ => name,
        };
        let set = labels
            .split(',')
            .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_owned()))
            .collect();
        out.entry(name.to_owned()).or_default().push(set);
    }
    out
}

fn tls_listener(name: &str, bind: SocketAddr) -> String {
    format!(
        "[[listeners]]\nname = \"{name}\"\nbind = \"{bind}\"\nprofile = \"direct_tls\"\ntls_cert = \"{}\"\ntls_key = \"{}\"\n",
        fixture("tls/edge.pem").display(),
        fixture("tls/edge.key").display()
    )
}

/// Enforce, with a limiter, a block rule, a route that requires clearance
/// and a `datacenter-asns` artifact.
fn bundle(version: u64, artifact: &mg_proto::v1::ArtifactRef) -> SiteBundle {
    let mut b = blog_bundle(version);
    b.monitor_only = false;
    b.artifacts = vec![artifact.clone()];
    let env = &mut b.environments[0];
    env.routes = vec![
        route("limited", &["/limited"], S::Low, false, false),
        route("members", &["/members/**"], S::Medium, true, false),
        default_route(),
    ];
    env.rules = vec![rule(
        "block-bad",
        "custom",
        Action::Block,
        glob(field("req.path"), "/blocked/**"),
        &[],
    )];
    env.rate_limits = vec![limiter(
        "limited-ip",
        &["limited"],
        &["ip"],
        (1, 60, 1),
        "rate_limit",
        30,
    )];
    b
}

/// §13.7: every family is served, with exactly its labels.
#[test]
fn every_family_is_served_with_its_labels() {
    let env = TestEnv::new("metrics-families");
    let (artifact, bytes) = testdata_artifact("datacenter-asns", "datacenter-asns.txt");
    // The LKG references an artifact that is not cached: MISSING
    // (mg_artifact_missing); the bundle root is still empty (fetch failures).
    env.write_lkg("blog", &sign(&bundle(1, &artifact)));
    let tls = free_addr();
    let config = env.config(&tls_listener("tls", tls), &env.site(""));
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge.wait_metric("mg_config_fetch_failures_total{site=\"blog\"}", 10, |v| {
        v >= 1.0
    });
    let ip = "198.51.100.40";
    for (path, headers, status) in [
        ("/", browser(ip), 200),
        ("/limited", browser(ip), 200),
        ("/limited", browser(ip), 429),
        ("/blocked/x", browser(ip), 403),
        ("/members/a", browser(ip), 403),
        // An http visitor is redirected instead of challenged (D-32).
        (
            "/members/b",
            browser(ip).replace("\"scheme\":\"https\"", "\"scheme\":\"http\""),
            308,
        ),
        // No CF-Connecting-IP: missing signals.
        ("/", String::new(), 200),
        (
            "/",
            format!("{}CF-Worker: attacker.example\r\n", cf(ip)),
            403,
        ),
    ] {
        let r = get(env.listen, "example.com", path, &headers);
        assert_eq!(r.status, status, "{path}: {}\n{}", r.head, r.body);
    }
    assert_eq!(get(env.listen, "unknown.invalid", "/", "").status, 404);
    let long = format!(
        "GET /{} HTTP/1.1\r\nHost: example.com\r\n{}\r\n",
        "a".repeat(9000),
        cf(ip)
    );
    assert_eq!(raw(env.listen, long.as_bytes()).unwrap().status, 414);
    // A newer bundle with its artifact published: applied, artifact fetched.
    env.publish_artifact(&bytes);
    env.publish("blog", &sign(&bundle(2, &artifact)));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 20, |v| v == 2.0);

    let text = edge.metrics_text();
    let seen = samples(&text);
    for (name, labels) in FAMILIES {
        let want: BTreeSet<String> = labels.iter().map(|l| (*l).to_owned()).collect();
        let sets = seen
            .get(*name)
            .unwrap_or_else(|| panic!("{name} is not served:\n{text}"));
        assert!(
            sets.iter().all(|s| *s == want),
            "{name}: labels {sets:?}, want {want:?}"
        );
    }
    // A few values the requests above must have produced.
    for (series, min) in [
        (
            "mg_requests_total{action=\"rate_limit\",class=\"human_likely\",env=\"production\",route=\"limited\",site=\"blog\"}",
            1.0,
        ),
        ("mg_ratelimit_exceeded_total{limiter=\"limited-ip\"}", 1.0),
        ("mg_https_redirect_total{site=\"blog\"}", 1.0),
        ("mg_cf_foreign_worker_total{site=\"blog\"}", 1.0),
        ("mg_cf_connecting_ip_missing_total{site=\"blog\"}", 1.0),
        ("mg_unknown_host_total{listener=\"cf-tunnel\"}", 1.0),
        (
            "mg_protocol_rejected_total{listener=\"cf-tunnel\",reason=\"uri_too_long\"}",
            1.0,
        ),
        (
            "mg_challenge_total{provider=\"none\",result=\"issued\",type=\"invisible\"}",
            1.0,
        ),
        ("mg_edge_added_latency_seconds_count{site=\"blog\"}", 8.0),
        ("mg_origin_connect_seconds_count{site=\"blog\"}", 1.0),
    ] {
        let v = common::metric_value(&text, series).unwrap_or(0.0);
        assert!(v >= min, "{series} = {v}, want >= {min}\n{text}");
    }
    // Series with fixed labels exist before their first event (§17 alerts).
    for series in [
        "mg_rdns_lookups_total{result=\"dropped\"}",
        "mg_policy_step_limit_total{site=\"blog\"}",
        "mg_upstream_auth_failures_total{listener=\"cf-tunnel\",profile=\"cloudflare\",reason=\"non_loopback_peer\"}",
        "mg_upstream_headers_stripped_total{profile=\"direct_tls\"}",
        "mg_listener_rejected_total{listener=\"tls\",site=\"blog\"}",
        "mg_cf_ip_filter_active{listener=\"cf-tunnel\"}",
    ] {
        assert_eq!(common::metric_value(&text, series), Some(0.0), "{series}");
    }
}

// ---------------------------------------------------------------------------
// An origin whose connections are delayed by the kernel: its accept queue is
// filled with idle connections, so the Edge's SYN is dropped and only
// retransmitted (after about one second) once the queue is drained.

struct SlowOrigin {
    addr: SocketAddr,
    release: std::sync::mpsc::Sender<Duration>,
}

impl SlowOrigin {
    /// `None` when this system does not drop SYNs to a full accept queue
    /// (the test then cannot delay a connection and says so).
    fn start() -> Option<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<Duration>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let socket = tokio::net::TcpSocket::new_v4().unwrap();
                socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let listener = socket.listen(1).unwrap();
                let addr = listener.local_addr().unwrap();
                // Fill the accept queue until a connection attempt stalls.
                let mut held = Vec::new();
                let mut full = false;
                for _ in 0..64 {
                    match tokio::time::timeout(
                        Duration::from_millis(300),
                        tokio::net::TcpStream::connect(addr),
                    )
                    .await
                    {
                        Ok(Ok(s)) => held.push(s),
                        Ok(Err(_)) => break,
                        Err(_) => {
                            full = true;
                            break;
                        }
                    }
                }
                let _ = tx.send(full.then_some(addr));
                if !full {
                    return;
                }
                // Wait for the test, then keep the queue full for `delay`.
                let Ok(delay) = released.recv() else { return };
                tokio::time::sleep(delay).await;
                drop(held);
                loop {
                    let Ok((mut s, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut got = Vec::new();
                        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => got.extend_from_slice(&buf[..n]),
                            }
                        }
                        let _ = s
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
                            )
                            .await;
                    });
                }
            });
        });
        let addr = rx.recv().ok().flatten()?;
        Some(Self { addr, release })
    }
}

fn sum_and_count(text: &str, family: &str) -> (f64, f64) {
    let get = |suffix: &str| {
        common::metric_value(text, &format!("{family}_{suffix}{{site=\"blog\"}}")).unwrap_or(0.0)
    };
    (get("sum"), get("count"))
}

/// §13.7: the added latency never contains the origin connection. The
/// origin's connection is delayed by about a second; the Edge's own time
/// for that request stays far below it, the connect histogram takes it.
#[test]
fn added_latency_excludes_the_origin_connection() {
    let Some(origin) = SlowOrigin::start() else {
        eprintln!("SKIPPED: this kernel does not hold back connections to a full accept queue");
        return;
    };
    let env = TestEnv::new("metrics-latency");
    let mut b = blog_bundle(1);
    b.monitor_only = true;
    env.write_lkg("blog", &sign(&b));
    let config = env
        .default_config("")
        .replace(&env.origin.addr.to_string(), &origin.addr.to_string());
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    let before = edge.metrics_text();
    let (added0, added_n0) = sum_and_count(&before, "mg_edge_added_latency_seconds");
    let (connect0, connect_n0) = sum_and_count(&before, "mg_origin_connect_seconds");

    origin.release.send(Duration::from_millis(400)).unwrap();
    let started = Instant::now();
    let r = get(env.listen, "example.com", "/slow", &cf("198.51.100.41"));
    let took = started.elapsed();
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    assert_eq!(r.body, "slow");
    assert!(took >= Duration::from_millis(400), "not delayed: {took:?}");

    let after = edge.metrics_text();
    let (added1, added_n1) = sum_and_count(&after, "mg_edge_added_latency_seconds");
    let (connect1, connect_n1) = sum_and_count(&after, "mg_origin_connect_seconds");
    assert_eq!(added_n1 - added_n0, 1.0);
    assert_eq!(connect_n1 - connect_n0, 1.0, "one new origin connection");
    let connect = connect1 - connect0;
    let added = added1 - added0;
    assert!(
        connect >= 0.35,
        "origin connect {connect:.3} s for a request that took {took:?}"
    );
    assert!(
        added < 0.25 && added < connect / 2.0,
        "added latency {added:.3} s includes the origin connection ({connect:.3} s)"
    );
}
