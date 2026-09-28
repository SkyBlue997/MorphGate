//! Protocol input limits through the real binary (docs/impl/phase1-spec.md
//! §9.3.1, D-26, integrator ruling I-2): enforce rejects (414 / 431 / 400);
//! monitor and bootstrap-open forward the request unevaluated and count
//! `mg_oversize_total`; an early rejection closes the connection without
//! reading the request body. Loopback only.

mod common;

use common::{Edge, TestEnv, blog_bundle, cf, get, raw, sign};
use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn with_bundle(env: &TestEnv, monitor_only: bool) -> Edge {
    let mut b = blog_bundle(1);
    b.monitor_only = monitor_only;
    env.write_lkg("blog", &sign(&b));
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge
}

/// Requests that exceed exactly one cap, with the §9.3.1 status and the
/// `mg_oversize_total` kind.
fn oversize_requests() -> Vec<(&'static str, String, u16, &'static str)> {
    let long = "a".repeat(8193);
    let many: String = (0..129).map(|i| format!("X-H{i}: v\r\n")).collect();
    vec![
        (
            "path",
            format!("GET /{} HTTP/1.1\r\n", &long[1..]),
            414,
            "path",
        ),
        ("query", format!("GET /q?{long} HTTP/1.1\r\n"), 414, "query"),
        (
            "header value",
            format!("GET /v HTTP/1.1\r\nX-Big: {long}\r\n"),
            431,
            "header_value",
        ),
        (
            "joined header",
            format!(
                "GET /j HTTP/1.1\r\nX-Big: {}\r\nX-Big: {}\r\n",
                &long[..5000],
                &long[..5000]
            ),
            431,
            "header_value",
        ),
        (
            "header name",
            format!("GET /n HTTP/1.1\r\nX-{}: v\r\n", &long[..255]),
            431,
            "header_value",
        ),
        (
            "header count",
            format!("GET /c HTTP/1.1\r\n{many}"),
            431,
            "header_count",
        ),
        (
            "method",
            format!("{} /m HTTP/1.1\r\n", "M".repeat(33)),
            400,
            "method",
        ),
    ]
}

fn send(env: &TestEnv, head: &str) -> common::Response {
    let req = format!(
        "{head}Host: example.com\r\n{}Connection: close\r\n\r\n",
        cf("198.51.100.7")
    );
    raw(env.listen, req.as_bytes()).unwrap()
}

#[test]
fn enforce_rejects_every_cap() {
    let env = TestEnv::new("limits-enforce");
    let edge = with_bundle(&env, false);
    for (what, head, status, _) in oversize_requests() {
        let r = send(&env, &head);
        assert_eq!(r.status, status, "{what}: {}", r.head);
        assert_eq!(
            r.header("cache-control"),
            Some("no-store, private"),
            "{what}"
        );
        assert_eq!(r.header("connection"), Some("close"), "{what}");
    }
    assert!(
        env.origin.seen().is_empty(),
        "nothing oversize reaches the origin"
    );
    let m = edge.metrics_text();
    for (reason, n) in [
        ("uri_too_long", 2),
        ("header_too_large", 4),
        ("bad_method", 1),
    ] {
        let series =
            format!("mg_protocol_rejected_total{{listener=\"cf-tunnel\",reason=\"{reason}\"}}");
        assert_eq!(
            common::metric_value(&m, &series),
            Some(f64::from(n)),
            "{series}\n{m}"
        );
    }
    assert!(
        !m.contains("mg_oversize_total{"),
        "enforce never forwards oversize requests"
    );

    // The limits themselves pass: 8192-byte path and value, 128 names, a
    // large Cookie (exempt), upstream-family names not counted.
    let at_limit = "a".repeat(8191);
    let names: String = (0..127).map(|i| format!("X-H{i}: v\r\n")).collect();
    for head in [
        format!("GET /{at_limit} HTTP/1.1\r\n"),
        format!("GET /ok HTTP/1.1\r\nX-Big: a{at_limit}\r\n"),
        format!("GET /ok HTTP/1.1\r\nCookie: a={}\r\n", "b".repeat(12_000)),
        format!("GET /ok HTTP/1.1\r\n{names}X-MG-CF-A: 1\r\nX-MG-CF-B: 1\r\n"),
    ] {
        let r = send(&env, &head);
        assert_eq!(r.status, 200, "{}", &head[..head.len().min(80)]);
    }
}

#[test]
fn monitor_and_bootstrap_forward_oversize_requests_unevaluated() {
    // I-2: monitor promises not to change traffic.
    let env = TestEnv::new("limits-monitor");
    let edge = with_bundle(&env, true);
    let mut expected: std::collections::BTreeMap<&str, u32> = Default::default();
    for (what, head, _, kind) in oversize_requests() {
        let r = send(&env, &head);
        assert_eq!(r.status, 200, "{what}: {}", r.head);
        *expected.entry(kind).or_default() += 1;
    }
    let m = edge.metrics_text();
    for (kind, n) in expected {
        let series = format!("mg_oversize_total{{kind=\"{kind}\",mode=\"monitor\",site=\"blog\"}}");
        assert_eq!(
            common::metric_value(&m, &series),
            Some(f64::from(n)),
            "{series}\n{m}"
        );
    }
    // The series exists from the start (at 0, WP-E1d) and stays there.
    assert_eq!(
        common::metric_value(
            &m,
            "mg_protocol_rejected_total{listener=\"cf-tunnel\",reason=\"uri_too_long\"}"
        ),
        Some(0.0)
    );
    // Recorded as hard.oversize_skipped, without route matching: the §9.4
    // cost bound of route matching assumes the 8 KiB path cap.
    let seen = env.origin.last("/q?").unwrap();
    let id = seen.header("mg-request-id").unwrap().to_owned();
    let line = edge.request_log(&id).expect("request log line");
    assert!(line.contains("rule=hard.oversize_skipped"), "{line}");
    assert!(line.contains(" route=- "), "{line}");
    let r = send(&env, &format!("GET /{} HTTP/1.1\r\n", "p".repeat(60_000)));
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/ppp").unwrap();
    let line = edge
        .request_log(seen.header("mg-request-id").unwrap())
        .expect("request log line");
    assert!(line.contains(" route=- "), "{line}");
    // A request within the caps is matched as usual.
    let r = send(&env, "GET /within HTTP/1.1\r\n");
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/within").unwrap();
    let line = edge
        .request_log(seen.header("mg-request-id").unwrap())
        .expect("request log line");
    assert!(line.contains(" route=default "), "{line}");
    assert!(line.contains(" rule=matrix."), "{line}");
    drop(edge);

    let env = TestEnv::new("limits-bootstrap");
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    let long = "a".repeat(8193);
    let r = send(&env, &format!("GET /q?{long} HTTP/1.1\r\n"));
    assert_eq!(r.status, 200);
    assert_eq!(
        edge.metric("mg_oversize_total{kind=\"query\",mode=\"bootstrap\",site=\"blog\"}"),
        1.0
    );
    drop(edge);

    // bootstrap = "closed" is not a record-only mode.
    let env = TestEnv::new("limits-closed");
    let _edge = env.spawn(&env.write_config(&env.default_config("bootstrap = \"closed\"")));
    let r = send(&env, &format!("GET /q?{long} HTTP/1.1\r\n"));
    assert_eq!(r.status, 414);
}

/// §9.9: a rejection sent before the body was read closes the connection;
/// the Edge must not read an attacker's 1 MiB body to the end first.
#[test]
fn early_rejection_closes_without_reading_the_body() {
    let env = TestEnv::new("limits-body");
    let _edge = with_bundle(&env, false);
    let mut s = TcpStream::connect(env.listen).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let head = format!(
        "POST /{} HTTP/1.1\r\nHost: example.com\r\n{}Content-Type: application/octet-stream\r\n\
         Content-Length: 1048576\r\n\r\n",
        "a".repeat(9000),
        cf("198.51.100.7")
    );
    // None of the promised 1 MiB follows: an Edge that drained the body
    // before closing would wait for it until the read timeout. (Unread
    // bytes in the Edge's receive buffer would turn its close into a TCP
    // reset, which may discard the response on the client side.)
    s.write_all(head.as_bytes()).unwrap();
    let started = Instant::now();
    let r = common::read_response(&mut s).expect("the Edge answers and closes");
    assert_eq!(r.status, 414, "{}", r.head);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the connection was held open (body drained?)"
    );
    assert!(env.origin.seen().is_empty());

    // Same for a 403 before the body (foreign Worker).
    let mut s = TcpStream::connect(env.listen).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let head = format!(
        "POST /w HTTP/1.1\r\nHost: example.com\r\n{}CF-Worker: evil.example\r\nContent-Length: 1048576\r\n\r\n",
        cf("198.51.100.7")
    );
    s.write_all(head.as_bytes()).unwrap();
    let r = common::read_response(&mut s).unwrap();
    assert_eq!(r.status, 403);

    // The health check is answered before the body too: with a body it
    // closes the connection instead of draining it.
    let mut s = TcpStream::connect(env.listen).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let head = format!(
        "GET /__mg/healthz HTTP/1.1\r\nHost: example.com\r\n{}Content-Length: 1048576\r\n\r\n",
        cf("198.51.100.7")
    );
    s.write_all(head.as_bytes()).unwrap();
    let started = Instant::now();
    let r = common::read_response(&mut s).expect("the Edge answers and closes");
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(r.header("connection"), Some("close"), "{}", r.head);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the health check held the connection open (body drained?)"
    );

    // A normal request still works afterwards.
    assert_eq!(
        get(env.listen, "example.com", "/fine", &cf("198.51.100.7")).status,
        200
    );
}
