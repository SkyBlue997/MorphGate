//! `POST /__mg/r` and `POST /__mg/t` through the real binary
//! (docs/impl/phase2-spec.md §9.3, §9.4, §15, §17 WP-E2b): the refresh and
//! every refusal it can reach on loopback, route R's monitor, the copied
//! claims and the session cap; the reports, their signing, the trusted
//! counters, suppression, redaction, the limits, the telemetry queue and
//! the schema 1 404s. Loopback only; proofs and solutions come from
//! mg-challenge's test-only helpers (D-59).

mod common;

use common::challenge::CHROME;
use common::interactive::{cookie, from_page, json_body, post_json, set_cookies, submission};
use common::{Edge, TestEnv, cf, get, sign};
use mg_challenge::testkit::TestSessionKey;
use mg_edge_core::testkit::http::test_site_bundle_v2;
use mg_proto::v1 as pb;
use serde_json::{Value, json};

fn route(name: &str, paths: &[&str], channel: pb::Channel) -> pb::Route {
    pb::Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: channel as i32,
        sensitivity: pb::RouteSensitivity::Medium as i32,
        ..Default::default()
    }
}

/// Schema 2, enforce, refresh on: `gate` (`min_level: pow`, where the
/// tests earn pow clearances), `inv` (`require_clearance`: invisible
/// clearances), `api` (channel api), `secret` (`redact_path`) and
/// `default` (route R).
fn bundle(version: u64) -> pb::SiteBundle {
    let mut b = test_site_bundle_v2("blog", &common::HOSTS, version);
    b.monitor_only = false;
    let mut gate = route("gate", &["/gate/**"], pb::Channel::Web);
    gate.min_level = pb::ChallengeType::Pow as i32;
    let mut inv = route("inv", &["/inv/**"], pb::Channel::Web);
    inv.require_clearance = true;
    let mut secret = route("secret", &["/secret/**"], pb::Channel::Web);
    secret.redact_path = true;
    let mut default = route("default", &["/**"], pb::Channel::Web);
    default.sensitivity = pb::RouteSensitivity::Low as i32;
    b.environments[0].routes = vec![
        gate,
        inv,
        route("api", &["/api/**"], pb::Channel::Api),
        secret,
        default,
    ];
    let c = b.challenge.as_mut().unwrap();
    c.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 8,
        high: 8,
        very_high: 8,
    });
    c.max_failures = 100;
    c.submit_rate = 1000;
    c.submit_burst = 1000;
    b.clearance.as_mut().unwrap().refresh = true;
    b
}

fn config(env: &TestEnv, events: &str) -> String {
    let c = env.default_config("").replace(
        "[valkey]\nmode = \"local\"\n",
        "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
    );
    common::with_events(
        &c,
        &format!(
            "file = \"{}\"\nflush_interval_ms = 50\n{events}",
            env.dir.join("events.jsonl").display()
        ),
    )
}

fn start(env: &TestEnv, b: &pb::SiteBundle, events: &str) -> Edge {
    env.publish("blog", &sign(b));
    let edge = env.spawn_logging(&env.write_config(&config(env, events)), "mg_edge=debug");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| {
        v == b.version as f64
    });
    // §9.2: the local `jti` verdict counts from the second after the start.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    edge
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jti() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut j = [0u8; 16];
    j[..8].copy_from_slice(&n.to_be_bytes());
    j[8..].copy_from_slice(&u64::from(std::process::id()).to_be_bytes());
    j
}

fn proof(key: &TestSessionKey, path: &str) -> String {
    key.proof(
        "POST",
        &format!("https://example.com{path}"),
        now_s() + 5,
        &jti(),
    )
}

fn navigation(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n",
        cf(ip)
    )
}

/// A clearance of `path`'s route bound to `key`.
fn token(env: &TestEnv, key: &TestSessionKey, ip: &str, path: &str) -> String {
    let r = get(env.listen, "example.com", path, &navigation(ip));
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    let s = from_page(&r.body);
    let r = post_json(env, "/__mg/c", ip, CHROME, "", &submission(key, &s, "", ""));
    assert_eq!(r.status, 200, "{}", r.body);
    cookie(&r, "__Host-mg_clr").unwrap()
}

fn refresh(env: &TestEnv, ip: &str, extra: &str, body: &Value) -> common::Response {
    post_json(env, "/__mg/r", ip, CHROME, extra, body)
}

fn claims(cookie: &str) -> mg_challenge::ClearanceClaims {
    let token = cookie.strip_prefix("__Host-mg_clr=").unwrap();
    let keys = std::fs::read(common::repo("testdata/phase1/keys/token.keys.json")).unwrap();
    let keys = mg_challenge::TokenKeySet::from_key_file(&keys, "blog", &["blog-t-20260927".into()])
        .unwrap();
    mg_challenge::verify(&keys, "blog", "production", token, now_s()).unwrap()
}

fn events(env: &TestEnv, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(env.dir.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["kind"] == kind)
        .collect()
}

fn wait_events(env: &TestEnv, kind: &str, n: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let e = events(env, kind);
        if e.len() >= n || std::time::Instant::now() > deadline {
            return e;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// §9.3 steps 4-9: a bound `pow` clearance refreshes into a v2 token with
/// the same `sub`, `sst`, `lat`, `lvl` and `cnf`, a new `iat` / `exp` and
/// both cookies; it is a `kind=refresh` event only. Then the refusals: a
/// replayed proof, no proof, another key, an unbound clearance, no
/// clearance, a level that never refreshes, the session limiter.
#[test]
fn refresh_and_its_refusals() {
    let env = TestEnv::new("refresh");
    let edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.31";
    let key = TestSessionKey::from_label("refresh-a");
    let clr = token(&env, &key, ip, "/gate/a");
    let before = claims(&clr);
    assert_eq!(before.lvl, mg_core::TokenLevel::Pow);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let p = proof(&key, "/__mg/r");
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n"),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let v = json_body(&r);
    assert_eq!((v["v"].as_u64(), v["ok"].as_bool()), (Some(2), Some(true)));
    let cookies = set_cookies(&r);
    assert!(cookies[0].starts_with("__Host-mg_clr=") && cookies[1].starts_with("__Host-mg_st="));
    let renewed = cookie(&r, "__Host-mg_clr").unwrap();
    let after = claims(&renewed);
    assert_eq!(v["iat"].as_i64(), Some(after.iat));
    assert_eq!(v["exp"].as_i64(), Some(after.exp));
    assert!(v["now_ms"].as_i64().unwrap() > 0);
    assert_eq!(
        (after.v, &after.sub, after.sst),
        (2, &before.sub, before.sst)
    );
    assert_eq!(after.lat, Some(before.level_at()));
    assert_eq!(after.lvl, before.lvl);
    assert_eq!(after.cnf, before.cnf);
    assert!(after.iat > before.iat && after.exp > before.exp);
    assert_ne!(after.jti, before.jti);
    // The refreshed token works.
    let r = get(
        env.listen,
        "example.com",
        "/gate/b",
        &format!("{}Cookie: {renewed}\r\n", navigation(ip)),
    );
    assert_eq!(r.status, 200);

    // The same proof again: replay.
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {renewed}\r\nMG-Proof: {p}\r\n"),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    assert_eq!(r.header("mg-error"), Some("mg_refresh_denied"));
    assert_eq!(json_body(&r)["error"], "mg_refresh_denied");
    // No proof; another key's proof.
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {renewed}\r\n"),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    let other = TestSessionKey::from_label("refresh-b");
    let r = refresh(
        &env,
        ip,
        &format!(
            "Cookie: {renewed}\r\nMG-Proof: {}\r\n",
            proof(&other, "/__mg/r")
        ),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    // No clearance.
    let r = refresh(
        &env,
        ip,
        &format!("MG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    // An invisible clearance never refreshes.
    let inv = token(&env, &key, ip, "/inv/a");
    assert_eq!(claims(&inv).lvl, mg_core::TokenLevel::Invisible);
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {inv}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    // A malformed body.
    for body in [
        json!({"v": 1}),
        json!({"v": 2, "x": 1}),
        json!({"v": 2, "t": 5}),
    ] {
        let r = refresh(
            &env,
            ip,
            &format!(
                "Cookie: {renewed}\r\nMG-Proof: {}\r\n",
                proof(&key, "/__mg/r")
            ),
            &body,
        );
        assert_eq!(r.status, 403, "{body}");
    }

    let text = edge.metrics_text();
    for (result, min) in [
        ("ok", 1.0),
        ("replay", 1.0),
        ("invalid", 6.0),
        ("not_refreshable", 1.0),
    ] {
        let v = common::metric_or_zero(
            &text,
            &format!("mg_token_refresh_total{{result=\"{result}\"}}"),
        );
        assert!(v >= min, "{result}: {v}\n{text}");
    }
    let ev = wait_events(&env, "refresh", 9);
    let results: Vec<&str> = ev.iter().filter_map(|e| e["result"].as_str()).collect();
    assert!(
        results.contains(&"ok") && results.contains(&"not_refreshable"),
        "{results:?}"
    );
    let ok = ev.iter().find(|e| e["result"] == "ok").unwrap();
    assert_eq!(ok["lvl"], "pow");
    assert_eq!(ok["bound"], true);
    assert!(
        ok["msg"]
            .as_str()
            .unwrap()
            .starts_with("refresh ok lvl=pow")
    );
    let replay = ev.iter().find(|e| e["result"] == "replay").unwrap();
    assert_eq!(replay["reason"], "proof.replay");
    // No decision event and no mg_requests_total for the refreshes.
    for d in events(&env, "decision") {
        assert_ne!(d["ctx"]["http"]["path"], "/__mg/r", "{d}");
    }
    assert!(!text.contains("route=\"__mg\""));

    // The session limiter: 10 / 600 s, burst 3 (the first refresh above
    // counted once already).
    let fresh = token(&env, &key, ip, "/gate/c");
    let mut statuses = Vec::new();
    for _ in 0..4 {
        let r = refresh(
            &env,
            ip,
            &format!(
                "Cookie: {fresh}\r\nMG-Proof: {}\r\n",
                proof(&key, "/__mg/r")
            ),
            &json!({"v": 2}),
        );
        statuses.push(r.status);
    }
    assert!(statuses.contains(&429), "{statuses:?}");
}

/// §9.3 step 8: route R demands more than the clearance's level (a rule
/// challenges `interactive` on R): `challenge`; under R's mode monitor the
/// refresh goes ahead and the event keeps the reason. A BLOCK on R is
/// `mg_blocked`. A refresh cap of 1 s makes an older level `too_old`.
#[test]
fn refresh_with_route_r_decisions() {
    use common::policy::{eq, field, rule, string};
    let ip = "198.51.100.32";
    let key = TestSessionKey::from_label("refresh-r");
    let challenge_rule = || {
        rule(
            "r-interactive",
            "custom",
            pb::Action::Challenge,
            eq(field("route.name"), string("default")),
            &[("type", "interactive")],
        )
    };
    let enable_ix = |b: &mut pb::SiteBundle| {
        let ix = b.challenge.as_mut().unwrap().interactive.as_mut().unwrap();
        ix.enabled = true;
    };

    // CHALLENGE(interactive) on R, enforce: refused.
    let env = TestEnv::new("refresh-challenge");
    let mut b = bundle(1);
    enable_ix(&mut b);
    b.environments[0].rules = vec![challenge_rule()];
    let edge = start(&env, &b, "");
    let clr = token(&env, &key, ip, "/gate/a");
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(
        edge.metric("mg_token_refresh_total{result=\"challenge\"}"),
        1.0
    );
    drop(edge);

    // R in mode monitor: refreshed, the reason recorded.
    let env = TestEnv::new("refresh-monitor");
    let mut b = bundle(1);
    enable_ix(&mut b);
    b.environments[0].rules = vec![challenge_rule()];
    b.environments[0].routes.last_mut().unwrap().mode = pb::RouteMode::Monitor as i32;
    let _edge = start(&env, &b, "");
    let clr = token(&env, &key, ip, "/gate/a");
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let ev = wait_events(&env, "refresh", 1);
    assert_eq!(ev[0]["result"], "ok");
    assert_eq!(ev[0]["reason"], "challenge");
    drop(_edge);

    // BLOCK on R: mg_blocked.
    let env = TestEnv::new("refresh-blocked");
    let mut b = bundle(1);
    b.environments[0].rules = vec![rule(
        "r-block",
        "custom",
        pb::Action::Block,
        eq(field("route.name"), string("default")),
        &[],
    )];
    let edge = start(&env, &b, "");
    let clr = token(&env, &key, ip, "/gate/a");
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    assert_eq!(json_body(&r)["error"], "mg_blocked");
    assert_eq!(r.header("mg-error"), Some("mg_blocked"));
    assert_eq!(
        edge.metric("mg_token_refresh_total{result=\"blocked\"}"),
        1.0
    );
    drop(edge);

    // refresh_max_pow_s = 1: too old after two seconds.
    let env = TestEnv::new("refresh-old");
    let mut b = bundle(1);
    b.clearance.as_mut().unwrap().refresh_max_pow_s = 1;
    let edge = start(&env, &b, "");
    let clr = token(&env, &key, ip, "/gate/a");
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    assert_eq!(
        edge.metric("mg_token_refresh_total{result=\"too_old\"}"),
        1.0
    );
}

/// §9.3 steps 0-3, §11.1, D-66: refresh off (`disabled`), an unbound
/// clearance (`not_bound`), `Early-Data`, no client IP, other methods,
/// and 404 in schema 1 for both endpoints.
#[test]
fn refresh_gates_and_schema_1() {
    let env = TestEnv::new("refresh-gates");
    let mut b = bundle(1);
    b.clearance.as_mut().unwrap().refresh = false;
    let edge = start(&env, &b, "");
    let ip = "198.51.100.33";
    let key = TestSessionKey::from_label("refresh-g");
    let clr = token(&env, &key, ip, "/gate/a");
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    assert_eq!(
        edge.metric("mg_token_refresh_total{result=\"disabled\"}"),
        1.0
    );
    let r = refresh(&env, ip, "Early-Data: 1\r\n", &json!({"v": 2}));
    assert_eq!(r.status, 425);
    assert_eq!(json_body(&r)["error"], "mg_too_early");
    let req = "POST /__mg/r HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 7\r\nContent-Type: application/json\r\n\r\n{\"v\":2}";
    let r = common::raw(env.listen, req.as_bytes()).unwrap();
    assert_eq!(r.status, 429);
    assert_eq!(r.header("retry-after"), Some("5"));
    let r = get(env.listen, "example.com", "/__mg/r", &cf(ip));
    assert_eq!((r.status, r.header("allow")), (405, Some("POST")));
    let r = get(env.listen, "example.com", "/__mg/t", &cf(ip));
    assert_eq!((r.status, r.header("allow")), (405, Some("POST")));
    drop(edge);

    // An unbound clearance (v1 form submission) with refresh on.
    let env = TestEnv::new("refresh-unbound");
    let edge = start(&env, &bundle(1), "");
    let r = get(env.listen, "example.com", "/gate/u", &navigation(ip));
    let s = common::challenge::from_page(&r.body);
    let r =
        common::challenge::submit_form(env.listen, ip, &common::challenge::solved(&s, CHROME), "");
    assert_eq!(r.status, 303);
    let clr = common::challenge::cookie_of(&r);
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2}),
    );
    assert_eq!(r.status, 403);
    assert_eq!(
        edge.metric("mg_token_refresh_total{result=\"not_bound\"}"),
        1.0
    );
    drop(edge);

    let env = TestEnv::new("refresh-schema1");
    let mut b1 = common::blog_bundle(1);
    b1.monitor_only = false;
    let _edge = start(&env, &b1, "");
    for path in ["/__mg/r", "/__mg/t"] {
        let r = post_json(&env, path, ip, CHROME, "", &json!({"v": 2}));
        assert_eq!(r.status, 404, "{path}");
    }
}

/// A valid behavior summary (§12.8), from `testdata/phase2/samples`.
fn behavior_summary() -> Value {
    json!({"v": 1, "ptr": {"speed": [0, 7, 1, 8, 2, 9, 3, 10, 4, 11, 5, 12, 6, 0, 7, 1],
        "curv": [0, 3, 1, 4, 2, 0, 3, 1, 4, 2, 0, 3, 1, 4, 2, 0], "pauses": 4},
        "keys": {"iki": [2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0]},
        "scroll": {"dist": 9, "speed": [0, 1, 2, 3, 4, 5, 6, 7]},
        "touch": {"area_var": 0, "pressure_var": 0}, "focus": 1, "vis": 2,
        "form": {"fill_ms": 12, "paste": 0}})
}

fn report(env: &TestEnv, ip: &str, extra: &str, reports: Value) -> common::Response {
    post_json(
        env,
        "/__mg/t",
        ip,
        CHROME,
        extra,
        &json!({"v": 1, "reports": reports}),
    )
}

/// §9.4: unsigned reports are recorded and counted `unsigned`, never in
/// the alert metrics; signed ones count once per session, kind and 10
/// minutes (then `suppressed`); `cache_hit` under `/__mg/s/` is `invalid`,
/// `behavior` without `telemetry_behavior` `disabled`; paths of a
/// `redact_path` route are `/<route>`; the lines go to vl-short with
/// `source = "sdk"` and `signed`.
#[test]
fn telemetry_reports() {
    let env = TestEnv::new("telemetry");
    let edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.34";
    let key = TestSessionKey::from_label("telemetry-a");
    let clr = token(&env, &key, ip, "/gate/a");
    let upstream = json!({"kind": "upstream_challenge", "scope": "protected_fetch", "path": "/api/save", "count": 2});

    // Unsigned.
    let r = report(
        &env,
        ip,
        "",
        json!([upstream, {"kind": "key_unavailable", "reason": "no_idb"}]),
    );
    assert_eq!(r.status, 204, "{}\n{}", r.head, r.body);
    assert!(r.body.is_empty());
    assert_eq!(
        edge.metric("mg_telemetry_reports_total{kind=\"upstream_challenge\",result=\"unsigned\"}"),
        1.0
    );
    assert_eq!(
        edge.metric("mg_double_challenge_total{route=\"api\",site=\"blog\"}"),
        0.0
    );

    // Signed: counted once, then suppressed.
    let signed = |extra_reports: Value| {
        let p = proof(&key, "/__mg/t");
        report(
            &env,
            ip,
            &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n"),
            extra_reports,
        )
    };
    let r = signed(json!([
        upstream,
        {"kind": "cache_hit", "path": "/__mg/c"},
        {"kind": "sw_intercept", "path": "/__mg/v"},
        {"kind": "behavior", "page": "/a", "summary": behavior_summary()},
    ]));
    assert_eq!(r.status, 204, "{}", r.body);
    let r = signed(json!([upstream, {"kind": "cache_hit", "path": "/__mg/s/mg.js"}]));
    assert_eq!(r.status, 204);
    let text = edge.metrics_text();
    for (series, want) in [
        (
            "mg_double_challenge_total{route=\"api\",site=\"blog\"}",
            1.0,
        ),
        ("mg_endpoint_cache_hit_reports_total{site=\"blog\"}", 1.0),
        ("mg_sw_intercept_reports_total{site=\"blog\"}", 1.0),
        (
            "mg_telemetry_reports_total{kind=\"upstream_challenge\",result=\"accepted\"}",
            1.0,
        ),
        (
            "mg_telemetry_reports_total{kind=\"upstream_challenge\",result=\"suppressed\"}",
            1.0,
        ),
        (
            "mg_telemetry_reports_total{kind=\"cache_hit\",result=\"invalid\"}",
            1.0,
        ),
        (
            "mg_telemetry_reports_total{kind=\"behavior\",result=\"disabled\"}",
            1.0,
        ),
        (
            "mg_telemetry_reports_total{kind=\"key_unavailable\",result=\"unsigned\"}",
            1.0,
        ),
    ] {
        assert_eq!(
            common::metric_or_zero(&text, series),
            want,
            "{series}\n{text}"
        );
    }

    // A redacting route's path, and the lines.
    let r = report(
        &env,
        ip,
        "",
        json!([{"kind": "upstream_challenge", "scope": "navigation", "path": "/secret/tok-123", "count": 1}]),
    );
    assert_eq!(r.status, 204);
    let lines = wait_events(&env, "telemetry", 7);
    assert!(lines.iter().all(|l| l["source"] == "sdk"), "{lines:?}");
    assert!(lines.iter().any(|l| l["signed"] == true));
    assert!(lines.iter().any(|l| l["signed"] == false));
    assert!(lines.iter().any(|l| l["path"] == "/secret"), "{lines:?}");
    let all = std::fs::read_to_string(env.dir.join("events.jsonl")).unwrap();
    assert!(!all.contains("tok-123"));

    // Bad bodies: 400 mg_bad_request.
    for bad in [
        json!({"v": 2, "reports": [upstream]}),
        json!({"v": 1, "reports": []}),
        json!({"v": 1, "reports": [{"kind": "nope"}]}),
        json!({"v": 1, "reports": [upstream, upstream]}),
        json!({"v": 1, "reports": vec![json!({"kind": "key_unavailable", "reason": "no_idb"}); 9]}),
        json!({"v": 1, "reports": [{"kind": "cache_hit", "path": "/x"}]}),
    ] {
        let r = post_json(&env, "/__mg/t", ip, CHROME, "", &bad);
        assert_eq!(r.status, 400, "{bad}");
        let v = json_body(&r);
        assert_eq!(v["error"], "mg_bad_request");
        assert_eq!(r.header("mg-error"), Some("mg_bad_request"));
    }
    let r = report(&env, ip, "Early-Data: 1\r\n", json!([upstream]));
    assert_eq!(r.status, 425);
}

/// §9.4 step 3 and §9.4 step 7: `mg.t` per ip entity (60 / 60 s, burst
/// 30); a full telemetry queue drops telemetry only, never the decision
/// events.
#[test]
fn telemetry_limits_and_queue() {
    let env = TestEnv::new("telemetry-limits");
    let edge = start(
        &env,
        &bundle(1),
        "queue_telemetry = 64\nmax_batch_lines = 100000\n",
    );
    let ip = "198.51.100.35";
    let eight = json!(vec![
        json!({"kind": "key_unavailable", "reason": "no_storage"});
        8
    ]);
    let mut statuses = Vec::new();
    for _ in 0..32 {
        statuses.push(report(&env, ip, "", eight.clone()).status);
    }
    assert!(statuses.iter().take(30).all(|s| *s == 204), "{statuses:?}");
    assert_eq!(statuses.last(), Some(&429));
    // The decision events still arrive (a blocked request is one).
    let r = get(env.listen, "example.com", "/inv/x", &navigation(ip));
    assert_eq!(r.status, 403);
    let rid = common::request_id_of(&r.body).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !events(&env, "decision")
        .iter()
        .any(|d| d["ctx"]["request_id"] == rid.as_str())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "decision event missing"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let text = edge.metrics_text();
    assert_eq!(
        common::metric_or_zero(
            &text,
            "mg_event_dropped_total{class=\"priority\",sink=\"buffer\"}"
        ),
        0.0
    );
}

/// §9.4 / §9.3 / §15.2 with `events.telemetry_behavior`: a behavior report
/// is accepted and written with its summary, and a refresh's `t` becomes a
/// `kind=telemetry` line with `source = "refresh"`.
#[test]
fn behavior_and_refresh_telemetry_when_enabled() {
    let env = TestEnv::new("telemetry-behavior");
    let mut b = bundle(1);
    b.events.as_mut().unwrap().telemetry_behavior = true;
    let edge = start(&env, &b, "");
    let ip = "198.51.100.36";
    let key = TestSessionKey::from_label("telemetry-b");
    let r = report(
        &env,
        ip,
        "",
        json!([{"kind": "behavior", "page": "/articles", "summary": behavior_summary()}]),
    );
    assert_eq!(r.status, 204, "{}", r.body);
    assert_eq!(
        edge.metric("mg_telemetry_reports_total{kind=\"behavior\",result=\"unsigned\"}"),
        1.0
    );
    let clr = token(&env, &key, ip, "/gate/a");
    let t = common::interactive::t_of("single", 2000);
    let r = refresh(
        &env,
        ip,
        &format!("Cookie: {clr}\r\nMG-Proof: {}\r\n", proof(&key, "/__mg/r")),
        &json!({"v": 2, "t": t}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let lines = wait_events(&env, "telemetry", 2);
    let behavior = lines.iter().find(|l| l["source"] == "sdk").unwrap();
    assert_eq!(behavior["summary"]["v"], 1, "{behavior}");
    assert_eq!(behavior["page"], "/articles");
    let refresh = lines.iter().find(|l| l["source"] == "refresh").unwrap();
    assert_eq!(refresh["ix"]["mode"], "single", "{refresh}");
}
