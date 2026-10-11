//! The Phase 2 events and counters through the real binary
//! (docs/impl/phase2-spec.md §15, §13.1, D-62; WP-E2b): the decision
//! event's `provider_id` and Phase 2 context fields, `kind=access` with
//! `sess` and `ct`, the renewal's `kind=feedback` (counted failure and
//! rebind), `mg_navigations_total`, and a replay-unchecked clearance that
//! forces its decision event and counts `mg_token_ruc_total`. Loopback only.

mod common;

use common::challenge::CHROME;
use common::interactive::{cookie, from_page, json_body, post_json, renewal, submission};
use common::{Edge, TestEnv, cf, get, sign};
use mg_challenge::testkit::TestSessionKey;
use mg_edge_core::testkit::http::test_site_bundle_v2;
use mg_proto::v1 as pb;
use serde_json::Value;

fn route(name: &str, paths: &[&str]) -> pb::Route {
    pb::Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: pb::Channel::Web as i32,
        sensitivity: pb::RouteSensitivity::Medium as i32,
        ..Default::default()
    }
}

/// Schema 2, enforce, interactive on: `ix` (`min_level: interactive`),
/// `gate` (`require_clearance`), `default`; every decision sampled out
/// (rate 0) so that only exempt ones are written.
fn bundle() -> pb::SiteBundle {
    let mut b = test_site_bundle_v2("blog", &common::HOSTS, 1);
    b.monitor_only = false;
    let mut ix = route("ix", &["/ix/**"]);
    ix.min_level = pb::ChallengeType::Interactive as i32;
    let mut gate = route("gate", &["/gate/**"]);
    gate.require_clearance = true;
    let mut default = route("default", &["/**"]);
    default.sensitivity = pb::RouteSensitivity::Low as i32;
    b.environments[0].routes = vec![ix, gate, default];
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
    let i = c.interactive.as_mut().unwrap();
    i.enabled = true;
    i.pow_bits = c.pow_bits;
    i.pow_k = 2;
    let e = b.events.as_mut().unwrap();
    e.allow_sample_rate = 0.0;
    e.access_log = true;
    b
}

fn start(env: &TestEnv, authoritative: bool) -> Edge {
    env.publish("blog", &sign(&bundle()));
    let c = env.default_config("");
    let c = if authoritative {
        c.replace(
            "[valkey]\nmode = \"local\"\n",
            "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
        )
    } else {
        c
    };
    let c = common::with_events(
        &c,
        &format!(
            "file = \"{}\"\nflush_interval_ms = 50\n",
            env.dir.join("events.jsonl").display()
        ),
    );
    let edge = env.spawn_logging(&env.write_config(&c), "mg_edge=debug");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 1.0);
    edge
}

fn navigation(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n",
        cf(ip)
    )
}

fn lines(env: &TestEnv, pred: impl Fn(&Value) -> bool, n: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let found: Vec<Value> = std::fs::read_to_string(env.dir.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| pred(v))
            .collect();
        if found.len() >= n || std::time::Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// §15.3: an interactive challenge's decision event names its first
/// provider and carries `http.navigation`; §15.1: a renewal with a bad
/// signature writes `kind=feedback` (`renew: true`, `fail`), a bound `C`
/// renewed from another prefix `renew_rebind`; §15.5:
/// `mg_navigations_total` counts the GET navigations.
#[test]
fn interactive_decision_and_renewal_feedback() {
    let env = TestEnv::new("p2ev-ix");
    let edge = start(&env, true);
    let ip = "198.51.100.41";
    let r = get(env.listen, "example.com", "/ix/a", &navigation(ip));
    assert_eq!(r.status, 403);
    let s = from_page(&r.body);
    let rid = common::request_id_of(&r.body).unwrap();
    let d = lines(
        &env,
        |v| v["kind"] == "decision" && v["ctx"]["request_id"] == rid.as_str(),
        1,
    );
    assert_eq!(d.len(), 1, "challenges are always written");
    assert_eq!(d[0]["decision"]["provider_id"], "self_hold", "{}", d[0]);
    assert_eq!(d[0]["ctx"]["http"]["navigation"], true);
    assert!(edge.metric("mg_navigations_total{site=\"blog\"}") >= 1.0);

    // A renewal whose signature does not verify: a counted failure.
    let key = TestSessionKey::from_label("p2ev-a");
    let other = TestSessionKey::from_label("p2ev-b");
    let mut bad = renewal(&key, &s.c);
    bad["sig"] = renewal(&other, &s.c)["sig"].clone();
    let r = post_json(&env, "/__mg/c/renew", ip, CHROME, "", &bad);
    assert_eq!(r.status, 403, "{}", r.body);
    let fb = lines(&env, |v| v["kind"] == "feedback" && v["renew"] == true, 1);
    assert_eq!(fb.len(), 1, "{fb:?}");
    assert_eq!(fb[0]["outcome"], "fail");
    assert_eq!(fb[0]["type"], "interactive");
    assert_eq!(fb[0]["route_id"], "ix");
    assert!(
        fb[0]["msg"]
            .as_str()
            .unwrap()
            .starts_with("challenge fail interactive/")
    );

    // Bind the C, then renew it from another /24: renew_rebind.
    let r = post_json(&env, "/__mg/c/renew", ip, CHROME, "", &renewal(&key, &s.c));
    assert_eq!(r.status, 200, "{}", r.body);
    let bound = json_body(&r)["challenge"].as_str().unwrap().to_owned();
    let r = post_json(
        &env,
        "/__mg/c/renew",
        "203.0.113.41",
        CHROME,
        "",
        &renewal(&key, &bound),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let fb = lines(
        &env,
        |v| v["kind"] == "feedback" && v["outcome"] == "renew_rebind",
        1,
    );
    assert_eq!(fb.len(), 1);
    assert_eq!(fb[0]["renew"], true);
    assert_eq!(fb[0]["bound"], true);
    // Successful renewals write nothing else.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        lines(&env, |v| v["kind"] == "feedback" && v["renew"] == true, 0).len(),
        2
    );
}

/// §15.3 `kind=access`: `sess` of the valid clearance and `ct` of the
/// origin's answer (absent when the Edge answered itself).
#[test]
fn access_records_carry_session_and_content_class() {
    let env = TestEnv::new("p2ev-access");
    let _edge = start(&env, true);
    let ip = "198.51.100.42";
    let key = TestSessionKey::from_label("p2ev-c");
    let r = get(env.listen, "example.com", "/gate/a", &navigation(ip));
    let s = from_page(&r.body);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&key, &s, "", ""),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let r = get(
        env.listen,
        "example.com",
        "/gate/b",
        &format!("{}Cookie: {clr}\r\n", navigation(ip)),
    );
    assert_eq!(r.status, 200);
    let rid = env
        .origin
        .last("/gate/b")
        .unwrap()
        .header("mg-request-id")
        .unwrap()
        .to_owned();
    let a = lines(
        &env,
        |v| v["kind"] == "access" && v["request_id"] == rid.as_str(),
        1,
    );
    assert_eq!(a[0]["ct"], "o", "the mock origin answers text/plain");
    let sub = a[0]["sess"].as_str().unwrap();
    assert_eq!(sub.len(), 22);
    // The challenge answer: no origin, no ct, no sess.
    let challenged = lines(&env, |v| v["kind"] == "access" && v["path"] == "/gate/a", 1);
    assert!(challenged[0].get("ct").is_none() && challenged[0].get("sess").is_none());
}

/// D-62: a clearance issued without a replay check (`ruc`, a local
/// non-authoritative replay set) forces the decision event of every request
/// that carries it, and counts `mg_token_ruc_total`.
#[test]
fn ruc_clearance_forces_decision_events() {
    let env = TestEnv::new("p2ev-ruc");
    let edge = start(&env, false);
    let ip = "198.51.100.43";
    let key = TestSessionKey::from_label("p2ev-d");
    let r = get(env.listen, "example.com", "/gate/a", &navigation(ip));
    let s = from_page(&r.body);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&key, &s, "", ""),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let r = get(
        env.listen,
        "example.com",
        "/plain",
        &format!("{}Cookie: {clr}\r\n", navigation(ip)),
    );
    assert_eq!(r.status, 200);
    let rid = env
        .origin
        .last("/plain")
        .unwrap()
        .header("mg-request-id")
        .unwrap()
        .to_owned();
    let d = lines(
        &env,
        |v| v["kind"] == "decision" && v["ctx"]["request_id"] == rid.as_str(),
        1,
    );
    assert_eq!(d.len(), 1, "an allow decision at rate 0 is written for ruc");
    assert_eq!(d[0]["token"]["replay_unchecked"], true);
    assert_eq!(d[0]["sample_rate"], 1.0);
    assert_eq!(edge.metric("mg_token_ruc_total{site=\"blog\"}"), 1.0);
}
