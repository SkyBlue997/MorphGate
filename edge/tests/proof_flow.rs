//! `MG-Proof` on routes through the real binary (docs/impl/phase2-spec.md
//! §9.1, §9.2, §9.5, §9.6, §17 WP-E2b): the failures of §6.7 and their
//! order, exempt navigations, a form POST and an `api` route that claim to
//! be navigations, bundles that never verify, `proof: required` under
//! monitor and enforce, the in-place recovery `C` and its conditions,
//! replay, the per-key quota and an unavailable replay store, `Early-Data`,
//! D-61 cookie stripping, `force_monitor` and the decision event's Phase 2
//! fields. Loopback only; proofs and solutions come from mg-challenge's
//! test-only helpers (D-59).

mod common;

use common::challenge::CHROME;
use common::interactive::{Shown, cookie, from_page, json_body, post_json, submission};
use common::{Edge, TestEnv, cf, get, raw, sign};
use mg_challenge::testkit::TestSessionKey;
use mg_edge_core::testkit::http::test_site_bundle_v2;
use mg_proto::v1 as pb;
use serde_json::Value;

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

fn required(mut r: pb::Route) -> pb::Route {
    r.proof = pb::ProofMode::Required as i32;
    r
}

/// The proof test site (enforce, schema 2): `api` (channel api, proof),
/// `strict` (api, proof, `fail_closed`), `form` (web, proof), `mon` (api,
/// proof, route mode monitor), `gate` (web, `require_clearance`: where the
/// tests earn their clearances) and `default`; PoW at 8 bits.
fn bundle(version: u64) -> pb::SiteBundle {
    let mut b = test_site_bundle_v2("blog", &common::HOSTS, version);
    b.monitor_only = false;
    let mut strict = required(route("strict", &["/strict/**"], pb::Channel::Api));
    strict.fail_closed = true;
    let mut mon = required(route("mon", &["/mon/**"], pb::Channel::Api));
    mon.mode = pb::RouteMode::Monitor as i32;
    let mut gate = route("gate", &["/gate/**"], pb::Channel::Web);
    gate.require_clearance = true;
    let mut default = route("default", &["/**"], pb::Channel::Web);
    default.sensitivity = pb::RouteSensitivity::Low as i32;
    b.environments[0].routes = vec![
        required(route("api", &["/api/**"], pb::Channel::Api)),
        strict,
        required(route("form", &["/form"], pb::Channel::Web)),
        mon,
        gate,
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
    b
}

fn config(env: &TestEnv, authoritative: bool, site_extra: &str) -> String {
    let c = env.default_config(site_extra);
    let c = if authoritative {
        c.replace(
            "[valkey]\nmode = \"local\"\n",
            "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
        )
    } else {
        c
    };
    common::with_events(
        &c,
        &format!("file = \"{}\"\n", env.dir.join("events.jsonl").display()),
    )
}

fn start(env: &TestEnv, b: &pb::SiteBundle, authoritative: bool, site_extra: &str) -> Edge {
    env.publish("blog", &sign(b));
    let edge = env.spawn_logging(
        &env.write_config(&config(env, authoritative, site_extra)),
        "mg_edge=debug",
    );
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| {
        v == b.version as f64
    });
    // §9.2: the local `jti` verdict counts from the second after the start.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    edge
}

/// `p` with one character of its signature changed (not the last one,
/// whose low bits are padding).
fn tamper_sig(p: &str) -> String {
    let mut chars: Vec<char> = p.chars().collect();
    let i = chars.len() - 10;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A fresh `jti` per call.
fn jti() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut j = [0u8; 16];
    j[..8].copy_from_slice(&n.to_be_bytes());
    j[8..].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
    j
}

/// A valid proof of `method https://example.com<path>`. Its `iat` is 5 s
/// ahead (the most §6.7 allows) so that the local `jti` set is
/// authoritative right after the start (§9.2: `iat − 5 ≥` the start).
fn proof(key: &TestSessionKey, method: &str, path: &str) -> String {
    key.proof(
        method,
        &format!("https://example.com{path}"),
        now_s() + 5,
        &jti(),
    )
}

/// Headers of a fetch from `ip` with `extra`.
fn fetch(ip: &str, extra: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: application/json\r\nSec-Fetch-Mode: cors\r\n{extra}",
        cf(ip)
    )
}

fn navigation(ip: &str, extra: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n{extra}",
        cf(ip)
    )
}

fn request(env: &TestEnv, method: &str, path: &str, headers: &str) -> common::Response {
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n{headers}\r\n"
    );
    raw(env.listen, req.as_bytes()).unwrap_or_else(|e| panic!("{method} {path}: {e}"))
}

/// A clearance bound to `key` (a v2 submission, D-46): the `Cookie` value.
fn bound_token(env: &TestEnv, key: &TestSessionKey, ip: &str) -> String {
    let r = get(env.listen, "example.com", "/gate/x", &navigation(ip, ""));
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    let s: Shown = from_page(&r.body);
    let r = post_json(env, "/__mg/c", ip, CHROME, "", &submission(key, &s, "", ""));
    assert_eq!(r.status, 200, "{}", r.body);
    cookie(&r, "__Host-mg_clr").unwrap()
}

/// A clearance without `cnf` (a v1 form submission).
fn unbound_token(env: &TestEnv, ip: &str) -> String {
    let r = get(env.listen, "example.com", "/gate/y", &navigation(ip, ""));
    assert_eq!(r.status, 403);
    let s = common::challenge::from_page(&r.body);
    let r =
        common::challenge::submit_form(env.listen, ip, &common::challenge::solved(&s, CHROME), "");
    assert_eq!(r.status, 303, "{}", r.body);
    common::challenge::cookie_of(&r)
}

fn line(edge: &Edge, r: &common::Response) -> String {
    common::answered_log(edge, &r.body)
}

fn forwarded_line(env: &TestEnv, edge: &Edge, path: &str) -> String {
    common::origin_log(env, edge, path)
}

fn events(env: &TestEnv) -> Vec<Value> {
    std::fs::read_to_string(env.dir.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The decision event of `request_id`, waiting for the flush.
fn decision_event(env: &TestEnv, request_id: &str) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(v) = events(env)
            .into_iter()
            .find(|v| v["kind"] == "decision" && v["ctx"]["request_id"] == request_id)
        {
            return v;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no decision event for {request_id}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// §9.1 / §6.7: a valid proof passes; the replay and every failure of §6.7
/// get the 403 `mg_proof_required` JSON with `now_ms` (never a `C`: the
/// key matches the clearance); exempt navigations pass without a proof; a
/// form POST that claims to be a navigation gets the HTML block page, a
/// navigation to an `api` route is not exempt; a CORS preflight passes.
#[test]
fn proofs_on_required_routes() {
    let env = TestEnv::new("proof-enforce");
    let edge = start(&env, &bundle(1), true, "");
    let ip = "198.51.100.21";
    let key = TestSessionKey::from_label("proof-a");
    let clr = bound_token(&env, &key, ip);
    let with = |extra: &str| fetch(ip, &format!("Cookie: {clr}\r\n{extra}"));

    // Valid.
    let p = proof(&key, "GET", "/api/items");
    let r = get(
        env.listen,
        "example.com",
        "/api/items",
        &with(&format!("MG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let l = forwarded_line(&env, &edge, "/api/items");
    assert!(l.contains("proof=valid"), "{l}");
    let seen = env.origin.last("/api/items").unwrap();
    assert!(!seen.has("mg-proof"), "MG-Proof is never forwarded");

    // The same proof again: a replay.
    let r = get(
        env.listen,
        "example.com",
        "/api/items",
        &with(&format!("MG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(line(&edge, &r).contains("proof=replay"));

    // No proof: `missing`; the answer and its fields.
    let r = get(env.listen, "example.com", "/api/items", &with(""));
    assert_eq!(r.status, 403);
    assert_eq!(r.header("mg-error"), Some("mg_proof_required"));
    assert_eq!(r.header("cache-control"), Some("no-store, private"));
    let v = json_body(&r);
    assert_eq!(v["v"], 2);
    assert_eq!(v["error"], "mg_proof_required");
    assert!(v["now_ms"].as_i64().unwrap() > 1_700_000_000_000);
    assert!(v.get("challenge").is_none(), "{v}");
    let l = line(&edge, &r);
    assert!(
        l.contains("proof=absent") && l.contains("rule=edge.proof_required"),
        "{l}"
    );

    // Each failure of §6.7.
    let iat = now_s();
    let fails = [
        ("garbage", "a.b.c".to_owned()),
        (
            "htm",
            key.proof("POST", "https://example.com/api/items", iat, &jti()),
        ),
        (
            "htm",
            key.proof("get", "https://example.com/api/items", iat, &jti()),
        ),
        (
            "htu",
            key.proof("GET", "https://example.com/api/other", iat, &jti()),
        ),
        (
            "htu",
            key.proof("GET", "https://example.com:443/api/items", iat, &jti()),
        ),
        (
            "htu",
            key.proof("GET", "https://www.example.com/api/items", iat, &jti()),
        ),
        (
            "iat",
            key.proof("GET", "https://example.com/api/items", iat - 60, &jti()),
        ),
        (
            "iat",
            key.proof("GET", "https://example.com/api/items", iat + 60, &jti()),
        ),
    ];
    for (want, value) in fails {
        let r = get(
            env.listen,
            "example.com",
            "/api/items",
            &with(&format!("MG-Proof: {value}\r\n")),
        );
        assert_eq!(r.status, 403, "{want}");
        let want = if want == "garbage" { "malformed" } else { want };
        let l = line(&edge, &r);
        assert!(l.contains(&format!("proof={want}")), "{want}: {l}");
    }
    // A bad signature (the last character of the signature changed).
    let bad = tamper_sig(&proof(&key, "GET", "/api/items"));
    let r = get(
        env.listen,
        "example.com",
        "/api/items",
        &with(&format!("MG-Proof: {bad}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(line(&edge, &r).contains("proof=sig"));
    // Two MG-Proof lines are malformed.
    let p2 = proof(&key, "GET", "/api/items");
    let r = get(
        env.listen,
        "example.com",
        "/api/items",
        &with(&format!("MG-Proof: {p2}\r\nMG-Proof: {p2}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(line(&edge, &r).contains("proof=malformed"));

    // The query does not matter to `htu`; the method string does.
    let p = key.proof(
        "GET",
        "https://example.com/api/q?ignored=1#f",
        now_s() + 5,
        &jti(),
    );
    let r = get(
        env.listen,
        "example.com",
        "/api/q?x=2",
        &with(&format!("MG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let p = proof(&key, "POST", "/api/items");
    let r = request(
        &env,
        "POST",
        "/api/items",
        &with(&format!("MG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.body);

    // Exempt: a GET navigation on a web route needs no proof (the header,
    // even a broken one, is ignored).
    let r = get(
        env.listen,
        "example.com",
        "/form",
        &navigation(ip, &format!("Cookie: {clr}\r\nMG-Proof: x\r\n")),
    );
    assert_eq!(r.status, 200);
    assert!(forwarded_line(&env, &edge, "/form").contains("proof=-"));
    // A form POST claiming to be a navigation is not exempt: HTML 403.
    let r = request(
        &env,
        "POST",
        "/form",
        &navigation(ip, &format!("Cookie: {clr}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(
        r.header("content-type").unwrap().starts_with("text/html"),
        "{}",
        r.head
    );
    assert!(r.header("mg-error").is_none());
    // A navigation to an api route is not exempt either.
    let r = get(
        env.listen,
        "example.com",
        "/api/page",
        &navigation(ip, &format!("Cookie: {clr}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    // A CORS preflight passes without a proof.
    let r = request(
        &env,
        "OPTIONS",
        "/api/items",
        &fetch(
            ip,
            "Access-Control-Request-Method: POST\r\nOrigin: https://example.com\r\n",
        ),
    );
    assert_eq!(r.status, 200, "{}", r.head);

    // §9.1: Early-Data on a proof route is 425 (the proof is still checked).
    let p = proof(&key, "GET", "/api/items");
    let r = get(
        env.listen,
        "example.com",
        "/api/items",
        &with(&format!("MG-Proof: {p}\r\nEarly-Data: 1\r\n")),
    );
    assert_eq!(r.status, 425);
    assert_eq!(json_body(&r)["error"], "mg_too_early");

    // The route mode monitor only records: forwarded, the substitution
    // with dry_run in the decision event.
    let r = get(env.listen, "example.com", "/mon/x", &with(""));
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/mon/x").unwrap();
    let rid = seen.header("mg-request-id").unwrap().to_owned();
    let ev = decision_event(&env, &rid);
    assert_eq!(ev["proof_required"], true, "{ev}");
    assert_eq!(ev["decision"]["rule_id"], "edge.proof_required");
    assert_eq!(ev["decision"]["dry_run"], true);
    assert_eq!(
        ev["ctx"]["identity"]["proof"]["present"],
        Value::Null,
        "{ev}"
    );
    assert_eq!(ev["ctx"]["identity"]["token"]["bound"], true);

    let text = edge.metrics_text();
    for (result, min) in [
        ("valid", 3.0),
        ("replay", 1.0),
        ("missing", 3.0),
        ("malformed", 2.0),
        ("htm", 2.0),
        ("htu", 3.0),
        ("iat", 2.0),
        ("sig", 1.0),
    ] {
        let v = common::metric_or_zero(
            &text,
            &format!("mg_proof_verify_total{{result=\"{result}\"}}"),
        );
        assert!(v >= min, "{result}: {v}");
    }
}

/// §9.1 in-place recovery: a clearance without `cnf` (`proof.unbound`) or
/// bound to another key (`proof.jkt`) gets a `pow` `C` bound to the proof's
/// key, with its `ret` (I-54); the old key cannot use it, the new key earns
/// a clearance bound to itself. No recovery without a valid clearance.
#[test]
fn in_place_recovery() {
    let env = TestEnv::new("proof-recover");
    let edge = start(&env, &bundle(1), true, "");
    let ip = "198.51.100.22";
    let old = TestSessionKey::from_label("proof-old");
    let new = TestSessionKey::from_label("proof-new");

    // proof.jkt: the visitor's key was replaced.
    let clr = bound_token(&env, &old, ip);
    let p = proof(&new, "GET", "/api/data");
    let r = get(
        env.listen,
        "example.com",
        "/api/data?page=2",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    let v = json_body(&r);
    assert_eq!(v["error"], "mg_proof_required");
    assert_eq!(v["type"], "pow", "{v}");
    assert_eq!(v["ret"], "/api/data?page=2");
    assert!(v["pow"]["bits"].as_u64().unwrap() > 0);
    assert!(line(&edge, &r).contains("proof=jkt"));
    let s = common::interactive::from_json(&v);
    // The C is bound to the new key: the old one fails ic.bind_jkt.
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&old, &s, "", ""),
    );
    assert_eq!(r.status, 403);
    assert!(
        line(&edge, &r).contains("ic.bind_jkt"),
        "{}",
        line(&edge, &r)
    );
    let r = get(
        env.listen,
        "example.com",
        "/api/data?page=2",
        &fetch(
            ip,
            &format!(
                "Cookie: {clr}\r\nMG-Proof: {}\r\n",
                proof(&new, "GET", "/api/data")
            ),
        ),
    );
    let s = common::interactive::from_json(&json_body(&r));
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&new, &s, "", ""),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let renewed = cookie(&r, "__Host-mg_clr").unwrap();
    let p = proof(&new, "GET", "/api/data");
    let r = get(
        env.listen,
        "example.com",
        "/api/data",
        &fetch(ip, &format!("Cookie: {renewed}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.body);

    // proof.unbound: a clearance without cnf.
    let clr = unbound_token(&env, ip);
    let p = proof(&new, "GET", "/api/data");
    let r = get(
        env.listen,
        "example.com",
        "/api/data",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    let v = json_body(&r);
    assert_eq!(v["type"], "pow", "{v}");
    assert!(line(&edge, &r).contains("proof=unbound"));

    // Without a clearance: proof.unbound, but nothing to recover.
    let p = proof(&new, "GET", "/api/data");
    let r = get(
        env.listen,
        "example.com",
        "/api/data",
        &fetch(ip, &format!("MG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(json_body(&r).get("challenge").is_none());
    // A proof whose signature fails is never recovered either.
    let bad = tamper_sig(&proof(&new, "GET", "/api/data"));
    let clr = bound_token(&env, &old, ip);
    let r = get(
        env.listen,
        "example.com",
        "/api/data",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {bad}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(json_body(&r).get("challenge").is_none(), "{}", r.body);
}

/// §9.1 recovery stops at `pow`: a route whose `min_level` is `interactive`
/// gets no recovery `C` (the SDK goes through `/__mg/v`, D-58).
#[test]
fn no_recovery_above_pow() {
    let env = TestEnv::new("proof-level");
    let mut b = bundle(1);
    let ix = b.challenge.as_mut().unwrap().interactive.as_mut().unwrap();
    ix.enabled = true;
    ix.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 8,
        high: 8,
        very_high: 8,
    });
    ix.pow_k = 2;
    let mut lvl = required(route("lvl", &["/lvl/**"], pb::Channel::Api));
    lvl.min_level = pb::ChallengeType::Interactive as i32;
    b.environments[0].routes.insert(0, lvl);
    let edge = start(&env, &b, true, "");
    let ip = "198.51.100.23";
    let key = TestSessionKey::from_label("proof-lvl");
    let other = TestSessionKey::from_label("proof-lvl-2");
    // An interactive clearance bound to `key`.
    let r = get(env.listen, "example.com", "/members", &navigation(ip, ""));
    assert_eq!(r.status, 200, "no challenge for the default route");
    let r = get(
        env.listen,
        "example.com",
        "/__mg/v?ret=/lvl/a&min=interactive",
        &navigation(ip, ""),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    let s = common::interactive::from_page(&r.body);
    assert_eq!(s.ty, "interactive");
    let rn = post_json(
        &env,
        "/__mg/c/renew",
        ip,
        CHROME,
        "",
        &common::interactive::renewal(&key, &s.c),
    );
    let v = json_body(&rn);
    let s = Shown {
        c: v["challenge"].as_str().unwrap().to_owned(),
        ix: Some(v["ix"].clone()),
        ..s
    };
    common::interactive::wait_min(&s);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &common::interactive::hold(&key, &s),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let p = proof(&key, "GET", "/lvl/a");
    let r = get(
        env.listen,
        "example.com",
        "/lvl/a",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    // Another key: proof.jkt, but the route asks for more than pow.
    let p = proof(&other, "GET", "/lvl/a");
    let r = get(
        env.listen,
        "example.com",
        "/lvl/a",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    let v = json_body(&r);
    assert_eq!(v["error"], "mg_proof_required");
    assert!(v.get("challenge").is_none(), "{v}");
    drop(edge);
}

/// §9.2: the per-key quota (600 `jti` per 60 s) makes the next proof of
/// that key a replay, and only that key's.
#[test]
fn per_key_jti_quota() {
    let env = TestEnv::new("proof-quota");
    let edge = start(&env, &bundle(1), true, "");
    let ip = "198.51.100.24";
    let key = TestSessionKey::from_label("proof-quota");
    let clr = bound_token(&env, &key, ip);
    let mut ok = 0;
    for _ in 0..600 {
        let p = proof(&key, "GET", "/api/n");
        let r = get(
            env.listen,
            "example.com",
            "/api/n",
            &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
        );
        if r.status == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 600);
    let p = proof(&key, "GET", "/api/n");
    let r = get(
        env.listen,
        "example.com",
        "/api/n",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 403);
    assert!(line(&edge, &r).contains("proof=replay"));
    // Another key is not affected.
    let other = TestSessionKey::from_label("proof-quota-2");
    let clr2 = bound_token(&env, &other, ip);
    let p = proof(&other, "GET", "/api/n");
    let r = get(
        env.listen,
        "example.com",
        "/api/n",
        &fetch(ip, &format!("Cookie: {clr2}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200);
}

/// §9.1 / §9.2: without an authoritative replay store a valid proof is
/// `unchecked`: it passes (counted), except on a `fail_closed` proof route
/// (429, `Retry-After: 5`).
#[test]
fn replay_store_unavailable() {
    let env = TestEnv::new("proof-unchecked");
    // The clearance comes from an authoritative run (a token issued without
    // a replay check, `ruc`, is no clearance on a fail_closed route, I-30).
    let edge = start(&env, &bundle(1), true, "");
    let ip = "198.51.100.25";
    let key = TestSessionKey::from_label("proof-u");
    let clr = bound_token(&env, &key, ip);
    drop(edge);
    let edge = start(&env, &bundle(1), false, "");
    let p = proof(&key, "GET", "/api/u");
    let r = get(
        env.listen,
        "example.com",
        "/api/u",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(forwarded_line(&env, &edge, "/api/u").contains("proof=unchecked"));
    let p = proof(&key, "GET", "/strict/u");
    let r = get(
        env.listen,
        "example.com",
        "/strict/u",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 429, "{}", r.body);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(line(&edge, &r).contains("rule=edge.proof_replay_unavailable"));
    assert!(edge.metric("mg_proof_verify_total{result=\"unchecked\"}") >= 2.0);
}

/// §9.1, §4.2: a bundle with no proof route and no rule reading
/// `identity.proof` never verifies (the header is ignored); one whose rule
/// reads it verifies on every request that is not exempt; schema 1 never
/// does (D-66).
#[test]
fn verification_only_when_needed() {
    use common::policy::{field, rule};
    let env = TestEnv::new("proof-needed");
    let mut b = bundle(1);
    for r in &mut b.environments[0].routes {
        r.proof = pb::ProofMode::Off as i32;
    }
    let edge = start(&env, &b, true, "");
    let ip = "198.51.100.26";
    let key = TestSessionKey::from_label("proof-n");
    let clr = bound_token(&env, &key, ip);
    let r = get(
        env.listen,
        "example.com",
        "/api/a",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: x\r\n")),
    );
    assert_eq!(r.status, 200);
    assert!(forwarded_line(&env, &edge, "/api/a").contains("proof=-"));
    drop(edge);

    // A rule that reads identity.proof.valid (log only).
    let env = TestEnv::new("proof-reads");
    let mut b = bundle(1);
    for r in &mut b.environments[0].routes {
        r.proof = pb::ProofMode::Off as i32;
    }
    let not_valid = pb::Expr {
        kind: Some(pb::expr::Kind::Not(Box::new(pb::Unary {
            arg: Some(Box::new(field("identity.proof.valid"))),
        }))),
    };
    b.environments[0].rules = vec![rule("no-proof", "custom", pb::Action::Log, not_valid, &[])];
    let edge = start(&env, &b, true, "");
    let clr = bound_token(&env, &key, ip);
    let r = get(
        env.listen,
        "example.com",
        "/api/a",
        &fetch(ip, &format!("Cookie: {clr}\r\n")),
    );
    assert_eq!(r.status, 200);
    let l = forwarded_line(&env, &edge, "/api/a");
    assert!(
        l.contains("proof=absent") && l.contains("no-proof:matched"),
        "{l}"
    );
    let p = proof(&key, "GET", "/api/b");
    let r = get(
        env.listen,
        "example.com",
        "/api/b",
        &fetch(ip, &format!("Cookie: {clr}\r\nMG-Proof: {p}\r\n")),
    );
    assert_eq!(r.status, 200);
    let l = forwarded_line(&env, &edge, "/api/b");
    assert!(
        l.contains("proof=valid") && !l.contains("no-proof:matched"),
        "{l}"
    );
    // Exempt navigation: MISSING, so the rule is not matched.
    let r = get(env.listen, "example.com", "/page", &navigation(ip, ""));
    assert_eq!(r.status, 200);
    let l = forwarded_line(&env, &edge, "/page");
    assert!(
        l.contains("proof=-") && l.contains("no-proof:missing_input"),
        "{l}"
    );
    drop(edge);

    // Schema 1: never verified, the cookies reach the origin (D-61, D-66).
    let env = TestEnv::new("proof-schema1");
    let mut b1 = common::blog_bundle(1);
    b1.monitor_only = false;
    let edge = start(&env, &b1, true, "");
    let r = get(
        env.listen,
        "example.com",
        "/s1",
        &fetch(
            ip,
            "MG-Proof: x\r\nCookie: a=1; __Host-mg_st=1.2.1; b=2\r\n",
        ),
    );
    assert_eq!(r.status, 200);
    assert!(forwarded_line(&env, &edge, "/s1").contains("proof=-"));
    let seen = env.origin.last("/s1").unwrap();
    assert_eq!(seen.header("cookie"), Some("a=1; __Host-mg_st=1.2.1; b=2"));
}

/// D-61: the origin never sees the three Edge cookies; the rest of every
/// `Cookie` field reaches it byte for byte.
#[test]
fn edge_cookies_are_stripped_before_forwarding() {
    let env = TestEnv::new("proof-cookies");
    let _edge = start(&env, &bundle(1), true, "");
    let ip = "198.51.100.27";
    let r = get(
        env.listen,
        "example.com",
        "/c1",
        &navigation(
            ip,
            "Cookie: a=1; __Host-mg_clr=x; __Host-mg_st=1.2.1; b=2;__Host-mg_a11y=1;c=3\r\n\
             Cookie: __Host-mg_clr=y\r\nCookie: __host-mg_clr=keep\r\n",
        ),
    );
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/c1").unwrap();
    assert_eq!(seen.all("cookie"), ["a=1; b=2;c=3", "__host-mg_clr=keep"]);
    let r = get(
        env.listen,
        "example.com",
        "/c2",
        &navigation(ip, "Cookie: a=1;  b=2\r\n"),
    );
    assert_eq!(r.status, 200);
    assert_eq!(env.origin.last("/c2").unwrap().all("cookie"), ["a=1;  b=2"]);
}

/// D-60 / §9.6: `force_monitor` forwards what the bundle would challenge,
/// sets the gauge, logs a WARN and counts as a `--check-config` warning;
/// the decision event says `forced_monitor` with `monitor_only`.
#[test]
fn force_monitor() {
    let env = TestEnv::new("proof-forced");
    let edge = start(&env, &bundle(1), true, "force_monitor = true\n");
    edge.wait_metric("mg_site_forced_monitor{site=\"blog\"}", 5, |v| v == 1.0);
    let ip = "198.51.100.28";
    let r = get(env.listen, "example.com", "/gate/f", &navigation(ip, ""));
    assert_eq!(r.status, 200, "forwarded instead of challenged");
    let r2 = get(env.listen, "example.com", "/api/f", &fetch(ip, ""));
    assert_eq!(r2.status, 200, "no proof required while forced");
    let seen = env.origin.last("/gate/f").unwrap();
    let ev = decision_event(&env, seen.header("mg-request-id").unwrap());
    assert_eq!(ev["forced_monitor"], true, "{ev}");
    assert_eq!(ev["monitor_only"], true);
    assert_eq!(ev["decision"]["dry_run"], true);
    assert_eq!(ev["ctx"]["http"]["navigation"], true);
    assert!(
        edge.log_text().contains("force_monitor = true"),
        "WARN at load"
    );
    let out = env.check(&env.write_config(&config(&env, true, "force_monitor = true\n")));
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("force_monitor"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// §10.1: `--check-config` warns when the bundle asks for `mg:ev` while the
/// Edge runs in local mode.
#[test]
fn check_config_warns_about_a_stream_in_local_mode() {
    let env = TestEnv::new("proof-stream-warning");
    let mut b = bundle(1);
    b.events.as_mut().unwrap().stream = true;
    env.write_lkg("blog", &sign(&b));
    let out = env.check(&env.write_config(&config(&env, true, "")));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("writes no mg:ev"), "{text}");
}
