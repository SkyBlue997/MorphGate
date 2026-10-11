//! Application logs never carry client secrets (docs/impl/phase1-spec.md
//! D-31, §2.4 item 5, §9.11; §15 WP-E1d `logs.rs`): at `trace` level, a
//! request flow with a challenge, its solved submission, the clearance
//! cookie, an upstream key and every Cloudflare header, plus failing event
//! outputs, leaves no client IP, cookie value, `C`, clearance token,
//! upstream key, `x-mg-cf-tls-random`, return path or query in the log.
//! Loopback only.

mod common;

use common::challenge::{self, browser, cookie_of, from_page, solved, submit_form};
use common::policy::{default_route, route};
use common::{TestEnv, blog_bundle, cf, free_addr, get, sign, with_events};
use mg_edge_core::testkit::vl::{FakeVl, VlReply};
use mg_proto::v1::RouteSensitivity as S;
use mg_proto::v1::challenge_config::PowBits;
use std::time::{Duration, Instant};

/// `values[0]` of `testdata/phase1/keys/upstream-keys.rotated.json`.
const UPSTREAM_KEY: &str = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
const WRONG_KEY: &str = "wrong-upstream-key-marker-77aa";
const IP: &str = "198.51.100.77";
const IPV6: &str = "2001:db8:77:1::99";
const COOKIE: &str = "cookie-marker-5f2d";
const TLS_RANDOM: &str = "dGxzLXJhbmRvbS1tYXJrZXItMzItYnl0ZXMtbG9uZyE=";
const QUERY: &str = "query-marker-1a2b";

#[test]
fn logs_never_contain_client_secrets() {
    let env = TestEnv::new("logs");
    let mut b = blog_bundle(1);
    b.monitor_only = false;
    let c = b.challenge.as_mut().unwrap();
    c.pow_bits = Some(PowBits {
        low: 8,
        medium: 9,
        high: 10,
        very_high: 11,
    });
    b.environments[0].routes = vec![
        route("members", &["/members/**"], S::Medium, true, false),
        default_route(),
    ];
    env.write_lkg("blog", &sign(&b));

    // Failing outputs make the flusher log (a 400 from VictoriaLogs, a file
    // path that is a directory): those logs must not quote the lines.
    let vl = FakeVl::start().unwrap();
    vl.set_default_reply(VlReply::Status(400));
    let config = env.default_config("").replace(
        "profile = \"cloudflare\"\n",
        "profile = \"cloudflare\"\nupstream_keys = \"cred://mg-upstream-keys\"\n",
    );
    let config = with_events(
        &config,
        &format!(
            "vl_main = \"{}\"\nfile = \"{}\"\nflush_interval_ms = 50\n",
            vl.url(),
            env.dir.display()
        ),
    );
    let edge = env.spawn_logging(&env.write_config(&config), "trace");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);

    let secrets = |ip: &str, key: &str| {
        format!(
            "{}x-mg-upstream-key: {key}\r\nCookie: session={COOKIE}\r\nx-mg-cf-tls-random: {TLS_RANDOM}\r\n",
            browser(ip)
        )
    };
    // The challenge page (C, return path with a query).
    let path = format!("/members/a?reset={QUERY}");
    let r = get(env.listen, "example.com", &path, &secrets(IP, UPSTREAM_KEY));
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    let shown = from_page(&r.body);
    assert!(shown.ret.contains(QUERY));
    // The solved submission and its clearance cookie.
    let extra = format!("x-mg-upstream-key: {UPSTREAM_KEY}\r\n");
    let r = submit_form(env.listen, IP, &solved(&shown, challenge::CHROME), &extra);
    assert_eq!(r.status, 303, "{}\n{}", r.head, r.body);
    let clearance = cookie_of(&r);
    let token = clearance.split_once('=').unwrap().1.to_owned();
    // The cookie in use, and a failed submission (a replay).
    let r = get(
        env.listen,
        "example.com",
        "/members/a",
        &format!("{}Cookie: {clearance}\r\n", secrets(IP, UPSTREAM_KEY)),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let r = submit_form(env.listen, IP, &solved(&shown, challenge::CHROME), &extra);
    assert_ne!(r.status, 303);
    // A wrong upstream key, and an IPv6 client.
    let r = get(env.listen, "example.com", "/", &secrets(IP, WRONG_KEY));
    assert_eq!(r.status, 403);
    let r = get(
        env.listen,
        "example.com",
        "/v6",
        &secrets(IPV6, UPSTREAM_KEY),
    );
    assert_eq!(r.status, 200);

    // Wait until both failing outputs have logged.
    edge.wait_metric(
        "mg_event_dropped_total{class=\"priority\",sink=\"victorialogs\"}",
        10,
        |v| v >= 1.0,
    );
    edge.wait_metric(
        "mg_event_dropped_total{class=\"access\",sink=\"file\"}",
        10,
        |v| v >= 1.0,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let log = loop {
        let log = edge.log_text();
        if (log.contains("rejected a batch") && log.contains("file sink write failed"))
            || Instant::now() > deadline
        {
            break log;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Not vacuous: the requests and the output failures were logged.
    assert!(log.contains("request_id="), "{log}");
    assert!(log.contains("rejected a batch"), "{log}");
    assert!(log.contains("file sink write failed"), "{log}");
    for (what, secret) in [
        ("client IP", IP),
        ("IPv6 client", IPV6),
        ("IPv6 client", "2001:db8:77:1:"),
        ("cookie value", COOKIE),
        ("C", shown.c.as_str()),
        ("clearance token", token.as_str()),
        ("upstream key", UPSTREAM_KEY),
        ("wrong upstream key", WRONG_KEY),
        ("x-mg-cf-tls-random", TLS_RANDOM),
        ("query", QUERY),
    ] {
        assert!(
            !log.contains(secret),
            "{what} ({secret}) in the log:\n{log}"
        );
    }
}

/// D-31: a `redact_path` route exists because its paths carry one-time
/// tokens. When the origin fails, Pingora's error log line ends with
/// `request_summary`; for such a route it names `/<route>`, never the
/// tokenized path (the query is never logged at all).
#[test]
fn redacted_route_paths_stay_out_of_proxy_error_logs() {
    const TOKEN: &str = "reset-token-marker-9c1e";
    let env = TestEnv::new("logs-redact");
    let mut b = blog_bundle(1);
    let mut reset = route("reset", &["/reset/**"], S::Low, false, false);
    reset.redact_path = true;
    b.environments[0].routes = vec![reset, default_route()];
    env.write_lkg("blog", &sign(&b));
    // Nothing listens on the origin address: every forwarded request fails.
    let config = env
        .default_config("")
        .replace(&env.origin.addr.to_string(), &free_addr().to_string());
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    let r = get(
        env.listen,
        "example.com",
        &format!("/reset/{TOKEN}"),
        &cf("198.51.100.78"),
    );
    assert_eq!(r.status, 502, "{}", r.head);
    let deadline = Instant::now() + Duration::from_secs(5);
    let log = loop {
        let log = edge.log_text();
        if log.contains("Fail to proxy") || Instant::now() > deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let line = log
        .lines()
        .find(|l| l.contains("Fail to proxy"))
        .unwrap_or_else(|| panic!("no proxy error logged:\n{log}"));
    assert!(line.contains("GET /reset route="), "{line}");
    assert!(!log.contains(TOKEN), "tokenized path in the log:\n{log}");
}

/// Phase 2 spec §2.4 item 10 (`logs_never_contain_client_secrets`
/// extended): at `trace` level, a v2 submission (session key JWK and
/// signature), the clearance bound to its key and `MG-Proof` headers (valid,
/// replayed, from another key, malformed) leave none of the proof, the JWK
/// coordinates, the thumbprint, the signatures or the clearance in the log.
#[test]
fn logs_never_contain_proofs_keys_or_signatures() {
    use common::interactive::{cookie, from_page, post_json, submission};
    use mg_challenge::testkit::TestSessionKey;
    let env = TestEnv::new("logs-proof");
    let mut b = mg_edge_core::testkit::http::test_site_bundle_v2("blog", &common::HOSTS, 1);
    b.monitor_only = false;
    b.challenge.as_mut().unwrap().pow_bits = Some(PowBits {
        low: 8,
        medium: 8,
        high: 8,
        very_high: 8,
    });
    let mut api = route("api", &["/api/**"], S::Medium, false, false);
    api.channel = mg_proto::v1::Channel::Api as i32;
    api.proof = mg_proto::v1::ProofMode::Required as i32;
    b.environments[0].routes = vec![
        api,
        route("members", &["/members/**"], S::Medium, true, false),
        default_route(),
    ];
    env.write_lkg("blog", &sign(&b));
    let config = env.default_config("").replace(
        "[valkey]\nmode = \"local\"\n",
        "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
    );
    let edge = env.spawn_logging(&env.write_config(&config), "trace");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    std::thread::sleep(Duration::from_millis(1100));

    let key = TestSessionKey::from_label("logs-proof");
    let other = TestSessionKey::from_label("logs-proof-other");
    let r = get(env.listen, "example.com", "/members/x", &browser(IP));
    assert_eq!(r.status, 403);
    let s = from_page(&r.body);
    let sub = submission(&key, &s, "", "");
    let sig = sub["sig"].as_str().unwrap().to_owned();
    let r = post_json(&env, "/__mg/c", IP, challenge::CHROME, "", &sub);
    assert_eq!(r.status, 200, "{}", r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let token = clr.split_once('=').unwrap().1.to_owned();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let valid = key.proof("GET", "https://example.com/api/a", now + 5, &[1; 16]);
    let foreign = other.proof("GET", "https://example.com/api/a", now, &[2; 16]);
    for p in [valid.as_str(), valid.as_str(), foreign.as_str(), "x.y.z"] {
        let r = get(
            env.listen,
            "example.com",
            "/api/a",
            &format!("{}Cookie: {clr}\r\nMG-Proof: {p}\r\n", browser(IP)),
        );
        assert!(r.status == 200 || r.status == 403, "{}", r.head);
    }
    let log = edge.log_text();
    assert!(
        log.contains("proof=valid") && log.contains("proof=replay"),
        "{log}"
    );
    let proof_sig = valid.rsplit('.').next().unwrap().to_owned();
    for (what, secret) in [
        ("MG-Proof", valid.as_str()),
        ("MG-Proof signature", proof_sig.as_str()),
        ("foreign MG-Proof", foreign.as_str()),
        ("JWK x", key.x()),
        ("JWK y", key.y()),
        ("thumbprint", key.thumbprint().as_str()),
        ("other thumbprint", other.thumbprint().as_str()),
        ("submission signature", sig.as_str()),
        ("clearance token", token.as_str()),
        ("client IP", IP),
    ] {
        assert!(
            !log.contains(secret),
            "{what} ({secret}) in the log:\n{log}"
        );
    }
}
