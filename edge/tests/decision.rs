//! Decisions end to end through the real binary (docs/impl/phase1-spec.md
//! §9.5-§9.9, §15 WP-E1b `decision.rs`): the detectors' inputs arrive, a
//! rule reading a MISSING field records `missing_input`, monitor only
//! records, and under enforce the Edge answers BLOCK (403), RATE_LIMIT
//! (429), a `fail_closed` route without a client IP (429), `Early-Data` on a
//! critical route (425), and forwards a request with a valid clearance
//! (`MG-Session`). Loopback only; local state mode.

mod common;

use common::policy::{default_route, eq, field, glob, limiter, route, rule, string};
use common::{Edge, TestEnv, answered_log, blog_bundle, cf, get, origin_log, sign};
use mg_challenge::{ClearanceBind, MintParams, TokenKeySet};
use mg_core::{Net, RiskBand, TokenLevel};
use mg_proto::v1::{Action, RouteSensitivity as S, SiteBundle};

const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Headers of a real Chrome navigation (keeps the score low).
fn browser(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html,application/xhtml+xml\r\n\
         Accept-Language: zh-CN,zh;q=0.9\r\nSec-Fetch-Mode: navigate\r\n\
         Sec-CH-UA: \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"\r\n",
        cf(ip)
    )
}

/// Headers of a script on a page of the site (fetch / XHR): not a
/// navigation, so the Edge answers JSON.
fn api_client(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: application/json\r\n\
         Accept-Language: zh-CN,zh;q=0.9\r\nSec-Fetch-Mode: cors\r\n\
         Sec-CH-UA: \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"\r\n",
        cf(ip)
    )
}

fn bundle(monitor: bool) -> SiteBundle {
    let mut b = blog_bundle(1);
    b.monitor_only = monitor;
    b.origin_headers.as_mut().unwrap().reasons = true;
    let env = &mut b.environments[0];
    env.routes = vec![
        route("login", &["/account/login"], S::Critical, true, true),
        route("checkout", &["/checkout"], S::Critical, false, false),
        route("members", &["/members/**"], S::Medium, true, false),
        route("admin", &["/admin/**"], S::High, false, false),
        route("api", &["/api/**"], S::Medium, false, false),
        default_route(),
    ];
    env.rules = vec![
        rule(
            "allow-checkout",
            "identity",
            Action::Allow,
            eq(field("route.name"), string("checkout")),
            &[],
        ),
        rule(
            "tls-version-gate",
            "bot",
            Action::Block,
            eq(field("tls.version"), string("TLSv1")),
            &[],
        ),
        rule(
            "block-admin",
            "custom",
            Action::Block,
            eq(field("route.name"), string("admin")),
            &[],
        ),
        rule(
            "tag-tagged",
            "custom",
            Action::Tag,
            glob(field("req.path"), "/tagged/**"),
            &[("label", "tagged_path")],
        ),
    ];
    env.rate_limits = vec![limiter(
        "api-per-ip",
        &["api"],
        &["ip"],
        (1, 60, 1),
        "rate_limit",
        30,
    )];
    b
}

fn start(env: &TestEnv, b: &SiteBundle) -> Edge {
    env.write_lkg("blog", &sign(b));
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge
}

/// Monitor: every decision is evaluated and recorded (`dry_run=true`) and
/// the request is forwarded with the decision headers.
#[test]
fn monitor_evaluates_and_only_records() {
    let env = TestEnv::new("dec-monitor");
    let edge = start(&env, &bundle(true));

    // A BLOCK rule matches: forwarded, recorded.
    let r = get(
        env.listen,
        "example.com",
        "/admin/x",
        &browser("198.51.100.20"),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let line = origin_log(&env, &edge, "/admin/x");
    assert!(line.contains(" route=admin "), "{line}");
    assert!(
        line.contains(" rule=block-admin action=block dry_run=true "),
        "{line}"
    );
    assert!(line.contains("enforcement=Forward"), "{line}");
    // §5.3 MISSING: tls.version is MISSING under cloudflare, so the bot
    // rule reading it records missing_input and does not match.
    assert!(line.contains("tls-version-gate:missing_input"), "{line}");
    let seen = env.origin.last("/admin/x").unwrap();
    assert!(seen.header("mg-bot-score").is_some());
    assert!(seen.header("mg-bot-class").is_some());

    // The rate limiter counts under monitor too; the second request is
    // recorded as the limiter's decision and still forwarded.
    for i in 0..2 {
        let path = format!("/api/m{i}");
        let r = get(env.listen, "example.com", &path, &browser("203.0.113.30"));
        assert_eq!(r.status, 200);
        let line = origin_log(&env, &edge, &path);
        if i == 1 {
            assert!(
                line.contains(" rule=ratelimit.api-per-ip action=rate_limit dry_run=true "),
                "{line}"
            );
        }
    }
    assert_eq!(
        edge.metric("mg_ratelimit_exceeded_total{limiter=\"api-per-ip\"}"),
        1.0
    );

    // Detector inputs arrive: an HTTP library, a browser navigation without
    // Accept-Language.
    let r = get(
        env.listen,
        "example.com",
        "/curl",
        &format!("{}User-Agent: curl/8.5.0\r\n", cf("198.51.100.21")),
    );
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/curl").unwrap();
    assert!(
        seen.header("mg-reasons")
            .unwrap()
            .contains("http.ua_library"),
        "{:?}",
        seen.headers
    );
    let r = get(
        env.listen,
        "example.com",
        "/nav",
        &format!(
            "{}User-Agent: {CHROME}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n",
            cf("198.51.100.22")
        ),
    );
    assert_eq!(r.status, 200);
    let reasons = env
        .origin
        .last("/nav")
        .unwrap()
        .header("mg-reasons")
        .unwrap()
        .to_owned();
    assert!(
        reasons.contains("http.accept_language_missing"),
        "{reasons}"
    );
    assert!(reasons.contains("http.client_hints"), "{reasons}");

    // fail_closed + unknown client IP is recorded as hard.client_ip_unknown.
    let r = get(env.listen, "example.com", "/account/login", "");
    assert_eq!(r.status, 200);
    let line = origin_log(&env, &edge, "/account/login");
    assert!(
        line.contains(" rule=hard.client_ip_unknown action=rate_limit dry_run=true "),
        "{line}"
    );
    assert_eq!(
        env.origin
            .last("/account/login")
            .unwrap()
            .header("mg-client-ip"),
        Some("unknown")
    );
}

/// Enforce: BLOCK and RATE_LIMIT answers (§9.9), JSON or HTML by request
/// kind, never reaching the origin.
#[test]
fn enforce_blocks_and_rate_limits() {
    let env = TestEnv::new("dec-enforce");
    let edge = start(&env, &bundle(false));

    let json = format!("{}Accept: application/json\r\n", cf("198.51.100.40"));
    let r = get(env.listen, "example.com", "/admin/x", &json);
    assert_eq!(r.status, 403, "{}", r.head);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("cache-control"), Some("no-store, private"));
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["error"], "mg_blocked");
    let line = answered_log(&edge, &r.body);
    assert!(
        line.contains(" rule=block-admin action=block dry_run=false "),
        "{line}"
    );
    assert!(line.contains("enforcement=Block"), "{line}");

    let r = get(
        env.listen,
        "example.com",
        "/admin/y",
        &browser("198.51.100.41"),
    );
    assert_eq!(r.status, 403);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert!(r.body.contains("如有疑问请联系站点所有者"), "{}", r.body);
    assert!(!r.has_header_prefix("mg-"), "{}", r.head);

    // The limiter: the second request of one client is 429 + Retry-After.
    let client = api_client("198.51.100.44");
    let r = get(env.listen, "example.com", "/api/1", &client);
    assert_eq!(r.status, 200, "{}", r.head);
    let r = get(env.listen, "example.com", "/api/2", &client);
    assert_eq!(r.status, 429, "{}", r.head);
    assert_eq!(r.header("retry-after"), Some("30"));
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["error"], "mg_rate_limited");
    assert_eq!(v["retry_after"], 30);
    let line = answered_log(&edge, &r.body);
    assert!(
        line.contains(" rule=ratelimit.api-per-ip action=rate_limit "),
        "{line}"
    );
    // Another client has its own bucket.
    let other = api_client("198.51.100.42");
    assert_eq!(get(env.listen, "example.com", "/api/3", &other).status, 200);

    // Nothing that was answered by the Edge reached the origin.
    for path in ["/admin/x", "/admin/y", "/api/2"] {
        assert!(env.origin.last(path).is_none(), "{path} reached the origin");
    }

    // A TAG rule forwards with MG-Tags.
    let r = get(
        env.listen,
        "example.com",
        "/tagged/a",
        &browser("198.51.100.43"),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/tagged/a").unwrap();
    assert_eq!(
        seen.header("mg-tags"),
        Some("tagged_path"),
        "{:?}",
        seen.headers
    );
}

/// §9.3.2 / §9.9: without a client IP the Edge is never more permissive:
/// a fail_closed route is 429 (Retry-After 5), a challenge is 429 without
/// a `C`. `Early-Data` on a critical route is 425.
#[test]
fn unknown_client_ip_and_early_data() {
    let env = TestEnv::new("dec-ipunknown");
    let edge = start(&env, &bundle(false));

    let r = get(
        env.listen,
        "example.com",
        "/account/login",
        "Accept: text/html\r\n",
    );
    assert_eq!(r.status, 429, "{}", r.head);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(r.body.contains("请求过多"));
    let line = answered_log(&edge, &r.body);
    assert!(line.contains(" rule=hard.client_ip_unknown "), "{line}");

    // require_clearance (not fail_closed): a challenge, which needs an IP.
    let r = get(
        env.listen,
        "example.com",
        "/members/a",
        "Accept: application/json\r\n",
    );
    assert_eq!(r.status, 429, "{}", r.head);
    assert_eq!(r.header("retry-after"), Some("5"));
    let line = answered_log(&edge, &r.body);
    assert!(
        line.contains(" rule=matrix.clearance.required action=challenge "),
        "{line}"
    );
    assert!(
        line.contains("enforcement=ChallengeClientIpUnknown"),
        "{line}"
    );

    // With a client IP the challenge is issued (403 with a sealed C,
    // WP-E1c; the whole flow is in challenge_flow.rs).
    let r = get(
        env.listen,
        "example.com",
        "/members/a",
        &format!("{}Accept: application/json\r\n", cf("198.51.100.50")),
    );
    assert_eq!(r.status, 403, "{}", r.head);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["error"], "mg_challenge");
    assert!(
        v["challenge"].as_str().is_some_and(|c| !c.is_empty()),
        "{v}"
    );

    // Early-Data on a critical route that would be forwarded: 425.
    let r = get(
        env.listen,
        "example.com",
        "/checkout",
        &format!("{}Early-Data: 1\r\n", browser("198.51.100.51")),
    );
    assert_eq!(r.status, 425, "{}", r.head);
    let r = get(
        env.listen,
        "example.com",
        "/checkout",
        &browser("198.51.100.51"),
    );
    assert_eq!(r.status, 200, "{}", r.head);
}

fn token(ua: &str, ip: &str, lvl: TokenLevel) -> String {
    let json = std::fs::read(common::repo("testdata/phase1/keys/token.keys.json")).unwrap();
    let keys = TokenKeySet::from_key_file(&json, "blog", &["blog-t-20260927".into()]).unwrap();
    let ua = mg_core::ua::parse(ua);
    let bind = mg_challenge::BindInputs {
        uah: mg_challenge::uah(ua.family, ua.major),
        ipp: Some(mg_challenge::ipp(&Net::prefix_of(ip.parse().unwrap()))),
        ipa: None,
        ctp: None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let p = MintParams {
        env: "production",
        session: None,
        lvl,
        now_s: now,
        ttl_s: 1800,
        bind: ClearanceBind::from_inputs(&bind).unwrap(),
        rb: RiskBand::Low,
        replay_unchecked: false,
    };
    mg_challenge::mint(&keys, "blog", &p, &mg_edge::rng::OsRng)
        .unwrap()
        .0
}

/// §9.6: a valid clearance satisfies `require_clearance` and forwards the
/// session; a token bound to another browser or prefix does not.
#[test]
fn clearance_cookie_is_verified() {
    let env = TestEnv::new("dec-clearance");
    let edge = start(&env, &bundle(false));
    let ip = "198.51.100.60";
    let t = token(CHROME, ip, TokenLevel::Pow);
    let cookie = format!("Cookie: theme=dark; {}={t}\r\n", mg_challenge::COOKIE_NAME);

    let r = get(
        env.listen,
        "example.com",
        "/members/home",
        &format!("{}{cookie}", browser(ip)),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/members/home").unwrap();
    let session = seen.header("mg-session").expect("MG-Session");
    assert_eq!(session.len(), 22);
    let line = origin_log(&env, &edge, "/members/home");
    assert!(line.contains(" token=valid "), "{line}");

    // Another /24 without an ASN binding: hard ipp mismatch.
    let r = get(
        env.listen,
        "example.com",
        "/members/moved",
        &format!("{}{cookie}Accept: application/json\r\n", cf("203.0.113.61")),
    );
    assert_eq!(r.status, 403, "{}", r.head);
    let line = answered_log(&edge, &r.body);
    assert!(line.contains(" token=binding_mismatch "), "{line}");

    // No cookie: challenged.
    let r = get(
        env.listen,
        "example.com",
        "/members/anon",
        &format!("{}Accept: application/json\r\n", cf(ip)),
    );
    assert_eq!(r.status, 403);
    let line = answered_log(&edge, &r.body);
    assert!(line.contains(" token=none "), "{line}");

    let m = edge.metrics_text();
    for result in ["valid", "binding_mismatch", "none"] {
        let v =
            common::metric_or_zero(&m, &format!("mg_token_verify_total{{result=\"{result}\"}}"));
        assert!(v >= 1.0, "{result}: {m}");
    }
}
