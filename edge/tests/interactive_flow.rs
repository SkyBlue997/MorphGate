//! The interactive challenge through the real binary (docs/impl/phase2-spec.md
//! §7, §11, §12.2, §17 WP-E2a): the template v2 page and the JSON challenge
//! with `ix`, the first-binding renewal, the `self_hold` / single activation
//! / `pow_a11y` submissions, replay, splicing and tampering, cross-client
//! submissions, a concurrent double submission, a restart in local mode,
//! interactive challenges becoming unavailable mid-flight, the verify entry
//! with `min=interactive`, the manifest v1 directory, the `mg.js` alias and
//! the schema 1 behaviour. Loopback only; solutions come from mg-challenge's
//! test-only helpers (D-59).

mod common;

use common::challenge::CHROME;
use common::interactive::{
    BUILD, Shown, cookie, from_json, from_page, hold, json_body, post_json, renewal, set_cookies,
    submission, t_of, wait_min,
};
use common::{Edge, TestEnv, cf, fixture, get, sign};
use mg_challenge::testkit::TestSessionKey;
use mg_core::TokenLevel;
use mg_edge_core::testkit::http::test_site_bundle_v2;
use mg_proto::v1 as pb;
use serde_json::{Value, json};

const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";

fn route(name: &str, paths: &[&str], channel: pb::Channel, s: pb::RouteSensitivity) -> pb::Route {
    pb::Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: channel as i32,
        sensitivity: s as i32,
        ..Default::default()
    }
}

/// The interactive test site (enforce, schema 2): `login` (critical,
/// `fail_closed`, `min_level: interactive`), `members` (`min_level:
/// interactive`), `api` (channel api, `min_level: interactive`), `page`
/// (no requirement) and `default`; PoW v2 at 8 bits with 2 sub-puzzles,
/// `pow_a11y` at 12 bits, no minimum PoW or a11y time.
fn bundle(version: u64) -> pb::SiteBundle {
    let mut b = test_site_bundle_v2("blog", &common::HOSTS, version);
    b.monitor_only = false;
    let interactive = pb::ChallengeType::Interactive as i32;
    let mut login = route(
        "login",
        &["/account/login"],
        pb::Channel::Web,
        pb::RouteSensitivity::Critical,
    );
    login.fail_closed = true;
    login.min_level = interactive;
    let mut members = route(
        "members",
        &["/members/**"],
        pb::Channel::Web,
        pb::RouteSensitivity::Medium,
    );
    members.min_level = interactive;
    let mut api = route(
        "api",
        &["/api/**"],
        pb::Channel::Api,
        pb::RouteSensitivity::Medium,
    );
    api.min_level = interactive;
    b.environments[0].routes = vec![
        login,
        members,
        api,
        route(
            "page",
            &["/page"],
            pb::Channel::Web,
            pb::RouteSensitivity::Low,
        ),
        route(
            "default",
            &["/**"],
            pb::Channel::Web,
            pb::RouteSensitivity::Low,
        ),
    ];
    let c = b.challenge.as_mut().unwrap();
    c.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 8,
        high: 9,
        very_high: 9,
    });
    c.max_failures = 100;
    c.submit_rate = 1000;
    c.submit_burst = 1000;
    let ix = c.interactive.as_mut().unwrap();
    ix.enabled = true;
    ix.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 8,
        high: 8,
        very_high: 8,
    });
    ix.pow_k = 2;
    ix.a11y_bits = 12;
    ix.a11y_min_ms = 0;
    b
}

/// The config of `env`: local state with an authoritative local replay set
/// (the single-host shape, D-38).
fn config(env: &TestEnv, site_extra: &str) -> String {
    env.default_config(site_extra).replace(
        "[valkey]\nmode = \"local\"\n",
        "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
    )
}

fn start(env: &TestEnv, b: &pb::SiteBundle, site_extra: &str) -> Edge {
    env.publish("blog", &sign(b));
    let edge = env.spawn_logging(&env.write_config(&config(env, site_extra)), "mg_edge=debug");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| {
        v == b.version as f64
    });
    edge
}

/// Headers of a Chrome navigation from `ip` without `Accept-Language`.
fn navigation(ip: &str, ua: &str) -> String {
    format!(
        "{}User-Agent: {ua}\r\nAccept: text/html,application/xhtml+xml\r\nSec-Fetch-Mode: navigate\r\n",
        cf(ip)
    )
}

/// Headers of a fetch from `ip`.
fn fetch(ip: &str, extra: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: application/json\r\nSec-Fetch-Mode: cors\r\n{extra}",
        cf(ip)
    )
}

/// The challenge page of `path` for a navigation from `ip`.
fn page(env: &TestEnv, path: &str, ip: &str) -> (common::Response, Shown) {
    let r = get(env.listen, "example.com", path, &navigation(ip, CHROME));
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    let s = from_page(&r.body);
    (r, s)
}

/// The first-binding renewal of `s` (D-41): its renewed form.
fn bind(env: &TestEnv, key: &TestSessionKey, s: &Shown, ip: &str) -> Shown {
    let r = post_json(env, "/__mg/c/renew", ip, CHROME, "", &renewal(key, &s.c));
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let v = json_body(&r);
    assert_eq!(v["v"], 2);
    assert_eq!(v["ix"]["bound"], true);
    Shown {
        c: v["challenge"].as_str().unwrap().to_owned(),
        ix: Some(v["ix"].clone()),
        ..s.clone()
    }
}

fn token_claims(cookie: &str) -> mg_challenge::ClearanceClaims {
    let token = cookie.strip_prefix("__Host-mg_clr=").unwrap();
    let keys = std::fs::read(common::repo("testdata/phase1/keys/token.keys.json")).unwrap();
    let keys = mg_challenge::TokenKeySet::from_key_file(&keys, "blog", &["blog-t-20260927".into()])
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    mg_challenge::verify(&keys, "blog", "production", token, now).unwrap()
}

/// The debug line of the answer whose body carries a request id.
fn line_of(edge: &Edge, r: &common::Response) -> String {
    common::answered_log(edge, &r.body)
}

/// §7.1-§7.5: the template v2 page carries `ix` (no third party, `zh-CN`
/// by the bundle's default language); the SDK binds the `C` first; a
/// `self_hold` hold earns an `interactive` v2 token bound to the key and the
/// status cookie; the token passes the route; replaying the submission or
/// re-renewing the spent `C` gets nothing.
#[test]
fn self_hold_end_to_end() {
    let env = TestEnv::new("ix-hold");
    let edge = start(&env, &bundle(1), "");
    edge.wait_metric("mg_interactive_available{site=\"blog\"}", 5, |v| v == 1.0);
    let ip = "198.51.100.7";
    let (r, s) = page(&env, "/members/a?x=1", ip);
    assert_eq!(s.ty, "interactive");
    assert!(r.body.contains("<html lang=\"zh-CN\">"), "default_lang");
    assert!(r.body.contains("href=\"/\""));
    let csp = r.header("content-security-policy").unwrap();
    assert!(!csp.contains("cloudflare") && !r.body.contains("challenges.cloudflare.com"));
    let ix = s.ix.clone().unwrap();
    assert_eq!(ix["providers"], json!(["self_hold", "pow_a11y"]));
    assert_eq!(
        (ix["bound"].as_bool(), ix["attempt"].as_u64()),
        (Some(false), Some(1))
    );
    assert_eq!(s.ret, "/members/a?x=1");

    let key = TestSessionKey::from_label("browser-1");
    let bound = bind(&env, &key, &s, ip);
    // The unbound C is spent: renewing it again gives no second C.
    let r = post_json(&env, "/__mg/c/renew", ip, CHROME, "", &renewal(&key, &s.c));
    assert_eq!(r.status, 403);
    assert!(json_body(&r).get("challenge").is_none());
    assert_eq!(r.header("mg-error"), Some("mg_challenge_failed"));

    wait_min(&bound);
    let body = hold(&key, &bound);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &body);
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let v = json_body(&r);
    assert_eq!(
        (v["ok"].as_bool(), v["ret"].as_str(), v["v"].as_u64()),
        (Some(true), Some("/members/a?x=1"), Some(2))
    );
    let cookies = set_cookies(&r);
    assert!(cookies[0].starts_with("__Host-mg_clr="), "{cookies:?}");
    assert!(
        cookies[1].starts_with("__Host-mg_st=") && cookies[1].contains(".1; Max-Age="),
        "{cookies:?}"
    );
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let claims = token_claims(&clr);
    assert_eq!((claims.v, claims.lvl), (2, TokenLevel::Interactive));
    assert_eq!(claims.cnf_jkt(), Some(key.thumbprint().as_str()));

    // The token passes the interactive route.
    let r = get(
        env.listen,
        "example.com",
        "/members/a?x=1",
        &format!("{}Cookie: {clr}\r\n", navigation(ip, CHROME)),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    // Replay of the same submission: the nonce is spent.
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &body);
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.nonce_reused"));
    assert!(edge.metric("mg_challenge_renew_total{result=\"ok\"}") >= 1.0);
    assert!(
        edge.metric(
            "mg_challenge_total{provider=\"self_hold\",result=\"solved\",type=\"interactive\"}"
        ) >= 1.0
    );
}

/// D-65 single activation and the accessible PoW (`pow_a11y`, without
/// `ix`): `interactive` and `interactive_a11y`; the preference cookie puts
/// `pow_a11y` first on the next page.
#[test]
fn single_activation_and_pow_a11y() {
    let env = TestEnv::new("ix-a11y");
    let _edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.8";
    let key = TestSessionKey::from_label("browser-2");

    let (_, s) = page(&env, "/members/b", ip);
    let s = bind(&env, &key, &s, ip);
    wait_min(&s);
    let ms = s.ix.as_ref().unwrap()["hold_ms"].as_u64().unwrap();
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&key, &s, "self_hold", &t_of("single", ms)),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        token_claims(&cookie(&r, "__Host-mg_clr").unwrap()).lvl,
        TokenLevel::Interactive
    );

    let (_, s) = page(&env, "/members/c", ip);
    let s = bind(&env, &key, &s, ip);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&key, &s, "pow_a11y", ""),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        token_claims(&cookie(&r, "__Host-mg_clr").unwrap()).lvl,
        TokenLevel::InteractiveA11y
    );
    let pref = cookie(&r, "__Host-mg_a11y").unwrap();
    assert_eq!(pref, "__Host-mg_a11y=1");
    assert!(set_cookies(&r)[2].contains("HttpOnly; SameSite=Lax"));
    // The preference reorders the providers (§5.4 rule 6).
    let r = get(
        env.listen,
        "example.com",
        "/members/d",
        &format!("{}Cookie: {pref}\r\n", navigation(ip, CHROME)),
    );
    let s = from_page(&r.body);
    let ix = s.ix.unwrap();
    assert_eq!(ix["providers"], json!(["pow_a11y", "self_hold"]));
    assert_eq!(ix["a11y_first"], true);
}

/// Splicing, tampering and cross-client submissions (D-41): a bound `C`
/// refuses another key and another browser; a tampered `C` does not open;
/// counters of another `C` do not solve this one.
#[test]
fn replay_splice_tamper_and_cross_client() {
    let env = TestEnv::new("ix-cross");
    let edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.9";
    let (a, b) = (
        TestSessionKey::from_label("a"),
        TestSessionKey::from_label("b"),
    );
    let (_, s1) = page(&env, "/members/1", ip);
    let s1 = bind(&env, &a, &s1, ip);
    let (_, s2) = page(&env, "/members/2", ip);
    let s2 = bind(&env, &a, &s2, ip);
    wait_min(&s1);

    // Another key.
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&b, &s1));
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.bind_jkt"));
    // Another browser (UA family).
    let r = post_json(&env, "/__mg/c", ip, FIREFOX, "", &hold(&a, &s1));
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.bind_uah"));
    // A tampered C.
    let mut tampered = s1.clone();
    let mut chars: Vec<char> = tampered.c.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    tampered.c = chars.into_iter().collect();
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&a, &tampered));
    assert!(line_of(&edge, &r).contains("reasons=ic.c_invalid"));
    // Spliced: the counters of s2 on s1 (signed correctly by the key).
    let mut spliced = hold(&a, &s2);
    let counters: Vec<u64> = serde_json::from_value(spliced["pow"]["counters"].clone()).unwrap();
    let t = spliced["t"].as_str().unwrap().to_owned();
    spliced["c"] = json!(s1.c);
    spliced["sig"] = json!(a.sign_submission(&mg_challenge::SubmissionFields {
        c: &s1.c,
        ty: "interactive",
        p: "self_hold",
        pp: "",
        t: &t,
        counters: &counters,
        ret: &s1.ret,
        ts: 1_790_000_000_123,
        build: BUILD,
    }));
    spliced["ret"] = json!(s1.ret);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &spliced);
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.pow"));
    // The genuine submission still works: nothing above consumed s1.
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&a, &s1));
    assert_eq!(r.status, 200, "{}", r.body);
}

/// Two simultaneous submissions of one solved `C`: exactly one is issued a
/// token (the nonce is consumed atomically).
#[test]
fn concurrent_double_submission() {
    let env = TestEnv::new("ix-double");
    let _edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.10";
    let key = TestSessionKey::from_label("c");
    let (_, s) = page(&env, "/members/x", ip);
    let s = bind(&env, &key, &s, ip);
    wait_min(&s);
    let body = hold(&key, &s);
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| post_json(&env, "/__mg/c", ip, CHROME, "", &body).status))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 403).count(),
        3,
        "{statuses:?}"
    );
}

/// D-38 / §7.10: in local mode a `C` issued before a restart is "replay
/// store unavailable": its renewal is 429, its submission is 429 on a
/// `fail_closed` route and earns a token with `ruc` elsewhere.
#[test]
fn restart_in_local_mode() {
    let env = TestEnv::new("ix-restart");
    let b = bundle(1);
    let key = TestSessionKey::from_label("d");
    let ip = "198.51.100.11";
    let edge = start(&env, &b, "");
    let (_, login) = page(&env, "/account/login", ip);
    let login = bind(&env, &key, &login, ip);
    let (_, members) = page(&env, "/members/r", ip);
    let members = bind(&env, &key, &members, ip);
    let (_, spare) = page(&env, "/members/s", ip);
    drop(edge);
    let edge = start(&env, &b, "");
    let r = post_json(
        &env,
        "/__mg/c/renew",
        ip,
        CHROME,
        "",
        &renewal(&key, &spare.c),
    );
    assert_eq!(
        (r.status, r.header("retry-after")),
        (429, Some("5")),
        "{}",
        r.body
    );
    wait_min(&login);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&key, &login));
    assert_eq!(r.status, 429, "{}", r.body);
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));
    wait_min(&members);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&key, &members));
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(token_claims(&cookie(&r, "__Host-mg_clr").unwrap()).ruc);
}

/// §5.1: interactive challenges switched off mid-flight: the renewal and
/// the submission of an interactive `C` fail (not counted) with a `pow`
/// `C`, and new decisions are `pow` again (D-08).
#[test]
fn interactive_becomes_unavailable() {
    let env = TestEnv::new("ix-off");
    let edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.12";
    let key = TestSessionKey::from_label("e");
    let (_, s) = page(&env, "/members/o", ip);
    let s = bind(&env, &key, &s, ip);
    let (_, unbound) = page(&env, "/members/p", ip);
    let mut off = bundle(2);
    off.challenge
        .as_mut()
        .unwrap()
        .interactive
        .as_mut()
        .unwrap()
        .enabled = false;
    env.publish("blog", &sign(&off));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 2.0);
    assert_eq!(edge.metric("mg_interactive_available{site=\"blog\"}"), 0.0);
    let r = post_json(
        &env,
        "/__mg/c/renew",
        ip,
        CHROME,
        "",
        &renewal(&key, &unbound.c),
    );
    assert_eq!(r.status, 403);
    assert_eq!(json_body(&r)["type"], "pow");
    wait_min(&s);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&key, &s));
    assert_eq!(r.status, 403);
    assert_eq!(json_body(&r)["type"], "pow");
    assert!(line_of(&edge, &r).contains("reasons=ic.interactive_unavailable"));
    let (_, s) = page(&env, "/members/q", ip);
    assert_eq!(s.ty, "pow");
    // The pow C clears the interactive route now (effective min_level, §5.2).
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
        "/members/q",
        &format!("{}Cookie: {clr}\r\n", navigation(ip, CHROME)),
    );
    assert_eq!(r.status, 200);
}

/// D-58 / §7.10: an API route requires `interactive` while the page does
/// not; the JSON challenge says `interactive` with `ix`; the verify entry
/// with `min=interactive` issues an interactive page for the page's path,
/// and its token passes the API route. Without `min` it issues `pow`.
#[test]
fn verify_entry_with_min_interactive() {
    let env = TestEnv::new("ix-verify");
    let _edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.13";
    let key = TestSessionKey::from_label("f");
    let r = get(env.listen, "example.com", "/api/data", &fetch(ip, ""));
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(r.header("mg-challenge"), Some("interactive"));
    assert_eq!(r.header("mg-error"), Some("mg_challenge"));
    let v = json_body(&r);
    assert_eq!(
        (v["v"].as_u64(), v["type"].as_str()),
        (Some(2), Some("interactive"))
    );
    assert!(v["ix"].is_object() && v.get("pow").is_none());
    let _ = from_json(&v);

    let (_, plain) = page(&env, "/__mg/v?ret=/page", ip);
    assert_eq!(plain.ty, "pow");
    for query in [
        "ret=/page&min=pow",
        "ret=/page&min=interactive&min=interactive",
    ] {
        let (_, s) = page(&env, &format!("/__mg/v?{query}"), ip);
        assert_eq!(s.ty, "pow", "{query}: ignored");
    }
    let (_, s) = page(&env, "/__mg/v?ret=/page&min=interactive", ip);
    assert_eq!((s.ty.as_str(), s.ret.as_str()), ("interactive", "/page"));
    let s = bind(&env, &key, &s, ip);
    wait_min(&s);
    let r = post_json(&env, "/__mg/c", ip, CHROME, "", &hold(&key, &s));
    assert_eq!(r.status, 200, "{}", r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let r = get(
        env.listen,
        "example.com",
        "/api/data",
        &fetch(ip, &format!("Cookie: {clr}\r\n")),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    // The verify entry never issues less than the clearance held (D-58).
    let r = get(
        env.listen,
        "example.com",
        "/__mg/v?ret=/page",
        &format!("{}Cookie: {clr}\r\n", navigation(ip, CHROME)),
    );
    assert_eq!(from_page(&r.body).ty, "interactive");
}

/// §12.2: a manifest v1 directory still works (template v1, no interactive
/// challenge: `interactive` runs as `pow`, `mg_interactive_available` 0);
/// the alias serves it too.
#[test]
fn manifest_v1_directory() {
    let env = TestEnv::new("ix-sdkv1");
    let config = config(&env, "").replace(
        &fixture("sdk").display().to_string(),
        &fixture("sdk-v1").display().to_string(),
    );
    env.publish("blog", &sign(&bundle(1)));
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 1.0);
    assert_eq!(edge.metric("mg_interactive_available{site=\"blog\"}"), 0.0);
    let ip = "198.51.100.14";
    let r = get(
        env.listen,
        "example.com",
        "/members/v1",
        &navigation(ip, CHROME),
    );
    assert_eq!(r.status, 403);
    assert!(!r.body.contains("data-mg-ix"), "template v1");
    assert_eq!(
        common::interactive::main_attr(&r.body, "data-mg-type"),
        "pow"
    );
    let r = get(env.listen, "example.com", "/__mg/s/mg.js", "");
    assert_eq!(r.status, 200);
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("sdk-v1/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        r.header("etag"),
        Some(format!("\"{}\"", manifest["build"].as_str().unwrap()).as_str())
    );
}

/// D-39 / §11.1: `/__mg/s/mg.js` is the SDK file of the build, cached 300 s,
/// with `ETag` and 304; the query string is ignored. A manifest listing
/// `mg.js` is refused at start-up.
#[test]
fn sdk_alias() {
    let env = TestEnv::new("ix-alias");
    let edge = start(&env, &bundle(1), "");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("sdk/manifest.json")).unwrap())
            .unwrap();
    let file = manifest["sdk"].as_str().unwrap();
    let bytes = std::fs::read(fixture("sdk").join(file)).unwrap();
    let etag = format!("\"{}\"", manifest["build"].as_str().unwrap());
    for path in ["/__mg/s/mg.js", "/__mg/s/mg.js?sv=0.3.0"] {
        let r = get(env.listen, "example.com", path, "");
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.body.as_bytes(), bytes.as_slice());
        assert_eq!(r.header("cache-control"), Some("public, max-age=300"));
        assert_eq!(r.header("etag"), Some(etag.as_str()));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    }
    for inm in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"x\", {etag}"),
        "*".into(),
    ] {
        let r = get(
            env.listen,
            "example.com",
            "/__mg/s/mg.js",
            &format!("If-None-Match: {inm}\r\n"),
        );
        assert_eq!(r.status, 304, "{inm}");
        assert!(r.body.is_empty());
        assert_eq!(r.header("etag"), Some(etag.as_str()));
    }
    let r = get(
        env.listen,
        "example.com",
        "/__mg/s/mg.js",
        "If-None-Match: \"other\"\r\n",
    );
    assert_eq!(r.status, 200);
    let r = get(env.listen, "example.com", &format!("/__mg/s/{file}"), "");
    assert_eq!(
        r.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    drop(edge);

    // A manifest that lists mg.js: --check-config fails.
    let dir = env.dir.join("sdk-alias");
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["challenge.html", file] {
        std::fs::copy(fixture("sdk").join(f), dir.join(f)).unwrap();
    }
    std::fs::copy(fixture("sdk").join(file), dir.join("mg.js")).unwrap();
    let mut m = manifest.clone();
    m["files"]["mg.js"] = m["files"][file].clone();
    std::fs::write(dir.join("manifest.json"), m.to_string()).unwrap();
    let config = config(&env, "").replace(
        &fixture("sdk").display().to_string(),
        &dir.display().to_string(),
    );
    let out = env.check(&env.write_config(&config));
    assert!(!out.status.success());
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("mg.js"), "{text}");
}

/// §11.1 / D-66: `/__mg/c/renew` is 404 for a schema 1 bundle, 405 for
/// other methods and 425 with `Early-Data` (JSON); a v2 submission under a
/// schema 1 bundle earns a v1 token without the status cookie.
#[test]
fn renew_endpoint_answers_and_schema_1() {
    let env = TestEnv::new("ix-schema");
    let edge = start(&env, &bundle(1), "");
    let ip = "198.51.100.15";
    let r = get(env.listen, "example.com", "/__mg/c/renew", &fetch(ip, ""));
    assert_eq!((r.status, r.header("allow")), (405, Some("POST")));
    let key = TestSessionKey::from_label("g");
    let (_, s) = page(&env, "/members/e", ip);
    let r = post_json(
        &env,
        "/__mg/c/renew",
        ip,
        CHROME,
        "Early-Data: 1\r\n",
        &renewal(&key, &s.c),
    );
    assert_eq!(r.status, 425);
    assert_eq!(json_body(&r)["error"], "mg_too_early");
    drop(edge);

    let env = TestEnv::new("ix-schema1");
    let mut b = common::blog_bundle(1);
    b.monitor_only = false;
    b.environments[0].routes[0].require_clearance = true;
    let _edge = start(&env, &b, "");
    let r = post_json(
        &env,
        "/__mg/c/renew",
        ip,
        CHROME,
        "",
        &renewal(&key, "AAAA"),
    );
    assert_eq!(r.status, 404);
    let (_, s) = page(&env, "/x", ip);
    assert_eq!(s.ty, "invisible");
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &submission(&key, &s, "", ""),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(set_cookies(&r).len(), 1, "no __Host-mg_st in schema 1");
    let claims = token_claims(&cookie(&r, "__Host-mg_clr").unwrap());
    assert_eq!(claims.v, 1);
    assert!(claims.cnf.is_none());
}

/// §5.1 / §10.1: `--check-config` warns when the LKG enables interactive
/// challenges with a manifest v1 SDK directory, and in local mode (with a
/// small nonce set).
#[test]
fn check_config_warns_about_interactive_challenges() {
    let env = TestEnv::new("ix-check");
    env.write_lkg("blog", &sign(&bundle(1)));
    let config = env.default_config("").replace(
        &fixture("sdk").display().to_string(),
        &fixture("sdk-v1").display().to_string(),
    );
    let out = env.check(&env.write_config(&config));
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("enables interactive challenges but [sdk] dir is a manifest v1 directory"),
        "{text}"
    );
    assert!(
        text.contains("interactive challenges in [valkey] mode = \"local\""),
        "{text}"
    );
    assert!(
        text.contains("local_nonce_capacity = 200000 is below 400000"),
        "{text}"
    );
    // A v2 directory and a large enough set: only the local-mode warning.
    let config = env.default_config("").replace(
        "[valkey]\nmode = \"local\"\n",
        "[valkey]\nmode = \"local\"\nlocal_nonce_capacity = 400000\n",
    );
    let out = env.check(&env.write_config(&config));
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("manifest v1") && !text.contains("is below 400000"),
        "{text}"
    );
    assert!(text.contains("mode = \"local\""), "{text}");
}
