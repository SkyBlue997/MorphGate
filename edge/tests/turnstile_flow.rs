//! Turnstile through the real binary (docs/impl/phase2-spec.md §5.4, §8,
//! §10.1, §17 WP-E2c): `--check-config` with and without the
//! `turnstile_keys` credential (valid, malformed, another site's), the
//! `[outbound]` URL and `MG_EDGE_TEST_OUTBOUND`, `disabled(no_secret)` at
//! run time, and the whole flow against WP-C6's loopback mock siteverify:
//! the challenge page's CSP and `ix.turnstile`, the countries of D-70, the
//! routes and hosts that never offer it, the first-binding renewal, a
//! passing submission earning `interactive_ext:turnstile`, and a rejected
//! secret disabling the provider. Nothing reaches any host but loopback
//! (D-52).

mod common;

use common::challenge::CHROME;
use common::interactive::{Shown, cookie, from_json, from_page, json_body, post_json, renewal};
use common::{Edge, TestEnv, cf, get, repo, sign};
use mg_challenge::testkit::TestSessionKey;
use mg_challenge::{SubmissionFields, pow_solve_v2};
use mg_edge_core::testkit::http::test_site_bundle_v2;
use mg_edge_core::testkit::siteverify::{FakeSiteverify, SvReply};
use mg_proto::v1 as pb;
use serde_json::{Value, json};

/// `t` of a Turnstile submission (§7.6 `external`).
const EXTERNAL_T: &str = r#"{"ix":{"v":1,"mode":"external","modality":"mouse","locale":"zh-CN","ks":"idb","sv":"0.3.0","fallback":null,"trusted":3,"act_ms":1500}}"#;
const BUILD: &str = "1df90640e0c5fec4";
const KEYS_CRED: &str = "mg-turnstile-keys-blog";

fn route(name: &str, paths: &[&str]) -> pb::Route {
    pb::Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: pb::Channel::Web as i32,
        sensitivity: pb::RouteSensitivity::Medium as i32,
        min_level: pb::ChallengeType::Interactive as i32,
        ..Default::default()
    }
}

/// The interactive test site with Turnstile (`enforce`, `first`, widget
/// hosts example.com and www.example.com): `members` and the redacting
/// `reset` require interactive, location headers are trusted.
fn bundle(version: u64, denied: &[&str]) -> pb::SiteBundle {
    let mut b = test_site_bundle_v2("blog", &common::HOSTS, version);
    b.monitor_only = false;
    let mut reset = route("reset", &["/reset/**"]);
    reset.redact_path = true;
    let mut default = route("default", &["/**"]);
    default.min_level = 0;
    default.sensitivity = pb::RouteSensitivity::Low as i32;
    b.environments[0].routes = vec![route("members", &["/members/**"]), reset, default];
    b.cloudflare.as_mut().unwrap().location_headers = true;
    let c = b.challenge.as_mut().unwrap();
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
    b.providers = vec![pb::ProviderConfig {
        id: "turnstile".into(),
        enabled: true,
        sitekey: "0x4AAAAAAAtest-sitekey".into(),
        denied_countries: denied.iter().map(|c| (*c).to_string()).collect(),
        timeout_ms: 3_000,
        fallback: "self_hold".into(),
        mode: "enforce".into(),
        hostnames: vec!["example.com".into(), "www.example.com".into()],
        selection: "first".into(),
        ..Default::default()
    }];
    b
}

/// Copies a `testdata/phase2/samples/keys` file into the credentials
/// directory as `name`.
fn install_keys(env: &TestEnv, sample: &str, name: &str) {
    std::fs::copy(
        repo("testdata/phase2/samples/keys").join(sample),
        env.creds.join(name),
    )
    .unwrap();
}

/// The config of `env`: local state with an authoritative replay set,
/// `site_extra` in `[[sites]]`, and `outbound` as the `[outbound]` URL.
fn config(env: &TestEnv, site_extra: &str, outbound: Option<&str>) -> String {
    let mut text = env.default_config(site_extra).replace(
        "[valkey]\nmode = \"local\"\n",
        "[valkey]\nmode = \"local\"\nlocal_replay_authoritative = true\n",
    );
    if let Some(url) = outbound {
        text.push_str(&format!(
            "\n[outbound]\nturnstile_siteverify_url = \"{url}\"\n"
        ));
    }
    text
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// §8.2, §8.4, §8.7, §10.1: what `--check-config` accepts and refuses.
#[test]
fn check_config_rules() {
    let env = TestEnv::new("ts-check");
    env.write_lkg("blog", &sign(&bundle(1, &[])));
    let keys = format!("turnstile_keys = \"cred://{KEYS_CRED}\"");

    // The bundle enables Turnstile, edge.toml has no credential.
    let out = env.check(&env.write_config(&config(&env, "", None)));
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("turnstile_keys is not set"),
        "{}",
        stderr(&out)
    );

    // A valid file: OK, with the privacy warning.
    install_keys(&env, "valid/two-values.json", KEYS_CRED);
    let out = env.check(&env.write_config(&config(&env, &keys, None)));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Turnstile is enabled"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("0x4AAAAAAAkat-test-secret"));

    // Malformed files and another site's file.
    for sample in [
        "invalid/unknown-field.json",
        "invalid/three-values.json",
        "invalid/value-with-space.json",
        "invalid/duplicate-key.json",
        "invalid/site-mismatch.json",
    ] {
        install_keys(&env, sample, KEYS_CRED);
        let out = env.check(&env.write_config(&config(&env, &keys, None)));
        assert_eq!(out.status.code(), Some(2), "{sample}: {}", stderr(&out));
        assert!(stderr(&out).contains("turnstile_keys"), "{sample}");
    }
    // A missing file.
    let out = env.check(&env.write_config(&config(
        &env,
        "turnstile_keys = \"cred://mg-turnstile-keys-missing\"",
        None,
    )));
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    install_keys(&env, "valid/one-value.json", KEYS_CRED);

    // [outbound]: a loopback URL only with MG_EDGE_TEST_OUTBOUND=1.
    let loopback = config(
        &env,
        &keys,
        Some("http://127.0.0.1:19999/turnstile/v0/siteverify"),
    );
    let path = env.write_config(&loopback);
    let out = env.check(&path);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("MG_EDGE_TEST_OUTBOUND"),
        "{}",
        stderr(&out)
    );
    let out = env.check_env(&path, &[("MG_EDGE_TEST_OUTBOUND", "true")]);
    assert_eq!(out.status.code(), Some(2), "only exactly 1");
    let out = env.check_env(&path, &[("MG_EDGE_TEST_OUTBOUND", "1")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("loopback test destination"),
        "{}",
        stderr(&out)
    );
    // Never anything but loopback, whatever the environment says.
    for url in [
        "http://192.0.2.1:80/x",
        "https://example.com/turnstile/v0/siteverify",
    ] {
        let path = env.write_config(&config(&env, &keys, Some(url)));
        let out = env.check_env(&path, &[("MG_EDGE_TEST_OUTBOUND", "1")]);
        assert_eq!(out.status.code(), Some(2), "{url}: {}", stderr(&out));
    }
    // A starting Edge refuses the loopback URL too.
    let start = std::process::Command::new(common::EDGE_BIN)
        .arg("--config")
        .arg(env.write_config(&loopback))
        .env("CREDENTIALS_DIRECTORY", &env.creds)
        .env_remove("MG_EDGE_TEST_OUTBOUND")
        .output()
        .unwrap();
    assert_eq!(start.status.code(), Some(2), "{}", stderr(&start));
}

/// Headers of a Chrome navigation from `ip` with `extra`.
fn navigation(ip: &str, extra: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n{extra}",
        cf(ip)
    )
}

/// The challenge page of `path` on `host`: the `C` and the CSP.
fn page(env: &TestEnv, host: &str, path: &str, ip: &str, extra: &str) -> (Shown, String, String) {
    let r = get(env.listen, host, path, &navigation(ip, extra));
    assert_eq!(r.status, 403, "{path}: {}\n{}", r.head, r.body);
    let csp = r.header("content-security-policy").unwrap().to_owned();
    (from_page(&r.body), csp, r.body)
}

fn offers_turnstile(s: &Shown) -> bool {
    let ix = s.ix.as_ref().unwrap();
    let first = ix["providers"][0] == "turnstile";
    assert_eq!(first, ix.get("turnstile").is_some(), "{ix}");
    first
}

/// RFC 3339 (UTC, milliseconds) of now.
fn rfc3339_now() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let (secs, millis) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The first-binding renewal of `s` (D-41).
fn bind(env: &TestEnv, key: &TestSessionKey, s: &Shown, ip: &str, extra: &str) -> Shown {
    let r = post_json(env, "/__mg/c/renew", ip, CHROME, extra, &renewal(key, &s.c));
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let v = json_body(&r);
    Shown {
        c: v["challenge"].as_str().unwrap().to_owned(),
        ix: Some(v["ix"].clone()),
        ..s.clone()
    }
}

/// The signed Turnstile submission of `s` with `token`.
fn ts_submission(key: &TestSessionKey, s: &Shown, token: &str) -> Value {
    let ix = s.ix.as_ref().unwrap();
    let bits = ix["pow"]["bits"].as_u64().unwrap() as u32;
    let k = ix["pow"]["k"].as_u64().unwrap() as usize;
    let counters = pow_solve_v2(&s.c, bits, k, 1 << 24).unwrap();
    let ts = 1_790_000_000_123u64;
    let sig = key.sign_submission(&SubmissionFields {
        c: &s.c,
        ty: "interactive",
        p: "turnstile",
        pp: token,
        t: EXTERNAL_T,
        counters: &counters,
        ret: &s.ret,
        ts,
        build: BUILD,
    });
    json!({"v": 2, "type": "interactive", "c": s.c, "p": "turnstile", "pp": token,
           "t": EXTERNAL_T, "pow": {"counters": counters}, "ret": s.ret, "ts": ts,
           "build": BUILD, "jwk": key.jwk_value(), "sig": sig})
}

/// The siteverify reply that echoes `s`'s `ix.turnstile`.
fn pass_for(s: &Shown) -> SvReply {
    let t = &s.ix.as_ref().unwrap()["turnstile"];
    SvReply::success(
        "example.com",
        t["action"].as_str().unwrap(),
        t["cdata"].as_str().unwrap(),
        &rfc3339_now(),
    )
}

fn start(env: &TestEnv, b: &pb::SiteBundle, mock: &FakeSiteverify) -> Edge {
    install_keys(env, "valid/one-value.json", KEYS_CRED);
    env.publish("blog", &sign(b));
    let text = config(
        env,
        &format!("turnstile_keys = \"cred://{KEYS_CRED}\""),
        Some(&mock.url()),
    );
    let edge = env.spawn_env(
        &env.write_config(&text),
        "info,mg_edge=debug",
        &[("MG_EDGE_TEST_OUTBOUND", "1")],
    );
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| {
        v == b.version as f64
    });
    edge
}

/// The whole flow (§5.4, §7.4, §7.5, §8.3-§8.6) on loopback.
#[test]
fn turnstile_end_to_end() {
    let mock = FakeSiteverify::start().unwrap();
    let env = TestEnv::new("ts-flow");
    let edge = start(&env, &bundle(1, &[]), &mock);
    assert_eq!(
        edge.metric("mg_outbound_override{target=\"siteverify\"}"),
        1.0
    );
    assert!(edge.log_text().contains("test destination"));
    assert_eq!(
        edge.metric("mg_provider_state{provider=\"turnstile\",site=\"blog\",state=\"healthy\"}"),
        1.0
    );
    let ip = "198.51.100.21";

    // §8.3: the page offers Turnstile first, with its CSP; mainland and
    // unknown countries alike while denied_countries is empty (D-70).
    for extra in ["", "CF-IPCountry: CN\r\n"] {
        let (s, csp, body) = page(&env, "example.com", "/members/a", ip, extra);
        assert!(offers_turnstile(&s), "{extra:?}");
        assert!(csp.contains("'strict-dynamic'"), "{csp}");
        assert!(
            csp.contains("frame-src https://challenges.cloudflare.com"),
            "{csp}"
        );
        let t = &s.ix.as_ref().unwrap()["turnstile"];
        assert_eq!(t["sitekey"], "0x4AAAAAAAtest-sitekey");
        assert_eq!(
            (t["action"].as_str(), t["lang"].as_str()),
            (Some("members"), Some("zh-cn"))
        );
        assert_eq!(t["cdata"].as_str().unwrap().len(), 43);
        // The template references no third party itself (§2.4 item 12).
        assert!(!body.contains("challenges.cloudflare.com"));
    }
    // Never on a redact_path route or on a host that is not the widget's.
    let (s, csp, _) = page(&env, "example.com", "/reset/token123", ip, "");
    assert!(!offers_turnstile(&s));
    assert!(
        !csp.contains("cloudflare") && !csp.contains("strict-dynamic"),
        "{csp}"
    );
    let (s, csp, _) = page(&env, "staging.example.com", "/members/a", ip, "");
    assert!(!offers_turnstile(&s));
    assert!(!csp.contains("cloudflare"));
    // The JSON challenge carries it too.
    let r = get(
        env.listen,
        "example.com",
        "/members/api",
        &format!(
            "{}User-Agent: {CHROME}\r\nAccept: application/json\r\nSec-Fetch-Mode: cors\r\n",
            cf(ip)
        ),
    );
    assert_eq!(r.status, 403);
    assert!(offers_turnstile(&from_json(&json_body(&r))));

    // Bind, then submit a token that siteverify passes.
    let key = TestSessionKey::from_label("ts-a");
    let (s, _, _) = page(&env, "example.com", "/members/a", ip, "");
    let s = bind(&env, &key, &s, ip, "");
    assert!(offers_turnstile(&s), "the renewal keeps Turnstile");
    mock.push_replies([pass_for(&s)]);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        "",
        &ts_submission(&key, &s, "tok-e2e-1"),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let clr = cookie(&r, "__Host-mg_clr").unwrap();
    let token = clr.strip_prefix("__Host-mg_clr=").unwrap();
    let keys = std::fs::read(repo("testdata/phase1/keys/token.keys.json")).unwrap();
    let keys = mg_challenge::TokenKeySet::from_key_file(&keys, "blog", &["blog-t-20260927".into()])
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = mg_challenge::verify(&keys, "blog", "production", token, now).unwrap();
    assert_eq!(claims.lvl.to_string(), "interactive_ext:turnstile");
    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].secret().as_deref(),
        Some("0x4AAAAAAAkat-test-secret-current-00000000")
    );
    assert_eq!(seen[0].response().as_deref(), Some("tok-e2e-1"));
    assert_eq!(seen[0].remoteip().as_deref(), Some(ip));
    assert_eq!(seen[0].header("user-agent"), Some("morphgate-dev-tooling"));
    // The clearance passes the interactive route.
    let r = get(
        env.listen,
        "example.com",
        "/members/a",
        &navigation(ip, &format!("Cookie: {clr}\r\n")),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(
        edge.metric(
            "mg_provider_verify_total{outcome=\"pass\",provider=\"turnstile\",reason=\"ok\"}"
        ),
        1.0
    );
    assert!(
        edge.metric(
            "mg_challenge_total{provider=\"turnstile\",result=\"issued\",type=\"interactive\"}"
        ) >= 3.0
    );
    let log = edge.log_text();
    assert!(!log.contains("tok-e2e-1") && !log.contains("kat-test-secret"));

    // D-70 with a list: CN (Cloudflare) and unknown countries are not
    // offered Turnstile; US is.
    env.publish("blog", &sign(&bundle(2, &["CN"])));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 2.0);
    for (extra, offered) in [
        ("CF-IPCountry: CN\r\n", false),
        ("", false),
        ("CF-IPCountry: XX\r\n", false),
        ("CF-IPCountry: US\r\n", true),
    ] {
        let (s, csp, _) = page(&env, "example.com", "/members/b", ip, extra);
        assert_eq!(offers_turnstile(&s), offered, "{extra:?}");
        assert_eq!(csp.contains("strict-dynamic"), offered, "{extra:?}");
    }
    // A C issued to a US visitor, renewed from CN: Turnstile is dropped.
    let us = "CF-IPCountry: US\r\n";
    let (s, _, _) = page(&env, "example.com", "/members/b", ip, us);
    let renewed = bind(&env, &key, &s, ip, "CF-IPCountry: CN\r\n");
    assert!(!offers_turnstile(&renewed));

    // A rejected secret (§8.6): Misconfigured, not counted, the new C
    // falls back, the provider is disabled and logged.
    let (s, _, _) = page(&env, "example.com", "/members/c", ip, us);
    let s = bind(&env, &key, &s, ip, us);
    assert!(offers_turnstile(&s));
    mock.push_replies([SvReply::error_codes(&["invalid-input-secret"])]);
    let r = post_json(
        &env,
        "/__mg/c",
        ip,
        CHROME,
        us,
        &ts_submission(&key, &s, "tok-e2e-2"),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    let next = from_json(&json_body(&r));
    assert!(!offers_turnstile(&next));
    assert!(common::answered_log(&edge, &r.body).contains("ic.provider_misconfigured"));
    edge.wait_metric(
        "mg_provider_state{provider=\"turnstile\",site=\"blog\",state=\"disabled\"}",
        5,
        |v| v == 1.0,
    );
    assert!(
        edge.log_text()
            .contains("disabled for site blog (misconfigured)")
    );
    let (s, csp, _) = page(&env, "example.com", "/members/d", ip, us);
    assert!(!offers_turnstile(&s));
    assert!(!csp.contains("cloudflare"));
    // A new bundle version brings it back.
    env.publish("blog", &sign(&bundle(3, &["CN"])));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 3.0);
    let (s, _, _) = page(&env, "example.com", "/members/e", ip, us);
    assert!(offers_turnstile(&s));
}

/// §8.2: at run time a bundle that enables Turnstile without a credential
/// leaves the provider `disabled(no_secret)` with an ERROR log; the site
/// works with the built-in providers and no third party on its pages.
#[test]
fn no_secret_at_run_time() {
    let env = TestEnv::new("ts-nosecret");
    env.publish("blog", &sign(&bundle(1, &[])));
    let edge = env.spawn(&env.write_config(&config(&env, "", None)));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 1.0);
    edge.wait_metric(
        "mg_provider_state{provider=\"turnstile\",site=\"blog\",state=\"disabled\"}",
        5,
        |v| v == 1.0,
    );
    let log = edge.log_text();
    assert!(log.contains("no_secret"), "{log}");
    assert!(log.contains("ERROR"), "{log}");
    let (s, csp, _) = page(&env, "example.com", "/members/a", "198.51.100.22", "");
    assert!(!offers_turnstile(&s));
    assert!(!csp.contains("cloudflare"));
    assert_eq!(
        edge.metric("mg_outbound_override{target=\"siteverify\"}"),
        0.0
    );
}
