//! Crawler verification through the real binary (docs/impl/phase1-spec.md
//! §7.3, §9.6, D-18, D-22, I-17, I-22, I-26; §15 WP-E1b `crawler.rs`), with
//! `[intel] dns_resolver = "static:<path>"` and the shared test registry
//! (`testdata/phase1/artifacts/crawler-registry.test.json`: GPTBot
//! `ip_ranges` 192.0.2.0/25; Googlebot `ip_ranges_or_rdns` 198.51.100.0/25
//! with `.googlebot.com` / `.google.com`). Enforce mode, local state.
//! Loopback only: the "DNS" is the static table.

mod common;

use common::{Edge, Response, TestEnv, blog_bundle, cf, get, line_of, sign, testdata_artifact};

const GPTBOT: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

/// PTR and forward records of the static resolver.
const DNS: &str = r#"{"v": 1,
 "ptr": {"198.51.100.200": ["crawl-198-51-100-200.googlebot.com."],
         "203.0.113.9": ["host.example.test."],
         "203.0.113.10": ["crawl-203-0-113-10.googlebot.com."],
         "203.0.113.11": ["crawl.evilgooglebot.com."]},
 "a": {"crawl-198-51-100-200.googlebot.com": ["198.51.100.200"],
       "crawl-203-0-113-10.googlebot.com": ["203.0.113.99"],
       "crawl.evilgooglebot.com": ["203.0.113.11"]}}"#;

fn start(env: &TestEnv, intel: &str) -> Edge {
    let (art, bytes) = testdata_artifact("crawler-registry", "crawler-registry.test.json");
    let mut b = blog_bundle(1);
    b.monitor_only = false;
    b.origin_headers.as_mut().unwrap().reasons = true;
    b.artifacts.push(art);
    env.cache_artifact(&bytes);
    env.write_lkg("blog", &sign(&b));
    let dns = env.dir.join("dns.json");
    std::fs::write(&dns, DNS).unwrap();
    let extra = format!(
        "\n[intel]\ndns_resolver = \"static:{}\"\ndns_timeout_ms = 200\n{intel}\n",
        dns.display()
    );
    let edge = env.spawn(&env.write_config(&env.config(&extra, &env.site(""))));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge
}

fn crawl(env: &TestEnv, ua: &str, ip: &str, path: &str, extra: &str) -> Response {
    get(
        env.listen,
        "example.com",
        path,
        &format!(
            "{}User-Agent: {ua}\r\nAccept: application/json\r\n{extra}",
            cf(ip)
        ),
    )
}

/// `ip_ranges`: decided on the first request (D-18, D-22): an address
/// outside the published ranges is an impersonator and blocked; one inside
/// is a verified crawler and let through.
#[test]
fn ip_ranges_operator_is_decided_synchronously() {
    let env = TestEnv::new("crawler-ipr");
    let edge = start(&env, "");

    let r = crawl(
        &env,
        GPTBOT,
        "192.0.2.200",
        "/fake",
        "x-mg-cf-vbot: true\r\n",
    );
    assert_eq!(r.status, 403, "{}", r.head);
    let line = line_of(&env, &edge, &r, "/fake");
    assert!(line.contains(" rule=matrix.class.impersonator "), "{line}");
    assert!(line.contains(" class=impersonator "), "{line}");
    assert!(line.contains(" crawler=failed "), "{line}");

    let r = crawl(
        &env,
        GPTBOT,
        "192.0.2.10",
        "/real",
        "x-mg-cf-vbot: false\r\n",
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/real").unwrap();
    assert_eq!(seen.header("mg-verified"), Some("crawler:gptbot"));
    assert_eq!(seen.header("mg-bot-class"), Some("verified_crawler"));
    let line = line_of(&env, &edge, &r, "/real");
    assert!(line.contains(" rule=matrix.crawler.allow "), "{line}");

    let m = edge.metrics_text();
    let v = |s: &str| common::metric_or_zero(&m, s);
    assert_eq!(
        v("mg_crawler_verify_total{method=\"ip_range\",result=\"fail\"}"),
        1.0
    );
    assert_eq!(
        v("mg_crawler_verify_total{method=\"ip_range\",result=\"pass\"}"),
        1.0
    );
    // docs/05 §3.4: MorphGate and Cloudflare disagree.
    assert_eq!(
        v("mg_cf_vbot_disagree_total{direction=\"mg_fail_cf_true\"}"),
        1.0
    );
    assert_eq!(
        v("mg_cf_vbot_disagree_total{direction=\"mg_pass_cf_false\"}"),
        1.0
    );
    // Nothing was looked up in DNS.
    assert_eq!(v("mg_rdns_lookups_total{result=\"pass\"}"), 0.0);
}

/// §0 "攻击者可控的输入大小不能让规则失效": the crawler claim is matched on
/// the whole `User-Agent` (≤ 8 KiB after §9.3.1), not on the 512-byte
/// `ctx.http.user_agent`. Otherwise an impersonator pads its UA so that the
/// crawler token starts after byte 512: the Edge sees no claim, while the
/// origin, which receives the full header, still sees "GPTBot".
#[test]
fn padded_user_agent_still_claims_the_crawler() {
    let env = TestEnv::new("crawler-pad");
    let edge = start(&env, "");
    let padded = format!(
        "Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
        "x".repeat(600)
    );
    assert!(padded.find("GPTBot").unwrap() > mg_edge::context::MAX_USER_AGENT);

    // Outside GPTBot's ranges: an impersonator, blocked on the first request.
    let r = crawl(&env, &padded, "192.0.2.201", "/pad-fake", "");
    assert_eq!(r.status, 403, "{}", r.head);
    let line = line_of(&env, &edge, &r, "/pad-fake");
    assert!(line.contains(" class=impersonator "), "{line}");
    assert!(line.contains(" crawler=failed "), "{line}");

    // Inside the ranges: verified, as with an unpadded UA.
    let r = crawl(&env, &padded, "192.0.2.11", "/pad-real", "");
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/pad-real").unwrap();
    assert_eq!(seen.header("mg-verified"), Some("crawler:gptbot"));
}

/// `ip_ranges_or_rdns`: the first request is `pending` (DECLARED_AGENT,
/// never VERIFIED_CRAWLER, D-22), with the `outside_ranges` signal (D-18);
/// once the rDNS job settles, later requests get its verdict.
#[test]
fn rdns_is_pending_first_then_settles() {
    let env = TestEnv::new("crawler-rdns");
    let edge = start(&env, "");

    // Forward-confirmed: verified.
    let r = crawl(&env, GOOGLEBOT, "198.51.100.200", "/g1", "");
    let line = line_of(&env, &edge, &r, "/g1");
    assert!(line.contains(" crawler=pending "), "{line}");
    assert!(line.contains(" class=declared_agent "), "{line}");
    assert!(
        line.contains("identity.crawler_failed"),
        "outside_ranges: {line}"
    );
    edge.wait_metric("mg_rdns_lookups_total{result=\"pass\"}", 10, |v| v == 1.0);
    let r = crawl(&env, GOOGLEBOT, "198.51.100.200", "/g2", "");
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/g2").unwrap();
    assert_eq!(seen.header("mg-verified"), Some("crawler:googlebot"));
    let line = line_of(&env, &edge, &r, "/g2");
    assert!(line.contains(" crawler=verified "), "{line}");

    // No matching PTR name, a forward answer without the address, and a
    // look-alike domain (I-22: `.googlebot.com` does not match
    // `evilgooglebot.com`): all fail, later requests are impersonators.
    for (i, ip) in ["203.0.113.9", "203.0.113.10", "203.0.113.11"]
        .iter()
        .enumerate()
    {
        let path = format!("/f{i}");
        let r = crawl(&env, GOOGLEBOT, ip, &path, "");
        let line = line_of(&env, &edge, &r, &path);
        assert!(line.contains(" crawler=pending "), "{ip}: {line}");
        assert!(!line.contains("verified_crawler"), "{ip}: {line}");
        edge.wait_metric("mg_rdns_lookups_total{result=\"fail\"}", 10, |v| {
            v == (i + 1) as f64
        });
        let path = format!("/f{i}-again");
        let r = crawl(&env, GOOGLEBOT, ip, &path, "");
        assert_eq!(r.status, 403, "{ip}: {}", r.head);
        let line = line_of(&env, &edge, &r, &path);
        assert!(line.contains(" class=impersonator "), "{ip}: {line}");
        assert!(line.contains(" crawler=failed "), "{ip}: {line}");
    }
    let m = edge.metrics_text();
    assert_eq!(
        common::metric_or_zero(
            &m,
            "mg_crawler_verify_total{method=\"rdns\",result=\"fail\"}"
        ),
        3.0
    );
    assert_eq!(
        common::metric_or_zero(
            &m,
            "mg_crawler_verify_total{method=\"rdns\",result=\"pass\"}"
        ),
        1.0
    );
}

/// §9.6: a job over the per-prefix budget is abandoned and counted as
/// `dropped`; the claim stays `pending` and the next request tries again
/// (the abandoned in-flight mark does not block it).
#[test]
fn dropped_jobs_are_abandoned_and_reissued() {
    let env = TestEnv::new("crawler-drop");
    let edge = start(&env, "rdns_jobs_per_prefix_per_min = 1");

    let r = crawl(&env, GOOGLEBOT, "203.0.113.9", "/d0", "");
    let _ = line_of(&env, &edge, &r, "/d0");
    edge.wait_metric("mg_rdns_lookups_total{result=\"fail\"}", 10, |v| v == 1.0);
    // Same /24: over the budget.
    for (i, expected) in [(1, 1.0), (2, 2.0)] {
        let path = format!("/d{i}");
        let r = crawl(&env, GOOGLEBOT, "203.0.113.10", &path, "");
        let line = line_of(&env, &edge, &r, &path);
        assert!(line.contains(" crawler=pending "), "{line}");
        assert_eq!(
            edge.metric("mg_rdns_lookups_total{result=\"dropped\"}"),
            expected,
            "each request re-issues the abandoned job"
        );
    }
    // Another prefix has its own budget.
    let r = crawl(&env, GOOGLEBOT, "198.51.100.200", "/d3", "");
    let _ = line_of(&env, &edge, &r, "/d3");
    edge.wait_metric("mg_rdns_lookups_total{result=\"pass\"}", 10, |v| v == 1.0);
}

/// A reload that keeps the `crawler-registry` artifact keeps the verifier
/// and so its rDNS cache; a new registry gets a new verifier, while a job
/// of the old one still reports to the old one (I-26).
#[test]
fn verifier_survives_reloads_with_the_same_registry() {
    use mg_edge::config::{BootstrapMode, CredRef, EdgeConfig};
    use mg_edge::creds::{CredResolver, read_secret};
    use mg_edge::sites::{Site, SiteKeys, SiteRuntime, SiteSettings};
    use mg_edge_core::bundle::verify_bundle;
    use mg_edge_core::testkit::http::owner_test_keys;
    use mg_intel::{CrawlerStatus, RdnsOutcome, VerifyMethod};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let env = TestEnv::new("crawler-reload");
    let cfg = EdgeConfig::from_toml_str(&env.default_config("")).unwrap();
    let settings = SiteSettings::new(&cfg.sites[0], &cfg);
    let token = CredRef::Path(common::repo("testdata/phase1/keys/token.keys.json"));
    let seal = std::fs::read(common::repo("testdata/phase1/keys/seal.root.json")).unwrap();
    let keys = SiteKeys {
        seal: mg_challenge::SealKeys::from_key_file(&seal, "blog").unwrap(),
        token_file: read_secret(&CredResolver::with_dir(None), &token, &mut |_| {}).unwrap(),
    };
    let hosts = settings.hosts.clone();
    let site = Site::new(settings, keys, SiteRuntime::bootstrap(BootstrapMode::Open));
    let apply = |version: u64, file: &str| {
        let (art, bytes) = testdata_artifact("crawler-registry", file);
        let mut b = blog_bundle(version);
        b.artifacts.push(art);
        let vb = verify_bundle(&sign(&b), &owner_test_keys(), "blog", &hosts).unwrap();
        site.apply(
            &vb,
            &BTreeMap::from([("crawler-registry".to_string(), bytes)]),
        )
        .unwrap();
        Arc::clone(
            site.runtime()
                .bundle
                .as_ref()
                .unwrap()
                .intel
                .crawler
                .as_ref()
                .unwrap(),
        )
    };
    let v1 = apply(1, "crawler-registry.test.json");
    let ip = Some("198.51.100.200".parse().unwrap());
    let (_, job) = v1.check(GOOGLEBOT, ip, 0);
    let job = job.expect("an rDNS job");
    v1.complete(&job, RdnsOutcome::Pass, 1);

    let v2 = apply(2, "crawler-registry.test.json");
    assert!(Arc::ptr_eq(&v1, &v2), "same registry: same verifier");
    assert!(matches!(
        v2.check(GOOGLEBOT, ip, 2).0,
        CrawlerStatus::Verified {
            method: VerifyMethod::Rdns,
            ..
        }
    ));

    // A pending job of the old verifier, then a new registry.
    let ip = Some("198.51.100.201".parse().unwrap());
    let (_, stale) = v2.check(GOOGLEBOT, ip, 3);
    let stale = stale.expect("an rDNS job");
    let v3 = apply(3, "crawler-registry.json");
    assert!(!Arc::ptr_eq(&v2, &v3), "new registry: new verifier");
    v2.complete(&stale, RdnsOutcome::Pass, 4);
    assert!(
        !matches!(v3.check(GOOGLEBOT, ip, 5).0, CrawlerStatus::Verified { .. }),
        "the old verifier's job never seeds the new cache"
    );
}
