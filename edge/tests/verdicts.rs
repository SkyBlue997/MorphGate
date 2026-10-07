//! Entity verdicts read from Valkey (docs/impl/phase1-spec.md §9.7, D-10;
//! §15 WP-E1b `verdicts.rs`): a verdict the owner wrote by hand raises the
//! request's score and its labels reach the policy; an unparsable value is
//! ignored and counted in `mg_verdict_parse_errors_total`.
//!
//! Skipped without a Valkey server (see `ratelimit_valkey.rs`). The client
//! addresses are derived from the fixture's random tag, and every key is
//! written with a TTL and deleted at the end.

mod common;

use common::policy::{field, in_list, rule, string};
use common::valkey::Valkey;
use common::{TestEnv, blog_bundle, cf, get, origin_log, sign, test_k_pseudo, with_valkey};
use mg_core::Net;
use mg_edge_core::state::{entity_key, verdict_key};
use mg_proto::v1::Action;
use redis::Commands;

const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                  Chrome/131.0.0.0 Safari/537.36";

/// A documentation IPv6 address unique to this run (`tag` = `t<16 hex>`),
/// in its own /64 (the `ip` entity, D-24) of a /48 per run.
fn address(tag: &str, net: u16) -> String {
    format!("2001:db8:{}:{net:x}::1", &tag[1..5])
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[test]
fn verdicts_raise_risk_and_parse_errors_are_counted() {
    let Some(vk) = Valkey::start() else { return };
    let env = TestEnv::new("verdicts");
    // Monitor: forwarded, so the origin sees MG-Bot-Score.
    let mut b = blog_bundle(1);
    b.environments[0].rules = vec![rule(
        "verdict-label",
        "custom",
        Action::Block,
        in_list(string("manual_bad"), field("labels")),
        &[],
    )];
    env.write_lkg("blog", &sign(&b));
    let config = with_valkey(&env.default_config(""), &vk.proxy_url(), 500);
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 10, |v| v == 1.0);

    let k = test_k_pseudo();
    let bad = address(&vk.tag, 1);
    let good = address(&vk.tag, 2);
    let broken = address(&vk.tag, 3);
    let ip_key = |ip: &str| {
        let ip = ip.parse().unwrap();
        verdict_key("blog", "ip", &entity_key(&k, "ip", &Net::entity_of(ip)))
    };
    let prefix_key = |ip: &str| {
        let ip = ip.parse().unwrap();
        verdict_key(
            "blog",
            "prefix",
            &entity_key(&k, "prefix", &Net::prefix_of(ip)),
        )
    };
    let verdict = serde_json::json!({
        "type": "ip", "key": "manual", "risk": 100, "labels": ["manual_bad"],
        "expires_at_ms": now_ms() + 600_000, "source": "owner", "version": "1",
        "site_id": "blog"
    })
    .to_string();
    let mut admin = vk.admin();
    let _: () = admin.pset_ex(ip_key(&bad), &verdict, 60_000).unwrap();
    let _: () = admin.pset_ex(ip_key(&broken), "{not json", 60_000).unwrap();

    let score = |ip: &str, path: &str| -> u8 {
        let r = get(
            env.listen,
            "example.com",
            path,
            &format!("{}User-Agent: {UA}\r\nAccept: text/html\r\n", cf(ip)),
        );
        assert_eq!(r.status, 200, "{}", r.head);
        env.origin
            .last(path)
            .unwrap()
            .header("mg-bot-score")
            .unwrap()
            .parse()
            .unwrap()
    };
    let with_verdict = score(&bad, "/bad");
    let without = score(&good, "/good");
    assert!(
        with_verdict > without,
        "a verdict raises the score: {with_verdict} vs {without}"
    );
    // Its labels reach the policy (`labels`).
    let line = origin_log(&env, &edge, "/bad");
    assert!(
        line.contains(" rule=verdict-label action=block dry_run=true "),
        "{line}"
    );
    let line = origin_log(&env, &edge, "/good");
    assert!(!line.contains("verdict-label"), "{line}");

    let errors = "mg_verdict_parse_errors_total";
    let before = edge.metric(errors);
    let _ = score(&broken, "/broken");
    assert_eq!(edge.metric(errors), before + 1.0);

    let _: () = admin
        .del(&[ip_key(&bad), ip_key(&broken), prefix_key(&bad)])
        .unwrap();
}
