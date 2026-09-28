//! End-to-end smoke test: the real `mg-edge` binary with an `edge.toml` v1
//! (one `cloudflare` loopback listener, local state mode, a `file://` bundle
//! root) in front of an in-process origin. Loopback only.

mod common;

use common::{TestEnv, cf, get};
use std::process::Command;

#[test]
fn edge_serves_healthz_proxies_origin_and_exposes_metrics() {
    let env = TestEnv::new("smoke");
    let edge = env.spawn(&env.write_config(&env.default_config("")));

    let health = get(env.listen, "example.com", "/__mg/healthz", "");
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "ok");
    assert_eq!(health.header("cache-control"), Some("no-store, private"));
    assert_eq!(health.header("x-content-type-options"), Some("nosniff"));

    let reserved = get(env.listen, "example.com", "/__mg/does-not-exist", "");
    assert_eq!(reserved.status, 404);
    assert_eq!(reserved.header("cache-control"), Some("no-store, private"));

    // Spellings that Cloudflare's rules normalize to /__mg/... (and exempt
    // from bot checks and caching) must not reach the origin either.
    for path in [
        "//__mg/c",
        "/%5F%5Fmg/c",
        "/x/../__mg/c",
        "/%5F%5Fmg/..%2F..%2Fsecret.txt",
    ] {
        let r = get(env.listen, "example.com", path, "");
        assert_eq!(r.status, 404, "{path}: {}", r.head);
        assert_eq!(
            r.header("cache-control"),
            Some("no-store, private"),
            "{path}"
        );
    }
    assert!(
        env.origin.seen().iter().all(|s| !s.line.contains("mg")),
        "a /__mg request reached the origin: {:?}",
        env.origin.seen()
    );

    // A bootstrap-open site forwards (no bundle yet), with the Edge's headers.
    let r = get(env.listen, "example.com", "/hello?x=1", &cf("198.51.100.7"));
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(r.body, "origin ok");
    let seen = env.origin.last("/hello").unwrap();
    assert_eq!(seen.line, "GET /hello?x=1 HTTP/1.1");
    assert_eq!(seen.header("mg-client-ip"), Some("198.51.100.7"));
    assert_eq!(seen.header("mg-request-id").map(str::len), Some(32));

    // An unknown host is never forwarded.
    let r = get(env.listen, "other.example", "/", "");
    assert_eq!(r.status, 404);
    assert_eq!(r.body, "unknown site");

    let metrics = edge.metrics_text();
    assert!(metrics.contains("mg_edge_requests_total{route=\"healthz\",status=\"2xx\"}"));
    assert!(metrics.contains("route=\"origin\",status=\"2xx\""));
    assert!(metrics.contains("mg_edge_info{"));
    assert!(metrics.contains("mg_site_state{site=\"blog\",state=\"bootstrap_open\"} 1"));
    assert!(metrics.contains("mg_unknown_host_total{listener=\"cf-tunnel\"} 1"));
    assert!(env.origin.last("other.example").is_none());
}

#[test]
fn check_config_flag_validates_and_exits() {
    let env = TestEnv::new("check");
    let good = env.write_config(&env.default_config(""));
    let ok = env.check(&good);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stdout).contains("OK"));
    // §8.1: a loopback listener without upstream_keys in front of an origin
    // on this host is a warning, not an error.
    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(
        stderr.contains("warning") && stderr.contains("has no upstream_keys"),
        "{stderr}"
    );
    let with_keys = env.write_config(&env.default_config("").replace(
        "profile = \"cloudflare\"\n",
        "profile = \"cloudflare\"\nupstream_keys = \"cred://mg-upstream-keys\"\n",
    ));
    let out = env.check(&with_keys);
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("upstream_keys"));

    // A syntax / semantic error exits 2.
    let bad = env.dir.join("bad.toml");
    std::fs::write(
        &bad,
        env.default_config("")
            .replace("profile = \"cloudflare\"", "profile = \"cloudfront\""),
    )
    .unwrap();
    let err = env.check(&bad);
    assert_eq!(err.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&err.stderr).contains("unknown variant `cloudfront`"));

    // The Phase 0 format is refused with a migration hint.
    let phase0 = env.dir.join("phase0.toml");
    std::fs::write(
        &phase0,
        "site_id = \"s\"\nlisten = \"127.0.0.1:18080\"\norigin = \"127.0.0.1:18081\"\n\
         upstream_profile = \"cloudflare\"\nmetrics_listen = \"127.0.0.1:19901\"\n",
    )
    .unwrap();
    let err = env.check(&phase0);
    assert_eq!(err.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&err.stderr).contains("config_version is missing"));

    // cred:// without CREDENTIALS_DIRECTORY is an error.
    let out = Command::new(common::EDGE_BIN)
        .args(["--check-config", "--config"])
        .arg(&good)
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CREDENTIALS_DIRECTORY"));

    // A key file for another site is an error.
    std::fs::copy(
        common::repo("testdata/phase1/keys/invalid/token.keys.site-shop.json"),
        env.creds.join("mg-blog-token-keys"),
    )
    .unwrap();
    let out = env.check(&good);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("token_keys"));
}

/// §8.1 "bundle_root: file:// 目录可读": `--check-config` fails on a
/// `file://` bundle root that is not a readable directory (a typo would
/// otherwise leave a bootstrap-open site forwarding unevaluated traffic
/// forever). A running Edge still starts (the site stays in bootstrap and
/// keeps polling), so a publish directory that is only briefly missing never
/// takes every site down.
#[test]
fn check_config_requires_a_readable_file_bundle_root() {
    let env = TestEnv::new("root");
    let missing = env.dir.join("no-such-publish-dir");
    let config = env.default_config("").replace(
        &env.bundle_root(),
        &format!("file://{}/", missing.display()),
    );
    let path = env.write_config(&config);
    let out = env.check(&path);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bundle_root") && stderr.contains("no-such-publish-dir"),
        "{stderr}"
    );

    // A file is not a directory either.
    let file = env.dir.join("a-file");
    std::fs::write(&file, b"x").unwrap();
    let path = env.write_config(
        &env.default_config("")
            .replace(&env.bundle_root(), &format!("file://{}/", file.display())),
    );
    assert_eq!(env.check(&path).status.code(), Some(2));

    // The Edge itself starts and serves the site in bootstrap mode.
    let path = env.write_config(&config);
    let edge = env.spawn(&path);
    assert_eq!(
        get(env.listen, "example.com", "/root", &cf("198.51.100.7")).status,
        200
    );
    assert!(edge.log_text().contains("no-such-publish-dir"));
}
