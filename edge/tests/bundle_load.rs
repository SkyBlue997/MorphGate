//! Bundles → site runtimes (docs/impl/phase1-spec.md §9.10, D-21, I-3,
//! §16 "跨语言签名"; WP-E1a test list):
//!
//! * the Go-built golden bundles verify, decode and convert through the full
//!   site runtime (rules, lists, routes, limiters, token keys, artifacts);
//! * candidates go through the real start-up wiring (`Startup::load`) and
//!   `poll_loop` with `Site::apply`: bad signature, unknown key, version
//!   rollback, same version with other bytes, other hosts, artifact hash
//!   mismatch, listener profile, token kids and `not_before` are handled;
//! * through the binary: LKG recovery on restart, the three site states and
//!   their 503s, an LKG with missing artifacts, `--check-config` failing on
//!   an unusable LKG.

mod common;

use common::{TestEnv, blog_bundle, cf, get, repo, sign};
use mg_edge::config::{CredRef, EdgeConfig};
use mg_edge::creds::{CredResolver, read_secret};
use mg_edge::sites::{SiteKeys, SiteSettings, SiteState, build_runtime};
use mg_edge::startup::Startup;
use mg_edge_core::bundle::{Fetcher, metrics, poll_loop, verify_bundle};
use mg_edge_core::testkit::http::{
    OWNER_TEST_SEED, owner_test_keys, sha256_hex, sign_test_bundle, sign_test_bytes,
};
use mg_proto::v1::{ArtifactRef, SiteBundle, UpstreamProfileKind};
use prost::Message as _;
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn artifact(name: &str, file: &str) -> (ArtifactRef, Vec<u8>) {
    let bytes = std::fs::read(repo("testdata/phase1/artifacts").join(file)).unwrap();
    let sha = sha256_hex(&bytes);
    (
        ArtifactRef {
            name: name.into(),
            uri: format!("artifacts/{sha}"),
            sha256: sha,
            version: String::new(),
            size: bytes.len() as u64,
        },
        bytes,
    )
}

fn settings_and_keys(token_file: &str) -> (SiteSettings, SiteKeys) {
    let env = TestEnv::new("bl-cfg");
    let cfg = EdgeConfig::from_toml_str(&env.default_config("")).unwrap();
    let settings = SiteSettings::new(&cfg.sites[0], &cfg);
    let seal = std::fs::read(repo("testdata/phase1/keys/seal.root.json")).unwrap();
    let keys = SiteKeys {
        seal: mg_challenge::SealKeys::from_key_file(&seal, "blog").unwrap(),
        token_file: read_secret(
            &CredResolver::with_dir(None),
            &CredRef::Path(repo("testdata/phase1/keys").join(token_file)),
            &mut |_| {},
        )
        .unwrap(),
    };
    (settings, keys)
}

#[test]
fn golden_bundles_convert_through_the_full_site_runtime() {
    let hosts = common::HOSTS.map(String::from);
    let golden = |name: &str| {
        let bytes = std::fs::read(repo("control-plane/testdata/sites/golden").join(name)).unwrap();
        verify_bundle(&bytes, &owner_test_keys(), "blog", &hosts).unwrap()
    };

    let vb = golden("golden-norules.bundle");
    let (settings, keys) = settings_and_keys("token.keys.json");
    let rt = build_runtime(&settings, &keys, &vb, &BTreeMap::new()).unwrap();
    assert_eq!(rt.version, 1_790_000_000);
    assert!(rt.monitor_only && rt.case_insensitive_paths);
    assert_eq!(rt.upstream_kind, mg_core::UpstreamProfileKind::Cloudflare);
    assert_eq!(rt.token_keys.active_kid(), "blog-t-20260927");
    let prod = rt.env_for_host("www.example.com").unwrap();
    assert_eq!(prod.name, "production");
    assert_eq!(
        prod.routes
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>(),
        ["login", "reset", "api", "default"]
    );
    assert_eq!(prod.limiters.len(), 2);
    assert!(rt.lists.contains("owner_cidrs"));
    assert_eq!(
        rt.env_for_host("staging.example.com").unwrap().name,
        "staging"
    );
    assert!(rt.missing_artifacts.is_empty());

    // golden-rules: rules with IR, two token kids, four artifacts.
    let vb = golden("golden-rules.bundle");
    let (settings, keys) = settings_and_keys("token.keys.rotated.json");
    let mut arts = BTreeMap::new();
    for (name, file) in [
        ("cloudflare-ips", "cloudflare-ips.json"),
        ("crawler-registry", "crawler-registry.test.json"),
        ("datacenter-asns", "datacenter-asns.txt"),
        ("tor-exits", "tor-exits.txt"),
    ] {
        let (r, bytes) = artifact(name, file);
        assert!(
            vb.bundle.artifacts.iter().any(|a| a.sha256 == r.sha256),
            "{file} is the artifact the golden bundle references"
        );
        arts.insert(name.to_owned(), bytes);
    }
    let rt = build_runtime(&settings, &keys, &vb, &arts).unwrap();
    let rules: usize = rt.environments.iter().map(|e| e.rules.len()).sum();
    let bundled: usize = vb.bundle.environments.iter().map(|e| e.rules.len()).sum();
    assert!(rules > 0 && rules == bundled);
    assert_eq!(
        rt.token_keys.kids().collect::<Vec<_>>(),
        ["blog-t-20260928", "blog-t-20260927"]
    );
    assert!(rt.intel.cloudflare_ips.is_some());
    assert!(rt.intel.crawler_registry.is_some());
    assert!(rt.intel.datacenter_asns.is_some());
    assert!(rt.intel.tor_exits.is_some());
    assert!(rt.intel.geo.is_none());

    // Without its artifacts the same bundle still converts; they are MISSING.
    let rt = build_runtime(&settings, &keys, &vb, &BTreeMap::new()).unwrap();
    assert_eq!(rt.missing_artifacts.len(), 4);
    assert!(rt.intel.tor_exits.is_none());

    // token_key_ids must all be in token.keys.json (I-14).
    let (settings, keys) = settings_and_keys("token.keys.json");
    let e = build_runtime(&settings, &keys, &vb, &arts).unwrap_err();
    assert!(e.contains("blog-t-20260928"), "{e}");
}

#[test]
fn runtime_conversion_rejects_what_the_edge_cannot_run() {
    let (settings, keys) = settings_and_keys("token.keys.json");
    let convert = |b: &SiteBundle, arts: &BTreeMap<String, Vec<u8>>| {
        let signed = sign(b);
        let vb = verify_bundle(&signed, &owner_test_keys(), "blog", &settings.hosts)
            .map_err(|e| format!("verify: {e}"))?;
        build_runtime(&settings, &keys, &vb, arts)
    };
    let none = BTreeMap::new();
    assert!(convert(&blog_bundle(1), &none).is_ok());

    // A direct_tls bundle for a site served by a cloudflare listener.
    let mut b = blog_bundle(1);
    b.upstream.as_mut().unwrap().kind = UpstreamProfileKind::DirectTls as i32;
    b.cloudflare = None;
    let e = convert(&b, &none).unwrap_err();
    assert!(
        e.contains("upstream.kind") && e.contains("cf-tunnel"),
        "{e}"
    );

    // A token kid that the site's key file does not have.
    let mut b = blog_bundle(1);
    b.token_key_ids = vec!["blog-t-20991231".into()];
    assert!(convert(&b, &none).unwrap_err().contains("token_key_ids"));

    // A rule whose IR does not decode.
    let mut b = blog_bundle(1);
    b.environments[0].rules.push(mg_proto::v1::CompiledRule {
        id: "broken".into(),
        phase: "custom".into(),
        ir_version: 1,
        expr_ir: vec![0xff, 0xff, 0xff],
        action: mg_proto::v1::Action::Log as i32,
        mode: "enforce".into(),
        rollout_percent: 100,
        ..Default::default()
    });
    let e = convert(&b, &none).unwrap_err();
    assert!(e.contains("rules[broken]"), "{e}");

    // An artifact that does not parse as its kind.
    let bogus = b"not an ip list\n".to_vec();
    let mut b = blog_bundle(1);
    let sha = sha256_hex(&bogus);
    b.artifacts.push(ArtifactRef {
        name: "tor-exits".into(),
        uri: format!("artifacts/{sha}"),
        sha256: sha,
        version: String::new(),
        size: bogus.len() as u64,
    });
    let arts = BTreeMap::from([("tor-exits".to_string(), bogus)]);
    assert!(
        convert(&b, &arts)
            .unwrap_err()
            .contains("artifact tor-exits")
    );
    // An empty list is a valid empty set.
    let arts = BTreeMap::from([("tor-exits".to_string(), Vec::new())]);
    let mut b2 = b.clone();
    b2.artifacts[0].sha256 = sha256_hex(b"");
    b2.artifacts[0].uri = format!("artifacts/{}", b2.artifacts[0].sha256);
    b2.artifacts[0].size = 0;
    let rt = convert(&b2, &arts).unwrap();
    assert!(rt.intel.tor_exits.as_ref().is_some_and(|s| s.is_empty()));
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Candidates through `Startup::load` + `poll_loop` + `Site::apply`.
#[test]
fn candidates_through_the_poll_loop() {
    let env = TestEnv::new("bl-poll");
    let cfg = EdgeConfig::from_toml_str(&env.default_config("")).unwrap();
    let startup = Startup::load(cfg, &CredResolver::with_dir(Some(env.creds.clone()))).unwrap();
    let site = std::sync::Arc::clone(startup.sites.by_id("blog").unwrap());
    assert_eq!(site.runtime().state, SiteState::BootstrapOpen);
    let mut source = startup.sources.into_iter().next().unwrap();
    source.interval = Duration::from_millis(40);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let fetcher = std::sync::Arc::new(Fetcher::new(&startup.fetcher).unwrap());
    let apply_site = std::sync::Arc::clone(&site);
    let dir = std::sync::Arc::clone(&startup.state_dir);
    let keys = std::sync::Arc::clone(&startup.owner_keys);
    let handle = std::thread::spawn(move || {
        rt.block_on(poll_loop(
            source,
            fetcher,
            dir,
            keys,
            move |vb, arts| apply_site.apply(&vb, &arts),
            stop_rx,
        ));
    });

    let rejected = || {
        metrics()
            .config_reload_total
            .with_label_values(&["blog", "rejected"])
            .get()
    };
    let version = || site.runtime().bundle.as_ref().map_or(0, |b| b.version);
    let wait = |what: &str, cond: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    // A valid bundle moves the site from bootstrap to active and becomes the LKG.
    let v10 = sign(&blog_bundle(10));
    env.publish("blog", &v10);
    wait("v10", &|| version() == 10);
    assert_eq!(site.runtime().state, SiteState::Active);
    wait("LKG", &|| {
        std::fs::read(env.state.join("bundles/blog.bundle"))
            .ok()
            .as_deref()
            == Some(&v10[..])
    });

    let mut bad_sig = mg_proto::v1::SignedBundle::decode(&sign(&blog_bundle(11))[..]).unwrap();
    bad_sig.ed25519_signature[0] ^= 1;
    let mut other_hosts = blog_bundle(12);
    other_hosts.hosts.pop();
    other_hosts.environments[0].hosts.pop();
    let mut same_version = blog_bundle(10);
    same_version.created_at_ms += 1;
    let mut profile = blog_bundle(14);
    profile.upstream.as_mut().unwrap().kind = UpstreamProfileKind::DirectTls as i32;
    profile.cloudflare = None;
    let mut kid = blog_bundle(15);
    kid.token_key_ids = vec!["blog-t-20991231".into()];
    let mut hash = blog_bundle(13);
    let published = env.publish_artifact(b"198.51.100.0/24\n");
    std::fs::write(
        env.publish.join("artifacts").join(&published),
        b"203.0.113.0/24\n",
    )
    .unwrap();
    hash.artifacts.push(ArtifactRef {
        name: "tor-exits".into(),
        uri: format!("artifacts/{published}"),
        sha256: published,
        version: String::new(),
        size: 16,
    });

    let candidates: Vec<(&str, Vec<u8>)> = vec![
        ("bad signature", bad_sig.encode_to_vec()),
        (
            "unknown key",
            sign_test_bundle(&blog_bundle(11), &OWNER_TEST_SEED, "owner-unknown"),
        ),
        ("version rollback", sign(&blog_bundle(9))),
        ("same version, other bytes", sign(&same_version)),
        ("other hosts", sign(&other_hosts)),
        ("artifact hash mismatch", sign(&hash)),
        ("listener profile", sign(&profile)),
        ("token kid", sign(&kid)),
        ("truncated", v10[..v10.len() / 2].to_vec()),
        (
            "not a bundle",
            sign_test_bytes(b"\xff\xff", &OWNER_TEST_SEED, "owner-test"),
        ),
    ];
    for (what, bytes) in candidates {
        let before = rejected();
        env.publish("blog", &bytes);
        wait(what, &|| rejected() > before);
        assert_eq!(version(), 10, "{what} replaced the bundle in effect");
        assert_eq!(site.runtime().state, SiteState::Active);
    }
    assert_eq!(
        std::fs::read(env.state.join("bundles/blog.bundle")).unwrap(),
        v10,
        "a rejected candidate never becomes the LKG"
    );

    // not_before: pending until due, then applied.
    let mut later = blog_bundle(16);
    later.not_before_ms = now_ms() + 1_500;
    env.publish("blog", &sign(&later));
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(version(), 10, "a pending bundle is not in effect yet");
    wait("not_before", &|| version() == 16);

    let v17 = sign(&blog_bundle(17));
    env.publish("blog", &v17);
    wait("v17", &|| version() == 17);
    wait("LKG v17", &|| {
        std::fs::read(env.state.join("bundles/blog.bundle"))
            .ok()
            .as_deref()
            == Some(&v17[..])
    });

    stop_tx.send(true).unwrap();
    handle.join().unwrap();
}

#[test]
fn lkg_is_used_on_restart() {
    let env = TestEnv::new("bl-lkg");
    env.write_lkg("blog", &sign(&blog_bundle(5)));
    let config = env.write_config(&env.default_config(""));
    for _ in 0..2 {
        let edge = env.spawn(&config);
        edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 5.0);
        let m = edge.metrics_text();
        assert!(
            m.contains("mg_site_state{site=\"blog\",state=\"active\"} 1"),
            "{m}"
        );
        let r = get(env.listen, "example.com", "/lkg", &cf("198.51.100.7"));
        assert_eq!(r.status, 200);
        let id = env
            .origin
            .last("/lkg")
            .unwrap()
            .header("mg-request-id")
            .unwrap()
            .to_owned();
        // Monitor mode: the Decision Core ran, its decision is only recorded.
        let line = edge.request_log(&id).unwrap();
        assert!(line.contains(" rule=matrix."), "{line}");
        assert!(line.contains(" dry_run=true "), "{line}");
    }
}

#[test]
fn site_states_and_their_answers() {
    // bootstrap = "open": forwarded, recorded as bootstrap.
    let env = TestEnv::new("bl-open");
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    assert_eq!(
        get(env.listen, "example.com", "/o", &cf("198.51.100.7")).status,
        200
    );
    let id = env
        .origin
        .last("/o")
        .unwrap()
        .header("mg-request-id")
        .unwrap()
        .to_owned();
    assert!(edge.request_log(&id).unwrap().contains(" rule=bootstrap "));
    assert!(
        edge.metrics_text()
            .contains("mg_site_state{site=\"blog\",state=\"bootstrap_open\"} 1")
    );
    assert_eq!(edge.metric("mg_config_version{site=\"blog\"}"), 0.0);
    drop(edge);

    // bootstrap = "closed": 503, health check still answered.
    let env = TestEnv::new("bl-closed");
    let edge = env.spawn(&env.write_config(&env.default_config("bootstrap = \"closed\"")));
    let r = get(env.listen, "example.com", "/c", &cf("198.51.100.7"));
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some("30"));
    assert_eq!(r.header("cache-control"), Some("no-store, private"));
    assert_eq!(
        get(env.listen, "example.com", "/__mg/healthz", "").status,
        200
    );
    assert_eq!(edge.metric("mg_site_unavailable_total{site=\"blog\"}"), 1.0);
    assert!(
        edge.metrics_text()
            .contains("mg_site_state{site=\"blog\",state=\"bootstrap_closed\"} 1")
    );
    assert!(env.origin.seen().is_empty());
    drop(edge);

    // lkg_invalid: 503 whatever bootstrap says (D-21).
    for (extra, status, rule) in [
        ("bootstrap = \"open\"", 503, None),
        ("on_lkg_invalid = \"open\"", 200, Some("lkg_invalid_open")),
    ] {
        let env = TestEnv::new("bl-invalid");
        let mut forged = sign(&blog_bundle(3));
        let n = forged.len();
        forged[n - 1] ^= 1; // breaks the signature
        env.write_lkg("blog", &forged);
        let edge = env.spawn(&env.write_config(&env.default_config(extra)));
        let r = get(env.listen, "example.com", "/i", &cf("198.51.100.7"));
        assert_eq!(r.status, status, "{extra}");
        assert_eq!(
            get(env.listen, "example.com", "/__mg/healthz", "").status,
            200
        );
        let m = edge.metrics_text();
        assert!(
            m.contains("mg_site_state{site=\"blog\",state=\"lkg_invalid\"} 1"),
            "{extra}: {m}"
        );
        assert!(
            edge.log_text().contains("lkg_invalid"),
            "the reason is logged"
        );
        if let Some(rule) = rule {
            let id = env
                .origin
                .last("/i")
                .unwrap()
                .header("mg-request-id")
                .unwrap()
                .to_owned();
            assert!(
                edge.request_log(&id)
                    .unwrap()
                    .contains(&format!(" rule={rule} "))
            );
        }
    }

    // A listener the bundle does not allow: 403.
    let env = TestEnv::new("bl-listener");
    let mut b = blog_bundle(1);
    b.allowed_listeners = vec!["aop".into()];
    env.write_lkg("blog", &sign(&b));
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    let r = get(env.listen, "example.com", "/l", &cf("198.51.100.7"));
    assert_eq!(r.status, 403);
    assert_eq!(
        edge.metric("mg_listener_rejected_total{listener=\"cf-tunnel\",site=\"blog\"}"),
        1.0
    );
}

#[test]
fn lkg_with_missing_artifacts_is_applied_and_they_are_fetched_later() {
    let env = TestEnv::new("bl-missing");
    let (tor, bytes) = artifact("tor-exits", "tor-exits.txt");
    let mut b = blog_bundle(4);
    b.artifacts.push(tor.clone());
    let signed = sign(&b);
    env.write_lkg("blog", &signed);
    env.publish("blog", &signed);
    let config = env.write_config(&env.default_config(""));

    let out = env.check(&config);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tor-exits"),
        "--check-config warns about the missing artifact"
    );

    let edge = env.spawn(&config);
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 4.0);
    let missing = "mg_artifact_missing{name=\"tor-exits\",site=\"blog\"}";
    assert_eq!(edge.metric(missing), 1.0);
    assert!(
        edge.metrics_text()
            .contains("mg_site_state{site=\"blog\",state=\"active\"} 1")
    );
    assert_eq!(
        get(env.listen, "example.com", "/m", &cf("198.51.100.7")).status,
        200
    );

    // Once the artifact is published, the poll loop fetches it and rebuilds.
    let sha = env.publish_artifact(&bytes);
    assert_eq!(sha, tor.sha256);
    edge.wait_metric(missing, 15, |v| v == 0.0);
    assert!(env.state.join("artifacts").join(&sha).exists());
}

#[test]
fn check_config_fails_on_an_unusable_lkg() {
    let env = TestEnv::new("bl-check");
    let config = env.write_config(&env.default_config("on_lkg_invalid = \"open\""));
    assert!(
        env.check(&config).status.success(),
        "no LKG: bootstrap is fine"
    );

    env.write_lkg("blog", &sign(&blog_bundle(2)));
    let out = env.check(&config);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // I-4: bootstrap_owner_zones that differ from the bundle's are a warning.
    let zones = env.dir.join("zones.toml");
    std::fs::write(
        &zones,
        env.default_config("bootstrap_owner_zones = [\"other.example\"]"),
    )
    .unwrap();
    let out = env.check(&zones);
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("bootstrap_owner_zones") && err.contains("I-4"),
        "{err}"
    );

    for (what, bytes) in [
        ("corrupt", b"garbage".to_vec()),
        (
            "unknown key",
            sign_test_bundle(&blog_bundle(2), &OWNER_TEST_SEED, "owner-retired"),
        ),
        ("other site", {
            let mut b = blog_bundle(2);
            b.site_id = "shop".into();
            sign(&b)
        }),
    ] {
        env.write_lkg("blog", &bytes);
        let out = env.check(&config);
        assert_eq!(out.status.code(), Some(1), "{what}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("site blog") && err.contains("LKG"),
            "{what}: {err}"
        );
    }
}
