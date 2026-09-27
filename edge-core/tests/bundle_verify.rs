//! `verify_bundle` (docs/impl/phase1-spec.md §9.10 "candidate", §3.2
//! signature input, §8.2 bounds re-checked by the Edge, §8.3 defaults).

use mg_edge_core::bundle::{
    BundleError, MAX_BUNDLE_BYTES, MAX_SIGNED_BUNDLE_BYTES, OwnerKeys, SIGNING_DOMAIN,
    signing_input, verify_bundle,
};
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_SEED, owner_test_keys, sign_test_bundle, sign_test_bytes,
    test_site_bundle,
};
use mg_proto::v1::{
    Action, ArtifactRef, ChallengeType, Channel, CompiledRule, Environment, NamedList, RateLimit,
    Route, RouteSensitivity, SignedBundle, SiteBundle, UpstreamProfileKind,
};
use prost::Message as _;

const SITE: &str = "blog";
const HOSTS: &[&str] = &["example.com", "www.example.com"];

fn hosts() -> Vec<String> {
    HOSTS.iter().map(|h| (*h).to_string()).collect()
}

fn bundle() -> SiteBundle {
    test_site_bundle(SITE, HOSTS, 1_790_000_000)
}

fn sign(b: &SiteBundle) -> Vec<u8> {
    sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID)
}

fn verify(bytes: &[u8]) -> Result<mg_edge_core::bundle::VerifiedBundle, BundleError> {
    verify_bundle(bytes, &owner_test_keys(), SITE, &hosts())
}

fn route(name: &str, paths: &[&str]) -> Route {
    Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: Channel::Web as i32,
        sensitivity: RouteSensitivity::Medium as i32,
        ..Default::default()
    }
}

fn limiter(id: &str) -> RateLimit {
    RateLimit {
        id: id.into(),
        key: vec!["ip".into()],
        algorithm: "gcra".into(),
        rate: 20,
        period_s: 60,
        burst: 5,
        on_exceed: "rate_limit".into(),
        mode: "enforce".into(),
        scope: "global".into(),
        retry_after_s: 60,
        ..Default::default()
    }
}

fn rule(id: &str) -> CompiledRule {
    CompiledRule {
        id: id.into(),
        phase: "custom".into(),
        expr_source: "true".into(),
        ir_version: 1,
        expr_ir: vec![0x08, 0x01],
        action: Action::Block as i32,
        mode: "enforce".into(),
        rollout_percent: 100,
        ..Default::default()
    }
}

fn env(b: &mut SiteBundle) -> &mut Environment {
    &mut b.environments[0]
}

/// A bundle exercising every repeated section with valid values.
fn rich_bundle() -> SiteBundle {
    let mut b = bundle();
    let e = env(&mut b);
    e.routes
        .insert(0, route("login", &["/account/login", "/api/login"]));
    e.routes[0].methods = vec!["GET".into(), "POST".into()];
    e.routes[0].sensitivity = RouteSensitivity::Critical as i32;
    e.routes[0].require_clearance = true;
    e.routes.insert(1, route("reset", &["/account/reset/**"]));
    e.routes[1].redact_path = true;
    let mut rl = limiter("login-per-ip");
    rl.route_ids = vec!["login".into()];
    e.rate_limits.push(rl);
    let mut sig = limiter("api.signal");
    sig.on_exceed = "signal".into();
    sig.signal_weight = 2.0;
    sig.scope = "local".into();
    sig.mode = "dry_run".into();
    e.rate_limits.push(sig);
    let mut ch = limiter("challenge_all");
    ch.on_exceed = "challenge".into();
    ch.challenge_type = ChallengeType::Pow as i32;
    e.rate_limits.push(ch);
    let mut r = rule("block-bad");
    r.params.insert("label".into(), "x".into());
    e.rules.push(r);
    b.lists.insert(
        "owner_cidrs".into(),
        NamedList {
            entries: vec!["203.0.113.0/24".into()],
        },
    );
    let sha = "a".repeat(64);
    b.artifacts.push(ArtifactRef {
        name: "cloudflare-ips".into(),
        uri: format!("artifacts/{sha}"),
        sha256: sha,
        version: "2026-09-27T10:00:00Z".into(),
        size: 720,
    });
    b
}

/// §9.10 / §3.2: a bundle signed by the owner test key verifies, and the
/// result carries the exact bytes and their SHA-256.
#[test]
fn valid_bundle_verifies() {
    for b in [bundle(), rich_bundle()] {
        let bytes = sign(&b);
        let vb = verify(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vb.bundle, b);
        assert_eq!(vb.bytes, bytes);
        assert_eq!(vb.sha256_hex().len(), 64);
        let dbg = format!("{vb:?}");
        assert!(
            dbg.contains("version: 1790000000") && dbg.len() < 300,
            "{dbg}"
        );
    }
}

/// kat.json `bundle_signature.domain_prefix_hex`.
#[test]
fn signing_domain_matches_kat() {
    let kat: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/phase1/kat.json")).unwrap();
    let hex = kat["bundle_signature"]["domain_prefix_hex"]
        .as_str()
        .unwrap();
    let got: String = SIGNING_DOMAIN.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, hex);
    assert_eq!(signing_input(b"xy"), [SIGNING_DOMAIN, b"xy"].concat());
}

/// §8.3: messages absent as a whole are valid (the Edge fills in defaults).
#[test]
fn absent_config_messages_are_valid() {
    let mut b = bundle();
    b.challenge = None;
    b.clearance = None;
    b.scoring = None;
    b.crawler_policy = None;
    b.events = None;
    b.origin_headers = None;
    verify(&sign(&b)).unwrap();
}

/// §9.10: hosts compare as sets (order does not matter).
#[test]
fn hosts_compare_as_sets() {
    let mut b = bundle();
    b.hosts.reverse();
    env(&mut b).hosts.reverse();
    verify(&sign(&b)).unwrap();
}

#[test]
fn bad_signature_is_rejected() {
    let good = sign(&bundle());
    let mut signed = SignedBundle::decode(good.as_slice()).unwrap();

    // Flipped signature bit.
    let mut s = signed.clone();
    s.ed25519_signature[10] ^= 1;
    assert!(matches!(
        verify(&s.encode_to_vec()),
        Err(BundleError::BadSignature)
    ));

    // Flipped bundle bit (signature over the original).
    let mut s = signed.clone();
    let last = s.bundle.len() - 1;
    s.bundle[last] ^= 0x40;
    assert!(matches!(
        verify(&s.encode_to_vec()),
        Err(BundleError::BadSignature)
    ));

    // Wrong signature length, empty signature.
    for sig in [vec![0u8; 63], vec![0u8; 65], Vec::new()] {
        let mut s = signed.clone();
        s.ed25519_signature = sig;
        assert!(matches!(
            verify(&s.encode_to_vec()),
            Err(BundleError::BadSignature)
        ));
    }

    // Signed without the domain prefix.
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(OWNER_TEST_SEED));
    signed.ed25519_signature = kp.sk.sign(&signed.bundle, None).to_vec();
    assert!(matches!(
        verify(&signed.encode_to_vec()),
        Err(BundleError::BadSignature)
    ));
}

#[test]
fn other_key_under_a_trusted_kid_is_rejected() {
    let bytes = sign_test_bundle(&bundle(), &[7u8; 32], OWNER_TEST_KID);
    assert!(matches!(verify(&bytes), Err(BundleError::BadSignature)));
}

#[test]
fn unknown_kid_is_rejected() {
    for kid in ["owner-2026", "", "OWNER-TEST"] {
        let bytes = sign_test_bundle(&bundle(), &OWNER_TEST_SEED, kid);
        assert!(
            matches!(verify(&bytes), Err(BundleError::UnknownKey(k)) if k == kid),
            "{kid}"
        );
    }
    // A second trusted key does not make the first one's bundles invalid.
    let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9u8; 32]));
    let pub2 = format!(
        r#"{{"v":1,"kind":"mg-owner-ed25519-pub","kid":"owner-2027","public_key":"{}","created_at":"2027-01-01T00:00:00Z"}}"#,
        base64_url(other.pk.as_ref())
    );
    let keys = OwnerKeys::from_pub_files(&[
        (
            "owner-test.pub",
            mg_edge_core::testkit::http::OWNER_TEST_PUB,
        ),
        ("owner-2027.pub", pub2.as_bytes()),
    ])
    .unwrap();
    for (seed, kid) in [(OWNER_TEST_SEED, OWNER_TEST_KID), ([9u8; 32], "owner-2027")] {
        let bytes = sign_test_bundle(&bundle(), &seed, kid);
        verify_bundle(&bytes, &keys, SITE, &hosts()).unwrap();
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn truncated_and_garbage_input_is_rejected() {
    let bytes = sign(&bundle());
    for len in [0, 1, 2, 10, bytes.len() / 2, bytes.len() - 1] {
        let err = verify(&bytes[..len]).unwrap_err();
        assert!(
            matches!(
                err,
                BundleError::Decode { .. } | BundleError::UnknownKey(_) | BundleError::BadSignature
            ),
            "len {len}: {err}"
        );
    }
    // Garbage inner bytes under a bad signature: the signature is checked
    // before anything inside is decoded.
    let unsigned = SignedBundle {
        bundle: vec![0xff; 32],
        key_id: OWNER_TEST_KID.into(),
        ed25519_signature: vec![0; 64],
    }
    .encode_to_vec();
    assert!(matches!(verify(&unsigned), Err(BundleError::BadSignature)));
    // A validly signed inner payload that is not a SiteBundle.
    let bytes = sign_test_bytes(&[0xff, 0xff, 0xff], &OWNER_TEST_SEED, OWNER_TEST_KID);
    assert!(matches!(
        verify(&bytes),
        Err(BundleError::Decode {
            what: "SiteBundle",
            ..
        })
    ));
}

/// §8.2 / §9.10: at most 8 MiB of bundle; the signed file may exceed that
/// only by the envelope.
#[test]
fn oversized_bundles_are_rejected() {
    let too_big = vec![0u8; MAX_SIGNED_BUNDLE_BYTES + 1];
    assert!(matches!(
        verify(&too_big),
        Err(BundleError::TooLarge {
            what: "signed bundle",
            ..
        })
    ));

    // Inner bundle of MAX_BUNDLE_BYTES + 1 (fits the envelope allowance).
    let inner = vec![0u8; MAX_BUNDLE_BYTES + 1];
    let signed = SignedBundle {
        bundle: inner,
        key_id: OWNER_TEST_KID.into(),
        ed25519_signature: vec![0; 64],
    }
    .encode_to_vec();
    assert!(signed.len() <= MAX_SIGNED_BUNDLE_BYTES);
    assert!(matches!(
        verify(&signed),
        Err(BundleError::TooLarge { what: "bundle", .. })
    ));

    // A bundle just under 8 MiB (a large named list) still verifies.
    let mut b = bundle();
    let entry = "x".repeat(256);
    for i in 0..3 {
        b.lists.insert(
            format!("big{i}"),
            NamedList {
                entries: vec![entry.clone(); 10_000],
            },
        );
    }
    let bytes = sign(&b);
    assert!(bytes.len() > 7 * 1024 * 1024 && bytes.len() <= MAX_SIGNED_BUNDLE_BYTES);
    verify(&bytes).unwrap();
}

#[test]
fn schema_version_must_be_1() {
    for v in [0, 2, u32::MAX] {
        let mut b = bundle();
        b.schema_version = v;
        assert!(
            matches!(verify(&sign(&b)), Err(BundleError::SchemaVersion(x)) if x == v),
            "{v}"
        );
    }
}

#[test]
fn site_id_must_match() {
    let mut b = bundle();
    b.site_id = "shop".into();
    assert!(matches!(
        verify(&sign(&b)),
        Err(BundleError::SiteMismatch { found, .. }) if found == "shop"
    ));
}

#[test]
fn hosts_must_match_edge_toml() {
    // Subset, superset, different, duplicate.
    let cases: [(&[&str], bool); 4] = [
        (&["example.com"], false),
        (
            &["example.com", "www.example.com", "staging.example.com"],
            false,
        ),
        (&["example.org", "www.example.com"], false),
        (&["example.com", "www.example.com", "example.com"], true),
    ];
    for (hosts_in_bundle, duplicate) in cases {
        let mut b = bundle();
        b.hosts = hosts_in_bundle.iter().map(|h| (*h).to_string()).collect();
        env(&mut b).hosts = b.hosts.clone();
        let err = verify(&sign(&b)).unwrap_err();
        if duplicate {
            assert!(
                matches!(err, BundleError::Invalid { ref field, .. } if field == "hosts"),
                "{err}"
            );
        } else {
            assert!(matches!(err, BundleError::HostsMismatch { .. }), "{err}");
        }
    }
}

type Mutation = fn(&mut SiteBundle);

/// Every §8.2 rule (and the structural rules of §8.3 / config.proto) that
/// the Edge re-checks: each mutation of an otherwise valid bundle must be
/// rejected with an `Invalid` error naming the field.
#[test]
fn bounds_are_enforced() {
    let cases: Vec<(&str, Mutation)> = vec![
        // Bundle-level.
        ("version", |b| b.version = 0),
        ("not_before_ms", |b| b.not_before_ms = -1),
        ("upstream", |b| b.upstream = None),
        ("upstream.kind", |b| {
            b.upstream.as_mut().unwrap().kind = UpstreamProfileKind::ProxyProtocol as i32
        }),
        ("upstream.kind", |b| b.upstream.as_mut().unwrap().kind = 99),
        ("cloudflare", |b| b.cloudflare = None),
        ("cloudflare", |b| {
            b.upstream.as_mut().unwrap().kind = UpstreamProfileKind::DirectTls as i32
        }),
        ("cloudflare.owner_zones[0]", |b| {
            b.cloudflare.as_mut().unwrap().owner_zones = vec!["Example.COM".into()]
        }),
        ("allowed_listeners[0]", |b| {
            b.allowed_listeners = vec!["CF tunnel".into()]
        }),
        ("allowed_listeners[1]", |b| {
            b.allowed_listeners = vec!["cf-tunnel".into(), "cf-tunnel".into()]
        }),
        ("token_key_ids", |b| b.token_key_ids.clear()),
        ("token_key_ids[0]", |b| {
            b.token_key_ids = vec!["-bad".into()]
        }),
        ("token_key_ids[1]", |b| {
            b.token_key_ids = vec!["blog-t-1".into(), "blog-t-1".into()]
        }),
        // Environments and host partition.
        ("environments", |b| b.environments.clear()),
        ("environments[0].name", |b| env(b).name = "prod".into()),
        ("environments[1].name", |b| {
            let mut e = b.environments[0].clone();
            e.hosts = vec!["www.example.com".into()];
            b.environments[0].hosts = vec!["example.com".into()];
            b.environments.push(e);
        }),
        ("environments", |b| {
            env(b).hosts = vec!["example.com".into()]
        }),
        ("environments[0].hosts", |b| {
            env(b).hosts.push("example.org".into())
        }),
        ("environments[0].hosts", |b| {
            env(b).hosts.push("example.com".into())
        }),
        ("environments[0].hosts", |b| env(b).hosts.clear()),
        ("environments[1].hosts", |b| {
            let mut e = b.environments[0].clone();
            e.name = "staging".into();
            e.hosts = vec!["example.com".into()];
            b.environments.push(e);
        }),
        // Routes.
        ("environments[0].routes", |b| {
            let e = env(b);
            e.routes = (0..65).map(|i| route(&format!("r{i}"), &["/x"])).collect();
        }),
        ("environments[0].routes[0].name", |b| {
            env(b).routes.insert(0, route("Login", &["/a"]))
        }),
        ("environments[0].routes[0].name", |b| {
            env(b).routes.insert(0, route(&"a".repeat(33), &["/a"]))
        }),
        ("environments[0].routes[3].name", |b| {
            env(b).routes.insert(0, route("default", &["/a"]))
        }),
        ("environments[0].routes[0].id", |b| {
            let mut r = route("login", &["/a"]);
            r.id = "login-id".into();
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].paths", |b| {
            env(b).routes.insert(0, route("a", &[]))
        }),
        ("environments[0].routes[0].paths", |b| {
            let paths: Vec<String> = (0..17).map(|i| format!("/p{i}")).collect();
            let mut r = route("a", &[]);
            r.paths = paths;
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].paths", |b| {
            // 16 paths plus the deprecated path_glob = 17 patterns.
            let mut r = route("a", &[]);
            r.paths = (0..16).map(|i| format!("/p{i}")).collect();
            r.path_glob = "/legacy".into();
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].paths", |b| {
            env(b).routes.insert(0, route("a", &["account"]))
        }),
        ("environments[0].routes[0].paths", |b| {
            env(b).routes.insert(0, route("a", &["/a b"]))
        }),
        ("environments[0].routes[0].paths", |b| {
            env(b).routes.insert(0, route("a", &["/caf\u{e9}"]))
        }),
        ("environments[0].routes[0].paths", |b| {
            let long = format!("/{}", "a".repeat(128));
            let mut r = route("a", &[]);
            r.paths = vec![long];
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].paths", |b| {
            env(b).routes.insert(0, route("a", &["/*/*/*/*/?"]))
        }),
        ("environments[0].routes[0].paths", |b| {
            let mut r = route("a", &["/a"]);
            r.path_glob = "no-slash".into();
            env(b).routes.insert(0, r);
        }),
        // §8.2 / D-25: with case_insensitive_paths the patterns are stored
        // lower-cased; the Edge lower-cases every path view, so an upper-case
        // pattern would silently never match (a critical route falling
        // through to "default").
        ("environments[0].routes[0].paths", |b| {
            b.case_insensitive_paths = true;
            env(b)
                .routes
                .insert(0, route("signin", &["/account/signin", "/Account/SignIn"]));
        }),
        ("environments[0].routes[0].paths", |b| {
            b.case_insensitive_paths = true;
            let mut r = route("signin", &["/account/signin"]);
            r.path_glob = "/API/signin".into();
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].methods", |b| {
            let mut r = route("a", &["/a"]);
            r.methods = vec!["get".into()];
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].channel", |b| {
            let mut r = route("a", &["/a"]);
            r.channel = Channel::Unspecified as i32;
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].sensitivity", |b| {
            let mut r = route("a", &["/a"]);
            r.sensitivity = 9;
            env(b).routes.insert(0, r);
        }),
        ("environments[0].routes[0].hosts", |b| {
            let mut r = route("a", &["/a"]);
            r.hosts = vec!["example.org".into()];
            env(b).routes.insert(0, r);
        }),
        // Rate limiters.
        ("environments[0].rate_limits", |b| {
            env(b).rate_limits = (0..65).map(|i| limiter(&format!("l{i}"))).collect();
        }),
        ("environments[0].rate_limits[0].id", |b| {
            env(b).rate_limits.insert(0, limiter("mg.c.submit"))
        }),
        ("environments[0].rate_limits[0].id", |b| {
            env(b).rate_limits.insert(0, limiter("Login"))
        }),
        ("environments[0].rate_limits[1].id", |b| {
            env(b).rate_limits.insert(0, limiter("a"));
            env(b).rate_limits.insert(0, limiter("a"));
        }),
        ("environments[0].rate_limits[0].algorithm", |b| {
            let mut l = limiter("a");
            l.algorithm = "token_bucket".into();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            let mut l = limiter("a");
            l.rate = 0;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            let mut l = limiter("a");
            l.period_s = 0;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            let mut l = limiter("a");
            l.period_s = 86_401;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            let mut l = limiter("a");
            l.burst = 0;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            let mut l = limiter("a");
            l.burst = 100_001;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].rate", |b| {
            // interval 86400 s x burst 8 = 8 days: the GCRA state would not
            // stay below 2^53 in Lua doubles (GcraParams::new is None).
            let mut l = limiter("a");
            l.rate = 1;
            l.period_s = 86_400;
            l.burst = 8;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].key", |b| {
            let mut l = limiter("a");
            l.key.clear();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].key", |b| {
            let mut l = limiter("a");
            l.key = vec!["cookie".into()];
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].key", |b| {
            let mut l = limiter("a");
            l.key = vec!["ip".into(), "ip".into()];
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].route_ids", |b| {
            let mut l = limiter("a");
            l.route_ids = vec!["nope".into()];
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].route_ids", |b| {
            let mut l = limiter("a");
            l.route_id = "nope".into();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].scope", |b| {
            let mut l = limiter("a");
            l.scope = "cluster".into();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].mode", |b| {
            let mut l = limiter("a");
            l.mode = "disabled".into();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].on_exceed", |b| {
            let mut l = limiter("a");
            l.on_exceed = "tarpit".into();
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].signal_weight", |b| {
            let mut l = limiter("a");
            l.on_exceed = "signal".into();
            l.signal_weight = 0.0;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].signal_weight", |b| {
            let mut l = limiter("a");
            l.on_exceed = "signal".into();
            l.signal_weight = 2.01;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].signal_weight", |b| {
            let mut l = limiter("a");
            l.on_exceed = "signal".into();
            l.signal_weight = f32::NAN;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].challenge_type", |b| {
            let mut l = limiter("a");
            l.on_exceed = "challenge".into();
            l.challenge_type = ChallengeType::Interactive as i32;
            env(b).rate_limits.insert(0, l);
        }),
        ("environments[0].rate_limits[0].challenge_type", |b| {
            let mut l = limiter("a");
            l.on_exceed = "challenge".into();
            env(b).rate_limits.insert(0, l);
        }),
        // Rules.
        ("environments[0].rules[0].action", |b| {
            let mut r = rule("r");
            r.action = Action::Tarpit as i32;
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].action", |b| {
            let mut r = rule("r");
            r.action = Action::Unspecified as i32;
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].id", |b| {
            env(b).rules.insert(0, rule(""))
        }),
        ("environments[0].rules[0].ir_version", |b| {
            let mut r = rule("r");
            r.ir_version = 0;
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].expr_ir", |b| {
            let mut r = rule("r");
            r.expr_ir.clear();
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].mode", |b| {
            let mut r = rule("r");
            r.mode = "disabled".into();
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].rollout_percent", |b| {
            let mut r = rule("r");
            r.rollout_percent = 101;
            env(b).rules.insert(0, r);
        }),
        ("environments[0].rules[0].params", |b| {
            let mut r = rule("r");
            r.params.insert("provider".into(), "turnstile".into());
            env(b).rules.insert(0, r);
        }),
        // challenge.
        ("challenge.ttl_s", |b| {
            b.challenge.as_mut().unwrap().ttl_s = 9
        }),
        ("challenge.ttl_s", |b| {
            b.challenge.as_mut().unwrap().ttl_s = 121
        }),
        ("challenge.pow_bits", |b| {
            b.challenge.as_mut().unwrap().pow_bits = None
        }),
        ("challenge.pow_bits.low", |b| {
            b.challenge.as_mut().unwrap().pow_bits.as_mut().unwrap().low = 7
        }),
        ("challenge.pow_bits.medium", |b| {
            b.challenge
                .as_mut()
                .unwrap()
                .pow_bits
                .as_mut()
                .unwrap()
                .medium = 25
        }),
        ("challenge.pow_bits.high", |b| {
            b.challenge
                .as_mut()
                .unwrap()
                .pow_bits
                .as_mut()
                .unwrap()
                .high = 0
        }),
        ("challenge.pow_bits.very_high", |b| {
            b.challenge
                .as_mut()
                .unwrap()
                .pow_bits
                .as_mut()
                .unwrap()
                .very_high = 32
        }),
        ("challenge.fallback_ret", |b| {
            b.challenge.as_mut().unwrap().fallback_ret = String::new()
        }),
        ("challenge.fallback_ret", |b| {
            b.challenge.as_mut().unwrap().fallback_ret = "//evil.example/".into()
        }),
        ("challenge.fallback_ret", |b| {
            b.challenge.as_mut().unwrap().fallback_ret = "/__mg/c".into()
        }),
        ("challenge.fallback_ret", |b| {
            b.challenge.as_mut().unwrap().fallback_ret = "/a#b".into()
        }),
        ("challenge.max_failures", |b| {
            b.challenge.as_mut().unwrap().max_failures = 0
        }),
        ("challenge.max_failures", |b| {
            b.challenge.as_mut().unwrap().max_failures = 1001
        }),
        ("challenge.failure_window_s", |b| {
            b.challenge.as_mut().unwrap().failure_window_s = 59
        }),
        ("challenge.failure_window_s", |b| {
            b.challenge.as_mut().unwrap().failure_window_s = 86_401
        }),
        ("challenge.submit", |b| {
            b.challenge.as_mut().unwrap().submit_rate = 0
        }),
        ("challenge.submit", |b| {
            b.challenge.as_mut().unwrap().submit_period_s = 86_401
        }),
        ("challenge.submit", |b| {
            b.challenge.as_mut().unwrap().submit_burst = 100_001
        }),
        ("challenge.issue_per_ipp", |b| {
            b.challenge.as_mut().unwrap().issue_per_ipp = 0
        }),
        ("challenge.issue_per_asn", |b| {
            b.challenge.as_mut().unwrap().issue_per_asn = 100_001
        }),
        ("challenge.issue_per_ipp", |b| {
            b.challenge.as_mut().unwrap().issue_period_s = 0
        }),
        // clearance.
        ("clearance.ttl_invisible_s", |b| {
            b.clearance.as_mut().unwrap().ttl_invisible_s = 59
        }),
        ("clearance.ttl_pow_s", |b| {
            b.clearance.as_mut().unwrap().ttl_pow_s = 86_401
        }),
        ("clearance.session_max_s", |b| {
            b.clearance.as_mut().unwrap().session_max_s = 1799
        }),
        ("clearance.session_max_s", |b| {
            b.clearance.as_mut().unwrap().session_max_s = 30 * 86_400 + 1
        }),
        // scoring, crawler policy, events.
        ("scoring.theta_c", |b| {
            b.scoring.as_mut().unwrap().theta_c = f32::NAN
        }),
        ("scoring.h_min", |b| {
            b.scoring.as_mut().unwrap().h_min = f32::NEG_INFINITY
        }),
        ("scoring.z0", |b| {
            b.scoring.as_mut().unwrap().z0.insert("extreme".into(), 0.0);
        }),
        ("scoring.family_modes", |b| {
            b.scoring
                .as_mut()
                .unwrap()
                .family_modes
                .insert("edge_tls".into(), "loud".into());
        }),
        ("scoring.family_modes", |b| {
            b.scoring
                .as_mut()
                .unwrap()
                .family_modes
                .insert("ja4".into(), "off".into());
        }),
        ("scoring.weights", |b| {
            b.scoring
                .as_mut()
                .unwrap()
                .weights
                .insert("http.ua_library".into(), f32::INFINITY);
        }),
        ("crawler_policy.default_action", |b| {
            b.crawler_policy.as_mut().unwrap().default_action = String::new()
        }),
        ("crawler_policy.purposes[ai_training]", |b| {
            b.crawler_policy
                .as_mut()
                .unwrap()
                .purposes
                .insert("ai_training".into(), "tarpit".into());
        }),
        ("crawler_policy.purposes[spam]", |b| {
            b.crawler_policy
                .as_mut()
                .unwrap()
                .purposes
                .insert("spam".into(), "block".into());
        }),
        ("events.allow_sample_rate", |b| {
            b.events.as_mut().unwrap().allow_sample_rate = 1.5
        }),
        ("events.allow_sample_rate", |b| {
            b.events.as_mut().unwrap().allow_sample_rate = f32::NAN
        }),
        // Named lists.
        ("lists[Owner]", |b| {
            b.lists.insert("Owner".into(), NamedList::default());
        }),
        ("lists[big]", |b| {
            b.lists.insert(
                "big".into(),
                NamedList {
                    entries: vec!["x".into(); 10_001],
                },
            );
        }),
        ("lists[long]", |b| {
            b.lists.insert(
                "long".into(),
                NamedList {
                    entries: vec!["x".repeat(257)],
                },
            );
        }),
        // Artifacts.
        ("artifacts[1].name", |b| {
            b.artifacts[1].name = "maxmind".into()
        }),
        ("artifacts[1].name", |b| {
            b.artifacts[1].name = "cloudflare-ips".into()
        }),
        ("artifacts[1].sha256", |b| {
            b.artifacts[1].sha256 = "B".repeat(64);
            b.artifacts[1].uri = format!("artifacts/{}", "B".repeat(64));
        }),
        ("artifacts[1].sha256", |b| {
            b.artifacts[1].sha256 = "../../etc/passwd".into();
            b.artifacts[1].uri = "artifacts/../../etc/passwd".into();
        }),
        ("artifacts[1].uri", |b| {
            b.artifacts[1].uri = "https://elsewhere.example/x".into()
        }),
        ("artifacts[1].size", |b| {
            b.artifacts[1].size = 4 * 1024 * 1024 + 1
        }),
    ];

    for (field, mutate) in cases {
        let mut b = rich_bundle();
        let sha = "b".repeat(64);
        b.artifacts.push(ArtifactRef {
            name: "datacenter-asns".into(),
            uri: format!("artifacts/{sha}"),
            sha256: sha,
            version: String::new(),
            size: 65,
        });
        verify(&sign(&b)).unwrap_or_else(|e| panic!("base bundle for {field}: {e}"));
        mutate(&mut b);
        match verify(&sign(&b)) {
            Err(BundleError::Invalid { field: got, reason }) => {
                assert_eq!(got, field, "reason: {reason}")
            }
            other => panic!("{field}: expected Invalid, got {other:?}"),
        }
    }
}

/// Boundary values that must still be accepted (the other side of each
/// §8.2 limit).
#[test]
fn bound_edges_are_accepted() {
    let cases: Vec<(&str, Mutation)> = vec![
        ("64 routes plus the builder's default", |b| {
            let e = env(b);
            let default = e.routes.pop().unwrap();
            e.rate_limits.clear();
            e.routes = (0..64).map(|i| route(&format!("r{i}"), &["/x"])).collect();
            e.routes.push(default);
        }),
        ("64 routes without a default", |b| {
            env(b).rate_limits.clear();
            env(b).routes = (0..64).map(|i| route(&format!("r{i}"), &["/x"])).collect();
        }),
        ("64 limiters", |b| {
            env(b).rate_limits = (0..64).map(|i| limiter(&format!("l{i}"))).collect();
        }),
        ("16 patterns, 128 bytes, 4 wildcards", |b| {
            let mut r = route("a", &[]);
            r.paths = (0..15).map(|i| format!("/p{i}")).collect();
            r.paths.push(format!("/**/*/?/{}*", "a".repeat(119)));
            assert_eq!(r.paths[15].len(), 128);
            env(b).routes.insert(0, r);
        }),
        ("upper-case patterns in a case-sensitive site", |b| {
            env(b)
                .routes
                .insert(0, route("signin", &["/Account/SignIn"]));
        }),
        ("lower-case patterns in a case-insensitive site", |b| {
            b.case_insensitive_paths = true;
            let mut r = route("signin", &["/account/signin", "/api/**/x?"]);
            r.path_glob = "/legacy/signin".into();
            env(b).routes.insert(0, r);
        }),
        ("15 paths plus path_glob", |b| {
            let mut r = route("a", &[]);
            r.paths = (0..15).map(|i| format!("/p{i}")).collect();
            r.path_glob = "/legacy/**".into();
            env(b).routes.insert(0, r);
        }),
        ("challenge limits", |b| {
            let c = b.challenge.as_mut().unwrap();
            c.ttl_s = 10;
            let bits = c.pow_bits.as_mut().unwrap();
            (bits.low, bits.medium, bits.high, bits.very_high) = (8, 8, 24, 24);
            c.max_failures = 1000;
            c.failure_window_s = 86_400;
            c.submit_burst = 100_000;
            c.submit_rate = 100_000;
            c.submit_period_s = 1;
        }),
        ("clearance limits", |b| {
            let c = b.clearance.as_mut().unwrap();
            c.ttl_invisible_s = 60;
            c.ttl_pow_s = 86_400;
            c.session_max_s = 86_400;
        }),
        ("session_max_s of 30 days", |b| {
            b.clearance.as_mut().unwrap().session_max_s = 30 * 86_400
        }),
        ("empty scope and mode mean the defaults", |b| {
            let mut l = limiter("a");
            l.scope.clear();
            l.mode.clear();
            env(b).rate_limits.push(l);
        }),
        ("block limiter with a composite key", |b| {
            let mut l = limiter("a");
            l.on_exceed = "block".into();
            l.key = vec![
                "ip_prefix".into(),
                "route".into(),
                "asn".into(),
                "session".into(),
            ];
            env(b).rate_limits.push(l);
        }),
        ("10000-entry list of 256-byte entries", |b| {
            b.lists.insert(
                "max".into(),
                NamedList {
                    entries: vec!["x".repeat(256); 10_000],
                },
            );
        }),
        ("direct_tls without cloudflare", |b| {
            b.upstream.as_mut().unwrap().kind = UpstreamProfileKind::DirectTls as i32;
            b.cloudflare = None;
        }),
        ("two environments partitioning the hosts", |b| {
            let mut e = b.environments[0].clone();
            e.name = "staging".into();
            e.hosts = vec!["www.example.com".into()];
            b.environments[0].hosts = vec!["example.com".into()];
            b.environments.push(e);
        }),
        // §12.4: a text list may be empty (the builder and mg-intel accept
        // a 0-byte file); only the §12.1 upper limits apply.
        ("empty text artifact", |b| {
            let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            b.artifacts.push(ArtifactRef {
                name: "tor-exits".into(),
                uri: format!("artifacts/{sha}"),
                sha256: sha.into(),
                version: String::new(),
                size: 0,
            });
        }),
        ("largest artifacts", |b| {
            for (i, (name, size)) in [("geoip-asn", 128u64 << 20), ("tor-exits", 16 << 20)]
                .into_iter()
                .enumerate()
            {
                let sha = format!("{i:0>64}");
                b.artifacts.push(ArtifactRef {
                    name: name.into(),
                    uri: format!("artifacts/{sha}"),
                    sha256: sha,
                    version: String::new(),
                    size,
                });
            }
        }),
    ];
    for (what, mutate) in cases {
        let mut b = rich_bundle();
        mutate(&mut b);
        verify(&sign(&b)).unwrap_or_else(|e| panic!("{what}: {e}"));
    }
}
