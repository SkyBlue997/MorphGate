//! Route matching (docs/impl/phase1-spec.md §9.4 step 6, D-25) on converted
//! bundles: every spelling an origin may treat as the login page selects the
//! `critical` route; `case_insensitive_paths` decides whether letter case
//! matters; the most sensitive match wins and `require_clearance` /
//! `fail_closed` are OR-ed over every match. The first test runs the real
//! binary with WP-G2's golden bundle as the LKG.

mod common;

use common::{TestEnv, cf, get, repo};
use mg_core::RouteSensitivity;
use mg_edge::config::{CredRef, EdgeConfig};
use mg_edge::creds::{CredResolver, read_secret};
use mg_edge::sites::{
    BundleRuntime, RouteRuntime, SiteKeys, SiteSettings, build_runtime, select_route,
};
use mg_edge_core::bundle::verify_bundle;
use mg_edge_core::testkit::http::owner_test_keys;
use mg_proto::v1::{Channel, Route, RouteSensitivity as PbSensitivity, SiteBundle};
use std::collections::BTreeMap;

const LOGIN_SPELLINGS: [&str; 6] = [
    "/account/login",
    "/account/login/",
    "/account%2Flogin",
    "/account/login;x",
    "//account/./login",
    "/api/../account/login",
];

#[test]
fn golden_bundle_routes_every_login_spelling_to_the_critical_route() {
    let env = TestEnv::new("routing-golden");
    let golden = std::fs::read(repo(
        "control-plane/testdata/sites/golden/golden-norules.bundle",
    ))
    .unwrap();
    env.write_lkg("blog", &golden);
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| {
        v == 1_790_000_000.0
    });

    // golden-norules.bundle has case_insensitive_paths = true.
    let mut paths: Vec<&str> = LOGIN_SPELLINGS.to_vec();
    paths.extend(["/Account/Login", "/ACCOUNT/LOGIN/"]);
    // One client address per request: the bundle's login-per-ip limiter
    // (burst 5) would otherwise decide the later ones.
    for (i, path) in paths.into_iter().enumerate() {
        let ip = format!("198.51.100.{}", 10 + i);
        let r = get(env.listen, "example.com", path, &cf(&ip));
        assert_eq!(r.status, 200, "{path}");
        let seen = env.origin.seen().pop().unwrap();
        let id = seen.header("mg-request-id").unwrap().to_owned();
        let line = edge.request_log(&id).expect("request log line");
        assert!(line.contains(" route=login "), "{path}: {line}");
        // Monitor: evaluated (the critical route requires a clearance) and
        // forwarded.
        assert!(
            line.contains(" rule=matrix.clearance.required "),
            "{path}: {line}"
        );
        assert!(line.contains(" dry_run=true "), "{path}: {line}");
    }
    for (path, route) in [
        ("/account/reset/abc", "reset"),
        ("/api/items", "api"),
        ("/blog/post", "default"),
    ] {
        get(env.listen, "example.com", path, &cf("198.51.100.7"));
        let id = env
            .origin
            .seen()
            .pop()
            .unwrap()
            .header("mg-request-id")
            .unwrap()
            .to_owned();
        let line = edge.request_log(&id).unwrap();
        assert!(line.contains(&format!(" route={route} ")), "{path}: {line}");
    }
    // login is GET / POST only; staging.example.com is another environment.
    let req = "DELETE /account/login HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 198.51.100.7\r\nConnection: close\r\n\r\n";
    common::raw(env.listen, req.as_bytes()).unwrap();
    let id = env
        .origin
        .seen()
        .pop()
        .unwrap()
        .header("mg-request-id")
        .unwrap()
        .to_owned();
    assert!(edge.request_log(&id).unwrap().contains(" route=default "));
    // ... in any letter case (origin frameworks normalize it).
    let req = "post /account/login HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 198.51.100.7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    common::raw(env.listen, req.as_bytes()).unwrap();
    let seen = env.origin.seen().pop().unwrap();
    assert!(
        seen.line.starts_with("post /account/login "),
        "{}",
        seen.line
    );
    let id = seen.header("mg-request-id").unwrap().to_owned();
    assert!(edge.request_log(&id).unwrap().contains(" route=login "));
    // HEAD of the GET / POST route selects it too: origins answer HEAD with
    // the GET handler, so it must not fall through to the default route.
    let req = "HEAD /account/login HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 198.51.100.8\r\nConnection: close\r\n\r\n";
    common::raw(env.listen, req.as_bytes()).unwrap();
    let seen = env.origin.seen().pop().unwrap();
    assert!(
        seen.line.starts_with("HEAD /account/login "),
        "{}",
        seen.line
    );
    let id = seen.header("mg-request-id").unwrap().to_owned();
    let line = edge.request_log(&id).unwrap();
    assert!(line.contains(" route=login "), "{line}");
    assert!(line.contains(" rule=matrix.clearance.required "), "{line}");
    get(
        env.listen,
        "staging.example.com",
        "/account/login",
        &cf("198.51.100.7"),
    );
    let id = env
        .origin
        .seen()
        .pop()
        .unwrap()
        .header("mg-request-id")
        .unwrap()
        .to_owned();
    assert!(edge.request_log(&id).unwrap().contains(" route=default "));
}

fn route(name: &str, paths: &[&str], sensitivity: PbSensitivity) -> Route {
    Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: Channel::Web as i32,
        sensitivity: sensitivity as i32,
        fail_closed: sensitivity == PbSensitivity::Critical,
        require_clearance: sensitivity == PbSensitivity::Critical,
        ..Default::default()
    }
}

/// Converts `b` exactly as the Edge does (verify, then build the runtime).
fn runtime(b: &SiteBundle) -> BundleRuntime {
    let text = format!(
        "{}\n",
        common::TestEnv::new("routing-cfg").default_config("")
    );
    let cfg = EdgeConfig::from_toml_str(&text).unwrap();
    let settings = SiteSettings::new(&cfg.sites[0], &cfg);
    let resolver = CredResolver::with_dir(None);
    let token = CredRef::Path(repo("testdata/phase1/keys/token.keys.json"));
    let seal = std::fs::read(repo("testdata/phase1/keys/seal.root.json")).unwrap();
    let keys = SiteKeys {
        seal: mg_challenge::SealKeys::from_key_file(&seal, "blog").unwrap(),
        token_file: read_secret(&resolver, &token, &mut |_| {}).unwrap(),
    };
    let signed = common::sign(b);
    let vb = verify_bundle(&signed, &owner_test_keys(), "blog", &settings.hosts).unwrap();
    build_runtime(&settings, &keys, &vb, &BTreeMap::new()).unwrap()
}

fn select<'a>(rt: &'a BundleRuntime, method: &str, path: &str) -> (&'a RouteRuntime, bool, bool) {
    static FALLBACK: std::sync::LazyLock<RouteRuntime> =
        std::sync::LazyLock::new(RouteRuntime::fallback);
    let env = rt.env_for_host("example.com").unwrap();
    let m = select_route(
        env,
        "example.com",
        method,
        path,
        rt.case_insensitive_paths,
        &FALLBACK,
    );
    (m.route, m.require_clearance, m.fail_closed)
}

#[test]
fn case_insensitive_paths_follow_the_bundle() {
    let mut b = common::blog_bundle(1);
    b.environments[0].routes = vec![
        route("login", &["/account/login"], PbSensitivity::Critical),
        route("default", &["/**"], PbSensitivity::Low),
    ];
    let sensitive = runtime(&b);
    for path in LOGIN_SPELLINGS {
        assert_eq!(select(&sensitive, "GET", path).0.name, "login", "{path}");
    }
    assert_eq!(
        select(&sensitive, "GET", "/Account/Login").0.name,
        "default"
    );

    b.case_insensitive_paths = true;
    let insensitive = runtime(&b);
    for path in ["/Account/Login", "/ACCOUNT/LOGIN/", "/Account%2FLogin"] {
        let (r, clearance, fail_closed) = select(&insensitive, "GET", path);
        assert_eq!(r.name, "login", "{path}");
        assert_eq!(r.sensitivity, RouteSensitivity::Critical);
        assert!(clearance && fail_closed);
    }
}

#[test]
fn most_sensitive_match_wins_and_flags_are_ored() {
    let mut b = common::blog_bundle(1);
    let mut raw_view = route("raw-view", &["/a%2Fb"], PbSensitivity::Medium);
    raw_view.require_clearance = true;
    let mut decoded = route("decoded", &["/a/b"], PbSensitivity::High);
    decoded.fail_closed = true;
    b.environments[0].routes = vec![
        raw_view,
        decoded,
        route("default", &["/**"], PbSensitivity::Low),
    ];
    let rt = runtime(&b);
    let (r, clearance, fail_closed) = select(&rt, "GET", "/a%2Fb");
    assert_eq!(r.name, "decoded", "the high route wins over the medium one");
    assert!(
        clearance,
        "require_clearance is OR-ed over every matched route"
    );
    assert!(fail_closed);
    let (r, clearance, _) = select(&rt, "GET", "/c");
    assert_eq!(r.name, "default");
    assert!(!clearance);
}
