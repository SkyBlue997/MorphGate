//! Unit tests of `/__mg/s/*` and the `POST /__mg/c` flow
//! (docs/impl/phase1-spec.md §10.3, §10.4, §9.7, §9.8), run in process
//! against the local state layer with fake request bodies. The end-to-end
//! tests through the binary are in `edge/tests/challenge_flow.rs`.

use super::*;
use crate::challenge::{IssueRequest, issue};
use crate::config::{BootstrapMode, CredRef, ListenerProfile, LkgInvalidMode};
use crate::context::{Facts, TlsInfo};
use crate::creds::{CredResolver, read_secret};
use crate::rng::OsRng;
use crate::sites::{SiteKeys, SiteSettings, build_runtime};
use mg_challenge::{RngError, SealKeys, pow_solve};
use mg_core::{Channel, RouteInfo, RouteSensitivity, UpstreamProfileKind};
use mg_edge_core::bundle::verify_bundle;
use mg_edge_core::state::{StateConfig, StateService};
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_SEED, owner_test_keys, sign_test_bundle, test_site_bundle,
};
use mg_proto::v1 as pb;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const HOSTS: [&str; 3] = ["example.com", "www.example.com", "staging.example.com"];
const HOST: &str = "example.com";
const ID: &str = "0123456789abcdef0123456789abcdef";
const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";
const IP: &str = "198.51.100.7";
const BUILD: &str = "1df90640e0c5fec4";

fn repo(rel: &str) -> std::path::PathBuf {
    crate::test_support::repo(rel)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn route(name: &str, paths: &[&str], s: pb::RouteSensitivity, fail_closed: bool) -> pb::Route {
    pb::Route {
        id: name.into(),
        name: name.into(),
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
        channel: pb::Channel::Web as i32,
        sensitivity: s as i32,
        require_clearance: true,
        fail_closed,
        ..Default::default()
    }
}

/// The test site: enforce, low difficulties (8 / 9 / 10 / 11 bits) so the
/// reference solver is fast, a `fail_closed` login route and a
/// non-`fail_closed` members route. The submission and failure quotas are
/// generous so that tests of other steps can submit many times; the quota
/// tests set their own.
fn test_bundle() -> pb::SiteBundle {
    let mut b = test_site_bundle("blog", &HOSTS, 1);
    b.monitor_only = false;
    let c = b.challenge.as_mut().unwrap();
    c.max_failures = 1000;
    c.submit_rate = 1000;
    c.submit_burst = 1000;
    c.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 9,
        high: 10,
        very_high: 11,
    });
    c.fallback_ret = "/home".into();
    b.environments[0].routes = vec![
        route(
            "login",
            &["/account/login"],
            pb::RouteSensitivity::Critical,
            true,
        ),
        route(
            "members",
            &["/members/**"],
            pb::RouteSensitivity::Medium,
            false,
        ),
        route("default", &["/**"], pb::RouteSensitivity::Low, false),
    ];
    b.environments[0].routes[2].require_clearance = false;
    b
}

fn settings() -> SiteSettings {
    SiteSettings {
        id: "blog".into(),
        hosts: HOSTS.iter().map(|h| (*h).to_string()).collect(),
        listeners: vec!["cf-tunnel".into()],
        listener_kinds: vec![("cf-tunnel".into(), UpstreamProfileKind::Cloudflare)],
        origin: "127.0.0.1:9".parse().unwrap(),
        bootstrap: BootstrapMode::Open,
        on_lkg_invalid: LkgInvalidMode::Closed,
        bootstrap_owner_zones: Vec::new(),
        crawler_cache: mg_intel::CacheConfig::default(),
    }
}

fn keys() -> SiteKeys {
    let seal = std::fs::read(repo("testdata/phase1/keys/seal.root.json")).unwrap();
    let token = CredRef::Path(repo("testdata/phase1/keys/token.keys.json"));
    SiteKeys {
        seal: SealKeys::from_key_file(&seal, "blog").unwrap(),
        token_file: read_secret(&CredResolver::with_dir(None), &token, &mut |_| {}).unwrap(),
    }
}

/// Converts `b` exactly as the Edge does (verify, then build the runtime).
fn runtime(b: &pb::SiteBundle) -> BundleRuntime {
    let signed = sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID);
    let s = settings();
    let vb = verify_bundle(&signed, &owner_test_keys(), "blog", &s.hosts).unwrap();
    build_runtime(&s, &keys(), &vb, &BTreeMap::new()).unwrap()
}

/// One site with its state layer.
struct Fixture {
    bundle: BundleRuntime,
    sealer: Sealer,
    sdk: SdkDir,
    state: StateHandle,
    _service: StateService,
}

impl Fixture {
    fn new(b: &pb::SiteBundle) -> Self {
        Self::with_state(b, |_| {})
    }

    fn with_state(b: &pb::SiteBundle, tune: impl FnOnce(&mut StateConfig)) -> Self {
        let mut cfg = StateConfig::local([7; 32]);
        cfg.local_replay_authoritative = true;
        tune(&mut cfg);
        let (service, state) = StateService::new(cfg);
        Self {
            bundle: runtime(b),
            sealer: Sealer::new("blog", keys().seal),
            sdk: SdkDir::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk"))
                .unwrap(),
            state,
            _service: service,
        }
    }
}

/// A request to `/__mg/c` from `ip` (none: the client IP is unknown).
struct Req {
    ip: Option<String>,
    headers: Vec<(String, Vec<u8>)>,
    host: String,
}

impl Req {
    fn new(ua: &str, content_type: &str) -> Self {
        Self {
            ip: Some(IP.into()),
            headers: vec![
                ("Host".into(), HOST.into()),
                ("User-Agent".into(), ua.into()),
                ("Content-Type".into(), content_type.into()),
                ("Accept-Language".into(), "zh-CN,zh;q=0.9".into()),
            ],
            host: HOST.into(),
        }
    }

    fn json() -> Self {
        Self::new(CHROME, "application/json")
    }

    fn form() -> Self {
        let mut r = Self::new(CHROME, "application/x-www-form-urlencoded");
        r.headers.push(("Sec-Fetch-Mode".into(), "navigate".into()));
        r
    }

    fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.as_bytes().to_vec()));
        self
    }

    fn built(&self, env: &str) -> Built {
        let route = RouteInfo {
            id: "__mg".into(),
            name: "__mg".into(),
            env: env.into(),
            channel: Channel::Web,
            sensitivity: RouteSensitivity::Low,
            require_clearance: false,
            fail_closed: false,
        };
        let removed = BTreeSet::new();
        let facts = Facts {
            request_id: ID,
            ts_ms: now_ms(),
            site_id: "blog",
            route: &route,
            profile: ListenerProfile::DirectTls,
            auth_method: "none",
            cf: None,
            location_headers: false,
            client_ip: self.ip.as_ref().map(|ip| ip.parse().unwrap()),
            tls: Some(TlsInfo::default()),
            http_version: "HTTP/1.1",
            method: "POST",
            host: &self.host,
            path: "/__mg/c",
            query: "",
            raw_headers: &self.headers,
            removed: &removed,
            expected_mask: 0,
        };
        crate::context::build(&facts, &crate::sites::Intel::default())
    }
}

/// The bindings of a request (as the proxy computes them).
fn bind_of(built: &Built) -> BindInputs {
    crate::identity::bind_inputs(&built.ua, &built.ctx.net, built.ctx.edge_tls.as_ref(), true)
}

/// A request body delivered in chunks.
struct Chunks(Vec<Bytes>);

#[async_trait]
impl BodySource for Chunks {
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
        Ok((!self.0.is_empty()).then(|| self.0.remove(0)))
    }
}

/// A body that never arrives.
struct Stalled;

#[async_trait]
impl BodySource for Stalled {
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
        std::future::pending().await
    }
}

/// A body that must not be read: the answer comes before it.
struct Untouched;

#[async_trait]
impl BodySource for Untouched {
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
        panic!("the body was read")
    }
}

#[derive(Debug)]
struct FailingRng;

impl Rng for FailingRng {
    fn fill(&self, _dst: &mut [u8]) -> Result<(), RngError> {
        Err(RngError)
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A challenge sealed for `req` on `route_class` returning to `ret`.
fn challenge_for(
    f: &Fixture,
    req: &Req,
    ty: ChallengeType,
    band: RiskBand,
    route_class: &str,
    ret: &str,
    now: i64,
) -> (String, u32) {
    let built = req.built("production");
    let bind = bind_of(&built);
    let bits = challenge::difficulty(&pow_bits(&f.bundle.challenge), ty, band);
    let issued = issue(
        &IssueRequest {
            sealer: &f.sealer,
            host: HOST,
            route_class,
            ty,
            band,
            bits,
            ttl_s: 120,
            ret,
            bind: &bind,
            now_ms: now,
        },
        &OsRng,
    )
    .unwrap();
    (issued.c, bits)
}

/// The submission JSON for `c` with a solved counter.
fn solved(c: &str, ty: ChallengeType, bits: u32, ret: &str, extra: Value) -> Value {
    let counter = pow_solve(c, bits, 1 << 24).unwrap();
    let mut v = json!({"v": 1, "type": ty.as_str(), "c": c, "pow": {"counters": [counter]},
                       "ret": ret, "ts": 1_790_000_000_123u64, "build": BUILD});
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e);
    }
    v
}

/// `mg=<json>` as the browser's form serializer writes it.
fn form_body(json: &str) -> Vec<u8> {
    let mut out = b"mg=".to_vec();
    for b in json.bytes() {
        match b {
            b' ' => out.push(b'+'),
            b'*' | b'-' | b'.' | b'_' => out.push(b),
            b if b.is_ascii_alphanumeric() => out.push(b),
            b => out.extend(format!("%{b:02X}").bytes()),
        }
    }
    out
}

/// Runs one submission of `body` for `req`.
fn run(f: &Fixture, req: &Req, body: &mut dyn BodySource) -> Submitted {
    run_at(f, req, body, now_ms(), &OsRng)
}

fn run_at(f: &Fixture, req: &Req, body: &mut dyn BodySource, now: i64, rng: &dyn Rng) -> Submitted {
    run_bound(f, req, body, now, rng, None)
}

/// [`run_at`] with the request's bindings replaced by `bind`.
fn run_bound(
    f: &Fixture,
    req: &Req,
    body: &mut dyn BodySource,
    now: i64,
    rng: &dyn Rng,
    bind: Option<BindInputs>,
) -> Submitted {
    let env = f.bundle.env_for_host(&req.host).unwrap();
    let built = req.built(&env.name);
    let bind = bind.unwrap_or_else(|| bind_of(&built));
    let s = Submit {
        request_id: ID,
        now_ms: now,
        site_id: "blog",
        sealer: &f.sealer,
        sdk: &f.sdk,
        bundle: &f.bundle,
        env,
        host: &req.host,
        built: &built,
        bind: &bind,
        content_encoding: crate::context::received(&req.headers, "content-encoding"),
    };
    rt().block_on(submit(&f.state, rng, &s, body))
}

fn run_json(f: &Fixture, req: &Req, v: &Value) -> Submitted {
    run(f, req, &mut Chunks(vec![Bytes::from(v.to_string())]))
}

fn header<'a>(r: &'a EdgeResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn body_json(r: &EdgeResponse) -> Value {
    serde_json::from_str(r.body_text()).unwrap()
}

/// The clearance token of a success answer, verified.
fn token_claims(f: &Fixture, r: &EdgeResponse, now_s: i64) -> mg_challenge::ClearanceClaims {
    let cookie = header(r, "Set-Cookie").expect("Set-Cookie");
    let token = cookie
        .strip_prefix("__Host-mg_clr=")
        .and_then(|c| c.split(';').next())
        .unwrap();
    mg_challenge::verify(&f.bundle.token_keys, "blog", "production", token, now_s).unwrap()
}

fn reasons(s: &Submitted) -> Vec<&str> {
    s.record
        .feedback
        .reason_codes
        .iter()
        .map(String::as_str)
        .collect()
}

// ---------------------------------------------------------------------------
// /__mg/s/<file> (§10.4)

#[test]
fn sdk_files_are_served_from_the_manifest_only() {
    let f = Fixture::new(&test_bundle());
    let path = format!("/__mg/s/{}", f.sdk.sdk);
    for method in ["GET", "HEAD"] {
        let r = sdk_file(&f.sdk, &path, method);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, f.sdk.files[&f.sdk.sdk]);
        assert!(!r.close);
        let h = r.header().unwrap();
        assert_eq!(h.headers["content-type"], "text/javascript; charset=utf-8");
        assert_eq!(h.headers["cache-control"], IMMUTABLE);
        assert_eq!(h.headers["x-content-type-options"], "nosniff");
        assert!(h.headers.get("content-security-policy").is_none());
    }
    for name in [
        "challenge.html",
        "manifest.json",
        "mg.js",
        "",
        "..",
        "../manifest.json",
        "%2e%2e/manifest.json",
        &format!("{}/x", f.sdk.sdk),
        &format!("{}?v=1", f.sdk.sdk),
        &f.sdk.sdk.to_uppercase(),
    ] {
        let r = sdk_file(&f.sdk, &format!("/__mg/s/{name}"), "GET");
        assert_eq!(r.status, 404, "{name}");
        assert_eq!(
            r.header().unwrap().headers["cache-control"],
            "no-store, private"
        );
    }
    let r = sdk_file(&f.sdk, &path, "POST");
    assert_eq!(r.status, 405);
    assert_eq!(header(&r, "Allow"), Some("GET, HEAD"));
}

// ---------------------------------------------------------------------------
// Pieces

#[test]
fn failure_counting_follows_the_spec_list() {
    for code in [
        "ic.body",
        "ic.c_invalid",
        "ic.c_kid",
        "ic.bind_uah",
        "ic.bind_ipp",
        "ic.pow",
        "ic.ret",
        "ic.automation_flag",
        "ic.ua_mismatch",
        "ic.nonce_reused",
    ] {
        assert!(counts_as_failure(code), "{code}");
    }
    for code in [
        "ic.c_expired",
        "ic.replay_unavailable",
        "ic.no_client_ip",
        "ic.issue_quota",
        "ic.rate_limited",
        "ic.too_early",
        "ic.bind_ipp_soft",
        "ic.replay_unchecked",
    ] {
        assert!(!counts_as_failure(code), "{code}");
    }
}

/// §10.3 step 3: at most 8192 bytes, the whole body within the deadline.
#[test]
fn body_reading_limits() {
    let rt = rt();
    let exact = vec![Bytes::from(vec![b'a'; 4096]), Bytes::from(vec![b'b'; 4096])];
    assert!(matches!(
        rt.block_on(read_body(&mut Chunks(exact), MAX_BODY, BODY_DEADLINE)),
        BodyRead::Complete(b) if b.len() == MAX_BODY
    ));
    let over = vec![Bytes::from(vec![b'a'; 8192]), Bytes::from_static(b"x")];
    assert_eq!(
        rt.block_on(read_body(&mut Chunks(over), MAX_BODY, BODY_DEADLINE)),
        BodyRead::TooLarge
    );
    assert_eq!(
        rt.block_on(read_body(&mut Stalled, MAX_BODY, Duration::from_millis(20))),
        BodyRead::Timeout
    );
    struct Broken;
    #[async_trait]
    impl BodySource for Broken {
        async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
            Err(BodyReadError)
        }
    }
    assert_eq!(
        rt.block_on(read_body(&mut Broken, MAX_BODY, BODY_DEADLINE)),
        BodyRead::Error
    );
    assert_eq!(
        rt.block_on(read_body(&mut Chunks(Vec::new()), MAX_BODY, BODY_DEADLINE)),
        BodyRead::Complete(Vec::new())
    );
}

/// §9.7 rule 5: the named route OR the route of `ret`; a route that is gone
/// is `fail_closed`.
#[test]
fn replay_fail_closed_resolution() {
    let f = Fixture::new(&test_bundle());
    let env = f.bundle.env_for_host(HOST).unwrap();
    let fc = |class: &str, ret: &str| replay_fail_closed(&f.bundle, env, HOST, class, ret);
    assert!(fc("login", "/account/login"));
    assert!(!fc("members", "/members/a?x=1"));
    // The named route is not fail_closed, but ret selects one that is.
    assert!(fc("members", "/account/login?next=/"));
    assert!(
        fc("default", "/account/login/"),
        "ret is matched on every view"
    );
    assert!(
        fc("default", "/account%2Flogin"),
        "ret is matched on every view"
    );
    assert!(!fc("default", "/Account/Login"), "case-sensitive paths");
    assert!(!fc("default", "/account/logout"));
    // A route that no longer exists (a newer bundle).
    assert!(fc("checkout", "/members/a"));
}

#[test]
fn new_challenges_return_where_the_old_one_did() {
    let sealed = ret_hash("/account/login?x=1");
    assert_eq!(
        new_challenge_ret(&sealed, "/account/login?x=1", "/home"),
        "/account/login?x=1"
    );
    assert_eq!(new_challenge_ret(&sealed, "/elsewhere", "/home"), "/home");
    assert_eq!(new_challenge_ret(&sealed, "//evil.test/", "/home"), "/home");
    // A valid path whose hash is not the sealed one.
    assert_eq!(
        new_challenge_ret(&[0; 16], "/account/login?x=1", "/home"),
        "/home"
    );
}

// ---------------------------------------------------------------------------
// The flow: successes

/// §10.3: a fetch submission gets 200 JSON with the cookie; the token is
/// bound to the request, has the C's level and risk band, and a new session.
#[test]
fn fetch_submission_succeeds() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let now = now_ms();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Medium,
        "members",
        "/members/a?x=1",
        now,
    );
    assert_eq!(bits, 9);
    let env = json!({"env": {"v": 1, "ua": {"userAgent": CHROME, "brands": null, "mobile": null, "platform": null},
                             "languages": ["zh-CN"], "graphics": null},
                     "auto": {"v": 1, "webdriver": false}});
    let out = run_json(
        &f,
        &req,
        &solved(&c, ChallengeType::Pow, bits, "/members/a?x=1", env),
    );
    let r = &out.response;
    assert_eq!(r.status, 200, "{}", r.body_text());
    assert_eq!(body_json(r), json!({"ok": true, "ret": "/members/a?x=1"}));
    let cookie = header(r, "Set-Cookie").unwrap();
    assert!(cookie.starts_with("__Host-mg_clr="), "{cookie}");
    assert!(cookie.ends_with("; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax"));
    let claims = token_claims(&f, r, now / 1000);
    assert_eq!(claims.lvl, TokenLevel::Pow);
    assert_eq!(claims.rb, RiskBand::Medium);
    assert_eq!(claims.env, "production");
    assert_eq!(claims.exp - claims.iat, 1800);
    assert_eq!(claims.sst, claims.iat);
    assert!(claims.bind.ipa.is_none() && claims.bind.ctp.is_none());
    assert!(!r.close, "the whole body was read");
    assert!(r.headers.iter().all(|(n, _)| !n.starts_with("MG-")));

    let rec = &out.record;
    assert_eq!(rec.result, "solved");
    assert_eq!(rec.feedback.outcome, Some(VerdictOutcome::Pass));
    assert_eq!(rec.feedback.lvl, Some(TokenLevel::Pow));
    assert_eq!(rec.feedback.route_id.as_deref(), Some("members"));
    assert_eq!(rec.feedback.risk_band, Some(RiskBand::Medium));
    assert_eq!(rec.feedback.challenge_type, ChallengeType::Pow);
    assert!(rec.feedback.reason_codes.is_empty());
    assert!(rec.feedback.solve_ms.is_some());
    let t = rec.telemetry.as_ref().unwrap();
    assert_eq!(t.build, BUILD);
    let tenv = serde_json::to_value(t.env.as_ref().unwrap()).unwrap();
    assert!(tenv["ua"].get("userAgent").is_none(), "{tenv}");
    assert_eq!(t.auto.unwrap().webdriver, Some(false));
    // Nothing secret in Debug.
    let text = format!("{out:?}");
    assert!(!text.contains(&c) && !text.contains(cookie), "{text}");
    assert!(!text.contains(CHROME), "{text}");
}

/// D-11 / I-28: a form navigation (spaces as `+`, `charset=UTF-8`) gets 303
/// to `ret` with the cookie; an invisible C mints an invisible token.
#[test]
fn form_submission_redirects() {
    let f = Fixture::new(&test_bundle());
    let req = Req::new(CHROME, "application/x-www-form-urlencoded; charset=UTF-8");
    let now = now_ms();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Invisible,
        RiskBand::High,
        "members",
        "/members/caf%C3%A9",
        now,
    );
    assert_eq!(bits, 8, "invisible uses pow_bits.low");
    let v = solved(
        &c,
        ChallengeType::Invisible,
        bits,
        "/members/caf%C3%A9",
        json!({"build": "0000000000000000",
               "env": {"v": 1, "ua": {"userAgent": CHROME}}}),
    );
    let out = run(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(form_body(&v.to_string()))]),
    );
    let r = &out.response;
    assert_eq!(r.status, 303, "{}", r.body_text());
    assert_eq!(header(r, "Location"), Some("/members/caf%C3%A9"));
    let claims = token_claims(&f, r, now / 1000);
    assert_eq!(claims.lvl, TokenLevel::Invisible);
    assert_eq!(claims.rb, RiskBand::High);
    assert_eq!(
        out.record.telemetry.as_ref().unwrap().build,
        "0000000000000000"
    );
}

/// §6.5: a clearance cookie of the same browser carries `sub` / `sst` over,
/// even when expired; a token of another browser does not.
#[test]
fn sessions_carry_over() {
    let f = Fixture::new(&test_bundle());
    let now = now_ms();
    let first = {
        let req = Req::json();
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            "/members/a",
            now,
        );
        let out = run_json(
            &f,
            &req,
            &solved(&c, ChallengeType::Pow, bits, "/members/a", json!({})),
        );
        let cookie = header(&out.response, "Set-Cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (token_claims(&f, &out.response, now / 1000), cookie)
    };
    let (prev, cookie) = first;
    // Same browser, 10 minutes later.
    let later = now + 600_000;
    let req = Req::json().with("Cookie", &format!("theme=dark; {cookie}"));
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/b",
        later,
    );
    let out = run_at(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(
            solved(&c, ChallengeType::Pow, bits, "/members/b", json!({})).to_string(),
        )]),
        later,
        &OsRng,
    );
    assert_eq!(out.response.status, 200, "{}", out.response.body_text());
    let next = token_claims(&f, &out.response, later / 1000);
    assert_eq!((next.sub.as_str(), next.sst), (prev.sub.as_str(), prev.sst));
    assert_ne!(next.jti, prev.jti);

    // Another browser presenting the cookie gets a new session.
    let req = Req::new(FIREFOX, "application/json").with("Cookie", &cookie);
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/c",
        later,
    );
    let out = run_at(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(
            solved(&c, ChallengeType::Pow, bits, "/members/c", json!({})).to_string(),
        )]),
        later,
        &OsRng,
    );
    let other = token_claims(&f, &out.response, later / 1000);
    assert_ne!(other.sub, prev.sub);
    assert_eq!(other.sst, later / 1000);
}

// ---------------------------------------------------------------------------
// The flow: failures

/// Replaying a submission: `ic.nonce_reused`, 403, a new pow C one band up,
/// no cookie.
#[test]
fn replay_is_refused_with_an_escalated_challenge() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Invisible,
        RiskBand::Low,
        "members",
        "/members/a",
        now_ms(),
    );
    let v = solved(&c, ChallengeType::Invisible, bits, "/members/a", json!({}));
    assert_eq!(run_json(&f, &req, &v).response.status, 200);
    let again = run_json(&f, &req, &v);
    let r = &again.response;
    assert_eq!(r.status, 403);
    assert!(header(r, "Set-Cookie").is_none());
    assert_eq!(reasons(&again), ["ic.nonce_reused"]);
    assert_eq!(again.record.result, "failed");
    let body = body_json(r);
    assert_eq!(body["error"], "mg_challenge_failed");
    assert_eq!(body["retry"], true);
    assert_eq!(body["request_id"], ID);
    assert_eq!(body["type"], "pow");
    // Low -> Medium (I-10): 9 bits.
    assert_eq!(body["pow"], json!({"alg": "sha256-hashcash-v1", "bits": 9}));
    assert_eq!(again.record.reissued, Some((RiskBand::Medium, 9)));
    // The new C opens as pow for this host, same route and return path.
    let new = f
        .sealer
        .open(
            body["challenge"].as_str().unwrap(),
            HOST,
            ChallengeType::Pow,
            now_ms(),
        )
        .unwrap();
    assert_eq!(new.route_class, "members");
    assert_eq!(new.risk_band, RiskBand::Medium);
    assert_eq!(new.ret_hash, ret_hash("/members/a").to_vec());
}

/// D-27 / I-10: the band escalates, very_high stays very_high.
#[test]
fn failed_pow_escalates_the_band() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    for (band, want) in [
        (RiskBand::Low, (RiskBand::Medium, 9)),
        (RiskBand::Medium, (RiskBand::High, 10)),
        (RiskBand::High, (RiskBand::High, 10)),
        (RiskBand::VeryHigh, (RiskBand::VeryHigh, 11)),
    ] {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            band,
            "members",
            "/members/a",
            now_ms(),
        );
        let mut v = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({}));
        // A counter that does not solve it.
        let good = v["pow"]["counters"][0].as_u64().unwrap();
        let bad = (0..)
            .find(|n| *n != good && !pow_verify(&c, bits, *n))
            .unwrap();
        v["pow"]["counters"] = json!([bad]);
        let out = run_json(&f, &req, &v);
        assert_eq!(reasons(&out), ["ic.pow"], "{band:?}");
        assert_eq!(out.record.reissued, Some(want), "{band:?}");
    }
}

/// Step 4: a tampered, foreign-host, wrong-type or expired C gets no new C;
/// only an expired one is not counted as a failure.
#[test]
fn unopenable_challenges() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let now = now_ms();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now,
    );
    let base = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({}));

    let mut tampered = base.clone();
    let mut chars: Vec<char> = c.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    tampered["c"] = json!(chars.into_iter().collect::<String>());
    let out = run_json(&f, &req, &tampered);
    assert_eq!(reasons(&out), ["ic.c_invalid"]);
    assert_eq!(out.response.status, 403);
    assert_eq!(
        body_json(&out.response),
        json!({"error": "mg_challenge_failed", "retry": true, "request_id": ID})
    );
    assert_eq!(out.record.reissued, None);

    // Another host of the site (the aad covers it).
    let mut other = Req::json();
    other.host = "www.example.com".into();
    assert_eq!(reasons(&run_json(&f, &other, &base)), ["ic.c_invalid"]);

    // The type claimed in the submission is part of the aad.
    let mut invisible = base.clone();
    invisible["type"] = json!("invisible");
    assert_eq!(reasons(&run_json(&f, &req, &invisible)), ["ic.c_invalid"]);

    // Expired: 121 s later.
    let out = run_at(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(base.to_string())]),
        now + 121_000,
        &OsRng,
    );
    assert_eq!(reasons(&out), ["ic.c_expired"]);
    assert_eq!(out.record.result, "expired");
    assert!(!counts_as_failure("ic.c_expired"));
}

/// A body that arrives after `delay`.
struct Late(Duration, Option<Bytes>);

#[async_trait]
impl BodySource for Late {
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
        if !self.0.is_zero() {
            tokio::time::sleep(std::mem::take(&mut self.0)).await;
        }
        Ok(self.1.take())
    }
}

/// §6.2 step 5: `C` is checked against the clock when it is opened, after
/// the body arrived, not when the request did. Reading the body may take up
/// to 5 s (step 3); a `C` that expired meanwhile is `ic.c_expired`, and a
/// token minted after a slow body starts at the time it is minted.
#[test]
fn challenges_are_judged_when_the_body_has_arrived() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let arrived = now_ms();
    // Issued 119.2 s before the request: 0.8 s of its 120 s left.
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        arrived - 119_200,
    );
    let body = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({})).to_string();
    let mut late = Late(Duration::from_millis(1200), Some(Bytes::from(body)));
    let out = run_at(&f, &req, &mut late, arrived, &OsRng);
    assert_eq!(reasons(&out), ["ic.c_expired"], "{:?}", out.response);
    assert!(header(&out.response, "Set-Cookie").is_none());

    // A body that arrives in time: the token's iat is the minting time.
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/b",
        arrived,
    );
    let body = solved(&c, ChallengeType::Pow, bits, "/members/b", json!({})).to_string();
    let mut late = Late(Duration::from_millis(1200), Some(Bytes::from(body)));
    let out = run_at(&f, &req, &mut late, arrived, &OsRng);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    let claims = token_claims(&f, &out.response, now_ms().div_euclid(1000));
    assert!(
        claims.iat >= (arrived + 1200).div_euclid(1000),
        "{} vs {arrived}",
        claims.iat
    );
    assert!(out.record.feedback.solve_ms.is_some_and(|ms| ms >= 1200));
}

/// Steps 5, 7, 8: bindings, return path and the basic environment. Each
/// attaches a new C.
#[test]
fn binding_ret_and_environment_failures() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let fresh = |ret: &str| {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            ret,
            now_ms(),
        );
        solved(&c, ChallengeType::Pow, bits, ret, json!({}))
    };

    // Another browser (User-Agent family / major): hard.
    let ff = Req::new(FIREFOX, "application/json");
    let out = run_json(&f, &ff, &fresh("/members/a"));
    assert_eq!(reasons(&out), ["ic.bind_uah"]);
    assert!(body_json(&out.response)["challenge"].is_string());

    // Another /24 without an ASN to soften it: hard.
    let mut moved = Req::json();
    moved.ip = Some("203.0.113.9".into());
    assert_eq!(
        reasons(&run_json(&f, &moved, &fresh("/members/a"))),
        ["ic.bind_ipp"]
    );

    // A different return path than the sealed one; the new C returns to
    // fallback_ret.
    let mut v = fresh("/members/a");
    v["ret"] = json!("/members/b");
    let out = run_json(&f, &req, &v);
    assert_eq!(reasons(&out), ["ic.ret"]);
    let new = body_json(&out.response)["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims = f
        .sealer
        .open(&new, HOST, ChallengeType::Pow, now_ms())
        .unwrap();
    assert_eq!(claims.ret_hash, ret_hash("/home").to_vec());
    let mut v = fresh("/members/a");
    v["ret"] = json!("//evil.test/");
    assert_eq!(reasons(&run_json(&f, &req, &v)), ["ic.ret"]);

    // webdriver.
    let mut v = fresh("/members/a");
    v["auto"] = json!({"v": 1, "webdriver": true});
    assert_eq!(reasons(&run_json(&f, &req, &v)), ["ic.automation_flag"]);
    // navigator.userAgent that is not a prefix of the header.
    let mut v = fresh("/members/a");
    v["env"] = json!({"v": 1, "ua": {"userAgent": "Mozilla/5.0 (Windows NT 10.0)"}});
    assert_eq!(reasons(&run_json(&f, &req, &v)), ["ic.ua_mismatch"]);
    // A truncated userAgent is a prefix; an empty one is not compared.
    for ua in [&CHROME[..40], ""] {
        let mut v = fresh("/members/a");
        v["env"] = json!({"v": 1, "ua": {"userAgent": ua}});
        assert_eq!(run_json(&f, &req, &v).response.status, 200, "{ua:?}");
    }
}

/// Step 3 (`ic.body`): encodings, sizes, media types and the form / JSON
/// rules; none of them attaches a new C.
#[test]
fn body_rules() {
    let f = Fixture::new(&test_bundle());
    let (c, bits) = challenge_for(
        &f,
        &Req::json(),
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now_ms(),
    );
    let good = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({})).to_string();
    let check = |req: Req, body: &mut dyn BodySource, close: bool| {
        let out = run(&f, &req, body);
        assert_eq!(reasons(&out), ["ic.body"], "{:?}", req.headers);
        assert_eq!(out.response.status, 403);
        assert_eq!(out.record.reissued, None);
        assert_eq!(out.response.close, close, "{:?}", req.headers);
        out
    };
    // Rejected before the body is read: the connection closes.
    check(
        Req::json().with("Content-Encoding", "gzip"),
        &mut Untouched,
        true,
    );
    check(
        Req::json().with("Content-Length", "8193"),
        &mut Untouched,
        true,
    );
    check(Req::new(CHROME, "text/plain"), &mut Untouched, true);
    check(
        Req::new(CHROME, "application/json; charset=iso-8859-1"),
        &mut Untouched,
        true,
    );
    let mut no_type = Req::json();
    no_type.headers.retain(|(n, _)| n != "Content-Type");
    check(no_type, &mut Untouched, true);
    // Too large or too slow: closes as well.
    check(
        Req::json(),
        &mut Chunks(vec![Bytes::from(vec![b' '; 8193])]),
        true,
    );
    // Read completely, but malformed.
    check(
        Req::form(),
        &mut Chunks(vec![Bytes::from(format!(
            "{}&mg=x",
            String::from_utf8(form_body(&good)).unwrap()
        ))]),
        false,
    );
    check(
        Req::form(),
        &mut Chunks(vec![Bytes::from(format!(
            "{}&x=1",
            String::from_utf8(form_body(&good)).unwrap()
        ))]),
        false,
    );
    check(
        Req::json(),
        &mut Chunks(vec![Bytes::from(
            good.replace("\"v\":1", "\"v\":1,\"v\":1"),
        )]),
        false,
    );
    check(
        Req::json(),
        &mut Chunks(vec![Bytes::from(good.clone() + "x")]),
        false,
    );
    check(
        Req::json(),
        &mut Chunks(vec![Bytes::from_static(b"\xff{}")]),
        false,
    );
    // A form answer is the failed challenge page with the CSP nonce.
    let out = check(
        Req::form(),
        &mut Chunks(vec![Bytes::from_static(b"mg=%7B")]),
        false,
    );
    let r = &out.response;
    assert!(r.body_text().contains("data-mg-state=\"failed\""));
    assert!(r.body_text().contains("data-mg-c=\"\""));
    assert!(r.body_text().contains("<html lang=\"zh-CN\">"));
    assert!(r.csp.as_deref().unwrap().contains("script-src 'nonce-"));
    assert!(!r.body_text().contains("{{"));
    // The same body split in chunks is fine.
    let (a, b) = good.split_at(good.len() / 2);
    let out = run(
        &f,
        &Req::json(),
        &mut Chunks(vec![Bytes::from(a.to_owned()), Bytes::from(b.to_owned())]),
    );
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
}

/// Step 0 (D-23) and step 1: no client IP and 0-RTT data are answered
/// before anything else, without reading the body.
#[test]
fn no_client_ip_and_early_data() {
    let f = Fixture::new(&test_bundle());
    let mut req = Req::json();
    req.ip = None;
    let out = run(&f, &req, &mut Untouched);
    assert_eq!(out.response.status, 429);
    assert_eq!(header(&out.response, "Retry-After"), Some("5"));
    assert_eq!(reasons(&out), ["ic.no_client_ip"]);
    assert!(header(&out.response, "Set-Cookie").is_none());
    assert!(out.response.close);
    let v = body_json(&out.response);
    assert_eq!(
        v,
        json!({"error": "mg_rate_limited", "retry_after": 5, "request_id": ID})
    );
    // Form navigations get the short page.
    let mut req = Req::form();
    req.ip = None;
    let out = run(&f, &req, &mut Untouched);
    assert_eq!(out.response.content_type, crate::enforce::HTML);

    let out = run(&f, &Req::json().with("Early-Data", "1"), &mut Untouched);
    assert_eq!(out.response.status, 425);
    assert_eq!(body_json(&out.response), json!({"error": "mg_too_early"}));
    assert_eq!(reasons(&out), ["ic.too_early"]);
}

/// §9.8 / D-28: after `max_failures` counted failures of one client the
/// next submission is 429 before its body is read; other prefixes are not
/// affected by the ip-entity quota.
#[test]
fn failure_quota() {
    let mut b = test_bundle();
    b.challenge.as_mut().unwrap().max_failures = 3;
    let f = Fixture::new(&b);
    let req = Req::json();
    for _ in 0..3 {
        let out = run(&f, &req, &mut Chunks(vec![Bytes::from_static(b"{}")]));
        assert_eq!(reasons(&out), ["ic.body"]);
    }
    let out = run(&f, &req, &mut Untouched);
    assert_eq!(out.response.status, 429);
    assert_eq!(reasons(&out), ["ic.rate_limited"]);
    let retry: u32 = header(&out.response, "Retry-After")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=600).contains(&retry), "{retry}");
    // Expired challenges are not failures: another client of another prefix
    // is not limited by them.
    let mut other = Req::json();
    other.ip = Some("192.0.2.44".into());
    let (c, bits) = challenge_for(
        &f,
        &other,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now_ms() - 125_000,
    );
    for _ in 0..5 {
        let out = run_json(
            &f,
            &other,
            &solved(&c, ChallengeType::Pow, bits, "/members/a", json!({})),
        );
        assert_eq!(reasons(&out), ["ic.c_expired"]);
    }
}

/// D-28: the prefix quota (4 × max_failures) limits a whole /24.
#[test]
fn prefix_failure_quota() {
    let mut b = test_bundle();
    b.challenge.as_mut().unwrap().max_failures = 1;
    let f = Fixture::new(&b);
    for i in 0..4 {
        let mut req = Req::json();
        req.ip = Some(format!("198.51.100.{}", 10 + i));
        let out = run(&f, &req, &mut Chunks(vec![Bytes::from_static(b"{}")]));
        assert_eq!(reasons(&out), ["ic.body"], "{i}");
    }
    let mut req = Req::json();
    req.ip = Some("198.51.100.99".into());
    assert_eq!(reasons(&run(&f, &req, &mut Untouched)), ["ic.rate_limited"]);
}

/// §9.8 `mg.c.submit`: submissions per prefix beyond the burst are 429.
#[test]
fn submit_rate_limit() {
    let mut b = test_bundle();
    let c = b.challenge.as_mut().unwrap();
    c.submit_rate = 2;
    c.submit_burst = 2;
    let f = Fixture::new(&b);
    let req = Req::json();
    for _ in 0..2 {
        assert_eq!(
            reasons(&run(&f, &req, &mut Chunks(vec![Bytes::from_static(b"{}")]))),
            ["ic.body"]
        );
    }
    let out = run(&f, &req, &mut Untouched);
    assert_eq!(reasons(&out), ["ic.rate_limited"]);
}

/// D-37: once the ipp issuance quota is used up, a correct submission is
/// 429 without a cookie (round trip 1 already sees it).
#[test]
fn issuance_quota() {
    let mut b = test_bundle();
    b.challenge.as_mut().unwrap().issue_per_ipp = 1;
    let f = Fixture::new(&b);
    let req = Req::json();
    let one = |ret: &str| {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            ret,
            now_ms(),
        );
        run_json(
            &f,
            &req,
            &solved(&c, ChallengeType::Pow, bits, ret, json!({})),
        )
    };
    assert_eq!(one("/members/a").response.status, 200);
    let out = one("/members/b");
    assert_eq!(out.response.status, 429);
    assert!(header(&out.response, "Set-Cookie").is_none());
    assert_eq!(reasons(&out), ["ic.issue_quota"]);
    assert!(!counts_as_failure("ic.issue_quota"));
}

/// §9.7 rules 3-5 without an authoritative replay store: a C of a
/// `fail_closed` route (or of a route that is gone) is 429 without a
/// cookie; other routes are issued with `ic.replay_unchecked`.
#[test]
fn replay_store_unavailable() {
    let f = Fixture::with_state(&test_bundle(), |c| c.local_replay_authoritative = false);
    let req = Req::json();
    let one = |class: &str, ret: &str| {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            class,
            ret,
            now_ms(),
        );
        run_json(
            &f,
            &req,
            &solved(&c, ChallengeType::Pow, bits, ret, json!({})),
        )
    };
    let out = one("login", "/account/login");
    assert_eq!(out.response.status, 429);
    assert_eq!(header(&out.response, "Retry-After"), Some("5"));
    assert!(header(&out.response, "Set-Cookie").is_none());
    assert_eq!(reasons(&out), ["ic.replay_unavailable"]);

    let out = one("members", "/members/a");
    assert_eq!(out.response.status, 200);
    assert!(header(&out.response, "Set-Cookie").is_some());
    assert_eq!(reasons(&out), ["ic.replay_unchecked"]);
    assert_eq!(out.record.result, "solved");

    // The route was removed from the bundle: fail closed.
    let out = one("checkout", "/members/a");
    assert_eq!(reasons(&out), ["ic.replay_unavailable"]);
    // The named route is open but ret belongs to a fail_closed route.
    let out = one("members", "/account/login");
    assert_eq!(reasons(&out), ["ic.replay_unavailable"]);
}

/// D-35: when the local replay set is full it cannot vouch for a nonce.
#[test]
fn full_local_replay_set_is_unavailable() {
    let f = Fixture::with_state(&test_bundle(), |c| c.local_nonce_capacity = 1);
    let req = Req::json();
    let one = |class: &str, ret: &str| {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            class,
            ret,
            now_ms(),
        );
        run_json(
            &f,
            &req,
            &solved(&c, ChallengeType::Pow, bits, ret, json!({})),
        )
    };
    assert_eq!(one("members", "/members/a").response.status, 200);
    assert_eq!(
        reasons(&one("login", "/account/login")),
        ["ic.replay_unavailable"]
    );
    let out = one("members", "/members/b");
    assert_eq!(out.response.status, 200);
    assert_eq!(reasons(&out), ["ic.replay_unchecked"]);
}

/// §9.9: an RNG failure while minting is 503, never a token or a C.
#[test]
fn rng_failure_is_503() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now_ms(),
    );
    let body = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({})).to_string();
    let out = run_at(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(body)]),
        now_ms(),
        &FailingRng,
    );
    assert_eq!(out.response.status, 503);
    assert!(header(&out.response, "Set-Cookie").is_none());
    // A failure that needs a new C cannot issue one either.
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now_ms(),
    );
    let mut v = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({}));
    v["ret"] = json!("/members/x");
    let out = run_at(
        &f,
        &req,
        &mut Chunks(vec![Bytes::from(v.to_string())]),
        now_ms(),
        &FailingRng,
    );
    assert_eq!(out.response.status, 503);
    // The failure was counted (mg.c.fail); the record keeps its reason for
    // the feedback event.
    assert_eq!(reasons(&out), ["ic.ret"]);
    assert_eq!(out.record.result, "failed");
    assert_eq!(out.record.reissued, None);

    // The failed page of a form submission: whichever of its random values
    // fails (the CSP nonce, the new C's nonce or xnonce), the answer is a
    // 503 without a C, and the record keeps the reason.
    let form = Req::form();
    for serve in 0..3 {
        let (c, bits) = challenge_for(
            &f,
            &form,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            "/members/a",
            now_ms(),
        );
        let mut v = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({}));
        v["ret"] = json!("/members/x");
        let rng = FailAfter(serve, std::sync::atomic::AtomicUsize::new(0));
        let out = run_at(
            &f,
            &form,
            &mut Chunks(vec![Bytes::from(form_body(&v.to_string()))]),
            now_ms(),
            &rng,
        );
        assert_eq!(out.response.status, 503, "{serve}");
        assert!(!out.response.body_text().contains("data-mg-c"), "{serve}");
        assert_eq!(reasons(&out), ["ic.ret"], "{serve}");
        assert_eq!(out.record.reissued, None, "{serve}");
    }
}

/// An RNG that serves `.0` fills, then fails.
#[derive(Debug)]
struct FailAfter(usize, std::sync::atomic::AtomicUsize);

impl Rng for FailAfter {
    fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
        if self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < self.0 {
            OsRng.fill(dst)
        } else {
            Err(RngError)
        }
    }
}

/// §6.4: another prefix of the same (non-zero) ASN is a soft mismatch: the
/// submission passes and records `ic.bind_ipp_soft`; without a matching ASN
/// it is a hard `ic.bind_ipp`.
#[test]
fn soft_ipp_mismatch() {
    let f = Fixture::new(&test_bundle());
    let req = Req::json();
    let current = bind_of(&req.built("production"));
    let sealed_bind = BindInputs {
        ipp: Some(mg_challenge::ipp("203.0.113.0/24")),
        ipa: mg_challenge::ipa(64500),
        ..current
    };
    let now = now_ms();
    let seal = |ret: &str| {
        let bits = f.bundle.challenge.pow_bits.unwrap().low;
        let c = issue(
            &IssueRequest {
                sealer: &f.sealer,
                host: HOST,
                route_class: "members",
                ty: ChallengeType::Pow,
                band: RiskBand::Low,
                bits,
                ttl_s: 120,
                ret,
                bind: &sealed_bind,
                now_ms: now,
            },
            &OsRng,
        )
        .unwrap()
        .c;
        Bytes::from(solved(&c, ChallengeType::Pow, bits, ret, json!({})).to_string())
    };
    let same_asn = BindInputs {
        ipa: mg_challenge::ipa(64500),
        ..current
    };
    let out = run_bound(
        &f,
        &req,
        &mut Chunks(vec![seal("/members/a")]),
        now,
        &OsRng,
        Some(same_asn),
    );
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    assert_eq!(reasons(&out), ["ic.bind_ipp_soft"]);
    // The token binds the current prefix, not the sealed one.
    let claims = token_claims(&f, &out.response, now / 1000);
    let check = mg_challenge::check_clearance_bind(&claims, &same_asn);
    assert_eq!(check.ipp, BindResult::Match);

    let other_asn = BindInputs {
        ipa: mg_challenge::ipa(64501),
        ..current
    };
    let out = run_bound(
        &f,
        &req,
        &mut Chunks(vec![seal("/members/b")]),
        now,
        &OsRng,
        Some(other_asn),
    );
    assert_eq!(reasons(&out), ["ic.bind_ipp"]);
    let out = run_bound(
        &f,
        &req,
        &mut Chunks(vec![seal("/members/c")]),
        now,
        &OsRng,
        Some(current),
    );
    assert_eq!(reasons(&out), ["ic.bind_ipp"], "no ASN on the request side");
}

/// A body that makes its submission yield once before it arrives, so two
/// submissions interleave on one thread.
struct Yielding(Option<Bytes>);

#[async_trait]
impl BodySource for Yielding {
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError> {
        if self.0.is_some() {
            tokio::task::yield_now().await;
        }
        Ok(self.0.take())
    }
}

/// D-37 / §10.3 step 9: two submissions both pass the check-only quota of
/// round trip 1; `mg_nonce_issue` (all-or-nothing) lets only the first
/// consume the last issuance, the second is 429 `ic.issue_quota` without
/// a cookie and is not counted as a failure.
#[test]
fn issuance_quota_used_up_after_round_trip_1() {
    let mut b = test_bundle();
    b.challenge.as_mut().unwrap().issue_per_ipp = 1;
    let f = Fixture::new(&b);
    let req = Req::json();
    let now = now_ms();
    let body = |ret: &str| {
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            ret,
            now,
        );
        Some(Bytes::from(
            solved(&c, ChallengeType::Pow, bits, ret, json!({})).to_string(),
        ))
    };
    let (mut a, mut b2) = (Yielding(body("/members/a")), Yielding(body("/members/b")));
    let env = f.bundle.env_for_host(HOST).unwrap();
    let built = req.built("production");
    let bind = bind_of(&built);
    let s = Submit {
        request_id: ID,
        now_ms: now,
        site_id: "blog",
        sealer: &f.sealer,
        sdk: &f.sdk,
        bundle: &f.bundle,
        env,
        host: HOST,
        built: &built,
        bind: &bind,
        content_encoding: false,
    };
    let (first, second) = rt().block_on(async {
        tokio::join!(
            submit(&f.state, &OsRng, &s, &mut a),
            submit(&f.state, &OsRng, &s, &mut b2)
        )
    });
    // join! rotates which future it polls first: one of them wins.
    let (won, lost) = if first.response.status == 200 {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(won.response.status, 200, "{:?}", reasons(&won));
    assert_eq!(lost.response.status, 429);
    assert!(header(&lost.response, "Set-Cookie").is_none());
    assert_eq!(reasons(&lost), ["ic.issue_quota"]);
    assert_eq!(lost.record.reissued, None);
    // It got past round trip 1 and opened its C: the quota ran out at step 9.
    assert_eq!(lost.record.feedback.route_id.as_deref(), Some("members"));
    assert!(lost.record.feedback.solve_ms.is_some());
}
