//! `verify_bundle` and the Phase 2 bundle fields (docs/impl/phase2-spec.md
//! §3.2 `schema_version` rules / D-66, §8.2 providers, §10.2 ranges; WP-C5
//! tests in §17): a counterexample for every `schema_version` rule and for
//! every new field's bounds.

use mg_edge_core::bundle::{BundleError, verify_bundle};
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_SEED, owner_test_keys, sign_test_bundle, test_site_bundle,
    test_site_bundle_v2,
};
use mg_proto::v1::expr::Kind;
use mg_proto::v1::{
    Action, ChallengeType, Channel, CompiledRule, Expr, PolicyExpr, ProofMode, ProviderConfig,
    RateLimit, Route, RouteSensitivity, SiteBundle, Unary,
};
use prost::Message as _;

const SITE: &str = "blog";
const HOSTS: &[&str] = &["example.com", "www.example.com"];

fn verify(b: &SiteBundle) -> Result<(), BundleError> {
    let hosts: Vec<String> = HOSTS.iter().map(|h| (*h).to_owned()).collect();
    let bytes = sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID);
    verify_bundle(&bytes, &owner_test_keys(), SITE, &hosts).map(|_| ())
}

fn v1() -> SiteBundle {
    test_site_bundle(SITE, HOSTS, 1_790_000_000)
}

fn v2() -> SiteBundle {
    test_site_bundle_v2(SITE, HOSTS, 1_790_000_000)
}

/// Asserts an `Invalid` error whose field contains `field`.
#[track_caller]
fn assert_invalid(b: &SiteBundle, field: &str) {
    match verify(b) {
        Err(BundleError::Invalid { field: f, reason }) => {
            assert!(f.contains(field), "expected {field}, got {f}: {reason}");
        }
        other => panic!("expected invalid {field}, got {other:?}"),
    }
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

fn with_route(mut b: SiteBundle, r: Route) -> SiteBundle {
    b.environments[0].routes.insert(0, r);
    b
}

fn limiter(on_exceed: &str, ty: ChallengeType) -> RateLimit {
    RateLimit {
        id: "signup-per-ip".into(),
        key: vec!["ip".into()],
        algorithm: "gcra".into(),
        rate: 20,
        period_s: 60,
        burst: 5,
        on_exceed: on_exceed.into(),
        mode: "enforce".into(),
        challenge_type: ty as i32,
        ..Default::default()
    }
}

fn turnstile() -> ProviderConfig {
    ProviderConfig {
        id: "turnstile".into(),
        enabled: true,
        sitekey: "0x4AAAAAAA_test-key".into(),
        denied_countries: vec!["CN".into()],
        route_ids: vec!["default".into()],
        timeout_ms: 4000,
        fallback: "self_hold".into(),
        mode: "shadow".into(),
        hostnames: vec!["example.com".into()],
        selection: "escalate_after_fail".into(),
        ..Default::default()
    }
}

#[test]
fn both_schemas_verify() {
    verify(&v1()).unwrap();
    verify(&v2()).unwrap();
    // Schema 2 with every feature on and a Turnstile provider.
    let mut b = v2();
    let ix = b.challenge.as_mut().unwrap().interactive.as_mut().unwrap();
    ix.enabled = true;
    ix.scoring_mode = "enforce".into();
    ix.t_pass = 0.4;
    ix.t_block = 0.8;
    let clr = b.clearance.as_mut().unwrap();
    clr.refresh = true;
    clr.refresh_max_pow_s = 0;
    let ev = b.events.as_mut().unwrap();
    ev.telemetry_behavior = true;
    ev.scanner_baits = vec!["/wp-admin/**".into(), "/.env".into()];
    b.providers.push(turnstile());
    let mut r = route("api", &["/api/**"]);
    r.channel = Channel::Api as i32;
    r.proof = ProofMode::Required as i32;
    r.min_level = ChallengeType::Interactive as i32;
    b = with_route(b, r);
    b.environments[0]
        .rate_limits
        .push(limiter("challenge", ChallengeType::Interactive));
    verify(&b).unwrap();
}

#[test]
fn schema_version_must_be_1_or_2() {
    for v in [0, 3, 255] {
        let mut b = v2();
        b.schema_version = v;
        assert!(
            matches!(verify(&b), Err(BundleError::SchemaVersion(x)) if x == v),
            "{v}"
        );
    }
}

type Mutation = fn(&mut SiteBundle);
type RouteMutation = fn(&mut Route);
type ProviderMutation = fn(&mut ProviderConfig);

/// D-66: in a schema 1 bundle every Phase 2 field is zero / empty.
#[test]
fn schema1_rejects_every_phase2_field() {
    let cases: Vec<(&str, Mutation)> = vec![
        ("routes[0].proof", |b| {
            b.environments[0].routes[0].proof = ProofMode::Required as i32
        }),
        ("routes[0].min_level", |b| {
            b.environments[0].routes[0].min_level = ChallengeType::Pow as i32
        }),
        ("challenge.interactive", |b| {
            let v2 = v2();
            b.challenge.as_mut().unwrap().interactive = v2.challenge.unwrap().interactive;
        }),
        ("challenge.default_lang", |b| {
            b.challenge.as_mut().unwrap().default_lang = "en".into()
        }),
        ("challenge.help_path", |b| {
            b.challenge.as_mut().unwrap().help_path = "/".into()
        }),
        ("challenge.privacy_path", |b| {
            b.challenge.as_mut().unwrap().privacy_path = "/".into()
        }),
        ("clearance.ttl_interactive_s", |b| {
            b.clearance.as_mut().unwrap().ttl_interactive_s = 1800
        }),
        ("clearance.ttl_interactive_a11y_s", |b| {
            b.clearance.as_mut().unwrap().ttl_interactive_a11y_s = 900
        }),
        ("clearance.ttl_interactive_ext_s", |b| {
            b.clearance.as_mut().unwrap().ttl_interactive_ext_s = 1800
        }),
        ("clearance.refresh", |b| {
            b.clearance.as_mut().unwrap().refresh = true
        }),
        ("clearance.refresh_max_interactive_s", |b| {
            b.clearance.as_mut().unwrap().refresh_max_interactive_s = 14_400
        }),
        ("clearance.refresh_max_ext_s", |b| {
            b.clearance.as_mut().unwrap().refresh_max_ext_s = 7200
        }),
        ("clearance.refresh_max_pow_s", |b| {
            b.clearance.as_mut().unwrap().refresh_max_pow_s = 3600
        }),
        ("events.telemetry_behavior", |b| {
            b.events.as_mut().unwrap().telemetry_behavior = true
        }),
        ("events.scanner_baits_builtin", |b| {
            b.events.as_mut().unwrap().scanner_baits_builtin = true
        }),
        ("events.scanner_baits", |b| {
            b.events.as_mut().unwrap().scanner_baits = vec!["/x".into()]
        }),
        ("providers", |b| b.providers.push(turnstile())),
        ("rate_limits[0].challenge_type", |b| {
            b.environments[0]
                .rate_limits
                .push(limiter("challenge", ChallengeType::Interactive))
        }),
        // Not even on a limiter that does not challenge.
        ("rate_limits[0].challenge_type", |b| {
            b.environments[0]
                .rate_limits
                .push(limiter("rate_limit", ChallengeType::Interactive))
        }),
    ];
    for (field, mutate) in cases {
        let mut b = v1();
        mutate(&mut b);
        assert_invalid(&b, field);
    }
    // Absent messages stay valid in schema 1 (Phase 1 §8.3 defaults).
    let mut b = v1();
    b.challenge = None;
    b.clearance = None;
    b.events = None;
    verify(&b).unwrap();
}

/// §3.2: schema 2 requires the four messages.
#[test]
fn schema2_requires_the_phase2_messages() {
    let cases: [(&str, Mutation); 4] = [
        ("challenge", |b| b.challenge = None),
        ("challenge.interactive", |b| {
            b.challenge.as_mut().unwrap().interactive = None
        }),
        ("clearance", |b| b.clearance = None),
        ("events", |b| b.events = None),
    ];
    for (field, mutate) in cases {
        let mut b = v2();
        mutate(&mut b);
        assert_invalid(&b, field);
    }
}

/// §10.2: every new field outside its range, below and above.
#[test]
fn schema2_field_ranges() {
    let cases: Vec<(&str, Mutation)> = vec![
        ("challenge.default_lang", |b| {
            b.challenge.as_mut().unwrap().default_lang = "zh-cn".into()
        }),
        ("challenge.default_lang", |b| {
            b.challenge.as_mut().unwrap().default_lang = String::new()
        }),
        ("challenge.help_path", |b| {
            b.challenge.as_mut().unwrap().help_path = String::new()
        }),
        ("challenge.help_path", |b| {
            b.challenge.as_mut().unwrap().help_path = "//evil.example".into()
        }),
        ("challenge.privacy_path", |b| {
            b.challenge.as_mut().unwrap().privacy_path = "/__mg/v".into()
        }),
        ("challenge.interactive.pow_bits.low", |b| {
            ix(b).pow_bits.as_mut().unwrap().low = 7
        }),
        ("challenge.interactive.pow_bits.very_high", |b| {
            ix(b).pow_bits.as_mut().unwrap().very_high = 23
        }),
        ("challenge.interactive.pow_bits", |b| {
            ix(b).pow_bits.as_mut().unwrap().high = 20
        }),
        ("challenge.interactive.pow_bits", |b| ix(b).pow_bits = None),
        ("challenge.interactive.pow_k", |b| ix(b).pow_k = 0),
        ("challenge.interactive.pow_k", |b| ix(b).pow_k = 9),
        ("challenge.interactive.a11y_bits", |b| ix(b).a11y_bits = 11),
        ("challenge.interactive.a11y_bits", |b| ix(b).a11y_bits = 25),
        ("challenge.interactive.escalate_after", |b| {
            ix(b).escalate_after = 0
        }),
        ("challenge.interactive.escalate_after", |b| {
            ix(b).escalate_after = 6
        }),
        ("challenge.interactive.scoring_mode", |b| {
            ix(b).scoring_mode = "learn".into()
        }),
        ("challenge.interactive.t_pass", |b| {
            let i = ix(b);
            i.scoring_mode = "enforce".into();
            (i.t_pass, i.t_block) = (0.0, 0.8);
        }),
        ("challenge.interactive.t_pass", |b| {
            let i = ix(b);
            i.scoring_mode = "enforce".into();
            (i.t_pass, i.t_block) = (0.8, 0.8);
        }),
        ("challenge.interactive.t_pass", |b| {
            let i = ix(b);
            i.scoring_mode = "enforce".into();
            (i.t_pass, i.t_block) = (0.4, 1.1);
        }),
        ("challenge.interactive.t_pass", |b| ix(b).t_pass = f32::NAN),
        ("challenge.interactive.min_pow_ms", |b| {
            ix(b).min_pow_ms = 5_001
        }),
        ("challenge.interactive.a11y_min_ms", |b| {
            ix(b).a11y_min_ms = 10_001
        }),
        ("challenge.interactive.issue", |b| ix(b).issue_rate = 0),
        ("challenge.interactive.issue", |b| ix(b).issue_burst = 0),
        ("challenge.interactive.issue", |b| ix(b).issue_period_s = 0),
        // The 4x ipp tier must be a valid GCRA limiter as well.
        ("challenge.interactive.issue", |b| {
            ix(b).issue_burst = 30_000
        }),
        ("challenge.interactive.renew", |b| ix(b).renew_rate = 0),
        ("challenge.interactive.renew", |b| {
            ix(b).renew_period_s = 86_401
        }),
        ("challenge.interactive.a11y_issue_per_ip", |b| {
            ix(b).a11y_issue_per_ip = 0
        }),
        ("challenge.interactive.a11y_issue_per_ip", |b| {
            ix(b).a11y_issue_period_s = 0
        }),
        ("challenge.interactive.a11y_issue_per_ipp", |b| {
            ix(b).a11y_issue_per_ipp = 5
        }),
        ("clearance.ttl_interactive_s", |b| {
            clr(b).ttl_interactive_s = 299
        }),
        ("clearance.ttl_interactive_s", |b| {
            clr(b).ttl_interactive_s = 7_201
        }),
        ("clearance.ttl_interactive_a11y_s", |b| {
            clr(b).ttl_interactive_a11y_s = 3_601
        }),
        ("clearance.ttl_interactive_ext_s", |b| {
            clr(b).ttl_interactive_ext_s = 0
        }),
        ("clearance.refresh_max_interactive_s", |b| {
            clr(b).refresh_max_interactive_s = 899
        }),
        ("clearance.refresh_max_ext_s", |b| {
            clr(b).refresh_max_ext_s = 86_401
        }),
        ("clearance.refresh_max_pow_s", |b| {
            clr(b).refresh_max_pow_s = 86_401
        }),
        ("events.scanner_baits", |b| {
            b.events.as_mut().unwrap().scanner_baits = vec!["/x".into(); 65]
        }),
        ("events.scanner_baits[0]", |b| {
            b.events.as_mut().unwrap().scanner_baits = vec!["no-slash".into()]
        }),
        ("events.scanner_baits[1]", |b| {
            b.events.as_mut().unwrap().scanner_baits = vec!["/ok".into(), "/a/*/*/*/*/*".into()]
        }),
    ];
    for (field, mutate) in cases {
        let mut b = v2();
        mutate(&mut b);
        assert_invalid(&b, field);
    }
    // The bounds themselves are accepted.
    let mut b = v2();
    let i = ix(&mut b);
    i.pow_bits.as_mut().unwrap().low = 8;
    i.pow_bits.as_mut().unwrap().very_high = 22;
    (i.pow_k, i.a11y_bits, i.escalate_after) = (1, 24, 5);
    (i.min_pow_ms, i.a11y_min_ms) = (5_000, 10_000);
    i.a11y_issue_per_ipp = i.a11y_issue_per_ip;
    let c = clr(&mut b);
    (
        c.ttl_interactive_s,
        c.ttl_interactive_a11y_s,
        c.ttl_interactive_ext_s,
    ) = (300, 3_600, 7_200);
    (
        c.refresh_max_interactive_s,
        c.refresh_max_ext_s,
        c.refresh_max_pow_s,
    ) = (900, 86_400, 0);
    b.events.as_mut().unwrap().scanner_baits = vec!["/x".into(); 64];
    verify(&b).unwrap();
}

fn ix(b: &mut SiteBundle) -> &mut mg_proto::v1::InteractiveConfig {
    b.challenge.as_mut().unwrap().interactive.as_mut().unwrap()
}

fn clr(b: &mut SiteBundle) -> &mut mg_proto::v1::ClearanceConfig {
    b.clearance.as_mut().unwrap()
}

/// §3.2 route fields: unknown values and the `never_challenge` conflict
/// (§10.2), in schema 2.
#[test]
fn route_proof_and_min_level() {
    let cases: Vec<(&str, RouteMutation)> = vec![
        ("proof", |r| r.proof = 2),
        ("proof", |r| r.proof = -1),
        ("min_level", |r| {
            r.min_level = ChallengeType::Attestation as i32
        }),
        ("min_level", |r| r.min_level = ChallengeType::StepUp as i32),
        ("min_level", |r| r.min_level = 99),
        ("proof", |r| {
            r.never_challenge = true;
            r.proof = ProofMode::Required as i32;
        }),
        ("min_level", |r| {
            r.never_challenge = true;
            r.min_level = ChallengeType::Invisible as i32;
        }),
    ];
    for (field, mutate) in cases {
        let mut r = route("api", &["/api/**"]);
        mutate(&mut r);
        assert_invalid(&with_route(v2(), r), &format!("routes[0].{field}"));
    }
    for level in [
        ChallengeType::Unspecified,
        ChallengeType::Invisible,
        ChallengeType::Pow,
        ChallengeType::Interactive,
    ] {
        let mut r = route("api", &["/api/**"]);
        r.min_level = level as i32;
        verify(&with_route(v2(), r)).unwrap();
    }
    let mut r = route("beacon", &["/beacon"]);
    r.never_challenge = true;
    verify(&with_route(v2(), r)).unwrap();
}

/// §3.2: INTERACTIVE limiters are allowed in schema 2; other challenge
/// types beyond it are not.
#[test]
fn schema2_limiter_challenge_types() {
    for (ty, ok) in [
        (ChallengeType::Invisible, true),
        (ChallengeType::Pow, true),
        (ChallengeType::Interactive, true),
        (ChallengeType::Unspecified, false),
        (ChallengeType::Attestation, false),
    ] {
        let mut b = v2();
        b.environments[0].rate_limits.push(limiter("challenge", ty));
        if ok {
            verify(&b).unwrap();
        } else {
            assert_invalid(&b, "rate_limits[0].challenge_type");
        }
    }
}

/// §8.2: every provider rule.
#[test]
fn provider_rules() {
    let cases: Vec<(&str, ProviderMutation)> = vec![
        ("id", |p| p.id = "tencent".into()),
        ("sitekey", |p| p.sitekey = String::new()),
        ("sitekey", |p| p.sitekey = "a".repeat(65)),
        ("sitekey", |p| p.sitekey = "key with space".into()),
        ("secret_refs", |p| p.secret_refs = vec!["cred://x".into()]),
        ("allowed_countries", |p| {
            p.allowed_countries = vec!["US".into()]
        }),
        ("denied_countries", |p| {
            p.denied_countries = vec!["cn".into()]
        }),
        ("denied_countries", |p| {
            p.denied_countries = vec!["CHN".into()]
        }),
        ("route_ids", |p| p.route_ids = vec!["nope".into()]),
        ("timeout_ms", |p| p.timeout_ms = 999),
        ("timeout_ms", |p| p.timeout_ms = 5_001),
        ("fallback", |p| p.fallback = "fail_closed".into()),
        ("fallback", |p| p.fallback = "fail_open_with_signal".into()),
        ("fallback", |p| p.fallback = String::new()),
        ("mode", |p| p.mode = "off".into()),
        ("selection", |p| p.selection = "random".into()),
        ("hostnames", |p| p.hostnames = vec![]),
        ("hostnames", |p| p.hostnames = vec!["evil.example".into()]),
    ];
    for (field, mutate) in cases {
        let mut p = turnstile();
        mutate(&mut p);
        let mut b = v2();
        b.providers.push(p);
        assert_invalid(&b, &format!("providers[0].{field}"));
    }
    let mut b = v2();
    b.providers = vec![turnstile(), turnstile()];
    assert_invalid(&b, "providers");
    // Disabled providers are checked as well; empty route_ids and
    // denied_countries are the defaults.
    let mut p = turnstile();
    p.enabled = false;
    p.route_ids.clear();
    p.denied_countries.clear();
    p.selection = "first".into();
    p.mode = "enforce".into();
    p.timeout_ms = 1_000;
    let mut b = v2();
    b.providers.push(p);
    verify(&b).unwrap();
}

fn ir(root: Expr) -> Vec<u8> {
    PolicyExpr {
        ir_version: 1,
        root: Some(root),
        fields: vec![],
        max_steps: 1,
    }
    .encode_to_vec()
}

fn field(path: &str) -> Expr {
    Expr {
        kind: Some(Kind::Field(path.into())),
    }
}

fn rule(action: Action, expr_ir: Vec<u8>) -> CompiledRule {
    CompiledRule {
        id: "r".into(),
        phase: "custom".into(),
        expr_source: "…".into(),
        ir_version: 1,
        expr_ir,
        action: action as i32,
        mode: "enforce".into(),
        rollout_percent: 100,
        ..Default::default()
    }
}

/// §4.2 / §10.2: an allow rule must not depend on `http.navigation`
/// (anywhere in its expression); other actions may.
#[test]
fn allow_rules_must_not_read_http_navigation() {
    let negated = Expr {
        kind: Some(Kind::Not(Box::new(Unary {
            arg: Some(Box::new(field("http.navigation"))),
        }))),
    };
    let has = Expr {
        kind: Some(Kind::Has("http.navigation".into())),
    };
    for root in [field("http.navigation"), negated.clone(), has] {
        for schema in [1, 2] {
            let mut b = if schema == 1 { v1() } else { v2() };
            b.environments[0]
                .rules
                .push(rule(Action::Allow, ir(root.clone())));
            assert_invalid(&b, "rules[0].expr_ir");
        }
    }
    for (action, root) in [
        (Action::Challenge, negated),
        (Action::Allow, field("http.navigationx")),
        (Action::Allow, field("http.method")),
    ] {
        let mut b = v2();
        b.environments[0].rules.push(rule(action, ir(root)));
        verify(&b).unwrap();
    }
}
