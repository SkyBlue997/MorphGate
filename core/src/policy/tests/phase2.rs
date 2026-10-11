//! Phase 2 (docs/impl/phase2-spec.md §4, §5.2, §9.1; WP-R4): `min_level`
//! and `effective_challenge` in the matrix and the rule engine, D-20 for
//! limiters, the new policy fields with their MISSING semantics and
//! `reads_field`.

use super::dsl::*;
use super::*;
use crate::context::{TokenLevel, TokenStatus};
use crate::decision::{HitOutcome, RiskAssessment};
use crate::enums::{Action, BotClass, ChallengeType, RouteSensitivity};
use crate::extras::{LimiterAction, RateObservation};
use crate::pipeline::{DecisionCore, PolicyEvaluator, PolicyInput, PolicyOutcome};
use crate::scoring::ScoringConfig;
use crate::testutil::Req;
use crate::values::{Confidence, Score};

use ChallengeType::{Interactive, Invisible, Pow};

fn risk(score: u32) -> RiskAssessment {
    RiskAssessment {
        score: Score::new(score),
        confidence: Confidence::new(1.0),
        bot_class: BotClass::HumanLikely,
        ..RiskAssessment::default()
    }
}

fn cfg(interactive_available: bool) -> EngineConfig {
    EngineConfig {
        interactive_available,
        ..EngineConfig::default()
    }
}

fn decide(policy: &SitePolicy, req: &Req, score: u32) -> PolicyOutcome {
    let r = risk(score);
    let out = req.with(|ctx, extras| {
        policy.evaluate(&PolicyInput {
            ctx,
            extras,
            signals: &[],
            risk: &r,
        })
    });
    assert_eq!(out.decision.validate(), Ok(()));
    out
}

/// (action, type, rule) of the matrix decision.
fn matrix_cell(req: &Req, score: u32, ia: bool) -> (Action, ChallengeType, String) {
    let p = SitePolicy::new(Vec::new(), NamedLists::default(), cfg(ia));
    let d = decide(&p, req, score).decision;
    (d.action, d.challenge_type, d.rule_id.unwrap_or_default())
}

fn with_token(mut req: Req, level: Option<TokenLevel>) -> Req {
    match level {
        Some(l) => {
            req.ctx.identity.token.status = TokenStatus::Valid;
            req.ctx.identity.token.level = Some(l);
        }
        None => req.ctx.identity.token = Default::default(),
    }
    req
}

fn route(min_level: Option<ChallengeType>) -> Req {
    let mut req = Req::cloudflare_browser();
    req.route.min_level = min_level;
    req
}

// --- helpers of §5.2 ------------------------------------------------------------

#[test]
fn effective_challenge_and_ranks() {
    assert_eq!(effective_challenge(Interactive, false), Pow, "D-08");
    assert_eq!(effective_challenge(Interactive, true), Interactive);
    assert_eq!(
        effective_challenge(ChallengeType::Unspecified, true),
        Invisible
    );
    for t in [Invisible, Pow] {
        for ia in [false, true] {
            assert_eq!(effective_challenge(t, ia), t);
        }
    }
    assert_eq!(required_level(None, true), Invisible);
    assert_eq!(required_level(Some(Interactive), false), Pow);
    assert_eq!(required_level(Some(Interactive), true), Interactive);
    assert_eq!([Invisible, Pow, Interactive].map(challenge_rank), [1, 2, 3]);
    let levels = [
        TokenLevel::Invisible,
        TokenLevel::Pow,
        TokenLevel::Interactive,
        TokenLevel::InteractiveA11y,
        TokenLevel::InteractiveExt(crate::challenge::ProviderId::Turnstile),
    ];
    assert_eq!(
        levels.map(level_rank),
        [1, 2, 3, 3, 3],
        "three interactive forms rank alike"
    );
    // With interactive unavailable, a pow clearance satisfies an interactive requirement.
    assert!(level_satisfies(TokenLevel::Pow, Interactive, false));
    assert!(!level_satisfies(TokenLevel::Pow, Interactive, true));
    assert!(level_satisfies(
        TokenLevel::InteractiveA11y,
        Interactive,
        true
    ));
    assert!(!level_satisfies(TokenLevel::Invisible, Pow, true));
}

// --- min_level in the matrix (D-64) --------------------------------------------------

#[test]
fn min_level_requires_a_clearance() {
    // No token: a min_level route challenges like require_clearance, with
    // the higher of the Phase 1 type and min_level.
    for (min, ia, score, want) in [
        (Invisible, true, 0, Invisible),
        (Invisible, true, 65, Pow),
        (Pow, true, 0, Pow),
        (Pow, false, 65, Pow),
        (Interactive, true, 0, Interactive),
        (Interactive, true, 65, Interactive),
        (Interactive, false, 0, Pow),
    ] {
        assert_eq!(
            matrix_cell(&route(Some(min)), score, ia),
            (Action::Challenge, want, "matrix.clearance.required".into()),
            "min {min} ia {ia} score {score}"
        );
    }
    // Without min_level and require_clearance: Phase 1 (low risk allows).
    assert_eq!(matrix_cell(&route(None), 0, true).0, Action::Allow);
    // require_clearance alone keeps the Phase 1 types.
    let mut req = route(None);
    req.route.require_clearance = true;
    assert_eq!(matrix_cell(&req, 0, true).1, Invisible);
    assert_eq!(matrix_cell(&req, 65, true).1, Pow);
    req.route.min_level = Some(Interactive);
    assert_eq!(matrix_cell(&req, 0, true).1, Interactive);
    // Very high still blocks before the clearance rule.
    assert_eq!(
        matrix_cell(&route(Some(Interactive)), 90, true).0,
        Action::Block
    );
}

/// D-64 with D-20: a valid clearance must reach `min_level`; insufficient
/// levels are challenged again, sufficient ones fall through to the bands.
#[test]
fn min_level_with_valid_clearances() {
    let cases: [(ChallengeType, bool, TokenLevel, bool); 12] = [
        // (min_level, interactive available, token level, satisfied)
        (Pow, true, TokenLevel::Invisible, false),
        (Pow, true, TokenLevel::Pow, true),
        (Pow, true, TokenLevel::Interactive, true),
        (Interactive, true, TokenLevel::Pow, false),
        (Interactive, true, TokenLevel::Interactive, true),
        (Interactive, true, TokenLevel::InteractiveA11y, true),
        (
            Interactive,
            true,
            TokenLevel::InteractiveExt(crate::challenge::ProviderId::Turnstile),
            true,
        ),
        // Interactive unavailable: the effective requirement is pow, so a
        // pow clearance is enough (no endless re-challenge, §5.2).
        (Interactive, false, TokenLevel::Pow, true),
        (Interactive, false, TokenLevel::Invisible, false),
        (Invisible, true, TokenLevel::Invisible, true),
        (Invisible, false, TokenLevel::Invisible, true),
        (Pow, false, TokenLevel::Invisible, false),
    ];
    for (min, ia, level, satisfied) in cases {
        let req = with_token(route(Some(min)), Some(level));
        let got = matrix_cell(&req, 0, ia);
        if satisfied {
            assert_eq!(got.2, "matrix.low", "min {min} ia {ia} {level}");
        } else {
            assert_eq!(
                got,
                (
                    Action::Challenge,
                    effective_challenge(min, ia),
                    "matrix.clearance.required".to_string()
                ),
                "min {min} ia {ia} {level}"
            );
        }
    }
    // A token that is not valid never satisfies.
    let mut req = with_token(route(Some(Pow)), Some(TokenLevel::Interactive));
    for status in [
        TokenStatus::Expired,
        TokenStatus::Invalid,
        TokenStatus::Replay,
        TokenStatus::BindingMismatch,
    ] {
        req.ctx.identity.token.status = status;
        assert_eq!(
            matrix_cell(&req, 0, true).2,
            "matrix.clearance.required",
            "{status}"
        );
    }
    // A satisfied min_level route still applies the bands and D-20 above it.
    let mut critical = with_token(route(Some(Pow)), Some(TokenLevel::Pow));
    critical.route.sensitivity = RouteSensitivity::Critical;
    assert_eq!(
        matrix_cell(&critical, 70, true),
        (
            Action::Challenge,
            Interactive,
            "matrix.critical.high".into()
        )
    );
    assert_eq!(
        matrix_cell(&critical, 70, false).2,
        "matrix.satisfied",
        "pow satisfies interactive-as-pow"
    );
    assert_eq!(matrix_cell(&critical, 45, true).2, "matrix.satisfied");
}

// --- rules and limiters ------------------------------------------------------------

fn challenge_rule(ty: ChallengeType) -> Rule {
    Rule {
        id: "challenge-all".into(),
        phase: Phase::Bot,
        priority: 0,
        program: prog(t()),
        action: RuleAction::Challenge(ty),
        mode: RuleMode::Enforce,
        rollout_percent: 100,
        expires_at_ms: 0,
    }
}

/// D-64: a rule challenge on a min_level route is raised to the route's
/// effective min_level.
#[test]
fn rule_challenges_respect_min_level() {
    for (asked, min, ia, want) in [
        (Invisible, None, true, Invisible),
        (Invisible, Some(Pow), true, Pow),
        (Invisible, Some(Interactive), true, Interactive),
        (Invisible, Some(Interactive), false, Pow),
        (Interactive, Some(Pow), true, Interactive),
        (Interactive, Some(Pow), false, Pow),
        (Pow, Some(Invisible), true, Pow),
    ] {
        let p = SitePolicy::new(vec![challenge_rule(asked)], NamedLists::default(), cfg(ia));
        let d = decide(&p, &route(min), 0).decision;
        assert_eq!(
            (d.action, d.challenge_type),
            (Action::Challenge, want),
            "{asked} {min:?} {ia}"
        );
        assert_eq!(d.rule_id.as_deref(), Some("challenge-all"));
    }
}

fn limiter(t: ChallengeType) -> RateObservation {
    RateObservation {
        limiter_id: "login-per-ip".into(),
        utilization: 1.0,
        exceeded: true,
        retry_after_ms: 2_000,
        action: LimiterAction::Challenge(t),
        dry_run: false,
    }
}

/// §5.2: D-20 also suppresses a limiter's challenge, but only for
/// `schema_version = 2` bundles (D-66: schema 1 behaves as Phase 1).
#[test]
fn limiter_challenges_and_d20() {
    let mut req = with_token(route(None), Some(TokenLevel::Pow));
    req.rate = vec![limiter(Pow)];
    let base = SitePolicy::new(Vec::new(), NamedLists::default(), cfg(true));
    assert_eq!(base.schema_version(), 1);

    // Schema 1: the limiter challenges whatever the clearance.
    let out = decide(&base, &req, 0);
    assert_eq!(
        (out.decision.action, out.decision.challenge_type),
        (Action::Challenge, Pow)
    );
    assert_eq!(
        out.decision.rule_id.as_deref(),
        Some("ratelimit.login-per-ip")
    );

    // Schema 2: satisfied → no decision from the limiter, a hit records it.
    let v2 = SitePolicy::new(Vec::new(), NamedLists::default(), cfg(true)).with_schema_version(2);
    assert_eq!(v2.schema_version(), 2);
    let out = decide(&v2, &req, 0);
    assert_eq!(out.decision.action, Action::Allow);
    assert_eq!(out.decision.rule_id.as_deref(), Some("matrix.low"));
    assert_eq!(out.hits.len(), 1);
    let hit = &out.hits[0];
    assert_eq!(hit.rule_id, "ratelimit.login-per-ip");
    assert_eq!(
        (hit.outcome, hit.mode, hit.action),
        (HitOutcome::Matched, RuleMode::Enforce, Action::Challenge)
    );
    assert_eq!(hit.fields, [LIMITER_SATISFIED]);

    // Not satisfied: an interactive limiter with a pow clearance.
    req.rate = vec![limiter(Interactive)];
    let out = decide(&v2, &req, 0);
    assert_eq!(out.decision.challenge_type, Interactive);
    // ... unless interactive is unavailable: it runs as pow, which pow satisfies.
    let v2_pow =
        SitePolicy::new(Vec::new(), NamedLists::default(), cfg(false)).with_schema_version(2);
    let out = decide(&v2_pow, &req, 0);
    assert_eq!(out.decision.action, Action::Allow);
    assert_eq!(out.hits[0].fields, [INTERACTIVE_AS_POW, LIMITER_SATISFIED]);

    // A later limiter still decides after a satisfied one.
    req.rate = vec![
        limiter(Invisible),
        RateObservation {
            limiter_id: "burst".into(),
            action: LimiterAction::RateLimit { retry_after_s: 7 },
            ..limiter(Pow)
        },
    ];
    let out = decide(&v2, &req, 0);
    assert_eq!(out.decision.action, Action::RateLimit);
    assert_eq!(out.decision.retry_after_s, Some(7));
    assert_eq!(out.hits.len(), 2);

    // Without a valid clearance the limiter challenges, raised to min_level.
    let mut req = route(Some(Interactive));
    req.rate = vec![limiter(Invisible)];
    let out = decide(&v2, &req, 0);
    assert_eq!(
        (out.decision.action, out.decision.challenge_type),
        (Action::Challenge, Interactive)
    );
    // Dry-run limiters are unchanged.
    let mut req = with_token(route(None), Some(TokenLevel::Pow));
    req.rate = vec![RateObservation {
        dry_run: true,
        ..limiter(Pow)
    }];
    let out = decide(&v2, &req, 0);
    assert_eq!(out.hits[0].mode, RuleMode::DryRun);
    assert!(out.hits[0].fields.is_empty());
}

// --- reads_field (§9.1) --------------------------------------------------------------

fn rule_reading(id: &str, e: Expr, mode: RuleMode) -> Rule {
    Rule {
        id: id.into(),
        phase: Phase::Custom,
        priority: 0,
        program: prog(e),
        action: RuleAction::Log,
        mode,
        rollout_percent: 100,
        expires_at_ms: 0,
    }
}

#[test]
fn reads_field_walks_every_rule() {
    let empty = SitePolicy::new(Vec::new(), NamedLists::default(), EngineConfig::default());
    assert!(!empty.reads_field("identity.proof"));

    let p = SitePolicy::new(
        vec![
            rule_reading("a", eq(f("route.name"), s("login")), RuleMode::Enforce),
            rule_reading(
                "b",
                and(vec![
                    f("identity.proof.present"),
                    not(f("identity.proof.valid")),
                ]),
                RuleMode::DryRun,
            ),
        ],
        NamedLists::default(),
        EngineConfig::default(),
    );
    assert!(p.reads_field("identity.proof"), "a field below");
    assert!(p.reads_field("identity.proof.valid"), "the field itself");
    assert!(p.reads_field("identity"), "any ancestor");
    assert!(!p.reads_field("identity.proof.replayed"));
    assert!(!p.reads_field("identity.token"));
    assert!(p.reads_field("route.name"));
    assert!(!p.reads_field("route.nam"), "segment boundaries");
    assert!(!p.reads_field(""));

    // has() of an ancestor reads every field below it.
    let p = SitePolicy::new(
        vec![rule_reading("h", has("identity.proof"), RuleMode::Enforce)],
        NamedLists::default(),
        EngineConfig::default(),
    );
    assert!(p.reads_field("identity.proof.replayed"));
    assert!(p.reads_field("identity.proof"));
    assert!(!p.reads_field("identity.token.bound"));

    // Through the pipeline and the trait default.
    let core = DecisionCore::phase1(ScoringConfig::default(), Box::new(p));
    assert!(core.reads_field("identity.proof.valid"));
    assert!(!core.reads_field("http.navigation"));
    struct Opaque;
    impl PolicyEvaluator for Opaque {
        fn evaluate(&self, _: &PolicyInput<'_>) -> PolicyOutcome {
            PolicyOutcome {
                decision: crate::decision::Decision::allow(),
                hits: Vec::new(),
                force_log: false,
            }
        }
    }
    assert!(
        Opaque.reads_field("identity.proof"),
        "unknown evaluators read everything"
    );
}

// --- the new fields and their MISSING semantics (§4) ----------------------------------

/// `Activation::build` maps the new context fields; token fields are zero
/// without a valid clearance, as `identity.token.level` is.
#[test]
fn activation_of_the_phase2_fields() {
    let mut req = Req::cloudflare_browser();
    req.ctx.http.navigation = true;
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Interactive);
    req.ctx.identity.token.bound = true;
    req.ctx.identity.token.level_age = 900;
    req.ctx.identity.proof.present = true;
    req.ctx.identity.proof.valid = true;
    req.ctx.identity.proof.replayed = true;
    let act = req.with(|ctx, extras| Activation::build(ctx, extras, &risk(0)));
    assert!(act.http.navigation);
    assert!(act.identity.token.bound);
    assert_eq!(act.identity.token.level_age, 900);
    assert!(act.identity.proof.present && act.identity.proof.valid && act.identity.proof.replayed);

    req.ctx.identity.token.status = TokenStatus::Expired;
    let act = req.with(|ctx, extras| Activation::build(ctx, extras, &risk(0)));
    assert_eq!(act.identity.token, TokenNs::default());

    // The JSON form (conformance fixtures) uses the CEL leaf names.
    let json = serde_json::json!({
        "http": {"navigation": true},
        "identity": {"token": {"bound": true, "level_age": 7},
                     "proof": {"present": true, "valid": false, "replayed": true}}
    });
    let act: Activation = serde_json::from_value(json).unwrap();
    assert!(act.http.navigation && act.identity.token.bound);
    assert_eq!(act.identity.token.level_age, 7);
    assert!(act.identity.proof.present && act.identity.proof.replayed);
}

fn eval_in(e: Expr, act: &Activation, missing: &[&str]) -> EvalResult {
    eval(
        &prog(e),
        act,
        &MissingSet::new(missing).unwrap(),
        &NamedLists::default(),
    )
}

/// §4.2: MISSING on an exempt navigation (and whenever unverified), plain
/// values without a header, `replayed` alone MISSING without a replay verdict.
#[test]
fn proof_fields_missing_semantics() {
    use EvalResult::{False, True, Unknown};
    let rule = || {
        and(vec![
            eq(f("route.name"), s("login")),
            not(f("identity.proof.valid")),
        ])
    };
    let mut act = Activation::default();
    act.route.name = "login".into();

    // Exempt navigation / not verified: the whole namespace is MISSING, so
    // `!identity.proof.valid` never matches (no challenge loop).
    let m = proof_missing(false, true).unwrap();
    assert_eq!(m, "identity.proof");
    assert!(matches!(eval_in(rule(), &act, &[m]), Unknown(_)));
    assert_eq!(eval_in(has("identity.proof"), &act, &[m]), False);

    // Verified, no header: present = valid = false are ordinary values.
    assert_eq!(proof_missing(true, true), None);
    assert_eq!(eval_in(rule(), &act, &[]), True);
    assert_eq!(eval_in(f("identity.proof.present"), &act, &[]), False);
    act.identity.proof.present = true;
    act.identity.proof.valid = true;
    assert_eq!(eval_in(rule(), &act, &[]), False);

    // Replay store unavailable: only `replayed` is MISSING.
    let m = proof_missing(true, false).unwrap();
    assert_eq!(m, "identity.proof.replayed");
    assert_eq!(eval_in(f("identity.proof.valid"), &act, &[m]), True);
    assert!(matches!(
        eval_in(f("identity.proof.replayed"), &act, &[m]),
        Unknown(_)
    ));
    assert_eq!(eval_in(has("identity.proof"), &act, &[m]), True);

    // The token fields evaluate like any other.
    act.identity.token.bound = true;
    act.identity.token.level_age = 3_600;
    assert_eq!(
        eval_in(
            and(vec![
                f("identity.token.bound"),
                cmp(CompareOp::Gt, f("identity.token.level_age"), i(1_800))
            ]),
            &act,
            &[]
        ),
        True
    );
    act.http.navigation = true;
    assert_eq!(eval_in(f("http.navigation"), &act, &[]), True);
}

/// D-40 and §9.1: which requests verify `MG-Proof`.
#[test]
fn exempt_navigation_and_verification() {
    assert!(is_exempt_navigation(true, "GET", true));
    assert!(is_exempt_navigation(true, "HEAD", true));
    assert!(
        !is_exempt_navigation(true, "POST", true),
        "a POST 'navigation' needs a proof"
    );
    assert!(
        !is_exempt_navigation(true, "get", true),
        "methods are case-sensitive"
    );
    assert!(!is_exempt_navigation(false, "GET", true));
    assert!(
        !is_exempt_navigation(true, "GET", false),
        "an api / mobile route matched"
    );

    // (schema, exempt, proof_required, policy reads) -> verify
    for (schema, exempt, required, reads, want) in [
        (1, false, true, true, false),
        (2, true, true, true, false),
        (2, false, false, false, false),
        (2, false, true, false, true),
        (2, false, false, true, true),
    ] {
        assert_eq!(
            proof_verification_needed(schema, exempt, required, reads),
            want
        );
    }
}
