//! §5.7 scoring: hand-computed fixed cases for the family caps, shadow
//! families, `h_min`, verdicts (raise only), the hard floors, confidence (κ
//! and the denominator), λ_src and `top_reasons`.

use super::*;
use crate::context::{Crawler, CrawlerVerification, TokenLevel, TokenStatus};
use crate::decision::EntityVerdict;
use crate::detectors::phase1_detectors;
use crate::enums::BotClass;
use crate::extras::{LimiterAction, RateObservation};
use crate::testutil::Req;

fn run(req: &Req, cfg: ScoringConfig) -> (RiskAssessment, Vec<Signal>) {
    let scorer = ScorerV1::new(cfg);
    req.with(|ctx, x| {
        let mut signals = Vec::new();
        for d in phase1_detectors() {
            d.detect(ctx, x, &mut signals);
        }
        scorer.annotate(&mut signals);
        (scorer.score(ctx, x, &signals), signals)
    })
}

fn risk(req: &Req) -> RiskAssessment {
    run(req, ScoringConfig::default()).0
}

/// `round(100 · sigmoid(z))`.
fn expect(z: f64) -> u8 {
    (100.0 / (1.0 + (-z).exp())).round() as u8
}

const Z0_LOW: f64 = -2.197;

fn close(a: f32, b: f64) -> bool {
    (f64::from(a) - b).abs() < 1e-4
}

#[test]
fn clean_browser_scores_the_route_prior() {
    let req = Req::cloudflare_browser();
    let r = risk(&req);
    assert_eq!(r.score.get(), expect(Z0_LOW));
    assert_eq!(r.score.get(), 10, "z0(low) is 10%");
    assert_eq!(r.shadow_score, r.score);
    assert_eq!(r.bot_class, BotClass::HumanLikely);
    assert!(r.top_reasons.is_empty());
    assert!(r.labels.is_empty());
    assert_eq!(
        (r.model_version.as_str(), r.ruleset_version.as_str()),
        ("v1", "v1")
    );
    // NETWORK 1.0·1 + HTTP 1.0·1 + IDENTITY 1.5·0 (clearance ABSENT) over 3.5, κ = 0.9.
    assert!(
        close(r.confidence.get(), 0.9 * 2.0 / 3.5),
        "{}",
        r.confidence.get()
    );

    for (sensitivity, z0) in [
        (RouteSensitivity::Medium, -1.735),
        (RouteSensitivity::High, -1.386),
        (RouteSensitivity::Critical, -1.099),
    ] {
        let mut req = Req::cloudflare_browser();
        req.route.sensitivity = sensitivity;
        assert_eq!(risk(&req).score.get(), expect(z0), "{sensitivity}");
    }
    let mut req = Req::cloudflare_browser();
    req.route.sensitivity = RouteSensitivity::Critical;
    assert_eq!(risk(&req).score.get(), 25);
}

/// One family's sum is clipped to its interval, however many signals fire.
#[test]
fn family_cap() {
    let mut req = Req::cloudflare_browser();
    // Browser-looking UA with a library marker, HTTP/1.0, no accept-language,
    // no client hints, no fetch metadata, GET + text/html navigation.
    req.ua("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 python-requests/2.31");
    req.without("accept-language")
        .without("sec-ch-ua")
        .without("sec-fetch-mode");
    req.ctx.http.version = Some("HTTP/1.0".into());
    let (r, signals) = run(&req, ScoringConfig::default());
    let http: f64 = [
        ("http.ua_library", 2.0 * 1.0 * 1.0),
        ("http.accept_language_missing", 0.5 * 0.8),
        ("http.client_hints", 0.5 * 0.7),
        ("http.fetch_metadata_missing", 0.5 * 0.7),
        ("http.version_old", 0.8 * 0.6 * 0.8), // λ = 0.8: forwarded by Cloudflare
    ]
    .iter()
    .map(|(id, c)| {
        assert!(
            signals.iter().any(|s| s.id == *id && s.value.get() > 0.0),
            "{id}"
        );
        c
    })
    .sum();
    assert!(http > 2.0, "uncapped HTTP sum {http}");
    assert_eq!(r.score.get(), expect(Z0_LOW + 2.0), "HTTP capped at +2.0");
    assert_eq!(r.score.get(), 45);
    assert_eq!(r.bot_class, BotClass::Unknown);
    assert_eq!(r.top_reasons[0], "http.ua_library");
    assert_eq!(r.top_reasons.len(), 5);
}

#[test]
fn identity_interval_is_asymmetric_and_h_min_floors_human_evidence() {
    let mut req = Req::cloudflare_browser();
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Pow);
    let r = risk(&req);
    assert_eq!(r.score.get(), expect(Z0_LOW - 0.4));
    assert_eq!(r.top_reasons, ["identity.clearance"]);

    // An inflated weight is still capped at the IDENTITY floor of -1.5 ...
    let mut cfg = ScoringConfig::default();
    cfg.weights.insert("identity.clearance".into(), 100.0);
    assert_eq!(run(&req, cfg.clone()).0.score.get(), expect(Z0_LOW - 1.5));
    // ... and all negative family contributions together at h_min.
    cfg.h_min = -1.0;
    assert_eq!(run(&req, cfg.clone()).0.score.get(), expect(Z0_LOW - 1.0));
    // Positive evidence is not floored: the floor only applies to the negative sum.
    req.ctx.net.conn_type = crate::context::ConnType::Datacenter;
    assert_eq!(
        run(&req, cfg).0.score.get(),
        expect(Z0_LOW - 1.0 + 0.6 * 0.8)
    );
}

#[test]
fn shadow_family_only_moves_the_shadow_score() {
    let mut req = Req::cloudflare_browser();
    req.ctx.edge_tls.as_mut().unwrap().version = Some("TLSv1.1".into());
    let (r, signals) = run(&req, ScoringConfig::default());
    let s = signals
        .iter()
        .find(|s| s.id == "edge_tls.proto_mismatch")
        .unwrap();
    assert!(
        s.shadow && !s.is_scored(),
        "annotate marks shadow-family signals"
    );
    assert_eq!(r.score.get(), expect(Z0_LOW));
    let edge = 0.8 * 0.4 * 0.6; // λ · v · c
    assert_eq!(r.shadow_score.get(), expect(Z0_LOW + edge));
    assert!(r.top_reasons.is_empty(), "shadow signals are not reasons");

    // Switching EDGE_TLS to active scores it.
    let mut cfg = ScoringConfig::default();
    cfg.family_modes
        .insert(SignalFamily::EdgeTls, FamilyMode::Active);
    let (r, signals) = run(&req, cfg);
    assert!(
        !signals
            .iter()
            .find(|s| s.id == "edge_tls.proto_mismatch")
            .unwrap()
            .shadow
    );
    assert_eq!(r.score.get(), expect(Z0_LOW + edge));
    assert_eq!(r.top_reasons, ["edge_tls.proto_mismatch"]);

    // An empty mode map keeps EDGE_TLS in shadow; Off removes a family entirely.
    let cfg = ScoringConfig {
        family_modes: BTreeMap::from([(SignalFamily::Network, FamilyMode::Off)]),
        ..ScoringConfig::default()
    };
    assert_eq!(cfg.family_mode(SignalFamily::EdgeTls), FamilyMode::Shadow);
    req.ctx.net.conn_type = crate::context::ConnType::Datacenter;
    let (r, _) = run(&req, cfg);
    assert_eq!(r.score.get(), expect(Z0_LOW));
    assert_eq!(
        r.shadow_score.get(),
        expect(Z0_LOW + edge),
        "off is not shadow either"
    );
}

fn verdict(t: EntityType, risk: u32) -> EntityVerdict {
    EntityVerdict {
        entity_type: t,
        key: "k".into(),
        risk: Score::new(risk),
        expires_at_ms: 1_790_000_060_000,
        site_id: "blog".into(),
        ..EntityVerdict::default()
    }
}

#[test]
fn verdicts_only_raise_risk() {
    let mut req = Req::cloudflare_browser();
    req.ctx.verdicts = vec![
        verdict(EntityType::Ip, 20),
        verdict(EntityType::Session, 50),
    ];
    assert_eq!(
        risk(&req).score.get(),
        expect(Z0_LOW),
        "R <= 50 never lowers the score"
    );
    req.ctx.verdicts = vec![verdict(EntityType::Ip, 90), verdict(EntityType::Ip, 60)];
    let r = risk(&req);
    let ip = 0.3 * (0.9f64 / 0.1).ln();
    assert_eq!(
        r.score.get(),
        expect(Z0_LOW + ip),
        "highest verdict per type"
    );
    assert_eq!(r.top_reasons, ["verdict.ip"]);
    req.ctx.verdicts = vec![
        verdict(EntityType::Session, 100),
        verdict(EntityType::Prefix, 99),
        verdict(EntityType::Asn, 99),
    ];
    let capped = 4.0f64.min((0.99f64 / 0.01).ln());
    assert_eq!(
        risk(&req).score.get(),
        expect(Z0_LOW + 0.6 * 4.0 + 0.2 * capped + 0.2 * capped)
    );
    // Expired verdicts and other sites' verdicts do not count.
    let mut expired = verdict(EntityType::Session, 100);
    expired.expires_at_ms = req.ctx.ts_ms;
    let mut other = verdict(EntityType::Session, 100);
    other.site_id = "shop".into();
    req.ctx.verdicts = vec![expired, other];
    assert_eq!(risk(&req).score.get(), expect(Z0_LOW));
}

#[test]
fn hard_floors() {
    let mut req = Req::cloudflare_browser();
    req.ctx.identity.crawler = Crawler {
        claimed: true,
        operator: Some("google".into()),
        verification: Some(CrawlerVerification::Failed),
        ..Crawler::default()
    };
    let r = risk(&req);
    assert_eq!(r.score.get(), 90);
    assert_eq!(r.shadow_score.get(), 90);
    assert_eq!(r.bot_class, BotClass::Impersonator);

    let mut req = Req::cloudflare_browser();
    let mut v = verdict(EntityType::Prefix, 10);
    v.labels = vec!["scanner".into()];
    req.ctx.verdicts = vec![v];
    let r = risk(&req);
    assert_eq!(r.score.get(), 85);
    assert_eq!(r.bot_class, BotClass::Scanner);
    assert_eq!(r.labels, ["scanner"]);
}

#[test]
fn confidence_kappa_and_denominator() {
    // direct_tls: NETWORK 1, TLS 1.5, HTTP 1, IDENTITY 1.5 (ABSENT), κ = 1.0.
    let mut req = Req::direct_browser();
    assert!(close(risk(&req).confidence.get(), 3.5 / 5.0));
    // A valid token makes IDENTITY fully covered.
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Invisible);
    assert!(close(risk(&req).confidence.get(), 1.0));
    // A limiter brings RATE (A = 0.5) into the denominator, covered.
    req.ctx.identity.token.status = TokenStatus::None;
    req.rate = vec![RateObservation {
        limiter_id: "l".into(),
        utilization: 0.1,
        exceeded: false,
        retry_after_ms: 0,
        action: LimiterAction::RateLimit { retry_after_s: 0 },
        dry_run: false,
    }];
    assert!(close(risk(&req).confidence.get(), 4.0 / 5.5));
    // κ override.
    let cfg = ScoringConfig {
        kappa: Some(0.5),
        ..ScoringConfig::default()
    };
    assert!(close(run(&req, cfg).0.confidence.get(), 0.5 * 4.0 / 5.5));
    // MISSING signals leave the denominator: client IP unknown drops NETWORK's
    // client_ip, conn_type and tor inputs entirely.
    let mut req = Req::cloudflare_browser();
    req.ctx.net.ip = None;
    for p in [
        "net.ip",
        "net.asn",
        "net.country",
        "net.conn_type",
        "net.tor",
    ] {
        req.missing.insert(p).unwrap();
    }
    let r = risk(&req);
    assert!(
        close(r.confidence.get(), 0.9 * 1.0 / 2.5),
        "{}",
        r.confidence.get()
    );
    assert_eq!(r.labels, ["client_ip_unknown"]);
    assert_eq!(
        r.bot_class,
        BotClass::Unknown,
        "0.36 < theta_c: never human-likely"
    );
    // No coverage at all: confidence 0.
    let s = ScorerV1::new(ScoringConfig::default());
    assert_eq!(s.confidence(&req.ctx, &[]), 0.0);
}

#[test]
fn top_reasons_order() {
    let got = top_reasons(vec![
        ("h".into(), -0.9),
        ("a".into(), 0.2),
        ("b".into(), 0.7),
        ("c".into(), 0.7),
        ("a".into(), 0.1),
        ("d".into(), 0.05),
        ("e".into(), 0.01),
    ]);
    assert_eq!(
        got,
        ["b", "c", "a", "d", "e"],
        "positive first, by magnitude, ties by code, unique"
    );
    assert_eq!(
        top_reasons(vec![("h".into(), -0.9), ("x".into(), 0.1)]),
        ["x", "h"]
    );
}

#[test]
fn rate_signals_use_their_reason_code() {
    let mut req = Req::cloudflare_browser();
    req.rate = vec![RateObservation {
        limiter_id: "burst".into(),
        utilization: 1.0,
        exceeded: true,
        retry_after_ms: 500,
        action: LimiterAction::Signal { weight: 1.0 },
        dry_run: false,
    }];
    let r = risk(&req);
    // rate.utilization 0.8 (w 1) + rate.exceeded 0.5 (w 2) = 1.8 within RATE's ±2.
    assert_eq!(r.score.get(), expect(Z0_LOW + 0.8 + 1.0));
    assert_eq!(r.top_reasons, ["rl.burst", "rate.utilization"]);
}

#[test]
fn config_sanitizing() {
    let cfg = ScoringConfig {
        theta_c: f32::NAN,
        kappa: Some(f32::INFINITY),
        z0: [f32::NAN, -1.0, -1.0, -1.0],
        h_min: 3.0,
        ruleset_version: String::new(),
        weights: BTreeMap::from([("http.ua_library".to_string(), f32::NAN)]),
        ..ScoringConfig::default()
    };
    let s = ScorerV1::new(cfg);
    let d = ScoringConfig::default();
    assert_eq!(s.config().theta_c, d.theta_c);
    assert_eq!(s.config().kappa, None);
    assert_eq!(s.config().z0[0], d.z0[0]);
    assert_eq!(s.config().h_min, d.h_min);
    assert_eq!(s.config().ruleset_version, "v1");
    assert!(s.config().weights.is_empty());
    assert_eq!(
        ScorerV1::new(ScoringConfig {
            kappa: Some(3.0),
            ..d
        })
        .config()
        .kappa,
        Some(1.0)
    );
}
