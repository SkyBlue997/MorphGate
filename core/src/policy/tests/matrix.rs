//! §5.5 default matrix: every cell, D-20 `matrix.satisfied`,
//! `require_clearance`, the crawler policy and verified crawlers' writes.

use super::*;
use crate::context::{TokenLevel, TokenStatus};
use crate::decision::RiskAssessment;
use crate::enums::{Action, BotClass, ChallengeType, RouteSensitivity};
use crate::pipeline::{PolicyEvaluator, PolicyInput};
use crate::testutil::Req;
use crate::values::{Confidence, Score};
use std::collections::BTreeMap;

fn policy(cfg: EngineConfig) -> SitePolicy {
    SitePolicy::new(Vec::new(), NamedLists::default(), cfg)
}

fn risk(score: u32, conf: f32, class: BotClass) -> RiskAssessment {
    RiskAssessment {
        score: Score::new(score),
        confidence: Confidence::new(conf),
        bot_class: class,
        ..RiskAssessment::default()
    }
}

/// (action, challenge type, rule id) of the matrix decision.
fn cell(req: &Req, r: &RiskAssessment, cfg: EngineConfig) -> (Action, ChallengeType, String) {
    let d = req
        .with(|ctx, extras| {
            policy(cfg).evaluate(&PolicyInput {
                ctx,
                extras,
                signals: &[],
                risk: r,
            })
        })
        .decision;
    assert_eq!(d.validate(), Ok(()));
    (d.action, d.challenge_type, d.rule_id.unwrap())
}

fn m(req: &Req, score: u32, conf: f32) -> (Action, ChallengeType, String) {
    cell(
        req,
        &risk(score, conf, BotClass::Unknown),
        EngineConfig::default(),
    )
}

use Action::{Allow, Block, Challenge, Tag};
use ChallengeType::{Invisible, Pow, Unspecified as None_};

fn want(a: Action, t: ChallengeType, rule: &str) -> (Action, ChallengeType, String) {
    (a, t, rule.to_string())
}

#[test]
fn band_by_sensitivity_cells() {
    let normal = Req::cloudflare_browser();
    let mut critical = Req::cloudflare_browser();
    critical.route.sensitivity = RouteSensitivity::Critical;

    assert_eq!(m(&normal, 0, 1.0), want(Allow, None_, "matrix.low"));
    assert_eq!(m(&normal, 29, 0.0), want(Allow, None_, "matrix.low"));
    assert_eq!(m(&critical, 29, 0.0), want(Allow, None_, "matrix.low"));
    assert_eq!(m(&normal, 30, 0.4), want(Tag, None_, "matrix.medium"));
    assert_eq!(
        m(&normal, 59, 0.39),
        want(Challenge, Invisible, "matrix.medium.low_confidence")
    );
    assert_eq!(
        m(&critical, 45, 1.0),
        want(Challenge, Invisible, "matrix.critical.medium")
    );
    assert_eq!(
        m(&normal, 60, 1.0),
        want(Challenge, Invisible, "matrix.high")
    );
    // D-08: interactive runs as pow in Phase 1.
    assert_eq!(
        m(&critical, 84, 1.0),
        want(Challenge, Pow, "matrix.critical.high")
    );
    assert_eq!(m(&normal, 85, 1.0), want(Block, None_, "matrix.very_high"));
    assert_eq!(
        m(&critical, 100, 0.0),
        want(Block, None_, "matrix.very_high")
    );
    // With interactive challenges available the critical/high cell is interactive.
    let cfg = EngineConfig {
        interactive_available: true,
        ..EngineConfig::default()
    };
    assert_eq!(
        cell(&critical, &risk(70, 1.0, BotClass::Unknown), cfg),
        want(
            Challenge,
            ChallengeType::Interactive,
            "matrix.critical.high"
        )
    );
    // theta_c comes from the engine config.
    let cfg = EngineConfig {
        theta_c: 0.9,
        ..EngineConfig::default()
    };
    assert_eq!(
        cell(&normal, &risk(40, 0.8, BotClass::Unknown), cfg),
        want(Challenge, Invisible, "matrix.medium.low_confidence")
    );
}

#[test]
fn classes() {
    let req = Req::cloudflare_browser();
    let c = |class| cell(&req, &risk(0, 1.0, class), EngineConfig::default());
    assert_eq!(
        c(BotClass::Impersonator),
        want(Block, None_, "matrix.class.impersonator")
    );
    assert_eq!(
        c(BotClass::Scanner),
        want(Block, None_, "matrix.class.scanner")
    );
    assert_eq!(
        c(BotClass::DeclaredAgent),
        want(Allow, None_, "matrix.low"),
        "declared agents follow the score"
    );
    assert_eq!(
        c(BotClass::VerifiedCrawler),
        want(Allow, None_, "matrix.crawler.allow")
    );
}

#[test]
fn crawler_policy_and_writes() {
    let mut req = Req::cloudflare_browser();
    req.ctx.identity.crawler.purpose = Some("ai_training".into());
    let cfg = EngineConfig {
        crawler_policy: CrawlerPolicy {
            purposes: BTreeMap::from([("ai_training".to_string(), CrawlerAction::Block)]),
            default_action: CrawlerAction::Allow,
        },
        ..EngineConfig::default()
    };
    let crawler = risk(95, 1.0, BotClass::VerifiedCrawler);
    assert_eq!(
        cell(&req, &crawler, cfg.clone()),
        want(Block, None_, "matrix.crawler.block")
    );
    req.ctx.identity.crawler.purpose = Some("search".into());
    assert_eq!(
        cell(&req, &crawler, cfg.clone()),
        want(Allow, None_, "matrix.crawler.allow"),
        "even at 95"
    );
    // Default action.
    let blocking = EngineConfig {
        crawler_policy: CrawlerPolicy {
            purposes: BTreeMap::new(),
            default_action: CrawlerAction::Block,
        },
        ..EngineConfig::default()
    };
    assert_eq!(
        cell(&req, &crawler, blocking),
        want(Block, None_, "matrix.crawler.block")
    );
    // D-36: a write on a require_clearance route falls through to the score rows.
    req.route.require_clearance = true;
    req.ctx.http.method = "HEAD".into();
    assert_eq!(
        cell(&req, &crawler, cfg.clone()),
        want(Allow, None_, "matrix.crawler.allow")
    );
    req.ctx.http.method = "POST".into();
    assert_eq!(
        cell(&req, &crawler, cfg.clone()),
        want(Block, None_, "matrix.very_high")
    );
    let low = risk(10, 1.0, BotClass::VerifiedCrawler);
    assert_eq!(
        cell(&req, &low, cfg.clone()),
        want(Challenge, Invisible, "matrix.clearance.required")
    );
    // Without require_clearance a write is allowed.
    req.route.require_clearance = false;
    assert_eq!(
        cell(&req, &low, cfg),
        want(Allow, None_, "matrix.crawler.allow")
    );
}

#[test]
fn require_clearance_and_binding() {
    let mut req = Req::cloudflare_browser();
    req.route.require_clearance = true;
    assert_eq!(
        m(&req, 0, 1.0),
        want(Challenge, Invisible, "matrix.clearance.required")
    );
    assert_eq!(
        m(&req, 45, 1.0),
        want(Challenge, Invisible, "matrix.clearance.required")
    );
    assert_eq!(
        m(&req, 70, 1.0),
        want(Challenge, Pow, "matrix.clearance.required")
    );
    assert_eq!(
        m(&req, 90, 1.0),
        want(Block, None_, "matrix.very_high"),
        "very high blocks first"
    );
    for status in [
        TokenStatus::Expired,
        TokenStatus::Invalid,
        TokenStatus::BindingMismatch,
        TokenStatus::Replay,
    ] {
        req.ctx.identity.token.status = status;
        assert_eq!(m(&req, 0, 1.0).2, "matrix.clearance.required", "{status}");
    }
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Invisible);
    assert_eq!(m(&req, 0, 1.0), want(Allow, None_, "matrix.low"));
    // A binding mismatch outside require_clearance routes re-challenges invisibly.
    req.route.require_clearance = false;
    req.ctx.identity.token.status = TokenStatus::BindingMismatch;
    assert_eq!(
        m(&req, 0, 1.0),
        want(Challenge, Invisible, "matrix.clearance.binding")
    );
}

/// D-20: a valid clearance of a sufficient level turns the challenge into TAG.
#[test]
fn satisfied_by_valid_clearance() {
    let mut req = Req::cloudflare_browser();
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Invisible);
    assert_eq!(
        m(&req, 65, 1.0),
        want(Tag, None_, "matrix.satisfied"),
        "invisible >= invisible"
    );
    assert_eq!(m(&req, 45, 0.1), want(Tag, None_, "matrix.satisfied"));
    let mut critical = req.clone();
    critical.route.sensitivity = RouteSensitivity::Critical;
    // critical/high demands pow (interactive as pow): invisible is not enough.
    assert_eq!(
        m(&critical, 70, 1.0),
        want(Challenge, Pow, "matrix.critical.high")
    );
    critical.ctx.identity.token.level = Some(TokenLevel::Pow);
    assert_eq!(m(&critical, 70, 1.0), want(Tag, None_, "matrix.satisfied"));
    // With interactive challenges available, pow no longer satisfies interactive.
    let cfg = EngineConfig {
        interactive_available: true,
        ..EngineConfig::default()
    };
    assert_eq!(
        cell(&critical, &risk(70, 1.0, BotClass::Unknown), cfg.clone()),
        want(
            Challenge,
            ChallengeType::Interactive,
            "matrix.critical.high"
        )
    );
    critical.ctx.identity.token.level = Some(TokenLevel::InteractiveA11y);
    assert_eq!(
        cell(&critical, &risk(70, 1.0, BotClass::Unknown), cfg),
        want(Tag, None_, "matrix.satisfied")
    );
    // Never for very high scores, never for a token that is not valid.
    assert_eq!(
        m(&critical, 90, 1.0),
        want(Block, None_, "matrix.very_high")
    );
    critical.ctx.identity.token.status = TokenStatus::Expired;
    assert_eq!(m(&critical, 70, 1.0).2, "matrix.critical.high");
    // A valid token without a level satisfies nothing.
    req.ctx.identity.token.level = None;
    assert_eq!(m(&req, 65, 1.0), want(Challenge, Invisible, "matrix.high"));
}
