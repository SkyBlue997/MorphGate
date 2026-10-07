//! The default treatment matrix (docs/03 §5.1, normalized in
//! docs/impl/phase1-spec.md §5.5): what happens when no terminal policy rule
//! or limiter decided.

use super::engine::{CrawlerAction, EngineConfig};
use crate::context::{RequestContext, TokenLevel, TokenStatus};
use crate::decision::{Decision, RiskAssessment};
use crate::enums::{Action, BotClass, ChallengeType, RouteSensitivity};
use crate::extras::RouteInfo;
use crate::values::RiskBand;

/// Rank of a clearance level for "does this token satisfy that challenge":
/// invisible 1, pow 2, every interactive form 3.
pub(crate) fn level_rank(level: TokenLevel) -> u8 {
    match level {
        TokenLevel::Invisible => 1,
        TokenLevel::Pow => 2,
        TokenLevel::Interactive | TokenLevel::InteractiveA11y | TokenLevel::InteractiveExt(_) => 3,
    }
}

/// Rank a challenge of type `t` demands (after [`effective_challenge`]).
fn challenge_rank(t: ChallengeType) -> u8 {
    match t {
        ChallengeType::Invisible | ChallengeType::Unspecified => 1,
        ChallengeType::Pow => 2,
        ChallengeType::Interactive | ChallengeType::Attestation | ChallengeType::StepUp => 3,
    }
}

/// The challenge that actually runs: without interactive challenges (Phase 1,
/// D-08) `interactive` runs as `pow`; an unspecified type is `invisible`.
pub(crate) fn effective_challenge(t: ChallengeType, interactive_available: bool) -> ChallengeType {
    match t {
        ChallengeType::Unspecified => ChallengeType::Invisible,
        ChallengeType::Interactive if !interactive_available => ChallengeType::Pow,
        t => t,
    }
}

fn block(rule: &str) -> Decision {
    Decision {
        action: Action::Block,
        status: Some(403),
        rule_id: Some(rule.to_string()),
        ..Decision::default()
    }
}

fn with_rule(mut d: Decision, rule: &str) -> Decision {
    d.rule_id = Some(rule.to_string());
    d
}

fn challenge(t: ChallengeType, cfg: &EngineConfig, rule: &str) -> Decision {
    with_rule(
        Decision::challenge(effective_challenge(t, cfg.interactive_available)),
        rule,
    )
}

/// §5.5 `matrix()`.
pub(crate) fn matrix(
    ctx: &RequestContext,
    route: &RouteInfo,
    risk: &RiskAssessment,
    cfg: &EngineConfig,
) -> Decision {
    let band = risk.score.band();
    let critical = route.sensitivity == RouteSensitivity::Critical;
    let token = &ctx.identity.token;

    match risk.bot_class {
        BotClass::VerifiedCrawler => {
            let purpose = ctx.identity.crawler.purpose.as_deref().unwrap_or("");
            if cfg.crawler_policy.action(purpose) == CrawlerAction::Block {
                return block("matrix.crawler.block");
            }
            let read = matches!(ctx.http.method.as_str(), "GET" | "HEAD");
            if read || !route.require_clearance {
                return with_rule(Decision::allow(), "matrix.crawler.allow");
            }
            // A verified crawler never bypasses require_clearance for writes
            // (D-36): fall through to the score-based rows.
        }
        BotClass::Impersonator => return block("matrix.class.impersonator"),
        BotClass::Scanner => return block("matrix.class.scanner"),
        _ => {}
    }
    if band == RiskBand::VeryHigh {
        return block("matrix.very_high");
    }
    if route.require_clearance && token.status != TokenStatus::Valid {
        let t = if band == RiskBand::High {
            ChallengeType::Pow
        } else {
            ChallengeType::Invisible
        };
        return challenge(t, cfg, "matrix.clearance.required");
    }
    if token.status == TokenStatus::BindingMismatch {
        return challenge(ChallengeType::Invisible, cfg, "matrix.clearance.binding");
    }
    let want = match (band, critical) {
        (RiskBand::Low, _) => with_rule(Decision::allow(), "matrix.low"),
        (RiskBand::Medium, false) => {
            if risk.confidence.get() < cfg.theta_c {
                challenge(
                    ChallengeType::Invisible,
                    cfg,
                    "matrix.medium.low_confidence",
                )
            } else {
                with_rule(
                    Decision {
                        action: Action::Tag,
                        ..Decision::default()
                    },
                    "matrix.medium",
                )
            }
        }
        (RiskBand::Medium, true) => {
            challenge(ChallengeType::Invisible, cfg, "matrix.critical.medium")
        }
        (RiskBand::High, false) => challenge(ChallengeType::Invisible, cfg, "matrix.high"),
        (RiskBand::High, true) => {
            challenge(ChallengeType::Interactive, cfg, "matrix.critical.high")
        }
        (RiskBand::VeryHigh, _) => block("matrix.very_high"),
    };
    // D-20: a valid clearance of a sufficient level satisfies the challenge.
    if want.action == Action::Challenge && token.status == TokenStatus::Valid {
        let have = token.level.map_or(0, level_rank);
        if have >= challenge_rank(want.challenge_type) {
            return with_rule(
                Decision {
                    action: Action::Tag,
                    ..Decision::default()
                },
                "matrix.satisfied",
            );
        }
    }
    want
}
