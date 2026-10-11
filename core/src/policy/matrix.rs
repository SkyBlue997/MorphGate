//! The default treatment matrix (docs/03 §5.1, normalized in
//! docs/impl/phase1-spec.md §5.5): what happens when no terminal policy rule
//! or limiter decided. Phase 2 adds the route's `min_level` (D-64,
//! docs/impl/phase2-spec.md §5.2).

use super::engine::{CrawlerAction, EngineConfig};
use crate::context::{RequestContext, Token, TokenLevel, TokenStatus};
use crate::decision::{Decision, RiskAssessment};
use crate::enums::{Action, BotClass, ChallengeType, RouteSensitivity};
use crate::extras::RouteInfo;
use crate::values::RiskBand;

/// Rank of a clearance level for "does this token satisfy that challenge":
/// invisible 1, pow 2, every interactive form 3.
pub fn level_rank(level: TokenLevel) -> u8 {
    match level {
        TokenLevel::Invisible => 1,
        TokenLevel::Pow => 2,
        TokenLevel::Interactive | TokenLevel::InteractiveA11y | TokenLevel::InteractiveExt(_) => 3,
    }
}

/// Rank a challenge of type `t` demands (compare after [`effective_challenge`]):
/// unspecified and invisible 1, pow 2, interactive 3 (attestation and
/// step-up, never issued, rank like interactive).
pub fn challenge_rank(t: ChallengeType) -> u8 {
    match t {
        ChallengeType::Invisible | ChallengeType::Unspecified => 1,
        ChallengeType::Pow => 2,
        ChallengeType::Interactive | ChallengeType::Attestation | ChallengeType::StepUp => 3,
    }
}

/// The challenge that actually runs (Phase 2 spec §5.2): without interactive
/// challenges (D-08, §5.1) `interactive` runs as `pow`; an unspecified type
/// is `invisible`; anything else is unchanged.
pub fn effective_challenge(t: ChallengeType, interactive_available: bool) -> ChallengeType {
    match t {
        ChallengeType::Unspecified => ChallengeType::Invisible,
        ChallengeType::Interactive if !interactive_available => ChallengeType::Pow,
        t => t,
    }
}

/// The higher-ranked of `a` and `b`; `a` on a tie.
pub(crate) fn higher(a: ChallengeType, b: ChallengeType) -> ChallengeType {
    if challenge_rank(b) > challenge_rank(a) {
        b
    } else {
        a
    }
}

/// The challenge type a route's `min_level` demands (D-64): the effective
/// `min_level`, or `invisible` when the route sets none.
pub fn required_level(
    min_level: Option<ChallengeType>,
    interactive_available: bool,
) -> ChallengeType {
    effective_challenge(
        min_level.unwrap_or(ChallengeType::Invisible),
        interactive_available,
    )
}

/// Whether a clearance of `level` satisfies a challenge of type `t` (D-20,
/// Phase 2 spec §5.2): `level_rank(level) >= challenge_rank(effective(t))`.
pub fn level_satisfies(level: TokenLevel, t: ChallengeType, interactive_available: bool) -> bool {
    level_rank(level) >= challenge_rank(effective_challenge(t, interactive_available))
}

/// Whether `token` is a valid clearance that satisfies a challenge of type
/// `t` (D-20). A token that is not `valid` never does; an `ruc` token on a
/// `fail_closed` route (I-30) reaches the Decision Core as not valid.
pub fn token_satisfies(token: &Token, t: ChallengeType, interactive_available: bool) -> bool {
    token.status == TokenStatus::Valid
        && token
            .level
            .is_some_and(|l| level_satisfies(l, t, interactive_available))
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
    // Phase 2 spec §5.2 (D-64): a route with `min_level` also requires a
    // clearance, of at least that (effective) level. Without `min_level` the
    // Phase 1 rule is unchanged: any valid clearance.
    let ia = cfg.interactive_available;
    let floor = required_level(route.min_level, ia);
    let cleared = match route.min_level {
        None => token.status == TokenStatus::Valid,
        Some(_) => token_satisfies(token, floor, ia),
    };
    if (route.require_clearance || route.min_level.is_some()) && !cleared {
        let t = if band == RiskBand::High {
            ChallengeType::Pow
        } else {
            ChallengeType::Invisible
        };
        return challenge(higher(t, floor), cfg, "matrix.clearance.required");
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
    if want.action == Action::Challenge && token_satisfies(token, want.challenge_type, ia) {
        return with_rule(
            Decision {
                action: Action::Tag,
                ..Decision::default()
            },
            "matrix.satisfied",
        );
    }
    want
}
