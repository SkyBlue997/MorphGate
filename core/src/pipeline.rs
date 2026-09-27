//! Decision pipeline contracts (docs/03 §1).
//!
//! ```text
//! RequestContext -> [Detector]* -> [Signal] -> Scorer -> RiskAssessment -> PolicyEvaluator -> Decision
//! ```
//!
//! All three traits are synchronous and pure: implementations must not do
//! I/O, block, read clocks or keep interior mutable state that changes the
//! result for identical inputs. Anything stateful (rate counters, near-line
//! verdicts, token replay sets) is resolved by the host *before* the call and
//! arrives as data in [`RequestContext`] (verdicts in
//! [`RequestContext::verdicts`]). That makes every decision reproducible from
//! its [`crate::DecisionEvent`].
//!
//! Phase 1 provides the v1 detectors, the family-capped log-odds scorer and
//! the policy IR evaluator; Phase 0 only fixes the contracts.

use crate::context::RequestContext;
use crate::decision::{Decision, RiskAssessment};
use crate::mask::FamilyMask;
use crate::signal::Signal;
use std::fmt;

/// Turns request facts into [`Signal`]s.
pub trait Detector: Send + Sync {
    /// Stable identifier, used in metrics and to enable / disable the detector.
    fn id(&self) -> &'static str;

    /// Families this detector may emit. Emitting any other family is a bug;
    /// [`DecisionCore`] drops such signals (and panics in debug builds).
    fn families(&self) -> FamilyMask;

    /// Appends zero or more signals for `ctx` to `out`.
    ///
    /// Must be pure and cheap (the whole pipeline budget is a few hundred µs).
    /// Unavailable input is never evidence: if the fields a detector needs are
    /// `ABSENT` or `MISSING`, it emits nothing or a value-less signal
    /// ([`Signal::without_input`]), never a "human" signal.
    fn detect(&self, ctx: &RequestContext, out: &mut Vec<Signal>);
}

/// Combines signals and entity verdicts into a [`RiskAssessment`].
pub trait Scorer: Send + Sync {
    /// Scores one request. Only [`Signal::is_scored`] signals count toward
    /// `score`; shadow ones only toward `shadow_score`. `ctx.verdicts` may
    /// include expired entries and other sites' entries: use
    /// [`RequestContext::active_verdicts`] and
    /// [`crate::EntityVerdict::applies_to_site`].
    fn score(&self, ctx: &RequestContext, signals: &[Signal]) -> RiskAssessment;
}

/// Maps an assessment to an enforcement [`Decision`] using the site's policy.
pub trait PolicyEvaluator: Send + Sync {
    /// Decides for one request. Must return a decision that passes
    /// [`Decision::validate`]; the global monitor switch is applied by the host
    /// by setting `dry_run`.
    fn evaluate(&self, ctx: &RequestContext, signals: &[Signal], risk: &RiskAssessment)
    -> Decision;
}

/// Result of one pass through the pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub signals: Vec<Signal>,
    pub risk: RiskAssessment,
    pub decision: Decision,
}

/// Wires detectors, a scorer and a policy evaluator together.
pub struct DecisionCore {
    detectors: Vec<Box<dyn Detector>>,
    scorer: Box<dyn Scorer>,
    policy: Box<dyn PolicyEvaluator>,
}

impl DecisionCore {
    /// A core with no detectors.
    pub fn new(scorer: Box<dyn Scorer>, policy: Box<dyn PolicyEvaluator>) -> Self {
        Self {
            detectors: Vec::new(),
            scorer,
            policy,
        }
    }

    /// Adds a detector; detectors run in insertion order.
    #[must_use]
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Runs every detector, then the scorer, then the policy.
    pub fn evaluate(&self, ctx: &RequestContext) -> Evaluation {
        let mut signals = Vec::new();
        for detector in &self.detectors {
            let start = signals.len();
            detector.detect(ctx, &mut signals);
            let allowed = detector.families();
            let mut i = start;
            while i < signals.len() {
                if allowed.contains(signals[i].family) {
                    i += 1;
                } else {
                    if cfg!(debug_assertions) {
                        panic!(
                            "detector {} emitted undeclared family {}",
                            detector.id(),
                            signals[i].family
                        );
                    }
                    signals.remove(i);
                }
            }
        }
        let risk = self.scorer.score(ctx, &signals);
        let decision = self.policy.evaluate(ctx, &signals, &risk);
        Evaluation {
            signals,
            risk,
            decision,
        }
    }
}

impl fmt::Debug for DecisionCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionCore")
            .field(
                "detectors",
                &self.detectors.iter().map(|d| d.id()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::EntityVerdict;
    use crate::enums::{Action, ChallengeType, EntityType, SignalFamily};
    use crate::values::Score;

    /// Flags requests without a User-Agent (illustrative only).
    struct NoUserAgent;
    impl Detector for NoUserAgent {
        fn id(&self) -> &'static str {
            "test.no_ua"
        }
        fn families(&self) -> FamilyMask {
            FamilyMask::of(&[SignalFamily::Http])
        }
        fn detect(&self, ctx: &RequestContext, out: &mut Vec<Signal>) {
            if ctx.http.user_agent.is_none() {
                out.push(Signal::new(
                    "http.no_user_agent",
                    SignalFamily::Http,
                    0.9,
                    1.0,
                ));
            }
        }
    }

    /// Sum of weighted values plus active verdict risk, scaled to 0..100 (not the real model).
    struct SumScorer;
    impl Scorer for SumScorer {
        fn score(&self, ctx: &RequestContext, signals: &[Signal]) -> RiskAssessment {
            let s: f32 = signals.iter().map(Signal::weighted_value).sum();
            let v: u32 = ctx
                .active_verdicts()
                .filter(|v| v.applies_to_site(&ctx.site_id))
                .map(|v| u32::from(v.risk.get()))
                .max()
                .unwrap_or(0);
            RiskAssessment {
                score: Score::new(((s.max(0.0) * 50.0) as u32).max(v)),
                ..RiskAssessment::default()
            }
        }
    }

    struct Threshold;
    impl PolicyEvaluator for Threshold {
        fn evaluate(&self, _: &RequestContext, _: &[Signal], risk: &RiskAssessment) -> Decision {
            if risk.score.get() >= 40 {
                Decision::challenge(ChallengeType::Invisible)
            } else {
                Decision::allow()
            }
        }
    }

    /// Emits a family it did not declare.
    struct Liar;
    impl Detector for Liar {
        fn id(&self) -> &'static str {
            "test.liar"
        }
        fn families(&self) -> FamilyMask {
            FamilyMask::of(&[SignalFamily::Http])
        }
        fn detect(&self, _: &RequestContext, out: &mut Vec<Signal>) {
            out.push(Signal::new("tls.fake", SignalFamily::Tls, 1.0, 1.0));
        }
    }

    fn core() -> DecisionCore {
        DecisionCore::new(Box::new(SumScorer), Box::new(Threshold))
            .with_detector(Box::new(NoUserAgent))
    }

    #[test]
    fn pipeline_runs_detectors_scorer_policy() {
        let ctx = RequestContext::new("r", "s", 0);
        let ev = core().evaluate(&ctx);
        assert_eq!(ev.signals.len(), 1);
        assert_eq!(ev.risk.score.get(), 45);
        assert_eq!(ev.decision.action, Action::Challenge);
        assert_eq!(ev.decision.validate(), Ok(()));

        let mut ctx = ctx;
        ctx.http.user_agent = Some("Mozilla/5.0".into());
        let ev = core().evaluate(&ctx);
        assert!(ev.signals.is_empty());
        assert_eq!(ev.decision, Decision::allow());
    }

    #[test]
    fn verdict_expiry_is_judged_against_request_time() {
        let mut ctx = RequestContext::new("r", "s", 1_000);
        ctx.http.user_agent = Some("ua".into());
        ctx.verdicts = vec![EntityVerdict {
            entity_type: EntityType::Ip,
            risk: Score::new(90),
            expires_at_ms: 2_000,
            site_id: "s".into(),
            ..EntityVerdict::default()
        }];
        assert_eq!(core().evaluate(&ctx).risk.score.get(), 90);
        ctx.ts_ms = 2_000;
        assert_eq!(core().evaluate(&ctx).risk.score.get(), 0);
    }

    #[test]
    fn verdicts_of_other_sites_are_ignored() {
        let mut ctx = RequestContext::new("r", "blog", 1_000);
        ctx.http.user_agent = Some("ua".into());
        let verdict = |t: EntityType, site: &str| EntityVerdict {
            entity_type: t,
            risk: Score::new(80),
            expires_at_ms: 2_000,
            site_id: site.into(),
            ..EntityVerdict::default()
        };
        ctx.verdicts = vec![verdict(EntityType::Session, "shop")];
        assert_eq!(core().evaluate(&ctx).risk.score.get(), 0);
        ctx.verdicts = vec![verdict(EntityType::Session, EntityVerdict::ALL_SITES)];
        assert_eq!(core().evaluate(&ctx).risk.score.get(), 0);
        ctx.verdicts = vec![verdict(EntityType::Asn, EntityVerdict::ALL_SITES)];
        assert_eq!(core().evaluate(&ctx).risk.score.get(), 80);
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "undeclared family"))]
    fn undeclared_families_are_rejected() {
        let core = DecisionCore::new(Box::new(SumScorer), Box::new(Threshold))
            .with_detector(Box::new(Liar));
        let ev = core.evaluate(&RequestContext::default());
        // Release builds: the signal is dropped instead.
        assert!(ev.signals.is_empty());
    }

    #[test]
    fn debug_lists_detector_ids() {
        assert_eq!(
            format!("{:?}", core()),
            "DecisionCore { detectors: [\"test.no_ua\"], .. }"
        );
    }
}
