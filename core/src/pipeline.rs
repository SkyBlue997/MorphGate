//! Decision pipeline contracts (docs/03 §1, docs/impl/phase1-spec.md §5.6).
//!
//! ```text
//! RequestContext + RequestExtras -> [Detector]* -> [Signal] -> Scorer -> RiskAssessment
//!                                -> PolicyEvaluator -> PolicyOutcome { Decision, hits, force_log }
//! ```
//!
//! All three traits are synchronous and pure: implementations must not do
//! I/O, block, read clocks or keep interior mutable state that changes the
//! result for identical inputs. Anything stateful (rate counters, near-line
//! verdicts, token replay sets) is resolved by the host *before* the call and
//! arrives as data: verdicts in [`RequestContext::verdicts`], limiter state in
//! [`RequestExtras::rate`]. That makes every decision reproducible from its
//! [`crate::DecisionEvent`] plus the bundle.

use crate::context::RequestContext;
use crate::decision::{Decision, RiskAssessment, RuleHit};
use crate::enums::{SignalFamily, SignalState, UpstreamProfileKind};
use crate::extras::RequestExtras;
use crate::mask::FamilyMask;
use crate::scoring::{ScorerV1, ScoringConfig};
use crate::signal::Signal;
use std::fmt;

/// Turns request facts into [`Signal`]s.
pub trait Detector: Send + Sync {
    /// Stable identifier, used in metrics and to enable / disable the detector.
    fn id(&self) -> &'static str;

    /// Families this detector may emit. Emitting any other family is a bug;
    /// [`DecisionCore`] drops such signals (and panics in debug builds).
    fn families(&self) -> FamilyMask;

    /// Appends zero or more signals for this request to `out`.
    ///
    /// Must be pure and cheap (the whole pipeline budget is a few hundred µs).
    /// Unavailable input is never evidence: if the fields a detector needs are
    /// `ABSENT` or `MISSING`, it emits nothing or a value-less signal
    /// ([`Signal::without_input`]), never a "human" signal.
    fn detect(&self, ctx: &RequestContext, extras: &RequestExtras<'_>, out: &mut Vec<Signal>);
}

/// Combines signals and entity verdicts into a [`RiskAssessment`].
pub trait Scorer: Send + Sync {
    /// Lets the scorer annotate signals before scoring and logging, e.g. mark
    /// the signals of a family that runs in shadow. The default does nothing.
    fn annotate(&self, _signals: &mut [Signal]) {}

    /// Scores one request. Only [`Signal::is_scored`] signals count toward
    /// `score`; shadow ones only toward `shadow_score`. `ctx.verdicts` may
    /// include expired entries and other sites' entries: use
    /// [`RequestContext::active_verdicts`] and
    /// [`crate::EntityVerdict::applies_to_site`].
    fn score(
        &self,
        ctx: &RequestContext,
        extras: &RequestExtras<'_>,
        signals: &[Signal],
    ) -> RiskAssessment;
}

/// Everything a [`PolicyEvaluator`] sees.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub ctx: &'a RequestContext,
    pub extras: &'a RequestExtras<'a>,
    pub signals: &'a [Signal],
    pub risk: &'a RiskAssessment,
}

/// A policy decision with its evaluation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    /// Passes [`Decision::validate`]. The global monitor switch and the
    /// client-IP-unknown / http-visitor substitutions are applied by the host.
    pub decision: Decision,
    /// Rules and limiters that matched or could not be evaluated, at most
    /// [`crate::DecisionEvent::MAX_HITS`], in evaluation order.
    pub hits: Vec<RuleHit>,
    /// A LOG rule matched: keep this request's decision event at 100%.
    pub force_log: bool,
}

/// Maps an assessment to an enforcement [`Decision`] using the site's policy.
pub trait PolicyEvaluator: Send + Sync {
    /// Decides for one request.
    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyOutcome;
}

/// Result of one pass through the pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub signals: Vec<Signal>,
    pub risk: RiskAssessment,
    pub outcome: PolicyOutcome,
}

impl Evaluation {
    /// Families with at least one `PRESENT` signal: the context's
    /// `availability_mask`, which the host back-fills after the run (§9.5).
    pub fn availability_mask(&self) -> FamilyMask {
        self.signals
            .iter()
            .filter(|s| s.state == SignalState::Present)
            .map(|s| s.family)
            .collect()
    }

    /// The signals a decision event records (§5.7): `PRESENT` with a non-zero
    /// value, `ABSENT`, and `MISSING` only where the profile expects the input
    /// (an upstream header that did not arrive), never for inputs the profile
    /// cannot supply or the route does not configure.
    pub fn event_signals(&self, profile: UpstreamProfileKind) -> Vec<Signal> {
        self.signals
            .iter()
            .filter(|s| match s.state {
                SignalState::Present => s.value.get() != 0.0,
                SignalState::Absent => true,
                SignalState::Missing => crate::detectors::missing_is_expected(&s.id, profile),
                SignalState::Unspecified => false,
            })
            .cloned()
            .collect()
    }
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

    /// The Phase 1 pipeline: [`crate::detectors::phase1_detectors`] and [`ScorerV1`].
    pub fn phase1(scoring: ScoringConfig, policy: Box<dyn PolicyEvaluator>) -> Self {
        Self {
            detectors: crate::detectors::phase1_detectors(),
            scorer: Box::new(ScorerV1::new(scoring)),
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
    pub fn evaluate(&self, ctx: &RequestContext, extras: &RequestExtras<'_>) -> Evaluation {
        let mut signals = Vec::new();
        for detector in &self.detectors {
            let start = signals.len();
            detector.detect(ctx, extras, &mut signals);
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
        self.scorer.annotate(&mut signals);
        let risk = self.scorer.score(ctx, extras, &signals);
        let outcome = self.policy.evaluate(&PolicyInput {
            ctx,
            extras,
            signals: &signals,
            risk: &risk,
        });
        Evaluation {
            signals,
            risk,
            outcome,
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

/// A family bit helper for detectors that emit exactly one family.
pub(crate) fn only(family: SignalFamily) -> FamilyMask {
    FamilyMask::of(&[family])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::EntityVerdict;
    use crate::enums::{Action, ChallengeType, EntityType};
    use crate::extras::RouteInfo;
    use crate::policy::MissingSet;
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
        fn detect(&self, ctx: &RequestContext, _: &RequestExtras<'_>, out: &mut Vec<Signal>) {
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
        fn score(
            &self,
            ctx: &RequestContext,
            _: &RequestExtras<'_>,
            signals: &[Signal],
        ) -> RiskAssessment {
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
        fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyOutcome {
            let decision = if input.risk.score.get() >= 40 {
                Decision::challenge(ChallengeType::Invisible)
            } else {
                Decision::allow()
            };
            PolicyOutcome {
                decision,
                hits: Vec::new(),
                force_log: false,
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
        fn detect(&self, _: &RequestContext, _: &RequestExtras<'_>, out: &mut Vec<Signal>) {
            out.push(Signal::new("tls.fake", SignalFamily::Tls, 1.0, 1.0));
        }
    }

    fn core() -> DecisionCore {
        DecisionCore::new(Box::new(SumScorer), Box::new(Threshold))
            .with_detector(Box::new(NoUserAgent))
    }

    fn run(core: &DecisionCore, ctx: &RequestContext) -> Evaluation {
        let route = RouteInfo::default();
        let missing = MissingSet::default();
        let ua = crate::ua::parse(ctx.http.user_agent.as_deref().unwrap_or(""));
        let extras = RequestExtras {
            route: &route,
            headers: &[],
            query: "",
            rate: &[],
            missing: &missing,
            ua: &ua,
            secure_context: true,
        };
        core.evaluate(ctx, &extras)
    }

    #[test]
    fn pipeline_runs_detectors_scorer_policy() {
        let ctx = RequestContext::new("r", "s", 0);
        let ev = run(&core(), &ctx);
        assert_eq!(ev.signals.len(), 1);
        assert_eq!(ev.risk.score.get(), 45);
        assert_eq!(ev.outcome.decision.action, Action::Challenge);
        assert_eq!(ev.outcome.decision.validate(), Ok(()));
        assert_eq!(
            ev.availability_mask(),
            FamilyMask::of(&[SignalFamily::Http])
        );

        let mut ctx = ctx;
        ctx.http.user_agent = Some("Mozilla/5.0".into());
        let ev = run(&core(), &ctx);
        assert!(ev.signals.is_empty());
        assert_eq!(ev.outcome.decision, Decision::allow());
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
        assert_eq!(run(&core(), &ctx).risk.score.get(), 90);
        ctx.ts_ms = 2_000;
        assert_eq!(run(&core(), &ctx).risk.score.get(), 0);
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
        assert_eq!(run(&core(), &ctx).risk.score.get(), 0);
        ctx.verdicts = vec![verdict(EntityType::Session, EntityVerdict::ALL_SITES)];
        assert_eq!(run(&core(), &ctx).risk.score.get(), 0);
        ctx.verdicts = vec![verdict(EntityType::Asn, EntityVerdict::ALL_SITES)];
        assert_eq!(run(&core(), &ctx).risk.score.get(), 80);
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "undeclared family"))]
    fn undeclared_families_are_rejected() {
        let core = DecisionCore::new(Box::new(SumScorer), Box::new(Threshold))
            .with_detector(Box::new(Liar));
        let ev = run(&core, &RequestContext::default());
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
