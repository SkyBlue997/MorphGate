//! The rule engine (docs/impl/phase1-spec.md §5.4): ordered policy rules,
//! rate-limiter outcomes and the default matrix (§5.5) combined into one
//! [`Decision`] plus the per-rule hits of the decision event.

use super::eval::{EvalError, EvalResult, eval};
use super::fields::Activation;
use super::ip::NamedLists;
use super::ir::Program;
use super::matrix::{effective_challenge, matrix};
use crate::context::RequestContext;
use crate::decision::{Decision, DecisionEvent, HitOutcome, RuleHit};
use crate::enums::{Action, ChallengeType};
use crate::extras::{LimiterAction, RateObservation};
use crate::pipeline::{PolicyEvaluator, PolicyInput, PolicyOutcome};
use std::collections::BTreeMap;
use std::fmt;

wire_enum! {
    /// Rule phase, in evaluation order (`CompiledRule.phase`).
    pub enum Phase {
        Identity => "identity",
        Protocol => "protocol",
        RateLimit => "rate_limit",
        Bot => "bot",
        Custom => "custom",
        Default => "default",
    }
}

wire_enum! {
    /// Whether a rule (or limiter) is enforced or only recorded.
    pub enum RuleMode {
        Enforce => "enforce",
        DryRun => "dry_run",
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// Terminal: let the request through.
    Allow,
    /// Non-terminal: log this request's decision event at 100%.
    Log,
    /// Non-terminal: add `label` to `MG-Tags`.
    Tag { label: String },
    /// Terminal: 429 with this `Retry-After`.
    RateLimit { retry_after_s: u32 },
    /// Terminal: challenge (`interactive` runs as `pow` in Phase 1, D-08).
    Challenge(ChallengeType),
    /// Terminal: 403.
    Block,
}

impl RuleAction {
    /// The wire [`Action`] of this rule action.
    pub fn action(&self) -> Action {
        match self {
            Self::Allow => Action::Allow,
            Self::Log => Action::Log,
            Self::Tag { .. } => Action::Tag,
            Self::RateLimit { .. } => Action::RateLimit,
            Self::Challenge(_) => Action::Challenge,
            Self::Block => Action::Block,
        }
    }
}

/// One compiled policy rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub phase: Phase,
    /// Higher runs first within a phase; ties by `id` (bytewise ascending).
    pub priority: i32,
    pub program: Program,
    pub action: RuleAction,
    pub mode: RuleMode,
    /// `0..=100`; share of rollout units the rule applies to.
    pub rollout_percent: u8,
    /// Unix ms after which the rule is skipped; 0 = never.
    pub expires_at_ms: i64,
}

wire_enum! {
    /// What the matrix does with a verified crawler of some purpose.
    #[derive(Default)]
    pub enum CrawlerAction {
        #[default]
        Allow => "allow",
        Block => "block",
    }
}

/// Per-purpose crawler treatment (`SiteBundle.crawler_policy`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrawlerPolicy {
    pub purposes: BTreeMap<String, CrawlerAction>,
    pub default_action: CrawlerAction,
}

impl CrawlerPolicy {
    /// `purposes[purpose]`, else `default_action`.
    pub fn action(&self, purpose: &str) -> CrawlerAction {
        self.purposes
            .get(purpose)
            .copied()
            .unwrap_or(self.default_action)
    }
}

/// Engine settings from the site bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineConfig {
    /// Confidence below which a medium-band request is challenged (`scoring.theta_c`).
    pub theta_c: f32,
    pub crawler_policy: CrawlerPolicy,
    /// Interactive challenges exist (Phase 2). `false` in Phase 1: every
    /// `interactive` runs as `pow` (D-08).
    pub interactive_available: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            theta_c: 0.4,
            crawler_policy: CrawlerPolicy::default(),
            interactive_available: false,
        }
    }
}

/// The policy of one site environment: rules in evaluation order, the named
/// lists they reference and the engine settings.
pub struct SitePolicy {
    rules: Vec<Rule>,
    lists: NamedLists,
    config: EngineConfig,
}

impl fmt::Debug for SitePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SitePolicy")
            .field(
                "rules",
                &self.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            )
            .field("lists", &self.lists.names().collect::<Vec<_>>())
            .field("config", &self.config)
            .finish()
    }
}

/// Hit annotation of a rule or limiter whose `interactive` ran as `pow` (D-08).
pub const INTERACTIVE_AS_POW: &str = "phase1.interactive_as_pow";

impl SitePolicy {
    /// Sorts `rules` into evaluation order: phase, then `priority`
    /// descending, then `id` bytewise ascending (§5.4, D-19).
    pub fn new(mut rules: Vec<Rule>, lists: NamedLists, config: EngineConfig) -> Self {
        rules.sort_by(|a, b| {
            a.phase
                .cmp(&b.phase)
                .then(b.priority.cmp(&a.priority))
                .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
        });
        Self {
            rules,
            lists,
            config,
        }
    }

    /// The rules in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The engine settings.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// The named lists.
    pub fn lists(&self) -> &NamedLists {
        &self.lists
    }
}

/// FNV-1a, 64 bit.
fn fnv1a64(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for &b in *part {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// §5.4 `in_rollout`: `fnv1a64("mg-rollout-v1" ‖ 0x00 ‖ rule_id ‖ 0x00 ‖ unit) % 100 < percent`.
pub fn in_rollout(rule_id: &str, unit: &str, rollout_percent: u8) -> bool {
    match rollout_percent {
        0 => false,
        p if p >= 100 => true,
        p => {
            let h = fnv1a64(&[
                b"mg-rollout-v1",
                &[0],
                rule_id.as_bytes(),
                &[0],
                unit.as_bytes(),
            ]);
            h % 100 < u64::from(p)
        }
    }
}

/// The rollout unit of a request: session, else IP prefix, else request id.
fn rollout_unit(ctx: &RequestContext) -> &str {
    [
        ctx.session_id.as_deref(),
        ctx.net.ip_prefix.as_deref(),
        Some(ctx.request_id.as_str()),
    ]
    .into_iter()
    .flatten()
    .find(|s| !s.is_empty())
    .unwrap_or("")
}

/// Per-request engine state.
struct Run {
    tags: Vec<String>,
    force_log: bool,
    hits: Vec<RuleHit>,
}

impl Run {
    fn hit(
        &mut self,
        rule_id: String,
        outcome: HitOutcome,
        mode: RuleMode,
        action: Action,
        fields: Vec<String>,
    ) {
        if self.hits.len() < DecisionEvent::MAX_HITS {
            self.hits.push(RuleHit {
                rule_id,
                outcome,
                mode,
                action,
                fields,
            });
        }
    }

    /// §5.4 `finish(d)`.
    fn finish(self, mut d: Decision) -> PolicyOutcome {
        if d.action == Action::Allow {
            if !self.tags.is_empty() {
                d.action = Action::Tag;
            } else if self.force_log {
                d.action = Action::Log;
            }
        }
        if d.action == Action::Tag {
            let mut tags: Vec<String> = Vec::new();
            // Labels are validated when the rule is loaded; an invalid one
            // (hand-built rule) is dropped rather than forwarded.
            for t in self.tags {
                if tags.len() == Decision::MAX_TAGS {
                    break;
                }
                if Decision::is_valid_tag(&t) && !tags.contains(&t) {
                    tags.push(t);
                }
            }
            d.tags = tags;
        }
        PolicyOutcome {
            decision: d,
            hits: self.hits,
            force_log: self.force_log,
        }
    }
}

impl SitePolicy {
    fn rule_decision(&self, r: &Rule) -> Decision {
        let mut d = match &r.action {
            RuleAction::Allow | RuleAction::Log | RuleAction::Tag { .. } => Decision::allow(),
            RuleAction::Block => Decision {
                action: Action::Block,
                status: Some(403),
                ..Decision::default()
            },
            RuleAction::Challenge(t) => {
                Decision::challenge(effective_challenge(*t, self.config.interactive_available))
            }
            RuleAction::RateLimit { retry_after_s } => Decision {
                action: Action::RateLimit,
                status: Some(429),
                retry_after_s: Some(*retry_after_s),
                ..Decision::default()
            },
        };
        d.rule_id = Some(r.id.clone());
        d
    }

    fn interactive_note(&self, t: ChallengeType) -> Vec<String> {
        if t == ChallengeType::Interactive && !self.config.interactive_available {
            vec![INTERACTIVE_AS_POW.to_string()]
        } else {
            Vec::new()
        }
    }

    /// Evaluates `rules` in order; returns the first terminal decision.
    fn eval_rules(
        &self,
        rules: &[Rule],
        input: &PolicyInput<'_>,
        act: &Activation,
        run: &mut Run,
    ) -> Option<Decision> {
        let now_ms = input.ctx.ts_ms;
        let unit = rollout_unit(input.ctx);
        for r in rules {
            if r.expires_at_ms != 0 && now_ms >= r.expires_at_ms {
                continue;
            }
            if !in_rollout(&r.id, unit, r.rollout_percent) {
                continue;
            }
            let action = r.action.action();
            match eval(&r.program, act, input.extras.missing, &self.lists) {
                EvalResult::False => continue,
                EvalResult::Unknown(paths) => {
                    let fields = paths.into_iter().map(str::to_string).collect();
                    run.hit(
                        r.id.clone(),
                        HitOutcome::MissingInput,
                        r.mode,
                        action,
                        fields,
                    );
                    continue;
                }
                EvalResult::Error(e) => {
                    run.hit(
                        r.id.clone(),
                        HitOutcome::EvalError,
                        r.mode,
                        action,
                        vec![e.to_string()],
                    );
                    continue;
                }
                EvalResult::True => {}
            }
            let fields = match r.action {
                RuleAction::Challenge(t) => self.interactive_note(t),
                _ => Vec::new(),
            };
            run.hit(r.id.clone(), HitOutcome::Matched, r.mode, action, fields);
            if r.mode == RuleMode::DryRun {
                continue;
            }
            match &r.action {
                RuleAction::Log => run.force_log = true,
                RuleAction::Tag { label } => run.tags.push(label.clone()),
                _ => return Some(self.rule_decision(r)),
            }
        }
        None
    }

    /// §5.4 `apply_limiters()`: the first exceeded enforce-mode limiter with
    /// a decision action is terminal; dry-run limiters only leave a hit.
    fn apply_limiters(&self, rate: &[RateObservation], run: &mut Run) -> Option<Decision> {
        for obs in rate.iter().filter(|o| o.exceeded) {
            let rule_id = format!("ratelimit.{}", obs.limiter_id);
            let (action, fields) = match obs.action {
                // A signal limiter never decides; a dry-run hit records it as "log".
                LimiterAction::Signal { .. } => (Action::Log, Vec::new()),
                LimiterAction::Challenge(t) => (Action::Challenge, self.interactive_note(t)),
                LimiterAction::RateLimit { .. } => (Action::RateLimit, Vec::new()),
                LimiterAction::Block => (Action::Block, Vec::new()),
            };
            if obs.dry_run {
                run.hit(
                    rule_id,
                    HitOutcome::Matched,
                    RuleMode::DryRun,
                    action,
                    fields,
                );
                continue;
            }
            let mut d = match obs.action {
                LimiterAction::Signal { .. } => continue,
                LimiterAction::RateLimit { retry_after_s } => {
                    let retry = if retry_after_s == 0 {
                        u32::try_from(obs.retry_after_ms.div_ceil(1000))
                            .unwrap_or(u32::MAX)
                            .max(1)
                    } else {
                        retry_after_s
                    };
                    Decision {
                        action: Action::RateLimit,
                        status: Some(429),
                        retry_after_s: Some(retry),
                        ..Decision::default()
                    }
                }
                LimiterAction::Block => Decision {
                    action: Action::Block,
                    status: Some(403),
                    ..Decision::default()
                },
                LimiterAction::Challenge(t) => {
                    Decision::challenge(effective_challenge(t, self.config.interactive_available))
                }
            };
            run.hit(
                rule_id.clone(),
                HitOutcome::Matched,
                RuleMode::Enforce,
                action,
                fields,
            );
            d.rule_id = Some(rule_id);
            return Some(d);
        }
        None
    }
}

impl PolicyEvaluator for SitePolicy {
    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyOutcome {
        let mut run = Run {
            tags: Vec::new(),
            force_log: false,
            hits: Vec::new(),
        };
        // Built once, and only when a rule can read it.
        let act = if self.rules.is_empty() {
            Activation::default()
        } else {
            Activation::build(input.ctx, input.extras, input.risk)
        };
        let split = self.rules.partition_point(|r| r.phase <= Phase::Protocol);
        let (early, late) = self.rules.split_at(split);
        if let Some(d) = self.eval_rules(early, input, &act, &mut run) {
            return run.finish(d);
        }
        if let Some(d) = self.apply_limiters(input.extras.rate, &mut run) {
            return run.finish(d);
        }
        if let Some(d) = self.eval_rules(late, input, &act, &mut run) {
            return run.finish(d);
        }
        let d = matrix(input.ctx, input.extras.route, input.risk, &self.config);
        run.finish(d)
    }
}

impl PolicyOutcome {
    /// Number of rules aborted by the runtime step limit (for
    /// `mg_policy_step_limit_total`; unreachable for valid bundles, §5.3).
    pub fn step_limit_count(&self) -> usize {
        self.hits
            .iter()
            .filter(|h| {
                h.outcome == HitOutcome::EvalError
                    && h.fields.iter().any(|f| f == EvalError::StepLimit.as_str())
            })
            .count()
    }
}
