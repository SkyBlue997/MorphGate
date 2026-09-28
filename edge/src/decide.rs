//! The Decision Core of a site environment and what the Edge does with its
//! decision (docs/impl/phase1-spec.md §5.4-§5.7, §9.9; WP-E1b).
//!
//! * [`build_core`]: one [`DecisionCore`] per bundle environment: the Phase 1
//!   detectors, `ScorerV1` with the bundle's `scoring`, and a [`SitePolicy`]
//!   with the environment's rules, the site's named lists and the engine
//!   settings (`theta_c` feeds both the scorer and the matrix; a `kappa` of
//!   0 means the profile default; a partial `family_modes` map keeps the
//!   defaults, so EDGE_TLS stays in shadow unless the bundle says otherwise).
//! * [`enforce`]: the §9.9 execution layer on top of the engine's decision:
//!   monitor (record only), `fail_closed` routes with an unknown client IP
//!   (429), a challenge for an unknown client IP (429, never a `C`), and
//!   `Early-Data` on critical routes (425).
//! * [`DecisionRecord`]: everything WP-E1d needs for the decision event.
//! * [`evaluate`]: one request from the facts to the record (§1.4 steps
//!   6-10): context, clearance, crawler, the state round trip, the Decision
//!   Core, the execution layer.

use crate::context::{self, Facts};
use crate::identity::{self, RdnsDispatcher};
use crate::metrics::metrics;
use crate::ratelimit::{self, Plan, Subject};
use crate::sites::{BundleRuntime, EnvRuntime};
use mg_challenge::BindInputs;
use mg_core::policy::{CrawlerAction, CrawlerPolicy, EngineConfig, NamedLists, Rule, SitePolicy};
use mg_core::{
    Action, ChallengeType, Decision, DecisionCore, FamilyMode, RequestContext, RequestExtras,
    RiskAssessment, RouteInfo, RouteSensitivity, RuleHit, ScoringConfig, Signal, SignalFamily,
};
use mg_edge_core::state::StateHandle;
use mg_proto::v1 as pb;
use std::collections::BTreeMap;
use std::time::Instant;

/// `rule_id` of the §9.9 / D-23 substitutions for an unknown client IP.
pub const CLIENT_IP_UNKNOWN_RULE: &str = "hard.client_ip_unknown";
/// `Retry-After` of the unknown-client-IP answers (§9.3.2).
pub const CLIENT_IP_UNKNOWN_RETRY_S: u32 = 5;
/// `retry_after_s` of a RATE_LIMIT decision without one (§5.4 default).
pub const DEFAULT_RETRY_AFTER_S: u32 = 60;

/// Converts the bundle's `scoring` (§8.3: always fully populated by the
/// builder; the Edge back-fills only an absent message) into the scorer's
/// configuration. Keys and values were validated by `verify_bundle`;
/// anything unknown is skipped rather than guessed.
pub fn scoring_config(s: &pb::ScoringConfig) -> ScoringConfig {
    let d = ScoringConfig::default();
    let mut z0 = d.z0;
    for (i, name) in ["low", "medium", "high", "critical"].iter().enumerate() {
        if let Some(v) = s.z0.get(*name) {
            z0[i] = *v;
        }
    }
    let family_modes = s
        .family_modes
        .iter()
        .filter_map(|(family, mode)| {
            let family: SignalFamily = family.parse().ok()?;
            let mode = match mode.as_str() {
                "active" => FamilyMode::Active,
                "shadow" => FamilyMode::Shadow,
                "off" => FamilyMode::Off,
                _ => return None,
            };
            Some((family, mode))
        })
        .collect();
    ScoringConfig {
        theta_c: s.theta_c,
        kappa: (s.kappa != 0.0).then_some(s.kappa),
        z0,
        family_modes,
        weights: s.weights.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        h_min: s.h_min,
        ruleset_version: s.ruleset_version.clone(),
    }
}

/// The engine settings: `theta_c` (the same value as the scorer's) and the
/// crawler policy; interactive challenges do not exist in Phase 1 (D-08).
pub fn engine_config(s: &pb::ScoringConfig, c: &pb::CrawlerPolicy) -> EngineConfig {
    let action = |v: &str| match v {
        "block" => CrawlerAction::Block,
        _ => CrawlerAction::Allow,
    };
    EngineConfig {
        theta_c: s.theta_c,
        crawler_policy: CrawlerPolicy {
            purposes: c
                .purposes
                .iter()
                .map(|(p, v)| (p.clone(), action(v)))
                .collect::<BTreeMap<_, _>>(),
            default_action: action(&c.default_action),
        },
        interactive_available: false,
    }
}

/// The Decision Core of one environment (see the module documentation).
pub fn build_core(
    rules: Vec<Rule>,
    lists: NamedLists,
    scoring: &pb::ScoringConfig,
    crawler: &pb::CrawlerPolicy,
) -> DecisionCore {
    let policy = SitePolicy::new(rules, lists, engine_config(scoring, crawler));
    DecisionCore::phase1(scoring_config(scoring), Box::new(policy))
}

/// What the Edge does with a request after the decision (§9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// ALLOW / TAG / LOG, and every decision under monitor or bootstrap-open:
    /// the request goes to the origin.
    Forward,
    /// 403 block page / JSON.
    Block,
    /// 429 with `Retry-After`.
    RateLimit { retry_after_s: u32 },
    /// Challenge of this type (answered by WP-E1c's challenge flow).
    Challenge(ChallengeType),
    /// A challenge for a request whose client IP is unknown: 429 +
    /// `Retry-After: 5`, no `C` is ever issued (D-23). The decision in the
    /// event stays the engine's (§5.4).
    ChallengeClientIpUnknown,
    /// `Early-Data: 1` on a critical route: 425 (§9.9).
    TooEarly,
}

impl Enforcement {
    /// The HTTP status the Edge answers with; `None` = forwarded.
    pub fn status(self) -> Option<u16> {
        match self {
            Self::Forward => None,
            Self::Block => Some(403),
            Self::RateLimit { .. } | Self::ChallengeClientIpUnknown => Some(429),
            Self::Challenge(_) => Some(403),
            Self::TooEarly => Some(425),
        }
    }
}

/// Facts about the request that the execution layer needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforceInput<'a> {
    pub route: &'a RouteInfo,
    /// The client IP is known.
    pub client_ip_known: bool,
    /// The request carries `Early-Data` (any instance counts as `1`,
    /// `crate::context::early_data`).
    pub early_data: bool,
    /// Global monitor (`SiteBundle.monitor_only`): record, never enforce.
    pub monitor: bool,
}

/// The §9.9 execution layer. Returns the decision to record (the engine's,
/// except for the `fail_closed` substitution) and what to do.
///
/// * `fail_closed` route and client IP unknown: the decision becomes
///   RATE_LIMIT 429, `Retry-After: 5`, `rule_id = hard.client_ip_unknown`
///   (also under monitor, where it is only recorded). A BLOCK or RATE_LIMIT
///   decision is already a denial and is kept, so the substitution never
///   answers more permissively than the engine.
/// * monitor: `dry_run = true`, forwarded as ALLOW.
/// * CHALLENGE with an unknown client IP: 429 without a `C` (D-23); the
///   recorded decision is unchanged (§5.4).
/// * `Early-Data: 1` on a critical route that would be forwarded: 425.
/// * An action the Phase 1 Edge cannot execute (TARPIT, unspecified) is
///   never forwarded: it is answered like BLOCK (fail closed).
pub fn enforce(engine: Decision, input: &EnforceInput<'_>) -> (Decision, Enforcement) {
    let mut d = engine;
    let denied = matches!(d.action, Action::Block | Action::RateLimit);
    if input.route.fail_closed && !input.client_ip_known && !denied {
        d = Decision {
            action: Action::RateLimit,
            status: Some(429),
            retry_after_s: Some(CLIENT_IP_UNKNOWN_RETRY_S),
            rule_id: Some(CLIENT_IP_UNKNOWN_RULE.to_string()),
            ..Decision::default()
        };
    }
    if input.monitor {
        d.dry_run = true;
        return (d, Enforcement::Forward);
    }
    let enforcement = match d.action {
        Action::Allow | Action::Tag | Action::Log => {
            if input.early_data && input.route.sensitivity == RouteSensitivity::Critical {
                Enforcement::TooEarly
            } else {
                Enforcement::Forward
            }
        }
        Action::RateLimit => Enforcement::RateLimit {
            retry_after_s: d
                .retry_after_s
                .filter(|s| *s > 0)
                .unwrap_or(DEFAULT_RETRY_AFTER_S),
        },
        Action::Challenge if !input.client_ip_known => Enforcement::ChallengeClientIpUnknown,
        Action::Challenge => Enforcement::Challenge(d.challenge_type),
        Action::Block | Action::Tarpit | Action::Unspecified => Enforcement::Block,
    };
    (d, enforcement)
}

/// One evaluated request: the inputs and outputs of the Decision Core and
/// what the Edge did (the material of the §13.2 decision event, WP-E1d).
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    /// With `availability_mask` back-filled after the evaluation (§9.5).
    pub ctx: RequestContext,
    /// `Evaluation::event_signals(profile)` (§5.7).
    pub signals: Vec<Signal>,
    pub risk: RiskAssessment,
    /// The recorded decision (after [`enforce`]'s substitutions; `dry_run`
    /// under monitor).
    pub decision: Decision,
    pub hits: Vec<RuleHit>,
    /// A LOG rule matched (100 % sampling, §9.11).
    pub force_log: bool,
    /// `DecisionCore::evaluate` time.
    pub latency_us: u32,
    pub bundle_version: u64,
    pub monitor_only: bool,
    pub route: RouteInfo,
    pub enforcement: Enforcement,
    /// The request's challenge / clearance bindings (§6.4), which a
    /// CHALLENGE seals into its `C` (WP-E1c). `Debug` shows presence only.
    pub bind: BindInputs,
}

impl DecisionRecord {
    /// The rule that decided (`matrix.*`, a policy rule id,
    /// `ratelimit.<id>`, `hard.client_ip_unknown`).
    pub fn rule_id(&self) -> &str {
        self.decision.rule_id.as_deref().unwrap_or("-")
    }

    /// `rule:outcome` of every hit, for the debug log line (rule ids and
    /// outcomes only: nothing about the client).
    pub fn hits_summary(&self) -> String {
        let hits: Vec<String> = self
            .hits
            .iter()
            .map(|h| format!("{}:{}", h.rule_id, h.outcome))
            .collect();
        if hits.is_empty() {
            "-".into()
        } else {
            hits.join(",")
        }
    }
}

/// The shared handles [`evaluate`] uses.
#[derive(Clone, Copy)]
pub struct Services<'a> {
    pub state: &'a StateHandle,
    /// `K_pseudo` (§9.7 keys). Never printed (§2.4 item 4).
    pub k_pseudo: &'a [u8; 32],
    pub rdns: &'a RdnsDispatcher,
}

impl std::fmt::Debug for Services<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("state", self.state)
            .field("k_pseudo", &crate::logging::REDACTED)
            .field("rdns", self.rdns)
            .finish()
    }
}

/// Runs the Decision Core for one request of an active site (see the module
/// documentation). `facts.route` must be the route selected in `env`.
pub async fn evaluate(
    svc: Services<'_>,
    bundle: &BundleRuntime,
    env: &EnvRuntime,
    facts: &Facts<'_>,
) -> DecisionRecord {
    let site = facts.site_id;
    let mut built = context::build(facts, &bundle.intel);
    let ctx = &mut built.ctx;

    // Identity (§9.6): clearance, then the crawler claim.
    let bind = identity::bind_inputs(
        &built.ua,
        &ctx.net,
        ctx.edge_tls.as_ref(),
        bundle.clearance.ctp_shadow,
    );
    let cookies: Vec<&str> = built.cookies.iter().map(String::as_str).collect();
    let clearance = identity::verify_clearance(
        &bundle.token_keys,
        site,
        &facts.route.env,
        &cookies,
        &bind,
        facts.ts_ms.div_euclid(1000),
    );
    ctx.identity.token = clearance.token;
    ctx.session_id = clearance.session;
    let now_us = ratelimit::unix_now_us();
    if let Some(verifier) = &bundle.intel.crawler {
        // The whole User-Agent (§4.1 `req.headers`, ≤ 8 KiB), never the
        // 512-byte `ctx.http.user_agent`: the origin sees the whole header,
        // so a crawler token past byte 512 is still a claim to verify (§0:
        // attacker-controlled input size must not disable a rule).
        let ua = context::header(&built.headers, "user-agent").unwrap_or("");
        let (status, job) = verifier.check(ua, ctx.net.ip, facts.ts_ms);
        identity::apply_crawler(&mut ctx.identity.crawler, &status);
        identity::count_crawler(&status, ctx.identity.crawler.cf_vbot);
        if let Some(job) = job {
            // Dropped jobs are abandoned and counted inside.
            let _ = svc.rdns.submit(verifier, job, now_us);
        }
    }

    // State (§9.7, §9.8): verdicts and limiters in one round trip.
    let subject = Subject {
        ip: ctx.net.ip,
        asn: ctx.net.asn,
        asn_available: bundle.intel.has_asn(),
        session: ctx.session_id.as_deref(),
        route: &facts.route.name,
    };
    let state = ratelimit::run(
        svc.state,
        svc.k_pseudo,
        &Plan {
            site,
            env,
            route_id: &facts.route.id,
            subject,
            share_ip_verdicts: bundle.share_ip_verdicts,
            now_us,
        },
    )
    .await;
    ctx.verdicts = state.verdicts;

    // The Decision Core (§5.4-§5.7).
    let extras = RequestExtras {
        route: facts.route,
        headers: &built.headers,
        query: facts.query,
        rate: &state.rate,
        missing: &built.missing,
        ua: &built.ua,
        secure_context: built.secure_context,
    };
    let started = Instant::now();
    let eval = env.core.evaluate(&built.ctx, &extras);
    let elapsed = started.elapsed();
    let m = metrics();
    m.decision_latency
        .with_label_values(&[site])
        .observe(elapsed.as_secs_f64());
    let aborted = eval.outcome.step_limit_count();
    if aborted > 0 {
        m.policy_step_limit
            .with_label_values(&[site])
            .inc_by(aborted as u64);
    }
    built.ctx.availability_mask = eval.availability_mask();
    let signals = eval.event_signals(built.ctx.upstream.profile);

    // The execution layer (§9.9).
    let (decision, enforcement) = enforce(
        eval.outcome.decision,
        &EnforceInput {
            route: facts.route,
            client_ip_known: built.ctx.net.ip.is_some(),
            early_data: built.ctx.http.early_data,
            monitor: bundle.monitor_only,
        },
    );
    DecisionRecord {
        ctx: built.ctx,
        signals,
        risk: eval.risk,
        decision,
        hits: eval.outcome.hits,
        force_log: eval.outcome.force_log,
        latency_us: u32::try_from(elapsed.as_micros()).unwrap_or(u32::MAX),
        bundle_version: bundle.version,
        monitor_only: bundle.monitor_only,
        route: facts.route.clone(),
        enforcement,
        bind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::Channel;

    fn route(sensitivity: RouteSensitivity, fail_closed: bool) -> RouteInfo {
        RouteInfo {
            id: "r".into(),
            name: "r".into(),
            env: "production".into(),
            channel: Channel::Web,
            sensitivity,
            require_clearance: false,
            fail_closed,
        }
    }

    fn input(route: &RouteInfo, ip: bool, early: bool, monitor: bool) -> EnforceInput<'_> {
        EnforceInput {
            route,
            client_ip_known: ip,
            early_data: early,
            monitor,
        }
    }

    fn block() -> Decision {
        Decision {
            action: Action::Block,
            status: Some(403),
            rule_id: Some("b".into()),
            ..Decision::default()
        }
    }

    #[test]
    fn forwarded_and_denied_decisions() {
        let r = route(RouteSensitivity::Low, false);
        let (d, e) = enforce(Decision::allow(), &input(&r, true, false, false));
        assert_eq!((d.action, e), (Action::Allow, Enforcement::Forward));
        assert!(!d.dry_run);
        let (_, e) = enforce(block(), &input(&r, true, false, false));
        assert_eq!(e, Enforcement::Block);
        let rl = Decision {
            action: Action::RateLimit,
            status: Some(429),
            retry_after_s: Some(30),
            ..Decision::default()
        };
        let (_, e) = enforce(rl.clone(), &input(&r, true, false, false));
        assert_eq!(e, Enforcement::RateLimit { retry_after_s: 30 });
        let (_, e) = enforce(
            Decision {
                retry_after_s: None,
                ..rl
            },
            &input(&r, true, false, false),
        );
        assert_eq!(
            e,
            Enforcement::RateLimit {
                retry_after_s: DEFAULT_RETRY_AFTER_S
            }
        );
        let (_, e) = enforce(
            Decision::challenge(ChallengeType::Pow),
            &input(&r, true, false, false),
        );
        assert_eq!(e, Enforcement::Challenge(ChallengeType::Pow));
    }

    /// D-23: a challenge is never issued for an unknown client IP; the
    /// recorded decision stays the engine's (§5.4).
    #[test]
    fn challenge_without_client_ip_is_429() {
        let r = route(RouteSensitivity::Medium, false);
        let engine = Decision {
            rule_id: Some("matrix.high".into()),
            ..Decision::challenge(ChallengeType::Invisible)
        };
        let (d, e) = enforce(engine.clone(), &input(&r, false, false, false));
        assert_eq!(e, Enforcement::ChallengeClientIpUnknown);
        assert_eq!(e.status(), Some(429));
        assert_eq!(d, engine);
    }

    /// §9.9: a fail_closed route with an unknown client IP is 429 whatever
    /// the engine said, except that a denial stays a denial.
    #[test]
    fn fail_closed_route_without_client_ip() {
        let r = route(RouteSensitivity::Critical, true);
        for engine in [
            Decision::allow(),
            Decision::challenge(ChallengeType::Pow),
            Decision {
                action: Action::Tag,
                tags: vec!["x".into()],
                ..Decision::default()
            },
        ] {
            let (d, e) = enforce(engine, &input(&r, false, false, false));
            assert_eq!(
                e,
                Enforcement::RateLimit {
                    retry_after_s: CLIENT_IP_UNKNOWN_RETRY_S
                }
            );
            assert_eq!(d.rule_id.as_deref(), Some(CLIENT_IP_UNKNOWN_RULE));
            assert_eq!(d.action, Action::RateLimit);
            assert_eq!(d.validate(), Ok(()));
        }
        let (d, e) = enforce(block(), &input(&r, false, false, false));
        assert_eq!((d.rule_id.as_deref(), e), (Some("b"), Enforcement::Block));
        // With a known IP nothing changes.
        let (d, e) = enforce(Decision::allow(), &input(&r, true, false, false));
        assert_eq!((d.action, e), (Action::Allow, Enforcement::Forward));
    }

    /// Monitor records the decision (dry_run) and forwards; the fail_closed
    /// substitution is recorded as well.
    #[test]
    fn monitor_only_records() {
        let r = route(RouteSensitivity::Critical, true);
        let (d, e) = enforce(block(), &input(&r, true, true, true));
        assert_eq!(e, Enforcement::Forward);
        assert!(d.dry_run);
        assert_eq!(d.action, Action::Block);
        let (d, e) = enforce(Decision::allow(), &input(&r, false, false, true));
        assert_eq!(e, Enforcement::Forward);
        assert!(d.dry_run);
        assert_eq!(d.rule_id.as_deref(), Some(CLIENT_IP_UNKNOWN_RULE));
    }

    #[test]
    fn early_data_on_critical_routes_is_425() {
        let critical = route(RouteSensitivity::Critical, false);
        let high = route(RouteSensitivity::High, false);
        let (_, e) = enforce(Decision::allow(), &input(&critical, true, true, false));
        assert_eq!((e, e.status()), (Enforcement::TooEarly, Some(425)));
        let (_, e) = enforce(Decision::allow(), &input(&high, true, true, false));
        assert_eq!(e, Enforcement::Forward);
        let (_, e) = enforce(block(), &input(&critical, true, true, false));
        assert_eq!(e, Enforcement::Block, "a denial stays a denial");
    }

    #[test]
    fn unexecutable_actions_fail_closed() {
        let r = route(RouteSensitivity::Low, false);
        for action in [Action::Tarpit, Action::Unspecified] {
            let d = Decision {
                action,
                ..Decision::default()
            };
            assert_eq!(
                enforce(d, &input(&r, true, false, false)).1,
                Enforcement::Block
            );
        }
    }

    /// §2.4 item 4: `Debug` of the request-path handles never prints
    /// `K_pseudo`.
    #[test]
    fn services_debug_hides_the_pseudonymization_key() {
        use mg_edge_core::state::{StateConfig, StateService};
        let key = [0xabu8; 32];
        let (_service, state) = StateService::new(StateConfig::local(key));
        let (rdns, _rx) = RdnsDispatcher::new(1, 1, 1, state.clone());
        let svc = Services {
            state: &state,
            k_pseudo: &key,
            rdns: &rdns,
        };
        let text = format!("{svc:?}");
        assert!(!text.contains("171"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("abab"), "{text}");
        assert!(text.contains("k_pseudo"), "{text}");
    }

    #[test]
    fn scoring_and_engine_config_from_the_bundle() {
        let pb_scoring = pb::ScoringConfig {
            theta_c: 0.5,
            kappa: 0.0,
            z0: [("high".to_string(), -1.0f32)].into(),
            family_modes: [
                ("http".to_string(), "shadow".to_string()),
                ("bogus".to_string(), "off".to_string()),
            ]
            .into(),
            weights: [("http.ua_library".to_string(), 2.5f32)].into(),
            h_min: -3.0,
            ruleset_version: "r7".into(),
        };
        let s = scoring_config(&pb_scoring);
        assert_eq!(s.theta_c, 0.5);
        assert_eq!(s.kappa, None, "kappa 0 = profile default");
        let d = ScoringConfig::default();
        assert_eq!(s.z0, [d.z0[0], d.z0[1], -1.0, d.z0[3]]);
        assert_eq!(s.family_mode(SignalFamily::Http), FamilyMode::Shadow);
        // A partial map keeps the defaults: EDGE_TLS stays in shadow.
        assert_eq!(s.family_mode(SignalFamily::EdgeTls), FamilyMode::Shadow);
        assert_eq!(s.family_mode(SignalFamily::Network), FamilyMode::Active);
        assert_eq!(s.weights["http.ua_library"], 2.5);
        assert_eq!((s.h_min, s.ruleset_version.as_str()), (-3.0, "r7"));
        let s = scoring_config(&pb::ScoringConfig {
            kappa: 0.8,
            ..pb_scoring.clone()
        });
        assert_eq!(s.kappa, Some(0.8));

        let crawler = pb::CrawlerPolicy {
            purposes: [("ai_training".to_string(), "block".to_string())].into(),
            default_action: "allow".into(),
        };
        let e = engine_config(&pb_scoring, &crawler);
        assert_eq!(e.theta_c, 0.5, "the scorer's theta_c feeds the matrix");
        assert_eq!(e.crawler_policy.action("ai_training"), CrawlerAction::Block);
        assert_eq!(e.crawler_policy.action("search"), CrawlerAction::Allow);
        assert!(!e.interactive_available);
    }
}
