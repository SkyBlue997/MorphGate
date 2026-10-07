//! §5.4 rule engine: phase order, priority, dry-run, LOG / TAG accumulation,
//! expiry, rollout, hit recording and the hit cap, limiter outcomes.

use super::dsl::*;
use super::*;
use crate::decision::{Decision, HitOutcome, RiskAssessment};
use crate::enums::{Action, BotClass, ChallengeType};
use crate::extras::{LimiterAction, RateObservation};
use crate::pipeline::{PolicyEvaluator, PolicyInput, PolicyOutcome};
use crate::testutil::Req;
use crate::values::{Confidence, Score};
use std::collections::BTreeMap;

fn rule(id: &str, phase: Phase, priority: i32, e: Expr, action: RuleAction) -> Rule {
    Rule {
        id: id.into(),
        phase,
        priority,
        program: prog(e),
        action,
        mode: RuleMode::Enforce,
        rollout_percent: 100,
        expires_at_ms: 0,
    }
}

fn low_risk() -> RiskAssessment {
    RiskAssessment {
        score: Score::new(10),
        confidence: Confidence::new(0.8),
        bot_class: BotClass::HumanLikely,
        ..RiskAssessment::default()
    }
}

fn decide(policy: &SitePolicy, req: &Req, risk: &RiskAssessment) -> PolicyOutcome {
    req.with(|ctx, extras| {
        policy.evaluate(&PolicyInput {
            ctx,
            extras,
            signals: &[],
            risk,
        })
    })
}

fn site(rules: Vec<Rule>) -> SitePolicy {
    let lists = NamedLists::new(BTreeMap::from([(
        "owner_cidrs".to_string(),
        vec!["10.0.0.0/8".to_string()],
    )]));
    SitePolicy::new(rules, lists, EngineConfig::default())
}

fn block() -> RuleAction {
    RuleAction::Block
}

fn tag(label: &str) -> RuleAction {
    RuleAction::Tag {
        label: label.into(),
    }
}

#[test]
fn sort_order_is_phase_then_priority_desc_then_id() {
    let p = site(vec![
        rule("b", Phase::Default, 0, t(), block()),
        rule("z", Phase::Bot, 1, t(), block()),
        rule("a", Phase::Bot, 1, t(), block()),
        rule("hi", Phase::Bot, 5, t(), block()),
        rule("neg", Phase::Bot, -3, t(), block()),
        rule("id", Phase::Identity, -100, t(), block()),
        rule("B", Phase::Bot, 1, t(), block()),
    ]);
    let ids: Vec<_> = p.rules().iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["id", "hi", "B", "a", "z", "neg", "b"]);
}

#[test]
fn first_terminal_rule_decides() {
    let p = site(vec![
        rule("bot-block", Phase::Bot, 0, t(), block()),
        rule("identity-allow", Phase::Identity, 0, t(), RuleAction::Allow),
    ]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.action, Action::Allow);
    assert_eq!(out.decision.rule_id.as_deref(), Some("identity-allow"));
    assert_eq!(out.hits.len(), 1);
    assert_eq!(out.hits[0].rule_id, "identity-allow");
    assert_eq!(out.hits[0].outcome, HitOutcome::Matched);
}

#[test]
fn terminal_actions_map_to_decisions() {
    let req = Req::cloudflare_browser();
    let one = |a: RuleAction| {
        decide(
            &site(vec![rule("r", Phase::Custom, 0, t(), a)]),
            &req,
            &low_risk(),
        )
        .decision
    };
    let d = one(block());
    assert_eq!((d.action, d.status), (Action::Block, Some(403)));
    let d = one(RuleAction::RateLimit { retry_after_s: 30 });
    assert_eq!(
        (d.action, d.status, d.retry_after_s),
        (Action::RateLimit, Some(429), Some(30))
    );
    let d = one(RuleAction::Challenge(ChallengeType::Invisible));
    assert_eq!(
        (d.action, d.challenge_type, d.status),
        (Action::Challenge, ChallengeType::Invisible, Some(403))
    );
    for d in [
        one(block()),
        one(RuleAction::Allow),
        one(RuleAction::Challenge(ChallengeType::Pow)),
    ] {
        assert_eq!(d.validate(), Ok(()));
        assert_eq!(d.rule_id.as_deref(), Some("r"));
    }
}

/// D-08: `interactive` runs as `pow` and the hit says so.
#[test]
fn interactive_runs_as_pow_in_phase1() {
    let p = site(vec![rule(
        "login-high-risk",
        Phase::Bot,
        0,
        t(),
        RuleAction::Challenge(ChallengeType::Interactive),
    )]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.challenge_type, ChallengeType::Pow);
    assert_eq!(out.hits[0].fields, [INTERACTIVE_AS_POW]);
    assert_eq!(out.hits[0].action, Action::Challenge);
    // With interactive challenges available (Phase 2) it stays interactive.
    let p = SitePolicy::new(
        vec![rule(
            "x",
            Phase::Bot,
            0,
            t(),
            RuleAction::Challenge(ChallengeType::Interactive),
        )],
        NamedLists::default(),
        EngineConfig {
            interactive_available: true,
            ..EngineConfig::default()
        },
    );
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.challenge_type, ChallengeType::Interactive);
    assert!(out.hits[0].fields.is_empty());
}

#[test]
fn dry_run_records_but_does_not_terminate() {
    let mut dry = rule("dry-block", Phase::Identity, 0, t(), block());
    dry.mode = RuleMode::DryRun;
    let mut dry_tag = rule("dry-tag", Phase::Identity, 0, t(), tag("x"));
    dry_tag.mode = RuleMode::DryRun;
    let p = site(vec![
        dry,
        dry_tag,
        rule("real", Phase::Bot, 0, t(), block()),
    ]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.rule_id.as_deref(), Some("real"));
    let hits: Vec<_> = out
        .hits
        .iter()
        .map(|h| (h.rule_id.as_str(), h.mode))
        .collect();
    assert_eq!(
        hits,
        [
            ("dry-block", RuleMode::DryRun),
            ("dry-tag", RuleMode::DryRun),
            ("real", RuleMode::Enforce)
        ]
    );
    assert!(out.decision.tags.is_empty(), "dry-run tags are not applied");
}

#[test]
fn log_and_tag_accumulate() {
    let p = site(vec![
        rule("log", Phase::Protocol, 0, t(), RuleAction::Log),
        rule("tag-a", Phase::Bot, 2, t(), tag("a")),
        rule("tag-b", Phase::Bot, 1, t(), tag("b")),
        rule("tag-a-again", Phase::Bot, 0, t(), tag("a")),
    ]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    // matrix.low (ALLOW) with tags -> TAG; TAG wins over LOG; tags deduplicated in order.
    assert_eq!(out.decision.action, Action::Tag);
    assert_eq!(out.decision.tags, ["a", "b"]);
    assert_eq!(out.decision.rule_id.as_deref(), Some("matrix.low"));
    assert!(out.force_log);
    assert_eq!(out.decision.validate(), Ok(()));

    let p = site(vec![rule("log", Phase::Protocol, 0, t(), RuleAction::Log)]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.action, Action::Log);
    assert!(out.force_log);

    // Tags never ride on a non-TAG decision.
    let p = site(vec![
        rule("tag", Phase::Identity, 0, t(), tag("a")),
        rule("blk", Phase::Bot, 0, t(), block()),
    ]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.action, Action::Block);
    assert!(out.decision.tags.is_empty());
    assert_eq!(out.decision.validate(), Ok(()));

    // At most 8 tags.
    let rules = (0..12)
        .map(|n| {
            rule(
                &format!("t{n:02}"),
                Phase::Bot,
                0,
                t(),
                tag(&format!("l{n}")),
            )
        })
        .collect();
    let out = decide(&site(rules), &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.decision.tags.len(), 8);
    assert_eq!(out.decision.validate(), Ok(()));
}

#[test]
fn expired_rules_are_skipped() {
    let req = Req::cloudflare_browser();
    let now = req.ctx.ts_ms;
    let mut r = rule("temp", Phase::Bot, 0, t(), block());
    r.expires_at_ms = now;
    let out = decide(&site(vec![r.clone()]), &req, &low_risk());
    assert_eq!(out.decision.rule_id.as_deref(), Some("matrix.low"));
    assert!(out.hits.is_empty());
    r.expires_at_ms = now + 1;
    assert_eq!(
        decide(&site(vec![r]), &req, &low_risk()).decision.action,
        Action::Block
    );
}

#[test]
fn rollout_is_deterministic_and_roughly_proportional() {
    assert!(in_rollout("r", "u", 100));
    assert!(!in_rollout("r", "u", 0));
    assert_eq!(in_rollout("r", "unit-1", 50), in_rollout("r", "unit-1", 50));
    for pct in [10u8, 25, 50, 90] {
        let n = (0..10_000)
            .filter(|k| in_rollout("rule-x", &format!("203.0.{}.0/24", k), pct))
            .count();
        let want = 100 * usize::from(pct);
        assert!(n.abs_diff(want) < 300, "{pct}%: {n} of 10000");
    }
    // Buckets are independent per rule.
    let a: Vec<bool> = (0..200)
        .map(|k| in_rollout("rule-a", &k.to_string(), 50))
        .collect();
    let b: Vec<bool> = (0..200)
        .map(|k| in_rollout("rule-b", &k.to_string(), 50))
        .collect();
    assert_ne!(a, b);
    // FNV-1a 64 known answer: fnv1a64("mg-rollout-v1\0r\0u").
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in b"mg-rollout-v1\0r\0u" {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    assert_eq!(in_rollout("r", "u", 37), h % 100 < 37);

    // The unit is the session, else the IP prefix, else the request id.
    let mut req = Req::cloudflare_browser();
    let mut r = rule("roll", Phase::Bot, 0, t(), block());
    r.rollout_percent = 50;
    let hit = |req: &Req| {
        decide(&site(vec![r.clone()]), req, &low_risk())
            .decision
            .action
            == Action::Block
    };
    let by_prefix = hit(&req);
    assert_eq!(by_prefix, in_rollout("roll", "203.0.113.0/24", 50));
    req.ctx.session_id = Some("sess-1".into());
    assert_eq!(hit(&req), in_rollout("roll", "sess-1", 50));
    req.ctx.session_id = None;
    req.ctx.net.ip_prefix = None;
    assert_eq!(hit(&req), in_rollout("roll", &req.ctx.request_id, 50));
}

#[test]
fn unknown_and_error_are_non_matches_with_hits() {
    let p = site(vec![
        rule(
            "reads-tls",
            Phase::Identity,
            0,
            eq(f("tls.version"), s("TLSv1.3")),
            block(),
        ),
        rule(
            "bad-key",
            Phase::Identity,
            0,
            eq(idx(f("req.headers"), s("x-nope")), s("1")),
            block(),
        ),
        rule(
            "owner",
            Phase::Identity,
            0,
            not(ip_in(f("net.ip"), named("owner_cidrs"))),
            tag("outside"),
        ),
    ]);
    let out = decide(&p, &Req::cloudflare_browser(), &low_risk());
    assert_eq!(
        out.decision.action,
        Action::Tag,
        "neither failing rule blocked"
    );
    let hits: Vec<_> = out
        .hits
        .iter()
        .map(|h| (h.rule_id.as_str(), h.outcome, h.fields.clone()))
        .collect();
    assert_eq!(
        hits,
        [
            (
                "bad-key",
                HitOutcome::EvalError,
                vec!["no_such_key".to_string()]
            ),
            ("owner", HitOutcome::Matched, vec![]),
            (
                "reads-tls",
                HitOutcome::MissingInput,
                vec!["tls.version".to_string()]
            ),
        ]
    );
    assert_eq!(out.step_limit_count(), 0);
}

#[test]
fn hits_are_capped_at_16() {
    let rules = (0..20)
        .map(|n| {
            rule(
                &format!("r{n:02}"),
                Phase::Bot,
                0,
                eq(f("tls.version"), s("x")),
                block(),
            )
        })
        .collect();
    let out = decide(&site(rules), &Req::cloudflare_browser(), &low_risk());
    assert_eq!(out.hits.len(), 16);
    assert_eq!(out.hits[15].rule_id, "r15");
}

fn obs(
    id: &str,
    exceeded: bool,
    action: LimiterAction,
    dry_run: bool,
    retry_after_ms: u64,
) -> RateObservation {
    RateObservation {
        limiter_id: id.into(),
        utilization: if exceeded { 1.0 } else { 0.5 },
        exceeded,
        retry_after_ms,
        action,
        dry_run,
    }
}

#[test]
fn limiters_run_after_protocol_rules_and_before_the_rest() {
    let mut req = Req::cloudflare_browser();
    req.rate = vec![
        obs("sig", true, LimiterAction::Signal { weight: 1.0 }, false, 0),
        obs("dry", true, LimiterAction::Block, true, 0),
        obs("calm", false, LimiterAction::Block, false, 0),
        obs(
            "login-per-ip",
            true,
            LimiterAction::RateLimit { retry_after_s: 0 },
            false,
            2_001,
        ),
        obs("later", true, LimiterAction::Block, false, 0),
    ];
    let bot = rule("bot-allow", Phase::Bot, 0, t(), RuleAction::Allow);
    let out = decide(&site(vec![bot.clone()]), &req, &low_risk());
    let d = &out.decision;
    assert_eq!(
        (d.action, d.status, d.retry_after_s),
        (Action::RateLimit, Some(429), Some(3))
    );
    assert_eq!(d.rule_id.as_deref(), Some("ratelimit.login-per-ip"));
    let hits: Vec<_> = out
        .hits
        .iter()
        .map(|h| (h.rule_id.as_str(), h.mode, h.action))
        .collect();
    assert_eq!(
        hits,
        [
            ("ratelimit.dry", RuleMode::DryRun, Action::Block),
            (
                "ratelimit.login-per-ip",
                RuleMode::Enforce,
                Action::RateLimit
            ),
        ]
    );
    // A protocol-phase allow wins over the limiter; an identity block too.
    let proto = rule("proto-allow", Phase::Protocol, 0, t(), RuleAction::Allow);
    assert_eq!(
        decide(&site(vec![proto, bot]), &req, &low_risk())
            .decision
            .rule_id
            .as_deref(),
        Some("proto-allow")
    );

    // Retry-After: the configured value, else the GCRA wait rounded up, at least 1 s.
    let retry = |cfg: u32, ms: u64| {
        let mut req = Req::cloudflare_browser();
        req.rate = vec![obs(
            "l",
            true,
            LimiterAction::RateLimit { retry_after_s: cfg },
            false,
            ms,
        )];
        decide(&site(vec![]), &req, &low_risk())
            .decision
            .retry_after_s
    };
    assert_eq!(retry(60, 1), Some(60));
    assert_eq!(retry(0, 0), Some(1));
    assert_eq!(retry(0, 1), Some(1));
    assert_eq!(retry(0, 1000), Some(1));
    assert_eq!(retry(0, 1001), Some(2));

    // Block and challenge limiters.
    let mut req = Req::cloudflare_browser();
    req.rate = vec![obs("b", true, LimiterAction::Block, false, 0)];
    let d = decide(&site(vec![]), &req, &low_risk()).decision;
    assert_eq!((d.action, d.status), (Action::Block, Some(403)));
    req.rate = vec![obs(
        "c",
        true,
        LimiterAction::Challenge(ChallengeType::Interactive),
        false,
        0,
    )];
    let out = decide(&site(vec![]), &req, &low_risk());
    assert_eq!(out.decision.challenge_type, ChallengeType::Pow);
    assert_eq!(out.hits[0].fields, [INTERACTIVE_AS_POW]);

    // Signal and dry-run limiters never decide.
    req.rate = vec![
        obs("s", true, LimiterAction::Signal { weight: 2.0 }, false, 0),
        obs(
            "d",
            true,
            LimiterAction::RateLimit { retry_after_s: 5 },
            true,
            0,
        ),
    ];
    let out = decide(&site(vec![]), &req, &low_risk());
    assert_eq!(out.decision.rule_id.as_deref(), Some("matrix.low"));
    assert_eq!(out.hits.len(), 1);
    assert_eq!(out.hits[0].mode, RuleMode::DryRun);
}

/// docs/06 §2 examples, as native programs.
#[test]
fn docs06_examples() {
    let class_is = |c: &str| eq(f("risk.class"), s(c));
    let rules = vec![
        rule(
            "test-env-default-deny",
            Phase::Identity,
            0,
            and(vec![
                in_list(
                    f("route.env"),
                    list(vec![s("staging"), s("test"), s("dev")]),
                ),
                cmp(CompareOp::Ne, f("risk.class"), s("AUTHORIZED_AGENT")),
                or(vec![
                    not(has("net.ip")),
                    not(ip_in(f("net.ip"), named("owner_cidrs"))),
                ]),
            ]),
            block(),
        ),
        rule(
            "block-impersonators",
            Phase::Identity,
            0,
            class_is("IMPERSONATOR"),
            block(),
        ),
        rule(
            "scanner-block",
            Phase::Protocol,
            0,
            in_list(s("scanner"), f("labels")),
            block(),
        ),
        rule(
            "login-require-proof",
            Phase::Bot,
            0,
            and(vec![
                eq(f("route.name"), s("login")),
                not(f("identity.proof.valid")),
            ]),
            RuleAction::Challenge(ChallengeType::Invisible),
        ),
    ];
    let p = site(rules);
    let mut req = Req::cloudflare_browser();
    // Staging from outside the owner's networks: blocked.
    req.route.env = "staging".into();
    assert_eq!(
        decide(&p, &req, &low_risk()).decision.rule_id.as_deref(),
        Some("test-env-default-deny")
    );
    // From an owner network: allowed through.
    req.ctx.net = crate::context::Net::for_ip("10.9.8.7".parse().unwrap());
    assert_eq!(
        decide(&p, &req, &low_risk()).decision.rule_id.as_deref(),
        Some("matrix.low")
    );
    // Impersonator.
    let risk = RiskAssessment {
        bot_class: BotClass::Impersonator,
        ..low_risk()
    };
    assert_eq!(
        decide(&p, &req, &risk).decision.rule_id.as_deref(),
        Some("block-impersonators")
    );
    // identity.proof is MISSING in Phase 1: login-require-proof never matches (D-07),
    // it records missing_input instead of challenging every login forever.
    req.route.name = "login".into();
    let out = decide(&p, &req, &low_risk());
    assert_eq!(out.decision.rule_id.as_deref(), Some("matrix.low"));
    let hit = out
        .hits
        .iter()
        .find(|h| h.rule_id == "login-require-proof")
        .unwrap();
    assert_eq!(hit.outcome, HitOutcome::MissingInput);
    assert_eq!(hit.fields, ["identity.proof.valid"]);
}

#[test]
fn no_rules_uses_the_matrix() {
    let out = decide(&site(vec![]), &Req::cloudflare_browser(), &low_risk());
    assert_eq!(
        out.decision,
        Decision {
            rule_id: Some("matrix.low".into()),
            ..Decision::allow()
        }
    );
    assert!(out.hits.is_empty() && !out.force_log);
    assert!(format!("{:?}", site(vec![])).contains("owner_cidrs"));
}
