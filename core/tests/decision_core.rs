//! WP-R1 done-definition (docs/impl/phase1-spec.md §15): the Phase 1
//! `DecisionCore` gives an `Evaluation` end to end for hand-built
//! `RequestContext` + `RequestExtras`, using only the public API.

use mg_core::policy::{
    CompareOp, CrawlerAction, CrawlerPolicy, EngineConfig, Expr, FieldId, Literal, MissingSet,
    NamedLists, Phase, Program, Rule, RuleAction, RuleMode, SitePolicy,
};
use mg_core::{
    Action, BotClass, ChallengeType, Channel, Crawler, CrawlerMethod, CrawlerVerification,
    DecisionCore, DecisionEvent, EdgeTls, FamilyMask, LimiterAction, Net, RateObservation,
    RequestContext, RequestExtras, RouteInfo, RouteSensitivity, ScoringConfig, SignalFamily,
    SignalState, TokenLevel, TokenStatus, UpstreamAuthMethod, UpstreamProfileKind, ua,
};
use std::collections::BTreeMap;

const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// A request as the Edge would hand it over (spec §9.5).
struct Request {
    ctx: RequestContext,
    route: RouteInfo,
    headers: Vec<(String, String)>,
    rate: Vec<RateObservation>,
    missing: MissingSet,
}

impl Request {
    fn browser() -> Self {
        let mut ctx = RequestContext::new(
            "0f0e0d0c0b0a09080706050403020100",
            "blog",
            1_790_000_000_123,
        );
        ctx.env = "production".into();
        ctx.channel = Channel::Web;
        ctx.upstream.profile = UpstreamProfileKind::Cloudflare;
        ctx.upstream.authenticated = true;
        ctx.upstream.auth_method = UpstreamAuthMethod::Loopback;
        ctx.net = Net {
            asn: Some(64500),
            country: Some("HK".into()),
            ..Net::for_ip("203.0.113.7".parse().unwrap())
        };
        ctx.edge_tls = Some(EdgeTls {
            version: Some("TLSv1.3".into()),
            ..EdgeTls::default()
        });
        ctx.http.version = Some("HTTP/2".into());
        ctx.http.method = "GET".into();
        ctx.http.host = "example.com".into();
        ctx.http.path = "/".into();
        ctx.http.user_agent = Some(CHROME.into());
        ctx.identity.crawler.cf_vbot = Some(false);
        let mut headers = vec![
            ("accept".to_string(), "text/html".to_string()),
            ("accept-language".to_string(), "en".to_string()),
            (
                "sec-ch-ua".to_string(),
                r#""Chromium";v="124", "Google Chrome";v="124""#.to_string(),
            ),
            ("sec-fetch-mode".to_string(), "navigate".to_string()),
            ("user-agent".to_string(), CHROME.to_string()),
        ];
        headers.sort();
        Self {
            ctx,
            route: RouteInfo {
                id: "default".into(),
                name: "default".into(),
                env: "production".into(),
                channel: Channel::Web,
                sensitivity: RouteSensitivity::Low,
                require_clearance: false,
                fail_closed: false,
            },
            headers,
            rate: Vec::new(),
            missing: MissingSet::new([
                "tls",
                "http.header_order",
                "identity.proof",
                "identity.agent",
            ])
            .unwrap(),
        }
    }

    fn login(mut self) -> Self {
        self.ctx.route_id = Some("login".into());
        self.ctx.http.path = "/account/login".into();
        self.route = RouteInfo {
            id: "login".into(),
            name: "login".into(),
            env: "production".into(),
            channel: Channel::Web,
            sensitivity: RouteSensitivity::Critical,
            require_clearance: true,
            fail_closed: true,
        };
        self
    }

    fn user_agent(mut self, ua: &str) -> Self {
        self.ctx.http.user_agent = Some(ua.into());
        self.headers.retain(|(k, _)| k != "user-agent");
        self.headers.push(("user-agent".into(), ua.into()));
        self.headers.sort();
        self
    }

    fn run(&self, core: &DecisionCore) -> mg_core::Evaluation {
        let ua = ua::parse(self.ctx.http.user_agent.as_deref().unwrap_or(""));
        let extras = RequestExtras {
            route: &self.route,
            headers: &self.headers,
            query: "",
            rate: &self.rate,
            missing: &self.missing,
            ua: &ua,
            secure_context: true,
        };
        core.evaluate(&self.ctx, &extras)
    }
}

fn b(e: Expr) -> Box<Expr> {
    Box::new(e)
}

fn field(p: &str) -> Expr {
    Expr::Field(FieldId::from_path(p).unwrap())
}

fn str_lit(s: &str) -> Expr {
    Expr::Literal(Literal::Str(s.into()))
}

fn rule(id: &str, phase: Phase, e: Expr, action: RuleAction) -> Rule {
    Rule {
        id: id.into(),
        phase,
        priority: 0,
        program: Program::new(e).unwrap(),
        action,
        mode: RuleMode::Enforce,
        rollout_percent: 100,
        expires_at_ms: 0,
    }
}

/// The site policy: two docs/06 examples and an owner TAG rule.
fn core() -> DecisionCore {
    let rules = vec![
        rule(
            "block-impersonators",
            Phase::Identity,
            Expr::Compare(
                CompareOp::Eq,
                b(field("risk.class")),
                b(str_lit("IMPERSONATOR")),
            ),
            RuleAction::Block,
        ),
        rule(
            "tag-hk",
            Phase::Custom,
            Expr::Compare(CompareOp::Eq, b(field("net.country")), b(str_lit("HK"))),
            RuleAction::Tag { label: "hk".into() },
        ),
    ];
    let config = EngineConfig {
        theta_c: 0.4,
        crawler_policy: CrawlerPolicy {
            purposes: BTreeMap::from([("ai_training".to_string(), CrawlerAction::Block)]),
            default_action: CrawlerAction::Allow,
        },
        interactive_available: false,
    };
    let policy = SitePolicy::new(rules, NamedLists::default(), config);
    DecisionCore::phase1(ScoringConfig::default(), Box::new(policy))
}

#[test]
fn browser_is_allowed_and_tagged() {
    let ev = Request::browser().run(&core());
    assert_eq!(ev.risk.score.get(), 10);
    assert_eq!(ev.risk.bot_class, BotClass::HumanLikely);
    let d = &ev.outcome.decision;
    assert_eq!(
        (d.action, d.rule_id.as_deref()),
        (Action::Tag, Some("matrix.low"))
    );
    assert_eq!(d.tags, ["hk"]);
    assert_eq!(d.validate(), Ok(()));
    assert_eq!(
        ev.signals.len(),
        16,
        "all 18 detectors but bind_ipp_soft / crawler_failed"
    );
    let avail = ev.availability_mask();
    assert!(avail.contains(SignalFamily::Network) && avail.contains(SignalFamily::Http));
    assert!(!avail.contains(SignalFamily::Tls));
    // The event records only non-zero PRESENT, ABSENT and expected-MISSING signals.
    let logged = ev.event_signals(UpstreamProfileKind::Cloudflare);
    assert_eq!(logged.len(), 1);
    assert_eq!(
        (logged[0].id.as_ref(), logged[0].state),
        ("identity.clearance", SignalState::Absent)
    );
}

#[test]
fn library_client_on_a_clearance_route_is_challenged() {
    let req = Request::browser()
        .login()
        .user_agent("python-requests/2.31.0");
    let ev = req.run(&core());
    assert!(ev.risk.top_reasons.iter().any(|r| r == "http.ua_library"));
    assert_eq!(ev.risk.score.get(), 71, "critical prior -1.099 + HTTP +2.0");
    let d = &ev.outcome.decision;
    assert_eq!(d.action, Action::Challenge);
    assert_eq!(d.challenge_type, ChallengeType::Pow, "high band: pow");
    assert_eq!(d.rule_id.as_deref(), Some("matrix.clearance.required"));
    assert_eq!(d.status, Some(403));
    assert!(d.tags.is_empty());
}

#[test]
fn valid_clearance_passes_the_clearance_route() {
    let mut req = Request::browser().login();
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Invisible);
    req.ctx.identity.token.age_s = 30;
    let ev = req.run(&core());
    // Critical prior -1.099 - 0.4 (clearance) -> 18: low band, allowed and tagged.
    assert_eq!(ev.risk.score.get(), 18);
    assert_eq!(ev.outcome.decision.action, Action::Tag);
    assert_eq!(ev.outcome.decision.rule_id.as_deref(), Some("matrix.low"));
}

#[test]
fn impersonating_crawler_is_blocked_by_policy() {
    let mut req = Request::browser()
        .user_agent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
    req.ctx.identity.crawler = Crawler {
        claimed: true,
        operator: Some("google".into()),
        purpose: Some("search".into()),
        verification: Some(CrawlerVerification::Failed),
        method: Some(CrawlerMethod::IpRange),
        cf_vbot: Some(false),
        ..Crawler::default()
    };
    let ev = req.run(&core());
    assert_eq!(ev.risk.score.get(), 90);
    assert_eq!(ev.risk.bot_class, BotClass::Impersonator);
    let d = &ev.outcome.decision;
    assert_eq!(
        (d.action, d.rule_id.as_deref()),
        (Action::Block, Some("block-impersonators"))
    );
    assert_eq!(ev.outcome.hits[0].rule_id, "block-impersonators");
}

#[test]
fn verified_crawlers_follow_the_crawler_policy() {
    let mut req = Request::browser()
        .user_agent("Mozilla/5.0 (compatible; ExampleBot/1.0; +https://example.test/bot)");
    req.ctx.identity.crawler = Crawler {
        claimed: true,
        operator: Some("example".into()),
        purpose: Some("search".into()),
        verified: true,
        verification: Some(CrawlerVerification::Verified),
        method: Some(CrawlerMethod::Rdns),
        cf_vbot: Some(true),
        ..Crawler::default()
    };
    let ev = req.run(&core());
    assert_eq!(ev.risk.bot_class, BotClass::VerifiedCrawler);
    assert_eq!(
        ev.outcome.decision.rule_id.as_deref(),
        Some("matrix.crawler.allow")
    );
    req.ctx.identity.crawler.purpose = Some("ai_training".into());
    let ev = req.run(&core());
    assert_eq!(ev.outcome.decision.action, Action::Block);
    assert_eq!(
        ev.outcome.decision.rule_id.as_deref(),
        Some("matrix.crawler.block")
    );
}

#[test]
fn exceeded_limiter_rate_limits_and_the_event_serializes() {
    let mut req = Request::browser().login();
    req.ctx.identity.token.status = TokenStatus::Valid;
    req.ctx.identity.token.level = Some(TokenLevel::Pow);
    req.rate = vec![RateObservation {
        limiter_id: "login-per-ip".into(),
        utilization: 1.0,
        exceeded: true,
        retry_after_ms: 2_500,
        action: LimiterAction::RateLimit { retry_after_s: 0 },
        dry_run: false,
    }];
    let ev = req.run(&core());
    let d = &ev.outcome.decision;
    assert_eq!(
        (d.action, d.status, d.retry_after_s),
        (Action::RateLimit, Some(429), Some(3))
    );
    assert_eq!(d.rule_id.as_deref(), Some("ratelimit.login-per-ip"));

    let event = DecisionEvent {
        ctx: req.ctx.clone(),
        signals: ev.event_signals(req.ctx.upstream.profile),
        risk: ev.risk.clone(),
        decision: ev.outcome.decision.clone(),
        latency_us: 42,
        sample_rate: 1.0,
        edge_id: "edge-1".into(),
        bundle_version: 7,
        monitor_only: false,
        hits: ev.outcome.hits.clone(),
    };
    let line = event.to_json_line().unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["decision"]["action"], "rate_limit");
    assert_eq!(v["hits"][0]["rule_id"], "ratelimit.login-per-ip");
    assert_eq!(v["hits"][0]["mode"], "enforce");
    assert_eq!(DecisionEvent::from_json_line(&line).unwrap(), event);
}

#[test]
fn client_ip_unknown_is_never_more_lenient() {
    let mut req = Request::browser();
    req.ctx.net = Net::default();
    req.ctx.upstream.client_ip_header_missing = true;
    for p in [
        "net.ip",
        "net.asn",
        "net.country",
        "net.conn_type",
        "net.tor",
    ] {
        req.missing.insert(p).unwrap();
    }
    let known = Request::browser().run(&core());
    let ev = req.run(&core());
    assert!(ev.risk.labels.iter().any(|l| l == "client_ip_unknown"));
    assert!(ev.risk.confidence.get() < known.risk.confidence.get());
    assert!(ev.risk.score >= known.risk.score);
    // The HK tag rule reads net.country: MISSING -> no match, recorded.
    assert_eq!(ev.outcome.decision.action, Action::Allow);
    let hit = ev
        .outcome
        .hits
        .iter()
        .find(|h| h.rule_id == "tag-hk")
        .unwrap();
    assert_eq!(hit.fields, ["net.country"]);
    // The expected-but-missing client IP is logged.
    assert!(
        ev.event_signals(UpstreamProfileKind::Cloudflare)
            .iter()
            .any(|s| s.id == "net.client_ip" && s.state == SignalState::Missing)
    );
}

#[test]
// Host-only timing observation in a test; the library itself never reads a clock.
#[allow(clippy::disallowed_methods)]
fn evaluation_is_deterministic_and_fast() {
    let core = core();
    let req = Request::browser().login().user_agent("curl/8.5.0");
    let first = req.run(&core);
    let start = std::time::Instant::now();
    for _ in 0..2_000 {
        assert_eq!(req.run(&core), first);
    }
    let per = start.elapsed() / 2_000;
    // Informational (spec §16): the order of magnitude of one Decision Core run.
    println!("DecisionCore::evaluate: {per:?} per request (debug build)");
    assert_eq!(FamilyMask::of(&[SignalFamily::Http]).len(), 1);
}
