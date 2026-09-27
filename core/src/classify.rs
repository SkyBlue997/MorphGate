//! BotClass derivation (docs/impl/phase1-spec.md §5.7 "BotClass 推导").

use crate::context::{CrawlerVerification, RequestContext};
use crate::enums::BotClass;
use crate::signal::Signal;
use crate::ua::{self, UaInfo};
use crate::values::{Confidence, Score};

/// Label of requests whose client IP is unknown (§9.3.2).
pub const LABEL_CLIENT_IP_UNKNOWN: &str = "client_ip_unknown";
/// Label of self-declared bots and unverified crawler claims.
pub const LABEL_DECLARED_BOT: &str = "declared_bot";
/// Entity label that classifies a request as `SCANNER` (score floor 85).
pub const LABEL_SCANNER: &str = "scanner";

/// Labels of the request's active entity verdicts that apply to its site
/// (sorted, unique).
pub(crate) fn verdict_labels(ctx: &RequestContext) -> Vec<String> {
    let mut labels: Vec<String> = ctx
        .active_verdicts()
        .filter(|v| v.applies_to_site(&ctx.site_id))
        .flat_map(|v| v.labels.iter().cloned())
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Derives the class, in priority order: crawler `verified` →
/// `VERIFIED_CRAWLER`; crawler `failed` → `IMPERSONATOR`; label `scanner` →
/// `SCANNER`; crawler `pending` / `unverifiable` or a self-declared bot UA →
/// `DECLARED_AGENT` (label `declared_bot`); `score >= 60` →
/// `AUTOMATION_LIKELY`; `score < 30` and `confidence >= theta_c` →
/// `HUMAN_LIKELY`; else `UNKNOWN`.
///
/// Returns the class and the request's labels: those of its active verdicts
/// plus `declared_bot` and `client_ip_unknown` where they apply (sorted, unique).
pub fn derive_bot_class(
    ctx: &RequestContext,
    signals: &[Signal],
    score: Score,
    confidence: Confidence,
    theta_c: f32,
) -> (BotClass, Vec<String>) {
    let ua = ua::parse(ctx.http.user_agent.as_deref().unwrap_or(""));
    derive_with_ua(ctx, signals, &ua, score, confidence, theta_c)
}

pub(crate) fn derive_with_ua(
    ctx: &RequestContext,
    _signals: &[Signal],
    ua: &UaInfo,
    score: Score,
    confidence: Confidence,
    theta_c: f32,
) -> (BotClass, Vec<String>) {
    let mut labels = verdict_labels(ctx);
    let crawler = &ctx.identity.crawler;
    let unconfirmed_claim = crawler.claimed
        && matches!(
            crawler.verification,
            Some(CrawlerVerification::Pending | CrawlerVerification::Unverifiable)
        );
    let class = if crawler.is_verified() {
        BotClass::VerifiedCrawler
    } else if crawler.is_failed() {
        BotClass::Impersonator
    } else if labels.iter().any(|l| l == LABEL_SCANNER) {
        BotClass::Scanner
    } else if unconfirmed_claim || ua.declared_bot {
        labels.push(LABEL_DECLARED_BOT.to_string());
        BotClass::DeclaredAgent
    } else if score.get() >= 60 {
        BotClass::AutomationLikely
    } else if score.get() < 30 && confidence.get() >= theta_c {
        BotClass::HumanLikely
    } else {
        BotClass::Unknown
    };
    if ctx.net.ip.is_none() {
        labels.push(LABEL_CLIENT_IP_UNKNOWN.to_string());
    }
    labels.sort();
    labels.dedup();
    (class, labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Crawler;
    use crate::decision::EntityVerdict;
    use crate::enums::EntityType;

    fn ctx() -> RequestContext {
        let mut ctx = RequestContext::new("r", "blog", 1_000);
        ctx.net = crate::context::Net::for_ip("203.0.113.7".parse().unwrap());
        ctx.http.user_agent =
            Some("Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36".into());
        ctx
    }

    fn class(ctx: &RequestContext, score: u32, conf: f32) -> (BotClass, Vec<String>) {
        derive_bot_class(ctx, &[], Score::new(score), Confidence::new(conf), 0.4)
    }

    fn crawler(v: CrawlerVerification) -> Crawler {
        Crawler {
            claimed: true,
            operator: Some("google".into()),
            verified: v == CrawlerVerification::Verified,
            verification: Some(v),
            ..Crawler::default()
        }
    }

    fn scanner_verdict() -> EntityVerdict {
        EntityVerdict {
            entity_type: EntityType::Prefix,
            labels: vec![LABEL_SCANNER.into()],
            expires_at_ms: 2_000,
            site_id: "blog".into(),
            ..EntityVerdict::default()
        }
    }

    /// §5.7: the priority order, each rule shadowing the ones below it.
    #[test]
    fn priority_order() {
        let mut c = ctx();
        c.verdicts = vec![scanner_verdict()];
        c.http.user_agent = Some("ExampleBot/1.0".into());

        c.identity.crawler = crawler(CrawlerVerification::Verified);
        assert_eq!(
            class(&c, 95, 1.0).0,
            BotClass::VerifiedCrawler,
            "verified beats everything"
        );
        c.identity.crawler = crawler(CrawlerVerification::Failed);
        assert_eq!(
            class(&c, 0, 1.0).0,
            BotClass::Impersonator,
            "failed beats scanner"
        );
        c.identity.crawler = crawler(CrawlerVerification::Pending);
        assert_eq!(
            class(&c, 0, 1.0).0,
            BotClass::Scanner,
            "scanner beats a pending claim"
        );
        c.verdicts.clear();
        let (cls, labels) = class(&c, 95, 1.0);
        assert_eq!(
            cls,
            BotClass::DeclaredAgent,
            "pending claim beats the score"
        );
        assert!(labels.contains(&LABEL_DECLARED_BOT.to_string()));
        c.identity.crawler = crawler(CrawlerVerification::Unverifiable);
        assert_eq!(class(&c, 95, 1.0).0, BotClass::DeclaredAgent);
        c.identity.crawler = Crawler::default();
        assert_eq!(
            class(&c, 95, 1.0).0,
            BotClass::DeclaredAgent,
            "self-declared bot UA"
        );
        c.http.user_agent = Some("Mozilla/5.0 Chrome/124".into());
        assert_eq!(class(&c, 60, 1.0).0, BotClass::AutomationLikely);
        assert_eq!(class(&c, 59, 1.0).0, BotClass::Unknown);
        assert_eq!(class(&c, 29, 0.4).0, BotClass::HumanLikely);
        assert_eq!(
            class(&c, 29, 0.39).0,
            BotClass::Unknown,
            "low confidence is never human"
        );
        assert_eq!(class(&c, 30, 1.0).0, BotClass::Unknown);
    }

    #[test]
    fn inconsistent_crawler_state_is_not_verified() {
        let mut c = ctx();
        c.identity.crawler = Crawler {
            claimed: true,
            verified: true,
            verification: Some(CrawlerVerification::Pending),
            ..Crawler::default()
        };
        assert_eq!(class(&c, 0, 1.0).0, BotClass::DeclaredAgent);
        // A verified flag without a verification state (older producers) still counts.
        c.identity.crawler.verification = None;
        assert_eq!(class(&c, 0, 1.0).0, BotClass::VerifiedCrawler);
    }

    #[test]
    fn labels_come_from_active_verdicts_of_this_site() {
        let mut c = ctx();
        let mut expired = scanner_verdict();
        expired.expires_at_ms = 1_000;
        let mut other_site = scanner_verdict();
        other_site.site_id = "shop".into();
        let mut shared_session = scanner_verdict();
        shared_session.entity_type = EntityType::Session;
        shared_session.site_id = EntityVerdict::ALL_SITES.into();
        c.verdicts = vec![expired, other_site, shared_session];
        let (cls, labels) = class(&c, 0, 1.0);
        assert_eq!(cls, BotClass::HumanLikely);
        assert!(labels.is_empty());

        c.net.ip = None;
        let (_, labels) = class(&c, 0, 1.0);
        assert_eq!(labels, [LABEL_CLIENT_IP_UNKNOWN]);
    }
}
