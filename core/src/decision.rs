//! Scorer / policy outputs and the per-request event.

use crate::challenge::{ProviderId, VerdictOutcome};
use crate::context::{RequestContext, TokenLevel};
use crate::enums::{Action, BotClass, ChallengeType, EntityType};
use crate::policy::RuleMode;
use crate::signal::Signal;
use crate::values::{Confidence, RiskBand, Score};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Scorer output (docs/03 §4).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskAssessment {
    /// `0..=100`, higher = more likely automated / abusive.
    pub score: Score,
    /// Evidence coverage `0..=1` (how many weighted families were available).
    pub confidence: Confidence,
    pub bot_class: BotClass,
    /// Extra labels, e.g. `scanner`, `delegated`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Reason codes of the largest contributions, most important first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_reasons: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ruleset_version: String,
    /// Score including shadow families and detectors. Never enforced; used
    /// to calibrate a family before it leaves shadow.
    pub shadow_score: Score,
}

/// What the Edge does with the request.
///
/// Use [`Decision::validate`] before acting on a decision built from
/// configuration; it enforces the invariants listed there.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Decision {
    pub action: Action,
    /// Set iff `action == Challenge`.
    #[serde(skip_serializing_if = "is_unspecified_challenge")]
    pub challenge_type: ChallengeType,
    /// Interactive provider chosen by the Decision Core (never by the client).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<ProviderId>,
    /// HTTP status the Edge answers with; `None` when the origin answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Record what would have happened, but let the request through.
    pub dry_run: bool,
    /// Labels added by TAG rules, forwarded to the origin as `MG-Tags`
    /// (only with `action == Tag`; see [`Decision::validate`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

fn is_unspecified_challenge(t: &ChallengeType) -> bool {
    *t == ChallengeType::Unspecified
}

/// A [`Decision`] that violates an invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// `action` is `Unspecified`.
    MissingAction,
    /// `challenge_type` set without `Challenge`, or `Challenge` without a type.
    ChallengeTypeMismatch,
    /// `provider_id` set for anything but an interactive challenge.
    UnexpectedProvider,
    /// Status not allowed for the action (see [`Decision::validate`]).
    InvalidStatus(u16),
    /// `tags` on a non-TAG decision, more than [`Decision::MAX_TAGS`] tags, or
    /// a tag outside `[a-z0-9_.-]{1,32}`.
    InvalidTags,
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAction => f.write_str("decision has no action"),
            Self::ChallengeTypeMismatch => {
                f.write_str("challenge_type must be set exactly when action is challenge")
            }
            Self::UnexpectedProvider => {
                f.write_str("provider_id is only valid for interactive challenges")
            }
            Self::InvalidStatus(s) => write!(f, "status {s} is not valid for this action"),
            Self::InvalidTags => {
                f.write_str("tags must be at most 8 labels of [a-z0-9_.-]{1,32} on a tag decision")
            }
        }
    }
}

impl std::error::Error for DecisionError {}

impl Decision {
    /// Most tags one decision forwards (docs/impl/phase1-spec.md §5.4).
    pub const MAX_TAGS: usize = 8;

    /// Whether `label` is a valid tag / rule label: `[a-z0-9_.-]{1,32}`.
    pub fn is_valid_tag(label: &str) -> bool {
        (1..=32).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
    }

    /// Let the request through untouched.
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            ..Self::default()
        }
    }

    /// Challenge with `challenge_type`, answered with 403 (docs/08: challenges
    /// use 403/429, never 200, so no cache stores them).
    pub fn challenge(challenge_type: ChallengeType) -> Self {
        Self {
            action: Action::Challenge,
            challenge_type,
            status: Some(403),
            ..Self::default()
        }
    }

    /// Checks the invariants:
    ///
    /// * `action` is set;
    /// * `challenge_type` is set iff `action == Challenge`;
    /// * `provider_id` only for `Interactive` challenges;
    /// * `status`, when present, is `100..=599`; a challenge uses `403` or `429`
    ///   (never 2xx, which caches may store); `RateLimit` uses `429`;
    ///   `Block` uses a 4xx;
    /// * `tags` only on a `Tag` decision: at most [`Decision::MAX_TAGS`]
    ///   labels, each [`Decision::is_valid_tag`].
    pub fn validate(&self) -> Result<(), DecisionError> {
        if self.action == Action::Unspecified {
            return Err(DecisionError::MissingAction);
        }
        let is_challenge = self.action == Action::Challenge;
        if is_challenge != (self.challenge_type != ChallengeType::Unspecified) {
            return Err(DecisionError::ChallengeTypeMismatch);
        }
        if self.provider_id.is_some() && self.challenge_type != ChallengeType::Interactive {
            return Err(DecisionError::UnexpectedProvider);
        }
        if let Some(status) = self.status {
            let ok = match self.action {
                _ if !(100..=599).contains(&status) => false,
                Action::Challenge => matches!(status, 403 | 429),
                Action::RateLimit => status == 429,
                Action::Block => (400..=499).contains(&status),
                _ => true,
            };
            if !ok {
                return Err(DecisionError::InvalidStatus(status));
            }
        }
        if !self.tags.is_empty()
            && (self.action != Action::Tag
                || self.tags.len() > Self::MAX_TAGS
                || !self.tags.iter().all(|t| Self::is_valid_tag(t)))
        {
            return Err(DecisionError::InvalidTags);
        }
        Ok(())
    }
}

wire_enum! {
    /// How a policy rule (or rate limiter) fared on one request.
    pub enum HitOutcome {
        /// The rule's expression evaluated to `true` (or the limiter was exceeded).
        Matched => "matched",
        /// The expression read a MISSING field and came out UNKNOWN: no match.
        MissingInput => "missing_input",
        /// The expression came out as an error: no match.
        EvalError => "eval_error",
    }
}

/// One policy rule (or rate limiter) that matched, or could not be
/// evaluated, on this request (`morphgate.v1.RuleHit`,
/// docs/impl/phase1-spec.md §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHit {
    /// `CompiledRule.id`, or `ratelimit.<limiter id>`.
    pub rule_id: String,
    pub outcome: HitOutcome,
    pub mode: RuleMode,
    /// The rule's (would-be) action.
    pub action: Action,
    /// `missing_input`: the MISSING field paths read (sorted); `eval_error`:
    /// `[error kind]`; `matched`: annotations such as `phase1.interactive_as_pow`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Near-line judgement about an entity, fed back to the Edge (docs/03 §4.1 `R_e`).
///
/// Stored in Valkey as `mg:v:{site}:{type}:{key}` (docs/02 §7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EntityVerdict {
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    /// Entity key; hashed where it identifies a person.
    pub key: String,
    pub risk: Score,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Unix epoch milliseconds.
    pub expires_at_ms: i64,
    /// Detector id, `owner`, or an intel feed name.
    pub source: String,
    pub version: String,
    /// Site the verdict belongs to, or [`EntityVerdict::ALL_SITES`] for a
    /// verdict shared across the owner's sites (IP / ASN types only, with the
    /// per-site sharing switch on).
    pub site_id: String,
}

impl EntityVerdict {
    /// `site_id` of a verdict shared across the owner's sites.
    pub const ALL_SITES: &'static str = "all";

    /// Whether the verdict still applies at `now_ms` (host-supplied time).
    pub fn is_active(&self, now_ms: i64) -> bool {
        now_ms < self.expires_at_ms
    }

    /// Whether this entity type may be shared across sites (IP / ASN class).
    pub const fn is_shareable_type(entity_type: EntityType) -> bool {
        matches!(
            entity_type,
            EntityType::Ip | EntityType::Prefix | EntityType::Asn
        )
    }

    /// Whether the verdict applies to requests of `site_id`: its own site, or
    /// a shared verdict of a shareable type. Anything else is ignored, so a
    /// mislabelled shared session or account verdict can never leak across sites.
    pub fn applies_to_site(&self, site_id: &str) -> bool {
        if self.site_id == Self::ALL_SITES {
            Self::is_shareable_type(self.entity_type)
        } else {
            !self.site_id.is_empty() && self.site_id == site_id
        }
    }
}

/// Outcome of one challenge submission (`POST /__mg/c`), emitted as a
/// `kind = feedback` event (docs/02 §7). Never contains telemetry values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChallengeResult {
    pub request_id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<ProviderId>,
    /// `pass | fail | unavailable | misconfigured`; `None` only in malformed input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<VerdictOutcome>,
    /// Token level issued on a pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lvl: Option<TokenLevel>,
    pub attempt_no: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solve_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_band: Option<RiskBand>,
    /// Internal only, never shown to visitors.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_ray: Option<String>,
}

/// One decision, as written to the event pipeline (docs/02 §7).
///
/// [`DecisionEvent::to_json_line`] is the exact line the Edge sends to
/// VictoriaLogs. The context should already be minimised per the retention
/// policy (docs/02 §9) before it is placed here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub ctx: RequestContext,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub risk: RiskAssessment,
    #[serde(default)]
    pub decision: Decision,
    /// Decision Core latency in microseconds.
    #[serde(default)]
    pub latency_us: u32,
    /// Probability with which this event was kept, for unbiased aggregation.
    #[serde(default = "full_sample_rate")]
    pub sample_rate: f32,
    /// Which Edge instance decided.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub edge_id: String,
    /// `SiteBundle.version` in effect.
    #[serde(default)]
    pub bundle_version: u64,
    /// The global monitor switch was on (the decision was not enforced).
    #[serde(default)]
    pub monitor_only: bool,
    /// Rules and limiters that matched or could not be evaluated, at most
    /// [`DecisionEvent::MAX_HITS`], in evaluation order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<RuleHit>,
}

fn full_sample_rate() -> f32 {
    1.0
}

impl DecisionEvent {
    /// Most hits one event carries (docs/impl/phase1-spec.md §3.4).
    pub const MAX_HITS: usize = 16;

    /// Serializes to a single JSON line (no trailing newline).
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parses one JSON line.
    pub fn from_json_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{SignalFamily, UpstreamProfileKind};

    fn event() -> DecisionEvent {
        let mut ctx = RequestContext::new("01J9ZQ", "blog", 1_758_000_000_123);
        ctx.upstream.profile = UpstreamProfileKind::Cloudflare;
        ctx.http.path = "/login".into();
        DecisionEvent {
            ctx,
            signals: vec![
                Signal::new("http.missing_accept_language", SignalFamily::Http, 0.4, 0.8)
                    .with_reason("no_accept_language"),
            ],
            risk: RiskAssessment {
                score: Score::new(71),
                confidence: Confidence::new(0.55),
                bot_class: BotClass::AutomationLikely,
                top_reasons: vec!["no_accept_language".into()],
                ruleset_version: "r1".into(),
                ..RiskAssessment::default()
            },
            decision: Decision {
                provider_id: Some(ProviderId::SelfHold),
                rule_id: Some("default.high".into()),
                ..Decision::challenge(ChallengeType::Interactive)
            },
            latency_us: 180,
            sample_rate: 1.0,
            edge_id: "edge-a".into(),
            bundle_version: 7,
            monitor_only: true,
            hits: vec![RuleHit {
                rule_id: "login-high-risk".into(),
                outcome: HitOutcome::Matched,
                mode: RuleMode::DryRun,
                action: Action::Challenge,
                fields: vec!["phase1.interactive_as_pow".into()],
            }],
        }
    }

    #[test]
    fn event_json_line_round_trip() {
        let ev = event();
        let line = ev.to_json_line().unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(DecisionEvent::from_json_line(&line).unwrap(), ev);
    }

    #[test]
    fn event_json_shape_is_snake_case() {
        let v: serde_json::Value = serde_json::from_str(&event().to_json_line().unwrap()).unwrap();
        assert_eq!(v["decision"]["action"], "challenge");
        assert_eq!(v["decision"]["challenge_type"], "interactive");
        assert_eq!(v["decision"]["provider_id"], "self_hold");
        assert_eq!(v["decision"]["status"], 403);
        assert_eq!(v["risk"]["bot_class"], "automation_likely");
        assert_eq!(v["risk"]["score"], 71);
        assert_eq!(v["signals"][0]["family"], "http");
        assert_eq!(v["ctx"]["upstream"]["profile"], "cloudflare");
        assert_eq!(v["latency_us"], 180);
        assert_eq!(v["edge_id"], "edge-a");
        assert_eq!(v["bundle_version"], 7);
        assert_eq!(v["monitor_only"], true);
        assert_eq!(v["risk"]["shadow_score"], 0);
        assert_eq!(
            v["hits"][0],
            serde_json::json!({"rule_id": "login-high-risk", "outcome": "matched",
                "mode": "dry_run", "action": "challenge",
                "fields": ["phase1.interactive_as_pow"]})
        );
        assert!(
            v["decision"].get("tags").is_none(),
            "empty tags are omitted"
        );
    }

    /// Spec §3.5: tags only on TAG decisions, at most 8, each `[a-z0-9_.-]{1,32}`.
    #[test]
    fn decision_tags_validation() {
        let tag = |tags: &[&str]| Decision {
            action: Action::Tag,
            tags: tags.iter().map(|t| t.to_string()).collect(),
            ..Decision::default()
        };
        assert_eq!(tag(&["old_tls.stack-1"]).validate(), Ok(()));
        assert_eq!(tag(&[]).validate(), Ok(()));
        let eight: Vec<String> = (0..8).map(|i| format!("t{i}")).collect();
        let eight: Vec<&str> = eight.iter().map(String::as_str).collect();
        assert_eq!(tag(&eight).validate(), Ok(()));
        let nine: Vec<String> = (0..9).map(|i| format!("t{i}")).collect();
        let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
        assert_eq!(tag(&nine).validate(), Err(DecisionError::InvalidTags));
        for bad in ["", "Upper", "has space", "a,b", &"x".repeat(33), "\u{e9}"] {
            assert_eq!(
                tag(&[bad]).validate(),
                Err(DecisionError::InvalidTags),
                "{bad:?}"
            );
        }
        assert!(Decision::is_valid_tag(&"x".repeat(32)));
        // Tags on anything but TAG are invalid: MG-Tags is only sent on TAG.
        let mut block = tag(&["a"]);
        block.action = Action::Block;
        assert_eq!(block.validate(), Err(DecisionError::InvalidTags));
        let mut allow = tag(&["a"]);
        allow.action = Action::Allow;
        assert_eq!(allow.validate(), Err(DecisionError::InvalidTags));
        let json = serde_json::to_value(tag(&["a", "b"])).unwrap();
        assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn hit_outcomes_match_spec() {
        let names: Vec<_> = HitOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(names, ["matched", "missing_input", "eval_error"]);
        let hit: RuleHit = serde_json::from_str(
            r#"{"rule_id":"r","outcome":"missing_input","mode":"enforce","action":"block"}"#,
        )
        .unwrap();
        assert!(hit.fields.is_empty());
        assert_eq!(hit.mode, RuleMode::Enforce);
    }

    #[test]
    fn minimal_event_line_uses_defaults() {
        let ev = DecisionEvent::from_json_line(r#"{"ctx":{"request_id":"r"}}"#).unwrap();
        assert_eq!(ev.sample_rate, 1.0);
        assert_eq!(ev.decision.action, Action::Unspecified);
        assert!(ev.signals.is_empty());
        assert_eq!((ev.bundle_version, ev.monitor_only), (0, false));
    }

    #[test]
    fn entity_verdict_uses_type_key_and_expiry() {
        let v = EntityVerdict {
            entity_type: EntityType::Prefix,
            key: "203.0.113.0/24".into(),
            risk: Score::new(80),
            labels: vec!["scanner".into()],
            expires_at_ms: 2_000,
            source: "nearline.scanner".into(),
            version: "1".into(),
            site_id: "blog".into(),
            ..EntityVerdict::default()
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["type"], "prefix");
        assert_eq!(json["site_id"], "blog");
        assert_eq!(serde_json::from_value::<EntityVerdict>(json).unwrap(), v);
        assert!(v.is_active(1_999));
        assert!(!v.is_active(2_000));
    }

    #[test]
    fn entity_verdict_site_scope() {
        let mut v = EntityVerdict {
            entity_type: EntityType::Asn,
            key: "64500".into(),
            site_id: "blog".into(),
            ..EntityVerdict::default()
        };
        assert!(v.applies_to_site("blog"));
        assert!(!v.applies_to_site("shop"));

        v.site_id = EntityVerdict::ALL_SITES.into();
        assert!(v.applies_to_site("blog") && v.applies_to_site("shop"));
        for t in [EntityType::Ip, EntityType::Prefix, EntityType::Asn] {
            v.entity_type = t;
            assert!(v.applies_to_site("shop"), "{t} may be shared");
        }
        for t in [
            EntityType::Session,
            EntityType::Device,
            EntityType::Account,
            EntityType::FpCluster,
            EntityType::Agent,
            EntityType::Unspecified,
        ] {
            v.entity_type = t;
            assert!(!v.applies_to_site("shop"), "{t} must never be shared");
        }

        v.entity_type = EntityType::Ip;
        v.site_id = String::new();
        assert!(
            !v.applies_to_site(""),
            "a verdict without a site applies nowhere"
        );
    }

    #[test]
    fn challenge_result_json_shape() {
        let r = ChallengeResult {
            request_id: "01J9ZR".into(),
            site_id: "blog".into(),
            route_id: Some("login".into()),
            challenge_type: ChallengeType::Interactive,
            provider_id: Some(ProviderId::PowA11y),
            outcome: Some(VerdictOutcome::Pass),
            lvl: Some(TokenLevel::InteractiveA11y),
            attempt_no: 2,
            solve_ms: Some(5_400),
            risk_band: Some(RiskBand::High),
            reason_codes: vec!["pow_ok".into()],
            cf_ray: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["type"], "interactive");
        assert_eq!(v["provider_id"], "pow_a11y");
        assert_eq!(v["outcome"], "pass");
        assert_eq!(v["lvl"], "interactive_a11y");
        assert_eq!(v["risk_band"], "high");
        assert!(v.get("cf_ray").is_none());
        assert_eq!(serde_json::from_value::<ChallengeResult>(v).unwrap(), r);

        // The outcome vocabulary is exactly docs/02 §7's.
        let outcomes: Vec<_> = VerdictOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(outcomes, ["pass", "fail", "unavailable", "misconfigured"]);
    }

    #[test]
    fn decision_validation() {
        assert_eq!(Decision::allow().validate(), Ok(()));
        assert_eq!(Decision::challenge(ChallengeType::Pow).validate(), Ok(()));
        assert_eq!(
            Decision::default().validate(),
            Err(DecisionError::MissingAction)
        );

        let mut d = Decision::allow();
        d.challenge_type = ChallengeType::Pow;
        assert_eq!(d.validate(), Err(DecisionError::ChallengeTypeMismatch));

        let mut d = Decision::challenge(ChallengeType::Invisible);
        d.provider_id = Some(ProviderId::Turnstile);
        assert_eq!(d.validate(), Err(DecisionError::UnexpectedProvider));

        let mut d = Decision::challenge(ChallengeType::Interactive);
        d.status = Some(200);
        assert_eq!(d.validate(), Err(DecisionError::InvalidStatus(200)));
        d.status = Some(429);
        assert_eq!(d.validate(), Ok(()));

        let rl = Decision {
            action: Action::RateLimit,
            status: Some(503),
            ..Decision::default()
        };
        assert_eq!(rl.validate(), Err(DecisionError::InvalidStatus(503)));

        let block = Decision {
            action: Action::Block,
            status: Some(1000),
            ..Decision::default()
        };
        assert_eq!(block.validate(), Err(DecisionError::InvalidStatus(1000)));
    }
}
