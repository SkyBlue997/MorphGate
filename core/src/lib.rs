//! # mg-core: the MorphGate Decision Core
//!
//! Native Rust types and traits for the per-request decision:
//!
//! ```text
//! RequestContext --Detector*--> [Signal] --Scorer--> RiskAssessment --PolicyEvaluator--> Decision
//!                                                                     \-> DecisionEvent (JSON line)
//! ```
//!
//! The wire contract lives in `proto/morphgate/v1/*.proto` (crate `mg-proto`);
//! the types here mirror it one-to-one in meaning, use stronger native types
//! (`Option`, `IpAddr`, clamped newtypes) and serialize to snake_case JSON.
//! The JSON form of [`DecisionEvent`] is the line the Edge ships to VictoriaLogs.
//!
//! ## Rules for this crate
//!
//! * **Pure.** No I/O, no threads, no async runtime, no environment reads, no
//!   clock reads. Time arrives as data (`RequestContext::ts_ms`,
//!   `VerifyCtx::now_ms`). Enforced by `core/clippy.toml`.
//! * **Portable.** Must compile for `wasm32-unknown-unknown` (kept open for a
//!   possible Cloudflare Worker adapter), so dependencies stay minimal.
//! * **State via traits.** Anything stateful or remote (rate counters,
//!   provider verification over HTTP) is injected by the host (`mg-edge`).
//!
//! Phase 1 (docs/impl/phase1-spec.md §5): the detectors of [`detectors`],
//! the family-capped log-odds scorer [`ScorerV1`] with [`derive_bot_class`],
//! and [`policy`]: the restricted policy IR evaluator (MISSING = UNKNOWN,
//! static step bound), the rule engine and the default treatment matrix.
//! [`DecisionCore::phase1`] wires them together. The interactive challenge
//! providers arrive in Phase 2.
//!
//! ```
//! use mg_core::policy::{EngineConfig, MissingSet, NamedLists, SitePolicy};
//! use mg_core::{DecisionCore, RequestContext, RequestExtras, RouteInfo, ScoringConfig, ua};
//!
//! let policy = SitePolicy::new(Vec::new(), NamedLists::default(), EngineConfig::default());
//! let core = DecisionCore::phase1(ScoringConfig::default(), Box::new(policy));
//! let mut ctx = RequestContext::new("req-1", "blog", 1_790_000_000_000);
//! ctx.http.user_agent = Some("curl/8.5.0".into());
//! let (route, missing) = (RouteInfo::default(), MissingSet::default());
//! let ua = ua::parse("curl/8.5.0");
//! let extras = RequestExtras {
//!     route: &route, headers: &[], query: "", rate: &[],
//!     missing: &missing, ua: &ua, secure_context: true,
//! };
//! let ev = core.evaluate(&ctx, &extras);
//! assert!(ev.risk.top_reasons.contains(&"http.ua_library".to_string()));
//! assert_eq!(ev.outcome.decision.validate(), Ok(()));
//! ```

#[macro_use]
mod macros;

pub mod challenge;
pub mod classify;
pub mod context;
pub mod decision;
pub mod detectors;
pub mod enums;
pub mod extras;
pub mod gcra;
pub mod mask;
pub mod paths;
pub mod pipeline;
pub mod policy;
pub mod scoring;
pub mod sealed;
pub mod signal;
#[cfg(test)]
mod testutil;
pub mod ua;
pub mod values;

pub use challenge::{
    BindingChecks, BindingMac, BoxFuture, ChallengeSpec, InteractiveChallengeProvider, IssueCtx,
    OutboundHttp, ProviderCaps, ProviderError, ProviderHealth, ProviderId, ProviderSubmission,
    ProviderVerdict, UnavailablePolicy, VerdictOutcome, VerifyCtx,
};
pub use classify::derive_bot_class;
pub use context::{
    Agent, BindResult, ClientSignals, ConnType, Crawler, CrawlerMethod, CrawlerVerification,
    EdgeTls, Http, Identity, IpSource, Ja4, Net, Proof, RequestContext, Tls, Token, TokenBind,
    TokenLevel, TokenStatus, UpstreamAuthMethod, UpstreamInfo,
};
pub use decision::{
    ChallengeResult, Decision, DecisionError, DecisionEvent, EntityVerdict, HitOutcome,
    RiskAssessment, RuleHit,
};
pub use detectors::phase1_detectors;
pub use enums::{
    Action, BotClass, ChallengeType, Channel, EntityType, RouteSensitivity, SignalFamily,
    SignalSource, SignalState, UnknownVariant, UpstreamProfileKind,
};
pub use extras::{LimiterAction, RateObservation, RequestExtras, RouteInfo};
pub use mask::FamilyMask;
pub use pipeline::{
    DecisionCore, Detector, Evaluation, PolicyEvaluator, PolicyInput, PolicyOutcome, Scorer,
};
pub use scoring::{FamilyMode, ScorerV1, ScoringConfig};
pub use sealed::{ChallengeBind, ClaimsError, PowParams, SealedChallengeClaims};
pub use signal::Signal;
pub use values::{Confidence, Evidence, RiskBand, Score};

/// What `Debug` prints in place of a client IP (spec §2.4 item 5).
pub(crate) const REDACTED: &str = "<redacted>";
