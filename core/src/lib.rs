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
//! Phase 0 ships the data model and trait contracts only. Detectors, the v1
//! family-capped scorer, the policy IR evaluator (with the `MISSING` =
//! "unknown" semantics of docs/06 §2) and challenge sealing arrive in Phase 1;
//! the interactive challenge providers in Phase 2.

#[macro_use]
mod macros;

pub mod challenge;
pub mod context;
pub mod decision;
pub mod enums;
pub mod mask;
pub mod pipeline;
pub mod sealed;
pub mod signal;
pub mod values;

pub use challenge::{
    BindingChecks, BindingMac, BoxFuture, ChallengeSpec, InteractiveChallengeProvider, IssueCtx,
    OutboundHttp, ProviderCaps, ProviderError, ProviderHealth, ProviderId, ProviderSubmission,
    ProviderVerdict, UnavailablePolicy, VerdictOutcome, VerifyCtx,
};
pub use context::{
    Agent, BindResult, ClientSignals, ConnType, Crawler, EdgeTls, Http, Identity, IpSource, Ja4,
    Net, Proof, RequestContext, Tls, Token, TokenBind, TokenLevel, TokenStatus, UpstreamAuthMethod,
    UpstreamInfo,
};
pub use decision::{
    ChallengeResult, Decision, DecisionError, DecisionEvent, EntityVerdict, RiskAssessment,
};
pub use enums::{
    Action, BotClass, ChallengeType, Channel, EntityType, RouteSensitivity, SignalFamily,
    SignalSource, SignalState, UnknownVariant, UpstreamProfileKind,
};
pub use mask::FamilyMask;
pub use pipeline::{DecisionCore, Detector, Evaluation, PolicyEvaluator, Scorer};
pub use sealed::{ChallengeBind, ClaimsError, PowParams, SealedChallengeClaims};
pub use signal::Signal;
pub use values::{Confidence, Evidence, RiskBand, Score};
