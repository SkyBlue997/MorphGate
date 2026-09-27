//! Interactive challenge provider contract (docs/09).
//!
//! A provider is one way of producing *capped* human evidence: the built-in
//! press-and-hold (`self_hold`), the non-interactive accessible proof of work
//! (`pow_a11y`), or an external service (Turnstile, Tencent, Aliyun). The
//! Decision Core picks the provider; the client never does.
//!
//! Lifecycle as seen by a provider:
//!
//! 1. [`InteractiveChallengeProvider::prepare`]: synchronous, no network I/O.
//!    Produces the [`ChallengeSpec`] the SDK renders. Called after the Edge
//!    sealed the challenge `C` (nonce, bindings, expiry).
//! 2. The Edge opens `C`, checks expiry, bindings, PoW and **consumes the
//!    nonce** (`SET NX`) *before* calling the provider.
//! 3. [`InteractiveChallengeProvider::verify`]: asynchronous. External
//!    providers call their verification API through the injected
//!    [`OutboundHttp`], so mg-core itself performs no I/O and the host
//!    controls egress (allowlist, timeouts, proxy).
//!
//! Security rules every implementation must keep:
//!
//! * never fail open: transport errors, timeouts and unknown provider replies
//!   are [`VerdictOutcome::Unavailable`], never `Pass`;
//! * a `Pass` counts only if every binding check holds ([`ProviderVerdict::is_pass`]);
//! * a provider that cannot serve a region (Turnstile: `CN`) says so in
//!   [`ProviderCaps::denied_regions`] and is never selected there.

use crate::values::{Confidence, RiskBand};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// A boxed `Send` future, as returned by the async parts of the contract.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

wire_enum! {
    /// Interactive challenge provider id (as stored in `Decision::provider_id`).
    pub enum ProviderId {
        /// Built-in press-and-hold with PoW in a worker (default).
        SelfHold => "self_hold",
        /// Non-interactive accessible PoW; issues `interactive_a11y` tokens.
        PowA11y => "pow_a11y",
        /// Cloudflare Turnstile (not offered in mainland China).
        Turnstile => "turnstile",
        /// Tencent Cloud Captcha (optional, paid).
        Tencent => "tencent",
        /// Alibaba Cloud Captcha 2.0 (optional, paid).
        AliyunV2 => "aliyun_v2",
    }
}

impl ProviderId {
    /// Third-party providers (verified over [`OutboundHttp`]); their tokens
    /// carry the level `interactive_ext:{provider}`.
    pub const fn is_external(self) -> bool {
        matches!(self, Self::Turnstile | Self::Tencent | Self::AliyunV2)
    }
}

wire_enum! {
    /// What the visitor has to do.
    pub enum InteractionKind {
        /// Nothing visible (e.g. `pow_a11y`).
        NonInteractive => "non_interactive",
        /// Press and hold a target (mouse, touch, or Space/Enter).
        PressAndHold => "press_and_hold",
        /// Third-party managed widget that may show a checkbox (Turnstile).
        ManagedWidget => "managed_widget",
        /// Third-party puzzle (slider etc.), only via vendor providers.
        VendorPuzzle => "vendor_puzzle",
    }
}

wire_enum! {
    /// How the provider's result is tied to our sealed nonce.
    pub enum NonceBinding {
        /// The provider protocol carries our nonce itself.
        Native => "native",
        /// Via a customer-data field echoed back by the provider (Turnstile `cData`).
        Cdata => "cdata",
        /// Only via the surrounding sealed challenge; the provider result is unbound.
        WrapperOnly => "wrapper_only",
    }
}

wire_enum! {
    /// Accessible alternative a provider offers (WCAG 2.2: 2.5.7, 3.3.8).
    pub enum A11yAlternative {
        /// Hold Space / Enter instead of the pointer.
        KeyboardHold => "keyboard_hold",
        /// "Can't hold?": press once, then again when prompted.
        PressTwice => "press_twice",
        /// Switch to the `pow_a11y` provider.
        PowA11y => "pow_a11y",
        /// Passkey sign-in (sites with accounts).
        Passkey => "passkey",
        /// E-mail link (sites with accounts).
        EmailLink => "email_link",
    }
}

wire_enum! {
    /// Currency of a provider's per-verification price.
    pub enum Currency {
        Usd => "usd",
        Cny => "cny",
    }
}

/// Per-verification price in millionths of the currency unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitCost {
    pub currency: Currency,
    pub micros: u64,
}

/// Static facts about a provider, used for selection, CSP and cost reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCaps {
    pub interaction_kind: InteractionKind,
    /// Requires solving a cognitive test (WCAG 3.3.8). Built-in providers: never.
    pub cognitive_test: bool,
    /// Requires dragging (WCAG 2.5.7).
    pub drag_required: bool,
    pub a11y_alternatives: Vec<A11yAlternative>,
    /// ISO 3166-1 alpha-2 codes where the provider must not be offered.
    pub denied_regions: Vec<String>,
    pub nonce_binding: NonceBinding,
    /// Whether `verify` calls out over [`OutboundHttp`].
    pub requires_outbound_verify: bool,
    /// Maximum accepted age of a provider token, in seconds.
    pub max_token_age_s: u32,
    /// Origins the page must allow in CSP when this provider is used.
    pub third_party_origins: Vec<String>,
    /// `None` for free / self-hosted providers.
    pub unit_cost: Option<UnitCost>,
}

impl ProviderCaps {
    /// Whether the provider may be offered to a visitor from `country`.
    ///
    /// Fails closed: a provider with any denied region is not offered when the
    /// visitor's country is unknown.
    pub fn is_usable_in(&self, country: Option<&str>) -> bool {
        if self.denied_regions.is_empty() {
            return true;
        }
        match country {
            Some(c) => !self
                .denied_regions
                .iter()
                .any(|d| d.eq_ignore_ascii_case(c)),
            None => false,
        }
    }
}

/// Keyed MAC supplied by the host's key store, so providers can derive binding
/// values (e.g. Turnstile `cData`) without mg-core holding key material.
pub trait BindingMac: Send + Sync {
    /// HMAC-SHA256 with the current epoch binding key over `domain` and `parts`.
    ///
    /// Implementations must length-prefix `domain` and each part before
    /// hashing, so that different splits of the same bytes never collide.
    fn mac(&self, domain: &'static str, parts: &[&[u8]]) -> [u8; 32];
}

/// Input to [`InteractiveChallengeProvider::prepare`]. All values come from the
/// sealed challenge the Edge just issued.
#[derive(Clone, Copy)]
pub struct IssueCtx<'a> {
    pub site_id: &'a str,
    /// Exact site hostname the challenge is served on.
    pub host: &'a str,
    /// Route class (≤ 32 chars), used as the provider "action" where supported.
    pub route_class: &'a str,
    /// 128-bit single-use nonce sealed in `C`.
    pub nonce: [u8; 16],
    /// 1 for the first attempt.
    pub attempt_no: u8,
    /// Issue time of `C`, Unix epoch milliseconds.
    pub iat_ms: i64,
    /// Expiry of `C`, Unix epoch milliseconds.
    pub exp_ms: i64,
    pub risk_band: RiskBand,
    /// Seed for UI variation (e.g. hold duration) so it is fixed per `C`.
    pub ui_seed: u64,
    /// Visitor country (ISO 3166-1 alpha-2), if known.
    pub country: Option<&'a str>,
    pub binder: &'a dyn BindingMac,
}

impl fmt::Debug for IssueCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssueCtx")
            .field("site_id", &self.site_id)
            .field("host", &self.host)
            .field("route_class", &self.route_class)
            .field("attempt_no", &self.attempt_no)
            .field("iat_ms", &self.iat_ms)
            .field("exp_ms", &self.exp_ms)
            .field("risk_band", &self.risk_band)
            .field("country", &self.country)
            .finish_non_exhaustive() // nonce and binder deliberately omitted
    }
}

/// What the SDK needs to render the provider's UI. Serialized into the
/// challenge page / JSON challenge; never contains secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSpec {
    pub provider: ProviderId,
    /// Provider-specific public parameters (e.g. `hold_ms`, `sitekey`, `action`, `cdata`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

/// What the client sent back for a provider (part of `POST /__mg/c`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSubmission {
    pub provider: ProviderId,
    /// Provider response token (e.g. Turnstile response, Tencent ticket).
    pub token: String,
    /// Additional provider-specific fields (e.g. Tencent `randstr`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl ProviderSubmission {
    /// Maximum token length in bytes (Turnstile tokens are ≤ 2048 characters).
    pub const MAX_TOKEN_LEN: usize = 4096;
    /// Maximum number of extra fields.
    pub const MAX_FIELDS: usize = 8;
    /// Maximum length of an extra field name or value, in bytes.
    pub const MAX_FIELD_LEN: usize = 256;

    /// Cheap shape check, done before any provider call.
    pub fn validate(&self) -> Result<(), ProviderError> {
        let bad = |what: &'static str| Err(ProviderError::InvalidSubmission(what.into()));
        if self.token.is_empty() || self.token.len() > Self::MAX_TOKEN_LEN {
            return bad("token length");
        }
        if !self.token.bytes().all(|b| b.is_ascii_graphic()) {
            return bad("token charset");
        }
        if self.fields.len() > Self::MAX_FIELDS {
            return bad("too many fields");
        }
        if self
            .fields
            .iter()
            .any(|(k, v)| k.len() > Self::MAX_FIELD_LEN || v.len() > Self::MAX_FIELD_LEN)
        {
            return bad("field length");
        }
        Ok(())
    }
}

/// Input to [`InteractiveChallengeProvider::verify`], reconstructed by the Edge
/// from the opened challenge `C` and the request.
#[derive(Clone, Copy)]
pub struct VerifyCtx<'a> {
    pub site_id: &'a str,
    /// Expected exact hostname (provider authorisation may be suffix-based).
    pub host: &'a str,
    /// Expected route class / action.
    pub route_class: &'a str,
    pub nonce: [u8; 16],
    /// Issue time of `C`, Unix epoch milliseconds.
    pub iat_ms: i64,
    /// Current time, Unix epoch milliseconds, supplied by the host.
    pub now_ms: i64,
    /// Absolute deadline for the whole verification, Unix epoch milliseconds.
    pub deadline_ms: i64,
    /// Client IP as resolved by the upstream trust rules (sent as `remoteip`).
    pub client_ip: Option<IpAddr>,
    pub binder: &'a dyn BindingMac,
}

impl VerifyCtx<'_> {
    /// Milliseconds left until `deadline_ms` (0 when already past).
    pub fn remaining_ms(&self) -> u32 {
        u32::try_from(self.deadline_ms.saturating_sub(self.now_ms).max(0)).unwrap_or(u32::MAX)
    }
}

impl fmt::Debug for VerifyCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyCtx")
            .field("site_id", &self.site_id)
            .field("host", &self.host)
            .field("route_class", &self.route_class)
            .field("iat_ms", &self.iat_ms)
            .field("now_ms", &self.now_ms)
            .field("deadline_ms", &self.deadline_ms)
            .field("client_ip", &self.client_ip)
            .finish_non_exhaustive() // nonce and binder deliberately omitted
    }
}

wire_enum! {
    /// Provider-level result.
    pub enum VerdictOutcome {
        Pass => "pass",
        Fail => "fail",
        /// Transport error, timeout, 5xx, or an unrecognised reply. Never a pass.
        Unavailable => "unavailable",
        /// Our configuration is wrong (e.g. invalid secret): alert and disable.
        Misconfigured => "misconfigured",
    }
}

/// Binding checks a provider performs on its own reply. All default to `false`
/// (fail closed); a provider sets each one only after checking it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingChecks {
    /// Reply hostname equals [`VerifyCtx::host`] exactly.
    pub hostname_ok: bool,
    /// Reply action equals [`VerifyCtx::route_class`].
    pub action_ok: bool,
    /// Echoed binding value matches (constant-time compare), or the binding
    /// is carried natively / by the sealed wrapper per [`NonceBinding`].
    pub cdata_ok: bool,
    /// Provider timestamp is within `[iat - 5 s, now + 5 s]` and the token is not too old.
    pub time_ok: bool,
}

impl BindingChecks {
    /// All checks passed.
    pub const ALL_OK: Self = Self {
        hostname_ok: true,
        action_ok: true,
        cdata_ok: true,
        time_ok: true,
    };

    /// Whether every check passed.
    pub const fn all_ok(&self) -> bool {
        self.hostname_ok && self.action_ok && self.cdata_ok && self.time_ok
    }
}

/// Result of [`InteractiveChallengeProvider::verify`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderVerdict {
    pub outcome: VerdictOutcome,
    pub binding: BindingChecks,
    /// Provider-reported solve time, Unix epoch milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ts_ms: Option<i64>,
    /// Provider risk estimate normalised to `[0, 1]`, if it offers one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_risk: Option<Confidence>,
    /// Quantised interaction features for server-side scoring.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub features: BTreeMap<String, f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<Cow<'static, str>>,
    /// Key for the replay set (e.g. hash of the provider token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_key: Option<String>,
    pub latency_us: u32,
}

impl ProviderVerdict {
    /// A verdict with `outcome` and one reason code; binding checks all false.
    pub fn new(outcome: VerdictOutcome, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            outcome,
            binding: BindingChecks::default(),
            provider_ts_ms: None,
            provider_risk: None,
            features: BTreeMap::new(),
            reason_codes: vec![reason.into()],
            replay_key: None,
            latency_us: 0,
        }
    }

    /// `Unavailable` with `reason`.
    pub fn unavailable(reason: impl Into<Cow<'static, str>>) -> Self {
        Self::new(VerdictOutcome::Unavailable, reason)
    }

    /// The only way to read a verdict as human evidence: the provider said
    /// `Pass` **and** every binding check holds.
    pub fn is_pass(&self) -> bool {
        self.outcome == VerdictOutcome::Pass && self.binding.all_ok()
    }
}

/// What to do when a provider is unavailable for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailablePolicy {
    /// Fall back to another provider (typically `self_hold`).
    UseProvider(ProviderId),
    /// Let the request through, recording the outage as a signal. Only for
    /// low-sensitivity routes, and never as a pass.
    FailOpenWithSignal,
    /// Keep the visitor challenged.
    FailClosed,
}

/// Provider health as last observed by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum ProviderHealth {
    Healthy,
    Degraded(Cow<'static, str>),
    /// Disabled automatically (e.g. invalid secret) or by the owner.
    Disabled(Cow<'static, str>),
}

/// Errors from `prepare` / submission validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// Missing or invalid provider configuration.
    Misconfigured(Cow<'static, str>),
    /// Provider must not be offered in the visitor's region.
    RegionNotSupported,
    /// Malformed client submission.
    InvalidSubmission(Cow<'static, str>),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misconfigured(m) => write!(f, "provider misconfigured: {m}"),
            Self::RegionNotSupported => f.write_str("provider not available in this region"),
            Self::InvalidSubmission(m) => write!(f, "invalid provider submission: {m}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// HTTP method for [`OutboundRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// A request a provider asks the host to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub method: HttpMethod,
    /// Absolute `https://` URL of the provider's verification endpoint.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Per-attempt timeout; hosts also enforce their own ceiling.
    pub timeout_ms: u32,
}

/// The host's reply to an [`OutboundRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Why an outbound request produced no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    Timeout,
    Transport(String),
    /// The host refused the destination (not on the egress allowlist).
    Denied(String),
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("outbound request timed out"),
            Self::Transport(m) => write!(f, "outbound transport error: {m}"),
            Self::Denied(u) => write!(f, "outbound destination not allowed: {u}"),
        }
    }
}

impl std::error::Error for OutboundError {}

/// HTTP client injected by the host (`mg-edge`).
///
/// Implementations must only reach an allowlist of provider endpoints
/// (e.g. `https://challenges.cloudflare.com/turnstile/v0/siteverify`) and
/// return [`OutboundError::Denied`] for anything else.
pub trait OutboundHttp: Send + Sync {
    /// Sends `req`, honouring `req.timeout_ms`.
    fn send(&self, req: OutboundRequest) -> BoxFuture<'_, Result<OutboundResponse, OutboundError>>;
}

/// An interactive challenge provider (see the module docs for the lifecycle).
pub trait InteractiveChallengeProvider: Send + Sync {
    /// Stable id.
    fn id(&self) -> ProviderId;

    /// Static capabilities.
    fn capabilities(&self) -> &ProviderCaps;

    /// Builds the client-side spec. Synchronous; must not perform network I/O.
    fn prepare(&self, ctx: &IssueCtx<'_>) -> Result<ChallengeSpec, ProviderError>;

    /// Verifies a submission. Called only after the Edge consumed the nonce.
    ///
    /// Must finish by `ctx.deadline_ms` (pass [`VerifyCtx::remaining_ms`] as
    /// the outbound timeout) and must map every error to `Unavailable` or
    /// `Misconfigured`, never to `Pass`.
    fn verify<'a>(
        &'a self,
        ctx: &'a VerifyCtx<'a>,
        submission: &'a ProviderSubmission,
        http: &'a dyn OutboundHttp,
    ) -> BoxFuture<'a, ProviderVerdict>;

    /// Behaviour while the provider is unavailable on `route_class`.
    /// Default: keep the visitor challenged.
    fn on_unavailable(&self, _route_class: &str) -> UnavailablePolicy {
        UnavailablePolicy::FailClosed
    }

    /// Current health as tracked by the provider.
    fn health(&self) -> ProviderHealth {
        ProviderHealth::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    /// Polls a future that is expected to complete without real I/O.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    struct FixedMac;
    impl BindingMac for FixedMac {
        fn mac(&self, domain: &'static str, parts: &[&[u8]]) -> [u8; 32] {
            // Test double: NOT a MAC. Just deterministic, length-prefixed input.
            let mut out = [0u8; 32];
            let mut i = 0;
            let mut feed = |b: u8| {
                out[i % 32] = out[i % 32].wrapping_mul(31).wrapping_add(b);
                i += 1;
            };
            for p in std::iter::once(domain.as_bytes()).chain(parts.iter().copied()) {
                (p.len() as u32)
                    .to_be_bytes()
                    .into_iter()
                    .for_each(&mut feed);
                p.iter().copied().for_each(&mut feed);
            }
            out
        }
    }

    /// Records requests; answers with a canned reply.
    struct FakeHttp {
        reply: Result<OutboundResponse, OutboundError>,
        seen: Mutex<Vec<OutboundRequest>>,
    }
    impl OutboundHttp for FakeHttp {
        fn send(
            &self,
            req: OutboundRequest,
        ) -> BoxFuture<'_, Result<OutboundResponse, OutboundError>> {
            self.seen.lock().unwrap().push(req);
            let reply = self.reply.clone();
            Box::pin(async move { reply })
        }
    }

    /// Minimal external provider: remote says "ok:<host>:<action>:<cdata>".
    struct EchoProvider {
        caps: ProviderCaps,
    }

    impl EchoProvider {
        fn new() -> Self {
            Self {
                caps: ProviderCaps {
                    interaction_kind: InteractionKind::ManagedWidget,
                    cognitive_test: false,
                    drag_required: false,
                    a11y_alternatives: vec![A11yAlternative::PowA11y],
                    denied_regions: vec!["CN".into()],
                    nonce_binding: NonceBinding::Cdata,
                    requires_outbound_verify: true,
                    max_token_age_s: 300,
                    third_party_origins: vec!["https://provider.example".into()],
                    unit_cost: None,
                },
            }
        }

        fn cdata(binder: &dyn BindingMac, site: &str, nonce: &[u8; 16]) -> String {
            binder.mac("echo", &[site.as_bytes(), nonce])[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
    }

    impl InteractiveChallengeProvider for EchoProvider {
        fn id(&self) -> ProviderId {
            ProviderId::Turnstile
        }
        fn capabilities(&self) -> &ProviderCaps {
            &self.caps
        }
        fn prepare(&self, ctx: &IssueCtx<'_>) -> Result<ChallengeSpec, ProviderError> {
            if !self.caps.is_usable_in(ctx.country) {
                return Err(ProviderError::RegionNotSupported);
            }
            let mut params = BTreeMap::new();
            params.insert("action".into(), ctx.route_class.into());
            params.insert(
                "cdata".into(),
                Self::cdata(ctx.binder, ctx.site_id, &ctx.nonce),
            );
            Ok(ChallengeSpec {
                provider: self.id(),
                params,
            })
        }
        fn verify<'a>(
            &'a self,
            ctx: &'a VerifyCtx<'a>,
            submission: &'a ProviderSubmission,
            http: &'a dyn OutboundHttp,
        ) -> BoxFuture<'a, ProviderVerdict> {
            Box::pin(async move {
                let req = OutboundRequest {
                    method: HttpMethod::Post,
                    url: "https://provider.example/verify".into(),
                    headers: vec![],
                    body: submission.token.clone().into_bytes(),
                    timeout_ms: ctx.remaining_ms(),
                };
                let resp = match http.send(req).await {
                    Ok(r) if r.status == 200 => r,
                    Ok(_) => return ProviderVerdict::unavailable("http_status"),
                    Err(_) => return ProviderVerdict::unavailable("transport"),
                };
                let body = String::from_utf8_lossy(&resp.body);
                let mut it = body.split(':');
                if it.next() != Some("ok") {
                    return ProviderVerdict::new(VerdictOutcome::Fail, "provider_fail");
                }
                let mut v = ProviderVerdict::new(VerdictOutcome::Pass, "provider_pass");
                v.binding.hostname_ok = it.next() == Some(ctx.host);
                v.binding.action_ok = it.next() == Some(ctx.route_class);
                v.binding.cdata_ok =
                    it.next() == Some(Self::cdata(ctx.binder, ctx.site_id, &ctx.nonce).as_str());
                v.binding.time_ok = true;
                v
            })
        }
    }

    fn verify_ctx(binder: &FixedMac) -> VerifyCtx<'_> {
        VerifyCtx {
            site_id: "blog",
            host: "blog.example.com",
            route_class: "login",
            nonce: [7; 16],
            iat_ms: 1_000,
            now_ms: 2_000,
            deadline_ms: 6_000,
            client_ip: Some("198.51.100.4".parse().unwrap()),
            binder,
        }
    }

    fn submission() -> ProviderSubmission {
        ProviderSubmission {
            provider: ProviderId::Turnstile,
            token: "tok_abc".into(),
            fields: BTreeMap::new(),
        }
    }

    fn http_reply(body: &str) -> FakeHttp {
        FakeHttp {
            reply: Ok(OutboundResponse {
                status: 200,
                headers: vec![],
                body: body.as_bytes().to_vec(),
            }),
            seen: Mutex::new(vec![]),
        }
    }

    #[test]
    fn prepare_is_sync_and_region_aware() {
        let p = EchoProvider::new();
        let binder = FixedMac;
        let mut ctx = IssueCtx {
            site_id: "blog",
            host: "blog.example.com",
            route_class: "login",
            nonce: [7; 16],
            attempt_no: 1,
            iat_ms: 1_000,
            exp_ms: 601_000,
            risk_band: RiskBand::High,
            ui_seed: 42,
            country: Some("HK"),
            binder: &binder,
        };
        let spec = p.prepare(&ctx).unwrap();
        assert_eq!(spec.params["action"], "login");
        assert_eq!(spec.params["cdata"].len(), 16);
        ctx.country = Some("cn");
        assert_eq!(p.prepare(&ctx), Err(ProviderError::RegionNotSupported));
        ctx.country = None;
        assert_eq!(p.prepare(&ctx), Err(ProviderError::RegionNotSupported));
        assert!(!format!("{ctx:?}").contains("nonce"));
    }

    #[test]
    fn verify_passes_only_with_all_bindings() {
        let p = EchoProvider::new();
        let binder = FixedMac;
        let ctx = verify_ctx(&binder);
        let cdata = EchoProvider::cdata(&binder, "blog", &[7; 16]);
        let sub = submission();

        let http = http_reply(&format!("ok:blog.example.com:login:{cdata}"));
        let v = block_on(p.verify(&ctx, &sub, &http));
        assert!(v.is_pass(), "{v:?}");
        let seen = http.seen.lock().unwrap();
        assert_eq!(
            seen[0].timeout_ms, 4_000,
            "timeout derives from the deadline"
        );

        // Suffix-authorised hostname: provider says pass, binding says no.
        let http = http_reply(&format!("ok:evil.blog.example.com:login:{cdata}"));
        let v = block_on(p.verify(&ctx, &sub, &http));
        assert_eq!(v.outcome, VerdictOutcome::Pass);
        assert!(!v.is_pass());

        // Token minted for another nonce.
        let http = http_reply("ok:blog.example.com:login:0000000000000000");
        assert!(!block_on(p.verify(&ctx, &sub, &http)).is_pass());
    }

    #[test]
    fn verify_never_fails_open() {
        let p = EchoProvider::new();
        let binder = FixedMac;
        let ctx = verify_ctx(&binder);
        let sub = submission();
        for reply in [
            Err(OutboundError::Timeout),
            Err(OutboundError::Transport("reset".into())),
            Ok(OutboundResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            }),
        ] {
            let http = FakeHttp {
                reply,
                seen: Mutex::new(vec![]),
            };
            let v = block_on(p.verify(&ctx, &sub, &http));
            assert_eq!(v.outcome, VerdictOutcome::Unavailable);
            assert!(!v.is_pass());
        }
        assert_eq!(p.on_unavailable("login"), UnavailablePolicy::FailClosed);
        assert_eq!(p.health(), ProviderHealth::Healthy);
    }

    #[test]
    fn remaining_ms_saturates() {
        let binder = FixedMac;
        let mut ctx = verify_ctx(&binder);
        ctx.now_ms = 10_000;
        assert_eq!(ctx.remaining_ms(), 0);
        ctx.deadline_ms = i64::MAX;
        ctx.now_ms = i64::MIN;
        assert_eq!(ctx.remaining_ms(), u32::MAX);
    }

    #[test]
    fn submission_validation() {
        assert_eq!(submission().validate(), Ok(()));
        let mut s = submission();
        s.token = String::new();
        assert!(s.validate().is_err());
        s.token = "x".repeat(ProviderSubmission::MAX_TOKEN_LEN + 1);
        assert!(s.validate().is_err());
        s.token = "has space".into();
        assert!(s.validate().is_err());
        s.token = "ok".into();
        s.fields = (0..9).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(s.validate().is_err());
        s.fields = [("k".to_string(), "v".repeat(300))].into_iter().collect();
        assert!(s.validate().is_err());
    }

    #[test]
    fn provider_types_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&ProviderId::AliyunV2).unwrap(),
            "\"aliyun_v2\""
        );
        assert_eq!(
            serde_json::to_string(&UnavailablePolicy::UseProvider(ProviderId::SelfHold)).unwrap(),
            r#"{"use_provider":"self_hold"}"#
        );
        assert_eq!(
            serde_json::to_string(&ProviderHealth::Disabled("invalid_secret".into())).unwrap(),
            r#"{"state":"disabled","reason":"invalid_secret"}"#
        );
        let v = ProviderVerdict::unavailable("timeout");
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<ProviderVerdict>(&json).unwrap(), v);
    }
}
