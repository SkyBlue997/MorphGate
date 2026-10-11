//! Outbound HTTP of the Edge (docs/impl/phase2-spec.md §8.4–§8.6; Phase 2,
//! WP-C6).
//!
//! * [`OutboundClient`]: the only implementation of
//!   [`mg_core::challenge::OutboundHttp`]: reqwest without proxies, User-Agent
//!   [`USER_AGENT`], an exact-URL allowlist and a process-wide concurrency
//!   limit of [`MAX_CONCURRENT_REQUESTS`] (a request without a free slot is
//!   refused at once, never queued).
//! * [`Siteverify`]: the Turnstile siteverify client: local token pre-check,
//!   the request of §8.4, retries (one transient retry with the same
//!   idempotency key; one retry with the previous secret on
//!   `invalid-input-secret`), response parsing ([`parse_siteverify_response`])
//!   and the pass conditions and error mapping of §8.5, as a
//!   [`mg_core::ProviderVerdict`]. The `cdata` comparison is a closure from
//!   the caller ([`SiteverifyExpect::cdata_ok`]), so this crate does not
//!   depend on mg-challenge.
//! * [`validate_siteverify_url`]: the production URL, or a loopback mock URL
//!   only when the caller allows test destinations (`MG_EDGE_TEST_OUTBOUND=1`
//!   in mg-edge); [`report_siteverify_url`] publishes
//!   `mg_outbound_override`.
//! * [`CircuitBreaker`]: per-(site, provider) health (§8.6): healthy, open,
//!   half-open, disabled; `mg_provider_state`.
//!
//! Everything async runs on the background-service runtime where the
//! client was built (spec §1.2). No test reaches an external host: they all
//! use the loopback mock in `testkit::siteverify` (D-52).

mod breaker;
mod http;
mod metrics;
mod response;
mod siteverify;
mod url;

pub use breaker::{
    Admission, BreakerSignal, BreakerState, CircuitBreaker, DisabledReason, FAILURE_THRESHOLD,
    FAILURE_WINDOW_MS, OPEN_BASE_MS, OPEN_MAX_MS, Refusal,
};
pub use http::{
    BuildError, CONNECT_TIMEOUT, MAX_CONCURRENT_REQUESTS, MAX_IDLE_PER_HOST, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, MAX_TIMEOUT_MS, OutboundClient, SendError, USER_AGENT,
};
pub use metrics::report_siteverify_url;
pub use response::{
    MAX_ERROR_CODES, ResponseError, SiteverifyResponse, parse_rfc3339_ns, parse_siteverify_response,
};
pub use siteverify::{
    KNOWN_ERROR_CODES, MAX_SECRET_CHARS, MAX_TOKEN_AGE_MS, MAX_TOKEN_CHARS,
    MIN_RETRY_AFTER_TIMEOUT_MS, RETRY_RESERVE_MS, SecretsError, Siteverify, SiteverifyExpect,
    SiteverifyReport, SiteverifyRequest, TS_SKEW_MS, TurnstileSecrets, VerifyReason,
    idempotency_key, reason, token_precheck,
};
pub use url::{
    MAX_TEST_URL_BYTES, SITEVERIFY_URL, SiteverifyUrl, UrlError, validate_siteverify_url,
};
