//! Turnstile siteverify client (spec §8.4) with the pass conditions and error
//! mapping of §8.5.
//!
//! Called after the nonce of the submitted C was consumed (spec §7.5 step
//! 13). The verdict never fails open: every transport error, timeout, non-200
//! status, malformed reply and unknown error code is `Unavailable`; a `Pass`
//! needs `success = true` **and** every binding check (hostname, action,
//! `cdata`, time).
//!
//! # Requests and retries
//!
//! * Local pre-check: a token that is empty, longer than 2048 characters or
//!   has characters outside visible ASCII is `Fail` (`ic.ts_fail`) without a
//!   request.
//! * `POST` `{"secret", "response", "remoteip", "idempotency_key"}` as JSON
//!   (≤ 4 KiB), with the deadline of [`SiteverifyExpect::deadline_ms`] (each
//!   request also at most 5 s).
//! * One transient retry, with the same idempotency key: after a transport
//!   error, an HTTP 5xx, `internal-error`, or a timeout when at least 1 s of
//!   the deadline is left (the first request leaves [`RETRY_RESERVE_MS`]
//!   unused when the deadline is at least twice that, so a timed-out first
//!   request can be retried). `timeout-or-duplicate` and
//!   `invalid-input-response` are never retried.
//! * `invalid-input-secret` with a previous secret in the credential: one
//!   more request with the previous secret and the previous-secret variant
//!   of the idempotency key (spec §6.9), so Cloudflare does not answer from
//!   its idempotency cache.
//!
//! So a verification sends at most three requests.
//!
//! # Privacy (spec §2.4 item 10)
//!
//! Neither the token nor the secrets appear in `Debug` output or logs.

use super::breaker::{BreakerSignal, CircuitBreaker};
use super::http::{MAX_REQUEST_BYTES, MAX_TIMEOUT_MS, OutboundClient, SendError};
use super::metrics;
use super::response::{SiteverifyResponse, parse_siteverify_response};
use super::url::SiteverifyUrl;
use mg_core::challenge::{HttpMethod, OutboundRequest, OutboundResponse};
use mg_core::{
    BindingChecks, EvalMode, ProviderId, ProviderOutcome, ProviderVerdict, VerdictOutcome,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest Turnstile token sent (spec §8.4).
pub const MAX_TOKEN_CHARS: usize = 2048;
/// Longest secret value (spec §8.7).
pub const MAX_SECRET_CHARS: usize = 256;
/// A timeout is retried only with at least this much of the deadline left.
pub const MIN_RETRY_AFTER_TIMEOUT_MS: i64 = 1_000;
/// Part of the deadline the first request leaves for a retry, when the
/// deadline is at least twice as long.
pub const RETRY_RESERVE_MS: i64 = 1_250;
/// Clock skew allowed around `challenge_ts` (spec §8.5).
pub const TS_SKEW_MS: i64 = 5_000;
/// Oldest accepted `challenge_ts`, relative to now (spec §8.5).
pub const MAX_TOKEN_AGE_MS: i64 = 300_000;

/// The siteverify error codes of spec §8.5; others are not reported.
pub const KNOWN_ERROR_CODES: [&str; 7] = [
    "missing-input-secret",
    "invalid-input-secret",
    "missing-input-response",
    "invalid-input-response",
    "bad-request",
    "timeout-or-duplicate",
    "internal-error",
];

/// `ic.*` reason codes (spec §8.5).
pub mod reason {
    pub const TS_HOSTNAME: &str = "ic.ts_hostname";
    pub const TS_ACTION: &str = "ic.ts_action";
    pub const TS_CDATA: &str = "ic.ts_cdata";
    pub const TS_TIME: &str = "ic.ts_time";
    pub const TS_FAIL: &str = "ic.ts_fail";
    pub const TS_DUP: &str = "ic.ts_dup";
    pub const PROVIDER_UNAVAILABLE: &str = "ic.provider_unavailable";
    pub const PROVIDER_MISCONFIGURED: &str = "ic.provider_misconfigured";
}

/// The Turnstile secrets of one site (`mg-turnstile-keys`, spec §8.7): the
/// current value and, during a rotation, the previous one. `Debug` shows
/// only how many there are.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnstileSecrets {
    values: Vec<String>,
}

/// Invalid secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretsError {
    #[error("a Turnstile credential has 1 or 2 values")]
    Count,
    #[error("a Turnstile secret is 1-256 visible ASCII characters")]
    Value,
}

impl TurnstileSecrets {
    /// `values[0]` is the current secret, `values[1]` the previous one.
    pub fn new(values: Vec<String>) -> Result<Self, SecretsError> {
        if values.is_empty() || values.len() > 2 {
            return Err(SecretsError::Count);
        }
        if values.iter().any(|v| {
            v.is_empty() || v.len() > MAX_SECRET_CHARS || !v.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return Err(SecretsError::Value);
        }
        Ok(Self { values })
    }

    pub fn current(&self) -> &str {
        &self.values[0]
    }

    pub fn previous(&self) -> Option<&str> {
        self.values.get(1).map(String::as_str)
    }
}

impl fmt::Debug for TurnstileSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnstileSecrets")
            .field("values", &self.values.len())
            .finish()
    }
}

/// What is sent to siteverify.
#[derive(Clone, Copy)]
pub struct SiteverifyRequest<'a> {
    pub secrets: &'a TurnstileSecrets,
    /// The Turnstile token from the submission (`pp`).
    pub response: &'a str,
    /// The trusted client IP (`remoteip`).
    pub remoteip: IpAddr,
    /// The nonce of the submitted C; the idempotency key derives from it
    /// (spec §6.9).
    pub nonce: &'a [u8; 16],
}

impl fmt::Debug for SiteverifyRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteverifyRequest")
            .field("remoteip", &self.remoteip)
            .finish_non_exhaustive() // secrets, token and nonce omitted
    }
}

/// What a passing reply must match (spec §8.5).
pub struct SiteverifyExpect<'a> {
    /// The normalized request host.
    pub host: &'a str,
    /// The provider's configured `hostnames`.
    pub hostnames: &'a [String],
    /// `C.route_class`.
    pub action: &'a str,
    /// `C.iat` in Unix milliseconds.
    pub c_iat_ms: i64,
    /// The time the submission was read, Unix milliseconds.
    pub now_ms: i64,
    /// Absolute deadline of the whole verification, Unix milliseconds
    /// (`now + min(timeout_ms, 5000)` at step 13).
    pub deadline_ms: i64,
    /// Whether a reply `cdata` matches the C (built by WP-E2c with
    /// `mg_challenge::turnstile_cdata_matches`); called once per successful
    /// reply.
    pub cdata_ok: &'a (dyn Fn(&str) -> bool + Sync),
}

impl fmt::Debug for SiteverifyExpect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteverifyExpect")
            .field("host", &self.host)
            .field("hostnames", &self.hostnames)
            .field("action", &self.action)
            .field("c_iat_ms", &self.c_iat_ms)
            .field("now_ms", &self.now_ms)
            .field("deadline_ms", &self.deadline_ms)
            .finish_non_exhaustive()
    }
}

/// The `reason` label of `mg_provider_verify_total` (spec §15.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyReason {
    Ok,
    Hostname,
    Action,
    Cdata,
    Time,
    /// `invalid-input-response` / `missing-input-response`.
    Fail,
    /// `timeout-or-duplicate`.
    Dup,
    BadRequest,
    /// `missing-input-secret` / `invalid-input-secret`.
    Secret,
    /// `internal-error` after the retry.
    Internal,
    Transport,
    Timeout,
    /// A status other than 200.
    Http,
    /// A reply that does not fit spec §8.4, or an unknown error code.
    Malformed,
    /// Token refused by the local pre-check; nothing sent.
    Precheck,
    /// No concurrency slot, or the circuit breaker refused; nothing sent.
    Busy,
}

impl VerifyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Hostname => "hostname",
            Self::Action => "action",
            Self::Cdata => "cdata",
            Self::Time => "time",
            Self::Fail => "fail",
            Self::Dup => "dup",
            Self::BadRequest => "bad_request",
            Self::Secret => "secret",
            Self::Internal => "internal",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Http => "http",
            Self::Malformed => "malformed",
            Self::Precheck => "precheck",
            Self::Busy => "busy",
        }
    }
}

/// A verification result with the details mg-edge records.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteverifyReport {
    pub verdict: ProviderVerdict,
    pub reason: VerifyReason,
    /// The known error codes ([`KNOWN_ERROR_CODES`]) of the last reply.
    pub error_codes: Vec<String>,
    /// Requests sent (0–3).
    pub requests: u8,
    /// The last request used the previous secret.
    pub previous_secret_used: bool,
    /// Wall time of the whole verification.
    pub latency_ms: u32,
}

impl SiteverifyReport {
    /// What the result tells the circuit breaker: `Pass` / `Fail` from
    /// siteverify are healthy; nothing sent (pre-check, concurrency limit,
    /// breaker refusal) is neutral (spec §8.4, §8.6).
    pub fn breaker_signal(&self) -> BreakerSignal {
        if self.requests == 0 {
            return BreakerSignal::Neutral;
        }
        match self.verdict.outcome {
            VerdictOutcome::Pass | VerdictOutcome::Fail => BreakerSignal::Healthy,
            VerdictOutcome::Misconfigured => BreakerSignal::Misconfigured,
            VerdictOutcome::Unavailable if self.reason == VerifyReason::Busy => {
                BreakerSignal::Neutral
            }
            VerdictOutcome::Unavailable => BreakerSignal::Unavailable,
        }
    }

    /// `ChallengeResult.provider` (spec §3.3).
    pub fn provider_outcome(&self, mode: EvalMode) -> ProviderOutcome {
        ProviderOutcome {
            id: ProviderId::Turnstile,
            outcome: self.verdict.outcome,
            mode,
            latency_ms: self.latency_ms,
            error_codes: self.error_codes.clone(),
        }
    }
}

/// `uuid_v4_format(SHA-256("mg-ts-idem-v1" ‖ 0x00 ‖ nonce [‖ 0x01])[0..16])`
/// (spec §6.9); `previous_secret` selects the variant for the retry with the
/// previous secret. Same formula as `mg_challenge::idempotency_key`; both are
/// checked against `testdata/phase2/kat.json`.
pub fn idempotency_key(nonce: &[u8; 16], previous_secret: bool) -> String {
    let mut h = Sha256::new();
    h.update(b"mg-ts-idem-v1\x00");
    h.update(nonce);
    if previous_secret {
        h.update([0x01]);
    }
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Local pre-check of a token (spec §8.4).
pub fn token_precheck(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_CHARS
        && token.bytes().all(|b| b.is_ascii_graphic())
}

#[derive(Serialize)]
struct Body<'a> {
    secret: &'a str,
    response: &'a str,
    remoteip: String,
    idempotency_key: &'a str,
}

/// The siteverify client: one per process, shared by every site.
#[derive(Debug, Clone)]
pub struct Siteverify {
    http: Arc<OutboundClient>,
    url: SiteverifyUrl,
}

/// One request's result, before retries are decided.
enum Step {
    Done(Draft),
    /// Retry with the same secret and key, if the retry budget allows.
    Transient(Draft),
    /// `invalid-input-secret`: try the previous secret if there is one.
    InvalidSecret(Draft),
}

struct Draft {
    outcome: VerdictOutcome,
    reason: VerifyReason,
    binding: BindingChecks,
    provider_ts_ms: Option<i64>,
    error_codes: Vec<String>,
}

impl Draft {
    fn new(outcome: VerdictOutcome, reason: VerifyReason) -> Self {
        Self {
            outcome,
            reason,
            binding: BindingChecks::default(),
            provider_ts_ms: None,
            error_codes: Vec::new(),
        }
    }

    fn unavailable(reason: VerifyReason) -> Self {
        Self::new(VerdictOutcome::Unavailable, reason)
    }
}

impl Siteverify {
    /// A client for `url` sharing `http` (whose allowlist must contain
    /// `url`; otherwise every verification is `Unavailable`).
    pub fn new(http: Arc<OutboundClient>, url: SiteverifyUrl) -> Self {
        Self { http, url }
    }

    /// Builds the [`OutboundClient`] (allowlist: `url` only) and the client.
    /// Call it on the background-service runtime that runs verifications.
    pub fn build(url: SiteverifyUrl) -> Result<Self, super::http::BuildError> {
        let http = Arc::new(OutboundClient::new(std::slice::from_ref(&url))?);
        Ok(Self::new(http, url))
    }

    /// The shared HTTP client (also usable as `dyn OutboundHttp`).
    pub fn http(&self) -> &Arc<OutboundClient> {
        &self.http
    }

    pub fn url(&self) -> &SiteverifyUrl {
        &self.url
    }

    /// Verifies a Turnstile token (spec §8.4, §8.5).
    pub async fn verify(
        &self,
        req: &SiteverifyRequest<'_>,
        expect: &SiteverifyExpect<'_>,
    ) -> ProviderVerdict {
        self.verify_detailed(req, expect).await.verdict
    }

    /// [`Siteverify::verify`] with the details for events and metrics;
    /// counts `mg_provider_verify_total` and
    /// `mg_provider_verify_latency_seconds`.
    pub async fn verify_detailed(
        &self,
        req: &SiteverifyRequest<'_>,
        expect: &SiteverifyExpect<'_>,
    ) -> SiteverifyReport {
        let report = self.run(req, expect).await;
        record_metrics(&report);
        report
    }

    /// [`Siteverify::verify_detailed`] behind `breaker` (spec §8.6): an open,
    /// disabled or busy half-open breaker answers `Unavailable` (reason
    /// `busy`) without a request; otherwise the result is recorded in it.
    pub async fn verify_with_breaker(
        &self,
        breaker: &CircuitBreaker,
        req: &SiteverifyRequest<'_>,
        expect: &SiteverifyExpect<'_>,
    ) -> SiteverifyReport {
        let Ok(admission) = breaker.admit(expect.now_ms) else {
            let report = finish(
                Draft::unavailable(VerifyReason::Busy),
                0,
                false,
                Duration::ZERO,
            );
            record_metrics(&report);
            return report;
        };
        let report = self.verify_detailed(req, expect).await;
        admission.record(
            report.breaker_signal(),
            expect.now_ms.saturating_add(i64::from(report.latency_ms)),
        );
        report
    }

    async fn run(
        &self,
        req: &SiteverifyRequest<'_>,
        expect: &SiteverifyExpect<'_>,
    ) -> SiteverifyReport {
        let started = Instant::now();
        let elapsed_ms = || i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        if !token_precheck(req.response) {
            return finish(
                Draft::new(VerdictOutcome::Fail, VerifyReason::Precheck),
                0,
                false,
                Duration::ZERO,
            );
        }
        let mut transient_retry = true;
        let mut previous = false;
        let mut requests = 0u8;
        loop {
            let secret = if previous {
                req.secrets.previous().unwrap_or_default()
            } else {
                req.secrets.current()
            };
            let key = idempotency_key(req.nonce, previous);
            let body = serde_json::to_vec(&Body {
                secret,
                response: req.response,
                remoteip: req.remoteip.to_string(),
                idempotency_key: &key,
            })
            .unwrap_or_default();
            if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
                // Only a token full of characters that JSON escapes gets here.
                return finish(
                    Draft::new(VerdictOutcome::Fail, VerifyReason::Precheck),
                    requests,
                    previous,
                    started.elapsed(),
                );
            }
            let remaining = remaining_ms(expect, elapsed_ms());
            if remaining <= 0 {
                // Also before a previous-secret retry: without that answer
                // the secret is not known to be wrong.
                return finish(
                    Draft::unavailable(VerifyReason::Timeout),
                    requests,
                    previous,
                    started.elapsed(),
                );
            }
            // The first request leaves RETRY_RESERVE_MS for a retry when the
            // deadline allows, so that a timed-out first request can be
            // retried (spec §8.4: only with >= 1 s left).
            let budget = if requests == 0 && remaining >= 2 * RETRY_RESERVE_MS {
                remaining - RETRY_RESERVE_MS
            } else {
                remaining
            };
            let result = self
                .http
                .send_checked(OutboundRequest {
                    method: HttpMethod::Post,
                    url: self.url.as_str().to_owned(),
                    headers: vec![("content-type".into(), "application/json".into())],
                    body,
                    timeout_ms: u32::try_from(budget)
                        .unwrap_or(u32::MAX)
                        .min(MAX_TIMEOUT_MS),
                })
                .await;
            if !matches!(
                result,
                Err(SendError::Busy | SendError::Denied(_) | SendError::RequestTooLarge)
            ) {
                requests += 1;
            }
            match classify(result, expect) {
                Step::Done(draft) => {
                    if previous && draft.outcome == VerdictOutcome::Pass {
                        log::warn!(
                            "outbound: siteverify rejected the current Turnstile secret and accepted the previous one; check the current value of the credential"
                        );
                    }
                    return finish(draft, requests, previous, started.elapsed());
                }
                Step::Transient(draft) => {
                    let left = remaining_ms(expect, elapsed_ms());
                    let allowed = if draft.reason == VerifyReason::Timeout {
                        left >= MIN_RETRY_AFTER_TIMEOUT_MS
                    } else {
                        left > 0
                    };
                    if transient_retry && allowed {
                        transient_retry = false;
                        continue;
                    }
                    return finish(draft, requests, previous, started.elapsed());
                }
                Step::InvalidSecret(draft) => {
                    if !previous && req.secrets.previous().is_some() {
                        previous = true;
                        continue;
                    }
                    log::error!(
                        "outbound: siteverify rejected the Turnstile secret (invalid-input-secret); the provider is disabled"
                    );
                    return finish(draft, requests, previous, started.elapsed());
                }
            }
        }
    }
}

fn remaining_ms(expect: &SiteverifyExpect<'_>, elapsed_ms: i64) -> i64 {
    expect
        .deadline_ms
        .saturating_sub(expect.now_ms)
        .saturating_sub(elapsed_ms)
}

fn classify(result: Result<OutboundResponse, SendError>, expect: &SiteverifyExpect<'_>) -> Step {
    let resp = match result {
        Ok(resp) => resp,
        Err(SendError::Busy) => return Step::Done(Draft::unavailable(VerifyReason::Busy)),
        Err(SendError::Timeout) => {
            return Step::Transient(Draft::unavailable(VerifyReason::Timeout));
        }
        Err(SendError::Transport(_)) => {
            return Step::Transient(Draft::unavailable(VerifyReason::Transport));
        }
        Err(SendError::ResponseTooLarge) => {
            return Step::Done(Draft::unavailable(VerifyReason::Malformed));
        }
        Err(e @ (SendError::Denied(_) | SendError::RequestTooLarge)) => {
            log::error!("outbound: siteverify request not sent: {e}");
            return Step::Done(Draft::unavailable(VerifyReason::Transport));
        }
    };
    if (500..=599).contains(&resp.status) {
        return Step::Transient(Draft::unavailable(VerifyReason::Http));
    }
    if resp.status != 200 {
        return Step::Done(Draft::unavailable(VerifyReason::Http));
    }
    if !is_json(&resp.headers) {
        return Step::Done(Draft::unavailable(VerifyReason::Malformed));
    }
    let Ok(parsed) = parse_siteverify_response(&resp.body) else {
        return Step::Done(Draft::unavailable(VerifyReason::Malformed));
    };
    evaluate(&parsed, expect)
}

/// `Content-Type: application/json`, parameters allowed.
fn is_json(headers: &[(String, String)]) -> bool {
    let mut values = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-type"));
    let Some((_, value)) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value
            .split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

fn evaluate(resp: &SiteverifyResponse, expect: &SiteverifyExpect<'_>) -> Step {
    let mut codes: Vec<String> = Vec::new();
    for code in &resp.error_codes {
        if KNOWN_ERROR_CODES.contains(&code.as_str()) && !codes.contains(code) {
            codes.push(code.clone());
        }
    }
    let with_codes = |mut d: Draft| {
        d.error_codes = codes.clone();
        d
    };
    if !resp.success {
        let has = |c: &str| resp.has_code(c);
        return if has("missing-input-secret") {
            log::error!(
                "outbound: siteverify reports missing-input-secret; the provider is disabled"
            );
            Step::Done(with_codes(Draft::new(
                VerdictOutcome::Misconfigured,
                VerifyReason::Secret,
            )))
        } else if has("invalid-input-secret") {
            Step::InvalidSecret(with_codes(Draft::new(
                VerdictOutcome::Misconfigured,
                VerifyReason::Secret,
            )))
        } else if has("bad-request") {
            log::error!("outbound: siteverify reports bad-request");
            Step::Done(with_codes(Draft::unavailable(VerifyReason::BadRequest)))
        } else if has("timeout-or-duplicate") {
            Step::Done(with_codes(Draft::new(
                VerdictOutcome::Fail,
                VerifyReason::Dup,
            )))
        } else if has("invalid-input-response") || has("missing-input-response") {
            Step::Done(with_codes(Draft::new(
                VerdictOutcome::Fail,
                VerifyReason::Fail,
            )))
        } else if has("internal-error") {
            Step::Transient(with_codes(Draft::unavailable(VerifyReason::Internal)))
        } else {
            Step::Done(with_codes(Draft::unavailable(VerifyReason::Malformed)))
        };
    }

    let hostname = resp.hostname.as_deref().unwrap_or_default();
    let ts_ns = resp.challenge_ts_ns.unwrap_or(i128::MIN);
    let ms = |v: i64| i128::from(v) * 1_000_000;
    let binding = BindingChecks {
        hostname_ok: hostname == expect.host
            && expect
                .hostnames
                .iter()
                .any(|h| h.eq_ignore_ascii_case(hostname)),
        action_ok: resp.action.as_deref() == Some(expect.action),
        cdata_ok: (expect.cdata_ok)(resp.cdata.as_deref().unwrap_or_default()),
        time_ok: ts_ns >= ms(expect.c_iat_ms.saturating_sub(TS_SKEW_MS))
            && ts_ns <= ms(expect.now_ms.saturating_add(TS_SKEW_MS))
            && ms(expect.now_ms) - ts_ns <= ms(MAX_TOKEN_AGE_MS),
    };
    let reason = if !binding.hostname_ok {
        VerifyReason::Hostname
    } else if !binding.action_ok {
        VerifyReason::Action
    } else if !binding.cdata_ok {
        VerifyReason::Cdata
    } else if !binding.time_ok {
        VerifyReason::Time
    } else {
        VerifyReason::Ok
    };
    let outcome = if reason == VerifyReason::Ok {
        VerdictOutcome::Pass
    } else {
        VerdictOutcome::Fail
    };
    let mut draft = with_codes(Draft::new(outcome, reason));
    draft.binding = binding;
    draft.provider_ts_ms = resp.challenge_ts_ms();
    Step::Done(draft)
}

fn ic_reason(outcome: VerdictOutcome, reason: VerifyReason) -> Option<&'static str> {
    Some(match (outcome, reason) {
        (VerdictOutcome::Pass, _) => return None,
        (VerdictOutcome::Misconfigured, _) => reason::PROVIDER_MISCONFIGURED,
        (VerdictOutcome::Unavailable, _) => reason::PROVIDER_UNAVAILABLE,
        (VerdictOutcome::Fail, VerifyReason::Hostname) => reason::TS_HOSTNAME,
        (VerdictOutcome::Fail, VerifyReason::Action) => reason::TS_ACTION,
        (VerdictOutcome::Fail, VerifyReason::Cdata) => reason::TS_CDATA,
        (VerdictOutcome::Fail, VerifyReason::Time) => reason::TS_TIME,
        (VerdictOutcome::Fail, VerifyReason::Dup) => reason::TS_DUP,
        (VerdictOutcome::Fail, _) => reason::TS_FAIL,
    })
}

fn finish(draft: Draft, requests: u8, previous: bool, elapsed: Duration) -> SiteverifyReport {
    let latency_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
    let reason_codes = ic_reason(draft.outcome, draft.reason)
        .map(|r| vec![Cow::Borrowed(r)])
        .unwrap_or_default();
    SiteverifyReport {
        verdict: ProviderVerdict {
            outcome: draft.outcome,
            binding: draft.binding,
            provider_ts_ms: draft.provider_ts_ms,
            provider_risk: None,
            features: BTreeMap::new(),
            reason_codes,
            replay_key: None,
            latency_us: u32::try_from(elapsed.as_micros()).unwrap_or(u32::MAX),
        },
        reason: draft.reason,
        error_codes: draft.error_codes,
        requests,
        previous_secret_used: previous,
        latency_ms,
    }
}

fn record_metrics(report: &SiteverifyReport) {
    let m = metrics::get();
    let provider = ProviderId::Turnstile.as_str();
    m.verify_total
        .with_label_values(&[
            provider,
            report.verdict.outcome.as_str(),
            report.reason.as_str(),
        ])
        .inc();
    if report.requests > 0 {
        m.verify_latency
            .with_label_values(&[provider])
            .observe(f64::from(report.latency_ms) / 1000.0);
    }
}
