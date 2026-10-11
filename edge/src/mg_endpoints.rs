//! The Edge's own endpoints under `/__mg/` (docs/impl/phase1-spec.md §10):
//! the SDK files (`/__mg/s/<file>`, §10.4), the challenge submission
//! (`POST /__mg/c`, §10.3, with §9.7, §9.8, D-27, D-28, D-35, D-37, I-10,
//! I-18, I-28) and the return path of the verify entry (`GET /__mg/v`,
//! §10.5, I-39; the proxy runs its decision). `/__mg/healthz` and the
//! reserved 404 stay in [`crate::enforce`].
//!
//! # `/__mg/s/<file>`
//!
//! `GET` / `HEAD` of a file listed in the SDK manifest's `files` (exact
//! name) is answered from memory with `text/javascript`, the immutable cache
//! policy and `nosniff` ([`sdk_file`]); any other name is 404 (`no-store`),
//! any other method 405 with `Allow: GET, HEAD`.
//!
//! `/__mg/s/mg.js` is the stable alias of the build (D-39, Phase 2 spec
//! §11.1): the SDK file's bytes with `Cache-Control: public, max-age=300`,
//! `ETag: "<build>"` and 304 for a matching `If-None-Match`.
//!
//! # `GET /__mg/v?ret=<path>`
//!
//! A script whose fetch got the JSON challenge sends the page there with
//! its own path; the Edge challenges and the solved form returns to `ret`.
//! [`verify_ret`] reads `ret`: exactly one `ret` parameter, percent-decoded
//! (`+` stays `+`), visible ASCII (as a raw request target is) and
//! `validate_ret`; anything else is the bundle's `fallback_ret`. The page
//! escapes it and the 303 `Location` percent-encodes it, as for any `ret`.
//!
//! # `POST /__mg/c`
//!
//! [`submit`] runs the checks of §10.3 in order; the first failure decides.
//! Reason codes (`ic.*`) only go to the [`SubmitRecord`] (the `kind=feedback`
//! event of WP-E1d and the debug log), never to the client:
//!
//! | # | Check | Answer |
//! |---|---|---|
//! | 0 | client IP unknown | 429, `Retry-After: 5` (`ic.no_client_ip`) |
//! | 1 | `Early-Data` (any instance, RFC 8470 §5.1; also one a `Connection` option names) | 425 `{"error":"mg_too_early"}` (`ic.too_early`) |
//! | 2 | round trip 1: `mg.c.submit` (write), `mg.c.fail` / `mg.c.fail.prefix` (check: would one more failure exceed?) | 429 (`ic.rate_limited`) |
//! | 2b | round trip 1: `mg.clr.issue.ipp` / `.asn` (check) | 429 (`ic.issue_quota`) |
//! | 3 | `Content-Encoding` (also one a `Connection` option names); `Content-Length` > 8192; media type; body > 8192 bytes or not read within 5 s; form / JSON rules ([`crate::submission`]) | uniform failure (`ic.body`), no new `C` |
//! | 4 | open `C` for the request host and the submitted type | uniform failure (`ic.c_*`), no new `C` |
//! | 5 | bindings: `uah` hard; `ipp` hard or soft | `ic.bind_uah` / `ic.bind_ipp`; soft only records `ic.bind_ipp_soft` |
//! | 6 | PoW at the sealed difficulty on `C` exactly as received | `ic.pow` |
//! | 7 | `ret` valid and `ret_hash(ret)` sealed | `ic.ret` |
//! | 8 | `auto.webdriver == true`; `env.ua.userAgent` not a prefix of `User-Agent` | `ic.automation_flag` / `ic.ua_mismatch` |
//! | 9 | round trip 2: `mg_nonce_issue` v2 (nonce + issuance quotas) | `ic.nonce_reused`; 429 `ic.issue_quota`; replay store unavailable: 429 `ic.replay_unavailable` on a `fail_closed` route, otherwise issued with `ic.replay_unchecked` |
//! | 10 | mint the clearance (`sub` / `sst` carried over per §6.5; `ruc: true` after `ic.replay_unchecked`, I-30) | success: 303 + cookie (form) or 200 JSON + cookie (fetch); RNG failure: 503 |
//!
//! A failure from step 5 on attaches a new `C` (D-27, I-10): type `pow`, the
//! original `route_class`, the band `RiskBand::after_failure(original)` and
//! its difficulty, the same return path (see [`new_challenge_ret`]). The
//! failures of §9.8 (`ic.body`, `ic.c_invalid`, `ic.c_kid`, `ic.bind_*`,
//! `ic.pow`, `ic.ret`, `ic.automation_flag`, `ic.ua_mismatch`,
//! `ic.nonce_reused`) are counted in `mg.c.fail` and `mg.c.fail.prefix`
//! asynchronously ([`counts_as_failure`]).
//!
//! ## Phase 2 (docs/impl/phase2-spec.md §7.5, WP-E2a)
//!
//! A v2 submission (`v = 2`, see [`crate::submission`]) runs the order of
//! §7.5: round trip 1 also checks both tiers of `mg.a11y.issue` and reads
//! the near-line session verdict of the carried clearance; after opening
//! `C`, an interactive `C` without `interactive_available` fails with a
//! `pow` `C` (4a, not counted); then the provider (5: in `C.providers`;
//! `pow_a11y` over its quota fails with `ix.a11y_quota`, not counted, no
//! nonce consumed), the server-side time window (6, `ic.too_fast`), the
//! bindings with the session key's `jkt` (7, `ic.bind_jkt`; a bound `C`
//! refuses v1), the signature (8, `ic.sig`), PoW v1 or v2 (9), `ret` (10),
//! the environment and the hard checks of §7.7 (11), the nonce with the
//! quotas, `mg.a11y.issue` for `pow_a11y` (12), the score (14: `enforce`
//! only) and the token (15): the level by provider, v2 with `cnf.jkt` and
//! `lat` in schema 2 (v1 in schema 1, D-66), `__Host-mg_st` after
//! `__Host-mg_clr` in schema 2, `__Host-mg_a11y` set by `pow_a11y` and
//! deleted by `self_hold`. A failure from 4a on attaches the `C` of
//! `next_challenge_after_failure` (D-50), bound to the key once the
//! signature verified. The nonce of an interactive `C` is kept until the
//! `C` can no longer be renewed (`crate::renew::interactive_nonce_ttl_ms`).
//!
//! Answers follow the submission's encoding: a form navigation gets HTML
//! (the failed challenge page, or the short 429 page), a fetch gets JSON.
//! When the media type is not one of the two, the §9.9 navigation test of
//! the request headers decides. An answer sent before the body was read
//! completely closes the connection (§9.9).
//!
//! Every submission counts `mg_challenge_total{type, provider="none",
//! result}` with `solved`, `expired` (`ic.c_expired`) or `failed`; `type` is
//! the sealed type once `C` opened, the submitted type once the body parsed,
//! and `unspecified` before that.
//!
//! # The replay store (§9.7 rules 3-5)
//!
//! `mg_edge_core::state::StateHandle::nonce_issue_v2` checks the local replay set
//! first, then Valkey, and decides whether the local set alone is
//! authoritative. When it is not (`NonceResultV2::Unavailable`), the route
//! the `C` belongs to decides ([`replay_fail_closed`]): the route of the
//! request host's environment named `claims.route_class` (inside the AEAD,
//! so trusted), OR the route the `ret` path selects for a GET; a route that
//! no longer exists (a newer bundle) counts as `fail_closed`. A token issued
//! with `ic.replay_unchecked` carries the claim `ruc` (I-30), and no
//! `fail_closed` route accepts it (`crate::identity::Acceptance`): there the
//! client is challenged again, and that `C` belongs to the `fail_closed`
//! route, so its submission is 429 until the replay store is back.

use crate::challenge::{self, IssueError, IssueRequest, Issued, fallback_ret, pow_bits};
use crate::context::{self, Built};
use crate::enforce::{EdgeResponse, IMMUTABLE, JAVASCRIPT, is_navigation};
use crate::interactive::{self, Gate};
use crate::metrics::metrics;
use crate::pages::{self, Page, PageState};
use crate::sdk::SdkDir;
use crate::sites::{BundleRuntime, EnvRuntime, RouteRuntime, select_route};
use crate::submission::{
    self, AutomationSummary, EnvSummary, MAX_BODY, MediaKind, Submission, media_kind,
};
use async_trait::async_trait;
use bytes::Bytes;
use mg_challenge::{
    BindInputs, ClearanceBind, ClearanceClaims, MintParams, MintV2Params, POW_ALG_V2, Rng, Sealer,
    TokenError, check_challenge_bind, check_clearance_bind, clearance_cookies, mint_v2, pow_verify,
    pow_verify_v2, ret_hash, reusable_session, reusable_session_v2, set_cookie_value,
    status_set_cookie_value, ui_params, validate_ret, verify_ignoring_expiry,
};
use mg_core::gcra::GcraOutcome;
use mg_core::providers::IxOutcome;
use mg_core::{
    BindResult, ChallengeResult, ChallengeType, InteractionInput, IxMode, IxTelemetry, Net,
    ProviderId, RiskBand, SealedChallengeClaims, TokenLevel, VerdictOutcome, assess_interaction,
    min_elapsed_ms, next_challenge_after_failure,
};
use mg_edge_core::state::builtin::ClientDims;
use mg_edge_core::state::{
    LimitCheck, NonceIssueV2, NonceResultV2, RoundTrip1, StateHandle, parse_verdict, verdict_key,
};
use std::fmt;
use std::time::Duration;

/// `Allow` of `/__mg/s/*`.
pub const SDK_ALLOW: &str = "GET, HEAD";
/// `Allow` of `/__mg/c`.
pub const SUBMIT_ALLOW: &str = "POST";
/// `Allow` of `/__mg/v`.
pub const VERIFY_ALLOW: &str = "GET, HEAD";
/// The whole body must arrive within this (§10.3 step 3).
pub const BODY_DEADLINE: Duration = Duration::from_secs(5);
/// `Retry-After` of the unknown-client-IP and replay-store answers.
pub const RETRY_S: u32 = 5;
/// A used nonce is remembered this long after its `C` expired (§9.7).
pub const NONCE_TTL_SLACK_MS: i64 = 60_000;

/// The internal reason codes of §10.3 (`ic.c_*` come from
/// `mg_challenge::OpenError::reason_code`).
pub mod reason {
    pub const NO_CLIENT_IP: &str = "ic.no_client_ip";
    pub const TOO_EARLY: &str = "ic.too_early";
    pub const RATE_LIMITED: &str = "ic.rate_limited";
    pub const ISSUE_QUOTA: &str = "ic.issue_quota";
    pub const BODY: &str = "ic.body";
    pub const C_INVALID: &str = "ic.c_invalid";
    pub const C_KID: &str = "ic.c_kid";
    pub const C_EXPIRED: &str = "ic.c_expired";
    pub const BIND_UAH: &str = "ic.bind_uah";
    pub const BIND_IPP: &str = "ic.bind_ipp";
    pub const BIND_IPP_SOFT: &str = "ic.bind_ipp_soft";
    pub const POW: &str = "ic.pow";
    pub const RET: &str = "ic.ret";
    pub const AUTOMATION_FLAG: &str = "ic.automation_flag";
    pub const UA_MISMATCH: &str = "ic.ua_mismatch";
    pub const NONCE_REUSED: &str = "ic.nonce_reused";
    pub const REPLAY_UNAVAILABLE: &str = "ic.replay_unavailable";
    pub const REPLAY_UNCHECKED: &str = "ic.replay_unchecked";
    // Phase 2 (docs/impl/phase2-spec.md §7.4, §7.5).
    pub const INTERACTIVE_UNAVAILABLE: &str = "ic.interactive_unavailable";
    pub const PROVIDER_NOT_OFFERED: &str = "ic.provider_not_offered";
    pub const PROVIDER_UNAVAILABLE: &str = "ic.provider_unavailable";
    pub const A11Y_QUOTA: &str = "ic.a11y_quota";
    pub const TOO_FAST: &str = mg_core::providers::reason::TOO_FAST;
    pub const BIND_JKT: &str = "ic.bind_jkt";
    pub const SIG: &str = "ic.sig";
    pub const IX_MODE: &str = mg_core::providers::reason::IX_MODE;
    pub const NO_TRUSTED_INPUT: &str = mg_core::providers::reason::NO_TRUSTED_INPUT;
    pub const HOLD_SHORT: &str = mg_core::providers::reason::HOLD_SHORT;
    pub const HOLD_LONG: &str = mg_core::providers::reason::HOLD_LONG;
    pub const SCORE_HIGH: &str = mg_core::providers::reason::SCORE_HIGH;
    pub const SCORE_BLOCK: &str = mg_core::providers::reason::SCORE_BLOCK;
    pub const RENEW_CAP: &str = "ic.renew_cap";
}

/// `Retry-After` of `ic.score_block` (enforce scoring, §7.8).
pub const SCORE_BLOCK_RETRY_S: u32 = 60;

/// Whether a failure with `code` is counted in `mg.c.fail` and
/// `mg.c.fail.prefix` (§9.8, D-28; Phase 2 spec §7.5). An expired `C` (a
/// sleeping tab), a missing client IP, quotas, rate limits, `Early-Data`,
/// an unavailable replay store, `ic.interactive_unavailable`,
/// `ic.renew_cap`, the provider's own unavailability and `ic.a11y_quota`
/// are not the client's failure.
pub fn counts_as_failure(code: &str) -> bool {
    use reason::*;
    matches!(
        code,
        BODY | C_INVALID
            | C_KID
            | BIND_UAH
            | BIND_IPP
            | POW
            | RET
            | AUTOMATION_FLAG
            | UA_MISMATCH
            | NONCE_REUSED
            | PROVIDER_NOT_OFFERED
            | TOO_FAST
            | BIND_JKT
            | SIG
            | IX_MODE
            | HOLD_SHORT
            | HOLD_LONG
            | NO_TRUSTED_INPUT
            | SCORE_HIGH
    )
}

// ---------------------------------------------------------------------------
// /__mg/s/<file>

/// Whether an `If-None-Match` value (a comma-separated list of entity tags,
/// or `*`) matches `etag` by the weak comparison of RFC 9110 §13.1.2.
pub fn if_none_match(value: &str, etag: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == etag)
}

/// The answer to `method /__mg/s/<name>` (see the module documentation);
/// `path` is the raw request path (the query string is not part of it, so
/// it is ignored), `if_none_match` the request's `If-None-Match` values.
///
/// `/__mg/s/mg.js` is the stable alias of the current build (D-39, Phase 2
/// spec §11.1): the bytes of `manifest.sdk`, `Cache-Control: public,
/// max-age=300`, `ETag: "<build>"`, and 304 when `If-None-Match` matches.
pub fn sdk_file(
    sdk: &SdkDir,
    path: &str,
    method: &str,
    if_none_match_values: &[&str],
) -> EdgeResponse {
    if method != "GET" && method != "HEAD" {
        return EdgeResponse::method_not_allowed(SDK_ALLOW);
    }
    let name = path.strip_prefix(crate::routes::SDK_PREFIX).unwrap_or("");
    if name == crate::sdk::ALIAS {
        let Some(bytes) = sdk.sdk_bytes() else {
            return EdgeResponse::not_found();
        };
        let etag = sdk.etag();
        let fresh = if_none_match_values.iter().any(|v| if_none_match(v, &etag));
        let mut r = if fresh {
            EdgeResponse::new(304, JAVASCRIPT, Bytes::new())
        } else {
            EdgeResponse::new(200, JAVASCRIPT, bytes.clone())
        };
        r.cache_control = crate::sdk::ALIAS_CACHE_CONTROL;
        r.close = false;
        return r.with("ETag", etag);
    }
    match sdk
        .files
        .get(name)
        .filter(|_| crate::sdk::is_file_name(name))
    {
        Some(bytes) => {
            let mut r = EdgeResponse::new(200, JAVASCRIPT, bytes.clone());
            r.cache_control = IMMUTABLE;
            r.close = false;
            r
        }
        None => EdgeResponse::not_found(),
    }
}

// ---------------------------------------------------------------------------
// /__mg/v

/// The return path of `/__mg/v?<query>` (see the module documentation):
/// the decoded `ret` parameter when it is a valid return path, otherwise
/// `fallback`.
pub fn verify_ret(query: &str, fallback: &str) -> String {
    let mut values = query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("ret="));
    let (Some(value), None) = (values.next(), values.next()) else {
        return fallback.to_owned();
    };
    percent_decode(value)
        .filter(|ret| ret.bytes().all(|b| matches!(b, 0x21..=0x7e)) && validate_ret(ret).is_ok())
        .unwrap_or_else(|| fallback.to_owned())
}

/// The `min` parameter of `/__mg/v?<query>` (Phase 2 spec §7.10, D-58):
/// `interactive` when exactly one `min` parameter says so; anything else
/// (absent, repeated, another value) is ignored.
pub fn verify_min(query: &str) -> Option<ChallengeType> {
    let mut values = query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("min="));
    match (values.next(), values.next()) {
        (Some("interactive"), None) => Some(ChallengeType::Interactive),
        _ => None,
    }
}

/// `%XX` decoding of an ASCII string; `None` for a malformed escape or a
/// result that is not ASCII.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out.is_ascii()
        .then(|| String::from_utf8(out).ok())
        .flatten()
}

// ---------------------------------------------------------------------------
// Body reading

/// Why the request body could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyReadError;

/// Where [`submit`] reads the request body from: the Pingora session in
/// production ([`crate::proxy`]), a fake in tests.
#[async_trait]
pub trait BodySource: Send {
    /// The next chunk; `Ok(None)` at the end of the body.
    async fn chunk(&mut self) -> Result<Option<Bytes>, BodyReadError>;
}

/// How reading the body ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRead {
    /// The whole body, at most `max` bytes.
    Complete(Vec<u8>),
    /// More than `max` bytes; reading stopped there.
    TooLarge,
    /// Not complete within the deadline.
    Timeout,
    /// The connection failed.
    Error,
}

/// Reads the body, stopping as soon as more than `max` bytes arrived or
/// `deadline` passed (§10.3 step 3: at most 8193 bytes, 5 s).
pub async fn read_body(src: &mut dyn BodySource, max: usize, deadline: Duration) -> BodyRead {
    let read = async {
        let mut buf = Vec::new();
        loop {
            match src.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len() + chunk.len() > max {
                        return BodyRead::TooLarge;
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => return BodyRead::Complete(buf),
                Err(BodyReadError) => return BodyRead::Error,
            }
        }
    };
    tokio::time::timeout(deadline, read)
        .await
        .unwrap_or(BodyRead::Timeout)
}

// ---------------------------------------------------------------------------
// The submission record (WP-E1d turns it into events)

/// `kind=telemetry` material of a parsed submission (§13.5). `Debug` shows
/// presence only (the summary holds the browser's User-Agent).
#[derive(Clone, PartialEq)]
pub struct Telemetry {
    pub build: String,
    pub solve_ms: Option<u32>,
    pub env: Option<EnvSummary>,
    pub auto: Option<AutomationSummary>,
    /// `t.ix` of a v2 submission (§7.6).
    pub ix: Option<IxTelemetry>,
}

impl fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Telemetry")
            .field("build", &self.build)
            .field("solve_ms", &self.solve_ms)
            .field("env", &self.env.is_some())
            .field("auto", &self.auto)
            .field("ix", &self.ix.is_some())
            .finish()
    }
}

/// What one `POST /__mg/c` did: the `kind=feedback` body, the metric result
/// and the telemetry of the submission. Nothing in it identifies the client
/// beyond `cf_ray` (never `C`, the token, the IP or `ret`).
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitRecord {
    /// `mg_core::ChallengeResult` (§13.3): outcome, `lvl`, `solve_ms`,
    /// `risk_band`, `reason_codes`, `route_id` (the `C`'s route), `cf_ray`.
    pub feedback: ChallengeResult,
    /// `result` of `mg_challenge_total`: `solved`, `failed` or `expired`.
    pub result: &'static str,
    /// Present once the body parsed.
    pub telemetry: Option<Telemetry>,
    /// The band and difficulty of the new `C` attached to a failure.
    pub reissued: Option<(RiskBand, u32)>,
    /// The `provider` label of `mg_challenge_total`: `none`, or the
    /// submitted provider of an interactive `C`.
    pub provider: &'static str,
}

impl SubmitRecord {
    fn new(request_id: &str, site_id: &str, cf_ray: Option<String>) -> Self {
        Self {
            feedback: ChallengeResult {
                request_id: request_id.to_owned(),
                site_id: site_id.to_owned(),
                challenge_type: ChallengeType::Unspecified,
                outcome: Some(VerdictOutcome::Fail),
                attempt_no: 0,
                cf_ray,
                ..ChallengeResult::default()
            },
            result: "failed",
            telemetry: None,
            reissued: None,
            provider: challenge::PROVIDER_NONE,
        }
    }

    /// The reason codes, comma-separated (debug log).
    pub fn reasons(&self) -> String {
        if self.feedback.reason_codes.is_empty() {
            "-".into()
        } else {
            self.feedback.reason_codes.join(",")
        }
    }
}

/// The answer and the record of one submission.
#[derive(Debug)]
pub struct Submitted {
    pub response: EdgeResponse,
    pub record: SubmitRecord,
}

// ---------------------------------------------------------------------------
// The flow

/// Everything [`submit`] reads about the request and the site.
#[derive(Clone, Copy)]
pub struct Submit<'a> {
    pub request_id: &'a str,
    /// Unix ms when the request arrived. Steps 4-10 (opening `C`, the replay
    /// TTL, the token times) use this plus the time [`submit`] has taken so
    /// far, i.e. the clock once the body has arrived (up to
    /// [`BODY_DEADLINE`] later).
    pub now_ms: i64,
    pub site_id: &'a str,
    pub sealer: &'a Sealer,
    pub sdk: &'a SdkDir,
    pub bundle: &'a BundleRuntime,
    /// The environment of the request host.
    pub env: &'a EnvRuntime,
    /// §9.4-normalized (the `aad` covers it, I-18).
    pub host: &'a str,
    /// The request as the Decision Core would see it (`crate::context::build`):
    /// `req.headers`, cookies, the parsed User-Agent, `net` (IP, ASN),
    /// `edge_tls`, `http.early_data`, `upstream.cf_ray`.
    pub built: &'a Built,
    /// The request's bindings (`crate::identity::bind_inputs`).
    pub bind: &'a BindInputs,
    /// The client sent a `Content-Encoding` field (`crate::context::received`
    /// on the raw headers: a `Connection` option naming it does not hide it
    /// from step 3).
    pub content_encoding: bool,
}

impl fmt::Debug for Submit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Submit")
            .field("request_id", &self.request_id)
            .field("site_id", &self.site_id)
            .field("env", &self.env.name)
            .field("host", &self.host)
            .field("bind", self.bind)
            .finish_non_exhaustive()
    }
}

/// How answers are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Form navigation: HTML.
    Page,
    /// fetch: JSON.
    Json,
}

/// Why the flow stopped (the step that decided).
enum Stop {
    /// 429 with `Retry-After`.
    Limited {
        code: &'static str,
        retry_after_s: u32,
    },
    /// 425.
    TooEarly,
    /// The uniform failure; `reissue` from step 5 on.
    Failed { code: &'static str, reissue: bool },
    /// 503 (the RNG failed, or a token could not be minted).
    Unavailable,
}

/// `Retry-After` (whole seconds, at least 1) of the exceeded outcomes.
fn retry_after_s<'o>(outcomes: impl IntoIterator<Item = &'o GcraOutcome>) -> u32 {
    let us = outcomes
        .into_iter()
        .filter(|o| !o.allowed)
        .map(|o| o.retry_after_us)
        .max()
        .unwrap_or(0);
    u32::try_from(us.div_ceil(1_000_000))
        .unwrap_or(u32::MAX)
        .max(1)
}

/// The outcomes of `checks` from a state reply; a reply of the wrong length
/// (a state-layer bug) counts every check as exceeded, never as allowed.
fn outcomes_for(checks: &[LimitCheck], got: Vec<GcraOutcome>) -> Vec<GcraOutcome> {
    if got.len() == checks.len() {
        return got;
    }
    log::error!(
        "state returned {} outcomes for {} challenge limiters",
        got.len(),
        checks.len()
    );
    checks
        .iter()
        .map(|c| GcraOutcome {
            allowed: false,
            retry_after_us: c.params.dvt_us(),
            tat_minus_now_us: c.params.dvt_us(),
            new_tat_us: None,
        })
        .collect()
}

/// Counts `mg_ratelimit_exceeded_total{limiter}` for the exceeded built-in
/// limiters (§9.8).
fn count_exceeded(checks: &[LimitCheck], outcomes: &[GcraOutcome]) {
    for (c, o) in checks.iter().zip(outcomes) {
        if !o.allowed {
            metrics()
                .ratelimit_exceeded
                .with_label_values(&[c.key.limiter.as_str()])
                .inc();
        }
    }
}

/// The `fail_closed` of the route a `C` belongs to (§9.7 rule 5): the route
/// of `env` named `route_class`, OR the route a GET of `ret`'s path
/// selects; a `route_class` that is no longer in `env` is `fail_closed`.
pub fn replay_fail_closed(
    bundle: &BundleRuntime,
    env: &EnvRuntime,
    host: &str,
    route_class: &str,
    ret: &str,
) -> bool {
    let Some(named) = env.routes.iter().find(|r| r.name == route_class) else {
        return true;
    };
    let path = ret.split('?').next().unwrap_or(ret);
    let fallback = RouteRuntime::fallback();
    let by_ret = select_route(
        env,
        host,
        "GET",
        path,
        bundle.case_insensitive_paths,
        &fallback,
    );
    named.fail_closed || by_ret.fail_closed
}

/// The return path of the new `C` attached to a failure: the submitted
/// `ret` when it is valid and is the one sealed in the failed `C` (so the
/// new `C` returns where the old one did, D-27); otherwise (the client
/// changed `ret`, which is itself the failure `ic.ret`) the bundle's
/// `fallback_ret`, since the original return path is only known as a hash.
pub fn new_challenge_ret<'a>(
    sealed_ret_hash: &[u8],
    submitted: &'a str,
    fallback: &'a str,
) -> &'a str {
    if validate_ret(submitted).is_ok() && ret_hash(submitted).as_slice() == sealed_ret_hash {
        submitted
    } else {
        fallback
    }
}

/// The clearance the request carries, for the session carry-over of §6.5
/// (Phase 2 spec §6.8): the first `__Host-mg_clr` candidate that verifies
/// for this site and environment, expiry ignored.
fn previous_clearance(s: &Submit<'_>, now_s: i64) -> Option<ClearanceClaims> {
    let cookies: Vec<&str> = s.built.cookies.iter().map(String::as_str).collect();
    clearance_cookies(&cookies).into_iter().find_map(|token| {
        verify_ignoring_expiry(&s.bundle.token_keys, s.site_id, &s.env.name, token, now_s).ok()
    })
}

/// The `(sub, sst)` a new token carries over (§6.5; Phase 2 spec §6.8): not
/// bound to another browser or prefix, at most `session_max_s` old; in a
/// schema 2 bundle also with the same session key (or none before) and no
/// active near-line session verdict (`flagged`).
fn reused_session(
    s: &Submit<'_>,
    prev: Option<&ClearanceClaims>,
    now_s: i64,
    jkt: Option<&str>,
    flagged: bool,
) -> Option<(String, i64)> {
    let prev = prev?;
    let check = check_clearance_bind(prev, s.bind);
    let max = s.bundle.clearance.session_max_s;
    if !s.bundle.phase2() {
        return reusable_session(prev, &check, now_s, max);
    }
    if flagged {
        return None;
    }
    reusable_session_v2(prev, &check, now_s, max, jkt)
}

/// A mutable run of the flow over one submission.
struct Flow<'a, 's> {
    s: &'a Submit<'s>,
    state: &'a StateHandle,
    rng: &'a dyn Rng,
    answer: Answer,
    record: SubmitRecord,
    /// Dimensions of the built-in limiters (known once step 0 passed).
    entity: String,
    prefix: String,
    /// The parsed submission (step 3 on).
    sub: Option<Submission>,
    /// The opened claims (step 4 on).
    claims: Option<SealedChallengeClaims>,
    /// The whole body was read (keep-alive is safe).
    body_done: bool,
    /// When [`submit`] started (monotonic: the wall clock is read once, by
    /// the caller).
    started: std::time::Instant,
    /// Unix ms that steps 4-15 judge by: `Submit::now_ms` advanced to the
    /// end of the body read (see [`Flow::clock`]).
    now_ms: i64,
    /// The thumbprint of the submission's session key once its signature
    /// verified (step 8): bound into the token and into a new `C`.
    jkt: Option<String>,
    /// `mg.a11y.issue` is over its limit (round trip 1, §7.9).
    a11y_exceeded: bool,
    /// The new `C` attached to this failure shows `ix.a11y_quota`.
    a11y_quota_reissue: bool,
    /// The clearance the request carries (session carry-over).
    previous: Option<ClearanceClaims>,
    /// Its `sub` has an active near-line session verdict (§6.8).
    session_flagged: bool,
}

impl<'s> Flow<'_, 's> {
    /// `Submit::now_ms` plus the time the flow has taken (round trip 1 and
    /// the body read): a `C` that expired while its body was trickling in is
    /// `ic.c_expired`, and the token starts when it is minted.
    fn clock(&self) -> i64 {
        let elapsed = i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX);
        self.s.now_ms.saturating_add(elapsed)
    }

    fn dims(&self) -> ClientDims<'_> {
        ClientDims {
            ip_entity: Some(&self.entity),
            ip_prefix: Some(&self.prefix),
            asn: self.s.built.ctx.net.asn,
            asn_available: self.s.bundle.intel.has_asn(),
        }
    }

    /// Steps 0-15; `Ok(response)` on success.
    async fn run(&mut self, body: &mut dyn BodySource) -> Result<EdgeResponse, Stop> {
        let s = self.s;
        let site = s.site_id;
        let bundle = s.bundle;
        let limits = &bundle.challenge_limits;

        // 0. Client IP (D-23): never a C or a token without one.
        let Some(ip) = s.built.ctx.net.ip else {
            return Err(Stop::Limited {
                code: reason::NO_CLIENT_IP,
                retry_after_s: RETRY_S,
            });
        };
        self.entity = Net::entity_of(ip);
        self.prefix = Net::prefix_of(ip);

        // 1. 0-RTT data: no token, no nonce (§9.9).
        if s.built.ctx.http.early_data {
            return Err(Stop::TooEarly);
        }

        // 2 / 2b. Round trip 1: the challenge limiters, in schema 2 also
        //    both tiers of mg.a11y.issue (check only, whatever `p` turns out
        //    to be) and the session verdict of the carried clearance (§6.8).
        self.previous = previous_clearance(s, s.now_ms.div_euclid(1000));
        let mut checks = limits.submit_round_trip(site, &self.dims());
        let base = checks.len();
        if let Some(ix) = &bundle.interactive {
            checks.extend(interactive::a11y_checks(site, ix, &self.dims(), false));
        }
        let verdict_keys: Vec<String> = match (&self.previous, bundle.phase2()) {
            (Some(prev), true) => vec![verdict_key(site, "session", &prev.sub)],
            _ => Vec::new(),
        };
        let rt1 = self
            .state
            .round_trip1(RoundTrip1 {
                verdict_keys,
                limits: checks.clone(),
            })
            .await;
        let now_for_verdicts = self.clock();
        self.session_flagged = rt1
            .verdicts
            .iter()
            .flatten()
            .filter_map(|raw| parse_verdict(raw))
            .any(|v| v.is_active(now_for_verdicts));
        let outcomes = outcomes_for(&checks, rt1.limits);
        count_exceeded(&checks, &outcomes);
        // submit_round_trip order: submit, fail, fail.prefix, issue.ipp[, issue.asn].
        if outcomes.iter().take(3).any(|o| !o.allowed) {
            return Err(Stop::Limited {
                code: reason::RATE_LIMITED,
                retry_after_s: retry_after_s(outcomes.iter().take(3)),
            });
        }
        if outcomes.iter().take(base).skip(3).any(|o| !o.allowed) {
            return Err(Stop::Limited {
                code: reason::ISSUE_QUOTA,
                retry_after_s: retry_after_s(outcomes.iter().take(base).skip(3)),
            });
        }
        self.a11y_exceeded = outcomes.iter().skip(base).any(|o| !o.allowed);

        // 3. The body.
        let body_fail = || {
            Err(Stop::Failed {
                code: reason::BODY,
                reissue: false,
            })
        };
        let headers = &s.built.headers;
        if s.content_encoding || context::header(headers, "content-encoding").is_some() {
            return body_fail();
        }
        if let Some(len) = context::header(headers, "content-length") {
            match len.trim().parse::<u64>() {
                Ok(n) if n <= MAX_BODY as u64 => {}
                _ => return body_fail(),
            }
        }
        let kind = match context::header(headers, "content-type").map(media_kind) {
            Some(Ok(kind)) => kind,
            _ => return body_fail(),
        };
        let bytes = match read_body(body, MAX_BODY, BODY_DEADLINE).await {
            BodyRead::Complete(b) => {
                self.body_done = true;
                b
            }
            BodyRead::TooLarge | BodyRead::Timeout | BodyRead::Error => return body_fail(),
        };
        let text = match kind {
            MediaKind::Form => submission::decode_form(&bytes),
            MediaKind::Json => String::from_utf8(bytes).map_err(|_| submission::BodyError::Utf8),
        };
        let Ok(parsed) = text.and_then(|t| submission::parse_submission(&t)) else {
            return body_fail();
        };
        self.record.feedback.challenge_type = parsed.ty;
        self.record.telemetry = Some(Telemetry {
            build: parsed.build.clone(),
            solve_ms: None,
            env: parsed.env.as_ref().map(EnvSummary::for_telemetry),
            auto: parsed.auto,
            ix: parsed.v2.as_ref().and_then(|v| v.ix.clone()),
        });
        self.sub = Some(parsed);
        self.now_ms = self.clock();
        let now_ms = self.now_ms;
        let Some(sub) = &self.sub else {
            return Err(Stop::Unavailable);
        };

        // 4. Open C (the aad covers the normalized host and the submitted type).
        let opened = s
            .sealer
            .open(&sub.c, s.host, sub.ty, now_ms)
            .map_err(|e| Stop::Failed {
                code: e.reason_code(),
                reissue: false,
            })?;
        let solve_ms = u32::try_from(now_ms.saturating_sub(opened.iat_ms).max(0)).ok();
        let fb = &mut self.record.feedback;
        fb.route_id = Some(opened.route_class.clone());
        fb.risk_band = Some(opened.risk_band);
        fb.solve_ms = solve_ms;
        fb.attempt_no = opened.attempt_no;
        fb.renew_no = opened.renew_no;
        fb.bound = opened.bind.jkt.is_some();
        if let Some(t) = &mut self.record.telemetry {
            t.solve_ms = solve_ms;
        }
        self.claims = Some(opened);
        let Some(claims) = &self.claims else {
            return Err(Stop::Unavailable);
        };
        let fail = |code| {
            Err(Stop::Failed {
                code,
                reissue: true,
            })
        };
        let interactive = claims.challenge_type == ChallengeType::Interactive;

        // 4a. An interactive C while interactive challenges are unavailable
        //     (§5.1): a pow C, nothing of InteractiveConfig is read.
        if interactive && !bundle.interactive_available {
            return fail(reason::INTERACTIVE_UNAVAILABLE);
        }
        let ix_cfg = if interactive {
            match &bundle.interactive {
                Some(cfg) => Some(cfg),
                None => return fail(reason::INTERACTIVE_UNAVAILABLE),
            }
        } else {
            None
        };
        let v2 = sub.v2.as_ref();

        // 5. The provider (interactive).
        let mut provider = None;
        if let (Some(cfg), Some(v2)) = (ix_cfg, v2) {
            let p =
                v2.p.parse::<ProviderId>()
                    .ok()
                    .filter(|p| claims.providers.contains(p));
            let Some(p) = p else {
                return fail(reason::PROVIDER_NOT_OFFERED);
            };
            self.record.provider = p.as_str();
            match p {
                ProviderId::SelfHold => {}
                ProviderId::PowA11y => {
                    if self.a11y_exceeded {
                        self.a11y_quota_reissue = true;
                        return fail(reason::A11Y_QUOTA);
                    }
                }
                // External providers are verified by WP-E2c; until then a
                // C never offers one, and nothing is counted against the
                // visitor.
                _ => return fail(reason::PROVIDER_UNAVAILABLE),
            }
            provider = Some((p, cfg));
        }

        // 6. The server-side time window (§7.7).
        let ui = ui_params(claims.ui_seed);
        let elapsed_ms =
            u32::try_from(now_ms.saturating_sub(claims.iat_ms).max(0)).unwrap_or(u32::MAX);
        if let (Some((_, cfg)), Some(v2)) = (provider, v2) {
            let mode = v2.ix.as_ref().map_or(IxMode::PowOnly, |t| t.mode);
            let min = min_elapsed_ms(mode, ui.required_hold_ms, cfg.min_pow_ms, cfg.a11y_min_ms);
            if elapsed_ms < min {
                return fail(reason::TOO_FAST);
            }
        }

        // 7. Bindings; a C bound to a session key needs a v2 submission
        //    signed with that key (D-41).
        let check = check_challenge_bind(&claims.bind, s.bind);
        if check.uah != BindResult::Match {
            return fail(reason::BIND_UAH);
        }
        match check.ipp {
            BindResult::Match => {}
            BindResult::SoftMismatch => self
                .record
                .feedback
                .reason_codes
                .push(reason::BIND_IPP_SOFT.to_owned()),
            _ => return fail(reason::BIND_IPP),
        }
        let key = match v2 {
            None => {
                if claims.bind.jkt.is_some() {
                    return fail(reason::BIND_JKT);
                }
                None
            }
            Some(v2) => {
                // I-45: a jwk that is not the §6.5 shape is ic.sig.
                let Some(key) = submission::session_key(&v2.jwk) else {
                    return fail(reason::SIG);
                };
                if claims.bind.jkt.is_some() && !interactive::jkt_matches(claims, key.thumbprint())
                {
                    return fail(reason::BIND_JKT);
                }
                Some(key)
            }
        };

        // 8. v2: the submission signature (§6.6).
        if let Some(key) = &key {
            if !submission::submission_signature_ok(sub, key) {
                return fail(reason::SIG);
            }
            self.jkt = Some(key.thumbprint().to_owned());
        }

        // 9. PoW on C exactly as received (I-18): v1 or v2 by the sealed
        //    algorithm; v2 at the difficulty of the submitted provider.
        let pow = claims.pow.clone().unwrap_or_default();
        let solved = if pow.alg == POW_ALG_V2 {
            let difficulty = match provider {
                Some((ProviderId::PowA11y, _)) => pow.a11y_difficulty,
                _ => pow.difficulty,
            };
            usize::try_from(pow.k).is_ok_and(|k| k == sub.counters.len())
                && pow_verify_v2(&sub.c, difficulty, &sub.counters)
        } else {
            sub.counters.len() == 1 && pow_verify(&sub.c, pow.difficulty, sub.counter())
        };
        if !solved {
            return fail(reason::POW);
        }

        // 10. Return path.
        if validate_ret(&sub.ret).is_err() || ret_hash(&sub.ret).as_slice() != claims.ret_hash {
            return fail(reason::RET);
        }

        // 11. Basic environment, then (interactive) the hard checks of §7.7.
        if sub.auto.is_some_and(|a| a.webdriver == Some(true)) {
            return fail(reason::AUTOMATION_FLAG);
        }
        let request_ua = context::header(headers, "user-agent").unwrap_or("");
        if let Some(ua) = sub.env.as_ref().and_then(EnvSummary::user_agent)
            && !ua.is_empty()
            && !request_ua.starts_with(ua)
        {
            return fail(reason::UA_MISMATCH);
        }
        let assessment = match (provider, v2) {
            (Some((p, cfg)), Some(v2)) => {
                let input = InteractionInput {
                    provider: p,
                    telemetry: v2.ix.as_ref(),
                    required_hold_ms: ui.required_hold_ms,
                    elapsed_ms,
                    pow_bits: if p == ProviderId::PowA11y {
                        pow.a11y_difficulty
                    } else {
                        pow.difficulty
                    },
                    pow_k: pow.k,
                    risk_band: claims.risk_band,
                    mode: cfg.scoring,
                };
                let a = assess_interaction(&input);
                self.record.feedback.ix = Some(a.summary(&input));
                if let Some(code) = a.hard_failure {
                    return fail(code);
                }
                Some((a, cfg))
            }
            _ => None,
        };

        // 12. Round trip 2: the nonce and the issuance quotas (D-37), with
        //     mg.a11y.issue for pow_a11y (§7.9).
        let mut quota_checks = limits.issuance(site, &self.dims());
        if let Some((ProviderId::PowA11y, cfg)) = provider {
            quota_checks.extend(interactive::a11y_checks(site, cfg, &self.dims(), true));
        }
        // An interactive C's nonce outlives its renewal window
        // (crate::renew::interactive_nonce_ttl_ms).
        let ttl_ms = if interactive {
            crate::renew::interactive_nonce_ttl_ms(claims, now_ms)
        } else {
            let ttl = claims
                .exp_ms
                .saturating_sub(now_ms)
                .saturating_add(NONCE_TTL_SLACK_MS)
                .max(1);
            u64::try_from(ttl).unwrap_or(1)
        };
        let nonce = self
            .state
            .nonce_issue_v2(
                NonceIssueV2 {
                    site: site.to_owned(),
                    nonce: claims.nonce,
                    ttl_ms,
                    replay: None,
                    limits: quota_checks.clone(),
                },
                now_ms,
                claims.iat_ms,
            )
            .await;
        let mut replay_unchecked = false;
        let quotas = match nonce {
            NonceResultV2::Reused | NonceResultV2::TokenReused => {
                return fail(reason::NONCE_REUSED);
            }
            NonceResultV2::Fresh { limits } => limits,
            NonceResultV2::Unavailable { limits } => {
                if replay_fail_closed(bundle, s.env, s.host, &claims.route_class, &sub.ret) {
                    return Err(Stop::Limited {
                        code: reason::REPLAY_UNAVAILABLE,
                        retry_after_s: RETRY_S,
                    });
                }
                self.record
                    .feedback
                    .reason_codes
                    .push(reason::REPLAY_UNCHECKED.to_owned());
                replay_unchecked = true;
                limits
            }
        };
        let quotas = outcomes_for(&quota_checks, quotas);
        count_exceeded(&quota_checks, &quotas);
        if quotas.iter().any(|o| !o.allowed) {
            return Err(Stop::Limited {
                code: reason::ISSUE_QUOTA,
                retry_after_s: retry_after_s(&quotas),
            });
        }

        // 13. (Turnstile's siteverify: WP-E2c.)
        // 14. The score (§7.8): only `enforce` decides with it.
        if let Some((a, cfg)) = &assessment {
            metrics()
                .interactive_score
                .with_label_values(&[self.record.provider, cfg.scoring.eval_mode().as_str()])
                .observe(f64::from(a.score));
            match a.outcome {
                IxOutcome::Pass => {}
                IxOutcome::Retry => return fail(reason::SCORE_HIGH),
                IxOutcome::Block => {
                    return Err(Stop::Limited {
                        code: reason::SCORE_BLOCK,
                        retry_after_s: SCORE_BLOCK_RETRY_S,
                    });
                }
            }
        }

        // 15. The clearance: the level by provider, v2 with `cnf.jkt` and
        //     `lat` in schema 2 (D-46, D-66), the status cookie, and the
        //     accessibility preference (§9.5).
        let lvl = match (claims.challenge_type, provider) {
            (ChallengeType::Invisible, _) => TokenLevel::Invisible,
            (ChallengeType::Interactive, Some((ProviderId::PowA11y, _))) => {
                TokenLevel::InteractiveA11y
            }
            (ChallengeType::Interactive, _) => TokenLevel::Interactive,
            _ => TokenLevel::Pow,
        };
        let ttl_s = bundle.ttl_for(&lvl);
        let Some(bind) = ClearanceBind::from_inputs(s.bind) else {
            // Unreachable: the client IP is known (step 0).
            return Err(Stop::Unavailable);
        };
        let now_s = now_ms.div_euclid(1000);
        let session = reused_session(
            s,
            self.previous.as_ref(),
            now_s,
            self.jkt.as_deref(),
            self.session_flagged,
        );
        let minted = mint_v2(
            &bundle.token_keys,
            site,
            &MintV2Params {
                base: MintParams {
                    env: &s.env.name,
                    session: session.as_ref().map(|(sub, sst)| (sub.as_str(), *sst)),
                    lvl,
                    now_s,
                    ttl_s,
                    bind,
                    rb: claims.risk_band,
                    replay_unchecked,
                },
                cnf_jkt: self.jkt.as_deref(),
                lat: None,
                allow_v2: bundle.phase2(),
            },
            self.rng,
        );
        let (token, minted) = match minted {
            Ok(t) => t,
            Err(e) => {
                if e == TokenError::Rng {
                    log::error!(
                        "request_id={} clearance: the OS random number generator failed",
                        s.request_id
                    );
                } else {
                    log::error!("request_id={} clearance not minted: {e}", s.request_id);
                }
                return Err(Stop::Unavailable);
            }
        };
        self.record.feedback.outcome = Some(VerdictOutcome::Pass);
        self.record.feedback.lvl = Some(lvl);
        self.record.result = "solved";
        let cookie = set_cookie_value(&token, ttl_s);
        let mut resp = match self.answer {
            Answer::Page => pages::submit_redirect(&sub.ret, cookie),
            Answer::Json => pages::submit_ok_json(&sub.ret, cookie, now_ms),
        };
        if bundle.phase2() {
            resp = resp.with("Set-Cookie", status_set_cookie_value(&minted, ttl_s));
        }
        match provider {
            Some((ProviderId::PowA11y, _)) => {
                resp = resp.with("Set-Cookie", interactive::a11y_set_cookie());
            }
            Some((ProviderId::SelfHold, _)) if interactive::has_a11y_cookie(&s.built.cookies) => {
                resp = resp.with("Set-Cookie", interactive::a11y_delete_cookie());
            }
            _ => {}
        }
        resp.close = !self.body_done;
        Ok(resp)
    }

    /// The new `C` of a failure from step 4a on (§5.3, D-50; Phase 1: D-27,
    /// I-10): type, band and attempt by `next_challenge_after_failure`; an
    /// interactive one with a new `ui_seed` and the providers selected
    /// again, bound to the submission's key once its signature verified.
    fn reissue(&self) -> Result<Issued, Stop> {
        let (Some(claims), Some(sub)) = (&self.claims, &self.sub) else {
            return Err(Stop::Unavailable);
        };
        let s = self.s;
        let bundle = s.bundle;
        let cfg = &bundle.challenge;
        let (ty, band, attempt_no) = next_challenge_after_failure(
            claims.challenge_type,
            claims.risk_band,
            claims.attempt_no,
            bundle.interactive_available,
        );
        let ret = new_challenge_ret(&claims.ret_hash, &sub.ret, fallback_ret(cfg));
        let unavailable = |e: IssueError| {
            log::error!(
                "request_id={} new challenge after a failure not issued: {e:?}",
                s.request_id
            );
            Stop::Unavailable
        };
        let issued = match (ty, &bundle.interactive) {
            (ChallengeType::Interactive, Some(ix)) => {
                let ip = s.built.ctx.net.ip.ok_or(Stop::Unavailable)?;
                let now_us = u64::try_from(self.now_ms).unwrap_or(0).saturating_mul(1000);
                if let Gate::Limited { retry_after_s } =
                    interactive::issue_gate(self.state, s.site_id, ix, ip, now_us)
                {
                    return Err(Stop::Limited {
                        code: reason::RATE_LIMITED,
                        retry_after_s,
                    });
                }
                challenge::issue_interactive(
                    &interactive::Seal {
                        sealer: s.sealer,
                        host: s.host,
                        route_class: &claims.route_class,
                        band,
                        attempt_no,
                        renew_no: 0,
                        providers: interactive::providers(
                            ix,
                            s.host,
                            &claims.route_class,
                            attempt_no,
                            interactive::a11y_pref(&s.built.cookies),
                        ),
                        ui_seed: None,
                        pow: interactive::pow_params(ix, band),
                        ret_hash: ret_hash(ret),
                        bind: s.bind,
                        jkt: self.jkt.as_deref(),
                        now_ms: self.now_ms,
                    },
                    ix,
                    ret,
                    self.a11y_quota_reissue,
                    self.rng,
                )
                .map_err(unavailable)?
            }
            _ => {
                let ty = if ty == ChallengeType::Invisible {
                    ty
                } else {
                    ChallengeType::Pow
                };
                challenge::issue(
                    &IssueRequest {
                        sealer: s.sealer,
                        host: s.host,
                        route_class: &claims.route_class,
                        ty,
                        band,
                        bits: challenge::difficulty(&pow_bits(cfg), ty, band),
                        ttl_s: cfg.ttl_s,
                        ret,
                        bind: s.bind,
                        jkt: self.jkt.as_deref(),
                        now_ms: self.now_ms,
                    },
                    self.rng,
                )
                .map_err(unavailable)?
            }
        };
        challenge::count_issued(&issued, "reissued");
        Ok(issued)
    }

    /// The return path shown on a failed page without a new `C`: the
    /// submitted `ret` when valid (the client goes back there to be
    /// challenged again), otherwise `fallback_ret`.
    fn failed_page_ret(&self) -> String {
        self.sub
            .as_ref()
            .map(|sub| sub.ret.as_str())
            .filter(|r| validate_ret(r).is_ok())
            .unwrap_or_else(|| fallback_ret(&self.s.bundle.challenge))
            .to_owned()
    }

    /// Turns a stop into the answer and completes the record.
    fn stopped(&mut self, stop: Stop) -> EdgeResponse {
        let s = self.s;
        let navigation = self.answer == Answer::Page;
        // The deciding code first, then notes such as ic.bind_ipp_soft
        // recorded on the way; kept even when the answer becomes a 503 below
        // (a counted failure stays a failure in the feedback event).
        let code = match &stop {
            Stop::Unavailable => None,
            Stop::TooEarly => Some(reason::TOO_EARLY),
            Stop::Limited { code, .. } | Stop::Failed { code, .. } => Some(*code),
        };
        self.record.result = if code == Some(reason::C_EXPIRED) {
            "expired"
        } else {
            "failed"
        };
        if let Some(code) = code {
            self.record.feedback.reason_codes.insert(0, code.to_owned());
        }
        let mut resp = match stop {
            Stop::Unavailable => return EdgeResponse::internal_unavailable(),
            Stop::TooEarly => pages::too_early_json(),
            Stop::Limited { retry_after_s, .. } => {
                EdgeResponse::rate_limited(s.request_id, retry_after_s, navigation)
            }
            Stop::Failed { code, reissue } => {
                if counts_as_failure(code) {
                    let failures = s.bundle.challenge_limits.failures(s.site_id, &self.dims());
                    // A full queue drops the count (mg_state_async_dropped_total).
                    let _ = self.state.record_failure(failures);
                }
                // The page's CSP nonce before the new C: when the RNG fails,
                // no C is issued (and counted) that the answer cannot carry.
                let nonce = match self.answer {
                    Answer::Json => None,
                    Answer::Page => match pages::csp_nonce(self.rng) {
                        Ok(nonce) => Some(nonce),
                        Err(_) => {
                            log::error!(
                                "request_id={} challenge page: the OS random number generator failed",
                                s.request_id
                            );
                            return EdgeResponse::internal_unavailable();
                        }
                    },
                };
                let new = if reissue {
                    match self.reissue() {
                        Ok(new) => Some(new),
                        Err(Stop::Limited { retry_after_s, .. }) => {
                            let mut r =
                                EdgeResponse::rate_limited(s.request_id, retry_after_s, navigation);
                            r.close = !self.body_done;
                            return r;
                        }
                        // The RNG failed (logged): 503, the record as above.
                        Err(_) => return EdgeResponse::internal_unavailable(),
                    }
                } else {
                    None
                };
                self.record.reissued = new.as_ref().map(|n| (n.band, n.bits));
                match nonce {
                    None => pages::failed_json(s.request_id, new.as_ref().map(Issued::shown)),
                    Some(nonce) => {
                        let ret = new
                            .as_ref()
                            .map_or_else(|| self.failed_page_ret(), |n| n.ret.clone());
                        pages::challenge_page(
                            s.sdk,
                            &Page {
                                lang: pages::page_lang(
                                    context::header(&s.built.headers, "accept-language"),
                                    s.bundle.default_lang,
                                ),
                                nonce: &nonce,
                                request_id: s.request_id,
                                ret: &ret,
                                state: PageState::Failed,
                                challenge: new.as_ref().map(Issued::shown),
                                help_href: &s.bundle.help_path,
                                privacy_href: &s.bundle.privacy_path,
                            },
                        )
                    }
                }
            }
        };
        resp.close = !self.body_done;
        resp
    }
}

/// Runs `POST /__mg/c` for an active site (see the module documentation)
/// and counts `mg_challenge_total`.
pub async fn submit(
    state: &StateHandle,
    rng: &dyn Rng,
    s: &Submit<'_>,
    body: &mut dyn BodySource,
) -> Submitted {
    let headers = &s.built.headers;
    let answer = match context::header(headers, "content-type").map(media_kind) {
        Some(Ok(MediaKind::Form)) => Answer::Page,
        Some(Ok(MediaKind::Json)) => Answer::Json,
        _ if is_navigation(headers) => Answer::Page,
        _ => Answer::Json,
    };
    let mut flow = Flow {
        s,
        state,
        rng,
        answer,
        record: SubmitRecord::new(s.request_id, s.site_id, s.built.ctx.upstream.cf_ray.clone()),
        entity: String::new(),
        prefix: String::new(),
        sub: None,
        claims: None,
        body_done: false,
        started: std::time::Instant::now(),
        now_ms: s.now_ms,
        jkt: None,
        a11y_exceeded: false,
        a11y_quota_reissue: false,
        previous: None,
        session_flagged: false,
    };
    let response = match flow.run(body).await {
        Ok(resp) => resp,
        Err(stop) => flow.stopped(stop),
    };
    let record = flow.record;
    challenge::count(
        record.feedback.challenge_type,
        record.provider,
        record.result,
    );
    Submitted { response, record }
}

#[cfg(test)]
mod tests;
