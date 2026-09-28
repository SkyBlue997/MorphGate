//! The Edge's own endpoints under `/__mg/` (docs/impl/phase1-spec.md §10):
//! the SDK files (`/__mg/s/<file>`, §10.4) and the challenge submission
//! (`POST /__mg/c`, §10.3, with §9.7, §9.8, D-27, D-28, D-35, D-37, I-10,
//! I-18, I-28). `/__mg/healthz` and the reserved 404 stay in
//! [`crate::enforce`].
//!
//! # `/__mg/s/<file>`
//!
//! `GET` / `HEAD` of a file listed in the SDK manifest's `files` (exact
//! name) is answered from memory with `text/javascript`, the immutable cache
//! policy and `nosniff` ([`sdk_file`]); any other name is 404 (`no-store`),
//! any other method 405 with `Allow: GET, HEAD`.
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
//! | 9 | round trip 2: `mg_nonce_issue` (nonce + issuance quotas) | `ic.nonce_reused`; 429 `ic.issue_quota`; replay store unavailable: 429 `ic.replay_unavailable` on a `fail_closed` route, otherwise issued with `ic.replay_unchecked` |
//! | 10 | mint the clearance (`sub` / `sst` carried over per §6.5) | success: 303 + cookie (form) or 200 JSON + cookie (fetch); RNG failure: 503 |
//!
//! A failure from step 5 on attaches a new `C` (D-27, I-10): type `pow`, the
//! original `route_class`, the band `RiskBand::after_failure(original)` and
//! its difficulty, the same return path (see [`new_challenge_ret`]). The
//! failures of §9.8 (`ic.body`, `ic.c_invalid`, `ic.c_kid`, `ic.bind_*`,
//! `ic.pow`, `ic.ret`, `ic.automation_flag`, `ic.ua_mismatch`,
//! `ic.nonce_reused`) are counted in `mg.c.fail` and `mg.c.fail.prefix`
//! asynchronously ([`counts_as_failure`]).
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
//! `mg_edge_core::state::StateHandle::nonce_issue` checks the local replay set
//! first, then Valkey, and decides whether the local set alone is
//! authoritative. When it is not ([`NonceResult::Unavailable`]), the route
//! the `C` belongs to decides ([`replay_fail_closed`]): the route of the
//! request host's environment named `claims.route_class` (inside the AEAD,
//! so trusted), OR the route the `ret` path selects for a GET; a route that
//! no longer exists (a newer bundle) counts as `fail_closed`.

use crate::challenge::{self, IssueRequest, Issued, fallback_ret, pow_bits};
use crate::context::{self, Built};
use crate::enforce::{EdgeResponse, IMMUTABLE, JAVASCRIPT, is_navigation};
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
    BindInputs, ClearanceBind, MintParams, Rng, Sealer, TokenError, check_challenge_bind,
    check_clearance_bind, clearance_cookies, pow_verify, ret_hash, reusable_session,
    set_cookie_value, validate_ret, verify_ignoring_expiry,
};
use mg_core::gcra::GcraOutcome;
use mg_core::{
    BindResult, ChallengeResult, ChallengeType, Net, RiskBand, SealedChallengeClaims, TokenLevel,
    VerdictOutcome,
};
use mg_edge_core::state::builtin::ClientDims;
use mg_edge_core::state::{LimitCheck, NonceIssue, NonceResult, RoundTrip1, StateHandle};
use std::fmt;
use std::time::Duration;

/// `Allow` of `/__mg/s/*`.
pub const SDK_ALLOW: &str = "GET, HEAD";
/// `Allow` of `/__mg/c`.
pub const SUBMIT_ALLOW: &str = "POST";
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
}

/// Whether a failure with `code` is counted in `mg.c.fail` and
/// `mg.c.fail.prefix` (§9.8, D-28). An expired `C` (a sleeping tab), a
/// missing client IP, quotas, rate limits, `Early-Data` and an unavailable
/// replay store are not the client's failure.
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
    )
}

// ---------------------------------------------------------------------------
// /__mg/s/<file>

/// The answer to `method /__mg/s/<name>` (see the module documentation);
/// `path` is the raw request path.
pub fn sdk_file(sdk: &SdkDir, path: &str, method: &str) -> EdgeResponse {
    if method != "GET" && method != "HEAD" {
        return EdgeResponse::method_not_allowed(SDK_ALLOW);
    }
    let name = path.strip_prefix(crate::routes::SDK_PREFIX).unwrap_or("");
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
}

impl fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Telemetry")
            .field("build", &self.build)
            .field("solve_ms", &self.solve_ms)
            .field("env", &self.env.is_some())
            .field("auto", &self.auto)
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

/// The `(sub, sst)` a new token carries over (§6.5): from the first
/// `__Host-mg_clr` candidate that verifies for this site and environment
/// (expired allowed), is not bound to another browser or prefix, and whose
/// session is at most `session_max_s` old.
fn reused_session(s: &Submit<'_>, now_s: i64) -> Option<(String, i64)> {
    let cookies: Vec<&str> = s.built.cookies.iter().map(String::as_str).collect();
    clearance_cookies(&cookies).into_iter().find_map(|token| {
        let prev =
            verify_ignoring_expiry(&s.bundle.token_keys, s.site_id, &s.env.name, token, now_s)
                .ok()?;
        let check = check_clearance_bind(&prev, s.bind);
        reusable_session(&prev, &check, now_s, s.bundle.clearance.session_max_s)
    })
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
    /// Unix ms that steps 4-10 judge by: `Submit::now_ms` advanced to the
    /// end of the body read (see [`Flow::clock`]).
    now_ms: i64,
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

    /// Steps 0-10; `Ok(response)` on success.
    async fn run(&mut self, body: &mut dyn BodySource) -> Result<EdgeResponse, Stop> {
        let s = self.s;
        let site = s.site_id;
        let limits = &s.bundle.challenge_limits;

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

        // 2 / 2b. Round trip 1.
        let checks = limits.submit_round_trip(site, &self.dims());
        let got = self
            .state
            .round_trip1(RoundTrip1 {
                verdict_keys: Vec::new(),
                limits: checks.clone(),
            })
            .await
            .limits;
        let outcomes = outcomes_for(&checks, got);
        count_exceeded(&checks, &outcomes);
        // submit_round_trip order: submit, fail, fail.prefix, issue.ipp[, issue.asn].
        if outcomes.iter().take(3).any(|o| !o.allowed) {
            return Err(Stop::Limited {
                code: reason::RATE_LIMITED,
                retry_after_s: retry_after_s(outcomes.iter().take(3)),
            });
        }
        if outcomes.iter().skip(3).any(|o| !o.allowed) {
            return Err(Stop::Limited {
                code: reason::ISSUE_QUOTA,
                retry_after_s: retry_after_s(outcomes.iter().skip(3)),
            });
        }

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
        self.record.feedback.route_id = Some(opened.route_class.clone());
        self.record.feedback.risk_band = Some(opened.risk_band);
        self.record.feedback.solve_ms = solve_ms;
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

        // 5. Bindings.
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

        // 6. PoW on C exactly as received (I-18).
        let difficulty = claims.pow.as_ref().map_or(u32::MAX, |p| p.difficulty);
        if !pow_verify(&sub.c, difficulty, sub.counter) {
            return fail(reason::POW);
        }

        // 7. Return path.
        if validate_ret(&sub.ret).is_err() || ret_hash(&sub.ret).as_slice() != claims.ret_hash {
            return fail(reason::RET);
        }

        // 8. Basic environment.
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

        // 9. Round trip 2: the nonce and the issuance quotas (D-37).
        let quota_checks = limits.issuance(site, &self.dims());
        let ttl_ms = claims
            .exp_ms
            .saturating_sub(now_ms)
            .saturating_add(NONCE_TTL_SLACK_MS)
            .max(1);
        let nonce = self
            .state
            .nonce_issue(
                NonceIssue {
                    site: site.to_owned(),
                    nonce: claims.nonce,
                    ttl_ms: u64::try_from(ttl_ms).unwrap_or(1),
                    limits: quota_checks.clone(),
                },
                now_ms,
                claims.iat_ms,
            )
            .await;
        let quotas = match nonce {
            NonceResult::Reused => return fail(reason::NONCE_REUSED),
            NonceResult::Fresh { limits } => limits,
            NonceResult::Unavailable { limits } => {
                if replay_fail_closed(s.bundle, s.env, s.host, &claims.route_class, &sub.ret) {
                    return Err(Stop::Limited {
                        code: reason::REPLAY_UNAVAILABLE,
                        retry_after_s: RETRY_S,
                    });
                }
                self.record
                    .feedback
                    .reason_codes
                    .push(reason::REPLAY_UNCHECKED.to_owned());
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

        // 10. The clearance.
        let (lvl, ttl_s) = if claims.challenge_type == ChallengeType::Invisible {
            (TokenLevel::Invisible, s.bundle.clearance.ttl_invisible_s)
        } else {
            (TokenLevel::Pow, s.bundle.clearance.ttl_pow_s)
        };
        let ttl_s = ttl_s.clamp(1, mg_challenge::MAX_TOKEN_LIFETIME_S as u32);
        let Some(bind) = ClearanceBind::from_inputs(s.bind) else {
            // Unreachable: the client IP is known (step 0).
            return Err(Stop::Unavailable);
        };
        let now_s = now_ms.div_euclid(1000);
        let session = reused_session(s, now_s);
        let minted = mg_challenge::mint(
            &s.bundle.token_keys,
            site,
            &MintParams {
                env: &s.env.name,
                session: session.as_ref().map(|(sub, sst)| (sub.as_str(), *sst)),
                lvl,
                now_s,
                ttl_s,
                bind,
                rb: claims.risk_band,
            },
            self.rng,
        );
        let token = match minted {
            Ok((token, _)) => token,
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
            Answer::Json => pages::submit_ok_json(&sub.ret, cookie),
        };
        resp.close = !self.body_done;
        Ok(resp)
    }

    /// The new `C` of a failure from step 5 on (D-27, I-10).
    fn reissue(&self) -> Result<Issued, Stop> {
        let (Some(claims), Some(sub)) = (&self.claims, &self.sub) else {
            return Err(Stop::Unavailable);
        };
        let s = self.s;
        let cfg = &s.bundle.challenge;
        let band = claims.risk_band.after_failure();
        let ty = ChallengeType::Pow;
        let bits = challenge::difficulty(&pow_bits(cfg), ty, band);
        let ret = new_challenge_ret(&claims.ret_hash, &sub.ret, fallback_ret(cfg));
        let issued = challenge::issue(
            &IssueRequest {
                sealer: s.sealer,
                host: s.host,
                route_class: &claims.route_class,
                ty,
                band,
                bits,
                ttl_s: cfg.ttl_s,
                ret,
                bind: s.bind,
                now_ms: self.now_ms,
            },
            self.rng,
        );
        if issued.is_ok() {
            challenge::count(ty, "issued");
        }
        issued.map_err(|e| {
            log::error!(
                "request_id={} new challenge after a failure not issued: {e:?}",
                s.request_id
            );
            Stop::Unavailable
        })
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
                                lang: pages::page_lang(context::header(
                                    &s.built.headers,
                                    "accept-language",
                                )),
                                nonce: &nonce,
                                request_id: s.request_id,
                                ret: &ret,
                                state: PageState::Failed,
                                challenge: new.as_ref().map(Issued::shown),
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
    };
    let response = match flow.run(body).await {
        Ok(resp) => resp,
        Err(stop) => flow.stopped(stop),
    };
    let record = flow.record;
    challenge::count(record.feedback.challenge_type, record.result);
    Submitted { response, record }
}

#[cfg(test)]
mod tests;
