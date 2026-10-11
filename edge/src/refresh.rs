//! `POST /__mg/r`: silent clearance refresh (docs/impl/phase2-spec.md §9.3,
//! §5.7, §6.8, D-47; WP-E2b).
//!
//! Off by default (`clearance.refresh = false`); a schema 1 bundle answers
//! 404 (D-66). Route R is `select_route(env, GET, "/")`. The checks run in
//! this order and the first failure decides; every answer is JSON with
//! `MG-Error` on errors:
//!
//! | # | Check | Answer (`mg_token_refresh_total{result}`) |
//! |---|---|---|
//! | 0 | client IP unknown | 429, `Retry-After: 5` (`rate_limited`) |
//! | 1 | `Early-Data` | 425 `mg_too_early` (`rate_limited`) |
//! | 2 | `mg.r` per ip entity and per ipp (in-process, both decide) | 429 (`rate_limited`) |
//! | 3 | body: JSON, at most 16 KiB, exactly `{"v": 2}` plus an optional `"t"` string | 403 `mg_refresh_denied` (`invalid`) |
//! | 4 | a valid clearance, and `clearance.refresh` | 403 (`invalid` / `disabled`) |
//! | 5 | `MG-Proof` (§6.7, `htm = POST`, `htu = https://<host>/__mg/r`, `expected_jkt = cnf.jkt`) | 403 (`not_bound` for `proof.unbound`, otherwise `invalid`) |
//! | 6 | `mg.r` per session (`sub`, after the clearance verified) | 429 (`rate_limited`) |
//! | 7 | one round trip: the verdicts, route R's global limiters (read only) and `mg_jti` | replay: 403 (`replay`); replay store unavailable: 429 + `Retry-After: 5` on a `fail_closed` R, otherwise counted `unchecked` and continued |
//! | 8 | the Decision Core with route R, `refresh_check` (§5.7), then `exp − now ≥ 60` | BLOCK / RATE_LIMIT: 403 `mg_blocked` (`blocked`); otherwise 403 (`not_refreshable`, `ruc`, `not_bound`, `binding`, `too_old`, `challenge`). Under an effective monitor (incl. `force_monitor`) `blocked` and `challenge` are only recorded |
//! | 9 | `mint_refresh` (§6.8): `__Host-mg_clr`, then `__Host-mg_st` | 200 `{"v": 2, "ok": true, "iat", "exp", "now_ms"}` (`ok`) |
//!
//! The request is decided as a page view of R (method GET, path `/`): the
//! question is whether this visitor would be challenged on the site now.
//! The refusal reason goes only to the `kind=refresh` event (§15.3), never
//! to the client. A refresh writes no decision event, no `mg:ev` entry and
//! is not counted in `mg_requests_total` (I-42).

use crate::context::{self, Facts};
use crate::decide::{self, Mode, Services};
use crate::enforce::{EdgeResponse, safe_id};
use crate::identity::{self, Acceptance, Clearance};
use crate::interactive::{self, Gate};
use crate::metrics::metrics;
use crate::mg_endpoints::{BODY_DEADLINE, BodyRead, BodySource, RETRY_S, read_body};
use crate::pages::{self, JSON_V};
use crate::proof::{self, ProofCheck, ProofOutcome};
use crate::sites::{BundleRuntime, EnvRuntime};
use crate::submission::{MediaKind, media_kind};
use mg_challenge::{
    BindInputs, ProofError, Rng, mint_refresh, set_cookie_value, status_set_cookie_value,
};
use mg_core::gcra::GcraParams;
use mg_core::providers::{RefreshDenied, RefreshInput, RefreshLimits, refresh_check};
use mg_core::{TokenLevel, TokenStatus};
use mg_edge_core::events::{ChallengeTelemetry, strict_json};
use mg_edge_core::state::{LimitCheck, LimiterKey, StateHandle, dims};
use serde_json::{Value, json};
use std::net::IpAddr;

/// The path of the endpoint.
pub const REFRESH_PATH: &str = "/__mg/r";
/// `Allow` of `/__mg/r`.
pub const REFRESH_ALLOW: &str = "POST";
/// Largest request body (§11.1).
pub const MAX_BODY: usize = 16 * 1024;
/// A refreshed token must live at least this long (§6.8).
pub const MIN_REMAINING_S: i64 = 60;

/// `mg.r` limiter ids (§7.9): ip entity, ipp (4x), session.
pub const LIMITER: &str = "mg.r";
pub const LIMITER_PREFIX: &str = "mg.r.prefix";
pub const LIMITER_SESSION: &str = "mg.r.session";

/// `result` values of `mg_token_refresh_total` (§9.3).
pub const RESULTS: [&str; 12] = [
    "ok",
    "disabled",
    "invalid",
    "not_refreshable",
    "ruc",
    "not_bound",
    "binding",
    "too_old",
    "challenge",
    "blocked",
    "replay",
    "rate_limited",
];

/// `mg.r` per ip entity: 30 / 600 s, burst 10; the ipp tier 4x (§7.9).
pub fn ip_params() -> (GcraParams, GcraParams) {
    (gcra(30, 600, 10), gcra(120, 600, 40))
}

/// `mg.r` per session: 10 / 600 s, burst 3 (§7.9).
pub fn session_params() -> GcraParams {
    gcra(10, 600, 3)
}

pub(crate) fn gcra(rate: u32, period_s: u32, burst: u32) -> GcraParams {
    GcraParams::new(rate, period_s, burst).unwrap_or_else(|| unreachable!("constant limiter"))
}

/// An in-process limiter keyed by the session (`sub`): `mg.r.session`,
/// `mg.t.session`.
pub(crate) fn session_gate(
    state: &StateHandle,
    site: &str,
    id: &str,
    sub: &str,
    params: GcraParams,
    now_us: u64,
) -> Gate {
    let o = state.local_check(
        &LimitCheck {
            key: LimiterKey::new(site, id, dims(&[("session", Some(sub))])),
            params,
            cost: 1,
            write: true,
        },
        now_us,
    );
    if o.allowed {
        Gate::Allowed
    } else {
        metrics().ratelimit_exceeded.with_label_values(&[id]).inc();
        Gate::Limited {
            retry_after_s: interactive::retry_after_s(&o),
        }
    }
}

/// Everything [`refresh`] reads about the request and the site.
pub struct Refresh<'a> {
    pub request_id: &'a str,
    /// Unix ms when the request arrived.
    pub now_ms: i64,
    pub site_id: &'a str,
    pub bundle: &'a BundleRuntime,
    pub env: &'a EnvRuntime,
    /// The normalized host.
    pub host: &'a str,
    /// The request method as received.
    pub method: &'a str,
    /// The visitor used https (`htu`).
    pub https: bool,
    pub client_ip: Option<IpAddr>,
    pub early_data: bool,
    /// `Content-Encoding` was sent (also as a `Connection` option).
    pub content_encoding: bool,
    /// The sorted `req.headers` of the request.
    pub headers: &'a [(String, String)],
    /// The `Cookie` field values (clearance candidates).
    pub cookies: &'a [String],
    pub bind: &'a BindInputs,
    /// The `MG-Proof` field lines.
    pub proof: proof::ProofHeader<'a>,
    /// The request decided as a page view of route R (step 8): GET `/`
    /// with the request's headers, client and TLS facts.
    pub facts_r: &'a Facts<'a>,
    /// Route R is `fail_closed` (step 7).
    pub r_fail_closed: bool,
}

impl std::fmt::Debug for Refresh<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refresh")
            .field("request_id", &self.request_id)
            .field("site_id", &self.site_id)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// What one refresh did: the answer and the `kind=refresh` event.
#[derive(Debug)]
pub struct Refreshed {
    pub response: EdgeResponse,
    /// `mg_token_refresh_total{result}`.
    pub result: &'static str,
    /// The refusal reason (§5.7 or `proof.*`), also for a refresh that
    /// passed under monitor although `blocked` / `challenge` applied.
    pub reason: Option<String>,
    pub lvl: Option<TokenLevel>,
    pub level_age_s: Option<u64>,
    pub bound: bool,
    /// `t`, only with `events.telemetry_behavior` (§15.2 `source =
    /// "refresh"`).
    pub telemetry: Option<ChallengeTelemetry>,
}

/// The `kind=refresh` material of a [`Refreshed`] (§15.3).
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshRecord {
    pub result: &'static str,
    pub reason: Option<String>,
    pub lvl: Option<TokenLevel>,
    pub level_age_s: Option<u64>,
    pub bound: bool,
    pub telemetry: Option<ChallengeTelemetry>,
}

impl Refreshed {
    /// The answer and the event material.
    pub fn split(self) -> (EdgeResponse, RefreshRecord) {
        (
            self.response,
            RefreshRecord {
                result: self.result,
                reason: self.reason,
                lvl: self.lvl,
                level_age_s: self.level_age_s,
                bound: self.bound,
                telemetry: self.telemetry,
            },
        )
    }
}

/// 403 `{"v": 2, "error": "mg_refresh_denied", "request_id": …}`.
pub fn denied_json(request_id: &str) -> EdgeResponse {
    pages::json_error(
        403,
        "mg_refresh_denied",
        &json!({"v": JSON_V, "error": "mg_refresh_denied", "request_id": safe_id(request_id)}),
    )
}

/// A body that does not fit step 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadBody;

/// Parses the body (step 3): exactly `{"v": 2}` plus an optional `"t"`
/// string. `Ok(t)`.
pub fn parse_body(bytes: &[u8]) -> Result<Option<String>, BadBody> {
    let v = strict_json(bytes, MAX_BODY).map_err(|_| BadBody)?;
    let o = v.as_object().ok_or(BadBody)?;
    if o.get("v").and_then(Value::as_u64) != Some(2) {
        return Err(BadBody);
    }
    if o.keys().any(|k| k != "v" && k != "t") {
        return Err(BadBody);
    }
    match o.get("t") {
        None => Ok(None),
        Some(Value::String(t)) => Ok(Some(t.clone())),
        Some(_) => Err(BadBody),
    }
}

struct Stop {
    response: EdgeResponse,
    result: &'static str,
    reason: Option<String>,
}

fn limited(r: &Refresh<'_>, retry_after_s: u32) -> Stop {
    Stop {
        response: pages::rate_limited_json(r.request_id, retry_after_s),
        result: "rate_limited",
        reason: None,
    }
}

fn denied(r: &Refresh<'_>, result: &'static str, reason: Option<String>) -> Stop {
    Stop {
        response: denied_json(r.request_id),
        result,
        reason,
    }
}

/// The per-level refresh caps of the bundle.
fn limits(b: &BundleRuntime) -> RefreshLimits {
    let c = &b.clearance;
    RefreshLimits {
        interactive_s: u64::from(c.refresh_max_interactive_s),
        interactive_ext_s: u64::from(c.refresh_max_ext_s),
        pow_s: u64::from(c.refresh_max_pow_s),
    }
}

/// Runs `POST /__mg/r` for an active schema 2 site (see the module
/// documentation) and counts `mg_token_refresh_total`.
pub async fn refresh(
    svc: Services<'_>,
    rng: &dyn Rng,
    r: &Refresh<'_>,
    body: &mut dyn BodySource,
) -> Refreshed {
    let mut out = Refreshed {
        response: EdgeResponse::internal_unavailable(),
        result: "invalid",
        reason: None,
        lvl: None,
        level_age_s: None,
        bound: false,
        telemetry: None,
    };
    let mut body_done = false;
    let res = run(svc, rng, r, body, &mut out, &mut body_done).await;
    match res {
        Ok(resp) => {
            out.response = resp;
            out.result = "ok";
        }
        Err(stop) => {
            out.response = stop.response;
            out.result = stop.result;
            if out.reason.is_none() {
                out.reason = stop.reason;
            }
        }
    }
    out.response.close = !body_done;
    metrics()
        .token_refresh
        .with_label_values(&[out.result])
        .inc();
    out
}

async fn run(
    svc: Services<'_>,
    rng: &dyn Rng,
    r: &Refresh<'_>,
    body: &mut dyn BodySource,
    out: &mut Refreshed,
    body_done: &mut bool,
) -> Result<EdgeResponse, Stop> {
    let b = r.bundle;
    let now_us = |ms: i64| u64::try_from(ms).unwrap_or(0).saturating_mul(1000);
    // 0. Client IP (D-23).
    let Some(ip) = r.client_ip else {
        return Err(limited(r, RETRY_S));
    };
    // 1. 0-RTT.
    if r.early_data {
        return Err(Stop {
            response: pages::too_early_json(),
            result: "rate_limited",
            reason: None,
        });
    }
    // 2. mg.r per ip entity and ipp.
    let (ip_p, ipp_p) = ip_params();
    if let Gate::Limited { retry_after_s } = interactive::two_tier(
        svc.state,
        r.site_id,
        (LIMITER, LIMITER_PREFIX),
        ip,
        (ip_p, ipp_p),
        true,
        now_us(r.now_ms),
    ) {
        return Err(limited(r, retry_after_s));
    }
    // 3. The body.
    let invalid = |reason: &str| Err(denied(r, "invalid", Some(reason.to_owned())));
    if r.content_encoding || context::header(r.headers, "content-encoding").is_some() {
        return invalid("body");
    }
    if let Some(len) = context::header(r.headers, "content-length") {
        match len.trim().parse::<u64>() {
            Ok(n) if n <= MAX_BODY as u64 => {}
            _ => return invalid("body"),
        }
    }
    if context::header(r.headers, "content-type").map(media_kind) != Some(Ok(MediaKind::Json)) {
        return invalid("body");
    }
    let bytes = match read_body(body, MAX_BODY, BODY_DEADLINE).await {
        BodyRead::Complete(bytes) => {
            *body_done = true;
            bytes
        }
        _ => return invalid("body"),
    };
    let Ok(t) = parse_body(&bytes) else {
        return invalid("body");
    };
    if b.events.telemetry_behavior {
        out.telemetry = t
            .as_deref()
            .and_then(|t| ChallengeTelemetry::parse(t).ok())
            .filter(|t| !t.is_empty());
    }
    let now_s = r.now_ms.div_euclid(1000);

    // 4. A valid clearance, and refresh enabled.
    let cookies: Vec<&str> = r.cookies.iter().map(String::as_str).collect();
    let clearance: Clearance = identity::verify_clearance(
        &b.token_keys,
        r.site_id,
        &r.env.name,
        &cookies,
        r.bind,
        now_s,
        Acceptance::Any,
    );
    let claims = match (&clearance.claims, clearance.token.status) {
        (Some(c), TokenStatus::Valid) => c.clone(),
        _ => return invalid("token"),
    };
    out.lvl = Some(claims.lvl);
    out.bound = claims.cnf_jkt().is_some();
    let level_age_s = u64::try_from(now_s.saturating_sub(claims.level_at()).max(0)).unwrap_or(0);
    out.level_age_s = Some(level_age_s);
    if !b.clearance.refresh {
        return Err(denied(r, "disabled", None));
    }

    // 5. MG-Proof.
    let check = proof::verify(
        r.proof,
        &proof::Request {
            method: r.method,
            https: r.https,
            host: r.host,
            path: REFRESH_PATH,
            now_s,
        },
        clearance.cnf_jkt.as_deref(),
    );
    match &check {
        ProofCheck::Passed { .. } => {}
        ProofCheck::Absent => {
            ProofOutcome::Absent.count(true);
            return Err(denied(r, "invalid", Some("proof.missing".into())));
        }
        ProofCheck::Failed(e) => {
            ProofOutcome::Failed(*e).count(true);
            let result = if *e == ProofError::Unbound {
                "not_bound"
            } else {
                "invalid"
            };
            return Err(denied(r, result, Some(e.reason_code().into())));
        }
    }

    // 6. mg.r per session.
    if let Gate::Limited { retry_after_s } = session_gate(
        svc.state,
        r.site_id,
        LIMITER_SESSION,
        &claims.sub,
        session_params(),
        now_us(r.now_ms),
    ) {
        return Err(limited(r, retry_after_s));
    }

    // 7-8. One round trip and the Decision Core with route R.
    let token_bind = clearance.token.bind;
    let ruc = claims.ruc;
    let rec = decide::evaluate_with(
        svc,
        b,
        r.env,
        r.facts_r,
        Mode::Refresh {
            clearance: Box::new(clearance),
            proof: check,
        },
    )
    .await;
    match rec.proof {
        ProofOutcome::Replayed => {
            return Err(denied(r, "replay", Some("proof.replay".into())));
        }
        ProofOutcome::Unchecked if r.r_fail_closed => {
            return Err(limited(r, RETRY_S));
        }
        _ => {}
    }
    let refresh_max_s = limits(b).max_for(claims.lvl);
    let verdict = refresh_check(&RefreshInput {
        level: claims.lvl,
        ruc,
        // The proof matched `cnf.jkt` (step 5).
        bound: true,
        bind: token_bind,
        level_age_s,
        refresh_max_s,
        decision: &rec.decision,
    });
    // An effective monitor only records `blocked` and `challenge`.
    let monitor = rec.monitor_only;
    match verdict {
        Ok(()) => {}
        Err(d @ (RefreshDenied::Blocked | RefreshDenied::ChallengeRequired(_))) if monitor => {
            out.reason = Some(d.as_str().into());
        }
        Err(RefreshDenied::Blocked) => {
            return Err(Stop {
                response: EdgeResponse::blocked(r.request_id, false),
                result: "blocked",
                reason: Some("blocked".into()),
            });
        }
        Err(d) => return Err(denied(r, d.as_str(), Some(d.as_str().into()))),
    }
    let ttl_s = b.ttl_for(&claims.lvl);
    let exp = (now_s + i64::from(ttl_s)).min(claims.sst + i64::from(b.clearance.session_max_s));
    if exp - now_s < MIN_REMAINING_S {
        return Err(denied(r, "too_old", Some("too_old".into())));
    }

    // 9. Mint.
    let (token, minted) = match mint_refresh(
        &b.token_keys,
        r.site_id,
        &claims,
        now_s,
        ttl_s,
        b.clearance.session_max_s,
        rng,
    ) {
        Ok(t) => t,
        Err(e) => {
            log::error!("request_id={} refresh not minted: {e}", r.request_id);
            return Err(Stop {
                response: EdgeResponse::internal_unavailable(),
                result: "invalid",
                reason: Some("mint".into()),
            });
        }
    };
    let max_age = u32::try_from(minted.exp - now_s).unwrap_or(1).max(1);
    let body =
        json!({"v": JSON_V, "ok": true, "iat": minted.iat, "exp": minted.exp, "now_ms": r.now_ms});
    Ok(
        EdgeResponse::new(200, crate::enforce::JSON, body.to_string())
            .with("Set-Cookie", set_cookie_value(&token, max_age))
            .with("Set-Cookie", status_set_cookie_value(&minted, max_age)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_rules() {
        assert_eq!(parse_body(br#"{"v":2}"#), Ok(None));
        assert_eq!(
            parse_body(br#"{"v":2,"t":"{\"ix\":null}"}"#),
            Ok(Some("{\"ix\":null}".into()))
        );
        for bad in [
            &br#"{"v":1}"#[..],
            br#"{"v":"2"}"#,
            br#"{}"#,
            br#"[]"#,
            br#"{"v":2,"x":1}"#,
            br#"{"v":2,"t":1}"#,
            br#"{"v":2,"v":2}"#,
            b"not json",
        ] {
            assert!(parse_body(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let big = format!(r#"{{"v":2,"t":"{}"}}"#, "a".repeat(MAX_BODY));
        assert!(parse_body(big.as_bytes()).is_err());
    }

    #[test]
    fn limiter_parameters_follow_section_7_9() {
        let (ip, ipp) = ip_params();
        assert_eq!(ip, GcraParams::new(30, 600, 10).unwrap());
        assert_eq!(ipp, GcraParams::new(120, 600, 40).unwrap());
        assert_eq!(session_params(), GcraParams::new(10, 600, 3).unwrap());
        assert!(RESULTS.contains(&"rate_limited") && RESULTS.len() == 12);
    }

    #[test]
    fn denied_answer() {
        let r = denied_json("0123456789abcdef0123456789abcdef");
        assert_eq!(r.status, 403);
        assert!(
            r.headers
                .iter()
                .any(|(n, v)| *n == "MG-Error" && v == "mg_refresh_denied")
        );
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["v"], 2);
        assert_eq!(v["error"], "mg_refresh_denied");
    }
}
