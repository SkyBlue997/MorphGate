//! `POST /__mg/t`: the Web SDK's reports (docs/impl/phase2-spec.md §9.4,
//! §15.2, D-48; WP-E2b).
//!
//! A schema 1 bundle answers 404 (D-66). Every answer is JSON. In order:
//!
//! 1. client IP unknown → 429 (`Retry-After: 5`);
//! 2. `Early-Data` → 425 `mg_too_early`;
//! 3. `mg.t` per ip entity and per ipp (in-process, both decide) → 429;
//! 4. the body (JSON, at most 16 KiB) and its schema
//!    (`mg_edge_core::events::parse_reports`: at most 8 reports, at most one
//!    `upstream_challenge` and one `cache_hit`) → 400 `mg_bad_request`;
//! 5. an `MG-Proof` that passes §6.7 (`htm = POST`, `htu =
//!    https://<host>/__mg/t`, `expected_jkt = cnf.jkt` of a valid clearance)
//!    and whose `jti` is new in the in-process set (no Valkey round trip)
//!    makes the reports `signed`; then `mg.t` per session (`sub`) → 429. An
//!    invalid proof never rejects the reports, they are only unsigned;
//! 6. report paths are matched against the routes (Phase 1 §9.4 path
//!    views); a `redact_path` route is written as `/<route name>`;
//! 7. one `kind=telemetry` line per report (vl-short, `source = "sdk"`,
//!    with `signed`) into the telemetry queue (`EventClass::Telemetry`, its
//!    own capacity: a full queue drops telemetry only); `behavior` only with
//!    `events.telemetry_behavior` (otherwise `disabled`), a `cache_hit` under
//!    `/__mg/s/` is `invalid`;
//! 8. 204.
//!
//! The two alert metrics count only trusted reports: `signed`, and at most
//! one per session (`sub`), kind and 10 minutes ([`Dedup`], a bounded
//! in-process table; when it is full nothing more is counted).
//! `mg_double_challenge_total{site, route}` takes `route` from the report's
//! path (the matched route's name, `default` without one), so its labels
//! stay bounded. `mg_sw_intercept_reports_total{site}` counts every
//! accepted `sw_intercept` report. Every report counts
//! `mg_telemetry_reports_total{kind, result}`.
//!
//! Telemetry never changes a decision in Phase 2 (§5.6).

use crate::context;
use crate::enforce::{EdgeResponse, safe_id};
use crate::identity::{self, Acceptance};
use crate::interactive::{self, Gate};
use crate::metrics::metrics;
use crate::mg_endpoints::{BODY_DEADLINE, BodyRead, BodySource, RETRY_S, read_body};
use crate::pages::{self, JSON_V};
use crate::proof::{self, ProofCheck};
use crate::refresh::{gcra, session_gate};
use crate::sites::{BundleRuntime, EnvRuntime, RouteRuntime, select_route};
use crate::submission::{MediaKind, media_kind};
use mg_challenge::BindInputs;
use mg_core::TokenStatus;
use mg_core::gcra::GcraParams;
use mg_edge_core::events::{
    EventClass, EventRecord, REPORT_BODY_MAX_BYTES, ReportEntry, ReportKind, Sink, TelemetryReport,
    envelope, parse_reports, redacted_path,
};
use mg_edge_core::state::StateHandle;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// The path of the endpoint.
pub const TELEMETRY_PATH: &str = "/__mg/t";
/// `Allow` of `/__mg/t`.
pub const TELEMETRY_ALLOW: &str = "POST";

/// `mg.t` limiter ids (§7.9): ip entity, ipp (4x), session.
pub const LIMITER: &str = "mg.t";
pub const LIMITER_PREFIX: &str = "mg.t.prefix";
pub const LIMITER_SESSION: &str = "mg.t.session";

/// `result` values of `mg_telemetry_reports_total` (§15.5).
pub const RESULTS: [&str; 6] = [
    "accepted",
    "unsigned",
    "suppressed",
    "invalid",
    "disabled",
    "rate_limited",
];

/// A trusted report of one kind is counted at most once per session in
/// this window (§9.4).
pub const DEDUP_WINDOW_MS: i64 = 10 * 60 * 1000;
/// Capacity of the [`Dedup`] table.
pub const DEDUP_CAPACITY: usize = 10_000;

/// `mg.t` per ip entity: 60 / 60 s, burst 30; the ipp tier 4x (§7.9).
pub fn ip_params() -> (GcraParams, GcraParams) {
    (gcra(60, 60, 30), gcra(240, 60, 120))
}

/// `mg.t` per session: 30 / 60 s, burst 15 (§7.9).
pub fn session_params() -> GcraParams {
    gcra(30, 60, 15)
}

/// The bounded once-per-10-minutes table of the alert metrics (§9.4):
/// `(site, sub, kind) → last counted (Unix ms)`. Never holds anything
/// beyond the session id and the report kind.
#[derive(Debug, Default)]
pub struct Dedup {
    seen: Mutex<HashMap<(String, String, ReportKind), i64>>,
}

impl Dedup {
    /// Whether a trusted report of `kind` from session `sub` is counted now
    /// (and records it): `false` within the window of the last one, and
    /// when the table is full of live entries.
    pub fn admit(&self, site: &str, sub: &str, kind: ReportKind, now_ms: i64) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (site.to_owned(), sub.to_owned(), kind);
        if let Some(last) = seen.get(&key)
            && now_ms.saturating_sub(*last) < DEDUP_WINDOW_MS
        {
            return false;
        }
        if !seen.contains_key(&key) && seen.len() >= DEDUP_CAPACITY {
            seen.retain(|_, last| now_ms.saturating_sub(*last) < DEDUP_WINDOW_MS);
            if seen.len() >= DEDUP_CAPACITY {
                return false;
            }
        }
        seen.insert(key, now_ms);
        true
    }
}

/// Everything [`report`] reads about the request and the site.
pub struct Reports<'a> {
    pub request_id: &'a str,
    pub now_ms: i64,
    pub site_id: &'a str,
    pub bundle: &'a BundleRuntime,
    pub env: &'a EnvRuntime,
    pub host: &'a str,
    pub method: &'a str,
    pub https: bool,
    pub client_ip: Option<IpAddr>,
    pub early_data: bool,
    pub content_encoding: bool,
    pub headers: &'a [(String, String)],
    pub cookies: &'a [String],
    pub bind: &'a BindInputs,
    pub proof: proof::ProofHeader<'a>,
}

impl std::fmt::Debug for Reports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reports")
            .field("request_id", &self.request_id)
            .field("site_id", &self.site_id)
            .finish_non_exhaustive()
    }
}

/// What one `POST /__mg/t` did.
#[derive(Debug)]
pub struct Reported {
    pub response: EdgeResponse,
    /// The `kind=telemetry` records (the caller queues them).
    pub records: Vec<EventRecord>,
    /// The proof made the reports trusted.
    pub signed: bool,
}

/// 400 `{"v": 2, "error": "mg_bad_request", "request_id": …}`.
pub fn bad_request_json(request_id: &str) -> EdgeResponse {
    pages::json_error(
        400,
        "mg_bad_request",
        &json!({"v": JSON_V, "error": "mg_bad_request", "request_id": safe_id(request_id)}),
    )
}

fn count(kind: ReportKind, result: &str) {
    metrics()
        .telemetry_reports
        .with_label_values(&[kind.as_str(), result])
        .inc();
}

/// The route name of a report path (§9.4 step 6): `(name, redact_path)`,
/// `default` when nothing matches.
fn report_route<'e>(
    env: &'e EnvRuntime,
    b: &BundleRuntime,
    host: &str,
    path: &str,
) -> (&'e str, bool) {
    static FALLBACK: std::sync::LazyLock<RouteRuntime> =
        std::sync::LazyLock::new(RouteRuntime::fallback);
    let m = select_route(env, host, "GET", path, b.case_insensitive_paths, &FALLBACK);
    if std::ptr::eq(m.route, &*FALLBACK) {
        return ("default", false);
    }
    (m.route.name.as_str(), m.route.redact_path)
}

/// Runs `POST /__mg/t` for an active schema 2 site (see the module
/// documentation).
pub async fn report(
    state: &StateHandle,
    k_pseudo: &[u8; 32],
    dedup: &Dedup,
    r: &Reports<'_>,
    body: &mut dyn BodySource,
) -> Reported {
    let mut body_done = false;
    let (mut response, records, signed) =
        match run(state, k_pseudo, dedup, r, body, &mut body_done).await {
            Ok((records, signed)) => (
                EdgeResponse::new(204, crate::enforce::JSON, ""),
                records,
                signed,
            ),
            Err(resp) => (resp, Vec::new(), false),
        };
    response.close = !body_done;
    Reported {
        response,
        records,
        signed,
    }
}

async fn run(
    state: &StateHandle,
    k_pseudo: &[u8; 32],
    dedup: &Dedup,
    r: &Reports<'_>,
    body: &mut dyn BodySource,
    body_done: &mut bool,
) -> Result<(Vec<EventRecord>, bool), EdgeResponse> {
    let b = r.bundle;
    let now_us = u64::try_from(r.now_ms).unwrap_or(0).saturating_mul(1000);
    // 1. Client IP (D-23).
    let Some(ip) = r.client_ip else {
        return Err(pages::rate_limited_json(r.request_id, RETRY_S));
    };
    // 2. 0-RTT.
    if r.early_data {
        return Err(pages::too_early_json());
    }
    // 3. mg.t per ip entity and ipp.
    if let Gate::Limited { retry_after_s } = interactive::two_tier(
        state,
        r.site_id,
        (LIMITER, LIMITER_PREFIX),
        ip,
        ip_params(),
        true,
        now_us,
    ) {
        return Err(pages::rate_limited_json(r.request_id, retry_after_s));
    }
    // 4. The body and its schema.
    let bad = || bad_request_json(r.request_id);
    if r.content_encoding || context::header(r.headers, "content-encoding").is_some() {
        return Err(bad());
    }
    if let Some(len) = context::header(r.headers, "content-length") {
        match len.trim().parse::<u64>() {
            Ok(n) if n <= REPORT_BODY_MAX_BYTES as u64 => {}
            _ => return Err(bad()),
        }
    }
    if context::header(r.headers, "content-type").map(media_kind) != Some(Ok(MediaKind::Json)) {
        return Err(bad());
    }
    let bytes = match read_body(body, REPORT_BODY_MAX_BYTES, BODY_DEADLINE).await {
        BodyRead::Complete(bytes) => {
            *body_done = true;
            bytes
        }
        _ => return Err(bad()),
    };
    let Ok(entries) = parse_reports(&bytes) else {
        return Err(bad());
    };

    // 5. Signed reports: a valid proof whose jti is new locally.
    let now_s = r.now_ms.div_euclid(1000);
    let mut session: Option<String> = None;
    if r.proof.present() {
        let cookies: Vec<&str> = r.cookies.iter().map(String::as_str).collect();
        let clearance = identity::verify_clearance(
            &b.token_keys,
            r.site_id,
            &r.env.name,
            &cookies,
            r.bind,
            now_s,
            Acceptance::Any,
        );
        let check = proof::verify(
            r.proof,
            &proof::Request {
                method: r.method,
                https: r.https,
                host: r.host,
                path: TELEMETRY_PATH,
                now_s,
            },
            clearance.cnf_jkt.as_deref(),
        );
        if let (ProofCheck::Passed { .. }, TokenStatus::Valid) = (&check, clearance.token.status)
            && let Some(jti) = check.jti(r.site_id, k_pseudo)
            && state.local_jti_fresh(&jti, r.now_ms)
        {
            session = clearance.session;
        }
    }
    let signed = session.is_some();
    if let Some(sub) = &session
        && let Gate::Limited { retry_after_s } = session_gate(
            state,
            r.site_id,
            LIMITER_SESSION,
            sub,
            session_params(),
            now_us,
        )
    {
        for e in &entries {
            count(entry_kind(e), "rate_limited");
        }
        return Err(pages::rate_limited_json(r.request_id, retry_after_s));
    }

    // 6-7. One line per report.
    let m = metrics();
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let report = match entry {
            ReportEntry::Dropped(kind) => {
                count(kind, "invalid");
                continue;
            }
            ReportEntry::Report(rep) => rep,
        };
        let kind = report.kind();
        if kind == ReportKind::Behavior && !b.events.telemetry_behavior {
            count(kind, "disabled");
            continue;
        }
        let (route, path) = match report.path() {
            Some(p) => {
                let (route, redact) = report_route(r.env, b, r.host, p);
                (route.to_owned(), redact.then(|| redacted_path(route)))
            }
            None => ("default".to_owned(), None),
        };
        let result = match (kind, &session) {
            (ReportKind::UpstreamChallenge | ReportKind::CacheHit, Some(sub)) => {
                if dedup.admit(r.site_id, sub, kind, r.now_ms) {
                    if kind == ReportKind::UpstreamChallenge {
                        m.double_challenge
                            .with_label_values(&[r.site_id, &route])
                            .inc();
                    } else {
                        m.endpoint_cache_hit_reports
                            .with_label_values(&[r.site_id])
                            .inc();
                    }
                    "accepted"
                } else {
                    "suppressed"
                }
            }
            (_, None) => "unsigned",
            (_, Some(_)) => "accepted",
        };
        if kind == ReportKind::SwIntercept {
            m.sw_intercept_reports.with_label_values(&[r.site_id]).inc();
        }
        count(kind, result);
        records.push(line(r, &report, path.as_deref(), signed));
    }
    Ok((records, signed))
}

fn entry_kind(e: &ReportEntry) -> ReportKind {
    match e {
        ReportEntry::Report(r) => r.kind(),
        ReportEntry::Dropped(k) => *k,
    }
}

/// The `kind=telemetry` line of one report (§15.2 `source = "sdk"`).
fn line(
    r: &Reports<'_>,
    report: &TelemetryReport,
    path: Option<&str>,
    signed: bool,
) -> EventRecord {
    let mut body = report.to_value(path);
    if let Some(o) = body.as_object_mut() {
        o.insert("source".into(), Value::from("sdk"));
        o.insert("request_id".into(), Value::from(r.request_id));
        o.insert("signed".into(), Value::from(signed));
    }
    let msg = format!("sdk {}", report.kind().as_str());
    let line = envelope("telemetry", r.site_id, r.now_ms, &msg, body);
    EventRecord::new(EventClass::Telemetry, Sink::Short, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_counts_once_per_window_and_stays_bounded() {
        let d = Dedup::default();
        let k = ReportKind::UpstreamChallenge;
        assert!(d.admit("blog", "s1", k, 0));
        assert!(!d.admit("blog", "s1", k, DEDUP_WINDOW_MS - 1));
        assert!(d.admit("blog", "s1", ReportKind::CacheHit, 1));
        assert!(d.admit("blog", "s2", k, 1));
        assert!(d.admit("blog", "s1", k, DEDUP_WINDOW_MS));
        // Full of live entries: nothing more is counted.
        let d = Dedup::default();
        for i in 0..DEDUP_CAPACITY {
            assert!(d.admit("blog", &format!("s{i}"), k, 0));
        }
        assert!(!d.admit("blog", "new", k, 1));
        // Expired entries make room again.
        assert!(d.admit("blog", "new", k, DEDUP_WINDOW_MS + 1));
    }

    #[test]
    fn limiter_parameters_follow_section_7_9() {
        let (ip, ipp) = ip_params();
        assert_eq!(ip, GcraParams::new(60, 60, 30).unwrap());
        assert_eq!(ipp, GcraParams::new(240, 60, 120).unwrap());
        assert_eq!(session_params(), GcraParams::new(30, 60, 15).unwrap());
    }

    #[test]
    fn bad_request_answer() {
        let r = bad_request_json("0123456789abcdef0123456789abcdef");
        assert_eq!(r.status, 400);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            (v["v"].as_u64(), v["error"].as_str()),
            (Some(2), Some("mg_bad_request"))
        );
        assert!(
            r.headers
                .iter()
                .any(|(n, v)| *n == "MG-Error" && v == "mg_bad_request")
        );
    }
}
