//! The Edge's events (docs/impl/phase1-spec.md §9.11, §13.2-§13.6; WP-E1d):
//! what one finished request writes to the event pipeline of
//! `mg_edge_core::events`.
//!
//! | Request | Records |
//! |---|---|
//! | evaluated by the Decision Core | `kind=decision` (sampled, §9.11), its `mg:ev` entry (unsampled), `kind=access` |
//! | forwarded unevaluated (`bootstrap`, `lkg_invalid_open`, `hard.oversize_skipped`) | the same, with a minimal context |
//! | `POST /__mg/c` | `kind=feedback` + its `mg:ev` entry, `kind=telemetry` (vl-short) when the submission carried an `env` (§10.3), `kind=access` |
//! | other `/__mg/*` | `kind=access` (`route = "__mg"`, no action) |
//! | answered before a decision: §9.3.1 protocol limits, §9.4 listener / site state / foreign Worker | `kind=access` (`route = "__protocol"` / `"__site"`) |
//!
//! A request whose host is not a site (404) writes nothing: every line
//! needs its site (a VictoriaLogs stream field).
//!
//! * **Classes**: decision events exempt from sampling
//!   ([`sampling_exempt`]) and feedback are P0, access records P1, sampled
//!   decision events and telemetry P2. A decision event that is sampled
//!   out still sends its `mg:ev` entry (a stream-only record, §13.6).
//! * **Sampling draw**: the first 32 bits of the request id (128 bits from
//!   the OS CSPRNG), so the draw is uniform, costs no extra random number
//!   and never depends on anything the client controls.
//! * **Unevaluated requests**: `bootstrap` and `lkg_invalid_open` decisions
//!   are ALLOW decisions and sampled like any other (without a bundle at the
//!   §8.3 default rate); `hard.oversize_skipped` is always kept, like a
//!   rule that could not be evaluated, and its event names the exceeded
//!   limit (`oversize`).
//! * **Path redaction** (D-31): when the selected route has `redact_path`,
//!   the decision event's `ctx.http.path` and the access record's `path`
//!   are `/<route name>` and `ctx.http.query_keys` is empty; a `/__mg/c`
//!   submission whose `route_class` route redacts gets `/<route_class>`.
//! * **Tier 1** (§9.3): the `x-mg-cf-as-org` value, which Phase 1 only
//!   records, is the decision event's top-level `upstream_as_org`.
//! * **Privacy**: lines carry what §13 lists and nothing else: never a
//!   cookie, `C`, clearance token, `ret`, request body, upstream key or
//!   `x-mg-cf-tls-random`; `mg:ev` carries IPs only as the keyed hashes
//!   `ipk` / `pfk`.

use crate::config::ListenerProfile;
use crate::context::{truncate_utf8, upstream_auth_method};
use crate::decide::DecisionRecord;
use crate::mg_endpoints::SubmitRecord;
use crate::proxy::DecisionSummary;
use mg_core::policy::RuleMode;
use mg_core::{
    Action, Decision, DecisionEvent, HitOutcome, Net, RequestContext, RiskAssessment,
    RouteSensitivity, VerdictOutcome,
};
use mg_edge_core::events::{
    DecisionEntry, EventClass, EventRecord, FeedbackEntry, SampleInputs, Sink, StreamEntry,
    access_path, decision_sample_rate, envelope, redacted_path, sample_keep, sampling_exempt,
};
use mg_edge_core::request::OversizeKind;
use mg_edge_core::state::entity_key;
use mg_proto::v1::EventConfig;
use serde_json::{Map, Value};
use std::net::IpAddr;
use std::time::Duration;

/// `route` of the access record of a `/__mg/*` request (§13.4).
pub const ROUTE_EDGE: &str = "__mg";
/// `route` of the access record of a §9.3.1 protocol rejection.
pub const ROUTE_PROTOCOL: &str = "__protocol";
/// `route` of the access record of a §9.4 rejection (listener, site state,
/// foreign Worker).
pub const ROUTE_SITE: &str = "__site";

/// Longest `ctx.http.path` in the event of a request forwarded
/// unevaluated: the §9.3.1 path cap (an oversize path can be much longer).
pub const UNEVALUATED_PATH_MAX_BYTES: usize = 8 * 1024;
/// Longest method written (the §9.3.1 method cap).
pub const METHOD_MAX_BYTES: usize = 32;
/// Longest `User-Agent` in an unevaluated request's context (§9.5 cap).
pub const USER_AGENT_MAX_BYTES: usize = 512;

/// What every record of a finished request shares.
#[derive(Clone, Copy)]
pub struct Finished<'a> {
    pub edge_id: &'a str,
    pub site: &'a str,
    pub request_id: &'a str,
    /// Arrival, Unix ms (the `ts` of every record).
    pub ts_ms: i64,
    pub method: &'a str,
    /// Normalized host (§9.4).
    pub host: &'a str,
    /// Request path without the query.
    pub path: &'a str,
    /// The environment serving the host, when a bundle is in effect.
    pub env: Option<&'a str>,
    /// HTTP status sent to the client; `None` if no response was sent.
    pub status: Option<u16>,
    /// Response body bytes sent to the client.
    pub bytes_out: u64,
    pub latency: Duration,
    pub client_ip: Option<IpAddr>,
    /// A validated `CF-Ray`.
    pub cf_ray: Option<&'a str>,
    /// The bundle's `events` (or the §8.3 defaults without a bundle).
    pub cfg: &'a EventConfig,
    /// `K_pseudo` for `ipk` / `pfk`. Never written.
    pub k_pseudo: &'a [u8; 32],
}

impl std::fmt::Debug for Finished<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finished")
            .field("site", &self.site)
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The access record's view of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessDecision {
    pub action: Action,
    pub dry_run: bool,
}

/// Network facts of the access record (§13.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessNet {
    pub asn: Option<u32>,
    pub country: Option<String>,
}

/// Uniform 32-bit draw from the request id (see the module documentation);
/// 0 (keep whenever the rate is above 0) if it is not hex.
pub fn sample_draw(request_id: &str) -> u32 {
    request_id
        .get(..8)
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0)
}

fn ipk_pfk(k: &[u8; 32], ip: Option<IpAddr>) -> (Option<String>, Option<String>) {
    match ip {
        Some(ip) => (
            Some(entity_key(k, "ip", &Net::entity_of(ip))),
            Some(entity_key(k, "prefix", &Net::prefix_of(ip))),
        ),
        None => (None, None),
    }
}

/// `<action> <rule_id> route=<route> score=<score>[ dry_run]` (§13.2).
fn decision_msg(d: &Decision, route: &str, score: u8) -> String {
    format!(
        "{} {} route={route} score={score}{}",
        d.action.as_str(),
        d.rule_id.as_deref().unwrap_or("-"),
        if d.dry_run { " dry_run" } else { "" }
    )
}

/// The `mg:ev` decision entry (§13.6).
fn decision_entry(f: &Finished<'_>, e: &DecisionEvent, route: &str) -> StreamEntry {
    let (ipk, pfk) = ipk_pfk(f.k_pseudo, f.client_ip);
    StreamEntry::decision(&DecisionEntry {
        site: f.site,
        ts_ms: f.ts_ms,
        request_id: f.request_id,
        session: e.ctx.session_id.as_deref(),
        route,
        action: e.decision.action,
        dry_run: e.decision.dry_run,
        class: e.risk.bot_class,
        score: e.risk.score.get(),
        ipk: ipk.as_deref(),
        pfk: pfk.as_deref(),
        asn: e.ctx.net.asn,
        status: f.status,
    })
}

/// The decision event and / or its `mg:ev` entry, sampled per §9.11.
/// `extra` fields go after the `DecisionEvent` fields.
fn decision_record(
    f: &Finished<'_>,
    mut event: DecisionEvent,
    inputs: &SampleInputs,
    route: &str,
    extra: Map<String, Value>,
) -> Option<EventRecord> {
    let exempt = sampling_exempt(inputs);
    let class = if exempt {
        EventClass::Priority
    } else {
        EventClass::Sampled
    };
    let rate = decision_sample_rate(inputs, f.cfg.allow_sample_rate);
    event.sample_rate = rate;
    let entry = f.cfg.stream.then(|| decision_entry(f, &event, route));
    if !sample_keep(rate, sample_draw(f.request_id)) {
        return entry.map(|e| EventRecord::stream_only(class, e));
    }
    let msg = decision_msg(&event.decision, route, event.risk.score.get());
    let mut body = match serde_json::to_value(&event) {
        Ok(Value::Object(map)) => map,
        // A DecisionEvent always serializes to an object; keep the entry.
        _ => return entry.map(|e| EventRecord::stream_only(class, e)),
    };
    body.extend(extra);
    let line = envelope("decision", f.site, f.ts_ms, &msg, Value::Object(body));
    let record = EventRecord::new(class, Sink::Main, line);
    Some(match entry {
        Some(e) => record.with_stream(e),
        None => record,
    })
}

/// A hit that must be looked at: MISSING input, an evaluation error, or a
/// dry-run rule (§9.11).
fn flagged(rec: &DecisionRecord) -> bool {
    rec.hits
        .iter()
        .any(|h| h.outcome != HitOutcome::Matched || h.mode == RuleMode::DryRun)
}

/// The records of a request the Decision Core evaluated (§13.2, §13.6).
/// `redact` is the selected route's `redact_path`; `upstream_as_org` the
/// Tier 1 `x-mg-cf-as-org` value, which Phase 1 only records (§9.3).
pub fn evaluated(
    f: &Finished<'_>,
    rec: DecisionRecord,
    redact: bool,
    upstream_as_org: Option<&str>,
) -> Option<EventRecord> {
    let inputs = SampleInputs {
        action: rec.decision.action,
        sensitivity: rec.route.sensitivity,
        force_log: rec.force_log,
        flagged_hit: flagged(&rec),
        monitor: rec.monitor_only,
    };
    let route = rec.route.name.clone();
    let mut ctx = rec.ctx;
    if redact {
        ctx.http.path = redacted_path(&route);
        ctx.http.query_keys.clear();
    }
    let event = DecisionEvent {
        ctx,
        signals: rec.signals,
        risk: rec.risk,
        decision: rec.decision,
        latency_us: rec.latency_us,
        sample_rate: 1.0,
        edge_id: f.edge_id.to_owned(),
        bundle_version: rec.bundle_version,
        monitor_only: rec.monitor_only,
        hits: rec.hits,
    };
    let mut extra = Map::new();
    if let Some(org) = upstream_as_org {
        extra.insert("upstream_as_org".into(), Value::from(org));
    }
    decision_record(f, event, &inputs, &route, extra)
}

/// What the Edge knows about a request it forwarded unevaluated.
#[derive(Debug, Clone, Copy)]
pub struct Unevaluated<'a> {
    pub summary: &'a DecisionSummary,
    pub profile: ListenerProfile,
    /// `loopback` / `origin_mtls` / `secret_header` / `none` (§9.2).
    pub auth_method: &'a str,
    /// The exceeded protocol limit (I-2), if that is why.
    pub oversize: Option<OversizeKind>,
    pub user_agent: Option<&'a str>,
    /// The event's `monitor_only`: the bundle's, or true without a bundle
    /// (bootstrap-open and `lkg_invalid_open` record like monitor, §9.9).
    pub monitor_only: bool,
}

/// The records of a request forwarded without evaluation: `bootstrap`,
/// `lkg_invalid_open` (no bundle) or `hard.oversize_skipped` (I-2). The
/// context holds only what the Edge knows without the Decision Core.
pub fn unevaluated(f: &Finished<'_>, u: &Unevaluated<'_>) -> Option<EventRecord> {
    let mut ctx = RequestContext::new(f.request_id, f.site, f.ts_ms);
    ctx.env = f.env.unwrap_or_default().to_owned();
    // As `crate::context::build` fills them.
    ctx.upstream.profile = u.profile.kind();
    ctx.upstream.auth_method = upstream_auth_method(u.auth_method);
    ctx.upstream.authenticated = u.profile == ListenerProfile::Cloudflare;
    ctx.upstream.cf_ray = f.cf_ray.map(str::to_owned);
    ctx.net.ip = f.client_ip;
    ctx.net.ip_prefix = f.client_ip.map(Net::prefix_of);
    ctx.http.method = truncate_utf8(f.method, METHOD_MAX_BYTES).to_owned();
    ctx.http.host = f.host.to_owned();
    ctx.http.path = truncate_utf8(f.path, UNEVALUATED_PATH_MAX_BYTES).to_owned();
    ctx.http.user_agent = u
        .user_agent
        .map(|ua| truncate_utf8(ua, USER_AGENT_MAX_BYTES).to_owned());
    let decision = Decision {
        action: u.summary.action,
        dry_run: u.summary.dry_run,
        rule_id: Some(u.summary.rule_id.clone()),
        ..Decision::default()
    };
    let inputs = SampleInputs {
        action: decision.action,
        sensitivity: RouteSensitivity::Low,
        force_log: false,
        // Not evaluated at all: kept like a rule that could not be.
        flagged_hit: u.oversize.is_some(),
        monitor: u.monitor_only,
    };
    let event = DecisionEvent {
        ctx,
        signals: Vec::new(),
        risk: RiskAssessment::default(),
        decision,
        latency_us: 0,
        sample_rate: 1.0,
        edge_id: f.edge_id.to_owned(),
        bundle_version: u.summary.bundle_version,
        monitor_only: u.monitor_only,
        hits: Vec::new(),
    };
    let mut extra = Map::new();
    if let Some(kind) = u.oversize {
        extra.insert("oversize".into(), Value::from(kind.as_str()));
    }
    decision_record(f, event, &inputs, "-", extra)
}

/// The `kind=access` record (§13.4), when `events.access_log` is on.
/// `redact_route` is the route name when its `redact_path` is set.
pub fn access(
    f: &Finished<'_>,
    route: &str,
    decision: Option<AccessDecision>,
    redact_route: Option<&str>,
    net: &AccessNet,
) -> Option<EventRecord> {
    if !f.cfg.access_log {
        return None;
    }
    let method = truncate_utf8(f.method, METHOD_MAX_BYTES);
    let path = access_path(f.path, redact_route);
    let msg = match f.status {
        Some(s) => format!("{method} {path} {s}"),
        None => format!("{method} {path} -"),
    };
    let mut body = Map::new();
    let mut put = |k: &str, v: Value| {
        body.insert(k.to_owned(), v);
    };
    if let Some(env) = f.env {
        put("env", env.into());
    }
    put("edge_id", f.edge_id.into());
    put("request_id", f.request_id.into());
    if let Some(ray) = f.cf_ray {
        put("cf_ray", ray.into());
    }
    put("method", method.into());
    put("host", f.host.into());
    put("path", path.as_ref().into());
    if let Some(s) = f.status {
        put("status", s.into());
    }
    if let Some(d) = decision {
        put("action", d.action.as_str().into());
        put("dry_run", d.dry_run.into());
    }
    put("route", route.into());
    if let Some(ip) = f.client_ip {
        put("ip_prefix", Net::prefix_of(ip).into());
    }
    if let Some(asn) = net.asn {
        put("asn", asn.into());
    }
    if let Some(country) = &net.country {
        put("country", country.as_str().into());
    }
    put("bytes_out", f.bytes_out.into());
    put(
        "latency_ms",
        u64::try_from(f.latency.as_millis())
            .unwrap_or(u64::MAX)
            .into(),
    );
    let line = envelope("access", f.site, f.ts_ms, &msg, Value::Object(body));
    Some(EventRecord::new(EventClass::Access, Sink::Main, line))
}

/// The records of one `POST /__mg/c` (§13.3, §13.5, §13.6): the feedback
/// event with its `mg:ev` entry, and the telemetry when the submission
/// carried an `env` that parsed (§10.3: "带 `env` 时另写一条
/// `kind=telemetry`"; a submission without one has nothing to report there,
/// and the feedback event already holds its outcome and reasons).
pub fn submission(f: &Finished<'_>, sub: &SubmitRecord, asn: Option<u32>) -> Vec<EventRecord> {
    let fb = &sub.feedback;
    let outcome = fb.outcome.unwrap_or(VerdictOutcome::Fail);
    let route = fb.route_id.as_deref().unwrap_or("-");
    let msg = format!(
        "challenge {} {} route={route}",
        outcome.as_str(),
        fb.challenge_type.as_str()
    );
    let body = serde_json::to_value(fb).unwrap_or(Value::Null);
    let line = envelope("feedback", f.site, f.ts_ms, &msg, body);
    let mut feedback = EventRecord::new(EventClass::Priority, Sink::Main, line);
    if f.cfg.stream {
        let (_, pfk) = ipk_pfk(f.k_pseudo, f.client_ip);
        feedback = feedback.with_stream(StreamEntry::feedback(&FeedbackEntry {
            site: f.site,
            ts_ms: f.ts_ms,
            request_id: f.request_id,
            route: fb.route_id.as_deref().unwrap_or(""),
            outcome,
            challenge_type: fb.challenge_type,
            pfk: pfk.as_deref(),
            asn,
        }));
    }
    let mut out = vec![feedback];
    if let Some(t) = sub.telemetry.as_ref().filter(|t| t.env.is_some()) {
        let mut body = Map::new();
        body.insert("source".into(), "challenge".into());
        body.insert("request_id".into(), f.request_id.into());
        body.insert("build".into(), t.build.as_str().into());
        if let Some(ms) = t.solve_ms {
            body.insert("solve_ms".into(), ms.into());
        }
        if let Some(env) = t.env.as_ref().and_then(|e| serde_json::to_value(e).ok()) {
            body.insert("env".into(), env);
        }
        if let Some(auto) = t.auto.as_ref().and_then(|a| serde_json::to_value(a).ok()) {
            body.insert("auto".into(), auto);
        }
        let line = envelope(
            "telemetry",
            f.site,
            f.ts_ms,
            "challenge env",
            Value::Object(body),
        );
        out.push(EventRecord::new(EventClass::Sampled, Sink::Short, line));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::Enforcement;
    use crate::mg_endpoints::Telemetry;
    use crate::submission::{AutomationSummary, EnvSummary, UaSummary};
    use mg_challenge::BindInputs;
    use mg_core::{
        BotClass, ChallengeResult, ChallengeType, Channel, RouteInfo, RuleHit, Score, TokenLevel,
    };
    use serde_json::json;

    const K: [u8; 32] = [9; 32];
    const IP: &str = "203.0.113.77";
    const RID: &str = "0123456789abcdef0123456789abcdef";

    fn cfg(rate: f32, access_log: bool, stream: bool) -> EventConfig {
        EventConfig {
            allow_sample_rate: rate,
            access_log,
            stream,
        }
    }

    fn finished<'a>(cfg: &'a EventConfig, path: &'a str) -> Finished<'a> {
        Finished {
            edge_id: "edge-1",
            site: "blog",
            request_id: RID,
            ts_ms: 1_790_000_000_123,
            method: "GET",
            host: "example.com",
            path,
            env: Some("production"),
            status: Some(403),
            bytes_out: 1234,
            latency: Duration::from_millis(12),
            client_ip: Some(IP.parse().unwrap()),
            cf_ray: Some("8f00aa11bb22cc33-HKG"),
            cfg,
            k_pseudo: &K,
        }
    }

    fn record(action: Action, sensitivity: RouteSensitivity) -> DecisionRecord {
        let mut ctx = RequestContext::new(RID, "blog", 1_790_000_000_123);
        ctx.env = "production".into();
        ctx.net.ip = Some(IP.parse().unwrap());
        ctx.net.asn = Some(64500);
        ctx.net.country = Some("HK".into());
        ctx.http.path = "/account/reset".into();
        ctx.http.query_keys = vec!["reset_code".into()];
        ctx.session_id = Some("c2Vzc2lvbi1zdWItMDAwMDAw".into());
        let decision = Decision {
            action,
            rule_id: Some("matrix.critical.medium".into()),
            ..Decision::default()
        };
        DecisionRecord {
            ctx,
            signals: Vec::new(),
            risk: RiskAssessment {
                score: Score::new(45),
                bot_class: BotClass::AutomationLikely,
                ..RiskAssessment::default()
            },
            decision,
            hits: Vec::new(),
            force_log: false,
            latency_us: 180,
            bundle_version: 1_790_000_000,
            monitor_only: false,
            route: RouteInfo {
                id: "reset".into(),
                name: "reset".into(),
                env: "production".into(),
                channel: Channel::Web,
                sensitivity,
                require_clearance: false,
                fail_closed: false,
            },
            enforcement: Enforcement::Forward,
            bind: BindInputs {
                uah: [0; 16],
                ipp: None,
                ipa: None,
                ctp: None,
            },
        }
    }

    fn json(line: &str) -> Value {
        serde_json::from_str(line).unwrap()
    }

    fn keys(line: &str) -> Vec<String> {
        // serde_json keeps insertion order only with preserve_order; read
        // the leading keys from the text instead.
        line.trim_start_matches('{')
            .split(",\"")
            .take(4)
            .map(|p| {
                p.trim_start_matches('"')
                    .split('"')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn sample_draw_uses_the_request_id() {
        assert_eq!(sample_draw("ffffffff00"), u32::MAX);
        assert_eq!(sample_draw("0000000a"), 10);
        assert_eq!(sample_draw("zz"), 0);
        assert_eq!(sample_draw(""), 0);
    }

    /// §13.2: envelope first, the DecisionEvent fields, `msg`; an exempt
    /// decision (critical route) is P0 with `sample_rate` 1 and carries its
    /// `mg:ev` entry; D-31 redaction replaces path and query keys.
    #[test]
    fn decision_event_of_an_exempt_request() {
        let c = cfg(0.0, true, true);
        let f = finished(&c, "/account/reset");
        let r = evaluated(
            &f,
            record(Action::Allow, RouteSensitivity::Critical),
            true,
            Some("Example Net"),
        )
        .unwrap();
        assert_eq!(r.class, EventClass::Priority);
        assert_eq!(r.target, Sink::Main);
        assert_eq!(keys(&r.line), ["kind", "site", "ts", "msg"]);
        let v = json(&r.line);
        assert_eq!(v["kind"], "decision");
        assert_eq!(v["ts"], 1_790_000_000_123i64);
        assert_eq!(
            v["msg"],
            "allow matrix.critical.medium route=reset score=45"
        );
        assert_eq!(v["sample_rate"], 1.0);
        assert_eq!(v["edge_id"], "edge-1");
        assert_eq!(v["bundle_version"], 1_790_000_000u64);
        assert_eq!(v["latency_us"], 180);
        assert_eq!(v["upstream_as_org"], "Example Net");
        assert_eq!(v["ctx"]["http"]["path"], "/reset");
        assert!(
            v["ctx"]["http"]
                .get("query_keys")
                .is_none_or(|q| q == &json!([]))
        );
        assert!(!r.line.contains("/account/reset") && !r.line.contains("reset_code"));
        let entry = r.stream.expect("mg:ev entry");
        assert_eq!(entry.get("rid"), Some(RID));
        assert_eq!(entry.get("route"), Some("reset"));
        assert_eq!(entry.get("status"), Some("403"));
        assert_eq!(entry.get("asn"), Some("64500"));
        assert_eq!(entry.get("class"), Some("automation_likely"));
        // Never the IP in clear: ipk / pfk are the §9.7 keyed hashes.
        let ipk = entry_key("ip", IP);
        assert_eq!(entry.get("ipk"), Some(ipk.as_str()));
        assert_eq!(
            entry.get("pfk"),
            Some(entity_key(&K, "prefix", "203.0.113.0/24").as_str())
        );
        assert!(entry.fields().iter().all(|(_, v)| !v.contains(IP)));
    }

    fn entry_key(typ: &str, ip: &str) -> String {
        entity_key(&K, typ, &Net::entity_of(ip.parse().unwrap()))
    }

    /// §9.11 / §13.6: a sampled-out allow decision still sends its
    /// `mg:ev` entry (P2, no line); without `events.stream` nothing.
    #[test]
    fn sampled_out_decisions_keep_their_stream_entry() {
        let c = cfg(0.0, true, true);
        let f = finished(&c, "/a");
        let r = evaluated(
            &f,
            record(Action::Allow, RouteSensitivity::Low),
            false,
            None,
        )
        .unwrap();
        assert_eq!(r.class, EventClass::Sampled);
        assert!(r.line.is_empty());
        assert_eq!(r.stream.unwrap().get("action"), Some("allow"));
        let c = cfg(0.0, true, false);
        let f = finished(&c, "/a");
        assert!(
            evaluated(
                &f,
                record(Action::Allow, RouteSensitivity::Low),
                false,
                None
            )
            .is_none()
        );
        // Rate 1 keeps it, in the sampled class with the rate recorded.
        let c = cfg(1.0, true, false);
        let f = finished(&c, "/a");
        let r = evaluated(
            &f,
            record(Action::Tag, RouteSensitivity::Medium),
            false,
            None,
        )
        .unwrap();
        assert_eq!(r.class, EventClass::Sampled);
        assert_eq!(json(&r.line)["sample_rate"], 1.0);
        assert!(r.stream.is_none());
        // A rate between: the request id decides (0x01234567 / 2^32 < 0.5).
        let c = cfg(0.5, true, false);
        let f = finished(&c, "/a");
        let r = evaluated(&f, record(Action::Log, RouteSensitivity::Low), false, None).unwrap();
        assert_eq!(json(&r.line)["sample_rate"], 0.5);
    }

    /// §9.11: always kept: non-allow actions, force_log, flagged hits and
    /// non-ALLOW decisions under monitor.
    #[test]
    fn exempt_decisions_are_priority() {
        let c = cfg(0.0, true, false);
        let f = finished(&c, "/a");
        let block = evaluated(
            &f,
            record(Action::Block, RouteSensitivity::Low),
            false,
            None,
        );
        assert_eq!(block.unwrap().class, EventClass::Priority);

        let mut forced = record(Action::Log, RouteSensitivity::Low);
        forced.force_log = true;
        let r = evaluated(&f, forced, false, None).unwrap();
        assert_eq!(r.class, EventClass::Priority);

        for (outcome, mode) in [
            (HitOutcome::MissingInput, RuleMode::Enforce),
            (HitOutcome::EvalError, RuleMode::Enforce),
            (HitOutcome::Matched, RuleMode::DryRun),
        ] {
            let mut rec = record(Action::Allow, RouteSensitivity::Low);
            rec.hits.push(RuleHit {
                rule_id: "r1".into(),
                outcome,
                mode,
                action: Action::Block,
                fields: Vec::new(),
            });
            let r = evaluated(&f, rec, false, None).unwrap();
            assert_eq!(r.class, EventClass::Priority, "{outcome:?} {mode:?}");
        }

        let mut monitored = record(Action::Challenge, RouteSensitivity::Low);
        monitored.monitor_only = true;
        monitored.decision.dry_run = true;
        monitored.decision.challenge_type = ChallengeType::Pow;
        let r = evaluated(&f, monitored, false, None).unwrap();
        assert_eq!(r.class, EventClass::Priority);
        let v = json(&r.line);
        assert!(v["msg"].as_str().unwrap().ends_with(" dry_run"), "{v}");
        assert_eq!(v["monitor_only"], true);
        // Monitor + ALLOW is sampled.
        let mut allowed = record(Action::Allow, RouteSensitivity::Low);
        allowed.monitor_only = true;
        assert!(evaluated(&f, allowed, false, None).is_none());
    }

    /// §13.4: the access record's fields, unknown values omitted, the path
    /// without its query, cut to 1024 bytes, or `/<route>` (D-31).
    #[test]
    fn access_records() {
        let c = cfg(0.1, true, true);
        let f = finished(&c, "/account/login");
        let net = AccessNet {
            asn: Some(64500),
            country: Some("HK".into()),
        };
        let d = AccessDecision {
            action: Action::Challenge,
            dry_run: false,
        };
        let r = access(&f, "login", Some(d), None, &net).unwrap();
        assert_eq!((r.class, r.target), (EventClass::Access, Sink::Main));
        assert!(r.stream.is_none());
        assert_eq!(keys(&r.line), ["kind", "site", "ts", "msg"]);
        let v = json(&r.line);
        let want = json!({"kind": "access", "site": "blog", "ts": 1_790_000_000_123i64,
            "msg": "GET /account/login 403", "env": "production", "edge_id": "edge-1",
            "request_id": RID, "cf_ray": "8f00aa11bb22cc33-HKG", "method": "GET",
            "host": "example.com", "path": "/account/login", "status": 403,
            "action": "challenge", "dry_run": false, "route": "login",
            "ip_prefix": "203.0.113.0/24", "asn": 64500, "country": "HK",
            "bytes_out": 1234, "latency_ms": 12});
        assert_eq!(v, want);
        assert!(!r.line.contains(IP));

        // /__mg: no action; unknown values omitted.
        let mut g = finished(&c, "/__mg/healthz");
        g.status = None;
        g.cf_ray = None;
        g.client_ip = None;
        g.env = None;
        let v = json(
            &access(&g, ROUTE_EDGE, None, None, &AccessNet::default())
                .unwrap()
                .line,
        );
        for absent in [
            "action",
            "dry_run",
            "status",
            "cf_ray",
            "ip_prefix",
            "asn",
            "country",
            "env",
        ] {
            assert!(v.get(absent).is_none(), "{absent}: {v}");
        }
        assert_eq!(v["msg"], "GET /__mg/healthz -");
        assert_eq!(v["route"], "__mg");

        // Redacted, and an over-long path is cut.
        let v = json(
            &access(&f, "login", Some(d), Some("login"), &net)
                .unwrap()
                .line,
        );
        assert_eq!(v["path"], "/login");
        let long = format!("/{}", "é".repeat(2000));
        let h = finished(&c, &long);
        let v = json(&access(&h, "default", Some(d), None, &net).unwrap().line);
        let path = v["path"].as_str().unwrap();
        assert!(
            path.len() <= 1024 && long.starts_with(path),
            "{}",
            path.len()
        );

        // access_log off.
        let off = cfg(0.1, false, true);
        assert!(access(&finished(&off, "/"), "x", None, None, &net).is_none());
    }

    fn summary(rule: &str) -> DecisionSummary {
        DecisionSummary {
            rule_id: rule.into(),
            action: Action::Allow,
            dry_run: true,
            bundle_version: 0,
        }
    }

    /// Unevaluated requests: `hard.oversize_skipped` is always kept and
    /// names the limit, with the path cut to 8 KiB; `bootstrap` is an
    /// ALLOW decision, sampled.
    #[test]
    fn unevaluated_requests() {
        let c = cfg(0.0, true, true);
        let long = format!("/{}", "p".repeat(60_000));
        let f = finished(&c, &long);
        let s = summary("hard.oversize_skipped");
        let u = Unevaluated {
            summary: &s,
            profile: ListenerProfile::Cloudflare,
            auth_method: "loopback",
            oversize: Some(OversizeKind::Path),
            user_agent: Some("curl/8.0"),
            monitor_only: true,
        };
        let r = unevaluated(&f, &u).unwrap();
        assert_eq!(r.class, EventClass::Priority);
        let v = json(&r.line);
        assert_eq!(v["oversize"], "path");
        assert_eq!(v["decision"]["rule_id"], "hard.oversize_skipped");
        assert_eq!(v["decision"]["dry_run"], true);
        assert_eq!(v["ctx"]["upstream"]["auth_method"], "loopback");
        assert_eq!(v["ctx"]["upstream"]["authenticated"], true);
        assert_eq!(v["ctx"]["http"]["user_agent"], "curl/8.0");
        assert_eq!(v["ctx"]["net"]["ip_prefix"], "203.0.113.0/24");
        assert_eq!(
            v["ctx"]["http"]["path"].as_str().unwrap().len(),
            UNEVALUATED_PATH_MAX_BYTES
        );
        assert_eq!(
            v["msg"],
            "allow hard.oversize_skipped route=- score=0 dry_run"
        );
        assert_eq!(r.stream.unwrap().get("route"), Some("-"));

        let s = summary("bootstrap");
        let u = Unevaluated {
            summary: &s,
            oversize: None,
            ..u
        };
        let f = finished(&c, "/x");
        let r = unevaluated(&f, &u).unwrap();
        assert_eq!(r.class, EventClass::Sampled);
        assert!(r.line.is_empty(), "sampled out at rate 0");
        let c = cfg(1.0, true, false);
        let f = finished(&c, "/x");
        let v = json(&unevaluated(&f, &u).unwrap().line);
        assert_eq!(v["decision"]["rule_id"], "bootstrap");
        assert_eq!(v["bundle_version"], 0);
        assert_eq!(v["monitor_only"], true);
    }

    fn submit_record(telemetry: bool) -> SubmitRecord {
        SubmitRecord {
            feedback: ChallengeResult {
                request_id: RID.into(),
                site_id: "blog".into(),
                route_id: Some("login".into()),
                challenge_type: ChallengeType::Pow,
                outcome: Some(VerdictOutcome::Pass),
                lvl: Some(TokenLevel::Pow),
                attempt_no: 0,
                solve_ms: Some(312),
                cf_ray: Some("8f00aa11bb22cc33-HKG".into()),
                ..ChallengeResult::default()
            },
            result: "solved",
            telemetry: telemetry.then(|| Telemetry {
                build: "0123456789abcdef".into(),
                solve_ms: Some(312),
                env: Some(
                    EnvSummary {
                        v: 1,
                        ua: Some(UaSummary {
                            user_agent: Some("Mozilla/5.0 secret-ua".into()),
                            mobile: Some(false),
                            ..UaSummary::default()
                        }),
                        languages: Some(vec!["zh-CN".into()]),
                        ..EnvSummary::default()
                    }
                    .for_telemetry(),
                ),
                auto: Some(AutomationSummary {
                    v: 1,
                    webdriver: Some(false),
                }),
            }),
            reissued: None,
        }
    }

    /// §13.3 / §13.5 / §13.6: feedback (P0, vl-main) with its `mg:ev`
    /// entry, telemetry (P2, vl-short) without `ua.userAgent`.
    #[test]
    fn submission_records() {
        let c = cfg(0.1, true, true);
        let mut f = finished(&c, "/__mg/c");
        f.method = "POST";
        let out = submission(&f, &submit_record(true), Some(64500));
        assert_eq!(out.len(), 2);
        let fb = &out[0];
        assert_eq!((fb.class, fb.target), (EventClass::Priority, Sink::Main));
        let v = json(&fb.line);
        assert_eq!(v["kind"], "feedback");
        assert_eq!(v["msg"], "challenge pass pow route=login");
        assert_eq!(v["outcome"], "pass");
        assert_eq!(v["type"], "pow");
        assert_eq!(v["solve_ms"], 312);
        let e = fb.stream.as_ref().unwrap();
        assert_eq!(e.kind(), "feedback");
        assert_eq!(e.get("route"), Some("login"));
        assert_eq!(e.get("asn"), Some("64500"));
        assert_eq!(
            e.get("pfk"),
            Some(entity_key(&K, "prefix", "203.0.113.0/24").as_str())
        );
        let t = &out[1];
        assert_eq!((t.class, t.target), (EventClass::Sampled, Sink::Short));
        let v = json(&t.line);
        assert_eq!(v["kind"], "telemetry");
        assert_eq!(v["msg"], "challenge env");
        assert_eq!(v["source"], "challenge");
        assert_eq!(v["build"], "0123456789abcdef");
        assert_eq!(v["env"]["languages"], json!(["zh-CN"]));
        assert_eq!(v["auto"], json!({"v": 1, "webdriver": false}));
        assert!(!t.line.contains("secret-ua"), "{}", t.line);

        // Without a parsed body: feedback only; without events.stream: no entry.
        let c = cfg(0.1, true, false);
        let f = finished(&c, "/__mg/c");
        let out = submission(&f, &submit_record(false), None);
        assert_eq!(out.len(), 1);
        assert!(out[0].stream.is_none());

        // A parsed body without `env` (or whose `env` did not parse): no
        // telemetry either (§10.3).
        let mut no_env = submit_record(true);
        no_env.telemetry.as_mut().unwrap().env = None;
        let out = submission(&f, &no_env, None);
        assert_eq!(out.len(), 1, "feedback only");
        assert!(json(&out[0].line)["kind"] == "feedback");
    }
}
