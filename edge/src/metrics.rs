//! Prometheus metrics of the Edge skeleton (docs/impl/phase1-spec.md §13.7),
//! registered once in the default registry that `pingora-prometheus` serves
//! on `metrics_listen`.
//!
//! Only bounded labels: `site` and `listener` come from edge.toml, `reason`,
//! `kind`, `mode` and `state` from fixed lists, `signal` from the §9.3
//! table, `route` is a route *kind* (`healthz` / `edge` / `origin`).
//!
//! Families registered by `mg-edge-core` (`mg_config_*`,
//! `mg_artifact_missing`, `mg_valkey_*`, `mg_state_*`,
//! `mg_verdict_parse_errors_total`) and the event pipeline's
//! `mg_event_dropped_total` are not registered here again.
//!
//! The decision families (WP-E1b): `mg_token_verify_total{result}`,
//! `mg_crawler_verify_total{method, result}`,
//! `mg_cf_vbot_disagree_total{direction}`, `mg_rdns_lookups_total{result}`,
//! `mg_ratelimit_exceeded_total{limiter}` (limiter ids come from the bundle),
//! `mg_policy_step_limit_total{site}` and
//! `mg_decision_latency_seconds{site}`.
//!
//! The challenge families (WP-E1c): `mg_challenge_total{type, provider,
//! result}` (`provider="none"` in Phase 1; `result` = issued / solved /
//! failed / expired) and `mg_https_redirect_total{site}`.
//!
//! The observability families (WP-E1d): `mg_requests_total{site, env,
//! route, action, class}`, `mg_edge_added_latency_seconds{site}` and
//! `mg_origin_connect_seconds{site}` (see [`EdgeMetrics::observe_timing`]).
//! [`EdgeMetrics::init_site`], [`EdgeMetrics::init_listener`] and
//! [`EdgeMetrics::init_static`] create every series with a small, fixed
//! label set at 0 when the server is built, so `/metrics` shows the full
//! §13.7 set from the start and the §17 alerts (`increase(...) > 0`) see a
//! series before its first event.

use crate::config::ListenerAuth;
use crate::routes::RouteKind;
use mg_core::ChallengeType;
use pingora_prometheus::prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge_vec,
};
use std::sync::LazyLock;
use std::time::Duration;

/// Request duration buckets (seconds), dense below 50 ms.
const DURATION_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Histogram buckets of §13.7 (seconds).
pub const LATENCY_BUCKETS: &[f64] = &[
    0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
];

/// Values of the `state` label of `mg_site_state` (§9.10).
pub const SITE_STATES: [&str; 4] = [
    "active",
    "bootstrap_open",
    "bootstrap_closed",
    "lkg_invalid",
];

/// The Edge's metric families.
#[derive(Debug)]
pub struct EdgeMetrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    /// `mg_edge_request_errors_total{route}` (Phase 0 family): proxy
    /// failures and Edge-internal errors such as the RNG (§9.9).
    pub(crate) errors: IntCounterVec,
    info: IntGaugeVec,
    /// `mg_site_state{site, state}`: 1 for the current state, 0 otherwise.
    pub site_state: IntGaugeVec,
    /// `mg_site_unavailable_total{site}`: 503 because of the site state.
    pub site_unavailable: IntCounterVec,
    /// `mg_protocol_rejected_total{listener, reason}` (§9.3.1).
    pub protocol_rejected: IntCounterVec,
    /// `mg_oversize_total{site, kind, mode}`: oversize requests forwarded
    /// unevaluated under monitor / bootstrap-open (I-2).
    pub oversize: IntCounterVec,
    /// `mg_upstream_auth_failures_total{listener, profile, reason}` (§9.2).
    pub upstream_auth_failures: IntCounterVec,
    /// `mg_upstream_headers_stripped_total{profile}` (§9.3 step 5).
    pub upstream_headers_stripped: IntCounterVec,
    /// `mg_upstream_signal_missing_total{profile, signal}` (§9.3).
    pub upstream_signal_missing: IntCounterVec,
    /// `mg_cf_connecting_ip_missing_total{site}` (§9.3.2).
    pub cf_connecting_ip_missing: IntCounterVec,
    /// `mg_cf_foreign_worker_total{site}` (§9.3.2).
    pub cf_foreign_worker: IntCounterVec,
    /// `mg_unknown_host_total{listener}` (§9.4).
    pub unknown_host: IntCounterVec,
    /// `mg_listener_rejected_total{listener, site}` (§9.4).
    pub listener_rejected: IntCounterVec,
    /// `mg_cf_ip_filter_active{listener}`: 1 while the filter has ranges.
    pub cf_ip_filter_active: IntGaugeVec,
    /// `mg_token_verify_total{result}`: none / valid / expired / invalid /
    /// binding_mismatch (§9.6).
    pub token_verify: IntCounterVec,
    /// `mg_crawler_verify_total{method, result}` (§7.3): `ip_range` results
    /// per request, `rdns` results when the job settles; `pending` is not
    /// counted.
    pub crawler_verify: IntCounterVec,
    /// `mg_cf_vbot_disagree_total{direction}` (§9.6, docs/05 §3.4).
    pub cf_vbot_disagree: IntCounterVec,
    /// `mg_rdns_lookups_total{result}`: pass / fail / dns_error / dropped
    /// (§9.6, §17 alarm on `dropped`).
    pub rdns_lookups: IntCounterVec,
    /// `mg_ratelimit_exceeded_total{limiter}`, dry-run limiters included
    /// (§9.8).
    pub ratelimit_exceeded: IntCounterVec,
    /// `mg_policy_step_limit_total{site}` (§5.3; should stay 0).
    pub policy_step_limit: IntCounterVec,
    /// `mg_decision_latency_seconds{site}`: `DecisionCore::evaluate` (§13.7).
    pub decision_latency: HistogramVec,
    /// `mg_challenge_total{type, provider, result}` (§10.3, §13.7): issued
    /// challenges and every `/__mg/c` submission.
    pub challenge: IntCounterVec,
    /// `mg_https_redirect_total{site}`: http visitors redirected to https
    /// instead of being challenged (§9.9, D-32).
    pub https_redirect: IntCounterVec,
    /// `mg_requests_total{site, env, route, action, class}` (§13.7): every
    /// request that reached the decision step, with the decision before
    /// execution (under monitor the action that would have been taken).
    pub requests_total: IntCounterVec,
    /// `mg_edge_added_latency_seconds{site}` (§13.7): the Edge's own time.
    pub edge_added_latency: HistogramVec,
    /// `mg_origin_connect_seconds{site}` (§13.7): new origin connections.
    pub origin_connect: HistogramVec,
}

static METRICS: LazyLock<EdgeMetrics> = LazyLock::new(EdgeMetrics::register);

/// Process-wide metrics.
pub fn metrics() -> &'static EdgeMetrics {
    &METRICS
}

macro_rules! counter {
    ($name:literal, $help:literal, $labels:expr) => {
        register_int_counter_vec!($name, $help, $labels).expect(concat!("register ", $name))
    };
}

macro_rules! gauge {
    ($name:literal, $help:literal, $labels:expr) => {
        register_int_gauge_vec!($name, $help, $labels).expect(concat!("register ", $name))
    };
}

impl EdgeMetrics {
    // Registration only fails on duplicate names, i.e. a programming error.
    fn register() -> Self {
        Self {
            requests: counter!(
                "mg_edge_requests_total",
                "Requests handled by the Edge, by route kind and response status class.",
                &["route", "status"]
            ),
            duration: register_histogram_vec!(
                "mg_edge_request_duration_seconds",
                "Time from request start to completion, including the origin, by route kind.",
                &["route"],
                DURATION_BUCKETS.to_vec()
            )
            .expect("register mg_edge_request_duration_seconds"),
            errors: counter!(
                "mg_edge_request_errors_total",
                "Requests that ended with a proxy error or an Edge-internal failure.",
                &["route"]
            ),
            info: gauge!(
                "mg_edge_info",
                "Constant 1, labelled with build and configuration facts.",
                &["version", "edge_id"]
            ),
            site_state: gauge!(
                "mg_site_state",
                "1 for the current state of each site (active, bootstrap_open, bootstrap_closed, lkg_invalid).",
                &["site", "state"]
            ),
            site_unavailable: counter!(
                "mg_site_unavailable_total",
                "Requests answered 503 because the site is lkg_invalid or bootstrap_closed.",
                &["site"]
            ),
            protocol_rejected: counter!(
                "mg_protocol_rejected_total",
                "Requests rejected by the protocol input limits (414 / 431 / 400).",
                &["listener", "reason"]
            ),
            oversize: counter!(
                "mg_oversize_total",
                "Oversize requests forwarded without policy evaluation (monitor / bootstrap-open).",
                &["site", "kind", "mode"]
            ),
            upstream_auth_failures: counter!(
                "mg_upstream_auth_failures_total",
                "Requests or handshakes that failed upstream authentication.",
                &["listener", "profile", "reason"]
            ),
            upstream_headers_stripped: counter!(
                "mg_upstream_headers_stripped_total",
                "Unauthenticated requests that carried upstream-family headers (stripped).",
                &["profile"]
            ),
            upstream_signal_missing: counter!(
                "mg_upstream_signal_missing_total",
                "Trusted upstream signals that were missing or invalid.",
                &["profile", "signal"]
            ),
            cf_connecting_ip_missing: counter!(
                "mg_cf_connecting_ip_missing_total",
                "Authenticated cloudflare requests without a usable CF-Connecting-IP.",
                &["site"]
            ),
            cf_foreign_worker: counter!(
                "mg_cf_foreign_worker_total",
                "Requests from a Cloudflare Worker of a zone outside owner_zones (403).",
                &["site"]
            ),
            unknown_host: counter!(
                "mg_unknown_host_total",
                "Requests for a host that no site serves (404).",
                &["listener"]
            ),
            listener_rejected: counter!(
                "mg_listener_rejected_total",
                "Requests for a site on a listener that may not serve it (403).",
                &["listener", "site"]
            ),
            cf_ip_filter_active: gauge!(
                "mg_cf_ip_filter_active",
                "1 while the listener's Cloudflare IP filter has ranges to check (0: accepting all).",
                &["listener"]
            ),
            token_verify: counter!(
                "mg_token_verify_total",
                "Clearance cookie verifications by result (none, valid, expired, invalid, binding_mismatch).",
                &["result"]
            ),
            crawler_verify: counter!(
                "mg_crawler_verify_total",
                "Settled crawler verifications by method (ip_range, rdns) and result (pass, fail, unverifiable).",
                &["method", "result"]
            ),
            cf_vbot_disagree: counter!(
                "mg_cf_vbot_disagree_total",
                "Requests where MorphGate's crawler verification and Cloudflare's verified-bot flag disagree.",
                &["direction"]
            ),
            rdns_lookups: counter!(
                "mg_rdns_lookups_total",
                "Reverse-DNS verification jobs by result (pass, fail, dns_error, dropped).",
                &["result"]
            ),
            ratelimit_exceeded: counter!(
                "mg_ratelimit_exceeded_total",
                "Requests over a rate limiter (dry-run limiters included).",
                &["limiter"]
            ),
            policy_step_limit: counter!(
                "mg_policy_step_limit_total",
                "Policy rules aborted by the runtime evaluation step limit (should stay 0).",
                &["site"]
            ),
            decision_latency: register_histogram_vec!(
                "mg_decision_latency_seconds",
                "Decision Core evaluation time per request.",
                &["site"],
                LATENCY_BUCKETS.to_vec()
            )
            .expect("register mg_decision_latency_seconds"),
            challenge: counter!(
                "mg_challenge_total",
                "Challenges issued and /__mg/c submissions by type, provider and result (issued, solved, failed, expired).",
                &["type", "provider", "result"]
            ),
            https_redirect: counter!(
                "mg_https_redirect_total",
                "http visitors redirected to https instead of being challenged (D-32).",
                &["site"]
            ),
            requests_total: counter!(
                "mg_requests_total",
                "Requests that reached the decision step, by site, environment, route, decided action (before execution) and bot class.",
                &["site", "env", "route", "action", "class"]
            ),
            edge_added_latency: register_histogram_vec!(
                "mg_edge_added_latency_seconds",
                "Time the Edge itself adds to a request: request_filter (Valkey round trip, Decision Core, /__mg bodies included), upstream_peer, upstream_request_filter and the response filters; never the origin connection or response.",
                &["site"],
                LATENCY_BUCKETS.to_vec()
            )
            .expect("register mg_edge_added_latency_seconds"),
            origin_connect: register_histogram_vec!(
                "mg_origin_connect_seconds",
                "Time from choosing the origin to a new origin connection being established (reused connections are not observed).",
                &["site"],
                LATENCY_BUCKETS.to_vec()
            )
            .expect("register mg_origin_connect_seconds"),
        }
    }

    /// Creates the per-site series (at 0) of the families the §17 alerts
    /// and the monitor week read.
    pub fn init_site(&self, site: &str) {
        for c in [
            &self.cf_connecting_ip_missing,
            &self.cf_foreign_worker,
            &self.site_unavailable,
            &self.policy_step_limit,
            &self.https_redirect,
        ] {
            c.with_label_values(&[site]);
        }
        for h in [
            &self.decision_latency,
            &self.edge_added_latency,
            &self.origin_connect,
        ] {
            h.with_label_values(&[site]);
        }
    }

    /// Creates the per-listener series (at 0): unknown hosts, rejected
    /// sites, the protocol rejections, the upstream authentication failures
    /// this listener can have (`bad_secret_header` only with upstream keys),
    /// stripped upstream headers (`direct_tls`) and, for a listener without
    /// a Cloudflare IP filter, `mg_cf_ip_filter_active` (0: accepting all).
    pub fn init_listener(
        &self,
        listener: &str,
        profile: &str,
        auth: ListenerAuth,
        keys: bool,
        ip_filter: bool,
        sites: &[&str],
    ) {
        self.unknown_host.with_label_values(&[listener]);
        for site in sites {
            self.listener_rejected.with_label_values(&[listener, site]);
        }
        if auth == ListenerAuth::None {
            self.upstream_headers_stripped.with_label_values(&[profile]);
        }
        if !ip_filter {
            self.cf_ip_filter_active
                .with_label_values(&[listener])
                .set(0);
        }
        for reason in ["uri_too_long", "header_too_large", "bad_method", "bad_host"] {
            self.protocol_rejected
                .with_label_values(&[listener, reason]);
        }
        let transport = match auth {
            ListenerAuth::Loopback => Some("non_loopback_peer"),
            ListenerAuth::OriginMtls => Some("untrusted_ca"),
            ListenerAuth::None => None,
        };
        for reason in transport
            .into_iter()
            .chain(keys.then_some("bad_secret_header"))
        {
            self.upstream_auth_failures
                .with_label_values(&[listener, profile, reason]);
        }
    }

    /// Creates the series with a fixed label set (at 0): request errors per
    /// route kind, token results, crawler and rDNS results, verified-bot
    /// disagreements, and the Phase 1 challenge types and results.
    pub fn init_static(&self) {
        for kind in [RouteKind::Healthz, RouteKind::Submit, RouteKind::Origin] {
            self.errors.with_label_values(&[kind.metric_label()]);
        }
        for result in ["none", "valid", "expired", "invalid", "binding_mismatch"] {
            self.token_verify.with_label_values(&[result]);
        }
        for result in ["pass", "fail", "dns_error", "dropped"] {
            self.rdns_lookups.with_label_values(&[result]);
        }
        for (method, result) in [
            ("ip_range", "pass"),
            ("ip_range", "fail"),
            ("rdns", "pass"),
            ("rdns", "fail"),
            ("rdns", "unverifiable"),
        ] {
            self.crawler_verify.with_label_values(&[method, result]);
        }
        for direction in ["mg_pass_cf_false", "mg_fail_cf_true"] {
            self.cf_vbot_disagree.with_label_values(&[direction]);
        }
        for ty in [ChallengeType::Invisible, ChallengeType::Pow] {
            for result in ["issued", "solved", "failed", "expired"] {
                self.challenge.with_label_values(&[
                    ty.as_str(),
                    crate::challenge::PROVIDER_NONE,
                    result,
                ]);
            }
        }
    }

    /// Records the Edge's own time and, for a new origin connection, the
    /// connect time of one request of `site` (§13.7).
    pub fn observe_timing(&self, site: &str, t: &Timing) {
        self.edge_added_latency
            .with_label_values(&[site])
            .observe(t.edge.as_secs_f64());
        if let Some(connect) = t.origin_connect {
            self.origin_connect
                .with_label_values(&[site])
                .observe(connect.as_secs_f64());
        }
    }

    /// Records one finished request. `status` is `None` if no response header was sent.
    pub fn observe_request(
        &self,
        route: RouteKind,
        status: Option<u16>,
        elapsed: Duration,
        failed: bool,
    ) {
        let route = route.metric_label();
        self.requests
            .with_label_values(&[route, status_class(status)])
            .inc();
        self.duration
            .with_label_values(&[route])
            .observe(elapsed.as_secs_f64());
        if failed {
            self.errors.with_label_values(&[route]).inc();
        }
    }

    /// Counts an Edge-internal failure (e.g. the RNG, §9.9) under `route`.
    pub fn internal_error(&self, route: RouteKind) {
        self.errors.with_label_values(&[route.metric_label()]).inc();
    }

    /// Publishes `mg_edge_info`.
    pub fn set_info(&self, edge_id: &str) {
        self.info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), edge_id])
            .set(1);
    }

    /// Sets `mg_site_state{site}`: 1 for `state`, 0 for the other states.
    pub fn set_site_state(&self, site: &str, state: &str) {
        for s in SITE_STATES {
            self.site_state
                .with_label_values(&[site, s])
                .set(i64::from(s == state));
        }
    }
}

/// Per-request timing of the Edge's own work (§13.7), kept in the request
/// context and recorded once in `logging`.
///
/// `mg_edge_added_latency_seconds` is the sum of the hooks the Edge runs:
/// `request_filter` (all of it: the state round trip, the Decision Core,
/// reading a `/__mg/c` body, an Edge answer), `upstream_peer`,
/// `upstream_request_filter` and `response_filter` (the Edge has no body
/// filter). Pingora 0.9 connects to the origin (or takes a pooled
/// connection) between `upstream_peer` and `upstream_request_filter`, so
/// origin connect time is never part of it; `mg_origin_connect_seconds`
/// measures that gap for new connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timing {
    /// The Edge's own time so far.
    pub edge: Duration,
    /// When `upstream_peer` returned (start of the connect gap).
    pub peer_done: Option<std::time::Instant>,
    /// The connect gap of a new origin connection.
    pub origin_connect: Option<Duration>,
}

impl Timing {
    /// Adds the time since `started` to the Edge's own time.
    pub fn add_since(&mut self, started: std::time::Instant) {
        self.edge += started.elapsed();
    }

    /// Called from `connected_to_upstream`: a new connection's connect
    /// gap is recorded (the first one, should Pingora retry).
    pub fn connected(&mut self, reused: bool) {
        if reused || self.origin_connect.is_some() {
            return;
        }
        if let Some(done) = self.peer_done {
            self.origin_connect = Some(done.elapsed());
        }
    }
}

/// `2xx`, `3xx`, ... or `none`.
pub fn status_class(status: Option<u16>) -> &'static str {
    match status {
        Some(100..=199) => "1xx",
        Some(200..=299) => "2xx",
        Some(300..=399) => "3xx",
        Some(400..=499) => "4xx",
        Some(500..=599) => "5xx",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_prometheus::prometheus::{self, Encoder, TextEncoder};

    #[test]
    fn status_classes() {
        assert_eq!(status_class(Some(200)), "2xx");
        assert_eq!(status_class(Some(304)), "3xx");
        assert_eq!(status_class(Some(429)), "4xx");
        assert_eq!(status_class(Some(502)), "5xx");
        assert_eq!(status_class(Some(99)), "none");
        assert_eq!(status_class(None), "none");
    }

    #[test]
    fn families_are_exposed_in_the_default_registry() {
        let m = metrics();
        let before = m.requests.with_label_values(&["healthz", "2xx"]).get();
        m.observe_request(
            RouteKind::Healthz,
            Some(200),
            Duration::from_micros(300),
            false,
        );
        m.observe_request(RouteKind::Origin, None, Duration::from_millis(3), true);
        m.set_info("edge-1");
        m.set_site_state("blog", "bootstrap_open");
        m.set_site_state("blog", "active");
        m.protocol_rejected
            .with_label_values(&["cf-tunnel", "uri_too_long"])
            .inc();
        assert_eq!(
            m.requests.with_label_values(&["healthz", "2xx"]).get(),
            before + 1
        );

        let mut out = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("mg_edge_requests_total{route=\"healthz\",status=\"2xx\"}"));
        assert!(text.contains("mg_edge_request_errors_total{route=\"origin\"}"));
        assert!(text.contains("mg_edge_info{edge_id=\"edge-1\""));
        assert!(text.contains("mg_site_state{site=\"blog\",state=\"active\"} 1"));
        assert!(text.contains("mg_site_state{site=\"blog\",state=\"bootstrap_open\"} 0"));
        assert!(text.contains(
            "mg_protocol_rejected_total{listener=\"cf-tunnel\",reason=\"uri_too_long\"}"
        ));
    }
}
