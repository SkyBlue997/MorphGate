//! Prometheus metrics, served by `pingora-prometheus` on `metrics_listen`
//! and scraped by VictoriaMetrics.
//!
//! Labels are kept low-cardinality (route kind and status class only); per-site
//! and per-rule breakdowns belong in the DecisionEvent log, not in metrics.

use crate::routes::RouteKind;
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

/// The Edge's metric families, registered once in the default registry.
#[derive(Debug)]
pub struct EdgeMetrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    errors: IntCounterVec,
    info: IntGaugeVec,
}

static METRICS: LazyLock<EdgeMetrics> = LazyLock::new(EdgeMetrics::register);

/// Process-wide metrics.
pub fn metrics() -> &'static EdgeMetrics {
    &METRICS
}

impl EdgeMetrics {
    fn register() -> Self {
        // Registration only fails on duplicate names, i.e. a programming error.
        Self {
            requests: register_int_counter_vec!(
                "mg_edge_requests_total",
                "Requests handled by the Edge, by route kind and response status class.",
                &["route", "status"]
            )
            .expect("register mg_edge_requests_total"),
            duration: register_histogram_vec!(
                "mg_edge_request_duration_seconds",
                "Time from request start to completion, including the origin, by route kind.",
                &["route"],
                DURATION_BUCKETS.to_vec()
            )
            .expect("register mg_edge_request_duration_seconds"),
            errors: register_int_counter_vec!(
                "mg_edge_request_errors_total",
                "Requests that ended with a proxy error (origin unreachable, client abort, ...).",
                &["route"]
            )
            .expect("register mg_edge_request_errors_total"),
            info: register_int_gauge_vec!(
                "mg_edge_info",
                "Constant 1, labelled with build and configuration facts.",
                &["version", "site_id", "upstream_profile"]
            )
            .expect("register mg_edge_info"),
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

    /// Publishes `mg_edge_info`.
    pub fn set_info(&self, site_id: &str, upstream_profile: &str) {
        self.info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), site_id, upstream_profile])
            .set(1);
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
    fn counters_are_exposed_in_default_registry() {
        let m = metrics();
        let before = m.requests.with_label_values(&["healthz", "2xx"]).get();
        m.observe_request(
            RouteKind::Healthz,
            Some(200),
            Duration::from_micros(300),
            false,
        );
        m.observe_request(RouteKind::Origin, None, Duration::from_millis(3), true);
        m.set_info("blog", "cloudflare");
        assert_eq!(
            m.requests.with_label_values(&["healthz", "2xx"]).get(),
            before + 1
        );

        // Same path pingora-prometheus takes when serving /metrics.
        let mut out = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("mg_edge_requests_total{route=\"healthz\",status=\"2xx\"}"));
        assert!(text.contains("mg_edge_request_errors_total{route=\"origin\"}"));
        assert!(text.contains("mg_edge_request_duration_seconds_bucket"));
        assert!(text.contains("site_id=\"blog\""));
    }
}
