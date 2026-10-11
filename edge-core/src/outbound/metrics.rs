//! Outbound and provider metrics (spec §15.5), registered once in the default
//! prometheus registry that mg-edge serves. A name that is already registered
//! does not panic: the collector still works but is not exported, and a
//! warning is logged.

use super::url::SiteverifyUrl;
use prometheus::core::Collector;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};
use std::sync::LazyLock;

/// Buckets of `mg_provider_verify_latency_seconds` (spec §15.5).
pub(crate) const LATENCY_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0];

pub(crate) struct OutboundMetrics {
    /// `mg_provider_verify_total{provider, outcome, reason}`.
    pub verify_total: IntCounterVec,
    /// `mg_provider_verify_latency_seconds{provider}`.
    pub verify_latency: HistogramVec,
    /// `mg_provider_state{site, provider, state}`.
    pub provider_state: IntGaugeVec,
    /// `mg_outbound_override{target}`.
    pub outbound_override: IntGaugeVec,
}

static METRICS: LazyLock<OutboundMetrics> = LazyLock::new(OutboundMetrics::register);

pub(crate) fn get() -> &'static OutboundMetrics {
    &METRICS
}

impl OutboundMetrics {
    fn register() -> Self {
        let m = Self {
            verify_total: IntCounterVec::new(
                Opts::new(
                    "mg_provider_verify_total",
                    "External provider verifications, by provider, outcome and reason.",
                ),
                &["provider", "outcome", "reason"],
            )
            .expect("static counter options are valid"),
            verify_latency: HistogramVec::new(
                HistogramOpts::new(
                    "mg_provider_verify_latency_seconds",
                    "Duration of external provider verifications, retries included.",
                )
                .buckets(LATENCY_BUCKETS.to_vec()),
                &["provider"],
            )
            .expect("static histogram options are valid"),
            provider_state: IntGaugeVec::new(
                Opts::new(
                    "mg_provider_state",
                    "External provider health: 1 for the current state (healthy, open, half_open, disabled).",
                ),
                &["site", "provider", "state"],
            )
            .expect("static gauge options are valid"),
            outbound_override: IntGaugeVec::new(
                Opts::new(
                    "mg_outbound_override",
                    "1 while a non-default (loopback test) outbound destination is in effect.",
                ),
                &["target"],
            )
            .expect("static gauge options are valid"),
        };
        register(m.verify_total.clone());
        register(m.verify_latency.clone());
        register(m.provider_state.clone());
        register(m.outbound_override.clone());
        m.outbound_override
            .with_label_values(&["siteverify"])
            .set(0);
        m
    }
}

fn register<C: Collector + 'static>(c: C) {
    if let Err(e) = prometheus::register(Box::new(c)) {
        log::warn!("outbound: metric not registered: {e}");
    }
}

/// Publishes the effective siteverify destination: sets
/// `mg_outbound_override{target="siteverify"}` to 1 for a loopback test URL
/// (0 otherwise) and logs a WARN for it. mg-edge calls it on every
/// configuration load (spec §8.4).
pub fn report_siteverify_url(url: &SiteverifyUrl) {
    get()
        .outbound_override
        .with_label_values(&["siteverify"])
        .set(i64::from(url.is_override()));
    if url.is_override() {
        log::warn!(
            "outbound: Turnstile siteverify goes to the test destination {url} (MG_EDGE_TEST_OUTBOUND=1); never use this in production"
        );
    }
}
