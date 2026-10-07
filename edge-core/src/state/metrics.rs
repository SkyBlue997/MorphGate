//! State-layer metrics (spec §13.7), registered once in the default
//! prometheus registry that `pingora-prometheus` serves.
//!
//! A name that is already registered (a programming error elsewhere) does not
//! panic: the collector still works but is not exported, and a warning is
//! logged.

use std::sync::LazyLock;

use prometheus::core::Collector;
use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGaugeVec, Opts};

use super::StateMode;

/// Histogram buckets (seconds) shared by every Edge latency metric (§13.7).
pub(crate) const BUCKETS: &[f64] = &[
    0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
];

pub(crate) struct StateMetrics {
    /// `mg_valkey_rtt_seconds`: one observation per successful pipeline.
    pub valkey_rtt: Histogram,
    /// `mg_valkey_errors_total{op}`: `pipeline`, `script_load`, `stream`.
    pub valkey_errors: IntCounterVec,
    /// `mg_state_mode{mode}`: 1 for the current mode.
    pub mode: IntGaugeVec,
    /// `mg_state_local_overflow_total{table}`: `gcra`, `nonce`.
    pub local_overflow: IntCounterVec,
    /// `mg_state_async_dropped_total`.
    pub async_dropped: IntCounter,
    /// `mg_verdict_parse_errors_total`.
    pub verdict_parse_errors: IntCounter,
}

static METRICS: LazyLock<StateMetrics> = LazyLock::new(StateMetrics::register);

pub(crate) fn get() -> &'static StateMetrics {
    &METRICS
}

impl StateMetrics {
    fn register() -> Self {
        let m = Self {
            valkey_rtt: Histogram::with_opts(
                HistogramOpts::new(
                    "mg_valkey_rtt_seconds",
                    "Duration of each Valkey pipeline issued by the state layer.",
                )
                .buckets(BUCKETS.to_vec()),
            )
            .expect("static histogram options are valid"),
            valkey_errors: IntCounterVec::new(
                Opts::new(
                    "mg_valkey_errors_total",
                    "Failed Valkey operations (errors and timeouts), by operation.",
                ),
                &["op"],
            )
            .expect("static counter options are valid"),
            mode: IntGaugeVec::new(
                Opts::new(
                    "mg_state_mode",
                    "State layer mode: 1 for the current mode (valkey or local).",
                ),
                &["mode"],
            )
            .expect("static gauge options are valid"),
            local_overflow: IntCounterVec::new(
                Opts::new(
                    "mg_state_local_overflow_total",
                    "Local state table full: GCRA overflow-bucket use or nonce set unable to insert.",
                ),
                &["table"],
            )
            .expect("static counter options are valid"),
            async_dropped: IntCounter::new(
                "mg_state_async_dropped_total",
                "Challenge failure-count updates dropped because the async channel was full.",
            )
            .expect("static counter options are valid"),
            verdict_parse_errors: IntCounter::new(
                "mg_verdict_parse_errors_total",
                "Entity verdict values in Valkey that could not be parsed and were ignored.",
            )
            .expect("static counter options are valid"),
        };
        register(m.valkey_rtt.clone());
        register(m.valkey_errors.clone());
        register(m.mode.clone());
        register(m.local_overflow.clone());
        register(m.async_dropped.clone());
        register(m.verdict_parse_errors.clone());
        // Pre-create the bounded label values so they are exported as 0.
        for op in ["pipeline", "script_load", "stream"] {
            m.valkey_errors.with_label_values(&[op]);
        }
        for table in ["gcra", "nonce"] {
            m.local_overflow.with_label_values(&[table]);
        }
        m.set_mode(StateMode::Local);
        m
    }

    pub(crate) fn set_mode(&self, mode: StateMode) {
        for m in [StateMode::Valkey, StateMode::Local] {
            self.mode
                .with_label_values(&[m.as_str()])
                .set(i64::from(m == mode));
        }
    }

    pub(crate) fn overflow(&self, table: &'static str) {
        self.local_overflow.with_label_values(&[table]).inc();
    }

    pub(crate) fn valkey_error(&self, op: &'static str) {
        self.valkey_errors.with_label_values(&[op]).inc();
    }
}

fn register<C: Collector + 'static>(c: C) {
    if let Err(e) = prometheus::register(Box::new(c)) {
        log::warn!("state: metric not registered: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_exported_with_bounded_labels() {
        let m = get();
        m.overflow("gcra");
        m.valkey_error("stream");
        let names: Vec<String> = prometheus::gather()
            .iter()
            .map(|f| f.name().to_owned())
            .collect();
        for n in [
            "mg_valkey_rtt_seconds",
            "mg_valkey_errors_total",
            "mg_state_mode",
            "mg_state_local_overflow_total",
            "mg_state_async_dropped_total",
            "mg_verdict_parse_errors_total",
        ] {
            assert!(names.iter().any(|x| x == n), "{n} not exported");
        }
    }
}
