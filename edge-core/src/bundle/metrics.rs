//! Bundle metrics (§9.10, §13.7), registered once in the default Prometheus
//! registry that `pingora-prometheus` serves on `metrics_listen`.
//!
//! The poll loop updates all of them; mg-edge sets the start-up values
//! (`mg_config_version` and `mg_artifact_missing` for a site loaded from its
//! LKG) through the same handles. `mg_site_state` belongs to mg-edge's site
//! state machine.

use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Opts};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Instant;

/// Handles of the bundle metric families. Labels are bounded: `site` comes
/// from edge.toml, `name` from the fixed artifact list, `result` from
/// `applied` / `rejected` / `unchanged`.
#[derive(Debug)]
pub struct BundleMetrics {
    /// `mg_config_version{site}`: version in effect; 0 in bootstrap and
    /// lkg_invalid.
    pub config_version: IntGaugeVec,
    /// `mg_config_age_seconds{site}`: seconds since the last successful fetch
    /// (200 or 304); since the poll loop started if none succeeded yet.
    /// Computed when scraped (§9.10 `now − last_fetch_ok`), so it keeps
    /// growing even if a poll loop stalls or dies.
    pub config_age_seconds: ConfigAge,
    /// `mg_config_reload_total{site, result}`.
    pub config_reload_total: IntCounterVec,
    /// `mg_config_fetch_failures_total{site}`: bundle or artifact fetches that
    /// failed on the network or file system.
    pub config_fetch_failures_total: IntCounterVec,
    /// `mg_artifact_missing{site, name}`: 1 while an artifact of the bundle
    /// in effect is not in the cache.
    pub artifact_missing: IntGaugeVec,
}

static METRICS: LazyLock<BundleMetrics> = LazyLock::new(BundleMetrics::register);

/// Process-wide bundle metrics.
pub fn metrics() -> &'static BundleMetrics {
    &METRICS
}

impl BundleMetrics {
    fn register() -> Self {
        // Constructors only fail on malformed names or labels, which are
        // constants here.
        let m = Self {
            config_version: IntGaugeVec::new(
                Opts::new(
                    "mg_config_version",
                    "Bundle version in effect per site (0: none).",
                ),
                &["site"],
            )
            .expect("valid metric mg_config_version"),
            config_age_seconds: ConfigAge {
                gauge: GaugeVec::new(
                    Opts::new(
                        "mg_config_age_seconds",
                        "Seconds since the last successful bundle fetch (200 or 304) per site.",
                    ),
                    &["site"],
                )
                .expect("valid metric mg_config_age_seconds"),
                last_ok: Arc::default(),
            },
            config_reload_total: IntCounterVec::new(
                Opts::new(
                    "mg_config_reload_total",
                    "Bundle poll outcomes per site: applied, rejected or unchanged.",
                ),
                &["site", "result"],
            )
            .expect("valid metric mg_config_reload_total"),
            config_fetch_failures_total: IntCounterVec::new(
                Opts::new(
                    "mg_config_fetch_failures_total",
                    "Bundle and artifact fetches that failed per site.",
                ),
                &["site"],
            )
            .expect("valid metric mg_config_fetch_failures_total"),
            artifact_missing: IntGaugeVec::new(
                Opts::new(
                    "mg_artifact_missing",
                    "1 while an artifact of the bundle in effect is missing from the cache.",
                ),
                &["site", "name"],
            )
            .expect("valid metric mg_artifact_missing"),
        };
        let collectors: [Box<dyn prometheus::core::Collector>; 5] = [
            Box::new(m.config_version.clone()),
            Box::new(m.config_age_seconds.clone()),
            Box::new(m.config_reload_total.clone()),
            Box::new(m.config_fetch_failures_total.clone()),
            Box::new(m.artifact_missing.clone()),
        ];
        for c in collectors {
            // Only a duplicate name can fail; the handles still work, they
            // are just not exported, so say so instead of panicking.
            if let Err(e) = prometheus::register(c) {
                log::error!("bundle metrics: registration failed: {e}");
            }
        }
        m
    }
}

/// `mg_config_age_seconds{site}`: the time of the last successful fetch per
/// site; the gauge values are `now − last_fetch_ok`, refreshed on every
/// scrape (the registry calls [`Collector::collect`]).
#[derive(Debug, Clone)]
pub struct ConfigAge {
    gauge: GaugeVec,
    last_ok: Arc<Mutex<BTreeMap<String, Instant>>>,
}

impl ConfigAge {
    /// Records a successful fetch (or the start of the poll loop) for `site`.
    pub fn mark(&self, site: &str) {
        self.map().insert(site.to_string(), Instant::now());
    }

    /// Current age in seconds, `None` for a site without a poll loop.
    pub fn get(&self, site: &str) -> Option<f64> {
        self.map().get(site).map(|t| t.elapsed().as_secs_f64())
    }

    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Instant>> {
        // The map holds plain timestamps: a panic elsewhere cannot leave it
        // inconsistent, so a poisoned lock is still usable.
        self.last_ok.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Collector for ConfigAge {
    fn desc(&self) -> Vec<&Desc> {
        self.gauge.desc()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        for (site, t) in self.map().iter() {
            self.gauge
                .with_label_values(&[site.as_str()])
                .set(t.elapsed().as_secs_f64());
        }
        self.gauge.collect()
    }
}
