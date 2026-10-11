//! The `[events]` table of `edge.toml` v1 (spec §8.1).

use super::EventsError;
use super::vl::endpoint_url;
use serde::Deserialize;
use std::path::PathBuf;

/// `edge.toml` `[events]` (spec §8.1). Every key is optional; missing keys take
/// the documented defaults, unknown keys are an error (`deny_unknown_fields`),
/// so mg-edge (WP-E1a) can embed this type directly in its config struct.
///
/// Deserialization only checks types; call [`EventsConfig::validate`] (as
/// `mg-edge --check-config` does) for the ranges and URL rules.
/// [`super::EventQueues::new`] never panics on an unvalidated value: it clamps
/// zero capacities and limits to 1.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// `vl-main` base URL (`http://host:9428`); absent = no vl-main sink.
    pub vl_main: Option<String>,
    /// `vl-short` base URL; absent = no vl-short sink.
    pub vl_short: Option<String>,
    /// Optional JSONL file sink (tests, the Lab); every line of both sinks.
    pub file: Option<PathBuf>,
    /// Each output flushes at least this often (ms).
    pub flush_interval_ms: u64,
    /// An output flushes as soon as it holds this many records; also the
    /// per-batch cap.
    pub max_batch_lines: usize,
    /// An output flushes as soon as it holds this many line bytes; also the
    /// per-batch cap.
    pub max_batch_bytes: usize,
    /// P0 capacity (non-allow decisions, feedback): of the request queue and
    /// of each output's backlog (ruling I-25).
    pub queue_priority: usize,
    /// P1 capacity (`kind=access`), as `queue_priority`.
    pub queue_access: usize,
    /// P2 capacity (sampled allow decisions, telemetry), as `queue_priority`.
    pub queue_sampled: usize,
    /// `XADD mg:ev MAXLEN ~ <stream_maxlen>`.
    pub stream_maxlen: u64,
    /// Phase 2 (docs/impl/phase2-spec.md §9.7, §10.1): how long the flusher
    /// keeps accepting and delivering events after the shutdown signal,
    /// before the Phase 1 final flush. `None` (absent): mg-edge computes
    /// `min(2000, max(0, grace_period_seconds * 1000 - 1000))` and checks a
    /// set value against `[server]` (`EdgeConfig::validate`, WP-E2b);
    /// [`EventsConfig::validate`] only checks `0..=10000`. The flusher uses
    /// [`EventsConfig::shutdown_drain`].
    pub shutdown_drain_ms: Option<u64>,
    /// Phase 2 (§9.4, §10.1): capacity of the `kind=telemetry` queue of
    /// `POST /__mg/t` ([`super::EventClass::Telemetry`]); when it is full
    /// only telemetry is dropped.
    pub queue_telemetry: usize,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            vl_main: None,
            vl_short: None,
            file: None,
            flush_interval_ms: 1000,
            max_batch_lines: 1000,
            max_batch_bytes: 1_048_576,
            queue_priority: 8192,
            queue_access: 16384,
            queue_sampled: 8192,
            stream_maxlen: 300_000,
            shutdown_drain_ms: None,
            queue_telemetry: 2048,
        }
    }
}

/// Inclusive bounds enforced by [`EventsConfig::validate`]. They are sanity
/// limits (no zero-capacity queue, no unbounded batch), not tuning advice.
const FLUSH_INTERVAL_MS: (u64, u64) = (10, 60_000);
const BATCH_LINES: (usize, usize) = (1, 100_000);
const BATCH_BYTES: (usize, usize) = (1024, 64 * 1024 * 1024);
const QUEUE_CAPACITY: (usize, usize) = (1, 1 << 20);
const STREAM_MAXLEN: (u64, u64) = (1, 100_000_000);
/// Phase 2 spec §10.1.
const SHUTDOWN_DRAIN_MS: (u64, u64) = (0, 10_000);
/// Phase 2 spec §10.1.
const QUEUE_TELEMETRY: (usize, usize) = (64, 65_536);

impl EventsConfig {
    /// The shutdown drain the flusher applies: `shutdown_drain_ms`, or zero
    /// (the Phase 1 behaviour) while it is absent, i.e. until mg-edge has
    /// resolved its default from the grace period (Phase 2 spec §10.1).
    /// Clamped to the `0..=10000` range.
    pub fn shutdown_drain(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.shutdown_drain_ms.unwrap_or(0).min(SHUTDOWN_DRAIN_MS.1),
        )
    }

    /// Checks every value; the error names the first offending key.
    pub fn validate(&self) -> Result<(), EventsError> {
        if let Some(ms) = self.shutdown_drain_ms {
            in_range("shutdown_drain_ms", ms, SHUTDOWN_DRAIN_MS)?;
        }
        in_range("queue_telemetry", self.queue_telemetry, QUEUE_TELEMETRY)?;
        in_range(
            "flush_interval_ms",
            self.flush_interval_ms,
            FLUSH_INTERVAL_MS,
        )?;
        in_range("max_batch_lines", self.max_batch_lines, BATCH_LINES)?;
        in_range("max_batch_bytes", self.max_batch_bytes, BATCH_BYTES)?;
        in_range("queue_priority", self.queue_priority, QUEUE_CAPACITY)?;
        in_range("queue_access", self.queue_access, QUEUE_CAPACITY)?;
        in_range("queue_sampled", self.queue_sampled, QUEUE_CAPACITY)?;
        in_range("stream_maxlen", self.stream_maxlen, STREAM_MAXLEN)?;
        for (key, url) in [("vl_main", &self.vl_main), ("vl_short", &self.vl_short)] {
            if let Some(url) = url {
                endpoint_url(url).map_err(|e| EventsError::Config(format!("{key}: {e}")))?;
            }
        }
        if let Some(file) = &self.file
            && file.as_os_str().is_empty()
        {
            return Err(EventsError::Config("file: empty path".into()));
        }
        Ok(())
    }
}

fn in_range<T: PartialOrd + std::fmt::Display + Copy>(
    key: &str,
    value: T,
    (min, max): (T, T),
) -> Result<(), EventsError> {
    if value < min || value > max {
        return Err(EventsError::Config(format!(
            "{key} = {value} is outside {min}..={max}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec_8_1() {
        let cfg = EventsConfig::default();
        assert_eq!(cfg.flush_interval_ms, 1000);
        assert_eq!(cfg.max_batch_lines, 1000);
        assert_eq!(cfg.max_batch_bytes, 1_048_576);
        assert_eq!(cfg.queue_priority, 8192);
        assert_eq!(cfg.queue_access, 16384);
        assert_eq!(cfg.queue_sampled, 8192);
        assert_eq!(cfg.stream_maxlen, 300_000);
        assert!(cfg.vl_main.is_none() && cfg.vl_short.is_none() && cfg.file.is_none());
        cfg.validate().unwrap();
    }

    #[test]
    fn deserializes_with_defaults_and_rejects_unknown_keys() {
        let cfg: EventsConfig =
            serde_json::from_str(r#"{"vl_main": "http://10.0.0.5:9428", "max_batch_lines": 10}"#)
                .unwrap();
        assert_eq!(cfg.vl_main.as_deref(), Some("http://10.0.0.5:9428"));
        assert_eq!(cfg.max_batch_lines, 10);
        assert_eq!(cfg.queue_access, 16384);
        cfg.validate().unwrap();

        let err = serde_json::from_str::<EventsConfig>(r#"{"vl_mian": "http://x"}"#);
        assert!(err.is_err(), "unknown key must be rejected");
    }

    type Mutation = fn(&mut EventsConfig);

    #[test]
    fn validate_rejects_out_of_range_values() {
        let cases: [(&str, Mutation); 11] = [
            ("shutdown_drain_ms", |c| c.shutdown_drain_ms = Some(10_001)),
            ("queue_telemetry", |c| c.queue_telemetry = 63),
            ("queue_telemetry", |c| c.queue_telemetry = 65_537),
            ("flush_interval_ms", |c| c.flush_interval_ms = 0),
            ("max_batch_lines", |c| c.max_batch_lines = 0),
            ("max_batch_bytes", |c| c.max_batch_bytes = 10),
            ("queue_priority", |c| c.queue_priority = 0),
            ("queue_access", |c| c.queue_access = 0),
            ("queue_sampled", |c| c.queue_sampled = usize::MAX),
            ("stream_maxlen", |c| c.stream_maxlen = 0),
            ("file", |c| c.file = Some(PathBuf::new())),
        ];
        for (key, mutate) in cases {
            let mut cfg = EventsConfig::default();
            mutate(&mut cfg);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    /// Phase 2 §10.1: the new keys, their defaults and bounds.
    #[test]
    fn phase2_keys() {
        let cfg = EventsConfig::default();
        assert_eq!(cfg.shutdown_drain_ms, None);
        assert_eq!(cfg.queue_telemetry, 2048);
        assert_eq!(cfg.shutdown_drain(), std::time::Duration::ZERO);
        let cfg: EventsConfig =
            serde_json::from_str(r#"{"shutdown_drain_ms": 0, "queue_telemetry": 64}"#).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.shutdown_drain_ms, Some(0));
        for (ms, ok) in [(0, true), (1500, true), (10_000, true), (10_001, false)] {
            let cfg = EventsConfig {
                shutdown_drain_ms: Some(ms),
                ..EventsConfig::default()
            };
            assert_eq!(cfg.validate().is_ok(), ok, "{ms}");
        }
        let cfg = EventsConfig {
            shutdown_drain_ms: Some(1500),
            ..EventsConfig::default()
        };
        assert_eq!(cfg.shutdown_drain(), std::time::Duration::from_millis(1500));
        let cfg = EventsConfig {
            shutdown_drain_ms: Some(u64::MAX),
            ..EventsConfig::default()
        };
        assert_eq!(cfg.shutdown_drain(), std::time::Duration::from_secs(10));
        for (n, ok) in [(63, false), (64, true), (65_536, true), (65_537, false)] {
            let cfg = EventsConfig {
                queue_telemetry: n,
                ..EventsConfig::default()
            };
            assert_eq!(cfg.validate().is_ok(), ok, "{n}");
        }
    }

    #[test]
    fn validate_checks_vl_urls() {
        for bad in [
            "ftp://10.0.0.5:9428",
            "not a url",
            "http://user:pw@10.0.0.5:9428",
            "http://10.0.0.5:9428/?x=1",
            "http://10.0.0.5:9428/#frag",
        ] {
            let cfg = EventsConfig {
                vl_short: Some(bad.into()),
                ..EventsConfig::default()
            };
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("vl_short"), "{bad}: {err}");
        }
        for good in [
            "http://10.0.0.5:9428",
            "https://vl.internal/",
            "http://[::1]:9428/vl",
        ] {
            let cfg = EventsConfig {
                vl_main: Some(good.into()),
                ..EventsConfig::default()
            };
            cfg.validate().unwrap();
        }
    }
}
