//! Event sinks (spec §9.11, §13): three bounded priority queues, VictoriaLogs
//! `/insert/jsonline` batches with retries, the JSONL file sink and `mg:ev`
//! stream entries.
//!
//! Implemented by work package WP-C4 (docs/impl/phase1-spec.md §15) and
//! reworked by WP-E1d for ruling I-25 (independent outputs); mg-edge (WP-E1d)
//! assembles the individual events and wires the flusher into the
//! `mg-events` background service (§9.1.1).
//!
//! # Data flow
//!
//! ```text
//! proxy (request path)                  mg-events background service
//!
//! EventRecord                                           ┌─> vl_main backlog ──> flush loop ─> vl_main  (§13.1)
//!   ─try_send─> P0 / P1 / P2 queues ─> dispatcher ──────┼─> vl_short backlog ─> flush loop ─> vl_short (§13.1)
//!   (never blocks; full: drop + count)  (P0 first)      ├─> file backlog ─────> flush loop ─> JSONL file (optional)
//!                                                       └─> mg:ev backlog ────> flush loop ─> StreamWriter: XADD mg:ev (§13.6)
//! ```
//!
//! * [`EventQueues`] is the request-path handle ([`EventSink`]); it only does
//!   a bounded `try_send`, so writing an event never blocks a request.
//!   Everything it needs is runtime-free, so it can be created in `main()`
//!   before Pingora daemonizes (§9.1.1).
//! * [`Flusher::run`] moves every record at once into a bounded backlog per
//!   output, and each output (each VictoriaLogs instance, the file, `mg:ev`)
//!   runs its own flush loop over its own backlog (ruling I-25): a
//!   VictoriaLogs outage never slows the file or the stream, a `vl_short`
//!   outage never slows `vl_main`, and vice versa. Each loop sends
//!   every `flush_interval_ms`, or as soon as `max_batch_lines` /
//!   `max_batch_bytes` are pending, in P0, P1, P2 order. It must run on the
//!   `mg-events` service's runtime, and the [`VlClient`] must be built there
//!   as well.
//! * Lost records are counted in `mg_event_dropped_total{sink, class}`
//!   ([`EventMetrics`]): a full request queue (`buffer`); and per output
//!   (`victorialogs`, `file`, `stream`) a refusal, exhausted retries or a
//!   failed write, a full backlog, or a record still held when the shutdown
//!   budget ran out. The one blind spot is a file append or `XADD` already
//!   in progress when shutdown interrupts it.
//! * [`envelope`], [`StreamEntry`], [`TelemetryEnv`] / [`TelemetryAuto`] and
//!   the sampling / redaction helpers are the pure encodings E1d uses to build
//!   the records. `StateHandle` implements [`StreamWriter`] (one pipelined
//!   `XADD` batch on the `mg-state` runtime).
//!
//! # Privacy (D-31, §2.4)
//!
//! Event lines carry request data (the decision context), so neither
//! [`EventRecord`]'s `Debug` output nor any log message written here contains
//! a line's content; logs only mention sinks, counts and HTTP status codes.

mod config;
mod encode;
mod output;
mod queue;
mod stream;
mod telemetry;
mod vl;

use std::fmt;

pub use config::EventsConfig;
pub use encode::{
    ACCESS_PATH_MAX_BYTES, SampleInputs, access_path, decision_sample_rate, envelope,
    redacted_path, sample_keep, sampling_exempt,
};
pub use queue::{DropSink, EventMetrics, EventQueues, FINAL_FLUSH_BUDGET, Flusher};
pub use stream::{
    DecisionEntry, FeedbackEntry, STREAM_ENTRY_VERSION, STREAM_KEY, StreamEntry, StreamWriter,
};
pub use telemetry::{
    AUTOMATION_SCHEMA_VERSION, Brand, ENV_SCHEMA_VERSION, TELEMETRY_MAX_ARRAY_ITEMS,
    TELEMETRY_MAX_INPUT_BYTES, TELEMETRY_MAX_STRING_BYTES, TelemetryAuto, TelemetryEnv,
    TelemetryScreen, TelemetryStorage, TelemetryTouch, TelemetryUa, TelemetryViewport,
};
pub use vl::{
    JSONLINE_CONTENT_TYPE, JSONLINE_PATH, JSONLINE_QUERY, PostOutcome, REQUEST_TIMEOUT,
    RETRY_BACKOFF, USER_AGENT, VlClient, VlOptions,
};

/// Queue class of an event record (§9.11). Each class has its own bounded
/// request queue and, in every output, its own bounded backlog; batches
/// always take P0 before P1 before P2, so a flood of sampled allow decisions
/// can never displace enforcement or feedback events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventClass {
    /// P0: non-allow decisions, `kind=feedback`, anything that must survive.
    Priority,
    /// P1: `kind=access` records.
    Access,
    /// P2: sampled allow decisions, `kind=telemetry`.
    Sampled,
}

impl EventClass {
    /// Every class in drain order (P0, P1, P2).
    pub const ALL: [EventClass; 3] = [Self::Priority, Self::Access, Self::Sampled];

    /// The `class` label of `mg_event_dropped_total`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Access => "access",
            Self::Sampled => "sampled",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Priority => 0,
            Self::Access => 1,
            Self::Sampled => 2,
        }
    }
}

impl fmt::Display for EventClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// VictoriaLogs instance a line is written to (§13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sink {
    /// `vl-main` (30 d): decision, feedback and access records.
    Main,
    /// `vl-short` (7 d): telemetry.
    Short,
}

impl Sink {
    /// The `edge.toml` key of the sink's URL (`vl_main` / `vl_short`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "vl_main",
            Self::Short => "vl_short",
        }
    }
}

impl fmt::Display for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One record handed to an [`EventSink`] (§9.11).
///
/// * `line` is one complete JSON object (normally produced by [`envelope`])
///   without a trailing newline. It is written to `target` and to the file
///   sink. A line containing `\n` or `\r` would break the JSONL framing and is
///   rejected by [`EventQueues`].
/// * An **empty** `line` marks a stream-only record: a request whose decision
///   event was sampled out still gets its `mg:ev` entry, which is written
///   unsampled (§13.6).
/// * `stream` is the request's `mg:ev` entry, if `events.stream` is on.
#[derive(Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub class: EventClass,
    pub target: Sink,
    pub line: String,
    pub stream: Option<StreamEntry>,
}

impl EventRecord {
    /// A record with a log line and no stream entry.
    pub fn new(class: EventClass, target: Sink, line: String) -> Self {
        Self {
            class,
            target,
            line,
            stream: None,
        }
    }

    /// A record that only carries an `mg:ev` entry (no log line).
    pub fn stream_only(class: EventClass, entry: StreamEntry) -> Self {
        Self {
            class,
            target: Sink::Main,
            line: String::new(),
            stream: Some(entry),
        }
    }

    /// Attaches the request's `mg:ev` entry.
    #[must_use]
    pub fn with_stream(mut self, entry: StreamEntry) -> Self {
        self.stream = Some(entry);
        self
    }

    /// Bytes the line occupies in a `jsonline` body (line plus `\n`); 0 for a
    /// stream-only record. This is what `max_batch_bytes` counts.
    pub fn wire_len(&self) -> usize {
        if self.line.is_empty() {
            0
        } else {
            self.line.len() + 1
        }
    }
}

/// Never prints the line: it carries request data (client IP, path, …).
impl fmt::Debug for EventRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventRecord")
            .field("class", &self.class)
            .field("target", &self.target)
            .field("line_len", &self.line.len())
            .field("stream", &self.stream.as_ref().map(StreamEntry::kind))
            .finish()
    }
}

/// Request-path entry point of the event pipeline (§9.11).
pub trait EventSink: Send + Sync {
    /// Never blocks; returns false (and counts a drop) when the class queue is full.
    fn try_send(&self, record: EventRecord) -> bool;
}

/// Configuration and client construction errors. Delivery failures are not
/// errors: they are counted in `mg_event_dropped_total` and logged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventsError {
    /// An `[events]` value is out of range or malformed.
    #[error("events config: {0}")]
    Config(String),
    /// The HTTP client could not be built.
    #[error("events http client: {0}")]
    Client(String),
}
