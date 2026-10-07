//! The request-path event queues, the drop counters and the flusher that
//! dispatches records to the outputs (spec §9.11, ruling I-25).

use super::output::{Item, Lane, Limits, Output};
use super::stream::StreamWriter;
use super::vl::VlClient;
use super::{EventClass, EventRecord, EventSink, EventsConfig, Sink};
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// How long the outputs keep trying to deliver the remaining P0 records
/// after the shutdown signal (§9.1.1 item 4). The outputs finish
/// concurrently, so this bounds the whole shutdown flush.
pub const FINAL_FLUSH_BUDGET: Duration = Duration::from_secs(2);

/// Hard cap on a queue's capacity (tokio rejects absurd capacities by
/// panicking; `EventsConfig::validate` reports the same bound as an error).
const MAX_QUEUE_CAPACITY: usize = 1 << 20;

/// Where a record was lost: the `sink` label of `mg_event_dropped_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropSink {
    /// The request-path class queue was full (or closed: the flusher is not
    /// running yet, or has stopped) when the record was offered.
    Buffer,
    /// VictoriaLogs lost the line: a non-retryable status or every attempt
    /// failed, its backlog was full, or it still held the line at shutdown.
    VictoriaLogs,
    /// `mg:ev` lost the entry: the `XADD` batch failed (never retried), its
    /// backlog was full, or it still held the entry at shutdown.
    Stream,
    /// The JSONL file lost the line: the append failed, its backlog was
    /// full, or it still held the line when the shutdown budget ran out.
    File,
}

impl DropSink {
    /// Every sink label.
    pub const ALL: [DropSink; 4] = [Self::Buffer, Self::VictoriaLogs, Self::Stream, Self::File];

    /// The label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buffer => "buffer",
            Self::VictoriaLogs => "victorialogs",
            Self::Stream => "stream",
            Self::File => "file",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Buffer => 0,
            Self::VictoriaLogs => 1,
            Self::Stream => 2,
            Self::File => 3,
        }
    }
}

/// `mg_event_dropped_total{sink, class}` (§13.7).
///
/// Created unregistered so every [`EventQueues`] (and every test) has its own
/// counters; mg-edge registers the process's instance once with
/// [`EventMetrics::register`] (normally into `prometheus::default_registry()`).
/// All 12 label combinations exist from the start, at 0.
#[derive(Clone)]
pub struct EventMetrics {
    vec: IntCounterVec,
    counters: Arc<[[IntCounter; 3]; 4]>,
}

impl EventMetrics {
    /// Metric name.
    pub const DROPPED_TOTAL: &'static str = "mg_event_dropped_total";

    /// Fresh, unregistered counters.
    pub fn new() -> Self {
        // The name and labels are static and valid, so construction cannot fail.
        let vec = IntCounterVec::new(
            Opts::new(
                Self::DROPPED_TOTAL,
                "Event records lost, by where they were lost (buffer = request queue full, \
                 otherwise the output) and queue class.",
            ),
            &["sink", "class"],
        )
        .expect("static metric definition");
        let counters = std::array::from_fn(|s| {
            std::array::from_fn(|c| {
                vec.with_label_values(&[DropSink::ALL[s].as_str(), EventClass::ALL[c].as_str()])
            })
        });
        Self {
            vec,
            counters: Arc::new(counters),
        }
    }

    /// Registers the counter family in `registry`. Fails if a family with the
    /// same name is already registered there.
    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        registry.register(Box::new(self.vec.clone()))
    }

    /// Current value of one series.
    pub fn dropped(&self, sink: DropSink, class: EventClass) -> u64 {
        self.counters[sink.index()][class.index()].get()
    }

    pub(super) fn add(&self, sink: DropSink, class: EventClass, n: u64) {
        if n > 0 {
            self.counters[sink.index()][class.index()].inc_by(n);
        }
    }

    pub(super) fn add_counts(&self, sink: DropSink, counts: &Counts) {
        for class in EventClass::ALL {
            self.add(sink, class, counts[class.index()]);
        }
    }
}

impl Default for EventMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EventMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventMetrics").finish_non_exhaustive()
    }
}

/// Records per class.
pub(super) type Counts = [u64; 3];

/// State shared by the request-path handles and the flusher.
struct Shared {
    /// Records offered and not yet dispatched to the outputs.
    pending_items: AtomicUsize,
    /// Their `wire_len` bytes.
    pending_bytes: AtomicUsize,
    metrics: EventMetrics,
}

impl Shared {
    fn reserve(&self, size: usize) {
        self.pending_items.fetch_add(1, Ordering::Relaxed);
        self.pending_bytes.fetch_add(size, Ordering::Relaxed);
    }

    /// Undoes [`Shared::reserve`] (record dispatched, or not queued). Every
    /// release follows its reserve (channel send -> receive), so the
    /// counters never underflow.
    fn release(&self, size: usize) {
        self.pending_items.fetch_sub(1, Ordering::Relaxed);
        self.pending_bytes.fetch_sub(size, Ordering::Relaxed);
    }
}

/// Request-path handle: three bounded queues (P0 / P1 / P2) in front of the
/// [`Flusher`]. Cheap to clone; runtime-free, so it can be created before
/// Pingora daemonizes and shared by every proxy service (§9.1.1).
#[derive(Clone)]
pub struct EventQueues {
    tx: [mpsc::Sender<EventRecord>; 3],
    shared: Arc<Shared>,
}

impl fmt::Debug for EventQueues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (items, bytes) = self.pending();
        f.debug_struct("EventQueues")
            .field("pending_items", &items)
            .field("pending_bytes", &bytes)
            .finish_non_exhaustive()
    }
}

impl EventQueues {
    /// Queues sized by `cfg` (`queue_priority` / `queue_access` /
    /// `queue_sampled`) and the flusher that drains them, with fresh
    /// [`EventMetrics`]. Zero or oversized values are clamped rather than
    /// rejected; `EventsConfig::validate` reports them.
    pub fn new(cfg: &EventsConfig) -> (Self, Flusher) {
        Self::with_metrics(cfg, EventMetrics::new())
    }

    /// Like [`EventQueues::new`], counting drops in `metrics`.
    pub fn with_metrics(cfg: &EventsConfig, metrics: EventMetrics) -> (Self, Flusher) {
        let capacity = |n: usize| n.clamp(1, MAX_QUEUE_CAPACITY);
        let capacities = [
            capacity(cfg.queue_priority),
            capacity(cfg.queue_access),
            capacity(cfg.queue_sampled),
        ];
        let (tx0, rx0) = mpsc::channel(capacities[0]);
        let (tx1, rx1) = mpsc::channel(capacities[1]);
        let (tx2, rx2) = mpsc::channel(capacities[2]);
        let shared = Arc::new(Shared {
            pending_items: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            metrics,
        });
        let flusher = Flusher {
            rx: [rx0, rx1, rx2],
            shared: Arc::clone(&shared),
            limits: Limits {
                max_items: cfg.max_batch_lines.max(1),
                max_bytes: cfg.max_batch_bytes.max(1),
                capacity: capacities,
                interval: Duration::from_millis(cfg.flush_interval_ms.max(1)),
            },
            stream_maxlen: cfg.stream_maxlen,
        };
        (
            Self {
                tx: [tx0, tx1, tx2],
                shared,
            },
            flusher,
        )
    }

    /// The drop counters (register them once per process).
    pub fn metrics(&self) -> &EventMetrics {
        &self.shared.metrics
    }

    /// Records (and their line bytes) offered but not yet handed to the
    /// outputs.
    pub fn pending(&self) -> (usize, usize) {
        (
            self.shared.pending_items.load(Ordering::Relaxed),
            self.shared.pending_bytes.load(Ordering::Relaxed),
        )
    }
}

impl EventSink for EventQueues {
    fn try_send(&self, record: EventRecord) -> bool {
        let class = record.class;
        if record.line.is_empty() && record.stream.is_none() {
            // Nothing to write, nothing lost.
            return true;
        }
        if record.line.contains(['\n', '\r']) {
            // Would split into two JSONL lines; serde_json never produces this.
            self.shared.metrics.add(DropSink::Buffer, class, 1);
            return false;
        }
        let size = record.wire_len();
        self.shared.reserve(size);
        match self.tx[class.index()].try_send(record) {
            Ok(()) => true,
            Err(_) => {
                // Full (or the flusher is gone): drop the new record, never wait.
                self.shared.release(size);
                self.shared.metrics.add(DropSink::Buffer, class, 1);
                false
            }
        }
    }
}

/// Drains the queues into the outputs; see [`Flusher::run`].
pub struct Flusher {
    rx: [mpsc::Receiver<EventRecord>; 3],
    shared: Arc<Shared>,
    limits: Limits,
    stream_maxlen: u64,
}

impl fmt::Debug for Flusher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flusher")
            .field("flush_interval", &self.limits.interval)
            .field("stream_maxlen", &self.stream_maxlen)
            .finish_non_exhaustive()
    }
}

/// The configured outputs of one flusher run.
struct Lanes {
    /// `vl_main`, if configured.
    vl_main: Option<Lane>,
    /// `vl_short`, if configured.
    vl_short: Option<Lane>,
    file: Option<Lane>,
    stream: Option<Lane>,
}

impl Lanes {
    /// Hands one record's shares to the outputs that take them: its line to
    /// the file and to the VictoriaLogs instance of its target; its `mg:ev`
    /// entry to the stream. A record for an output that is not configured
    /// is simply not written there (nothing is lost).
    fn dispatch(&self, record: EventRecord) {
        let EventRecord {
            class,
            target,
            line,
            stream,
        } = record;
        if let (Some(entry), Some(lane)) = (stream, &self.stream) {
            lane.push(Item::entry(class, entry));
        }
        if line.is_empty() {
            return;
        }
        let text: Arc<str> = line.into();
        if let Some(lane) = &self.file {
            lane.push(Item::line(class, target, Arc::clone(&text)));
        }
        let vl = match target {
            Sink::Main => &self.vl_main,
            Sink::Short => &self.vl_short,
        };
        if let Some(lane) = vl {
            debug_assert!(lane.accepts(target));
            lane.push(Item::line(class, target, text));
        }
    }
}

impl Flusher {
    /// Runs until `shutdown` becomes true (or its sender is dropped).
    ///
    /// Ruling I-25: each configured VictoriaLogs instance (`vl`'s `vl_main`
    /// and `vl_short`, separate servers), the JSONL file (`file`) and the
    /// `mg:ev` stream (`stream`) are independent outputs. A dispatcher moves
    /// every record from the three request queues (P0 first) into a backlog
    /// per output, and each output has its own flush loop over its own
    /// backlog, so a slow or failing output never delays, blocks or drops
    /// another output's copy of a record:
    ///
    /// * Backlogs are bounded per class by the queue capacities
    ///   (`queue_priority` / `queue_access` / `queue_sampled`, plus the batch
    ///   in flight). When an output's class backlog is full, the new record
    ///   is dropped for that output only and counted under its sink label
    ///   (`victorialogs`, `file`, `stream`); P0 never competes with P1 / P2.
    /// * Every `flush_interval_ms` an output sends everything it holds; as
    ///   soon as it holds `max_batch_lines` records or `max_batch_bytes` line
    ///   bytes it sends full batches without waiting for the interval
    ///   (§9.11). A batch takes records in P0, P1, P2 order, never more than
    ///   `max_batch_lines` records or `max_batch_bytes` bytes (a single larger
    ///   line travels alone); an item that does not fit closes the batch
    ///   rather than letting a lower class overtake it.
    /// * VictoriaLogs: each instance gets the lines whose
    ///   [`EventRecord::target`] it is, one POST per batch, retried per §9.11
    ///   (at most 4 attempts of 5 s plus 6.2 s of backoff); its next batch
    ///   starts after the current one. File: one append per batch (created
    ///   `0600`).
    ///   Stream: one `XADD` batch with `MAXLEN ~ stream_maxlen`, never
    ///   retried.
    /// * On shutdown the dispatcher moves whatever is still queued into the
    ///   backlogs and closes the queues (later `try_send` calls fail fast and
    ///   count `buffer`). Each output then abandons its in-flight batch
    ///   (VictoriaLogs retries are cut short) and, within one shared
    ///   [`FINAL_FLUSH_BUDGET`], delivers its remaining P0 records (the
    ///   interrupted batch's P0 part first); the file, being local, writes
    ///   every class. What an output could not deliver is counted under its
    ///   sink label.
    ///
    /// `vl` must be built on the runtime that runs this future (§9.1.1).
    pub async fn run(
        mut self,
        vl: Option<VlClient>,
        file: Option<PathBuf>,
        stream: Option<Arc<dyn StreamWriter>>,
        shutdown: watch::Receiver<bool>,
    ) {
        let metrics = &self.shared.metrics;
        let lane = |output| Lane::new(output, self.limits, metrics.clone());
        // One lane per configured VictoriaLogs instance (separate servers).
        let vl_lane = |sink: Sink| {
            vl.as_ref()
                .filter(|client| client.endpoint(sink).is_some())
                .map(|client| {
                    lane(Output::Vl {
                        client: client.clone(),
                        sink,
                    })
                })
        };
        let lanes = Lanes {
            vl_main: vl_lane(Sink::Main),
            vl_short: vl_lane(Sink::Short),
            file: file.map(|path| lane(Output::File(path))),
            stream: stream.map(|writer| {
                lane(Output::Stream {
                    writer,
                    maxlen: self.stream_maxlen,
                })
            }),
        };
        // The outputs stop once the dispatcher has moved every queued record
        // to them, never before.
        let (stop_tx, stop_rx) = watch::channel(false);
        let (rx, shared) = (&mut self.rx, &*self.shared);
        tokio::join!(
            dispatch(rx, shared, &lanes, shutdown, stop_tx),
            run_lane(lanes.vl_main.as_ref(), stop_rx.clone()),
            run_lane(lanes.vl_short.as_ref(), stop_rx.clone()),
            run_lane(lanes.file.as_ref(), stop_rx.clone()),
            run_lane(lanes.stream.as_ref(), stop_rx),
        );
    }
}

/// Runs one output's flush loop, if that output is configured.
async fn run_lane(lane: Option<&Lane>, stop: watch::Receiver<bool>) {
    if let Some(lane) = lane {
        lane.run(stop).await;
    }
}

/// Moves records from the request queues (P0 first when several are ready)
/// to the outputs until shutdown; then moves what is left, closes the
/// queues and tells the outputs to finish.
async fn dispatch(
    rx: &mut [mpsc::Receiver<EventRecord>; 3],
    shared: &Shared,
    lanes: &Lanes,
    mut shutdown: watch::Receiver<bool>,
    stop: watch::Sender<bool>,
) {
    let [rx0, rx1, rx2] = rx;
    let mut open = [true; 3];
    loop {
        let record = tokio::select! {
            biased;
            () = shutdown_signal(&mut shutdown) => break,
            r = rx0.recv(), if open[0] => r.or_else(|| { open[0] = false; None }),
            r = rx1.recv(), if open[1] => r.or_else(|| { open[1] = false; None }),
            r = rx2.recv(), if open[2] => r.or_else(|| { open[2] = false; None }),
            else => {
                // Every request-path handle is gone: nothing can arrive.
                shutdown_signal(&mut shutdown).await;
                break;
            }
        };
        if let Some(record) = record {
            shared.release(record.wire_len());
            lanes.dispatch(record);
        }
    }
    for rx in [rx0, rx1, rx2] {
        rx.close();
        while let Ok(record) = rx.try_recv() {
            shared.release(record.wire_len());
            lanes.dispatch(record);
        }
    }
    // The receivers of `stop` are the output loops; one that already ended
    // (none configured) does not matter.
    let _ = stop.send(true);
}

/// Resolves once `rx` holds `true` or its sender is gone.
pub(super) async fn shutdown_signal(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}
