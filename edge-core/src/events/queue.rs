//! The three bounded event queues and the flusher that drains them into the
//! sinks (spec §9.11).

use super::stream::StreamWriter;
use super::vl::{PostOutcome, VlClient};
use super::{EventClass, EventRecord, EventSink, EventsConfig, Sink, StreamEntry};
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::MissedTickBehavior;

/// How long the flusher keeps trying to deliver the remaining P0 records
/// after the shutdown signal (§9.1.1 item 4).
pub const FINAL_FLUSH_BUDGET: Duration = Duration::from_secs(2);

/// Upper bound on one `mg:ev` batch; the writer normally answers within the
/// state layer's own timeout.
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on a queue's capacity (tokio rejects absurd capacities by
/// panicking; `EventsConfig::validate` reports the same bound as an error).
const MAX_QUEUE_CAPACITY: usize = 1 << 20;

/// Where a record was lost: the `sink` label of `mg_event_dropped_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropSink {
    /// The class queue was full (or closed) when the record was offered, or
    /// the record was still queued when the flusher stopped.
    Buffer,
    /// VictoriaLogs refused the batch (non-retryable status) or every attempt failed.
    VictoriaLogs,
    /// The `mg:ev` `XADD` batch failed (never retried).
    Stream,
    /// Appending to the JSONL file failed.
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
                "Event records lost, by where they were lost (buffer = queue full) and queue class.",
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

    fn add(&self, sink: DropSink, class: EventClass, n: u64) {
        if n > 0 {
            self.counters[sink.index()][class.index()].inc_by(n);
        }
    }

    fn add_counts(&self, sink: DropSink, counts: &Counts) {
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
type Counts = [u64; 3];

/// State shared by the request-path handles and the flusher.
struct Shared {
    /// Records offered and not yet taken into a batch (held-over included).
    pending_items: AtomicUsize,
    /// Their `wire_len` bytes.
    pending_bytes: AtomicUsize,
    /// Woken when a threshold is reached.
    notify: Notify,
    max_items: usize,
    max_bytes: usize,
    metrics: EventMetrics,
}

impl Shared {
    /// Accounts for one offered record; true when a flush threshold is reached.
    fn reserve(&self, size: usize) -> bool {
        let items = self.pending_items.fetch_add(1, Ordering::Relaxed) + 1;
        let bytes = self.pending_bytes.fetch_add(size, Ordering::Relaxed) + size;
        items >= self.max_items || bytes >= self.max_bytes
    }

    /// Undoes [`Shared::reserve`] (record taken into a batch, or not queued).
    /// Every release follows its reserve (channel send -> receive), so the
    /// counters never underflow.
    fn release(&self, size: usize) {
        self.pending_items.fetch_sub(1, Ordering::Relaxed);
        self.pending_bytes.fetch_sub(size, Ordering::Relaxed);
    }

    fn is_full(&self) -> bool {
        self.pending_items.load(Ordering::Relaxed) >= self.max_items
            || self.pending_bytes.load(Ordering::Relaxed) >= self.max_bytes
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
        let (tx0, rx0) = mpsc::channel(capacity(cfg.queue_priority));
        let (tx1, rx1) = mpsc::channel(capacity(cfg.queue_access));
        let (tx2, rx2) = mpsc::channel(capacity(cfg.queue_sampled));
        let shared = Arc::new(Shared {
            pending_items: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            notify: Notify::new(),
            max_items: cfg.max_batch_lines.max(1),
            max_bytes: cfg.max_batch_bytes.max(1),
            metrics,
        });
        let flusher = Flusher {
            rx: [rx0, rx1, rx2],
            held: [None, None, None],
            shared: Arc::clone(&shared),
            flush_interval: Duration::from_millis(cfg.flush_interval_ms.max(1)),
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

    /// Records (and their line bytes) offered but not yet taken into a batch.
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
        let flush_now = self.shared.reserve(size);
        match self.tx[class.index()].try_send(record) {
            Ok(()) => {
                if flush_now {
                    self.shared.notify.notify_one();
                }
                true
            }
            Err(_) => {
                // Full (or the flusher is gone): drop the new record, never wait.
                self.shared.release(size);
                self.shared.metrics.add(DropSink::Buffer, class, 1);
                false
            }
        }
    }
}

/// Drains the queues into the sinks; see [`Flusher::run`].
pub struct Flusher {
    rx: [mpsc::Receiver<EventRecord>; 3],
    /// A record taken from a queue that did not fit into the previous batch's
    /// byte budget; it opens the next batch of its class.
    held: [Option<EventRecord>; 3],
    shared: Arc<Shared>,
    flush_interval: Duration,
    stream_maxlen: u64,
}

impl fmt::Debug for Flusher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flusher")
            .field("flush_interval", &self.flush_interval)
            .field("stream_maxlen", &self.stream_maxlen)
            .finish_non_exhaustive()
    }
}

/// The configured outputs of one flusher.
struct Sinks {
    vl: Option<VlClient>,
    file: Option<PathBuf>,
    stream: Option<Arc<dyn StreamWriter>>,
}

/// One line bound for VictoriaLogs.
struct Line {
    class: EventClass,
    text: String,
}

#[derive(Default)]
struct FilePart {
    body: Vec<u8>,
    counts: Counts,
}

#[derive(Default)]
struct StreamPart {
    entries: Vec<StreamEntry>,
    counts: Counts,
}

/// Records taken from the queues together, split per output. A part is
/// `None` once delivered (or when there is nothing for that output).
#[derive(Default)]
struct Batch {
    records: usize,
    main: Option<Vec<Line>>,
    short: Option<Vec<Line>>,
    file: Option<FilePart>,
    stream: Option<StreamPart>,
}

impl Batch {
    fn push(&mut self, record: EventRecord, sinks: &Sinks) {
        self.records += 1;
        let EventRecord {
            class,
            target,
            line,
            stream,
        } = record;
        let c = class.index();
        if let (Some(entry), Some(_)) = (stream, &sinks.stream) {
            let part = self.stream.get_or_insert_with(StreamPart::default);
            part.entries.push(entry);
            part.counts[c] += 1;
        }
        if line.is_empty() {
            return;
        }
        if sinks.file.is_some() {
            let part = self.file.get_or_insert_with(FilePart::default);
            part.body.extend_from_slice(line.as_bytes());
            part.body.push(b'\n');
            part.counts[c] += 1;
        }
        if sinks
            .vl
            .as_ref()
            .is_some_and(|vl| vl.endpoint(target).is_some())
        {
            let slot = match target {
                Sink::Main => &mut self.main,
                Sink::Short => &mut self.short,
            };
            slot.get_or_insert_with(Vec::new)
                .push(Line { class, text: line });
        }
    }

    /// At shutdown only P0 lines are still worth a VictoriaLogs attempt; the
    /// others are counted as lost there.
    fn keep_priority_vl_lines(&mut self, metrics: &EventMetrics) {
        for slot in [&mut self.main, &mut self.short] {
            if let Some(lines) = slot {
                lines.retain(|line| {
                    let keep = line.class == EventClass::Priority;
                    if !keep {
                        metrics.add(DropSink::VictoriaLogs, line.class, 1);
                    }
                    keep
                });
                if lines.is_empty() {
                    *slot = None;
                }
            }
        }
    }

    /// Counts every part that was never delivered.
    fn count_undelivered(self, metrics: &EventMetrics) {
        for lines in [self.main, self.short].into_iter().flatten() {
            metrics.add_counts(DropSink::VictoriaLogs, &line_counts(&lines));
        }
        if let Some(part) = self.file {
            metrics.add_counts(DropSink::File, &part.counts);
        }
        if let Some(part) = self.stream {
            metrics.add_counts(DropSink::Stream, &part.counts);
        }
    }
}

fn line_counts(lines: &[Line]) -> Counts {
    let mut counts = Counts::default();
    for line in lines {
        counts[line.class.index()] += 1;
    }
    counts
}

impl Flusher {
    /// Runs until `shutdown` becomes true (or its sender is dropped).
    ///
    /// * Every `flush_interval_ms`, everything pending is sent; as soon as
    ///   `max_batch_lines` records or `max_batch_bytes` line bytes are pending,
    ///   full batches are sent without waiting for the interval (§9.11).
    /// * A batch takes records in P0, P1, P2 order, never more than
    ///   `max_batch_lines` records or `max_batch_bytes` bytes (a single larger
    ///   line travels alone). Its lines go to `vl_main` / `vl_short` by
    ///   [`EventRecord::target`] (one POST each, retried per §9.11), every line
    ///   to `file` (appended, created `0600`), and its [`StreamEntry`]s to
    ///   `stream` as one `XADD` batch with `MAXLEN ~ stream_maxlen`. The
    ///   outputs of a batch are written concurrently; a failed output only
    ///   counts its own drops.
    /// * The next batch starts once every output is done with the current
    ///   one, so a slow VictoriaLogs (at most 4 attempts of 5 s plus 6.2 s of
    ///   backoff per batch) delays all outputs. Backpressure then lands on the
    ///   class queues, which drop the newest lowest-class records first; P0
    ///   keeps its own queue and is always drained first.
    /// * Records for an output that is not configured are simply not written
    ///   there (e.g. a `vl_short` line without `vl_short`): nothing is lost.
    /// * On shutdown an in-flight VictoriaLogs retry is abandoned, then the
    ///   remaining P0 records (and the P0 lines of the interrupted batch) get
    ///   up to [`FINAL_FLUSH_BUDGET`]; P1 / P2 records still queued are
    ///   counted as `buffer` drops and the queues are closed, so later
    ///   `try_send` calls fail fast.
    ///
    /// `vl` must be built on the runtime that runs this future (§9.1.1).
    pub async fn run(
        mut self,
        vl: Option<VlClient>,
        file: Option<PathBuf>,
        stream: Option<Arc<dyn StreamWriter>>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let sinks = Sinks { vl, file, stream };
        let metrics = self.shared.metrics.clone();
        let maxlen = self.stream_maxlen;
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + self.flush_interval,
            self.flush_interval,
        );
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut interrupted = None;
        'run: loop {
            let tick = tokio::select! {
                biased;
                () = shutdown_signal(&mut shutdown) => break 'run,
                _ = ticker.tick() => true,
                () = self.shared.notify.notified() => false,
            };
            // A tick sends everything pending; a threshold wake-up only full batches.
            while tick || self.shared.is_full() {
                let mut batch = self.assemble(&sinks, &EventClass::ALL);
                if batch.records == 0 {
                    break;
                }
                let delivered = tokio::select! {
                    biased;
                    () = shutdown_signal(&mut shutdown) => false,
                    () = deliver(&sinks, maxlen, &metrics, &mut batch) => true,
                };
                if !delivered {
                    interrupted = Some(batch);
                    break 'run;
                }
            }
        }
        self.finish(&sinks, &metrics, interrupted).await;
    }

    /// Final best-effort P0 flush, then accounting for everything left.
    async fn finish(mut self, sinks: &Sinks, metrics: &EventMetrics, interrupted: Option<Batch>) {
        let maxlen = self.stream_maxlen;
        let mut current = interrupted.map(|mut batch| {
            batch.keep_priority_vl_lines(metrics);
            batch
        });
        let work = async {
            loop {
                if current.is_none() {
                    let batch = self.assemble(sinks, &[EventClass::Priority]);
                    if batch.records == 0 {
                        break;
                    }
                    current = Some(batch);
                }
                if let Some(batch) = current.as_mut() {
                    deliver(sinks, maxlen, metrics, batch).await;
                }
                current = None;
            }
        };
        if tokio::time::timeout(FINAL_FLUSH_BUDGET, work)
            .await
            .is_err()
        {
            log::warn!(
                "events: shutdown flush budget ({} ms) exhausted",
                FINAL_FLUSH_BUDGET.as_millis()
            );
        }
        if let Some(batch) = current {
            batch.count_undelivered(metrics);
        }
        let mut left = Counts::default();
        for (i, rx) in self.rx.iter_mut().enumerate() {
            rx.close();
            left[i] += u64::from(self.held[i].take().is_some());
            while rx.try_recv().is_ok() {
                left[i] += 1;
            }
        }
        metrics.add_counts(DropSink::Buffer, &left);
        if left.iter().any(|&n| n > 0) {
            log::info!(
                "events: dropped {} / {} / {} queued P0 / P1 / P2 records at shutdown",
                left[0],
                left[1],
                left[2]
            );
        }
    }

    /// Takes the next batch from `classes`, in order.
    fn assemble(&mut self, sinks: &Sinks, classes: &[EventClass]) -> Batch {
        let mut batch = Batch::default();
        let mut bytes = 0usize;
        'classes: for &class in classes {
            let i = class.index();
            loop {
                if batch.records >= self.shared.max_items {
                    break 'classes;
                }
                let record = match self.held[i].take() {
                    Some(record) => record,
                    None => match self.rx[i].try_recv() {
                        Ok(record) => record,
                        Err(_) => break,
                    },
                };
                let size = record.wire_len();
                if batch.records > 0 && bytes + size > self.shared.max_bytes {
                    // Keep strict priority order: close the batch rather than
                    // topping it up with smaller lower-class records.
                    self.held[i] = Some(record);
                    break 'classes;
                }
                bytes += size;
                self.shared.release(size);
                batch.push(record, sinks);
            }
        }
        batch
    }
}

/// Resolves once `rx` holds `true` or its sender is gone.
async fn shutdown_signal(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Writes one batch to every output concurrently. Each part is set to `None`
/// when its output is done with it (delivered or counted as dropped), so an
/// interrupted delivery leaves exactly the unfinished parts behind.
async fn deliver(sinks: &Sinks, maxlen: u64, metrics: &EventMetrics, batch: &mut Batch) {
    let Batch {
        main,
        short,
        file,
        stream,
        ..
    } = batch;
    tokio::join!(
        deliver_vl(sinks.vl.as_ref(), Sink::Main, main, metrics),
        deliver_vl(sinks.vl.as_ref(), Sink::Short, short, metrics),
        deliver_file(sinks.file.as_deref(), file, metrics),
        deliver_stream(sinks.stream.as_deref(), maxlen, stream, metrics),
    );
}

async fn deliver_vl(
    vl: Option<&VlClient>,
    sink: Sink,
    slot: &mut Option<Vec<Line>>,
    metrics: &EventMetrics,
) {
    let (Some(vl), Some(lines)) = (vl, slot.as_ref()) else {
        return;
    };
    let mut body = Vec::with_capacity(lines.iter().map(|l| l.text.len() + 1).sum());
    for line in lines {
        body.extend_from_slice(line.text.as_bytes());
        body.push(b'\n');
    }
    let counts = line_counts(lines);
    let n = lines.len();
    match vl.post_batch(sink, body).await {
        PostOutcome::Accepted { .. } | PostOutcome::NoEndpoint => {}
        PostOutcome::Rejected { status } => {
            log::warn!("events: {sink} rejected a batch of {n} lines with HTTP {status}; dropped");
            metrics.add_counts(DropSink::VictoriaLogs, &counts);
        }
        PostOutcome::Failed { attempts } => {
            log::warn!("events: {sink} unreachable after {attempts} attempts; dropped {n} lines");
            metrics.add_counts(DropSink::VictoriaLogs, &counts);
        }
    }
    *slot = None;
}

async fn deliver_file(path: Option<&Path>, slot: &mut Option<FilePart>, metrics: &EventMetrics) {
    let Some(path) = path else {
        return;
    };
    // Taken before the blocking write starts: an interrupted delivery must not
    // write these lines a second time.
    let Some(FilePart { body, counts }) = slot.take() else {
        return;
    };
    let path = path.to_path_buf();
    let written = tokio::task::spawn_blocking(move || append(&path, &body)).await;
    let error = match written {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    log::warn!("events: file sink write failed: {error}");
    metrics.add_counts(DropSink::File, &counts);
}

fn append(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Events carry request data (D-31): owner-only on creation.
        options.mode(0o600);
    }
    // One O_APPEND write per batch: whole lines, even with a second Edge
    // process appending during a graceful upgrade.
    options.open(path)?.write_all(body)
}

async fn deliver_stream(
    writer: Option<&dyn StreamWriter>,
    maxlen: u64,
    slot: &mut Option<StreamPart>,
    metrics: &EventMetrics,
) {
    let Some(writer) = writer else {
        return;
    };
    // Never retried (§9.11), so it is taken up front.
    let Some(StreamPart { entries, counts }) = slot.take() else {
        return;
    };
    let n = entries.len();
    let error = match tokio::time::timeout(STREAM_TIMEOUT, writer.xadd_batch(maxlen, entries)).await
    {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e,
        Err(_) => format!("timed out after {} ms", STREAM_TIMEOUT.as_millis()),
    };
    log::warn!("events: mg:ev XADD of {n} entries failed ({error}); dropped");
    metrics.add_counts(DropSink::Stream, &counts);
}
