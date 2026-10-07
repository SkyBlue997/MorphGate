//! The outputs of the event pipeline (ruling I-25): each VictoriaLogs
//! instance (`vl_main`, `vl_short`), the JSONL file and the `mg:ev` stream
//! have their own bounded backlog ([`Lane`]) and their own flush loop
//! ([`Lane::run`]). A slow or failing output therefore only delays or drops
//! its own copy of a record; the others keep their pace. The two
//! VictoriaLogs instances are separate servers (30 d and 7 d retention), so
//! a `vl_short` outage never holds back decision, access or feedback lines
//! bound for `vl_main`.

use super::queue::{Counts, DropSink, EventMetrics, FINAL_FLUSH_BUDGET, shutdown_signal};
use super::stream::StreamWriter;
use super::vl::{PostOutcome, VlClient};
use super::{EventClass, Sink, StreamEntry};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::time::{Instant, MissedTickBehavior};

/// Upper bound on one `mg:ev` batch; the writer normally answers within the
/// state layer's own timeout.
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Batch and backlog limits shared by every output (from `EventsConfig`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Most records per batch; also the "flush now" threshold.
    pub max_items: usize,
    /// Most line bytes per batch; also the "flush now" threshold.
    pub max_bytes: usize,
    /// Backlog capacity per class (P0, P1, P2).
    pub capacity: [usize; 3],
    /// Flush at least this often.
    pub interval: Duration,
}

/// One record's share for one output.
pub(super) struct Item {
    class: EventClass,
    payload: Payload,
}

enum Payload {
    /// A JSON line (shared by the VictoriaLogs and file outputs).
    Line { target: Sink, text: Arc<str> },
    /// An `mg:ev` entry.
    Entry(StreamEntry),
}

impl Item {
    pub(super) fn line(class: EventClass, target: Sink, text: Arc<str>) -> Self {
        Self {
            class,
            payload: Payload::Line { target, text },
        }
    }

    pub(super) fn entry(class: EventClass, entry: StreamEntry) -> Self {
        Self {
            class,
            payload: Payload::Entry(entry),
        }
    }

    /// Bytes counted against `max_batch_bytes`: a line and its `\n`. Stream
    /// entries are bounded by `max_batch_lines` only.
    fn bytes(&self) -> usize {
        match &self.payload {
            Payload::Line { text, .. } => text.len() + 1,
            Payload::Entry(_) => 0,
        }
    }
}

/// Where a lane delivers.
pub(super) enum Output {
    /// One VictoriaLogs instance: the lane only ever holds lines whose
    /// target is `sink`.
    Vl {
        client: VlClient,
        sink: Sink,
    },
    File(PathBuf),
    Stream {
        writer: Arc<dyn StreamWriter>,
        maxlen: u64,
    },
}

impl Output {
    fn sink(&self) -> DropSink {
        match self {
            Self::Vl { .. } => DropSink::VictoriaLogs,
            Self::File(_) => DropSink::File,
            Self::Stream { .. } => DropSink::Stream,
        }
    }

    /// Classes still delivered after the shutdown signal (§9.1.1 item 4:
    /// P0; the local file takes everything it holds).
    fn final_classes(&self) -> &'static [EventClass] {
        match self {
            Self::File(_) => &EventClass::ALL,
            Self::Vl { .. } | Self::Stream { .. } => &[EventClass::Priority],
        }
    }
}

/// One line of a batch.
struct Line {
    class: EventClass,
    text: Arc<str>,
}

/// Items taken from a lane together, as its output sends them. A part is
/// `None` once its output is done with it (delivered or counted as
/// dropped), so an interrupted delivery leaves exactly the unfinished parts.
#[derive(Default)]
struct Batch {
    main: Option<Vec<Line>>,
    short: Option<Vec<Line>>,
    file: Option<Vec<Line>>,
    stream: Option<Vec<(EventClass, StreamEntry)>>,
}

fn line_counts(lines: &[Line]) -> Counts {
    let mut counts = Counts::default();
    for line in lines {
        counts[line.class.index()] += 1;
    }
    counts
}

fn entry_counts(entries: &[(EventClass, StreamEntry)]) -> Counts {
    let mut counts = Counts::default();
    for (class, _) in entries {
        counts[class.index()] += 1;
    }
    counts
}

/// Keeps the items of `classes` in `part`, counting the others as dropped
/// at `sink`.
fn retain<T>(
    part: &mut Option<Vec<T>>,
    classes: &[EventClass],
    class_of: impl Fn(&T) -> EventClass,
    metrics: &EventMetrics,
    sink: DropSink,
) {
    if let Some(items) = part {
        items.retain(|item| {
            let class = class_of(item);
            let keep = classes.contains(&class);
            if !keep {
                metrics.add(sink, class, 1);
            }
            keep
        });
        if items.is_empty() {
            *part = None;
        }
    }
}

impl Batch {
    fn is_empty(&self) -> bool {
        self.main.is_none() && self.short.is_none() && self.file.is_none() && self.stream.is_none()
    }

    /// At shutdown only `classes` are still worth an attempt; the rest is
    /// counted as lost at `sink`.
    fn retain_classes(&mut self, classes: &[EventClass], metrics: &EventMetrics, sink: DropSink) {
        for part in [&mut self.main, &mut self.short, &mut self.file] {
            retain(part, classes, |l: &Line| l.class, metrics, sink);
        }
        retain(&mut self.stream, classes, |(c, _)| *c, metrics, sink);
    }

    /// Counts every part that was never delivered.
    fn count_undelivered(self, metrics: &EventMetrics, sink: DropSink) {
        for lines in [self.main, self.short, self.file].into_iter().flatten() {
            metrics.add_counts(sink, &line_counts(&lines));
        }
        if let Some(entries) = self.stream {
            metrics.add_counts(sink, &entry_counts(&entries));
        }
    }
}

/// An output's backlog: one queue per class, bounded by
/// [`Limits::capacity`].
#[derive(Default)]
struct Backlog {
    queues: [VecDeque<Item>; 3],
    items: usize,
    bytes: usize,
}

/// One output with its backlog (see the module documentation).
pub(super) struct Lane {
    output: Output,
    backlog: Mutex<Backlog>,
    /// Woken when the backlog reaches a flush threshold.
    notify: Notify,
    limits: Limits,
    metrics: EventMetrics,
}

impl Lane {
    pub(super) fn new(output: Output, limits: Limits, metrics: EventMetrics) -> Self {
        Self {
            output,
            backlog: Mutex::new(Backlog::default()),
            notify: Notify::new(),
            limits,
            metrics,
        }
    }

    fn sink(&self) -> DropSink {
        self.output.sink()
    }

    /// Whether this output writes lines for `target`: a VictoriaLogs
    /// output only its own instance's lines; the others every line.
    pub(super) fn accepts(&self, target: Sink) -> bool {
        match &self.output {
            Output::Vl { sink, .. } => *sink == target,
            Output::File(_) | Output::Stream { .. } => true,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Backlog> {
        // The critical sections never panic; a poisoned lock still holds
        // consistent queues.
        self.backlog.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues one item; never waits. When the item's class backlog is full
    /// the new item is dropped and counted under this output's sink label.
    pub(super) fn push(&self, item: Item) {
        let class = item.class;
        let size = item.bytes();
        let threshold = {
            let mut b = self.lock();
            let queue = &mut b.queues[class.index()];
            if queue.len() >= self.limits.capacity[class.index()] {
                None
            } else {
                queue.push_back(item);
                b.items += 1;
                b.bytes += size;
                Some(b.items >= self.limits.max_items || b.bytes >= self.limits.max_bytes)
            }
        };
        match threshold {
            None => self.metrics.add(self.sink(), class, 1),
            Some(true) => self.notify.notify_one(),
            Some(false) => {}
        }
    }

    /// A flush threshold is reached.
    fn is_full(&self) -> bool {
        let b = self.lock();
        b.items >= self.limits.max_items || b.bytes >= self.limits.max_bytes
    }

    /// Takes the next batch from `classes`, in order: at most `max_items`
    /// records and `max_bytes` bytes (a single larger line travels alone).
    /// An item that does not fit closes the batch, so a lower class never
    /// overtakes a higher one.
    fn take(&self, classes: &[EventClass]) -> Batch {
        let mut taken = Vec::new();
        let mut bytes = 0usize;
        {
            let mut b = self.lock();
            'classes: for &class in classes {
                loop {
                    if taken.len() >= self.limits.max_items {
                        break 'classes;
                    }
                    let Some(size) = b.queues[class.index()].front().map(Item::bytes) else {
                        break;
                    };
                    if !taken.is_empty() && bytes + size > self.limits.max_bytes {
                        break 'classes;
                    }
                    if let Some(item) = b.queues[class.index()].pop_front() {
                        bytes += size;
                        b.items -= 1;
                        b.bytes -= size;
                        taken.push(item);
                    }
                }
            }
        }
        self.batch(taken)
    }

    /// Everything still in the backlog, per class (removed).
    fn drain(&self) -> Counts {
        let mut b = self.lock();
        let mut counts = Counts::default();
        for (i, queue) in b.queues.iter_mut().enumerate() {
            counts[i] = queue.len() as u64;
            queue.clear();
        }
        b.items = 0;
        b.bytes = 0;
        counts
    }

    fn batch(&self, items: Vec<Item>) -> Batch {
        let mut batch = Batch::default();
        for Item { class, payload } in items {
            match payload {
                Payload::Line { target, text } => {
                    let slot = match (&self.output, target) {
                        (Output::Vl { .. }, Sink::Main) => &mut batch.main,
                        (Output::Vl { .. }, Sink::Short) => &mut batch.short,
                        _ => &mut batch.file,
                    };
                    slot.get_or_insert_with(Vec::new).push(Line { class, text });
                }
                Payload::Entry(entry) => {
                    batch
                        .stream
                        .get_or_insert_with(Vec::new)
                        .push((class, entry));
                }
            }
        }
        batch
    }

    /// The output's flush loop: runs until `stop`, then the final flush
    /// (see `Flusher::run`).
    pub(super) async fn run(&self, mut stop: watch::Receiver<bool>) {
        let interval = self.limits.interval;
        let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut interrupted = None;
        'run: loop {
            let tick = tokio::select! {
                biased;
                () = shutdown_signal(&mut stop) => break 'run,
                _ = ticker.tick() => true,
                () = self.notify.notified() => false,
            };
            // A tick sends everything held; a threshold wake-up full batches.
            while tick || self.is_full() {
                let mut batch = self.take(&EventClass::ALL);
                if batch.is_empty() {
                    break;
                }
                let delivered = tokio::select! {
                    biased;
                    () = shutdown_signal(&mut stop) => false,
                    () = self.deliver(&mut batch) => true,
                };
                if !delivered {
                    interrupted = Some(batch);
                    break 'run;
                }
            }
        }
        self.finish(interrupted).await;
    }

    /// Final best-effort flush of the classes this output still delivers
    /// after shutdown, then accounting for everything left.
    async fn finish(&self, interrupted: Option<Batch>) {
        let sink = self.sink();
        let classes = self.output.final_classes();
        let mut current = interrupted.map(|mut batch| {
            batch.retain_classes(classes, &self.metrics, sink);
            batch
        });
        let work = async {
            loop {
                if current.as_ref().is_none_or(Batch::is_empty) {
                    let batch = self.take(classes);
                    if batch.is_empty() {
                        break;
                    }
                    current = Some(batch);
                }
                if let Some(batch) = current.as_mut() {
                    self.deliver(batch).await;
                }
                current = None;
            }
        };
        if tokio::time::timeout(FINAL_FLUSH_BUDGET, work)
            .await
            .is_err()
        {
            log::warn!(
                "events: {} shutdown flush budget ({} ms) exhausted",
                sink.as_str(),
                FINAL_FLUSH_BUDGET.as_millis()
            );
        }
        if let Some(batch) = current {
            batch.count_undelivered(&self.metrics, sink);
        }
        let left = self.drain();
        self.metrics.add_counts(sink, &left);
        if left.iter().any(|&n| n > 0) {
            log::info!(
                "events: {} dropped {} / {} / {} P0 / P1 / P2 records at shutdown",
                sink.as_str(),
                left[0],
                left[1],
                left[2]
            );
        }
    }

    /// Writes one batch to the output. Each part is set to `None` when the
    /// output is done with it.
    async fn deliver(&self, batch: &mut Batch) {
        let m = &self.metrics;
        match &self.output {
            Output::Vl { client, sink } => {
                let slot = match sink {
                    Sink::Main => &mut batch.main,
                    Sink::Short => &mut batch.short,
                };
                deliver_vl(client, *sink, slot, m).await;
            }
            Output::File(path) => deliver_file(path, &mut batch.file, m).await,
            Output::Stream { writer, maxlen } => {
                deliver_stream(writer.as_ref(), *maxlen, &mut batch.stream, m).await;
            }
        }
    }
}

fn body(lines: &[Line]) -> Vec<u8> {
    let mut body = Vec::with_capacity(lines.iter().map(|l| l.text.len() + 1).sum());
    for line in lines {
        body.extend_from_slice(line.text.as_bytes());
        body.push(b'\n');
    }
    body
}

async fn deliver_vl(
    vl: &VlClient,
    sink: Sink,
    slot: &mut Option<Vec<Line>>,
    metrics: &EventMetrics,
) {
    let Some(lines) = slot.as_ref() else {
        return;
    };
    let counts = line_counts(lines);
    let n = lines.len();
    match vl.post_batch(sink, body(lines)).await {
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

async fn deliver_file(path: &Path, slot: &mut Option<Vec<Line>>, metrics: &EventMetrics) {
    // Taken before the blocking write starts: an interrupted delivery must not
    // write these lines a second time.
    let Some(lines) = slot.take() else {
        return;
    };
    let counts = line_counts(&lines);
    let body = body(&lines);
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
    writer: &dyn StreamWriter,
    maxlen: u64,
    slot: &mut Option<Vec<(EventClass, StreamEntry)>>,
    metrics: &EventMetrics,
) {
    // Never retried (§9.11), so it is taken up front.
    let Some(entries) = slot.take() else {
        return;
    };
    let counts = entry_counts(&entries);
    let n = entries.len();
    let entries = entries.into_iter().map(|(_, e)| e).collect();
    let error = match tokio::time::timeout(STREAM_TIMEOUT, writer.xadd_batch(maxlen, entries)).await
    {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e,
        Err(_) => format!("timed out after {} ms", STREAM_TIMEOUT.as_millis()),
    };
    log::warn!("events: mg:ev XADD of {n} entries failed ({error}); dropped");
    metrics.add_counts(DropSink::Stream, &counts);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::{Action, BotClass};

    fn limits(max_items: usize, max_bytes: usize, capacity: usize) -> Limits {
        Limits {
            max_items,
            max_bytes,
            capacity: [capacity; 3],
            interval: Duration::from_secs(60),
        }
    }

    fn file_lane(limits: Limits) -> Lane {
        Lane::new(
            Output::File(PathBuf::from("/nonexistent")),
            limits,
            EventMetrics::new(),
        )
    }

    fn text(n: usize) -> Arc<str> {
        "x".repeat(n).into()
    }

    fn classes(batch: &Batch) -> Vec<EventClass> {
        batch
            .file
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|l| l.class)
            .collect()
    }

    /// A full class backlog drops the new item for this output only and
    /// counts it under the output's label; other classes still have room.
    #[test]
    fn full_backlog_drops_new_items_per_class() {
        let lane = file_lane(limits(100, 1 << 20, 2));
        for _ in 0..3 {
            lane.push(Item::line(EventClass::Sampled, Sink::Short, text(3)));
        }
        lane.push(Item::line(EventClass::Priority, Sink::Main, text(3)));
        let m = &lane.metrics;
        assert_eq!(m.dropped(DropSink::File, EventClass::Sampled), 1);
        assert_eq!(m.dropped(DropSink::File, EventClass::Priority), 0);
        assert_eq!(m.dropped(DropSink::Buffer, EventClass::Sampled), 0);
        let batch = lane.take(&EventClass::ALL);
        assert_eq!(
            classes(&batch),
            [
                EventClass::Priority,
                EventClass::Sampled,
                EventClass::Sampled
            ]
        );
        assert_eq!(lane.drain(), [0, 0, 0]);
    }

    /// Batches respect both limits; a line larger than the byte limit
    /// travels alone; a line that does not fit closes the batch.
    #[test]
    fn take_respects_limits_and_class_order() {
        let lane = file_lane(limits(3, 100, 10));
        lane.push(Item::line(EventClass::Priority, Sink::Main, text(150)));
        lane.push(Item::line(EventClass::Priority, Sink::Main, text(10)));
        lane.push(Item::line(EventClass::Access, Sink::Main, text(95)));
        lane.push(Item::line(EventClass::Sampled, Sink::Main, text(1)));
        assert!(lane.is_full(), "bytes over the threshold");
        assert_eq!(classes(&lane.take(&EventClass::ALL)).len(), 1, "alone");
        // 11 + 96 > 100: the P1 line closes the batch, the P2 line waits.
        assert_eq!(
            classes(&lane.take(&EventClass::ALL)),
            [EventClass::Priority]
        );
        assert_eq!(
            classes(&lane.take(&EventClass::ALL)),
            [EventClass::Access, EventClass::Sampled]
        );
        assert!(lane.take(&EventClass::ALL).is_empty());
        assert!(!lane.is_full());
    }

    /// Stream entries count against `max_batch_lines` only.
    #[test]
    fn stream_items_have_no_byte_size() {
        let entry = StreamEntry::decision(&super::super::DecisionEntry {
            site: "s",
            ts_ms: 1,
            request_id: "r",
            session: None,
            route: "default",
            action: Action::Allow,
            dry_run: false,
            class: BotClass::HumanLikely,
            score: 1,
            ipk: None,
            pfk: None,
            asn: None,
            status: Some(200),
        });
        assert_eq!(Item::entry(EventClass::Sampled, entry).bytes(), 0);
        assert_eq!(
            Item::line(EventClass::Sampled, Sink::Main, text(9)).bytes(),
            10
        );
    }

    /// At shutdown the interrupted batch keeps only the final classes; the
    /// rest is counted at the output's label.
    #[test]
    fn retain_classes_counts_what_is_given_up() {
        let metrics = EventMetrics::new();
        let mut batch = Batch {
            main: Some(vec![
                Line {
                    class: EventClass::Priority,
                    text: text(1),
                },
                Line {
                    class: EventClass::Access,
                    text: text(1),
                },
            ]),
            short: Some(vec![Line {
                class: EventClass::Sampled,
                text: text(1),
            }]),
            ..Batch::default()
        };
        batch.retain_classes(&[EventClass::Priority], &metrics, DropSink::VictoriaLogs);
        assert_eq!(batch.main.as_ref().map(Vec::len), Some(1));
        assert!(batch.short.is_none());
        assert_eq!(
            metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
            1
        );
        assert_eq!(
            metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
            1
        );
        batch.count_undelivered(&metrics, DropSink::VictoriaLogs);
        assert_eq!(
            metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
            1
        );
    }
}
