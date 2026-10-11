//! The Phase 2 shutdown drain and telemetry queue of the event pipeline
//! (docs/impl/phase2-spec.md §9.4, §9.7 item 2, §10.1; WP-C5 tests in §17):
//! with `shutdown_drain_ms`, records still held or offered after the
//! shutdown signal are delivered (every class, not only P0) until all is
//! delivered or the drain time has passed; the drain never extends the
//! shutdown beyond `drain + FINAL_FLUSH_BUDGET`; without it (absent or 0)
//! the Phase 1 behaviour is unchanged. `queue_telemetry` is its own bounded
//! queue: a flood of reports only drops reports.

use mg_core::{Action, BotClass, BoxFuture};
use mg_edge_core::events::{
    DecisionEntry, DecisionEntryV2, DropSink, EventClass, EventQueues, EventRecord, EventSink,
    EventsConfig, FINAL_FLUSH_BUDGET, Sink, StreamEntry, StreamWriter,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// A stream writer that records entries (by `rid`) after a delay; with
/// `hang` it never answers.
struct Writer {
    delay: Duration,
    hang: bool,
    seen: Mutex<Vec<String>>,
}

impl Writer {
    fn new(delay: Duration, hang: bool) -> Arc<Self> {
        Arc::new(Self {
            delay,
            hang,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl StreamWriter for Writer {
    fn xadd_batch(
        &self,
        _maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            if self.hang {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(self.delay).await;
            let mut seen = self.seen.lock().unwrap();
            for e in entries {
                seen.push(e.get("rid").unwrap_or("").to_owned());
            }
            Ok(())
        })
    }
}

fn entry(rid: &str) -> StreamEntry {
    StreamEntry::decision_v2(&DecisionEntryV2::new(
        DecisionEntry {
            site: "blog",
            ts_ms: 1,
            request_id: rid,
            session: None,
            route: "default",
            action: Action::Allow,
            dry_run: false,
            class: BotClass::Unknown,
            score: 0,
            ipk: None,
            pfk: None,
            asn: None,
            status: None,
        },
        "GET",
    ))
}

fn record(class: EventClass, rid: &str) -> EventRecord {
    EventRecord::stream_only(class, entry(rid))
}

/// A long flush interval: nothing leaves a backlog before the shutdown
/// unless a test says so.
fn cfg(drain_ms: Option<u64>) -> EventsConfig {
    EventsConfig {
        flush_interval_ms: 60_000,
        shutdown_drain_ms: drain_ms,
        ..EventsConfig::default()
    }
}

struct Run {
    queues: EventQueues,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(cfg: &EventsConfig, writer: Arc<Writer>) -> Run {
    let (queues, flusher) = EventQueues::new(cfg);
    let (stop, rx) = watch::channel(false);
    let stream: Arc<dyn StreamWriter> = writer;
    let task = tokio::spawn(flusher.run(None, None, Some(stream), rx));
    Run { queues, stop, task }
}

async fn settle() {
    // Let the dispatcher move offered records into the backlogs.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Phase 1 behaviour without a drain: at shutdown the stream only delivers
/// P0; the sampled and telemetry entries it held are counted as lost.
#[tokio::test]
async fn without_drain_shutdown_is_phase1() {
    for drain in [None, Some(0)] {
        let writer = Writer::new(Duration::ZERO, false);
        let run = start(&cfg(drain), Arc::clone(&writer));
        for (class, rid) in [
            (EventClass::Priority, "p0"),
            (EventClass::Sampled, "p2"),
            (EventClass::Telemetry, "t"),
        ] {
            assert!(run.queues.try_send(record(class, rid)));
        }
        settle().await;
        run.stop.send_replace(true);
        run.task.await.unwrap();
        assert_eq!(writer.seen(), ["p0"]);
        let m = run.queues.metrics();
        assert_eq!(m.dropped(DropSink::Stream, EventClass::Sampled), 1);
        assert_eq!(m.dropped(DropSink::Stream, EventClass::Telemetry), 1);
        // Records offered after the shutdown are refused (buffer).
        assert!(!run.queues.try_send(record(EventClass::Priority, "late")));
        assert_eq!(m.dropped(DropSink::Buffer, EventClass::Priority), 1);
    }
}

/// §9.7 item 2: during the drain every class is delivered, including
/// records offered after the signal while a batch is in flight; the drain
/// ends as soon as everything is delivered, long before its time limit.
#[tokio::test]
async fn drain_delivers_every_class_and_ends_when_empty() {
    let writer = Writer::new(Duration::from_millis(200), false);
    let run = start(&cfg(Some(5_000)), Arc::clone(&writer));
    for (class, rid) in [
        (EventClass::Priority, "p0"),
        (EventClass::Access, "p1"),
        (EventClass::Sampled, "p2"),
        (EventClass::Telemetry, "t"),
    ] {
        assert!(run.queues.try_send(record(class, rid)));
    }
    settle().await;
    let started = Instant::now();
    run.stop.send_replace(true);
    // While the first batch is in flight (200 ms), a request that ends now
    // still gets its event written.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(run.queues.try_send(record(EventClass::Sampled, "late")));
    run.task.await.unwrap();
    let elapsed = started.elapsed();
    let mut seen = writer.seen();
    seen.sort();
    assert_eq!(seen, ["late", "p0", "p1", "p2", "t"]);
    assert!(
        elapsed < Duration::from_millis(2_000),
        "the drain ends once everything is delivered: {elapsed:?}"
    );
    let m = run.queues.metrics();
    for class in EventClass::ALL {
        assert_eq!(m.dropped(DropSink::Stream, class), 0, "{class}");
        assert_eq!(m.dropped(DropSink::Buffer, class), 0, "{class}");
    }
    // After the drain the queues are closed.
    assert!(!run.queues.try_send(record(EventClass::Priority, "after")));
}

/// The drain's time limit: an output that never answers holds the shutdown
/// for at most `drain + FINAL_FLUSH_BUDGET`, even while records keep coming.
#[tokio::test]
async fn drain_is_bounded_by_its_time_limit() {
    let writer = Writer::new(Duration::ZERO, true);
    let drain = Duration::from_millis(300);
    let run = start(&cfg(Some(300)), Arc::clone(&writer));
    assert!(run.queues.try_send(record(EventClass::Priority, "p0")));
    settle().await;
    // Force a flush attempt that hangs: the writer is now busy forever.
    let started = Instant::now();
    run.stop.send_replace(true);
    let queues = run.queues.clone();
    let feeder = tokio::spawn(async move {
        for i in 0..1_000 {
            let _ = queues.try_send(record(EventClass::Sampled, &format!("s{i}")));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    run.task.await.unwrap();
    let elapsed = started.elapsed();
    feeder.abort();
    assert!(writer.seen().is_empty());
    assert!(
        elapsed >= drain,
        "the drain waited for the hung output: {elapsed:?}"
    );
    assert!(
        elapsed <= drain + FINAL_FLUSH_BUDGET + Duration::from_millis(500),
        "bounded: {elapsed:?}"
    );
    // What the hung output still held is counted (the XADD in flight is the
    // documented Phase 1 blind spot).
    let m = run.queues.metrics();
    assert!(m.dropped(DropSink::Stream, EventClass::Sampled) >= 1);
}

/// `Flusher::with_shutdown_drain` overrides the configured value (mg-edge
/// passes the default it computes from the grace period) and is clamped.
#[tokio::test]
async fn with_shutdown_drain_sets_the_resolved_value() {
    let (_queues, flusher) = EventQueues::new(&cfg(None));
    assert_eq!(flusher.shutdown_drain(), Duration::ZERO);
    let flusher = flusher.with_shutdown_drain(Duration::from_millis(1_500));
    assert_eq!(flusher.shutdown_drain(), Duration::from_millis(1_500));
    let flusher = flusher.with_shutdown_drain(Duration::from_secs(60));
    assert_eq!(flusher.shutdown_drain(), Duration::from_secs(10));
    let (_queues, flusher) = EventQueues::new(&cfg(Some(700)));
    assert_eq!(flusher.shutdown_drain(), Duration::from_millis(700));
}

/// §9.4 step 7: telemetry has its own bounded queue; when it is full only
/// telemetry is dropped (`class="telemetry"`), decisions still queue.
#[tokio::test]
async fn telemetry_queue_is_separate_and_bounded() {
    let cfg = EventsConfig {
        queue_telemetry: 64,
        ..cfg(None)
    };
    // No flusher running: the request queues fill up.
    let (queues, _flusher) = EventQueues::new(&cfg);
    let line = |i: usize| format!("{{\"kind\":\"telemetry\",\"i\":{i}}}");
    for i in 0..64 {
        assert!(queues.try_send(EventRecord::new(
            EventClass::Telemetry,
            Sink::Short,
            line(i)
        )));
    }
    assert!(!queues.try_send(EventRecord::new(
        EventClass::Telemetry,
        Sink::Short,
        line(64)
    )));
    let m = queues.metrics();
    assert_eq!(m.dropped(DropSink::Buffer, EventClass::Telemetry), 1);
    assert!(queues.try_send(record(EventClass::Priority, "decision")));
    assert!(queues.try_send(record(EventClass::Sampled, "sampled")));
    assert_eq!(m.dropped(DropSink::Buffer, EventClass::Priority), 0);
    assert_eq!(m.dropped(DropSink::Buffer, EventClass::Sampled), 0);
    assert_eq!(EventClass::Telemetry.as_str(), "telemetry");
}
