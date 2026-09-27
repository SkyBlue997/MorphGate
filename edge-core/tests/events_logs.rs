//! Application logs of the event pipeline never contain event content
//! (spec §2.4 item 5, §9.11 "应用日志", D-31): every failure path logs only
//! sinks, counts and status codes, never a line, a path, a client IP or a
//! stream value.
//!
//! Installs a process-wide `log` logger, so it lives in its own test binary.

use mg_core::{Action, BotClass};
use mg_edge_core::events::{
    DecisionEntry, DropSink, EventClass, EventQueues, EventRecord, EventSink, EventsConfig, Sink,
    StreamEntry, StreamWriter, VlClient, VlOptions, envelope,
};
use mg_edge_core::testkit::vl::{FakeVl, RecordingStreamWriter, VlReply};
use serde_json::json;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Collects every log record of this process.
struct Capture(Mutex<Vec<String>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let line = format!("{} {}: {}", record.level(), record.target(), record.args());
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    fn flush(&self) {}
}

static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

/// Values that must never reach a log: a client IP, a clearance cookie, a
/// one-time token in a path, a session id and a request id.
const SECRETS: [&str; 5] = [
    "203.0.113.77",
    "v4.local.SECRET",
    "tok3n-secret",
    "sess-SECRET",
    "rid-SECRET",
];

fn secret_record(class: EventClass, target: Sink) -> EventRecord {
    let line = envelope(
        "decision",
        "blog",
        1_790_000_000_000,
        "block rule.x route=reset score=90",
        json!({"ctx": {
            "net": {"ip": "203.0.113.77"},
            "http": {"path": "/reset/tok3n-secret", "cookie": "__Host-mg=v4.local.SECRET"}
        }}),
    );
    EventRecord::new(class, target, line).with_stream(StreamEntry::decision(&DecisionEntry {
        site: "blog",
        ts_ms: 1_790_000_000_000,
        request_id: "rid-SECRET",
        session: Some("sess-SECRET"),
        route: "reset",
        action: Action::Block,
        dry_run: false,
        class: BotClass::Scanner,
        score: 90,
        ipk: None,
        pfk: None,
        asn: None,
        status: Some(403),
    }))
}

/// Every warn / info path of the flusher: VictoriaLogs rejection (400),
/// unreachable VictoriaLogs (retries exhausted), failed file append, failed
/// `XADD`, exhausted shutdown budget and records dropped at shutdown.
#[tokio::test]
async fn failure_logs_never_contain_event_content() {
    log::set_logger(&CAPTURE).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let main = FakeVl::start().unwrap();
    main.push_replies([VlReply::Status(400)]);
    // Nothing listens on a port that was just released.
    let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = VlClient::with_options(
        Some(&main.url()),
        Some(&format!("http://127.0.0.1:{closed_port}")),
        VlOptions {
            // Two hanging attempts exceed the 2 s shutdown budget.
            timeout: Duration::from_millis(1500),
            backoff: vec![Duration::from_millis(10); 3],
        },
    )
    .unwrap();
    let writer = RecordingStreamWriter::new();
    writer.set_fail(true);
    // A directory cannot be appended to.
    let dir = std::env::temp_dir().join(format!("mg-events-logs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = EventsConfig {
        flush_interval_ms: 50,
        ..EventsConfig::default()
    };
    let (queues, flusher) = EventQueues::new(&cfg);
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(flusher.run(
        Some(client),
        Some(dir.clone()),
        Some(writer.clone() as Arc<dyn StreamWriter>),
        shutdown,
    ));

    // One batch: main answers 400, short is unreachable, the file and the
    // stream fail.
    assert!(queues.try_send(secret_record(EventClass::Priority, Sink::Main)));
    assert!(queues.try_send(secret_record(EventClass::Priority, Sink::Short)));
    let metrics = queues.metrics().clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    while metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority) < 2
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        2
    );
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 2);
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 2);

    // Shutdown with VictoriaLogs hanging: the final P0 flush runs out of
    // budget, and the queued P1 / P2 records are dropped.
    main.set_default_reply(VlReply::Hang);
    assert!(queues.try_send(secret_record(EventClass::Priority, Sink::Main)));
    assert!(queues.try_send(secret_record(EventClass::Access, Sink::Main)));
    assert!(queues.try_send(secret_record(EventClass::Sampled, Sink::Main)));
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    let logs = CAPTURE
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    for line in &logs {
        for secret in SECRETS {
            assert!(!line.contains(secret), "{secret} logged: {line}");
        }
    }
    // Every failure path above did log, so the check is not vacuous.
    let ours: Vec<&String> = logs
        .iter()
        .filter(|l| l.contains("mg_edge_core::events"))
        .collect();
    for expected in [
        "rejected a batch of 1 lines with HTTP 400",
        "unreachable after 4 attempts",
        "file sink write failed",
        "mg:ev XADD of 2 entries failed",
        "shutdown flush budget",
        "at shutdown",
    ] {
        assert!(
            ours.iter().any(|l| l.contains(expected)),
            "no log containing {expected:?}: {ours:#?}"
        );
    }
}
