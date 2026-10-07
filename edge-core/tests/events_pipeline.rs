//! Event queues, flusher and sinks end to end against the loopback fake
//! VictoriaLogs (spec §9.11, §13.1, §13.6; WP-C4 test list in §15).

use mg_core::{Action, BotClass, BoxFuture, ChallengeType, VerdictOutcome};
use mg_edge_core::events::{
    DecisionEntry, DropSink, EventClass, EventMetrics, EventQueues, EventRecord, EventSink,
    EventsConfig, FeedbackEntry, PostOutcome, Sink, StreamEntry, StreamWriter, VlClient, VlOptions,
    envelope,
};
use mg_edge_core::testkit::vl::{FakeVl, RecordingStreamWriter, VlReply, VlRequest};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Generous upper bound for anything that should happen "promptly"; tests
/// only rely on lower bounds for timing, so a loaded machine cannot flake them.
const PROMPT: Duration = Duration::from_secs(10);

fn base_cfg() -> EventsConfig {
    EventsConfig {
        // Long interval: flushes in these tests are triggered explicitly
        // (thresholds or shutdown) unless a test shortens it.
        flush_interval_ms: 60_000,
        ..EventsConfig::default()
    }
}

/// Short retry schedule so retry tests finish quickly.
fn fast_options() -> VlOptions {
    VlOptions {
        timeout: Duration::from_millis(500),
        backoff: vec![
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(150),
        ],
    }
}

fn line(kind: &str, seq: usize) -> String {
    envelope(
        kind,
        "blog",
        1_790_000_000_000 + seq as i64,
        &format!("{kind} {seq}"),
        json!({"seq": seq}),
    )
}

fn record(class: EventClass, seq: usize) -> EventRecord {
    let kind = match class {
        EventClass::Priority => "decision",
        EventClass::Access => "access",
        EventClass::Sampled => "telemetry",
    };
    let target = if class == EventClass::Sampled {
        Sink::Short
    } else {
        Sink::Main
    };
    EventRecord::new(class, target, line(kind, seq))
}

/// `seq` of every line in a request body.
fn seqs(req: &VlRequest) -> Vec<u64> {
    req.lines()
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect()
}

struct Running {
    queues: EventQueues,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(
        cfg: &EventsConfig,
        vl: Option<VlClient>,
        file: Option<PathBuf>,
        stream: Option<Arc<dyn StreamWriter>>,
    ) -> Self {
        let (queues, flusher) = EventQueues::new(cfg);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(flusher.run(vl, file, stream, shutdown));
        Self { queues, stop, task }
    }

    fn send(&self, record: EventRecord) {
        assert!(self.queues.try_send(record), "queue unexpectedly full");
    }

    /// Signals shutdown and waits for the flusher; returns how long it took.
    async fn shutdown(self) -> (EventMetrics, Duration) {
        let started = Instant::now();
        self.stop.send(true).unwrap();
        tokio::time::timeout(PROMPT, self.task)
            .await
            .expect("flusher did not stop")
            .unwrap();
        (self.queues.metrics().clone(), started.elapsed())
    }
}

fn main_client(vl: &FakeVl) -> VlClient {
    VlClient::with_options(Some(&vl.url()), None, fast_options()).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "mg-events-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// §13.1: method, path, query parameters, Content-Type, User-Agent (I-7) and
/// the JSON-line body whose lines start with the envelope fields.
#[tokio::test]
async fn vl_request_wire_format_13_1() {
    let vl = FakeVl::start().unwrap();
    let run = Running::start(&base_cfg(), Some(main_client(&vl)), None, None);
    for seq in 0..3 {
        run.send(record(EventClass::Priority, seq));
    }
    let (metrics, _) = run.shutdown().await;

    let requests = vl.requests();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/insert/jsonline");
    assert_eq!(
        req.query.as_deref(),
        Some("_stream_fields=kind,site&_time_field=ts&_msg_field=msg")
    );
    assert_eq!(
        req.query_pairs(),
        vec![
            ("_stream_fields".to_owned(), "kind,site".to_owned()),
            ("_time_field".to_owned(), "ts".to_owned()),
            ("_msg_field".to_owned(), "msg".to_owned()),
        ]
    );
    assert_eq!(req.header("content-type"), Some("application/stream+json"));
    assert_eq!(req.header("user-agent"), Some("morphgate-dev-tooling"));
    assert!(
        req.body.ends_with(b"\n"),
        "every line is newline-terminated"
    );
    assert_eq!(
        req.header("content-length"),
        Some(req.body.len().to_string().as_str())
    );
    let lines = req.lines();
    assert_eq!(lines.len(), 3);
    for (seq, l) in lines.iter().enumerate() {
        assert!(
            l.starts_with(r#"{"kind":"decision","site":"blog","ts":"#),
            "envelope first: {l}"
        );
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["msg"], format!("decision {seq}"));
        assert_eq!(v["seq"], seq);
    }
    for sink in DropSink::ALL {
        for class in EventClass::ALL {
            assert_eq!(metrics.dropped(sink, class), 0, "{sink:?} {class:?}");
        }
    }
}

/// §9.11: `max_batch_lines` pending records trigger a flush without waiting
/// for the interval, and each batch holds at most that many lines.
#[tokio::test]
async fn line_threshold_flushes_full_batches_only() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        max_batch_lines: 3,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(main_client(&vl)), None, None);
    for seq in 0..7 {
        run.send(record(EventClass::Access, seq));
    }
    let requests = vl.wait_for_requests(2, PROMPT).await;
    assert_eq!(requests.len(), 2);
    assert_eq!(seqs(&requests[0]), vec![0, 1, 2]);
    assert_eq!(seqs(&requests[1]), vec![3, 4, 5]);
    // The 7th record is below the threshold and the interval is 60 s.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        vl.requests().len(),
        2,
        "partial batch sent before the interval"
    );
    // It left the request queue at once; VictoriaLogs holds it.
    assert_eq!(run.queues.pending(), (0, 0));
    // Shutdown only flushes P0; the held P1 record is counted as lost there.
    let (metrics, _) = run.shutdown().await;
    assert_eq!(vl.requests().len(), 2);
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
        1
    );
    assert_eq!(metrics.dropped(DropSink::Buffer, EventClass::Access), 0);
}

/// §9.11: `max_batch_bytes` bounds every body; a single larger line travels alone.
#[tokio::test]
async fn byte_threshold_bounds_each_body() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        max_batch_bytes: 1024,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(main_client(&vl)), None, None);
    let padded = |seq: usize, pad: usize| {
        EventRecord::new(
            EventClass::Priority,
            Sink::Main,
            envelope(
                "decision",
                "blog",
                1,
                "m",
                json!({"seq": seq, "pad": "x".repeat(pad)}),
            ),
        )
    };
    // ~300-byte lines: three fit into 1024 bytes, four do not.
    for seq in 0..6 {
        run.send(padded(seq, 250));
    }
    // A 2000-byte line exceeds the budget on its own.
    run.send(padded(6, 2000));
    let requests = vl.wait_for_requests(3, PROMPT).await;
    let (_, _) = run.shutdown().await;
    let requests = if requests.len() >= 3 {
        requests
    } else {
        vl.requests()
    };
    let batches: Vec<Vec<u64>> = requests.iter().map(seqs).collect();
    assert_eq!(batches, vec![vec![0, 1, 2], vec![3, 4, 5], vec![6]]);
    for req in &requests[..2] {
        assert!(req.body.len() <= 1024, "{}", req.body.len());
    }
    assert!(requests[2].body.len() > 1024);
}

/// §9.11: below both thresholds, records wait for `flush_interval_ms`.
#[tokio::test]
async fn interval_flushes_partial_batch() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        flush_interval_ms: 400,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(main_client(&vl)), None, None);
    let sent = Instant::now();
    run.send(record(EventClass::Access, 0));
    run.send(record(EventClass::Access, 1));
    let requests = vl.wait_for_requests(1, PROMPT).await;
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].received_at.duration_since(sent) >= Duration::from_millis(300),
        "flushed after {:?}, before the interval",
        requests[0].received_at.duration_since(sent)
    );
    assert_eq!(seqs(&requests[0]), vec![0, 1]);
    run.shutdown().await;
}

/// §9.11 / §13.1: 429 and 5xx are retried with the backoff schedule; the
/// same body is re-sent and finally accepted.
#[tokio::test]
async fn retries_429_and_5xx_with_backoff() {
    let vl = FakeVl::start().unwrap();
    vl.push_replies([
        VlReply::Status(429),
        VlReply::Status(500),
        VlReply::Status(503),
    ]);
    let client = main_client(&vl);
    let outcome = client
        .post_batch(Sink::Main, line("decision", 1).into_bytes())
        .await;
    assert_eq!(outcome, PostOutcome::Accepted { attempts: 4 });
    let requests = vl.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|r| r.body == requests[0].body));
    let backoff = fast_options().backoff;
    for (i, pair) in requests.windows(2).enumerate() {
        let gap = pair[1].received_at.duration_since(pair[0].received_at);
        assert!(
            gap >= backoff[i],
            "retry {i} after {gap:?}, backoff {:?}",
            backoff[i]
        );
    }
}

/// §9.11: after the third retry fails the batch is dropped and counted per class.
#[tokio::test]
async fn exhausted_retries_drop_and_count() {
    let vl = FakeVl::start().unwrap();
    vl.set_default_reply(VlReply::Status(500));
    let cfg = EventsConfig {
        max_batch_lines: 3,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(main_client(&vl)), None, None);
    run.send(record(EventClass::Priority, 0));
    run.send(record(EventClass::Access, 1));
    run.send(record(EventClass::Access, 2));
    let requests = vl.wait_for_requests(4, PROMPT).await;
    assert_eq!(requests.len(), 4, "1 attempt + 3 retries");
    // Wait until the flusher has accounted for the failure, then stop it
    // (nothing left). Stopping earlier would interrupt the batch and give its
    // P0 line a final attempt, so a fixed sleep could flake on a slow machine.
    let deadline = Instant::now() + PROMPT;
    while run
        .queues
        .metrics()
        .dropped(DropSink::VictoriaLogs, EventClass::Access)
        < 2
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (metrics, _) = run.shutdown().await;
    assert_eq!(vl.requests().len(), 4, "no further attempts");
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        1
    );
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
        2
    );
}

/// §13.1: other 4xx responses drop the batch without retrying.
#[tokio::test]
async fn other_4xx_is_not_retried() {
    for status in [400, 404, 413] {
        let vl = FakeVl::start().unwrap();
        vl.push_replies([VlReply::Status(status)]);
        let outcome = main_client(&vl)
            .post_batch(Sink::Main, line("access", 0).into_bytes())
            .await;
        assert_eq!(outcome, PostOutcome::Rejected { status });
        assert_eq!(vl.requests().len(), 1, "{status} must not be retried");
    }
}

/// §13.1: a timeout, a dropped connection and a refused connection are retried.
#[tokio::test]
async fn transport_failures_are_retried() {
    let vl = FakeVl::start().unwrap();
    vl.push_replies([VlReply::Hang, VlReply::Close]);
    let outcome = main_client(&vl)
        .post_batch(Sink::Main, line("decision", 0).into_bytes())
        .await;
    assert_eq!(outcome, PostOutcome::Accepted { attempts: 3 });

    // Nothing listens on a port that was just released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = VlClient::with_options(
        Some(&format!("http://127.0.0.1:{port}")),
        None,
        fast_options(),
    )
    .unwrap();
    let outcome = client.post_batch(Sink::Main, b"{}\n".to_vec()).await;
    assert_eq!(outcome, PostOutcome::Failed { attempts: 4 });
    assert_eq!(
        client.post_batch(Sink::Short, b"{}\n".to_vec()).await,
        PostOutcome::NoEndpoint
    );
}

/// Loopback responder that answers each of its next `connections`
/// connections with `status` and `Location: <location>`, then stops.
fn redirecting_server(status: u16, location: String, connections: usize) -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(connections) {
            let Ok(mut stream) = stream else { continue };
            // The request (head and small body) arrives in one read.
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.read(&mut [0u8; 64 * 1024]);
            let response = format!(
                "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    addr
}

/// §13.1 / D-31: event bodies carry request data (client IPs, paths), so the
/// client never follows a redirect: a 307 / 308 would re-send the whole body
/// to whatever host `Location` names. A redirect status drops the batch like
/// any other non-retryable status.
#[tokio::test]
async fn redirects_are_never_followed() {
    for status in [301, 302, 303, 307, 308] {
        let elsewhere = FakeVl::start().unwrap();
        let addr = redirecting_server(status, format!("{}/insert/jsonline", elsewhere.url()), 2);
        let client =
            VlClient::with_options(Some(&format!("http://{addr}")), None, fast_options()).unwrap();
        let outcome = client
            .post_batch(Sink::Main, line("decision", 0).into_bytes())
            .await;
        assert_eq!(outcome, PostOutcome::Rejected { status });
        assert!(
            elsewhere.requests().is_empty(),
            "VlClient followed a {status}"
        );

        // Control: reqwest's default policy follows the same response, so
        // the assertion above is not vacuous.
        let plain = reqwest::Client::builder().no_proxy().build().unwrap();
        plain
            .post(format!("http://{addr}/insert/jsonline"))
            .body("{}\n")
            .send()
            .await
            .unwrap();
        assert_eq!(
            elsewhere.requests().len(),
            1,
            "control client did not follow the {status}"
        );
    }
}

/// §2.4 items 4–5 / D-31: the `Debug` output of the request-path types never
/// contains a line's content or the request's stream values.
#[test]
fn debug_output_never_contains_event_data() {
    let secret_line = envelope(
        "decision",
        "blog",
        1,
        "block rule.x route=reset score=90",
        json!({"ctx": {"net": {"ip": "203.0.113.77"}, "http": {"path": "/reset/tok3n-secret"}}}),
    );
    let record = EventRecord::new(EventClass::Priority, Sink::Main, secret_line)
        .with_stream(decision_entry("rid-secret"));
    let (queues, flusher) = EventQueues::new(&base_cfg());
    assert!(queues.try_send(record.clone()));
    let debug = [
        format!("{record:?}"),
        format!("{record:#?}"),
        format!("{queues:?}"),
        format!("{flusher:?}"),
    ];
    for text in &debug {
        for secret in [
            "203.0.113.77",
            "tok3n-secret",
            "rid-secret",
            "sess-1",
            "0123456789abcdef0123456789abcdef",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }
    assert!(debug[0].contains("Priority") && debug[0].contains("line_len"));
}

/// §9.11: a full class queue drops the new record and counts it, without
/// touching the other classes; the flusher drains P0 before P1 before P2.
#[tokio::test]
async fn full_queue_drops_new_records_and_p0_goes_first() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        queue_priority: 2,
        queue_access: 2,
        queue_sampled: 2,
        max_batch_lines: 3,
        ..base_cfg()
    };
    let (queues, flusher) = EventQueues::new(&cfg);
    // Offer lower classes first, and flood P2: arrival order must not matter.
    for seq in 0..5 {
        let accepted = queues.try_send(EventRecord::new(
            EventClass::Sampled,
            Sink::Main,
            line("decision", 200 + seq),
        ));
        assert_eq!(accepted, seq < 2, "P2 record {seq}");
    }
    for seq in 0..3 {
        assert_eq!(
            queues.try_send(record(EventClass::Access, 100 + seq)),
            seq < 2
        );
    }
    for seq in 0..3 {
        assert_eq!(queues.try_send(record(EventClass::Priority, seq)), seq < 2);
    }
    let metrics = queues.metrics();
    assert_eq!(metrics.dropped(DropSink::Buffer, EventClass::Sampled), 3);
    assert_eq!(metrics.dropped(DropSink::Buffer, EventClass::Access), 1);
    assert_eq!(metrics.dropped(DropSink::Buffer, EventClass::Priority), 1);

    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(flusher.run(Some(main_client(&vl)), None, None, shutdown));
    let requests = vl.wait_for_requests(2, PROMPT).await;
    assert_eq!(seqs(&requests[0]), vec![0, 1, 100], "P0 first, then P1");
    assert_eq!(seqs(&requests[1]), vec![101, 200, 201], "then P2");
    stop.send(true).unwrap();
    task.await.unwrap();
}

/// §9.11: a byte-limited batch is closed rather than topped up with
/// lower-class records, so priority order holds across batches.
#[tokio::test]
async fn byte_budget_keeps_strict_class_order() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        max_batch_bytes: 1024,
        max_batch_lines: 100,
        // The remainder after the first (full) batch is below both
        // thresholds, so the interval sends it.
        flush_interval_ms: 100,
        ..base_cfg()
    };
    let (queues, flusher) = EventQueues::new(&cfg);
    let big = |seq: usize| {
        EventRecord::new(
            EventClass::Priority,
            Sink::Main,
            envelope(
                "decision",
                "blog",
                1,
                "m",
                json!({"seq": seq, "pad": "x".repeat(550)}),
            ),
        )
    };
    assert!(queues.try_send(big(0)));
    assert!(queues.try_send(big(1)));
    assert!(queues.try_send(record(EventClass::Access, 100)));
    assert!(queues.try_send(record(EventClass::Access, 101)));
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(flusher.run(Some(main_client(&vl)), None, None, shutdown));
    let requests = vl.wait_for_requests(2, PROMPT).await;
    assert_eq!(seqs(&requests[0]), vec![0]);
    assert_eq!(seqs(&requests[1]), vec![1, 100, 101]);
    stop.send(true).unwrap();
    task.await.unwrap();
}

/// §9.11: lines go to the VictoriaLogs instance named by `target`; a target
/// without a configured URL is skipped without counting a drop.
#[tokio::test]
async fn records_are_routed_by_target_sink() {
    let main = FakeVl::start().unwrap();
    let short = FakeVl::start().unwrap();
    let client =
        VlClient::with_options(Some(&main.url()), Some(&short.url()), fast_options()).unwrap();
    let run = Running::start(&base_cfg(), Some(client), None, None);
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Main,
        line("feedback", 1),
    ));
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Short,
        line("telemetry", 2),
    ));
    run.shutdown().await;
    assert_eq!(main.accepted_lines(), vec![line("feedback", 1)]);
    assert_eq!(short.accepted_lines(), vec![line("telemetry", 2)]);

    let only_main = FakeVl::start().unwrap();
    let run = Running::start(&base_cfg(), Some(main_client(&only_main)), None, None);
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Short,
        line("telemetry", 3),
    ));
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Main,
        line("decision", 4),
    ));
    let (metrics, _) = run.shutdown().await;
    assert_eq!(only_main.accepted_lines(), vec![line("decision", 4)]);
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
}

/// §9.11 file sink: every line of both sinks, in batch order, owner-only
/// permissions; a failing file counts `sink="file"` drops without affecting
/// VictoriaLogs.
#[tokio::test]
async fn file_sink_appends_every_line() {
    let dir = temp_dir("file");
    let path = dir.join("events.jsonl");
    let cfg = EventsConfig {
        flush_interval_ms: 50,
        ..base_cfg()
    };
    let run = Running::start(&cfg, None, Some(path.clone()), None);
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Main,
        line("decision", 0),
    ));
    run.send(EventRecord::new(
        EventClass::Sampled,
        Sink::Short,
        line("telemetry", 1),
    ));
    run.send(EventRecord::new(
        EventClass::Access,
        Sink::Main,
        line("access", 2),
    ));
    let deadline = Instant::now() + PROMPT;
    while std::fs::read_to_string(&path).map_or(0, |s| s.lines().count()) < 3
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    run.send(EventRecord::new(
        EventClass::Priority,
        Sink::Main,
        line("feedback", 3),
    ));
    run.shutdown().await;
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // Batch order is P0, P1, P2; the shutdown flush appends the last P0 record.
    assert_eq!(
        lines,
        vec![
            line("decision", 0),
            line("access", 2),
            line("telemetry", 1),
            line("feedback", 3)
        ]
    );
    assert!(text.ends_with('\n'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "events file readable by others: {mode:o}");
    }

    // A directory cannot be appended to: file drops are counted, VL unaffected.
    let vl = FakeVl::start().unwrap();
    let run = Running::start(&base_cfg(), Some(main_client(&vl)), Some(dir.clone()), None);
    run.send(record(EventClass::Priority, 7));
    let (metrics, _) = run.shutdown().await;
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 1);
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
    assert_eq!(vl.accepted_lines().len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn decision_entry(rid: &str) -> StreamEntry {
    StreamEntry::decision(&DecisionEntry {
        site: "blog",
        ts_ms: 1_790_000_000_123,
        request_id: rid,
        session: Some("sess-1"),
        route: "login",
        action: Action::Challenge,
        dry_run: true,
        class: BotClass::AutomationLikely,
        score: 45,
        ipk: Some("0123456789abcdef0123456789abcdef"),
        pfk: Some("fedcba9876543210fedcba9876543210"),
        asn: Some(64500),
        status: Some(403),
    })
}

/// §13.6: the writer receives every entry of the batch (stream-only records
/// included, not sampled), fields in contract order, with `stream_maxlen`.
#[tokio::test]
async fn stream_writer_receives_ordered_entries() {
    let vl = FakeVl::start().unwrap();
    let writer = RecordingStreamWriter::new();
    let cfg = EventsConfig {
        stream_maxlen: 1234,
        flush_interval_ms: 50,
        ..base_cfg()
    };
    let run = Running::start(
        &cfg,
        Some(main_client(&vl)),
        None,
        Some(writer.clone() as Arc<dyn StreamWriter>),
    );
    run.send(record(EventClass::Priority, 0).with_stream(decision_entry("r0")));
    // A sampled-out decision: no log line, but its stream entry.
    run.send(EventRecord::stream_only(
        EventClass::Sampled,
        decision_entry("r1"),
    ));
    run.send(
        EventRecord::new(EventClass::Priority, Sink::Main, line("feedback", 2)).with_stream(
            StreamEntry::feedback(&FeedbackEntry {
                site: "blog",
                ts_ms: 1_790_000_000_124,
                request_id: "r2",
                route: "login",
                outcome: VerdictOutcome::Pass,
                challenge_type: ChallengeType::Pow,
                pfk: None,
                asn: None,
            }),
        ),
    );
    // All three are queued before the flusher runs again (no await above),
    // so the next tick sends them as one batch.
    let deadline = Instant::now() + PROMPT;
    while writer.entries().len() < 3 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    run.shutdown().await;

    assert_eq!(
        vl.accepted_lines().len(),
        2,
        "stream-only record has no line"
    );
    let batches = writer.batches();
    assert_eq!(batches.len(), 1, "one XADD pipeline per batch");
    assert_eq!(batches[0].0, 1234);
    let entries = &batches[0].1;
    assert_eq!(entries.len(), 3);
    let names = |e: &StreamEntry| e.fields().iter().map(|(n, _)| *n).collect::<Vec<_>>();
    // P0 records first (r0, r2), then the P2 stream-only record (r1).
    assert_eq!(entries[0].get("rid"), Some("r0"));
    assert_eq!(entries[1].get("rid"), Some("r2"));
    assert_eq!(entries[2].get("rid"), Some("r1"));
    assert_eq!(
        names(&entries[0]),
        [
            "v", "kind", "site", "ts", "rid", "sess", "route", "action", "dry", "class", "score",
            "ipk", "pfk", "asn", "status"
        ]
    );
    let values: Vec<&str> = entries[0]
        .fields()
        .iter()
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        values,
        [
            "1",
            "decision",
            "blog",
            "1790000000123",
            "r0",
            "sess-1",
            "login",
            "challenge",
            "1",
            "automation_likely",
            "45",
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
            "64500",
            "403"
        ]
    );
    assert_eq!(
        entries[1].fields(),
        [
            ("v", "1".to_owned()),
            ("kind", "feedback".to_owned()),
            ("site", "blog".to_owned()),
            ("ts", "1790000000124".to_owned()),
            ("rid", "r2".to_owned()),
            ("route", "login".to_owned()),
            ("outcome", "pass".to_owned()),
            ("type", "pow".to_owned()),
            ("pfk", String::new()),
            ("asn", "0".to_owned()),
        ]
    );
    // Never the client IP in clear.
    for entry in entries {
        assert!(
            entry
                .fields()
                .iter()
                .all(|(n, _)| *n != "ip" && *n != "client_conn_key")
        );
    }
}

/// §9.11: a failed `XADD` batch is counted as `sink="stream"` and never retried.
#[tokio::test]
async fn stream_failure_is_counted_not_retried() {
    let writer = RecordingStreamWriter::new();
    writer.set_fail(true);
    let run = Running::start(
        &base_cfg(),
        None,
        None,
        Some(writer.clone() as Arc<dyn StreamWriter>),
    );
    run.send(EventRecord::stream_only(
        EventClass::Priority,
        decision_entry("a"),
    ));
    run.send(EventRecord::stream_only(
        EventClass::Priority,
        decision_entry("b"),
    ));
    let (metrics, _) = run.shutdown().await;
    assert_eq!(writer.calls(), 1);
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 2);
}

/// A writer whose `XADD` never answers (Valkey stalled behind a black hole).
struct HangingStreamWriter;

impl StreamWriter for HangingStreamWriter {
    fn xadd_batch(
        &self,
        _maxlen: u64,
        _entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(std::future::pending())
    }
}

/// §9.11: an `XADD` batch that never answers is a failed write. The flusher
/// abandons it after its stream timeout (5 s), counts it as `sink="stream"`
/// without retrying, and keeps delivering later batches.
#[tokio::test]
async fn hung_stream_write_is_abandoned_and_counted() {
    let vl = FakeVl::start().unwrap();
    let cfg = EventsConfig {
        flush_interval_ms: 50,
        ..base_cfg()
    };
    let run = Running::start(
        &cfg,
        Some(main_client(&vl)),
        None,
        Some(Arc::new(HangingStreamWriter)),
    );
    run.send(record(EventClass::Priority, 0).with_stream(decision_entry("r0")));
    // The line is delivered at once; only the stream part hangs.
    assert_eq!(vl.wait_for_accepted_lines(1, PROMPT).await.len(), 1);
    let metrics = run.queues.metrics().clone();
    let deadline = Instant::now() + PROMPT;
    while metrics.dropped(DropSink::Stream, EventClass::Priority) == 0 && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        metrics.dropped(DropSink::Stream, EventClass::Priority),
        1,
        "hung XADD never abandoned"
    );
    // The pipeline is not stuck behind the abandoned write.
    run.send(record(EventClass::Priority, 1));
    assert_eq!(vl.wait_for_accepted_lines(2, PROMPT).await.len(), 2);
    let (metrics, _) = run.shutdown().await;
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
}

/// §9.1.1 item 4: on shutdown the queued P0 records are delivered; P1 / P2
/// records VictoriaLogs still holds are counted as lost there (I-25: per
/// output); the queues close.
#[tokio::test]
async fn shutdown_sends_remaining_p0_only() {
    let vl = FakeVl::start().unwrap();
    let run = Running::start(&base_cfg(), Some(main_client(&vl)), None, None);
    for seq in 0..2 {
        run.send(record(EventClass::Priority, seq));
    }
    for seq in 10..13 {
        run.send(record(EventClass::Access, seq));
    }
    for seq in 20..24 {
        run.send(record(EventClass::Sampled, seq));
    }
    let queues = run.queues.clone();
    let (metrics, _) = run.shutdown().await;
    let lines = vl.accepted_lines();
    assert_eq!(lines, vec![line("decision", 0), line("decision", 1)]);
    for class in EventClass::ALL {
        assert_eq!(metrics.dropped(DropSink::Buffer, class), 0);
    }
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
        3
    );
    // The P2 records target vl_short, which is not configured: never
    // written there, so never lost there.
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        0
    );
    // The flusher is gone: offering more fails fast and is counted.
    assert!(!queues.try_send(record(EventClass::Priority, 99)));
    assert_eq!(metrics.dropped(DropSink::Buffer, EventClass::Priority), 1);
}

/// §9.1.1 item 4: the shutdown flush takes at most 2 s even when
/// VictoriaLogs hangs; what could not be delivered is counted.
#[tokio::test]
async fn shutdown_flush_is_bounded_when_vl_hangs() {
    let vl = FakeVl::start().unwrap();
    vl.set_default_reply(VlReply::Hang);
    let client = VlClient::with_options(Some(&vl.url()), None, VlOptions::default()).unwrap();
    let cfg = EventsConfig {
        flush_interval_ms: 50,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(client), None, None);
    run.send(record(EventClass::Priority, 0));
    run.send(EventRecord::new(
        EventClass::Sampled,
        Sink::Main,
        line("telemetry", 1),
    ));
    // The batch is now in flight against a server that never answers.
    assert_eq!(vl.wait_for_requests(1, PROMPT).await.len(), 1);
    let (metrics, took) = run.shutdown().await;
    assert!(took < Duration::from_millis(3500), "shutdown took {took:?}");
    assert!(
        took >= Duration::from_millis(1900),
        "final P0 attempt skipped: {took:?}"
    );
    // The interrupted batch was retried with its P0 line only.
    let last = vl.requests().pop().unwrap();
    assert_eq!(seqs(&last), vec![0]);
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        1
    );
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        1
    );
}

/// §9.1.1 item 4: shutdown interrupts a retry backoff; the interrupted
/// batch's P0 lines get their final attempt.
#[tokio::test]
async fn shutdown_interrupts_retry_backoff() {
    let vl = FakeVl::start().unwrap();
    vl.push_replies([VlReply::Status(500)]);
    let client = VlClient::with_options(
        Some(&vl.url()),
        None,
        VlOptions {
            timeout: Duration::from_secs(5),
            backoff: vec![Duration::from_secs(60)],
        },
    )
    .unwrap();
    let cfg = EventsConfig {
        flush_interval_ms: 50,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(client), None, None);
    run.send(record(EventClass::Priority, 0));
    run.send(EventRecord::new(
        EventClass::Sampled,
        Sink::Main,
        line("telemetry", 1),
    ));
    assert_eq!(vl.wait_for_requests(1, PROMPT).await.len(), 1);
    // The flusher now sleeps 60 s before its retry.
    let (metrics, took) = run.shutdown().await;
    assert!(took < Duration::from_millis(2500), "shutdown took {took:?}");
    assert_eq!(vl.accepted_lines(), vec![line("decision", 0)]);
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        1
    );
}

/// A dropped shutdown sender also stops the flusher.
#[tokio::test]
async fn dropped_shutdown_sender_stops_flusher() {
    let (queues, flusher) = EventQueues::new(&base_cfg());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(flusher.run(None, None, None, shutdown));
    drop(stop);
    tokio::time::timeout(PROMPT, task).await.unwrap().unwrap();
    assert!(!queues.try_send(record(EventClass::Priority, 0)));
}

/// §9.11 "never blocks": without a running flusher, `try_send` returns at
/// once whether or not the queue has room, and a line that would break the
/// JSONL framing is refused.
#[test]
fn try_send_never_blocks_and_rejects_raw_newlines() {
    let cfg = EventsConfig {
        queue_priority: 1,
        ..base_cfg()
    };
    let (queues, flusher) = EventQueues::new(&cfg);
    assert!(queues.try_send(record(EventClass::Priority, 0)));
    let started = Instant::now();
    for seq in 0..10_000 {
        assert!(!queues.try_send(record(EventClass::Priority, seq)));
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        queues
            .metrics()
            .dropped(DropSink::Buffer, EventClass::Priority),
        10_000
    );
    for bad in ["{\"a\":1}\n{\"b\":2}", "{\"a\":\r1}"] {
        assert!(!queues.try_send(EventRecord::new(EventClass::Access, Sink::Main, bad.into())));
    }
    assert_eq!(
        queues
            .metrics()
            .dropped(DropSink::Buffer, EventClass::Access),
        2
    );
    // An empty record carries nothing and is not a loss.
    assert!(queues.try_send(EventRecord::new(
        EventClass::Sampled,
        Sink::Main,
        String::new()
    )));
    assert_eq!(queues.pending().0, 1);
    // Dropping the flusher closes the queues.
    drop(flusher);
    assert!(!queues.try_send(record(EventClass::Access, 1)));
    assert!(format!("{queues:?}").contains("pending_items"));
}

/// `mg_event_dropped_total{sink, class}` (§13.7): all 12 series exist from
/// the start; registering twice in one registry fails.
#[test]
fn metrics_register_with_all_label_combinations() {
    let metrics = EventMetrics::new();
    let registry = prometheus::Registry::new();
    metrics.register(&registry).unwrap();
    assert!(metrics.register(&registry).is_err());
    let families = registry.gather();
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].name(), "mg_event_dropped_total");
    let mut labels: Vec<(String, String)> = families[0]
        .get_metric()
        .iter()
        .map(|m| {
            let get = |name: &str| {
                m.get_label()
                    .iter()
                    .find(|l| l.name() == name)
                    .unwrap()
                    .value()
                    .to_owned()
            };
            (get("sink"), get("class"))
        })
        .collect();
    labels.sort();
    let mut want = Vec::new();
    for sink in ["buffer", "file", "stream", "victorialogs"] {
        for class in ["access", "priority", "sampled"] {
            want.push((sink.to_owned(), class.to_owned()));
        }
    }
    assert_eq!(labels, want);
}

/// The fake itself: keep-alive requests on one connection are all recorded.
#[tokio::test]
async fn fake_vl_records_sequential_requests() {
    let vl = FakeVl::start().unwrap();
    let client = main_client(&vl);
    for seq in 0..3 {
        let outcome = client
            .post_batch(
                Sink::Main,
                format!("{}\n", line("decision", seq)).into_bytes(),
            )
            .await;
        assert_eq!(outcome, PostOutcome::Accepted { attempts: 1 });
    }
    assert_eq!(vl.accepted_lines().len(), 3);
    assert!(vl.requests().iter().all(VlRequest::accepted));
}

/// The fake also understands chunked bodies and answers scripted statuses
/// on a keep-alive connection (raw HTTP/1.1 over loopback).
#[test]
fn fake_vl_parses_chunked_bodies() {
    use std::io::{Read, Write};
    let vl = FakeVl::start().unwrap();
    vl.push_replies([VlReply::Status(429)]);
    let mut conn = std::net::TcpStream::connect(vl.addr()).unwrap();
    conn.set_read_timeout(Some(PROMPT)).unwrap();
    let request = "POST /insert/jsonline?_msg_field=msg HTTP/1.1\r\nHost: x\r\n\
                   Transfer-Encoding: chunked\r\n\r\n\
                   5\r\n{\"a\":\r\n4;ext=1\r\n1}\n{\r\n3\r\n\"b\"\r\n4\r\n:2}\n\r\n0\r\n\r\n";
    conn.write_all(request.as_bytes()).unwrap();
    let mut response = [0u8; 256];
    let n = conn.read(&mut response).unwrap();
    assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 429 "));
    conn.write_all(b"POST /insert/jsonline HTTP/1.1\r\nContent-Length: 8\r\nConnection: close\r\n\r\n{\"c\":3}\n")
        .unwrap();
    let n = conn.read(&mut response).unwrap();
    assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200 "));
    let requests = vl.wait_for_requests_blocking(2, PROMPT);
    assert_eq!(requests[0].lines(), vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    assert_eq!(requests[0].query.as_deref(), Some("_msg_field=msg"));
    assert!(!requests[0].accepted());
    assert_eq!(requests[1].lines(), vec![r#"{"c":3}"#]);
    assert_eq!(vl.accepted_lines(), vec![r#"{"c":3}"#]);
}

// ---------------------------------------------------------------------------
// Ruling I-25: VictoriaLogs, the file and mg:ev are independent outputs.

/// Waits until `path` holds at least `n` lines; returns them.
async fn wait_file_lines(path: &std::path::Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + PROMPT;
    loop {
        let lines: Vec<String> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        if lines.len() >= n || Instant::now() >= deadline {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// I-25: while VictoriaLogs hangs on a batch, later records still reach the
/// file and `mg:ev` at their own pace (with one shared flusher they waited
/// for VictoriaLogs' retries, about 26 s per batch).
#[tokio::test]
async fn hanging_victorialogs_does_not_hold_back_file_or_stream() {
    let vl = FakeVl::start().unwrap();
    vl.set_default_reply(VlReply::Hang);
    let client = VlClient::with_options(
        Some(&vl.url()),
        None,
        VlOptions {
            timeout: Duration::from_secs(60),
            backoff: vec![],
        },
    )
    .unwrap();
    let dir = temp_dir("decoupled");
    let path = dir.join("events.jsonl");
    let writer = RecordingStreamWriter::new();
    let cfg = EventsConfig {
        flush_interval_ms: 20,
        ..base_cfg()
    };
    let run = Running::start(
        &cfg,
        Some(client),
        Some(path.clone()),
        Some(writer.clone() as Arc<dyn StreamWriter>),
    );
    run.send(record(EventClass::Priority, 0).with_stream(decision_entry("r0")));
    // VictoriaLogs now holds the first batch and never answers.
    assert_eq!(vl.wait_for_requests(1, PROMPT).await.len(), 1);
    assert_eq!(wait_file_lines(&path, 1).await.len(), 1);
    for seq in 1..=3 {
        run.send(record(EventClass::Priority, seq).with_stream(decision_entry(&format!("r{seq}"))));
        let lines = wait_file_lines(&path, seq + 1).await;
        assert_eq!(lines.len(), seq + 1, "file stalled behind VictoriaLogs");
    }
    let deadline = Instant::now() + PROMPT;
    while writer.entries().len() < 4 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        writer.entries().len(),
        4,
        "stream stalled behind VictoriaLogs"
    );
    // VictoriaLogs is still on its first request.
    assert_eq!(vl.requests().len(), 1);
    let metrics = run.queues.metrics().clone();
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 0);
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 0);

    // Shutdown: VictoriaLogs gets its final attempt (it hangs again) and
    // what it still holds is counted there only.
    let (metrics, took) = run.shutdown().await;
    assert!(took < Duration::from_millis(3500), "shutdown took {took:?}");
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        4
    );
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 0);
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// I-25: a failing `XADD` and a failing file only count their own drops;
/// VictoriaLogs receives every line.
#[tokio::test]
async fn failing_stream_and_file_do_not_affect_victorialogs() {
    let vl = FakeVl::start().unwrap();
    let writer = RecordingStreamWriter::new();
    writer.set_fail(true);
    let dir = temp_dir("failing-outputs");
    let cfg = EventsConfig {
        flush_interval_ms: 20,
        ..base_cfg()
    };
    // A directory cannot be appended to.
    let run = Running::start(
        &cfg,
        Some(main_client(&vl)),
        Some(dir.clone()),
        Some(writer.clone() as Arc<dyn StreamWriter>),
    );
    for seq in 0..5 {
        run.send(record(EventClass::Priority, seq).with_stream(decision_entry(&format!("r{seq}"))));
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(vl.wait_for_accepted_lines(5, PROMPT).await.len(), 5);
    let (metrics, _) = run.shutdown().await;
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 5);
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 5);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// I-25: each output's backlog is bounded per class. While VictoriaLogs
/// hangs, its backlog fills and further records are dropped for
/// VictoriaLogs only (counted `victorialogs`); the file keeps every line.
#[tokio::test]
async fn full_output_backlog_drops_for_that_output_only() {
    let vl = FakeVl::start().unwrap();
    vl.set_default_reply(VlReply::Hang);
    let client = VlClient::with_options(
        Some(&vl.url()),
        None,
        VlOptions {
            timeout: Duration::from_secs(60),
            backoff: vec![],
        },
    )
    .unwrap();
    let dir = temp_dir("backlog");
    let path = dir.join("events.jsonl");
    let cfg = EventsConfig {
        flush_interval_ms: 20,
        queue_priority: 2,
        queue_access: 2,
        queue_sampled: 2,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(client), Some(path.clone()), None);
    for seq in 0..10 {
        run.send(EventRecord::new(
            EventClass::Sampled,
            Sink::Main,
            line("decision", seq),
        ));
        assert_eq!(wait_file_lines(&path, seq + 1).await.len(), seq + 1);
        if seq == 0 {
            // The first record is VictoriaLogs' batch in flight.
            assert_eq!(vl.wait_for_requests(1, PROMPT).await.len(), 1);
        }
    }
    let metrics = run.queues.metrics().clone();
    // One in flight, two held, seven dropped at the full backlog.
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        7
    );
    for class in EventClass::ALL {
        assert_eq!(metrics.dropped(DropSink::File, class), 0);
        assert_eq!(metrics.dropped(DropSink::Buffer, class), 0);
    }
    // Shutdown flushes P0 only: the held and the in-flight record are lost too.
    let (metrics, took) = run.shutdown().await;
    assert!(took < Duration::from_secs(1), "no P0 to deliver: {took:?}");
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        10
    );
    assert_eq!(wait_file_lines(&path, 10).await.len(), 10);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §9.1.1 item 4 with I-25: the local file writes everything it still holds
/// at shutdown, every class, while VictoriaLogs only gets its P0 records.
#[tokio::test]
async fn shutdown_writes_every_class_to_the_file() {
    let vl = FakeVl::start().unwrap();
    let dir = temp_dir("file-shutdown");
    let path = dir.join("events.jsonl");
    let run = Running::start(
        &base_cfg(),
        Some(main_client(&vl)),
        Some(path.clone()),
        None,
    );
    run.send(record(EventClass::Sampled, 2));
    run.send(record(EventClass::Access, 1));
    run.send(record(EventClass::Priority, 0));
    let (metrics, _) = run.shutdown().await;
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![line("decision", 0), line("access", 1), line("telemetry", 2)]
    );
    assert_eq!(vl.accepted_lines(), vec![line("decision", 0)]);
    for class in EventClass::ALL {
        assert_eq!(metrics.dropped(DropSink::File, class), 0);
    }
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
        1
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// I-25: `vl_main` and `vl_short` are separate VictoriaLogs instances (30 d
/// and 7 d retention). A hung `vl_short` (telemetry) must not hold back
/// `vl_main` (decisions, access records, feedback): with one delivery loop
/// for both, every `vl_main` batch waited for the `vl_short` retries.
#[tokio::test]
async fn hanging_vl_short_does_not_hold_back_vl_main() {
    let main = FakeVl::start().unwrap();
    let short = FakeVl::start().unwrap();
    short.set_default_reply(VlReply::Hang);
    let client = VlClient::with_options(
        Some(&main.url()),
        Some(&short.url()),
        VlOptions {
            timeout: Duration::from_secs(60),
            backoff: vec![],
        },
    )
    .unwrap();
    let cfg = EventsConfig {
        flush_interval_ms: 20,
        ..base_cfg()
    };
    let run = Running::start(&cfg, Some(client), None, None);
    // A telemetry line: vl_short now holds it and never answers.
    run.send(record(EventClass::Sampled, 0));
    assert_eq!(short.wait_for_requests(1, PROMPT).await.len(), 1);
    for seq in 1..=3 {
        run.send(record(EventClass::Priority, seq));
        let lines = main
            .wait_for_accepted_lines(seq, Duration::from_secs(3))
            .await;
        assert_eq!(lines.len(), seq, "vl_main stalled behind vl_short");
    }
    // An access record (P1) goes the same way.
    run.send(record(EventClass::Access, 4));
    assert_eq!(
        main.wait_for_accepted_lines(4, Duration::from_secs(3))
            .await
            .len(),
        4
    );
    assert_eq!(
        short.requests().len(),
        1,
        "vl_short is still on its first batch"
    );
    let (metrics, took) = run.shutdown().await;
    assert!(took < Duration::from_millis(3500), "shutdown took {took:?}");
    for class in EventClass::ALL {
        assert_eq!(metrics.dropped(DropSink::Buffer, class), 0);
    }
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Priority),
        0
    );
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Access),
        0
    );
    // The hung telemetry line is the only loss, counted at VictoriaLogs.
    assert_eq!(
        metrics.dropped(DropSink::VictoriaLogs, EventClass::Sampled),
        1
    );
}
