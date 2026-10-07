//! `StateHandle` as the flusher's `StreamWriter` (ruling I-25, §9.11,
//! §13.6): entries reach `mg:ev` through the state service as one `XADD`
//! pipeline, fields in contract order; in local mode the batch fails and is
//! counted as `sink="stream"` while the other outputs are unaffected.
//!
//! The Valkey test is skipped (with `SKIPPED: …`) without a server.

use mg_core::{Action, BotClass};
use mg_edge_core::events::{
    DecisionEntry, DropSink, EventClass, EventQueues, EventRecord, EventSink, EventsConfig, Sink,
    StreamEntry, StreamWriter, envelope,
};
use mg_edge_core::state::{EVENT_STREAM_KEY, StateConfig, StateHandle, StateMode, StateService};
use mg_edge_core::testkit::valkey::ValkeyFixture;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const K: [u8; 32] = [7; 32];
const PROMPT: Duration = Duration::from_secs(10);

fn entry(site: &str, rid: &str) -> StreamEntry {
    StreamEntry::decision(&DecisionEntry {
        site,
        ts_ms: 1_790_000_000_123,
        request_id: rid,
        session: None,
        route: "default",
        action: Action::Allow,
        dry_run: true,
        class: BotClass::HumanLikely,
        score: 12,
        ipk: Some("0123456789abcdef0123456789abcdef"),
        pfk: Some("fedcba9876543210fedcba9876543210"),
        asn: Some(64500),
        status: Some(200),
    })
}

fn cfg() -> EventsConfig {
    EventsConfig {
        flush_interval_ms: 20,
        stream_maxlen: 10_000,
        ..EventsConfig::default()
    }
}

/// The `mg:ev` entries whose `site` field is `site`, as field lists.
async fn stream_entries(url: &str, site: &str) -> Vec<Vec<String>> {
    let mut conn = redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let raw: redis::Value = redis::cmd("XRANGE")
        .arg(EVENT_STREAM_KEY)
        .arg("-")
        .arg("+")
        .query_async(&mut conn)
        .await
        .unwrap();
    let redis::Value::Array(items) = raw else {
        panic!("XRANGE reply")
    };
    let mut ours = Vec::new();
    for item in items {
        let redis::Value::Array(parts) = item else {
            continue;
        };
        let Some(redis::Value::Array(fields)) = parts.get(1) else {
            continue;
        };
        let fields: Vec<String> = fields
            .iter()
            .map(|f| match f {
                redis::Value::BulkString(b) => String::from_utf8(b.clone()).unwrap(),
                _ => String::new(),
            })
            .collect();
        if fields.get(5).map(String::as_str) == Some(site) {
            ours.push(fields);
        }
    }
    ours
}

async fn wait_mode(h: &StateHandle, mode: StateMode) -> bool {
    let end = Instant::now() + PROMPT;
    while Instant::now() < end {
        if h.mode() == mode {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// I-25 / §13.6: the flusher writes `mg:ev` through `StateHandle`: every
/// entry of the batch, stream-only records included, fields in order.
#[tokio::test]
async fn state_handle_writes_the_stream() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let mut state_cfg = StateConfig::valkey(fx.url(), K);
    state_cfg.timeout_ms = 1_000;
    state_cfg.connect_timeout_ms = 1_000;
    let (service, handle) = StateService::new(state_cfg);
    let (stop_state, rx) = watch::channel(false);
    let state_task = tokio::spawn(service.run(rx));
    assert!(wait_mode(&handle, StateMode::Valkey).await);

    let site = fx.site().to_owned();
    let (queues, flusher) = EventQueues::new(&cfg());
    let (stop, shutdown) = watch::channel(false);
    let writer: Arc<dyn StreamWriter> = Arc::new(handle.clone());
    let task = tokio::spawn(flusher.run(None, None, Some(writer), shutdown));
    let line = envelope("decision", &site, 1, "allow", json!({"seq": 1}));
    assert!(queues.try_send(
        EventRecord::new(EventClass::Priority, Sink::Main, line).with_stream(entry(&site, "r1"))
    ));
    assert!(queues.try_send(EventRecord::stream_only(
        EventClass::Sampled,
        entry(&site, "r2")
    )));

    let deadline = Instant::now() + PROMPT;
    let mut ours = Vec::new();
    while ours.len() < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        ours = stream_entries(fx.url(), &site).await;
    }
    assert_eq!(ours.len(), 2, "{ours:?}");
    let want = |rid: &str| -> Vec<String> {
        entry(&site, rid)
            .fields()
            .iter()
            .flat_map(|(n, v)| [(*n).to_owned(), v.clone()])
            .collect()
    };
    assert_eq!(ours[0], want("r1"));
    assert_eq!(ours[1], want("r2"));
    stop.send(true).unwrap();
    tokio::time::timeout(PROMPT, task).await.unwrap().unwrap();
    assert_eq!(
        queues
            .metrics()
            .dropped(DropSink::Stream, EventClass::Priority),
        0
    );
    stop_state.send(true).unwrap();
    tokio::time::timeout(PROMPT, state_task)
        .await
        .unwrap()
        .unwrap();
}

/// I-25: in local mode `XADD` fails with the state layer's error; the
/// flusher counts `sink="stream"` for those entries only and the file still
/// receives every line.
#[tokio::test]
async fn local_mode_stream_failure_is_counted_and_isolated() {
    let (_service, handle) = StateService::new(StateConfig::local(K));
    let as_writer: &dyn StreamWriter = &handle;
    let direct = as_writer
        .xadd_batch(10, vec![entry("blog", "probe")])
        .await
        .expect_err("no Valkey in local mode");
    assert!(direct.contains("unavailable"), "{direct}");

    let dir = std::env::temp_dir().join(format!("mg-events-stream-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let (queues, flusher) = EventQueues::new(&cfg());
    let (stop, shutdown) = watch::channel(false);
    let writer: Arc<dyn StreamWriter> = Arc::new(handle);
    let task = tokio::spawn(flusher.run(None, Some(path.clone()), Some(writer), shutdown));
    for rid in ["a", "b"] {
        let line = envelope("decision", "blog", 1, rid, json!({}));
        assert!(
            queues.try_send(
                EventRecord::new(EventClass::Priority, Sink::Main, line)
                    .with_stream(entry("blog", rid))
            )
        );
    }
    let metrics = queues.metrics().clone();
    let deadline = Instant::now() + PROMPT;
    while metrics.dropped(DropSink::Stream, EventClass::Priority) < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(metrics.dropped(DropSink::Stream, EventClass::Priority), 2);
    stop.send(true).unwrap();
    tokio::time::timeout(PROMPT, task).await.unwrap().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    assert_eq!(metrics.dropped(DropSink::File, EventClass::Priority), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}
