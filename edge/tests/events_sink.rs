//! The Edge's events end to end (docs/impl/phase1-spec.md §9.11, §13.1-§13.6;
//! §15 WP-E1d `events_sink.rs`): a loopback fake VictoriaLogs (vl-main and
//! vl-short) and the file sink receive the four kinds (decision, access,
//! feedback, telemetry) with their envelope fields; `redact_path` hides the
//! path; ALLOW decisions on low routes are sampled while blocks, challenges
//! and critical routes are always kept; with Valkey, every request has its
//! `mg:ev` entry, sampled out or not.

mod common;

use common::challenge::{self, browser, from_page, solved, submit_form};
use common::policy::{default_route, field, glob, route, rule};
use common::valkey::Valkey;
use common::{Edge, TestEnv, blog_bundle, cf, get, sign, with_events, with_valkey};
use mg_edge_core::testkit::vl::FakeVl;
use mg_proto::v1::challenge_config::PowBits;
use mg_proto::v1::{Action, EventConfig, RouteSensitivity as S, SiteBundle};
use serde_json::Value;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

/// Enforce: a critical `login` route and a `members` route that requires
/// clearance, both with `redact_path`, a block rule, and ALLOW decisions
/// sampled at 0.
fn bundle() -> SiteBundle {
    let mut b = blog_bundle(1);
    b.monitor_only = false;
    b.events = Some(EventConfig {
        allow_sample_rate: 0.0,
        access_log: true,
        stream: true,
    });
    let c = b.challenge.as_mut().unwrap();
    c.pow_bits = Some(PowBits {
        low: 8,
        medium: 9,
        high: 10,
        very_high: 11,
    });
    c.submit_rate = 1000;
    c.submit_burst = 1000;
    c.max_failures = 1000;
    let env = &mut b.environments[0];
    let mut login = route("login", &["/account/login"], S::Critical, false, false);
    login.redact_path = true;
    let mut members = route("members", &["/members/**"], S::Medium, true, false);
    members.redact_path = true;
    env.routes = vec![login, members, default_route()];
    env.rules = vec![rule(
        "block-bad",
        "custom",
        Action::Block,
        glob(field("req.path"), "/blocked/**"),
        &[],
    )];
    b
}

struct Sinks {
    main: FakeVl,
    short: FakeVl,
    file: std::path::PathBuf,
}

fn start(env: &TestEnv, b: &SiteBundle, config: &str) -> (Edge, Sinks) {
    let sinks = Sinks {
        main: FakeVl::start().unwrap(),
        short: FakeVl::start().unwrap(),
        file: env.dir.join("events.jsonl"),
    };
    let config = with_events(
        config,
        &format!(
            "vl_main = \"{}\"\nvl_short = \"{}\"\nfile = \"{}\"\nflush_interval_ms = 50\n",
            sinks.main.url(),
            sinks.short.url(),
            sinks.file.display()
        ),
    );
    env.write_lkg("blog", &sign(b));
    let edge = env.spawn(&env.write_config(&config));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    (edge, sinks)
}

fn parse(lines: Vec<String>) -> Vec<Value> {
    lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

/// Waits until some accepted line of `vl` satisfies `pred`.
fn wait_line(vl: &FakeVl, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(v) = parse(vl.accepted_lines()).into_iter().find(|v| pred(v)) {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "no {what} line in {:#?}",
            vl.accepted_lines()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn is(v: &Value, kind: &str, rid: &str) -> bool {
    v["kind"] == kind && (v["request_id"] == rid || v["ctx"]["request_id"] == rid)
}

fn origin_rid(env: &TestEnv, needle: &str) -> String {
    env.origin
        .last(needle)
        .unwrap_or_else(|| panic!("the origin never saw {needle}"))
        .header("mg-request-id")
        .unwrap()
        .to_owned()
}

/// The first four keys of a line, as written.
fn leading_keys(line: &str) -> Vec<String> {
    line.trim_start_matches('{')
        .split(",\"")
        .take(4)
        .map(|p| {
            p.trim_start_matches('"')
                .split('"')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn four_kinds_with_envelopes_sampling_and_redaction() {
    let env = TestEnv::new("events-sink");
    let (edge, sinks) = start(&env, &bundle(), &env.default_config(""));
    let ip = "198.51.100.30";

    // 1. ALLOW on a low route: sampled out (rate 0), its access record kept.
    let r = get(env.listen, "example.com", "/hello", &browser(ip));
    assert_eq!(r.status, 200, "{}", r.head);
    let hello = origin_rid(&env, "/hello");
    let access = wait_line(&sinks.main, "access /hello", |v| is(v, "access", &hello));

    // 2. The redacted critical route: always kept, path and query hidden.
    let r = get(
        env.listen,
        "example.com",
        "/account/login?reset_code=SECRET123",
        &browser(ip),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let login = origin_rid(&env, "/account/login");
    let decision = wait_line(&sinks.main, "decision login", |v| is(v, "decision", &login));
    assert_eq!(decision["ctx"]["http"]["path"], "/login");
    assert!(
        decision["ctx"]["http"]
            .get("query_keys")
            .is_none_or(|q| q.as_array().is_some_and(Vec::is_empty)),
        "{decision}"
    );
    assert_eq!(decision["sample_rate"], 1.0);
    assert_eq!(decision["decision"]["action"], "allow");
    assert!(
        decision["msg"]
            .as_str()
            .unwrap()
            .starts_with("allow matrix."),
        "{decision}"
    );
    let login_access = wait_line(&sinks.main, "access login", |v| is(v, "access", &login));
    assert_eq!(login_access["path"], "/login");
    assert_eq!(login_access["route"], "login");

    // 3. A block: always kept.
    let r = get(env.listen, "example.com", "/blocked/x", &browser(ip));
    assert_eq!(r.status, 403, "{}", r.head);
    let blocked = common::request_id_of(&r.body).expect("request id in the block page");
    let block = wait_line(&sinks.main, "decision block", |v| {
        is(v, "decision", &blocked)
    });
    assert_eq!(block["decision"]["action"], "block");
    assert_eq!(block["decision"]["rule_id"], "block-bad");
    assert_eq!(block["sample_rate"], 1.0);

    // 4. A challenge, solved: decision, feedback (vl-main), telemetry
    //    (vl-short), and the access record of /__mg/c.
    let r = get(env.listen, "example.com", "/members/a-secret", &browser(ip));
    assert_eq!(r.status, 403, "{}", r.head);
    let shown = from_page(&r.body);
    let r = submit_form(env.listen, ip, &solved(&shown, challenge::CHROME), "");
    assert_eq!(r.status, 303, "{}\n{}", r.head, r.body);
    let feedback = wait_line(&sinks.main, "feedback", |v| v["kind"] == "feedback");
    assert_eq!(feedback["outcome"], "pass");
    assert_eq!(feedback["type"], shown.ty.as_str());
    assert_eq!(feedback["route_id"], "members");
    assert_eq!(
        feedback["msg"],
        format!("challenge pass {} route=members", shown.ty.as_str())
    );
    let submit_rid = feedback["request_id"].as_str().unwrap().to_owned();
    let telemetry = wait_line(&sinks.short, "telemetry", |v| {
        is(v, "telemetry", &submit_rid)
    });
    assert_eq!(telemetry["source"], "challenge");
    assert_eq!(telemetry["build"], "1df90640e0c5fec4");
    assert_eq!(telemetry["env"]["timeZone"], "Asia/Shanghai");
    assert!(telemetry["env"]["ua"].get("userAgent").is_none());
    assert_eq!(telemetry["auto"]["webdriver"], false);
    let submit_access = wait_line(&sinks.main, "access /__mg/c", |v| {
        is(v, "access", &submit_rid)
    });
    assert_eq!(submit_access["route"], "__mg");
    // The submission's route_class redacts: its access record shows it.
    assert_eq!(submit_access["path"], "/members");
    assert_eq!(submit_access["status"], 303);
    assert!(submit_access.get("action").is_none());
    let challenged = wait_line(&sinks.main, "decision challenge", |v| {
        v["kind"] == "decision" && v["decision"]["action"] == "challenge"
    });
    assert_eq!(challenged["ctx"]["route_id"], "members");
    assert_eq!(challenged["ctx"]["http"]["path"], "/members");

    // 5. /__mg/healthz and 6. a foreign Worker: access records only.
    let r = get(env.listen, "example.com", "/__mg/healthz", &cf(ip));
    assert_eq!(r.status, 200);
    let health = wait_line(&sinks.main, "access healthz", |v| {
        v["kind"] == "access" && v["path"] == "/__mg/healthz"
    });
    assert_eq!(health["route"], "__mg");
    let r = get(
        env.listen,
        "example.com",
        "/worker",
        &format!("{}CF-Worker: attacker.example\r\n", cf(ip)),
    );
    assert_eq!(r.status, 403);
    let worker = wait_line(&sinks.main, "access foreign worker", |v| {
        v["kind"] == "access" && v["path"] == "/worker"
    });
    assert_eq!(worker["route"], "__site");
    assert_eq!(worker["status"], 403);

    // Envelope (§13.1, §13.2): stream fields, time field, message field,
    // Content-Type, the I-7 User-Agent; every line starts with the envelope.
    let requests = sinks.main.requests();
    for req in requests.iter().chain(sinks.short.requests().iter()) {
        assert_eq!(req.path, "/insert/jsonline");
        assert_eq!(
            req.query.as_deref(),
            Some("_stream_fields=kind,site&_time_field=ts&_msg_field=msg")
        );
        assert_eq!(req.header("content-type"), Some("application/stream+json"));
        assert_eq!(req.header("user-agent"), Some("morphgate-dev-tooling"));
    }
    let main_lines = sinks.main.accepted_lines();
    let short_lines = sinks.short.accepted_lines();
    for line in main_lines.iter().chain(&short_lines) {
        assert_eq!(leading_keys(line), ["kind", "site", "ts", "msg"], "{line}");
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["site"], "blog");
        assert!(v["ts"].as_i64().unwrap() > 1_700_000_000_000);
        // D-31: the redacted paths and the query never appear.
        for hidden in ["SECRET123", "/account/login", "a-secret"] {
            assert!(!line.contains(hidden), "{hidden} in {line}");
        }
    }
    assert!(
        short_lines
            .iter()
            .all(|l| l.contains("\"kind\":\"telemetry\""))
    );

    // Sampling (§9.11): the ALLOW on the low route has no decision line.
    assert!(
        !parse(main_lines.clone())
            .iter()
            .any(|v| is(v, "decision", &hello)),
        "sampled-out decision was written"
    );
    assert_eq!(access["action"], "allow");
    assert_eq!(access["route"], "default");
    assert_eq!(access["ip_prefix"], "198.51.100.0/24");

    // The file holds every line of both instances.
    let deadline = Instant::now() + WAIT;
    let file = loop {
        let text = std::fs::read_to_string(&sinks.file).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= main_lines.len() + short_lines.len() || Instant::now() > deadline {
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    for line in main_lines.iter().chain(&short_lines) {
        assert!(file.contains(line), "file lacks {line}");
    }
    // Nothing was lost on the way.
    let metrics = edge.metrics_text();
    for sink in ["buffer", "victorialogs", "file", "stream"] {
        for class in ["priority", "access", "sampled"] {
            let series = format!("mg_event_dropped_total{{class=\"{class}\",sink=\"{sink}\"}}");
            assert_eq!(
                common::metric_value(&metrics, &series),
                Some(0.0),
                "{series}"
            );
        }
    }
}

/// §9.11: under monitor, a non-ALLOW decision is always kept (and marked
/// `dry_run`); a `bootstrap` site records its decisions with rule
/// `bootstrap`.
#[test]
fn monitor_and_bootstrap_decisions() {
    let env = TestEnv::new("events-monitor");
    let mut b = bundle();
    b.monitor_only = true;
    let (_edge, sinks) = start(&env, &b, &env.default_config(""));
    let r = get(
        env.listen,
        "example.com",
        "/blocked/m",
        &browser("198.51.100.31"),
    );
    assert_eq!(r.status, 200, "monitor forwards");
    let rid = origin_rid(&env, "/blocked/m");
    let v = wait_line(&sinks.main, "monitor block", |v| is(v, "decision", &rid));
    assert_eq!(v["decision"]["action"], "block");
    assert_eq!(v["decision"]["dry_run"], true);
    assert_eq!(v["monitor_only"], true);
    assert!(v["msg"].as_str().unwrap().ends_with(" dry_run"), "{v}");
    let access = wait_line(&sinks.main, "monitor access", |v| is(v, "access", &rid));
    assert_eq!(
        (access["action"].clone(), access["dry_run"].clone()),
        ("block".into(), true.into())
    );

    // Bootstrap (no bundle): the §8.3 defaults apply (access_log on).
    let env = TestEnv::new("events-bootstrap");
    let main = FakeVl::start().unwrap();
    let config = with_events(
        &env.default_config(""),
        &format!("vl_main = \"{}\"\nflush_interval_ms = 50\n", main.url()),
    );
    let _edge = env.spawn(&env.write_config(&config));
    let r = get(env.listen, "example.com", "/boot", &cf("198.51.100.32"));
    assert_eq!(r.status, 200);
    let rid = origin_rid(&env, "/boot");
    let access = wait_line(&main, "bootstrap access", |v| is(v, "access", &rid));
    assert_eq!(access["action"], "allow");
    assert_eq!(access["dry_run"], true);
    assert_eq!(access["route"], "-");
    assert!(access.get("env").is_none());
    // §9.9: bootstrap-open records like monitor (`dry_run`, `monitor_only`).
    // An oversize request's decision is always kept, whatever the rate.
    let long = format!("/boot-{}", "b".repeat(9000));
    let r = get(env.listen, "example.com", &long, &cf("198.51.100.32"));
    assert_eq!(r.status, 200, "bootstrap-open forwards: {}", r.head);
    let d = wait_line(&main, "bootstrap oversize decision", |v| {
        v["kind"] == "decision" && v["decision"]["rule_id"] == "hard.oversize_skipped"
    });
    assert_eq!(d["decision"]["dry_run"], true);
    assert_eq!(d["monitor_only"], true, "{d}");
    assert_eq!(d["bundle_version"], 0);
}

/// §13.6 with Valkey: every request writes its `mg:ev` entry through
/// `mg-state`, including a decision event that was sampled out.
#[test]
fn every_request_has_its_stream_entry() {
    let Some(valkey) = Valkey::start() else {
        return;
    };
    let env = TestEnv::new("events-stream");
    let config = with_valkey(&env.default_config(""), &valkey.proxy_url(), 1000);
    let (edge, _sinks) = start(&env, &bundle(), &config);
    edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 10, |v| v == 1.0);
    let r = get(
        env.listen,
        "example.com",
        "/stream-a",
        &browser("198.51.100.33"),
    );
    assert_eq!(r.status, 200);
    let rid = origin_rid(&env, "/stream-a");

    let mut conn = valkey.admin();
    let deadline = Instant::now() + WAIT;
    let fields = loop {
        let items: Vec<(String, Vec<(String, String)>)> = redis::cmd("XRANGE")
            .arg("mg:ev")
            .arg("-")
            .arg("+")
            .query(&mut conn)
            .unwrap();
        if let Some((_, fields)) = items
            .into_iter()
            .find(|(_, f)| f.iter().any(|(k, v)| k == "rid" && *v == rid))
        {
            break fields;
        }
        assert!(Instant::now() < deadline, "no mg:ev entry for {rid}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "v", "kind", "site", "ts", "rid", "sess", "route", "action", "dry", "class", "score",
            "ipk", "pfk", "asn", "status"
        ]
    );
    let get_field = |k: &str| fields.iter().find(|(n, _)| n == k).unwrap().1.clone();
    assert_eq!(get_field("kind"), "decision");
    assert_eq!(get_field("action"), "allow");
    assert_eq!(get_field("status"), "200");
    assert_eq!(get_field("ipk").len(), 32);
    assert!(fields.iter().all(|(_, v)| !v.contains("198.51.100.33")));
    assert_eq!(
        edge.metric("mg_event_dropped_total{class=\"sampled\",sink=\"stream\"}"),
        0.0
    );
}

/// §13.4 / §9.3.1 / I-2: an enforce protocol rejection writes only an
/// access record (`route = "__protocol"`, no action, the path cut to 1024
/// bytes); under monitor the oversize request is forwarded unevaluated and
/// its decision event is always kept (sampling rate 0 here), names the
/// exceeded limit and holds at most 8 KiB of the path.
#[test]
fn protocol_rejections_and_oversize_requests() {
    let long = format!("/o{}", "a".repeat(9000));
    let env = TestEnv::new("events-oversize");
    let (_edge, sinks) = start(&env, &bundle(), &env.default_config(""));
    let r = get(env.listen, "example.com", &long, &cf("198.51.100.34"));
    assert_eq!(r.status, 414, "{}", r.head);
    let v = wait_line(&sinks.main, "access __protocol", |v| {
        v["kind"] == "access" && v["route"] == "__protocol"
    });
    assert_eq!(v["status"], 414);
    assert_eq!(v["path"].as_str().unwrap().len(), 1024);
    assert!(long.starts_with(v["path"].as_str().unwrap()));
    assert!(v.get("action").is_none(), "{v}");
    assert_eq!(v["ip_prefix"], "198.51.100.0/24");
    let rid = v["request_id"].as_str().unwrap().to_owned();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !parse(sinks.main.accepted_lines())
            .iter()
            .any(|v| is(v, "decision", &rid)),
        "a protocol rejection has no decision event"
    );

    let env = TestEnv::new("events-oversize-monitor");
    let mut b = bundle();
    b.monitor_only = true;
    let (_edge, sinks) = start(&env, &b, &env.default_config(""));
    let r = get(env.listen, "example.com", &long, &cf("198.51.100.35"));
    assert_eq!(r.status, 200, "monitor forwards: {}", r.head);
    let d = wait_line(&sinks.main, "oversize decision", |v| {
        v["kind"] == "decision" && v["decision"]["rule_id"] == "hard.oversize_skipped"
    });
    assert_eq!(d["oversize"], "path");
    assert_eq!(d["sample_rate"], 1.0);
    assert_eq!(d["decision"]["dry_run"], true);
    assert_eq!(d["ctx"]["http"]["path"].as_str().unwrap().len(), 8 * 1024);
    let rid = d["ctx"]["request_id"].as_str().unwrap().to_owned();
    let a = wait_line(&sinks.main, "oversize access", |v| is(v, "access", &rid));
    assert_eq!(a["route"], "-");
    assert_eq!(a["status"], 200);
    assert_eq!(a["path"].as_str().unwrap().len(), 1024);
}
