//! The Phase 2 alerts (docs/impl/phase2-spec.md §19 step 8, §17 WP-E2b):
//! `deploy/vmalert/mg-phase2.rules.yml` only uses series that the binaries
//! serve, with labels they have, and `scripts/mg-daily-check.sh` flags each
//! condition from two snapshots of a real `/metrics` page, stays quiet when
//! nothing changed, and never compares across a restart. Loopback only.

mod common;

use common::{TestEnv, get, repo, sign};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const RULES: &str = "deploy/vmalert/mg-phase2.rules.yml";
const SCRIPT: &str = "scripts/mg-daily-check.sh";
/// The request counter of [`edge_metrics`]'s request.
const REQUESTS: &str = "mg_requests_total{action=\"allow\",class=\"human_likely\",env=\"production\",route=\"default\",site=\"blog\"}";

/// `name -> label names` of every sample in a /metrics page (histograms by
/// their base name).
fn families(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (name, labels) = match line.split_once('{') {
            Some((n, rest)) => (n, rest.split_once('}').map_or("", |(l, _)| l)),
            None => (line.split_whitespace().next().unwrap_or(""), ""),
        };
        let name = ["_bucket", "_count", "_sum"]
            .iter()
            .find_map(|s| name.strip_suffix(s))
            .unwrap_or(name);
        let set = out.entry(name.to_owned()).or_default();
        for pair in labels.split(',').filter(|p| !p.is_empty()) {
            if let Some((k, _)) = pair.split_once('=') {
                set.insert(k.to_owned());
            }
        }
    }
    out
}

/// A running Edge's /metrics after a few requests (a schema 2 bundle).
fn edge_metrics() -> String {
    let env = TestEnv::new("alerts");
    let mut b = mg_edge_core::testkit::http::test_site_bundle_v2("blog", &common::HOSTS, 1);
    b.monitor_only = false;
    env.publish("blog", &sign(&b));
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 1.0);
    let r = get(
        env.listen,
        "example.com",
        "/x",
        &common::challenge::browser("198.51.100.50"),
    );
    assert_eq!(r.status, 200);
    edge.metrics_text()
}

/// The `expr` texts of the prometheus groups of the rules file (the
/// `type: vlogs` group holds LogsQL, not PromQL).
fn prometheus_exprs(rules: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_logs = false;
    let mut lines = rules.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with("- name:") {
            in_logs = false;
        }
        if t == "type: vlogs" {
            in_logs = true;
        }
        let Some(rest) = t.strip_prefix("expr:") else {
            continue;
        };
        let mut expr = rest.trim().to_owned();
        if expr == "|" {
            expr.clear();
            let indent = line.len() - line.trim_start().len();
            while let Some(next) = lines.peek() {
                let ni = next.len() - next.trim_start().len();
                if next.trim().is_empty() || ni <= indent {
                    break;
                }
                expr.push(' ');
                expr.push_str(next.trim());
                lines.next();
            }
        }
        if !in_logs {
            out.push(expr);
        }
    }
    out
}

/// `(metric, labels used in its selector)` of every `mg_*` series in `expr`.
fn selectors(expr: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while let Some(pos) = expr[i..].find("mg_") {
        let start = i + pos;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let name = expr[start..end].to_owned();
        let mut labels = Vec::new();
        if bytes.get(end) == Some(&b'{') {
            let close = expr[end..].find('}').map_or(expr.len(), |c| end + c);
            for m in expr[end + 1..close].split(',') {
                let k: String = m
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !k.is_empty() {
                    labels.push(k);
                }
            }
            end = close;
        }
        out.push((name, labels));
        i = end.max(start + 3);
    }
    out
}

/// The labels of every `by (...)` clause in `expr`.
fn grouping(expr: &str) -> Vec<String> {
    expr.split("by (")
        .skip(1)
        .filter_map(|s| s.split(')').next())
        .flat_map(|s| s.split(',').map(|l| l.trim().to_owned()))
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn vmalert_rules_use_served_series() {
    let rules = std::fs::read_to_string(repo(RULES)).unwrap();
    assert!(rules.contains("groups:"));
    let exprs = prometheus_exprs(&rules);
    assert!(exprs.len() >= 12, "{exprs:#?}");
    let edge = families(&edge_metrics());
    // mg-nearline's families are defined in its Go metrics writer.
    let nearline: String = std::fs::read_dir(repo("control-plane/internal/nearline"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "go"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect();
    let mut seen = BTreeSet::new();
    for expr in &exprs {
        let sels = selectors(expr);
        for (name, labels) in &sels {
            seen.insert(name.clone());
            if name.starts_with("mg_nl_") {
                assert!(
                    nearline.contains(&format!("\"{name}\"")),
                    "{name} is not an mg-nearline family"
                );
                continue;
            }
            let have = edge
                .get(name)
                .unwrap_or_else(|| panic!("{name} (in `{expr}`) is not served by mg-edge"));
            for l in labels.iter().chain(&grouping(expr)) {
                if sels.iter().all(|(n, _)| n.starts_with("mg_nl_")) {
                    continue;
                }
                assert!(have.contains(l), "{name} has no label {l}: {have:?}");
            }
        }
    }
    for must in [
        "mg_double_challenge_total",
        "mg_endpoint_cache_hit_reports_total",
        "mg_sw_intercept_reports_total",
        "mg_token_ruc_total",
        "mg_state_local_overflow_total",
        "mg_challenge_renew_total",
        "mg_site_forced_monitor",
        "mg_interactive_available",
        "mg_proof_verify_total",
        "mg_navigations_total",
        "mg_nl_backlog",
        "mg_nl_lag_seconds",
    ] {
        assert!(seen.contains(must), "no rule uses {must}");
    }
    assert!(rules.contains("type: vlogs") && rules.contains("ic.no_trusted_input"));
}

/// Replaces (or adds) the sample `series` of a /metrics page.
fn set(text: &str, series: &str, value: f64) -> String {
    let mut found = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            if l.strip_prefix(series).is_some_and(|r| r.starts_with(' ')) {
                found = true;
                format!("{series} {value}")
            } else {
                l.to_owned()
            }
        })
        .collect();
    if !found {
        out.push(format!("{series} {value}"));
    }
    out.join("\n") + "\n"
}

/// Adds `by` to the sample `series` (0 when absent).
fn bump(text: &str, series: &str, by: f64) -> String {
    let now = common::metric_value(text, series).unwrap_or(0.0);
    set(text, series, now + by)
}

fn run(dir: &Path, metrics: &str, pid: &str, extra: &[&str]) -> (i32, String) {
    let file = dir.join("metrics.txt");
    std::fs::write(&file, metrics).unwrap();
    let out = Command::new("bash")
        .arg(repo(SCRIPT))
        .args(["--metrics-file", file.to_str().unwrap()])
        .args(["--state", dir.join("state").to_str().unwrap()])
        .args(["--pid", pid])
        .args(extra)
        .env_remove("MG_INTERACTIVE_SITES")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

fn scratch(tag: &str) -> PathBuf {
    let dir = common::temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn daily_check_flags_each_condition() {
    let base = edge_metrics();
    let dir = scratch("daily-check");
    // A quiet day with traffic: the first run saves, the second compares.
    let (code, out) = run(&dir, &base, "4242", &[]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("first snapshot"), "{out}");
    let mut quiet = bump(&base, REQUESTS, 1000.0);
    quiet = bump(&quiet, "mg_navigations_total{site=\"blog\"}", 1000.0);
    let (code, out) = run(&dir, &quiet, "4242", &["--interactive-sites", ""]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("mg-daily-check: ok"), "{out}");
    assert!(!out.contains("ALERT"), "{out}");
    assert!(
        out.contains("cf audit 18: worst missing signal 0 / 1000"),
        "{out}"
    );

    // A bad day: every condition at once.
    let mut bad = quiet.clone();
    for (series, v) in [
        (
            "mg_double_challenge_total{route=\"default\",site=\"blog\"}",
            11.0,
        ),
        ("mg_endpoint_cache_hit_reports_total{site=\"blog\"}", 1.0),
        ("mg_sw_intercept_reports_total{site=\"blog\"}", 2.0),
        ("mg_token_ruc_total{site=\"blog\"}", 3.0),
        ("mg_state_local_overflow_total{table=\"jti\"}", 1.0),
        ("mg_challenge_renew_total{result=\"unavailable\"}", 1.0),
        ("mg_site_forced_monitor{site=\"blog\"}", 1.0),
        ("mg_proof_verify_total{result=\"valid\"}", 90.0),
        ("mg_proof_verify_total{result=\"jkt\"}", 10.0),
        (
            "mg_challenge_total{provider=\"self_hold\",result=\"issued\",type=\"interactive\"}",
            5.0,
        ),
        ("mg_cf_foreign_worker_total{site=\"blog\"}", 1.0),
        (
            "mg_upstream_signal_missing_total{profile=\"cloudflare\",signal=\"rtt\"}",
            20.0,
        ),
    ] {
        bad = set(&bad, series, v);
    }
    let nl = dir.join("nl.txt");
    std::fs::write(&nl, "# HELP x\nmg_nl_backlog 20000\nmg_nl_lag_seconds 5\n").unwrap();
    let (code, out) = run(
        &dir,
        &bad,
        "4242",
        &[
            "--interactive-sites",
            "blog",
            "--nearline-file",
            nl.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 1, "{out}");
    for want in [
        "ALERT mg_double_challenge_total +11",
        "ALERT mg_endpoint_cache_hit_reports_total +1",
        "ALERT mg_sw_intercept_reports_total +2",
        "ALERT mg_token_ruc_total +3",
        "ALERT mg_state_local_overflow_total +1",
        "ALERT mg_challenge_renew_total{result=\"unavailable\"} +1",
        "ALERT force_monitor is on",
        "ALERT mg_interactive_available{site=\"blog\"} = 0",
        "ALERT MG-Proof failures 10 / 100",
        "ALERT mg-nearline backlog 20000",
        "ALERT cf audit 18: mg_cf_foreign_worker_total +1",
    ] {
        assert!(out.contains(want), "missing `{want}` in:\n{out}");
    }
    // No navigations and no requests that day: friction has no ratio, and
    // check 18 has no evidence.
    assert!(
        out.contains("interactive challenges / navigations 5 / 0 = -"),
        "{out}"
    );
    assert!(out.contains("no traffic"), "{out}");

    // With traffic in the interval the ratios are judged.
    let mut busy = bump(&bad, REQUESTS, 1000.0);
    busy = bump(&busy, "mg_navigations_total{site=\"blog\"}", 1000.0);
    busy = set(
        &busy,
        "mg_upstream_signal_missing_total{profile=\"cloudflare\",signal=\"rtt\"}",
        40.0,
    );
    busy = set(
        &busy,
        "mg_challenge_total{provider=\"self_hold\",result=\"issued\",type=\"interactive\"}",
        10.0,
    );
    let (code, out) = run(&dir, &busy, "4242", &[]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("ALERT interactive challenges / navigations 5 / 1000 = 0.0050"),
        "{out}"
    );
    assert!(
        out.contains("ALERT cf audit 18: worst missing signal 20 / 1000 requests = 0.0200"),
        "{out}"
    );
    // hdr-names never counts (I-12).
    let hdr = set(
        &busy,
        "mg_upstream_signal_missing_total{profile=\"cloudflare\",signal=\"hdr-names\"}",
        999.0,
    );
    let mut hdr = bump(&hdr, REQUESTS, 1000.0);
    hdr = bump(&hdr, "mg_navigations_total{site=\"blog\"}", 1000.0);
    let (_, out) = run(&dir, &hdr, "4242", &[]);
    assert!(
        out.contains("OK    cf audit 18: worst missing signal 0 / 1000"),
        "{out}"
    );

    // A restart: nothing compared, the snapshot starts over.
    let (code, out) = run(&dir, &base, "5151", &[]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("MainPID changed (4242 -> 5151)"), "{out}");
    assert!(!out.contains("ALERT"), "{out}");
    let (code, _) = run(&dir, &base, "5151", &["--bogus"]);
    assert_eq!(code, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}
