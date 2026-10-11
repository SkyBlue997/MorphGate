//! The single Phase 2 telemetry decoder (docs/impl/phase2-spec.md §7.6,
//! §9.4, §12.8, §15.2; WP-C5 tests in §17) against every shared sample of
//! `testdata/phase2/samples/telemetry/` and its expected result, the
//! canonical re-serialization, and 10,000+ seeded random inputs (§2.4
//! item 9).

use mg_core::telemetry::{InputModality, IxLocale, IxMode, KeyStore, PowImpl};
use mg_edge_core::events::{
    BehaviorSummary, ChallengeTelemetry, ReportEntry, ReportKind, TelemetryError, TelemetryReport,
    UpstreamScope, ix_from_value, ix_to_value, parse_reports,
};
use serde_json::{Value, json};
use std::path::PathBuf;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase2/samples/telemetry")
}

/// A sample's JSON text (the trailing newline is not part of it).
fn sample(file: &str) -> String {
    let text =
        std::fs::read_to_string(samples_dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    text.strip_suffix('\n').unwrap_or(&text).to_owned()
}

fn cases() -> Vec<(String, String)> {
    let doc: Value = serde_json::from_str(&sample("cases.json")).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["file"].as_str().unwrap().to_owned(),
                c["expect"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// Every case of `cases.json` gets exactly its expected result.
#[test]
fn every_sample_has_its_expected_result() {
    let cases = cases();
    assert!(cases.len() >= 60, "{}", cases.len());
    let mut seen = std::collections::BTreeSet::new();
    for (file, expect) in &cases {
        let text = sample(file);
        let dir = file.split('/').next().unwrap();
        seen.insert((dir.to_owned(), expect.clone()));
        match (dir, expect.as_str()) {
            ("t", "ok") => {
                let t = ChallengeTelemetry::parse(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
                assert!(!t.ix_rejected, "{file}");
                let raw: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(t.ix.is_some(), raw.get("ix").is_some(), "{file}");
                assert_eq!(t.env.is_some(), raw.get("env").is_some(), "{file}");
                assert_eq!(t.auto.is_some(), raw.get("auto").is_some(), "{file}");
                if let Some(ix) = &t.ix {
                    assert_eq!(ix.check(), Ok(()), "{file}");
                }
            }
            ("t", "ix_rejected") => {
                let t = ChallengeTelemetry::parse(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
                assert!(t.ix.is_none() && t.ix_rejected, "{file}");
            }
            ("t", "t_rejected") => {
                assert!(ChallengeTelemetry::parse(&text).is_err(), "{file}");
            }
            ("behavior", "ok") => {
                BehaviorSummary::from_json(text.as_bytes())
                    .unwrap_or_else(|e| panic!("{file}: {e}"));
            }
            ("behavior", "summary_rejected") => {
                assert!(
                    BehaviorSummary::from_json(text.as_bytes()).is_err(),
                    "{file}"
                );
            }
            ("report", "ok") => {
                let r = parse_reports(text.as_bytes()).unwrap_or_else(|e| panic!("{file}: {e}"));
                assert!(
                    r.iter().all(|e| matches!(e, ReportEntry::Report(_))),
                    "{file}: {r:?}"
                );
            }
            ("report", "report_dropped") => {
                let r = parse_reports(text.as_bytes()).unwrap_or_else(|e| panic!("{file}: {e}"));
                assert!(
                    r.iter().any(|e| matches!(e, ReportEntry::Dropped(_))),
                    "{file}"
                );
            }
            ("report", "bad_request") => {
                assert!(parse_reports(text.as_bytes()).is_err(), "{file}");
            }
            other => panic!("{file}: unexpected case {other:?}"),
        }
    }
    // Every expectation of the README appears.
    for (dir, expect) in [
        ("t", "ok"),
        ("t", "ix_rejected"),
        ("t", "t_rejected"),
        ("behavior", "ok"),
        ("behavior", "summary_rejected"),
        ("report", "ok"),
        ("report", "report_dropped"),
        ("report", "bad_request"),
    ] {
        assert!(
            seen.contains(&(dir.to_owned(), expect.to_owned())),
            "{dir} {expect}"
        );
    }
}

/// §7.6: the decoded values of the hold sample, and the canonical form is
/// the sample's `ix` itself (it has no unknown field).
#[test]
fn hold_sample_decodes_to_the_quantized_values() {
    let text = sample("t/valid/hold.json");
    let t = ChallengeTelemetry::parse(&text).unwrap();
    let ix = t.ix.clone().unwrap();
    assert_eq!(ix.mode, IxMode::Hold);
    assert_eq!(ix.modality, InputModality::Mouse);
    assert_eq!(ix.locale, IxLocale::ZhCn);
    assert_eq!(ix.ks, KeyStore::Idb);
    assert_eq!(ix.sv, "0.3.0");
    assert_eq!((ix.trusted, ix.act_ms), (3, 2300));
    let pre = ix.pre.unwrap();
    assert_eq!((pre.straight, pre.moves, pre.to_target_ms), (7, 5, 9));
    let hold = ix.hold.unwrap();
    assert_eq!((hold.ms, hold.offset, hold.pressure), (1910, [1, -2], 5));
    assert!(!hold.pressure_var && !hold.contact_var);
    let pow = ix.pow.unwrap();
    assert_eq!((pow.ms, pow.worker, pow.pow_impl), (8, true, PowImpl::Js));
    assert!(ix.single.is_none());

    let raw: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(ix_to_value(t.ix.as_ref().unwrap()), raw["ix"]);
    // The canonical t: env without ua.userAgent, auto, ix.
    let canon = t.to_value();
    assert!(canon["env"]["ua"].get("userAgent").is_none());
    assert_eq!(canon["env"]["ua"]["platform"], "macOS");
    assert_eq!(canon["auto"], json!({"v": 1, "webdriver": false}));
    assert_eq!(canon["ix"], raw["ix"]);
}

/// Re-serialization drops unknown fields and is a fixed point: decoding the
/// canonical form gives the same values, and its bytes stay within the
/// limits.
#[test]
fn canonical_forms_are_fixed_points() {
    for (file, expect) in cases() {
        if expect != "ok" {
            continue;
        }
        let text = sample(&file);
        if file.starts_with("t/") {
            let t = ChallengeTelemetry::parse(&text).unwrap();
            let canon = serde_json::to_string(&t.to_value()).unwrap();
            let again = ChallengeTelemetry::parse(&canon).unwrap();
            assert_eq!(again.ix, t.ix, "{file}");
            assert_eq!(again.auto, t.auto, "{file}");
            assert_eq!(again.to_value(), t.to_value(), "{file}");
            assert!(
                !canon.contains("future") && !canon.contains("extra"),
                "{file}"
            );
            assert!(!canon.contains("other"), "{file}");
        } else if file.starts_with("behavior/") {
            let s = BehaviorSummary::from_json(text.as_bytes()).unwrap();
            let canon = serde_json::to_vec(&s.to_value()).unwrap();
            assert!(canon.len() <= 2048, "{file}");
            assert_eq!(BehaviorSummary::from_json(&canon).unwrap(), s, "{file}");
            let canon = String::from_utf8(canon).unwrap();
            assert!(
                !canon.contains("future") && !canon.contains("extra"),
                "{file}"
            );
        } else if file.starts_with("report/") {
            for entry in parse_reports(text.as_bytes()).unwrap() {
                let ReportEntry::Report(r) = entry else {
                    continue;
                };
                let v = r.to_value(None);
                assert_eq!(v["kind"], r.kind().as_str(), "{file}");
                assert!(v.get("extra").is_none(), "{file}");
                if let Some(p) = r.path() {
                    let redacted = r.to_value(Some("/api"));
                    assert!(!redacted.to_string().contains(p), "{file}");
                }
            }
        }
    }
}

#[test]
fn report_values() {
    let r = parse_reports(sample("report/valid/eight-reports.json").as_bytes()).unwrap();
    assert_eq!(r.len(), 8);
    let kinds: Vec<ReportKind> = r
        .iter()
        .map(|e| match e {
            ReportEntry::Report(r) => r.kind(),
            ReportEntry::Dropped(k) => *k,
        })
        .collect();
    assert_eq!(kinds[0], ReportKind::UpstreamChallenge);
    let ReportEntry::Report(TelemetryReport::UpstreamChallenge { scope, path, count }) = &r[0]
    else {
        panic!("{r:?}");
    };
    assert_eq!(
        (*scope, path.as_str(), *count),
        (UpstreamScope::ProtectedFetch, "/api/save", 1)
    );
    let dropped = parse_reports(sample("report/valid/cache-hit-static.json").as_bytes()).unwrap();
    assert_eq!(dropped, vec![ReportEntry::Dropped(ReportKind::CacheHit)]);
    // A report path is a page path.
    for bad in [
        r#"{"v":1,"reports":[{"kind":"sw_intercept","path":"/__mg/v#x"}]}"#,
        r#"{"v":1,"reports":[{"kind":"sw_intercept","path":"/articles"}]}"#,
        r#"{"v":1,"reports":[{"kind":"upstream_challenge","scope":"navigation","path":"api","count":1}]}"#,
        r#"{"v":1,"reports":[{"kind":"upstream_challenge","scope":"navigation","path":"/a\u0000","count":1}]}"#,
        r#"{"v":1,"reports":[]}"#,
        r#"{"v":1,"reports":{}}"#,
        r#"[]"#,
    ] {
        assert!(parse_reports(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn ix_details() {
    // A section of another mode is dropped, not rejected.
    let v = json!({"v":1,"mode":"single","modality":"keyboard","locale":"en","ks":"idb","sv":"0.3.0",
                   "trusted":3,"act_ms":2000,"single":{"wait_ms":1880},
                   "hold":{"ms":10,"offset":[0,0],"jitter_px":0,"moves":0,"cancels":0,"pressure":0,
                           "pressure_var":0,"contact_var":0}});
    let ix = ix_from_value(&v).unwrap();
    assert!(ix.hold.is_none() && ix.single.is_some());
    assert!(ix.fallback.is_none(), "an absent fallback is null");
    // A missing required scalar rejects ix.
    let mut missing = v.clone();
    missing.as_object_mut().unwrap().remove("act_ms");
    assert_eq!(
        ix_from_value(&missing),
        Err(TelemetryError::Schema("act_ms"))
    );
    // Wrong types.
    for (key, bad) in [
        ("trusted", json!("3")),
        ("sv", json!(3)),
        ("fallback", json!(1)),
        ("act_ms", json!(-100)),
        ("act_ms", json!(100.5)),
    ] {
        let mut t = v.clone();
        t[key] = bad;
        assert!(ix_from_value(&t).is_err(), "{key}");
    }
    // `t` with a null member: absent.
    let t = ChallengeTelemetry::parse(r#"{"ix":null,"env":null}"#).unwrap();
    assert!(t.is_empty() && !t.ix_rejected);
    assert_eq!(t.to_value(), json!({}));
}

/// §2.4 item 9: seeded random inputs never panic the decoders, and whatever
/// they accept is within bounds and re-serializes within the limits.
#[test]
fn random_inputs_never_panic() {
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[(self.next() % items.len() as u64) as usize]
        }
    }
    const KEYS: &[&str] = &[
        "v",
        "ix",
        "env",
        "auto",
        "mode",
        "modality",
        "locale",
        "ks",
        "sv",
        "fallback",
        "trusted",
        "act_ms",
        "pre",
        "hold",
        "single",
        "page",
        "pow",
        "ms",
        "offset",
        "straight",
        "pressure",
        "pressure_var",
        "cancels",
        "wait_ms",
        "vis",
        "vis_during",
        "impl",
        "worker",
        "reports",
        "kind",
        "path",
        "page",
        "scope",
        "count",
        "reason",
        "summary",
        "ptr",
        "speed",
        "curv",
        "pauses",
        "keys",
        "iki",
        "scroll",
        "dist",
        "touch",
        "area_var",
        "focus",
        "form",
        "fill_ms",
        "paste",
    ];
    const STRINGS: &[&str] = &[
        "hold",
        "single",
        "pow_only",
        "external",
        "mouse",
        "zh-CN",
        "en",
        "idb",
        "0.3.0",
        "upstream_challenge",
        "cache_hit",
        "behavior",
        "sw_intercept",
        "key_unavailable",
        "/__mg/c",
        "/__mg/s/x",
        "/a",
        "navigation",
        "no_idb",
        "js",
        "wasm",
        "",
    ];
    fn value(r: &mut XorShift, depth: u32) -> Value {
        match r.next() % if depth > 5 { 4 } else { 6 } {
            0 => Value::Null,
            1 => match r.next() % 6 {
                0 => json!(r.next() % 40),
                1 => json!(r.next() % 70_000),
                2 => json!(-((r.next() % 20) as i64)),
                3 => json!((r.next() % 21) as f64 / 10.0 - 1.0),
                4 => json!(1),
                _ => json!(r.next()),
            },
            2 => json!(r.pick(STRINGS)),
            3 => Value::Bool(r.next().is_multiple_of(2)),
            4 => Value::Array((0..r.next() % 18).map(|_| value(r, depth + 1)).collect()),
            _ => {
                let mut o = serde_json::Map::new();
                for _ in 0..r.next() % 10 {
                    o.insert(r.pick(KEYS).to_owned(), value(r, depth + 1));
                }
                if r.next().is_multiple_of(2) {
                    o.insert("v".into(), json!(1));
                }
                Value::Object(o)
            }
        }
    }
    let mut r = XorShift(0x5eed_c5c5_0002_0001);
    let mut accepted = 0;
    for i in 0..12_000 {
        let v = value(&mut r, 0);
        let mut text = v.to_string();
        if i % 7 == 0 && !text.is_empty() {
            // Byte-level damage as well.
            let cut = (r.next() as usize) % text.len();
            text.truncate(cut);
            if text.is_char_boundary(text.len()) {
                text.push(['{', '"', ',', ']', '\u{0}'][(r.next() % 5) as usize]);
            }
        }
        if let Ok(t) = ChallengeTelemetry::parse(&text) {
            if let Some(ix) = &t.ix {
                assert_eq!(ix.check(), Ok(()));
                accepted += 1;
            }
            let _ = t.to_value();
        }
        if let Ok(ix) = ix_from_value(&v) {
            assert_eq!(ix.check(), Ok(()));
            assert_eq!(ix_from_value(&ix_to_value(&ix)).unwrap(), ix);
        }
        if let Ok(s) = BehaviorSummary::from_json(text.as_bytes()) {
            assert!(serde_json::to_vec(&s.to_value()).unwrap().len() <= 2048);
        }
        if let Ok(reports) = parse_reports(text.as_bytes()) {
            assert!((1..=8).contains(&reports.len()));
            for e in reports {
                if let ReportEntry::Report(rep) = e {
                    let _ = rep.to_value(None);
                }
            }
        }
    }
    let _ = accepted;
}
