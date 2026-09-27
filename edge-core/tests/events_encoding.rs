//! Pure event encodings: the JSON-line envelope (§13.2, D-16), telemetry
//! re-serialization (§9.11, §13.5, D-31), sampling (§9.11), path redaction
//! (§9.11, §13.4) and the §2.4 item 3 no-panic tests.

use mg_core::{Action, RouteSensitivity};
use mg_edge_core::events::{
    ACCESS_PATH_MAX_BYTES, SampleInputs, TELEMETRY_MAX_ARRAY_ITEMS, TELEMETRY_MAX_INPUT_BYTES,
    TELEMETRY_MAX_STRING_BYTES, TelemetryAuto, TelemetryEnv, access_path, decision_sample_rate,
    envelope, redacted_path, sample_keep,
};
use serde_json::{Value, json};

/// Deterministic xorshift64* for the no-panic tests (§2.4 item 3).
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Keys of a JSON object line in textual order (serde_json's `Map` sorts).
fn key_order(line: &str) -> Vec<String> {
    struct Keys(Vec<String>);
    impl<'de> serde::Deserialize<'de> for Keys {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Keys;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Keys, A::Error> {
                    let mut keys = Vec::new();
                    while let Some((k, _)) = map.next_entry::<String, serde::de::IgnoredAny>()? {
                        keys.push(k);
                    }
                    Ok(Keys(keys))
                }
            }
            d.deserialize_map(V)
        }
    }
    serde_json::from_str::<Keys>(line).unwrap().0
}

/// §13.2 / D-16: `kind`, `site`, `ts`, `msg` open every line, then the body.
#[test]
fn envelope_puts_envelope_fields_first() {
    let body = json!({
        "ctx": {"request_id": "r1", "ts_ms": 1_790_000_000_123_i64, "site_id": "blog"},
        "signals": [],
        "risk": {"score": 45},
        "decision": {"action": "challenge"},
        "latency_us": 180,
        "sample_rate": 1.0,
        "monitor_only": true,
    });
    let line = envelope(
        "decision",
        "blog",
        1_790_000_000_123,
        "challenge matrix.critical.medium route=login score=45",
        body,
    );
    let keys = key_order(&line);
    assert_eq!(keys[..4], ["kind", "site", "ts", "msg"]);
    assert_eq!(keys.len(), 11);
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["kind"], "decision");
    assert_eq!(v["site"], "blog");
    assert_eq!(v["ts"], 1_790_000_000_123_i64);
    assert_eq!(
        v["msg"],
        "challenge matrix.critical.medium route=login score=45"
    );
    assert_eq!(v["ctx"]["request_id"], "r1");
    assert_eq!(v["monitor_only"], true);
    assert!(!line.contains('\n'));
}

/// A body can never override or duplicate an envelope key; strings are
/// escaped so a line never contains a raw newline.
#[test]
fn envelope_drops_colliding_body_keys_and_escapes() {
    let line = envelope(
        "access",
        "blo\"g",
        -1,
        "GET /a\nb 200",
        json!({"kind": "evil", "site": "x", "ts": 0, "msg": "y", "path": "/p\r\n"}),
    );
    assert!(!line.contains('\n') && !line.contains('\r'));
    assert_eq!(key_order(&line), ["kind", "site", "ts", "msg", "path"]);
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["kind"], "access");
    assert_eq!(v["site"], "blo\"g");
    assert_eq!(v["ts"], -1);
    assert_eq!(v["msg"], "GET /a\nb 200");
    assert_eq!(v["path"], "/p\r\n");

    let null_body = envelope("telemetry", "blog", 5, "m", Value::Null);
    assert_eq!(
        null_body,
        r#"{"kind":"telemetry","site":"blog","ts":5,"msg":"m"}"#
    );
    let scalar = envelope("telemetry", "blog", 5, "m", json!([1, 2]));
    assert_eq!(
        scalar,
        r#"{"kind":"telemetry","site":"blog","ts":5,"msg":"m","body":[1,2]}"#
    );
}

/// A full SDK `EnvSummary` (sdk/web/src/env.ts, v = 1).
fn sdk_env() -> Value {
    json!({
        "v": 1,
        "ua": {
            "userAgent": "Mozilla/5.0 (Macintosh) Test/1.0",
            "brands": [{"brand": "Chromium", "version": "130"}, {"brand": "Not?A_Brand", "version": "99"}],
            "mobile": false,
            "platform": "macOS"
        },
        "languages": ["zh-CN", "en"],
        "timeZone": "Asia/Shanghai",
        "utcOffsetMin": 480,
        "screen": {"width": 1512, "height": 982, "availWidth": 1510, "availHeight": 950, "colorDepth": 30},
        "viewport": {"width": 1200, "height": 800},
        "dpr": 2.0,
        "cores": 8,
        "memoryGb": 8,
        "touch": {"maxTouchPoints": 0, "coarsePointer": false},
        "storage": {"cookies": true, "local": true, "session": true, "indexedDb": true},
        "graphics": null
    })
}

/// §13.5: canonical form = the SDK schema without `ua.userAgent`, schema
/// order, absent values as null.
#[test]
fn telemetry_env_round_trips_known_fields_without_user_agent() {
    let input = sdk_env();
    let env = TelemetryEnv::from_json(input.to_string().as_bytes()).unwrap();
    assert_eq!(env.user_agent(), Some("Mozilla/5.0 (Macintosh) Test/1.0"));
    let out = env.to_value();
    let mut want = input.clone();
    want["ua"].as_object_mut().unwrap().remove("userAgent");
    assert_eq!(out, want);
    let text = serde_json::to_string(&env).unwrap();
    assert!(!text.contains("userAgent") && !text.contains("Macintosh"));
    assert_eq!(
        key_order(&text),
        [
            "v",
            "ua",
            "languages",
            "timeZone",
            "utcOffsetMin",
            "screen",
            "viewport",
            "dpr",
            "cores",
            "memoryGb",
            "touch",
            "storage",
            "graphics"
        ]
    );
    // Integers stay integers.
    assert!(text.contains(r#""utcOffsetMin":480"#), "{text}");
    // `from_value` is the same parser.
    assert_eq!(TelemetryEnv::from_value(&input).unwrap(), env);
}

/// §9.11: unknown fields are dropped at every level.
#[test]
fn telemetry_env_drops_unknown_fields() {
    let mut input = sdk_env();
    input["canvasHash"] = json!("deadbeef");
    input["ua"]["fullVersionList"] = json!([{"brand": "x"}]);
    input["ua"]["brands"][0]["extra"] = json!("drop me");
    input["screen"]["orientation"] = json!("landscape");
    input["touch"]["force"] = json!(1);
    input["storage"]["opfs"] = json!(true);
    input["graphics"] = json!({"renderer": "ANGLE (Apple M1)"});
    let out = TelemetryEnv::from_value(&input).unwrap().to_value();
    let text = out.to_string();
    for gone in [
        "canvasHash",
        "fullVersionList",
        "drop me",
        "orientation",
        "force",
        "opfs",
        "ANGLE",
    ] {
        assert!(!text.contains(gone), "{gone} survived: {text}");
    }
    assert_eq!(out["graphics"], Value::Null);
    assert_eq!(
        out["ua"]["brands"][0],
        json!({"brand": "Chromium", "version": "130"})
    );
}

/// §9.11: strings are cut to 256 bytes on a character boundary, arrays to 16 items.
#[test]
fn telemetry_env_bounds_strings_and_arrays() {
    let mut input = sdk_env();
    input["timeZone"] = json!("z".repeat(10_000));
    // 3-byte characters: 256 is not a multiple of 3.
    input["ua"]["platform"] = json!("平".repeat(200));
    input["languages"] = json!((0..100).map(|i| format!("l{i}")).collect::<Vec<_>>());
    input["ua"]["brands"] = json!(
        (0..40)
            .map(|i| json!({"brand": "b".repeat(300), "version": i.to_string()}))
            .collect::<Vec<_>>()
    );
    let env = TelemetryEnv::from_value(&input).unwrap();
    assert_eq!(
        env.time_zone.as_deref().unwrap().len(),
        TELEMETRY_MAX_STRING_BYTES
    );
    let platform = env.ua.platform.as_deref().unwrap();
    assert_eq!(platform.len(), 255);
    assert!(platform.chars().all(|c| c == '平'));
    assert_eq!(
        env.languages.as_ref().unwrap().len(),
        TELEMETRY_MAX_ARRAY_ITEMS
    );
    let brands = env.ua.brands.as_ref().unwrap();
    assert_eq!(brands.len(), TELEMETRY_MAX_ARRAY_ITEMS);
    assert!(
        brands
            .iter()
            .all(|b| b.brand.len() == TELEMETRY_MAX_STRING_BYTES)
    );
    assert_bounded(&env.to_value(), 1);
}

/// Wrong-typed fields become null (the SDK's own "unknown" value); items of
/// the wrong type are skipped.
#[test]
fn telemetry_env_wrong_types_become_null() {
    let input = json!({
        "v": 1,
        "ua": "not an object",
        "languages": ["en", 5, null, {"x": 1}, "de"],
        "timeZone": 8,
        "utcOffsetMin": "480",
        "screen": [1, 2],
        "viewport": {"width": "wide", "height": 700},
        "dpr": true,
        "touch": {"maxTouchPoints": "5", "coarsePointer": "yes"},
        "storage": {"cookies": 1, "local": false}
    });
    let env = TelemetryEnv::from_value(&input).unwrap();
    let out = env.to_value();
    assert_eq!(
        out["ua"],
        json!({"brands": null, "mobile": null, "platform": null})
    );
    assert_eq!(out["languages"], json!(["en", "de"]));
    assert_eq!(out["timeZone"], Value::Null);
    assert_eq!(out["utcOffsetMin"], Value::Null);
    assert_eq!(out["screen"], Value::Null);
    assert_eq!(out["viewport"], json!({"width": null, "height": 700}));
    assert_eq!(out["dpr"], Value::Null);
    assert_eq!(
        out["touch"],
        json!({"maxTouchPoints": null, "coarsePointer": null})
    );
    assert_eq!(
        out["storage"],
        json!({"cookies": null, "local": false, "session": null, "indexedDb": null})
    );
    assert_eq!(env.user_agent(), None);
}

/// Numbers are re-encoded from their u64 / i64 / f64 value, never copied as
/// text: a 60-digit integer comes out as a short f64, negative and integral
/// values keep their form.
#[test]
fn telemetry_numbers_are_reencoded() {
    let text = format!(
        r#"{{"v":1,"cores":{},"utcOffsetMin":-330,"dpr":1.25,"memoryGb":8}}"#,
        "9".repeat(60)
    );
    let env = TelemetryEnv::from_json(text.as_bytes()).unwrap();
    let out = env.to_value();
    assert_eq!(out["utcOffsetMin"], json!(-330));
    assert_eq!(out["dpr"], json!(1.25));
    assert_eq!(out["memoryGb"], json!(8));
    let cores = out["cores"].to_string();
    assert!(cores.len() < 32, "{cores}");
    assert_eq!(out["cores"].as_f64(), Some(1e60));
}

/// §9.11 / §10.3: anything that is not a v1 object is "absent".
#[test]
fn telemetry_structural_failures_omit_env() {
    for bad in [
        &b""[..],
        b"null",
        b"[]",
        b"\"env\"",
        b"{}",
        b"{\"v\": 2}",
        b"{\"v\": \"1\"}",
        b"{\"v\": 1.5}",
        b"{\"v\": -1}",
        b"{\"v\": 1",
        b"\xff\xfe",
    ] {
        assert!(
            TelemetryEnv::from_json(bad).is_none(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
        assert!(
            TelemetryAuto::from_json(bad).is_none(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // Oversized input is refused before parsing.
    let mut big = sdk_env();
    big["pad"] = json!("x".repeat(TELEMETRY_MAX_INPUT_BYTES));
    assert!(TelemetryEnv::from_json(big.to_string().as_bytes()).is_none());
    // Deep nesting is an error, not a stack overflow.
    let deep = format!("{{\"v\":1,\"x\":{}{}}}", "[".repeat(5000), "]".repeat(5000));
    assert!(TelemetryEnv::from_json(deep.as_bytes()).is_none());
}

/// `auto` (`AutomationSummary`, v = 1): only `webdriver` survives.
#[test]
fn telemetry_auto_keeps_webdriver_only() {
    let auto = TelemetryAuto::from_json(br#"{"v":1,"webdriver":true,"headless":true}"#).unwrap();
    assert_eq!(auto.webdriver, Some(true));
    assert_eq!(auto.to_value(), json!({"v": 1, "webdriver": true}));
    let auto = TelemetryAuto::from_json(br#"{"v":1,"webdriver":"true"}"#).unwrap();
    assert_eq!(auto.to_value(), json!({"v": 1, "webdriver": null}));
    let auto = TelemetryAuto::from_json(br#"{"v":1}"#).unwrap();
    assert_eq!(auto.webdriver, None);
}

/// Asserts the §9.11 bounds on a re-serialized value: strings ≤ 256 bytes,
/// arrays ≤ 16 items, nesting depth ≤ 4 (the top-level object is depth 1),
/// and no `userAgent`.
fn assert_bounded(value: &Value, depth: usize) {
    match value {
        Value::String(s) => assert!(s.len() <= TELEMETRY_MAX_STRING_BYTES),
        Value::Array(items) => {
            assert!(depth <= 4, "depth {depth}");
            assert!(items.len() <= TELEMETRY_MAX_ARRAY_ITEMS);
            items.iter().for_each(|v| assert_bounded(v, depth + 1));
        }
        Value::Object(map) => {
            assert!(depth <= 4, "depth {depth}");
            assert!(!map.contains_key("userAgent"));
            map.values().for_each(|v| assert_bounded(v, depth + 1));
        }
        _ => {}
    }
}

/// Random JSON built from the schema's own field names, so the parser's
/// deeper paths are exercised rather than only the "not an object" exit.
fn random_value(rng: &mut XorShift, depth: usize) -> Value {
    const KEYS: &[&str] = &[
        "v",
        "ua",
        "userAgent",
        "brands",
        "brand",
        "version",
        "mobile",
        "platform",
        "languages",
        "timeZone",
        "utcOffsetMin",
        "screen",
        "width",
        "height",
        "availWidth",
        "availHeight",
        "colorDepth",
        "viewport",
        "dpr",
        "cores",
        "memoryGb",
        "touch",
        "maxTouchPoints",
        "coarsePointer",
        "storage",
        "cookies",
        "local",
        "session",
        "indexedDb",
        "graphics",
        "webdriver",
        "x",
    ];
    let pick = if depth > 5 {
        rng.below(5)
    } else {
        rng.below(7)
    };
    match pick {
        0 => Value::Null,
        1 => Value::Bool(rng.next() & 1 == 0),
        2 => match rng.below(4) {
            0 => json!(1),
            1 => json!(rng.next() as i64),
            2 => json!((rng.next() % 10_000) as f64 / 7.0),
            _ => json!(-(rng.below(1000) as i64)),
        },
        3 => {
            let len = rng.below(400);
            Value::String(
                (0..len)
                    .map(|i| ['a', 'é', '平', '\n', '"'][(i + rng.below(5)) % 5])
                    .collect(),
            )
        }
        4 => Value::String(KEYS[rng.below(KEYS.len())].to_owned()),
        5 => Value::Array(
            (0..rng.below(20))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut map = serde_json::Map::new();
            if rng.below(4) != 0 {
                map.insert("v".into(), json!(1));
            }
            for _ in 0..rng.below(8) {
                map.insert(
                    KEYS[rng.below(KEYS.len())].to_owned(),
                    random_value(rng, depth + 1),
                );
            }
            Value::Object(map)
        }
    }
}

/// §2.4 item 3: ≥ 10,000 deterministic random inputs (raw bytes, mutated
/// valid documents and schema-shaped random JSON) never panic, and whatever
/// parses re-serializes within the §9.11 bounds.
#[test]
fn telemetry_parsers_never_panic_on_random_input() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let valid = sdk_env().to_string().into_bytes();
    let mut parsed = 0usize;
    for i in 0..12_000 {
        let input: Vec<u8> = match i % 3 {
            0 => (0..rng.below(300)).map(|_| rng.next() as u8).collect(),
            1 => {
                let mut bytes = valid.clone();
                for _ in 0..=rng.below(8) {
                    let at = rng.below(bytes.len());
                    match rng.below(3) {
                        0 => bytes[at] = rng.next() as u8,
                        1 => {
                            bytes.remove(at);
                        }
                        _ => bytes.insert(at, b"{}[],:\"1ae"[rng.below(10)]),
                    }
                }
                bytes
            }
            _ => random_value(&mut rng, 0).to_string().into_bytes(),
        };
        if let Some(env) = TelemetryEnv::from_json(&input) {
            parsed += 1;
            // No `userAgent` key anywhere (checked by assert_bounded); the
            // string can still occur as a value, e.g. in `languages`.
            assert_bounded(&env.to_value(), 1);
            let reparsed: Value =
                serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
            assert_eq!(reparsed, env.to_value());
        }
        if let Some(auto) = TelemetryAuto::from_json(&input) {
            assert_bounded(&auto.to_value(), 1);
        }
    }
    assert!(
        parsed > 100,
        "random inputs too rarely valid ({parsed}) to exercise the parser"
    );
}

/// The envelope stays one valid JSON line for arbitrary strings.
#[test]
fn envelope_is_always_one_json_line() {
    let mut rng = XorShift(42);
    for _ in 0..10_000 {
        let s = |rng: &mut XorShift| -> String {
            (0..rng.below(40))
                .map(|_| char::from_u32(rng.next() as u32 % 0x11_0000).unwrap_or('\u{fffd}'))
                .collect()
        };
        let (kind, site, msg) = (s(&mut rng), s(&mut rng), s(&mut rng));
        let body = random_value(&mut rng, 3);
        let line = envelope(&kind, &site, rng.next() as i64, &msg, body);
        assert!(!line.contains('\n') && !line.contains('\r'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], kind.as_str());
        assert_eq!(v["msg"], msg.as_str());
        assert_eq!(key_order(&line)[..4], ["kind", "site", "ts", "msg"]);
    }
}

fn inputs(action: Action) -> SampleInputs {
    SampleInputs {
        action,
        sensitivity: RouteSensitivity::Low,
        force_log: false,
        flagged_hit: false,
        monitor: false,
    }
}

/// §9.11 sampling rule, row by row.
#[test]
fn decision_sampling_rule() {
    let rate = 0.1;
    for action in [Action::Allow, Action::Tag, Action::Log] {
        assert_eq!(
            decision_sample_rate(&inputs(action), rate),
            rate,
            "{action}"
        );
    }
    for action in [
        Action::Challenge,
        Action::Block,
        Action::RateLimit,
        Action::Unspecified,
    ] {
        assert_eq!(decision_sample_rate(&inputs(action), rate), 1.0, "{action}");
    }
    let base = inputs(Action::Allow);
    for sensitivity in [RouteSensitivity::High, RouteSensitivity::Critical] {
        let i = SampleInputs {
            sensitivity,
            ..base
        };
        assert_eq!(decision_sample_rate(&i, rate), 1.0);
    }
    let i = SampleInputs {
        sensitivity: RouteSensitivity::Medium,
        ..base
    };
    assert_eq!(decision_sample_rate(&i, rate), rate);
    assert_eq!(
        decision_sample_rate(
            &SampleInputs {
                force_log: true,
                ..base
            },
            rate
        ),
        1.0
    );
    assert_eq!(
        decision_sample_rate(
            &SampleInputs {
                flagged_hit: true,
                ..base
            },
            rate
        ),
        1.0
    );
    // Monitor mode: any recorded non-ALLOW decision is kept, ALLOW is sampled.
    let monitor_tag = SampleInputs {
        monitor: true,
        ..inputs(Action::Tag)
    };
    assert_eq!(decision_sample_rate(&monitor_tag, rate), 1.0);
    let monitor_allow = SampleInputs {
        monitor: true,
        ..base
    };
    assert_eq!(decision_sample_rate(&monitor_allow, rate), rate);
    // Out-of-range configuration values.
    assert_eq!(decision_sample_rate(&base, 7.0), 1.0);
    assert_eq!(decision_sample_rate(&base, -1.0), 0.0);
    assert_eq!(decision_sample_rate(&base, f32::NAN), 1.0);
    assert!(sample_keep(1.0, u32::MAX));
    assert!(!sample_keep(0.0, 0));
}

/// §9.11 / D-31 redaction and the §13.4 access-record path.
#[test]
fn path_redaction_and_access_path() {
    assert_eq!(redacted_path("password-reset"), "/password-reset");
    assert_eq!(
        access_path("/reset/tok3n-secret?email=a@b", Some("password-reset")),
        "/password-reset"
    );
    assert_eq!(
        access_path("/account/login?next=/x", None),
        "/account/login"
    );
    assert_eq!(access_path("/plain", None), "/plain");
    let long = format!("/{}", "é".repeat(2000));
    let cut = access_path(&long, None);
    assert!(cut.len() <= ACCESS_PATH_MAX_BYTES);
    assert!(cut.len() >= ACCESS_PATH_MAX_BYTES - 1);
    assert!(long.starts_with(cut.as_ref()));
}
