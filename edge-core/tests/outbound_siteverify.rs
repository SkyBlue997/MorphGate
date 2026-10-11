//! Siteverify client against the loopback mock (docs/impl/phase2-spec.md
//! §8.4, §8.5; WP-C6): the shared response samples of
//! `testdata/phase2/samples/siteverify/`, the request shape, the
//! idempotency-key vectors, retries, the previous secret, the deadline, the
//! local pre-check, the concurrency limit and the URL allowlist. Nothing
//! leaves the loopback interface.

use mg_core::challenge::{HttpMethod, OutboundError, OutboundHttp, OutboundRequest};
use mg_core::{EvalMode, ProviderId, VerdictOutcome};
use mg_edge_core::outbound::{
    MAX_CONCURRENT_REQUESTS, OutboundClient, SITEVERIFY_URL, SendError, Siteverify,
    SiteverifyExpect, SiteverifyReport, SiteverifyRequest, TurnstileSecrets, USER_AGENT,
    VerifyReason, idempotency_key, reason, report_siteverify_url, validate_siteverify_url,
};
use mg_edge_core::testkit::siteverify::{FakeSiteverify, MOCK_PATH, SvReply};
use serde_json::Value;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const TOKEN: &str = "0.tok_kat-Abc_123";
const NOW_MS: i64 = 1_790_000_060_000;
const C_IAT_MS: i64 = 1_790_000_000_000;
const CDATA: &str = "73JZ2i2xITj7ZpLLQN4TQePZjAncib9iP5EDW7ZYrFI";
/// `C_IAT_MS + 30 s`.
const TS: &str = "2026-09-21T14:13:50.000Z";

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase2/samples/siteverify")
}

fn kat() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase2/kat.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn client(mock: &FakeSiteverify) -> Siteverify {
    Siteverify::build(validate_siteverify_url(&mock.url(), true).unwrap()).unwrap()
}

fn secrets(values: &[&str]) -> TurnstileSecrets {
    TurnstileSecrets::new(values.iter().map(|v| (*v).to_owned()).collect()).unwrap()
}

fn hostnames() -> Vec<String> {
    vec!["example.com".into(), "www.example.com".into()]
}

/// Verifies `token` with the sample expectation; returns the report and the
/// `cdata` values the closure saw.
async fn run(
    sv: &Siteverify,
    secrets: &TurnstileSecrets,
    token: &str,
    now_ms: i64,
    deadline_after_ms: i64,
) -> (SiteverifyReport, Vec<String>) {
    let seen = std::sync::Mutex::new(Vec::new());
    let cdata_ok = |c: &str| {
        seen.lock().unwrap().push(c.to_owned());
        c == CDATA
    };
    let hostnames = hostnames();
    let expect = SiteverifyExpect {
        host: "example.com",
        hostnames: &hostnames,
        action: "login",
        c_iat_ms: C_IAT_MS,
        now_ms,
        deadline_ms: now_ms + deadline_after_ms,
        cdata_ok: &cdata_ok,
    };
    let req = SiteverifyRequest {
        secrets,
        response: token,
        remoteip: "203.0.113.7".parse().unwrap(),
        nonce: &NONCE,
    };
    let report = sv.verify_detailed(&req, &expect).await;
    (report, seen.into_inner().unwrap())
}

fn ic(report: &SiteverifyReport) -> Option<&str> {
    report.verdict.reason_codes.first().map(|c| c.as_ref())
}

#[tokio::test]
async fn shared_samples_map_as_specified() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    let one = secrets(&["0x4AAAAAAA-current"]);
    let cases: Value =
        serde_json::from_slice(&std::fs::read(samples().join("cases.json")).unwrap()).unwrap();
    let expect = &cases["expect"];
    assert_eq!(expect["cdata"], CDATA);
    assert_eq!(expect["c_iat_ms"], C_IAT_MS);
    assert_eq!(expect["now_ms"], NOW_MS);
    assert_eq!(expect["host"], "example.com");
    assert_eq!(expect["action"], "login");
    let all = cases["cases"].as_array().unwrap();
    assert_eq!(all.len(), 26);
    for case in all {
        let file = case["file"].as_str().unwrap();
        let body = std::fs::read(samples().join(file)).unwrap();
        mock.set_default_reply(SvReply::json(body.clone()));
        let before = mock.requests().len();
        let now = case["now_ms"].as_i64().unwrap_or(NOW_MS);
        let (report, seen) = run(&sv, &one, TOKEN, now, 5_000).await;
        let sent = mock.requests().len() - before;

        assert_eq!(
            report.verdict.outcome.as_str(),
            case["outcome"].as_str().unwrap(),
            "{file}: {report:?}"
        );
        assert_eq!(ic(&report), case["reason"].as_str(), "{file}");
        assert_eq!(
            report.verdict.is_pass(),
            case["outcome"] == "pass",
            "{file}"
        );
        // internal-error is retried once (same idempotency key); nothing else is.
        let want_sent = if file == "internal-error.json" { 2 } else { 1 };
        assert_eq!(sent, want_sent, "{file}");
        assert_eq!(usize::from(report.requests), want_sent, "{file}");
        // The cdata closure runs exactly once, on successful replies only.
        let parsed: Option<Value> = serde_json::from_slice(&body).ok();
        let success = parsed
            .as_ref()
            .and_then(|v| v.get("success"))
            .and_then(Value::as_bool)
            == Some(true);
        if success && !file.starts_with("malformed/") {
            let want = parsed.unwrap()["cdata"].as_str().unwrap().to_owned();
            assert_eq!(seen, vec![want], "{file}");
        } else {
            assert!(seen.is_empty(), "{file}: {seen:?}");
        }
        if report.verdict.outcome == VerdictOutcome::Pass {
            assert_eq!(report.reason, VerifyReason::Ok);
            assert!(report.verdict.reason_codes.is_empty());
            assert!(report.verdict.provider_ts_ms.is_some());
        }
    }
}

#[tokio::test]
async fn binding_checks_and_metric_reasons() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    let one = secrets(&["s1"]);
    let cases: &[(SvReply, VerdictOutcome, VerifyReason, Option<&str>)] = &[
        (
            SvReply::success("example.com", "login", CDATA, TS),
            VerdictOutcome::Pass,
            VerifyReason::Ok,
            None,
        ),
        // The configured list matches case-insensitively, the request host exactly.
        (
            SvReply::success("EXAMPLE.com", "login", CDATA, TS),
            VerdictOutcome::Fail,
            VerifyReason::Hostname,
            Some(reason::TS_HOSTNAME),
        ),
        (
            SvReply::success("sub.example.com", "login", CDATA, TS),
            VerdictOutcome::Fail,
            VerifyReason::Hostname,
            Some(reason::TS_HOSTNAME),
        ),
        (
            SvReply::success("example.com", "Login", CDATA, TS),
            VerdictOutcome::Fail,
            VerifyReason::Action,
            Some(reason::TS_ACTION),
        ),
        (
            SvReply::success("example.com", "login", &CDATA.to_lowercase(), TS),
            VerdictOutcome::Fail,
            VerifyReason::Cdata,
            Some(reason::TS_CDATA),
        ),
        (
            SvReply::success("example.com", "login", "", TS),
            VerdictOutcome::Fail,
            VerifyReason::Cdata,
            Some(reason::TS_CDATA),
        ),
        // Offsets are honoured: 14:13:15Z is C.iat - 5 s.
        (
            SvReply::success("example.com", "login", CDATA, "2026-09-21T22:13:15+08:00"),
            VerdictOutcome::Pass,
            VerifyReason::Ok,
            None,
        ),
        (
            SvReply::success(
                "example.com",
                "login",
                CDATA,
                "2026-09-21T22:13:14.999999999+08:00",
            ),
            VerdictOutcome::Fail,
            VerifyReason::Time,
            Some(reason::TS_TIME),
        ),
        // Several mismatches: the first in hostname, action, cdata, time order.
        (
            SvReply::success("evil.example", "signup", "x", "2020-01-01T00:00:00Z"),
            VerdictOutcome::Fail,
            VerifyReason::Hostname,
            Some(reason::TS_HOSTNAME),
        ),
        (
            SvReply::success("example.com", "signup", "x", "2020-01-01T00:00:00Z"),
            VerdictOutcome::Fail,
            VerifyReason::Action,
            Some(reason::TS_ACTION),
        ),
        (
            SvReply::success("example.com", "login", "x", "2020-01-01T00:00:00Z"),
            VerdictOutcome::Fail,
            VerifyReason::Cdata,
            Some(reason::TS_CDATA),
        ),
        // Error-code priority: secret > bad-request > duplicate > response > internal.
        (
            SvReply::error_codes(&["internal-error", "missing-input-secret"]),
            VerdictOutcome::Misconfigured,
            VerifyReason::Secret,
            Some(reason::PROVIDER_MISCONFIGURED),
        ),
        (
            SvReply::error_codes(&["timeout-or-duplicate", "bad-request"]),
            VerdictOutcome::Unavailable,
            VerifyReason::BadRequest,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::error_codes(&["internal-error", "timeout-or-duplicate"]),
            VerdictOutcome::Fail,
            VerifyReason::Dup,
            Some(reason::TS_DUP),
        ),
        (
            SvReply::error_codes(&["internal-error", "invalid-input-response"]),
            VerdictOutcome::Fail,
            VerifyReason::Fail,
            Some(reason::TS_FAIL),
        ),
        (
            SvReply::error_codes(&[]),
            VerdictOutcome::Unavailable,
            VerifyReason::Malformed,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::error_codes(&["some-new-code"]),
            VerdictOutcome::Unavailable,
            VerifyReason::Malformed,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        // Transport-level replies.
        (
            SvReply::status(400),
            VerdictOutcome::Unavailable,
            VerifyReason::Http,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::status(302),
            VerdictOutcome::Unavailable,
            VerifyReason::Http,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::raw(200, Some("text/plain"), r#"{"success":true}"#),
            VerdictOutcome::Unavailable,
            VerifyReason::Malformed,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::raw(
                200,
                None,
                r#"{"success":false,"error-codes":["timeout-or-duplicate"]}"#,
            ),
            VerdictOutcome::Unavailable,
            VerifyReason::Malformed,
            Some(reason::PROVIDER_UNAVAILABLE),
        ),
        (
            SvReply::raw(
                200,
                Some("Application/JSON; charset=utf-8"),
                r#"{"success":false,"error-codes":["timeout-or-duplicate"]}"#,
            ),
            VerdictOutcome::Fail,
            VerifyReason::Dup,
            Some(reason::TS_DUP),
        ),
    ];
    for (reply, outcome, why, code) in cases {
        mock.set_default_reply(reply.clone());
        let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 5_000).await;
        assert_eq!(report.verdict.outcome, *outcome, "{reply:?}: {report:?}");
        assert_eq!(report.reason, *why, "{reply:?}");
        assert_eq!(ic(&report), *code, "{reply:?}");
        assert_eq!(report.verdict.is_pass(), *outcome == VerdictOutcome::Pass);
    }
}

#[tokio::test]
async fn request_shape_user_agent_and_idempotency_key() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    mock.set_default_reply(SvReply::success("example.com", "login", CDATA, TS));
    let (report, _) = run(&sv, &secrets(&["sec-current"]), TOKEN, NOW_MS, 5_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, MOCK_PATH);
    assert_eq!(r.header("user-agent"), Some(USER_AGENT));
    assert_eq!(r.header("user-agent"), Some("morphgate-dev-tooling"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("referer"), None);
    assert!(r.body.len() <= 4096);
    let json = r.json().unwrap();
    let mut keys: Vec<&str> = json.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["idempotency_key", "remoteip", "response", "secret"]);
    assert_eq!(r.secret().as_deref(), Some("sec-current"));
    assert_eq!(r.response().as_deref(), Some(TOKEN));
    assert_eq!(r.remoteip().as_deref(), Some("203.0.113.7"));
    assert_eq!(
        r.idempotency_key().as_deref(),
        Some("4ed6c721-a6b4-4e1f-acd9-76593e646d6f"),
        "kat.json idempotency_key case 0"
    );

    // IPv6 client addresses are sent in their canonical form.
    let hostnames = hostnames();
    let ok = |_: &str| true;
    let expect = SiteverifyExpect {
        host: "example.com",
        hostnames: &hostnames,
        action: "login",
        c_iat_ms: C_IAT_MS,
        now_ms: NOW_MS,
        deadline_ms: NOW_MS + 5_000,
        cdata_ok: &ok,
    };
    let s = secrets(&["sec-current"]);
    let ip: IpAddr = "2001:db8:0:0::1".parse().unwrap();
    let req = SiteverifyRequest {
        secrets: &s,
        response: TOKEN,
        remoteip: ip,
        nonce: &NONCE,
    };
    assert!(sv.verify(&req, &expect).await.is_pass());
    assert_eq!(
        mock.requests()[1].remoteip().as_deref(),
        Some("2001:db8::1")
    );
}

#[test]
fn idempotency_keys_match_the_vectors() {
    let kat = kat();
    let cases = kat["idempotency_key"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let nonce = hex16(c["nonce_hex"].as_str().unwrap());
        assert_eq!(idempotency_key(&nonce, false), c["idempotency_key"]);
        assert_eq!(
            idempotency_key(&nonce, true),
            c["idempotency_key_previous_secret"]
        );
    }
}

#[test]
fn secrets_are_validated_and_never_printed() {
    let s = secrets(&["very-secret-1", "very-secret-0"]);
    assert_eq!(s.current(), "very-secret-1");
    assert_eq!(s.previous(), Some("very-secret-0"));
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("very-secret"), "{dbg}");
    for bad in [
        vec![],
        vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        vec![String::new()],
        vec!["has space".to_owned()],
        vec!["x".repeat(257)],
        vec!["ok".to_owned(), "tab\t".to_owned()],
    ] {
        assert!(TurnstileSecrets::new(bad.clone()).is_err(), "{bad:?}");
    }
    assert!(TurnstileSecrets::new(vec!["x".repeat(256)]).is_ok());

    let ok = |_: &str| true;
    let hn = hostnames();
    let req = SiteverifyRequest {
        secrets: &s,
        response: "the-token-value",
        remoteip: "203.0.113.7".parse().unwrap(),
        nonce: &NONCE,
    };
    let expect = SiteverifyExpect {
        host: "example.com",
        hostnames: &hn,
        action: "login",
        c_iat_ms: 0,
        now_ms: 0,
        deadline_ms: 0,
        cdata_ok: &ok,
    };
    let dbg = format!("{req:?} {expect:?}");
    assert!(
        !dbg.contains("the-token-value") && !dbg.contains("very-secret"),
        "{dbg}"
    );
}

#[tokio::test]
async fn transient_errors_are_retried_once_with_the_same_key() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    let one = secrets(&["s1"]);
    let pass = || SvReply::success("example.com", "login", CDATA, TS);
    let internal = || SvReply::error_codes(&["internal-error"]);
    let cases: Vec<(Vec<SvReply>, VerdictOutcome, VerifyReason, usize)> = vec![
        (
            vec![SvReply::status(503), pass()],
            VerdictOutcome::Pass,
            VerifyReason::Ok,
            2,
        ),
        (
            vec![SvReply::status(500), SvReply::status(502)],
            VerdictOutcome::Unavailable,
            VerifyReason::Http,
            2,
        ),
        (
            vec![SvReply::disconnect(), pass()],
            VerdictOutcome::Pass,
            VerifyReason::Ok,
            2,
        ),
        (
            vec![SvReply::disconnect(), SvReply::disconnect()],
            VerdictOutcome::Unavailable,
            VerifyReason::Transport,
            2,
        ),
        (
            vec![internal(), pass()],
            VerdictOutcome::Pass,
            VerifyReason::Ok,
            2,
        ),
        (
            vec![internal(), internal()],
            VerdictOutcome::Unavailable,
            VerifyReason::Internal,
            2,
        ),
        // One retry in total, whatever the mix.
        (
            vec![SvReply::status(503), internal(), pass()],
            VerdictOutcome::Unavailable,
            VerifyReason::Internal,
            2,
        ),
        (
            vec![internal(), SvReply::error_codes(&["timeout-or-duplicate"])],
            VerdictOutcome::Fail,
            VerifyReason::Dup,
            2,
        ),
        // Never retried.
        (
            vec![SvReply::error_codes(&["timeout-or-duplicate"]), pass()],
            VerdictOutcome::Fail,
            VerifyReason::Dup,
            1,
        ),
        (
            vec![SvReply::error_codes(&["invalid-input-response"]), pass()],
            VerdictOutcome::Fail,
            VerifyReason::Fail,
            1,
        ),
        (
            vec![SvReply::error_codes(&["bad-request"]), pass()],
            VerdictOutcome::Unavailable,
            VerifyReason::BadRequest,
            1,
        ),
        (
            vec![SvReply::status(429), pass()],
            VerdictOutcome::Unavailable,
            VerifyReason::Http,
            1,
        ),
        (
            vec![
                SvReply::json(format!(
                    "{{\"success\":false,\"p\":\"{}\"}}",
                    "x".repeat(17_000)
                )),
                pass(),
            ],
            VerdictOutcome::Unavailable,
            VerifyReason::Malformed,
            1,
        ),
    ];
    for (replies, outcome, why, sent) in cases {
        let label = format!("{replies:?}");
        let total = replies.len();
        mock.clear_replies();
        mock.set_default_reply(SvReply::error_codes(&["bad-request"]));
        let before = mock.requests().len();
        mock.push_replies(replies);
        let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 5_000).await;
        let reqs = mock.requests()[before..].to_vec();
        assert_eq!(report.verdict.outcome, outcome, "{label}: {report:?}");
        assert_eq!(report.reason, why, "{label}");
        assert_eq!(reqs.len(), sent, "{label}");
        assert_eq!(usize::from(report.requests), sent, "{label}");
        assert_eq!(mock.queued(), total - sent, "{label}");
        let key = idempotency_key(&NONCE, false);
        assert!(
            reqs.iter()
                .all(|r| r.idempotency_key().as_deref() == Some(key.as_str())
                    && r.secret().as_deref() == Some("s1")),
            "{label}"
        );
    }
}

#[tokio::test]
async fn timeouts_retry_only_with_a_second_left() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    let one = secrets(&["s1"]);
    let pass = SvReply::success("example.com", "login", CDATA, TS);

    // 3 s deadline: the first request gets 1.75 s, the retry the rest.
    mock.push_replies([SvReply::hang(), pass.clone()]);
    let t = Instant::now();
    let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 3_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
    assert_eq!(report.requests, 2);
    let elapsed = t.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_700) && elapsed < Duration::from_millis(3_000),
        "{elapsed:?}"
    );

    // 1.5 s deadline: the whole budget goes to the first request; no retry.
    mock.push_replies([SvReply::hang(), pass.clone()]);
    let before = mock.requests().len();
    let t = Instant::now();
    let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 1_500).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Unavailable);
    assert_eq!(report.reason, VerifyReason::Timeout);
    assert_eq!(ic(&report), Some(reason::PROVIDER_UNAVAILABLE));
    assert_eq!(report.requests, 1);
    let elapsed = t.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_400) && elapsed < Duration::from_millis(2_500),
        "{elapsed:?}"
    );
    assert_eq!(mock.requests().len(), before + 1);
    assert_eq!(mock.queued(), 1);
    mock.clear_replies();

    // A slow but timely reply passes; a deadline already spent sends nothing.
    mock.push_replies([pass.clone().after(Duration::from_millis(300))]);
    let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 1_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
    let before = mock.requests().len();
    for deadline in [0, -1] {
        let (report, seen) = run(&sv, &one, TOKEN, NOW_MS, deadline).await;
        assert_eq!(report.verdict.outcome, VerdictOutcome::Unavailable);
        assert_eq!(report.reason, VerifyReason::Timeout);
        assert_eq!(report.requests, 0);
        assert!(seen.is_empty());
    }
    assert_eq!(mock.requests().len(), before);

    // A 5xx retry is not bound by the one-second rule.
    mock.push_replies([
        SvReply::status(503).after(Duration::from_millis(1_200)),
        pass,
    ]);
    let (report, _) = run(&sv, &one, TOKEN, NOW_MS, 2_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
    assert_eq!(report.requests, 2);
}

#[tokio::test]
async fn previous_secret_is_tried_once_with_its_own_key() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    let two = secrets(&["new-secret", "old-secret"]);
    let key = idempotency_key(&NONCE, false);
    let old_key = idempotency_key(&NONCE, true);
    assert_eq!(old_key, "f320d6d0-7cc4-438f-8cc6-9a3ebd6c51d0");

    // Only the previous secret works.
    mock.set_responder(|r| {
        Some(if r.secret().as_deref() == Some("old-secret") {
            SvReply::success("example.com", "login", CDATA, TS)
        } else {
            SvReply::error_codes(&["invalid-input-secret"])
        })
    });
    let before = mock.requests().len();
    let (report, _) = run(&sv, &two, TOKEN, NOW_MS, 5_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
    assert!(report.previous_secret_used);
    let reqs = &mock.requests()[before..];
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].secret().as_deref(), Some("new-secret"));
    assert_eq!(reqs[0].idempotency_key().as_deref(), Some(key.as_str()));
    assert_eq!(reqs[1].secret().as_deref(), Some("old-secret"));
    assert_eq!(reqs[1].idempotency_key().as_deref(), Some(old_key.as_str()));

    // Both rejected: misconfigured after exactly two requests.
    mock.set_responder(|_| Some(SvReply::error_codes(&["invalid-input-secret"])));
    let before = mock.requests().len();
    let (report, _) = run(&sv, &two, TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Misconfigured);
    assert_eq!(report.reason, VerifyReason::Secret);
    assert_eq!(ic(&report), Some(reason::PROVIDER_MISCONFIGURED));
    assert_eq!(report.error_codes, ["invalid-input-secret"]);
    assert_eq!(mock.requests().len() - before, 2);

    // Without a previous secret: misconfigured after one request.
    let before = mock.requests().len();
    let (report, _) = run(&sv, &secrets(&["new-secret"]), TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Misconfigured);
    assert!(!report.previous_secret_used);
    assert_eq!(mock.requests().len() - before, 1);

    // missing-input-secret never tries the previous secret.
    mock.set_responder(|_| Some(SvReply::error_codes(&["missing-input-secret"])));
    let before = mock.requests().len();
    let (report, _) = run(&sv, &two, TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Misconfigured);
    assert_eq!(mock.requests().len() - before, 1);

    // The previous-secret request may itself get its transient retry, with
    // the previous-secret key: three requests at most.
    let n = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&n);
    mock.set_responder(move |r| {
        counter.fetch_add(1, Ordering::Relaxed);
        Some(match r.secret().as_deref() {
            Some("old-secret") => SvReply::error_codes(&["internal-error"]),
            _ => SvReply::error_codes(&["invalid-input-secret"]),
        })
    });
    let before = mock.requests().len();
    let (report, _) = run(&sv, &two, TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Unavailable);
    assert_eq!(report.reason, VerifyReason::Internal);
    let reqs = &mock.requests()[before..];
    assert_eq!(reqs.len(), 3);
    assert_eq!(n.load(Ordering::Relaxed), 3);
    assert_eq!(reqs[1].idempotency_key(), reqs[2].idempotency_key());
    assert_eq!(reqs[2].idempotency_key().as_deref(), Some(old_key.as_str()));
}

#[tokio::test]
async fn local_precheck_sends_nothing() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    mock.set_default_reply(SvReply::success("example.com", "login", CDATA, TS));
    let one = secrets(&["s1"]);
    let long = "a".repeat(2049);
    for token in ["", long.as_str(), "a b", "tok\u{e9}n", "tok\n", "tok\u{7f}"] {
        let (report, seen) = run(&sv, &one, token, NOW_MS, 5_000).await;
        assert_eq!(report.verdict.outcome, VerdictOutcome::Fail, "{token:?}");
        assert_eq!(report.reason, VerifyReason::Precheck);
        assert_eq!(ic(&report), Some(reason::TS_FAIL));
        assert_eq!(report.requests, 0);
        assert!(seen.is_empty());
    }
    assert!(mock.requests().is_empty());
    // A 2048-character token of characters JSON escapes would exceed 4 KiB.
    let quotes = "\"".repeat(2048);
    let (report, _) = run(&sv, &one, &quotes, NOW_MS, 5_000).await;
    assert_eq!(report.reason, VerifyReason::Precheck);
    assert!(mock.requests().is_empty());
    let max = "a".repeat(2048);
    let (report, _) = run(&sv, &one, &max, NOW_MS, 5_000).await;
    assert!(report.verdict.is_pass());
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn concurrency_limit_answers_busy() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = client(&mock);
    mock.set_default_reply(SvReply::hang());
    let s = Arc::new(secrets(&["s1"]));
    let mut tasks = Vec::new();
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        let (sv, s) = (sv.clone(), Arc::clone(&s));
        tasks.push(tokio::spawn(async move {
            run(&sv, &s, TOKEN, NOW_MS, 5_000).await;
        }));
    }
    let arrived = mock
        .wait_for_requests(MAX_CONCURRENT_REQUESTS, Duration::from_secs(5))
        .await;
    assert_eq!(arrived.len(), MAX_CONCURRENT_REQUESTS);
    assert_eq!(sv.http().in_flight(), MAX_CONCURRENT_REQUESTS);

    let (report, _) = run(&sv, &s, TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Unavailable);
    assert_eq!(report.reason, VerifyReason::Busy);
    assert_eq!(ic(&report), Some(reason::PROVIDER_UNAVAILABLE));
    assert_eq!(report.requests, 0);
    assert_eq!(
        report.breaker_signal(),
        mg_edge_core::outbound::BreakerSignal::Neutral
    );
    assert_eq!(mock.requests().len(), MAX_CONCURRENT_REQUESTS);
    // The raw client says Busy too, and the trait folds it into Transport.
    let raw = sv
        .http()
        .send_checked(OutboundRequest {
            method: HttpMethod::Post,
            url: mock.url(),
            headers: vec![],
            body: b"{}".to_vec(),
            timeout_ms: 1_000,
        })
        .await;
    assert_eq!(raw, Err(SendError::Busy));

    for t in &tasks {
        t.abort();
    }
    for t in tasks {
        let _ = t.await;
    }
    assert_eq!(sv.http().in_flight(), 0);
    mock.set_default_reply(SvReply::success("example.com", "login", CDATA, TS));
    let (report, _) = run(&sv, &s, TOKEN, NOW_MS, 5_000).await;
    assert!(report.verdict.is_pass(), "slots are released: {report:?}");
}

#[tokio::test]
async fn only_allowlisted_destinations_are_reached() {
    let mock = FakeSiteverify::start().unwrap();
    let other = FakeSiteverify::start().unwrap();
    let url = validate_siteverify_url(&mock.url(), true).unwrap();
    let http = OutboundClient::new(std::slice::from_ref(&url)).unwrap();
    assert!(http.allows(&mock.url()));
    for dest in [
        other.url(),
        format!("{}/", mock.url()),
        mock.url().replace("127.0.0.1", "localhost"),
        SITEVERIFY_URL.to_owned(),
    ] {
        let req = OutboundRequest {
            method: HttpMethod::Post,
            url: dest.clone(),
            headers: vec![],
            body: b"{}".to_vec(),
            timeout_ms: 1_000,
        };
        assert_eq!(
            http.send(req).await,
            Err(OutboundError::Denied(dest.clone())),
            "{dest}"
        );
    }
    assert!(other.requests().is_empty());
    assert!(mock.requests().is_empty());

    // A Siteverify whose URL is not on its client's allowlist never sends.
    let sv = Siteverify::new(Arc::new(OutboundClient::new(&[]).unwrap()), url.clone());
    let (report, _) = run(&sv, &secrets(&["s1"]), TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.verdict.outcome, VerdictOutcome::Unavailable);
    assert_eq!(report.requests, 0);
    assert!(mock.requests().is_empty());

    // Request bodies over 4 KiB are refused before sending.
    let req = OutboundRequest {
        method: HttpMethod::Post,
        url: mock.url(),
        headers: vec![],
        body: vec![b'x'; 4097],
        timeout_ms: 1_000,
    };
    assert_eq!(
        http.send_checked(req).await,
        Err(SendError::RequestTooLarge)
    );
    assert!(mock.requests().is_empty());

    // Through the trait, an allowed request works and keeps the status.
    mock.set_default_reply(SvReply::status(204));
    let resp = http
        .send(OutboundRequest {
            method: HttpMethod::Get,
            url: mock.url(),
            headers: vec![],
            body: vec![],
            timeout_ms: 1_000,
        })
        .await
        .unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(mock.requests()[0].method, "GET");
}

#[tokio::test]
async fn ipv6_loopback_mock_works_when_available() {
    let Ok(mock) = FakeSiteverify::start_ipv6() else {
        eprintln!("no IPv6 loopback; skipped");
        return;
    };
    assert!(mock.url().starts_with("http://[::1]:"));
    let sv = client(&mock);
    mock.set_default_reply(SvReply::success("example.com", "login", CDATA, TS));
    let (report, _) = run(&sv, &secrets(&["s1"]), TOKEN, NOW_MS, 5_000).await;
    assert!(report.verdict.is_pass(), "{report:?}");
}

#[tokio::test]
async fn metrics_and_provider_outcome() {
    let mock = FakeSiteverify::start().unwrap();
    let url = validate_siteverify_url(&mock.url(), true).unwrap();
    report_siteverify_url(&url);
    let sv = Siteverify::build(url).unwrap();
    mock.set_default_reply(SvReply::error_codes(&["timeout-or-duplicate", "x-unknown"]));
    let (report, _) = run(&sv, &secrets(&["s1"]), TOKEN, NOW_MS, 5_000).await;
    assert_eq!(report.error_codes, ["timeout-or-duplicate"]);
    let po = report.provider_outcome(EvalMode::Shadow);
    assert_eq!(po.id, ProviderId::Turnstile);
    assert_eq!(po.outcome, VerdictOutcome::Fail);
    assert_eq!(po.mode, EvalMode::Shadow);
    assert_eq!(po.error_codes, ["timeout-or-duplicate"]);

    let dup = scraped(
        "mg_provider_verify_total",
        &[
            ("provider", "turnstile"),
            ("outcome", "fail"),
            ("reason", "dup"),
        ],
    )
    .expect("dup counted");
    assert!(dup >= 1.0);
    let count = scraped(
        "mg_provider_verify_latency_seconds_count",
        &[("provider", "turnstile")],
    )
    .expect("latency exported");
    assert!(count >= 1.0);
    assert_eq!(
        scraped("mg_outbound_override", &[("target", "siteverify")]),
        Some(1.0)
    );
    report_siteverify_url(&validate_siteverify_url(SITEVERIFY_URL, false).unwrap());
    assert_eq!(
        scraped("mg_outbound_override", &[("target", "siteverify")]),
        Some(0.0)
    );
}

/// Value of `name{labels}` as the default registry exports it (text
/// exposition format, which is stable whichever prometheus features the
/// workspace build unifies); `None` when absent.
fn scraped(name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    use prometheus::Encoder as _;
    let mut text = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&prometheus::gather(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(name)?.strip_prefix('{')?;
        let (set, value) = rest.split_once("} ")?;
        labels
            .iter()
            .all(|(k, v)| set.split(',').any(|p| p == format!("{k}=\"{v}\"")))
            .then(|| value.parse().unwrap())
    })
}
