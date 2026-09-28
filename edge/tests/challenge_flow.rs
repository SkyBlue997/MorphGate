//! The challenge flow end to end through the real binary
//! (docs/impl/phase1-spec.md §10, §9.7-§9.9, §15 WP-E1c `challenge_flow.rs`):
//! the challenge page and the JSON challenge, a solved submission (form
//! navigation: 303 + cookie; fetch: 200 JSON + cookie) whose cookie then
//! passes `require_clearance` with `MG-Session`, replay, tampering, the body
//! rules, the failure and issuance quotas, unknown client IPs, the replay
//! store without Valkey (`FaultProxy`), a route removed by a newer bundle, a
//! full local replay set, escalation after a failure, the https redirect of
//! http visitors and `/__mg/c` in bootstrap. A clearance issued without a
//! replay check (`ruc`, I-30) is accepted except on `fail_closed` routes,
//! which challenge again (429 while the replay store is still unavailable).
//!
//! The solver is `mg_challenge::pow_solve` (a test-only reference). Loopback
//! only. Reason codes are read from the Edge's debug log line
//! (`submit=<result> type=<type> reasons=<codes>`).

mod common;

use common::policy::{default_route, field, glob, route, rule};
use common::valkey::Valkey;
use common::{Edge, Response, TestEnv, blog_bundle, cf, get, raw, sign, with_valkey};
use mg_challenge::{SealKeys, Sealer, pow_solve};
use mg_core::{ChallengeType, RiskBand, SealedChallengeClaims};
use mg_edge_core::testkit::valkey::FaultMode;
use mg_proto::v1::challenge_config::PowBits;
use mg_proto::v1::{Action, RouteSensitivity as S, SiteBundle};
use serde_json::{Value, json};
use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";
const BITS: PowBits = PowBits {
    low: 8,
    medium: 9,
    high: 10,
    very_high: 11,
};

fn bits_of(band: RiskBand) -> u32 {
    match band {
        RiskBand::Low => BITS.low,
        RiskBand::Medium => BITS.medium,
        RiskBand::High => BITS.high,
        RiskBand::VeryHigh => BITS.very_high,
    }
}

/// Headers of a Chrome navigation from `ip` (a low score).
fn browser(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: text/html,application/xhtml+xml\r\n\
         Accept-Language: zh-CN,zh;q=0.9\r\nSec-Fetch-Mode: navigate\r\n\
         Sec-CH-UA: \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"\r\n",
        cf(ip)
    )
}

/// Headers of a script of the site (fetch): the Edge answers JSON.
fn fetcher(ip: &str) -> String {
    format!(
        "{}User-Agent: {CHROME}\r\nAccept: application/json\r\n\
         Accept-Language: en\r\nSec-Fetch-Mode: cors\r\n\
         Sec-CH-UA: \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"\r\n",
        cf(ip)
    )
}

/// An enforce bundle: low difficulties (fast to solve), a `fail_closed`
/// critical login route, a members route that requires clearance, a route
/// whose rule asks for a `pow` challenge, and generous submission quotas
/// (the quota tests lower them).
fn bundle() -> SiteBundle {
    let mut b = blog_bundle(1);
    b.monitor_only = false;
    let c = b.challenge.as_mut().unwrap();
    c.pow_bits = Some(BITS);
    c.submit_rate = 1000;
    c.submit_burst = 1000;
    c.max_failures = 1000;
    let env = &mut b.environments[0];
    env.routes = vec![
        route("login", &["/account/login"], S::Critical, true, true),
        route("members", &["/members/**"], S::Medium, true, false),
        route("gate", &["/gate/**"], S::Low, false, false),
        default_route(),
    ];
    env.rules = vec![rule(
        "pow-gate",
        "custom",
        Action::Challenge,
        glob(field("req.path"), "/gate/**"),
        &[("type", "pow")],
    )];
    b
}

/// The default test config with `valkey_extra` lines added to `[valkey]`.
fn config(env: &TestEnv, valkey_extra: &str) -> String {
    let local = "[valkey]\nmode = \"local\"\n";
    let text = env.default_config("");
    assert!(text.contains(local));
    text.replace(local, &format!("{local}{valkey_extra}"))
}

/// Starts the Edge with `b` as its LKG, local state, and a replay set that
/// may decide alone (one Edge, §9.7 rule 3).
fn start(env: &TestEnv, b: &SiteBundle) -> Edge {
    start_with(env, b, "local_replay_authoritative = true\n")
}

fn start_with(env: &TestEnv, b: &SiteBundle, valkey_extra: &str) -> Edge {
    env.write_lkg("blog", &sign(b));
    let edge = env.spawn(&env.write_config(&config(env, valkey_extra)));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge
}

/// The site's sealer (the test seal root), to inspect issued challenges.
fn sealer() -> Sealer {
    let json = std::fs::read(common::repo("testdata/phase1/keys/seal.root.json")).unwrap();
    Sealer::new("blog", SealKeys::from_key_file(&json, "blog").unwrap())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn open(c: &str, ty: ChallengeType) -> SealedChallengeClaims {
    sealer().open(c, "example.com", ty, now_ms()).unwrap()
}

/// A challenge as the page or the JSON shows it.
#[derive(Debug, Clone)]
struct Shown {
    c: String,
    ty: ChallengeType,
    bits: u32,
    ret: String,
}

fn ty(s: &str) -> ChallengeType {
    match s {
        "invisible" => ChallengeType::Invisible,
        "pow" => ChallengeType::Pow,
        other => panic!("unexpected type {other}"),
    }
}

/// The value of the attribute `name` in the challenge page.
fn attr(html: &str, name: &str) -> String {
    html.split(&format!("{name}=\""))
        .nth(1)
        .and_then(|t| t.split('"').next())
        .unwrap_or_else(|| panic!("no {name} in {html}"))
        .to_owned()
}

fn from_page(html: &str) -> Shown {
    Shown {
        c: attr(html, "data-mg-c"),
        ty: ty(&attr(html, "data-mg-type")),
        bits: attr(html, "data-mg-pow-bits").parse().unwrap(),
        ret: attr(html, "data-mg-ret").replace("&amp;", "&"),
    }
}

fn from_json(v: &Value) -> Shown {
    Shown {
        c: v["challenge"].as_str().unwrap().to_owned(),
        ty: ty(v["type"].as_str().unwrap()),
        bits: v["pow"]["bits"].as_u64().unwrap() as u32,
        ret: v["ret"].as_str().unwrap_or_default().to_owned(),
    }
}

/// The submission JSON of the SDK for `s`, solved.
fn solved(s: &Shown, ua: &str) -> Value {
    let counter = pow_solve(&s.c, s.bits, 1 << 24).expect("solvable");
    json!({"v": 1, "type": s.ty.as_str(), "c": s.c, "pow": {"counters": [counter]},
           "ret": s.ret, "ts": now_ms(), "build": "1df90640e0c5fec4",
           "env": {"v": 1, "ua": {"userAgent": ua, "brands": null, "mobile": false, "platform": null},
                   "languages": ["zh-CN"], "graphics": null},
           "auto": {"v": 1, "webdriver": false}})
}

/// `mg=<json>` as the browser's form serializer writes it (spaces as `+`).
fn form_body(json: &Value) -> Vec<u8> {
    let mut out = b"mg=".to_vec();
    for b in json.to_string().bytes() {
        match b {
            b' ' => out.push(b'+'),
            b'*' | b'-' | b'.' | b'_' => out.push(b),
            b if b.is_ascii_alphanumeric() => out.push(b),
            b => out.extend(format!("%{b:02X}").bytes()),
        }
    }
    out
}

/// `POST <path>` with `headers` (each ending in `\r\n`) and `body`.
fn post(env: &TestEnv, host: &str, path: &str, headers: &str, body: &[u8]) -> Response {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    raw(env.listen, &req).unwrap_or_else(|e| panic!("POST {path}: {e}"))
}

/// A form navigation submitting `v` from `ip` with `ua`.
fn submit_form(env: &TestEnv, ip: &str, ua: &str, v: &Value) -> Response {
    let headers = format!(
        "{}User-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Sec-Fetch-Mode: navigate\r\nAccept-Language: zh-CN\r\n",
        cf(ip)
    );
    post(env, "example.com", "/__mg/c", &headers, &form_body(v))
}

/// A fetch submission of `v` from `ip` with `ua` and extra header lines.
fn submit_json(env: &TestEnv, ip: &str, ua: &str, extra: &str, v: &Value) -> Response {
    let headers = format!(
        "{}User-Agent: {ua}\r\nContent-Type: application/json\r\nSec-Fetch-Mode: cors\r\n{extra}",
        cf(ip)
    );
    post(
        env,
        "example.com",
        "/__mg/c",
        &headers,
        v.to_string().as_bytes(),
    )
}

/// The JSON challenge of `path` for a fetch from `ip`.
fn json_challenge(env: &TestEnv, path: &str, ip: &str) -> Shown {
    let r = get(env.listen, "example.com", path, &fetcher(ip));
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    from_json(&serde_json::from_str(&r.body).unwrap())
}

/// Waits for the debug line of the request whose body carries its id.
fn line_of(edge: &Edge, r: &Response) -> String {
    common::answered_log(edge, &r.body)
}

/// Waits until a debug line contains every needle.
fn wait_log(edge: &Edge, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(l) = edge
            .log_text()
            .lines()
            .find(|l| needles.iter().all(|n| l.contains(n)))
        {
            return l.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "no log line with {needles:?}:\n{}",
            edge.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn cookie_of(r: &Response) -> String {
    let set = r.header("set-cookie").expect("Set-Cookie");
    assert!(
        set.ends_with("; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax"),
        "{set}"
    );
    set.split(';').next().unwrap().to_owned()
}

fn metric(edge: &Edge, ty: &str, result: &str) -> f64 {
    edge.metric(&format!(
        "mg_challenge_total{{provider=\"none\",result=\"{result}\",type=\"{ty}\"}}"
    ))
}

// ---------------------------------------------------------------------------

/// §10.2 / §10.3 / D-11: GET → 403 challenge page; the form submission of
/// the solved challenge → 303 + cookie; the cookie passes the
/// `require_clearance` route and the origin gets `MG-Session`; a replay of
/// the same submission is refused.
#[test]
fn challenge_page_to_clearance() {
    let env = TestEnv::new("chal-page");
    let edge = start(&env, &bundle());
    let ip = "198.51.100.20";

    let r = get(env.listen, "example.com", "/members/a?x=1", &browser(ip));
    assert_eq!(r.status, 403, "{}", r.head);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(r.header("cache-control"), Some("no-store, private"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert!(!r.has_header_prefix("mg-"), "{}", r.head);
    assert!(
        !r.body.contains("{{") && !r.body.contains("}}"),
        "{}",
        r.body
    );
    // The CSP nonce is the one on the page's script and style.
    let csp = r.header("content-security-policy").unwrap();
    let nonce = attr(&r.body, "nonce");
    assert_eq!(
        csp,
        format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
             worker-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; \
             base-uri 'none'; frame-ancestors 'none'"
        )
    );
    assert_eq!(nonce.len(), 24);
    assert_eq!(r.body.matches(&format!("nonce=\"{nonce}\"")).count(), 2);
    assert!(r.body.contains("<html lang=\"zh-CN\">"));
    assert!(r.body.contains("data-mg-state=\"challenge\""));
    assert!(r.body.contains("data-mg-prefix=\"/__mg/\""));
    let shown = from_page(&r.body);
    assert_eq!(shown.ret, "/members/a?x=1");
    assert_eq!(shown.ty, ChallengeType::Invisible);
    assert_eq!(shown.bits, BITS.low, "invisible uses pow_bits.low (D-27)");
    let claims = open(&shown.c, ChallengeType::Invisible);
    assert_eq!(claims.route_class, "members");
    assert!(claims.exp_ms - claims.iat_ms <= 120_000);
    // A fresh page has a fresh nonce and a fresh C.
    let again = get(env.listen, "example.com", "/members/a?x=1", &browser(ip));
    assert_ne!(attr(&again.body, "nonce"), nonce);
    assert_ne!(from_page(&again.body).c, shown.c);
    // §10.2: HEAD gets the page's headers only.
    let head = raw(
        env.listen,
        format!(
            "HEAD /members/a?x=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n{}\r\n",
            browser(ip)
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(head.status, 403, "{}", head.head);
    assert_eq!(
        head.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(
        head.header("content-security-policy")
            .is_some_and(|p| p.contains("script-src 'nonce-"))
    );
    assert!(head.header("content-length").is_some_and(|n| n != "0"));
    assert!(head.body.is_empty(), "{}", head.body);

    // The SDK the page loads is served from the manifest, immutable.
    let src = attr(&r.body, "src");
    let js = get(env.listen, "example.com", &src, "");
    assert_eq!(js.status, 200, "{}", js.head);
    assert_eq!(
        js.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(
        js.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(js.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        get(env.listen, "example.com", "/__mg/s/challenge.html", "").status,
        404
    );

    // Solve and submit as the SDK does (form navigation, `+` for spaces).
    let v = solved(&shown, CHROME);
    let r = submit_form(&env, ip, CHROME, &v);
    assert_eq!(r.status, 303, "{}\n{}", r.head, r.body);
    assert_eq!(r.header("location"), Some("/members/a?x=1"));
    let cookie = cookie_of(&r);
    wait_log(&edge, &["submit=solved type=invisible reasons=-"]);

    // The cookie passes require_clearance; the origin gets the session.
    let r = get(
        env.listen,
        "example.com",
        "/members/a?x=1",
        &format!("{}Cookie: {cookie}\r\n", browser(ip)),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let seen = env.origin.last("/members/a?x=1").unwrap();
    assert_eq!(seen.header("mg-session").map(str::len), Some(22));

    // Replaying the same submission: refused, a new pow C one band up.
    let r = submit_form(&env, ip, CHROME, &v);
    assert_eq!(r.status, 403, "{}", r.head);
    assert!(r.header("set-cookie").is_none());
    assert!(r.body.contains("data-mg-state=\"failed\""));
    let line = line_of(&edge, &r);
    assert!(
        line.contains(" submit=failed type=invisible reasons=ic.nonce_reused"),
        "{line}"
    );
    let new = from_page(&r.body);
    assert_eq!(new.ty, ChallengeType::Pow);
    let new_claims = open(&new.c, ChallengeType::Pow);
    assert_eq!(new_claims.risk_band, claims.risk_band.after_failure());
    assert_eq!(new.bits, bits_of(new_claims.risk_band));
    assert_eq!(new.ret, "/members/a?x=1");

    assert!(metric(&edge, "invisible", "issued") >= 2.0);
    assert!(
        metric(&edge, "pow", "issued") >= 1.0,
        "the new C of a failure"
    );
    assert_eq!(metric(&edge, "invisible", "solved"), 1.0);
    assert_eq!(metric(&edge, "invisible", "failed"), 1.0);
}

/// §10.2 JSON challenge and the fetch submission (200 JSON + cookie); the
/// media type may carry `charset=UTF-8` and other parameters.
#[test]
fn json_challenge_and_fetch_submission() {
    let env = TestEnv::new("chal-json");
    let edge = start(&env, &bundle());
    let ip = "198.51.100.21";
    let r = get(env.listen, "example.com", "/members/api", &fetcher(ip));
    assert_eq!(r.status, 403);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("mg-challenge"), Some("invisible"));
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["error"], "mg_challenge");
    assert_eq!(v["retry"], true);
    assert_eq!(v["ret"], "/members/api");
    assert_eq!(v["pow"]["alg"], "sha256-hashcash-v1");
    assert_eq!(v["request_id"].as_str().unwrap().len(), 32);
    let shown = from_json(&v);

    let r = submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body, json!({"ok": true, "ret": "/members/api"}));
    cookie_of(&r);

    // charset=UTF-8 (any case) and other parameters are accepted.
    let shown = json_challenge(&env, "/members/b", ip);
    let headers = format!(
        "{}User-Agent: {CHROME}\r\nContent-Type: application/x-www-form-urlencoded; Charset=\"UTF-8\"; x=y\r\n",
        cf(ip)
    );
    let r = post(
        &env,
        "example.com",
        "/__mg/c",
        &headers,
        &form_body(&solved(&shown, CHROME)),
    );
    assert_eq!(r.status, 303, "{}\n{}", r.head, r.body);
    // Another charset is ic.body.
    let headers = format!(
        "{}User-Agent: {CHROME}\r\nContent-Type: application/json; charset=iso-8859-1\r\n",
        cf(ip)
    );
    let shown = json_challenge(&env, "/members/d", ip);
    let r = post(
        &env,
        "example.com",
        "/__mg/c",
        &headers,
        solved(&shown, CHROME).to_string().as_bytes(),
    );
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.body"));

    // Other methods: 405 with Allow.
    let r = get(env.listen, "example.com", "/__mg/c", &fetcher(ip));
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("POST"));
    // Reserved spellings stay 404 and never reach the origin.
    for path in ["/__mg/c/renew", "/__mg//c", "/%5F%5Fmg/c"] {
        let r = post(&env, "example.com", path, &fetcher(ip), b"{}");
        assert_eq!(r.status, 404, "{path}");
    }
    assert!(env.origin.seen().iter().all(|s| !s.line.contains("__mg")));
}

/// §10.3 steps 1, 3-8: each failure, its answer and its reason.
#[test]
fn submission_failures() {
    let env = TestEnv::new("chal-fail");
    let edge = start(&env, &bundle());
    let ip = "198.51.100.22";

    // Tampered C: no new C.
    let shown = json_challenge(&env, "/gate/a", ip);
    assert_eq!(shown.ty, ChallengeType::Pow, "the rule asks for pow");
    let mut v = solved(&shown, CHROME);
    let c = shown.c.clone();
    let mid = c.len() / 2;
    let flipped = if &c[mid..=mid] == "A" { "B" } else { "A" };
    v["c"] = json!(format!("{}{flipped}{}", &c[..mid], &c[mid + 1..]));
    let r = submit_json(&env, ip, CHROME, "", &v);
    assert_eq!(r.status, 403);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body["error"], "mg_challenge_failed");
    assert!(body.get("challenge").is_none(), "{body}");
    assert!(line_of(&edge, &r).contains("reasons=ic.c_invalid"));

    // Another browser (User-Agent): a new pow C one band up.
    let shown = json_challenge(&env, "/gate/b", ip);
    let band = open(&shown.c, ChallengeType::Pow).risk_band;
    assert_eq!(shown.bits, bits_of(band));
    let r = submit_json(&env, ip, FIREFOX, "", &solved(&shown, FIREFOX));
    assert_eq!(r.status, 403);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    let new = from_json(&body);
    assert_eq!(new.ty, ChallengeType::Pow);
    let new_claims = open(&new.c, ChallengeType::Pow);
    assert_eq!(new_claims.risk_band, band.after_failure());
    assert_eq!(new.bits, bits_of(band.after_failure()));
    assert_eq!(new_claims.route_class, "gate");
    let line = line_of(&edge, &r);
    assert!(line.contains("reasons=ic.bind_uah"), "{line}");
    assert!(
        line.contains(&format!("reissued={}/{}", band.after_failure(), new.bits)),
        "{line}"
    );

    // A wrong counter (pow).
    let shown = json_challenge(&env, "/gate/c", ip);
    let mut v = solved(&shown, CHROME);
    let good = v["pow"]["counters"][0].as_u64().unwrap();
    let bad = (0..)
        .find(|n| *n != good && !mg_challenge::pow_verify(&shown.c, shown.bits, *n))
        .unwrap();
    v["pow"]["counters"] = json!([bad]);
    let r = submit_json(&env, ip, CHROME, "", &v);
    assert!(line_of(&edge, &r).contains("reasons=ic.pow"));

    // The C of example.com submitted on www.example.com (the aad covers it).
    let shown = json_challenge(&env, "/gate/d", ip);
    let headers = format!(
        "{}User-Agent: {CHROME}\r\nContent-Type: application/json\r\n",
        cf(ip)
    );
    let r = post(
        &env,
        "www.example.com",
        "/__mg/c",
        &headers,
        solved(&shown, CHROME).to_string().as_bytes(),
    );
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.c_invalid"));

    // webdriver / a navigator.userAgent that is not the header's prefix.
    let shown = json_challenge(&env, "/gate/e", ip);
    let mut v = solved(&shown, CHROME);
    v["auto"]["webdriver"] = json!(true);
    let r = submit_json(&env, ip, CHROME, "", &v);
    assert!(line_of(&edge, &r).contains("reasons=ic.automation_flag"));
    let shown = json_challenge(&env, "/gate/f", ip);
    let r = submit_json(
        &env,
        ip,
        CHROME,
        "",
        &solved(&shown, "Mozilla/5.0 (Windows NT 10.0)"),
    );
    assert!(line_of(&edge, &r).contains("reasons=ic.ua_mismatch"));

    // Early-Data: 425 before anything else.
    let shown = json_challenge(&env, "/gate/g", ip);
    let r = submit_json(
        &env,
        ip,
        CHROME,
        "Early-Data: 1\r\n",
        &solved(&shown, CHROME),
    );
    assert_eq!(r.status, 425);
    assert_eq!(r.body, "{\"error\":\"mg_too_early\"}");

    // Content-Encoding.
    let r = submit_json(
        &env,
        ip,
        CHROME,
        "Content-Encoding: gzip\r\n",
        &solved(&shown, CHROME),
    );
    assert_eq!(r.status, 403);
    assert!(line_of(&edge, &r).contains("reasons=ic.body"));

    // A repeated mg field.
    let mut body = form_body(&solved(&shown, CHROME));
    body.extend_from_slice(b"&mg=x");
    let headers = format!(
        "{}User-Agent: {CHROME}\r\nContent-Type: application/x-www-form-urlencoded\r\nSec-Fetch-Mode: navigate\r\n",
        cf(ip)
    );
    let r = post(&env, "example.com", "/__mg/c", &headers, &body);
    assert_eq!(r.status, 403);
    assert!(r.body.contains("data-mg-state=\"failed\""));
    assert!(line_of(&edge, &r).contains("reasons=ic.body"));

    // A body over 8 KiB is refused on its Content-Length, before it is read:
    // the answer comes at once and the connection is closed.
    let mut s = TcpStream::connect(env.listen).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "POST /__mg/c HTTP/1.1\r\nHost: example.com\r\n{}User-Agent: {CHROME}\r\n\
         Content-Type: application/json\r\nContent-Length: 1048576\r\n\r\n",
        cf(ip)
    );
    let started = Instant::now();
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(&[b' '; 1024]).unwrap();
    let r = common::read_response(&mut s).unwrap();
    assert_eq!(r.status, 403, "{}", r.head);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "answered without waiting for the body"
    );
    assert!(line_of(&edge, &r).contains("reasons=ic.body"));
    // A chunked body over 8 KiB: reading stops at 8193 bytes.
    let mut s = TcpStream::connect(env.listen).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "POST /__mg/c HTTP/1.1\r\nHost: example.com\r\n{}User-Agent: {CHROME}\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
        cf(ip)
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(format!("{:x}\r\n", 9000).as_bytes()).unwrap();
    s.write_all(&[b' '; 9000]).unwrap();
    s.write_all(b"\r\n").unwrap();
    // read_response reads until EOF: the Edge closed the connection (this
    // request did not ask for it) instead of draining the rest.
    let r = common::read_response(&mut s).unwrap();
    assert_eq!(r.status, 403, "{}", r.head);

    let m = edge.metrics_text();
    assert!(
        common::metric_or_zero(
            &m,
            "mg_challenge_total{provider=\"none\",result=\"failed\",type=\"pow\"}"
        ) >= 5.0,
        "{m}"
    );
}

/// §10.3 steps 1 and 3 read what the client sent. A `Connection` option
/// naming `Early-Data` or `Content-Encoding` makes the Edge remove the field
/// before forwarding, but the Edge is the recipient of that option and must
/// still see the field; and any `Early-Data` instance, whatever its value or
/// count, means early data (RFC 8470 §5.1). None of these gets a cookie.
#[test]
fn connection_options_do_not_hide_early_data_or_content_encoding() {
    let env = TestEnv::new("chal-hop");
    let edge = start(&env, &bundle());
    let ip = "198.51.100.31";
    for extra in [
        "Connection: early-data\r\nEarly-Data: 1\r\n",
        "Early-Data: 0\r\n",
        "Early-Data: 1\r\nEarly-Data: 1\r\n",
    ] {
        let shown = json_challenge(&env, "/members/e", ip);
        let r = submit_json(&env, ip, CHROME, extra, &solved(&shown, CHROME));
        assert_eq!(r.status, 425, "{extra:?}: {}\n{}", r.head, r.body);
        assert!(r.header("set-cookie").is_none(), "{extra:?}");
    }
    let shown = json_challenge(&env, "/members/f", ip);
    let r = submit_json(
        &env,
        ip,
        CHROME,
        "Connection: content-encoding\r\nContent-Encoding: gzip\r\n",
        &solved(&shown, CHROME),
    );
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.body"));
}

/// §9.8 / D-28: max_failures counted failures of one ip entity, and
/// 4 × max_failures of one /24, are 429 before the body is read.
#[test]
fn failure_quotas() {
    let env = TestEnv::new("chal-quota");
    let mut b = bundle();
    b.challenge.as_mut().unwrap().max_failures = 2;
    let edge = start(&env, &b);

    let bad = |ip: &str| submit_json(&env, ip, CHROME, "", &json!({"v": 2}));
    for _ in 0..2 {
        assert_eq!(bad("203.0.113.10").status, 403);
    }
    let r = bad("203.0.113.10");
    assert_eq!(r.status, 429, "{}", r.head);
    let retry: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=600).contains(&retry), "{retry}");
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["error"], "mg_rate_limited");
    assert!(line_of(&edge, &r).contains("reasons=ic.rate_limited"));
    // A correct submission of that client is refused as well.
    let shown = json_challenge(&env, "/members/q", "203.0.113.10");
    let r = submit_json(&env, "203.0.113.10", CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 429);
    assert!(r.header("set-cookie").is_none());

    // The prefix quota: 8 failures spread over the /24 (2 already counted).
    for i in 0..6 {
        let ip = format!("203.0.113.{}", 20 + i / 2);
        assert_eq!(bad(&ip).status, 403, "{ip}");
    }
    let r = bad("203.0.113.99");
    assert_eq!(r.status, 429);
    // Another /24 is not affected.
    assert_eq!(bad("198.51.100.99").status, 403);
    assert!(edge.metric("mg_ratelimit_exceeded_total{limiter=\"mg.c.fail\"}") >= 1.0);
    assert!(edge.metric("mg_ratelimit_exceeded_total{limiter=\"mg.c.fail.prefix\"}") >= 1.0);
}

/// D-37: when the issuance quota of the prefix is used up, a correct
/// submission is 429 without `Set-Cookie`.
#[test]
fn issuance_quota() {
    let env = TestEnv::new("chal-issue");
    let mut b = bundle();
    b.challenge.as_mut().unwrap().issue_per_ipp = 1;
    let edge = start(&env, &b);
    let ip = "198.51.100.23";
    let shown = json_challenge(&env, "/members/a", ip);
    assert_eq!(
        submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME)).status,
        200
    );
    let shown = json_challenge(&env, "/members/b", ip);
    let r = submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 429, "{}", r.head);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.issue_quota"));
}

/// D-23: without a client IP neither a CHALLENGE nor `/__mg/c` issues
/// anything: 429 + `Retry-After: 5`, no C, no cookie.
#[test]
fn unknown_client_ip() {
    let env = TestEnv::new("chal-noip");
    let edge = start(&env, &bundle());
    let headers = format!(
        "User-Agent: {CHROME}\r\nAccept: application/json\r\nCF-Visitor: {{\"scheme\":\"https\"}}\r\n"
    );
    let r = get(env.listen, "example.com", "/members/a", &headers);
    assert_eq!(r.status, 429);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(!r.body.contains("challenge"), "{}", r.body);

    // A C issued to a client with an IP, submitted without one.
    let shown = json_challenge(&env, "/members/a", "198.51.100.24");
    let headers = format!(
        "User-Agent: {CHROME}\r\nContent-Type: application/json\r\nCF-Visitor: {{\"scheme\":\"https\"}}\r\n"
    );
    let r = post(
        &env,
        "example.com",
        "/__mg/c",
        &headers,
        solved(&shown, CHROME).to_string().as_bytes(),
    );
    assert_eq!(r.status, 429);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(r.header("set-cookie").is_none());
    assert!(!r.body.contains("challenge"));
    assert!(line_of(&edge, &r).contains("reasons=ic.no_client_ip"));
}

/// §9.7 rules 3-5 without Valkey (`FaultProxy`): a C of a `fail_closed`
/// route is 429 without a cookie; another route is issued with
/// `ic.replay_unchecked`.
#[test]
fn valkey_down_replay_unavailable() {
    let Some(vk) = Valkey::start() else { return };
    let env = TestEnv::new("chal-valkey");
    env.write_lkg("blog", &sign(&bundle()));
    let cfg = with_valkey(&env.default_config(""), &vk.proxy_url(), 500);
    let edge = env.spawn(&env.write_config(&cfg));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 10, |v| v == 1.0);
    // A client address of this run only (a shared test server keeps buckets).
    let n = vk
        .tag
        .bytes()
        .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b)));
    let ip = format!("198.51.{}.{}", n % 200 + 20, (n / 200) % 250 + 1);

    let login = from_page(&get(env.listen, "example.com", "/account/login", &browser(&ip)).body);
    let members = json_challenge(&env, "/members/a", &ip);
    vk.set_mode(FaultMode::Refuse);

    let r = submit_form(&env, &ip, CHROME, &solved(&login, CHROME));
    assert_eq!(r.status, 429, "{}\n{}", r.head, r.body);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));

    let r = submit_json(&env, &ip, CHROME, "", &solved(&members, CHROME));
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let unchecked = cookie_of(&r);
    wait_log(&edge, &["submit=solved", "reasons=ic.replay_unchecked"]);
    assert!(token_claims(&unchecked).ruc, "I-30: issued unchecked");

    // I-30: that clearance is no clearance on the fail_closed login route.
    // The client is challenged again, and while Valkey is down the
    // submission of that challenge is 429 without a cookie.
    let with_unchecked = format!("{}Cookie: {unchecked}\r\n", browser(&ip));
    let r = get(env.listen, "example.com", "/account/login", &with_unchecked);
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    let again = from_page(&r.body);
    let r = submit_form(&env, &ip, CHROME, &solved(&again, CHROME));
    assert_eq!(r.status, 429, "{}\n{}", r.head, r.body);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));

    // Valkey is back: a new challenge of the login route is checked, and
    // its clearance (without `ruc`) passes there.
    vk.set_mode(FaultMode::Pass);
    let deadline = Instant::now() + Duration::from_secs(45);
    let checked = loop {
        let r = get(env.listen, "example.com", "/account/login", &with_unchecked);
        assert_eq!(r.status, 403, "still no clearance: {}", r.head);
        let r = submit_form(&env, &ip, CHROME, &solved(&from_page(&r.body), CHROME));
        if r.status == 303 {
            break cookie_of(&r);
        }
        assert_eq!(r.status, 429, "{}\n{}", r.head, r.body);
        assert!(Instant::now() < deadline, "Valkey never came back");
        std::thread::sleep(Duration::from_millis(250));
    };
    assert!(!token_claims(&checked).ruc);
    let r = get(
        env.listen,
        "example.com",
        "/account/login",
        &format!("{}Cookie: {checked}\r\n", browser(&ip)),
    );
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
}

/// The claims of a clearance cookie (`__Host-mg_clr=<token>`) the test site
/// issued, verified now.
fn token_claims(cookie: &str) -> mg_challenge::ClearanceClaims {
    let json = std::fs::read(common::repo("testdata/phase1/keys/token.keys.json")).unwrap();
    let keys = mg_challenge::TokenKeySet::from_key_file(&json, "blog", &["blog-t-20260927".into()])
        .unwrap();
    let token = cookie
        .strip_prefix("__Host-mg_clr=")
        .expect("clearance cookie");
    mg_challenge::verify(&keys, "blog", "production", token, now_ms() / 1000).unwrap()
}

/// Waits until the JSONL events file holds a decision event whose
/// `ctx.http.path` is `path`, and returns it.
fn decision_event(file: &std::path::Path, path: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if let Some(v) = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["kind"] == "decision" && v["ctx"]["http"]["path"] == path)
        {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "no decision event for {path}:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// I-30 without Valkey (local state that may not decide alone, so the
/// replay store is unavailable for every submission): the members
/// clearance is issued with `ic.replay_unchecked` and carries `ruc`. The
/// members route accepts it; the `fail_closed` login route does not: the
/// client is challenged again (`matrix.clearance.required`, the token
/// counted as `expired`) and that challenge's submission is 429 without a
/// cookie. Both decision events record `token.replay_unchecked`.
#[test]
fn replay_unchecked_clearance_is_refused_by_fail_closed_routes() {
    let env = TestEnv::new("chal-ruc");
    let mut b = bundle();
    b.events = Some(mg_proto::v1::EventConfig {
        allow_sample_rate: 1.0,
        access_log: false,
        stream: false,
    });
    env.write_lkg("blog", &sign(&b));
    let events = env.dir.join("events.jsonl");
    let cfg = common::with_events(
        &config(&env, ""),
        &format!("file = \"{}\"\nflush_interval_ms = 50\n", events.display()),
    );
    let edge = env.spawn(&env.write_config(&cfg));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    let ip = "198.51.100.32";

    let shown = json_challenge(&env, "/members/a", ip);
    let r = submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let cookie = cookie_of(&r);
    wait_log(&edge, &["submit=solved", "reasons=ic.replay_unchecked"]);
    let claims = token_claims(&cookie);
    assert!(claims.ruc);
    let with_cookie = format!("{}Cookie: {cookie}\r\n", browser(ip));

    // Accepted where the route is not fail_closed (require_clearance too).
    let r = get(env.listen, "example.com", "/members/b", &with_cookie);
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let seen = env.origin.last("/members/b").unwrap();
    assert_eq!(seen.header("mg-session"), Some(claims.sub.as_str()));

    // Refused by the fail_closed login route: challenged again.
    let r = get(env.listen, "example.com", "/account/login", &with_cookie);
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    assert!(env.origin.last("/account/login").is_none());
    let login = from_page(&r.body);
    assert_eq!(open(&login.c, login.ty).route_class, "login");
    // The replay store is still unavailable: 429 + Retry-After, no cookie.
    let r = submit_form(&env, ip, CHROME, &solved(&login, CHROME));
    assert_eq!(r.status, 429, "{}\n{}", r.head, r.body);
    assert_eq!(r.header("retry-after"), Some("5"));
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));
    // Every other path view and method that selects the login route
    // (D-25) refuses the token too.
    for (method, path) in [
        ("GET", "/account/login/"),
        ("GET", "/account/login;x"),
        ("GET", "/account/%6Cogin"),
        ("HEAD", "/account/login"),
        ("POST", "/account/login"),
    ] {
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\
             Content-Length: 0\r\n{with_cookie}\r\n"
        );
        let r = raw(env.listen, req.as_bytes()).unwrap();
        assert_eq!(r.status, 403, "{method} {path}: {}", r.head);
    }
    assert!(
        env.origin
            .seen()
            .iter()
            .all(|s| !s.line.contains("/account/")),
        "a login view reached the origin"
    );

    let members = decision_event(&events, "/members/b");
    assert_eq!(members["token"]["replay_unchecked"], true, "{members}");
    assert_eq!(members["ctx"]["identity"]["token"]["status"], "valid");
    let refused = decision_event(&events, "/account/login");
    assert_eq!(refused["token"]["replay_unchecked"], true, "{refused}");
    assert_eq!(refused["ctx"]["identity"]["token"]["status"], "expired");
    assert_eq!(refused["decision"]["action"], "challenge");
    assert_eq!(refused["decision"]["rule_id"], "matrix.clearance.required");
    // A request without the token records nothing of the kind.
    let r = get(env.listen, "example.com", "/plain", &browser(ip));
    assert_eq!(r.status, 200);
    let plain = decision_event(&events, "/plain");
    assert!(plain.get("token").is_none(), "{plain}");
}

/// §9.7 rule 5: the C's route was removed by a newer bundle, so it counts
/// as `fail_closed` when the replay store cannot decide (local mode, not
/// authoritative).
#[test]
fn removed_route_is_fail_closed() {
    let env = TestEnv::new("chal-removed");
    let edge = start_with(&env, &bundle(), "");
    let ip = "198.51.100.25";
    // Before: members is not fail_closed, so it is issued unchecked.
    let shown = json_challenge(&env, "/members/a", ip);
    let r = submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 200, "{}", r.body);
    wait_log(&edge, &["submit=solved", "reasons=ic.replay_unchecked"]);

    let shown = json_challenge(&env, "/members/b", ip);
    let mut b2 = bundle();
    b2.version = 2;
    b2.environments[0].routes.retain(|r| r.name != "members");
    env.publish("blog", &sign(&b2));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 15, |v| v == 2.0);
    let r = submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME));
    assert_eq!(r.status, 429, "{}\n{}", r.head, r.body);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));
}

/// D-35: a full local replay set cannot vouch for a nonce.
#[test]
fn full_local_replay_set() {
    let env = TestEnv::new("chal-full");
    let edge = start_with(
        &env,
        &bundle(),
        "local_replay_authoritative = true\nlocal_nonce_capacity = 1\n",
    );
    let ip = "198.51.100.26";
    let shown = json_challenge(&env, "/members/a", ip);
    assert_eq!(
        submit_json(&env, ip, CHROME, "", &solved(&shown, CHROME)).status,
        200
    );
    let login = from_page(&get(env.listen, "example.com", "/account/login", &browser(ip)).body);
    let r = submit_form(&env, ip, CHROME, &solved(&login, CHROME));
    assert_eq!(r.status, 429, "{}", r.head);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge, &r).contains("reasons=ic.replay_unavailable"));
}

/// D-32: an http visitor's GET is redirected to https instead of being
/// challenged; other methods are challenged.
#[test]
fn http_visitor_is_redirected() {
    let env = TestEnv::new("chal-http");
    let edge = start(&env, &bundle());
    let headers = browser("198.51.100.27").replace(
        "CF-Visitor: {\"scheme\":\"https\"}",
        "CF-Visitor: {\"scheme\":\"http\"}",
    );
    let r = get(env.listen, "example.com", "/members/a?x=1&y=%20", &headers);
    assert_eq!(r.status, 308, "{}", r.head);
    assert_eq!(
        r.header("location"),
        Some("https://example.com/members/a?x=1&y=%20")
    );
    assert!(r.header("set-cookie").is_none());
    assert_eq!(edge.metric("mg_https_redirect_total{site=\"blog\"}"), 1.0);
    let r = post(&env, "example.com", "/members/a", &headers, b"x=1");
    assert_eq!(r.status, 403);
    assert!(r.body.contains("data-mg-c=\""));
}

/// §10.1: without a bundle (bootstrap-open) `/__mg/c` is 404; the SDK is
/// still served.
#[test]
fn bootstrap_has_no_submissions() {
    let env = TestEnv::new("chal-boot");
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    edge.wait_metric(
        "mg_site_state{site=\"blog\",state=\"bootstrap_open\"}",
        10,
        |v| v == 1.0,
    );
    let r = submit_json(&env, "198.51.100.28", CHROME, "", &json!({"v": 1}));
    assert_eq!(r.status, 404, "{}", r.head);
    assert!(r.header("set-cookie").is_none());
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(common::fixture("sdk/manifest.json")).unwrap())
            .unwrap();
    let sdk = manifest["sdk"].as_str().unwrap();
    let r = get(env.listen, "example.com", &format!("/__mg/s/{sdk}"), "");
    assert_eq!(r.status, 200);
    assert!(env.origin.seen().is_empty());
}

/// §10.1: a site that cannot serve (here `bootstrap = "closed"` without a
/// bundle; `lkg_invalid` takes the same path) answers `/__mg/c` 503 with
/// `Retry-After: 30`, never a cookie.
#[test]
fn closed_sites_refuse_submissions() {
    let env = TestEnv::new("chal-closed");
    let edge = env.spawn(&env.write_config(&env.default_config("bootstrap = \"closed\"")));
    edge.wait_metric(
        "mg_site_state{site=\"blog\",state=\"bootstrap_closed\"}",
        10,
        |v| v == 1.0,
    );
    let r = submit_json(&env, "198.51.100.30", CHROME, "", &json!({"v": 1}));
    assert_eq!(r.status, 503, "{}", r.head);
    assert_eq!(r.header("retry-after"), Some("30"));
    assert!(r.header("set-cookie").is_none());
    assert!(env.origin.seen().is_empty());
}

/// §9.7: with Valkey the replay check spans Edges: a submission accepted by
/// one Edge is refused by another sharing the seal root and Valkey
/// (`mg_nonce_issue` finds the nonce), even on a `fail_closed` route.
#[test]
fn replay_is_refused_across_edges() {
    let Some(vk) = Valkey::start() else { return };
    let spawn = |tag: &str| {
        let env = TestEnv::new(tag);
        env.write_lkg("blog", &sign(&bundle()));
        let cfg = with_valkey(&env.default_config(""), &vk.proxy_url(), 500);
        let edge = env.spawn(&env.write_config(&cfg));
        edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
        edge.wait_metric("mg_state_mode{mode=\"valkey\"}", 10, |v| v == 1.0);
        (env, edge)
    };
    let (a, _edge_a) = spawn("chal-edge-a");
    let (b, edge_b) = spawn("chal-edge-b");
    let n = vk
        .tag
        .bytes()
        .fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b)));
    let ip = format!("203.0.{}.{}", n % 200 + 20, (n / 200) % 250 + 1);

    let login = from_page(&get(a.listen, "example.com", "/account/login", &browser(&ip)).body);
    let v = solved(&login, CHROME);
    let r = submit_form(&a, &ip, CHROME, &v);
    assert_eq!(r.status, 303, "{}\n{}", r.head, r.body);
    cookie_of(&r);
    let r = submit_form(&b, &ip, CHROME, &v);
    assert_eq!(r.status, 403, "{}\n{}", r.head, r.body);
    assert!(r.header("set-cookie").is_none());
    assert!(line_of(&edge_b, &r).contains("reasons=ic.nonce_reused"));
}

/// §18 acceptance: a client that does not run the SDK never obtains a
/// clearance under enforce. Posting the page's C back without a solution,
/// or a forged C, is refused without a cookie; the route stays challenged.
#[test]
fn clients_without_javascript_get_no_clearance() {
    let env = TestEnv::new("chal-nojs");
    let edge = start(&env, &bundle());
    let ip = "198.51.100.29";
    let page = get(env.listen, "example.com", "/members/a", &browser(ip));
    assert_eq!(page.status, 403);
    assert!(page.header("set-cookie").is_none());
    let shown = from_page(&page.body);
    let unsolved = (0..)
        .find(|n| !mg_challenge::pow_verify(&shown.c, shown.bits, *n))
        .unwrap();
    for c in [shown.c.as_str(), "AAAA", ""] {
        let v = json!({"v": 1, "type": shown.ty.as_str(), "c": c, "pow": {"counters": [unsolved]},
                       "ret": "/members/a", "ts": 0, "build": "0000000000000000"});
        let r = submit_form(&env, ip, CHROME, &v);
        assert_eq!(r.status, 403, "{c:?}: {}", r.head);
        assert!(r.header("set-cookie").is_none(), "{c:?}");
    }
    // Without a body at all.
    let r = post(&env, "example.com", "/__mg/c", &browser(ip), b"");
    assert_eq!(r.status, 403);
    assert!(r.header("set-cookie").is_none());
    let r = get(env.listen, "example.com", "/members/a", &browser(ip));
    assert_eq!(r.status, 403);
    assert!(env.origin.seen().is_empty(), "nothing reached the origin");
    assert_eq!(
        metric(&edge, "invisible", "solved") + metric(&edge, "pow", "solved"),
        0.0
    );
}
