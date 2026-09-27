//! §5.7: every detector's positive and negative case and its MISSING / ABSENT
//! / no-output branches.

use super::*;
use crate::context::{Crawler, TokenLevel};
use crate::extras::RateObservation;
use crate::testutil::Req;

/// Runs every Phase 1 detector; returns the signal of `id` (at most one exists).
fn sig(req: &Req, id: &str) -> Option<Signal> {
    req.with(|ctx, x| {
        let mut out = Vec::new();
        for d in phase1_detectors() {
            let before = out.len();
            d.detect(ctx, x, &mut out);
            assert!(
                out.len() - before <= 1,
                "{} emitted more than one signal",
                d.id()
            );
            for s in &out[before..] {
                assert_eq!(s.id, d.id(), "signal id is the detector id");
                assert!(d.families().contains(s.family));
            }
        }
        out.into_iter().find(|s| s.id == id)
    })
}

/// (state, value, confidence, source) of the signal.
fn shape(s: &Signal) -> (SignalState, f32, f32, SignalSource) {
    (s.state, s.value.get(), s.confidence.get(), s.source)
}

fn is_present(req: &Req, id: &str, value: f32, confidence: f32) {
    let s = sig(req, id).unwrap_or_else(|| panic!("{id}: no signal"));
    assert_eq!(s.state, SignalState::Present, "{id}");
    assert!(
        (s.value.get() - value).abs() < 1e-6,
        "{id}: value {} != {value}",
        s.value.get()
    );
    if value != 0.0 {
        assert!(
            (s.confidence.get() - confidence).abs() < 1e-6,
            "{id}: confidence"
        );
    }
}

fn is_zero(req: &Req, id: &str) {
    is_present(req, id, 0.0, 0.0);
}

fn is_state(req: &Req, id: &str, state: SignalState) {
    let s = sig(req, id).unwrap_or_else(|| panic!("{id}: no signal"));
    assert_eq!(s.state, state, "{id}");
    assert_eq!(s.value.get(), 0.0);
}

#[test]
fn table_order_ids_and_families() {
    let ids: Vec<_> = phase1_detectors().iter().map(|d| d.id()).collect();
    assert_eq!(
        ids,
        [
            "net.client_ip",
            "net.datacenter",
            "net.tor",
            "tls.proto_old",
            "edge_tls.proto_mismatch",
            "http.ua_missing",
            "http.ua_library",
            "http.accept_language_missing",
            "http.client_hints",
            "http.fetch_metadata_missing",
            "http.fetch_metadata_mismatch",
            "http.version_old",
            "rate.utilization",
            "rate.exceeded",
            "identity.clearance",
            "identity.bind_ipp_soft",
            "identity.crawler_failed",
            "external.cf_vbot",
        ]
    );
    for d in phase1_detectors() {
        let area = d.id().split('.').next().unwrap();
        let family = if area == "net" { "network" } else { area };
        let fam = d.families().iter().next().unwrap();
        assert_eq!(d.families().len(), 1);
        assert_eq!(fam.as_str(), family, "{}", d.id());
        assert!(Signal::is_valid_id(d.id()));
    }
}

/// A plain browser behind Cloudflare trips nothing.
#[test]
fn clean_browser_is_all_zero_or_neutral() {
    let req = Req::cloudflare_browser();
    req.with(|ctx, x| {
        let mut out = Vec::new();
        for d in phase1_detectors() {
            d.detect(ctx, x, &mut out);
        }
        for s in &out {
            assert_eq!(s.value.get(), 0.0, "{}", s.id);
        }
        // Not emitted without a valid token / crawler claim.
        assert!(
            !out.iter()
                .any(|s| s.id == "identity.bind_ipp_soft" || s.id == "identity.crawler_failed")
        );
    });
}

#[test]
fn net_client_ip() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "net.client_ip");
    req.ctx.net.ip = None;
    is_state(&req, "net.client_ip", SignalState::Missing);
    let mut req = Req::cloudflare_browser();
    req.missing.insert("net.ip").unwrap();
    is_state(&req, "net.client_ip", SignalState::Missing);
}

#[test]
fn net_datacenter_and_tor() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "net.datacenter");
    is_zero(&req, "net.tor");
    req.ctx.net.conn_type = crate::context::ConnType::Datacenter;
    req.ctx.net.tor = true;
    is_present(&req, "net.datacenter", 0.6, 0.8);
    is_present(&req, "net.tor", 0.5, 0.9);
    // No datacenter-asns artifact / no tor source: MISSING, never "not a datacenter".
    req.missing.insert("net.conn_type").unwrap();
    req.missing.insert("net.tor").unwrap();
    is_state(&req, "net.datacenter", SignalState::Missing);
    is_state(&req, "net.tor", SignalState::Missing);
    // net as a whole missing covers both.
    let mut req = Req::cloudflare_browser();
    req.missing.insert("net").unwrap();
    is_state(&req, "net.datacenter", SignalState::Missing);
}

#[test]
fn tls_proto_old() {
    // Behind Cloudflare the visitor's TLS is never visible.
    is_state(
        &Req::cloudflare_browser(),
        "tls.proto_old",
        SignalState::Missing,
    );
    let mut req = Req::direct_browser();
    is_zero(&req, "tls.proto_old");
    req.ctx.tls.version = Some("TLSv1.1".into());
    is_present(&req, "tls.proto_old", 0.5, 0.8);
    req.ctx.tls.version = Some("TLSv1".into());
    is_present(&req, "tls.proto_old", 0.5, 0.8);
    // Old browsers and non-browsers are not mismatches.
    req.ua("Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 Chrome/69.0.3497.100 Safari/537.36");
    is_zero(&req, "tls.proto_old");
    req.ua("curl/8.5.0");
    is_zero(&req, "tls.proto_old");
    req.ua("Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0");
    is_present(&req, "tls.proto_old", 0.5, 0.8);
    req.ua("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15");
    is_zero(&req, "tls.proto_old");
    req.ctx.tls.version = None;
    is_state(&req, "tls.proto_old", SignalState::Missing);
}

#[test]
fn edge_tls_proto_mismatch() {
    is_state(
        &Req::direct_browser(),
        "edge_tls.proto_mismatch",
        SignalState::Missing,
    );
    let mut req = Req::cloudflare_browser();
    let s = sig(&req, "edge_tls.proto_mismatch").unwrap();
    assert_eq!(
        shape(&s),
        (SignalState::Present, 0.0, 1.0, SignalSource::Cloudflare)
    );
    req.ctx.edge_tls.as_mut().unwrap().version = Some("TLSv1.1".into());
    is_present(&req, "edge_tls.proto_mismatch", 0.4, 0.6);
    req.ctx.edge_tls.as_mut().unwrap().version = Some("SSLv3".into());
    is_present(&req, "edge_tls.proto_mismatch", 0.4, 0.6);
    req.ctx.edge_tls.as_mut().unwrap().version = Some("TLSv1.2".into());
    is_zero(&req, "edge_tls.proto_mismatch");
    // Header did not arrive.
    req.ctx.edge_tls = None;
    is_state(&req, "edge_tls.proto_mismatch", SignalState::Missing);
    let mut req = Req::cloudflare_browser();
    req.missing.insert("edge_tls.version").unwrap();
    is_state(&req, "edge_tls.proto_mismatch", SignalState::Missing);
}

#[test]
fn http_ua_missing_and_library() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "http.ua_missing");
    is_zero(&req, "http.ua_library");
    req.ua("");
    is_present(&req, "http.ua_missing", 0.8, 1.0);
    is_zero(&req, "http.ua_library");
    req.ctx.http.user_agent = Some("   ".into());
    is_present(&req, "http.ua_missing", 0.8, 1.0);
    req.ua("python-requests/2.31.0");
    is_zero(&req, "http.ua_missing");
    is_present(&req, "http.ua_library", 1.0, 1.0);
}

#[test]
fn http_accept_language_missing() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "http.accept_language_missing");
    req.without("accept-language");
    is_present(&req, "http.accept_language_missing", 0.5, 0.8);
    req.header("accept-language", " ");
    is_present(&req, "http.accept_language_missing", 0.5, 0.8);
    req.without("accept-language");
    // Not a navigation: neither sec-fetch-mode navigate nor GET + text/html.
    req.header("sec-fetch-mode", "cors")
        .header("accept", "application/json");
    is_zero(&req, "http.accept_language_missing");
    // GET + text/html counts as navigation even without Fetch Metadata.
    req.without("sec-fetch-mode").header("accept", "TEXT/HTML");
    is_present(&req, "http.accept_language_missing", 0.5, 0.8);
    req.ctx.http.method = "POST".into();
    is_zero(&req, "http.accept_language_missing");
    req.header("sec-fetch-mode", "navigate");
    is_present(&req, "http.accept_language_missing", 0.5, 0.8);
    // Only for UAs that claim to be a browser.
    req.ua("curl/8.5.0");
    is_zero(&req, "http.accept_language_missing");
}

#[test]
fn http_client_hints() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "http.client_hints");
    req.without("sec-ch-ua");
    is_present(&req, "http.client_hints", 0.5, 0.7);
    // Chromium sends client hints only in secure contexts.
    req.secure = false;
    is_zero(&req, "http.client_hints");
    req.secure = true;
    req.header("sec-ch-ua", r#""Not-A.Brand";v="99", "Chromium";v="120""#);
    is_present(&req, "http.client_hints", 0.7, 0.8);
    req.header(
        "sec-ch-ua",
        r#""Google Chrome";v="123", "Chromium";v="124""#,
    );
    is_present(&req, "http.client_hints", 0.7, 0.8);
    req.header("sec-ch-ua", r#""Not-A.Brand";v="99""#);
    is_zero(&req, "http.client_hints");
    // Opera: OPR/109 is Chromium 123; the brands carry the Chromium version.
    req.ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0");
    req.header("sec-ch-ua", r#""Chromium";v="123", "Opera";v="109""#);
    is_zero(&req, "http.client_hints");
    // Edge on iOS is WebKit: no client hints expected.
    req.ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/124.2478.50 Mobile/15E148 Safari/605.1.15");
    req.without("sec-ch-ua");
    is_zero(&req, "http.client_hints");
    // Old Chromium and Firefox are out of scope.
    req.ua("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0 Safari/537.36");
    is_zero(&req, "http.client_hints");
    req.ua("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0");
    is_zero(&req, "http.client_hints");
}

#[test]
fn brand_major_parsing() {
    let v = r#""Chromium";v="124", "Google Chrome";v="124.0.6367.60", "Not-A.Brand";v="99""#;
    assert_eq!(brand_major(v, "Chromium"), Some(124));
    assert_eq!(brand_major(v, "Google Chrome"), Some(124));
    assert_eq!(brand_major(v, "Microsoft Edge"), None);
    assert_eq!(brand_major("garbage", "Chromium"), None);
    assert_eq!(brand_major(r#""Chromium";v="""#, "Chromium"), None);
    assert_eq!(brand_major(r#""Chromium";q=1"#, "Chromium"), None);
}

#[test]
fn http_fetch_metadata() {
    let mut req = Req::cloudflare_browser();
    is_zero(&req, "http.fetch_metadata_missing");
    is_zero(&req, "http.fetch_metadata_mismatch");
    req.without("sec-fetch-mode");
    is_present(&req, "http.fetch_metadata_missing", 0.5, 0.7);
    // http visitors never get Fetch Metadata: not evidence.
    req.secure = false;
    is_zero(&req, "http.fetch_metadata_missing");
    req.secure = true;
    req.ua("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/79.0 Safari/537.36");
    is_zero(&req, "http.fetch_metadata_missing");
    req.ua("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15");
    is_present(&req, "http.fetch_metadata_missing", 0.5, 0.7);
    req.ua("Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0");
    is_zero(&req, "http.fetch_metadata_missing");

    let mut req = Req::cloudflare_browser();
    req.route.channel = Channel::Api;
    is_present(&req, "http.fetch_metadata_mismatch", 0.4, 0.6);
    req.header("sec-fetch-mode", "cors");
    is_zero(&req, "http.fetch_metadata_mismatch");
}

#[test]
fn http_version_old() {
    let mut req = Req::cloudflare_browser();
    let s = sig(&req, "http.version_old").unwrap();
    assert_eq!(
        shape(&s),
        (SignalState::Present, 0.0, 1.0, SignalSource::Cloudflare)
    );
    req.ctx.http.version = Some("HTTP/1.0".into());
    let s = sig(&req, "http.version_old").unwrap();
    assert_eq!(
        shape(&s),
        (SignalState::Present, 0.6, 0.8, SignalSource::Cloudflare)
    );
    req.ua("curl/8.5.0");
    is_zero(&req, "http.version_old");
    req.ctx.http.version = None;
    is_state(&req, "http.version_old", SignalState::Missing);
    let mut req = Req::direct_browser();
    req.ctx.http.version = Some("HTTP/1.0".into());
    let s = sig(&req, "http.version_old").unwrap();
    assert_eq!(s.source, SignalSource::SelfComputed);
    req.missing.insert("http.version").unwrap();
    is_state(&req, "http.version_old", SignalState::Missing);
}

fn obs(
    id: &str,
    utilization: f32,
    exceeded: bool,
    action: LimiterAction,
    dry_run: bool,
) -> RateObservation {
    RateObservation {
        limiter_id: id.into(),
        utilization,
        exceeded,
        retry_after_ms: 0,
        action,
        dry_run,
    }
}

#[test]
fn rate_utilization() {
    let mut req = Req::cloudflare_browser();
    is_state(&req, "rate.utilization", SignalState::Missing);
    let rl = LimiterAction::RateLimit { retry_after_s: 0 };
    req.rate = vec![
        obs("a", 0.5, false, rl, false),
        obs("b", 0.7, false, rl, false),
    ];
    is_zero(&req, "rate.utilization");
    req.rate[1].utilization = 0.85;
    is_present(&req, "rate.utilization", 0.4, 1.0);
    req.rate[1].utilization = 1.0;
    is_present(&req, "rate.utilization", 0.8, 1.0);
    req.rate[1].utilization = f32::NAN;
    is_zero(&req, "rate.utilization");
}

#[test]
fn rate_exceeded() {
    let mut req = Req::cloudflare_browser();
    is_state(&req, "rate.exceeded", SignalState::Missing);
    // Only signal limiters feed this detector.
    req.rate = vec![obs("rl", 1.0, true, LimiterAction::Block, false)];
    is_state(&req, "rate.exceeded", SignalState::Missing);
    req.rate.push(obs(
        "sig-a",
        0.3,
        false,
        LimiterAction::Signal { weight: 0.5 },
        false,
    ));
    is_zero(&req, "rate.exceeded");
    req.rate[1].exceeded = true;
    let s = sig(&req, "rate.exceeded").unwrap();
    assert_eq!(
        shape(&s),
        (SignalState::Present, 0.25, 1.0, SignalSource::SelfComputed)
    );
    assert_eq!(s.reason_code, "rl.sig-a");
    req.rate.push(obs(
        "sig-b",
        1.0,
        true,
        LimiterAction::Signal { weight: 2.0 },
        false,
    ));
    is_present(&req, "rate.exceeded", 1.0, 1.0);
    assert_eq!(sig(&req, "rate.exceeded").unwrap().reason_code, "rl.sig-a");
    // Dry-run signal limiters never score.
    req.rate[1].dry_run = true;
    req.rate[2].dry_run = true;
    is_zero(&req, "rate.exceeded");
}

#[test]
fn identity_clearance() {
    let mut req = Req::cloudflare_browser();
    is_state(&req, "identity.clearance", SignalState::Absent);
    let t = &mut req.ctx.identity.token;
    t.status = TokenStatus::Expired;
    is_state(&req, "identity.clearance", SignalState::Absent);
    for (status, v, c) in [
        (TokenStatus::Valid, -0.4, 1.0),
        (TokenStatus::Invalid, 0.5, 0.6),
        (TokenStatus::Replay, 0.5, 0.6),
        (TokenStatus::BindingMismatch, 0.3, 0.8),
    ] {
        req.ctx.identity.token.status = status;
        is_present(&req, "identity.clearance", v, c);
    }
    // Both Phase 1 levels are the same evidence.
    req.ctx.identity.token.status = TokenStatus::Valid;
    for level in [TokenLevel::Invisible, TokenLevel::Pow] {
        req.ctx.identity.token.level = Some(level);
        is_present(&req, "identity.clearance", -0.4, 1.0);
    }
}

#[test]
fn identity_bind_ipp_soft() {
    let mut req = Req::cloudflare_browser();
    assert!(
        sig(&req, "identity.bind_ipp_soft").is_none(),
        "no valid token: no output"
    );
    req.ctx.identity.token.status = TokenStatus::BindingMismatch;
    req.ctx.identity.token.bind.ipp = Some(BindResult::SoftMismatch);
    assert!(sig(&req, "identity.bind_ipp_soft").is_none());
    req.ctx.identity.token.status = TokenStatus::Valid;
    is_present(&req, "identity.bind_ipp_soft", 0.4, 0.6);
    req.ctx.identity.token.bind.ipp = Some(BindResult::Match);
    is_zero(&req, "identity.bind_ipp_soft");
}

#[test]
fn identity_crawler_failed() {
    let mut req = Req::cloudflare_browser();
    assert!(
        sig(&req, "identity.crawler_failed").is_none(),
        "no claim: no output"
    );
    req.ctx.identity.crawler = Crawler {
        claimed: true,
        operator: Some("google".into()),
        verification: Some(CrawlerVerification::Failed),
        ..Crawler::default()
    };
    is_present(&req, "identity.crawler_failed", 1.0, 1.0);
    req.ctx.identity.crawler.verification = Some(CrawlerVerification::Pending);
    is_zero(&req, "identity.crawler_failed");
    req.ctx.identity.crawler.outside_ranges = true;
    is_present(&req, "identity.crawler_failed", 0.5, 0.6);
    req.ctx.identity.crawler.verification = Some(CrawlerVerification::Verified);
    req.ctx.identity.crawler.verified = true;
    is_zero(&req, "identity.crawler_failed");
    req.ctx.identity.crawler.verification = Some(CrawlerVerification::Unverifiable);
    req.ctx.identity.crawler.verified = false;
    is_zero(&req, "identity.crawler_failed");
}

#[test]
fn external_cf_vbot() {
    is_state(
        &Req::direct_browser(),
        "external.cf_vbot",
        SignalState::Missing,
    );
    let mut req = Req::cloudflare_browser();
    let s = sig(&req, "external.cf_vbot").unwrap();
    assert_eq!(
        shape(&s),
        (SignalState::Present, 0.0, 1.0, SignalSource::Cloudflare)
    );
    // vbot false + a crawler claim: impersonation corroboration.
    req.ctx.identity.crawler.claimed = true;
    is_present(&req, "external.cf_vbot", 0.3, 0.8);
    // vbot true without our own verification.
    req.ctx.identity.crawler.cf_vbot = Some(true);
    is_present(&req, "external.cf_vbot", 0.3, 0.8);
    req.ctx.identity.crawler.claimed = false;
    is_present(&req, "external.cf_vbot", 0.3, 0.8);
    // vbot true and verified by MorphGate: 0.
    req.ctx.identity.crawler.claimed = true;
    req.ctx.identity.crawler.verified = true;
    req.ctx.identity.crawler.verification = Some(CrawlerVerification::Verified);
    is_zero(&req, "external.cf_vbot");
    // Header did not arrive.
    req.ctx.identity.crawler.cf_vbot = None;
    is_state(&req, "external.cf_vbot", SignalState::Missing);
}

#[test]
fn missing_expectation_table() {
    use UpstreamProfileKind as P;
    assert!(missing_is_expected("net.client_ip", P::Cloudflare));
    assert!(missing_is_expected("external.cf_vbot", P::Cloudflare));
    assert!(!missing_is_expected("external.cf_vbot", P::DirectTls));
    assert!(missing_is_expected("tls.proto_old", P::DirectTls));
    assert!(!missing_is_expected("tls.proto_old", P::Cloudflare));
    assert!(!missing_is_expected("rate.utilization", P::Cloudflare));
    assert!(!missing_is_expected("net.datacenter", P::Cloudflare));
}

/// Spec §2.4-style robustness: arbitrary header values never panic a detector.
#[test]
fn random_headers_do_not_panic() {
    let pieces = [
        "\"Chromium\";v=\"",
        "124",
        "\"",
        ";",
        ",",
        "v=",
        "é",
        " ",
        "navigate",
        "text/html",
        "\u{0}",
    ];
    let mut state: u64 = 0x0bad_c0de_1234_5678;
    for _ in 0..10_000 {
        let mut v = String::new();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for i in 0..(state % 10) {
            v.push_str(pieces[((state >> (i * 5)) % pieces.len() as u64) as usize]);
        }
        let mut req = Req::cloudflare_browser();
        req.header("sec-ch-ua", &v)
            .header("sec-fetch-mode", &v)
            .header("accept", &v);
        let _ = sig(&req, "http.client_hints");
    }
}
