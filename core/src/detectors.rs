//! Phase 1 detectors (docs/impl/phase1-spec.md §5.7 table, in table order).
//!
//! Each detector emits **at most one** signal per request: `PRESENT` (value 0
//! means "had the input, nothing odd", which still counts toward coverage),
//! `ABSENT`, or `MISSING`; "no output" rows produce nothing and do not touch
//! coverage. A detector whose profile column does not include the request's
//! upstream profile emits `MISSING`. Inputs forwarded by Cloudflare carry
//! `source = cloudflare` (the scorer's λ = 0.8); everything the Edge derives
//! itself carries `source = self`.

use crate::context::{BindResult, CrawlerVerification, RequestContext, TokenStatus};
use crate::enums::{Channel, SignalFamily, SignalSource, SignalState, UpstreamProfileKind};
use crate::extras::{LimiterAction, RequestExtras};
use crate::mask::FamilyMask;
use crate::pipeline::{Detector, only};
use crate::signal::Signal;
use crate::ua::{UaInfo, major_after};
use std::borrow::Cow;

type DetectFn = fn(&RequestContext, &RequestExtras<'_>) -> Option<Signal>;

/// A detector defined by one function of the §5.7 table.
struct TableDetector {
    id: &'static str,
    family: SignalFamily,
    run: DetectFn,
}

impl Detector for TableDetector {
    fn id(&self) -> &'static str {
        self.id
    }

    fn families(&self) -> FamilyMask {
        only(self.family)
    }

    fn detect(&self, ctx: &RequestContext, extras: &RequestExtras<'_>, out: &mut Vec<Signal>) {
        out.extend((self.run)(ctx, extras));
    }
}

/// The §5.7 detectors, in table order.
pub fn phase1_detectors() -> Vec<Box<dyn Detector>> {
    use SignalFamily as F;
    let table: [(&'static str, SignalFamily, DetectFn); 18] = [
        ("net.client_ip", F::Network, net_client_ip),
        ("net.datacenter", F::Network, net_datacenter),
        ("net.tor", F::Network, net_tor),
        ("tls.proto_old", F::Tls, tls_proto_old),
        (
            "edge_tls.proto_mismatch",
            F::EdgeTls,
            edge_tls_proto_mismatch,
        ),
        ("http.ua_missing", F::Http, http_ua_missing),
        ("http.ua_library", F::Http, http_ua_library),
        (
            "http.accept_language_missing",
            F::Http,
            http_accept_language_missing,
        ),
        ("http.client_hints", F::Http, http_client_hints),
        (
            "http.fetch_metadata_missing",
            F::Http,
            http_fetch_metadata_missing,
        ),
        (
            "http.fetch_metadata_mismatch",
            F::Http,
            http_fetch_metadata_mismatch,
        ),
        ("http.version_old", F::Http, http_version_old),
        ("rate.utilization", F::Rate, rate_utilization),
        ("rate.exceeded", F::Rate, rate_exceeded),
        ("identity.clearance", F::Identity, identity_clearance),
        (
            "identity.bind_ipp_soft",
            F::Identity,
            identity_bind_ipp_soft,
        ),
        (
            "identity.crawler_failed",
            F::Identity,
            identity_crawler_failed,
        ),
        ("external.cf_vbot", F::External, external_cf_vbot),
    ];
    table
        .into_iter()
        .map(|(id, family, run)| Box::new(TableDetector { id, family, run }) as Box<dyn Detector>)
        .collect()
}

/// Default signal weight `w_s` (§5.7 last column).
pub(crate) fn default_weight(id: &str) -> f32 {
    match id {
        "http.ua_missing" => 1.5,
        "http.ua_library" | "rate.exceeded" | "identity.crawler_failed" => 2.0,
        _ => 1.0,
    }
}

/// Whether a `MISSING` signal of detector `id` under `profile` means an
/// expected input did not arrive (an upstream header, the client IP), as
/// opposed to an input the profile never supplies, an optional artifact that
/// is not configured, or a route without limiters. Only the former is
/// recorded in decision events.
pub(crate) fn missing_is_expected(id: &str, profile: UpstreamProfileKind) -> bool {
    match id {
        "net.client_ip" | "http.version_old" => true,
        "tls.proto_old" => profile == UpstreamProfileKind::DirectTls,
        "edge_tls.proto_mismatch" | "external.cf_vbot" => {
            profile == UpstreamProfileKind::Cloudflare
        }
        _ => false,
    }
}

// --- signal constructors -------------------------------------------------------

fn present(
    id: &'static str,
    family: SignalFamily,
    value: f32,
    confidence: f32,
    source: SignalSource,
) -> Option<Signal> {
    Some(Signal::new(id, family, value, confidence).with_source(source))
}

/// PRESENT with value `v` / confidence `c` when `hit`, else PRESENT 0.
fn flag(
    id: &'static str,
    family: SignalFamily,
    hit: bool,
    v: f32,
    c: f32,
    source: SignalSource,
) -> Option<Signal> {
    if hit {
        present(id, family, v, c, source)
    } else {
        present(id, family, 0.0, 1.0, source)
    }
}

fn missing(id: &'static str, family: SignalFamily) -> Option<Signal> {
    Some(Signal::without_input(id, family, SignalState::Missing))
}

fn absent(id: &'static str, family: SignalFamily) -> Option<Signal> {
    Some(Signal::without_input(id, family, SignalState::Absent))
}

const SELF: SignalSource = SignalSource::SelfComputed;
const CF: SignalSource = SignalSource::Cloudflare;

fn is_cloudflare(ctx: &RequestContext) -> bool {
    ctx.upstream.profile == UpstreamProfileKind::Cloudflare
}

/// UA claims a modern browser for the TLS checks: `claims_browser` and
/// Chrome / Edge >= 70, Firefox >= 63 or Safari >= 13.
fn modern_for_tls(ua: &UaInfo) -> bool {
    ua.claims_browser
        && match ua.family {
            "chrome" | "edge" => ua.major >= 70,
            "firefox" => ua.major >= 63,
            "safari" => ua.major >= 13,
            _ => false,
        }
}

/// Protocol versions older than TLS 1.2.
fn tls_is_old(version: &str) -> bool {
    matches!(version, "SSLv2" | "SSLv3" | "TLSv1" | "TLSv1.0" | "TLSv1.1")
}

// --- NETWORK -----------------------------------------------------------------

fn net_client_ip(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "net.client_ip";
    if ctx.net.ip.is_none() || x.missing.is_missing("net.ip") {
        return missing(ID, SignalFamily::Network);
    }
    present(ID, SignalFamily::Network, 0.0, 1.0, SELF)
}

fn net_datacenter(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "net.datacenter";
    if x.missing.is_missing("net.conn_type") {
        return missing(ID, SignalFamily::Network);
    }
    let dc = ctx.net.conn_type == crate::context::ConnType::Datacenter;
    flag(ID, SignalFamily::Network, dc, 0.6, 0.8, SELF)
}

fn net_tor(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "net.tor";
    if x.missing.is_missing("net.tor") {
        return missing(ID, SignalFamily::Network);
    }
    flag(ID, SignalFamily::Network, ctx.net.tor, 0.5, 0.9, SELF)
}

// --- TLS / EDGE_TLS ------------------------------------------------------------

fn tls_proto_old(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "tls.proto_old";
    if ctx.upstream.profile != UpstreamProfileKind::DirectTls || x.missing.is_missing("tls.version")
    {
        return missing(ID, SignalFamily::Tls);
    }
    let Some(version) = ctx.tls.version.as_deref() else {
        return missing(ID, SignalFamily::Tls);
    };
    flag(
        ID,
        SignalFamily::Tls,
        modern_for_tls(x.ua) && tls_is_old(version),
        0.5,
        0.8,
        SELF,
    )
}

fn edge_tls_proto_mismatch(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "edge_tls.proto_mismatch";
    if !is_cloudflare(ctx) || x.missing.is_missing("edge_tls.version") {
        return missing(ID, SignalFamily::EdgeTls);
    }
    let Some(version) = ctx.edge_tls.as_ref().and_then(|e| e.version.as_deref()) else {
        return missing(ID, SignalFamily::EdgeTls);
    };
    let old = matches!(version, "SSLv3" | "TLSv1" | "TLSv1.1");
    flag(
        ID,
        SignalFamily::EdgeTls,
        modern_for_tls(x.ua) && old,
        0.4,
        0.6,
        CF,
    )
}

// --- HTTP ----------------------------------------------------------------------

fn http_ua_missing(ctx: &RequestContext, _: &RequestExtras<'_>) -> Option<Signal> {
    let empty = ctx
        .http
        .user_agent
        .as_deref()
        .is_none_or(|ua| ua.trim().is_empty());
    flag("http.ua_missing", SignalFamily::Http, empty, 0.8, 1.0, SELF)
}

fn http_ua_library(_: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    flag(
        "http.ua_library",
        SignalFamily::Http,
        x.ua.library,
        1.0,
        1.0,
        SELF,
    )
}

fn header_is(x: &RequestExtras<'_>, name: &str, value: &str) -> bool {
    x.header(name)
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(value))
}

fn header_present(x: &RequestExtras<'_>, name: &str) -> bool {
    x.header(name).is_some_and(|v| !v.trim().is_empty())
}

fn http_accept_language_missing(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    let navigation = header_is(x, "sec-fetch-mode", "navigate")
        || (ctx.http.method == "GET"
            && x.header("accept")
                .is_some_and(|a| a.to_ascii_lowercase().contains("text/html")));
    let hit = navigation && x.ua.claims_browser && !header_present(x, "accept-language");
    flag(
        "http.accept_language_missing",
        SignalFamily::Http,
        hit,
        0.5,
        0.8,
        SELF,
    )
}

/// The major version of `brand` in a `Sec-CH-UA` value such as
/// `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`.
fn brand_major(sec_ch_ua: &str, brand: &str) -> Option<u32> {
    sec_ch_ua.split(',').find_map(|item| {
        let (name, params) = item.trim().split_once(';')?;
        if name.trim().trim_matches('"') != brand {
            return None;
        }
        let v = params.trim().strip_prefix("v=")?.trim().trim_matches('"');
        let digits: &str = &v[..v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len())];
        digits.parse().ok()
    })
}

fn is_ios(ua: &str) -> bool {
    ["iPhone", "iPad", "iPod", "EdgiOS/", "CriOS/", "FxiOS/"]
        .iter()
        .any(|m| ua.contains(m))
}

fn http_client_hints(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "http.client_hints";
    let ua = ctx.http.user_agent.as_deref().unwrap_or("");
    let chromium = matches!(x.ua.family, "chrome" | "edge" | "opera") && !is_ios(ua);
    if !(chromium && x.ua.major >= 90 && x.secure_context) {
        return present(ID, SignalFamily::Http, 0.0, 1.0, SELF);
    }
    let Some(ch) = x.header("sec-ch-ua").filter(|v| !v.trim().is_empty()) else {
        return present(ID, SignalFamily::Http, 0.5, 0.7, SELF);
    };
    // Compare with the Chromium version in the UA (`Chrome/`), which is what
    // the brands carry; for Opera the family major (`OPR/`) differs by design.
    let ua_major = major_after(ua, "Chrome/").unwrap_or(x.ua.major);
    let mismatch = ["Chromium", "Google Chrome"]
        .iter()
        .filter_map(|b| brand_major(ch, b))
        .any(|m| m != ua_major);
    flag(ID, SignalFamily::Http, mismatch, 0.7, 0.8, SELF)
}

fn http_fetch_metadata_missing(_: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    let modern = x.ua.claims_browser
        && match x.ua.family {
            "chrome" | "edge" => x.ua.major >= 80,
            "firefox" => x.ua.major >= 90,
            "safari" => x.ua.major >= 17,
            _ => false,
        };
    // Browsers send Fetch Metadata to potentially trustworthy (https) origins
    // only, so an http visitor never has it.
    let hit = modern && x.secure_context && !header_present(x, "sec-fetch-mode");
    flag(
        "http.fetch_metadata_missing",
        SignalFamily::Http,
        hit,
        0.5,
        0.7,
        SELF,
    )
}

fn http_fetch_metadata_mismatch(_: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    let hit = x.route.channel == Channel::Api && header_is(x, "sec-fetch-mode", "navigate");
    flag(
        "http.fetch_metadata_mismatch",
        SignalFamily::Http,
        hit,
        0.4,
        0.6,
        SELF,
    )
}

fn http_version_old(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "http.version_old";
    if x.missing.is_missing("http.version") {
        return missing(ID, SignalFamily::Http);
    }
    let Some(version) = ctx.http.version.as_deref() else {
        return missing(ID, SignalFamily::Http);
    };
    let source = if is_cloudflare(ctx) { CF } else { SELF };
    flag(
        ID,
        SignalFamily::Http,
        x.ua.claims_browser && version == "HTTP/1.0",
        0.6,
        0.8,
        source,
    )
}

// --- RATE ----------------------------------------------------------------------

fn rate_utilization(_: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "rate.utilization";
    if x.rate.is_empty() {
        // The route has no limiter: the input does not exist here.
        return missing(ID, SignalFamily::Rate);
    }
    let u = x
        .rate
        .iter()
        .map(|o| {
            if o.utilization.is_nan() {
                0.0
            } else {
                o.utilization.clamp(0.0, 1.0)
            }
        })
        .fold(0.0f32, f32::max);
    let v = ((u - 0.7) / 0.3).clamp(0.0, 1.0) * 0.8;
    present(ID, SignalFamily::Rate, v, 1.0, SELF)
}

fn rate_exceeded(_: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "rate.exceeded";
    let signal_limiters = || {
        x.rate.iter().filter_map(|o| match o.action {
            LimiterAction::Signal { weight } => Some((o, weight)),
            _ => None,
        })
    };
    if signal_limiters().next().is_none() {
        return missing(ID, SignalFamily::Rate);
    }
    // Dry-run limiters are recorded as hits by the engine; they never score.
    let exceeded: Vec<_> = signal_limiters()
        .filter(|(o, _)| o.exceeded && !o.dry_run)
        .collect();
    let Some((first, _)) = exceeded.first() else {
        return present(ID, SignalFamily::Rate, 0.0, 1.0, SELF);
    };
    let total: f32 = exceeded
        .iter()
        .map(|(_, w)| {
            if w.is_finite() {
                w.clamp(0.0, 2.0)
            } else {
                0.0
            }
        })
        .sum();
    let reason: Cow<'static, str> = Cow::Owned(format!("rl.{}", first.limiter_id));
    Some(
        Signal::new(ID, SignalFamily::Rate, (total / 2.0).min(1.0), 1.0)
            .with_source(SELF)
            .with_reason(reason),
    )
}

// --- IDENTITY ------------------------------------------------------------------

fn identity_clearance(ctx: &RequestContext, _: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "identity.clearance";
    let f = SignalFamily::Identity;
    match ctx.identity.token.status {
        TokenStatus::None | TokenStatus::Expired => absent(ID, f),
        // Both Phase 1 levels only prove "ran JS and paid a PoW": same evidence.
        TokenStatus::Valid => present(ID, f, -0.4, 1.0, SELF),
        TokenStatus::Invalid | TokenStatus::Replay => present(ID, f, 0.5, 0.6, SELF),
        TokenStatus::BindingMismatch => present(ID, f, 0.3, 0.8, SELF),
    }
}

fn identity_bind_ipp_soft(ctx: &RequestContext, _: &RequestExtras<'_>) -> Option<Signal> {
    let token = &ctx.identity.token;
    if token.status != TokenStatus::Valid {
        return None;
    }
    let soft = token.bind.ipp == Some(BindResult::SoftMismatch);
    flag(
        "identity.bind_ipp_soft",
        SignalFamily::Identity,
        soft,
        0.4,
        0.6,
        SELF,
    )
}

fn identity_crawler_failed(ctx: &RequestContext, _: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "identity.crawler_failed";
    let c = &ctx.identity.crawler;
    if !c.claimed {
        return None;
    }
    let f = SignalFamily::Identity;
    match c.verification {
        Some(CrawlerVerification::Failed) => present(ID, f, 1.0, 1.0, SELF),
        // D-18: the operator publishes ranges, the IP is outside them, rDNS pending.
        Some(CrawlerVerification::Pending) if c.outside_ranges => present(ID, f, 0.5, 0.6, SELF),
        _ => present(ID, f, 0.0, 1.0, SELF),
    }
}

// --- EXTERNAL ------------------------------------------------------------------

fn external_cf_vbot(ctx: &RequestContext, x: &RequestExtras<'_>) -> Option<Signal> {
    const ID: &str = "external.cf_vbot";
    let f = SignalFamily::External;
    if !is_cloudflare(ctx) || x.missing.is_missing("identity.crawler.cf_vbot") {
        return missing(ID, f);
    }
    let c = &ctx.identity.crawler;
    let Some(vbot) = c.cf_vbot else {
        return missing(ID, f);
    };
    // docs/03 §3.9: corroboration only, never human evidence.
    let hit = match vbot {
        true => !c.is_verified(),
        false => c.claimed,
    };
    flag(ID, f, hit, 0.3, 0.8, CF)
}

#[cfg(test)]
mod tests;
