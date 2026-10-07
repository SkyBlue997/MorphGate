//! The Decision Core's inputs (docs/impl/phase1-spec.md §9.5, §4.1, §4.3;
//! WP-E1b): the [`RequestContext`] of a request, the sanitized header map of
//! `req.headers`, the parsed User-Agent and the per-request [`MissingSet`].
//!
//! [`build`] is pure: the proxy collects the request facts ([`Facts`]) and
//! the site's intelligence artifacts ([`Intel`]); identity (clearance,
//! crawler), verdicts and rate-limiter observations are added afterwards
//! ([`crate::identity`], [`crate::ratelimit`]).
//!
//! # Size caps
//!
//! Everything here is bounded as §4.1 and §9.5 require, so the event stays
//! small and the static step bound of the policy (§5.3) holds: `req.headers`
//! values keep at most the bytes the client sent (at most 8 KiB after
//! §9.3.1; invalid UTF-8 is replaced without growing), the User-Agent is cut
//! at 512 bytes, `query_keys` and `cookie_names` hold at most 32 names of at
//! most 64 bytes, `content_type` at most 64 bytes, other strings 256 bytes.
//!
//! # MISSING (§4.1 last column)
//!
//! | Path | MISSING when |
//! |---|---|
//! | `net.ip` | the client IP is unknown |
//! | `net.asn` / `net.country` | no GeoLite2 ASN / country database, or `net.ip` MISSING |
//! | `net.conn_type` | no `datacenter-asns` artifact, or `net.asn` MISSING |
//! | `net.tor` | neither source: `tor-exits` with a known IP, nor Cloudflare's `cf-ipcountry` under trusted location headers |
//! | `tls` / `tls.ja4` | `cloudflare` (the whole namespace) / `direct_tls` (D-07) |
//! | `tls.version` | `direct_tls` without a negotiated version (never in practice) |
//! | `http.version` | `cloudflare` and `x-mg-cf-http-version` missing or invalid |
//! | `http.header_order` | `cloudflare`; `direct_tls` over HTTP/2 |
//! | `edge_tls[.*]` | `direct_tls` (all); `cloudflare` per missing header |
//! | `identity.proof`, `identity.agent` | always (Phase 1, D-07) |
//! | `identity.crawler.{claimed,operator,purpose,verified}` | no `crawler-registry` artifact |
//! | `identity.crawler.cf_vbot[_cat]` | `direct_tls`; `cloudflare` without a valid `x-mg-cf-vbot` |

use crate::config::ListenerProfile;
use crate::sites::Intel;
use mg_core::policy::MissingSet;
use mg_core::ua::{self, UaInfo};
use mg_core::{
    ConnType, FamilyMask, Http, IpSource, Net, RequestContext, RouteInfo, SignalSource, Tls,
    UpstreamAuthMethod, UpstreamInfo,
};
use mg_edge_core::request::header_order;
use mg_edge_core::upstream::CfHeaders;
use mg_intel::Lookup;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// `ctx.http.user_agent` cap (§9.5).
pub const MAX_USER_AGENT: usize = 512;
/// `query_keys` / `cookie_names` count cap (§9.5).
pub const MAX_NAMES: usize = 32;
/// Byte cap of one query key or cookie name (§9.5).
pub const MAX_NAME_BYTES: usize = 64;
/// `content_type` cap (§9.5).
pub const MAX_CONTENT_TYPE: usize = 64;
/// Cap of strings without their own rule (§4.1 "其他字符串").
pub const MAX_STRING: usize = 256;
/// Cap of one `req.headers` value (§9.3.1, §4.1).
pub const MAX_HEADER_VALUE: usize = 8192;
/// Only this much of the `Cookie` headers is scanned for names (§6.6).
pub const MAX_COOKIE_SCAN: usize = 16 * 1024;

/// Headers that never enter `req.headers` (§4.1).
const PRIVATE_HEADERS: [&str; 3] = ["cookie", "authorization", "proxy-authorization"];

/// Cloudflare's own cookies are never evidence (§9.5); nor is the Edge's
/// clearance cookie.
fn is_excluded_cookie(name: &str) -> bool {
    matches!(
        name,
        "__cf_bm"
            | "cf_clearance"
            | "_cfuvid"
            | "__cflb"
            | "__cfseq"
            | "__cfwaitingroom"
            | mg_challenge::COOKIE_NAME
    ) || name.starts_with("cf_chl_")
}

/// The TLS handshake of a `direct_tls` request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsInfo<'a> {
    /// `SslDigest.version`, e.g. `TLSv1.3`.
    pub version: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub alpn: Option<&'a str>,
    /// The JA4 of a `ja4_spike` listener (WP-J1): recorded in `ctx.tls.ja4`
    /// for the decision event, never evaluated (`tls.ja4` stays MISSING,
    /// D-07).
    pub ja4: Option<&'a str>,
}

/// What the proxy knows about a request when the Decision Core is about to
/// run. Its `Debug` shows no client address, header value or query
/// (§2.4 items 4-5, D-31).
#[derive(Clone, Copy)]
pub struct Facts<'a> {
    pub request_id: &'a str,
    /// Arrival time, Unix ms.
    pub ts_ms: i64,
    pub site_id: &'a str,
    pub route: &'a RouteInfo,
    pub profile: ListenerProfile,
    /// `loopback` / `origin_mtls` / `secret_header` / `none` (§9.2).
    pub auth_method: &'a str,
    /// Trusted `cloudflare` headers (cloudflare listeners only).
    pub cf: Option<&'a CfHeaders>,
    /// The bundle trusts Cloudflare's location headers
    /// (`cloudflare.location_headers`).
    pub location_headers: bool,
    /// `cf-connecting-ip` (cloudflare) or the TCP peer (direct_tls).
    pub client_ip: Option<IpAddr>,
    /// `direct_tls` only.
    pub tls: Option<TlsInfo<'a>>,
    /// The protocol version Pingora negotiated with the client.
    pub http_version: &'static str,
    pub method: &'a str,
    /// Normalized host (§9.4 step 1).
    pub host: &'a str,
    /// Raw path, without the query.
    pub path: &'a str,
    /// Raw query, without `?`.
    pub query: &'a str,
    /// The client's field lines as received (names as sent).
    pub raw_headers: &'a [(String, Vec<u8>)],
    /// Lower-case names removed by header hygiene (§9.3 steps 3 and 5).
    pub removed: &'a BTreeSet<String>,
    /// `SiteBundle.upstream.expected_mask`.
    pub expected_mask: u32,
}

/// `<redacted ipv4>` / `<redacted ipv6>` for a client address in `Debug`
/// output (D-31).
pub(crate) fn redacted_ip(ip: Option<IpAddr>) -> Option<&'static str> {
    ip.map(|ip| match ip.to_canonical() {
        IpAddr::V4(_) => "<redacted ipv4>",
        IpAddr::V6(_) => "<redacted ipv6>",
    })
}

impl std::fmt::Debug for Facts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.raw_headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("Facts")
            .field("request_id", &self.request_id)
            .field("ts_ms", &self.ts_ms)
            .field("site_id", &self.site_id)
            .field("route", &self.route)
            .field("profile", &self.profile)
            .field("auth_method", &self.auth_method)
            .field("cf", &self.cf)
            .field("location_headers", &self.location_headers)
            .field("client_ip", &redacted_ip(self.client_ip))
            .field("tls", &self.tls)
            .field("http_version", &self.http_version)
            .field("method", &self.method)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("query_len", &self.query.len())
            .field("header_names", &names)
            .field("removed", &self.removed)
            .field("expected_mask", &self.expected_mask)
            .finish()
    }
}

/// The Decision Core inputs built from [`Facts`]. Its `Debug` shows header
/// names only and the number of `Cookie` fields, never their values.
#[derive(Clone)]
pub struct Built {
    /// Identity, session and verdicts still at their defaults.
    pub ctx: RequestContext,
    pub missing: MissingSet,
    /// §4.1 `req.headers`, sorted by name.
    pub headers: Vec<(String, String)>,
    /// `mg_core::ua::parse` of `ctx.http.user_agent`.
    pub ua: UaInfo,
    /// The visitor used https (`direct_tls`, or `CF-Visitor` https).
    pub secure_context: bool,
    /// The `Cookie` header values (clearance candidates, §6.6).
    pub cookies: Vec<String>,
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("Built")
            .field("ctx", &self.ctx)
            .field("missing", &self.missing)
            .field("header_names", &names)
            .field("ua", &self.ua)
            .field("secure_context", &self.secure_context)
            .field("cookies", &self.cookies.len())
            .finish()
    }
}

/// The `Pingora` version as the §4.1 `http.version` string.
pub fn http_version_str(v: pingora::http::Version) -> &'static str {
    use pingora::http::Version;
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

/// The longest prefix of `s` of at most `max` bytes that ends on a char
/// boundary.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// UTF-8 text of a header value that is never longer than the bytes
/// received: invalid sequences are replaced and the result is cut back to
/// the original length (U+FFFD takes three bytes).
fn header_text(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            let lossy = String::from_utf8_lossy(value);
            truncate_utf8(&lossy, value.len()).to_owned()
        }
    }
}

/// §4.1 `req.headers`: the client headers left after hygiene, lower-case
/// names, repeated fields joined with `", "`, without `cookie`,
/// `authorization` and `proxy-authorization`, sorted by name. Values are
/// capped at 8 KiB (§9.3.1 already rejects longer joined values under
/// enforce; monitor never evaluates such requests, I-2).
pub fn req_headers(raw: &[(String, Vec<u8>)], removed: &BTreeSet<String>) -> Vec<(String, String)> {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, value) in raw {
        let lower = name.to_ascii_lowercase();
        if removed.contains(&lower) || PRIVATE_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        let text = header_text(value);
        map.entry(lower)
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&text);
            })
            .or_insert(text);
    }
    map.into_iter()
        .map(|(k, v)| {
            let v = truncate_utf8(&v, MAX_HEADER_VALUE).to_owned();
            (k, v)
        })
        .collect()
}

/// The value of `name` (lower-case) in a sorted `req.headers` list.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .binary_search_by(|(k, _)| k.as_str().cmp(name))
        .ok()
        .map(|i| headers[i].1.as_str())
}

/// Distinct query parameter names in order (values never), at most 32, each
/// cut to 64 bytes (§9.5).
pub fn query_keys(query: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pair in query.split('&') {
        if out.len() == MAX_NAMES {
            break;
        }
        let key = pair.split('=').next().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let key = truncate_utf8(key, MAX_NAME_BYTES);
        if !out.iter().any(|k| k == key) {
            out.push(key.to_owned());
        }
    }
    out
}

/// Distinct cookie names of the `Cookie` headers (values never), at most 32
/// of at most 64 bytes, without Cloudflare's cookies and the clearance
/// cookie (§9.5). Only the first 16 KiB are scanned (§6.6).
pub fn cookie_names(cookie_headers: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut budget = MAX_COOKIE_SCAN;
    for header in cookie_headers {
        if budget == 0 || out.len() == MAX_NAMES {
            break;
        }
        let window = truncate_utf8(header, budget);
        budget -= window.len();
        for pair in window.split(';') {
            let name = pair.split('=').next().unwrap_or_default().trim();
            if name.is_empty()
                || name.len() > MAX_NAME_BYTES
                || is_excluded_cookie(name)
                || out.iter().any(|n| n == name)
            {
                continue;
            }
            out.push(name.to_owned());
            if out.len() == MAX_NAMES {
                break;
            }
        }
    }
    out
}

/// The `Cookie` field values, copied only as far as anything reads them:
/// the clearance parser and [`cookie_names`] look at the first 16 KiB of
/// all `Cookie` fields together (§6.6). The field where that budget ends
/// keeps one byte more, so `mg_challenge::clearance_cookies` still sees it
/// as cut and ignores its last, incomplete pair; later fields are dropped.
pub fn cookie_headers(raw: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut budget = MAX_COOKIE_SCAN;
    for (_, value) in raw.iter().filter(|(n, _)| n.eq_ignore_ascii_case("cookie")) {
        if budget == 0 {
            break;
        }
        let take = value.len().min(budget + 1);
        out.push(header_text(&value[..take]));
        budget = budget.saturating_sub(value.len());
    }
    out
}

/// `http.early_data` (§9.5, §9.9, §10.3 step 1): the request carries an
/// `Early-Data` field. Read from the headers as received: a `Connection`
/// option naming it removes it before forwarding, but the Edge is that
/// option's recipient and must still honour it. Any instance counts, whatever
/// its value or number: RFC 8470 §5.1 makes a server treat multiple or
/// invalid instances as `Early-Data: 1` (otherwise a client-sent
/// `Early-Data: 0` next to the one Cloudflare adds would unmark a 0-RTT
/// request and get it a clearance).
pub fn early_data(raw: &[(String, Vec<u8>)]) -> bool {
    received(raw, "early-data")
}

/// Whether the client sent a field called `name` (lower-case), including one
/// that hygiene removes before forwarding (a `Connection` option).
pub fn received(raw: &[(String, Vec<u8>)], name: &str) -> bool {
    raw.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// The media type of `Content-Type` (before `;`), lower-case, at most 64
/// bytes.
pub fn content_type(value: &str) -> Option<String> {
    let media = value.split(';').next().unwrap_or_default().trim();
    (!media.is_empty())
        .then(|| truncate_utf8(&media.to_ascii_lowercase(), MAX_CONTENT_TYPE).to_owned())
}

/// `UpstreamInfo.auth_method` of a listener's `auth_method` string.
pub(crate) fn upstream_auth_method(s: &str) -> UpstreamAuthMethod {
    match s {
        "loopback" => UpstreamAuthMethod::Loopback,
        "origin_mtls" => UpstreamAuthMethod::OriginMtls,
        "secret_header" => UpstreamAuthMethod::SecretHeader,
        _ => UpstreamAuthMethod::None,
    }
}

/// Builds the context, `req.headers`, the parsed User-Agent and the
/// MissingSet of one request (see the module documentation).
pub fn build(f: &Facts<'_>, intel: &Intel) -> Built {
    let cloudflare = f.profile == ListenerProfile::Cloudflare;
    let cf = f.cf.filter(|_| cloudflare);
    let headers = req_headers(f.raw_headers, f.removed);
    let mut missing: Vec<&'static str> = vec!["identity.proof", "identity.agent"];

    // upstream (§9.5).
    let upstream = UpstreamInfo {
        profile: f.profile.kind(),
        authenticated: cloudflare,
        cf_ray: cf.and_then(|c| c.cf_ray.clone()),
        auth_method: upstream_auth_method(f.auth_method),
        client_ip_header_missing: cf.is_some_and(|c| {
            matches!(
                c.client_ip,
                mg_edge_core::upstream::ClientIp::Unknown {
                    header_missing: true
                }
            )
        }),
    };

    // net (§9.5, §4.1).
    let ip = f.client_ip.map(|ip| ip.to_canonical());
    let mut net = match ip {
        Some(ip) => Net::for_ip(ip),
        None => Net::default(),
    };
    net.ip_source = match (ip, cf) {
        (None, _) => None,
        (Some(_), Some(c)) => c.client_ip.source(),
        (Some(_), None) => Some(IpSource::TcpPeer),
    };
    let (mut asn_missing, mut country_missing) = (true, true);
    if let (Some(ip), Some(geo)) = (ip, intel.geo.as_deref()) {
        let info = geo.lookup(ip);
        asn_missing = info.asn.is_unavailable();
        country_missing = info.country.is_unavailable();
        net.asn = info.asn.found().copied().filter(|a| *a != 0);
        if let Lookup::Found(org) = &info.as_org {
            net.as_org = Some(truncate_utf8(org, MAX_STRING).to_owned());
        }
        net.country = info
            .country
            .found()
            .map(|c| truncate_utf8(c, MAX_STRING).to_owned());
    }
    let conn_type_missing = asn_missing || intel.datacenter_asns.is_none();
    if !conn_type_missing
        && let (Some(asn), Some(dc)) = (net.asn, intel.datacenter_asns.as_deref())
        && dc.contains(&asn)
    {
        net.conn_type = ConnType::Datacenter;
    }
    // net.tor: IP in tor-exits, or Cloudflare's T1 country (trusted location
    // headers). MISSING only when neither source can answer.
    let exits = ip.and_then(|ip| intel.tor_exits.as_deref().map(|set| set.contains(ip)));
    let cf_country = cf
        .filter(|_| f.location_headers)
        .and_then(|c| c.upstream_country.as_ref().map(|_| c.is_tor()));
    net.tor = exits == Some(true) || cf_country == Some(true);
    if exits.is_none() && cf_country.is_none() {
        missing.push("net.tor");
    }
    if let Some(c) = cf {
        net.upstream_asn = c.upstream_asn;
        net.upstream_country = c.upstream_country.clone();
        net.upstream_region = c.upstream_region.clone();
        net.upstream_timezone = c.upstream_timezone.clone();
        net.rtt_ms = c.rtt_ms;
    }
    if ip.is_none() {
        missing.push("net.ip");
    }
    if asn_missing {
        missing.push("net.asn");
    }
    if country_missing {
        missing.push("net.country");
    }
    if conn_type_missing {
        missing.push("net.conn_type");
    }

    // tls / edge_tls (§9.5).
    let mut tls = Tls::default();
    if cloudflare {
        missing.push("tls");
    } else {
        // D-07: MISSING for the policy even when the JA4 spike computed a
        // value; that value only reaches the decision event.
        missing.push("tls.ja4");
        let t = f.tls.unwrap_or_default();
        tls = Tls {
            available: true,
            version: t.version.map(|v| truncate_utf8(v, MAX_STRING).to_owned()),
            sni: t.sni.map(|v| truncate_utf8(v, MAX_STRING).to_owned()),
            alpn: t.alpn.map(|v| truncate_utf8(v, MAX_STRING).to_owned()),
            ja4: t.ja4.map(|v| mg_core::Ja4 {
                value: truncate_utf8(v, MAX_STRING).to_owned(),
                source: SignalSource::SelfComputed,
                authenticated: true,
            }),
        };
        if tls.version.is_none() {
            missing.push("tls.version");
        }
    }
    let edge_tls = cf.and_then(|c| c.edge_tls.clone());
    match (&edge_tls, cloudflare) {
        (Some(e), true) => {
            for (present, path) in [
                (e.version.is_some(), "edge_tls.version"),
                (e.cipher.is_some(), "edge_tls.cipher"),
                (e.ciphers_sha1.is_some(), "edge_tls.ciphers_sha1"),
                (e.ext_sha1.is_some(), "edge_tls.ext_sha1"),
                (e.hello_len.is_some(), "edge_tls.hello_len"),
            ] {
                if !present {
                    missing.push(path);
                }
            }
        }
        _ => missing.push("edge_tls"),
    }

    // http (§9.5).
    let raw_names: Vec<&str> = f.raw_headers.iter().map(|(n, _)| n.as_str()).collect();
    let http1 = f.http_version.starts_with("HTTP/1") || f.http_version == "HTTP/0.9";
    let (version, version_source) = match cf {
        Some(c) => (c.http_version.clone(), SignalSource::Cloudflare),
        None => (Some(f.http_version.to_owned()), SignalSource::SelfComputed),
    };
    if version.is_none() {
        missing.push("http.version");
    }
    let header_order_list = if !cloudflare && http1 {
        header_order(&raw_names)
    } else {
        missing.push("http.header_order");
        Vec::new()
    };
    let header_names = match cf {
        Some(c) => c.header_names.clone().unwrap_or_default(),
        None => header_order(&raw_names),
    };
    let user_agent =
        header(&headers, "user-agent").map(|ua| truncate_utf8(ua, MAX_USER_AGENT).to_owned());
    let cookie_values = cookie_headers(f.raw_headers);
    let cookie_refs: Vec<&str> = cookie_values.iter().map(String::as_str).collect();
    let tier1 = cf.and_then(|c| c.tier1.as_ref());
    let http = Http {
        version,
        version_source,
        method: f.method.to_ascii_uppercase(),
        host: f.host.to_owned(),
        path: f.path.to_owned(),
        query_keys: query_keys(f.query),
        header_order: header_order_list,
        header_names,
        user_agent: user_agent.clone(),
        cookie_names: cookie_names(&cookie_refs),
        body_size: header(&headers, "content-length").and_then(|v| v.trim().parse().ok()),
        content_type: header(&headers, "content-type").and_then(content_type),
        early_data: early_data(f.raw_headers),
        priority: tier1.and_then(|t| t.priority.clone()),
        accept_encoding_orig: tier1.and_then(|t| t.accept_encoding_orig.clone()),
    };

    // identity: cf_vbot here; clearance and crawler in crate::identity.
    let mut ctx = RequestContext::new(f.request_id, f.site_id, f.ts_ms);
    match cf.and_then(|c| c.cf_vbot) {
        Some(vbot) => {
            ctx.identity.crawler.cf_vbot = Some(vbot);
            ctx.identity.crawler.cf_vbot_cat = cf.and_then(|c| c.cf_vbot_cat.clone());
        }
        None => {
            missing.push("identity.crawler.cf_vbot");
            missing.push("identity.crawler.cf_vbot_cat");
        }
    }
    if intel.crawler.is_none() {
        missing.extend([
            "identity.crawler.claimed",
            "identity.crawler.operator",
            "identity.crawler.purpose",
            "identity.crawler.verified",
        ]);
    }

    ctx.env = f.route.env.clone();
    ctx.route_id = Some(f.route.id.clone());
    ctx.channel = f.route.channel;
    ctx.upstream = upstream;
    ctx.net = net;
    ctx.tls = tls;
    ctx.edge_tls = edge_tls;
    ctx.http = http;
    ctx.expected_mask = FamilyMask::from_bits_truncate(f.expected_mask);

    let ua = ua::parse(user_agent.as_deref().unwrap_or(""));
    let secure_context = cf.is_none_or(|c| c.visitor_https);
    Built {
        ctx,
        missing: missing_set(&missing),
        headers,
        ua,
        secure_context,
        cookies: cookie_values,
    }
}

/// A MissingSet of schema paths. Every path above is a §4.1 schema path
/// (unit-tested); an unknown one would be a programming error and is logged
/// rather than turned into a panic on the request path.
fn missing_set(paths: &[&'static str]) -> MissingSet {
    let mut set = MissingSet::default();
    for p in paths {
        if let Err(e) = set.insert(p) {
            debug_assert!(false, "{e}");
            log::error!("MissingSet: {e}");
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::{Channel, EdgeTls, RouteSensitivity, UpstreamProfileKind};
    use mg_edge_core::upstream::{ClientIp, Tier1, Tier1Source, WorkerZone};
    use std::sync::Arc;

    fn route() -> RouteInfo {
        RouteInfo {
            id: "login".into(),
            name: "login".into(),
            env: "production".into(),
            channel: Channel::Web,
            sensitivity: RouteSensitivity::Critical,
            require_clearance: true,
            fail_closed: true,
        }
    }

    fn cf_headers(ip: Option<&str>) -> CfHeaders {
        CfHeaders {
            client_ip: match ip {
                Some(ip) => ClientIp::Known(ip.parse().unwrap(), IpSource::CfConnectingIp),
                None => ClientIp::Unknown {
                    header_missing: true,
                },
            },
            worker: WorkerZone::None,
            cf_ray: Some("8f00aa-HKG".into()),
            visitor_https: true,
            edge_tls: Some(EdgeTls {
                version: Some("TLSv1.3".into()),
                cipher: Some("TLS_AES_128_GCM_SHA256".into()),
                ciphers_sha1: None,
                ext_sha1: Some("x".into()),
                hello_len: Some(512),
            }),
            http_version: Some("HTTP/2".into()),
            rtt_ms: Some(20),
            upstream_asn: Some(64500),
            upstream_country: Some("HK".into()),
            upstream_region: None,
            upstream_timezone: None,
            cf_vbot: Some(false),
            cf_vbot_cat: None,
            header_names: Some(vec!["Accept".into()]),
            tier1: Some(Tier1 {
                source: Tier1Source::Snippet,
                priority: Some("u=0, i".into()),
                accept_encoding_orig: None,
                as_org: None,
            }),
            missing_signals: Vec::new(),
        }
    }

    fn raw(h: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        h.iter()
            .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
            .collect()
    }

    struct Req {
        raw: Vec<(String, Vec<u8>)>,
        removed: BTreeSet<String>,
        route: RouteInfo,
    }

    impl Req {
        fn new(h: &[(&str, &[u8])]) -> Self {
            Self {
                raw: raw(h),
                removed: BTreeSet::new(),
                route: route(),
            }
        }

        fn facts<'a>(
            &'a self,
            profile: ListenerProfile,
            cf: Option<&'a CfHeaders>,
            ip: Option<&str>,
        ) -> Facts<'a> {
            Facts {
                request_id: "0123456789abcdef0123456789abcdef",
                ts_ms: 1_790_000_000_000,
                site_id: "blog",
                route: &self.route,
                profile,
                auth_method: if cf.is_some() { "loopback" } else { "none" },
                cf,
                location_headers: true,
                client_ip: ip.map(|s| s.parse().unwrap()),
                tls: (profile == ListenerProfile::DirectTls).then_some(TlsInfo {
                    version: Some("TLSv1.3"),
                    sni: Some("example.com"),
                    alpn: Some("h2"),
                    ja4: None,
                }),
                http_version: "HTTP/1.1",
                method: "post",
                host: "example.com",
                path: "/account/login",
                query: "next=%2F&a=1&next=2",
                raw_headers: &self.raw,
                removed: &self.removed,
                expected_mask: 0b111_1000_1010,
            }
        }
    }

    fn paths(m: &MissingSet) -> Vec<&str> {
        m.paths().collect()
    }

    #[test]
    fn cloudflare_context_and_missing_set() {
        let req = Req::new(&[
            ("Host", b"example.com"),
            (
                "User-Agent",
                b"Mozilla/5.0 (X11) Chrome/131.0 Safari/537.36",
            ),
            ("Accept", b"text/html"),
            ("accept", b"*/*"),
            (
                "Cookie",
                b"__cf_bm=1; sid=2; __Host-mg_clr=t; cf_chl_x=3; theme=d",
            ),
            ("Authorization", b"Bearer secret"),
            ("Content-Type", b"Application/JSON; charset=utf-8"),
            ("Content-Length", b"12"),
            ("Early-Data", b"1"),
        ]);
        let cf = cf_headers(Some("203.0.113.7"));
        let b = build(
            &req.facts(ListenerProfile::Cloudflare, Some(&cf), Some("203.0.113.7")),
            &Intel::default(),
        );
        let c = &b.ctx;
        assert_eq!(c.request_id.len(), 32);
        assert_eq!(c.site_id, "blog");
        assert_eq!(c.env, "production");
        assert_eq!(c.route_id.as_deref(), Some("login"));
        assert_eq!(c.upstream.profile, UpstreamProfileKind::Cloudflare);
        assert!(c.upstream.authenticated);
        assert_eq!(c.upstream.auth_method, UpstreamAuthMethod::Loopback);
        assert_eq!(c.upstream.cf_ray.as_deref(), Some("8f00aa-HKG"));
        assert_eq!(c.net.ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(c.net.ip_prefix.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(c.net.ip_source, Some(IpSource::CfConnectingIp));
        assert_eq!(c.net.upstream_asn, Some(64500));
        assert_eq!(c.net.rtt_ms, Some(20));
        assert!(!c.net.tor);
        assert!(!c.tls.available);
        assert_eq!(c.edge_tls.as_ref().unwrap().hello_len, Some(512));
        assert_eq!(c.http.version.as_deref(), Some("HTTP/2"));
        assert_eq!(c.http.version_source, SignalSource::Cloudflare);
        assert_eq!(c.http.method, "POST", "§4.1: upper case");
        assert_eq!(c.http.query_keys, ["next", "a"]);
        assert!(c.http.header_order.is_empty());
        assert_eq!(c.http.header_names, ["Accept"]);
        assert_eq!(c.http.cookie_names, ["sid", "theme"]);
        assert_eq!(c.http.body_size, Some(12));
        assert_eq!(c.http.content_type.as_deref(), Some("application/json"));
        assert!(c.http.early_data);
        assert_eq!(c.http.priority.as_deref(), Some("u=0, i"));
        assert_eq!(c.identity.crawler.cf_vbot, Some(false));
        assert_eq!(c.expected_mask.bits(), 0b111_1000_1010);
        assert_eq!(b.ua.family, "chrome");
        assert_eq!(b.ua.major, 131);
        assert!(b.secure_context);
        // req.headers: lower-case, joined, private headers excluded, sorted.
        assert_eq!(header(&b.headers, "accept"), Some("text/html, */*"));
        assert!(header(&b.headers, "cookie").is_none());
        assert!(header(&b.headers, "authorization").is_none());
        assert!(b.headers.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            paths(&b.missing),
            [
                "edge_tls.ciphers_sha1",
                "http.header_order",
                "identity.agent",
                "identity.crawler.claimed",
                "identity.crawler.operator",
                "identity.crawler.purpose",
                "identity.crawler.verified",
                "identity.proof",
                "net.asn",
                "net.conn_type",
                "net.country",
                "tls",
            ]
        );
        assert!(!b.missing.is_missing("net.tor"), "cf-ipcountry answers it");
        assert!(b.missing.is_missing("tls.version"));
        assert!(b.missing.is_missing("tls.ja4.value"));
        assert!(!b.missing.is_missing("http.version"));
    }

    /// §9.3.2: an unknown client IP makes the NETWORK inputs MISSING and
    /// never falls back to another address.
    /// §9.5 `early_data`: any `Early-Data` instance (RFC 8470 §5.1), also
    /// one that a `Connection` option removes before forwarding.
    #[test]
    fn early_data_cannot_be_unmarked() {
        let early = |h: &[(&str, &[u8])], connection_listed: bool| {
            let mut req = Req::new(h);
            if connection_listed {
                req.removed.insert("early-data".into());
            }
            build(
                &req.facts(ListenerProfile::DirectTls, None, Some("203.0.113.7")),
                &Intel::default(),
            )
            .ctx
            .http
            .early_data
        };
        assert!(!early(&[("Host", b"example.com")], false));
        assert!(early(&[("Early-Data", b"1")], false));
        assert!(early(&[("early-data", b"0")], false), "invalid value");
        assert!(early(&[("Early-Data", b"")], false), "empty value");
        assert!(
            early(&[("Early-Data", b"0"), ("Early-Data", b"1")], false),
            "multiple instances"
        );
        assert!(
            early(&[("Early-Data", b"1")], true),
            "Connection: early-data"
        );
    }

    #[test]
    fn unknown_client_ip() {
        let req = Req::new(&[("Host", b"example.com")]);
        let mut cf = cf_headers(None);
        cf.upstream_country = None;
        cf.http_version = None;
        cf.edge_tls = None;
        cf.cf_vbot = None;
        let b = build(
            &req.facts(ListenerProfile::Cloudflare, Some(&cf), None),
            &Intel::default(),
        );
        assert_eq!(b.ctx.net.ip, None);
        assert_eq!(b.ctx.net.ip_prefix, None);
        assert_eq!(b.ctx.net.ip_source, None);
        assert!(b.ctx.upstream.client_ip_header_missing);
        for p in [
            "net.ip",
            "net.asn",
            "net.country",
            "net.conn_type",
            "net.tor",
            "http.version",
            "edge_tls.version",
            "identity.crawler.cf_vbot",
            "identity.crawler.cf_vbot_cat",
        ] {
            assert!(b.missing.is_missing(p), "{p}");
        }
        assert_eq!(b.ctx.http.user_agent, None);
        assert_eq!(b.ua.family, "other");
    }

    #[test]
    fn direct_tls_context_and_missing_set() {
        let req = Req::new(&[
            ("Host", b"example.com"),
            ("User-Agent", b"curl/8.5.0"),
            ("X-Forwarded-For", b"10.0.0.1"),
            ("Accept", b"*/*"),
            ("host", b"dup"),
        ]);
        let mut req = req;
        req.removed.insert("x-forwarded-for".into());
        let b = build(
            &req.facts(
                ListenerProfile::DirectTls,
                None,
                Some("::ffff:198.51.100.7"),
            ),
            &Intel::default(),
        );
        let c = &b.ctx;
        assert_eq!(c.upstream.profile, UpstreamProfileKind::DirectTls);
        assert!(!c.upstream.authenticated);
        assert_eq!(c.upstream.auth_method, UpstreamAuthMethod::None);
        assert_eq!(
            c.net.ip,
            Some("198.51.100.7".parse().unwrap()),
            "mapped -> v4"
        );
        assert_eq!(c.net.ip_source, Some(IpSource::TcpPeer));
        assert!(c.tls.available);
        assert_eq!(c.tls.version.as_deref(), Some("TLSv1.3"));
        assert_eq!(c.tls.sni.as_deref(), Some("example.com"));
        assert_eq!(c.tls.alpn.as_deref(), Some("h2"));
        assert_eq!(c.edge_tls, None);
        assert_eq!(c.http.version.as_deref(), Some("HTTP/1.1"));
        assert_eq!(c.http.version_source, SignalSource::SelfComputed);
        // Distinct names in first-arrival order, original case, hygiene
        // does not change what the client sent.
        assert_eq!(
            c.http.header_order,
            ["Host", "User-Agent", "X-Forwarded-For", "Accept"]
        );
        assert_eq!(c.http.header_names, c.http.header_order);
        assert!(header(&b.headers, "x-forwarded-for").is_none(), "removed");
        assert_eq!(header(&b.headers, "host"), Some("example.com, dup"));
        assert!(b.ua.library);
        for p in [
            "tls.ja4",
            "edge_tls",
            "identity.crawler.cf_vbot",
            "identity.crawler.cf_vbot_cat",
        ] {
            assert!(b.missing.is_missing(p), "{p}");
        }
        for p in ["tls.version", "http.version", "http.header_order", "net.ip"] {
            assert!(!b.missing.is_missing(p), "{p}");
        }

        // HTTP/2: no header order.
        let mut f = req.facts(ListenerProfile::DirectTls, None, Some("198.51.100.7"));
        f.http_version = "HTTP/2";
        let b = build(&f, &Intel::default());
        assert!(b.missing.is_missing("http.header_order"));
        assert!(b.ctx.http.header_order.is_empty());
        assert_eq!(b.ctx.http.header_names.len(), 4);
    }

    #[test]
    fn artifacts_answer_their_fields() {
        let geo = mg_intel::GeoDb::load(
            Some(
                std::fs::read(crate::test_support::repo(
                    "intel/testdata/mmdb/test-asn.mmdb",
                ))
                .unwrap(),
            ),
            Some(
                std::fs::read(crate::test_support::repo(
                    "intel/testdata/mmdb/test-country.mmdb",
                ))
                .unwrap(),
            ),
        )
        .unwrap();
        // intel/testdata/mmdb: 192.0.2.0/24 is AS64496 in DE.
        let ip = "192.0.2.7";
        let found = geo.lookup(ip.parse().unwrap());
        assert_eq!(found.asn.found(), Some(&64496));
        let asn = 64496;
        let intel = Intel {
            geo: Some(Arc::new(geo)),
            datacenter_asns: Some(Arc::new([asn].into())),
            tor_exits: Some(Arc::new(mg_intel::IpSet::parse([ip]).unwrap())),
            ..Intel::default()
        };
        let req = Req::new(&[("Host", b"example.com")]);
        let b = build(
            &req.facts(ListenerProfile::DirectTls, None, Some(ip)),
            &intel,
        );
        assert_eq!(b.ctx.net.asn, Some(asn));
        assert!(b.ctx.net.country.is_some());
        assert_eq!(b.ctx.net.conn_type, ConnType::Datacenter);
        assert!(b.ctx.net.tor);
        for p in ["net.asn", "net.country", "net.conn_type", "net.tor"] {
            assert!(!b.missing.is_missing(p), "{p}");
        }
        assert_eq!(b.ctx.net.country.as_deref(), Some("DE"));
        // An address the databases do not know: ABSENT, not MISSING.
        let b = build(
            &req.facts(ListenerProfile::DirectTls, None, Some("3fff::1")),
            &intel,
        );
        assert_eq!(b.ctx.net.country, None);
        assert_eq!(b.ctx.net.asn, None);
        assert_eq!(b.ctx.net.conn_type, ConnType::Unknown);
        assert!(!b.ctx.net.tor);
        for p in ["net.asn", "net.country", "net.conn_type", "net.tor"] {
            assert!(!b.missing.is_missing(p), "{p}");
        }
    }

    #[test]
    fn caps_and_parsers() {
        assert_eq!(query_keys(""), Vec::<String>::new());
        assert_eq!(query_keys("a&&b=&=c&a=2"), ["a", "b"]);
        let many: String = (0..40).map(|i| format!("k{i}=1&")).collect();
        assert_eq!(query_keys(&many).len(), MAX_NAMES);
        let long = "é".repeat(40);
        assert_eq!(query_keys(&long)[0].len(), 64);
        assert_eq!(
            cookie_names(&["a=1; b=2", "a=3; __cfwaitingroom=x; cf_clearance=y; c"]),
            ["a", "b", "c"]
        );
        let long_name = format!("{}=1; ok=1", "n".repeat(65));
        assert_eq!(cookie_names(&[&long_name]), ["ok"]);
        assert_eq!(content_type(" text/HTML ; q=1"), Some("text/html".into()));
        // Cookie fields are copied only as far as the 16 KiB scan reaches,
        // and a cut clearance cookie is still recognised as cut.
        let big = format!(
            "a={}; {}=tok",
            "x".repeat(MAX_COOKIE_SCAN - 12),
            mg_challenge::COOKIE_NAME
        );
        let fields = raw(&[
            ("Cookie", big.as_bytes()),
            ("cookie", b"late=1"),
            ("Accept", b"*/*"),
        ]);
        let copied = cookie_headers(&fields);
        assert_eq!(copied.len(), 1, "the budget ends inside the first field");
        assert_eq!(copied[0].len(), MAX_COOKIE_SCAN + 1);
        let refs: Vec<&str> = copied.iter().map(String::as_str).collect();
        assert!(mg_challenge::clearance_cookies(&refs).is_empty());
        let small = raw(&[("Cookie", b"a=1"), ("Cookie", b"b=2")]);
        assert_eq!(cookie_headers(&small), ["a=1", "b=2"]);
        assert_eq!(content_type(";x"), None);
        assert_eq!(truncate_utf8("aé", 2), "a");
        // Non-UTF-8 header values never grow.
        let raw = raw(&[("X-Bin", &[0xff; 100])]);
        let h = req_headers(&raw, &BTreeSet::new());
        assert!(h[0].1.len() <= 100);
        // The User-Agent is cut at 512 bytes.
        let ua = format!("Mozilla/5.0 {}", "x".repeat(1000));
        let req = Req::new(&[("User-Agent", ua.as_bytes())]);
        let b = build(
            &req.facts(ListenerProfile::DirectTls, None, Some("192.0.2.1")),
            &Intel::default(),
        );
        assert_eq!(
            b.ctx.http.user_agent.as_ref().unwrap().len(),
            MAX_USER_AGENT
        );
    }

    /// §2.4 items 4-5, D-31: `Debug` of the request facts and of the built
    /// inputs never shows the client address, a cookie (the clearance
    /// token), `Authorization`, the upstream key or the query.
    #[test]
    fn debug_output_has_no_client_secrets() {
        let req = Req::new(&[
            ("Host", b"example.com"),
            (
                "Cookie",
                b"sid=cookie-secret; __Host-mg_clr=v4.local.token-secret",
            ),
            ("Authorization", b"Bearer auth-secret"),
            ("x-mg-upstream-key", b"upstream-secret"),
            ("X-Api-Key", b"app-secret"),
            ("User-Agent", b"Mozilla/5.0 Chrome/131.0"),
        ]);
        let cf = cf_headers(Some("203.0.113.7"));
        let mut facts = req.facts(ListenerProfile::Cloudflare, Some(&cf), Some("203.0.113.7"));
        facts.query = "reset=query-secret";
        let built = build(&facts, &Intel::default());
        for text in [format!("{facts:?}"), format!("{built:?}")] {
            for secret in [
                "203.0.113.7",
                "cookie-secret",
                "token-secret",
                "auth-secret",
                "upstream-secret",
                "app-secret",
                "query-secret",
            ] {
                assert!(!text.contains(secret), "{secret} in {text}");
            }
        }
        // Still useful for debugging: names and counts.
        assert!(format!("{facts:?}").contains("Cookie"));
        assert!(format!("{built:?}").contains("cookies: 1"));
        let v6 = req.facts(ListenerProfile::DirectTls, None, Some("2001:db8::7"));
        assert!(!format!("{v6:?}").contains("2001:db8"));
    }

    /// §2.4 item 3: the header / cookie / query parsers never panic.
    #[test]
    fn random_inputs_never_panic() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..10_000 {
            let len = (next() % 64) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let _ = query_keys(&text);
            let _ = cookie_names(&[&text, &text]);
            let _ = content_type(&text);
            let _ = truncate_utf8(&text, (next() % 70) as usize);
            let raw = vec![
                ("x".to_owned(), bytes.clone()),
                ("X".to_owned(), bytes.clone()),
            ];
            let h = req_headers(&raw, &BTreeSet::new());
            assert_eq!(h.len(), 1);
            let cookies = vec![
                ("Cookie".to_owned(), bytes.clone()),
                ("cookie".to_owned(), bytes),
            ];
            let copied = cookie_headers(&cookies);
            assert!(copied.iter().map(String::len).sum::<usize>() <= 2 * len);
        }
    }
}
