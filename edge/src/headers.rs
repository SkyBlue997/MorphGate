//! Header hygiene and origin headers (docs/impl/phase1-spec.md §9.3, §9.9,
//! D-34).
//!
//! Toward the origin the Edge is the only party that may send `MG-*`
//! headers, and it forwards no upstream-family header (`cf-*`, `x-mg-*`,
//! `x-forwarded-*`, `forwarded`, `mg-*`, ..., and the I-29 client-IP,
//! URL-rewrite and method-override names such as `x-client-ip`,
//! `x-original-url` and `x-http-method-override`; underscore spellings
//! included) except the few §9.9 re-writes from values it parsed itself:
//!
//! 1. [`raw_headers`] takes the client's field lines (original case, arrival
//!    order within the limits of `http::HeaderMap`: distinct names in first
//!    arrival order, repeated values grouped after their first occurrence).
//! 2. The proxy removes `mg_edge_core::upstream::hop_by_hop` names and every
//!    family name from the downstream request ([`remove_names`]), so neither
//!    Pingora's own hop-by-hop handling nor the origin ever sees them.
//! 3. [`OriginHeaders::apply`] sets `Host` to the normalized host, strips the
//!    families once more (defense in depth) and writes `MG-Client-IP`,
//!    `MG-Request-Id`, a single-valued `X-Forwarded-For`,
//!    `X-Forwarded-Proto` and, for authenticated `cloudflare` requests,
//!    `CF-IPCountry` / `Cf-Ray` / `CF-Visitor` / `CF-Connecting-IP`.
//!
//! Origin responses lose every `MG-*` / `MG_*` header ([`strip_edge_owned`]).
//!
//! Evaluated requests also carry the decision (§9.9, [`DecisionHeaders`]):
//! with `origin_headers.scores` `MG-Bot-Score` (0-100), `MG-Bot-Class`
//! (lower-case wire name) and, for a verified crawler, `MG-Verified:
//! crawler:<operator>`; with `origin_headers.session` and a valid clearance
//! `MG-Session`; for a TAG decision `MG-Tags: a,b`; with
//! `origin_headers.reasons` `MG-Reasons` (the top reasons). Under monitor
//! they reflect the recorded (would-be) decision.

use crate::decide::DecisionRecord;
use mg_core::Action;
use mg_edge_core::upstream::is_upstream_family;
use mg_proto::v1::OriginHeaderConfig;
use pingora::http::{RequestHeader, ResponseHeader};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// The client's header field lines: `(name as sent, value)`.
pub fn raw_headers(req: &RequestHeader) -> Vec<(String, Vec<u8>)> {
    if req.has_case() {
        req.case_header_iter()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name.as_slice()).into_owned(),
                    value.as_bytes().to_vec(),
                )
            })
            .collect()
    } else {
        req.headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect()
    }
}

/// Borrowed `(name, value)` slices of [`raw_headers`], the input shape of
/// `mg_edge_core::{upstream, request}`.
pub fn as_slices(raw: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    raw.iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect()
}

/// Lower-cased names of the upstream-family headers among `raw`.
pub fn family_names(raw: &[(String, Vec<u8>)]) -> BTreeSet<String> {
    raw.iter()
        .filter(|(n, _)| is_upstream_family(n))
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect()
}

/// Distinct lower-cased names of `raw` that are not in `removed`: the
/// §9.3.1 distinct-name count after hygiene.
pub fn distinct_after(raw: &[(String, Vec<u8>)], removed: &BTreeSet<String>) -> usize {
    raw.iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .filter(|n| !removed.contains(n))
        .collect::<BTreeSet<_>>()
        .len()
}

/// Removes every header whose lower-cased name is in `names`.
pub fn remove_names<'a>(req: &mut RequestHeader, names: impl IntoIterator<Item = &'a String>) {
    for name in names {
        req.remove_header(name.as_str());
    }
}

/// The single value of `name` in `raw` (case-insensitive), `None` if absent
/// or repeated.
pub fn single_value<'a>(raw: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    let mut found = raw.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let first = found.next()?;
    found.next().is_none().then_some(first.1.as_slice())
}

/// Whether `name` is an Edge-owned header: `MG-*` in any case, and also
/// `MG_*`, because CGI-style origins (PHP, WSGI, Rack) map `-` and `_` to the
/// same `HTTP_MG_*` variable.
pub fn is_edge_owned(name: &str) -> bool {
    match name.as_bytes() {
        [m, g, sep, ..] => {
            m.eq_ignore_ascii_case(&b'm')
                && g.eq_ignore_ascii_case(&b'g')
                && matches!(sep, b'-' | b'_')
        }
        _ => false,
    }
}

/// Removes every Edge-owned header from an origin response (§9.9); returns
/// how many names were removed.
pub fn strip_edge_owned(resp: &mut ResponseHeader) -> usize {
    let owned: Vec<_> = resp
        .headers
        .keys()
        .filter(|name| is_edge_owned(name.as_str()))
        .cloned()
        .collect();
    for name in &owned {
        resp.remove_header(name);
    }
    owned.len()
}

/// Cloudflare headers the Edge re-writes for an authenticated `cloudflare`
/// request (§9.9), as the client's upstream sent them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareForward {
    /// `CF-IPCountry`, only when the site trusts location headers.
    pub ip_country: Option<Vec<u8>>,
    pub ray: Option<Vec<u8>>,
    pub visitor: Option<Vec<u8>>,
}

/// The decision headers of a forwarded request (see the module
/// documentation). Values that are not valid header values (impossible for
/// what the Edge produces) are left out rather than failing the request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionHeaders {
    pub score: Option<u8>,
    pub class: Option<&'static str>,
    /// `crawler:<operator>`.
    pub verified: Option<String>,
    pub session: Option<String>,
    pub tags: Vec<String>,
    pub reasons: Option<String>,
}

impl DecisionHeaders {
    /// The headers of an evaluated request under `cfg`.
    pub fn from_record(rec: &DecisionRecord, cfg: &OriginHeaderConfig) -> Self {
        let crawler = &rec.ctx.identity.crawler;
        Self {
            score: cfg.scores.then(|| rec.risk.score.get()),
            class: cfg.scores.then(|| rec.risk.bot_class.as_str()),
            verified: (cfg.scores && crawler.is_verified())
                .then(|| crawler.operator.as_ref().map(|op| format!("crawler:{op}")))
                .flatten(),
            session: rec.ctx.session_id.clone().filter(|_| cfg.session),
            tags: if rec.decision.action == Action::Tag {
                rec.decision.tags.clone()
            } else {
                Vec::new()
            },
            reasons: (cfg.reasons && !rec.risk.top_reasons.is_empty())
                .then(|| rec.risk.top_reasons.join(",")),
        }
    }

    fn apply(&self, req: &mut RequestHeader) -> pingora::Result<()> {
        let tags = (!self.tags.is_empty()).then(|| self.tags.join(","));
        let score = self.score.map(|s| s.to_string());
        for (name, value) in [
            ("MG-Bot-Score", score.as_deref()),
            ("MG-Bot-Class", self.class),
            ("MG-Verified", self.verified.as_deref()),
            ("MG-Session", self.session.as_deref()),
            ("MG-Tags", tags.as_deref()),
            ("MG-Reasons", self.reasons.as_deref()),
        ] {
            if let Some(v) = value.filter(|v| is_header_value(v)) {
                req.insert_header(name, v)?;
            }
        }
        Ok(())
    }
}

/// Visible ASCII, space and tab only: a safe `field-value` (RFC 9110).
fn is_header_value(v: &str) -> bool {
    v.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

/// What [`OriginHeaders::apply`] writes to the upstream request. Its `Debug`
/// never shows the client address (D-31).
#[derive(Clone, PartialEq, Eq)]
pub struct OriginHeaders<'a> {
    /// The normalized host the site was selected by (§9.4 step 1).
    pub host: &'a str,
    pub request_id: &'a str,
    /// `None`: client IP unknown (`MG-Client-IP: unknown`, no XFF, no
    /// `CF-Connecting-IP`).
    pub client_ip: Option<IpAddr>,
    /// `X-Forwarded-Proto`.
    pub https: bool,
    /// `Some` for authenticated `cloudflare` requests.
    pub cloudflare: Option<&'a CloudflareForward>,
    /// A WebSocket upgrade: forward `Connection: upgrade` (the client's
    /// `Connection` field is never forwarded).
    pub websocket: bool,
    /// The decision headers of an evaluated request.
    pub decision: Option<&'a DecisionHeaders>,
}

impl std::fmt::Debug for OriginHeaders<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginHeaders")
            .field("host", &self.host)
            .field("request_id", &self.request_id)
            .field("client_ip", &crate::context::redacted_ip(self.client_ip))
            .field("https", &self.https)
            .field("cloudflare", &self.cloudflare)
            .field("websocket", &self.websocket)
            .field("decision", &self.decision)
            .finish()
    }
}

impl OriginHeaders<'_> {
    /// Rewrites `req` for the origin (see the module documentation).
    pub fn apply(&self, req: &mut RequestHeader) -> pingora::Result<()> {
        let families: Vec<String> = req
            .headers
            .keys()
            .filter(|n| is_upstream_family(n.as_str()))
            .map(|n| n.as_str().to_owned())
            .collect();
        for name in &families {
            req.remove_header(name.as_str());
        }
        req.insert_header("Host", self.host)?;
        let ip = self.client_ip.map(|ip| ip.to_canonical().to_string());
        req.insert_header("MG-Client-IP", ip.as_deref().unwrap_or("unknown"))?;
        req.insert_header("MG-Request-Id", self.request_id)?;
        if let Some(ip) = &ip {
            req.insert_header("X-Forwarded-For", ip.as_str())?;
        }
        req.insert_header(
            "X-Forwarded-Proto",
            if self.https { "https" } else { "http" },
        )?;
        if let Some(cf) = self.cloudflare {
            for (name, value) in [
                ("CF-IPCountry", &cf.ip_country),
                ("Cf-Ray", &cf.ray),
                ("CF-Visitor", &cf.visitor),
            ] {
                if let Some(v) = value {
                    req.insert_header(name, pingora::http::header_value_from_slice(v))?;
                }
            }
            if let Some(ip) = &ip {
                req.insert_header("CF-Connecting-IP", ip.as_str())?;
            }
        }
        if self.websocket {
            req.insert_header("Connection", "upgrade")?;
        }
        if let Some(d) = self.decision {
            d.apply(req)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (n, v) in headers {
            req.append_header(n.to_string(), *v).unwrap();
        }
        req
    }

    #[test]
    fn recognises_edge_owned_names() {
        for name in [
            "mg-bot-score",
            "MG-Request-Id",
            "Mg-",
            "mg_bot_score",
            "MG_Verified",
        ] {
            assert!(is_edge_owned(name), "{name}");
        }
        for name in ["x-mg-cf-asn", "mgx-foo", "mg", "", "x_mg_foo"] {
            assert!(!is_edge_owned(name), "{name}");
        }
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("MG-Session", "x").unwrap();
        resp.insert_header("mg_bot_class", "human").unwrap();
        resp.insert_header("Content-Type", "text/plain").unwrap();
        assert_eq!(strip_edge_owned(&mut resp), 2);
        assert_eq!(resp.headers.len(), 1);
    }

    #[test]
    fn raw_headers_keep_case_and_repeats() {
        let req = request(&[("Host", "example.com"), ("X-A", "1"), ("x-a", "2")]);
        let raw = raw_headers(&req);
        assert_eq!(raw.len(), 3);
        assert_eq!(raw[0].0, "Host");
        assert_eq!(single_value(&raw, "host"), Some(&b"example.com"[..]));
        assert_eq!(single_value(&raw, "x-a"), None, "repeated");
        assert_eq!(single_value(&raw, "missing"), None);
        let fam = family_names(&[
            ("CF_Connecting_IP".into(), b"1".to_vec()),
            ("X-Forwarded-For".into(), b"1".to_vec()),
            ("Accept".into(), b"*/*".to_vec()),
        ]);
        assert_eq!(
            fam.into_iter().collect::<Vec<_>>(),
            ["cf_connecting_ip", "x-forwarded-for"]
        );
    }

    #[test]
    fn origin_headers_for_a_known_cloudflare_client() {
        let mut req = request(&[
            ("Host", "Example.COM:443"),
            ("CF-Connecting-IP", "198.51.100.7"),
            ("cf_connecting_ip", "10.0.0.1"),
            ("X-Forwarded-For", "10.0.0.1, 10.0.0.2"),
            ("MG-Client-IP", "10.0.0.1"),
            ("X-MG-CF-ASN", "1"),
            ("Forwarded", "for=10.0.0.1"),
            // I-29.
            ("X-Original-URL", "/admin"),
            ("x_http_method_override", "DELETE"),
            ("X-Client-IP", "10.0.0.5"),
            ("Accept", "*/*"),
        ]);
        let cf = CloudflareForward {
            ip_country: Some(b"HK".to_vec()),
            ray: Some(b"8f00aa-HKG".to_vec()),
            visitor: Some(br#"{"scheme":"https"}"#.to_vec()),
        };
        OriginHeaders {
            host: "example.com",
            request_id: "0123456789abcdef0123456789abcdef",
            client_ip: Some("::ffff:198.51.100.7".parse().unwrap()),
            https: true,
            cloudflare: Some(&cf),
            websocket: false,
            decision: None,
        }
        .apply(&mut req)
        .unwrap();
        let h = &req.headers;
        assert_eq!(h["host"], "example.com");
        assert_eq!(h["mg-client-ip"], "198.51.100.7");
        assert_eq!(h["mg-request-id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(h["x-forwarded-for"], "198.51.100.7");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["cf-connecting-ip"], "198.51.100.7");
        assert_eq!(h.get_all("cf-connecting-ip").iter().count(), 1);
        assert_eq!(h["cf-ipcountry"], "HK");
        assert_eq!(h["cf-ray"], "8f00aa-HKG");
        assert_eq!(h["cf-visitor"], r#"{"scheme":"https"}"#);
        assert!(h.get("cf_connecting_ip").is_none());
        assert!(h.get("x-mg-cf-asn").is_none());
        assert!(h.get("forwarded").is_none());
        for name in ["x-original-url", "x_http_method_override", "x-client-ip"] {
            assert!(h.get(name).is_none(), "{name}");
        }
        assert_eq!(h["accept"], "*/*");
        assert!(h.get("connection").is_none());
    }

    #[test]
    fn origin_headers_for_an_unknown_client() {
        let mut req = request(&[
            ("CF-Connecting-IP", "not-an-ip"),
            ("X-Forwarded-For", "203.0.113.9"),
        ]);
        OriginHeaders {
            host: "example.com",
            request_id: "r",
            client_ip: None,
            https: false,
            cloudflare: Some(&CloudflareForward::default()),
            websocket: true,
            decision: None,
        }
        .apply(&mut req)
        .unwrap();
        let h = &req.headers;
        assert_eq!(h["mg-client-ip"], "unknown");
        assert!(h.get("x-forwarded-for").is_none());
        assert!(h.get("cf-connecting-ip").is_none());
        assert_eq!(h["x-forwarded-proto"], "http");
        assert_eq!(h["connection"], "upgrade");
    }

    /// §2.4 item 5: `Debug` of what goes to the origin never shows the
    /// client address.
    #[test]
    fn origin_headers_debug_has_no_client_address() {
        let h = OriginHeaders {
            host: "example.com",
            request_id: "r",
            client_ip: Some("203.0.113.77".parse().unwrap()),
            https: true,
            cloudflare: None,
            websocket: false,
            decision: None,
        };
        let text = format!("{h:?}");
        assert!(!text.contains("203.0.113.77"), "{text}");
        assert!(text.contains("example.com"), "{text}");
    }

    #[test]
    fn decision_headers() {
        let mut req = request(&[("MG-Tags", "forged"), ("mg_bot_score", "0")]);
        let d = DecisionHeaders {
            score: Some(87),
            class: Some("impersonator"),
            verified: None,
            session: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
            tags: vec!["legacy_browser".into(), "b".into()],
            reasons: Some("http.ua_library,net.datacenter".into()),
        };
        OriginHeaders {
            host: "example.com",
            request_id: "r",
            client_ip: None,
            https: true,
            cloudflare: None,
            websocket: false,
            decision: Some(&d),
        }
        .apply(&mut req)
        .unwrap();
        let h = &req.headers;
        assert_eq!(h["mg-bot-score"], "87");
        assert_eq!(h["mg-bot-class"], "impersonator");
        assert_eq!(h["mg-session"], "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(h.get_all("mg-tags").iter().count(), 1);
        assert_eq!(h["mg-tags"], "legacy_browser,b");
        assert_eq!(h["mg-reasons"], "http.ua_library,net.datacenter");
        assert!(h.get("mg-verified").is_none());
        assert!(
            h.get("mg_bot_score").is_none(),
            "client MG_* never survives"
        );
        // An invalid value is skipped, not an error.
        let bad = DecisionHeaders {
            verified: Some("crawler:\nX".into()),
            ..DecisionHeaders::default()
        };
        let mut req = request(&[]);
        bad.apply(&mut req).unwrap();
        assert!(req.headers.get("mg-verified").is_none());
    }
}
