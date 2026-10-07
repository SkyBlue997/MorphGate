//! Responses the Edge generates itself (docs/impl/phase1-spec.md §9.9,
//! §9.3.1, §9.4, §10).
//!
//! Every one carries `X-Content-Type-Options: nosniff`, `Cache-Control:
//! no-store, private` unless it is an SDK file (`/__mg/s/*`, immutable,
//! §10.4), and never an `MG-*` header except `MG-Challenge` on a JSON
//! challenge (§10.2). A response sent before the request body was read
//! closes the connection (`set_keepalive(None)`, §9.9): Pingora 0.9 drains
//! the rest of the body before reusing a keep-alive connection, with no total
//! deadline. Its `close_on_response_before_downstream_finish` default happens
//! to close such connections too; the explicit close keeps §9.9 independent
//! of that default.
//!
//! WP-E1a produces the plain-text protocol, trust and site-state answers;
//! WP-E1b the block and rate-limit answers (§9.9): an HTML page for
//! navigation requests ([`is_navigation`]), JSON otherwise, both with the
//! request id and nothing else about the decision. HTML answers also carry
//! `X-Robots-Tag: noindex`, `Referrer-Policy: same-origin`,
//! `X-Frame-Options: DENY` and a CSP: [`HTML_CSP`], which allows nothing
//! (the pages have no scripts, styles or subresources), or the challenge
//! page's nonce policy (WP-E1c, [`crate::pages`]).

use crate::decide::{CLIENT_IP_UNKNOWN_RETRY_S, Enforcement};
use bytes::Bytes;
use mg_edge_core::request::Reject;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

/// Cache policy of everything the Edge answers itself.
pub const NO_STORE: &str = "no-store, private";
/// Cache policy of the SDK files (`/__mg/s/*`, content-hashed names, §10.4).
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// CSP of the Edge's static HTML answers.
pub const HTML_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub(crate) const TEXT: &str = "text/plain; charset=utf-8";
pub(crate) const HTML: &str = "text/html; charset=utf-8";
pub(crate) const JSON: &str = "application/json";
/// `Content-Type` of the SDK files (§10.4).
pub(crate) const JAVASCRIPT: &str = "text/javascript; charset=utf-8";

/// A navigation request (§9.9): `Sec-Fetch-Mode: navigate`, or no
/// `Sec-Fetch-Mode` and an `Accept` that includes `text/html`. `headers` is
/// the sorted §4.1 `req.headers` list.
pub fn is_navigation(headers: &[(String, String)]) -> bool {
    match crate::context::header(headers, "sec-fetch-mode") {
        Some(mode) => mode.trim().eq_ignore_ascii_case("navigate"),
        None => crate::context::header(headers, "accept")
            .is_some_and(|a| a.to_ascii_lowercase().contains("text/html")),
    }
}

/// The request id as it may appear in a body: 32 lower-case hex characters
/// (anything else, which the Edge never generates, is left out).
pub(crate) fn safe_id(request_id: &str) -> &str {
    if request_id.len() == 32 && request_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        request_id
    } else {
        "-"
    }
}

/// A response produced by the Edge. Its `Debug` shows the status, the
/// header names and the body size only: bodies can carry a sealed challenge
/// and `Set-Cookie` a clearance token (§2.4 item 4).
#[derive(Clone, PartialEq, Eq)]
pub struct EdgeResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Bytes,
    /// Extra headers (`Allow`, `Retry-After`, `Location`, `Set-Cookie`,
    /// `MG-Challenge`). Values must be visible ASCII.
    pub headers: Vec<(&'static str, String)>,
    /// `Cache-Control` ([`NO_STORE`] except SDK files).
    pub cache_control: &'static str,
    /// The CSP of an HTML answer; `None` = [`HTML_CSP`].
    pub csp: Option<String>,
    /// Close the connection after the response (answered before the body
    /// was read).
    pub close: bool,
}

impl std::fmt::Debug for EdgeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| *n).collect();
        f.debug_struct("EdgeResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .field("headers", &names)
            .field("cache_control", &self.cache_control)
            .field("csp", &self.csp.is_some())
            .field("close", &self.close)
            .finish()
    }
}

impl EdgeResponse {
    /// A response with the common headers and a body of `content_type`.
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            headers: Vec::new(),
            cache_control: NO_STORE,
            csp: None,
            close: true,
        }
    }

    fn plain(status: u16, body: &'static str) -> Self {
        Self::new(status, TEXT, Bytes::from_static(body.as_bytes()))
    }

    fn page(status: u16, navigation: bool, html: String, json: String) -> Self {
        if navigation {
            Self::new(status, HTML, html)
        } else {
            Self::new(status, JSON, json)
        }
    }

    /// The body as text (every Edge body is UTF-8; empty otherwise).
    pub fn body_text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or_default()
    }

    /// Adds a header.
    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// BLOCK (§9.9): 403, a generic page with the request id, or
    /// `{"error":"mg_blocked","request_id":"…"}`.
    pub fn blocked(request_id: &str, navigation: bool) -> Self {
        let id = safe_id(request_id);
        Self::page(
            403,
            navigation,
            format!(
                "<!doctype html>\n<html lang=\"zh\"><head><meta charset=\"utf-8\">\
                 <meta name=\"viewport\" content=\"width=device-width\">\
                 <title>访问被拒绝 / Access denied</title></head><body>\
                 <h1>访问被拒绝 / Access denied</h1>\
                 <p>如有疑问请联系站点所有者。If you think this is a mistake, please contact the site owner.</p>\
                 <p>Request ID: <code>{id}</code></p></body></html>\n"
            ),
            format!("{{\"error\":\"mg_blocked\",\"request_id\":\"{id}\"}}"),
        )
    }

    /// RATE_LIMIT (§9.9, §10.3): 429 + `Retry-After`, a short page ("请求过
    /// 多") with the request id, or `{"error":"mg_rate_limited",
    /// "retry_after":N,"request_id":"…"}`.
    pub fn rate_limited(request_id: &str, retry_after_s: u32, navigation: bool) -> Self {
        let id = safe_id(request_id);
        Self::page(
            429,
            navigation,
            format!(
                "<!doctype html>\n<html lang=\"zh\"><head><meta charset=\"utf-8\">\
                 <meta name=\"viewport\" content=\"width=device-width\">\
                 <title>请求过多 / Too many requests</title></head><body>\
                 <h1>请求过多 / Too many requests</h1>\
                 <p>请 {retry_after_s} 秒后再试。Please try again in {retry_after_s} seconds.</p>\
                 <p>Request ID: <code>{id}</code></p></body></html>\n"
            ),
            format!(
                "{{\"error\":\"mg_rate_limited\",\"retry_after\":{retry_after_s},\"request_id\":\"{id}\"}}"
            ),
        )
        .with("Retry-After", retry_after_s.to_string())
    }

    /// `Early-Data: 1` on a critical route (§9.9): 425, retry without
    /// 0-RTT.
    pub fn too_early() -> Self {
        Self::plain(425, "too early")
    }

    /// The answer to an evaluated request (§9.9), `None` when it is
    /// forwarded. `navigation` is only called for answers that have an HTML
    /// and a JSON form.
    ///
    /// A CHALLENGE with a known client IP is answered by
    /// [`crate::challenge::respond`] (it needs the site's sealer and the SDK
    /// directory); the proxy never passes one here. Should it happen, the
    /// answer is a 503 rather than anything that lets the request through.
    pub fn for_enforcement(
        e: Enforcement,
        request_id: &str,
        navigation: impl FnOnce() -> bool,
    ) -> Option<Self> {
        Some(match e {
            Enforcement::Forward => return None,
            Enforcement::Block => Self::blocked(request_id, navigation()),
            Enforcement::RateLimit { retry_after_s } => {
                Self::rate_limited(request_id, retry_after_s, navigation())
            }
            // D-23: never a `C` for an unknown client IP.
            Enforcement::ChallengeClientIpUnknown => {
                Self::rate_limited(request_id, CLIENT_IP_UNKNOWN_RETRY_S, navigation())
            }
            Enforcement::Challenge(_) => Self::internal_unavailable(),
            Enforcement::TooEarly => Self::too_early(),
        })
    }

    /// `GET` / `HEAD /__mg/healthz`.
    pub fn healthz() -> Self {
        Self {
            close: false,
            ..Self::plain(200, "ok")
        }
    }

    /// 405 for a method the endpoint does not serve.
    pub fn method_not_allowed(allow: &'static str) -> Self {
        Self::plain(405, "method not allowed").with("Allow", allow)
    }

    /// 404 for a reserved `/__mg/*` path.
    pub fn not_found() -> Self {
        Self::plain(404, "not found")
    }

    /// 404 for a host no site serves (§9.4 step 1).
    pub fn unknown_site() -> Self {
        Self::plain(404, "unknown site")
    }

    /// 403 for upstream authentication failures, foreign Workers and
    /// listeners that may not serve the site (§9.2, §9.4).
    pub fn forbidden() -> Self {
        Self::plain(403, "forbidden")
    }

    /// 503 for `lkg_invalid` / `bootstrap_closed` sites (§9.4 step 3).
    pub fn site_unavailable() -> Self {
        Self::plain(503, "site unavailable").with("Retry-After", "30")
    }

    /// 503 when the Edge itself cannot proceed (e.g. the RNG failed, §9.9).
    pub fn internal_unavailable() -> Self {
        Self::plain(503, "service unavailable")
    }

    /// Pingora's proxy failures (origin unreachable: 502; malformed
    /// downstream request: 400; internal: 500), with the common headers.
    pub fn error(status: u16) -> Self {
        let body = match status {
            400 => "bad request",
            502 => "bad gateway",
            503 => "service unavailable",
            504 => "gateway timeout",
            _ => "error",
        };
        Self::plain(status, body)
    }

    /// The §9.3.1 protocol rejections: 414 / 431 / 400.
    pub fn protocol(reject: Reject) -> Self {
        let body = match reject {
            Reject::UriTooLong => "uri too long",
            Reject::HeaderTooLarge => "request header fields too large",
            Reject::BadMethod => "bad method",
            Reject::BadHost => "bad host",
        };
        Self::plain(reject.status(), body)
    }

    /// The response header with the §9.9 common headers.
    pub fn header(&self) -> pingora::Result<ResponseHeader> {
        let mut h = ResponseHeader::build(self.status, Some(10 + self.headers.len()))?;
        h.insert_header("Content-Type", self.content_type)?;
        h.insert_header("Content-Length", self.body.len())?;
        h.insert_header("Cache-Control", self.cache_control)?;
        h.insert_header("X-Content-Type-Options", "nosniff")?;
        if self.content_type == HTML {
            h.insert_header("X-Robots-Tag", "noindex")?;
            h.insert_header("Referrer-Policy", "same-origin")?;
            h.insert_header("X-Frame-Options", "DENY")?;
            h.insert_header(
                "Content-Security-Policy",
                self.csp.as_deref().unwrap_or(HTML_CSP),
            )?;
        }
        for (name, value) in &self.headers {
            h.append_header(*name, value.as_str())?;
        }
        Ok(h)
    }

    /// Writes the response (headers only for `HEAD`).
    pub async fn send(&self, session: &mut Session) -> pingora::Result<()> {
        if self.close {
            session.set_keepalive(None);
        }
        let head_only = session.req_header().method == pingora::http::Method::HEAD;
        session
            .write_response_header(Box::new(self.header()?), head_only)
            .await?;
        if !head_only {
            session
                .write_response_body(Some(self.body.clone()), true)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_responses_are_never_cacheable() {
        for resp in [
            EdgeResponse::healthz(),
            EdgeResponse::method_not_allowed("GET, HEAD"),
            EdgeResponse::not_found(),
            EdgeResponse::unknown_site(),
            EdgeResponse::forbidden(),
            EdgeResponse::site_unavailable(),
            EdgeResponse::internal_unavailable(),
            EdgeResponse::protocol(Reject::UriTooLong),
            EdgeResponse::protocol(Reject::HeaderTooLarge),
            EdgeResponse::protocol(Reject::BadMethod),
            EdgeResponse::protocol(Reject::BadHost),
            EdgeResponse::blocked(ID, true),
            EdgeResponse::blocked(ID, false),
            EdgeResponse::rate_limited(ID, 7, true),
            EdgeResponse::rate_limited(ID, 7, false),
            EdgeResponse::too_early(),
        ] {
            let h = resp.header().unwrap();
            assert_eq!(h.status.as_u16(), resp.status);
            assert_eq!(h.headers["cache-control"], NO_STORE);
            assert_eq!(h.headers["x-content-type-options"], "nosniff");
            assert_eq!(
                h.headers["content-length"],
                resp.body.len().to_string().as_str()
            );
            assert!(
                h.headers.keys().all(|k| !k.as_str().starts_with("mg-")),
                "Edge responses never carry MG-* headers"
            );
            // Only the health check keeps the connection open.
            assert_eq!(resp.close, resp.status != 200, "{}", resp.status);
        }
    }

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn hdrs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = list
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn answers_by_enforcement() {
        use mg_core::ChallengeType;
        let answer = |e| EdgeResponse::for_enforcement(e, ID, || false).map(|r| r.status);
        assert_eq!(answer(Enforcement::Forward), None);
        assert_eq!(answer(Enforcement::Block), Some(403));
        assert_eq!(
            answer(Enforcement::RateLimit { retry_after_s: 9 }),
            Some(429)
        );
        // Challenges are crate::challenge's; this path fails closed.
        assert_eq!(
            answer(Enforcement::Challenge(ChallengeType::Pow)),
            Some(503)
        );
        assert_eq!(answer(Enforcement::TooEarly), Some(425));
        let r = EdgeResponse::for_enforcement(Enforcement::ChallengeClientIpUnknown, ID, || true)
            .unwrap();
        assert_eq!(r.status, 429);
        assert_eq!(r.content_type, HTML);
        assert!(r.headers.contains(&("Retry-After", "5".to_string())));
        // Forwarded requests never pay for the header scan.
        assert!(
            EdgeResponse::for_enforcement(Enforcement::Forward, ID, || unreachable!()).is_none()
        );
        for e in [
            Enforcement::Forward,
            Enforcement::Block,
            Enforcement::TooEarly,
        ] {
            assert_eq!(
                answer(e),
                e.status(),
                "Enforcement::status agrees with the answer"
            );
        }
    }

    #[test]
    fn navigation_requests() {
        assert!(is_navigation(&hdrs(&[("sec-fetch-mode", "navigate")])));
        assert!(is_navigation(&hdrs(&[("accept", "text/html,*/*")])));
        assert!(!is_navigation(&hdrs(&[
            ("accept", "text/html"),
            ("sec-fetch-mode", "cors")
        ])));
        assert!(!is_navigation(&hdrs(&[("accept", "application/json")])));
        assert!(!is_navigation(&[]));
    }

    /// §9.9 bodies: the request id and nothing else about the decision.
    #[test]
    fn block_and_rate_limit_bodies() {
        let b = EdgeResponse::blocked(ID, false);
        assert_eq!((b.status, b.content_type), (403, JSON));
        let v: serde_json::Value = serde_json::from_str(b.body_text()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"error": "mg_blocked", "request_id": ID})
        );
        let r = EdgeResponse::rate_limited(ID, 30, false);
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"error": "mg_rate_limited", "retry_after": 30, "request_id": ID})
        );
        let h = r.header().unwrap();
        assert_eq!(h.status.as_u16(), 429);
        assert_eq!(h.headers["retry-after"], "30");
        let page = EdgeResponse::rate_limited(ID, 30, true);
        assert!(page.body_text().contains("请求过多") && page.body_text().contains(ID));
        let h = page.header().unwrap();
        assert_eq!(h.headers["x-robots-tag"], "noindex");
        assert_eq!(h.headers["x-frame-options"], "DENY");
        assert_eq!(h.headers["referrer-policy"], "same-origin");
        assert_eq!(h.headers["content-security-policy"], HTML_CSP);
        let page = EdgeResponse::blocked(ID, true);
        assert!(
            page.body_text().contains("如有疑问请联系站点所有者") && page.body_text().contains(ID)
        );
        assert!(!page.body_text().contains("<script"));
        // Anything that is not an Edge request id never reaches a body.
        let odd = EdgeResponse::blocked("<script>", true);
        assert!(!odd.body_text().contains("<script>"));
    }

    #[test]
    fn statuses_and_extra_headers() {
        assert_eq!(EdgeResponse::protocol(Reject::UriTooLong).status, 414);
        assert_eq!(EdgeResponse::protocol(Reject::HeaderTooLarge).status, 431);
        assert_eq!(EdgeResponse::protocol(Reject::BadHost).status, 400);
        let h = EdgeResponse::site_unavailable().header().unwrap();
        assert_eq!(h.status.as_u16(), 503);
        assert_eq!(h.headers["retry-after"], "30");
        let h = EdgeResponse::method_not_allowed("GET, HEAD")
            .header()
            .unwrap();
        assert_eq!(h.headers["allow"], "GET, HEAD");
        // A per-response CSP replaces the static one; the cache policy can
        // be the SDK files' immutable one.
        let mut r = EdgeResponse::new(200, HTML, "x");
        r.csp = Some("default-src 'none'; script-src 'nonce-abc'".into());
        r.cache_control = IMMUTABLE;
        let h = r.header().unwrap();
        assert_eq!(
            h.headers["content-security-policy"],
            "default-src 'none'; script-src 'nonce-abc'"
        );
        assert_eq!(h.headers["cache-control"], IMMUTABLE);
    }
}
