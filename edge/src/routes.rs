//! Paths the Edge answers itself.
//!
//! `/__mg/*` is the Edge's reserved namespace (health, and from Phase 1/2 the
//! SDK, challenge and token endpoints). Requests under it never reach the
//! origin. Every Edge-generated response carries `Cache-Control: no-store,
//! private` so that no CDN in front (Cloudflare's Origin Cache Control is
//! always on) can store it (docs/08).
//!
//! Cloudflare matches its rules against a *normalized* path but forwards the
//! raw one, and the `/__mg/` rules in `adapters/cloudflare` skip bot checks,
//! rate limiting and caching. So the namespace test here runs on the raw path
//! and on both of Cloudflare's normalizations: any spelling that Cloudflare
//! can treat as `/__mg/...` (`//__mg/x`, `/%5F%5Fmg/x`, `/a/../__mg/x`, ...)
//! is answered by the Edge and never reaches the origin without Cloudflare's
//! protections.

use pingora::http::{Method, ResponseHeader};

/// Reserved path prefix (defined in `mg_core::paths`, shared with mg-challenge).
pub use mg_core::paths::EDGE_PREFIX;
/// Path views used for the namespace test; they live in `mg_core::paths` so
/// that the Edge and mg-challenge's return-path check share one implementation.
pub use mg_core::paths::{cloudflare_view, rfc3986_view};
/// Liveness endpoint.
pub const HEALTHZ_PATH: &str = "/__mg/healthz";
/// Cache policy for everything the Edge answers itself.
pub const NO_STORE: &str = "no-store, private";

/// Who answers a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
    /// `GET /__mg/healthz`.
    Healthz,
    /// Any other path under `/__mg`: reserved, answered 404 for now.
    EdgeReserved,
    /// Everything else: proxied to the origin.
    #[default]
    Origin,
}

impl RouteKind {
    /// Low-cardinality label for metrics.
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Healthz => "healthz",
            Self::EdgeReserved => "edge",
            Self::Origin => "origin",
        }
    }
}

/// Classifies a request path (without query string).
///
/// Only the exact raw path `/__mg/healthz` is the health check. A path is in
/// the reserved namespace if its raw form, its RFC 3986 form or its Cloudflare
/// form (see [`rfc3986_view`], [`cloudflare_view`]) is `/__mg` or starts with
/// `/__mg/` ([`mg_core::paths::is_reserved`]).
pub fn classify(path: &str) -> RouteKind {
    if path == HEALTHZ_PATH {
        RouteKind::Healthz
    } else if mg_core::paths::is_reserved(path) {
        RouteKind::EdgeReserved
    } else {
        RouteKind::Origin
    }
}

/// A small, fixed response produced by the Edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalResponse {
    pub status: u16,
    pub body: &'static str,
    /// `Allow` header value for 405 responses.
    pub allow: Option<&'static str>,
}

/// The Edge's own answer for `kind`, or `None` if the origin should answer.
pub fn local_response(kind: RouteKind, method: &Method) -> Option<LocalResponse> {
    match kind {
        RouteKind::Origin => None,
        RouteKind::Healthz if method == Method::GET || method == Method::HEAD => {
            Some(LocalResponse {
                status: 200,
                body: "ok",
                allow: None,
            })
        }
        RouteKind::Healthz => Some(LocalResponse {
            status: 405,
            body: "method not allowed",
            allow: Some("GET, HEAD"),
        }),
        RouteKind::EdgeReserved => Some(LocalResponse {
            status: 404,
            body: "not found",
            allow: None,
        }),
    }
}

/// Response header for a [`LocalResponse`].
pub fn response_header(resp: &LocalResponse) -> pingora::Result<ResponseHeader> {
    let mut h = ResponseHeader::build(resp.status, Some(5))?;
    h.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    h.insert_header("Content-Length", resp.body.len())?;
    h.insert_header("Cache-Control", NO_STORE)?;
    h.insert_header("X-Content-Type-Options", "nosniff")?;
    if let Some(allow) = resp.allow {
        h.insert_header("Allow", allow)?;
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_edge_namespace() {
        assert_eq!(classify("/__mg/healthz"), RouteKind::Healthz);
        assert_eq!(classify("/__mg"), RouteKind::EdgeReserved);
        assert_eq!(classify("/__mg/"), RouteKind::EdgeReserved);
        assert_eq!(classify("/__mg/healthz/extra"), RouteKind::EdgeReserved);
        assert_eq!(classify("/__mg/c"), RouteKind::EdgeReserved);
        assert_eq!(classify("/"), RouteKind::Origin);
        assert_eq!(classify("/__mgx"), RouteKind::Origin);
        assert_eq!(classify("/blog/__mg/healthz"), RouteKind::Origin);
    }

    /// Cloudflare evaluates rules on the normalized path (percent-decoded
    /// unreserved characters, `\` -> `/`, merged slashes, dot segments
    /// removed; or only decoding + dot segments in "RFC 3986" mode) but, by
    /// default, forwards the raw path. Every spelling that its
    /// `starts_with(http.request.uri.path, "/__mg/")` rules (WAF skip, cache
    /// bypass) can match must be answered by the Edge, never proxied.
    #[test]
    fn normalized_spellings_of_the_namespace_are_edge_owned() {
        for path in [
            "//__mg/c",
            "///__mg/healthz",
            "//__mg/healthz",
            "/%5F%5Fmg/c",
            "/%5f%5fmg/c",
            "/_%5Fmg/",
            "/%5F%5F%6D%67/c",
            "/./__mg/c",
            "/%2e/__mg/c",
            "/x/../__mg/c",
            "/x/%2E%2E/__mg/c",
            "/\\__mg/c",
            "/__mg/./healthz",
            "/__mg/..%2F..%2Fadmin",
            "/%5F%5Fmg/..%2F..%2Fadmin",
            "/a//../__mg/x", // "/__mg/x" after Cloudflare's slash merging
            "/__mg//../x",   // "/__mg/x" under plain RFC 3986 dot removal
            "/__mg/%2e%2e",
        ] {
            assert_eq!(classify(path), RouteKind::EdgeReserved, "{path}");
        }
    }

    #[test]
    fn lookalikes_outside_the_namespace_still_go_to_the_origin() {
        for path in [
            "/__mg%2Fc", // %2F is reserved: Cloudflare keeps it encoded
            "/__MG/c",   // rule matching is case-sensitive
            "/x/__mg/c",
            "/__mgx/c",
            "/%5F%5Fmgx",
            "/__mg_/",
            "/a/b/../c",
            "/%7Euser/",
            "/assets//app.js",
            "*",
            "",
        ] {
            assert_eq!(classify(path), RouteKind::Origin, "{path}");
        }
    }

    #[test]
    fn path_views() {
        assert_eq!(cloudflare_view("/a//b/./c/../%7E%41%2f"), "/a/b/~A%2F");
        assert_eq!(rfc3986_view("/a//b/./c/../%7E%41%2f"), "/a//b/~A%2F");
        assert_eq!(cloudflare_view("/a/b/.."), "/a/");
        assert_eq!(cloudflare_view("/.."), "/");
        assert_eq!(rfc3986_view("/%zz/%4"), "/%zz/%4");
        assert_eq!(rfc3986_view("/caf%C3%A9"), "/caf%C3%A9");
    }

    #[test]
    fn healthz_answers_get_and_head_only() {
        let ok = local_response(RouteKind::Healthz, &Method::GET).unwrap();
        assert_eq!((ok.status, ok.body), (200, "ok"));
        assert_eq!(local_response(RouteKind::Healthz, &Method::HEAD), Some(ok));
        let post = local_response(RouteKind::Healthz, &Method::POST).unwrap();
        assert_eq!((post.status, post.allow), (405, Some("GET, HEAD")));
        assert_eq!(
            local_response(RouteKind::EdgeReserved, &Method::GET).map(|r| r.status),
            Some(404)
        );
        assert_eq!(local_response(RouteKind::Origin, &Method::GET), None);
    }

    #[test]
    fn local_responses_are_never_cacheable() {
        for (kind, method) in [
            (RouteKind::Healthz, Method::GET),
            (RouteKind::Healthz, Method::DELETE),
            (RouteKind::EdgeReserved, Method::GET),
        ] {
            let resp = local_response(kind, &method).unwrap();
            let h = response_header(&resp).unwrap();
            assert_eq!(h.status.as_u16(), resp.status);
            assert_eq!(h.headers["cache-control"], NO_STORE);
            assert_eq!(
                h.headers["content-length"],
                resp.body.len().to_string().as_str()
            );
            assert_eq!(h.headers["x-content-type-options"], "nosniff");
        }
    }
}
