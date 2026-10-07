//! Paths the Edge answers itself.
//!
//! `/__mg/*` is the Edge's reserved namespace (health, the SDK files and the
//! challenge submission in Phase 1; the token endpoints in Phase 2). Requests
//! under it never reach the origin; they are answered after the site is
//! resolved (§9.4 step 4) and before route matching (§10.1). The endpoints
//! are served only under their exact raw paths; every other spelling of the
//! namespace is reserved (404). The responses themselves are built in
//! [`crate::enforce`] and [`crate::mg_endpoints`].
//!
//! Cloudflare matches its rules against a *normalized* path but forwards the
//! raw one, and the `/__mg/` rules in `adapters/cloudflare` skip bot checks,
//! rate limiting and caching. So the namespace test here runs on the raw path
//! and on both of Cloudflare's normalizations: any spelling that Cloudflare
//! can treat as `/__mg/...` (`//__mg/x`, `/%5F%5Fmg/x`, `/a/../__mg/x`, ...)
//! is answered by the Edge and never reaches the origin without Cloudflare's
//! protections.

/// Reserved path prefix (defined in `mg_core::paths`, shared with mg-challenge).
pub use mg_core::paths::EDGE_PREFIX;
/// Path views used for the namespace test; they live in `mg_core::paths` so
/// that the Edge and mg-challenge's return-path check share one implementation.
pub use mg_core::paths::{cloudflare_view, rfc3986_view};
/// Liveness endpoint.
pub const HEALTHZ_PATH: &str = "/__mg/healthz";
/// Challenge submission endpoint (§10.3).
pub const SUBMIT_PATH: &str = "/__mg/c";
/// Prefix of the SDK files (§10.4): `/__mg/s/<file>`.
pub const SDK_PREFIX: &str = "/__mg/s/";

/// Who answers a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
    /// `GET /__mg/healthz`.
    Healthz,
    /// `/__mg/s/<file>`: an SDK file (§10.4).
    SdkFile,
    /// `POST /__mg/c`: a challenge submission (§10.3).
    Submit,
    /// Any other path under `/__mg`: reserved, answered 404.
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
            Self::SdkFile | Self::Submit | Self::EdgeReserved => "edge",
            Self::Origin => "origin",
        }
    }
}

/// Classifies a request path (without query string).
///
/// Only the exact raw paths are endpoints: `/__mg/healthz`, `/__mg/c` and
/// `/__mg/s/<file>` (the file name is checked against the SDK manifest by
/// [`crate::mg_endpoints::sdk_file`]). A path is in the reserved namespace if
/// its raw form, its RFC 3986 form or its Cloudflare form (see
/// [`rfc3986_view`], [`cloudflare_view`]) is `/__mg` or starts with `/__mg/`
/// ([`mg_core::paths::is_reserved`]).
pub fn classify(path: &str) -> RouteKind {
    if path == HEALTHZ_PATH {
        RouteKind::Healthz
    } else if path == SUBMIT_PATH {
        RouteKind::Submit
    } else if path.starts_with(SDK_PREFIX) {
        RouteKind::SdkFile
    } else if mg_core::paths::is_reserved(path) {
        RouteKind::EdgeReserved
    } else {
        RouteKind::Origin
    }
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
        assert_eq!(classify("/__mg/c"), RouteKind::Submit);
        assert_eq!(classify("/__mg/c/renew"), RouteKind::EdgeReserved);
        assert_eq!(classify("/__mg/r"), RouteKind::EdgeReserved);
        assert_eq!(classify("/__mg/t"), RouteKind::EdgeReserved);
        assert_eq!(
            classify("/__mg/s/mg.0123456789abcdef.js"),
            RouteKind::SdkFile
        );
        assert_eq!(classify("/__mg/s/"), RouteKind::SdkFile);
        assert_eq!(classify("/__mg/s"), RouteKind::EdgeReserved);
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
            "/__mg/c/",
            "/__mg/%63",
            "//__mg/s/mg.js",
            "/%5F%5Fmg/s/mg.js",
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
}
