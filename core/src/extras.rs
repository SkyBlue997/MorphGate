//! Per-request inputs that are not part of the logged [`crate::RequestContext`]
//! (docs/impl/phase1-spec.md §5.6).
//!
//! The Edge builds one [`RequestExtras`] next to the context: the selected
//! route (with `require_clearance` / `fail_closed` OR-ed over every matching
//! route, §9.4), the sanitized request headers of `req.headers`, the raw
//! query string, this request's rate-limiter observations (§9.8), the policy
//! MISSING set (§4.3) and the parsed User-Agent. None of it is written to the
//! decision event as such; detectors, the scorer and the policy read it.

use crate::enums::{ChallengeType, Channel, RouteSensitivity};
use crate::policy::MissingSet;
use crate::ua::UaInfo;

/// The route the request was matched to (§9.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteInfo {
    /// `Route.id` (equal to the name in Phase 1 bundles).
    pub id: String,
    /// `Route.name`, CEL `route.name`.
    pub name: String,
    /// Environment name, CEL `route.env`.
    pub env: String,
    pub channel: Channel,
    pub sensitivity: RouteSensitivity,
    /// OR over every route that matched any path view (§9.4), not only the selected one.
    pub require_clearance: bool,
    /// OR over every route that matched any path view (§9.4).
    pub fail_closed: bool,
}

/// What an exceeded limiter does (`RateLimit.on_exceed`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LimiterAction {
    /// Becomes RATE-family evidence (`rate.exceeded`, §5.7) instead of a decision.
    /// `weight` is the log-odds contribution, `0 < weight <= 2`.
    Signal { weight: f32 },
    /// Challenge with this type (`interactive` runs as `pow` in Phase 1, D-08).
    Challenge(ChallengeType),
    /// 429; `retry_after_s == 0` means "from the GCRA wait time".
    RateLimit { retry_after_s: u32 },
    /// 403.
    Block,
}

/// One limiter's state for this request (§9.8).
#[derive(Debug, Clone, PartialEq)]
pub struct RateObservation {
    /// `"login-per-ip"`, or a built-in id such as `"mg.c.submit"`.
    pub limiter_id: String,
    /// `[0, 1]`; `1.0` when exceeded (`GcraOutcome::utilization`).
    pub utilization: f32,
    pub exceeded: bool,
    /// GCRA wait time when exceeded, in milliseconds.
    pub retry_after_ms: u64,
    pub action: LimiterAction,
    /// The limiter runs in `dry_run` mode: it is recorded, never enforced.
    pub dry_run: bool,
}

/// Everything the Decision Core needs besides the [`crate::RequestContext`].
#[derive(Debug, Clone, Copy)]
pub struct RequestExtras<'a> {
    pub route: &'a RouteInfo,
    /// §4.1 `req.headers`: sanitized client headers, lower-case names,
    /// repeated headers joined with `", "`, without `cookie`,
    /// `authorization` and `proxy-authorization`. **Sorted by name**, names unique.
    pub headers: &'a [(String, String)],
    /// Raw query string without `?` (`req.query`).
    pub query: &'a str,
    /// Observations of every limiter that applies to this request, in bundle
    /// declaration order (built-in limiters first).
    pub rate: &'a [RateObservation],
    /// Policy fields that are MISSING on this request (§4.3).
    pub missing: &'a MissingSet,
    /// `mg_core::ua::parse` of the User-Agent header.
    pub ua: &'a UaInfo,
    /// The visitor used https (`direct_tls`, or `CF-Visitor` scheme `https`).
    pub secure_context: bool,
}

impl RequestExtras<'_> {
    /// The value of request header `name` (lower-case), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .binary_search_by(|(k, _)| k.as_str().cmp(name))
            .ok()
            .map(|i| self.headers[i].1.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_uses_sorted_names() {
        let headers = vec![
            ("accept".to_string(), "text/html".to_string()),
            ("sec-fetch-mode".to_string(), "navigate".to_string()),
            ("user-agent".to_string(), "x".to_string()),
        ];
        let route = RouteInfo::default();
        let missing = MissingSet::default();
        let ua = crate::ua::parse("x");
        let extras = RequestExtras {
            route: &route,
            headers: &headers,
            query: "",
            rate: &[],
            missing: &missing,
            ua: &ua,
            secure_context: true,
        };
        assert_eq!(extras.header("accept"), Some("text/html"));
        assert_eq!(extras.header("sec-fetch-mode"), Some("navigate"));
        assert_eq!(extras.header("user-agent"), Some("x"));
        assert_eq!(extras.header("accept-language"), None);
        assert_eq!(extras.header("Accept"), None, "names are lower-case");
    }
}
