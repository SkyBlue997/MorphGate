//! Request normalization and protocol limits (docs/impl/phase1-spec.md
//! §9.3.1, §9.4 step 1, §4.1 size caps; work package WP-C1).
//!
//! * [`check_limits`] / [`check_limits_detailed`] and [`check_header_count`]
//!   enforce the policy-input invariants of D-26: path and query ≤ 8 KiB
//!   (414), header values ≤ 8 KiB and names ≤ 256 bytes, at most 128
//!   distinct names after hygiene (431), a 1–32 `tchar` method (400). The
//!   compiler's static step bound (`max_steps`) assumes exactly these caps,
//!   so a request that exceeds one never reaches the policy evaluator. Under
//!   `enforce` the Edge answers with [`Reject::status`]; under `monitor` or
//!   `bootstrap = "open"` it forwards the request unevaluated and counts
//!   `mg_oversize_total{kind}` ([`OversizeKind`], integrator ruling I-2).
//! * [`resolve_host`] picks the one host name a request is for: `Host`,
//!   `:authority` and an absolute-form target must agree, and the result is
//!   normalized (lower-case, no port, no trailing dot) and validated as a DNS
//!   host name or IP literal of at most 253 bytes.
//! * [`header_order`] records distinct client header names in arrival order
//!   (`http.header_order`, `direct_tls` HTTP/1.x only).
//!
//! Everything here is a pure function of plain slices: `mg-edge` adapts
//! Pingora's request header to `&[(&str, &[u8])]` (one entry per field line,
//! in arrival order) and calls these functions from `request_filter`.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Longest accepted path (without the query string), in bytes (§9.3.1).
pub const MAX_PATH_BYTES: usize = 8192;
/// Longest accepted query string (without `?`), in bytes (§9.3.1).
pub const MAX_QUERY_BYTES: usize = 8192;
/// Longest accepted header value, and longest accepted concatenation of all
/// values of one header name joined with `", "` (§9.3.1).
pub const MAX_HEADER_VALUE_BYTES: usize = 8192;
/// Longest accepted header name, in bytes (§9.3.1).
pub const MAX_HEADER_NAME_BYTES: usize = 256;
/// Most distinct header names a request may carry after hygiene (§9.3.1).
pub const MAX_DISTINCT_HEADER_NAMES: usize = 128;
/// Longest accepted method, in bytes (§9.3.1).
pub const MAX_METHOD_BYTES: usize = 32;
/// Longest normalized host name, in bytes (§9.4).
pub const MAX_HOST_BYTES: usize = 253;
/// Most entries in [`header_order`] (`http.header_order`, §4.1).
pub const MAX_HEADER_ORDER: usize = 128;
/// Header names whose values are exempt from the value-size caps (§9.3.1):
/// they never enter `req.headers`, and the cookie parser reads only the first
/// 16 KiB (§6.6). Their names are still subject to the name-length cap.
pub const LIMIT_EXEMPT_HEADERS: [&str; 3] = ["cookie", "authorization", "proxy-authorization"];

/// Why the Edge refuses a request before any policy runs (§9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Reject {
    /// Path or query string longer than 8192 bytes: 414.
    #[error("URI too long")]
    UriTooLong,
    /// A header value, a joined header, a header name or the distinct name
    /// count over its cap: 431.
    #[error("request header too large")]
    HeaderTooLarge,
    /// Method is not 1–32 `tchar`s: 400.
    #[error("bad method")]
    BadMethod,
    /// `Host` missing, invalid, or disagreeing with `:authority` or an
    /// absolute-form target: 400.
    #[error("bad host")]
    BadHost,
}

impl Reject {
    /// The HTTP status of the Edge-generated plain-text response.
    pub fn status(self) -> u16 {
        match self {
            Self::UriTooLong => 414,
            Self::HeaderTooLarge => 431,
            Self::BadMethod | Self::BadHost => 400,
        }
    }

    /// The `reason` label of `mg_protocol_rejected_total` (§9.3.1, §13.7).
    pub fn reason(self) -> &'static str {
        match self {
            Self::UriTooLong => "uri_too_long",
            Self::HeaderTooLarge => "header_too_large",
            Self::BadMethod => "bad_method",
            Self::BadHost => "bad_host",
        }
    }
}

/// Which protocol input cap a request exceeded: the `kind` label of
/// `mg_oversize_total` (integrator ruling I-2). Under `monitor` and
/// `bootstrap = "open"` an oversize request is forwarded without policy
/// evaluation instead of being rejected, and this is what gets counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OversizeKind {
    /// Path longer than [`MAX_PATH_BYTES`].
    Path,
    /// Query string longer than [`MAX_QUERY_BYTES`].
    Query,
    /// A header value (or one name's joined values) longer than
    /// [`MAX_HEADER_VALUE_BYTES`], or a header name longer than
    /// [`MAX_HEADER_NAME_BYTES`]. I-2 has no separate name kind, and both
    /// are the same 431 "header too large" condition.
    HeaderValue,
    /// More than [`MAX_DISTINCT_HEADER_NAMES`] distinct names after hygiene
    /// ([`check_header_count`]).
    HeaderCount,
    /// Method not 1–[`MAX_METHOD_BYTES`] `tchar`s.
    Method,
}

impl OversizeKind {
    /// The `kind` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::HeaderValue => "header_value",
            Self::HeaderCount => "header_count",
            Self::Method => "method",
        }
    }

    /// The rejection used under `enforce`.
    pub const fn reject(self) -> Reject {
        match self {
            Self::Path | Self::Query => Reject::UriTooLong,
            Self::HeaderValue | Self::HeaderCount => Reject::HeaderTooLarge,
            Self::Method => Reject::BadMethod,
        }
    }
}

/// Checks the per-request protocol input caps of §9.3.1 that do not depend on
/// header hygiene: path and query length, header value and name length, and
/// the method. `headers` is every client header field line in arrival order
/// (before hygiene); `path` excludes the query string, `query` excludes `?`.
///
/// The distinct-name cap is checked separately after hygiene
/// ([`check_header_count`]). See [`check_limits_detailed`] for which cap was
/// exceeded.
pub fn check_limits(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &[u8])],
) -> Result<(), Reject> {
    check_limits_detailed(method, path, query, headers).map_err(OversizeKind::reject)
}

/// [`check_limits`], reporting which cap was exceeded (integrator ruling
/// I-2: `monitor` and `bootstrap = "open"` count the kind instead of
/// rejecting). When several caps are exceeded the first in this order is
/// reported: path, query, headers (in arrival order), method.
///
/// Header rules: a name longer than 256 bytes always fails; for every name
/// except [`LIMIT_EXEMPT_HEADERS`], a single value longer than 8192 bytes
/// fails, and so do all values of one name (compared case-insensitively)
/// joined with `", "` when the result is longer than 8192 bytes, because that
/// joined string is what `req.headers` holds (§4.1).
pub fn check_limits_detailed(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &[u8])],
) -> Result<(), OversizeKind> {
    if path.len() > MAX_PATH_BYTES {
        return Err(OversizeKind::Path);
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(OversizeKind::Query);
    }
    check_header_sizes(headers)?;
    if !is_method(method) {
        return Err(OversizeKind::Method);
    }
    Ok(())
}

fn check_header_sizes(headers: &[(&str, &[u8])]) -> Result<(), OversizeKind> {
    // Length of each case-insensitive name's values joined with ", ".
    let mut joined: HashMap<CiKey<'_>, usize> = HashMap::with_capacity(headers.len());
    for (name, value) in headers {
        if name.len() > MAX_HEADER_NAME_BYTES {
            return Err(OversizeKind::HeaderValue);
        }
        if is_limit_exempt(name) {
            continue;
        }
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(OversizeKind::HeaderValue);
        }
        let total = joined
            .entry(CiKey(name.as_bytes()))
            .and_modify(|len| *len = len.saturating_add(2).saturating_add(value.len()))
            .or_insert(value.len());
        if *total > MAX_HEADER_VALUE_BYTES {
            return Err(OversizeKind::HeaderValue);
        }
    }
    Ok(())
}

fn is_limit_exempt(name: &str) -> bool {
    LIMIT_EXEMPT_HEADERS
        .iter()
        .any(|exempt| name.eq_ignore_ascii_case(exempt))
}

/// The distinct-name cap of §9.3.1, checked after hygiene (§9.3 step 5):
/// more than [`MAX_DISTINCT_HEADER_NAMES`] distinct names is a 431
/// ([`OversizeKind::HeaderCount`]).
pub fn check_header_count(distinct_names_after_hygiene: usize) -> Result<(), Reject> {
    if distinct_names_after_hygiene > MAX_DISTINCT_HEADER_NAMES {
        Err(Reject::HeaderTooLarge)
    } else {
        Ok(())
    }
}

/// Resolves the host a request is for (§9.4 step 1, §9.3.1 `bad_host`).
///
/// * `host_header`: the `Host` field (HTTP/1; HTTP/2 clients may send it
///   too), `None` when absent. A request with more than one `Host` field
///   line is malformed (RFC 9112 §3.2): the caller rejects it with
///   [`Reject::BadHost`] without calling this function.
/// * `authority`: the HTTP/2 `:authority` pseudo-header.
/// * `absolute_form_host`: the authority component (`host[:port]`, no
///   scheme) of an absolute-form request target (`GET http://host/
///   HTTP/1.1`).
///
/// At least one of `host_header` / `authority` must be present, every
/// present value must be a valid host, and all of them must normalize to the
/// same name; otherwise [`Reject::BadHost`]. Comparison is on the normalized
/// name, so a port or letter-case difference is not a mismatch (the port is
/// dropped everywhere downstream: sites are selected by name, and the origin
/// receives the normalized name as `Host`).
///
/// Normalization: ASCII lower-case, port and one trailing dot removed. The
/// result is either a DNS host name (LDH labels of 1–63 bytes, no leading or
/// trailing hyphen, ≤ 253 bytes, not ending in a numeric label unless it is
/// a dotted-quad IPv4 address), an IPv4 literal, or a bracketed IPv6 literal
/// in RFC 5952 form (`[2001:db8::1]`). Zone identifiers, IPvFuture, userinfo
/// and non-ASCII names (use punycode) are rejected.
pub fn resolve_host(
    host_header: Option<&str>,
    authority: Option<&str>,
    absolute_form_host: Option<&str>,
) -> Result<String, Reject> {
    if host_header.is_none() && authority.is_none() {
        return Err(Reject::BadHost);
    }
    let mut resolved: Option<String> = None;
    for raw in [host_header, authority, absolute_form_host]
        .into_iter()
        .flatten()
    {
        let host = normalize_host(raw).ok_or(Reject::BadHost)?;
        match &resolved {
            None => resolved = Some(host),
            Some(first) if *first == host => {}
            Some(_) => return Err(Reject::BadHost),
        }
    }
    resolved.ok_or(Reject::BadHost)
}

/// Normalizes one `host[:port]` authority (no userinfo) per [`resolve_host`].
fn normalize_host(raw: &str) -> Option<String> {
    // Longest valid input: a 253-byte name, a trailing dot and ":65535".
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES + 1 + 6 {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        if !is_port_suffix(after) {
            return None;
        }
        // Rejects zone identifiers ("%25eth0") and IPvFuture ("v1.x").
        let v6: Ipv6Addr = inner.parse().ok()?;
        return Some(format!("[{v6}]"));
    }
    let (host, port_suffix) = match raw.find(':') {
        Some(i) => raw.split_at(i),
        None => (raw, ""),
    };
    if !is_port_suffix(port_suffix) {
        return None;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOST_BYTES {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    if let Ok(v4) = lower.parse::<Ipv4Addr>() {
        // std rejects leading zeros, so "010.0.0.1" never aliases 8.0.0.1.
        return Some(v4.to_string());
    }
    if !is_dns_name(lower.as_bytes()) || ends_in_number(&lower) {
        return None;
    }
    Some(lower)
}

/// `""`, `":"` or `":"` followed by 1–5 digits with a value ≤ 65535
/// (RFC 9110 `Host = uri-host [ ":" port ]`, `port = *DIGIT`).
fn is_port_suffix(suffix: &str) -> bool {
    let Some(digits) = suffix.strip_prefix(':') else {
        return suffix.is_empty();
    };
    digits.is_empty()
        || (digits.len() <= 5
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse::<u32>().is_ok_and(|port| port <= 65_535))
}

/// Whether `name` is a lower-case LDH host name: dot-separated labels of
/// 1–63 bytes from `[a-z0-9-]`, no label starting or ending with `-`, at
/// most 253 bytes in total, no trailing dot. Shared with the `CF-Worker`
/// zone check (§9.3).
pub(crate) fn is_dns_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_BYTES
        && name.split(|&b| b == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .iter()
                    .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

/// WHATWG URL "ends in a number": the last label is all digits or a
/// `0x`-prefixed hex number. Such names are IPv4 addresses to browsers
/// (`127.1`, `0x7f.1`), so they are accepted only as canonical dotted quads.
fn ends_in_number(lower: &str) -> bool {
    let last = lower.rsplit('.').next().unwrap_or(lower);
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Distinct header names in order of first arrival, original case kept, at
/// most [`MAX_HEADER_ORDER`] (`http.header_order` and the `direct_tls`
/// `http.header_names`, §4.1, §9.3 step 2). Names are compared
/// case-insensitively (`Accept` and `accept` are one field; the first
/// spelling wins). Empty names and names longer than
/// [`MAX_HEADER_NAME_BYTES`] are skipped rather than truncated, so a
/// truncated name can never impersonate another one; §9.3.1 already rejects
/// such requests under `enforce`.
pub fn header_order(raw_names_in_arrival_order: &[&str]) -> Vec<String> {
    let mut seen: HashSet<CiKey<'_>> = HashSet::with_capacity(MAX_HEADER_ORDER);
    let mut order = Vec::with_capacity(raw_names_in_arrival_order.len().min(MAX_HEADER_ORDER));
    for name in raw_names_in_arrival_order {
        if order.len() == MAX_HEADER_ORDER {
            break;
        }
        if name.is_empty() || name.len() > MAX_HEADER_NAME_BYTES {
            continue;
        }
        if seen.insert(CiKey(name.as_bytes())) {
            order.push((*name).to_owned());
        }
    }
    order
}

/// RFC 9110 `tchar`.
pub(crate) const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A method is 1–32 `tchar`s (RFC 9110 `method = token`, capped by §9.3.1).
fn is_method(method: &str) -> bool {
    !method.is_empty() && method.len() <= MAX_METHOD_BYTES && method.bytes().all(is_tchar)
}

/// A byte string compared and hashed ASCII-case-insensitively, for header
/// names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CiKey<'a>(pub(crate) &'a [u8]);

impl PartialEq for CiKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for CiKey<'_> {}

impl Hash for CiKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.0.len());
        for chunk in self.0.chunks(32) {
            let mut lower = [0u8; 32];
            let lower = &mut lower[..chunk.len()];
            lower.copy_from_slice(chunk);
            lower.make_ascii_lowercase();
            state.write(lower);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash_of(key: CiKey<'_>) -> u64 {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        h.finish()
    }

    #[test]
    fn ci_key_is_case_insensitive_in_eq_and_hash() {
        let long_a = "X-Some-Rather-Long-Header-Name-That-Spans-Chunks-Abc";
        let long_b = long_a.to_ascii_lowercase();
        assert_eq!(CiKey(long_a.as_bytes()), CiKey(long_b.as_bytes()));
        assert_eq!(
            hash_of(CiKey(long_a.as_bytes())),
            hash_of(CiKey(long_b.as_bytes()))
        );
        assert_ne!(CiKey(b"accept"), CiKey(b"accept-"));
        assert_ne!(CiKey(b"a_b"), CiKey(b"a-b"));
    }

    #[test]
    fn tchar_table_matches_rfc_9110() {
        let specials = "!#$%&'*+-.^_`|~";
        for b in 0u8..=255 {
            let expected = b.is_ascii_alphanumeric() || specials.as_bytes().contains(&b);
            assert_eq!(is_tchar(b), expected, "byte {b:#04x}");
        }
    }

    #[test]
    fn port_suffixes() {
        for ok in ["", ":", ":0", ":80", ":65535"] {
            assert!(is_port_suffix(ok), "{ok:?}");
        }
        for bad in [":65536", ":123456", ":8a", "80", ": 80", ":+80", "::80"] {
            assert!(!is_port_suffix(bad), "{bad:?}");
        }
    }

    #[test]
    fn numeric_last_labels() {
        assert!(ends_in_number("127.1"));
        assert!(ends_in_number("a.0x7f"));
        assert!(ends_in_number("a.0x"));
        assert!(ends_in_number("123"));
        assert!(!ends_in_number("example.com"));
        assert!(!ends_in_number("a1.b2c"));
        assert!(!ends_in_number("a.0xg"));
    }
}
