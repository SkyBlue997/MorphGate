//! Protocol input limits (docs/impl/phase1-spec.md §9.3.1, D-26, integrator
//! ruling I-2, §4.1 size caps; WP-C1): every boundary at 8192 / 8193 bytes,
//! 256 / 257-byte names, 128 / 129 distinct names, the Cookie exemption and
//! the method rule.

use mg_edge_core::request::{
    LIMIT_EXEMPT_HEADERS, MAX_DISTINCT_HEADER_NAMES, MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES,
    MAX_METHOD_BYTES, MAX_PATH_BYTES, MAX_QUERY_BYTES, OversizeKind, Reject, check_header_count,
    check_limits, check_limits_detailed,
};

const BROWSER: &[(&str, &str)] = &[
    ("Host", "blog.example.com"),
    (
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    ),
    ("Accept", "text/html,application/xhtml+xml"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Cookie", "a=1; b=2"),
];

fn owned(pairs: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.as_bytes().to_vec()))
        .collect()
}

fn slices(headers: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect()
}

/// Checks `headers` with an ordinary method, path and query.
fn check_headers(headers: &[(String, Vec<u8>)]) -> Result<(), OversizeKind> {
    let result = check_limits_detailed("GET", "/", "", &slices(headers));
    assert_eq!(
        check_limits("GET", "/", "", &slices(headers)),
        result.map_err(OversizeKind::reject)
    );
    result
}

fn header(name: &str, len: usize) -> (String, Vec<u8>) {
    (name.to_owned(), vec![b'v'; len])
}

#[test]
fn spec_constants() {
    assert_eq!(MAX_PATH_BYTES, 8192);
    assert_eq!(MAX_QUERY_BYTES, 8192);
    assert_eq!(MAX_HEADER_VALUE_BYTES, 8192);
    assert_eq!(MAX_HEADER_NAME_BYTES, 256);
    assert_eq!(MAX_DISTINCT_HEADER_NAMES, 128);
    assert_eq!(MAX_METHOD_BYTES, 32);
    assert_eq!(
        LIMIT_EXEMPT_HEADERS,
        ["cookie", "authorization", "proxy-authorization"]
    );
}

/// §9.3.1 response table and the `mg_protocol_rejected_total` reasons.
#[test]
fn reject_status_and_reason() {
    let table = [
        (Reject::UriTooLong, 414, "uri_too_long"),
        (Reject::HeaderTooLarge, 431, "header_too_large"),
        (Reject::BadMethod, 400, "bad_method"),
        (Reject::BadHost, 400, "bad_host"),
    ];
    for (reject, status, reason) in table {
        assert_eq!(reject.status(), status);
        assert_eq!(reject.reason(), reason);
        assert!(!reject.to_string().is_empty());
    }
}

/// I-2: the `kind` labels of `mg_oversize_total` and the enforce-mode
/// rejection of each.
#[test]
fn oversize_kinds() {
    let table = [
        (OversizeKind::Path, "path", Reject::UriTooLong),
        (OversizeKind::Query, "query", Reject::UriTooLong),
        (
            OversizeKind::HeaderValue,
            "header_value",
            Reject::HeaderTooLarge,
        ),
        (
            OversizeKind::HeaderCount,
            "header_count",
            Reject::HeaderTooLarge,
        ),
        (OversizeKind::Method, "method", Reject::BadMethod),
    ];
    for (kind, label, reject) in table {
        assert_eq!(kind.as_str(), label);
        assert_eq!(kind.reject(), reject);
    }
}

#[test]
fn ordinary_browser_request_passes() {
    let headers = owned(BROWSER);
    assert_eq!(
        check_limits("GET", "/account/login", "next=%2F", &slices(&headers)),
        Ok(())
    );
    assert_eq!(check_limits("POST", "/", "", &[]), Ok(()));
}

#[test]
fn path_boundary() {
    let at = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
    let over = format!("{at}b");
    assert_eq!(at.len(), 8192);
    assert_eq!(check_limits_detailed("GET", &at, "", &[]), Ok(()));
    assert_eq!(
        check_limits_detailed("GET", &over, "", &[]),
        Err(OversizeKind::Path)
    );
    assert_eq!(check_limits("GET", &over, "", &[]), Err(Reject::UriTooLong));
}

#[test]
fn query_boundary() {
    let at = "q".repeat(MAX_QUERY_BYTES);
    let over = format!("{at}q");
    assert_eq!(check_limits_detailed("GET", "/", &at, &[]), Ok(()));
    assert_eq!(
        check_limits_detailed("GET", "/", &over, &[]),
        Err(OversizeKind::Query)
    );
    assert_eq!(
        check_limits("GET", "/", &over, &[]),
        Err(Reject::UriTooLong)
    );
    // Path and query are capped separately, not together.
    let path = format!("/{}", "p".repeat(MAX_PATH_BYTES - 1));
    assert_eq!(check_limits("GET", &path, &at, &[]), Ok(()));
}

#[test]
fn header_value_boundary() {
    assert_eq!(check_headers(&[header("X-Long", 8192)]), Ok(()));
    assert_eq!(
        check_headers(&[header("X-Long", 8193)]),
        Err(OversizeKind::HeaderValue)
    );
    // Also for upstream-family headers: limits run before hygiene.
    assert_eq!(
        check_headers(&[header("x-mg-cf-hdr-names", 8193)]),
        Err(OversizeKind::HeaderValue)
    );
}

/// §9.3.1 / §4.1: the values of one name joined with `", "` must fit too,
/// names compared case-insensitively (`_` is a different name).
#[test]
fn joined_header_boundary() {
    // 4095 + 2 + 4095 = 8192.
    let at = [header("X-Rep", 4095), header("x-rep", 4095)];
    assert_eq!(check_headers(&at), Ok(()));
    let over = [header("X-Rep", 4095), header("X-REP", 4096)];
    assert_eq!(check_headers(&over), Err(OversizeKind::HeaderValue));
    // Three values: 2730 * 3 + 2 * 2 = 8194.
    let three = [
        header("accept", 2730),
        header("Accept", 2730),
        header("ACCEPT", 2730),
    ];
    assert_eq!(check_headers(&three), Err(OversizeKind::HeaderValue));
    // Different names are not joined.
    let distinct = [
        header("X-Rep", 8000),
        header("X_Rep", 8000),
        header("X-Rep2", 8000),
    ];
    assert_eq!(check_headers(&distinct), Ok(()));
    // Empty values still count their separators: 4098 values join to
    // 2 * 4097 = 8194 bytes, 4097 values to exactly 8192.
    let empties: Vec<_> = (0..4098).map(|_| header("x-e", 0)).collect();
    assert_eq!(check_headers(&empties), Err(OversizeKind::HeaderValue));
    assert_eq!(check_headers(&empties[..4097]), Ok(()));
}

/// §9.3.1: `Cookie`, `Authorization` and `Proxy-Authorization` values are
/// exempt from the value caps (single and joined), in any case; their names
/// are not.
#[test]
fn cookie_and_authorization_are_exempt() {
    for name in [
        "Cookie",
        "cookie",
        "COOKIE",
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "proxy-authorization",
    ] {
        assert_eq!(check_headers(&[header(name, 20_000)]), Ok(()), "{name}");
        let split = [header(name, 8000), header(name, 8000)];
        assert_eq!(check_headers(&split), Ok(()), "{name}");
    }
    for name in [
        "Cookie2",
        "Set-Cookie",
        "X-Authorization",
        "Proxy_Authorization",
        "cookie_",
    ] {
        assert_eq!(
            check_headers(&[header(name, 8193)]),
            Err(OversizeKind::HeaderValue),
            "{name}"
        );
    }
}

#[test]
fn header_name_boundary() {
    let at = "n".repeat(MAX_HEADER_NAME_BYTES);
    let over = "n".repeat(MAX_HEADER_NAME_BYTES + 1);
    assert_eq!(check_headers(&[header(&at, 1)]), Ok(()));
    assert_eq!(
        check_headers(&[header(&over, 1)]),
        Err(OversizeKind::HeaderValue)
    );
    // The Cookie exemption does not cover over-long names.
    let long_exempt_like = format!("cookie{}", "x".repeat(251));
    assert_eq!(
        check_headers(&[header(&long_exempt_like, 0)]),
        Err(OversizeKind::HeaderValue)
    );
}

#[test]
fn distinct_header_count_boundary() {
    assert_eq!(check_header_count(0), Ok(()));
    assert_eq!(check_header_count(128), Ok(()));
    assert_eq!(check_header_count(129), Err(Reject::HeaderTooLarge));
    assert_eq!(check_header_count(usize::MAX), Err(Reject::HeaderTooLarge));
    assert_eq!(OversizeKind::HeaderCount.reject(), Reject::HeaderTooLarge);
}

#[test]
fn method_rule() {
    let at = "M".repeat(MAX_METHOD_BYTES);
    for good in [
        "GET",
        "HEAD",
        "POST",
        "OPTIONS",
        "PROPFIND",
        "get",
        "M-SEARCH",
        at.as_str(),
        "!#$%&'*+-.^_`|~",
    ] {
        assert_eq!(check_limits(good, "/", "", &[]), Ok(()), "{good:?}");
    }
    let over = "M".repeat(MAX_METHOD_BYTES + 1);
    for bad in [
        "",
        "GE T",
        "GET\r",
        "GET\n",
        "G\u{c9}T",
        "(GET)",
        "GET/1",
        "GET,POST",
        "\"GET\"",
        over.as_str(),
    ] {
        assert_eq!(
            check_limits_detailed(bad, "/", "", &[]),
            Err(OversizeKind::Method),
            "{bad:?}"
        );
        assert_eq!(check_limits(bad, "/", "", &[]), Err(Reject::BadMethod));
    }
}

/// When several caps are exceeded the first in the documented order wins:
/// path, query, headers, method.
#[test]
fn first_violation_order() {
    let path = "/".repeat(MAX_PATH_BYTES + 1);
    let query = "q".repeat(MAX_QUERY_BYTES + 1);
    let big = [header("X-Big", 9000)];
    let big = slices(&big);
    assert_eq!(
        check_limits_detailed("BAD METHOD", &path, &query, &big),
        Err(OversizeKind::Path)
    );
    assert_eq!(
        check_limits_detailed("BAD METHOD", "/", &query, &big),
        Err(OversizeKind::Query)
    );
    assert_eq!(
        check_limits_detailed("BAD METHOD", "/", "", &big),
        Err(OversizeKind::HeaderValue)
    );
}
