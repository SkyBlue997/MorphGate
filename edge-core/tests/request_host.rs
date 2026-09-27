//! Host resolution (docs/impl/phase1-spec.md §9.4 step 1, §9.3.1
//! `bad_host`) and the distinct header-name order (§4.1 `http.header_order`,
//! §9.3 step 2); WP-C1.

use mg_edge_core::request::{MAX_HEADER_ORDER, Reject, header_order, resolve_host};

fn host(value: &str) -> Result<String, Reject> {
    resolve_host(Some(value), None, None)
}

#[test]
fn host_is_normalized() {
    let cases = [
        ("blog.example.com", "blog.example.com"),
        ("Blog.Example.COM", "blog.example.com"),
        ("blog.example.com:8443", "blog.example.com"),
        ("blog.example.com.", "blog.example.com"),
        ("BLOG.example.com.:443", "blog.example.com"),
        ("blog.example.com:", "blog.example.com"),
        ("localhost", "localhost"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a1.b2c", "a1.b2c"),
        ("192.0.2.1", "192.0.2.1"),
        ("192.0.2.1:8080", "192.0.2.1"),
        ("192.0.2.1.", "192.0.2.1"),
        ("[2001:DB8::1]", "[2001:db8::1]"),
        ("[2001:db8:0:0::1]:443", "[2001:db8::1]"),
        ("[::1]", "[::1]"),
        ("[::ffff:192.0.2.1]", "[::ffff:192.0.2.1]"),
    ];
    for (raw, expected) in cases {
        assert_eq!(host(raw).as_deref(), Ok(expected), "{raw:?}");
    }
}

#[test]
fn host_length_boundaries() {
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 bytes.
    let at = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
    assert_eq!(at.len(), 253);
    assert_eq!(host(&at), Ok(at.clone()));
    assert_eq!(host(&format!("{at}.")), Ok(at.clone()));
    assert_eq!(host(&format!("{at}.:65535")), Ok(at.clone()));
    let over = format!("{at}b");
    assert_eq!(host(&over), Err(Reject::BadHost));
    let label_63 = format!("{}.com", "l".repeat(63));
    assert_eq!(host(&label_63), Ok(label_63.clone()));
    let label_64 = format!("{}.com", "l".repeat(64));
    assert_eq!(host(&label_64), Err(Reject::BadHost));
}

#[test]
fn invalid_hosts_are_rejected() {
    for bad in [
        "",
        " ",
        " example.com",
        "example.com ",
        "exa mple.com",
        "example.com/",
        "example.com/path",
        "example.com?x",
        "example.com#x",
        "user@example.com",
        "user:pass@example.com",
        "example.com:abc",
        "example.com:65536",
        "example.com:-1",
        "example.com:80:80",
        "::1",
        "2001:db8::1",
        "[::1",
        "::1]",
        "[::1]x",
        "[::1]:99999",
        "[fe80::1%25eth0]",
        "[fe80::1%eth0]",
        "[v1.fe80::a+en1]",
        "[192.0.2.1]",
        "[]",
        "exämple.com",
        "-a.com",
        "a-.com",
        "a..com",
        ".example.com",
        ".",
        "..",
        "example.com..",
        "a_b.com",
        "a*b.com",
        "a\tb",
        "127.1",
        "0x7f.0.0.1",
        "0x7f000001",
        "1.2.3.256",
        "010.0.0.1",
        "1.2.3.4.5",
        "example.123",
        "example.0x1f",
    ] {
        assert_eq!(host(bad), Err(Reject::BadHost), "{bad:?}");
    }
}

/// §9.4: HTTP/2 uses `:authority`; when a `Host` field is present as well,
/// both must agree (after normalization).
#[test]
fn authority_and_host_must_agree() {
    assert_eq!(
        resolve_host(None, Some("blog.example.com"), None).as_deref(),
        Ok("blog.example.com")
    );
    assert_eq!(
        resolve_host(Some("Blog.Example.com:443"), Some("blog.example.com"), None).as_deref(),
        Ok("blog.example.com")
    );
    assert_eq!(
        resolve_host(Some("[2001:db8::1]"), Some("[2001:DB8:0::1]:443"), None).as_deref(),
        Ok("[2001:db8::1]")
    );
    assert_eq!(
        resolve_host(Some("blog.example.com"), Some("shop.example.com"), None),
        Err(Reject::BadHost)
    );
    assert_eq!(
        resolve_host(
            Some("blog.example.com"),
            Some("blog.example.com.evil"),
            None
        ),
        Err(Reject::BadHost)
    );
    // An invalid value anywhere is a bad host, even if another one is valid.
    assert_eq!(
        resolve_host(Some("blog.example.com"), Some("bad host"), None),
        Err(Reject::BadHost)
    );
    assert_eq!(
        resolve_host(Some("bad host"), Some("blog.example.com"), None),
        Err(Reject::BadHost)
    );
}

/// §9.4: the host of an absolute-form request target must agree too.
#[test]
fn absolute_form_must_agree() {
    assert_eq!(
        resolve_host(Some("blog.example.com"), None, Some("blog.example.com")).as_deref(),
        Ok("blog.example.com")
    );
    assert_eq!(
        resolve_host(Some("blog.example.com"), None, Some("BLOG.example.com:80")).as_deref(),
        Ok("blog.example.com")
    );
    assert_eq!(
        resolve_host(Some("blog.example.com"), None, Some("internal.example.com")),
        Err(Reject::BadHost)
    );
    assert_eq!(
        resolve_host(None, Some("blog.example.com"), Some("admin.example.com")),
        Err(Reject::BadHost)
    );
    assert_eq!(
        resolve_host(
            Some("blog.example.com"),
            Some("blog.example.com"),
            Some("x.example.com")
        ),
        Err(Reject::BadHost)
    );
    assert_eq!(
        resolve_host(Some("blog.example.com"), None, Some("")),
        Err(Reject::BadHost)
    );
}

/// §9.3.1: a request without `Host` (and without `:authority`) is a bad
/// host, even with an absolute-form target.
#[test]
fn missing_host_is_rejected() {
    assert_eq!(resolve_host(None, None, None), Err(Reject::BadHost));
    assert_eq!(
        resolve_host(None, None, Some("blog.example.com")),
        Err(Reject::BadHost)
    );
    assert_eq!(Reject::BadHost.status(), 400);
    assert_eq!(Reject::BadHost.reason(), "bad_host");
}

// ---- header_order (§4.1, §9.3 step 2) ----

#[test]
fn header_order_is_distinct_first_occurrence_original_case() {
    let names = [
        "Host",
        "User-Agent",
        "accept",
        "Accept",
        "host",
        "Cookie",
        "X_Custom",
        "X-Custom",
        "ACCEPT",
        "cookie",
    ];
    assert_eq!(
        header_order(&names),
        [
            "Host",
            "User-Agent",
            "accept",
            "Cookie",
            "X_Custom",
            "X-Custom"
        ]
    );
    assert!(header_order(&[]).is_empty());
}

/// Interleaved repeats keep only the first position (the Pingora header
/// table cannot restore interleaved order either, §4.1).
#[test]
fn header_order_interleaved_repeats() {
    assert_eq!(header_order(&["a", "b", "a", "c", "b"]), ["a", "b", "c"]);
}

#[test]
fn header_order_is_capped_at_128() {
    assert_eq!(MAX_HEADER_ORDER, 128);
    let owned: Vec<String> = (0..200).map(|i| format!("X-H{i}")).collect();
    let names: Vec<&str> = owned.iter().map(String::as_str).collect();
    let order = header_order(&names);
    assert_eq!(order.len(), 128);
    assert_eq!(order[..], owned[..128]);
    // Repeats do not use up the budget.
    let mut repeated: Vec<&str> = vec!["dup"; 500];
    repeated.extend(&names);
    let order = header_order(&repeated);
    assert_eq!(order.len(), 128);
    assert_eq!(order[0], "dup");
    assert_eq!(order[1..], owned[..127]);
}

#[test]
fn header_order_skips_empty_and_overlong_names() {
    let at = "n".repeat(256);
    let over = "o".repeat(257);
    let order = header_order(&["", over.as_str(), at.as_str(), "Accept"]);
    assert_eq!(order, [at.as_str(), "Accept"]);
}
