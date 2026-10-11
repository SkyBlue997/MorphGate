//! Request limits, host resolution and header order (spec §9.3.1, §9.4):
//! `check_limits` agrees with `check_limits_detailed`, a resolved host is
//! canonical (resolving it again is the identity), and the header order is
//! bounded and free of duplicates.
//!
//! Input lines: method, path, query, then `name: value` header lines. The
//! `host`, `:authority` and `absolute-form` headers feed `resolve_host`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge_core::request::{
    MAX_HEADER_NAME_BYTES, MAX_HEADER_ORDER, check_limits, check_limits_detailed, header_order,
    resolve_host,
};
use std::collections::HashSet;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.split('\n');
    let method = lines.next().unwrap_or_default();
    let path = lines.next().unwrap_or_default();
    let query = lines.next().unwrap_or_default();
    let headers: Vec<(&str, &[u8])> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n, v.strip_prefix(' ').unwrap_or(v).as_bytes()))
        .collect();

    let detailed = check_limits_detailed(method, path, query, &headers);
    assert_eq!(
        check_limits(method, path, query, &headers).is_ok(),
        detailed.is_ok()
    );

    let value = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| std::str::from_utf8(v).ok())
    };
    if let Ok(h) = resolve_host(value("host"), value(":authority"), value("absolute-form")) {
        assert_eq!(h, h.to_ascii_lowercase());
        assert!(!h.ends_with('.'));
        assert_eq!(resolve_host(Some(&h), None, None).as_ref(), Ok(&h));
        assert_eq!(resolve_host(None, Some(&h), Some(&h)).as_ref(), Ok(&h));
    }

    let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
    let order = header_order(&names);
    assert!(order.len() <= MAX_HEADER_ORDER);
    let distinct: HashSet<String> = order.iter().map(|n| n.to_ascii_lowercase()).collect();
    assert_eq!(distinct.len(), order.len());
    assert!(
        order
            .iter()
            .all(|n| !n.is_empty() && n.len() <= MAX_HEADER_NAME_BYTES)
    );
});
