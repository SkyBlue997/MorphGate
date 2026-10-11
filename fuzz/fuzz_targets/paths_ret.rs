//! Request-path views, `/__mg` ownership and return paths (spec §9.4,
//! §10.1, I-39): the views never panic, route candidates start with the raw
//! path and hold no duplicates, and every return path the Edge produces is
//! either the fallback or one `validate_ret` accepts.
//!
//! Input: a path; also read as the query of `/__mg/v` and of a challenged
//! GET.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_challenge::validate_ret;
use mg_core::paths::{cloudflare_view, decoded_view, is_reserved, rfc3986_view, route_candidates};
use mg_edge::challenge::challenge_ret;
use mg_edge::mg_endpoints::verify_ret;

const FALLBACK: &str = "/";

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    let reserved = is_reserved(path);
    for view in [rfc3986_view(path), cloudflare_view(path)] {
        // A spelling Cloudflare's /__mg/ rules can match is the Edge's.
        if view == "/__mg" || view.starts_with("/__mg/") {
            assert!(reserved, "{path:?} -> {view:?}");
        }
    }
    let _ = decoded_view(path);
    for case_insensitive in [false, true] {
        let c = route_candidates(path, case_insensitive);
        assert!(!c.is_empty() && c.len() <= 8);
        if !case_insensitive {
            assert_eq!(c[0], path);
        }
        for (i, a) in c.iter().enumerate() {
            assert!(!c[i + 1..].contains(a));
        }
    }

    if validate_ret(path).is_ok() {
        assert!(path.starts_with('/') && path.len() <= 512 && !path.contains(['#', '\\']));
    }
    for ret in [
        verify_ret(path, FALLBACK),
        challenge_ret("GET", "/a", path, FALLBACK),
        challenge_ret("GET", path, "", FALLBACK),
    ] {
        assert!(ret == FALLBACK || validate_ret(&ret).is_ok(), "{ret:?}");
    }
});
