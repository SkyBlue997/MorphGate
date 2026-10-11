//! Turnstile siteverify response bodies (Phase 2 spec §8.4, §8.5): the
//! parser rejects what it cannot read without panicking (a JSON object, at
//! most 16 KiB, at most 8 error codes, RFC 3339 `challenge_ts`, the fields
//! of a success all present), and the `cdata` it returns is compared in
//! constant time against a challenge's own value without panicking.
//!
//! Input: the response body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_challenge::{SealKeys, SealRoot, turnstile_cdata_matches};
use mg_edge_core::outbound::{parse_rfc3339_ns, parse_siteverify_response, token_precheck};
use std::sync::LazyLock;

static KEYS: LazyLock<SealKeys> =
    LazyLock::new(|| SealKeys::new(vec![SealRoot::from_bytes([1; 32])]).unwrap());

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = parse_siteverify_response(data) {
        let _ = r.challenge_ts_ms();
        let _ = r.has_code("timeout-or-duplicate");
        if let Some(c) = r.cdata.as_deref() {
            let _ = turnstile_cdata_matches(&KEYS, "blog", 20_717, &[0; 16], c);
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_rfc3339_ns(text);
        let _ = token_precheck(text);
    }
});
