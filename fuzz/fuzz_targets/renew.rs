//! `POST /__mg/c/renew` bodies (Phase 2 spec §7.4): the renewal parser and
//! the session-key and signature checks reject what they cannot read
//! without panicking.
//!
//! Input: the request body (JSON).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::submission::{parse_renew, renew_signature_ok, session_key};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(r) = parse_renew(text)
        && let Some(key) = session_key(&r.jwk)
    {
        let _ = renew_signature_ok(&r, &key);
    }
});
