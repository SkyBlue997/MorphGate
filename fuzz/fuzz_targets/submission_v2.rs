//! `POST /__mg/c` v2 bodies (Phase 2 spec §7.5): the submission parser,
//! its `t` decoding and the session-key and signature checks of steps 7-8
//! reject what they cannot read without panicking.
//!
//! Input: the request body (JSON).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::submission::{parse_submission, session_key, submission_signature_ok};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(sub) = parse_submission(text)
        && let Some(v2) = &sub.v2
        && let Some(key) = session_key(&v2.jwk)
    {
        let _ = submission_signature_ok(&sub, &key);
    }
});
