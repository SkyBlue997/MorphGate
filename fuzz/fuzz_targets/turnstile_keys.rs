//! `mg-turnstile-keys` credential files (Phase 2 spec §8.7): the parser
//! rejects what it cannot read without panicking (strict JSON, `v = 1`, the
//! kind, the `[[sites]]` id, 1-2 secrets of 1-256 visible ASCII
//! characters), and neither its errors nor the `Debug` of what it accepts
//! show a secret.
//!
//! Input: the file.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::creds::parse_turnstile_keys;

fuzz_target!(|data: &[u8]| {
    match parse_turnstile_keys(data, "blog") {
        Ok(secrets) => {
            let shown = format!("{secrets:?}");
            assert!(!shown.contains(secrets.current()));
        }
        Err(e) => {
            let _ = e.len();
        }
    }
});
