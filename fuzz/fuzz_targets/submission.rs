//! Challenge submissions (spec §6.4, POST `/__mg/c`): the content type,
//! form and strict JSON decoders and the submission parser reject what they
//! cannot read without panicking.
//!
//! Input: a `Content-Type` line, then the body; the body is decoded both as
//! a form and as JSON.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::submission::{decode_form, media_kind, parse_submission, strict_json};
use mg_edge_core::events::{TelemetryAuto, TelemetryEnv};

fuzz_target!(|data: &[u8]| {
    let (content_type, body) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&[][..], data),
    };
    if let Ok(ct) = std::str::from_utf8(content_type) {
        let _ = media_kind(ct);
    }
    if let Ok(json) = decode_form(body) {
        let _ = parse_submission(&json);
    }
    if let Ok(text) = std::str::from_utf8(body) {
        let _ = parse_submission(text);
        if let Ok(v) = strict_json(text) {
            if let Some(env) = TelemetryEnv::from_value(&v) {
                let _ = env.to_value();
            }
            let _ = TelemetryAuto::from_value(&v);
        }
    }
});
