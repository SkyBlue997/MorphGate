//! `POST /__mg/r` (Phase 2 spec §9.3): the body rules (exactly `{"v": 2}`
//! plus an optional `t` string, at most 16 KiB) and the `t` it may carry,
//! and an `MG-Proof` header value, reject what they cannot read without
//! panicking.
//!
//! Input: the request body; when it contains a NUL byte, the bytes after the
//! first NUL are the `MG-Proof` value instead.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::refresh::parse_body;
use mg_edge_core::events::ChallengeTelemetry;

fuzz_target!(|data: &[u8]| {
    let (body, proof) = match data.iter().position(|b| *b == 0) {
        Some(i) => (&data[..i], Some(&data[i + 1..])),
        None => (data, None),
    };
    if let Ok(Some(t)) = parse_body(body) {
        let _ = ChallengeTelemetry::parse(&t);
    }
    if let Some(p) = proof.and_then(|p| std::str::from_utf8(p).ok()) {
        let req = mg_challenge::ProofRequest {
            method: "POST",
            scheme: "https",
            host: "example.com",
            path: "/__mg/r",
            now_s: 1_790_000_000,
            expected_jkt: Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
        };
        let _ = mg_challenge::verify_proof(p, &req);
        let _ = mg_challenge::proof_signing_key(p);
    }
});
