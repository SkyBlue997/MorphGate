//! `MG-Proof` headers (Phase 2 spec §6.7, D-40): `verify_proof` rejects what
//! it cannot verify, in the order of §6.7, without panicking, for any header
//! value and with or without an expected thumbprint.
//!
//! Input: one mode byte (bit 0: the request carries a bound clearance; bit
//! 1: the request method is `post` in lower case), then the header value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_challenge::{ProofRequest, verify_proof};

const JKT: &str = "L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc";

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let header = String::from_utf8_lossy(rest);
    let req = ProofRequest {
        method: if mode & 2 == 0 { "POST" } else { "post" },
        scheme: "https",
        host: "example.com",
        path: "/api/save",
        now_s: 1_790_000_000,
        expected_jkt: (mode & 1 == 1).then_some(JKT),
    };
    if let Err(e) = verify_proof(&header, &req) {
        assert!(e.reason_code().starts_with("proof."));
    }
});
