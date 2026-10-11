//! TLS ClientHello and JA4 (spec §9.6, `ja4_spike`): the parser walks any
//! input without panicking, and `ja4` and its raw form agree on what parses.
//! The Edge calls `ja4` behind `catch_unwind`; this target calls it
//! directly so that a panic is found rather than hidden.
//!
//! Input: a ClientHello body (from `legacy_version`), also read as a TLS
//! record.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge::tls::client_hello::{
    ClientHello, body_from_record, first_alpn, signature_algorithms, supported_versions,
};
use mg_edge::tls::ja4::{ja4, ja4_r};

fuzz_target!(|data: &[u8]| {
    for body in [Some(data), body_from_record(data).ok()]
        .into_iter()
        .flatten()
    {
        if let Ok(hello) = ClientHello::parse(body) {
            let _ = hello.cipher_suites().count();
            for (_, ext) in hello.extensions() {
                let _ = supported_versions(ext);
                let _ = signature_algorithms(ext);
                let _ = first_alpn(ext);
            }
        }
        match ja4(body) {
            Ok(v) => {
                let _ = v.to_string();
                assert!(ja4_r(body).is_ok());
            }
            Err(_) => assert!(ja4_r(body).is_err()),
        }
    }
});
