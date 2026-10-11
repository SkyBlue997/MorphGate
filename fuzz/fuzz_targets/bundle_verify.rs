//! Signed configuration bundles (spec §8.1): envelopes, and random payloads
//! in a validly signed envelope (so the inner `SiteBundle` decoder and the
//! bound checks see them too), never panic the verifier.
//!
//! Input: one mode byte; even = the rest is the envelope, odd = the rest is
//! signed with the test owner key first.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge_core::bundle::verify_bundle;
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_SEED, owner_test_keys, sign_test_bytes,
};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let keys = owner_test_keys();
    let hosts = ["example.com".to_owned()];
    if mode % 2 == 0 {
        let _ = verify_bundle(rest, &keys, "blog", &hosts);
    } else {
        let signed = sign_test_bytes(rest, &OWNER_TEST_SEED, OWNER_TEST_KID);
        let _ = verify_bundle(&signed, &keys, "blog", &hosts);
    }
});
