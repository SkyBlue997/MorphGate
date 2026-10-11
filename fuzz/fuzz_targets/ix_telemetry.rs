//! The `t` of a v2 submission with its interaction telemetry (Phase 2 spec
//! §7.6, §15.2): the single decoder rejects what does not fit without
//! panicking, and what it accepts is within `IxTelemetry::check` and
//! re-serializes.
//!
//! Input: the content of `t`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge_core::events::{ChallengeTelemetry, ix_from_value, ix_to_value};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(t) = ChallengeTelemetry::parse(text) {
        let _ = t.to_value();
        if let Some(ix) = &t.ix {
            assert!(ix.check().is_ok());
            let again = ix_from_value(&ix_to_value(ix)).expect("re-serialized ix decodes");
            assert_eq!(&again, ix);
        }
    }
});
