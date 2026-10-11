//! `POST /__mg/t` bodies (Phase 2 spec §9.4, §12.8): the report parser
//! (strict JSON, at most 8 reports, the per-kind rules, the behavior
//! summary) rejects what it cannot read without panicking, and every report
//! it accepts re-serializes.
//!
//! Input: the request body (JSON).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_edge_core::events::{ReportEntry, parse_reports};

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = parse_reports(data) {
        for e in entries {
            if let ReportEntry::Report(r) = e {
                let _ = r.to_value(Some("/redacted"));
                let _ = r.to_value(None);
            }
        }
    }
});
