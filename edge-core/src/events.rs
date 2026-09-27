//! Event sinks (spec §9.11, §13): three bounded priority queues, VictoriaLogs
//! `/insert/jsonline` batches with retries, the JSONL file sink and `mg:ev`
//! stream entries.
//!
//! Implemented by work package WP-C4 (docs/impl/phase1-spec.md §15); empty
//! until then.
