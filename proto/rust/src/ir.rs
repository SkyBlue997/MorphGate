//! Policy IR: wire (`morphgate.v1.PolicyExpr`, `policy_ir.proto`) to native
//! (`mg_core::policy`) conversion.
//!
//! Implemented in Phase 1 by work package WP-R1 (docs/impl/phase1-spec.md
//! §5.6): `decode_program` validates a serialized `PolicyExpr` (ir_version,
//! schema field paths, node and depth limits, literal glob patterns) and
//! builds the evaluator's native expression tree; `rule_from_proto` does the
//! same for a whole `CompiledRule`. The cross-language conformance test lives
//! in `tests/policy_ir_conformance.rs`. Until then this module is empty.
