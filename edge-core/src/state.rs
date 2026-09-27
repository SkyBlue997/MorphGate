//! State layer (spec §9.7, §9.8): Valkey pipelines with the `mg_gcra` and
//! `mg_nonce_issue` Lua scripts, verdict `MGET`, the circuit breaker, and the
//! local mode (bounded GCRA table, fixed-capacity TTL nonce set).
//!
//! Implemented by work package WP-C3 (docs/impl/phase1-spec.md §15); empty
//! until then.
