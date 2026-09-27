//! Request normalization and protocol limits (spec §9.3.1, §9.4): Host /
//! `:authority` / absolute-form consistency, the Activation size caps
//! (414 / 431 / 400), `Connection`-token stripping and the distinct
//! header-name order.
//!
//! Implemented by work package WP-C1 (docs/impl/phase1-spec.md §15); empty
//! until then.
