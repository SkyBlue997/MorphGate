//! Upstream trust (spec §9.2, §9.3): the header-family predicate (lower-case,
//! `_` -> `-`), exact-name parsing of the `cloudflare` trusted headers into a
//! plain struct, the `CF-Worker` owner-zone check and the `x-mg-cf-t1` Tier 1
//! marker.
//!
//! Implemented by work package WP-C1 (docs/impl/phase1-spec.md §15); empty
//! until then.
