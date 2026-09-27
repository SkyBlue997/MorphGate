//! Signed bundle client (spec §9.10): fetch `<bundle_root>bundles/<site>.bundle`
//! from `file://` or HTTP(S) with ETag, verify the Ed25519 signature against
//! the owner keys, schema and bound checks, LKG persistence (tmp + rename) and
//! the content-addressed artifact cache.
//!
//! Implemented by work package WP-C2 (docs/impl/phase1-spec.md §15); empty
//! until then.
