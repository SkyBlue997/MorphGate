//! SDK session public keys (docs/impl/phase2-spec.md §6.5): the strict
//! four-member P-256 JWK, its RFC 7638 thumbprint `jkt` (43 characters) and
//! ES256 verification of 64-byte `r || s` signatures through `aws-lc-rs`
//! (`signature::ECDSA_P256_SHA256_FIXED`).
//!
//! Phase 2, WP-R5. Empty until that work package lands.
