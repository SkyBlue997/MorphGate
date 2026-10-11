//! Turnstile `cData` and the siteverify idempotency key
//! (docs/impl/phase2-spec.md §6.9): an HMAC of the challenge nonce under the
//! epoch binding key, and a UUID-formatted hash of the nonce (with a variant
//! for the retry with the previous secret).
//!
//! Phase 2, WP-R5. Empty until that work package lands. Nothing here talks to
//! Cloudflare; the siteverify client is `mg_edge_core::outbound` (WP-C6).
