//! # mg-challenge: challenge and clearance cryptography
//!
//! Phase 1 work package WP-R2 (docs/impl/phase1-spec.md §6) implements, as a
//! pure library used by `mg-edge`:
//!
//! * sealed challenges `C`: prost-encoded `SealedChallengeClaims` inside
//!   XChaCha20-Poly1305 with `aad = len16(host) || host || len16(type) || type
//!   || len16(kid) || kid`, keyed by per-day epoch keys derived with
//!   HKDF-SHA256 from the per-site root `K_seal_root` (ADR-0005);
//! * SHA-256 hashcash proof of work: parameters, verification and a
//!   reference solver for tests;
//! * PASETO v4.local clearance tokens (`__Host-mg_clr`): mint, verify and the
//!   binding checks `uah` (hard), `ipp`/`ipa` (soft) and `ctp` (shadow);
//! * binding, return-path and key-file helpers shared with the Edge.
//!
//! No network or file I/O, no clock and no global RNG: callers pass `now`
//! and an `Rng`. The crate is empty until WP-R2 lands.
