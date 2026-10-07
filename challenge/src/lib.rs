//! # mg-challenge: challenge and clearance cryptography
//!
//! Phase 1 work package WP-R2 (docs/impl/phase1-spec.md §6). A pure library
//! used by `mg-edge` for every cryptographic step of the challenge flow, so
//! the Edge never touches `pasetors` or `chacha20poly1305` directly:
//!
//! * [`keys`]: per-site key files (`seal.root.json`, `token.keys.json`,
//!   §12.7), daily epochs and the HKDF-derived epoch keys (§6.1);
//! * [`sealed`]: the sealed challenge `C`, prost-encoded
//!   `SealedChallengeClaims` inside XChaCha20-Poly1305 with a
//!   length-delimited `aad = host ‖ type ‖ kid` (§6.2, ADR-0005);
//! * [`pow`]: the SHA-256 hashcash proof of work and a reference solver for
//!   tests (§6.3);
//! * [`bind`]: binding hashes (`uah`, `ipp`, `ipa`, `ctp`), the return path
//!   `ret` and the binding comparison shared by `C` and clearance tokens
//!   (§6.4);
//! * [`clearance`]: PASETO v4.local clearance tokens (`__Host-mg_clr`): mint,
//!   verify, session reuse and the cookie helpers (§6.5, §6.6).
//!
//! ## Rules for this crate
//!
//! * **No I/O, no clock, no global RNG.** Callers pass `now` and an [`Rng`]
//!   (`mg-edge` backs it with `getrandom`). The one exception is the PASETO
//!   nonce, which `pasetors` draws from the OS RNG itself. Enforced for the
//!   clock, threads and the environment by `challenge/clippy.toml`.
//! * **Never panics on input.** Every parser checks lengths before any
//!   fixed-size cryptographic construction; errors are values.
//! * **Nothing secret in `Debug` or `Display`.** Keys, nonces, `C`, tokens,
//!   session ids and binding hashes (an `ipp` hash is as good as the IP
//!   prefix) are never printed.
//!
//! Every public item is re-exported at the crate root.

mod b64;
pub mod bind;
pub mod clearance;
mod json;
pub mod keys;
pub mod pow;
pub mod rng;
pub mod sealed;

pub use bind::{
    BIND_HASH_LEN, BindCheck, BindInputs, MAX_RET_LEN, RetError, bind_hash, check_challenge_bind,
    ctp, ipa, ipp, ret_hash, uah, validate_ret,
};
pub use clearance::{
    COOKIE_NAME, ClearanceBind, ClearanceClaims, MAX_COOKIE_BYTES, MAX_COOKIE_CANDIDATES,
    MAX_TOKEN_LEN, MAX_TOKEN_LIFETIME_S, MintParams, TOKEN_CLOCK_SKEW_S, TokenError,
    check_clearance_bind, clearance_cookies, mint, reusable_session, set_cookie_value, verify,
    verify_ignoring_expiry,
};
pub use keys::{
    CLOCK_SKEW_MS, EPOCH_MS, KeyError, MAX_C_LIFETIME_MS, SealKeys, SealRoot, TokenKeySet,
    accepted_epochs, derive_bind_epoch_key, derive_epoch_key, epoch_kid, epoch_no, parse_epoch_kid,
};
#[doc(hidden)]
pub use pow::pow_solve;
pub use pow::{MAX_POW_BITS, MAX_POW_COUNTER, POW_ALG, leading_zero_bits, pow_prefix, pow_verify};
pub use rng::{Rng, RngError};
pub use sealed::{MAX_C_LEN, MAX_HOST_LEN, OpenError, SealError, Sealer, aad, random_nonce};
