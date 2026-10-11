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
//! Phase 2 (WP-R5, docs/impl/phase2-spec.md §6) changes and adds:
//!
//! * [`keys`]: one accepted-epoch window of 605 s for every type (§6.1);
//! * [`sealed`]: per-type lifetimes (interactive 600 s) and
//!   [`Sealer::open_for_renew`] (§6.1, §6.10);
//! * [`ui`]: the control parameters derived from `ui_seed` (§6.3);
//! * [`pow`]: the interactive `sha256-hashcash-v2` with `k` sub-puzzles
//!   (§6.4);
//! * [`jwk`]: SDK session keys, RFC 7638 thumbprints and ES256 verification
//!   through `aws-lc-rs` (§6.5);
//! * [`sig`]: the signed submission and renewal messages (§6.6);
//! * [`proof`]: `MG-Proof` verification (§6.7);
//! * [`clearance`]: claims v2 with `lat` and `cnf`, [`mint_v2`],
//!   [`mint_refresh`] and the status cookie (§6.8);
//! * [`turnstile`]: Turnstile `cData` and the siteverify idempotency key
//!   (§6.9);
//! * `testkit` (feature `testkit`): signing, proofs and the v2 PoW solver for
//!   the Edge's integration tests.
//!
//! ## Rules for this crate
//!
//! * **No I/O, no clock, no global RNG.** Callers pass `now` and an [`Rng`]
//!   (`mg-edge` backs it with `getrandom`). The one exception is the PASETO
//!   nonce, which `pasetors` draws from the OS RNG itself (and, in the
//!   `testkit` module only, the test signatures). Enforced for the
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
pub mod jwk;
pub mod keys;
pub mod pow;
pub mod proof;
pub mod rng;
pub mod sealed;
pub mod sig;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod turnstile;
pub mod ui;

pub use bind::{
    BIND_HASH_LEN, BindCheck, BindInputs, MAX_RET_LEN, RetError, bind_hash, check_challenge_bind,
    ctp, ipa, ipp, ret_hash, uah, validate_ret,
};
pub use clearance::{
    CLAIMS_V1, CLAIMS_V2, COOKIE_NAME, ClearanceBind, ClearanceClaims, Cnf, MAX_COOKIE_BYTES,
    MAX_COOKIE_CANDIDATES, MAX_TOKEN_LEN, MAX_TOKEN_LIFETIME_S, MintParams, MintV2Params,
    STATUS_COOKIE_NAME, TOKEN_CLOCK_SKEW_S, TokenError, check_clearance_bind, clearance_cookies,
    mint, mint_refresh, mint_v2, reusable_session, reusable_session_v2, set_cookie_value,
    status_cookie_value, status_set_cookie_value, verify, verify_ignoring_expiry,
};
pub use jwk::{
    ES256_SIG_B64_LEN, JKT_LEN, Jwk, JwkError, MAX_JWK_JSON_LEN, SessionKey, is_jkt, jwk_thumbprint,
};
pub use keys::{
    CLOCK_SKEW_MS, EPOCH_MS, KeyError, MAX_C_LIFETIME_MS, MAX_INTERACTIVE_C_LIFETIME_MS,
    PREVIOUS_EPOCH_WINDOW_MS, SealKeys, SealRoot, TokenKeySet, accepted_epochs,
    derive_bind_epoch_key, derive_epoch_key, epoch_kid, epoch_no, parse_epoch_kid,
};
pub use pow::{
    MAX_POW_BITS, MAX_POW_COUNTER, MAX_POW_K, POW_ALG, POW_ALG_V2, leading_zero_bits,
    pow_digest_v2, pow_prefix, pow_prefix_v2, pow_verify, pow_verify_v2,
};
#[doc(hidden)]
pub use pow::{pow_solve, pow_solve_v2};
pub use proof::{
    JTI_B64_LEN, MAX_HTM_LEN, MAX_HTU_LEN, MAX_PROOF_LEN, PROOF_MAX_AGE_S, PROOF_MAX_FUTURE_S,
    ProofError, ProofRequest, VerifiedProof, proof_signing_key, verify_proof,
};
pub use rng::{Rng, RngError};
pub use sealed::{
    MAX_C_LEN, MAX_HOST_LEN, OpenError, RENEW_MAX_EXPIRED_MS, RenewOpenError, SealError, Sealer,
    aad, max_c_lifetime_ms, random_nonce,
};
pub use sig::{SubmissionFields, counters_text, renew_message, submission_message};
pub use turnstile::{
    CDATA_LEN, idempotency_key, turnstile_cdata, turnstile_cdata_for, turnstile_cdata_matches,
};
pub use ui::{MAX_HOLD_MS, MIN_HOLD_MS, UiParams, ui_params};
