//! `MG-Proof` verification (docs/impl/phase2-spec.md §6.7, D-40): the
//! compact ES256 JWS with header `{alg, typ: "mg-proof+jwt", jwk}` and payload
//! `{htm, htu, iat, jti}`, checked cheapest first (`proof.malformed`,
//! `unbound`, `jkt`, `htm`, `htu`, `iat`, `sig`).
//!
//! Phase 2, WP-R5. Empty until that work package lands.
