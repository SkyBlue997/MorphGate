//! # mg-edge-core: Edge components without Pingora
//!
//! Pre-registered Phase 1 crate (docs/impl/phase1-spec.md §2, §9). Each module
//! is owned by one stage-1 work package and takes plain Rust inputs (header
//! name / value slices, socket addresses, bytes), so it is unit-testable
//! without Pingora; `mg-edge` wires the modules into its proxy services and
//! background services in stage 2.
//!
//! | Module | Work package | Contents |
//! |---|---|---|
//! | [`upstream`] | WP-C1 | header-family stripping, `cloudflare` trusted-header parsing, `CF-Worker` zone check |
//! | [`request`] | WP-C1 | Host / `:authority` resolution, protocol limits (414 / 431 / 400), header-name order |
//! | [`bundle`] | WP-C2 | signed bundle fetch (file / HTTP(S), ETag), Ed25519 verification, LKG store, artifact cache |
//! | [`state`] | WP-C3 | Valkey client (pipelines, `mg_gcra`, `mg_nonce_issue`), circuit breaker, local mode |
//! | [`events`] | WP-C4 | bounded event queues, VictoriaLogs `jsonline` batches, file sink, `mg:ev` entries |
//! | [`origin_auth`] | I-38 | `MG-Origin-Auth`: Edge → origin HMAC signing and the reference check |
//! | [`outbound`] | Phase 2 WP-C6 | outbound HTTP, the Turnstile siteverify client and its circuit breaker (docs/impl/phase2-spec.md §8.4) |
//!
//! The `testkit` feature adds shared test helpers (a signed-bundle builder and
//! HTTP test server, a Valkey fixture with a fault-injecting proxy, a fake
//! VictoriaLogs), for these crate tests and for `mg-edge`'s stage-2 tests.

pub mod bundle;
pub mod events;
pub mod origin_auth;
pub mod outbound;
pub mod request;
pub mod state;
pub mod upstream;

#[cfg(feature = "testkit")]
pub mod testkit;
