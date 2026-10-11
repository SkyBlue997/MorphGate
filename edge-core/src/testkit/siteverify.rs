//! Loopback mock of the Turnstile siteverify endpoint
//! (docs/impl/phase2-spec.md §8.4, D-52): programmable responses, delays and
//! disconnects per request, and a record of the requests received. Every
//! Turnstile test uses it; no test reaches `challenges.cloudflare.com`.
//!
//! Phase 2, WP-C6. Empty until that work package lands.
