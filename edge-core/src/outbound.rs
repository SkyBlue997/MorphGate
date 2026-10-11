//! Outbound HTTP of the Edge (docs/impl/phase2-spec.md §8.4, §8.6): the only
//! implementation of `mg_core::challenge::OutboundHttp` (reqwest without
//! proxies, a fixed User-Agent, a process-wide concurrency limit), the
//! Turnstile siteverify client with the error mapping of §8.5, the
//! siteverify URL check (the production URL, or a loopback mock only when
//! the caller allows test destinations) and the per-provider circuit
//! breaker. It runs only on the background-service runtime.
//!
//! Phase 2, WP-C6. Empty until that work package lands.
