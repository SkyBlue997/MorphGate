//! # mg-edge: the MorphGate Edge
//!
//! A Pingora (`=0.9.0`, BoringSSL) reverse proxy that sits between the
//! upstream (Cloudflare Tunnel's `cloudflared` on loopback, or visitors
//! directly) and the origin.
//!
//! Phase 0 behaviour:
//!
//! * serves `GET /__mg/healthz` itself (`200 ok`, `Cache-Control: no-store, private`);
//!   other `/__mg/*` paths, including every spelling Cloudflare's rules
//!   normalize to one (`//__mg/x`, `/%5F%5Fmg/x`, ...), are reserved and
//!   answered `404`;
//! * proxies everything else to the configured origin, removing client-sent
//!   `MG-*` headers;
//! * exposes Prometheus metrics on `metrics_listen`.
//!
//! All Pingora-specific code lives in this crate. Upstream authentication,
//! signal extraction and the Decision Core call are added in Phase 1 at the
//! points marked in [`proxy`].

pub mod config;
pub mod headers;
pub mod metrics;
pub mod proxy;
pub mod routes;
pub mod server;
