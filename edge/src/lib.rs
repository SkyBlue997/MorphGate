//! # mg-edge: the MorphGate Edge
//!
//! A Pingora (`=0.9.0`, BoringSSL) reverse proxy between the upstream
//! (Cloudflare Tunnel's `cloudflared` on loopback, Cloudflare Authenticated
//! Origin Pulls, or visitors directly) and the owner's origin.
//! docs/impl/phase1-spec.md §9 is the contract; this crate wires the
//! Pingora-free components of `mg-edge-core`, `mg-core`, `mg-challenge` and
//! `mg-intel` into Pingora services.
//!
//! Phase 1 skeleton (WP-E1a):
//!
//! * `edge.toml` v1 with credentials and `--check-config` ([`config`],
//!   [`creds`], [`startup`]);
//! * the process model: synchronous start-up, then Pingora background
//!   services for bundles, state, events and rDNS ([`server`],
//!   [`background`]);
//! * listeners with upstream authentication and TLS ([`listener`], [`tls`]);
//! * the request pipeline: protocol limits, header hygiene and trusted
//!   `cloudflare` headers, Host → site, the site state machine, foreign
//!   Worker rejection, `/__mg/*`, multi-view route matching, monitor /
//!   bootstrap forwarding with the origin headers ([`proxy`], [`headers`],
//!   [`enforce`], [`routes`], [`sites`]);
//! * signed bundles → site runtimes ([`sites`]), the SDK directory
//!   ([`sdk`]), the OS random number generator ([`rng`]), metrics
//!   ([`metrics`]) and logging without client addresses ([`logging`]).
//!
//! Phase 1 decisions (WP-E1b):
//!
//! * the Decision Core's inputs: [`context`] (RequestContext, `req.headers`,
//!   MissingSet), [`identity`] (clearance cookies, crawler verification and
//!   the rDNS job dispatch), [`dns`] (the hickory resolver), [`ratelimit`]
//!   (limiters, verdicts, the state round trip);
//! * [`decide`]: one `DecisionCore` per bundle environment and the §9.9
//!   execution layer (monitor, block, rate limit, unknown client IP).
//!
//! Phase 1 challenges (WP-E1c):
//!
//! * [`challenge`]: issuing a sealed challenge `C` for a CHALLENGE decision
//!   (difficulty, return path, 429 without a client IP, 308 for http
//!   visitors);
//! * [`pages`]: the challenge page with its per-response CSP nonce and the
//!   JSON answers; [`sdk`]: the SDK directory and the template contract;
//! * [`mg_endpoints`]: `/__mg/s/<file>` and the `POST /__mg/c` flow (body
//!   rules in [`submission`], replay checks, issuance quotas, failure
//!   escalation and counting, the clearance cookie).
//!
//! Phase 1 observability (WP-E1d):
//!
//! * [`events`]: the decision, access, feedback, telemetry and `mg:ev`
//!   records of a finished request (sampling, path redaction), written from
//!   [`proxy`]'s `logging` into the `mg-events` pipeline, whose `mg:ev`
//!   output is the state layer ([`background`]);
//! * [`metrics`]: the full §13.7 set, including the Edge's added latency
//!   and the origin connect time ([`metrics::Timing`]).

pub mod background;
pub mod challenge;
pub mod config;
pub mod context;
pub mod creds;
pub mod decide;
pub mod dns;
pub mod enforce;
pub mod events;
pub mod headers;
pub mod identity;
pub mod listener;
pub mod logging;
pub mod metrics;
pub mod mg_endpoints;
pub mod pages;
pub mod proxy;
pub mod ratelimit;
pub mod rng;
pub mod routes;
pub mod sdk;
pub mod server;
pub mod sites;
pub mod startup;
pub mod submission;
pub mod tls;

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};

    /// A path relative to the repository root.
    pub(crate) fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
    }
}
