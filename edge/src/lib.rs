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
//!
//! Phase 2 interactive challenges (docs/impl/phase2-spec.md, WP-E2a):
//!
//! * the bundle's `schema_version` (D-66), interactive settings and
//!   `interactive_available` (§5.1) in [`sites`]; manifest v1 / v2 SDK
//!   directories and the `/__mg/s/mg.js` alias in [`sdk`] and
//!   [`mg_endpoints`];
//! * [`interactive`]: the interactive `C`, its plain parameters `ix` and the
//!   built-in limiters `mg.ix.issue`, `mg.c.renew`, `mg.a11y.issue`;
//!   issued by [`challenge`] (template v2 page, JSON with `ix`);
//! * `POST /__mg/c` v2 (session-key signature, PoW v2, the hard checks and
//!   the score, v2 tokens with `cnf.jkt`, `__Host-mg_st`, `__Host-mg_a11y`)
//!   in [`mg_endpoints`] and [`submission`], and `POST /__mg/c/renew` in
//!   [`renew`]; `/__mg/v?…&min=interactive` (D-58) in [`decide`].

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
pub mod interactive;
pub mod listener;
pub mod logging;
pub mod metrics;
pub mod mg_endpoints;
pub mod pages;
pub mod proof;
pub mod proxy;
pub mod ratelimit;
pub mod renew;
pub mod rng;
pub mod routes;
pub mod sdk;
pub mod server;
pub mod sites;
pub mod startup;
pub mod submission;
pub mod tls;

/// The commit this binary was built from (`edge/build.rs`), or `unknown`.
pub const COMMIT: &str = env!("MG_EDGE_COMMIT");

/// `mg-edge --version`: the package version and [`COMMIT`].
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("MG_EDGE_COMMIT"), ")");

#[cfg(test)]
pub(crate) mod test_support {
    use crate::config::{BootstrapMode, CredRef, LkgInvalidMode};
    use crate::creds::{CredResolver, read_secret};
    use crate::sdk::SdkDir;
    use crate::sites::{BundleRuntime, SiteKeys, SiteSettings, build_runtime};
    use mg_challenge::SealKeys;
    use mg_core::UpstreamProfileKind;
    use mg_edge_core::bundle::verify_bundle;
    use mg_edge_core::testkit::http::{
        OWNER_TEST_KID, OWNER_TEST_SEED, owner_test_keys, sign_test_bundle,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// The test hosts of site "blog".
    pub(crate) const HOSTS: [&str; 3] = ["example.com", "www.example.com", "staging.example.com"];

    /// A path relative to the repository root.
    pub(crate) fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
    }

    /// The SDK directory fixture: manifest v2 (the current build), or the
    /// frozen manifest v1 directory of the Phase 2 switch (§2.1).
    pub(crate) fn sdk(v2: bool) -> SdkDir {
        let dir = if v2 { "sdk" } else { "sdk-v1" };
        SdkDir::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(dir),
        )
        .unwrap()
    }

    /// The edge.toml side of site "blog" (one cloudflare listener).
    pub(crate) fn settings(sdk_v2: bool) -> SiteSettings {
        SiteSettings {
            id: "blog".into(),
            hosts: HOSTS.iter().map(|h| (*h).to_string()).collect(),
            listeners: vec!["cf-tunnel".into()],
            listener_kinds: vec![("cf-tunnel".into(), UpstreamProfileKind::Cloudflare)],
            origin: "127.0.0.1:9".parse().unwrap(),
            bootstrap: BootstrapMode::Open,
            on_lkg_invalid: LkgInvalidMode::Closed,
            bootstrap_owner_zones: Vec::new(),
            crawler_cache: mg_intel::CacheConfig::default(),
            sdk_manifest_v2: sdk_v2,
            force_monitor: false,
        }
    }

    /// The test keys of site "blog".
    pub(crate) fn keys() -> SiteKeys {
        let seal = std::fs::read(repo("testdata/phase1/keys/seal.root.json")).unwrap();
        let token = CredRef::Path(repo("testdata/phase1/keys/token.keys.json"));
        SiteKeys {
            seal: SealKeys::from_key_file(&seal, "blog").unwrap(),
            token_file: read_secret(&CredResolver::with_dir(None), &token, &mut |_| {}).unwrap(),
            origin: None,
        }
    }

    /// Converts `b` exactly as the Edge does (verify, then build the
    /// runtime), with a manifest v2 SDK directory when `sdk_v2`.
    pub(crate) fn runtime(b: &mg_proto::v1::SiteBundle, sdk_v2: bool) -> BundleRuntime {
        let signed = sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID);
        let s = settings(sdk_v2);
        let vb = verify_bundle(&signed, &owner_test_keys(), "blog", &s.hosts).unwrap();
        build_runtime(&s, &keys(), &vb, &BTreeMap::new()).unwrap()
    }
}
