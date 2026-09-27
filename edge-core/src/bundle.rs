//! Signed bundle client (docs/impl/phase1-spec.md §9.10, work package WP-C2).
//!
//! The Edge's policy arrives as one owner-signed `morphgate.v1.SignedBundle`
//! per site, published by `mgctl bundle publish` into a static directory
//! (§12.1):
//!
//! ```text
//! <bundle_root>bundles/<site>.bundle   SignedBundle, replaced atomically
//! <bundle_root>artifacts/<sha256>      content-addressed artifact files
//! ```
//!
//! This module holds everything between "bytes on a disk or a web server" and
//! "a verified `SiteBundle` plus its artifact bytes"; turning those into a
//! site runtime (rules, routes, limiters, key sets, intel tables) is the
//! caller's job (mg-edge, WP-E1a):
//!
//! | Item | Purpose |
//! |---|---|
//! | [`OwnerKeys`] | the `[trust] owner_keys` public key files (§12.6) |
//! | [`verify_bundle`] | synchronous: size, decode, Ed25519 signature, schema, site, hosts and the §8.2 bounds |
//! | [`Source`], [`Fetcher`] | `file://` and HTTP(S) fetches with ETag, same-origin redirects, no proxy |
//! | [`StateDir`] | the last-known-good (LKG) bundle per site and the artifact cache |
//! | [`poll_loop`] | one site's poll / verify / fetch-artifacts / apply / persist loop |
//! | [`metrics`] | `mg_config_*` and `mg_artifact_missing` (§13.7) |
//!
//! Security properties this module guarantees (§9.10):
//!
//! * Nothing is applied unless its Ed25519 signature verifies under a key in
//!   [`OwnerKeys`], over exactly `"mg-bundle-v1" || 0x00 || bundle`.
//! * A bundle for another site, other hosts, an unknown schema or with any
//!   §8.2 bound violated is rejected as a whole.
//! * The poll loop only moves forward: a candidate must have a higher
//!   `version` than the bundle in effect (equal version with identical bytes
//!   is a no-op).
//! * Artifacts are content-addressed: every artifact is checked against the
//!   SHA-256 and size in the signed bundle, whether it came from the cache or
//!   the network.
//! * Outbound HTTP never uses a proxy from the environment
//!   (`ClientBuilder::no_proxy`) and never follows a redirect to another
//!   origin.
//! * The LKG file is replaced atomically (temporary file, `fsync`, `rename`),
//!   so a crash never leaves a half-written bundle where the next start reads
//!   it.

mod fetch;
mod keys;
mod metrics;
mod poll;
mod store;
mod util;
mod validate;
mod verify;

pub(crate) use fetch::is_internal_ip;
pub use fetch::{Fetched, Fetcher, FetcherConfig, Source};
pub use keys::OwnerKeys;
pub use metrics::{BundleMetrics, metrics};
pub use poll::{SiteSource, poll_loop};
pub use store::StateDir;
pub use verify::{VerifiedBundle, verify_bundle};

/// Largest accepted serialized `SiteBundle` (§8.2: "序列化后的配置包 ≤ 8 MiB").
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// Largest accepted `SignedBundle` file: [`MAX_BUNDLE_BYTES`] plus room for
/// the envelope (key id and 64-byte signature, well under 1 KiB), so every
/// bundle the builder accepts also fits the Edge's fetch limit.
pub const MAX_SIGNED_BUNDLE_BYTES: usize = MAX_BUNDLE_BYTES + 1024;

/// Domain prefix of the signing input (§3.2, `kat.json` `bundle_signature`).
pub const SIGNING_DOMAIN: &[u8] = b"mg-bundle-v1\x00";

/// The only `SiteBundle.schema_version` this Edge understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Artifact names of Phase 1 and their size limits in bytes (§12.1).
pub const ARTIFACT_LIMITS: &[(&str, u64)] = &[
    ("geoip-asn", 128 * 1024 * 1024),
    ("geoip-country", 128 * 1024 * 1024),
    ("cloudflare-ips", 1024 * 1024),
    ("crawler-registry", 16 * 1024 * 1024),
    ("datacenter-asns", 4 * 1024 * 1024),
    ("tor-exits", 16 * 1024 * 1024),
];

/// Size limit of the artifact kind `name`, or `None` for an unknown name.
pub fn artifact_limit(name: &str) -> Option<u64> {
    ARTIFACT_LIMITS
        .iter()
        .find_map(|&(n, limit)| (n == name).then_some(limit))
}

/// The bytes the owner key signs: `"mg-bundle-v1" || 0x00 || bundle`.
pub fn signing_input(bundle: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNING_DOMAIN.len() + bundle.len());
    input.extend_from_slice(SIGNING_DOMAIN);
    input.extend_from_slice(bundle);
    input
}

/// Why a bundle, key file, fetch or artifact was refused.
///
/// Messages never contain key material; they may contain site ids, host
/// names, key ids, artifact hashes and URLs (which [`Source::parse`] keeps
/// free of credentials).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// The input exceeds its size limit.
    #[error("{what} is larger than {limit} bytes")]
    TooLarge { what: &'static str, limit: u64 },
    /// Protobuf decoding failed.
    #[error("cannot decode {what}: {detail}")]
    Decode { what: &'static str, detail: String },
    /// `SignedBundle.key_id` is not one of the trusted owner keys.
    #[error("bundle signed with unknown owner key {0:?}")]
    UnknownKey(String),
    /// The Ed25519 signature does not verify.
    #[error("bundle signature does not verify")]
    BadSignature,
    /// `SiteBundle.schema_version` is not [`SCHEMA_VERSION`].
    #[error("unsupported schema_version {0} (expected {SCHEMA_VERSION})")]
    SchemaVersion(u32),
    /// `SiteBundle.site_id` is not the site this bundle was fetched for.
    #[error("bundle is for site {found:?}, expected {expected:?}")]
    SiteMismatch { expected: String, found: String },
    /// `SiteBundle.hosts` differs from the site's hosts in edge.toml.
    #[error("bundle hosts {found:?} differ from edge.toml hosts {expected:?}")]
    HostsMismatch {
        expected: Vec<String>,
        found: Vec<String>,
    },
    /// A §8.2 bound or another structural rule is violated.
    #[error("invalid bundle: {field}: {reason}")]
    Invalid { field: String, reason: String },
    /// An owner public key file is malformed (§12.6).
    #[error("owner key file {file}: {reason}")]
    KeyFile { file: String, reason: String },
    /// A `bundle_root` is not an acceptable source.
    #[error("invalid bundle source: {0}")]
    Source(String),
    /// The HTTP client could not be built from the configuration.
    #[error("bundle client configuration: {0}")]
    Client(String),
    /// Network or file-system failure while fetching.
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// The fetch did not complete within the configured timeout.
    #[error("fetch timed out")]
    Timeout,
    /// The server answered with a status other than 200 / 304.
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    /// A fetched or cached artifact does not match its reference.
    #[error("artifact {sha256}: {reason}")]
    Artifact { sha256: String, reason: String },
    /// Local file-system error.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl BundleError {
    /// Short, stable reason code for logs and `--check-config` output.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "too_large",
            Self::Decode { .. } => "decode",
            Self::UnknownKey(_) => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::SchemaVersion(_) => "schema_version",
            Self::SiteMismatch { .. } => "site_mismatch",
            Self::HostsMismatch { .. } => "hosts_mismatch",
            Self::Invalid { .. } => "invalid",
            Self::KeyFile { .. } => "key_file",
            Self::Source(_) => "source",
            Self::Client(_) => "client",
            Self::Fetch(_) => "fetch",
            Self::Timeout => "timeout",
            Self::Status(_) => "status",
            Self::Artifact { .. } => "artifact",
            Self::Io(_) => "io",
        }
    }

    /// Whether the error came from reaching the source (network, file
    /// system, HTTP status) rather than from the content that was fetched.
    /// The poll loop counts these as `mg_config_fetch_failures_total`.
    pub fn is_fetch_failure(&self) -> bool {
        matches!(
            self,
            Self::Fetch(_) | Self::Timeout | Self::Status(_) | Self::Io(_)
        )
    }

    pub(crate) fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.into(),
        }
    }
}
