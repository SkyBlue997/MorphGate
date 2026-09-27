//! # mg-intel: intelligence data for the Edge
//!
//! Phase 1 work package WP-R3 (docs/impl/phase1-spec.md §7, §12.1–§12.4):
//!
//! * [`IpSet`]: CIDR prefix sets with IPv4-mapped IPv6 normalisation
//!   (Cloudflare ranges, crawler ranges, Tor exits);
//! * [`GeoDb`]: GeoLite2 ASN / country enrichment from `.mmdb` bytes,
//!   distinguishing "not in the database" ([`Lookup::NotFound`], ABSENT) from
//!   "no database" ([`Lookup::Unavailable`], MISSING);
//! * [`CrawlerRegistry`]: the crawler registry artifact with every validation
//!   rule of §12.3 (D-36), UA claim matching;
//! * [`CrawlerVerifier`]: official IP range checks and the asynchronous rDNS
//!   verification state machine with its cache and in-flight set, behind the
//!   [`DnsResolver`] trait ([`resolve_rdns`]; hickory implementation in
//!   mg-edge, [`StaticResolver`] for tests and the Validation Lab);
//! * parsers for the Cloudflare IP ranges artifact ([`parse_cloudflare_ips`])
//!   and the plain-text lists ([`parse_asn_list`], [`IpSet::from_text`]);
//! * [`ArtifactKind`] names, size limits and [`verify_sha256`].
//!
//! No network or file I/O and no clock: artifacts are parsed from bytes, DNS
//! goes through [`DnsResolver`], and every time is passed in by the caller.
//! `Debug` output never contains client addresses.

mod artifact;
mod cfips;
mod cidr;
mod crawler;
mod dns;
mod error;
mod geo;
mod ipset;
mod lists;
mod text;

pub use artifact::{ArtifactKind, sha256_hex, verify_sha256};
pub use cfips::{CloudflareIps, parse_cloudflare_ips};
pub use crawler::{
    CacheConfig, CrawlerRegistry, CrawlerStatus, CrawlerVerifier, Operator, PURPOSES, RdnsJob,
    RdnsOutcome, VerifyMethod, VerifyMode,
};
pub use dns::{DnsError, DnsResolver, MAX_PTR_NAMES, StaticResolver, resolve_rdns};
pub use error::IntelError;
pub use geo::{GeoDb, GeoInfo, Lookup};
pub use ipset::{IpSet, MAX_IPSET_ENTRIES};
pub use lists::parse_asn_list;
