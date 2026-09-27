//! # mg-intel: intelligence data for the Edge
//!
//! Phase 1 work package WP-R3 (docs/impl/phase1-spec.md §7) implements:
//!
//! * `IpSet`: CIDR prefix sets with IPv4-mapped IPv6 normalisation (Cloudflare
//!   ranges, crawler ranges, Tor exits);
//! * GeoLite2 ASN / country enrichment from `.mmdb` bytes, distinguishing "not
//!   in the database" (ABSENT) from "no database" (MISSING);
//! * the crawler registry artifact format, UA claim matching, official IP
//!   range checks and the asynchronous rDNS verification state machine with
//!   its cache, behind a `DnsResolver` trait (hickory implementation in
//!   mg-edge; a static resolver for tests and the Validation Lab here);
//! * parsers for the Cloudflare IP ranges artifact and plain-text lists.
//!
//! No network I/O. The crate is empty until WP-R3 lands.
