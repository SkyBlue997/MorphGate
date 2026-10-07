//! Artifact kinds, their size limits and content-hash checks (spec §12.1).

use sha2::{Digest, Sha256};

use crate::error::IntelError;
use crate::text::{is_lower_hex_sha256, to_lower_hex};

const MIB: u64 = 1024 * 1024;

/// The artifact kinds a site bundle can reference (`ArtifactRef.name`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// `geoip-asn`: GeoLite2-ASN MaxMind DB.
    GeoipAsn,
    /// `geoip-country`: GeoLite2-Country or City MaxMind DB.
    GeoipCountry,
    /// `cloudflare-ips`: JSON, §12.2.
    CloudflareIps,
    /// `crawler-registry`: JSON, §12.3.
    CrawlerRegistry,
    /// `datacenter-asns`: text ASN list, §12.4.
    DatacenterAsns,
    /// `tor-exits`: text IP / CIDR list, §12.4.
    TorExits,
}

impl ArtifactKind {
    /// Every kind, in the order of the §12.1 table.
    pub const ALL: [ArtifactKind; 6] = [
        ArtifactKind::GeoipAsn,
        ArtifactKind::GeoipCountry,
        ArtifactKind::CloudflareIps,
        ArtifactKind::CrawlerRegistry,
        ArtifactKind::DatacenterAsns,
        ArtifactKind::TorExits,
    ];

    /// Parses an `ArtifactRef.name`. Exact, case-sensitive match.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The `ArtifactRef.name` of this kind.
    pub fn name(self) -> &'static str {
        match self {
            ArtifactKind::GeoipAsn => "geoip-asn",
            ArtifactKind::GeoipCountry => "geoip-country",
            ArtifactKind::CloudflareIps => "cloudflare-ips",
            ArtifactKind::CrawlerRegistry => "crawler-registry",
            ArtifactKind::DatacenterAsns => "datacenter-asns",
            ArtifactKind::TorExits => "tor-exits",
        }
    }

    /// The largest accepted artifact, in bytes (§12.1).
    pub fn max_size(self) -> u64 {
        match self {
            ArtifactKind::GeoipAsn | ArtifactKind::GeoipCountry => 128 * MIB,
            ArtifactKind::CloudflareIps => MIB,
            ArtifactKind::CrawlerRegistry | ArtifactKind::TorExits => 16 * MIB,
            ArtifactKind::DatacenterAsns => 4 * MIB,
        }
    }
}

/// Checks that `bytes` hash to `expected_hex` (64 lower-case hex characters,
/// as in `ArtifactRef.sha256` and content-addressed file names).
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), IntelError> {
    if !is_lower_hex_sha256(expected_hex) {
        return Err(IntelError::MalformedHash);
    }
    let actual = sha256_hex(bytes);
    if actual != expected_hex {
        return Err(IntelError::HashMismatch {
            expected: expected_hex.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_lower_hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §12.1 table.
    #[test]
    fn kinds_and_limits() {
        let table = [
            ("geoip-asn", ArtifactKind::GeoipAsn, 128 * MIB),
            ("geoip-country", ArtifactKind::GeoipCountry, 128 * MIB),
            ("cloudflare-ips", ArtifactKind::CloudflareIps, MIB),
            ("crawler-registry", ArtifactKind::CrawlerRegistry, 16 * MIB),
            ("datacenter-asns", ArtifactKind::DatacenterAsns, 4 * MIB),
            ("tor-exits", ArtifactKind::TorExits, 16 * MIB),
        ];
        for (name, kind, max) in table {
            assert_eq!(ArtifactKind::from_name(name), Some(kind));
            assert_eq!(kind.name(), name);
            assert_eq!(kind.max_size(), max);
        }
        for bad in ["", "GEOIP-ASN", "geoip_asn", "geoip-asn ", "geoip-city"] {
            assert_eq!(ArtifactKind::from_name(bad), None, "{bad:?}");
        }
    }

    /// §7.6 `verify_sha256`: FIPS 180-2 "abc" vector, mismatch, malformed.
    #[test]
    fn sha256_verification() {
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        verify_sha256(b"abc", abc).unwrap();
        assert_eq!(sha256_hex(b"abc"), abc);
        assert!(matches!(
            verify_sha256(b"abd", abc),
            Err(IntelError::HashMismatch { .. })
        ));
        assert!(matches!(
            verify_sha256(b"abc", &abc.to_uppercase()),
            Err(IntelError::MalformedHash)
        ));
        assert!(matches!(
            verify_sha256(b"abc", &abc[..63]),
            Err(IntelError::MalformedHash)
        ));
        assert!(matches!(
            verify_sha256(b"abc", ""),
            Err(IntelError::MalformedHash)
        ));
    }
}
