//! GeoLite2 ASN / country enrichment (spec §7.2).

use std::fmt;
use std::net::IpAddr;

use maxminddb::{PathElement, Reader};

use crate::artifact::ArtifactKind;
use crate::error::{IntelError, bounded, check_size, quote};

/// The result of looking one field up.
///
/// The distinction matters for policy evaluation (spec §4.1): `NotFound` means
/// the database was consulted and has no value for this address (the field is
/// ABSENT, i.e. its zero value), `Unavailable` means there is no database to
/// consult (the field is MISSING).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<T> {
    /// The database has a value for this address.
    Found(T),
    /// The database has no value for this address (ABSENT).
    NotFound,
    /// No database, or its record could not be decoded (MISSING).
    Unavailable,
}

impl<T> Lookup<T> {
    /// The value, if found.
    pub fn found(&self) -> Option<&T> {
        match self {
            Lookup::Found(v) => Some(v),
            _ => None,
        }
    }

    /// True for [`Lookup::Unavailable`].
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Lookup::Unavailable)
    }
}

/// GeoLite2 data for one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoInfo {
    /// `autonomous_system_number`; ASN 0 is reported as `NotFound`.
    pub asn: Lookup<u32>,
    /// `autonomous_system_organization`.
    pub as_org: Lookup<String>,
    /// `country.iso_code`, else `registered_country.iso_code`.
    pub country: Lookup<String>,
}

/// The loaded GeoLite2 databases. Either may be absent; lookups against an
/// absent database return [`Lookup::Unavailable`].
pub struct GeoDb {
    asn: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
}

impl fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind =
            |r: &Option<Reader<Vec<u8>>>| r.as_ref().map(|r| r.metadata().database_type.clone());
        f.debug_struct("GeoDb")
            .field("asn", &kind(&self.asn))
            .field("country", &kind(&self.country))
            .finish()
    }
}

impl GeoDb {
    /// Opens the databases from their bytes (the Edge reads them from the
    /// artifact cache). The ASN database's `database_type` must contain
    /// `ASN`; the country database's must contain `Country` or `City`
    /// (spec §7.2). Each is limited to the 128 MiB artifact size (§12.1).
    pub fn load(
        asn_mmdb: Option<Vec<u8>>,
        country_mmdb: Option<Vec<u8>>,
    ) -> Result<Self, IntelError> {
        let asn = asn_mmdb
            .map(|bytes| open(bytes, ArtifactKind::GeoipAsn, "ASN", &["ASN"]))
            .transpose()?;
        let country = country_mmdb
            .map(|bytes| {
                open(
                    bytes,
                    ArtifactKind::GeoipCountry,
                    "country",
                    &["Country", "City"],
                )
            })
            .transpose()?;
        Ok(Self { asn, country })
    }

    /// No databases: every lookup is `Unavailable`.
    pub fn empty() -> Self {
        Self {
            asn: None,
            country: None,
        }
    }

    /// Whether an ASN database is loaded.
    pub fn has_asn(&self) -> bool {
        self.asn.is_some()
    }

    /// Whether a country database is loaded.
    pub fn has_country(&self) -> bool {
        self.country.is_some()
    }

    /// Looks `ip` up in both databases. IPv4-mapped addresses are looked up
    /// as IPv4. A record that cannot be decoded (corrupt database) yields
    /// `Unavailable` for that database's fields rather than a guess.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let ip = ip.to_canonical();
        let (asn, as_org) = match &self.asn {
            None => (Lookup::Unavailable, Lookup::Unavailable),
            Some(reader) => lookup_asn(reader, ip),
        };
        let country = match &self.country {
            None => Lookup::Unavailable,
            Some(reader) => lookup_country(reader, ip),
        };
        GeoInfo {
            asn,
            as_org,
            country,
        }
    }
}

fn open(
    bytes: Vec<u8>,
    kind: ArtifactKind,
    which: &'static str,
    accepted: &[&str],
) -> Result<Reader<Vec<u8>>, IntelError> {
    check_size(kind.name(), bytes.len(), kind.max_size())?;
    let reader = Reader::from_source(bytes).map_err(|e| IntelError::Mmdb {
        which,
        reason: bounded(e.to_string()),
    })?;
    let database_type = &reader.metadata().database_type;
    if !accepted.iter().any(|a| database_type.contains(a)) {
        return Err(IntelError::Mmdb {
            which,
            reason: wrong_type(database_type, accepted),
        });
    }
    Ok(reader)
}

/// The rejection reason for a wrong `database_type`, which comes from the
/// file and is therefore quoted with a length bound.
fn wrong_type(database_type: &str, accepted: &[&str]) -> String {
    format!(
        "database_type {} does not contain {}",
        quote(database_type),
        accepted.join(" or ")
    )
}

/// What one record lookup produced.
enum Record<'a> {
    /// The address is not in the database.
    Absent,
    /// The lookup itself failed (corrupt tree).
    Error,
    Present(maxminddb::LookupResult<'a, Vec<u8>>),
}

fn record(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Record<'_> {
    // An IPv4-only database has no IPv6 addresses; maxminddb reports an
    // input error for them, which is simply "not in the database".
    if ip.is_ipv6() && reader.metadata().ip_version == 4 {
        return Record::Absent;
    }
    match reader.lookup(ip) {
        Ok(r) if r.has_data() => Record::Present(r),
        Ok(_) => Record::Absent,
        Err(_) => Record::Error,
    }
}

fn lookup_asn(reader: &Reader<Vec<u8>>, ip: IpAddr) -> (Lookup<u32>, Lookup<String>) {
    let r = match record(reader, ip) {
        Record::Absent => return (Lookup::NotFound, Lookup::NotFound),
        Record::Error => return (Lookup::Unavailable, Lookup::Unavailable),
        Record::Present(r) => r,
    };
    match r.decode_path::<u32>(&[PathElement::Key("autonomous_system_number")]) {
        Err(_) => (Lookup::Unavailable, Lookup::Unavailable),
        // A record without an ASN, or with ASN 0, is not a known ASN (§7.2).
        Ok(None | Some(0)) => (Lookup::NotFound, Lookup::NotFound),
        Ok(Some(asn)) => {
            let org = match r
                .decode_path::<String>(&[PathElement::Key("autonomous_system_organization")])
            {
                Ok(Some(org)) if !org.is_empty() => Lookup::Found(org),
                Ok(_) => Lookup::NotFound,
                Err(_) => Lookup::Unavailable,
            };
            (Lookup::Found(asn), org)
        }
    }
}

fn lookup_country(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Lookup<String> {
    let r = match record(reader, ip) {
        Record::Absent => return Lookup::NotFound,
        Record::Error => return Lookup::Unavailable,
        Record::Present(r) => r,
    };
    for top in ["country", "registered_country"] {
        match r.decode_path::<String>(&[PathElement::Key(top), PathElement::Key("iso_code")]) {
            Ok(Some(code)) if !code.is_empty() => return Lookup::Found(code),
            Ok(_) => {}
            Err(_) => return Lookup::Unavailable,
        }
    }
    Lookup::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file's `database_type` is quoted with a bound: a corrupt or hostile
    /// database cannot produce an unbounded log line.
    #[test]
    fn wrong_type_reason_is_bounded() {
        let reason = wrong_type("GeoLite2-City", &["ASN"]);
        assert_eq!(
            reason,
            "database_type \"GeoLite2-City\" does not contain ASN"
        );
        let huge = format!("Bogus{}", "\u{e9}".repeat(100_000));
        let reason = wrong_type(&huge, &["Country", "City"]);
        assert!(reason.len() < 300, "{} bytes", reason.len());
        assert!(
            reason.ends_with("does not contain Country or City"),
            "{reason}"
        );
    }
}
