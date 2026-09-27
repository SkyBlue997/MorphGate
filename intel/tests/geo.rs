//! GeoLite2 lookups against the generated fixtures in `intel/testdata/mmdb/`
//! (spec §7.2, §7.7).

mod common;

use common::{intel_testdata, ip, read};
use mg_intel::{GeoDb, GeoInfo, IntelError, Lookup};

fn mmdb(name: &str) -> Vec<u8> {
    read(intel_testdata().join("mmdb").join(name))
}

fn both() -> GeoDb {
    GeoDb::load(Some(mmdb("test-asn.mmdb")), Some(mmdb("test-country.mmdb"))).unwrap()
}

fn found<T>(v: T) -> Lookup<T> {
    Lookup::Found(v)
}

/// §7.2: records are Found, other addresses NotFound.
#[test]
fn found_and_not_found() {
    let db = both();
    assert!(db.has_asn() && db.has_country());
    assert_eq!(
        db.lookup(ip("192.0.2.77")),
        GeoInfo {
            asn: found(64496),
            as_org: found("MorphGate Test Network A".to_owned()),
            country: found("DE".to_owned()),
        }
    );
    assert_eq!(
        db.lookup(ip("2001:db8:1::1")),
        GeoInfo {
            asn: found(65536),
            as_org: found("MorphGate Test Network V6".to_owned()),
            country: found("AU".to_owned()),
        }
    );
    // Not in either database: ABSENT, not MISSING.
    for outside in ["8.8.8.8", "2001:db9::1", "10.0.0.1", "::1"] {
        assert_eq!(
            db.lookup(ip(outside)),
            GeoInfo {
                asn: Lookup::NotFound,
                as_org: Lookup::NotFound,
                country: Lookup::NotFound,
            },
            "{outside}"
        );
    }
}

/// §7.2: an ASN record may lack the organisation.
#[test]
fn asn_without_organisation() {
    let info = both().lookup(ip("198.51.100.200"));
    assert_eq!(info.asn, found(64500));
    assert_eq!(info.as_org, Lookup::NotFound);
    let info = both().lookup(ip("198.51.100.10"));
    assert_eq!(info.asn, found(64511));
    assert_eq!(info.as_org, found("MorphGate Test Network B".to_owned()));
}

/// §7.2 / R1-15: ASN 0 is never a known ASN.
#[test]
fn asn_zero_is_not_found() {
    let info = both().lookup(ip("203.0.113.5"));
    assert_eq!(info.asn, Lookup::NotFound);
    assert_eq!(info.as_org, Lookup::NotFound);
    // The country database still answers for the same address.
    assert_eq!(info.country, found("BR".to_owned()));
}

/// §7.2: `country.iso_code`, else `registered_country.iso_code`.
#[test]
fn country_fallback() {
    let db = both();
    // registered_country only.
    assert_eq!(
        db.lookup(ip("198.51.100.1")).country,
        found("JP".to_owned())
    );
    // country wins over registered_country.
    assert_eq!(db.lookup(ip("203.0.113.1")).country, found("BR".to_owned()));
    // A record without any ISO code.
    assert_eq!(db.lookup(ip("203.0.113.200")).country, Lookup::NotFound);
}

/// §7.2: no database → Unavailable (MISSING), per database.
#[test]
fn unavailable_without_database() {
    let info = GeoDb::empty().lookup(ip("192.0.2.1"));
    assert_eq!(
        info,
        GeoInfo {
            asn: Lookup::Unavailable,
            as_org: Lookup::Unavailable,
            country: Lookup::Unavailable,
        }
    );
    assert!(info.asn.is_unavailable());

    let asn_only = GeoDb::load(Some(mmdb("test-asn.mmdb")), None).unwrap();
    assert!(!asn_only.has_country());
    let info = asn_only.lookup(ip("192.0.2.1"));
    assert_eq!(info.asn, found(64496));
    assert_eq!(info.country, Lookup::Unavailable);

    let country_only = GeoDb::load(None, Some(mmdb("test-country.mmdb"))).unwrap();
    let info = country_only.lookup(ip("192.0.2.1"));
    assert_eq!(info.asn, Lookup::Unavailable);
    assert_eq!(info.as_org, Lookup::Unavailable);
    assert_eq!(info.country, found("DE".to_owned()));
}

/// §7.1 / §7.2: IPv4-mapped queries are looked up as IPv4.
#[test]
fn mapped_queries() {
    let db = both();
    assert_eq!(
        db.lookup(ip("::ffff:192.0.2.77")),
        db.lookup(ip("192.0.2.77"))
    );
}

/// §7.2: a City database is an accepted country source; an IPv4-only tree
/// answers NotFound for IPv6 addresses.
#[test]
fn city_database_and_ipv4_only_tree() {
    let db = GeoDb::load(None, Some(mmdb("test-city.mmdb"))).unwrap();
    assert_eq!(db.lookup(ip("192.0.2.1")).country, found("NL".to_owned()));
    assert_eq!(
        db.lookup(ip("198.51.100.1")).country,
        found("CA".to_owned())
    );
    assert_eq!(db.lookup(ip("2001:db8::1")).country, Lookup::NotFound);
    assert_eq!(
        db.lookup(ip("::ffff:192.0.2.1")).country,
        found("NL".to_owned())
    );
}

/// §7.2: a database of the wrong `database_type` is refused.
#[test]
fn wrong_database_type_rejected() {
    for (asn, country) in [
        (Some(mmdb("test-country.mmdb")), None),
        (Some(mmdb("test-city.mmdb")), None),
        (None, Some(mmdb("test-asn.mmdb"))),
    ] {
        match GeoDb::load(asn, country) {
            Err(IntelError::Mmdb { reason, .. }) => {
                assert!(reason.contains("database_type"), "{reason}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    // One bad database fails the whole load.
    assert!(GeoDb::load(Some(mmdb("test-asn.mmdb")), Some(mmdb("test-asn.mmdb"))).is_err());
}

#[test]
fn garbage_rejected() {
    for bytes in [
        Vec::new(),
        b"not a maxmind database".to_vec(),
        vec![0u8; 4096],
    ] {
        assert!(matches!(
            GeoDb::load(Some(bytes.clone()), None),
            Err(IntelError::Mmdb { .. })
        ));
        assert!(matches!(
            GeoDb::load(None, Some(bytes)),
            Err(IntelError::Mmdb { .. })
        ));
    }
    let mut truncated = mmdb("test-asn.mmdb");
    truncated.truncate(truncated.len() / 2);
    assert!(GeoDb::load(Some(truncated), None).is_err());
}

/// A record that cannot be decoded is Unavailable (MISSING), not a guess and
/// not a panic; other records stay readable.
#[test]
fn undecodable_record_is_unavailable() {
    let mut bytes = mmdb("test-asn.mmdb");
    // AS64496 is stored as uint32 (control byte 0xC2, then 0xFB 0xF0).
    // Retype it as a 2-byte UTF-8 string, which is invalid UTF-8.
    let at = bytes
        .windows(3)
        .position(|w| w == [0xC2, 0xFB, 0xF0])
        .expect("AS64496 value in the fixture");
    bytes[at] = 0x42;
    let db = GeoDb::load(Some(bytes), None).unwrap();
    let info = db.lookup(ip("192.0.2.1"));
    assert_eq!(info.asn, Lookup::Unavailable);
    assert_eq!(info.as_org, Lookup::Unavailable);
    assert_eq!(db.lookup(ip("198.51.100.1")).asn, found(64511));
}

#[test]
fn debug_shows_types_only() {
    let d = format!("{:?}", both());
    assert!(
        d.contains("GeoLite2-ASN") && d.contains("GeoLite2-Country"),
        "{d}"
    );
}
