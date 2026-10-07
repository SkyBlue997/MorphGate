//! `x-mg-upstream-key` comparison (docs/impl/phase1-spec.md §9.2, key file
//! §12.7; WP-C1), against the shared key-file samples in
//! `testdata/phase1/keys/`.

use mg_edge_core::upstream::secret_header_ok;
use std::path::PathBuf;

/// The `values` of an `mg-upstream-keys` sample file, as the header carries
/// them (the base64url text itself is the shared secret, §12.7).
fn key_values(file: &str) -> Vec<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/phase1/keys")
        .join(file);
    let text = std::fs::read_to_string(&path).expect("read key sample");
    let json: serde_json::Value = serde_json::from_str(&text).expect("key sample is JSON");
    assert_eq!(json["kind"], "mg-upstream-keys");
    json["values"]
        .as_array()
        .expect("values")
        .iter()
        .map(|v| v.as_str().expect("string value").as_bytes().to_vec())
        .collect()
}

#[test]
fn accepts_the_single_value() {
    let accepted = key_values("upstream-keys.json");
    assert_eq!(accepted.len(), 1);
    assert!(secret_header_ok(Some(&accepted[0]), &accepted));
}

/// §9.2 / §12.7: during rotation both the new and the previous value pass.
#[test]
fn accepts_both_values_while_rotating() {
    let rotated = key_values("upstream-keys.rotated.json");
    assert_eq!(rotated.len(), 2);
    for value in &rotated {
        assert!(secret_header_ok(Some(value), &rotated));
    }
    // The new value is not accepted by an Edge still on the old file.
    let old = key_values("upstream-keys.json");
    assert!(!secret_header_ok(Some(&rotated[0]), &old));
    assert!(secret_header_ok(Some(&rotated[1]), &old));
}

/// Same length, one byte different (first, middle, last), different case.
#[test]
fn rejects_equal_length_mismatches() {
    let accepted = key_values("upstream-keys.rotated.json");
    let good = accepted[0].clone();
    for index in [0, good.len() / 2, good.len() - 1] {
        let mut bad = good.clone();
        bad[index] ^= 0x01;
        assert_eq!(bad.len(), good.len());
        assert!(!secret_header_ok(Some(&bad), &accepted), "byte {index}");
    }
    let swapped_case: Vec<u8> = good
        .iter()
        .map(|b| {
            if b.is_ascii_lowercase() {
                b.to_ascii_uppercase()
            } else {
                b.to_ascii_lowercase()
            }
        })
        .collect();
    assert_ne!(swapped_case, good);
    assert!(!secret_header_ok(Some(&swapped_case), &accepted));
}

/// Prefixes, extensions and whitespace-padded values never match: the
/// comparison is exact and does not trim.
#[test]
fn rejects_unequal_lengths() {
    let accepted = key_values("upstream-keys.rotated.json");
    let good = &accepted[1];
    let mut longer = good.clone();
    longer.push(b'A');
    let mut padded = good.clone();
    padded.push(b' ');
    let joined = [accepted[0].as_slice(), b", ", accepted[1].as_slice()].concat();
    for bad in [
        &good[..good.len() - 1],
        &good[..1],
        longer.as_slice(),
        padded.as_slice(),
        joined.as_slice(),
    ] {
        assert!(!secret_header_ok(Some(bad), &accepted), "{bad:?}");
    }
}

#[test]
fn missing_and_empty_never_match() {
    let accepted = key_values("upstream-keys.json");
    assert!(!secret_header_ok(None, &accepted));
    assert!(!secret_header_ok(Some(b""), &accepted));
    // No accepted values at all.
    assert!(!secret_header_ok(Some(&accepted[0]), &[]));
    assert!(!secret_header_ok(None, &[]));
    // A (misconfigured) empty accepted value matches nothing, not even "".
    let with_empty = vec![Vec::new(), accepted[0].clone()];
    assert!(!secret_header_ok(Some(b""), &with_empty));
    assert!(!secret_header_ok(None, &with_empty));
    assert!(secret_header_ok(Some(&accepted[0]), &with_empty));
}

/// Arbitrary bytes (not UTF-8, very long) are compared, not parsed.
#[test]
fn arbitrary_bytes_do_not_match() {
    let accepted = key_values("upstream-keys.rotated.json");
    let long = vec![b'k'; 64 * 1024];
    for bad in [&b"\xff\xfe\x00"[..], &long] {
        assert!(!secret_header_ok(Some(bad), &accepted));
    }
    let binary = vec![vec![0u8, 0xff, 0x80]];
    assert!(secret_header_ok(Some(&[0u8, 0xff, 0x80]), &binary));
}
