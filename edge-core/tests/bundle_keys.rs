//! Owner public key files (docs/impl/phase1-spec.md §12.6, §12.0: readers
//! accept every valid sample and reject every invalid one).

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use mg_edge_core::bundle::{BundleError, OwnerKeys};
use std::path::PathBuf;

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase1/keys")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(keys_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse(bytes: &[u8]) -> Result<OwnerKeys, BundleError> {
    OwnerKeys::from_pub_files(&[("x.pub", bytes)])
}

/// A canonical-looking `.pub` for `key`, with `edit` applied to the JSON.
fn pub_file(kid: &str, key: &[u8], edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v = serde_json::json!({
        "v": 1,
        "kind": "mg-owner-ed25519-pub",
        "kid": kid,
        "public_key": URL_SAFE_NO_PAD.encode(key),
        "created_at": "2026-09-27T10:00:00Z",
    });
    edit(&mut v);
    serde_json::to_vec_pretty(&v).unwrap()
}

fn test_pk() -> Vec<u8> {
    let pk = OwnerKeys::from_pub_files(&[("owner-test.pub", &read("owner-test.pub"))]).unwrap();
    assert_eq!(pk.kids().collect::<Vec<_>>(), ["owner-test"]);
    // RFC 8032 §7.1 test 1 public key.
    (0..32)
        .map(|i| {
            u8::from_str_radix(
                &"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    [i * 2..i * 2 + 2],
                16,
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn accepts_the_valid_sample() {
    let keys = parse(&read("owner-test.pub")).unwrap();
    assert_eq!(keys.kids().collect::<Vec<_>>(), ["owner-test"]);
    // Formatting does not matter to the reader (§12.0).
    let compact = pub_file("owner-test", &test_pk(), |_| {});
    parse(&compact).unwrap();
}

/// §12.0: every `invalid/owner-test.pub.*` sample is rejected.
#[test]
fn rejects_every_invalid_owner_sample() {
    let mut n = 0;
    for entry in std::fs::read_dir(keys_dir().join("invalid")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("owner-test.pub.") {
            continue;
        }
        n += 1;
        let err = parse(&std::fs::read(&path).unwrap()).unwrap_err();
        assert!(matches!(err, BundleError::KeyFile { .. }), "{name}: {err}");
    }
    assert!(n >= 2, "expected the owner-test.pub.* invalid samples");
}

/// Other key kinds (§12.7, and the private owner key of §12.6) are not owner
/// public keys, valid or not.
#[test]
fn rejects_other_key_kinds() {
    let mut names: Vec<String> = std::fs::read_dir(keys_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.extend(
        std::fs::read_dir(keys_dir().join("invalid"))
            .unwrap()
            .map(|e| format!("invalid/{}", e.unwrap().file_name().to_string_lossy()))
            .filter(|n| !n.contains("owner-test.pub.")),
    );
    assert!(names.len() > 10);
    for name in names {
        assert!(
            parse(&read(&name)).is_err(),
            "{name} accepted as an owner public key"
        );
    }
}

#[test]
fn rejects_malformed_files() {
    let pk = test_pk();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("v 2", pub_file("k", &pk, |v| v["v"] = 2.into())),
        ("v as string", pub_file("k", &pk, |v| v["v"] = "1".into())),
        ("private kind", pub_file("k", &pk, |v| v["kind"] = "mg-owner-ed25519".into())),
        ("unknown field", pub_file("k", &pk, |v| v["comment"] = "hi".into())),
        ("missing created_at", pub_file("k", &pk, |v| {
            v.as_object_mut().unwrap().remove("created_at");
        })),
        ("created_at not RFC 3339", pub_file("k", &pk, |v| v["created_at"] = "2026-09-27".into())),
        ("missing kid", pub_file("k", &pk, |v| {
            v.as_object_mut().unwrap().remove("kid");
        })),
        ("kid upper case", pub_file("Owner", &pk, |_| {})),
        ("kid with slash", pub_file("a/b", &pk, |_| {})),
        ("kid too long", pub_file(&"a".repeat(65), &pk, |_| {})),
        ("padded base64", pub_file("k", &pk, |v| v["public_key"] = URL_SAFE.encode(&pk).into())),
        ("standard base64", pub_file("k", &pk, |v| {
            v["public_key"] = base64::engine::general_purpose::STANDARD_NO_PAD
                .encode([0xfb; 32])
                .into()
        })),
        ("31 bytes", pub_file("k", &pk[..31], |_| {})),
        ("33 bytes", pub_file("k", &[pk.as_slice(), &[0]].concat(), |_| {})),
        ("empty key", pub_file("k", &[], |_| {})),
        ("small-order point", pub_file("k", &{
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        }, |_| {})),
        ("duplicate JSON key", br#"{"v":1,"v":1,"kind":"mg-owner-ed25519-pub","kid":"k","public_key":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","created_at":"2026-09-27T10:00:00Z"}"#.to_vec()),
        ("not JSON", b"-----BEGIN PUBLIC KEY-----".to_vec()),
        ("array", b"[]".to_vec()),
        ("empty", Vec::new()),
        ("oversized", {
            let mut f = pub_file("k", &pk, |_| {});
            f.extend(std::iter::repeat_n(b' ', 5000));
            f
        }),
    ];
    for (what, bytes) in cases {
        let err = parse(&bytes).unwrap_err();
        assert!(
            matches!(err, BundleError::KeyFile { ref file, .. } if file == "x.pub"),
            "{what}: {err}"
        );
    }
}

#[test]
fn rotation_trusts_two_keys_but_not_the_same_kid_twice() {
    let pk = test_pk();
    let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([3u8; 32]));
    let a = read("owner-test.pub");
    let b = pub_file("owner-2027", other.pk.as_ref(), |_| {});
    let keys = OwnerKeys::from_pub_files(&[("a.pub", &a), ("b.pub", &b)]).unwrap();
    assert_eq!(
        keys.kids().collect::<Vec<_>>(),
        ["owner-2027", "owner-test"]
    );

    let dup = pub_file("owner-test", &pk, |_| {});
    let err = OwnerKeys::from_pub_files(&[("a.pub", &a), ("dup.pub", &dup)]).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
    assert!(err.to_string().contains("dup.pub"), "{err}");
}

#[test]
fn at_least_one_key_is_required() {
    assert!(matches!(
        OwnerKeys::from_pub_files(&[]),
        Err(BundleError::KeyFile { .. })
    ));
}
