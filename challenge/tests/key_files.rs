//! Site key files (spec §12.7, §6.8): every valid sample in
//! `testdata/phase1/keys/` is accepted, every `keys/invalid/` sample of the
//! same kind is rejected (for the reason its name gives), and the parsed keys
//! are the documented bytes.

mod common;

use common::{TestRng, read, sealer};
use mg_challenge::{
    ClearanceBind, KeyError, MintParams, SealKeys, Sealer, TokenKeySet, mint, verify,
};
use mg_core::{ChallengeType, RiskBand, TokenLevel};

fn kids(k: &[&str]) -> Vec<String> {
    k.iter().map(|s| s.to_string()).collect()
}

/// Every file in `keys/invalid/` whose name starts with `prefix`.
fn invalid_samples(prefix: &str) -> Vec<String> {
    let dir = common::phase1("keys/invalid");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(prefix))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no {prefix}* samples");
    names
}

#[test]
fn valid_seal_root_files() {
    let one = SealKeys::from_key_file(&read("keys/seal.root.json"), "blog").unwrap();
    assert_eq!(one.root_count(), 1);
    let two = SealKeys::from_key_file(&read("keys/seal.root.rotating.json"), "blog").unwrap();
    assert_eq!(two.root_count(), 2);

    // The parsed roots are the documented bytes (README: 32 x 0x01, then
    // 32 x 0x02 placed first): what one seals, the equivalent sealer opens.
    let now = common::MIDDAY_MS;
    let rng = TestRng::new(1);
    let from_file = Sealer::new("blog", one);
    let c = from_file
        .seal(&common::pow_claims(now), "example.com", &rng)
        .unwrap();
    sealer("blog", &[1])
        .open(&c, "example.com", ChallengeType::Pow, now)
        .unwrap();
    let rotating = Sealer::new("blog", two);
    let c = rotating
        .seal(&common::pow_claims(now), "example.com", &rng)
        .unwrap();
    sealer("blog", &[2])
        .open(&c, "example.com", ChallengeType::Pow, now)
        .expect("roots[0] of the rotating file is 32 x 0x02");
}

#[test]
fn invalid_seal_root_files() {
    let expected = |name: &str| match name {
        "seal.root.no-roots.json" | "seal.root.three-roots.json" => KeyError::Count,
        other => panic!("new invalid sample {other}: add its expected error"),
    };
    for name in invalid_samples("seal.root") {
        let err = SealKeys::from_key_file(&read(&format!("keys/invalid/{name}")), "blog")
            .expect_err(&name);
        assert_eq!(err, expected(&name), "{name}");
    }
}

#[test]
fn valid_token_key_files() {
    let set = TokenKeySet::from_key_file(
        &read("keys/token.keys.json"),
        "blog",
        &kids(&["blog-t-20260927"]),
    )
    .unwrap();
    assert_eq!(set.active_kid(), "blog-t-20260927");

    let rotated = read("keys/token.keys.rotated.json");
    let set = TokenKeySet::from_key_file(
        &rotated,
        "blog",
        &kids(&["blog-t-20260928", "blog-t-20260927"]),
    )
    .unwrap();
    assert_eq!(set.active_kid(), "blog-t-20260928");
    assert_eq!(
        set.kids().collect::<Vec<_>>(),
        ["blog-t-20260928", "blog-t-20260927"]
    );

    // Only allowed kids are kept: a bundle that still signs with the old
    // key does not verify with the new one.
    let old_only =
        TokenKeySet::from_key_file(&rotated, "blog", &kids(&["blog-t-20260927"])).unwrap();
    assert_eq!(old_only.kids().collect::<Vec<_>>(), ["blog-t-20260927"]);

    // Repeated kids in the bundle list are harmless.
    let dup = TokenKeySet::from_key_file(
        &rotated,
        "blog",
        &kids(&["blog-t-20260928", "blog-t-20260928"]),
    )
    .unwrap();
    assert_eq!(dup.kids().count(), 1);

    // The key of token.keys.json (bytes 0x20..0x3f) is the key of the same
    // kid in the rotated file: a token minted with one verifies with the other.
    let first = TokenKeySet::from_key_file(
        &read("keys/token.keys.json"),
        "blog",
        &kids(&["blog-t-20260927"]),
    )
    .unwrap();
    let bind = ClearanceBind::from_inputs(&common::bindings()).unwrap();
    let (token, _) = mint(
        &first,
        "blog",
        &MintParams {
            env: "production",
            session: None,
            lvl: TokenLevel::Pow,
            now_s: 1_790_000_000,
            ttl_s: 1800,
            bind,
            rb: RiskBand::Low,
        },
        &TestRng::new(3),
    )
    .unwrap();
    verify(&old_only, "blog", "production", &token, 1_790_000_001).unwrap();
}

#[test]
fn invalid_token_key_files() {
    let expected = |name: &str| match name {
        "token.keys.bad-kid.json" => KeyError::Id,
        "token.keys.duplicate-kid.json" => KeyError::DuplicateId,
        "token.keys.padded-base64.json" | "token.keys.short-key.json" => KeyError::Key,
        "token.keys.site-shop.json" => KeyError::Site,
        "token.keys.too-many.json" => KeyError::Count,
        "token.keys.version-2.json" => KeyError::Version(2),
        "token.keys.wrong-kind.json" => KeyError::Kind,
        // serde reports the position of the unknown key ("comment", line 12).
        "token.keys.unknown-field.json" => KeyError::Json {
            line: 12,
            column: 0,
        },
        other => panic!("new invalid sample {other}: add its expected error"),
    };
    for name in invalid_samples("token.keys") {
        let json = read(&format!("keys/invalid/{name}"));
        let err = TokenKeySet::from_key_file(&json, "blog", &kids(&["blog-t-20260927"]))
            .expect_err(&name);
        match (err, expected(&name)) {
            (KeyError::Json { line, .. }, KeyError::Json { line: want, .. }) => {
                assert_eq!(line, want, "{name}")
            }
            (err, want) => assert_eq!(err, want, "{name}"),
        }
    }
}

#[test]
fn allowed_kids_must_be_present() {
    let json = read("keys/token.keys.json");
    assert_eq!(
        TokenKeySet::from_key_file(&json, "blog", &[]).unwrap_err(),
        KeyError::NoActiveKid
    );
    assert_eq!(
        TokenKeySet::from_key_file(&json, "blog", &kids(&["blog-t-20260928"])).unwrap_err(),
        KeyError::MissingKid("blog-t-20260928".into())
    );
    // A verify-only kid missing from the file fails closed too (spec §9.10:
    // every token_key_ids[*] must be in token.keys.json).
    assert_eq!(
        TokenKeySet::from_key_file(
            &json,
            "blog",
            &kids(&["blog-t-20260927", "blog-t-20260926"])
        )
        .unwrap_err(),
        KeyError::MissingKid("blog-t-20260926".into())
    );
}

#[test]
fn files_are_not_interchangeable() {
    // A token key file is not a seal root file and vice versa.
    for (name, json) in [
        ("token.keys.json", read("keys/token.keys.json")),
        ("pseudo.key.json", read("keys/pseudo.key.json")),
        ("upstream-keys.json", read("keys/upstream-keys.json")),
    ] {
        assert!(
            SealKeys::from_key_file(&json, "blog").is_err(),
            "{name} as seal root"
        );
    }
    for (name, json) in [
        ("seal.root.json", read("keys/seal.root.json")),
        ("pseudo.key.json", read("keys/pseudo.key.json")),
        ("owner-test.pub", read("keys/owner-test.pub")),
    ] {
        assert!(
            TokenKeySet::from_key_file(&json, "blog", &kids(&["blog-t-20260927"])).is_err(),
            "{name} as token keys"
        );
    }
    // Loading for another site is rejected.
    assert_eq!(
        SealKeys::from_key_file(&read("keys/seal.root.json"), "shop").unwrap_err(),
        KeyError::Site
    );
}

#[test]
fn schema_edge_cases() {
    let seal = |body: &str| SealKeys::from_key_file(body.as_bytes(), "blog");
    let root = r#"{"root_id":"blog-r-20260927","key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","created_at":"2026-09-27T10:00:00Z"}"#;
    let file = |roots: &str| {
        format!(r#"{{"v":1,"kind":"mg-site-seal-root","site":"blog","roots":[{roots}]}}"#)
    };
    assert!(seal(&file(root)).is_ok());
    // Duplicate root ids.
    assert_eq!(
        seal(&file(&format!("{root},{root}"))).unwrap_err(),
        KeyError::DuplicateId
    );
    // Missing created_at, bad created_at, root id of another site.
    assert!(matches!(
        seal(&file(
            r#"{"root_id":"blog-r-20260927","key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#
        )),
        Err(KeyError::Json { .. })
    ));
    assert_eq!(
        seal(&file(&root.replace("2026-09-27T10:00:00Z", "yesterday"))).unwrap_err(),
        KeyError::CreatedAt
    );
    assert_eq!(
        seal(&file(&root.replace("blog-r-", "shop-r-"))).unwrap_err(),
        KeyError::Id
    );
    // A duplicated JSON key is rejected rather than "last one wins".
    assert!(matches!(
        seal(&file(root).replace(r#""v":1,"#, r#""v":1,"v":1,"#)),
        Err(KeyError::Json { .. })
    ));
    // Array forms that serde's derive would otherwise accept for structs.
    let array_top = r#"[1,"mg-site-seal-root","blog",[{"root_id":"blog-r-20260927","key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","created_at":"2026-09-27T10:00:00Z"}]]"#;
    assert!(matches!(seal(array_top), Err(KeyError::Json { .. })));
    let array_entry = file(
        r#"["blog-r-20260927","AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","2026-09-27T10:00:00Z"]"#,
    );
    assert!(matches!(seal(&array_entry), Err(KeyError::Json { .. })));
    // Not JSON at all, trailing garbage, wrong top-level type.
    for bad in ["", "null", "[]", "{", &format!("{} x", file(root))] {
        assert!(matches!(seal(bad), Err(KeyError::Json { .. })), "{bad:?}");
    }
}

#[test]
fn debug_output_never_contains_keys() {
    let seal = SealKeys::from_key_file(&read("keys/seal.root.rotating.json"), "blog").unwrap();
    let tokens = TokenKeySet::from_key_file(
        &read("keys/token.keys.rotated.json"),
        "blog",
        &kids(&["blog-t-20260928", "blog-t-20260927"]),
    )
    .unwrap();
    let dbg = format!(
        "{seal:?} {tokens:?} {:?}",
        Sealer::new("blog", seal.clone())
    );
    for secret in [
        "AQEBAQEBAQEBAQEB",
        "AgICAgICAgICAgIC",
        "QEFCQ0RFRkdISUpL",
        "ICEiIyQlJicoKSor",
    ] {
        assert!(!dbg.contains(secret), "{dbg}");
    }
    assert!(
        !dbg.contains("1, 1, 1") && !dbg.contains("2, 2, 2"),
        "{dbg}"
    );
    assert!(
        dbg.contains("blog-t-20260928"),
        "kids are not secret: {dbg}"
    );
}
