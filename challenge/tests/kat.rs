//! Known-answer vectors from `testdata/phase1/kat.json` (spec §6.8): epoch
//! keys, accepted epochs, aad, binding hashes, return-path hashes and PoW.
//! Every case of the shared file must pass; the Web SDK (WP-W1) checks the
//! PoW cases against the same file.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{hex, kat};
use mg_challenge::{
    SealRoot, aad, accepted_epochs, bind_hash, derive_bind_epoch_key, derive_epoch_key,
    leading_zero_bits, pow_prefix, pow_solve, pow_verify, ret_hash,
};
use mg_core::ChallengeType;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn cases<'a>(kat: &'a Value, section: &str) -> &'a Vec<Value> {
    let cases = kat[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("kat.json {section}.cases"));
    assert!(!cases.is_empty(), "{section} has cases");
    cases
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key} in {v}"))
}

fn u64_of(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or_else(|| panic!("{key} in {v}"))
}

/// §6.1: `k_epoch` / `k_bind_epoch` = HKDF-SHA256 over the documented `info`.
#[test]
fn epoch_keys() {
    let kat = kat();
    let root: [u8; 32] = hex(str_of(&kat["epoch_keys"], "root_hex"))
        .try_into()
        .unwrap();
    let root = SealRoot::from_bytes(root);
    for case in cases(&kat, "epoch_keys") {
        let site = str_of(case, "site");
        let epoch = u64_of(case, "epoch_no");
        let (derived, label) = match str_of(case, "key") {
            "k_epoch" => (derive_epoch_key(&root, site, epoch), "mg-seal-v1"),
            "k_bind_epoch" => (derive_bind_epoch_key(&root, site, epoch), "mg-bind-v1"),
            other => panic!("unknown key kind {other}"),
        };
        // The documented info layout, spelled out independently of the crate.
        let info = [
            label.as_bytes(),
            &[0],
            site.as_bytes(),
            &[0],
            &epoch.to_be_bytes(),
        ]
        .concat();
        assert_eq!(info, hex(str_of(case, "info_hex")), "{case}");
        assert_eq!(derived.to_vec(), hex(str_of(case, "okm_hex")), "{case}");
    }
}

/// §6.1: the accepted epoch window around day boundaries.
#[test]
fn accepted_epoch_windows() {
    let kat = kat();
    for case in cases(&kat, "accepted_epochs") {
        let now = case["now_ms"].as_i64().unwrap();
        let range = accepted_epochs(now);
        assert_eq!(
            (*range.start(), *range.end()),
            (u64_of(case, "min_epoch"), u64_of(case, "max_epoch")),
            "{}",
            str_of(case, "name")
        );
    }
}

/// §6.2: the length-delimited aad.
#[test]
fn aad_encoding() {
    let kat = kat();
    for case in cases(&kat, "aad") {
        let ty: ChallengeType = str_of(case, "type").parse().unwrap();
        assert_eq!(
            aad(str_of(case, "host"), ty, str_of(case, "kid")),
            hex(str_of(case, "aad_hex")),
            "{case}"
        );
    }
}

/// §6.4: binding hashes, including the typed helpers.
#[test]
fn binding_hashes() {
    let kat = kat();
    for case in cases(&kat, "bind") {
        let (kind, value) = (str_of(case, "kind"), str_of(case, "value"));
        let want = str_of(case, "hash_b64url");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(bind_hash(kind, value)),
            want,
            "{case}"
        );
        // The helper that builds the value from its parts gives the same hash.
        let typed = match kind {
            "uah" => {
                let (family, major) = value.split_once('/').unwrap();
                mg_challenge::uah(family, major.parse().unwrap())
            }
            "ipp" => mg_challenge::ipp(value),
            "ipa" => mg_challenge::ipa(value.parse().unwrap()).unwrap(),
            "ctp" => {
                let parts: Vec<&str> = value.split('|').collect();
                let bucket: u32 = parts[3].parse().unwrap();
                // Any ClientHello length in the bucket gives the same hash.
                let a = mg_challenge::ctp(parts[0], parts[1], parts[2], bucket * 64);
                let b = mg_challenge::ctp(parts[0], parts[1], parts[2], bucket * 64 + 63);
                assert_eq!(a, b);
                a
            }
            other => panic!("unknown bind kind {other}"),
        };
        assert_eq!(URL_SAFE_NO_PAD.encode(typed), want, "{case}");
    }
}

/// §6.4: `ret_hash`.
#[test]
fn return_path_hashes() {
    let kat = kat();
    for case in cases(&kat, "ret") {
        let ret = str_of(case, "ret");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(ret_hash(ret)),
            str_of(case, "hash_b64url"),
            "{case}"
        );
        assert_eq!(mg_challenge::validate_ret(ret), Ok(()), "{ret}");
    }
}

/// §6.3: prefix, digest, leading zero bits, first solving counter.
#[test]
fn proof_of_work() {
    let kat = kat();
    for case in cases(&kat, "pow") {
        let c = str_of(case, "c");
        let bits = u64_of(case, "bits") as u32;
        let first = u64_of(case, "first_counter");
        let prefix = pow_prefix(c);
        assert_eq!(prefix.to_vec(), hex(str_of(case, "prefix_hex")), "{case}");

        let digest: [u8; 32] = Sha256::new()
            .chain_update(prefix)
            .chain_update(first.to_be_bytes())
            .finalize()
            .into();
        assert_eq!(digest.to_vec(), hex(str_of(case, "digest_hex")), "{case}");
        assert_eq!(
            u64::from(leading_zero_bits(&digest)),
            u64_of(case, "leading_zero_bits"),
            "{case}"
        );

        assert!(pow_verify(c, bits, first), "{case}");
        assert_eq!(pow_solve(c, bits, first + 1), Some(first), "{case}");
        if first > 0 {
            assert!(!pow_verify(c, bits, first - 1), "{case}");
            assert_eq!(pow_solve(c, bits, first), None, "iteration cap: {case}");
        }
    }
}
