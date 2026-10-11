//! Known-answer vectors from `testdata/phase2/kat.json` (Phase 2 spec §6.11):
//! every section and every case. The Web SDK (WP-W2) checks the same file.

mod common;

use common::{hex, kat2};
use mg_challenge::testkit::TestSessionKey;
use mg_challenge::{
    ProofError, ProofRequest, SealKeys, SealRoot, SessionKey, SubmissionFields, accepted_epochs,
    bind_hash, derive_bind_epoch_key, idempotency_key, jwk_thumbprint, leading_zero_bits,
    pow_digest_v2, pow_prefix_v2, pow_solve_v2, pow_verify_v2, renew_message, submission_message,
    turnstile_cdata, turnstile_cdata_matches, ui_params, verify_proof,
};
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

fn name(v: &Value) -> &str {
    v["name"].as_str().unwrap_or("<unnamed>")
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn session_key(jwk: &Value) -> SessionKey {
    SessionKey::from_jwk_json(jwk.to_string().as_bytes()).unwrap()
}

#[test]
fn file_version() {
    assert_eq!(kat2()["version"], 1);
}

/// `test_keys`: the testkit derives the same keys from their labels, so the
/// Edge's integration tests can sign with the keys of the vectors.
#[test]
fn test_keys() {
    let kat = kat2();
    let keys = kat["test_keys"]["keys"].as_array().unwrap();
    assert!(keys.len() >= 4);
    for k in keys {
        let key = TestSessionKey::from_label(str_of(k, "label"));
        assert_eq!(key.x(), str_of(&k["jwk"], "x"), "{k}");
        assert_eq!(key.y(), str_of(&k["jwk"], "y"), "{k}");
        assert_eq!(key.thumbprint(), str_of(k, "jkt"));
        assert_eq!(session_key(&k["jwk"]).thumbprint(), str_of(k, "jkt"));
        // What the testkit signs, the verifier accepts.
        let sig = key.sign(b"mg-phase2-testkit");
        assert!(session_key(&k["jwk"]).verify_es256(b"mg-phase2-testkit", &sig));
    }
}

/// §6.1: the accepted-epoch window (replaces the Phase 1 vectors).
#[test]
fn accepted_epoch_windows() {
    let kat = kat2();
    assert_eq!(cases(&kat, "accepted_epochs").len(), 7);
    for case in cases(&kat, "accepted_epochs") {
        let range = accepted_epochs(case["now_ms"].as_i64().unwrap());
        assert_eq!(
            (*range.start(), *range.end()),
            (u64_of(case, "min_epoch"), u64_of(case, "max_epoch")),
            "{}",
            name(case)
        );
    }
}

/// §6.3: `ui_seed` → hold time and offsets (seeds are decimal strings).
#[test]
fn ui_parameters() {
    let kat = kat2();
    let cases = cases(&kat, "ui_params");
    assert!(cases.len() >= 8);
    let mut seeds = Vec::new();
    for case in cases {
        let seed: u64 = str_of(case, "ui_seed").parse().unwrap();
        seeds.push(seed);
        let mut h = Sha256::new();
        h.update(b"mg-ui-v1\0");
        h.update(seed.to_be_bytes());
        assert_eq!(h.finalize().to_vec(), hex(str_of(case, "u_hex")), "{case}");
        let p = ui_params(seed);
        assert_eq!(
            (
                i64::from(p.required_hold_ms),
                i64::from(p.offset_x_px),
                i64::from(p.offset_y_px)
            ),
            (
                case["required_hold_ms"].as_i64().unwrap(),
                case["offset_x_px"].as_i64().unwrap(),
                case["offset_y_px"].as_i64().unwrap()
            ),
            "seed {seed}"
        );
    }
    assert!(seeds.contains(&1) && seeds.contains(&u64::MAX));
}

/// §6.4: prefixes, canonical counters and every sub-puzzle digest.
#[test]
fn pow_v2() {
    let kat = kat2();
    let mut ks = Vec::new();
    for case in cases(&kat, "pow_v2") {
        let c = str_of(case, "c");
        let d = u64_of(case, "d") as u32;
        let k = u64_of(case, "k") as usize;
        ks.push(k);
        let prefix = pow_prefix_v2(c);
        assert_eq!(prefix.to_vec(), hex(str_of(case, "prefix_hex")), "{c}");
        let counters: Vec<u64> = case["counters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        assert_eq!(counters.len(), k);
        assert!(pow_verify_v2(c, d, &counters), "{c}");
        // The reference solver finds exactly the canonical counters.
        assert_eq!(
            pow_solve_v2(c, d, k, 1 << 24).as_deref(),
            Some(counters.as_slice())
        );
        for sub in case["sub_puzzles"].as_array().unwrap() {
            let i = u64_of(sub, "i") as u8;
            let digest = pow_digest_v2(&prefix, i, u64_of(sub, "counter"));
            assert_eq!(digest.to_vec(), hex(str_of(sub, "digest_hex")), "{sub}");
            assert_eq!(
                u64::from(leading_zero_bits(&digest)),
                u64_of(sub, "leading_zero_bits")
            );
            assert_eq!(counters[usize::from(i)], u64_of(sub, "counter"));
        }
        // Negative cases around the vector: one counter off, a missing or an
        // extra sub-puzzle, the counters of another C.
        if counters[0] > 0 {
            let mut smaller = counters.clone();
            smaller[0] -= 1;
            assert!(!pow_verify_v2(c, d, &smaller), "{c}: smallest counter");
        }
        if k > 1 {
            assert!(
                pow_verify_v2(c, d, &counters[..k - 1]),
                "a prefix still solves its own puzzles"
            );
        }
        assert!(!pow_verify_v2(&format!("{c}x"), d, &counters) || d == 0);
    }
    ks.sort_unstable();
    assert_eq!(ks, [1, 2, 3, 4]);
}

/// §6.5: RFC 7638 thumbprints.
#[test]
fn jwk_thumbprints() {
    let kat = kat2();
    let rfc = &kat["jwk_thumbprint"]["rfc7638_example"];
    assert_eq!(
        b64(&Sha256::digest(str_of(rfc, "canonical_json").as_bytes())),
        str_of(rfc, "thumbprint"),
        "the formula on the RFC 7638 example"
    );
    for case in cases(&kat, "jwk_thumbprint") {
        let jwk = &case["jwk"];
        let want = str_of(case, "thumbprint");
        assert_eq!(session_key(jwk).thumbprint(), want, "{}", name(case));
        assert_eq!(jwk_thumbprint(str_of(jwk, "x"), str_of(jwk, "y")), want);
        if let Some(canonical) = case["canonical_json"].as_str() {
            assert_eq!(b64(&Sha256::digest(canonical.as_bytes())), want);
            assert_eq!(
                canonical,
                format!(
                    r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                    str_of(jwk, "x"),
                    str_of(jwk, "y")
                )
            );
        }
    }
}

/// §6.5: ES256 over 64-byte `r || s`; high S accepted, DER and points off the
/// curve rejected.
#[test]
fn es256() {
    let kat = kat2();
    let names: Vec<&str> = cases(&kat, "es256").iter().map(name).collect();
    for want in [
        "valid_low_s",
        "valid_high_s",
        "message_changed",
        "der_encoded",
        "point_not_on_curve",
    ] {
        assert!(names.contains(&want), "{want}");
    }
    for case in cases(&kat, "es256") {
        let key = session_key(&case["jwk"]);
        let ok = key.verify_es256(&hex(str_of(case, "msg_hex")), str_of(case, "sig_b64url"));
        assert_eq!(ok, case["valid"].as_bool().unwrap(), "{}", name(case));
    }
}

fn submission_case(case: &Value) -> (SubmissionFields<'_>, Vec<u64>) {
    let f = &case["fields"];
    let counters: Vec<u64> = f["counters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap())
        .collect();
    (
        SubmissionFields {
            c: str_of(f, "c"),
            ty: str_of(f, "type"),
            p: str_of(f, "p"),
            pp: str_of(f, "pp"),
            t: str_of(f, "t"),
            counters: &[],
            ret: str_of(f, "ret"),
            ts: u64_of(f, "ts"),
            build: str_of(f, "build"),
        },
        counters,
    )
}

/// §6.6: the submission and renewal messages and their signatures.
#[test]
fn signed_messages() {
    let kat = kat2();
    for case in cases(&kat, "submission_message") {
        let (fields, counters) = submission_case(case);
        let fields = SubmissionFields {
            counters: &counters,
            ..fields
        };
        assert_eq!(
            mg_challenge::counters_text(&counters),
            str_of(case, "counters_text")
        );
        let msg = submission_message(&fields);
        assert_eq!(msg, hex(str_of(case, "message_hex")), "{}", name(case));
        if let Some(sig) = case["sig_b64url"].as_str() {
            let key = session_key(&case["jwk"]);
            assert!(key.verify_es256(&msg, sig), "{}", name(case));
            // The signature covers every field.
            let other = SubmissionFields {
                ret: "/other",
                ..fields
            };
            assert!(!key.verify_es256(&submission_message(&other), sig));
        }
    }
    for case in cases(&kat, "renew_message") {
        let msg = renew_message(str_of(case, "c"), u64_of(case, "ts"));
        assert_eq!(msg, hex(str_of(case, "message_hex")), "{}", name(case));
        let key = session_key(&case["jwk"]);
        assert!(key.verify_es256(&msg, str_of(case, "sig_b64url")));
        let later = renew_message(str_of(case, "c"), u64_of(case, "ts") + 1);
        assert!(!key.verify_es256(&later, str_of(case, "sig_b64url")));
    }
}

/// §6.7: every `MG-Proof` case with the first failing check as `expect`.
#[test]
fn mg_proof() {
    let kat = kat2();
    let mut seen = std::collections::BTreeSet::new();
    for case in cases(&kat, "mg_proof") {
        let r = &case["request"];
        let req = ProofRequest {
            method: str_of(r, "method"),
            scheme: str_of(r, "scheme"),
            host: str_of(r, "host"),
            path: str_of(r, "path"),
            now_s: r["now_s"].as_i64().unwrap(),
            expected_jkt: r["expected_jkt"].as_str(),
        };
        let got = verify_proof(str_of(case, "mg_proof"), &req);
        let expect = str_of(case, "expect");
        seen.insert(expect.to_owned());
        match got {
            Ok(v) => {
                assert_eq!(expect, "valid", "{}", name(case));
                assert_eq!(
                    v.jti.to_vec(),
                    hex(str_of(case, "jti_hex")),
                    "{}",
                    name(case)
                );
                assert_eq!(v.iat, case["iat"].as_i64().unwrap());
            }
            Err(e) => assert_eq!(e.reason_code(), expect, "{}", name(case)),
        }
    }
    let all: std::collections::BTreeSet<String> = [
        "valid",
        ProofError::Malformed.reason_code(),
        ProofError::Unbound.reason_code(),
        ProofError::Jkt.reason_code(),
        ProofError::Htm.reason_code(),
        ProofError::Htu.reason_code(),
        ProofError::Iat.reason_code(),
        ProofError::Sig.reason_code(),
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(seen, all, "every result has a case");
}

/// §6.9: `cData` under one or two roots.
#[test]
fn cdata() {
    let kat = kat2();
    for case in cases(&kat, "cdata") {
        let root = SealRoot::from_bytes(hex(str_of(case, "root_hex")).try_into().unwrap());
        let site = str_of(case, "site");
        let epoch = u64_of(case, "epoch");
        let nonce: [u8; 16] = hex(str_of(case, "nonce_hex")).try_into().unwrap();
        assert_eq!(
            derive_bind_epoch_key(&root, site, epoch).to_vec(),
            hex(str_of(case, "k_bind_hex")),
            "{}",
            name(case)
        );
        let want = str_of(case, "cdata");
        assert_eq!(
            turnstile_cdata(&root, site, epoch, &nonce),
            want,
            "{}",
            name(case)
        );
        // Checking tries every root: the root may sit first or second.
        let other = SealRoot::from_bytes([0xee; 32]);
        for keys in [
            SealKeys::new(vec![root.clone()]).unwrap(),
            SealKeys::new(vec![other.clone(), root.clone()]).unwrap(),
            SealKeys::new(vec![root.clone(), other.clone()]).unwrap(),
        ] {
            assert!(turnstile_cdata_matches(&keys, site, epoch, &nonce, want));
            assert!(!turnstile_cdata_matches(
                &keys,
                site,
                epoch + 1,
                &nonce,
                want
            ));
        }
        let wrong = SealKeys::new(vec![other]).unwrap();
        assert!(!turnstile_cdata_matches(&wrong, site, epoch, &nonce, want));
    }
}

/// §6.9: the siteverify idempotency key and its previous-secret variant.
#[test]
fn idempotency_keys() {
    let kat = kat2();
    for case in cases(&kat, "idempotency_key") {
        let nonce: [u8; 16] = hex(str_of(case, "nonce_hex")).try_into().unwrap();
        assert_eq!(
            idempotency_key(&nonce, false),
            str_of(case, "idempotency_key")
        );
        assert_eq!(
            idempotency_key(&nonce, true),
            str_of(case, "idempotency_key_previous_secret")
        );
    }
}

/// §6.5: `bind.jkt = bind_hash("jkt", jkt)`.
#[test]
fn bind_jkt() {
    let kat = kat2();
    for case in cases(&kat, "bind_jkt") {
        let h = bind_hash("jkt", str_of(case, "jkt"));
        assert_eq!(h.to_vec(), hex(str_of(case, "hash_hex")));
        assert_eq!(b64(&h), str_of(case, "hash_b64url"));
    }
}
