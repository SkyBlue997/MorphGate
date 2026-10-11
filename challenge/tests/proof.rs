//! `MG-Proof` (Phase 2 spec §6.7) with proofs built by the testkit: the
//! order of the checks when several fail, the time window, the JSON rules and
//! the in-place recovery key of §9.1. The full vector set is in
//! `kat_phase2.rs`.

use mg_challenge::testkit::TestSessionKey;
use mg_challenge::{ProofError, ProofRequest, proof_signing_key, verify_proof};

const NOW: i64 = 1_790_000_000;
const HTU: &str = "https://example.com/api/save";

fn key() -> TestSessionKey {
    TestSessionKey::from_label("mg-phase2-kat-key-0")
}

fn req(jkt: Option<&str>) -> ProofRequest<'_> {
    ProofRequest {
        method: "POST",
        scheme: "https",
        host: "example.com",
        path: "/api/save",
        now_s: NOW,
        expected_jkt: jkt,
    }
}

/// Replaces the signature with that of another key.
fn resign(proof: &str, other: &TestSessionKey) -> String {
    let (input, _) = proof.rsplit_once('.').unwrap();
    format!("{input}.{}", other.sign(input.as_bytes()))
}

#[test]
fn valid_proofs() {
    let k = key();
    let jkt = k.thumbprint();
    for (iat, jti) in [(NOW, [1u8; 16]), (NOW - 30, [2; 16]), (NOW + 5, [0xff; 16])] {
        let p = k.proof("POST", HTU, iat, &jti);
        let v = verify_proof(&p, &req(Some(&jkt))).unwrap();
        assert_eq!((v.jti, v.iat), (jti, iat));
    }
    // A fresh random key works the same way.
    let fresh = TestSessionKey::generate();
    let jkt = fresh.thumbprint();
    let p = fresh.proof("DELETE", "https://example.com/api/save?x=1", NOW, &[3; 16]);
    let r = ProofRequest {
        method: "DELETE",
        ..req(Some(&jkt))
    };
    assert!(verify_proof(&p, &r).is_ok());
}

/// When several checks fail, the first in §6.7 order is reported.
#[test]
fn first_failure_wins() {
    let k = key();
    let other = TestSessionKey::from_label("mg-phase2-kat-key-1");
    let jkt = k.thumbprint();
    let other_jkt = other.thumbprint();
    // Everything wrong after step 1, step by step.
    let bad_all = resign(
        &k.proof("GET", "https://other.example/x", NOW - 31, &[0; 16]),
        &other,
    );
    let cases = [
        (req(None), ProofError::Unbound),
        (req(Some(&other_jkt)), ProofError::Jkt),
        (req(Some(&jkt)), ProofError::Htm),
    ];
    for (r, want) in cases {
        assert_eq!(verify_proof(&bad_all, &r), Err(want));
    }
    let bad_url = resign(
        &k.proof("POST", "https://other.example/x", NOW - 31, &[0; 16]),
        &other,
    );
    assert_eq!(
        verify_proof(&bad_url, &req(Some(&jkt))),
        Err(ProofError::Htu)
    );
    let bad_time = resign(&k.proof("POST", HTU, NOW - 31, &[0; 16]), &other);
    assert_eq!(
        verify_proof(&bad_time, &req(Some(&jkt))),
        Err(ProofError::Iat)
    );
    let bad_time = k.proof("POST", HTU, NOW + 6, &[0; 16]);
    assert_eq!(
        verify_proof(&bad_time, &req(Some(&jkt))),
        Err(ProofError::Iat)
    );
    let bad_sig = resign(&k.proof("POST", HTU, NOW, &[0; 16]), &other);
    assert_eq!(
        verify_proof(&bad_sig, &req(Some(&jkt))),
        Err(ProofError::Sig)
    );
    // Malformed beats everything, including a missing clearance.
    let malformed = k.sign_jws(
        r#"{"alg":"ES256","typ":"mg-proof+jwt","jwk":{}}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    );
    assert_eq!(
        verify_proof(&malformed, &req(None)),
        Err(ProofError::Malformed)
    );
}

#[test]
fn json_rules() {
    let k = key();
    let jkt = k.thumbprint();
    let jwk = k.jwk_json();
    let header = format!(r#"{{"alg":"ES256","typ":"mg-proof+jwt","jwk":{jwk}}}"#);
    let payload = r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    assert!(verify_proof(&k.sign_jws(&header, payload), &req(Some(&jkt))).is_ok());
    // Insignificant whitespace is fine (the signature covers the bytes sent).
    let spaced = format!(r#"{{ "alg" : "ES256", "typ":"mg-proof+jwt", "jwk":{jwk} }}"#);
    assert!(verify_proof(&k.sign_jws(&spaced, payload), &req(Some(&jkt))).is_ok());
    let bad_headers = [
        format!(r#"{{"alg":"ES256","typ":"mg-proof+jwt","jwk":{jwk},"kid":"x"}}"#),
        format!(r#"{{"alg":"ES256","alg":"ES256","typ":"mg-proof+jwt","jwk":{jwk}}}"#),
        format!(r#"{{"alg":"none","typ":"mg-proof+jwt","jwk":{jwk}}}"#),
        format!(r#"{{"alg":"ES256","typ":"dpop+jwt","jwk":{jwk}}}"#),
        r#"{"alg":"ES256","typ":"mg-proof+jwt"}"#.to_owned(),
        format!(r#"["ES256","mg-proof+jwt",{jwk}]"#),
        format!(r#"{{"alg":"ES256","typ":"mg-proof+jwt","jwk":{jwk}}} "#) + "x",
    ];
    for h in &bad_headers {
        assert_eq!(
            verify_proof(&k.sign_jws(h, payload), &req(Some(&jkt))),
            Err(ProofError::Malformed),
            "{h}"
        );
    }
    let bad_payloads = [
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAA","ath":"x"}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000.0,"jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":-1e3,"jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAB"}"#,
        r#"{"htm":"POST","htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"htm":null,"htu":"https://example.com/api/save","iat":1790000000,"jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ];
    for p in bad_payloads {
        assert_eq!(
            verify_proof(&k.sign_jws(&header, p), &req(Some(&jkt))),
            Err(ProofError::Malformed),
            "{p}"
        );
    }
    // The limits themselves: htm of 32 bytes, htu of 2048 bytes.
    let long_method = "P".repeat(32);
    let p = k.proof(&long_method, HTU, NOW, &[0; 16]);
    let r = ProofRequest {
        method: &long_method,
        ..req(Some(&jkt))
    };
    assert!(verify_proof(&p, &r).is_ok());
    let path = format!("/{}", "a".repeat(2048 - "https://example.com/".len()));
    let htu = format!("https://example.com{path}");
    assert_eq!(htu.len(), 2048);
    let r = ProofRequest {
        path: &path,
        ..req(Some(&jkt))
    };
    assert!(verify_proof(&k.proof("POST", &htu, NOW, &[0; 16]), &r).is_ok());
    let r2 = ProofRequest {
        path: &format!("{path}a"),
        ..req(Some(&jkt))
    };
    assert_eq!(
        verify_proof(&k.proof("POST", &format!("{htu}a"), NOW, &[0; 16]), &r2),
        Err(ProofError::Malformed)
    );
}

/// §9.1 in-place recovery: the key of a correctly signed proof, whatever
/// else is wrong with it.
#[test]
fn recovery_key() {
    let k = key();
    let other = TestSessionKey::from_label("mg-phase2-kat-key-1");
    let stale = k.proof("GET", "https://other.example/", NOW - 3_600, &[0; 16]);
    let got = proof_signing_key(&stale).unwrap();
    assert_eq!(got.thumbprint(), k.thumbprint());
    assert!(proof_signing_key(&resign(&stale, &other)).is_none());
    assert!(proof_signing_key("x.y.z").is_none());
}
