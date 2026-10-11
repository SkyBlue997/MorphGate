//! Deterministic random-input tests for the Phase 2 parsers (Phase 2 spec
//! §2.4 item 9, §6.11): JWK, `MG-Proof`, clearance claims v2, the renewal
//! open and the Turnstile `cData` check each get at least 10,000 inputs from
//! a fixed-seed xorshift (random and mutated valid ones) and must return an
//! error or a consistent result, never panic.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::random::{N, mutate, mutate_text, random_bytes, random_text};
use common::{MIDDAY_MS, TestRng, interactive_claims, read, sealer};
use mg_challenge::testkit::TestSessionKey;
use mg_challenge::{
    ClearanceBind, MintParams, MintV2Params, ProofRequest, SealKeys, SealRoot, SessionKey,
    TokenKeySet, mint_v2, proof_signing_key, turnstile_cdata, turnstile_cdata_matches, verify,
    verify_proof,
};
use mg_core::{RiskBand, TokenLevel};
use pasetors::keys::SymmetricKey;
use pasetors::version4::{LocalToken, V4};

const NOW_S: i64 = 1_790_000_000;

#[test]
fn jwk_parser_never_panics() {
    let rng = TestRng::new(0x5eed_1001);
    let key = TestSessionKey::from_label("mg-phase2-kat-key-0");
    let valid = key.jwk_json();
    for i in 0..N {
        let _ = SessionKey::from_jwk_json(random_text(&rng, 300).as_bytes());
        let _ = SessionKey::from_jwk_json(&random_bytes(&rng, 300));
        let m = mutate(&rng, valid.as_bytes());
        if let Ok(k) = SessionKey::from_jwk_json(&m) {
            // Whatever parses has the documented shape.
            assert_eq!(k.thumbprint().len(), 43, "{i}");
            assert_eq!(k.point()[0], 4);
            let _ = k.verify_es256(b"m", &random_text(&rng, 90));
        }
    }
}

#[test]
fn mg_proof_never_panics() {
    let rng = TestRng::new(0x5eed_1002);
    let key = TestSessionKey::from_label("mg-phase2-kat-key-0");
    let jkt = key.thumbprint();
    let valid = key.proof("POST", "https://example.com/api/save", NOW_S, &[7; 16]);
    let req = ProofRequest {
        method: "POST",
        scheme: "https",
        host: "example.com",
        path: "/api/save",
        now_s: NOW_S,
        expected_jkt: Some(&jkt),
    };
    assert!(verify_proof(&valid, &req).is_ok());
    let (head, rest) = valid.split_once('.').unwrap();
    let (payload, sig) = rest.split_once('.').unwrap();
    for i in 0..N {
        let _ = verify_proof(&random_text(&rng, 600), &req);
        // Three segments of random base64url.
        let shaped = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(random_bytes(&rng, 200)),
            URL_SAFE_NO_PAD.encode(random_bytes(&rng, 200)),
            URL_SAFE_NO_PAD.encode(random_bytes(&rng, 70)),
        );
        assert!(verify_proof(&shaped, &req).is_err(), "{i}");
        // Mutated header or payload JSON, re-encoded: reaches the JSON rules.
        let h = String::from_utf8_lossy(&URL_SAFE_NO_PAD.decode(head).unwrap()).into_owned();
        let p = String::from_utf8_lossy(&URL_SAFE_NO_PAD.decode(payload).unwrap()).into_owned();
        let forged = format!(
            "{}.{}.{sig}",
            URL_SAFE_NO_PAD.encode(mutate_text(&rng, &h)),
            URL_SAFE_NO_PAD.encode(mutate_text(&rng, &p)),
        );
        // The signature no longer matches whatever changed.
        let got = verify_proof(&forged, &req);
        assert!(got.is_err() || forged == valid, "{i}");
        // Mutations of the whole value can only fail.
        let m = mutate_text(&rng, &valid);
        assert!(m == valid || verify_proof(&m, &req).is_err(), "{i}");
        let _ = proof_signing_key(&m);
    }
}

#[test]
fn clearance_v2_verify_never_panics() {
    let rng = TestRng::new(0x5eed_1003);
    let kids = vec!["blog-t-20260927".to_string()];
    let keys = TokenKeySet::from_key_file(&read("keys/token.keys.json"), "blog", &kids).unwrap();
    let p = MintV2Params {
        base: MintParams {
            env: "production",
            session: None,
            lvl: TokenLevel::Interactive,
            now_s: NOW_S,
            ttl_s: 1800,
            bind: ClearanceBind::from_inputs(&common::bindings()).unwrap(),
            rb: RiskBand::High,
            replay_unchecked: false,
        },
        cnf_jkt: Some("L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc"),
        lat: None,
        allow_v2: true,
    };
    let (valid, claims) = mint_v2(&keys, "blog", &p, &rng).unwrap();
    let payload = serde_json::to_vec(&claims).unwrap();
    let sk = SymmetricKey::<V4>::from(&(0x20..0x40).collect::<Vec<u8>>()).unwrap();
    let implicit = [b"mg-clr-v1".as_slice(), &[0], b"blog"].concat();
    let run = |t: &str| verify(&keys, "blog", "production", t, NOW_S);
    assert!(run(&valid).is_ok());
    for i in 0..N {
        let m = mutate_text(&rng, &valid);
        assert!(m == valid || run(&m).is_err(), "{i}");
        // Correctly encrypted mutations of the v2 claims.
        let mut claims_bytes = mutate(&rng, &payload);
        claims_bytes.push(b' ');
        let t = LocalToken::encrypt(
            &sk,
            &claims_bytes,
            Some(br#"{"kid":"blog-t-20260927"}"#),
            Some(&implicit),
        )
        .unwrap();
        if let Ok(c) = run(&t) {
            // Whatever verifies obeys the version rules of §6.8.
            match c.v {
                1 => assert!(c.lat.is_none() && c.cnf.is_none(), "{i}"),
                2 => assert!(c.lat.is_some_and(|l| c.sst <= l && l <= c.iat), "{i}"),
                v => panic!("version {v} verified"),
            }
        }
    }
}

#[test]
fn open_for_renew_never_panics() {
    let rng = TestRng::new(0x5eed_1004);
    let s = sealer("blog", &[1, 2]);
    let claims = interactive_claims(MIDDAY_MS);
    let valid = s.seal(&claims, "example.com", &rng).unwrap();
    for i in 0..N {
        let now = MIDDAY_MS + (rng.below(8_000_000) as i64);
        let _ = s.open_for_renew(&random_text(&rng, 1100), "example.com", now);
        let m = mutate_text(&rng, &valid);
        let got = s.open_for_renew(&m, "example.com", now);
        assert!(m == valid || got.is_err(), "{i}");
        let got = s.open_for_renew(&valid, "example.com", now);
        let expired = now >= claims.exp_ms;
        match got {
            Ok((c, e)) => assert!(c == claims && e == expired, "{i}"),
            Err(e) => assert!(
                expired && now - claims.exp_ms > mg_challenge::RENEW_MAX_EXPIRED_MS,
                "{i}: {e:?}"
            ),
        }
    }
}

#[test]
fn cdata_check_never_panics() {
    let rng = TestRng::new(0x5eed_1005);
    let root = SealRoot::from_bytes([1; 32]);
    let keys = SealKeys::new(vec![root.clone()]).unwrap();
    let nonce = [3; 16];
    let valid = turnstile_cdata(&root, "blog", 20_736, &nonce);
    for i in 0..N {
        let text = random_text(&rng, 60);
        assert_eq!(
            turnstile_cdata_matches(&keys, "blog", 20_736, &nonce, &text),
            text == valid,
            "{i}"
        );
        let m = mutate_text(&rng, &valid);
        assert_eq!(
            turnstile_cdata_matches(&keys, "blog", 20_736, &nonce, &m),
            m == valid,
            "{i}"
        );
    }
}
