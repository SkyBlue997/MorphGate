//! Deterministic random-input tests (spec §2.4 item 3): every parser of
//! this crate (sealed challenges, clearance tokens and their footers,
//! cookies, key files, return paths, epoch kids) gets at least 10,000
//! inputs from a fixed-seed xorshift and must return an error, never panic.
//! Inputs are both random and mutations of valid ones, and some are
//! correctly encrypted random plaintexts, so the checks behind the AEAD and
//! PASETO layers are reached too.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use common::{MIDDAY_MS, TestRng, read, sealer};
use mg_challenge::{
    ClearanceBind, MintParams, SealKeys, TokenKeySet, aad, clearance_cookies, derive_epoch_key,
    epoch_kid, epoch_no, mint, parse_epoch_kid, validate_ret, verify,
};
use mg_core::{ChallengeType, RiskBand, TokenLevel};
use mg_proto::v1::SealedChallenge;
use pasetors::keys::SymmetricKey;
use pasetors::version4::{LocalToken, V4};
use prost::Message;

const N: usize = 10_000;
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STRUCTURAL: &[u8] = b".;=:/?#%\\\" {}[],\t\r\n\x00\x7f";

/// A random string mostly over the base64url alphabet, with structural
/// characters and the occasional multi-byte character mixed in.
fn random_text(rng: &TestRng, max_len: u64) -> String {
    let len = rng.below(max_len + 1) as usize;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        match rng.below(20) {
            0 => s.push(STRUCTURAL[rng.below(STRUCTURAL.len() as u64) as usize] as char),
            1 => s.push(['é', '中', '\u{feff}', '🦀'][rng.below(4) as usize]),
            _ => s.push(B64URL[rng.below(B64URL.len() as u64) as usize] as char),
        }
    }
    s
}

fn random_bytes(rng: &TestRng, max_len: u64) -> Vec<u8> {
    let mut v = vec![0u8; rng.below(max_len + 1) as usize];
    mg_challenge::Rng::fill(rng, &mut v).unwrap();
    v
}

/// Replaces, inserts or deletes a few bytes of `input`.
fn mutate(rng: &TestRng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..=rng.below(3) {
        let pos = if v.is_empty() {
            0
        } else {
            rng.below(v.len() as u64) as usize
        };
        let byte = (rng.next_u64() >> 56) as u8;
        match rng.below(3) {
            0 if !v.is_empty() => v[pos] = byte,
            1 => v.insert(pos, byte),
            _ if !v.is_empty() => {
                v.remove(pos);
            }
            _ => v.push(byte),
        }
    }
    v
}

fn mutate_text(rng: &TestRng, input: &str) -> String {
    String::from_utf8_lossy(&mutate(rng, input.as_bytes())).into_owned()
}

#[test]
fn sealed_challenge_open_never_panics() {
    let rng = TestRng::new(0x5eed_0001);
    let s = sealer("blog", &[1, 2]);
    let now = MIDDAY_MS;
    let valid = s
        .seal(&common::pow_claims(now), "example.com", &rng)
        .unwrap();
    let kid = epoch_kid(epoch_no(now));
    let key = derive_epoch_key(&common::seal_root(1), "blog", epoch_no(now));
    let open = |c: &str| s.open(c, "example.com", ChallengeType::Pow, now);

    for i in 0..N {
        // Random text and random base64url of random bytes.
        assert!(open(&random_text(&rng, 1100)).is_err(), "text {i}");
        let b = URL_SAFE_NO_PAD.encode(random_bytes(&rng, 700));
        assert!(open(&b).is_err(), "bytes {i}");
        // Mutations of a valid C (a mutation can only fail).
        let m = mutate_text(&rng, &valid);
        assert!(m == valid || open(&m).is_err(), "mutation {i}");
        // A valid envelope around random ciphertext.
        let env = SealedChallenge {
            v: 1,
            kid: kid.clone(),
            xnonce: random_bytes(&rng, 30),
            ct: random_bytes(&rng, 400),
        };
        assert!(open(&URL_SAFE_NO_PAD.encode(env.encode_to_vec())).is_err());
        // Random plaintext correctly encrypted: exercises claims decoding.
        let mut nonce = [0u8; 24];
        mg_challenge::Rng::fill(&rng, &mut nonce).unwrap();
        let pt = random_bytes(&rng, 300);
        let ct = XChaCha20Poly1305::new(&Key::from(key))
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &pt,
                    aad: &aad("example.com", ChallengeType::Pow, &kid),
                },
            )
            .unwrap();
        let env = SealedChallenge {
            v: 1,
            kid: kid.clone(),
            xnonce: nonce.to_vec(),
            ct,
        };
        assert!(open(&URL_SAFE_NO_PAD.encode(env.encode_to_vec())).is_err());
    }
}

#[test]
fn clearance_verify_never_panics() {
    let rng = TestRng::new(0x5eed_0002);
    let kids = vec!["blog-t-20260927".to_string()];
    let keys = TokenKeySet::from_key_file(&read("keys/token.keys.json"), "blog", &kids).unwrap();
    let now = 1_790_000_000;
    let params = MintParams {
        env: "production",
        session: None,
        lvl: TokenLevel::Invisible,
        now_s: now,
        ttl_s: 1800,
        bind: ClearanceBind::from_inputs(&common::bindings()).unwrap(),
        rb: RiskBand::Low,
    };
    let (valid, _) = mint(&keys, "blog", &params, &rng).unwrap();
    let footer = valid.rsplit('.').next().unwrap().to_owned();
    let sk = SymmetricKey::<V4>::from(&(0x20..0x40).collect::<Vec<u8>>()).unwrap();
    let implicit = [b"mg-clr-v1".as_slice(), &[0], b"blog"].concat();
    let run = |t: &str| verify(&keys, "blog", "production", t, now);

    for i in 0..N {
        assert!(run(&random_text(&rng, 1100)).is_err(), "text {i}");
        let t = format!(
            "v4.local.{}.{}",
            random_text(&rng, 600),
            random_text(&rng, 60)
        );
        assert!(run(&t).is_err(), "shaped {i}");
        let t = format!(
            "v4.local.{}.{footer}",
            URL_SAFE_NO_PAD.encode(random_bytes(&rng, 500))
        );
        assert!(run(&t).is_err(), "payload {i}");
        let m = mutate_text(&rng, &valid);
        assert!(m == valid || run(&m).is_err(), "mutation {i}");
        // Correctly encrypted random claims (JSON-ish and raw bytes).
        let payload = if i % 2 == 0 {
            mutate(&rng, br#"{"v":1,"kid":"blog-t-20260927","sid":"blog","env":"production","sub":"AAAAAAAAAAAAAAAAAAAAAA","sst":1790000000,"lvl":"pow","iat":1790000000,"exp":1790001800,"bind":{"uah":"iXRgjCj6tPt2cFcPqeHr_A","ipp":"JxTqJG6DMjc-DDCAwG3WYw"},"rb":"low","jti":"AAAAAAAAAAAAAAAAAAAAAA"}"#)
        } else {
            let mut b = random_bytes(&rng, 300);
            b.push(b'x'); // pasetors refuses empty payloads
            b
        };
        let t = LocalToken::encrypt(
            &sk,
            &payload,
            Some(br#"{"kid":"blog-t-20260927"}"#),
            Some(&implicit),
        )
        .unwrap();
        // A mutation may leave the claims valid; it must never panic.
        let _ = run(&t);
    }
}

#[test]
fn cookie_parser_never_panics() {
    let rng = TestRng::new(0x5eed_0003);
    for i in 0..N {
        let headers: Vec<String> = (0..rng.below(4))
            .map(|_| {
                let mut h = random_text(&rng, 400);
                if rng.below(3) == 0 {
                    h.push_str("; __Host-mg_clr=");
                    h.push_str(&random_text(&rng, 50));
                }
                if rng.below(20) == 0 {
                    h = h.repeat(60); // beyond 16 KiB
                }
                h
            })
            .collect();
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let found = clearance_cookies(&refs);
        assert!(found.len() <= 2, "{i}");
        for f in found {
            assert!(headers.iter().any(|h| h.contains(f)), "{i}");
        }
    }
}

#[test]
fn key_file_parsers_never_panic() {
    let rng = TestRng::new(0x5eed_0004);
    let seal_files = [
        read("keys/seal.root.json"),
        read("keys/seal.root.rotating.json"),
    ];
    let token_files = [
        read("keys/token.keys.json"),
        read("keys/token.keys.rotated.json"),
    ];
    let kids = vec!["blog-t-20260927".to_string()];
    for i in 0..N {
        let junk = random_bytes(&rng, 600);
        assert!(SealKeys::from_key_file(&junk, "blog").is_err(), "{i}");
        assert!(
            TokenKeySet::from_key_file(&junk, "blog", &kids).is_err(),
            "{i}"
        );
        let text = random_text(&rng, 600);
        assert!(SealKeys::from_key_file(text.as_bytes(), "blog").is_err());
        // Mutations of valid files may stay valid (e.g. in created_at digits).
        let m = mutate(&rng, &seal_files[i % 2]);
        let _ = SealKeys::from_key_file(&m, "blog");
        let m = mutate(&rng, &token_files[i % 2]);
        let _ = TokenKeySet::from_key_file(&m, "blog", &kids);
    }
}

#[test]
fn small_parsers_never_panic() {
    let rng = TestRng::new(0x5eed_0005);
    for _ in 0..N {
        let s = random_text(&rng, 700);
        if validate_ret(&s).is_ok() {
            assert!(s.starts_with('/') && s.len() <= 512 && !s.contains(['#', '\\']));
        }
        let r = format!("/{s}");
        let _ = validate_ret(&r);
        let k = random_text(&rng, 24);
        if let Some(e) = parse_epoch_kid(&k) {
            assert_eq!(epoch_kid(e), k, "only the canonical spelling parses");
        }
        let _ = parse_epoch_kid(&format!("e{}", rng.next_u64()));
    }
}
