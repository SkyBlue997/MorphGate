//! Clearance tokens and cookies (spec §7): `verify` rejects what it cannot
//! verify without panicking, including correctly encrypted random claims;
//! `clearance_cookies` only returns values that appear in the headers.
//!
//! Input: one mode byte; 0 = the rest is a token, 1 = the rest is the claims
//! payload of a token encrypted with the test key, 2 = the rest is `Cookie`
//! header lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mg_challenge::{TokenKeySet, clearance_cookies, verify, verify_ignoring_expiry};
use pasetors::keys::SymmetricKey;
use pasetors::version4::{LocalToken, V4};

const KEYS: &[u8] = include_bytes!("../../testdata/phase1/keys/token.keys.json");
const NOW_S: i64 = 1_790_000_000;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let kids = vec!["blog-t-20260927".to_owned()];
    let keys = TokenKeySet::from_key_file(KEYS, "blog", &kids).unwrap();
    let check = |token: &str| {
        let _ = verify(&keys, "blog", "production", token, NOW_S);
        let _ = verify_ignoring_expiry(&keys, "blog", "production", token, NOW_S);
    };
    match mode % 3 {
        0 => check(&String::from_utf8_lossy(rest)),
        1 if !rest.is_empty() => {
            // The key of blog-t-20260927 in token.keys.json.
            let sk = SymmetricKey::<V4>::from(&(0x20..0x40).collect::<Vec<u8>>()).unwrap();
            let implicit = [b"mg-clr-v1".as_slice(), &[0], b"blog"].concat();
            let token = LocalToken::encrypt(
                &sk,
                rest,
                Some(br#"{"kid":"blog-t-20260927"}"#),
                Some(&implicit),
            )
            .unwrap();
            check(&token);
        }
        1 => {}
        _ => {
            let text = String::from_utf8_lossy(rest);
            let headers: Vec<&str> = text.split('\n').collect();
            let found = clearance_cookies(&headers);
            assert!(found.len() <= 2);
            for f in found {
                assert!(headers.iter().any(|h| h.contains(f)));
            }
        }
    }
});
