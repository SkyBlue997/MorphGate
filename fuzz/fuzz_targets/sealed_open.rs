//! Sealed challenges `C` (spec §6.2): `Sealer::open` rejects what it cannot
//! open without panicking, including correctly encrypted random plaintexts,
//! so the claims decoder and the checks behind the AEAD are reached too.
//!
//! Input: one mode byte; even = the rest is `C`, odd = the rest is the
//! plaintext of an envelope sealed with the right epoch key.
#![no_main]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use libfuzzer_sys::fuzz_target;
use mg_challenge::{SealKeys, SealRoot, Sealer, aad, derive_epoch_key, epoch_kid, epoch_no};
use mg_core::ChallengeType;
use mg_proto::v1::SealedChallenge;
use prost::Message;

/// Midday of 2026-10-10 (epoch 20736).
const NOW_MS: i64 = 20_736 * 86_400_000 + 43_200_000;
const HOST: &str = "example.com";

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let root = SealRoot::from_bytes([1; 32]);
    let sealer = Sealer::new("blog", SealKeys::new(vec![root.clone()]).unwrap());
    let c = if mode % 2 == 0 {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        let kid = epoch_kid(epoch_no(NOW_MS));
        let key = derive_epoch_key(&root, "blog", epoch_no(NOW_MS));
        let nonce = [0x24; 24];
        let ct = XChaCha20Poly1305::new(&Key::from(key))
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: rest,
                    aad: &aad(HOST, ChallengeType::Pow, &kid),
                },
            )
            .unwrap();
        let env = SealedChallenge {
            v: 1,
            kid,
            xnonce: nonce.to_vec(),
            ct,
        };
        URL_SAFE_NO_PAD.encode(env.encode_to_vec())
    };
    let _ = sealer.open(&c, HOST, ChallengeType::Pow, NOW_MS);
});
