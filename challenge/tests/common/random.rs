//! Seeded random inputs for the never-panic tests (spec §2.4 item 3,
//! Phase 2 spec §2.4 item 9): random text over the base64url alphabet with
//! structural and multi-byte characters, random bytes and small mutations.

use super::TestRng;

pub const N: usize = 10_000;
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STRUCTURAL: &[u8] = b".;=:/?#%\\\" {}[],\t\r\n\x00\x7f";

/// A random string mostly over the base64url alphabet, with structural
/// characters and the occasional multi-byte character mixed in.
pub fn random_text(rng: &TestRng, max_len: u64) -> String {
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

pub fn random_bytes(rng: &TestRng, max_len: u64) -> Vec<u8> {
    let mut v = vec![0u8; rng.below(max_len + 1) as usize];
    mg_challenge::Rng::fill(rng, &mut v).unwrap();
    v
}

/// Replaces, inserts or deletes a few bytes of `input`.
pub fn mutate(rng: &TestRng, input: &[u8]) -> Vec<u8> {
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

pub fn mutate_text(rng: &TestRng, input: &str) -> String {
    String::from_utf8_lossy(&mutate(rng, input.as_bytes())).into_owned()
}
