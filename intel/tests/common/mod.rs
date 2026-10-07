//! Helpers shared by mg-intel's integration tests.
#![allow(dead_code)] // each test binary uses a subset

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use mg_core::BoxFuture;
use mg_intel::{DnsError, DnsResolver};

/// `testdata/phase1/` at the repository root.
pub fn phase1() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/phase1")
}

/// `intel/testdata/`.
pub fn intel_testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

pub fn read(path: PathBuf) -> Vec<u8> {
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Polls a future that must be ready at once (spec §2.3: no executor; the
/// resolvers used in tests answer synchronously).
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future was not immediately ready"),
    }
}

/// Deterministic xorshift64 (spec §2.4 fuzz inputs).
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform-ish in `0..n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    /// Applies 1-4 random edits to `seed`: byte flips, replacements from a
    /// syntax-heavy alphabet, deletions, duplications and truncation. Keeps
    /// most of the structure so parsers get past their first byte.
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8] = b"0123456789abcdefAS./:\"[]{},-_ #\n\\tfnu";
        let mut out = seed.to_vec();
        for _ in 0..=self.below(4) {
            if out.is_empty() {
                out.push(ALPHABET[self.below(ALPHABET.len())]);
                continue;
            }
            let i = self.below(out.len());
            match self.below(6) {
                0 => out[i] ^= 1 << self.below(8),
                1 | 2 => out[i] = ALPHABET[self.below(ALPHABET.len())],
                3 => {
                    let end = (i + 1 + self.below(16)).min(out.len());
                    out.drain(i..end);
                }
                4 => {
                    let end = (i + 1 + self.below(32)).min(out.len());
                    let chunk = out[i..end].to_vec();
                    let at = self.below(out.len() + 1);
                    out.splice(at..at, chunk);
                }
                _ => out.truncate(i),
            }
        }
        out
    }
}

/// A scripted resolver that records every query. Unscripted queries answer
/// `NoRecords`.
#[derive(Default)]
pub struct Scripted {
    pub ptr: HashMap<IpAddr, Result<Vec<String>, DnsError>>,
    pub fwd: HashMap<String, Result<Vec<IpAddr>, DnsError>>,
    pub calls: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Scripted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scripted")
    }
}

impl Scripted {
    pub fn ptr(mut self, ip: &str, answer: Result<&[&str], DnsError>) -> Self {
        self.ptr.insert(
            ip.parse().unwrap(),
            answer.map(|names| names.iter().map(|s| (*s).to_owned()).collect()),
        );
        self
    }

    /// `name` is the fully-qualified form `resolve_rdns` queries (trailing dot).
    pub fn fwd(mut self, name: &str, answer: Result<&[&str], DnsError>) -> Self {
        self.fwd.insert(
            name.to_owned(),
            answer.map(|ips| ips.iter().map(|s| s.parse().unwrap()).collect()),
        );
        self
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl DnsResolver for Scripted {
    fn reverse(&self, ip: IpAddr) -> BoxFuture<'_, Result<Vec<String>, DnsError>> {
        self.calls.lock().unwrap().push(format!("PTR {ip}"));
        let answer = self
            .ptr
            .get(&ip)
            .cloned()
            .unwrap_or(Err(DnsError::NoRecords));
        Box::pin(std::future::ready(answer))
    }

    fn forward(&self, name: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, DnsError>> {
        self.calls.lock().unwrap().push(format!("A {name}"));
        let answer = self
            .fwd
            .get(name)
            .cloned()
            .unwrap_or(Err(DnsError::NoRecords));
        Box::pin(std::future::ready(answer))
    }
}
