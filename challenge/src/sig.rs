//! Signed messages of the SDK session key (docs/impl/phase2-spec.md §6.6):
//! the `mg-sub-v2` submission message and the `mg-renew-v1` renewal message,
//! built from length-prefixed fields.
//!
//! ```text
//! lp(x) = u16be(len(x)) ‖ x            (x ≤ 65535 bytes; strings as UTF-8)
//! H(x)  = SHA-256(x)
//!
//! submission (mg-sub-v2):
//!   "mg-sub-v2" ‖ 0x00 ‖ lp(c) ‖ lp(type) ‖ lp(p) ‖ lp(H(pp)) ‖ lp(H(t)) ‖ lp(counters) ‖ lp(ret) ‖ u64be(ts) ‖ lp(build)
//! renew (mg-renew-v1):
//!   "mg-renew-v1" ‖ 0x00 ‖ lp(c) ‖ u64be(ts)
//! ```
//!
//! `pp` and `t` are the UTF-8 bytes of the submitted string fields (after
//! JSON decoding; empty when absent), so both sides hash the same bytes
//! without any JSON canonicalization. `counters` is the decimal counters
//! joined by `,`. Signatures are verified with
//! [`crate::SessionKey::verify_es256`] against the key of the submitted JWK.

use sha2::{Digest, Sha256};
use std::fmt::{self, Write as _};

const SUB_DOMAIN: &[u8] = b"mg-sub-v2";
const RENEW_DOMAIN: &[u8] = b"mg-renew-v1";

/// The fields of a `/__mg/c` v2 submission that its signature covers.
/// `Debug` shows only the type, provider and sizes: `c` is a single-use
/// secret and `pp` may be a Turnstile token.
#[derive(Clone, Copy)]
pub struct SubmissionFields<'a> {
    pub c: &'a str,
    /// `invisible`, `pow` or `interactive`.
    pub ty: &'a str,
    /// Provider id; empty for non-interactive submissions.
    pub p: &'a str,
    /// Provider payload (Turnstile token or empty).
    pub pp: &'a str,
    /// Telemetry text (`t`), empty when absent.
    pub t: &'a str,
    pub counters: &'a [u64],
    pub ret: &'a str,
    /// Client time in milliseconds; a feature only.
    pub ts: u64,
    pub build: &'a str,
}

impl fmt::Debug for SubmissionFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmissionFields")
            .field("ty", &self.ty)
            .field("p", &self.p)
            .field("pp_len", &self.pp.len())
            .field("t_len", &self.t.len())
            .field("counters", &self.counters.len())
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

/// `lp(x) = u16be(len(x)) ‖ x`, appended to `out`. Longer fields cannot occur
/// (request bodies are at most 8 KiB); their prefix saturates, so the result
/// never matches a client's message instead of aliasing another one.
pub(crate) fn push_lp(out: &mut Vec<u8>, x: &[u8]) {
    let len = u16::try_from(x.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

/// The decimal counters joined by `,` without spaces, e.g. `387,10648`.
pub fn counters_text(counters: &[u64]) -> String {
    let mut s = String::with_capacity(counters.len() * 8);
    for (i, n) in counters.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        // Writing to a String never fails.
        let _ = write!(s, "{n}");
    }
    s
}

/// The `mg-sub-v2` message the SDK signs for a `/__mg/c` v2 submission.
pub fn submission_message(f: &SubmissionFields<'_>) -> Vec<u8> {
    let counters = counters_text(f.counters);
    let mut out = Vec::with_capacity(
        SUB_DOMAIN.len()
            + 1
            + 2 * 8
            + f.c.len()
            + f.ty.len()
            + f.p.len()
            + 64
            + counters.len()
            + f.ret.len()
            + 8
            + f.build.len(),
    );
    out.extend_from_slice(SUB_DOMAIN);
    out.push(0);
    push_lp(&mut out, f.c.as_bytes());
    push_lp(&mut out, f.ty.as_bytes());
    push_lp(&mut out, f.p.as_bytes());
    push_lp(&mut out, &Sha256::digest(f.pp.as_bytes()));
    push_lp(&mut out, &Sha256::digest(f.t.as_bytes()));
    push_lp(&mut out, counters.as_bytes());
    push_lp(&mut out, f.ret.as_bytes());
    out.extend_from_slice(&f.ts.to_be_bytes());
    push_lp(&mut out, f.build.as_bytes());
    out
}

/// The `mg-renew-v1` message the SDK signs for `/__mg/c/renew`.
pub fn renew_message(c: &str, ts: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(RENEW_DOMAIN.len() + 3 + c.len() + 8);
    out.extend_from_slice(RENEW_DOMAIN);
    out.push(0);
    push_lp(&mut out, c.as_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_join() {
        assert_eq!(counters_text(&[]), "");
        assert_eq!(counters_text(&[387, 10648]), "387,10648");
        assert_eq!(counters_text(&[u64::MAX]), "18446744073709551615");
    }

    #[test]
    fn length_prefixes_separate_fields() {
        let base = SubmissionFields {
            c: "ab",
            ty: "pow",
            p: "",
            pp: "",
            t: "",
            counters: &[1],
            ret: "/",
            ts: 0,
            build: "b",
        };
        let moved = SubmissionFields {
            c: "a",
            ty: "bpow",
            ..base
        };
        assert_ne!(submission_message(&base), submission_message(&moved));
        let mut lp = Vec::new();
        push_lp(&mut lp, &vec![0; 70_000]);
        assert_eq!(&lp[..2], &[0xff, 0xff]);
        assert_eq!(
            renew_message("c", 1),
            b"mg-renew-v1\0\x00\x01c\0\0\0\0\0\0\0\x01"
        );
    }

    #[test]
    fn debug_hides_c_and_payload() {
        let f = SubmissionFields {
            c: "SECRET-C",
            ty: "interactive",
            p: "turnstile",
            pp: "SECRET-TOKEN",
            t: "{}",
            counters: &[1, 2],
            ret: "/r",
            ts: 5,
            build: "b",
        };
        let s = format!("{f:?}");
        assert!(!s.contains("SECRET"), "{s}");
        assert!(s.contains("turnstile"), "{s}");
    }
}
