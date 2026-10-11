//! Edge → origin authentication (docs/impl/phase1-spec.md I-38).
//!
//! With `[[sites]] origin_keys` set, the Edge adds `MG-Origin-Auth` to every
//! request it forwards, so the origin can tell the `MG-*` headers it trusts
//! (client IP, request id, scores, session) were written by the Edge and not
//! by another process that can reach it:
//!
//! ```text
//! MG-Origin-Auth: v1;t=<unix seconds>;sig=<unpadded base64url>
//! sig = HMAC-SHA256(values[0] decoded, msg)
//! msg = "mg-origin-auth-v1\n" t "\n" method "\n" target "\n"
//!       then "<name>:<value>\n" for each of COVERED that is present
//! ```
//!
//! `target` is the origin-form request target as forwarded (path and query).
//! The origin accepts any value of its copy of the key file (newest first,
//! 1–2 during a rotation) and a `t` within [`MAX_SKEW_S`] of its clock, and
//! trusts no `MG-*` header until the signature verifies. [`verify`] is the
//! reference check; `adapters/origin/verify-origin-auth.mjs` is the same in
//! JavaScript, and `kat.json` `origin_auth` pins both.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The header the Edge writes.
pub const HEADER: &str = "MG-Origin-Auth";

/// The `MG-*` headers the signature covers, in signing order (lower case):
/// every header the Edge writes for the origin (§9.9).
pub const COVERED: [&str; 8] = [
    "mg-client-ip",
    "mg-request-id",
    "mg-bot-score",
    "mg-bot-class",
    "mg-verified",
    "mg-session",
    "mg-tags",
    "mg-reasons",
];

/// The clock difference an origin should accept, in seconds.
pub const MAX_SKEW_S: u64 = 60;

const DOMAIN: &str = "mg-origin-auth-v1";

/// The signing input. `header` returns the value of a [`COVERED`] header
/// (looked up by its lower-case name), `None` when it is absent.
pub fn message<'a>(
    t: u64,
    method: &str,
    target: &[u8],
    header: impl Fn(&str) -> Option<&'a str>,
) -> Vec<u8> {
    let mut msg = format!("{DOMAIN}\n{t}\n{method}\n").into_bytes();
    msg.extend_from_slice(target);
    msg.push(b'\n');
    for name in COVERED {
        if let Some(value) = header(name) {
            msg.extend_from_slice(name.as_bytes());
            msg.push(b':');
            msg.extend_from_slice(value.as_bytes());
            msg.push(b'\n');
        }
    }
    msg
}

fn mac(key: &[u8; 32], msg: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac
}

/// The `MG-Origin-Auth` value for `msg` (see [`message`]).
pub fn sign(key: &[u8; 32], t: u64, msg: &[u8]) -> String {
    let sig = mac(key, msg).finalize().into_bytes();
    format!("v1;t={t};sig={}", URL_SAFE_NO_PAD.encode(sig))
}

/// Why [`verify`] refused a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Not `v1;t=<digits>;sig=<43 characters>`.
    Malformed,
    /// `t` is more than [`MAX_SKEW_S`] away from `now_s`.
    Stale,
    /// No key produces the signature.
    BadSignature,
}

/// The `t` of a well-formed header value.
pub fn timestamp(value: &str) -> Result<u64, VerifyError> {
    parse(value).map(|(t, _)| t)
}

fn parse(value: &str) -> Result<(u64, Vec<u8>), VerifyError> {
    let rest = value.strip_prefix("v1;t=").ok_or(VerifyError::Malformed)?;
    let (t, sig) = rest.split_once(";sig=").ok_or(VerifyError::Malformed)?;
    if t.is_empty() || t.len() > 19 || !t.bytes().all(|b| b.is_ascii_digit()) || sig.len() != 43 {
        return Err(VerifyError::Malformed);
    }
    let t = t.parse().map_err(|_| VerifyError::Malformed)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| VerifyError::Malformed)?;
    Ok((t, sig))
}

/// Reference check of a header `value` against `keys` (the origin's copy of
/// the key file) and the request's own `msg`, built with the `t` of
/// [`timestamp`]. Constant time in the signature.
pub fn verify(keys: &[[u8; 32]], value: &str, msg: &[u8], now_s: u64) -> Result<(), VerifyError> {
    let (t, sig) = parse(value)?;
    if t.abs_diff(now_s) > MAX_SKEW_S {
        return Err(VerifyError::Stale);
    }
    let mut ok = false;
    for key in keys {
        ok |= mac(key, msg).verify_slice(&sig).is_ok();
    }
    if ok {
        Ok(())
    } else {
        Err(VerifyError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn headers<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> {
        move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    #[test]
    fn message_lists_present_headers_in_order() {
        let msg = message(
            1_791_700_000,
            "GET",
            b"/a?b=1",
            headers(&[("mg-request-id", "r1"), ("mg-client-ip", "203.0.113.9")]),
        );
        assert_eq!(
            String::from_utf8(msg).unwrap(),
            "mg-origin-auth-v1\n1791700000\nGET\n/a?b=1\nmg-client-ip:203.0.113.9\nmg-request-id:r1\n"
        );
    }

    #[test]
    fn sign_then_verify() {
        let t = 1_791_700_000;
        let msg = message(t, "POST", b"/x", headers(&[("mg-client-ip", "unknown")]));
        let value = sign(&KEY, t, &msg);
        assert!(value.starts_with("v1;t=1791700000;sig="), "{value}");
        assert_eq!(timestamp(&value), Ok(t));
        let other = [9; 32];
        assert_eq!(verify(&[KEY], &value, &msg, t), Ok(()));
        assert_eq!(verify(&[other, KEY], &value, &msg, t + MAX_SKEW_S), Ok(()));
        assert_eq!(
            verify(&[other], &value, &msg, t),
            Err(VerifyError::BadSignature)
        );
        assert_eq!(
            verify(&[KEY], &value, &msg, t + MAX_SKEW_S + 1),
            Err(VerifyError::Stale)
        );
        assert_eq!(
            verify(&[KEY], &value, &msg, t - MAX_SKEW_S - 1),
            Err(VerifyError::Stale)
        );
        // Any covered header, the method or the target changes the input.
        for changed in [
            message(
                t,
                "POST",
                b"/x",
                headers(&[("mg-client-ip", "203.0.113.1")]),
            ),
            message(t, "POST", b"/x", headers(&[])),
            message(t, "GET", b"/x", headers(&[("mg-client-ip", "unknown")])),
            message(t, "POST", b"/y", headers(&[("mg-client-ip", "unknown")])),
        ] {
            assert_eq!(
                verify(&[KEY], &value, &changed, t),
                Err(VerifyError::BadSignature)
            );
        }
    }

    #[test]
    fn malformed_values() {
        let msg = message(1, "GET", b"/", headers(&[]));
        let good = sign(&KEY, 1, &msg);
        let sig = good.rsplit_once('=').unwrap().1;
        for bad in [
            String::new(),
            "v2;t=1;sig=x".into(),
            format!("v1;t=;sig={sig}"),
            format!("v1;t=+1;sig={sig}"),
            format!("v1;t=99999999999999999999;sig={sig}"),
            format!("v1;t=1;sig={sig}="),
            format!("v1;t=1;sig={}", &sig[1..]),
            format!("v1;t=1;sig={}*", &sig[1..]),
            format!("v1;t=1 ;sig={sig}"),
        ] {
            assert_eq!(
                verify(&[KEY], &bad, &msg, 1),
                Err(VerifyError::Malformed),
                "{bad}"
            );
        }
    }
}
