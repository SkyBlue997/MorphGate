//! Small validation and encoding helpers shared by the bundle submodules.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Lower-case hex encoding.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// 64 lower-case hex digits (an artifact name / `ArtifactRef.sha256`).
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `first` then up to `max_len - 1` bytes of `rest`, ASCII only.
fn charset(s: &str, max_len: usize, first: fn(u8) -> bool, rest: fn(u8) -> bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= max_len && first(b[0]) && b[1..].iter().all(|&c| rest(c))
}

fn lower_alnum(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

/// Key ids (`kid`, `token_key_ids`): `[a-z0-9][a-z0-9._-]{0,63}` (§12.6, §8.2).
pub(crate) fn is_kid(s: &str) -> bool {
    charset(s, 64, lower_alnum, |c| {
        lower_alnum(c) || matches!(c, b'.' | b'_' | b'-')
    })
}

/// Site ids: `[a-z0-9][a-z0-9_-]{0,63}` (§8.1, §8.2).
pub(crate) fn is_site_id(s: &str) -> bool {
    charset(s, 64, lower_alnum, |c| {
        lower_alnum(c) || matches!(c, b'_' | b'-')
    })
}

/// Limiter ids and list names: `[a-z0-9][a-z0-9_.-]{0,63}` (§8.2, config.proto).
pub(crate) fn is_limiter_id(s: &str) -> bool {
    is_kid(s)
}

/// Listener names: `[a-z0-9][a-z0-9-]{0,31}` (§8.1).
pub(crate) fn is_listener_name(s: &str) -> bool {
    charset(s, 32, lower_alnum, |c| lower_alnum(c) || c == b'-')
}

/// Route names: `[a-z0-9_-]{1,32}` (§8.2).
pub(crate) fn is_route_name(s: &str) -> bool {
    let rest = |c: u8| lower_alnum(c) || matches!(c, b'_' | b'-');
    charset(s, 32, rest, rest)
}

/// Upper-case HTTP method token, 1-32 bytes (§8.2, §9.3.1): `A-Z`, `-`, `_`.
pub(crate) fn is_method(s: &str) -> bool {
    charset(
        s,
        32,
        |c| c.is_ascii_uppercase(),
        |c| c.is_ascii_uppercase() || matches!(c, b'-' | b'_'),
    )
}

/// Lower-case DNS name without trailing dot, <= 253 bytes, labels of 1-63
/// `[a-z0-9-]` bytes that neither start nor end with `-`.
pub(crate) fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
                && b.iter().all(|&c| lower_alnum(c) || c == b'-')
        })
}

/// RFC 3339 date-time (`2026-09-27T10:00:00Z`, optional fraction, `Z` or
/// `±hh:mm`), with calendar-valid fields.
pub(crate) fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0u32, |acc, &d| Some(acc * 10 + u32::from(d - b'0')))
    };
    let sep = |i: usize, c: &[u8]| b.get(i).is_some_and(|x| c.contains(x));
    let (Some(year), Some(month), Some(day), Some(hour), Some(min), Some(sec)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };
    if !(sep(4, b"-") && sep(7, b"-") && sep(10, b"Tt") && sep(13, b":") && sep(16, b":")) {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days_in_month || hour > 23 || min > 59 || sec > 60 {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z' | b'z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6
                && sep(i + 3, b":")
                && digits(i + 1..i + 3).is_some_and(|h| h <= 23)
                && digits(i + 4..i + 6).is_some_and(|m| m <= 59)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_sha256() {
        assert_eq!(hex_lower(&[0x00, 0x7f, 0xff]), "007fff");
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_hex(&hex_lower(&sha256(b""))));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex("../../../../etc/passwd"));
    }

    #[test]
    fn identifiers() {
        for ok in [
            "owner-test",
            "owner-2026",
            "a",
            "blog-t-20260927.2",
            &"a".repeat(64),
        ] {
            assert!(is_kid(ok), "{ok}");
        }
        for bad in ["", "-a", ".a", "Owner", "a b", "a/b", &"a".repeat(65)] {
            assert!(!is_kid(bad), "{bad}");
        }
        assert!(is_site_id("blog_2-x"));
        assert!(!is_site_id("blog.x"));
        assert!(is_listener_name("cf-tunnel"));
        assert!(!is_listener_name("cf_tunnel"));
        assert!(!is_listener_name(&"a".repeat(33)));
        assert!(is_route_name("_login-2"));
        assert!(!is_route_name(""));
        assert!(!is_route_name(&"a".repeat(33)));
        assert!(is_method("GET") && is_method("M-SEARCH"));
        assert!(!is_method("get") && !is_method("-GET") && !is_method(""));
        assert!(is_dns_name("example.com") && is_dns_name("a-b.c0"));
        for bad in [
            "",
            "Example.com",
            "a..b",
            "a.",
            "-a.b",
            "a-.b",
            "a_b.c",
            "a:80",
        ] {
            assert!(!is_dns_name(bad), "{bad}");
        }
    }

    #[test]
    fn rfc3339() {
        for ok in [
            "2026-09-27T10:00:00Z",
            "2026-09-27t10:00:00z",
            "2026-09-27T10:00:00.123456789Z",
            "2024-02-29T23:59:60+08:00",
            "2026-12-31T00:00:00-00:30",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-09-27",
            "2026-09-27 10:00:00Z",
            "2026-09-27T10:00:00",
            "2026-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-09-27T24:00:00Z",
            "2026-09-27T10:00:00.Z",
            "2026-09-27T10:00:00+0800",
            "2026-09-27T10:00:00Z ",
            "２026-09-27T10:00:00Z",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }
}
