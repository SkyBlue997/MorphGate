//! Small textual validators shared by the artifact parsers.

/// True for exactly 64 lower-case hex characters (a SHA-256 digest, §12.3).
pub(crate) fn is_lower_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lower-case hex encoding.
pub(crate) fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Validates an RFC 3339 `date-time` (e.g. `2026-09-27T10:00:00Z`,
/// `2026-09-27T10:00:00.5+02:00`), including calendar ranges and leap years.
/// A leap second (`:60`) is accepted as RFC 3339 allows.
pub(crate) fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let num = |from: usize, len: usize| -> Option<u32> {
        let digits = b.get(from..from + len)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            digits
                .iter()
                .fold(0, |acc, d| acc * 10 + u32::from(d - b'0')),
        )
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        num(0, 4),
        num(5, 2),
        num(8, 2),
        num(11, 2),
        num(14, 2),
        num(17, 2),
    ) else {
        return false;
    };
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
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
            i + 6 == b.len()
                && b[i + 3] == b':'
                && num(i + 1, 2).is_some_and(|h| h <= 23)
                && num(i + 4, 2).is_some_and(|m| m <= 59)
        }
        _ => false,
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        _ => 28,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        for ok in [
            "2026-09-27T10:00:00Z",
            "2026-09-27t10:00:00z",
            "2026-09-27T10:00:00.123456789Z",
            "2026-09-27T10:00:00+02:00",
            "2026-09-27T10:00:00.5-11:30",
            "2024-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "2026-12-31T23:59:60Z",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-09-27",
            "2026-09-27 10:00:00Z",
            "2026-09-27T10:00:00",
            "2026-09-27T10:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-09-27T24:00:00Z",
            "2026-09-27T10:60:00Z",
            "2026-09-27T10:00:61Z",
            "2026-09-27T10:00:00.Z",
            "2026-09-27T10:00:00+0200",
            "2026-09-27T10:00:00+24:00",
            "2026-09-27T10:00:00Z ",
            "2026-09-25T14:49:23.000000",
            "+026-09-27T10:00:00Z",
            "２026-09-27T10:00:00Z",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn hex() {
        assert_eq!(to_lower_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert!(is_lower_hex_sha256(&"a".repeat(64)));
        assert!(!is_lower_hex_sha256(&"A".repeat(64)));
        assert!(!is_lower_hex_sha256(&"a".repeat(63)));
        assert!(!is_lower_hex_sha256(&"g".repeat(64)));
    }
}
