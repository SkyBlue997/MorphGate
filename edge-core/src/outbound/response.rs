//! Parsing of a siteverify response body (spec §8.4): untrusted input, so the
//! parser is strict about the fields it reads and ignores every other field.

use serde::Deserialize;

/// Most `error-codes` entries accepted (spec §8.4).
pub const MAX_ERROR_CODES: usize = 8;
/// Longest accepted `error-codes` entry, in bytes.
pub const MAX_ERROR_CODE_BYTES: usize = 64;
/// Largest accepted response body (spec §8.4).
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The fields of a siteverify response that the Edge reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteverifyResponse {
    pub success: bool,
    /// `challenge_ts` as Unix nanoseconds (RFC 3339, any offset). Always
    /// present when `success`.
    pub challenge_ts_ns: Option<i128>,
    /// Always present when `success`.
    pub hostname: Option<String>,
    /// `error-codes` (at most [`MAX_ERROR_CODES`]); empty when absent.
    pub error_codes: Vec<String>,
    /// Always present when `success`.
    pub action: Option<String>,
    /// Always present when `success`.
    pub cdata: Option<String>,
}

impl SiteverifyResponse {
    /// `challenge_ts` in Unix milliseconds, rounded down.
    pub fn challenge_ts_ms(&self) -> Option<i64> {
        self.challenge_ts_ns
            .and_then(|ns| i64::try_from(ns.div_euclid(1_000_000)).ok())
    }

    /// Whether `error-codes` contains `code`.
    pub fn has_code(&self, code: &str) -> bool {
        self.error_codes.iter().any(|c| c == code)
    }
}

/// Why a response body does not fit spec §8.4 (it is then `Unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    #[error("siteverify response larger than 16 KiB")]
    TooLarge,
    #[error("siteverify response is not a JSON object")]
    NotObject,
    #[error("siteverify response has missing or ill-typed fields")]
    Shape,
    #[error("siteverify response has more than 8 error codes or an over-long one")]
    ErrorCodes,
    #[error("siteverify challenge_ts is not RFC 3339")]
    Timestamp,
    #[error("successful siteverify response without challenge_ts, hostname, action or cdata")]
    MissingSuccessFields,
}

#[derive(Deserialize)]
struct Raw {
    success: bool,
    #[serde(default)]
    challenge_ts: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default, rename = "error-codes")]
    error_codes: Option<Vec<String>>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    cdata: Option<String>,
}

/// Parses a siteverify response body.
///
/// The body must be at most [`MAX_BODY_BYTES`] and a JSON object with a
/// boolean `success`; `challenge_ts` (RFC 3339), `hostname`, `action` and
/// `cdata` are strings and `error-codes` an array of at most
/// [`MAX_ERROR_CODES`] strings when present (`null` counts as absent); a
/// known field given twice is an error; other fields are ignored. When
/// `success` is true, `challenge_ts`, `hostname`, `action` and `cdata` must
/// all be present.
pub fn parse_siteverify_response(body: &[u8]) -> Result<SiteverifyResponse, ResponseError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ResponseError::TooLarge);
    }
    // serde would also read a struct from a JSON array; only objects count.
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(ResponseError::NotObject);
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|_| ResponseError::Shape)?;
    let error_codes = raw.error_codes.unwrap_or_default();
    if error_codes.len() > MAX_ERROR_CODES
        || error_codes.iter().any(|c| c.len() > MAX_ERROR_CODE_BYTES)
    {
        return Err(ResponseError::ErrorCodes);
    }
    let challenge_ts_ns = match raw.challenge_ts.as_deref() {
        Some(ts) => Some(parse_rfc3339_ns(ts).ok_or(ResponseError::Timestamp)?),
        None => None,
    };
    let resp = SiteverifyResponse {
        success: raw.success,
        challenge_ts_ns,
        hostname: raw.hostname,
        error_codes,
        action: raw.action,
        cdata: raw.cdata,
    };
    if resp.success
        && (resp.challenge_ts_ns.is_none()
            || resp.hostname.is_none()
            || resp.action.is_none()
            || resp.cdata.is_none())
    {
        return Err(ResponseError::MissingSuccessFields);
    }
    Ok(resp)
}

/// Parses an RFC 3339 `date-time` (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`,
/// `T` / `Z` in either case, 1–9 fraction digits, no leap second) into Unix
/// nanoseconds.
pub fn parse_rfc3339_ns(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = b.get(range)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            digits
                .iter()
                .fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0')),
        )
    };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut i = 19;
    let mut nanos: i64 = 0;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = i - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        nanos = num(start..i)? * 10i64.pow(9 - digits as u32);
    }
    let offset_s = match b.get(i..)? {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let off = oh * 3600 + om * 60;
            if *sign == b'+' { off } else { -off }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_s;
    Some(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i128 = 1_000_000;

    #[test]
    fn rfc3339_values() {
        let cases: &[(&str, i128)] = &[
            ("1970-01-01T00:00:00Z", 0),
            ("1970-01-01t00:00:00z", 0),
            ("2026-09-21T14:13:20.000Z", 1_790_000_000_000 * MS),
            ("2026-09-21T14:13:20Z", 1_790_000_000_000 * MS),
            ("2026-09-21T22:13:20+08:00", 1_790_000_000_000 * MS),
            ("2026-09-21T13:43:20-00:30", 1_790_000_000_000 * MS),
            ("2026-09-21T14:13:14.999Z", 1_789_999_994_999 * MS),
            ("2026-09-21T14:13:20.000000001Z", 1_790_000_000_000 * MS + 1),
            ("2026-09-21T14:13:20.5Z", 1_790_000_000_500 * MS),
            ("1969-12-31T23:59:59.9Z", -100 * MS),
            ("2024-02-29T00:00:00Z", 1_709_164_800_000 * MS),
            ("2000-03-01T00:00:00Z", 951_868_800_000 * MS),
        ];
        for (s, want) in cases {
            assert_eq!(parse_rfc3339_ns(s), Some(*want), "{s}");
        }
    }

    #[test]
    fn rfc3339_rejects() {
        for s in [
            "",
            "1790000030",
            "2026-09-21",
            "2026-09-21 14:13:20Z",
            "2026-09-21T14:13:20",
            "2026-09-21T14:13:20.Z",
            "2026-09-21T14:13:20.0000000001Z",
            "2026-09-21T14:13:20+0800",
            "2026-09-21T14:13:20+24:00",
            "2026-09-21T14:13:20+08:60",
            "2026-13-21T14:13:20Z",
            "2026-00-21T14:13:20Z",
            "2026-02-29T14:13:20Z",
            "1900-02-29T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-09-21T24:00:00Z",
            "2026-09-21T23:60:00Z",
            "2026-09-21T23:59:60Z",
            "+026-09-21T14:13:20Z",
            "2026-09-21T14:13:20ZZ",
            "２026-09-21T14:13:20Z",
        ] {
            assert_eq!(parse_rfc3339_ns(s), None, "{s}");
        }
    }

    #[test]
    fn parse_shapes() {
        let ok = br#" {"success":false,"error-codes":["internal-error"],"x":{"y":[1]}} "#;
        let r = parse_siteverify_response(ok).unwrap();
        assert!(!r.success && r.has_code("internal-error"));
        let ok = br#"{"success":false,"error-codes":null,"hostname":null}"#;
        assert!(
            parse_siteverify_response(ok)
                .unwrap()
                .error_codes
                .is_empty()
        );

        let bad: &[(&[u8], ResponseError)] = &[
            (b"", ResponseError::NotObject),
            (b"[{\"success\":true}]", ResponseError::NotObject),
            (b"{\"success\":true", ResponseError::Shape),
            (b"{}", ResponseError::Shape),
            (b"{\"success\":1}", ResponseError::Shape),
            (b"{\"success\":true,\"success\":true}", ResponseError::Shape),
            (b"{\"success\":false,\"hostname\":7}", ResponseError::Shape),
            (
                b"{\"success\":false,\"error-codes\":\"x\"}",
                ResponseError::Shape,
            ),
            (
                b"{\"success\":false,\"error-codes\":[1]}",
                ResponseError::Shape,
            ),
            (
                b"{\"success\":false,\"challenge_ts\":\"x\"}",
                ResponseError::Timestamp,
            ),
            (
                b"{\"success\":true,\"hostname\":\"a\",\"action\":\"b\",\"cdata\":\"c\"}",
                ResponseError::MissingSuccessFields,
            ),
        ];
        for (body, want) in bad {
            assert_eq!(
                parse_siteverify_response(body),
                Err(*want),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let long = format!(
            r#"{{"success":false,"error-codes":["{}"]}}"#,
            "x".repeat(65)
        );
        assert_eq!(
            parse_siteverify_response(long.as_bytes()),
            Err(ResponseError::ErrorCodes)
        );
        let big = format!(
            r#"{{"success":false,"p":"{}"}}"#,
            "x".repeat(MAX_BODY_BYTES)
        );
        assert_eq!(
            parse_siteverify_response(big.as_bytes()),
            Err(ResponseError::TooLarge)
        );
    }

    #[test]
    fn challenge_ts_ms_rounds_down() {
        let r = SiteverifyResponse {
            success: false,
            challenge_ts_ns: Some(-1),
            hostname: None,
            error_codes: vec![],
            action: None,
            cdata: None,
        };
        assert_eq!(r.challenge_ts_ms(), Some(-1));
    }
}
