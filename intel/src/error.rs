//! The crate's single error type.

/// Why an intelligence artifact, list or database was rejected.
///
/// Messages name the offending entry (a CIDR, ASN or JSON path from the
/// artifact itself) but never a client address: artifacts are owner-published
/// data, and nothing in this crate formats request data into an error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntelError {
    /// A line of a text list, or an entry of an address list, is invalid.
    /// `line` is 1-based (the entry index for [`crate::IpSet::parse`]).
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
    /// More entries than the format allows.
    #[error("too many entries (limit {limit})")]
    TooManyEntries { limit: usize },
    /// The input is larger than the artifact kind allows (spec §12.1).
    #[error("{what} is {size} bytes, limit {limit}")]
    TooLarge {
        what: &'static str,
        size: u64,
        limit: u64,
    },
    /// Not valid JSON for the format: syntax, types, missing or unknown fields.
    #[error("malformed JSON: {0}")]
    Json(String),
    /// Well-formed JSON that violates a validation rule of the format.
    #[error("invalid artifact: {0}")]
    Invalid(String),
    /// A MaxMind DB could not be opened or has the wrong `database_type`.
    #[error("GeoLite2 {which} database: {reason}")]
    Mmdb { which: &'static str, reason: String },
    /// The expected digest is not 64 lower-case hex characters.
    #[error("malformed sha256 (expected 64 lower-case hex characters)")]
    MalformedHash,
    /// The bytes do not hash to the expected digest.
    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
}

impl IntelError {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    /// serde_json quotes an offending string value or unknown key in full,
    /// so its message is bounded like every other artifact detail.
    pub(crate) fn json(err: &serde_json::Error) -> Self {
        Self::Json(bounded(err.to_string()))
    }
}

/// Quotes an artifact entry for an error message, truncated so a hostile or
/// corrupt artifact cannot produce unbounded log lines.
pub(crate) fn quote(entry: &str) -> String {
    const MAX: usize = 80;
    if entry.len() <= MAX {
        return format!("{entry:?}");
    }
    format!("{:?}...", &entry[..floor_char_boundary(entry, MAX)])
}

/// Truncates a third-party error message (serde_json, maxminddb) that may
/// quote artifact content, for the same reason as [`quote`].
pub(crate) fn bounded(mut msg: String) -> String {
    const MAX: usize = 256;
    if msg.len() > MAX {
        msg.truncate(floor_char_boundary(&msg, MAX));
        msg.push_str("...");
    }
    msg
}

/// The largest char boundary `<= max` (`str::floor_char_boundary` is not
/// stable at the MSRV).
fn floor_char_boundary(s: &str, max: usize) -> usize {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Rejects inputs above `limit` bytes before parsing them.
pub(crate) fn check_size(what: &'static str, len: usize, limit: u64) -> Result<(), IntelError> {
    let size = len as u64;
    if size > limit {
        return Err(IntelError::TooLarge { what, size, limit });
    }
    Ok(())
}
