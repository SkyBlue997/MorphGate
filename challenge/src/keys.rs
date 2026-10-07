//! Site key files, epochs and epoch keys (spec §6.1, §12.7).
//!
//! * `seal.root.json` holds one or two 32-byte roots `K_seal_root` (D-30):
//!   `roots[0]` seals, every root opens (tried in order), so Edges can switch
//!   roots one host at a time without failing each other's challenges.
//! * Each UTC day is an epoch; its key is derived, never distributed:
//!   `k_epoch = HKDF-SHA256(salt = empty, ikm = root,
//!   info = "mg-seal-v1" ‖ 0x00 ‖ site_id ‖ 0x00 ‖ u64be(epoch_no), L = 32)`
//!   (`k_bind_epoch` alike with the label `mg-bind-v1`).
//! * `token.keys.json` holds one to three PASETO v4.local keys; the bundle's
//!   `token_key_ids` pick the ones in use, the first of them signs.
//!
//! Key material lives in zeroize-on-drop buffers and never appears in
//! `Debug` or error messages.

use crate::b64;
use crate::json::ObjectOnly;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use std::fmt;
use std::ops::RangeInclusive;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of one epoch (a UTC day) in milliseconds.
pub const EPOCH_MS: i64 = 86_400_000;
/// Longest lifetime of a Phase 1 challenge (`invisible` / `pow`).
pub const MAX_C_LIFETIME_MS: i64 = 120_000;
/// Tolerated clock difference between Edges.
pub const CLOCK_SKEW_MS: i64 = 5_000;

/// Upper bound on a key file; real files are a few hundred bytes.
const MAX_KEY_FILE_LEN: usize = 64 * 1024;
const SEAL_LABEL: &[u8] = b"mg-seal-v1";
const BIND_LABEL: &[u8] = b"mg-bind-v1";
const SEAL_ROOT_KIND: &str = "mg-site-seal-root";
const TOKEN_KEYS_KIND: &str = "mg-site-token-keys";
const KEY_FILE_VERSION: u32 = 1;

/// The epoch (UTC day number) of a Unix time in milliseconds. Times before
/// 1970 count as epoch 0.
pub fn epoch_no(now_ms: i64) -> u64 {
    (now_ms.max(0) / EPOCH_MS).unsigned_abs()
}

/// The key id of an epoch: `"e"` + decimal epoch number, e.g. `e20724`.
pub fn epoch_kid(epoch: u64) -> String {
    format!("e{epoch}")
}

/// Inverse of [`epoch_kid`]. Only the canonical spelling is accepted (no
/// sign, no leading zeros, at most 20 digits).
pub fn parse_epoch_kid(kid: &str) -> Option<u64> {
    let digits = kid.strip_prefix('e')?;
    if digits.is_empty()
        || digits.len() > 20
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok()
}

/// Epochs whose challenges may be opened at `now_ms` (spec §6.1): the current
/// epoch `e`; also `e − 1` during the first 125 s of the day (a challenge
/// lives at most 120 s, plus 5 s of skew); also `e + 1` during the last 5 s
/// of the day (another Edge's clock may already be in the next day).
pub fn accepted_epochs(now_ms: i64) -> RangeInclusive<u64> {
    let now = now_ms.max(0);
    let e = now / EPOCH_MS;
    let into_day = now - e * EPOCH_MS;
    let lo = if into_day <= MAX_C_LIFETIME_MS + CLOCK_SKEW_MS && e > 0 {
        e - 1
    } else {
        e
    };
    let hi = if EPOCH_MS - into_day <= CLOCK_SKEW_MS {
        e + 1
    } else {
        e
    };
    lo.unsigned_abs()..=hi.unsigned_abs()
}

/// `k_epoch` for `site_id` and `epoch`: the key that seals and opens `C`.
pub fn derive_epoch_key(root: &SealRoot, site_id: &str, epoch: u64) -> [u8; 32] {
    derive(SEAL_LABEL, root, site_id, epoch)
}

/// `k_bind_epoch`: the same derivation with the label `mg-bind-v1` (Phase 2
/// Turnstile `cData`; Phase 1 only provides the function).
pub fn derive_bind_epoch_key(root: &SealRoot, site_id: &str, epoch: u64) -> [u8; 32] {
    derive(BIND_LABEL, root, site_id, epoch)
}

/// HKDF `info`: `label ‖ 0x00 ‖ site_id ‖ 0x00 ‖ u64be(epoch)`.
fn epoch_info(label: &[u8], site_id: &str, epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + site_id.len() + 10);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(site_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

fn derive(label: &[u8], root: &SealRoot, site_id: &str, epoch: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &root.0);
    let mut okm = [0u8; 32];
    // HKDF-SHA256 can expand up to 255 * 32 bytes; 32 never fails.
    hk.expand(&epoch_info(label, site_id, epoch), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// A 32-byte seal root `K_seal_root`, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealRoot([u8; 32]);

impl SealRoot {
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl fmt::Debug for SealRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealRoot(..)")
    }
}

/// The seal roots of one site: one or two, `roots[0]` seals (D-30).
#[derive(Clone)]
pub struct SealKeys {
    roots: Vec<SealRoot>,
}

impl SealKeys {
    /// At most two roots are in use during a rotation (spec §17).
    pub const MAX_ROOTS: usize = 2;

    /// One or two roots; the first seals, all open.
    pub fn new(roots: Vec<SealRoot>) -> Result<Self, KeyError> {
        if roots.is_empty() || roots.len() > Self::MAX_ROOTS {
            return Err(KeyError::Count);
        }
        Ok(Self { roots })
    }

    /// Parses `seal.root.json` (§12.7); checks kind, v, site, 1-2 roots,
    /// unknown fields.
    pub fn from_key_file(json: &[u8], site_id: &str) -> Result<Self, KeyError> {
        let file: SealRootFile = parse_json(json)?;
        check_header(file.v, &file.kind, SEAL_ROOT_KIND, &file.site, site_id)?;
        if file.roots.is_empty() || file.roots.len() > Self::MAX_ROOTS {
            return Err(KeyError::Count);
        }
        let mut roots = Vec::with_capacity(file.roots.len());
        for (i, ObjectOnly(entry)) in file.roots.iter().enumerate() {
            if !is_dated_id(&entry.root_id, site_id, "-r-") {
                return Err(KeyError::Id);
            }
            if file.roots[..i].iter().any(|r| r.0.root_id == entry.root_id) {
                return Err(KeyError::DuplicateId);
            }
            check_created_at(&entry.created_at)?;
            roots.push(SealRoot(decode_key(&entry.key)?));
        }
        Self::new(roots)
    }

    /// Number of roots (1 or 2).
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    pub(crate) fn roots(&self) -> &[SealRoot] {
        &self.roots
    }
}

impl fmt::Debug for SealKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealKeys")
            .field("roots", &self.roots.len())
            .finish()
    }
}

/// One PASETO v4.local key with its id.
#[derive(Clone)]
struct TokenKey {
    kid: String,
    key: Zeroizing<[u8; 32]>,
}

/// The clearance-token keys of one site that the current bundle allows:
/// the first signs, all verify (spec §6.5).
#[derive(Clone)]
pub struct TokenKeySet {
    /// In `allowed_kids` order, without duplicates; `keys[0]` is active.
    keys: Vec<TokenKey>,
}

impl TokenKeySet {
    /// A key file holds one to three keys, newest first (§12.7).
    pub const MAX_KEYS: usize = 3;

    /// Parses token.keys.json; keeps only kids listed in `allowed_kids`;
    /// `allowed_kids[0]` must exist.
    ///
    /// Every other listed kid must exist too ([`KeyError::MissingKid`]): the
    /// bundle check "every `token_key_ids[*]` present in token.keys.json"
    /// (spec §9.10) fails closed here rather than silently dropping a
    /// verification key. Repeated kids in `allowed_kids` are ignored.
    pub fn from_key_file(
        json: &[u8],
        site_id: &str,
        allowed_kids: &[String],
    ) -> Result<Self, KeyError> {
        let file: TokenKeysFile = parse_json(json)?;
        check_header(file.v, &file.kind, TOKEN_KEYS_KIND, &file.site, site_id)?;
        if file.keys.is_empty() || file.keys.len() > Self::MAX_KEYS {
            return Err(KeyError::Count);
        }
        let mut available = Vec::with_capacity(file.keys.len());
        for (i, ObjectOnly(entry)) in file.keys.iter().enumerate() {
            if !is_dated_id(&entry.kid, site_id, "-t-") {
                return Err(KeyError::Id);
            }
            if file.keys[..i].iter().any(|k| k.0.kid == entry.kid) {
                return Err(KeyError::DuplicateId);
            }
            check_created_at(&entry.created_at)?;
            available.push(TokenKey {
                kid: entry.kid.clone(),
                key: Zeroizing::new(decode_key(&entry.key)?),
            });
        }
        if allowed_kids.is_empty() {
            return Err(KeyError::NoActiveKid);
        }
        let mut keys: Vec<TokenKey> = Vec::with_capacity(allowed_kids.len());
        for kid in allowed_kids {
            if keys.iter().any(|k| &k.kid == kid) {
                continue;
            }
            let key = available
                .iter()
                .find(|k| &k.kid == kid)
                .ok_or_else(|| KeyError::MissingKid(kid.clone()))?;
            keys.push(key.clone());
        }
        Ok(Self { keys })
    }

    /// The kid that signs new tokens (`token_key_ids[0]`).
    pub fn active_kid(&self) -> &str {
        &self.keys[0].kid
    }

    /// Every kid that verifies, active first.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| k.kid.as_str())
    }

    /// The active kid and its key.
    pub(crate) fn active(&self) -> (&str, &[u8; 32]) {
        let k = &self.keys[0];
        (&k.kid, &k.key)
    }

    /// The key for `kid`, if it is allowed.
    pub(crate) fn get(&self, kid: &str) -> Option<&[u8; 32]> {
        self.keys.iter().find(|k| k.kid == kid).map(|k| &*k.key)
    }
}

impl fmt::Debug for TokenKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenKeySet")
            .field("kids", &self.kids().collect::<Vec<_>>())
            .finish()
    }
}

/// Why a key file or key set was rejected. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("key file is larger than 64 KiB")]
    TooLarge,
    /// Syntax error, not an object, wrong type, missing, duplicate or
    /// unknown field. Only the position is kept: serde's message could quote
    /// a key.
    #[error("key file does not match its schema (line {line}, column {column})")]
    Json { line: usize, column: usize },
    #[error("unsupported key file version {0}")]
    Version(u32),
    #[error("wrong key file kind")]
    Kind,
    #[error("key file belongs to another site")]
    Site,
    #[error("wrong number of keys in the key file")]
    Count,
    /// `kid` / `root_id` is not `<site>-t-<YYYYMMDD>` / `<site>-r-<YYYYMMDD>`
    /// (optionally with a `-N` same-day suffix).
    #[error("malformed key id")]
    Id,
    #[error("duplicate key id")]
    DuplicateId,
    #[error("key is not 32 bytes of unpadded base64url")]
    Key,
    #[error("created_at is not an RFC 3339 timestamp")]
    CreatedAt,
    #[error("no active token kid")]
    NoActiveKid,
    #[error("token kid {0:?} is not in the key file")]
    MissingKid(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRootFile {
    v: u32,
    kind: String,
    site: String,
    roots: Vec<ObjectOnly<SealRootEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRootEntry {
    root_id: String,
    key: String,
    created_at: String,
}

impl Drop for SealRootEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenKeysFile {
    v: u32,
    kind: String,
    site: String,
    keys: Vec<ObjectOnly<TokenKeyEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenKeyEntry {
    kid: String,
    key: String,
    created_at: String,
}

impl Drop for TokenKeyEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn parse_json<'a, T: Deserialize<'a>>(json: &'a [u8]) -> Result<T, KeyError> {
    if json.len() > MAX_KEY_FILE_LEN {
        return Err(KeyError::TooLarge);
    }
    serde_json::from_slice::<ObjectOnly<T>>(json)
        .map(|file| file.0)
        .map_err(|e| KeyError::Json {
            line: e.line(),
            column: e.column(),
        })
}

fn check_header(
    v: u32,
    kind: &str,
    want_kind: &str,
    site: &str,
    site_id: &str,
) -> Result<(), KeyError> {
    if v != KEY_FILE_VERSION {
        return Err(KeyError::Version(v));
    }
    if kind != want_kind {
        return Err(KeyError::Kind);
    }
    if site != site_id {
        return Err(KeyError::Site);
    }
    Ok(())
}

fn decode_key(s: &str) -> Result<[u8; 32], KeyError> {
    b64::decode_array::<32>(s).ok_or(KeyError::Key)
}

fn check_created_at(s: &str) -> Result<(), KeyError> {
    if is_rfc3339(s) {
        Ok(())
    } else {
        Err(KeyError::CreatedAt)
    }
}

/// `<site><tag><YYYYMMDD>` with an optional same-day suffix `-N` (1 to 3
/// digits, no leading zero), e.g. `blog-t-20260927` or `blog-r-20260927-2`.
fn is_dated_id(id: &str, site: &str, tag: &str) -> bool {
    let Some(rest) = id.strip_prefix(site).and_then(|r| r.strip_prefix(tag)) else {
        return false;
    };
    let Some((date, suffix)) = rest.split_at_checked(8) else {
        return false;
    };
    if !date.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if suffix.is_empty() {
        return true;
    }
    let Some(n) = suffix.strip_prefix('-') else {
        return false;
    };
    (1..=3).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0')
}

/// RFC 3339 `date-time`: `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if !(20..=35).contains(&b.len()) {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let d = b.get(r)?;
        if d.iter().all(u8::is_ascii_digit) {
            Some(d.iter().fold(0, |acc, &c| acc * 10 + u32::from(c - b'0')))
        } else {
            None
        }
    };
    let sep = |i: usize, c: &[u8]| b.get(i).is_some_and(|x| c.contains(x));
    let fields = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    );
    let (Some(_), Some(mo), Some(d), Some(h), Some(mi), Some(sec)) = fields else {
        return false;
    };
    if !(sep(4, b"-") && sep(7, b"-") && sep(10, b"Tt") && sep(13, b":") && sep(16, b":")) {
        return false;
    }
    if !((1..=12).contains(&mo) && (1..=31).contains(&d) && h <= 23 && mi <= 59 && sec <= 60) {
        return false;
    }
    let mut i = 19;
    if sep(i, b".") {
        let frac = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=9).contains(&frac) {
            return false;
        }
        i += 1 + frac;
    }
    match &b[i..] {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', ..] if b.len() - i == 6 => {
            sep(i + 3, b":")
                && num(i + 1..i + 3).is_some_and(|oh| oh <= 23)
                && num(i + 4..i + 6).is_some_and(|om| om <= 59)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_kid_round_trip_and_canonical_form() {
        assert_eq!(epoch_kid(20724), "e20724");
        assert_eq!(parse_epoch_kid("e20724"), Some(20724));
        assert_eq!(parse_epoch_kid("e0"), Some(0));
        assert_eq!(parse_epoch_kid(&epoch_kid(u64::MAX)), Some(u64::MAX));
        for bad in [
            "",
            "e",
            "20724",
            "E20724",
            "e020724",
            "e+1",
            "e-1",
            "e1a",
            " e1",
            "e18446744073709551616",
            "e123456789012345678901",
        ] {
            assert_eq!(parse_epoch_kid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn epoch_of_negative_time_is_zero() {
        assert_eq!(epoch_no(-1), 0);
        assert_eq!(epoch_no(i64::MIN), 0);
        assert_eq!(accepted_epochs(i64::MIN), 0..=0);
        assert_eq!(epoch_no(i64::MAX), (i64::MAX / EPOCH_MS) as u64);
        let hi = accepted_epochs(i64::MAX);
        assert!(hi.contains(&epoch_no(i64::MAX)));
    }

    #[test]
    fn epoch_info_layout() {
        // kat.json epoch_keys.cases[0].info_hex
        assert_eq!(
            epoch_info(SEAL_LABEL, "blog", 20724),
            [
                b"mg-seal-v1".as_slice(),
                &[0],
                b"blog",
                &[0],
                &20724u64.to_be_bytes()
            ]
            .concat()
        );
    }

    #[test]
    fn dated_ids() {
        for ok in [
            "blog-t-20260927",
            "blog-t-20260927-2",
            "blog-t-20260927-999",
        ] {
            assert!(is_dated_id(ok, "blog", "-t-"), "{ok}");
        }
        for bad in [
            "Blog_T",
            "blog-t-2026092",
            "blog-t-202609270",
            "blog-t-2026092a",
            "blog-t-20260927-",
            "blog-t-20260927-02",
            "blog-t-20260927-1000",
            "blog-r-20260927",
            "shop-t-20260927",
            "blogx-t-20260927",
            "blog-t-20260927é",
        ] {
            assert!(!is_dated_id(bad, "blog", "-t-"), "{bad}");
        }
        assert!(is_dated_id("blog-r-20260927", "blog", "-r-"));
    }

    #[test]
    fn rfc3339_timestamps() {
        for ok in [
            "2026-09-27T10:00:00Z",
            "2026-09-27t10:00:00z",
            "2026-09-27T10:00:00.123456789Z",
            "2026-09-27T10:00:00+08:00",
            "2026-12-31T23:59:60-00:30",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-09-27",
            "2026-09-27 10:00:00Z",
            "2026-13-27T10:00:00Z",
            "2026-09-00T10:00:00Z",
            "2026-09-27T24:00:00Z",
            "2026-09-27T10:60:00Z",
            "2026-09-27T10:00:61Z",
            "2026-09-27T10:00:00",
            "2026-09-27T10:00:00.Z",
            "2026-09-27T10:00:00.1234567890Z",
            "2026-09-27T10:00:00+0800",
            "2026-09-27T10:00:00+24:00",
            "2026-09-27T10:00:00Z ",
            "２026-09-27T10:00:00Z",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn seal_keys_count_and_debug() {
        assert_eq!(SealKeys::new(vec![]).unwrap_err(), KeyError::Count);
        let r = SealRoot::from_bytes([7; 32]);
        assert_eq!(
            SealKeys::new(vec![r.clone(), r.clone(), r.clone()]).unwrap_err(),
            KeyError::Count
        );
        let keys = SealKeys::new(vec![r.clone(), r]).unwrap();
        assert_eq!(keys.root_count(), 2);
        let dbg = format!("{keys:?} {:?}", SealRoot::from_bytes([7; 32]));
        assert_eq!(dbg, "SealKeys { roots: 2 } SealRoot(..)");
    }

    #[test]
    fn json_errors_do_not_quote_values() {
        let json = br#"{"v":1,"kind":"mg-site-seal-root","site":"blog","roots":[{"root_id":"blog-r-20260927","key":7,"created_at":"x"}]}"#;
        let err = SealKeys::from_key_file(json, "blog").unwrap_err();
        assert!(matches!(err, KeyError::Json { line: 1, .. }), "{err:?}");
        assert!(
            !err.to_string().contains("invalid type"),
            "serde's message is not kept: {err}"
        );
        let too_big = vec![b' '; MAX_KEY_FILE_LEN + 1];
        assert_eq!(
            SealKeys::from_key_file(&too_big, "blog").unwrap_err(),
            KeyError::TooLarge
        );
    }
}
