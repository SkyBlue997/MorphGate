//! Credentials and host-local key files (docs/impl/phase1-spec.md §8.1
//! "凭证引用" / "密钥文件", §12.7).
//!
//! * [`CredResolver`] turns a [`CredRef`] into a path: `cred://<name>` is
//!   `$CREDENTIALS_DIRECTORY/<name>` (systemd `LoadCredential=` /
//!   `LoadCredentialEncrypted=`), an absolute path is used as is.
//! * [`read_secret`] reads a key file of at most 64 KiB (I-14) into memory
//!   that is zeroized on drop, and warns when a plain file (not a systemd
//!   credential) is readable by group or others.
//! * [`PseudoKey`] (`pseudo.key.json`) and [`UpstreamKeys`]
//!   (`upstream-keys.json`) are the two §12.7 formats no other crate parses;
//!   `token.keys.json` and `seal.root.json` go to `mg-challenge`, owner public
//!   keys to `mg_edge_core::bundle::OwnerKeys`.
//!
//! Nothing here logs or formats key material: `Debug` output and error
//! messages carry file names, kinds and positions only.

use crate::config::CredRef;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Largest accepted key or credential file (I-14).
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Environment variable systemd sets for units with credentials.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

/// Why a credential or key file was refused. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredError {
    #[error("{reference}: CREDENTIALS_DIRECTORY is not set (cred:// needs a systemd credential)")]
    NoCredentialsDirectory { reference: String },
    #[error("{path}: {reason}")]
    Read { path: String, reason: String },
    #[error("{path}: larger than {MAX_KEY_FILE_BYTES} bytes")]
    TooLarge { path: String },
    #[error("{path}: {reason}")]
    Format { path: String, reason: String },
}

/// Resolves [`CredRef`]s against `$CREDENTIALS_DIRECTORY`.
#[derive(Debug, Clone, Default)]
pub struct CredResolver {
    dir: Option<PathBuf>,
}

impl CredResolver {
    /// Reads `$CREDENTIALS_DIRECTORY` from the environment (unset or empty:
    /// `cred://` references fail).
    pub fn from_env() -> Self {
        let dir = std::env::var_os(CREDENTIALS_DIRECTORY)
            .filter(|d| !d.is_empty())
            .map(PathBuf::from);
        Self { dir }
    }

    /// A resolver with an explicit credentials directory (tests).
    pub fn with_dir(dir: Option<PathBuf>) -> Self {
        Self { dir }
    }

    /// The file a reference names.
    pub fn resolve(&self, r: &CredRef) -> Result<PathBuf, CredError> {
        match r {
            CredRef::Path(p) => Ok(p.clone()),
            CredRef::Credential(name) => match &self.dir {
                Some(dir) => Ok(dir.join(name)),
                None => Err(CredError::NoCredentialsDirectory {
                    reference: r.to_string(),
                }),
            },
        }
    }
}

/// The bytes of a key file; zeroized on drop, never printed.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// Reads a key file referenced by `r` (at most [`MAX_KEY_FILE_BYTES`]).
///
/// For a plain path (not `cred://`), a file that group or others may read is
/// reported through `warn` (the Edge still starts: the owner decides).
pub fn read_secret(
    resolver: &CredResolver,
    r: &CredRef,
    warn: &mut dyn FnMut(String),
) -> Result<Secret, CredError> {
    let path = resolver.resolve(r)?;
    if let CredRef::Path(_) = r
        && let Some(mode) = group_or_other_readable(&path)
    {
        warn(format!(
            "{}: key file is readable by group or others (mode {mode:o}); use a systemd \
             credential or chmod 0600",
            path.display()
        ));
    }
    read_capped(&path).map(Secret)
}

/// Reads a non-secret file with the same size cap (owner `.pub` files).
pub fn read_public(path: &Path) -> Result<Vec<u8>, CredError> {
    read_capped(path).map(|z| z.to_vec())
}

fn read_capped(path: &Path) -> Result<Zeroizing<Vec<u8>>, CredError> {
    let err = |e: std::io::Error| CredError::Read {
        path: path.display().to_string(),
        reason: e.to_string(),
    };
    let file = std::fs::File::open(path).map_err(err)?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(err)?;
    if buf.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(CredError::TooLarge {
            path: path.display().to_string(),
        });
    }
    Ok(buf)
}

#[cfg(unix)]
fn group_or_other_readable(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(not(unix))]
fn group_or_other_readable(_path: &Path) -> Option<u32> {
    None
}

/// `pseudo.key.json` (§12.7): the owner-level pseudonymization key
/// `K_pseudo` (D-06).
pub struct PseudoKey {
    pub id: String,
    key: Zeroizing<[u8; 32]>,
}

impl PseudoKey {
    const KIND: &'static str = "mg-pseudo-key";

    /// Parses the §12.7 JSON: `v == 1`, `kind`, `id` (`[a-z0-9][a-z0-9._-]{0,63}`),
    /// `key` = unpadded base64url of 32 bytes, RFC 3339 `created_at`; every
    /// field required, unknown and duplicate fields rejected.
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            v: u32,
            kind: String,
            id: String,
            key: String,
            created_at: String,
        }
        let mut f: File = parse_object(json)?;
        let key = decode_key32(&f.key);
        f.key.zeroize();
        check_header(f.v, &f.kind, Self::KIND)?;
        if !is_key_id(&f.id) {
            return Err("id must be 1-64 of [a-z0-9._-] starting with [a-z0-9]".into());
        }
        check_rfc3339(&f.created_at)?;
        Ok(Self {
            id: f.id,
            key: Zeroizing::new(key?),
        })
    }

    /// `K_pseudo`.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for PseudoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PseudoKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// `upstream-keys.json` (§12.7): the accepted `x-mg-upstream-key` values,
/// newest first (1–2 during a rotation).
#[derive(Clone)]
pub struct UpstreamKeys {
    values: Vec<Vec<u8>>,
}

impl UpstreamKeys {
    const KIND: &'static str = "mg-upstream-keys";

    /// Parses the §12.7 JSON: `v == 1`, `kind`, `values` = 1–2 distinct
    /// 43-character unpadded base64url strings of 32 random bytes, RFC 3339
    /// `created_at`.
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            v: u32,
            kind: String,
            values: Vec<String>,
            created_at: String,
        }
        let mut f: File = parse_object(json)?;
        let result = (|| {
            check_header(f.v, &f.kind, Self::KIND)?;
            if !(1..=2).contains(&f.values.len()) {
                return Err(format!(
                    "values has {} entries, expected 1-2",
                    f.values.len()
                ));
            }
            for (i, v) in f.values.iter().enumerate() {
                if v.len() != 43 || decode_key32(v).is_err() {
                    return Err(format!(
                        "values[{i}] is not 43 characters of unpadded base64url (32 bytes)"
                    ));
                }
                if f.values[..i].contains(v) {
                    return Err(format!("values[{i}] repeats an earlier value"));
                }
            }
            check_rfc3339(&f.created_at)?;
            Ok(())
        })();
        let values = f.values.iter().map(|v| v.as_bytes().to_vec()).collect();
        for v in &mut f.values {
            v.zeroize();
        }
        result.map(|()| Self { values })
    }

    /// The accepted header values (the base64url text, compared in constant
    /// time by `mg_edge_core::upstream::secret_header_ok`).
    pub fn values(&self) -> &[Vec<u8>] {
        &self.values
    }
}

impl Drop for UpstreamKeys {
    fn drop(&mut self) {
        for v in &mut self.values {
            v.zeroize();
        }
    }
}

impl fmt::Debug for UpstreamKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamKeys")
            .field("values", &self.values.len())
            .finish()
    }
}

/// Deserializes a JSON **object** (serde would also accept an array for a
/// struct). Errors keep only the position: serde's message could quote a key.
fn parse_object<T: serde::de::DeserializeOwned>(json: &[u8]) -> Result<T, String> {
    let first = json.iter().find(|b| !b.is_ascii_whitespace());
    if first != Some(&b'{') {
        return Err("not a JSON object".into());
    }
    serde_json::from_slice(json).map_err(|e| {
        format!(
            "does not match its schema (line {}, column {}; missing, unknown, duplicate or \
             mistyped field)",
            e.line(),
            e.column()
        )
    })
}

fn check_header(v: u32, kind: &str, want: &str) -> Result<(), String> {
    if v != 1 {
        return Err(format!("unsupported v {v}"));
    }
    if kind != want {
        return Err(format!("kind must be {want:?}"));
    }
    Ok(())
}

fn decode_key32(s: &str) -> Result<[u8; 32], String> {
    let mut raw = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| "key is not unpadded base64url".to_string())?,
    );
    let out: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "key is not 32 bytes".to_string())?;
    raw.zeroize();
    Ok(out)
}

fn is_key_id(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// RFC 3339 `date-time` (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`, `T`/`Z` in
/// either case), with calendar-valid dates.
pub fn check_rfc3339(s: &str) -> Result<(), String> {
    if is_rfc3339(s) {
        Ok(())
    } else {
        Err("created_at is not an RFC 3339 timestamp".into())
    }
}

fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(r)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
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
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || min > 59 || sec > 60 {
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
    match &b[i..] {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', ..] if b.len() - i == 6 => {
            let (Some(oh), Some(om)) = (digits(i + 1..i + 3), digits(i + 4..i + 6)) else {
                return false;
            };
            b[i + 3] == b':' && oh <= 23 && om <= 59
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rel: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/phase1/keys")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn accepts_the_shared_pseudo_key_sample() {
        let k = PseudoKey::parse(&sample("pseudo.key.json")).unwrap();
        assert_eq!(k.id, "pseudo-20260927");
        // kat.json entity_key.k_pseudo_hex: bytes 0x00..0x1f.
        let want: Vec<u8> = (0u8..32).collect();
        assert_eq!(k.key().as_slice(), want.as_slice());
        assert_eq!(
            format!("{k:?}"),
            "PseudoKey { id: \"pseudo-20260927\", .. }"
        );
    }

    #[test]
    fn rejects_the_invalid_pseudo_key_sample_and_variants() {
        let e =
            PseudoKey::parse(&sample("invalid/pseudo.key.missing-created-at.json")).unwrap_err();
        assert!(e.contains("schema"), "{e}");
        let good = String::from_utf8(sample("pseudo.key.json")).unwrap();
        for (from, to, needle) in [
            ("\"v\": 1", "\"v\": 2", "unsupported v"),
            ("mg-pseudo-key", "mg-upstream-keys", "kind"),
            ("pseudo-20260927", "Pseudo", "id must be"),
            (
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "AAECAw==",
                "base64url",
            ),
            (
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "AAECAw",
                "32 bytes",
            ),
            ("2026-09-27T10:00:00Z", "2026-02-30T10:00:00Z", "RFC 3339"),
            ("\"id\"", "\"extra\": 1, \"id\"", "schema"),
            ("\"id\"", "\"id\": \"x\", \"id\"", "schema"),
        ] {
            let e = PseudoKey::parse(good.replace(from, to).as_bytes()).unwrap_err();
            assert!(e.contains(needle), "{to}: {e}");
            assert!(!e.contains("AAEC"), "error leaks key material: {e}");
        }
        assert!(
            PseudoKey::parse(b"[1, \"mg-pseudo-key\"]")
                .unwrap_err()
                .contains("object")
        );
    }

    #[test]
    fn accepts_the_shared_upstream_key_samples() {
        let k = UpstreamKeys::parse(&sample("upstream-keys.json")).unwrap();
        assert_eq!(k.values().len(), 1);
        assert_eq!(
            k.values()[0],
            b"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"
        );
        let r = UpstreamKeys::parse(&sample("upstream-keys.rotated.json")).unwrap();
        assert_eq!(r.values().len(), 2);
        assert_eq!(r.values()[1], k.values()[0]);
        assert_eq!(format!("{r:?}"), "UpstreamKeys { values: 2 }");
    }

    #[test]
    fn rejects_the_invalid_upstream_key_sample_and_variants() {
        let e =
            UpstreamKeys::parse(&sample("invalid/upstream-keys.three-values.json")).unwrap_err();
        assert!(e.contains("1-2"), "{e}");
        let good = String::from_utf8(sample("upstream-keys.rotated.json")).unwrap();
        for (from, to, needle) in [
            (
                "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8",
                "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
                "repeats",
            ),
            (
                "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8",
                "short",
                "43 characters",
            ),
            ("\"values\"", "\"value\"", "schema"),
            ("2026-09-28T10:00:00Z", "yesterday", "RFC 3339"),
        ] {
            let e = UpstreamKeys::parse(good.replace(from, to).as_bytes()).unwrap_err();
            assert!(e.contains(needle), "{to}: {e}");
            assert!(
                !e.contains("YGFi") && !e.contains("gIGC"),
                "error leaks a key: {e}"
            );
        }
        let empty = good.replace(
            "\"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8\",\n    \"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8\"",
            "",
        );
        assert!(
            UpstreamKeys::parse(empty.as_bytes())
                .unwrap_err()
                .contains("1-2")
        );
    }

    #[test]
    fn rfc3339() {
        for ok in [
            "2026-09-27T10:00:00Z",
            "2026-09-27t10:00:00z",
            "2026-09-27T10:00:00.123456789Z",
            "2026-09-27T10:00:00+08:00",
            "2024-02-29T00:00:00Z",
            "2026-12-31T23:59:60Z",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-09-27",
            "2026-09-27 10:00:00Z",
            "2026-09-27T10:00:00",
            "2026-09-27T10:00:00.Z",
            "2026-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-09-27T24:00:00Z",
            "2026-09-27T10:00:00+8:00",
            "2026-09-27T10:00:00+08:60",
            "2026-09-27T10:00:00Zjunk",
            "２026-09-27T10:00:00Z",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn credential_resolution() {
        let r = CredResolver::with_dir(Some("/run/credentials/mg-edge.service".into()));
        assert_eq!(
            r.resolve(&CredRef::parse("cred://mg-pseudo-key").unwrap())
                .unwrap(),
            Path::new("/run/credentials/mg-edge.service/mg-pseudo-key")
        );
        assert_eq!(
            r.resolve(&CredRef::parse("/etc/k.json").unwrap()).unwrap(),
            Path::new("/etc/k.json")
        );
        let none = CredResolver::with_dir(None);
        let e = none
            .resolve(&CredRef::parse("cred://mg-pseudo-key").unwrap())
            .unwrap_err();
        assert!(e.to_string().contains("CREDENTIALS_DIRECTORY"), "{e}");
    }

    #[test]
    fn read_secret_caps_size_and_warns_on_loose_permissions() {
        let dir = std::env::temp_dir().join(format!("mg-edge-creds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; (MAX_KEY_FILE_BYTES + 1) as usize]).unwrap();
        let small = dir.join("small.json");
        std::fs::write(&small, b"{}").unwrap();
        let resolver = CredResolver::with_dir(Some(dir.clone()));
        let mut warnings = Vec::new();

        let e = read_secret(&resolver, &CredRef::Path(big.clone()), &mut |w| {
            warnings.push(w)
        })
        .unwrap_err();
        assert!(matches!(e, CredError::TooLarge { .. }), "{e}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&small, std::fs::Permissions::from_mode(0o644)).unwrap();
            warnings.clear();
            let s = read_secret(&resolver, &CredRef::Path(small.clone()), &mut |w| {
                warnings.push(w)
            })
            .unwrap();
            assert_eq!(s.bytes(), b"{}");
            assert_eq!(format!("{s:?}"), "Secret(2 bytes)");
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert!(warnings[0].contains("readable by group or others"));

            std::fs::set_permissions(&small, std::fs::Permissions::from_mode(0o600)).unwrap();
            warnings.clear();
            read_secret(&resolver, &CredRef::Path(small.clone()), &mut |w| {
                warnings.push(w)
            })
            .unwrap();
            assert!(warnings.is_empty(), "{warnings:?}");

            // systemd credentials are never flagged (their mode is systemd's).
            std::fs::set_permissions(&small, std::fs::Permissions::from_mode(0o644)).unwrap();
            read_secret(
                &resolver,
                &CredRef::Credential("small.json".into()),
                &mut |w| warnings.push(w),
            )
            .unwrap();
            assert!(warnings.is_empty(), "{warnings:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §2.4 item 3: parsers never panic on arbitrary input.
    #[test]
    fn random_input_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds = [
            sample("pseudo.key.json"),
            sample("upstream-keys.rotated.json"),
        ];
        for i in 0..10_000 {
            let mut input = seeds[i % 2].clone();
            let edits = (next() % 8) as usize;
            for _ in 0..edits {
                if input.is_empty() {
                    break;
                }
                let at = (next() as usize) % input.len();
                match next() % 3 {
                    0 => input[at] = next() as u8,
                    1 => {
                        input.remove(at);
                    }
                    _ => input.insert(at, next() as u8),
                }
            }
            let _ = PseudoKey::parse(&input);
            let _ = UpstreamKeys::parse(&input);
            let _ = is_rfc3339(&String::from_utf8_lossy(&input));
        }
    }
}
