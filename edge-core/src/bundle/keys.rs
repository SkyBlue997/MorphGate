//! Owner public keys (`[trust] owner_keys` in edge.toml; file format §12.6).

use super::BundleError;
use super::util::{is_kid, is_rfc3339};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

/// Largest accepted `.pub` file (the canonical file is under 200 bytes).
const MAX_PUB_FILE_BYTES: usize = 4096;

const PUB_KIND: &str = "mg-owner-ed25519-pub";

/// `<kid>.pub` (§12.6). Every field is required; unknown fields are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PubFile {
    v: u32,
    kind: String,
    kid: String,
    public_key: String,
    created_at: String,
}

/// The owner signing keys the Edge trusts, by key id.
///
/// Built once from the `[trust] owner_keys` files; a bundle verifies only if
/// its `key_id` names one of these keys and the signature checks out under
/// it. During an owner key rotation (§17 step 5) two keys are trusted at the
/// same time.
#[derive(Clone)]
pub struct OwnerKeys {
    keys: BTreeMap<String, ed25519_compact::PublicKey>,
}

impl fmt::Debug for OwnerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerKeys")
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OwnerKeys {
    /// Parses `(file name, contents)` pairs of `.pub` files.
    ///
    /// Rejects: no files; a file larger than 4 KiB or not the exact §12.6
    /// JSON (`v == 1`, `kind == "mg-owner-ed25519-pub"`, `kid` matching
    /// `[a-z0-9][a-z0-9._-]{0,63}`, `public_key` = unpadded base64url of 32
    /// bytes, `created_at` in RFC 3339, no unknown or missing fields); a key
    /// that is not a valid, non-small-order Ed25519 point; the same kid twice.
    /// The file name only appears in error messages.
    pub fn from_pub_files(files: &[(&str, &[u8])]) -> Result<Self, BundleError> {
        if files.is_empty() {
            return Err(BundleError::KeyFile {
                file: String::new(),
                reason: "at least one owner public key is required".into(),
            });
        }
        let mut keys = BTreeMap::new();
        for &(name, bytes) in files {
            let err = |reason: String| BundleError::KeyFile {
                file: name.to_string(),
                reason,
            };
            let (kid, key) = parse_pub_file(bytes).map_err(err)?;
            if keys.contains_key(&kid) {
                return Err(err(format!("duplicate owner key id {kid:?}")));
            }
            keys.insert(kid, key);
        }
        Ok(Self { keys })
    }

    /// The trusted key ids, sorted.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// The public key with id `kid`.
    pub(crate) fn get(&self, kid: &str) -> Option<&ed25519_compact::PublicKey> {
        self.keys.get(kid)
    }
}

fn parse_pub_file(bytes: &[u8]) -> Result<(String, ed25519_compact::PublicKey), String> {
    if bytes.len() > MAX_PUB_FILE_BYTES {
        return Err(format!("larger than {MAX_PUB_FILE_BYTES} bytes"));
    }
    let file: PubFile =
        serde_json::from_slice(bytes).map_err(|e| format!("not a §12.6 public key file: {e}"))?;
    if file.v != 1 {
        return Err(format!("unsupported v {}", file.v));
    }
    if file.kind != PUB_KIND {
        return Err(format!("kind is {:?}, expected {PUB_KIND:?}", file.kind));
    }
    if !is_kid(&file.kid) {
        return Err(format!("invalid kid {:?}", file.kid));
    }
    if !is_rfc3339(&file.created_at) {
        return Err("created_at is not an RFC 3339 time".into());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(file.public_key.as_bytes())
        .map_err(|_| "public_key is not unpadded base64url".to_string())?;
    let key = ed25519_compact::PublicKey::from_slice(&raw)
        .map_err(|_| format!("public_key is {} bytes, expected 32", raw.len()))?;
    key.validate()
        .map_err(|_| "public_key is not a valid Ed25519 public key".to_string())?;
    Ok((file.kid, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_TEST_PUB: &[u8] = include_bytes!("../../../testdata/phase1/keys/owner-test.pub");

    fn pub_json(kid: &str, key: &[u8]) -> Vec<u8> {
        format!(
            r#"{{"v":1,"kind":"mg-owner-ed25519-pub","kid":"{kid}","public_key":"{}","created_at":"2026-09-27T10:00:00Z"}}"#,
            URL_SAFE_NO_PAD.encode(key)
        )
        .into_bytes()
    }

    #[test]
    fn accepts_the_shared_sample() {
        let keys = OwnerKeys::from_pub_files(&[("owner-test.pub", OWNER_TEST_PUB)]).unwrap();
        assert_eq!(keys.kids().collect::<Vec<_>>(), ["owner-test"]);
        // RFC 8032 §7.1 test 1 public key.
        assert_eq!(
            super::super::util::hex_lower(keys.get("owner-test").unwrap().as_ref()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn rejects_weak_and_invalid_points() {
        // The identity point (small order) and a non-canonical encoding.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = OwnerKeys::from_pub_files(&[("x.pub", &pub_json("x", &identity))]).unwrap_err();
        assert!(err.to_string().contains("not a valid Ed25519"), "{err}");
        let err = OwnerKeys::from_pub_files(&[("x.pub", &pub_json("x", &[0xff; 32]))]).unwrap_err();
        assert!(err.to_string().contains("not a valid Ed25519"), "{err}");
    }

    #[test]
    fn debug_lists_kids_only() {
        let keys = OwnerKeys::from_pub_files(&[("owner-test.pub", OWNER_TEST_PUB)]).unwrap();
        let dbg = format!("{keys:?}");
        assert_eq!(dbg, r#"OwnerKeys { kids: ["owner-test"] }"#);
    }
}
