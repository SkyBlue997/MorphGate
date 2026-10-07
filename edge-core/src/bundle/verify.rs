//! Bundle verification: decode, signature, identity and bounds (§9.10).

use super::keys::OwnerKeys;
use super::util::{hex_lower, sha256};
use super::{
    BundleError, MAX_BUNDLE_BYTES, MAX_SIGNED_BUNDLE_BYTES, SCHEMA_VERSION, SIGNING_DOMAIN,
};
use mg_proto::v1::{SignedBundle, SiteBundle};
use prost::Message as _;
use std::collections::BTreeSet;
use std::fmt;

/// A bundle that passed [`verify_bundle`].
#[derive(Clone, PartialEq)]
pub struct VerifiedBundle {
    /// The `SignedBundle` bytes exactly as fetched (what the LKG file stores).
    pub bytes: Vec<u8>,
    /// The decoded `SiteBundle`.
    pub bundle: SiteBundle,
    /// SHA-256 of [`Self::bytes`].
    pub sha256: [u8; 32],
}

impl VerifiedBundle {
    /// Lower-case hex of [`Self::sha256`].
    pub fn sha256_hex(&self) -> String {
        hex_lower(&self.sha256)
    }
}

impl fmt::Debug for VerifiedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedBundle")
            .field("site_id", &self.bundle.site_id)
            .field("version", &self.bundle.version)
            .field("sha256", &self.sha256_hex())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Synchronous: size, SignedBundle decode, key_id, Ed25519 over "mg-bundle-v1" || 0x00 || bundle,
/// SiteBundle decode, schema_version, site_id, hosts (as sets), §8.2 bounds. No version check.
///
/// `site_id` and `hosts` come from the site's `edge.toml` entry. Checks run
/// in the order above and stop at the first failure; nothing is decoded
/// from the inner bundle before the signature has verified. The version
/// ordering against the bundle in effect, the listener profiles, the token
/// key ids and the conversion of rules / IR / artifacts are the caller's
/// (§9.10), because they need edge.toml, credentials or other crates.
pub fn verify_bundle(
    bytes: &[u8],
    keys: &OwnerKeys,
    site_id: &str,
    hosts: &[String],
) -> Result<VerifiedBundle, BundleError> {
    if bytes.len() > MAX_SIGNED_BUNDLE_BYTES {
        return Err(BundleError::TooLarge {
            what: "signed bundle",
            limit: MAX_SIGNED_BUNDLE_BYTES as u64,
        });
    }
    let signed = SignedBundle::decode(bytes).map_err(|e| BundleError::Decode {
        what: "SignedBundle",
        detail: e.to_string(),
    })?;
    if signed.bundle.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge {
            what: "bundle",
            limit: MAX_BUNDLE_BYTES as u64,
        });
    }
    let key = keys
        .get(&signed.key_id)
        .ok_or_else(|| BundleError::UnknownKey(printable(&signed.key_id)))?;
    let signature = ed25519_compact::Signature::from_slice(&signed.ed25519_signature)
        .map_err(|_| BundleError::BadSignature)?;
    // Streaming verification: no copy of the (up to 8 MiB) bundle.
    let mut state = key
        .verify_incremental(&signature)
        .map_err(|_| BundleError::BadSignature)?;
    state.absorb(SIGNING_DOMAIN);
    state.absorb(&signed.bundle);
    state.verify().map_err(|_| BundleError::BadSignature)?;

    let bundle = SiteBundle::decode(signed.bundle.as_slice()).map_err(|e| BundleError::Decode {
        what: "SiteBundle",
        detail: e.to_string(),
    })?;
    if bundle.schema_version != SCHEMA_VERSION {
        return Err(BundleError::SchemaVersion(bundle.schema_version));
    }
    if bundle.site_id != site_id {
        return Err(BundleError::SiteMismatch {
            expected: site_id.to_string(),
            found: printable(&bundle.site_id),
        });
    }
    check_hosts(&bundle, hosts)?;
    super::validate::check_bounds(&bundle)?;

    Ok(VerifiedBundle {
        sha256: sha256(bytes),
        bytes: bytes.to_vec(),
        bundle,
    })
}

/// `SiteBundle.hosts` must equal the edge.toml hosts as sets, without
/// duplicates on the bundle side (they are a partition base, §8.2).
fn check_hosts(bundle: &SiteBundle, hosts: &[String]) -> Result<(), BundleError> {
    let found: BTreeSet<&str> = bundle.hosts.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = hosts.iter().map(String::as_str).collect();
    if found.len() != bundle.hosts.len() {
        return Err(BundleError::invalid("hosts", "duplicate host"));
    }
    if found != expected {
        return Err(BundleError::HostsMismatch {
            expected: expected.into_iter().map(printable).collect(),
            found: found.into_iter().map(printable).collect(),
        });
    }
    Ok(())
}

/// Attacker-influenced strings in error messages: bounded length, control
/// characters escaped (they end up in log lines).
pub(crate) fn printable(s: &str) -> String {
    const MAX: usize = 128;
    let mut out: String = s.chars().take(MAX).flat_map(char::escape_default).collect();
    if s.chars().nth(MAX).is_some() {
        out.push('…');
    }
    out
}
