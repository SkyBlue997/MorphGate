//! `state_dir`: the last-known-good bundle per site and the artifact cache
//! (§8.1 `state_dir`, §9.10).
//!
//! ```text
//! <state_dir>/bundles/<site>.bundle   SignedBundle bytes of the bundle in effect (LKG)
//! <state_dir>/artifacts/<sha256>      content-addressed artifact files
//! ```
//!
//! Every write goes to a temporary file in the same directory (name starting
//! with `.`), is `fsync`ed, then renamed over the target, and the directory
//! is `fsync`ed: a reader sees either the old or the new file, never a
//! partial one, and a crash leaves at most a stray temporary file that
//! readers never open and [`StateDir::gc`] eventually removes.

use super::fetch::read_file_capped;
use super::util::{hex_lower, is_sha256_hex, is_site_id, sha256};
use super::{BundleError, MAX_SIGNED_BUNDLE_BYTES};
use mg_proto::v1::{SignedBundle, SiteBundle};
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Largest artifact of any kind (§12.1).
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

/// Temporary files older than this are leftovers of a crash.
const STALE_TMP_AGE: Duration = Duration::from_secs(3600);

const TMP_PREFIX: &str = ".tmp-";

/// The Edge's persistent bundle state (`state_dir` in edge.toml).
///
/// Construction touches nothing on disk (so `mg-edge --check-config` can use
/// it read-only); the subdirectories are created on the first write.
#[derive(Debug)]
pub struct StateDir {
    bundles: PathBuf,
    artifacts: PathBuf,
    /// Artifact hashes each site's poll loop still needs (bundle in effect,
    /// pending bundle, candidate being fetched); [`StateDir::gc`] never
    /// deletes them. Several sites share one artifact directory.
    protected: Mutex<BTreeMap<String, BTreeSet<String>>>,
}

impl StateDir {
    /// `root` is edge.toml's `state_dir`.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            bundles: root.join("bundles"),
            artifacts: root.join("artifacts"),
            protected: Mutex::new(BTreeMap::new()),
        }
    }

    /// `<state_dir>/bundles/<site>.bundle`.
    pub fn lkg_path(&self, site: &str) -> io::Result<PathBuf> {
        if !is_site_id(site) {
            return Err(invalid_input("invalid site id"));
        }
        Ok(self.bundles.join(format!("{site}.bundle")))
    }

    /// `<state_dir>/artifacts/<sha256_hex>`.
    pub fn artifact_path(&self, sha256_hex: &str) -> io::Result<PathBuf> {
        if !is_sha256_hex(sha256_hex) {
            return Err(invalid_input("not a lower-case SHA-256 hex digest"));
        }
        Ok(self.artifacts.join(sha256_hex))
    }

    /// The site's LKG bytes, `None` if there is no LKG file. A file larger
    /// than [`MAX_SIGNED_BUNDLE_BYTES`] is an `InvalidData` error (the caller
    /// treats any error as "LKG exists but is unusable", §9.10).
    pub fn read_lkg(&self, site: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.lkg_path(site)?;
        match read_file_capped(&path, MAX_SIGNED_BUNDLE_BYTES as u64, "LKG bundle") {
            Ok(bytes) => Ok(Some(bytes)),
            Err(BundleError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(BundleError::Io(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    }

    /// Replaces the site's LKG with `signed` atomically (tmp + fsync + rename).
    pub fn write_lkg(&self, site: &str, signed: &[u8]) -> io::Result<()> {
        let path = self.lkg_path(site)?;
        atomic_write(&self.bundles, &path, signed)
    }

    /// The cached artifact, `None` if absent. The content is checked against
    /// its name: a file whose SHA-256 differs (disk corruption, tampering) is
    /// removed and reported as absent, so the poll loop fetches it again.
    pub fn artifact(&self, sha256_hex: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.artifact_path(sha256_hex)?;
        let bytes = match read_file_capped(&path, MAX_ARTIFACT_BYTES, "artifact") {
            Ok(bytes) => bytes,
            Err(BundleError::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(BundleError::Io(e)) => return Err(e),
            Err(_) => Vec::new(), // too large: cannot match any Phase 1 artifact hash
        };
        if hex_lower(&sha256(&bytes)) != sha256_hex {
            log::warn!("artifact cache: {sha256_hex} does not match its hash; removing it");
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    /// Stores an artifact under its SHA-256 (tmp + fsync + rename). Fails
    /// with `InvalidInput` if `bytes` do not hash to `sha256_hex`.
    pub fn store_artifact(&self, sha256_hex: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.artifact_path(sha256_hex)?;
        if hex_lower(&sha256(bytes)) != sha256_hex {
            return Err(invalid_input("artifact bytes do not match their SHA-256"));
        }
        atomic_write(&self.artifacts, &path, bytes)
    }

    /// Replaces the set of artifact hashes `site` needs right now; used by
    /// the poll loop so that another site's [`StateDir::gc`] cannot delete a
    /// file between download and apply, or one a pending bundle refers to.
    pub fn protect(&self, site: &str, hashes: BTreeSet<String>) {
        let mut map = self
            .protected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if hashes.is_empty() {
            map.remove(site);
        } else {
            map.insert(site.to_string(), hashes);
        }
    }

    /// Deletes cached artifacts that nothing refers to and returns how many
    /// were deleted. Kept: every hash in `keep`, every hash protected by a
    /// poll loop ([`StateDir::protect`]) and every artifact referenced by any
    /// site's LKG file on disk (§9.10: an artifact the LKG refers to is never
    /// deleted). If an LKG file cannot be read or decoded, nothing is deleted.
    /// Temporary files older than an hour are removed as well (not counted).
    pub fn gc(&self, keep: &BTreeSet<String>) -> io::Result<usize> {
        let mut keep_all = keep.clone();
        {
            let map = self
                .protected
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            keep_all.extend(map.values().flatten().cloned());
        }
        match self.lkg_references() {
            Ok(refs) => keep_all.extend(refs),
            Err(e) => {
                log::warn!(
                    "artifact cache: not collecting garbage, an LKG file is unreadable: {e}"
                );
                return Ok(0);
            }
        }
        let entries = match fs::read_dir(&self.artifacts) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if is_sha256_hex(name) {
                if !keep_all.contains(name) {
                    remove_if_present(&entry.path())?;
                    removed += 1;
                }
            } else if name.starts_with(TMP_PREFIX) && is_stale(&entry) {
                remove_if_present(&entry.path())?;
            }
        }
        if let Ok(entries) = fs::read_dir(&self.bundles) {
            for entry in entries.flatten() {
                let stale_tmp = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(TMP_PREFIX));
                if stale_tmp && is_stale(&entry) {
                    remove_if_present(&entry.path())?;
                }
            }
        }
        Ok(removed)
    }

    /// Artifact hashes referenced by every `<site>.bundle` in `bundles/`.
    /// The signature is not checked: the result only ever keeps files.
    fn lkg_references(&self) -> Result<BTreeSet<String>, String> {
        let mut refs = BTreeSet::new();
        let entries = match fs::read_dir(&self.bundles) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(refs),
            Err(e) => return Err(e.to_string()),
        };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') || !name.ends_with(".bundle") {
                continue;
            }
            let bytes =
                read_file_capped(&entry.path(), MAX_SIGNED_BUNDLE_BYTES as u64, "LKG bundle")
                    .map_err(|e| format!("{name}: {e}"))?;
            let signed =
                SignedBundle::decode(bytes.as_slice()).map_err(|e| format!("{name}: {e}"))?;
            let bundle =
                SiteBundle::decode(signed.bundle.as_slice()).map_err(|e| format!("{name}: {e}"))?;
            refs.extend(bundle.artifacts.into_iter().map(|a| a.sha256));
        }
        Ok(refs)
    }
}

fn invalid_input(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn is_stale(entry: &fs::DirEntry) -> bool {
    entry
        .metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age > STALE_TMP_AGE)
}

/// Writes `bytes` to `target` via a temporary file in `dir` (same file
/// system, so the rename is atomic), with `fsync` of the file and the
/// directory (and of the parent when `dir` had to be created, so that a
/// first LKG survives a power loss together with its directory).
fn atomic_write(dir: &Path, target: &Path, bytes: &[u8]) -> io::Result<()> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
        // A relative `state_dir` of one component has the parent "".
        let parent = dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        sync_dir(parent)?;
    }
    let (tmp, mut file) = create_tmp(dir)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, target)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Creates a new temporary file in `dir`. The name carries the pid, a
/// counter and a random part, and creation retries on a name that already
/// exists: a crashed process may have left one behind under the same pid
/// (containers, pid namespaces), and it is never ours to overwrite.
fn create_tmp(dir: &Path) -> io::Result<(PathBuf, fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const ATTEMPTS: usize = 16;
    let mut attempt = 0;
    loop {
        let tmp = dir.join(format!(
            "{TMP_PREFIX}{}-{}-{:016x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            // Uniqueness only; the counter alone still works if the RNG fails.
            getrandom::u64().unwrap_or(0)
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt + 1 < ATTEMPTS => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}
