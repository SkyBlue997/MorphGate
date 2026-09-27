//! `StateDir`: LKG persistence and the artifact cache (docs/impl/phase1-spec.md
//! §9.10 "persist signed bytes ... via tmp + fsync + rename", artifact cache
//! cleanup: "从不删除 LKG 引用的工件").

use mg_edge_core::bundle::StateDir;
use mg_edge_core::testkit::http::{
    OWNER_TEST_KID, OWNER_TEST_SEED, sha256_hex, sign_test_bundle, test_site_bundle,
};
use mg_proto::v1::ArtifactRef;
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "mg-bundle-store-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        Self(base)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn files(dir: &Path) -> BTreeSet<String> {
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

#[test]
fn new_touches_nothing_and_missing_lkg_is_none() {
    let tmp = TempDir::new("empty");
    let root = tmp.path().join("state");
    let dir = StateDir::new(&root);
    assert!(!root.exists());
    assert_eq!(dir.read_lkg("blog").unwrap(), None);
    assert_eq!(dir.artifact(&"a".repeat(64)).unwrap(), None);
    assert_eq!(dir.gc(&BTreeSet::new()).unwrap(), 0);
    assert!(!root.exists(), "read-only use must not create directories");
}

#[test]
fn lkg_round_trip_and_replace() {
    let tmp = TempDir::new("lkg");
    let dir = StateDir::new(tmp.path());
    dir.write_lkg("blog", b"first").unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap().as_deref(),
        Some(&b"first"[..])
    );
    dir.write_lkg("blog", b"second, longer").unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap().as_deref(),
        Some(&b"second, longer"[..])
    );
    assert_eq!(dir.read_lkg("shop").unwrap(), None);
    // Only the final file remains: no temporary files are left behind.
    assert_eq!(
        files(&tmp.path().join("bundles")),
        BTreeSet::from(["blog.bundle".to_string()])
    );
    assert_eq!(
        dir.lkg_path("blog").unwrap(),
        tmp.path().join("bundles/blog.bundle")
    );
}

/// §9.10: a half-written temporary file (a crash during `write_lkg`) is
/// never what `read_lkg` returns.
#[test]
fn partial_temporary_file_is_never_read() {
    let tmp = TempDir::new("atomic");
    let dir = StateDir::new(tmp.path());
    dir.write_lkg("blog", b"complete bundle").unwrap();
    let bundles = tmp.path().join("bundles");
    // What an interrupted writer leaves: a truncated temporary file, and
    // (for a first write) no final file at all.
    fs::write(bundles.join(".tmp-99999-0"), b"compl").unwrap();
    fs::write(bundles.join(".tmp-99999-1"), b"trunc").unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap().as_deref(),
        Some(&b"complete bundle"[..])
    );
    assert_eq!(dir.read_lkg("shop").unwrap(), None);
    // The next write still succeeds and replaces the file atomically.
    dir.write_lkg("blog", b"newer").unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap().as_deref(),
        Some(&b"newer"[..])
    );
}

#[test]
fn site_ids_cannot_escape_the_directory() {
    let tmp = TempDir::new("traversal");
    let dir = StateDir::new(tmp.path().join("state"));
    for site in ["", "../x", "a/b", "..", "Blog", ".hidden", &"a".repeat(65)] {
        assert_eq!(
            dir.write_lkg(site, b"x").unwrap_err().kind(),
            ErrorKind::InvalidInput,
            "{site}"
        );
        assert_eq!(
            dir.read_lkg(site).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
    for sha in ["", "../../x", &"A".repeat(64), &"a".repeat(63)] {
        assert_eq!(
            dir.artifact(sha).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            dir.store_artifact(sha, b"x").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
    assert!(!tmp.path().join("x").exists());
}

#[test]
fn oversized_lkg_is_invalid_data() {
    let tmp = TempDir::new("oversize");
    let dir = StateDir::new(tmp.path());
    fs::create_dir_all(tmp.path().join("bundles")).unwrap();
    fs::write(
        tmp.path().join("bundles/blog.bundle"),
        vec![0u8; mg_edge_core::bundle::MAX_SIGNED_BUNDLE_BYTES + 1],
    )
    .unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn artifacts_are_content_addressed() {
    let tmp = TempDir::new("artifacts");
    let dir = StateDir::new(tmp.path());
    let bytes = b"AS64500\n".to_vec();
    let sha = sha256_hex(&bytes);
    dir.store_artifact(&sha, &bytes).unwrap();
    assert_eq!(dir.artifact(&sha).unwrap(), Some(bytes.clone()));
    // Storing again is idempotent.
    dir.store_artifact(&sha, &bytes).unwrap();

    // Bytes that do not hash to the name are refused.
    let err = dir.store_artifact(&sha, b"other").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(dir.artifact(&sha).unwrap(), Some(bytes.clone()));
}

/// A cached file whose content no longer matches its name (corruption,
/// tampering) is dropped and reported missing, so it gets fetched again.
#[test]
fn corrupted_cached_artifact_is_dropped() {
    let tmp = TempDir::new("corrupt");
    let dir = StateDir::new(tmp.path());
    let bytes = b"198.51.100.7\n".to_vec();
    let sha = sha256_hex(&bytes);
    dir.store_artifact(&sha, &bytes).unwrap();
    let path = tmp.path().join("artifacts").join(&sha);
    fs::write(&path, b"198.51.100.8\n").unwrap();
    assert_eq!(dir.artifact(&sha).unwrap(), None);
    assert!(!path.exists());
}

fn lkg_with_artifacts(site: &str, shas: &[&str]) -> Vec<u8> {
    let mut b = test_site_bundle(site, &["example.com"], 1);
    for (i, sha) in shas.iter().enumerate() {
        b.artifacts.push(ArtifactRef {
            name: ["cloudflare-ips", "tor-exits", "datacenter-asns"][i].into(),
            uri: format!("artifacts/{sha}"),
            sha256: (*sha).to_string(),
            version: String::new(),
            size: 1,
        });
    }
    sign_test_bundle(&b, &OWNER_TEST_SEED, OWNER_TEST_KID)
}

/// §9.10: gc keeps everything in `keep`, everything a poll loop protects and
/// everything any site's LKG refers to; it deletes the rest.
#[test]
fn gc_keeps_referenced_artifacts() {
    let tmp = TempDir::new("gc");
    let dir = StateDir::new(tmp.path());
    let mut shas = Vec::new();
    for i in 0..6 {
        let bytes = format!("artifact {i}").into_bytes();
        let sha = sha256_hex(&bytes);
        dir.store_artifact(&sha, &bytes).unwrap();
        shas.push(sha);
    }
    // Another site's LKG refers to shas[1]; site "shop" protects shas[2].
    dir.write_lkg("blog", &lkg_with_artifacts("blog", &[&shas[1]]))
        .unwrap();
    dir.protect("shop", BTreeSet::from([shas[2].clone()]));
    // Unrelated files in the cache directory are left alone.
    fs::write(tmp.path().join("artifacts/README"), b"x").unwrap();

    let keep = BTreeSet::from([shas[0].clone()]);
    assert_eq!(dir.gc(&keep).unwrap(), 3);
    let left = files(&tmp.path().join("artifacts"));
    for (i, sha) in shas.iter().enumerate() {
        assert_eq!(left.contains(sha), i < 3, "artifact {i}");
    }
    assert!(left.contains("README"));

    // Dropping the protection frees shas[2]; the LKG reference stays.
    dir.protect("shop", BTreeSet::new());
    assert_eq!(dir.gc(&keep).unwrap(), 1);
    assert!(dir.artifact(&shas[1]).unwrap().is_some());
}

/// If an LKG cannot be decoded its references are unknown: delete nothing.
#[test]
fn gc_deletes_nothing_when_an_lkg_is_unreadable() {
    let tmp = TempDir::new("gc-bad-lkg");
    let dir = StateDir::new(tmp.path());
    let bytes = b"orphan".to_vec();
    let sha = sha256_hex(&bytes);
    dir.store_artifact(&sha, &bytes).unwrap();
    dir.write_lkg("blog", &[0xff, 0xff, 0xff]).unwrap();
    assert_eq!(dir.gc(&BTreeSet::new()).unwrap(), 0);
    assert!(dir.artifact(&sha).unwrap().is_some());
    // Once the LKG is fixed, the orphan goes.
    dir.write_lkg("blog", &lkg_with_artifacts("blog", &[]))
        .unwrap();
    assert_eq!(dir.gc(&BTreeSet::new()).unwrap(), 1);
}

#[test]
fn gc_removes_only_stale_temporary_files() {
    let tmp = TempDir::new("gc-tmp");
    let dir = StateDir::new(tmp.path());
    let artifacts = tmp.path().join("artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    let old = artifacts.join(".tmp-1-0");
    let fresh = artifacts.join(".tmp-1-1");
    fs::write(&old, b"x").unwrap();
    fs::write(&fresh, b"x").unwrap();
    let f = fs::File::options().write(true).open(&old).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(2 * 3600))
        .unwrap();
    drop(f);
    assert_eq!(dir.gc(&BTreeSet::new()).unwrap(), 0);
    assert!(!old.exists());
    assert!(fresh.exists(), "a temporary file of a running writer stays");
}

/// A crash between creating and renaming a temporary file leaves it behind;
/// a later process that happens to get the same pid (containers, pid
/// namespaces) must still be able to write the LKG and cache artifacts.
#[test]
fn leftover_temporary_files_do_not_block_writes() {
    let tmp = TempDir::new("tmp-collision");
    let dir = StateDir::new(tmp.path());
    let pid = std::process::id();
    for sub in ["bundles", "artifacts"] {
        let d = tmp.path().join(sub);
        fs::create_dir_all(&d).unwrap();
        for n in 0..256 {
            fs::write(d.join(format!(".tmp-{pid}-{n}")), b"leftover").unwrap();
        }
    }
    dir.write_lkg("blog", b"bundle").unwrap();
    assert_eq!(
        dir.read_lkg("blog").unwrap().as_deref(),
        Some(&b"bundle"[..])
    );
    let bytes = b"AS64500\n";
    dir.store_artifact(&sha256_hex(bytes), bytes).unwrap();
    // The leftovers of the other process are not touched by the writer.
    for sub in ["bundles", "artifacts"] {
        let left = files(&tmp.path().join(sub));
        assert!(
            (0..256).all(|n| left.contains(&format!(".tmp-{pid}-{n}"))),
            "{sub}"
        );
    }
}
