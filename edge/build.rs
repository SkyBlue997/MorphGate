//! Sets `MG_EDGE_COMMIT` for `mg-edge --version`, the start-up log and
//! `mg_edge_info{commit}`: the `MG_EDGE_COMMIT` environment variable when
//! set (builds from a source archive), else the 12-digit abbreviation of the
//! checkout's `HEAD`, else `unknown`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MG_EDGE_COMMIT");
    let commit = match std::env::var("MG_EDGE_COMMIT") {
        Ok(v) => {
            assert!(
                valid(&v),
                "MG_EDGE_COMMIT must be 1-64 characters of [0-9A-Za-z._-], got {v:?}"
            );
            v
        }
        Err(_) => from_git().unwrap_or_else(|| "unknown".to_owned()),
    };
    println!("cargo:rustc-env=MG_EDGE_COMMIT={commit}");
}

fn valid(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

fn from_git() -> Option<String> {
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let commit = git(&dir, &["rev-parse", "--short=12", "HEAD"])?;
    if !valid(&commit) {
        return None;
    }
    // Rebuild when HEAD moves: HEAD itself, the branch it points at (loose
    // or packed), and the loose ref's directory, where the ref appears when
    // a packed branch moves. Only existing paths: a missing one would rerun
    // this script on every build.
    let git_path = |p: &str| git(&dir, &["rev-parse", "--git-path", p]).map(|g| dir.join(g));
    let mut watch = vec![git_path("HEAD"), git_path("packed-refs")];
    if let Some(r) = git(&dir, &["symbolic-ref", "-q", "HEAD"]) {
        let loose = git_path(&r);
        let parent = loose
            .as_ref()
            .and_then(|l| l.parent().map(Path::to_path_buf));
        watch.extend([loose, parent]);
    }
    for p in watch.into_iter().flatten().filter(|p| p.exists()) {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    Some(commit)
}
