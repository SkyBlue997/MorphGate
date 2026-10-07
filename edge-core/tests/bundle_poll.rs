//! `poll_loop` (docs/impl/phase1-spec.md §9.10: candidate checks, version
//! ordering, artifacts, `not_before_ms`, LKG persistence, cache cleanup,
//! missing-artifact retry, metrics, shutdown).

use mg_edge_core::bundle::{
    Fetcher, FetcherConfig, OwnerKeys, SiteSource, Source, StateDir, VerifiedBundle, metrics,
    poll_loop, verify_bundle,
};
use mg_edge_core::testkit::http::{
    HttpServer, OWNER_TEST_KID, OWNER_TEST_SEED, Reply, owner_test_keys, sha256_hex,
    sign_test_bundle, test_site_bundle,
};
use mg_proto::v1::{ArtifactRef, SiteBundle};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const HOSTS: &[&str] = &["example.com"];
const INTERVAL: Duration = Duration::from_millis(40);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mg-bundle-poll-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
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

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn artifact_ref(name: &str, bytes: &[u8]) -> ArtifactRef {
    let sha = sha256_hex(bytes);
    ArtifactRef {
        name: name.into(),
        uri: format!("artifacts/{sha}"),
        sha256: sha,
        version: String::new(),
        size: bytes.len() as u64,
    }
}

fn site_bundle(site: &str, version: u64, artifacts: &[(&str, &[u8])]) -> SiteBundle {
    let mut b = test_site_bundle(site, HOSTS, version);
    b.artifacts = artifacts.iter().map(|(n, a)| artifact_ref(n, a)).collect();
    b
}

fn sign(b: &SiteBundle) -> Vec<u8> {
    sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID)
}

fn hosts() -> Vec<String> {
    HOSTS.iter().map(|h| (*h).to_string()).collect()
}

/// Artifacts by `ArtifactRef.name`, as `apply` receives them.
type Artifacts = BTreeMap<String, Vec<u8>>;

/// What `apply` saw, and a switch to make it fail for one version.
#[derive(Default)]
struct Recorder {
    applied: Mutex<Vec<(u64, Artifacts)>>,
    fail_version: Mutex<Option<u64>>,
}

impl Recorder {
    fn versions(&self) -> Vec<u64> {
        self.applied
            .lock()
            .unwrap()
            .iter()
            .map(|(v, _)| *v)
            .collect()
    }
    fn last_artifacts(&self) -> Artifacts {
        self.applied.lock().unwrap().last().unwrap().1.clone()
    }
}

struct Harness {
    site: String,
    rec: Arc<Recorder>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

fn start(site: &str, root: Source, dir: Arc<StateDir>, current: Option<VerifiedBundle>) -> Harness {
    let rec = Arc::new(Recorder::default());
    let r = Arc::clone(&rec);
    let apply = move |vb: VerifiedBundle, artifacts: Artifacts| {
        if *r.fail_version.lock().unwrap() == Some(vb.bundle.version) {
            return Err("token key blog-t-x is not in token.keys.json".to_string());
        }
        r.applied
            .lock()
            .unwrap()
            .push((vb.bundle.version, artifacts));
        Ok(())
    };
    let (stop, stopped) = watch::channel(false);
    let source = SiteSource {
        site: site.to_string(),
        hosts: hosts(),
        root,
        interval: INTERVAL,
        current,
    };
    let fetcher = Arc::new(Fetcher::new(&FetcherConfig::new(Duration::from_secs(2))).unwrap());
    let keys: Arc<OwnerKeys> = Arc::new(owner_test_keys());
    let task = tokio::spawn(poll_loop(source, fetcher, dir, keys, apply, stopped));
    Harness {
        site: site.to_string(),
        rec,
        stop,
        task,
    }
}

impl Harness {
    fn reloads(&self, result: &str) -> u64 {
        metrics()
            .config_reload_total
            .with_label_values(&[self.site.as_str(), result])
            .get()
    }
    fn fetch_failures(&self) -> u64 {
        metrics()
            .config_fetch_failures_total
            .with_label_values(&[self.site.as_str()])
            .get()
    }
    fn version_gauge(&self) -> i64 {
        metrics()
            .config_version
            .with_label_values(&[self.site.as_str()])
            .get()
    }
    fn missing_gauge(&self, name: &str) -> i64 {
        metrics()
            .artifact_missing
            .with_label_values(&[self.site.as_str(), name])
            .get()
    }
    async fn stop(self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("poll loop stops on shutdown")
            .unwrap();
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A few poll intervals, for "nothing else happens" checks.
async fn settle() {
    tokio::time::sleep(INTERVAL * 6).await;
}

/// §9.10: bootstrap → first bundle applied with its artifacts, persisted as
/// the LKG, then a newer version replaces it and the cache drops the
/// artifact nobody refers to any more.
#[tokio::test]
async fn applies_new_versions_persists_lkg_and_cleans_cache() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("apply");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-apply";
    let (a1, a2) = (b"AS64500\n".as_slice(), b"AS64501\n".as_slice());
    server.publish_artifact(a1);
    server.publish_artifact(a2);
    let v1 = sign(&site_bundle(site, 1, &[("datacenter-asns", a1)]));
    server.publish_bundle(site, &v1);

    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;
    assert_eq!(
        h.rec.last_artifacts(),
        BTreeMap::from([("datacenter-asns".into(), a1.to_vec())])
    );
    wait_for("LKG v1", || {
        dir.read_lkg(site).unwrap().as_deref() == Some(v1.as_slice())
    })
    .await;
    assert!(dir.artifact(&sha256_hex(a1)).unwrap().is_some());
    // The metrics follow the LKG write.
    wait_for("version gauge", || h.version_gauge() == 1).await;
    assert_eq!(h.reloads("applied"), 1);

    // Unchanged content: conditional requests, no second apply.
    settle().await;
    assert_eq!(h.rec.versions(), [1]);
    assert!(h.reloads("unchanged") >= 2);
    let conditional = server
        .requests()
        .iter()
        .filter(|r| r.path.ends_with(".bundle") && r.header("if-none-match").is_some())
        .count();
    assert!(conditional >= 2);
    assert_eq!(server.hits(&format!("artifacts/{}", sha256_hex(a1))), 1);

    let v2 = sign(&site_bundle(site, 2, &[("datacenter-asns", a2)]));
    server.publish_bundle(site, &v2);
    wait_for("v2", || h.rec.versions() == [1, 2]).await;
    wait_for("LKG v2", || {
        dir.read_lkg(site).unwrap().as_deref() == Some(v2.as_slice())
    })
    .await;
    wait_for("gc", || dir.artifact(&sha256_hex(a1)).unwrap().is_none()).await;
    assert!(dir.artifact(&sha256_hex(a2)).unwrap().is_some());
    wait_for("version gauge", || h.version_gauge() == 2).await;
    assert_eq!(h.reloads("rejected"), 0);
    h.stop().await;
}

/// §9.10: every failed candidate check keeps the bundle in effect: bad
/// signature, older version, same version with other bytes, other site;
/// identical bytes are "unchanged".
#[tokio::test]
async fn rejects_bad_candidates_and_keeps_current() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("reject");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-reject";
    let v5 = sign(&site_bundle(site, 5, &[]));
    let current = verify_bundle(&v5, &owner_test_keys(), site, &hosts()).unwrap();
    dir.write_lkg(site, &v5).unwrap();
    server.publish_bundle(site, &v5);

    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        Some(current),
    );
    wait_for("unchanged", || h.reloads("unchanged") >= 1).await;
    assert_eq!(h.version_gauge(), 5);

    let mut other_bytes = site_bundle(site, 5, &[]);
    other_bytes.monitor_only = false;
    let mut tampered = sign(&site_bundle(site, 9, &[]));
    let n = tampered.len();
    tampered[n / 2] ^= 1;
    let candidates = [
        ("bad signature", tampered),
        (
            "other key",
            sign_test_bundle(&site_bundle(site, 9, &[]), &[5; 32], OWNER_TEST_KID),
        ),
        ("older version", sign(&site_bundle(site, 4, &[]))),
        ("same version, other bytes", sign(&other_bytes)),
        ("other site", sign(&site_bundle("poll-other", 9, &[]))),
        (
            "other hosts",
            sign(&test_site_bundle(site, &["example.org"], 9)),
        ),
    ];
    for (i, (what, bytes)) in candidates.iter().enumerate() {
        server.publish_bundle(site, bytes);
        let want = i as u64 + 1;
        wait_for(what, || h.reloads("rejected") >= want).await;
        // Rejected bytes are not processed again on later polls.
        settle().await;
        assert_eq!(h.reloads("rejected"), want, "{what} re-processed");
    }
    assert!(h.rec.versions().is_empty(), "nothing applied");
    assert_eq!(dir.read_lkg(site).unwrap().as_deref(), Some(v5.as_slice()));
    assert_eq!(h.version_gauge(), 5);

    let v6 = sign(&site_bundle(site, 6, &[]));
    server.publish_bundle(site, &v6);
    wait_for("v6", || h.rec.versions() == [6]).await;
    wait_for("LKG v6", || {
        dir.read_lkg(site).unwrap().as_deref() == Some(v6.as_slice())
    })
    .await;
    h.stop().await;
}

/// §9.10: an artifact whose content does not match the bundle rejects the
/// candidate; the same bundle is retried and applied once the artifact is
/// served correctly.
#[tokio::test]
async fn artifact_mismatch_rejects_then_recovers() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("artifact");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-artifact";
    let good = b"203.0.113.9\n".as_slice();
    let sha = sha256_hex(good);
    server.put(&format!("artifacts/{sha}"), b"203.0.113.6\n".to_vec());
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[("tor-exits", good)])));

    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("rejected", || h.reloads("rejected") >= 2).await;
    assert!(h.rec.versions().is_empty());
    assert!(dir.read_lkg(site).unwrap().is_none());
    assert!(dir.artifact(&sha).unwrap().is_none());

    // Missing artifact: a fetch failure, still nothing applied.
    server.remove(&format!("artifacts/{sha}"));
    let failures = h.fetch_failures();
    wait_for("fetch failure", || h.fetch_failures() > failures).await;
    assert!(h.rec.versions().is_empty());

    server.put(&format!("artifacts/{sha}"), good.to_vec());
    wait_for("applied", || h.rec.versions() == [1]).await;
    assert_eq!(h.rec.last_artifacts()["tor-exits"], good);
    wait_for("cached", || dir.artifact(&sha).unwrap().is_some()).await;
    h.stop().await;
}

/// §9.10: "sha256 and size must match": an artifact with the right hash
/// but a different size than the bundle declares rejects the candidate.
#[tokio::test]
async fn artifact_size_mismatch_rejects() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("artifact-size");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-artifact-size";
    let bytes = b"AS64503\n".as_slice();
    server.publish_artifact(bytes);
    let mut b = site_bundle(site, 1, &[("datacenter-asns", bytes)]);
    b.artifacts[0].size += 1;
    server.publish_bundle(site, &sign(&b));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("rejected", || h.reloads("rejected") >= 2).await;
    assert!(h.rec.versions().is_empty());
    assert!(dir.read_lkg(site).unwrap().is_none());
    h.stop().await;
}

/// §9.10: `not_before_ms > now` → pending, swapped in when due.
#[tokio::test]
async fn not_before_bundle_waits_until_due() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("pending");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-pending";
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[])));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;

    let due = now_ms() + 600;
    let mut b2 = site_bundle(site, 2, &[]);
    b2.not_before_ms = due;
    let v2 = sign(&b2);
    server.publish_bundle(site, &v2);
    settle().await;
    assert_eq!(h.rec.versions(), [1], "applied before not_before");
    assert_ne!(dir.read_lkg(site).unwrap().as_deref(), Some(v2.as_slice()));

    wait_for("v2", || h.rec.versions() == [1, 2]).await;
    assert!(now_ms() >= due);
    wait_for("LKG v2", || {
        dir.read_lkg(site).unwrap().as_deref() == Some(v2.as_slice())
    })
    .await;
    assert_eq!(h.reloads("rejected"), 0);
    h.stop().await;
}

/// §9.10: the runtime refusing a bundle (e.g. unknown token key id) is a
/// rejection: no LKG write, the bundle in effect stays.
#[tokio::test]
async fn apply_error_is_a_rejection() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("apply-err");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-apply-err";
    let v1 = sign(&site_bundle(site, 1, &[]));
    server.publish_bundle(site, &v1);
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;

    *h.rec.fail_version.lock().unwrap() = Some(2);
    server.publish_bundle(site, &sign(&site_bundle(site, 2, &[])));
    wait_for("rejected", || h.reloads("rejected") == 1).await;
    settle().await;
    assert_eq!(h.reloads("rejected"), 1);
    assert_eq!(h.rec.versions(), [1]);
    assert_eq!(dir.read_lkg(site).unwrap().as_deref(), Some(v1.as_slice()));
    assert_eq!(h.version_gauge(), 1);

    server.publish_bundle(site, &sign(&site_bundle(site, 3, &[])));
    wait_for("v3", || h.rec.versions() == [1, 3]).await;
    h.stop().await;
}

/// §9.10: an LKG whose artifacts are not cached is applied without them by
/// `main()`; the loop fetches them and applies the same bundle again.
#[tokio::test]
async fn missing_lkg_artifacts_are_fetched_and_reapplied() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("missing");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-missing";
    let (cached, missing) = (b"AS64500\n".as_slice(), b"198.51.100.1\n".as_slice());
    let v1 = sign(&site_bundle(
        site,
        1,
        &[("datacenter-asns", cached), ("tor-exits", missing)],
    ));
    dir.store_artifact(&sha256_hex(cached), cached).unwrap();
    dir.write_lkg(site, &v1).unwrap();
    let current = verify_bundle(&v1, &owner_test_keys(), site, &hosts()).unwrap();
    server.publish_bundle(site, &v1);

    // The artifact is not published yet: marked missing, retried each poll.
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        Some(current),
    );
    wait_for("missing gauge", || h.missing_gauge("tor-exits") == 1).await;
    let sha = sha256_hex(missing);
    wait_for("retries", || server.hits(&format!("artifacts/{sha}")) >= 2).await;
    assert!(h.rec.versions().is_empty());
    assert_eq!(h.missing_gauge("datacenter-asns"), 0);

    server.publish_artifact(missing);
    wait_for("re-applied", || h.rec.versions() == [1]).await;
    assert_eq!(
        h.rec.last_artifacts(),
        BTreeMap::from([
            ("datacenter-asns".into(), cached.to_vec()),
            ("tor-exits".into(), missing.to_vec()),
        ])
    );
    wait_for("missing gauge cleared", || {
        h.missing_gauge("tor-exits") == 0
    })
    .await;
    assert!(dir.artifact(&sha).unwrap().is_some());
    settle().await;
    assert_eq!(h.rec.versions(), [1], "applied once");
    h.stop().await;
}

/// A rebuild never drops an artifact the runtime already has: if a cached
/// artifact vanished and cannot be fetched, the arrival of a missing one
/// waits until the cache is whole again.
#[tokio::test]
async fn rebuild_waits_for_vanished_artifacts() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("vanished");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-vanished";
    let (had, missing) = (b"AS64502\n".as_slice(), b"198.51.100.2\n".as_slice());
    let v1 = sign(&site_bundle(
        site,
        1,
        &[("datacenter-asns", had), ("tor-exits", missing)],
    ));
    dir.store_artifact(&sha256_hex(had), had).unwrap();
    let current = verify_bundle(&v1, &owner_test_keys(), site, &hosts()).unwrap();
    server.publish_bundle(site, &v1);

    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        Some(current),
    );
    wait_for("missing gauge", || h.missing_gauge("tor-exits") == 1).await;
    // The cached artifact disappears (and is not served); the missing one arrives.
    fs::remove_file(tmp.path().join("artifacts").join(sha256_hex(had))).unwrap();
    server.publish_artifact(missing);
    let sha = sha256_hex(missing);
    wait_for("fetched", || dir.artifact(&sha).unwrap().is_some()).await;
    settle().await;
    assert!(
        h.rec.versions().is_empty(),
        "rebuilt without datacenter-asns"
    );
    assert_eq!(h.missing_gauge("tor-exits"), 1);

    server.publish_artifact(had);
    wait_for("rebuilt", || h.rec.versions() == [1]).await;
    assert_eq!(h.rec.last_artifacts().len(), 2);
    h.stop().await;
}

/// §9.10: `lkg_invalid` (LKG present but unusable; `current` is None): the
/// first valid candidate brings the site back and replaces the LKG.
#[tokio::test]
async fn lkg_invalid_site_recovers_with_a_valid_bundle() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("lkg-invalid");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-lkg-invalid";
    dir.write_lkg(site, b"garbage").unwrap();
    let v3 = sign(&site_bundle(site, 3, &[]));
    server.publish_bundle(site, &v3);
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v3", || h.rec.versions() == [3]).await;
    wait_for("LKG", || {
        dir.read_lkg(site).unwrap().as_deref() == Some(v3.as_slice())
    })
    .await;
    h.stop().await;
}

/// §9.10: `file://` roots work the same (ETag = SHA-256 of the file).
#[tokio::test]
async fn file_root() {
    let publish = TempDir::new("file-root");
    let state = TempDir::new("file-state");
    let dir = Arc::new(StateDir::new(state.path()));
    let site = "poll-file";
    let art = b"AS64510\n".as_slice();
    fs::create_dir_all(publish.path().join("bundles")).unwrap();
    fs::create_dir_all(publish.path().join("artifacts")).unwrap();
    fs::write(publish.path().join("artifacts").join(sha256_hex(art)), art).unwrap();
    let write = |b: &[u8]| {
        let tmp = publish.path().join("bundles/.tmp");
        fs::write(&tmp, b).unwrap();
        fs::rename(tmp, publish.path().join(format!("bundles/{site}.bundle"))).unwrap();
    };
    write(&sign(&site_bundle(site, 1, &[("datacenter-asns", art)])));
    let root = Source::parse(&format!("file://{}/", publish.path().display())).unwrap();
    let h = start(site, root, Arc::clone(&dir), None);
    wait_for("v1", || h.rec.versions() == [1]).await;
    // Polled, not slept: a loaded machine may need more than a few
    // intervals for two unchanged polls.
    wait_for("unchanged polls", || h.reloads("unchanged") >= 2).await;
    assert_eq!(
        h.rec.versions(),
        [1],
        "an unchanged file is never re-applied"
    );
    write(&sign(&site_bundle(site, 2, &[("datacenter-asns", art)])));
    wait_for("v2", || h.rec.versions() == [1, 2]).await;
    h.stop().await;
}

/// §9.10: fetch errors count `mg_config_fetch_failures_total` and age
/// `mg_config_age_seconds`; the loop keeps going.
#[tokio::test]
async fn fetch_failures_are_counted() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("failures");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-failures";
    server.set(&format!("bundles/{site}.bundle"), Reply::Status(503));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("failures", || h.fetch_failures() >= 3).await;
    let age = metrics().config_age_seconds.get(site).unwrap();
    assert!(age > 0.0, "age {age}");
    // §9.10: the exported value is `now - last_fetch_ok` at scrape time.
    let scraped = scraped_age(site);
    assert!(scraped >= age, "scraped {scraped} < {age}");
    assert_eq!(h.version_gauge(), 0);
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[])));
    wait_for("v1", || h.rec.versions() == [1]).await;
    h.stop().await;
}

/// Shutdown interrupts an in-flight fetch.
#[tokio::test]
async fn shutdown_interrupts_a_slow_fetch() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("shutdown");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-shutdown";
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[])));
    server.set_delay(&format!("bundles/{site}.bundle"), Duration::from_secs(30));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("request in flight", || {
        server.hits(&format!("bundles/{site}.bundle")) == 1
    })
    .await;
    let started = Instant::now();
    h.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// §9.10 "version > current.version": a newer immediate version supersedes a
/// pending one (which is then never applied), and a candidate that is not
/// newer than the pending bundle is rejected.
#[tokio::test]
async fn pending_bundle_is_superseded_and_never_rolled_back() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("pending-order");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-pending-order";
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[])));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;

    // v4 pending; v3 (immediate, older than the pending one) is rejected.
    let due = now_ms() + 1_500;
    let mut b4 = site_bundle(site, 4, &[]);
    b4.not_before_ms = due;
    let v4 = sign(&b4);
    server.publish_bundle(site, &v4);
    let hits = server.hits(&format!("bundles/{site}.bundle"));
    wait_for("v4 fetched", || {
        server.hits(&format!("bundles/{site}.bundle")) > hits + 1
    })
    .await;
    server.publish_bundle(site, &sign(&site_bundle(site, 3, &[])));
    wait_for("v3 rejected", || h.reloads("rejected") == 1).await;
    assert_eq!(h.rec.versions(), [1]);

    // v5 (immediate) supersedes the pending v4, which is never applied.
    let v5 = sign(&site_bundle(site, 5, &[]));
    server.publish_bundle(site, &v5);
    wait_for("v5", || h.rec.versions() == [1, 5]).await;
    while now_ms() < due + 200 {
        tokio::time::sleep(INTERVAL).await;
    }
    settle().await;
    assert_eq!(h.rec.versions(), [1, 5], "the superseded v4 was applied");
    assert_eq!(dir.read_lkg(site).unwrap().as_deref(), Some(v5.as_slice()));
    assert_eq!(h.version_gauge(), 5);
    h.stop().await;
}

/// §9.10 "pending 配置包引用的文件也保留": several sites share one artifact
/// cache; another site's cleanup never deletes an artifact that only a
/// pending bundle refers to, but does delete unreferenced files.
#[tokio::test]
async fn cache_cleanup_keeps_another_sites_pending_artifacts() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("shared-cache");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let (site_a, site_b) = ("poll-shared-a", "poll-shared-b");
    let root = || Source::parse(&server.root()).unwrap();

    server.publish_bundle(site_a, &sign(&site_bundle(site_a, 1, &[])));
    let a = start(site_a, root(), Arc::clone(&dir), None);
    wait_for("a v1", || a.rec.versions() == [1]).await;

    // Site A: v2 is pending and refers to an artifact no LKG refers to.
    let pending_art = b"198.51.100.40\n".as_slice();
    server.publish_artifact(pending_art);
    let due = now_ms() + 2_000;
    let mut a2 = site_bundle(site_a, 2, &[("tor-exits", pending_art)]);
    a2.not_before_ms = due;
    server.publish_bundle(site_a, &sign(&a2));
    let pending_sha = sha256_hex(pending_art);
    wait_for("pending artifact cached", || {
        dir.artifact(&pending_sha).unwrap().is_some()
    })
    .await;

    // An orphan that nothing refers to.
    let orphan = b"AS64999\n".as_slice();
    dir.store_artifact(&sha256_hex(orphan), orphan).unwrap();

    // Site B applies a bundle, which runs the cache cleanup.
    let b_art = b"AS64520\n".as_slice();
    server.publish_artifact(b_art);
    server.publish_bundle(
        site_b,
        &sign(&site_bundle(site_b, 1, &[("datacenter-asns", b_art)])),
    );
    let b = start(site_b, root(), Arc::clone(&dir), None);
    wait_for("b v1", || b.rec.versions() == [1]).await;
    wait_for("orphan removed", || {
        dir.artifact(&sha256_hex(orphan)).unwrap().is_none()
    })
    .await;
    assert!(
        now_ms() < due,
        "test too slow: site A's bundle is no longer pending"
    );
    assert!(
        dir.artifact(&pending_sha).unwrap().is_some(),
        "site B's cleanup deleted site A's pending artifact"
    );
    assert!(dir.artifact(&sha256_hex(b_art)).unwrap().is_some());

    // When due, site A applies v2 with the artifact.
    wait_for("a v2", || a.rec.versions() == [1, 2]).await;
    assert_eq!(a.rec.last_artifacts()["tor-exits"], pending_art);
    a.stop().await;
    b.stop().await;
}

/// The loop stops only when shutdown is requested (`true`) or the sender
/// is gone; a `false` value is not a shutdown request.
#[tokio::test]
async fn shutdown_only_on_true() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("shutdown-false");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-shutdown-false";
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[])));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;
    h.stop.send(false).unwrap();
    settle().await;
    assert!(!h.task.is_finished(), "a false value stopped the loop");
    server.publish_bundle(site, &sign(&site_bundle(site, 2, &[])));
    wait_for("v2", || h.rec.versions() == [1, 2]).await;
    h.stop().await;
}

/// §12.4: an empty text list is a valid artifact (0 bytes, the SHA-256 of
/// the empty string); the bundle applies with the empty file.
#[tokio::test]
async fn empty_text_artifact_is_applied() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("empty-artifact");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-empty-artifact";
    server.publish_artifact(b"");
    server.publish_bundle(site, &sign(&site_bundle(site, 1, &[("tor-exits", b"")])));
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        None,
    );
    wait_for("v1", || h.rec.versions() == [1]).await;
    assert_eq!(h.rec.last_artifacts()["tor-exits"], b"");
    assert_eq!(dir.artifact(&sha256_hex(b"")).unwrap(), Some(Vec::new()));
    assert_eq!(h.reloads("rejected"), 0);
    h.stop().await;
}

/// While an artifact of the bundle in effect stays unavailable, each poll
/// only retries that artifact: the artifacts the runtime already has (up to
/// 128 MiB each) are not re-read and re-hashed on every poll. Observable
/// here because reading a cached file whose content no longer matches its
/// name removes it.
#[tokio::test]
async fn missing_artifact_retries_do_not_reread_the_cache() {
    let server = HttpServer::start().unwrap();
    let tmp = TempDir::new("no-reread");
    let dir = Arc::new(StateDir::new(tmp.path()));
    let site = "poll-no-reread";
    let (had, missing) = (b"AS64530\n".as_slice(), b"198.51.100.30\n".as_slice());
    let v1 = sign(&site_bundle(
        site,
        1,
        &[("datacenter-asns", had), ("tor-exits", missing)],
    ));
    dir.store_artifact(&sha256_hex(had), had).unwrap();
    let current = verify_bundle(&v1, &owner_test_keys(), site, &hosts()).unwrap();
    server.publish_bundle(site, &v1);
    let h = start(
        site,
        Source::parse(&server.root()).unwrap(),
        Arc::clone(&dir),
        Some(current),
    );
    wait_for("missing gauge", || h.missing_gauge("tor-exits") == 1).await;
    let cached = tmp.path().join("artifacts").join(sha256_hex(had));
    fs::write(&cached, b"AS64531\n").unwrap();
    let sha = sha256_hex(missing);
    let hits = server.hits(&format!("artifacts/{sha}"));
    wait_for("retries", || {
        server.hits(&format!("artifacts/{sha}")) >= hits + 3
    })
    .await;
    assert!(cached.exists(), "a present artifact was re-read on a retry");
    h.stop().await;
}

/// `mg_config_age_seconds{site}` as the default registry exports it (text
/// exposition format, which is stable whichever prometheus features the
/// workspace build unifies).
fn scraped_age(site: &str) -> f64 {
    use prometheus::Encoder as _;
    let mut text = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&prometheus::gather(), &mut text)
        .unwrap();
    let prefix = format!("mg_config_age_seconds{{site=\"{site}\"}} ");
    String::from_utf8(text)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .expect("mg_config_age_seconds{site} is exported")
        .parse()
        .unwrap()
}
