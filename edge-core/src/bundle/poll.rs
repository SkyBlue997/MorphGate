//! One site's poll loop (§9.10 "every bundle_poll_seconds ...").

use super::BundleError;
use super::fetch::{Fetched, Fetcher, Source};
use super::keys::OwnerKeys;
use super::metrics::metrics;
use super::store::StateDir;
use super::util::sha256;
use super::verify::{VerifiedBundle, verify_bundle};
use mg_proto::v1::ArtifactRef;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

/// One site as the poll loop sees it.
#[derive(Debug, Clone)]
pub struct SiteSource {
    /// Site id (edge.toml `[[sites]].id`).
    pub site: String,
    /// edge.toml `hosts`; a bundle must carry exactly these (as a set).
    pub hosts: Vec<String>,
    /// edge.toml `bundle_root`.
    pub root: Source,
    /// edge.toml `bundle_poll_seconds`; each wait is jittered by ±20 %.
    pub interval: Duration,
    /// The bundle `main()` put into effect from the LKG file (state
    /// `active`), or `None` (`bootstrap`, `lkg_invalid`). Candidates must
    /// have a higher version. Artifacts it references that are not in the
    /// cache are fetched on every poll until they arrive, and `apply` is
    /// called again with them (§9.10).
    pub current: Option<VerifiedBundle>,
}

/// One site's poll loop; calls `apply` with each new verified candidate (the caller converts it with
/// mg-core / mg-challenge / mg-intel and swaps the runtime). Runs until `shutdown` fires.
///
/// Per poll (the first one immediately, then every `interval` ± 20 %, drawn
/// from the OS CSPRNG):
///
/// 1. A pending bundle whose `not_before_ms` has passed is applied.
/// 2. `fetch_bundle` with the last ETag. Failure: `mg_config_fetch_failures_total`.
///    304, or the same SHA-256 as the bundle in effect, the pending one or
///    the last rejected one: `unchanged`.
/// 3. A new body is verified ([`verify_bundle`]) and must have a higher
///    `version` than the bundle in effect and the pending one. Its artifacts
///    come from the cache or `<root>artifacts/<sha256>` (SHA-256 and size
///    checked, stored in the cache). A candidate whose `not_before_ms` is in
///    the future becomes the pending bundle; otherwise `apply(bundle,
///    artifacts by ArtifactRef.name)` runs. On `Ok` the signed bytes become
///    the LKG, the cache is garbage-collected and the result is `applied`;
///    any failure is `rejected` and the bundle in effect stays.
/// 4. Missing artifacts of the bundle in effect are fetched; if any arrives,
///    `apply` runs again with the same bundle and every artifact now
///    available (the map lacks the ones still missing).
///
/// `apply` is synchronous and must not block for long: it runs on the
/// runtime of the caller's background service.
pub async fn poll_loop(
    site: SiteSource,
    fetcher: Arc<Fetcher>,
    dir: Arc<StateDir>,
    keys: Arc<OwnerKeys>,
    apply: impl Fn(VerifiedBundle, BTreeMap<String, Vec<u8>>) -> Result<(), String> + Send + Sync,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut poller = Poller::new(site, fetcher, dir, keys, &apply);
    tokio::select! {
        () = poller.init() => {}
        () = shutdown_requested(&mut shutdown) => return,
    }
    loop {
        tokio::select! {
            () = poller.tick() => {}
            () = shutdown_requested(&mut shutdown) => return,
        }
        let wait = poller.next_wait();
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = shutdown_requested(&mut shutdown) => return,
        }
    }
}

/// Resolves once `shutdown` holds `true` (immediately if it already does) or
/// its sender is gone; a change to `false` is not a shutdown request.
async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    // `Err` means the sender was dropped: nobody can ask any more, stop.
    let _ = shutdown.wait_for(|stop| *stop).await;
}

type ApplyFn<'a> =
    dyn Fn(VerifiedBundle, BTreeMap<String, Vec<u8>>) -> Result<(), String> + Send + Sync + 'a;

/// The bundle in effect.
struct Current {
    vb: VerifiedBundle,
    /// `ArtifactRef.name`s not in the cache.
    missing: BTreeSet<String>,
}

/// A verified bundle waiting for its `not_before_ms`.
struct Pending {
    vb: VerifiedBundle,
    artifacts: BTreeMap<String, Vec<u8>>,
}

struct Poller<'a> {
    source: SiteSource,
    fetcher: Arc<Fetcher>,
    dir: Arc<StateDir>,
    keys: Arc<OwnerKeys>,
    apply: &'a ApplyFn<'a>,
    current: Option<Current>,
    pending: Option<Pending>,
    /// ETag of the last response that was fully processed.
    etag: Option<String>,
    /// SHA-256 of the last body that was applied, made pending or rejected
    /// for good; the same bytes are not processed (or logged) again.
    seen: Option<[u8; 32]>,
}

impl<'a> Poller<'a> {
    fn new(
        mut source: SiteSource,
        fetcher: Arc<Fetcher>,
        dir: Arc<StateDir>,
        keys: Arc<OwnerKeys>,
        apply: &'a ApplyFn<'a>,
    ) -> Self {
        let current = source.current.take().map(|vb| Current {
            vb,
            missing: BTreeSet::new(),
        });
        Self {
            source,
            fetcher,
            dir,
            keys,
            apply,
            current,
            pending: None,
            etag: None,
            seen: None,
        }
    }

    fn site(&self) -> &str {
        &self.source.site
    }

    /// Start-up bookkeeping: version gauge, and which artifacts of the
    /// bundle in effect are missing from the cache.
    async fn init(&mut self) {
        let m = metrics();
        let site = self.source.site.clone();
        m.config_age_seconds.mark(&site);
        let Some(cur) = &self.current else {
            m.config_version.with_label_values(&[site.as_str()]).set(0);
            return;
        };
        m.config_version
            .with_label_values(&[site.as_str()])
            .set(i64::try_from(cur.vb.bundle.version).unwrap_or(i64::MAX));
        let mut missing = BTreeSet::new();
        for r in &cur.vb.bundle.artifacts {
            if !matches!(self.cached(&r.sha256).await, Some(b) if b.len() as u64 == r.size) {
                missing.insert(r.name.clone());
                m.artifact_missing
                    .with_label_values(&[site.as_str(), r.name.as_str()])
                    .set(1);
            }
        }
        if let Some(cur) = &mut self.current {
            cur.missing = missing;
        }
        self.protect(None);
    }

    async fn tick(&mut self) {
        let m = metrics();
        let site = self.source.site.clone();

        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.vb.bundle.not_before_ms <= now_ms())
            && let Some(p) = self.pending.take()
        {
            self.commit(p.vb, p.artifacts).await;
        }

        let etag = self.etag.clone();
        match self
            .fetcher
            .fetch_bundle(&self.source.root, &site, etag.as_deref())
            .await
        {
            Err(e) => {
                m.config_fetch_failures_total
                    .with_label_values(&[site.as_str()])
                    .inc();
                log::warn!("bundle {site}: fetch failed: {e}");
            }
            Ok(Fetched::NotModified) => {
                m.config_age_seconds.mark(&site);
                m.config_reload_total
                    .with_label_values(&[site.as_str(), "unchanged"])
                    .inc();
            }
            Ok(Fetched::Body { bytes, etag }) => {
                m.config_age_seconds.mark(&site);
                let digest = sha256(&bytes);
                let known = self.current.as_ref().map(|c| c.vb.sha256) == Some(digest)
                    || self.pending.as_ref().map(|p| p.vb.sha256) == Some(digest)
                    || self.seen == Some(digest);
                if known {
                    self.etag = Some(etag).filter(|t| !t.is_empty());
                    m.config_reload_total
                        .with_label_values(&[site.as_str(), "unchanged"])
                        .inc();
                } else {
                    self.candidate(bytes, digest, etag).await;
                }
            }
        }

        self.retry_missing().await;
    }

    /// Step 3: a body that differs from everything known.
    async fn candidate(&mut self, bytes: Vec<u8>, digest: [u8; 32], etag: String) {
        let site = self.source.site.clone();
        let vb = match verify_bundle(&bytes, &self.keys, &site, &self.source.hosts) {
            Ok(vb) => vb,
            Err(e) => return self.reject_for_good(digest, etag, &e.to_string()),
        };
        let version = vb.bundle.version;
        if let Some(cur) = &self.current
            && version <= cur.vb.bundle.version
        {
            let why = format!(
                "version {version} is not newer than {}",
                cur.vb.bundle.version
            );
            return self.reject_for_good(digest, etag, &why);
        }
        if let Some(p) = &self.pending
            && version <= p.vb.bundle.version
        {
            let why = format!(
                "version {version} is not newer than pending {}",
                p.vb.bundle.version
            );
            return self.reject_for_good(digest, etag, &why);
        }

        self.protect(Some(&vb));
        let artifacts = match self.collect_artifacts(&vb).await {
            Ok(a) => a,
            Err(e) => {
                // Transient or not, retry these bytes on the next poll: keep
                // neither the ETag nor the digest.
                let m = metrics();
                if e.is_fetch_failure() {
                    m.config_fetch_failures_total
                        .with_label_values(&[site.as_str()])
                        .inc();
                } else {
                    m.config_reload_total
                        .with_label_values(&[site.as_str(), "rejected"])
                        .inc();
                }
                log::warn!("bundle {site}: version {version} rejected: artifact: {e}");
                self.protect(None);
                return;
            }
        };
        self.seen = Some(digest);
        self.etag = Some(etag).filter(|t| !t.is_empty());

        if vb.bundle.not_before_ms > now_ms() {
            log::info!(
                "bundle {site}: version {version} verified, pending until not_before_ms {}",
                vb.bundle.not_before_ms
            );
            self.pending = Some(Pending { vb, artifacts });
            self.protect(None);
            return;
        }
        self.commit(vb, artifacts).await;
    }

    fn reject_for_good(&mut self, digest: [u8; 32], etag: String, why: &str) {
        let site = self.site();
        metrics()
            .config_reload_total
            .with_label_values(&[site, "rejected"])
            .inc();
        log::warn!("bundle {site}: candidate rejected: {why}");
        self.seen = Some(digest);
        self.etag = Some(etag).filter(|t| !t.is_empty());
    }

    /// Artifacts of `vb` by name, from the cache or the source; each must
    /// match the reference's SHA-256 and size.
    async fn collect_artifacts(
        &self,
        vb: &VerifiedBundle,
    ) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
        let mut out = BTreeMap::new();
        for r in &vb.bundle.artifacts {
            let bytes = match self.cached(&r.sha256).await {
                Some(bytes) => bytes,
                None => self.download(&r.sha256, r.size).await?,
            };
            if bytes.len() as u64 != r.size {
                return Err(BundleError::Artifact {
                    sha256: r.sha256.clone(),
                    reason: format!("{} bytes, the bundle says {}", bytes.len(), r.size),
                });
            }
            out.insert(r.name.clone(), bytes);
        }
        Ok(out)
    }

    /// The cached artifact, or `None` if absent or unreadable (the caller
    /// then downloads it).
    async fn cached(&self, sha256_hex: &str) -> Option<Vec<u8>> {
        let dir = Arc::clone(&self.dir);
        let sha = sha256_hex.to_string();
        match tokio::task::spawn_blocking(move || dir.artifact(&sha)).await {
            Ok(Ok(found)) => found,
            Ok(Err(e)) => {
                log::warn!("bundle {}: artifact cache read failed: {e}", self.site());
                None
            }
            Err(e) => {
                log::warn!("bundle {}: artifact cache task failed: {e}", self.site());
                None
            }
        }
    }

    /// Fetches an artifact and stores it in the cache (a cache write failure
    /// is logged, not fatal: the bytes are in memory).
    async fn download(&self, sha256_hex: &str, size: u64) -> Result<Vec<u8>, BundleError> {
        let bytes = self
            .fetcher
            .fetch_artifact(&self.source.root, sha256_hex, size)
            .await?;
        let dir = Arc::clone(&self.dir);
        let sha = sha256_hex.to_string();
        let copy = bytes.clone();
        match tokio::task::spawn_blocking(move || dir.store_artifact(&sha, &copy)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!(
                "bundle {}: cannot cache artifact {sha256_hex}: {e}",
                self.site()
            ),
            Err(e) => log::warn!("bundle {}: artifact cache task failed: {e}", self.site()),
        }
        Ok(bytes)
    }

    /// Applies `vb`, persists it as the LKG and cleans the cache.
    async fn commit(&mut self, vb: VerifiedBundle, artifacts: BTreeMap<String, Vec<u8>>) {
        let m = metrics();
        let site = self.source.site.clone();
        let version = vb.bundle.version;
        if let Err(why) = (self.apply)(vb.clone(), artifacts) {
            m.config_reload_total
                .with_label_values(&[site.as_str(), "rejected"])
                .inc();
            log::warn!("bundle {site}: version {version} rejected by the runtime: {why}");
            self.protect(None);
            return;
        }

        let dir = Arc::clone(&self.dir);
        let (lkg_site, bytes) = (site.clone(), vb.bytes.clone());
        match tokio::task::spawn_blocking(move || dir.write_lkg(&lkg_site, &bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                log::error!("bundle {site}: version {version} applied but not persisted: {e}")
            }
            Err(e) => log::error!("bundle {site}: LKG write task failed: {e}"),
        }

        if let Some(old) = self.current.take() {
            for name in &old.missing {
                m.artifact_missing
                    .with_label_values(&[site.as_str(), name.as_str()])
                    .set(0);
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.vb.bundle.version <= version)
        {
            self.pending = None;
        }
        log::info!(
            "bundle {site}: version {version} applied (sha256 {})",
            vb.sha256_hex()
        );
        self.current = Some(Current {
            vb,
            missing: BTreeSet::new(),
        });
        m.config_reload_total
            .with_label_values(&[site.as_str(), "applied"])
            .inc();
        m.config_version
            .with_label_values(&[site.as_str()])
            .set(i64::try_from(version).unwrap_or(i64::MAX));

        self.protect(None);
        let keep = self.needed(None);
        let dir = Arc::clone(&self.dir);
        match tokio::task::spawn_blocking(move || dir.gc(&keep)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => log::info!("bundle {site}: removed {n} unused cached artifacts"),
            Ok(Err(e)) => log::warn!("bundle {site}: artifact cache cleanup failed: {e}"),
            Err(e) => log::warn!("bundle {site}: artifact cache cleanup task failed: {e}"),
        }
    }

    /// Step 4: fetch artifacts of the bundle in effect that were missing
    /// from the cache, and rebuild the runtime once any of them arrives.
    ///
    /// Only the missing artifacts are retried on every poll; the ones the
    /// runtime already has (up to 128 MiB each) are read from the cache
    /// again only for an actual rebuild.
    async fn retry_missing(&mut self) {
        let Some(cur) = &self.current else { return };
        if cur.missing.is_empty() {
            return;
        }
        let site = self.source.site.clone();
        let refs = cur.vb.bundle.artifacts.clone();
        let old_missing = cur.missing.clone();

        let mut available = BTreeMap::new();
        for r in refs.iter().filter(|r| old_missing.contains(&r.name)) {
            if let Some(bytes) = self.obtain(r).await {
                available.insert(r.name.clone(), bytes);
            }
        }
        if available.is_empty() {
            return;
        }
        let arrived: Vec<String> = available.keys().cloned().collect();
        let still_missing: BTreeSet<String> = old_missing
            .iter()
            .filter(|n| !available.contains_key(*n))
            .cloned()
            .collect();
        for r in refs.iter().filter(|r| !old_missing.contains(&r.name)) {
            match self.obtain(r).await {
                Some(bytes) => {
                    available.insert(r.name.clone(), bytes);
                }
                None => {
                    // The runtime has it (it was cached at start) but it is
                    // neither cached nor fetchable any more: a rebuild would
                    // drop it, so keep the runtime until the cache is whole.
                    log::warn!(
                        "bundle {site}: not rebuilding: cached artifact {} vanished and cannot be fetched",
                        r.name
                    );
                    return;
                }
            }
        }

        let m = metrics();
        let Some(cur) = &mut self.current else { return };
        let version = cur.vb.bundle.version;
        match (self.apply)(cur.vb.clone(), available) {
            Ok(()) => {
                for name in &arrived {
                    m.artifact_missing
                        .with_label_values(&[site.as_str(), name.as_str()])
                        .set(0);
                }
                log::info!(
                    "bundle {site}: version {version} rebuilt with {} newly cached artifacts",
                    arrived.len()
                );
                cur.missing = still_missing;
            }
            Err(why) => {
                log::warn!(
                    "bundle {site}: rebuild of version {version} with fetched artifacts failed: {why}"
                );
            }
        }
    }

    /// One artifact of the bundle in effect, from the cache or the source,
    /// with the reference's size; `None` (logged, fetch failures counted) if
    /// it cannot be obtained.
    async fn obtain(&self, r: &ArtifactRef) -> Option<Vec<u8>> {
        let bytes = match self.cached(&r.sha256).await {
            Some(bytes) => bytes,
            None => match self.download(&r.sha256, r.size).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    if e.is_fetch_failure() {
                        metrics()
                            .config_fetch_failures_total
                            .with_label_values(&[self.site()])
                            .inc();
                    }
                    log::warn!(
                        "bundle {}: artifact {} unavailable: {e}",
                        self.site(),
                        r.name
                    );
                    return None;
                }
            },
        };
        (bytes.len() as u64 == r.size).then_some(bytes)
    }

    /// Artifact hashes of the bundle in effect, the pending one and `extra`.
    fn needed(&self, extra: Option<&VerifiedBundle>) -> BTreeSet<String> {
        self.current
            .as_ref()
            .map(|c| &c.vb)
            .into_iter()
            .chain(self.pending.as_ref().map(|p| &p.vb))
            .chain(extra)
            .flat_map(|vb| vb.bundle.artifacts.iter().map(|a| a.sha256.clone()))
            .collect()
    }

    fn protect(&self, extra: Option<&VerifiedBundle>) {
        self.dir.protect(self.site(), self.needed(extra));
    }

    /// The jittered poll interval, shortened to the pending bundle's
    /// activation time.
    fn next_wait(&self) -> Duration {
        let mut wait = jittered(self.source.interval);
        if let Some(p) = &self.pending {
            let until =
                u64::try_from(p.vb.bundle.not_before_ms.saturating_sub(now_ms())).unwrap_or(0);
            wait = wait.min(Duration::from_millis(until));
        }
        wait
    }
}

/// `interval` × uniform [0.8, 1.2], from the OS CSPRNG (§2.4 item 6); the
/// plain interval if the RNG fails.
fn jittered(interval: Duration) -> Duration {
    match getrandom::u32() {
        Ok(r) => interval.mul_f64(0.8 + 0.4 * (f64::from(r) / f64::from(u32::MAX))),
        Err(_) => interval,
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = Duration::from_secs(10);
        for _ in 0..1000 {
            let w = jittered(base);
            assert!(
                w >= Duration::from_secs(8) && w <= Duration::from_secs(12),
                "{w:?}"
            );
        }
    }
}
