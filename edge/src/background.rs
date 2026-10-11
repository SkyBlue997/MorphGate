//! Pingora background services (docs/impl/phase1-spec.md §9.1.1).
//!
//! Pingora forks (daemon mode, `-d`) before it creates the per-service tokio
//! runtimes, so every async client and loop lives here and starts only once
//! the service runs: nothing created before the fork is needed. `main()`
//! prepares the inputs (runtime-free handles, channels, verified LKG
//! bundles) and each service takes them out of its `Mutex<Option<…>>` when
//! Pingora starts it (the trait gives the service only `&self`).
//!
//! | Service | Runs |
//! |---|---|
//! | `mg-bundles` | one `poll_loop` per site; `Site::apply` swaps the runtime |
//! | `mg-state` | `StateService::run`: all Valkey I/O (proxies use `StateHandle`) |
//! | `mg-events` | `Flusher::run`: VictoriaLogs (client built on this runtime), the file and `mg:ev` (through `mg-state`), each output on its own (I-25) |
//! | `mg-rdns` | the resolver (hickory or static) and one task per rDNS job |
//!
//! The proxies never wait for these services (§9.1.1 item 3): the state
//! handle falls back to local mode, events queue up, rDNS jobs are abandoned
//! until `mg-rdns` runs.

use crate::dns::ResolverSetup;
use crate::identity::{RdnsReceiver, execute};
use crate::sites::Site;
use async_trait::async_trait;
use mg_edge_core::bundle::{Fetcher, FetcherConfig, OwnerKeys, SiteSource, StateDir, poll_loop};
use mg_edge_core::events::{EventsConfig, Flusher, StreamWriter, VlClient};
use mg_edge_core::state::StateService;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How often a site forced to monitor is logged again (Phase 2 spec §9.6).
pub const FORCED_MONITOR_REMINDER: Duration = Duration::from_secs(3600);

/// Capacity of the rDNS submission queue (a full queue drops the job,
/// §9.6).
pub const RDNS_QUEUE_CAPACITY: usize = 1024;

fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// What `mg-bundles` needs.
pub struct BundleWork {
    pub fetcher: FetcherConfig,
    pub dir: Arc<StateDir>,
    pub keys: Arc<OwnerKeys>,
    /// Each site's poll-loop source (with the LKG in effect as `current`)
    /// and the site it applies to.
    pub sites: Vec<(SiteSource, Arc<Site>)>,
}

impl fmt::Debug for BundleWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleWork")
            .field("fetcher", &self.fetcher)
            .field("sites", &self.sites.len())
            .finish_non_exhaustive()
    }
}

/// `mg-bundles`: every site's poll loop (§9.10).
#[derive(Debug)]
pub struct BundleService(Mutex<Option<BundleWork>>);

impl BundleService {
    pub fn new(work: BundleWork) -> Self {
        Self(Mutex::new(Some(work)))
    }
}

#[async_trait]
impl BackgroundService for BundleService {
    async fn start(&self, shutdown: ShutdownWatch) {
        let Some(work) = take(&self.0) else { return };
        // Built on this service's runtime (§9.1.1); the configuration was
        // already checked at start-up, so this only fails on a broken host.
        let fetcher = match Fetcher::new(&work.fetcher) {
            Ok(f) => Arc::new(f),
            Err(e) => {
                log::error!("mg-bundles: cannot build the bundle client: {e}; no bundle updates");
                return;
            }
        };
        let mut loops = tokio::task::JoinSet::new();
        // D-60: an hourly reminder while a site is forced to monitor.
        let forced: Vec<String> = work
            .sites
            .iter()
            .filter(|(_, s)| s.settings.force_monitor)
            .map(|(_, s)| s.settings.id.clone())
            .collect();
        if !forced.is_empty() {
            let mut shutdown = shutdown.clone();
            loops.spawn(async move {
                let mut tick = tokio::time::interval(FORCED_MONITOR_REMINDER);
                tick.tick().await; // the start-up WARN was the first one
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            for site in &forced {
                                log::warn!("{}", crate::startup::forced_monitor_warning(site));
                            }
                        }
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                    }
                }
            });
        }
        for (source, site) in work.sites {
            let apply = move |vb, artifacts| site.apply(&vb, &artifacts);
            loops.spawn(poll_loop(
                source,
                Arc::clone(&fetcher),
                Arc::clone(&work.dir),
                Arc::clone(&work.keys),
                apply,
                shutdown.clone(),
            ));
        }
        while let Some(done) = loops.join_next().await {
            if let Err(e) = done {
                log::error!("mg-bundles: a poll loop ended abnormally: {e}");
            }
        }
    }
}

/// `mg-state`: the Valkey connection, scripts, breaker and the async
/// failure consumer (§9.7).
#[derive(Debug)]
pub struct StateBackground(Mutex<Option<StateService>>);

impl StateBackground {
    pub fn new(service: StateService) -> Self {
        Self(Mutex::new(Some(service)))
    }
}

#[async_trait]
impl BackgroundService for StateBackground {
    async fn start(&self, shutdown: ShutdownWatch) {
        if let Some(service) = take(&self.0) {
            service.run(shutdown).await;
        }
    }
}

/// `mg-events`: the event flusher (§9.11, ruling I-25). Its `mg:ev` output
/// is the state layer (`StateHandle`), so the `XADD` pipelines run on the
/// `mg-state` runtime; it exists only with `[valkey] mode = "valkey"`
/// (without Valkey there is no stream, and nothing is counted as lost).
pub struct EventsBackground {
    flusher: Mutex<Option<Flusher>>,
    cfg: EventsConfig,
    stream: Option<Arc<dyn StreamWriter>>,
    /// The proxies' requests in flight (I-52).
    inflight: Arc<AtomicUsize>,
    /// The shutdown drain (Phase 2 spec §9.7).
    drain: Duration,
}

impl fmt::Debug for EventsBackground {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventsBackground")
            .field("cfg", &self.cfg)
            .field("stream", &self.stream.is_some())
            .finish_non_exhaustive()
    }
}

impl EventsBackground {
    /// `stream`: the `mg:ev` writer, `None` without Valkey; `inflight`: the
    /// proxies' request count; `drain`: the shutdown drain.
    pub fn new(
        flusher: Flusher,
        cfg: EventsConfig,
        stream: Option<Arc<dyn StreamWriter>>,
        inflight: Arc<AtomicUsize>,
        drain: Duration,
    ) -> Self {
        Self {
            flusher: Mutex::new(Some(flusher)),
            cfg,
            stream,
            inflight,
            drain,
        }
    }
}

#[async_trait]
impl BackgroundService for EventsBackground {
    async fn start(&self, shutdown: ShutdownWatch) {
        let Some(flusher) = take(&self.flusher) else {
            return;
        };
        // The HTTP client must be built on this runtime (§9.1.1).
        let vl = match VlClient::from_config(&self.cfg) {
            Ok(vl) => vl,
            Err(e) => {
                log::error!("mg-events: VictoriaLogs sinks disabled: {e}");
                None
            }
        };
        // Ruling I-52: the flusher's drain ends as soon as everything handed
        // to it was delivered, so it hears of the shutdown only once the
        // proxies have finished their requests (or the drain time is up).
        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let inflight = Arc::clone(&self.inflight);
        let drain = self.drain;
        tokio::spawn(async move {
            gate_after_requests(shutdown, &inflight, drain).await;
            let _ = gate_tx.send(true);
        });
        flusher
            .run(vl, self.cfg.file.clone(), self.stream.clone(), gate_rx)
            .await;
    }
}

/// How often the shutdown gate looks at the in-flight count.
const INFLIGHT_POLL: Duration = Duration::from_millis(5);

/// Returns once Pingora's shutdown has started and then either no request
/// is in flight or `drain` has passed (I-52, Phase 2 spec §9.7).
pub async fn gate_after_requests(
    mut shutdown: ShutdownWatch,
    inflight: &AtomicUsize,
    drain: Duration,
) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
    let deadline = tokio::time::Instant::now() + drain;
    while inflight.load(Ordering::Acquire) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(INFLIGHT_POLL).await;
    }
}

/// `mg-rdns` (§9.1.1, §9.6): builds the resolver on its own runtime, marks
/// the dispatcher running, and runs every submitted job in its own task
/// ([`crate::identity::execute`]; the dispatcher already bounds how many are
/// in flight). On shutdown it stops accepting jobs; queued and running jobs
/// are dropped, which abandons them on their verifiers.
pub struct RdnsBackground {
    receiver: Mutex<Option<RdnsReceiver>>,
    setup: ResolverSetup,
    deadline: Duration,
}

impl fmt::Debug for RdnsBackground {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdnsBackground")
            .field("setup", &self.setup)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl RdnsBackground {
    /// `deadline`: the whole-job deadline (`crate::dns::job_deadline`).
    pub fn new(receiver: RdnsReceiver, setup: ResolverSetup, deadline: Duration) -> Self {
        Self {
            receiver: Mutex::new(Some(receiver)),
            setup,
            deadline,
        }
    }
}

#[async_trait]
impl BackgroundService for RdnsBackground {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(mut receiver) = take(&self.receiver) else {
            return;
        };
        let resolver = match self.setup.build() {
            Ok(r) => r,
            Err(e) => {
                // Crawler claims stay `pending` (never verified); the jobs
                // are dropped and counted.
                log::error!("mg-rdns: {e}; rDNS verification disabled");
                return;
            }
        };
        receiver.set_running(true);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                task = receiver.rx.recv() => {
                    let Some(task) = task else { break };
                    let resolver = Arc::clone(&resolver);
                    let deadline = self.deadline;
                    tasks.spawn(async move {
                        execute(task, resolver.as_ref(), deadline).await;
                    });
                }
                Some(done) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(e) = done
                        && e.is_panic()
                    {
                        log::error!("mg-rdns: a job panicked (abandoned)");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        receiver.set_running(false);
        drop(receiver);
        tasks.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-52: the gate opens only after the shutdown signal, then once the
    /// requests in flight are done, or when the drain time is up.
    #[tokio::test]
    async fn shutdown_gate_waits_for_requests() {
        let inflight = Arc::new(AtomicUsize::new(1));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let count = Arc::clone(&inflight);
        let gate = tokio::spawn(async move {
            gate_after_requests(rx, &count, Duration::from_secs(5)).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!gate.is_finished(), "no shutdown yet");
        tx.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!gate.is_finished(), "a request is still in flight");
        inflight.store(0, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), gate)
            .await
            .unwrap()
            .unwrap();

        // The drain time bounds the wait.
        let stuck = AtomicUsize::new(3);
        let (tx, rx) = tokio::sync::watch::channel(false);
        tx.send(true).unwrap();
        let started = std::time::Instant::now();
        gate_after_requests(rx, &stuck, Duration::from_millis(100)).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
