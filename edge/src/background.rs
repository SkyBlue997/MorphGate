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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

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
    /// `stream`: the `mg:ev` writer, `None` without Valkey.
    pub fn new(flusher: Flusher, cfg: EventsConfig, stream: Option<Arc<dyn StreamWriter>>) -> Self {
        Self {
            flusher: Mutex::new(Some(flusher)),
            cfg,
            stream,
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
        flusher
            .run(vl, self.cfg.file.clone(), self.stream.clone(), shutdown)
            .await;
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
