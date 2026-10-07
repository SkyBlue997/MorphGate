//! `StateService` (the `mg-state` background service) and `StateHandle`
//! (used by proxies), spec §9.1.1 and §9.7.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mg_core::gcra::GcraOutcome;
use redis::ConnectionInfo;
use redis::aio::ConnectionManager;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, timeout_at};

use super::health::{Backoff, Health};
use super::local::{LocalGcra, NonceInsert, NonceSet, PreparedLimit, lock};
use super::valkey::{self, Scripts, StreamBatch};
use super::verdicts::VerdictCache;
use super::{
    FAILURE_QUEUE_CAPACITY, LimitCheck, MAX_NONCE_TTL_MS, NonceIssue, NonceResult,
    REQUEST_QUEUE_CAPACITY, RoundTrip1, RoundTrip1Result, StateConfig, StateError, StateMode,
    VERDICT_CACHE_CAPACITY, VERDICT_CACHE_TTL_MS, metrics, nonce_key, unix_now_ms, unix_now_us,
};

/// Timeout of `xadd_batch` (not on the request path).
const STREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Response timeout of the redis connection itself: a backstop behind the
/// per-request deadlines, long enough for a full `XADD` batch.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Period of the local-table cleanup.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

type Reply<T> = oneshot::Sender<Result<T, StateError>>;

/// A request from a proxy to the `mg-state` service.
enum Job {
    RoundTrip1 {
        mget: Vec<String>,
        limits: Vec<PreparedLimit>,
        deadline: Instant,
        reply: Reply<(Vec<Option<String>>, Vec<GcraOutcome>)>,
    },
    Nonce {
        key: String,
        ttl_ms: u64,
        limits: Vec<PreparedLimit>,
        deadline: Instant,
        reply: Reply<Option<Vec<GcraOutcome>>>,
    },
    Xadd {
        maxlen: u64,
        entries: StreamBatch,
        deadline: Instant,
        reply: Reply<()>,
    },
}

impl Job {
    fn fail(self, e: StateError) {
        // A dropped receiver means the proxy already gave up; nothing to do.
        match self {
            Job::RoundTrip1 { reply, .. } => drop(reply.send(Err(e))),
            Job::Nonce { reply, .. } => drop(reply.send(Err(e))),
            Job::Xadd { reply, .. } => drop(reply.send(Err(e))),
        }
    }

    fn deadline(&self) -> Instant {
        match self {
            Job::RoundTrip1 { deadline, .. }
            | Job::Nonce { deadline, .. }
            | Job::Xadd { deadline, .. } => *deadline,
        }
    }
}

/// State shared by the handles and the service.
struct Core {
    mode: StateMode,
    timeout: Duration,
    connect_timeout: Duration,
    breaker_base: Duration,
    breaker_max: Duration,
    local_replay_authoritative: bool,
    process_start_ms: i64,
    k_pseudo: [u8; 32],
    gcra: LocalGcra,
    nonces: NonceSet,
    verdicts: VerdictCache,
    health: Health,
    scripts: Scripts,
}

impl Core {
    fn valkey_usable(&self) -> bool {
        self.mode == StateMode::Valkey && self.health.is_up()
    }

    fn prepare(&self, limits: &[LimitCheck]) -> Vec<PreparedLimit> {
        limits
            .iter()
            .map(|c| PreparedLimit::new(c, &self.k_pseudo))
            .collect()
    }

    /// Records the outcome of a Valkey operation in the breaker and the
    /// metrics. Every failure counts; a success resets the failure count only
    /// if it took at most `timeout_ms` (the request-path budget): the async
    /// failure consumer waits longer, and its slow successes must not keep a
    /// Valkey that is too slow for requests from ever tripping the breaker.
    fn settle<T>(
        &self,
        generation: u64,
        started: Instant,
        result: Result<Result<T, StateError>, tokio::time::error::Elapsed>,
    ) -> Result<T, StateError> {
        let result = result.unwrap_or(Err(StateError::Timeout));
        match &result {
            Ok(_) => {
                let elapsed = started.elapsed();
                if elapsed <= self.timeout {
                    self.health.success(generation);
                }
                metrics::get().valkey_rtt.observe(elapsed.as_secs_f64());
            }
            Err(_) => {
                self.health.failure(generation);
                metrics::get().valkey_error("pipeline");
            }
        }
        result
    }
}

/// The current connection and its generation.
type Slot = Arc<Mutex<Option<(ConnectionManager, u64)>>>;

/// Owns the Valkey connection; `mg-edge` runs [`StateService::run`] inside
/// the `mg-state` Pingora background service (spec §9.1.1).
pub struct StateService {
    core: Arc<Core>,
    jobs: mpsc::Receiver<Job>,
    failures: mpsc::Receiver<Vec<PreparedLimit>>,
    /// `Err`: valkey mode with an unusable URL (reported by `run`).
    conn_info: Option<Result<ConnectionInfo, StateError>>,
}

impl fmt::Debug for StateService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateService")
            .field("mode", &self.core.mode)
            .finish_non_exhaustive()
    }
}

/// Snapshot of the state layer, for metrics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateStatus {
    /// [`StateMode::Valkey`] iff Valkey is currently used.
    pub mode: StateMode,
    pub consecutive_failures: u32,
    /// Times the circuit breaker opened since start.
    pub trips: u64,
    /// Length of the current (or last) open period.
    pub open_ms: u64,
}

impl StateService {
    /// Synchronous and runtime-free: may be called in `main()` before
    /// Pingora daemonizes. Until [`StateService::run`] has connected, the
    /// handle works in local mode.
    pub fn new(cfg: StateConfig) -> (Self, StateHandle) {
        let conn_info = (cfg.mode == StateMode::Valkey).then(|| valkey::connection_info(&cfg));
        let core = Arc::new(Core {
            mode: cfg.mode,
            timeout: Duration::from_millis(cfg.timeout_ms.max(1)),
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms.max(1)),
            breaker_base: Duration::from_millis(cfg.breaker.base_open_ms.max(1)),
            breaker_max: Duration::from_millis(cfg.breaker.max_open_ms.max(1)),
            local_replay_authoritative: cfg.local_replay_authoritative,
            process_start_ms: cfg.process_start_ms,
            k_pseudo: cfg.k_pseudo,
            gcra: LocalGcra::new(cfg.local_limiter_capacity),
            nonces: NonceSet::new(cfg.local_nonce_capacity),
            verdicts: VerdictCache::new(
                VERDICT_CACHE_CAPACITY,
                Duration::from_millis(VERDICT_CACHE_TTL_MS),
            ),
            health: Health::new(cfg.breaker.failure_threshold),
            scripts: Scripts::new(),
        });
        metrics::get().set_mode(StateMode::Local);
        let (jobs_tx, jobs) = mpsc::channel(REQUEST_QUEUE_CAPACITY);
        let (failures_tx, failures) = mpsc::channel(FAILURE_QUEUE_CAPACITY);
        let handle = StateHandle {
            core: Arc::clone(&core),
            jobs: jobs_tx,
            failures: failures_tx,
        };
        (
            Self {
                core,
                jobs,
                failures,
                conn_info,
            },
            handle,
        )
    }

    /// Runs until `shutdown` becomes `true` (or its sender is dropped):
    /// connects (and reconnects under the breaker), serves proxy requests,
    /// consumes the failure-count channel and cleans the local tables.
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        let StateService {
            core,
            jobs,
            failures,
            conn_info,
        } = self;
        let slot: Slot = Arc::new(Mutex::new(None));
        let supervisor = async {
            match conn_info {
                Some(Ok(info)) => supervise(&core, &slot, &info, shutdown.clone()).await,
                Some(Err(e)) => log::error!("state: {e}; using local mode only"),
                None => {}
            }
        };
        tokio::join!(
            supervisor,
            dispatch(&core, &slot, jobs, shutdown.clone()),
            consume_failures(&core, &slot, failures, shutdown.clone()),
            sweep(&core, shutdown.clone()),
        );
        core.health.set_down();
        *lock(&slot) = None;
        metrics::get().set_mode(StateMode::Local);
    }
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    // Err: the sender is gone, which also means shutdown.
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Connection lifecycle and circuit breaker.
async fn supervise(
    core: &Arc<Core>,
    slot: &Slot,
    info: &ConnectionInfo,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Backoff::new(core.breaker_base, core.breaker_max);
    let mut wait = Duration::ZERO;
    let probe_timeout = core.connect_timeout * 2 + core.timeout.max(Duration::from_millis(100));
    loop {
        if !wait.is_zero() {
            core.health.set_open_ms(wait);
            tokio::select! {
                () = wait_shutdown(&mut shutdown) => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
        let attempt = tokio::time::timeout(
            probe_timeout,
            valkey::connect(info, core.connect_timeout, RESPONSE_TIMEOUT, &core.scripts),
        );
        let result = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            r = attempt => r.unwrap_or(Err(StateError::Timeout)),
        };
        match result {
            Ok(conn) => {
                let generation = core.health.next_generation();
                *lock(slot) = Some((conn, generation));
                core.health.set_up(generation);
                backoff.on_close(Instant::now());
                metrics::get().set_mode(StateMode::Valkey);
                log::info!("state: valkey connected, scripts loaded");
            }
            Err(e) => {
                wait = backoff.on_probe_failed();
                log::warn!(
                    "state: valkey unavailable ({e}); retrying in {} ms",
                    wait.as_millis()
                );
                continue;
            }
        }
        tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            () = core.health.tripped.notified() => {}
        }
        // Drop the connection: a blackholed TCP connection would otherwise
        // hold every later request until the kernel gives up on it.
        *lock(slot) = None;
        metrics::get().set_mode(StateMode::Local);
        wait = backoff.on_trip(Instant::now());
        log::warn!(
            "state: circuit open after consecutive valkey failures; local mode for {} ms",
            wait.as_millis()
        );
    }
}

fn current(core: &Core, slot: &Slot) -> Option<(ConnectionManager, u64)> {
    if core.health.is_up() {
        lock(slot).clone()
    } else {
        None
    }
}

/// Serves proxy requests: one task per request, so that requests are
/// pipelined on the multiplexed connection.
async fn dispatch(
    core: &Arc<Core>,
    slot: &Slot,
    mut jobs: mpsc::Receiver<Job>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let job = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            j = jobs.recv() => match j { Some(j) => j, None => return },
        };
        match current(core, slot) {
            Some((conn, generation)) => {
                tokio::spawn(run_job(Arc::clone(core), conn, generation, job));
            }
            None => job.fail(StateError::Unavailable),
        }
    }
}

async fn run_job(core: Arc<Core>, mut conn: ConnectionManager, generation: u64, job: Job) {
    let started = Instant::now();
    if started >= job.deadline() {
        // Never send a request nobody waits for (a late nonce SET would
        // consume the nonce without an answer).
        if !matches!(job, Job::Xadd { .. }) {
            core.health.failure(generation);
            metrics::get().valkey_error("pipeline");
        }
        job.fail(StateError::Timeout);
        return;
    }
    match job {
        Job::RoundTrip1 {
            mget,
            limits,
            deadline,
            reply,
        } => {
            let r = timeout_at(
                deadline,
                valkey::round_trip1(&mut conn, &core.scripts, &mget, &limits),
            )
            .await;
            let _ = reply.send(core.settle(generation, started, r));
        }
        Job::Nonce {
            key,
            ttl_ms,
            limits,
            deadline,
            reply,
        } => {
            let r = timeout_at(
                deadline,
                valkey::nonce_issue(&mut conn, &core.scripts, &key, ttl_ms, &limits),
            )
            .await;
            let _ = reply.send(core.settle(generation, started, r));
        }
        Job::Xadd {
            maxlen,
            entries,
            deadline,
            reply,
        } => {
            // Stream writes do not move the breaker (they are not on the
            // request path and fail for their own reasons, e.g. ACLs).
            let r = timeout_at(deadline, valkey::xadd(&mut conn, maxlen, &entries))
                .await
                .unwrap_or(Err(StateError::Timeout));
            match &r {
                Ok(()) => metrics::get()
                    .valkey_rtt
                    .observe(started.elapsed().as_secs_f64()),
                Err(_) => metrics::get().valkey_error("stream"),
            }
            let _ = reply.send(r);
        }
    }
}

/// The single consumer of the async failure-count channel (§9.7).
async fn consume_failures(
    core: &Arc<Core>,
    slot: &Slot,
    mut failures: mpsc::Receiver<Vec<PreparedLimit>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let op_timeout = core.timeout.max(core.connect_timeout);
    loop {
        let limits = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            l = failures.recv() => match l { Some(l) => l, None => return },
        };
        if let Some((mut conn, generation)) = current(core, slot) {
            let started = Instant::now();
            let r = timeout_at(
                started + op_timeout,
                valkey::gcra(&mut conn, &core.scripts, &limits),
            )
            .await;
            if core.settle(generation, started, r).is_ok() {
                continue;
            }
        }
        let now = unix_now_us();
        for l in &limits {
            core.gcra.check(l, l.write, now);
        }
    }
}

async fn sweep(core: &Arc<Core>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            () = tokio::time::sleep(SWEEP_INTERVAL) => {}
        }
        // CPU work (an expiry burst of the nonce set can take milliseconds)
        // runs off the runtime: this task is joined with the dispatcher,
        // which must keep forwarding requests within their `timeout_ms`.
        let core = Arc::clone(core);
        let _ = tokio::task::spawn_blocking(move || {
            core.gcra.sweep(unix_now_us());
            core.nonces.expire_all(unix_now_ms());
            core.verdicts.sweep(std::time::Instant::now());
        })
        .await;
    }
}

/// Used by proxies (cheap to clone). Every method is safe to call before
/// the service runs, and while Valkey is down: it then uses local state.
#[derive(Clone)]
pub struct StateHandle {
    core: Arc<Core>,
    jobs: mpsc::Sender<Job>,
    failures: mpsc::Sender<Vec<PreparedLimit>>,
}

impl fmt::Debug for StateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateHandle")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl StateHandle {
    /// [`StateMode::Valkey`] iff requests are currently sent to Valkey.
    pub fn mode(&self) -> StateMode {
        if self.core.valkey_usable() {
            StateMode::Valkey
        } else {
            StateMode::Local
        }
    }

    pub fn status(&self) -> StateStatus {
        StateStatus {
            mode: self.mode(),
            consecutive_failures: self.core.health.consecutive_failures(),
            trips: self.core.health.trips(),
            open_ms: self.core.health.open_ms(),
        }
    }

    async fn call<T>(
        &self,
        deadline: Instant,
        make: impl FnOnce(Reply<T>) -> Job,
    ) -> Result<T, StateError> {
        let (tx, rx) = oneshot::channel();
        self.jobs
            .try_send(make(tx))
            .map_err(|_| StateError::Overloaded)?;
        match timeout_at(deadline, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(StateError::Unavailable),
            Err(_) => Err(StateError::Timeout),
        }
    }

    /// Round trip 1 of a request: verdicts (2 s cache first) and the global
    /// limiters in one pipeline; on any failure within `timeout_ms`, the
    /// local GCRA table and no verdicts beyond the cache.
    pub async fn round_trip1(&self, req: RoundTrip1) -> RoundTrip1Result {
        let deadline = Instant::now() + self.core.timeout;
        let clock = std::time::Instant::now();
        let mut verdicts = vec![None; req.verdict_keys.len()];
        let mut fetch_idx = Vec::new();
        let mut fetch_keys = Vec::new();
        for (i, key) in req.verdict_keys.into_iter().enumerate() {
            match self.core.verdicts.get(&key, clock) {
                Some(v) => verdicts[i] = v,
                None => {
                    fetch_idx.push(i);
                    fetch_keys.push(key);
                }
            }
        }
        let limits = self.core.prepare(&req.limits);
        if fetch_keys.is_empty() && limits.is_empty() {
            return RoundTrip1Result {
                verdicts,
                limits: Vec::new(),
                mode: self.mode(),
            };
        }
        if self.core.valkey_usable() {
            let mget = fetch_keys.clone();
            let sent = limits.clone();
            let r = self
                .call(deadline, |reply| Job::RoundTrip1 {
                    mget,
                    limits: sent,
                    deadline,
                    reply,
                })
                .await;
            if let Ok((values, outcomes)) = r {
                for ((i, key), v) in fetch_idx.into_iter().zip(fetch_keys).zip(values) {
                    self.core.verdicts.put(key, v.clone(), clock);
                    verdicts[i] = v;
                }
                return RoundTrip1Result {
                    verdicts,
                    limits: outcomes,
                    mode: StateMode::Valkey,
                };
            }
        }
        let now = unix_now_us();
        let outcomes = limits
            .iter()
            .map(|l| self.core.gcra.check(l, l.write, now))
            .collect();
        RoundTrip1Result {
            verdicts,
            limits: outcomes,
            mode: StateMode::Local,
        }
    }

    /// Round trip 2 of `POST /__mg/c` with the replay rules of §9.7:
    ///
    /// 1. the local replay set is checked and updated first, in every mode;
    ///    a live entry means [`NonceResult::Reused`];
    /// 2. with Valkey: `mg_nonce_issue` decides (`Reused` or `Fresh` with the
    ///    quota outcomes);
    /// 3. without a Valkey answer the quotas are counted in the local table
    ///    (all-or-nothing), and the local check is authoritative only if
    ///    `local_replay_authoritative`, the nonce was recorded, and the
    ///    challenge was issued (`c_iat_ms`) after this process started and
    ///    after the last time the local set was full (a nonce that could not
    ///    be recorded then is unknown to the set); otherwise
    ///    [`NonceResult::Unavailable`].
    pub async fn nonce_issue(&self, req: NonceIssue, now_ms: i64, c_iat_ms: i64) -> NonceResult {
        let deadline = Instant::now() + self.core.timeout;
        let key = nonce_key(&req.site, &req.nonce);
        let ttl_ms = req.ttl_ms.clamp(1, MAX_NONCE_TTL_MS);
        let expiry_ms = now_ms.saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
        let recorded = match self.core.nonces.insert(&key, expiry_ms, now_ms) {
            NonceInsert::Exists => return NonceResult::Reused,
            NonceInsert::Inserted => true,
            NonceInsert::Full => false,
        };
        let limits = self.core.prepare(&req.limits);
        if self.core.valkey_usable() {
            let sent = limits.clone();
            let r = self
                .call(deadline, |reply| Job::Nonce {
                    key,
                    ttl_ms,
                    limits: sent,
                    deadline,
                    reply,
                })
                .await;
            match r {
                Ok(None) => return NonceResult::Reused,
                Ok(Some(outcomes)) => return NonceResult::Fresh { limits: outcomes },
                Err(_) => {}
            }
        }
        let now_us = u64::try_from(now_ms).unwrap_or(0).saturating_mul(1000);
        let outcomes = self.core.gcra.check_all_or_nothing(&limits, now_us);
        let after_overflow = self
            .core
            .nonces
            .last_overflow_ms()
            .is_none_or(|t| c_iat_ms > t);
        if self.core.local_replay_authoritative
            && recorded
            && c_iat_ms >= self.core.process_start_ms
            && after_overflow
        {
            NonceResult::Fresh { limits: outcomes }
        } else {
            NonceResult::Unavailable { limits: outcomes }
        }
    }

    /// Queues a failure count (`mg.c.fail`, `mg.c.fail.prefix`; the caller
    /// sets `write: true`). Never blocks; `false` = dropped because the
    /// channel (capacity 1024) is full, counted in
    /// `mg_state_async_dropped_total`. In local mode the local table is
    /// updated immediately. An empty list records nothing (`true`).
    pub fn record_failure(&self, limits: Vec<LimitCheck>) -> bool {
        if limits.is_empty() {
            return true;
        }
        let prepared = self.core.prepare(&limits);
        if self.core.mode == StateMode::Local {
            let now = unix_now_us();
            for l in &prepared {
                self.core.gcra.check(l, l.write, now);
            }
            return true;
        }
        match self.failures.try_send(prepared) {
            Ok(()) => true,
            Err(_) => {
                metrics::get().async_dropped.inc();
                false
            }
        }
    }

    /// Writes stream entries with one `XADD` pipeline (§13.6). Errors (local
    /// mode, Valkey down, timeout) are returned, never retried.
    pub async fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<Vec<(&'static str, String)>>,
    ) -> Result<(), StateError> {
        if entries.is_empty() {
            return Ok(());
        }
        if !self.core.valkey_usable() {
            return Err(StateError::Unavailable);
        }
        let deadline = Instant::now() + STREAM_TIMEOUT;
        self.call(deadline, |reply| Job::Xadd {
            maxlen,
            entries,
            deadline,
            reply,
        })
        .await
    }

    /// A `scope = local` limiter check (never touches Valkey).
    pub fn local_check(&self, check: &LimitCheck, now_us: u64) -> GcraOutcome {
        let l = PreparedLimit::new(check, &self.core.k_pseudo);
        self.core.gcra.check(&l, l.write, now_us)
    }
}
