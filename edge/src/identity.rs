//! Identity (docs/impl/phase1-spec.md §9.6, §6.5, §7.3, I-17, I-26;
//! WP-E1b): the clearance cookie, the crawler claim and the rDNS jobs.
//!
//! # Clearance
//!
//! [`verify_clearance`] takes the `__Host-mg_clr` candidates of the `Cookie`
//! headers (at most two, §6.6), verifies each with `mg_challenge::verify`
//! for the site and the request's environment, and compares its bindings
//! with the current request ([`bind_inputs`]): `uah` from the parsed
//! User-Agent, `ipp` when the client IP is known, `ipa` when the ASN is
//! known and not 0, `ctp` under `clearance.ctp_shadow` when all four
//! Cloudflare TLS inputs arrived. The first `valid` candidate wins, else the
//! first candidate's status. An unknown client IP has no `ipp`, so a token
//! is then `binding_mismatch` (D-23). Statuses map as §6.5 says (unknown
//! kid and expiry → `expired`).
//!
//! A token issued without a replay check (`ruc`, I-30) is accepted like any
//! other, except on a `fail_closed` route: there it is not a clearance
//! ([`Acceptance::FailClosed`]). It counts as `expired` (ABSENT: no level,
//! no age, no session, no added risk), so the matrix challenges again
//! wherever a clearance is required or would have satisfied the challenge,
//! and the `C` of that challenge belongs to the `fail_closed` route, whose
//! submission is 429 while the replay store is still unavailable (§9.7
//! rule 4). A later candidate that is a full clearance is still chosen.
//! [`Clearance::replay_unchecked`] reports the `ruc` of the chosen token
//! either way (the decision event's `token.replay_unchecked`).
//!
//! # Crawlers
//!
//! [`apply_crawler`] maps a `CrawlerStatus` to `identity.crawler` (§9.6
//! table). A `check()` that returns an `RdnsJob` hands it to the
//! [`RdnsDispatcher`], which abandons it (and counts
//! `mg_rdns_lookups_total{result="dropped"}`) when `mg-rdns` is not running,
//! `rdns_concurrency` jobs are in flight, the client's `ip_prefix` already
//! started `rdns_jobs_per_prefix_per_min` jobs in the last minute (a GCRA in
//! the state layer's local table), or the queue is full. Otherwise
//! `mg-rdns` runs it with [`execute`]: `resolve_rdns` under the
//! `2 × dns_timeout_ms + 1 s` deadline (expiry reports `DnsError`, I-17),
//! then `complete()` on the verifier that issued the job (I-26). A task that
//! is dropped without reporting (queue full, shutdown, cancellation, panic)
//! abandons its job, so the next request re-issues it.

use mg_challenge::{
    BindCheck, BindInputs, ClearanceClaims, TokenKeySet, check_clearance_bind, clearance_cookies,
};
use mg_core::gcra::GcraParams;
use mg_core::ua::UaInfo;
use mg_core::{Crawler, CrawlerMethod, CrawlerVerification, EdgeTls, Net, Token, TokenStatus};
use mg_edge_core::state::{LimitCheck, LimiterKey, StateHandle, dims};
use mg_intel::{
    CrawlerStatus, CrawlerVerifier, DnsResolver, RdnsJob, RdnsOutcome, VerifyMethod, resolve_rdns,
};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::metrics::metrics;

/// The bindings of the current request (§6.4, §9.6).
pub fn bind_inputs(
    ua: &UaInfo,
    net: &Net,
    edge_tls: Option<&EdgeTls>,
    ctp_shadow: bool,
) -> BindInputs {
    let ctp = edge_tls.filter(|_| ctp_shadow).and_then(|e| {
        Some(mg_challenge::ctp(
            e.version.as_deref()?,
            e.cipher.as_deref()?,
            e.ciphers_sha1.as_deref()?,
            e.hello_len?,
        ))
    });
    BindInputs {
        uah: mg_challenge::uah(ua.family, ua.major),
        ipp: net.ip.map(|ip| mg_challenge::ipp(&Net::prefix_of(ip))),
        // The ASN comes from the IP; without one it can never soften an
        // `ipp` mismatch (D-23).
        ipa: net.ip.and(net.asn).and_then(mg_challenge::ipa),
        ctp,
    }
}

/// `identity.token` and the session of a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Clearance {
    pub token: Token,
    /// The valid token's `sub` (`ctx.session_id`, `MG-Session`).
    pub session: Option<String>,
    /// The chosen token verified and carries `ruc` (issued without a replay
    /// check, I-30), whether or not the route accepted it.
    pub replay_unchecked: bool,
}

/// Which clearances the selected route accepts (I-30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Every valid token.
    Any,
    /// A `fail_closed` route: a token with `ruc` (issued without a replay
    /// check) is not a clearance here.
    FailClosed,
}

impl Acceptance {
    /// The acceptance of a route with this `fail_closed` (OR-ed over the
    /// matching routes, §9.4).
    pub fn for_route(fail_closed: bool) -> Self {
        if fail_closed {
            Self::FailClosed
        } else {
            Self::Any
        }
    }
}

/// One candidate: its status, and for a verified token its claims and
/// binding check. A binding-valid `ruc` token on a `fail_closed` route is
/// `expired` (not a clearance there, I-30).
fn candidate(
    keys: &TokenKeySet,
    site: &str,
    env: &str,
    token: &str,
    current: &BindInputs,
    now_s: i64,
    accept: Acceptance,
) -> (TokenStatus, Option<(ClearanceClaims, BindCheck)>) {
    match mg_challenge::verify(keys, site, env, token, now_s) {
        Err(e) => (e.status(), None),
        Ok(claims) => {
            let check = check_clearance_bind(&claims, current);
            let status = if check.hard_failure() {
                TokenStatus::BindingMismatch
            } else if claims.ruc && accept == Acceptance::FailClosed {
                TokenStatus::Expired
            } else {
                TokenStatus::Valid
            };
            (status, Some((claims, check)))
        }
    }
}

/// Verifies the clearance cookie of a request (see the module
/// documentation) for a route with `accept`, and counts
/// `mg_token_verify_total{result}` with the resulting status.
pub fn verify_clearance(
    keys: &TokenKeySet,
    site: &str,
    env: &str,
    cookie_headers: &[&str],
    current: &BindInputs,
    now_s: i64,
    accept: Acceptance,
) -> Clearance {
    let mut first: Option<(TokenStatus, Option<(ClearanceClaims, BindCheck)>)> = None;
    let mut chosen = None;
    for token in clearance_cookies(cookie_headers) {
        let c = candidate(keys, site, env, token, current, now_s, accept);
        if c.0 == TokenStatus::Valid {
            chosen = Some(c);
            break;
        }
        first.get_or_insert(c);
    }
    let (status, verified) = chosen.or(first).unwrap_or((TokenStatus::None, None));
    metrics()
        .token_verify
        .with_label_values(&[status.as_str()])
        .inc();
    let mut out = Clearance {
        token: Token {
            status,
            ..Token::default()
        },
        session: None,
        replay_unchecked: false,
    };
    if let Some((claims, check)) = verified {
        out.replay_unchecked = claims.ruc;
        out.token.bind = check.token_bind();
        if status == TokenStatus::Valid {
            out.token.level = Some(claims.lvl);
            out.token.age_s =
                u32::try_from(now_s.saturating_sub(claims.iat).max(0)).unwrap_or(u32::MAX);
            out.session = Some(claims.sub);
        }
    }
    out
}

/// Maps a crawler verification result to `identity.crawler` (§9.6 table);
/// `cf_vbot` / `cf_vbot_cat` are left as they are.
pub fn apply_crawler(c: &mut Crawler, status: &CrawlerStatus) {
    let method = |m: &VerifyMethod| match m {
        VerifyMethod::IpRange => CrawlerMethod::IpRange,
        VerifyMethod::Rdns => CrawlerMethod::Rdns,
    };
    c.claimed = true;
    c.verified = false;
    c.method = None;
    c.outside_ranges = false;
    match status {
        CrawlerStatus::NotClaimed => {
            c.claimed = false;
            c.operator = None;
            c.purpose = None;
            c.verification = Some(CrawlerVerification::None);
        }
        CrawlerStatus::Verified {
            operator,
            purpose,
            method: m,
        } => {
            c.operator = Some(operator.clone());
            c.purpose = Some(purpose.clone());
            c.verified = true;
            c.verification = Some(CrawlerVerification::Verified);
            c.method = Some(method(m));
        }
        CrawlerStatus::Failed {
            operator,
            purpose,
            method: m,
        } => {
            c.operator = Some(operator.clone());
            c.purpose = Some(purpose.clone());
            c.verification = Some(CrawlerVerification::Failed);
            c.method = Some(method(m));
        }
        CrawlerStatus::Pending {
            operator,
            purpose,
            outside_ranges,
        } => {
            c.operator = Some(operator.clone());
            c.purpose = Some(purpose.clone());
            c.verification = Some(CrawlerVerification::Pending);
            c.outside_ranges = *outside_ranges;
        }
        CrawlerStatus::Unverifiable {
            operator, purpose, ..
        } => {
            c.operator = Some(operator.clone());
            c.purpose = Some(purpose.clone());
            c.verification = Some(CrawlerVerification::Unverifiable);
        }
    }
}

/// The per-request crawler metrics: `mg_crawler_verify_total` for the
/// synchronous `ip_range` results (rDNS results are counted when their job
/// settles, [`execute`]; `pending` is never counted, §7.3) and
/// `mg_cf_vbot_disagree_total` (§9.6, docs/05 §3.4).
pub fn count_crawler(status: &CrawlerStatus, cf_vbot: Option<bool>) {
    let m = metrics();
    match status {
        CrawlerStatus::Verified {
            method: VerifyMethod::IpRange,
            ..
        } => m
            .crawler_verify
            .with_label_values(&["ip_range", "pass"])
            .inc(),
        CrawlerStatus::Failed {
            method: VerifyMethod::IpRange,
            ..
        } => m
            .crawler_verify
            .with_label_values(&["ip_range", "fail"])
            .inc(),
        _ => {}
    }
    let disagreement = match (status, cf_vbot) {
        (CrawlerStatus::Verified { .. }, Some(false)) => Some("mg_pass_cf_false"),
        (CrawlerStatus::Failed { .. }, Some(true)) => Some("mg_fail_cf_true"),
        _ => None,
    };
    if let Some(direction) = disagreement {
        m.cf_vbot_disagree.with_label_values(&[direction]).inc();
    }
}

/// One rDNS job from submission until it is reported. Dropping it without
/// [`RdnsTask::complete`] abandons the job on its verifier (the next
/// `check()` issues a new one) and frees its concurrency slot.
pub struct RdnsTask {
    verifier: Arc<CrawlerVerifier>,
    job: RdnsJob,
    inflight: Arc<AtomicUsize>,
    reported: bool,
}

impl fmt::Debug for RdnsTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdnsTask")
            .field("job", &self.job)
            .field("reported", &self.reported)
            .finish_non_exhaustive()
    }
}

impl RdnsTask {
    /// The job to run.
    pub fn job(&self) -> &RdnsJob {
        &self.job
    }

    /// Reports the outcome to the verifier that issued the job (I-26).
    pub fn complete(mut self, outcome: RdnsOutcome, now_ms: i64) {
        self.verifier.complete(&self.job, outcome, now_ms);
        self.reported = true;
    }
}

impl Drop for RdnsTask {
    fn drop(&mut self) {
        if !self.reported {
            self.verifier.abandon(&self.job);
        }
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Why a job was not queued (all count as `dropped`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// `mg-rdns` is not running (before start-up or after shutdown).
    NotRunning,
    /// `rdns_concurrency` jobs are in flight.
    Concurrency,
    /// The client's prefix started its per-minute share of jobs.
    PrefixLimit,
    /// The submission queue is full.
    QueueFull,
}

/// The `limiter` part of the per-prefix job limiter's local key.
pub const RDNS_PREFIX_LIMITER: &str = "mg.rdns.prefix";
/// The `site` part of that key: one budget per prefix for the whole process.
const RDNS_LIMITER_SCOPE: &str = "*";

/// Hands rDNS jobs from the proxies to `mg-rdns` (see the module
/// documentation). Cheap to share (`Arc`).
pub struct RdnsDispatcher {
    queue: mpsc::Sender<RdnsTask>,
    inflight: Arc<AtomicUsize>,
    running: Arc<AtomicBool>,
    concurrency: usize,
    per_prefix: Option<GcraParams>,
    state: StateHandle,
}

impl fmt::Debug for RdnsDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdnsDispatcher")
            .field("inflight", &self.inflight.load(Ordering::Relaxed))
            .field("running", &self.running.load(Ordering::Relaxed))
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

/// The receiving side, owned by `mg-rdns`.
#[derive(Debug)]
pub struct RdnsReceiver {
    pub rx: mpsc::Receiver<RdnsTask>,
    running: Arc<AtomicBool>,
}

impl RdnsReceiver {
    /// Marks `mg-rdns` as running (jobs are queued from now on) or stopped.
    pub fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::Release);
    }
}

impl RdnsDispatcher {
    /// A dispatcher for `concurrency` jobs in flight, at most
    /// `jobs_per_prefix_per_min` new jobs per `ip_prefix` and minute (the
    /// local GCRA table of `state`), and a queue of `capacity` tasks. Jobs
    /// are dropped until the receiver is marked running.
    pub fn new(
        concurrency: usize,
        jobs_per_prefix_per_min: u32,
        capacity: usize,
        state: StateHandle,
    ) -> (Self, RdnsReceiver) {
        let (queue, rx) = mpsc::channel(capacity.max(1));
        let running = Arc::new(AtomicBool::new(false));
        let dispatcher = Self {
            queue,
            inflight: Arc::new(AtomicUsize::new(0)),
            running: Arc::clone(&running),
            concurrency,
            per_prefix: GcraParams::new(jobs_per_prefix_per_min, 60, jobs_per_prefix_per_min),
            state,
        };
        (dispatcher, RdnsReceiver { rx, running })
    }

    /// Jobs queued or running.
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    /// Reserves a concurrency slot; `false` when all are taken.
    fn reserve(&self) -> bool {
        let mut cur = self.inflight.load(Ordering::Acquire);
        loop {
            if cur >= self.concurrency {
                return false;
            }
            match self.inflight.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    /// Queues `job` (issued by `verifier`) or abandons it (see the module
    /// documentation). `now_us`: the Edge clock for the per-prefix GCRA.
    pub fn submit(
        &self,
        verifier: &Arc<CrawlerVerifier>,
        job: RdnsJob,
        now_us: u64,
    ) -> Result<(), Dropped> {
        let result = self.try_submit(verifier, job, now_us);
        if result.is_err() {
            metrics().rdns_lookups.with_label_values(&["dropped"]).inc();
        }
        result
    }

    fn try_submit(
        &self,
        verifier: &Arc<CrawlerVerifier>,
        job: RdnsJob,
        now_us: u64,
    ) -> Result<(), Dropped> {
        if !self.running.load(Ordering::Acquire) {
            verifier.abandon(&job);
            return Err(Dropped::NotRunning);
        }
        if !self.reserve() {
            verifier.abandon(&job);
            return Err(Dropped::Concurrency);
        }
        // From here on the task owns the slot and the job: dropping it
        // abandons the job and frees the slot.
        let task = RdnsTask {
            verifier: Arc::clone(verifier),
            job,
            inflight: Arc::clone(&self.inflight),
            reported: false,
        };
        let allowed = self.per_prefix.is_some_and(|params| {
            let check = LimitCheck {
                key: LimiterKey::new(
                    RDNS_LIMITER_SCOPE,
                    RDNS_PREFIX_LIMITER,
                    dims(&[("ip_prefix", Some(&Net::prefix_of(task.job.ip)))]),
                ),
                params,
                cost: 1,
                write: true,
            };
            self.state.local_check(&check, now_us).allowed
        });
        if !allowed {
            return Err(Dropped::PrefixLimit);
        }
        self.queue.try_send(task).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Dropped::QueueFull,
            mpsc::error::TrySendError::Closed(_) => Dropped::NotRunning,
        })
    }
}

/// Runs one job (`mg-rdns`): `resolve_rdns` under `deadline`, whose expiry
/// is a `DnsError` (I-17), then reports it to the issuing verifier and
/// counts `mg_rdns_lookups_total` and `mg_crawler_verify_total{method=
/// "rdns"}`. Cancelling the future drops the task, which abandons the job.
pub async fn execute(
    task: RdnsTask,
    resolver: &dyn DnsResolver,
    deadline: Duration,
) -> RdnsOutcome {
    let outcome = tokio::time::timeout(deadline, resolve_rdns(task.job(), resolver))
        .await
        .unwrap_or(RdnsOutcome::DnsError);
    let m = metrics();
    let (lookup, verify) = match outcome {
        RdnsOutcome::Pass => ("pass", "pass"),
        RdnsOutcome::Fail => ("fail", "fail"),
        RdnsOutcome::DnsError => ("dns_error", "unverifiable"),
    };
    m.rdns_lookups.with_label_values(&[lookup]).inc();
    m.crawler_verify.with_label_values(&["rdns", verify]).inc();
    task.complete(outcome, unix_now_ms());
    outcome
}

/// Wall clock, Unix ms (the verifier's cache is driven by caller time).
pub fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_challenge::{ClearanceBind, MintParams, Rng, RngError};
    use mg_core::{RiskBand, TokenLevel};
    use mg_edge_core::state::{StateConfig, StateService};
    use mg_intel::{CacheConfig, CrawlerRegistry};

    /// Deterministic bytes for minting test tokens.
    struct Counter(std::sync::atomic::AtomicU8);
    impl Rng for Counter {
        fn fill(&self, dst: &mut [u8]) -> Result<(), RngError> {
            for b in dst {
                *b = self.0.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    fn keys() -> TokenKeySet {
        let json = std::fs::read(crate::test_support::repo(
            "testdata/phase1/keys/token.keys.json",
        ))
        .unwrap();
        TokenKeySet::from_key_file(&json, "blog", &["blog-t-20260927".to_string()]).unwrap()
    }

    fn net(ip: &str, asn: Option<u32>) -> Net {
        let mut n = Net::for_ip(ip.parse().unwrap());
        n.asn = asn;
        n
    }

    const NOW: i64 = 1_790_000_000;

    fn mint(bind_from: &BindInputs, lvl: TokenLevel, now: i64, ttl: u32, env: &str) -> String {
        mint_with(bind_from, lvl, now, ttl, env, false)
    }

    fn mint_with(
        bind_from: &BindInputs,
        lvl: TokenLevel,
        now: i64,
        ttl: u32,
        env: &str,
        replay_unchecked: bool,
    ) -> String {
        let p = MintParams {
            env,
            session: None,
            lvl,
            now_s: now,
            ttl_s: ttl,
            bind: ClearanceBind::from_inputs(bind_from).unwrap(),
            rb: RiskBand::Low,
            replay_unchecked,
        };
        mg_challenge::mint(&keys(), "blog", &p, &Counter(Default::default()))
            .unwrap()
            .0
    }

    fn cookie(token: &str) -> String {
        format!("a=1; {}={token}; b=2", mg_challenge::COOKIE_NAME)
    }

    #[test]
    fn clearance_statuses() {
        let ua = mg_core::ua::parse("Mozilla/5.0 (X11) Chrome/131.0 Safari/537.36");
        let here = bind_inputs(&ua, &net("203.0.113.7", Some(64500)), None, true);
        let token = mint(&here, TokenLevel::Pow, NOW, 1800, "production");
        let k = keys();
        let verify = |headers: &[&str], cur: &BindInputs, now: i64, env: &str| {
            verify_clearance(&k, "blog", env, headers, cur, now, Acceptance::Any)
        };

        let none = verify(&["a=1"], &here, NOW + 10, "production");
        assert_eq!(none.token.status, TokenStatus::None);
        assert!(none.session.is_none());

        let c = cookie(&token);
        let ok = verify(&[&c], &here, NOW + 10, "production");
        assert_eq!(ok.token.status, TokenStatus::Valid);
        assert_eq!(ok.token.level, Some(TokenLevel::Pow));
        assert_eq!(ok.token.age_s, 10);
        assert_eq!(ok.session.as_ref().map(String::len), Some(22));
        assert_eq!(ok.token.bind.uah, Some(mg_core::BindResult::Match));

        // Expired and wrong environment.
        let expired = verify(&[&c], &here, NOW + 1801, "production");
        assert_eq!(expired.token.status, TokenStatus::Expired);
        assert!(expired.session.is_none() && expired.token.level.is_none());
        assert_eq!(
            verify(&[&c], &here, NOW + 10, "staging").token.status,
            TokenStatus::Invalid
        );
        // Tampered.
        let bad = cookie(&token.replacen("v4.local.", "v4.local.A", 1));
        assert_eq!(
            verify(&[&bad], &here, NOW + 10, "production").token.status,
            TokenStatus::Invalid
        );

        // Another UA family: hard binding failure.
        let firefox = mg_core::ua::parse("Mozilla/5.0 (X11) Gecko/20100101 Firefox/131.0");
        let other = bind_inputs(&firefox, &net("203.0.113.7", Some(64500)), None, true);
        let mm = verify(&[&c], &other, NOW + 10, "production");
        assert_eq!(mm.token.status, TokenStatus::BindingMismatch);
        assert!(mm.session.is_none());
        // Another prefix in the same ASN: soft, still valid.
        let moved = bind_inputs(&ua, &net("198.51.100.9", Some(64500)), None, true);
        let soft = verify(&[&c], &moved, NOW + 10, "production");
        assert_eq!(soft.token.status, TokenStatus::Valid);
        assert_eq!(soft.token.bind.ipp, Some(mg_core::BindResult::SoftMismatch));
        // D-23: an unknown client IP never keeps a token valid, not even
        // through a (stale) ASN.
        let unknown_net = Net {
            asn: Some(64500),
            ..Net::default()
        };
        let unknown = bind_inputs(&ua, &unknown_net, None, true);
        assert_eq!((unknown.ipp, unknown.ipa), (None, None));
        assert_eq!(
            verify(&[&c], &unknown, NOW + 10, "production").token.status,
            TokenStatus::BindingMismatch
        );

        // First valid candidate wins; otherwise the first candidate's status.
        let both = format!(
            "{}={}; {}",
            mg_challenge::COOKIE_NAME,
            "junk",
            cookie(&token)
        );
        assert_eq!(
            verify(&[&both], &here, NOW + 10, "production").token.status,
            TokenStatus::Valid
        );
        let expired_then_bad = [c.as_str(), bad.as_str()];
        assert_eq!(
            verify(&expired_then_bad, &here, NOW + 1801, "production")
                .token
                .status,
            TokenStatus::Expired
        );
    }

    /// I-30: a token issued without a replay check (`ruc`) is a clearance
    /// on every route except a `fail_closed` one, where it is `expired`
    /// (no level, no session: the matrix challenges again); a later full
    /// clearance still wins there. `replay_unchecked` reports the `ruc` of
    /// the chosen token either way.
    #[test]
    fn replay_unchecked_tokens_are_not_accepted_on_fail_closed_routes() {
        let ua = mg_core::ua::parse("Mozilla/5.0 (X11) Chrome/131.0 Safari/537.36");
        let here = bind_inputs(&ua, &net("203.0.113.7", Some(64500)), None, true);
        let ruc = mint_with(&here, TokenLevel::Pow, NOW, 1800, "production", true);
        let checked = mint(&here, TokenLevel::Invisible, NOW, 1800, "production");
        let k = keys();
        let verify = |headers: &[&str], accept: Acceptance| {
            verify_clearance(&k, "blog", "production", headers, &here, NOW + 10, accept)
        };
        let c = cookie(&ruc);

        let open = verify(&[&c], Acceptance::for_route(false));
        assert_eq!(open.token.status, TokenStatus::Valid);
        assert_eq!(open.token.level, Some(TokenLevel::Pow));
        assert!(open.session.is_some());
        assert!(open.replay_unchecked);

        let closed = verify(&[&c], Acceptance::for_route(true));
        assert_eq!(closed.token.status, TokenStatus::Expired);
        assert_eq!((closed.token.level, closed.token.age_s), (None, 0));
        assert!(closed.session.is_none());
        assert!(closed.replay_unchecked);

        // A checked token is a clearance on a fail_closed route.
        let full = verify(&[&cookie(&checked)], Acceptance::FailClosed);
        assert_eq!(full.token.status, TokenStatus::Valid);
        assert!(!full.replay_unchecked);

        // ruc first, then a checked token: the checked one is chosen there.
        let both = format!(
            "{}={ruc}; {}={checked}",
            mg_challenge::COOKIE_NAME,
            mg_challenge::COOKIE_NAME
        );
        let chosen = verify(&[&both], Acceptance::FailClosed);
        assert_eq!(chosen.token.status, TokenStatus::Valid);
        assert_eq!(chosen.token.level, Some(TokenLevel::Invisible));
        assert!(!chosen.replay_unchecked);
        // ... and on other routes the first valid one (the ruc token).
        let any = verify(&[&both], Acceptance::Any);
        assert_eq!(any.token.level, Some(TokenLevel::Pow));
        assert!(any.replay_unchecked);

        // A hard binding failure stays binding_mismatch on any route.
        let firefox = mg_core::ua::parse("Mozilla/5.0 (X11) Gecko/20100101 Firefox/131.0");
        let other = bind_inputs(&firefox, &net("203.0.113.7", Some(64500)), None, true);
        let mm = verify_clearance(
            &k,
            "blog",
            "production",
            &[&c],
            &other,
            NOW + 10,
            Acceptance::FailClosed,
        );
        assert_eq!(mm.token.status, TokenStatus::BindingMismatch);
    }

    #[test]
    fn ctp_needs_every_input_and_the_shadow_switch() {
        let ua = mg_core::ua::parse("curl/8");
        let n = net("203.0.113.7", None);
        let full = EdgeTls {
            version: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_128_GCM_SHA256".into()),
            ciphers_sha1: Some("x".into()),
            ext_sha1: None,
            hello_len: Some(512),
        };
        assert!(bind_inputs(&ua, &n, Some(&full), true).ctp.is_some());
        assert!(bind_inputs(&ua, &n, Some(&full), false).ctp.is_none());
        let partial = EdgeTls {
            hello_len: None,
            ..full
        };
        assert!(bind_inputs(&ua, &n, Some(&partial), true).ctp.is_none());
        // ASN 0 / unknown is never bound.
        assert!(bind_inputs(&ua, &n, None, true).ipa.is_none());
    }

    #[test]
    fn crawler_mapping_follows_the_spec_table() {
        let mut c = Crawler {
            cf_vbot: Some(true),
            ..Crawler::default()
        };
        apply_crawler(&mut c, &CrawlerStatus::NotClaimed);
        assert!(!c.claimed && !c.verified && c.operator.is_none());
        assert_eq!(c.verification, Some(CrawlerVerification::None));
        assert_eq!(c.cf_vbot, Some(true), "untouched");
        let who = || ("googlebot".to_string(), "search".to_string());
        apply_crawler(
            &mut c,
            &CrawlerStatus::Verified {
                operator: who().0,
                purpose: who().1,
                method: VerifyMethod::Rdns,
            },
        );
        assert!(c.claimed && c.verified && c.is_verified());
        assert_eq!(c.method, Some(CrawlerMethod::Rdns));
        assert_eq!(c.purpose.as_deref(), Some("search"));
        apply_crawler(
            &mut c,
            &CrawlerStatus::Failed {
                operator: who().0,
                purpose: who().1,
                method: VerifyMethod::IpRange,
            },
        );
        assert!(c.claimed && !c.verified && c.is_failed());
        assert_eq!(c.method, Some(CrawlerMethod::IpRange));
        apply_crawler(
            &mut c,
            &CrawlerStatus::Pending {
                operator: who().0,
                purpose: who().1,
                outside_ranges: true,
            },
        );
        assert_eq!(c.verification, Some(CrawlerVerification::Pending));
        assert!(c.outside_ranges && !c.verified && c.method.is_none());
        apply_crawler(
            &mut c,
            &CrawlerStatus::Unverifiable {
                operator: who().0,
                purpose: who().1,
                reason: "no_client_ip",
            },
        );
        assert_eq!(c.verification, Some(CrawlerVerification::Unverifiable));
        assert!(c.claimed && !c.outside_ranges);
    }

    fn verifier() -> Arc<CrawlerVerifier> {
        let json = std::fs::read(crate::test_support::repo(
            "testdata/phase1/artifacts/crawler-registry.test.json",
        ))
        .unwrap();
        let reg = Arc::new(CrawlerRegistry::from_artifact(&json).unwrap());
        Arc::new(CrawlerVerifier::new(reg, CacheConfig::default()))
    }

    const GOOGLEBOT: &str =
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

    fn state() -> StateHandle {
        StateService::new(StateConfig::local([7; 32])).1
    }

    /// §9.6: a full concurrency budget abandons the job, and the next
    /// request re-issues it once a slot is free.
    #[test]
    fn concurrency_limit_abandons_and_reissues() {
        let v = verifier();
        let (d, recv) = RdnsDispatcher::new(1, 100, 8, state());
        recv.set_running(true);
        let (_, a) = v.check(GOOGLEBOT, Some("203.0.113.1".parse().unwrap()), 0);
        d.submit(&v, a.expect("job"), 0).unwrap();
        assert_eq!(d.inflight(), 1);
        let ip_b = Some("203.0.113.2".parse().unwrap());
        let (_, b) = v.check(GOOGLEBOT, ip_b, 0);
        assert_eq!(d.submit(&v, b.expect("job"), 0), Err(Dropped::Concurrency));
        // Abandoned: the next check issues a new job at once (no stuck mark).
        let (_, again) = v.check(GOOGLEBOT, ip_b, 1);
        let again = again.expect("re-issued after abandon");
        assert_eq!(d.submit(&v, again, 1), Err(Dropped::Concurrency));
        // Finish the first job: its slot is freed.
        let mut recv = recv;
        let task = recv.rx.try_recv().unwrap();
        task.complete(RdnsOutcome::Fail, 2);
        assert_eq!(d.inflight(), 0);
        let (_, third) = v.check(GOOGLEBOT, ip_b, 3);
        d.submit(&v, third.expect("job"), 3).unwrap();
        assert_eq!(d.inflight(), 1);
    }

    #[test]
    fn prefix_limit_queue_and_running_state() {
        let v = verifier();
        let (d, mut recv) = RdnsDispatcher::new(16, 1, 1, state());
        let job = |ip: &str, now: i64| v.check(GOOGLEBOT, Some(ip.parse().unwrap()), now).1;
        // Not running yet: dropped and released.
        assert_eq!(
            d.submit(&v, job("203.0.113.1", 0).unwrap(), 0),
            Err(Dropped::NotRunning)
        );
        assert_eq!(d.inflight(), 0);
        recv.set_running(true);
        d.submit(&v, job("203.0.113.1", 1).unwrap(), 1_000).unwrap();
        // Same /24: the per-minute budget of 1 is spent.
        assert_eq!(
            d.submit(&v, job("203.0.113.9", 1).unwrap(), 2_000),
            Err(Dropped::PrefixLimit)
        );
        // Another prefix: allowed by the limiter, but the queue (1) is full.
        assert_eq!(
            d.submit(&v, job("198.51.100.200", 1).unwrap(), 3_000),
            Err(Dropped::QueueFull)
        );
        assert_eq!(d.inflight(), 1);
        // A minute later the prefix may start a job again.
        drop(recv.rx.try_recv().unwrap());
        assert_eq!(d.inflight(), 0, "a dropped task frees its slot");
        d.submit(&v, job("203.0.113.9", 2).unwrap(), 61_000_000)
            .unwrap();
        // After shutdown (receiver gone) submissions are dropped.
        drop(recv);
        assert_eq!(
            d.submit(&v, job("192.0.2.200", 3).unwrap(), 62_000_000),
            Err(Dropped::NotRunning)
        );
    }

    /// A resolver that never answers.
    struct Hang;
    impl DnsResolver for Hang {
        fn reverse(
            &self,
            _ip: std::net::IpAddr,
        ) -> mg_core::BoxFuture<'_, Result<Vec<String>, mg_intel::DnsError>> {
            Box::pin(std::future::pending())
        }
        fn forward(
            &self,
            _name: &str,
        ) -> mg_core::BoxFuture<'_, Result<Vec<std::net::IpAddr>, mg_intel::DnsError>> {
            Box::pin(std::future::pending())
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// I-17: the whole-job deadline reports `DnsError`, which is cached like
    /// any other result; a cancelled task abandons its job.
    #[test]
    fn deadline_reports_dns_error_and_cancellation_abandons() {
        let v = verifier();
        let (d, mut recv) = RdnsDispatcher::new(4, 100, 8, state());
        recv.set_running(true);
        let now = unix_now_ms();
        let ip = Some("203.0.113.50".parse().unwrap());
        let (_, job) = v.check(GOOGLEBOT, ip, now);
        d.submit(&v, job.unwrap(), 0).unwrap();
        let task = recv.rx.try_recv().unwrap();
        let rt = runtime();
        let outcome = rt.block_on(execute(task, &Hang, Duration::from_millis(50)));
        assert_eq!(outcome, RdnsOutcome::DnsError);
        assert_eq!(d.inflight(), 0);
        let (status, job) = v.check(GOOGLEBOT, ip, unix_now_ms());
        assert!(
            matches!(
                status,
                CrawlerStatus::Unverifiable {
                    reason: "dns_error",
                    ..
                }
            ),
            "{status:?}"
        );
        assert!(job.is_none());

        // Cancelled mid-flight (shutdown): abandoned, re-issued next time.
        let ip = Some("203.0.113.51".parse().unwrap());
        let (_, job) = v.check(GOOGLEBOT, ip, now);
        d.submit(&v, job.unwrap(), 0).unwrap();
        let task = recv.rx.try_recv().unwrap();
        rt.block_on(async {
            let _ = tokio::time::timeout(
                Duration::from_millis(20),
                execute(task, &Hang, Duration::from_secs(60)),
            )
            .await;
        });
        assert_eq!(d.inflight(), 0);
        assert!(v.check(GOOGLEBOT, ip, now + 1).1.is_some());
    }

    #[test]
    fn execute_reports_to_the_issuing_verifier() {
        let v = verifier();
        let (d, mut recv) = RdnsDispatcher::new(4, 100, 8, state());
        recv.set_running(true);
        let resolver = mg_intel::StaticResolver::from_json(
            br#"{"v":1,"ptr":{"198.51.100.200":["crawl-1.googlebot.com."]},"a":{"crawl-1.googlebot.com":["198.51.100.200"]}}"#,
        )
        .unwrap();
        let ip = Some("198.51.100.200".parse().unwrap());
        let now = unix_now_ms();
        let (status, job) = v.check(GOOGLEBOT, ip, now);
        assert!(matches!(
            status,
            CrawlerStatus::Pending {
                outside_ranges: true,
                ..
            }
        ));
        d.submit(&v, job.unwrap(), 0).unwrap();
        let outcome = runtime().block_on(execute(
            recv.rx.try_recv().unwrap(),
            &resolver,
            Duration::from_secs(5),
        ));
        assert_eq!(outcome, RdnsOutcome::Pass);
        assert!(matches!(
            v.check(GOOGLEBOT, ip, unix_now_ms()).0,
            CrawlerStatus::Verified {
                method: VerifyMethod::Rdns,
                ..
            }
        ));

        // A job of a replaced verifier reports to the old one only (I-26).
        let replacement = verifier();
        let ip = Some("198.51.100.201".parse().unwrap());
        let (_, job) = v.check(GOOGLEBOT, ip, now);
        d.submit(&v, job.unwrap(), 0).unwrap();
        runtime().block_on(execute(
            recv.rx.try_recv().unwrap(),
            &resolver,
            Duration::from_secs(5),
        ));
        assert!(matches!(
            replacement.check(GOOGLEBOT, ip, unix_now_ms()).0,
            CrawlerStatus::Pending { .. }
        ));
    }
}
