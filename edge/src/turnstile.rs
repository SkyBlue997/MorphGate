//! Turnstile in the Edge (docs/impl/phase2-spec.md §5.4, §8, D-51, D-52,
//! D-70; WP-E2c). The siteverify client, its error mapping and the circuit
//! breaker are mg-edge-core's (`mg_edge_core::outbound`, WP-C6); the
//! provider selection is mg-core's (`select_providers`); `cData` and the
//! idempotency key are mg-challenge's. This module wires them:
//!
//! * [`TurnstileRuntime`]: the bundle's public provider configuration
//!   (`SiteBundle.providers`, §8.2), present only when the provider is
//!   enabled;
//! * [`SiteTurnstile`]: a site's secret (`[[sites]] turnstile_keys`, §8.7)
//!   and its circuit breaker (§8.6), which outlive bundle swaps: a bundle
//!   that enables Turnstile without a secret disables the provider
//!   (`disabled(no_secret)`, ERROR log); a disabled-as-misconfigured
//!   provider comes back when the bundle version changes;
//! * [`Offer`]: what a request may offer (configuration, usability, the seal
//!   keys for `cData`); [`Countries`]: the two country sources of §8.1;
//! * [`ix_member`]: `ix.turnstile` (§7.2): sitekey, action (= the route
//!   class), `cdata` (§6.9, under `roots[0]`) and the widget language;
//! * [`Verifier`] / [`Dispatcher`] / [`OutboundBackground`]: siteverify runs
//!   on the background service `mg-outbound`, whose runtime built the HTTP
//!   client (§8.4); a proxy sends a [`Job`] over a bounded queue and waits at
//!   most the deadline plus [`ANSWER_SLACK_MS`]. A full queue or a missing
//!   answer is `Unavailable` (`busy` / `timeout`), never a pass.
//!
//! Nothing here contacts any host but the configured siteverify URL: the
//! production URL, or (tests only, `MG_EDGE_TEST_OUTBOUND=1`) a loopback
//! mock. Every test uses the loopback mock (D-52). Neither the token nor the
//! secret appears in a log line, an event or `Debug` output.

use crate::sites::BundleRuntime;
use async_trait::async_trait;
use mg_challenge::{SealKeys, parse_epoch_kid, turnstile_cdata_for, turnstile_cdata_matches};
use mg_core::{
    BoxFuture, EvalMode, Net, ProviderId, ProviderVerdict, SealedChallengeClaims, Selection,
    TurnstileChoice, VerdictOutcome,
};
use mg_edge_core::outbound::{
    BreakerState, CircuitBreaker, DisabledReason, Siteverify, SiteverifyExpect, SiteverifyReport,
    SiteverifyRequest, SiteverifyUrl, TurnstileSecrets, VerifyReason,
};
use mg_proto::v1::SiteBundle;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde_json::{Value, json};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// The environment switch that allows a loopback siteverify URL (§8.4).
pub const TEST_OUTBOUND_ENV: &str = "MG_EDGE_TEST_OUTBOUND";

/// Capacity of the siteverify job queue; a full queue answers `busy`.
pub const QUEUE_CAPACITY: usize = 256;

/// How long past a job's deadline a proxy still waits for its answer.
pub const ANSWER_SLACK_MS: u64 = 1_000;

/// Longest siteverify deadline (§7.5 step 13: `min(timeout_ms, 5000)`).
pub const MAX_DEADLINE_MS: u32 = 5_000;

/// Whether `MG_EDGE_TEST_OUTBOUND=1` is set (exactly `1`).
pub fn test_outbound_allowed() -> bool {
    std::env::var(TEST_OUTBOUND_ENV).is_ok_and(|v| v == "1")
}

// ---------------------------------------------------------------------------
// The bundle's provider configuration

/// The enabled Turnstile provider of a schema 2 bundle (§3.2, §8.2; checked
/// by `verify_bundle`).
#[derive(Debug, Clone, PartialEq)]
pub struct TurnstileRuntime {
    /// The public widget sitekey.
    pub sitekey: String,
    /// Exact FQDNs of the widget, lower-case.
    pub hostnames: Vec<String>,
    /// Route ids; empty: every route.
    pub route_ids: Vec<String>,
    /// Countries that never get Turnstile; empty by default (D-70).
    pub denied_countries: Vec<String>,
    /// 1000..=5000.
    pub timeout_ms: u32,
    /// `shadow`: a failure only falls back; `enforce`: it counts.
    pub mode: EvalMode,
    pub selection: Selection,
}

impl TurnstileRuntime {
    /// The bundle's `turnstile` provider when it is present and enabled
    /// (schema 1 bundles have none, D-66).
    pub fn from_bundle(b: &SiteBundle) -> Result<Option<Self>, String> {
        let Some(p) = b
            .providers
            .iter()
            .find(|p| p.id == ProviderId::Turnstile.as_str())
        else {
            return Ok(None);
        };
        if !p.enabled || b.schema_version < 2 {
            return Ok(None);
        }
        let mode = p
            .mode
            .parse::<EvalMode>()
            .map_err(|_| format!("providers[turnstile].mode {:?}", p.mode))?;
        let selection = p
            .selection
            .parse::<Selection>()
            .map_err(|_| format!("providers[turnstile].selection {:?}", p.selection))?;
        if !(1_000..=5_000).contains(&p.timeout_ms) {
            return Err(format!(
                "providers[turnstile].timeout_ms {} must be 1000..=5000",
                p.timeout_ms
            ));
        }
        Ok(Some(Self {
            sitekey: p.sitekey.clone(),
            hostnames: p.hostnames.iter().map(|h| h.to_ascii_lowercase()).collect(),
            route_ids: p.route_ids.clone(),
            denied_countries: p.denied_countries.clone(),
            timeout_ms: p.timeout_ms,
            mode,
            selection,
        }))
    }

    /// The siteverify deadline from `now_ms` (§7.5 step 13).
    pub fn deadline_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_add(i64::from(self.timeout_ms.min(MAX_DEADLINE_MS)))
    }
}

// ---------------------------------------------------------------------------
// Countries (§8.1)

/// The two country sources of §8.1, `None` when a source has nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Countries<'a> {
    /// GeoLite2 (`net.country`).
    pub geo: Option<&'a str>,
    /// Cloudflare's authenticated `cf-ipcountry` (`net.upstream_country`).
    pub cf: Option<&'a str>,
}

/// Two upper-case ASCII letters, not `XX` (no data) or `T1` (Tor).
fn country(c: Option<&str>) -> Option<&str> {
    c.filter(|c| {
        c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) && *c != "XX" && *c != "T1"
    })
}

impl<'a> Countries<'a> {
    /// From the request's `net` (§8.1): GeoLite2's country (MISSING without
    /// a `geoip-country` artifact) and the trusted `cf-ipcountry` (only with
    /// `cloudflare.location_headers` and an authenticated upstream);
    /// malformed values, `XX` and `T1` are nothing.
    pub fn of(net: &'a Net) -> Self {
        Self {
            geo: country(net.country.as_deref()),
            cf: country(net.upstream_country.as_deref()),
        }
    }

    /// Neither source knows the country.
    pub fn unknown(&self) -> bool {
        self.geo.is_none() && self.cf.is_none()
    }
}

// ---------------------------------------------------------------------------
// The site's secret and health

/// A site's Turnstile secret and circuit breaker (see the module docs).
pub struct SiteTurnstile {
    site: String,
    secrets: Option<Arc<TurnstileSecrets>>,
    breaker: OnceLock<Arc<CircuitBreaker>>,
    /// The bundle version the breaker last saw (§8.6: a misconfigured
    /// provider comes back with a new bundle version).
    version: Mutex<Option<u64>>,
}

impl fmt::Debug for SiteTurnstile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteTurnstile")
            .field("site", &self.site)
            .field("secret", &self.secrets.is_some())
            .field("breaker", &self.breaker.get())
            .finish()
    }
}

fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl SiteTurnstile {
    /// `secrets`: the parsed `turnstile_keys` credential, if configured.
    pub fn new(site: &str, secrets: Option<TurnstileSecrets>) -> Self {
        Self {
            site: site.to_owned(),
            secrets: secrets.map(Arc::new),
            breaker: OnceLock::new(),
            version: Mutex::new(None),
        }
    }

    pub fn secrets(&self) -> Option<&Arc<TurnstileSecrets>> {
        self.secrets.as_ref()
    }

    /// The breaker of (site, turnstile), created (and its gauge published)
    /// on first use.
    pub fn breaker(&self) -> &Arc<CircuitBreaker> {
        self.breaker
            .get_or_init(|| Arc::new(CircuitBreaker::new(&self.site, ProviderId::Turnstile)))
    }

    /// §8.2 "usable": a secret, and the breaker neither disabled nor open
    /// (half-open admits the trial verification).
    pub fn usable(&self, now_ms: i64) -> bool {
        self.secrets.is_some() && self.breaker().usable(now_ms)
    }

    /// Follows a new runtime of the site (start-up and every bundle swap):
    /// a bundle that enables Turnstile without a secret disables it
    /// (`disabled(no_secret)`, ERROR log); a new bundle version clears
    /// `disabled(misconfigured)` (§8.6).
    pub fn apply(&self, bundle: Option<&BundleRuntime>) {
        let Some(b) = bundle else { return };
        let mut seen = self.version.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = *seen != Some(b.version);
        *seen = Some(b.version);
        drop(seen);
        if b.turnstile.is_none() {
            return;
        }
        let breaker = self.breaker();
        if self.secrets.is_none() {
            if breaker.state(unix_now_ms()) != BreakerState::Disabled(DisabledReason::NoSecret) {
                log::error!(
                    "site {}: bundle version {} enables the Turnstile provider but edge.toml has no [[sites]] turnstile_keys: Turnstile is disabled (no_secret); visitors get the built-in providers (Phase 2 spec §8.2)",
                    self.site,
                    b.version
                );
            }
            breaker.disable(DisabledReason::NoSecret);
            return;
        }
        if changed
            && breaker.state(unix_now_ms()) == BreakerState::Disabled(DisabledReason::Misconfigured)
        {
            log::warn!(
                "site {}: bundle version {}: Turnstile enabled again after its secret was rejected",
                self.site,
                b.version
            );
            breaker.reset();
        }
    }
}

// ---------------------------------------------------------------------------
// What a request may offer

/// The site's Turnstile as one request sees it.
#[derive(Clone, Copy)]
pub struct Offer<'a> {
    pub cfg: &'a TurnstileRuntime,
    pub site: &'a SiteTurnstile,
    /// The site's seal roots (`cData`, §6.9).
    pub keys: &'a SealKeys,
    /// [`SiteTurnstile::usable`] when the request started.
    pub usable: bool,
}

impl fmt::Debug for Offer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Offer")
            .field("cfg", self.cfg)
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

impl<'a> Offer<'a> {
    /// The offer of a site whose bundle enables Turnstile; `None` otherwise.
    pub fn new(
        bundle: &'a BundleRuntime,
        site: &'a SiteTurnstile,
        keys: &'a SealKeys,
        now_ms: i64,
    ) -> Option<Self> {
        let cfg = bundle.turnstile.as_ref()?;
        Some(Self {
            cfg,
            site,
            keys,
            usable: site.usable(now_ms),
        })
    }

    /// mg-core's view (§5.4).
    pub fn choice(&self) -> TurnstileChoice<'a> {
        TurnstileChoice {
            selection: self.cfg.selection,
            route_ids: &self.cfg.route_ids,
            hostnames: &self.cfg.hostnames,
            denied_countries: &self.cfg.denied_countries,
            usable: self.usable,
        }
    }
}

/// The widget language of `ix.turnstile.lang` (§7.2): `zh-cn` for a zh-CN
/// page, otherwise `en`.
pub fn widget_lang(page_lang: &str) -> &'static str {
    if page_lang.eq_ignore_ascii_case("zh-CN") {
        "zh-cn"
    } else {
        "en"
    }
}

/// `ix.turnstile` of an interactive `C` that offers Turnstile (§7.2):
/// `sitekey`, `action` = `route_class`, `cdata` (§6.9, `roots[0]`, the
/// epoch of the `C`'s kid) and `lang`.
pub fn ix_member(offer: &Offer<'_>, claims: &SealedChallengeClaims, lang: &str) -> Value {
    let epoch = parse_epoch_kid(&claims.kid).unwrap_or_default();
    json!({
        "sitekey": offer.cfg.sitekey,
        "action": claims.route_class,
        "cdata": turnstile_cdata_for(offer.keys, &claims.site, epoch, &claims.nonce),
        "lang": lang,
    })
}

// ---------------------------------------------------------------------------
// Verification jobs

/// One siteverify call, owned so it can cross to the `mg-outbound` runtime.
pub struct Job {
    pub secrets: Arc<TurnstileSecrets>,
    /// The token (`pp`).
    pub token: String,
    /// The trusted client IP.
    pub remoteip: IpAddr,
    /// The submitted `C`'s claims: nonce, kid epoch, iat, route class, site.
    pub nonce: [u8; 16],
    pub epoch: u64,
    pub site_id: String,
    pub action: String,
    pub c_iat_ms: i64,
    /// The normalized request host and the configured hostnames.
    pub host: String,
    pub hostnames: Vec<String>,
    pub now_ms: i64,
    pub deadline_ms: i64,
    /// The site's seal roots (`cdata` is checked against every one).
    pub keys: SealKeys,
    pub breaker: Arc<CircuitBreaker>,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("site_id", &self.site_id)
            .field("action", &self.action)
            .field("host", &self.host)
            .field("now_ms", &self.now_ms)
            .field("deadline_ms", &self.deadline_ms)
            .finish_non_exhaustive() // no token, secret, address or nonce
    }
}

impl Job {
    /// The job of a submission of `claims` with `token`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer: &Offer<'_>,
        secrets: &Arc<TurnstileSecrets>,
        claims: &SealedChallengeClaims,
        token: &str,
        remoteip: IpAddr,
        host: &str,
        now_ms: i64,
    ) -> Self {
        Self {
            secrets: Arc::clone(secrets),
            token: token.to_owned(),
            remoteip,
            nonce: claims.nonce,
            epoch: parse_epoch_kid(&claims.kid).unwrap_or_default(),
            site_id: claims.site.clone(),
            action: claims.route_class.clone(),
            c_iat_ms: claims.iat_ms,
            host: host.to_owned(),
            hostnames: offer.cfg.hostnames.clone(),
            now_ms,
            deadline_ms: offer.cfg.deadline_ms(now_ms),
            keys: offer.keys.clone(),
            breaker: Arc::clone(offer.site.breaker()),
        }
    }

    /// Runs the verification behind the site's breaker (§8.4-§8.6).
    pub async fn run(&self, sv: &Siteverify) -> SiteverifyReport {
        let (keys, site, epoch, nonce) =
            (&self.keys, self.site_id.as_str(), self.epoch, self.nonce);
        let cdata_ok = move |c: &str| turnstile_cdata_matches(keys, site, epoch, &nonce, c);
        let req = SiteverifyRequest {
            secrets: &self.secrets,
            response: &self.token,
            remoteip: self.remoteip,
            nonce: &self.nonce,
        };
        let expect = SiteverifyExpect {
            host: &self.host,
            hostnames: &self.hostnames,
            action: &self.action,
            c_iat_ms: self.c_iat_ms,
            now_ms: self.now_ms,
            deadline_ms: self.deadline_ms,
            cdata_ok: &cdata_ok,
        };
        sv.verify_with_breaker(&self.breaker, &req, &expect).await
    }
}

/// A verification that sent nothing: `Unavailable` with `reason` (`busy`
/// for a full queue or a missing `mg-outbound`, `timeout` for an answer that
/// did not come in time). Neutral for the breaker.
pub fn not_sent(reason: VerifyReason) -> SiteverifyReport {
    SiteverifyReport {
        verdict: ProviderVerdict::new(
            VerdictOutcome::Unavailable,
            mg_edge_core::outbound::reason::PROVIDER_UNAVAILABLE,
        ),
        reason,
        error_codes: Vec::new(),
        requests: 0,
        previous_secret_used: false,
        latency_ms: 0,
    }
}

/// Runs siteverify jobs.
pub trait Verifier: Send + Sync {
    fn verify(&self, job: Job) -> BoxFuture<'_, SiteverifyReport>;
}

/// The verifier of a process without any Turnstile secret: every job is
/// `Unavailable` (`busy`). (Unreachable in practice: without a secret the
/// provider is never usable, so no `C` offers it.)
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVerifier;

impl Verifier for NoVerifier {
    fn verify(&self, _job: Job) -> BoxFuture<'_, SiteverifyReport> {
        Box::pin(async { not_sent(VerifyReason::Busy) })
    }
}

type Queued = (Job, oneshot::Sender<SiteverifyReport>);

/// The proxies' side of `mg-outbound`: a bounded queue of jobs.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    tx: mpsc::Sender<Queued>,
}

/// The `mg-outbound` side of the queue.
#[derive(Debug)]
pub struct JobReceiver {
    rx: mpsc::Receiver<Queued>,
}

impl Dispatcher {
    pub fn new(capacity: usize) -> (Self, JobReceiver) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self { tx }, JobReceiver { rx })
    }
}

impl Verifier for Dispatcher {
    fn verify(&self, job: Job) -> BoxFuture<'_, SiteverifyReport> {
        Box::pin(async move {
            let wait_ms = u64::try_from(job.deadline_ms.saturating_sub(job.now_ms).max(0))
                .unwrap_or(0)
                .saturating_add(ANSWER_SLACK_MS);
            let (tx, rx) = oneshot::channel();
            if self.tx.try_send((job, tx)).is_err() {
                return not_sent(VerifyReason::Busy);
            }
            match tokio::time::timeout(Duration::from_millis(wait_ms), rx).await {
                Ok(Ok(report)) => report,
                Ok(Err(_)) => not_sent(VerifyReason::Busy),
                Err(_) => not_sent(VerifyReason::Timeout),
            }
        })
    }
}

/// Serves `rx` with `sv` until the queue closes or `stop` resolves: one task
/// per job (the client's own concurrency limit bounds the requests).
pub async fn serve(
    mut rx: JobReceiver,
    sv: Arc<Siteverify>,
    stop: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(stop);
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            job = rx.rx.recv() => {
                let Some((job, reply)) = job else { break };
                let sv = Arc::clone(&sv);
                tasks.spawn(async move {
                    let report = job.run(&sv).await;
                    let _ = reply.send(report);
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            () = &mut stop => break,
        }
    }
    tasks.shutdown().await;
}

/// `mg-outbound`: builds the siteverify client on its own runtime (§8.4)
/// and runs the jobs of the [`Dispatcher`].
pub struct OutboundBackground {
    rx: Mutex<Option<JobReceiver>>,
    url: SiteverifyUrl,
}

impl fmt::Debug for OutboundBackground {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundBackground")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl OutboundBackground {
    pub fn new(rx: JobReceiver, url: SiteverifyUrl) -> Self {
        Self {
            rx: Mutex::new(Some(rx)),
            url,
        }
    }
}

#[async_trait]
impl BackgroundService for OutboundBackground {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(rx) = self
            .rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let sv = match Siteverify::build(self.url.clone()) {
            Ok(sv) => Arc::new(sv),
            Err(e) => {
                // Dropping the receiver answers every job `busy`: Turnstile
                // is unavailable and visitors fall back (§8.5).
                log::error!("mg-outbound: {e}; Turnstile verifications are unavailable");
                return;
            }
        };
        let stop = async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        };
        serve(rx, sv, stop).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mg_edge_core::testkit::siteverify::{FakeSiteverify, SvReply};
    use mg_proto::v1 as pb;

    /// A verifier that runs jobs on the caller's runtime (unit tests only).
    pub(crate) struct DirectVerifier(pub Siteverify);

    impl Verifier for DirectVerifier {
        fn verify(&self, job: Job) -> BoxFuture<'_, SiteverifyReport> {
            Box::pin(async move { job.run(&self.0).await })
        }
    }

    /// The test bundle's Turnstile provider (§3.2).
    pub(crate) fn provider() -> pb::ProviderConfig {
        pb::ProviderConfig {
            id: "turnstile".into(),
            enabled: true,
            sitekey: "0x4AAAAAAAtest-sitekey".into(),
            denied_countries: Vec::new(),
            route_ids: Vec::new(),
            timeout_ms: 2_000,
            fallback: "self_hold".into(),
            mode: "enforce".into(),
            hostnames: vec!["example.com".into(), "www.example.com".into()],
            selection: "first".into(),
            ..Default::default()
        }
    }

    #[test]
    fn runtime_from_bundle() {
        let mut b = mg_edge_core::testkit::http::test_site_bundle_v2("blog", &["example.com"], 1);
        assert_eq!(TurnstileRuntime::from_bundle(&b).unwrap(), None);
        let mut p = provider();
        p.hostnames = vec!["Example.COM".into()];
        p.mode = "shadow".into();
        p.selection = "escalate_after_fail".into();
        p.denied_countries = vec!["CN".into()];
        b.providers = vec![p.clone()];
        let rt = TurnstileRuntime::from_bundle(&b).unwrap().unwrap();
        assert_eq!(rt.hostnames, vec!["example.com"]);
        assert_eq!(
            (rt.mode, rt.selection),
            (EvalMode::Shadow, Selection::EscalateAfterFail)
        );
        assert_eq!(rt.deadline_ms(1_000), 3_000);
        let five = TurnstileRuntime {
            timeout_ms: 5_000,
            ..rt.clone()
        };
        assert_eq!(five.deadline_ms(0), 5_000);
        // Disabled: absent at runtime.
        b.providers[0].enabled = false;
        assert_eq!(TurnstileRuntime::from_bundle(&b).unwrap(), None);
        b.providers[0].enabled = true;
        b.providers[0].mode = "off".into();
        assert!(TurnstileRuntime::from_bundle(&b).is_err());
    }

    #[test]
    fn countries_follow_section_8_1() {
        let mut net = Net::default();
        assert!(Countries::of(&net).unknown());
        net.country = Some("CN".into());
        net.upstream_country = Some("T1".into());
        let c = Countries::of(&net);
        assert_eq!((c.geo, c.cf), (Some("CN"), None));
        net.country = Some("cn".into());
        net.upstream_country = Some("XX".into());
        assert!(Countries::of(&net).unknown());
        net.upstream_country = Some("HK".into());
        assert_eq!(Countries::of(&net).cf, Some("HK"));
        assert_eq!(widget_lang("zh-CN"), "zh-cn");
        assert_eq!(widget_lang("en"), "en");
    }

    fn runtime_with(version: u64, turnstile: bool) -> BundleRuntime {
        let mut b = mg_edge_core::testkit::http::test_site_bundle_v2(
            "blog",
            &crate::test_support::HOSTS,
            version,
        );
        if turnstile {
            b.providers = vec![provider()];
        }
        crate::test_support::runtime(&b, true)
    }

    /// §8.2 / §8.6: no secret → `disabled(no_secret)`; a rejected secret
    /// stays disabled until the bundle version changes.
    #[test]
    fn site_state_follows_bundles_and_secrets() {
        let now = unix_now_ms();
        let without = SiteTurnstile::new("blog-ts-a", None);
        without.apply(Some(&runtime_with(1, true)));
        assert!(!without.usable(now));
        assert_eq!(
            without.breaker().state(now),
            BreakerState::Disabled(DisabledReason::NoSecret)
        );

        let secrets = TurnstileSecrets::new(vec!["s1".into()]).unwrap();
        let with = SiteTurnstile::new("blog-ts-b", Some(secrets));
        with.apply(Some(&runtime_with(1, true)));
        assert!(with.usable(now));
        with.breaker().disable(DisabledReason::Misconfigured);
        assert!(!with.usable(now));
        with.apply(Some(&runtime_with(1, true)));
        assert!(!with.usable(now), "same version: still disabled");
        with.apply(Some(&runtime_with(2, true)));
        assert!(with.usable(now), "a new version clears misconfigured");
        // A bundle without Turnstile leaves the breaker alone.
        with.breaker().disable(DisabledReason::Misconfigured);
        with.apply(Some(&runtime_with(3, false)));
        assert!(!with.usable(now));
        assert!(!format!("{with:?}").contains("s1"));
    }

    fn claims() -> SealedChallengeClaims {
        SealedChallengeClaims {
            v: SealedChallengeClaims::VERSION,
            kid: mg_challenge::epoch_kid(20_717),
            nonce: [3; 16],
            site: "blog".into(),
            route_class: "login".into(),
            challenge_type: mg_core::ChallengeType::Interactive,
            providers: vec![
                ProviderId::Turnstile,
                ProviderId::SelfHold,
                ProviderId::PowA11y,
            ],
            risk_band: mg_core::RiskBand::Low,
            attempt_no: 1,
            iat_ms: 1_790_000_000_000,
            exp_ms: 1_790_000_600_000,
            ui_seed: 7,
            pow: None,
            ret_hash: vec![0; 16],
            bind: mg_core::ChallengeBind::default(),
            renew_no: 0,
        }
    }

    fn seal_keys() -> SealKeys {
        crate::test_support::keys().seal
    }

    /// `ix.turnstile` carries the `cData` that siteverify must echo.
    #[test]
    fn ix_member_and_cdata() {
        let cfg = TurnstileRuntime::from_bundle(&{
            let mut b =
                mg_edge_core::testkit::http::test_site_bundle_v2("blog", &["example.com"], 1);
            b.providers = vec![provider()];
            b
        })
        .unwrap()
        .unwrap();
        let site = SiteTurnstile::new("blog", None);
        let keys = seal_keys();
        let offer = Offer {
            cfg: &cfg,
            site: &site,
            keys: &keys,
            usable: true,
        };
        let c = claims();
        let m = ix_member(&offer, &c, "zh-cn");
        assert_eq!(m["sitekey"], "0x4AAAAAAAtest-sitekey");
        assert_eq!(m["action"], "login");
        assert_eq!(m["lang"], "zh-cn");
        let cdata = m["cdata"].as_str().unwrap();
        assert_eq!(cdata.len(), mg_challenge::CDATA_LEN);
        assert!(turnstile_cdata_matches(
            &keys, "blog", 20_717, &[3; 16], cdata
        ));
        let choice = offer.choice();
        assert_eq!(choice.selection, Selection::First);
        assert!(choice.usable);
    }

    fn job(url_secrets: &Arc<TurnstileSecrets>, breaker: &Arc<CircuitBreaker>, now: i64) -> Job {
        let c = claims();
        Job {
            secrets: Arc::clone(url_secrets),
            token: "tok-123".into(),
            remoteip: "198.51.100.7".parse().unwrap(),
            nonce: c.nonce,
            epoch: 20_717,
            site_id: "blog".into(),
            action: "login".into(),
            c_iat_ms: now - 1_000,
            host: "example.com".into(),
            hostnames: vec!["example.com".into()],
            now_ms: now,
            deadline_ms: now + 2_000,
            keys: seal_keys(),
            breaker: Arc::clone(breaker),
        }
    }

    /// The dispatcher hands jobs to another runtime (as `mg-outbound`),
    /// answers `busy` without one, and never passes a reply whose `cdata`
    /// is not the `C`'s. Loopback mock only (D-52).
    #[test]
    fn dispatcher_runs_jobs_on_another_runtime() {
        let mock = FakeSiteverify::start().unwrap();
        let url = mg_edge_core::outbound::validate_siteverify_url(&mock.url(), true).unwrap();
        let (dispatcher, rx) = Dispatcher::new(4);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let sv = Arc::new(Siteverify::build(url).unwrap());
                serve(rx, sv, async move {
                    let _ = stop_rx.await;
                })
                .await;
            });
        });
        let secrets = Arc::new(TurnstileSecrets::new(vec!["sec-current".into()]).unwrap());
        let breaker = Arc::new(CircuitBreaker::new("blog-dispatch", ProviderId::Turnstile));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let now = unix_now_ms();
        let ts = chrono_like(now);
        let good = turnstile_cdata_for(&seal_keys(), "blog", 20_717, &[3; 16]);
        mock.push_replies([
            SvReply::success("example.com", "login", &good, &ts),
            SvReply::success("example.com", "login", &"A".repeat(43), &ts),
        ]);
        let r = rt.block_on(dispatcher.verify(job(&secrets, &breaker, now)));
        assert_eq!(r.verdict.outcome, VerdictOutcome::Pass, "{r:?}");
        let r = rt.block_on(dispatcher.verify(job(&secrets, &breaker, now)));
        assert_eq!(r.verdict.outcome, VerdictOutcome::Fail);
        assert_eq!(r.reason, VerifyReason::Cdata);
        let seen = mock.requests();
        assert_eq!(seen[0].secret().as_deref(), Some("sec-current"));
        assert_eq!(seen[0].response().as_deref(), Some("tok-123"));
        assert_eq!(seen[0].remoteip().as_deref(), Some("198.51.100.7"));
        assert_eq!(
            seen[0].idempotency_key().unwrap(),
            mg_challenge::idempotency_key(&[3; 16], false)
        );
        stop_tx.send(()).unwrap();
        worker.join().unwrap();
        // No mg-outbound any more: busy, nothing sent.
        let r = rt.block_on(dispatcher.verify(job(&secrets, &breaker, now)));
        assert_eq!(
            (r.verdict.outcome, r.reason, r.requests),
            (VerdictOutcome::Unavailable, VerifyReason::Busy, 0)
        );
        let r = rt.block_on(NoVerifier.verify(job(&secrets, &breaker, now)));
        assert_eq!(r.verdict.outcome, VerdictOutcome::Unavailable);
        assert!(!format!("{:?}", job(&secrets, &breaker, now)).contains("tok-123"));
    }

    /// A job that nobody answers in time is `timeout`, never a pass.
    #[test]
    fn unanswered_job_times_out() {
        let (dispatcher, _rx) = Dispatcher::new(1);
        let secrets = Arc::new(TurnstileSecrets::new(vec!["x".into()]).unwrap());
        let breaker = Arc::new(CircuitBreaker::new("blog-timeout", ProviderId::Turnstile));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let now = unix_now_ms();
        let mut j = job(&secrets, &breaker, now);
        j.deadline_ms = now; // waits ANSWER_SLACK_MS only
        let started = std::time::Instant::now();
        let r = rt.block_on(dispatcher.verify(j));
        assert_eq!(r.reason, VerifyReason::Timeout);
        assert!(started.elapsed() >= Duration::from_millis(ANSWER_SLACK_MS));
    }

    /// RFC 3339 (UTC, milliseconds) of Unix ms `ms`.
    pub(crate) fn chrono_like(ms: i64) -> String {
        let secs = ms.div_euclid(1000);
        let millis = ms.rem_euclid(1000);
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        // Civil from days (Howard Hinnant).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mo = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if mo <= 2 { y + 1 } else { y };
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
    }

    #[test]
    fn rfc3339_helper() {
        assert_eq!(chrono_like(1_790_000_000_000), "2026-09-21T14:13:20.000Z");
        assert_eq!(
            mg_edge_core::outbound::parse_rfc3339_ns(&chrono_like(1_790_000_000_123)),
            Some(1_790_000_000_123_000_000)
        );
    }
}
