//! Sites: the §9.10 state machine, the bundle → runtime conversion and route
//! matching (docs/impl/phase1-spec.md §9.4, §9.10, D-21, I-3, I-4).
//!
//! Every `[[sites]]` entry becomes one [`Site`]: its edge.toml settings, its
//! key files, and an [`ArcSwap`] with the current [`SiteRuntime`]. Requests
//! load the runtime once and keep that `Arc` to the end (a bundle swap never
//! changes a request in flight); the `mg-bundles` background service stores
//! a new runtime whenever a verified candidate converts ([`Site::apply`]).
//!
//! | State | When | Requests |
//! |---|---|---|
//! | `active` | a verified bundle is in effect | normal |
//! | `bootstrap_open` | never had a bundle, `bootstrap = "open"` | forwarded and recorded (`rule_id = "bootstrap"`) |
//! | `bootstrap_closed` | never had a bundle, `bootstrap = "closed"` | 503 |
//! | `lkg_invalid` | the LKG file exists but cannot be used | 503, or like bootstrap-open with `on_lkg_invalid = "open"` (`rule_id = "lkg_invalid_open"`) |
//!
//! Any bundle that verifies and converts moves a site to `active`; nothing
//! ever moves it back (a later rejected candidate keeps the bundle in effect).

mod convert;
mod routing;

pub use convert::{
    BundleRuntime, EnvRuntime, Intel, LimiterDim, LimiterScope, LimiterSpec, RouteRuntime,
    build_runtime, default_challenge, default_clearance, default_crawler_policy, default_events,
    default_origin_headers, default_scoring,
};
pub use routing::{RouteMatch, select_env, select_route};

use crate::config::{BootstrapMode, EdgeConfig, IntelConfig, LkgInvalidMode, SiteConfig};
use crate::creds::Secret;
use crate::metrics::metrics;
use arc_swap::ArcSwap;
use mg_challenge::{SealKeys, Sealer};
use mg_core::UpstreamProfileKind;
use mg_edge_core::bundle::VerifiedBundle;
use mg_intel::CacheConfig;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

/// Where a site stands (§9.10), the `state` label of `mg_site_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteState {
    Active,
    BootstrapOpen,
    BootstrapClosed,
    LkgInvalid,
}

impl SiteState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::BootstrapOpen => "bootstrap_open",
            Self::BootstrapClosed => "bootstrap_closed",
            Self::LkgInvalid => "lkg_invalid",
        }
    }
}

/// How a site serves requests right now.
#[derive(Debug, Clone, Copy)]
pub enum Serving<'a> {
    /// A bundle is in effect.
    Active(&'a BundleRuntime),
    /// Forward everything and record it with this `rule_id`
    /// (`bootstrap` or `lkg_invalid_open`), `bundle_version = 0`.
    Open { rule_id: &'static str },
    /// 503 (`bootstrap_closed`, or `lkg_invalid` with `on_lkg_invalid =
    /// "closed"`).
    Unavailable,
}

impl Serving<'_> {
    /// The `mode` of `mg_oversize_total` when oversize requests are forwarded
    /// instead of rejected (I-2), `None` under enforce and for unavailable
    /// sites.
    pub fn record_only_mode(&self) -> Option<&'static str> {
        match self {
            Self::Active(b) if b.monitor_only => Some("monitor"),
            Self::Active(_) | Self::Unavailable => None,
            Self::Open { rule_id } => Some(rule_id),
        }
    }
}

/// The current runtime of a site.
#[derive(Debug)]
pub struct SiteRuntime {
    pub state: SiteState,
    /// `Some` iff `state == Active`.
    pub bundle: Option<Arc<BundleRuntime>>,
    /// Why the LKG was unusable (`lkg_invalid` only), for logs and
    /// `--check-config`.
    pub lkg_error: Option<String>,
}

impl SiteRuntime {
    /// A site without a bundle: `bootstrap_open` or `bootstrap_closed`.
    pub fn bootstrap(mode: BootstrapMode) -> Self {
        Self {
            state: match mode {
                BootstrapMode::Open => SiteState::BootstrapOpen,
                BootstrapMode::Closed => SiteState::BootstrapClosed,
            },
            bundle: None,
            lkg_error: None,
        }
    }

    /// A site whose LKG exists but cannot be used.
    pub fn lkg_invalid(reason: String) -> Self {
        Self {
            state: SiteState::LkgInvalid,
            bundle: None,
            lkg_error: Some(reason),
        }
    }

    /// A site with a bundle in effect.
    pub fn active(bundle: BundleRuntime) -> Self {
        Self {
            state: SiteState::Active,
            bundle: Some(Arc::new(bundle)),
            lkg_error: None,
        }
    }

    /// How requests are served (`settings` decides lkg_invalid's behaviour).
    pub fn serving(&self, settings: &SiteSettings) -> Serving<'_> {
        match (self.state, &self.bundle) {
            (SiteState::Active, Some(b)) => Serving::Active(b),
            (SiteState::BootstrapOpen, _) => Serving::Open {
                rule_id: "bootstrap",
            },
            (SiteState::LkgInvalid, _) if settings.on_lkg_invalid == LkgInvalidMode::Open => {
                Serving::Open {
                    rule_id: "lkg_invalid_open",
                }
            }
            _ => Serving::Unavailable,
        }
    }

    /// The zones whose `CF-Worker` subrequests are the owner's: the bundle's
    /// `cloudflare.owner_zones` once a bundle is in effect, otherwise the
    /// edge.toml `bootstrap_owner_zones` (I-4; empty: every Worker is foreign).
    pub fn owner_zones<'a>(&'a self, settings: &'a SiteSettings) -> &'a [String] {
        match self.bundle.as_deref().and_then(|b| b.cloudflare.as_ref()) {
            Some(cf) => &cf.owner_zones,
            None if self.bundle.is_some() => &[],
            None => &settings.bootstrap_owner_zones,
        }
    }
}

/// The edge.toml side of a site.
#[derive(Debug, Clone)]
pub struct SiteSettings {
    pub id: String,
    pub hosts: Vec<String>,
    /// edge.toml listener names that route to this site.
    pub listeners: Vec<String>,
    /// The profile kind of each of those listeners (§9.10: the bundle's
    /// `upstream.kind` must equal every one of them).
    pub listener_kinds: Vec<(String, UpstreamProfileKind)>,
    pub origin: SocketAddr,
    pub bootstrap: BootstrapMode,
    pub on_lkg_invalid: LkgInvalidMode,
    pub bootstrap_owner_zones: Vec<String>,
    /// The rDNS cache of the site's crawler verifier (edge.toml `[intel]`,
    /// [`crawler_cache_config`]).
    pub crawler_cache: CacheConfig,
}

/// The crawler verifier's cache settings from `[intel]` (§7.3, §9.6):
/// `rdns_cache_capacity`, the default result TTLs, and I-17's in-flight TTL
/// `2 × dns_timeout_ms + 3000`, strictly longer than a job's whole deadline
/// (`2 × dns_timeout_ms + 1 s`, [`crate::dns::job_deadline`]) plus queueing,
/// so an in-flight mark never expires while its job may still report.
pub fn crawler_cache_config(intel: &IntelConfig) -> CacheConfig {
    let dns = i64::try_from(intel.dns_timeout_ms).unwrap_or(i64::MAX / 4);
    CacheConfig {
        capacity: intel.rdns_cache_capacity,
        inflight_ttl_ms: dns.saturating_mul(2).saturating_add(3_000),
        ..CacheConfig::default()
    }
}

impl SiteSettings {
    /// From the site's `[[sites]]` entry (listener names already validated).
    pub fn new(site: &SiteConfig, cfg: &EdgeConfig) -> Self {
        let listener_kinds = site
            .listeners
            .iter()
            .filter_map(|name| cfg.listener(name).map(|l| (name.clone(), l.profile.kind())))
            .collect();
        Self {
            id: site.id.clone(),
            hosts: site.hosts.clone(),
            listeners: site.listeners.clone(),
            listener_kinds,
            origin: site.origin,
            bootstrap: site.bootstrap,
            on_lkg_invalid: site.on_lkg_invalid,
            bootstrap_owner_zones: site.bootstrap_owner_zones.clone(),
            crawler_cache: crawler_cache_config(&cfg.intel),
        }
    }
}

/// A site's key material from edge.toml credentials (§12.7).
pub struct SiteKeys {
    /// `seal.root.json`, parsed at start-up (independent of the bundle).
    pub seal: SealKeys,
    /// `token.keys.json` bytes; parsed against each bundle's
    /// `token_key_ids` ([`build_runtime`]).
    pub token_file: Secret,
}

impl fmt::Debug for SiteKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteKeys")
            .field("seal", &self.seal)
            .field("token_file", &self.token_file)
            .finish()
    }
}

/// One site: settings, keys and the swappable runtime.
pub struct Site {
    pub settings: SiteSettings,
    pub keys: SiteKeys,
    /// Seals and opens the site's challenges (§6.2). Built once from
    /// `keys.seal`, so its epoch-key cache lives as long as the process and
    /// is independent of bundle swaps (the seal roots are edge.toml
    /// credentials, not bundle content).
    pub sealer: Sealer,
    runtime: ArcSwap<SiteRuntime>,
}

impl fmt::Debug for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rt = self.runtime.load();
        f.debug_struct("Site")
            .field("id", &self.settings.id)
            .field("state", &rt.state)
            .field(
                "version",
                &rt.bundle.as_ref().map(|b| b.version).unwrap_or(0),
            )
            .finish()
    }
}

impl Site {
    /// A site with its initial runtime (from `main()`); publishes
    /// `mg_site_state`.
    pub fn new(settings: SiteSettings, keys: SiteKeys, initial: SiteRuntime) -> Self {
        metrics().set_site_state(&settings.id, initial.state.as_str());
        let sealer = Sealer::new(&settings.id, keys.seal.clone());
        Self {
            settings,
            keys,
            sealer,
            runtime: ArcSwap::from_pointee(initial),
        }
    }

    /// The runtime in effect (keep the `Arc` for the whole request).
    pub fn runtime(&self) -> Arc<SiteRuntime> {
        self.runtime.load_full()
    }

    /// Swaps in `rt` and publishes `mg_site_state`.
    pub fn store(&self, rt: SiteRuntime) {
        metrics().set_site_state(&self.settings.id, rt.state.as_str());
        self.runtime.store(Arc::new(rt));
    }

    /// The `poll_loop` `apply` callback: converts a verified bundle with its
    /// artifacts (absent names are MISSING) and, only if that succeeds,
    /// makes it the site's runtime. On error nothing changes and the poll
    /// loop counts the candidate as rejected.
    pub fn apply(
        &self,
        vb: &VerifiedBundle,
        artifacts: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), String> {
        let mut rt = build_runtime(&self.settings, &self.keys, vb, artifacts)?;
        if let Some(previous) = &self.runtime().bundle {
            rt.adopt_crawler_state(previous);
        }
        let missing = rt.missing_artifacts.len();
        let version = rt.version;
        self.store(SiteRuntime::active(rt));
        if missing > 0 {
            log::warn!(
                "site {}: bundle version {version} in effect with {missing} artifact(s) missing (their fields are MISSING)",
                self.settings.id
            );
        }
        Ok(())
    }
}

/// Every site, indexed by host.
#[derive(Debug, Default)]
pub struct Sites {
    list: Vec<Arc<Site>>,
    by_host: HashMap<String, usize>,
}

impl Sites {
    /// Hosts are unique across sites (edge.toml validation).
    pub fn new(list: Vec<Arc<Site>>) -> Self {
        let mut by_host = HashMap::new();
        for (i, s) in list.iter().enumerate() {
            for h in &s.settings.hosts {
                by_host.insert(h.clone(), i);
            }
        }
        Self { list, by_host }
    }

    /// The site serving the normalized host `host`.
    pub fn by_host(&self, host: &str) -> Option<&Arc<Site>> {
        self.by_host.get(host).map(|&i| &self.list[i])
    }

    /// The site with id `id`.
    pub fn by_id(&self, id: &str) -> Option<&Arc<Site>> {
        self.list.iter().find(|s| s.settings.id == id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Site>> {
        self.list.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-17: an in-flight mark outlives the whole rDNS job.
    #[test]
    fn crawler_cache_follows_intel() {
        let intel = IntelConfig {
            dns_timeout_ms: 2_000,
            rdns_cache_capacity: 1234,
            ..IntelConfig::default()
        };
        let c = crawler_cache_config(&intel);
        assert_eq!(c.capacity, 1234);
        assert_eq!(c.inflight_ttl_ms, 7_000);
        let job = crate::dns::job_deadline(intel.dns_timeout_ms);
        assert!(i64::try_from(job.as_millis()).unwrap() < c.inflight_ttl_ms);
        let d = CacheConfig::default();
        assert_eq!(
            (c.pass_ttl_ms, c.fail_ttl_ms, c.error_ttl_ms),
            (d.pass_ttl_ms, d.fail_ttl_ms, d.error_ttl_ms)
        );
    }
}
