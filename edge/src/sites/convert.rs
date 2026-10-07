//! Verified bundle → site runtime (§9.10 "lists / rules / IR (incl.
//! max_steps) / routes / limiters convert", §8.3 defaults, §12 artifacts).
//!
//! `mg_edge_core::bundle::verify_bundle` has already checked the signature,
//! identity, hosts and the §8.2 bounds. [`build_runtime`] runs the remaining
//! checks that need edge.toml, the site's credentials or other crates, and
//! fails the whole bundle on the first problem:
//!
//! * `upstream.kind` equals the profile of every listener serving the site;
//! * every `token_key_ids[*]` is in `token.keys.json` (I-14);
//! * every rule converts with `mg_proto::ir::rule_from_proto` (IR limits,
//!   `max_steps` recomputed, params per action, Phase 2 actions rejected);
//! * every route pattern compiles to a `mg_core::policy::Glob`;
//! * every limiter has GCRA parameters, a known key, action, mode and scope,
//!   and names existing routes;
//! * the `challenge` message yields the parameters of the built-in
//!   `/__mg/c` limiters (`mg_edge_core::state::builtin::ChallengeLimits`,
//!   §9.8);
//! * every artifact that is present parses with `mg-intel` (an empty
//!   `tor-exits` / `datacenter-asns` list is a valid empty set); an artifact
//!   that is referenced but absent is MISSING (start-up LKG only).
//!
//! Messages that are absent as a whole get the §8.3 defaults; present
//! messages are used as they are (proto3 cannot tell "unset" from zero).
//!
//! WP-E1b adds the per-environment Decision Core ([`EnvRuntime::core`],
//! built by [`crate::decide::build_core`]) and the crawler verifier of the
//! `crawler-registry` artifact ([`Intel::crawler`]).

use super::{SiteKeys, SiteSettings};
use mg_challenge::TokenKeySet;
use mg_core::gcra::GcraParams;
use mg_core::policy::{Glob, NamedLists, Rule};
use mg_core::{
    ChallengeType, Channel, DecisionCore, LimiterAction, RouteSensitivity, UpstreamProfileKind,
};
use mg_edge_core::bundle::VerifiedBundle;
use mg_edge_core::state::builtin::ChallengeLimits;
use mg_intel::{ArtifactKind, CrawlerRegistry, CrawlerVerifier, GeoDb, IpSet};
use mg_proto::ir::rule_from_proto;
use mg_proto::v1::{
    ChallengeConfig, ClearanceConfig, CloudflareSiteConfig, CrawlerPolicy, EventConfig,
    OriginHeaderConfig, RateLimit, Route, ScoringConfig, challenge_config::PowBits,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// A converted bundle: everything the request path needs, immutable.
pub struct BundleRuntime {
    pub site_id: String,
    pub version: u64,
    /// Lower-case hex SHA-256 of the signed bundle bytes.
    pub sha256_hex: String,
    pub monitor_only: bool,
    pub upstream_kind: UpstreamProfileKind,
    pub expected_mask: u32,
    pub allowed_listeners: BTreeSet<String>,
    pub case_insensitive_paths: bool,
    pub share_ip_verdicts: bool,
    pub environments: Vec<EnvRuntime>,
    /// The site's named lists (`list()` / `ip_in`).
    pub lists: NamedLists,
    /// Clearance token keys allowed by `token_key_ids` (`[0]` signs).
    pub token_keys: TokenKeySet,
    pub challenge: ChallengeConfig,
    /// The built-in `/__mg/c` limiters of `challenge` (§9.8).
    pub challenge_limits: ChallengeLimits,
    pub clearance: ClearanceConfig,
    pub scoring: ScoringConfig,
    pub crawler_policy: CrawlerPolicy,
    pub events: EventConfig,
    pub origin_headers: OriginHeaderConfig,
    /// Present iff `upstream.kind == cloudflare`.
    pub cloudflare: Option<CloudflareSiteConfig>,
    pub intel: Intel,
    /// `ArtifactRef.name`s referenced by the bundle but not available: their
    /// fields are MISSING (§9.10).
    pub missing_artifacts: BTreeSet<String>,
}

impl fmt::Debug for BundleRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleRuntime")
            .field("site_id", &self.site_id)
            .field("version", &self.version)
            .field("sha256", &self.sha256_hex)
            .field("monitor_only", &self.monitor_only)
            .field("upstream_kind", &self.upstream_kind)
            .field("environments", &self.environments)
            .field("token_keys", &self.token_keys)
            .field("intel", &self.intel)
            .field("missing_artifacts", &self.missing_artifacts)
            .finish_non_exhaustive()
    }
}

impl BundleRuntime {
    /// The environment serving `host`.
    pub fn env_for_host(&self, host: &str) -> Option<&EnvRuntime> {
        super::select_env(&self.environments, host)
    }

    /// Keeps `previous`'s crawler verifier (its rDNS cache and in-flight
    /// marks) when both bundles carry the same `crawler-registry` artifact:
    /// a bundle reload that does not change the registry must neither forget
    /// verified crawlers nor re-run their rDNS. With a different registry the
    /// new verifier stays; jobs of the old one keep reporting to the old one
    /// (they carry it, ruling I-26).
    pub fn adopt_crawler_state(&mut self, previous: &BundleRuntime) {
        if let (Some(sha), Some(prev_sha), Some(verifier)) = (
            &self.intel.crawler_sha,
            &previous.intel.crawler_sha,
            &previous.intel.crawler,
        ) && sha == prev_sha
        {
            self.intel.crawler = Some(Arc::clone(verifier));
        }
    }
}

/// Parsed intelligence artifacts; `None` = not in the bundle, or MISSING.
#[derive(Debug, Default)]
pub struct Intel {
    /// GeoLite2 ASN / country (either may be absent).
    pub geo: Option<Arc<GeoDb>>,
    pub cloudflare_ips: Option<Arc<IpSet>>,
    pub crawler_registry: Option<Arc<CrawlerRegistry>>,
    /// The verifier of `crawler_registry` (rDNS cache and in-flight jobs,
    /// §7.3, §9.6).
    pub crawler: Option<Arc<CrawlerVerifier>>,
    /// SHA-256 of the `crawler-registry` artifact (verifier reuse across
    /// reloads, [`BundleRuntime::adopt_crawler_state`]).
    pub crawler_sha: Option<String>,
    pub datacenter_asns: Option<Arc<BTreeSet<u32>>>,
    pub tor_exits: Option<Arc<IpSet>>,
}

impl Intel {
    /// A usable GeoLite2 ASN database (§9.7: without one, `asn` limiters are
    /// skipped and `net.asn` is MISSING).
    pub fn has_asn(&self) -> bool {
        self.geo.as_ref().is_some_and(|g| g.has_asn())
    }
}

/// One environment.
#[derive(Debug)]
pub struct EnvRuntime {
    pub name: String,
    pub hosts: Vec<String>,
    /// Declared order; the builder's `default` (`/**`) comes last.
    pub routes: Vec<RouteRuntime>,
    /// Converted rules in bundle order (the engine sorts them, §5.4).
    pub rules: Vec<Rule>,
    pub limiters: Vec<LimiterSpec>,
    pub automation_allowlist_only: bool,
    /// Detectors, scorer and this environment's policy (§5.6).
    pub core: DecisionCore,
}

/// One route with its compiled patterns.
#[derive(Debug, Clone)]
pub struct RouteRuntime {
    pub id: String,
    pub name: String,
    /// Empty: every host of the environment.
    pub hosts: Vec<String>,
    /// Upper-case; empty: every method.
    pub methods: Vec<String>,
    pub channel: Channel,
    pub sensitivity: RouteSensitivity,
    pub fail_closed: bool,
    pub require_clearance: bool,
    pub redact_path: bool,
    pub patterns: Vec<Glob>,
}

impl RouteRuntime {
    /// The implicit catch-all used when no route matches (the builder always
    /// appends one, so this only covers hand-made bundles).
    pub fn fallback() -> Self {
        Self {
            id: "default".into(),
            name: "default".into(),
            hosts: Vec::new(),
            methods: Vec::new(),
            channel: Channel::Web,
            sensitivity: RouteSensitivity::Low,
            fail_closed: false,
            require_clearance: false,
            redact_path: false,
            patterns: Vec::new(),
        }
    }
}

/// A limiter key dimension (§9.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterDim {
    Ip,
    IpPrefix,
    Asn,
    Session,
    Route,
}

impl LimiterDim {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ip" => Self::Ip,
            "ip_prefix" => Self::IpPrefix,
            "asn" => Self::Asn,
            "session" => Self::Session,
            "route" => Self::Route,
            _ => return None,
        })
    }

    /// The name used in limiter `dims` (§9.7).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::IpPrefix => "ip_prefix",
            Self::Asn => "asn",
            Self::Session => "session",
            Self::Route => "route",
        }
    }
}

/// Where a limiter keeps its state (§9.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterScope {
    /// Valkey (`mg_gcra`), local fallback.
    Global,
    /// In-process only.
    Local,
}

/// One converted `RateLimit`.
#[derive(Debug, Clone)]
pub struct LimiterSpec {
    pub id: String,
    /// Key dimensions in declared order.
    pub dims: Vec<LimiterDim>,
    pub params: GcraParams,
    pub on_exceed: LimiterAction,
    pub dry_run: bool,
    /// Routes this limiter applies to; empty = every route.
    pub route_ids: Vec<String>,
    pub scope: LimiterScope,
}

/// Converts `vb` for `settings` (see the module documentation). `artifacts`
/// maps `ArtifactRef.name` to bytes whose SHA-256 and size were checked by
/// the caller; an absent name is MISSING.
pub fn build_runtime(
    settings: &SiteSettings,
    keys: &SiteKeys,
    vb: &VerifiedBundle,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<BundleRuntime, String> {
    let b = &vb.bundle;
    let upstream = b.upstream.as_ref().ok_or("upstream: missing")?;
    let kind = UpstreamProfileKind::from_proto(upstream.kind)
        .ok_or_else(|| format!("upstream.kind {} is unknown", upstream.kind))?;
    for (listener, lkind) in &settings.listener_kinds {
        if *lkind != kind {
            return Err(format!(
                "upstream.kind is {kind} but listener {listener} serving this site is {lkind}"
            ));
        }
    }
    let token_keys =
        TokenKeySet::from_key_file(keys.token_file.bytes(), &settings.id, &b.token_key_ids)
            .map_err(|e| format!("token_key_ids against token.keys.json: {e}"))?;
    let lists = NamedLists::new(
        b.lists
            .iter()
            .map(|(name, l)| (name.clone(), l.entries.clone()))
            .collect(),
    );

    let scoring = b.scoring.clone().unwrap_or_else(default_scoring);
    let crawler_policy = b
        .crawler_policy
        .clone()
        .unwrap_or_else(default_crawler_policy);

    let mut environments = Vec::with_capacity(b.environments.len());
    for env in &b.environments {
        let at = |what: &str| format!("environments[{}].{what}", env.name);
        let mut routes = Vec::with_capacity(env.routes.len());
        for r in &env.routes {
            routes.push(
                convert_route(r, b.case_insensitive_paths)
                    .map_err(|e| format!("{}: {e}", at(&format!("routes[{}]", r.name))))?,
            );
        }
        let mut rules = Vec::with_capacity(env.rules.len());
        for r in &env.rules {
            rules.push(
                rule_from_proto(r, &lists)
                    .map_err(|e| format!("{}: {e}", at(&format!("rules[{}]", r.id))))?,
            );
        }
        let mut limiters = Vec::with_capacity(env.rate_limits.len());
        for l in &env.rate_limits {
            limiters.push(
                convert_limiter(l, &routes)
                    .map_err(|e| format!("{}: {e}", at(&format!("rate_limits[{}]", l.id))))?,
            );
        }
        let core =
            crate::decide::build_core(rules.clone(), lists.clone(), &scoring, &crawler_policy);
        environments.push(EnvRuntime {
            name: env.name.clone(),
            hosts: env.hosts.clone(),
            routes,
            rules,
            limiters,
            automation_allowlist_only: env.automation_allowlist_only,
            core,
        });
    }

    let challenge = b.challenge.clone().unwrap_or_else(default_challenge);
    let challenge_limits =
        ChallengeLimits::try_from(&challenge).map_err(|e| format!("challenge: {e}"))?;

    let (mut intel, missing_artifacts) = convert_artifacts(vb, artifacts)?;
    intel.crawler = intel.crawler_registry.as_ref().map(|reg| {
        Arc::new(CrawlerVerifier::new(
            Arc::clone(reg),
            settings.crawler_cache,
        ))
    });

    Ok(BundleRuntime {
        site_id: b.site_id.clone(),
        version: b.version,
        sha256_hex: vb.sha256_hex(),
        monitor_only: b.monitor_only,
        upstream_kind: kind,
        expected_mask: upstream.expected_mask,
        allowed_listeners: b.allowed_listeners.iter().cloned().collect(),
        case_insensitive_paths: b.case_insensitive_paths,
        share_ip_verdicts: b.share_ip_verdicts,
        environments,
        lists,
        token_keys,
        challenge,
        challenge_limits,
        clearance: b.clearance.unwrap_or_else(default_clearance),
        scoring,
        crawler_policy,
        events: b.events.unwrap_or_else(default_events),
        origin_headers: b.origin_headers.unwrap_or_else(default_origin_headers),
        cloudflare: b.cloudflare.clone(),
        intel,
        missing_artifacts,
    })
}

fn convert_route(r: &Route, case_insensitive: bool) -> Result<RouteRuntime, String> {
    let channel = Channel::from_proto(r.channel)
        .filter(|c| *c != Channel::Unspecified)
        .ok_or("channel is unspecified or unknown")?;
    let sensitivity = RouteSensitivity::from_proto(r.sensitivity)
        .filter(|s| *s != RouteSensitivity::Unspecified)
        .ok_or("sensitivity is unspecified or unknown")?;
    let mut sources: Vec<&str> = r.paths.iter().map(String::as_str).collect();
    // Deprecated in Phase 1: a non-empty path_glob is one more entry of paths.
    if !r.path_glob.is_empty() {
        sources.push(&r.path_glob);
    }
    if sources.is_empty() {
        return Err("no path patterns".into());
    }
    let mut patterns = Vec::with_capacity(sources.len());
    for p in sources {
        let p = if case_insensitive {
            p.to_lowercase()
        } else {
            p.to_owned()
        };
        patterns.push(Glob::new(&p).map_err(|e| format!("pattern {p:?}: {e}"))?);
    }
    Ok(RouteRuntime {
        id: r.id.clone(),
        name: r.name.clone(),
        hosts: r.hosts.clone(),
        methods: r.methods.clone(),
        channel,
        sensitivity,
        fail_closed: r.fail_closed,
        require_clearance: r.require_clearance,
        redact_path: r.redact_path,
        patterns,
    })
}

fn convert_limiter(l: &RateLimit, routes: &[RouteRuntime]) -> Result<LimiterSpec, String> {
    if l.algorithm != "gcra" {
        return Err(format!("algorithm {:?} is not gcra", l.algorithm));
    }
    if l.key.is_empty() {
        return Err("no key dimensions".into());
    }
    let dims = l
        .key
        .iter()
        .map(|k| LimiterDim::parse(k).ok_or_else(|| format!("unknown key {k:?}")))
        .collect::<Result<Vec<_>, _>>()?;
    let params = GcraParams::new(l.rate, l.period_s, l.burst)
        .ok_or("rate / period_s / burst out of range")?;
    let on_exceed = match l.on_exceed.as_str() {
        "signal" => LimiterAction::Signal {
            weight: l.signal_weight,
        },
        "challenge" => {
            let t = ChallengeType::from_proto(l.challenge_type)
                .filter(|t| matches!(t, ChallengeType::Invisible | ChallengeType::Pow))
                .ok_or("challenge_type must be invisible or pow")?;
            LimiterAction::Challenge(t)
        }
        "rate_limit" => LimiterAction::RateLimit {
            retry_after_s: l.retry_after_s,
        },
        "block" => LimiterAction::Block,
        other => return Err(format!("unknown on_exceed {other:?}")),
    };
    let dry_run = match l.mode.as_str() {
        "" | "enforce" => false,
        "dry_run" => true,
        other => return Err(format!("unknown mode {other:?}")),
    };
    let scope = match l.scope.as_str() {
        "" | "global" => LimiterScope::Global,
        "local" => LimiterScope::Local,
        other => return Err(format!("unknown scope {other:?}")),
    };
    let mut route_ids = l.route_ids.clone();
    // Deprecated in Phase 1: folded into route_ids.
    if !l.route_id.is_empty() && !route_ids.contains(&l.route_id) {
        route_ids.push(l.route_id.clone());
    }
    for id in &route_ids {
        if !routes.iter().any(|r| &r.id == id) {
            return Err(format!("unknown route {id:?}"));
        }
    }
    Ok(LimiterSpec {
        id: l.id.clone(),
        dims,
        params,
        on_exceed,
        dry_run,
        route_ids,
        scope,
    })
}

fn convert_artifacts(
    vb: &VerifiedBundle,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<(Intel, BTreeSet<String>), String> {
    let mut intel = Intel::default();
    let mut missing = BTreeSet::new();
    let (mut asn, mut country) = (None, None);
    for r in &vb.bundle.artifacts {
        let kind = ArtifactKind::from_name(&r.name)
            .ok_or_else(|| format!("artifact {:?}: unknown kind", r.name))?;
        let Some(bytes) = artifacts.get(&r.name) else {
            missing.insert(r.name.clone());
            continue;
        };
        let at = |e: &dyn fmt::Display| format!("artifact {}: {e}", r.name);
        if bytes.len() as u64 > kind.max_size() {
            return Err(at(&format!("larger than {} bytes", kind.max_size())));
        }
        let text = || std::str::from_utf8(bytes).map_err(|_| at(&"not valid UTF-8"));
        match kind {
            ArtifactKind::GeoipAsn => asn = Some(bytes.clone()),
            ArtifactKind::GeoipCountry => country = Some(bytes.clone()),
            ArtifactKind::CloudflareIps => {
                let parsed = mg_intel::parse_cloudflare_ips(bytes).map_err(|e| at(&e))?;
                intel.cloudflare_ips = Some(Arc::new(parsed.set));
            }
            ArtifactKind::CrawlerRegistry => {
                let reg = CrawlerRegistry::from_artifact(bytes).map_err(|e| at(&e))?;
                if reg.is_test() {
                    log::warn!(
                        "site {}: crawler-registry artifact {} is a test registry (documentation ranges allowed)",
                        vb.bundle.site_id,
                        r.sha256
                    );
                }
                intel.crawler_registry = Some(Arc::new(reg));
                intel.crawler_sha = Some(r.sha256.to_ascii_lowercase());
            }
            ArtifactKind::DatacenterAsns => {
                let set = mg_intel::parse_asn_list(text()?).map_err(|e| at(&e))?;
                intel.datacenter_asns = Some(Arc::new(set));
            }
            ArtifactKind::TorExits => {
                let set = IpSet::from_text(text()?).map_err(|e| at(&e))?;
                intel.tor_exits = Some(Arc::new(set));
            }
        }
    }
    if asn.is_some() || country.is_some() {
        let geo = GeoDb::load(asn, country).map_err(|e| format!("artifact geoip: {e}"))?;
        intel.geo = Some(Arc::new(geo));
    }
    Ok((intel, missing))
}

/// §8.3 default of an absent `challenge` message.
pub fn default_challenge() -> ChallengeConfig {
    ChallengeConfig {
        ttl_s: 120,
        pow_bits: Some(PowBits {
            low: 14,
            medium: 16,
            high: 18,
            very_high: 20,
        }),
        fallback_ret: "/".into(),
        max_failures: 5,
        failure_window_s: 600,
        submit_rate: 30,
        submit_period_s: 60,
        submit_burst: 10,
        issue_per_ipp: 60,
        issue_per_asn: 600,
        issue_period_s: 3600,
    }
}

/// §8.3 default of an absent `clearance` message.
pub fn default_clearance() -> ClearanceConfig {
    ClearanceConfig {
        ttl_invisible_s: 1800,
        ttl_pow_s: 1800,
        session_max_s: 86_400,
        ctp_shadow: true,
    }
}

/// §8.3 / §5.7 default of an absent `scoring` message.
pub fn default_scoring() -> ScoringConfig {
    ScoringConfig {
        theta_c: 0.4,
        kappa: 0.0,
        z0: [
            ("low", -2.197),
            ("medium", -1.735),
            ("high", -1.386),
            ("critical", -1.099),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        family_modes: [("edge_tls".to_string(), "shadow".to_string())].into(),
        weights: Default::default(),
        h_min: -4.0,
        ruleset_version: "v1".into(),
    }
}

/// §8.3 default of an absent `crawler_policy` message.
pub fn default_crawler_policy() -> CrawlerPolicy {
    CrawlerPolicy {
        purposes: Default::default(),
        default_action: "allow".into(),
    }
}

/// §8.3 default of an absent `events` message.
pub fn default_events() -> EventConfig {
    EventConfig {
        allow_sample_rate: 0.1,
        access_log: true,
        stream: true,
    }
}

/// §8.3 default of an absent `origin_headers` message.
pub fn default_origin_headers() -> OriginHeaderConfig {
    OriginHeaderConfig {
        scores: true,
        reasons: false,
        session: true,
    }
}
