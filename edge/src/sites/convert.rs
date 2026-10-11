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
//! Phase 2 (WP-E2a, docs/impl/phase2-spec.md §3.2, D-66): the bundle's
//! `schema_version` (1: strictly Phase 1; 2: the Phase 2 fields, which
//! `verify_bundle` has range-checked and which are used as they are, never
//! back-filled), the interactive settings ([`InteractiveRuntime`]),
//! `interactive_available` (§5.1: schema 2, `challenge.interactive.enabled`
//! and a manifest v2 SDK directory), the routes' `proof` / `min_level` and
//! `interactive` limiter challenges (schema 2 only).
//!
//! WP-E1b adds the per-environment Decision Core ([`EnvRuntime::core`],
//! built by [`crate::decide::build_core`]) and the crawler verifier of the
//! `crawler-registry` artifact ([`Intel::crawler`]).

use super::{SiteKeys, SiteSettings};
use mg_challenge::TokenKeySet;
use mg_core::gcra::GcraParams;
use mg_core::policy::{Glob, NamedLists, Rule};
use mg_core::{
    ChallengeType, Channel, DecisionCore, LimiterAction, RouteSensitivity, ScoringMode, TokenLevel,
    UpstreamProfileKind,
};
use mg_edge_core::bundle::VerifiedBundle;
use mg_edge_core::state::builtin::ChallengeLimits;
use mg_intel::{ArtifactKind, CrawlerRegistry, CrawlerVerifier, GeoDb, IpSet};
use mg_proto::ir::rule_from_proto;
use mg_proto::v1::{
    ChallengeConfig, ClearanceConfig, CloudflareSiteConfig, CrawlerPolicy, EventConfig,
    InteractiveConfig, OriginHeaderConfig, ProofMode, RateLimit, Route, ScoringConfig,
    challenge_config::PowBits,
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
    /// `SiteBundle.schema_version`: 1 (strictly Phase 1, D-66) or 2.
    pub schema_version: u32,
    /// The interactive settings; `Some` iff `schema_version = 2`.
    pub interactive: Option<InteractiveRuntime>,
    /// Phase 2 spec §5.1: `schema_version = 2`, `challenge.interactive.enabled`
    /// and a manifest v2 SDK directory. `false`: `interactive` runs as `pow`.
    pub interactive_available: bool,
    /// `challenge.default_lang` (§7.3): `zh-CN` or `en` (`en` in schema 1).
    pub default_lang: &'static str,
    /// `challenge.help_path` / `privacy_path` (§12.3; `/` in schema 1).
    pub help_path: String,
    pub privacy_path: String,
    /// The site's monitor switch; a route's [`RouteMode`] overrides it.
    /// With edge.toml `force_monitor` (D-60) it is `true` and every route is
    /// [`RouteMode::Monitor`].
    pub monitor_only: bool,
    /// edge.toml `[[sites]] force_monitor` (Phase 2 spec §9.6, D-60): the
    /// whole site only records, whatever the bundle says.
    pub forced_monitor: bool,
    /// Some route of some environment has `mode = enforce` (I-36): oversize
    /// requests, which skip route matching, are then rejected even under the
    /// site's monitor switch.
    pub has_enforce_route: bool,
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
    /// The scanner baits of `mg:ev` v2 `bt` (Phase 2 spec §13.1): the
    /// built-in list with `events.scanner_baits_builtin` and the extra globs,
    /// lower-cased (schema 2 only).
    pub scanner_baits: Vec<Glob>,
}

impl fmt::Debug for BundleRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleRuntime")
            .field("site_id", &self.site_id)
            .field("version", &self.version)
            .field("sha256", &self.sha256_hex)
            .field("schema_version", &self.schema_version)
            .field("interactive_available", &self.interactive_available)
            .field("monitor_only", &self.monitor_only)
            .field("has_enforce_route", &self.has_enforce_route)
            .field("upstream_kind", &self.upstream_kind)
            .field("environments", &self.environments)
            .field("token_keys", &self.token_keys)
            .field("intel", &self.intel)
            .field("missing_artifacts", &self.missing_artifacts)
            .finish_non_exhaustive()
    }
}

impl BundleRuntime {
    /// `schema_version = 2` (Phase 2 behaviour, D-66).
    pub fn phase2(&self) -> bool {
        self.schema_version >= 2
    }

    /// The clearance lifetime of `lvl` (§6.8), clamped to 1..=86400 s.
    pub fn ttl_for(&self, lvl: &TokenLevel) -> u32 {
        let c = &self.clearance;
        let ttl = match lvl {
            TokenLevel::Invisible => c.ttl_invisible_s,
            TokenLevel::Pow => c.ttl_pow_s,
            TokenLevel::Interactive => c.ttl_interactive_s,
            TokenLevel::InteractiveA11y => c.ttl_interactive_a11y_s,
            TokenLevel::InteractiveExt(_) => c.ttl_interactive_ext_s,
        };
        ttl.clamp(1, mg_challenge::MAX_TOKEN_LIFETIME_S as u32)
    }

    /// `bt` of `mg:ev` v2 (Phase 2 spec §13.1): the fully decoded path
    /// view matches a scanner bait, case-insensitively.
    pub fn is_bait(&self, path: &str) -> bool {
        if self.scanner_baits.is_empty() {
            return false;
        }
        let view = mg_core::paths::decoded_view(path).to_lowercase();
        self.scanner_baits.iter().any(|g| g.matches(&view))
    }

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
    /// Some rule reads `identity.proof` (Phase 2 spec §9.1: the proof is
    /// then verified even off `proof = required` routes); computed once from
    /// the policy IR (`DecisionCore::reads_field`).
    pub reads_proof: bool,
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
    pub mode: RouteMode,
    /// A CHALLENGE is recorded and the request forwarded (I-37).
    pub never_challenge: bool,
    /// `proof = required` (Phase 2 spec D-40; schema 2 only).
    pub proof_required: bool,
    /// `min_level` (Phase 2 spec D-64; schema 2 only).
    pub min_level: Option<ChallengeType>,
    pub patterns: Vec<Glob>,
}

/// A route's override of the site's monitor switch (`Route.mode`, I-36).
///
/// The variants are ordered from least to most strict: when a request
/// matches several routes through different path views (§9.4), the maximum
/// applies, so that spelling a path differently never downgrades enforcement
/// to recording.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteMode {
    /// Record decisions, enforce nothing.
    Monitor,
    /// Follow `SiteBundle.monitor_only`.
    #[default]
    Inherit,
    /// Enforce even when the site is in monitor mode.
    Enforce,
}

impl RouteMode {
    /// Whether a request with this (combined) mode is only recorded, given
    /// the site's `monitor_only`.
    pub fn monitor(self, site_monitor_only: bool) -> bool {
        match self {
            Self::Monitor => true,
            Self::Inherit => site_monitor_only,
            Self::Enforce => false,
        }
    }
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
            mode: RouteMode::Inherit,
            never_challenge: false,
            proof_required: false,
            min_level: None,
            patterns: Vec::new(),
        }
    }
}

/// The interactive challenge settings of a schema 2 bundle
/// (`challenge.interactive`, Phase 2 spec §3.2, §10.2, §7.9), range-checked
/// by `verify_bundle`.
#[derive(Debug, Clone, PartialEq)]
pub struct InteractiveRuntime {
    pub enabled: bool,
    /// `self_hold`, per sub-puzzle, by risk band.
    pub pow_bits: PowBits,
    pub pow_k: u32,
    /// `pow_a11y`, per sub-puzzle.
    pub a11y_bits: u32,
    /// `N` of D-50.
    pub escalate_after: u32,
    pub scoring: ScoringMode,
    pub min_pow_ms: u32,
    pub a11y_min_ms: u32,
    /// `mg.ix.issue` per ip entity and its 4x ipp tier (D-67).
    pub issue: GcraParams,
    pub issue_ipp: GcraParams,
    /// `mg.c.renew` per ip entity and its 4x ipp tier.
    pub renew: GcraParams,
    pub renew_ipp: GcraParams,
    /// `mg.a11y.issue` per ip entity and per ipp.
    pub a11y_ip: GcraParams,
    pub a11y_ipp: GcraParams,
}

impl InteractiveRuntime {
    /// From the verified `challenge.interactive`.
    pub fn from_proto(ix: &InteractiveConfig) -> Result<Self, String> {
        let gcra = |name: &str, rate: u32, period: u32, burst: u32| {
            GcraParams::new(rate, period, burst)
                .ok_or_else(|| format!("challenge.interactive.{name}: invalid GCRA parameters"))
        };
        let scoring = match ix.scoring_mode.as_str() {
            "shadow" => ScoringMode::Shadow,
            "enforce" => ScoringMode::Enforce {
                t_pass: ix.t_pass,
                t_block: ix.t_block,
            },
            other => return Err(format!("challenge.interactive.scoring_mode {other:?}")),
        };
        Ok(Self {
            enabled: ix.enabled,
            pow_bits: ix
                .pow_bits
                .ok_or("challenge.interactive.pow_bits: missing")?,
            pow_k: ix.pow_k,
            a11y_bits: ix.a11y_bits,
            escalate_after: ix.escalate_after,
            scoring,
            min_pow_ms: ix.min_pow_ms,
            a11y_min_ms: ix.a11y_min_ms,
            issue: gcra("issue", ix.issue_rate, ix.issue_period_s, ix.issue_burst)?,
            issue_ipp: gcra(
                "issue",
                ix.issue_rate.saturating_mul(4),
                ix.issue_period_s,
                ix.issue_burst.saturating_mul(4),
            )?,
            renew: gcra("renew", ix.renew_rate, ix.renew_period_s, ix.renew_burst)?,
            renew_ipp: gcra(
                "renew",
                ix.renew_rate.saturating_mul(4),
                ix.renew_period_s,
                ix.renew_burst.saturating_mul(4),
            )?,
            a11y_ip: gcra(
                "a11y_issue_per_ip",
                ix.a11y_issue_per_ip,
                ix.a11y_issue_period_s,
                ix.a11y_issue_per_ip,
            )?,
            a11y_ipp: gcra(
                "a11y_issue_per_ipp",
                ix.a11y_issue_per_ipp,
                ix.a11y_issue_period_s,
                ix.a11y_issue_per_ipp,
            )?,
        })
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

    let schema_version = b.schema_version;
    let phase2 = schema_version >= 2;
    let interactive = match b.challenge.as_ref().and_then(|c| c.interactive.as_ref()) {
        Some(ix) if phase2 => Some(InteractiveRuntime::from_proto(ix)?),
        None if phase2 => {
            return Err("challenge.interactive: required with schema_version 2".into());
        }
        _ => None,
    };
    // Phase 2 spec §5.1.
    let interactive_available =
        interactive.as_ref().is_some_and(|ix| ix.enabled) && settings.sdk_manifest_v2;

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
            let mut route = convert_route(r, b.case_insensitive_paths, phase2)
                .map_err(|e| format!("{}: {e}", at(&format!("routes[{}]", r.name))))?;
            // D-60: no route enforces while the site is forced to monitor
            // (the I-36 oversize exception does not apply either).
            if settings.force_monitor {
                route.mode = RouteMode::Monitor;
            }
            routes.push(route);
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
                convert_limiter(l, &routes, phase2)
                    .map_err(|e| format!("{}: {e}", at(&format!("rate_limits[{}]", l.id))))?,
            );
        }
        let core = crate::decide::build_core(
            rules.clone(),
            lists.clone(),
            &scoring,
            &crawler_policy,
            schema_version,
            interactive_available,
        );
        let reads_proof = core.reads_field("identity.proof");
        environments.push(EnvRuntime {
            name: env.name.clone(),
            hosts: env.hosts.clone(),
            routes,
            rules,
            limiters,
            automation_allowlist_only: env.automation_allowlist_only,
            core,
            reads_proof,
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

    let has_enforce_route = environments
        .iter()
        .flat_map(|e| &e.routes)
        .any(|r| r.mode == RouteMode::Enforce);

    let (default_lang, help_path, privacy_path) = match &challenge {
        c if phase2 => (
            if c.default_lang == "zh-CN" {
                "zh-CN"
            } else {
                "en"
            },
            page_path(&c.help_path),
            page_path(&c.privacy_path),
        ),
        _ => ("en", "/".to_owned(), "/".to_owned()),
    };

    let events = b.events.clone().unwrap_or_else(default_events);
    let mut scanner_baits = Vec::new();
    if phase2 {
        let builtin: &[&str] = if events.scanner_baits_builtin {
            &crate::events::BUILTIN_SCANNER_BAITS
        } else {
            &[]
        };
        for p in builtin
            .iter()
            .copied()
            .chain(events.scanner_baits.iter().map(String::as_str))
        {
            scanner_baits.push(
                Glob::new(&p.to_lowercase())
                    .map_err(|e| format!("events.scanner_baits {p:?}: {e}"))?,
            );
        }
    }

    Ok(BundleRuntime {
        site_id: b.site_id.clone(),
        version: b.version,
        sha256_hex: vb.sha256_hex(),
        schema_version,
        interactive,
        interactive_available,
        default_lang,
        help_path,
        privacy_path,
        monitor_only: b.monitor_only || settings.force_monitor,
        forced_monitor: settings.force_monitor,
        has_enforce_route,
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
        events,
        origin_headers: b.origin_headers.unwrap_or_else(default_origin_headers),
        cloudflare: b.cloudflare.clone(),
        intel,
        missing_artifacts,
        scanner_baits,
    })
}

/// A site-relative page path (`help_path`, `privacy_path`; validated like
/// `ret` by `verify_bundle`); `/` when empty or invalid.
fn page_path(p: &str) -> String {
    if mg_challenge::validate_ret(p).is_ok() {
        p.to_owned()
    } else {
        "/".to_owned()
    }
}

fn convert_route(r: &Route, case_insensitive: bool, phase2: bool) -> Result<RouteRuntime, String> {
    let channel = Channel::from_proto(r.channel)
        .filter(|c| *c != Channel::Unspecified)
        .ok_or("channel is unspecified or unknown")?;
    let sensitivity = RouteSensitivity::from_proto(r.sensitivity)
        .filter(|s| *s != RouteSensitivity::Unspecified)
        .ok_or("sensitivity is unspecified or unknown")?;
    let mode = match mg_proto::v1::RouteMode::try_from(r.mode) {
        Ok(mg_proto::v1::RouteMode::Inherit) => RouteMode::Inherit,
        Ok(mg_proto::v1::RouteMode::Monitor) => RouteMode::Monitor,
        Ok(mg_proto::v1::RouteMode::Enforce) => RouteMode::Enforce,
        Err(_) => return Err(format!("mode {} is unknown", r.mode)),
    };
    // The builder refuses these (I-37); a hand-made bundle must not turn a
    // route that demands clearance into one that never asks for it.
    if r.never_challenge && (r.require_clearance || sensitivity >= RouteSensitivity::High) {
        return Err(
            "never_challenge on a high or critical route, or with require_clearance".into(),
        );
    }
    // Phase 2 fields (D-40, D-64); a schema 1 bundle has them at zero
    // (verify_bundle), and is strictly Phase 1 anyway (D-66).
    let proof_required = match ProofMode::try_from(r.proof) {
        Ok(ProofMode::Off) => false,
        Ok(ProofMode::Required) => phase2,
        Err(_) => return Err(format!("proof {} is unknown", r.proof)),
    };
    let min_level = match ChallengeType::from_proto(r.min_level) {
        Some(ChallengeType::Unspecified) => None,
        Some(t @ (ChallengeType::Invisible | ChallengeType::Pow | ChallengeType::Interactive)) => {
            phase2.then_some(t)
        }
        _ => return Err(format!("min_level {} is not allowed", r.min_level)),
    };
    if r.never_challenge && (proof_required || min_level.is_some()) {
        return Err("never_challenge with proof or min_level".into());
    }
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
        mode,
        never_challenge: r.never_challenge,
        proof_required,
        min_level,
        patterns,
    })
}

fn convert_limiter(
    l: &RateLimit,
    routes: &[RouteRuntime],
    phase2: bool,
) -> Result<LimiterSpec, String> {
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
            // `interactive` only in schema 2 (Phase 2 spec §3.2, §5.2).
            let t = ChallengeType::from_proto(l.challenge_type)
                .filter(|t| {
                    matches!(t, ChallengeType::Invisible | ChallengeType::Pow)
                        || (phase2 && *t == ChallengeType::Interactive)
                })
                .ok_or("challenge_type must be invisible or pow (or interactive in schema 2)")?;
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
        ..Default::default()
    }
}

/// §8.3 default of an absent `clearance` message.
pub fn default_clearance() -> ClearanceConfig {
    ClearanceConfig {
        ttl_invisible_s: 1800,
        ttl_pow_s: 1800,
        session_max_s: 86_400,
        ctp_shadow: true,
        ..Default::default()
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
        ..Default::default()
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
