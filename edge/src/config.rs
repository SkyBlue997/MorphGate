//! `edge.toml` v1 (docs/impl/phase1-spec.md §8.1).
//!
//! Host-local configuration only: listeners, sites (hosts, origin, bundle
//! source, bootstrap behaviour, key references), state and event sinks. All
//! policy comes from the owner-signed site bundle. Unknown keys are rejected
//! everywhere (`deny_unknown_fields`); the Phase 0 single-site format is
//! refused with a migration hint.
//!
//! This module checks everything that can be checked from the text alone
//! ([`EdgeConfig::validate`]). Reading key files, credentials, the LKG
//! bundles and the SDK directory is [`crate::startup`]'s job; `mg-edge
//! --check-config` runs both.
//!
//! Plain file paths (`state_dir`, `[trust] owner_keys`, TLS files, `[sdk]
//! dir`, ...) may be relative: [`EdgeConfig::load`] resolves them against the
//! directory of the configuration file. Credential references
//! ([`CredRef`]) are `cred://<name>` or absolute paths only.

use mg_core::UpstreamProfileKind;
use mg_edge_core::bundle::Source;
use mg_edge_core::events::EventsConfig;
use mg_edge_core::request::resolve_host;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// The only `config_version` this binary understands.
pub const CONFIG_VERSION: u32 = 1;

/// Default seconds between SIGTERM and closing listeners' in-flight work.
/// Pingora's own default is 300 s, far longer than systemd's stop timeout.
pub const DEFAULT_GRACE_PERIOD_SECONDS: u64 = 10;

/// Default seconds the runtimes get to wind down after the grace period.
pub const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 5;

/// `bundle_poll_seconds` range (§8.1); the poll loop itself does not clamp.
pub const BUNDLE_POLL_SECONDS: std::ops::RangeInclusive<u64> = 2..=300;

/// Process-level settings passed to Pingora (unchanged from Phase 0).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Worker threads per proxy service (Pingora default: 1).
    pub threads: Option<usize>,
    /// PID file (used for daemon mode and graceful upgrades).
    pub pid_file: Option<PathBuf>,
    /// Unix socket used to hand listeners to a new binary on graceful upgrade.
    pub upgrade_sock: Option<PathBuf>,
    /// Seconds to keep serving in-flight requests after SIGTERM.
    pub grace_period_seconds: u64,
    /// Seconds the runtimes get to stop after the grace period.
    pub graceful_shutdown_timeout_seconds: u64,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            threads: None,
            pid_file: None,
            upgrade_sock: None,
            grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
            graceful_shutdown_timeout_seconds: DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS,
        }
    }
}

/// A reference to a secret file (§8.1 "凭证引用"): `cred://<name>` resolves
/// to `$CREDENTIALS_DIRECTORY/<name>` (systemd `LoadCredential=` /
/// `LoadCredentialEncrypted=`), anything else must be an absolute path.
#[derive(Clone, PartialEq, Eq)]
pub enum CredRef {
    /// `cred://<name>`, `name` = `[A-Za-z0-9_.-]{1,64}` and not only dots.
    Credential(String),
    /// An absolute path to a file (permissions are checked at load time).
    Path(PathBuf),
}

impl CredRef {
    /// Parses `cred://<name>` or an absolute path.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(name) = s.strip_prefix("cred://") {
            let ok = (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                && !name.bytes().all(|b| b == b'.');
            return if ok {
                Ok(Self::Credential(name.to_owned()))
            } else {
                Err(format!(
                    "{s:?}: a credential name is 1-64 of [A-Za-z0-9_.-] (not only dots)"
                ))
            };
        }
        let path = PathBuf::from(s);
        if path.is_absolute() {
            Ok(Self::Path(path))
        } else {
            Err(format!(
                "{s:?}: must be cred://<name> or an absolute path (relative key paths are not accepted)"
            ))
        }
    }
}

impl fmt::Debug for CredRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for CredRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential(name) => write!(f, "cred://{name}"),
            Self::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

impl<'de> Deserialize<'de> for CredRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// `[trust]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    /// Owner public key files (§12.6); at least one.
    pub owner_keys: Vec<PathBuf>,
}

/// `[[listeners]] profile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProfile {
    /// Behind Cloudflare: Tunnel on loopback, or Authenticated Origin Pulls.
    Cloudflare,
    /// No CDN: the Edge terminates visitor TLS itself.
    DirectTls,
}

impl ListenerProfile {
    /// The bundle's `upstream.kind` this listener can serve (§9.10).
    pub fn kind(self) -> UpstreamProfileKind {
        match self {
            Self::Cloudflare => UpstreamProfileKind::Cloudflare,
            Self::DirectTls => UpstreamProfileKind::DirectTls,
        }
    }

    /// Metric label value.
    pub fn as_str(self) -> &'static str {
        self.kind().as_str()
    }
}

/// `[[listeners]] auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerAuth {
    /// `cloudflare`: the TCP peer must be a loopback address (cloudflared on
    /// this host).
    Loopback,
    /// `cloudflare`: TLS with a client certificate from `client_ca`
    /// (Cloudflare Authenticated Origin Pulls).
    OriginMtls,
    /// `direct_tls`: visitors connect directly.
    None,
}

impl ListenerAuth {
    /// `auth_method` of the requests this listener authenticates (§9.2).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::OriginMtls => "origin_mtls",
            Self::None => "none",
        }
    }
}

/// One `[[listeners]]` entry (§8.1, §9.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// `[a-z0-9][a-z0-9-]{0,31}`, unique.
    pub name: String,
    pub bind: SocketAddr,
    pub profile: ListenerProfile,
    /// Default: `loopback` for `cloudflare`, `none` for `direct_tls`.
    #[serde(default)]
    pub auth: Option<ListenerAuth>,
    /// `cloudflare` only: `upstream-keys.json`; when set, every request needs
    /// a matching `x-mg-upstream-key`.
    #[serde(default)]
    pub upstream_keys: Option<CredRef>,
    /// Certificate chain (PEM); `origin_mtls` and `direct_tls`.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// Private key (PEM); `origin_mtls` and `direct_tls`.
    #[serde(default)]
    pub tls_key: Option<CredRef>,
    /// `origin_mtls` only (required there): CA that signs Cloudflare's client
    /// certificate.
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
    /// `origin_mtls` only: drop TCP peers outside the sites' `cloudflare-ips`
    /// artifacts before the TLS handshake.
    #[serde(default)]
    pub cloudflare_ip_filter: bool,
    /// `direct_tls` only (WP-J1 spike, default off): compute the JA4 of every
    /// ClientHello; it reaches the decision event only (`crate::tls`, D-07).
    #[serde(default)]
    pub ja4_spike: bool,
}

impl ListenerConfig {
    /// `auth` with its profile default applied.
    pub fn auth(&self) -> ListenerAuth {
        self.auth.unwrap_or(match self.profile {
            ListenerProfile::Cloudflare => ListenerAuth::Loopback,
            ListenerProfile::DirectTls => ListenerAuth::None,
        })
    }

    /// Whether this listener terminates TLS.
    pub fn is_tls(&self) -> bool {
        matches!(self.auth(), ListenerAuth::OriginMtls | ListenerAuth::None)
    }
}

/// `[[sites]] bootstrap`: behaviour before the site ever had a bundle (D-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    /// Forward everything and record it (`rule_id = "bootstrap"`).
    #[default]
    Open,
    /// Answer 503.
    Closed,
}

/// `[[sites]] on_lkg_invalid` (integrator ruling I-3): behaviour while the
/// LKG bundle exists but cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LkgInvalidMode {
    /// 503 (fail closed, the default).
    #[default]
    Closed,
    /// Treated like `bootstrap = "open"` (`rule_id = "lkg_invalid_open"`);
    /// `mg_site_state` still reports `lkg_invalid`.
    Open,
}

fn default_poll_seconds() -> u64 {
    10
}

/// One `[[sites]]` entry (§8.1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// `[a-z0-9][a-z0-9_-]{0,63}`.
    pub id: String,
    /// Lower-case, no port, no trailing dot; unique across sites; must equal
    /// `SiteBundle.hosts` as a set.
    pub hosts: Vec<String>,
    /// Names of the listeners that route to this site.
    pub listeners: Vec<String>,
    /// Plain HTTP origin.
    pub origin: SocketAddr,
    /// `file://` / `https://` / `http://` (private address literals only),
    /// ending in `/`.
    pub bundle_root: String,
    #[serde(default = "default_poll_seconds")]
    pub bundle_poll_seconds: u64,
    #[serde(default)]
    pub bootstrap: BootstrapMode,
    #[serde(default)]
    pub on_lkg_invalid: LkgInvalidMode,
    /// Zones whose `CF-Worker` subrequests are the owner's while the site has
    /// no bundle yet (I-4); the bundle's `owner_zones` win once one is in
    /// effect.
    #[serde(default)]
    pub bootstrap_owner_zones: Vec<String>,
    /// `token.keys.json` (§12.7).
    pub token_keys: CredRef,
    /// `seal.root.json` (§12.7).
    pub seal_root: CredRef,
}

fn default_bundle_timeout_ms() -> u64 {
    5000
}

/// `[bundle_client]` (optional; used for `https://` bundle roots).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleClientConfig {
    /// PEM CA bundle; when set, only these roots are trusted.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate chain (mTLS to the brain VM).
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// PEM private key of `client_cert`.
    #[serde(default)]
    pub client_key: Option<CredRef>,
    #[serde(default = "default_bundle_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for BundleClientConfig {
    fn default() -> Self {
        Self {
            ca_file: None,
            client_cert: None,
            client_key: None,
            timeout_ms: default_bundle_timeout_ms(),
        }
    }
}

/// `[pseudo]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PseudoConfig {
    /// `pseudo.key.json` (§12.7).
    pub key: CredRef,
}

/// `[valkey] mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValkeyMode {
    Valkey,
    Local,
}

/// `[valkey]` (§8.1, §9.7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeyConfig {
    pub mode: ValkeyMode,
    /// Required for `mode = "valkey"`; never contains a password.
    #[serde(default)]
    pub url: Option<String>,
    /// File with the ACL user's password (one line).
    #[serde(default)]
    pub password: Option<CredRef>,
    #[serde(default = "ValkeyConfig::default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "ValkeyConfig::default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub local_replay_authoritative: bool,
    #[serde(default = "ValkeyConfig::default_local_limiter_capacity")]
    pub local_limiter_capacity: usize,
    #[serde(default = "ValkeyConfig::default_local_nonce_capacity")]
    pub local_nonce_capacity: usize,
}

impl ValkeyConfig {
    fn default_timeout_ms() -> u64 {
        mg_edge_core::state::DEFAULT_TIMEOUT_MS
    }
    fn default_connect_timeout_ms() -> u64 {
        mg_edge_core::state::DEFAULT_CONNECT_TIMEOUT_MS
    }
    fn default_local_limiter_capacity() -> usize {
        mg_edge_core::state::DEFAULT_LOCAL_LIMITER_CAPACITY
    }
    fn default_local_nonce_capacity() -> usize {
        mg_edge_core::state::DEFAULT_LOCAL_NONCE_CAPACITY
    }
}

/// `[intel] dns_resolver`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResolverConfig {
    /// hickory with `/etc/resolv.conf` (WP-E1b).
    System,
    /// `mg_intel::StaticResolver` JSON (§7.4; tests and the Validation Lab).
    Static(PathBuf),
}

impl<'de> Deserialize<'de> for DnsResolverConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "system" {
            return Ok(Self::System);
        }
        match s.strip_prefix("static:") {
            Some(path) if !path.is_empty() => Ok(Self::Static(PathBuf::from(path))),
            _ => Err(serde::de::Error::custom(format!(
                "{s:?}: expected \"system\" or \"static:<path>\""
            ))),
        }
    }
}

/// `[intel]` (§8.1, §9.6).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {
    pub dns_resolver: DnsResolverConfig,
    /// Per DNS query.
    pub dns_timeout_ms: u64,
    pub rdns_concurrency: usize,
    /// New rDNS jobs per `ip_prefix` per minute.
    pub rdns_jobs_per_prefix_per_min: u32,
    pub rdns_cache_capacity: usize,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            dns_resolver: DnsResolverConfig::System,
            dns_timeout_ms: 2000,
            rdns_concurrency: 16,
            rdns_jobs_per_prefix_per_min: 10,
            rdns_cache_capacity: 100_000,
        }
    }
}

/// `[sdk]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConfig {
    /// Directory with `manifest.json`, the SDK file and `challenge.html`
    /// (§11.1).
    pub dir: PathBuf,
}

/// Validated `edge.toml` v1.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Must be [`CONFIG_VERSION`].
    pub config_version: u32,
    /// `[a-z0-9][a-z0-9-]{0,31}`; logged as `DecisionEvent.edge_id`.
    pub edge_id: String,
    /// Prometheus `/metrics` (no authentication): loopback, RFC 1918, ULA or
    /// 100.64.0.0/10 only.
    pub metrics_listen: SocketAddr,
    /// `bundles/<site>.bundle` (LKG) and `artifacts/<sha256>`.
    pub state_dir: PathBuf,
    #[serde(default)]
    pub server: ServerSettings,
    pub trust: TrustConfig,
    pub listeners: Vec<ListenerConfig>,
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub bundle_client: BundleClientConfig,
    pub pseudo: PseudoConfig,
    pub valkey: ValkeyConfig,
    #[serde(default)]
    pub events: EventsConfig,
    #[serde(default)]
    pub intel: IntelConfig,
    pub sdk: SdkConfig,
}

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

impl EdgeConfig {
    /// Reads, parses and validates a TOML file; relative plain paths are
    /// resolved against the file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let base = std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf());
        Self::from_toml_str_at(&text, Some(&base))
    }

    /// Parses and validates TOML text; relative paths stay as written.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        Self::from_toml_str_at(text, None)
    }

    /// Parses TOML text, resolves relative plain paths against `base` (when
    /// given) and validates the result.
    pub fn from_toml_str_at(text: &str, base: Option<&Path>) -> Result<Self, ConfigError> {
        // The Phase 0 format has no config_version: say how to migrate
        // instead of listing a dozen unknown and missing keys.
        let table: toml::Table = toml::from_str(text)?;
        match table.get("config_version") {
            None => {
                return invalid(
                    "config_version is missing: this looks like a Phase 0 edge.toml; \
                     migrate to the v1 format (config_version = 1, [[listeners]], [[sites]]; \
                     see deploy/systemd/edge.toml.example and docs/impl/phase1-spec.md §8.1)",
                );
            }
            Some(toml::Value::Integer(v)) if *v == i64::from(CONFIG_VERSION) => {}
            Some(v) => {
                return invalid(format!(
                    "config_version = {v}: this mg-edge only understands config_version = {CONFIG_VERSION}"
                ));
            }
        }
        let mut cfg: Self = toml::from_str(text)?;
        if let Some(base) = base {
            cfg.resolve_relative(base);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn resolve_relative(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.state_dir);
        fix(&mut self.sdk.dir);
        self.trust.owner_keys.iter_mut().for_each(fix);
        for l in &mut self.listeners {
            l.tls_cert.as_mut().map(fix);
            l.client_ca.as_mut().map(fix);
        }
        self.bundle_client.ca_file.as_mut().map(fix);
        self.bundle_client.client_cert.as_mut().map(fix);
        if let DnsResolverConfig::Static(p) = &mut self.intel.dns_resolver {
            fix(p);
        }
        self.events.file.as_mut().map(fix);
        if let Some(p) = self.server.pid_file.as_mut() {
            fix(p);
        }
        if let Some(p) = self.server.upgrade_sock.as_mut() {
            fix(p);
        }
    }

    /// Every rule of the §8.1 table that needs nothing but this text.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !is_short_name(&self.edge_id) {
            return invalid(format!(
                "edge_id {:?} must be 1-32 of [a-z0-9-] starting with [a-z0-9]",
                self.edge_id
            ));
        }
        check_port("metrics_listen", self.metrics_listen)?;
        // /metrics has no authentication. The brain VM scrapes it over a
        // private network or VPN, so a public or wildcard bind is a mistake.
        if !is_internal_ip(self.metrics_listen.ip()) {
            return invalid(format!(
                "metrics_listen {}: must be a loopback, private (RFC 1918 / ULA) or \
                 CGNAT/VPN (100.64.0.0/10) address; /metrics has no authentication",
                self.metrics_listen
            ));
        }
        if self.state_dir.as_os_str().is_empty() {
            return invalid("state_dir must not be empty");
        }
        if let Some(t) = self.server.threads
            && !(1..=1024).contains(&t)
        {
            return invalid(format!("server.threads {t}: must be 1..=1024"));
        }
        if self.trust.owner_keys.is_empty() {
            return invalid("[trust] owner_keys needs at least one public key file");
        }
        self.validate_listeners()?;
        self.validate_sites()?;
        self.validate_bundle_client()?;
        self.validate_valkey()?;
        self.events
            .validate()
            .map_err(|e| ConfigError::Invalid(format!("[events] {e}")))?;
        self.validate_intel()?;
        if self.sdk.dir.as_os_str().is_empty() {
            return invalid("[sdk] dir must not be empty");
        }
        Ok(())
    }

    fn validate_listeners(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return invalid("at least one [[listeners]] entry is required");
        }
        let mut names = BTreeSet::new();
        let mut binds = BTreeMap::new();
        for (i, l) in self.listeners.iter().enumerate() {
            let at = format!("listeners[{i}] ({})", l.name);
            if !is_short_name(&l.name) {
                return invalid(format!(
                    "{at}: name must be 1-32 of [a-z0-9-] starting with [a-z0-9]"
                ));
            }
            if !names.insert(l.name.as_str()) {
                return invalid(format!("{at}: duplicate listener name"));
            }
            check_port(&format!("{at}: bind"), l.bind)?;
            if let Some(other) = binds.insert(l.bind, l.name.as_str()) {
                return invalid(format!("{at}: bind {} is also used by {other}", l.bind));
            }
            if l.bind == self.metrics_listen {
                return invalid(format!("{at}: bind {} equals metrics_listen", l.bind));
            }
            let auth = l.auth();
            match (l.profile, auth) {
                (
                    ListenerProfile::Cloudflare,
                    ListenerAuth::Loopback | ListenerAuth::OriginMtls,
                )
                | (ListenerProfile::DirectTls, ListenerAuth::None) => {}
                (profile, auth) => {
                    return invalid(format!(
                        "{at}: auth {:?} is not valid for profile {:?} \
                         (cloudflare: loopback | origin_mtls; direct_tls: none)",
                        auth.as_str(),
                        profile.as_str()
                    ));
                }
            }
            if auth == ListenerAuth::Loopback && !l.bind.ip().is_loopback() {
                return invalid(format!(
                    "{at}: bind {}: a cloudflare + loopback listener must bind a loopback \
                     address (cloudflared on this host); use origin_mtls for a public bind",
                    l.bind
                ));
            }
            if l.is_tls() {
                if l.tls_cert.is_none() || l.tls_key.is_none() {
                    return invalid(format!(
                        "{at}: tls_cert and tls_key are required for {}",
                        auth.as_str()
                    ));
                }
            } else if l.tls_cert.is_some() || l.tls_key.is_some() {
                return invalid(format!(
                    "{at}: tls_cert / tls_key are only used by origin_mtls and direct_tls listeners"
                ));
            }
            if auth == ListenerAuth::OriginMtls {
                if l.client_ca.is_none() {
                    return invalid(format!("{at}: client_ca is required for origin_mtls"));
                }
            } else {
                if l.client_ca.is_some() {
                    return invalid(format!("{at}: client_ca is only used by origin_mtls"));
                }
                if l.cloudflare_ip_filter {
                    return invalid(format!(
                        "{at}: cloudflare_ip_filter is only used by origin_mtls"
                    ));
                }
            }
            if l.ja4_spike && l.profile != ListenerProfile::DirectTls {
                return invalid(format!(
                    "{at}: ja4_spike is only used by direct_tls listeners"
                ));
            }
            if l.upstream_keys.is_some() && l.profile != ListenerProfile::Cloudflare {
                return invalid(format!(
                    "{at}: upstream_keys is only used by cloudflare listeners"
                ));
            }
        }
        Ok(())
    }

    fn validate_sites(&self) -> Result<(), ConfigError> {
        if self.sites.is_empty() {
            return invalid("at least one [[sites]] entry is required");
        }
        let listeners: BTreeMap<&str, &ListenerConfig> = self
            .listeners
            .iter()
            .map(|l| (l.name.as_str(), l))
            .collect();
        let mut ids = BTreeSet::new();
        let mut hosts: BTreeMap<&str, &str> = BTreeMap::new();
        for (i, s) in self.sites.iter().enumerate() {
            let at = format!("sites[{i}] ({})", s.id);
            if !is_site_id(&s.id) {
                return invalid(format!(
                    "{at}: id must be 1-64 of [a-z0-9_-] starting with [a-z0-9]"
                ));
            }
            if !ids.insert(s.id.as_str()) {
                return invalid(format!("{at}: duplicate site id"));
            }
            if s.hosts.is_empty() {
                return invalid(format!("{at}: hosts must not be empty"));
            }
            for h in &s.hosts {
                if resolve_host(Some(h), None, None).as_deref() != Ok(h.as_str()) {
                    return invalid(format!(
                        "{at}: host {h:?} must be a lower-case host name or IP literal \
                         without port or trailing dot"
                    ));
                }
                if let Some(other) = hosts.insert(h.as_str(), s.id.as_str()) {
                    return invalid(format!("{at}: host {h:?} is also a host of site {other}"));
                }
            }
            if s.listeners.is_empty() {
                return invalid(format!("{at}: listeners must not be empty"));
            }
            let mut seen = BTreeSet::new();
            let mut profiles = BTreeMap::new();
            for name in &s.listeners {
                let Some(l) = listeners.get(name.as_str()) else {
                    return invalid(format!("{at}: unknown listener {name:?}"));
                };
                if !seen.insert(name.as_str()) {
                    return invalid(format!("{at}: listener {name:?} listed twice"));
                }
                profiles
                    .entry(l.profile.as_str())
                    .or_insert_with(Vec::new)
                    .push(name.as_str());
            }
            // §9.10: a bundle's upstream.kind must equal the profile of every
            // listener serving the site, so mixed profiles could never load
            // a bundle (the site would stay in bootstrap for good).
            if profiles.len() > 1 {
                return invalid(format!(
                    "{at}: listeners of different profiles {profiles:?}; every listener of a \
                     site must have the profile of the bundle's upstream.kind"
                ));
            }
            check_port(&format!("{at}: origin"), s.origin)?;
            if s.origin.ip().is_unspecified() {
                return invalid(format!("{at}: origin {}: unspecified address", s.origin));
            }
            if s.origin == self.metrics_listen || self.listeners.iter().any(|l| l.bind == s.origin)
            {
                return invalid(format!(
                    "{at}: origin {} must differ from every listener bind and metrics_listen \
                     (proxy loop)",
                    s.origin
                ));
            }
            Source::parse(&s.bundle_root)
                .map_err(|e| ConfigError::Invalid(format!("{at}: bundle_root: {e}")))?;
            if !BUNDLE_POLL_SECONDS.contains(&s.bundle_poll_seconds) {
                return invalid(format!(
                    "{at}: bundle_poll_seconds {} must be {}..={}",
                    s.bundle_poll_seconds,
                    BUNDLE_POLL_SECONDS.start(),
                    BUNDLE_POLL_SECONDS.end()
                ));
            }
            for z in &s.bootstrap_owner_zones {
                let dns = resolve_host(Some(z), None, None).as_deref() == Ok(z.as_str())
                    && z.parse::<IpAddr>().is_err()
                    && !z.starts_with('[');
                if !dns {
                    return invalid(format!(
                        "{at}: bootstrap_owner_zones entry {z:?} must be a lower-case DNS name"
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_bundle_client(&self) -> Result<(), ConfigError> {
        let b = &self.bundle_client;
        if !(100..=60_000).contains(&b.timeout_ms) {
            return invalid(format!(
                "[bundle_client] timeout_ms {} must be 100..=60000",
                b.timeout_ms
            ));
        }
        if b.client_cert.is_some() != b.client_key.is_some() {
            return invalid("[bundle_client] client_cert and client_key must be set together");
        }
        Ok(())
    }

    fn validate_valkey(&self) -> Result<(), ConfigError> {
        let v = &self.valkey;
        if v.mode == ValkeyMode::Valkey && v.url.is_none() {
            return invalid("[valkey] url is required for mode = \"valkey\"");
        }
        // The remaining rules (URL shape, no password in the URL, non-zero
        // timeouts and capacities) are StateConfig::validate's; startup runs
        // it once the pseudonymization key is loaded.
        Ok(())
    }

    fn validate_intel(&self) -> Result<(), ConfigError> {
        let i = &self.intel;
        if !(100..=30_000).contains(&i.dns_timeout_ms) {
            return invalid(format!(
                "[intel] dns_timeout_ms {} must be 100..=30000",
                i.dns_timeout_ms
            ));
        }
        if !(1..=1024).contains(&i.rdns_concurrency) {
            return invalid(format!(
                "[intel] rdns_concurrency {} must be 1..=1024",
                i.rdns_concurrency
            ));
        }
        if !(1..=10_000).contains(&i.rdns_jobs_per_prefix_per_min) {
            return invalid(format!(
                "[intel] rdns_jobs_per_prefix_per_min {} must be 1..=10000",
                i.rdns_jobs_per_prefix_per_min
            ));
        }
        if !(1..=10_000_000).contains(&i.rdns_cache_capacity) {
            return invalid(format!(
                "[intel] rdns_cache_capacity {} must be 1..=10000000",
                i.rdns_cache_capacity
            ));
        }
        Ok(())
    }

    /// The listener named `name`.
    pub fn listener(&self, name: &str) -> Option<&ListenerConfig> {
        self.listeners.iter().find(|l| l.name == name)
    }
}

fn check_port(what: &str, addr: SocketAddr) -> Result<(), ConfigError> {
    if addr.port() == 0 {
        return invalid(format!("{what} {addr}: port 0 is not allowed"));
    }
    Ok(())
}

/// Loopback, RFC 1918, shared address space (100.64.0.0/10, used by
/// Tailscale-style VPNs) or IPv6 unique local. Excludes unspecified (bind to
/// all interfaces), link-local, multicast and every public address. The same
/// rule as `http://` bundle roots and event sinks (§8.1, I-11).
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_internal_ip(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unique_local(),
        },
    }
}

/// `[a-z0-9][a-z0-9-]{0,31}` (edge ids and listener names).
pub fn is_short_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// `[a-z0-9][a-z0-9_-]{0,63}` (site ids).
pub fn is_site_id(id: &str) -> bool {
    let b = id.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// Test configurations shared by unit tests of other modules.
#[cfg(test)]
pub(crate) mod tests_support {
    /// The minimal valid configuration with the listener's `auth` set to
    /// `auth` (`origin_mtls` adds the TLS files it requires).
    pub(crate) fn minimal_with_listener(auth: &str) -> String {
        let extra = match auth {
            "origin_mtls" => {
                "auth = \"origin_mtls\"\ntls_cert = \"/e.pem\"\ntls_key = \"/e.key\"\nclient_ca = \"/ca.pem\"\n"
            }
            other => {
                assert_eq!(other, "loopback");
                "auth = \"loopback\"\n"
            }
        };
        super::tests::VALID.replacen(
            "profile = \"cloudflare\"\n",
            &format!("profile = \"cloudflare\"\n{extra}"),
            1,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal valid v1 configuration (one loopback listener, one site).
    pub(crate) const VALID: &str = r#"
config_version = 1
edge_id = "edge-1"
metrics_listen = "127.0.0.1:9901"
state_dir = "/var/lib/morphgate"

[trust]
owner_keys = ["/etc/morphgate/owner-keys/owner-2026.pub"]

[[listeners]]
name = "cf-tunnel"
bind = "127.0.0.1:8080"
profile = "cloudflare"

[[sites]]
id = "blog"
hosts = ["example.com", "www.example.com"]
listeners = ["cf-tunnel"]
origin = "127.0.0.1:3000"
bundle_root = "file:///srv/mg/"
token_keys = "cred://mg-blog-token-keys"
seal_root = "cred://mg-blog-seal-root"

[pseudo]
key = "cred://mg-pseudo-key"

[valkey]
mode = "local"

[sdk]
dir = "/opt/morphgate/sdk"
"#;

    fn err(text: &str) -> String {
        EdgeConfig::from_toml_str(text).unwrap_err().to_string()
    }

    fn replace(from: &str, to: &str) -> String {
        assert!(VALID.contains(from), "{from}");
        VALID.replacen(from, to, 1)
    }

    #[test]
    fn parses_the_minimal_config_with_defaults() {
        let cfg = EdgeConfig::from_toml_str(VALID).unwrap();
        assert_eq!(cfg.edge_id, "edge-1");
        assert_eq!(cfg.server, ServerSettings::default());
        let l = &cfg.listeners[0];
        assert_eq!(l.auth(), ListenerAuth::Loopback);
        assert!(!l.is_tls());
        let s = &cfg.sites[0];
        assert_eq!(s.bundle_poll_seconds, 10);
        assert_eq!(s.bootstrap, BootstrapMode::Open);
        assert_eq!(s.on_lkg_invalid, LkgInvalidMode::Closed);
        assert!(s.bootstrap_owner_zones.is_empty());
        assert_eq!(
            s.token_keys,
            CredRef::Credential("mg-blog-token-keys".into())
        );
        assert_eq!(cfg.bundle_client, BundleClientConfig::default());
        assert_eq!(cfg.events, EventsConfig::default());
        assert_eq!(cfg.intel, IntelConfig::default());
        assert_eq!(cfg.valkey.timeout_ms, 10);
        assert_eq!(cfg.valkey.local_nonce_capacity, 200_000);
    }

    #[test]
    fn phase0_format_gets_a_migration_hint() {
        let phase0 = r#"
            site_id = "blog"
            listen = "127.0.0.1:8080"
            origin = "127.0.0.1:8081"
            upstream_profile = "cloudflare"
            metrics_listen = "127.0.0.1:9901"
        "#;
        let e = err(phase0);
        assert!(
            e.contains("config_version is missing") && e.contains("v1"),
            "{e}"
        );
        let e = err(&VALID.replace("config_version = 1", "config_version = 2"));
        assert!(e.contains("config_version = 2"), "{e}");
        let e = err(&VALID.replace("config_version = 1", "config_version = \"1\""));
        assert!(e.contains("config_version"), "{e}");
    }

    #[test]
    fn unknown_keys_are_rejected_everywhere() {
        for (anchor, extra) in [
            ("edge_id = \"edge-1\"", "\nedge_idd = 1"),
            ("profile = \"cloudflare\"", "\nja4 = true"),
            (
                "seal_root = \"cred://mg-blog-seal-root\"",
                "\norigin_tls = true",
            ),
            ("mode = \"local\"", "\npasword = \"x\""),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "\n[events]\nvl_mian = \"http://10.0.0.5:9428\"",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "\n[intel]\ndns = \"system\"",
            ),
        ] {
            let e = err(&replace(anchor, &format!("{anchor}{extra}")));
            assert!(e.contains("unknown field"), "{extra}: {e}");
        }
    }

    #[test]
    fn listener_rules() {
        let cases = [
            (
                "bind = \"127.0.0.1:8080\"",
                "bind = \"0.0.0.0:8080\"",
                "loopback",
            ),
            (
                "bind = \"127.0.0.1:8080\"",
                "bind = \"127.0.0.1:0\"",
                "port 0",
            ),
            (
                "bind = \"127.0.0.1:8080\"",
                "bind = \"127.0.0.1:9901\"",
                "metrics_listen",
            ),
            ("name = \"cf-tunnel\"", "name = \"CF\"", "name must be"),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nauth = \"none\"",
                "not valid for profile",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\ntls_cert = \"/x.pem\"",
                "only used by origin_mtls and direct_tls",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nauth = \"origin_mtls\"\ntls_cert = \"/x.pem\"\ntls_key = \"/x.key\"",
                "client_ca is required",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nauth = \"origin_mtls\"",
                "tls_cert and tls_key are required",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\ncloudflare_ip_filter = true",
                "only used by origin_mtls",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"direct_tls\"\ntls_cert = \"/x.pem\"\ntls_key = \"/x.key\"\nupstream_keys = \"cred://k\"",
                "upstream_keys is only used by cloudflare",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nja4_spike = true",
                "ja4_spike is only used by direct_tls",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nauth = \"origin_mtls\"\ntls_cert = \"/x.pem\"\ntls_key = \"/x.key\"\nclient_ca = \"/ca.pem\"\nja4_spike = true",
                "ja4_spike is only used by direct_tls",
            ),
            (
                "profile = \"cloudflare\"",
                "profile = \"cloudflare\"\nupstream_keys = \"keys.json\"",
                "absolute path",
            ),
        ];
        for (from, to, needle) in cases {
            let e = err(&replace(from, to));
            assert!(e.contains(needle), "{to}: {e}");
        }
        // A direct_tls listener may bind any address.
        let text = replace(
            "profile = \"cloudflare\"",
            "profile = \"direct_tls\"\ntls_cert = \"/x.pem\"\ntls_key = \"/x.key\"",
        )
        .replace("bind = \"127.0.0.1:8080\"", "bind = \"0.0.0.0:443\"");
        let cfg = EdgeConfig::from_toml_str(&text).unwrap();
        assert_eq!(cfg.listeners[0].auth(), ListenerAuth::None);
        assert!(cfg.listeners[0].is_tls());
        assert!(
            !cfg.listeners[0].ja4_spike,
            "the JA4 spike is off by default"
        );
        // WP-J1: the JA4 spike is a direct_tls listener key.
        let spike = text.replace(
            "tls_key = \"/x.key\"",
            "tls_key = \"/x.key\"\nja4_spike = true",
        );
        assert!(EdgeConfig::from_toml_str(&spike).unwrap().listeners[0].ja4_spike);
    }

    #[test]
    fn duplicate_listener_names_and_binds_are_rejected() {
        let second = "\n[[listeners]]\nname = \"cf-tunnel\"\nbind = \"127.0.0.1:8081\"\nprofile = \"cloudflare\"\n";
        let text = replace("[[sites]]", &format!("{second}\n[[sites]]"));
        assert!(err(&text).contains("duplicate listener name"));
        let second = "\n[[listeners]]\nname = \"other\"\nbind = \"127.0.0.1:8080\"\nprofile = \"cloudflare\"\n";
        let text = replace("[[sites]]", &format!("{second}\n[[sites]]"));
        assert!(err(&text).contains("also used by cf-tunnel"));
    }

    #[test]
    fn site_rules() {
        let cases = [
            ("id = \"blog\"", "id = \"Blog\"", "id must be"),
            (
                "hosts = [\"example.com\", \"www.example.com\"]",
                "hosts = []",
                "hosts must not be empty",
            ),
            (
                "hosts = [\"example.com\", \"www.example.com\"]",
                "hosts = [\"Example.com\"]",
                "lower-case",
            ),
            (
                "hosts = [\"example.com\", \"www.example.com\"]",
                "hosts = [\"example.com:443\"]",
                "without port",
            ),
            (
                "hosts = [\"example.com\", \"www.example.com\"]",
                "hosts = [\"example.com.\"]",
                "trailing dot",
            ),
            (
                "hosts = [\"example.com\", \"www.example.com\"]",
                "hosts = [\"a.com\", \"a.com\"]",
                "also a host",
            ),
            (
                "listeners = [\"cf-tunnel\"]",
                "listeners = [\"nope\"]",
                "unknown listener",
            ),
            (
                "listeners = [\"cf-tunnel\"]",
                "listeners = []",
                "listeners must not be empty",
            ),
            (
                "listeners = [\"cf-tunnel\"]",
                "listeners = [\"cf-tunnel\", \"cf-tunnel\"]",
                "listed twice",
            ),
            (
                "origin = \"127.0.0.1:3000\"",
                "origin = \"127.0.0.1:8080\"",
                "proxy loop",
            ),
            (
                "origin = \"127.0.0.1:3000\"",
                "origin = \"127.0.0.1:9901\"",
                "proxy loop",
            ),
            (
                "origin = \"127.0.0.1:3000\"",
                "origin = \"0.0.0.0:3000\"",
                "unspecified",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg\"",
                "end with '/'",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"http://brain.internal/\"",
                "https://",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"http://203.0.113.5/\"",
                "https://",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\nbundle_poll_seconds = 1",
                "2..=300",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\nbundle_poll_seconds = 301",
                "2..=300",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\nbootstrap = \"maybe\"",
                "unknown variant",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\non_lkg_invalid = \"half\"",
                "unknown variant",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\nbootstrap_owner_zones = [\"Example.com\"]",
                "DNS name",
            ),
            (
                "bundle_root = \"file:///srv/mg/\"",
                "bundle_root = \"file:///srv/mg/\"\nbootstrap_owner_zones = [\"10.0.0.1\"]",
                "DNS name",
            ),
            (
                "token_keys = \"cred://mg-blog-token-keys\"",
                "token_keys = \"cred://..\"",
                "not only dots",
            ),
            (
                "token_keys = \"cred://mg-blog-token-keys\"",
                "token_keys = \"cred://a/b\"",
                "credential name",
            ),
            (
                "token_keys = \"cred://mg-blog-token-keys\"",
                "token_keys = \"cred://\"",
                "credential name",
            ),
            (
                "seal_root = \"cred://mg-blog-seal-root\"",
                "seal_root = \"seal.root.json\"",
                "absolute path",
            ),
        ];
        for (from, to, needle) in cases {
            let e = err(&replace(from, to));
            assert!(e.contains(needle), "{to}: {e}");
        }
        let ok = replace(
            "bundle_root = \"file:///srv/mg/\"",
            "bundle_root = \"http://10.0.0.5:8088/mg/\"\nbundle_poll_seconds = 2\nbootstrap = \"closed\"\non_lkg_invalid = \"open\"\nbootstrap_owner_zones = [\"example.com\"]",
        );
        let cfg = EdgeConfig::from_toml_str(&ok).unwrap();
        let s = &cfg.sites[0];
        assert_eq!(s.bootstrap, BootstrapMode::Closed);
        assert_eq!(s.on_lkg_invalid, LkgInvalidMode::Open);
        assert_eq!(s.bootstrap_owner_zones, ["example.com"]);
    }

    /// §9.10: a bundle's `upstream.kind` must equal the profile of every
    /// listener serving the site, so a site behind listeners of two
    /// profiles could never leave bootstrap (and would forward unevaluated
    /// traffic forever under `bootstrap = "open"`).
    #[test]
    fn a_site_cannot_mix_listener_profiles() {
        let tls = r#"
[[listeners]]
name = "direct"
bind = "0.0.0.0:8443"
profile = "direct_tls"
tls_cert = "/e.pem"
tls_key = "/e.key"
"#;
        let text = replace("[[sites]]", &format!("{tls}\n[[sites]]"));
        EdgeConfig::from_toml_str(&text).unwrap();
        let mixed = text.replacen(
            "listeners = [\"cf-tunnel\"]",
            "listeners = [\"cf-tunnel\", \"direct\"]",
            1,
        );
        let e = err(&mixed);
        assert!(e.contains("profile") && e.contains("direct"), "{e}");
    }

    #[test]
    fn two_sites_cannot_share_a_host() {
        let second = r#"
[[sites]]
id = "shop"
hosts = ["shop.example.com", "www.example.com"]
listeners = ["cf-tunnel"]
origin = "127.0.0.1:3001"
bundle_root = "file:///srv/mg/"
token_keys = "cred://mg-shop-token-keys"
seal_root = "cred://mg-shop-seal-root"
"#;
        let text = replace("[pseudo]", &format!("{second}\n[pseudo]"));
        assert!(err(&text).contains("also a host of site blog"));
        let dup = second
            .replace("\"shop\"", "\"blog\"")
            .replace(", \"www.example.com\"", "");
        let text = replace("[pseudo]", &format!("{dup}\n[pseudo]"));
        assert!(err(&text).contains("duplicate site id"));
    }

    /// /metrics has no authentication, so it may only listen on loopback or on
    /// a private / VPN address that the brain VM scrapes.
    #[test]
    fn metrics_listen_must_not_be_public() {
        for value in [
            "0.0.0.0:9901",
            "[::]:9901",
            "203.0.113.10:9901",
            "[2001:db8::1]:9901",
            "169.254.10.1:9901",
            "[fe80::1]:9901",
        ] {
            let e = err(&replace(
                "metrics_listen = \"127.0.0.1:9901\"",
                &format!("metrics_listen = \"{value}\""),
            ));
            assert!(e.contains("metrics_listen"), "{value}: {e}");
        }
        for value in [
            "10.0.0.5:9901",
            "100.64.1.2:9901",
            "[fd7a:115c:a1e0::1]:9901",
        ] {
            let text = replace(
                "metrics_listen = \"127.0.0.1:9901\"",
                &format!("metrics_listen = \"{value}\""),
            );
            assert!(EdgeConfig::from_toml_str(&text).is_ok(), "{value}");
        }
    }

    #[test]
    fn other_sections() {
        let cases = [
            ("mode = \"local\"", "mode = \"valkey\"", "url is required"),
            ("mode = \"local\"", "mode = \"redis\"", "unknown variant"),
            (
                "mode = \"local\"",
                "mode = \"local\"\npassword = \"cred://../x\"",
                "credential name",
            ),
            (
                "[valkey]",
                "[bundle_client]\nclient_cert = \"/c.pem\"\n[valkey]",
                "set together",
            ),
            (
                "[valkey]",
                "[bundle_client]\ntimeout_ms = 50\n[valkey]",
                "timeout_ms",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "dir = \"/opt/morphgate/sdk\"\n[events]\nvl_main = \"http://vl.internal:9428\"",
                "https://",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "dir = \"/opt/morphgate/sdk\"\n[events]\nvl_short = \"http://localhost:9429\"",
                "https://",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "dir = \"/opt/morphgate/sdk\"\n[events]\nflush_interval_ms = 0",
                "flush_interval_ms",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "dir = \"/opt/morphgate/sdk\"\n[intel]\ndns_resolver = \"dynamic\"",
                "static:<path>",
            ),
            (
                "dir = \"/opt/morphgate/sdk\"",
                "dir = \"/opt/morphgate/sdk\"\n[intel]\nrdns_concurrency = 0",
                "rdns_concurrency",
            ),
            (
                "owner_keys = [\"/etc/morphgate/owner-keys/owner-2026.pub\"]",
                "owner_keys = []",
                "owner_keys",
            ),
            ("edge_id = \"edge-1\"", "edge_id = \"Edge_1\"", "edge_id"),
        ];
        for (from, to, needle) in cases {
            let e = err(&replace(from, to));
            assert!(e.contains(needle), "{to}: {e}");
        }
        let ok = replace(
            "dir = \"/opt/morphgate/sdk\"",
            "dir = \"/opt/morphgate/sdk\"\n[events]\nvl_main = \"http://10.0.0.5:9428\"\nvl_short = \"https://vl.internal/\"\n[intel]\ndns_resolver = \"static:/etc/morphgate/dns.json\"",
        );
        let cfg = EdgeConfig::from_toml_str(&ok).unwrap();
        assert_eq!(
            cfg.intel.dns_resolver,
            DnsResolverConfig::Static("/etc/morphgate/dns.json".into())
        );
    }

    #[test]
    fn relative_plain_paths_resolve_against_the_config_directory() {
        let text = VALID
            .replace(
                "state_dir = \"/var/lib/morphgate\"",
                "state_dir = \"state\"",
            )
            .replace("dir = \"/opt/morphgate/sdk\"", "dir = \"../sdk\"")
            .replace(
                "\"/etc/morphgate/owner-keys/owner-2026.pub\"",
                "\"keys/owner.pub\"",
            );
        let cfg = EdgeConfig::from_toml_str_at(&text, Some(Path::new("/etc/mg"))).unwrap();
        assert_eq!(cfg.state_dir, Path::new("/etc/mg/state"));
        assert_eq!(cfg.sdk.dir, Path::new("/etc/mg/../sdk"));
        assert_eq!(cfg.trust.owner_keys[0], Path::new("/etc/mg/keys/owner.pub"));
        // Credential references never resolve relatively.
        assert!(CredRef::parse("keys/token.json").is_err());
    }

    #[test]
    fn load_reports_path_on_io_error() {
        let e = EdgeConfig::load(Path::new("/nonexistent/mg-edge.toml")).unwrap_err();
        assert!(e.to_string().contains("/nonexistent/mg-edge.toml"), "{e}");
    }
}
