//! Synchronous start-up (docs/impl/phase1-spec.md §9.1.1 item 1, §8.1
//! check rules, §9.10 "on start"): everything `main()` does before Pingora
//! forks, and everything `mg-edge --check-config` checks.
//!
//! * key files and credentials: owner public keys, `pseudo.key.json`,
//!   `upstream-keys.json`, each site's `token.keys.json` and
//!   `seal.root.json`, the Valkey password, the bundle client's CA /
//!   certificate / key, the TLS listeners' certificates and keys;
//! * the SDK directory (manifest, hashes, template contract);
//! * each site's LKG bundle: verified and converted exactly like a
//!   candidate (except the version order) against the cached artifacts;
//!   missing artifacts are MISSING (warning), an unusable LKG puts the site
//!   in `lkg_invalid` (`--check-config` fails, exit code 1).
//!
//! Configuration errors are returned as `Err` (exit code 2); warnings are
//! collected for the caller to print or log.

use crate::config::{
    DnsResolverConfig, EdgeConfig, ListenerAuth, ListenerConfig, ListenerProfile, ValkeyMode,
};
use crate::creds::{CredResolver, PseudoKey, UpstreamKeys, read_public, read_secret};
use crate::dns::ResolverSetup;
use crate::listener::ListenerRuntime;
use crate::sdk::SdkDir;
use crate::sites::{Site, SiteKeys, SiteRuntime, SiteSettings, Sites, build_runtime};
use mg_challenge::{KeyError, SealKeys, TokenKeySet};
use mg_edge_core::bundle::{
    Fetcher, FetcherConfig, OwnerKeys, SiteSource, Source, StateDir, VerifiedBundle, verify_bundle,
};
use mg_edge_core::state::{StateConfig, StateMode};
use pingora::listeners::tls::TlsSettings;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One listener, ready for the server.
pub struct ListenerSetup {
    pub cfg: ListenerConfig,
    pub runtime: Arc<ListenerRuntime>,
    /// TLS listeners only; taken by the server builder.
    pub tls: Mutex<Option<TlsSettings>>,
}

impl fmt::Debug for ListenerSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerSetup")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

/// Everything loaded and checked before the server is built.
pub struct Startup {
    pub cfg: EdgeConfig,
    pub owner_keys: Arc<OwnerKeys>,
    pub state_dir: Arc<StateDir>,
    pub sites: Arc<Sites>,
    /// Poll-loop sources, one per site in `cfg.sites` order.
    pub sources: Vec<SiteSource>,
    pub listeners: Vec<ListenerSetup>,
    /// `[valkey]` plus `K_pseudo` (`process_start_ms` = now).
    pub state: StateConfig,
    pub fetcher: FetcherConfig,
    pub sdk: Arc<SdkDir>,
    /// What `mg-rdns` resolves with (`[intel] dns_resolver`).
    pub resolver: ResolverSetup,
    /// Non-fatal findings (`--check-config` prints them).
    pub warnings: Vec<String>,
    /// Findings that fail `--check-config` (exit code 2) but do not stop a
    /// starting Edge, which logs them: a `file://` bundle root that is not a
    /// readable directory (§8.1). The site then stays in bootstrap and keeps
    /// polling, so a briefly missing publish directory never takes every
    /// site down, while a typo is caught before a reload.
    pub check_errors: Vec<String>,
}

impl fmt::Debug for Startup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Startup")
            .field("edge_id", &self.cfg.edge_id)
            .field("sites", &self.sites)
            .field("listeners", &self.listeners)
            .field("warnings", &self.warnings)
            .field("check_errors", &self.check_errors)
            .finish_non_exhaustive()
    }
}

impl Startup {
    /// Loads and checks everything (see the module documentation). `Err`
    /// is a configuration error; an unusable LKG is not (see
    /// [`Startup::lkg_failures`]).
    pub fn load(cfg: EdgeConfig, resolver: &CredResolver) -> Result<Self, String> {
        let mut warnings = Vec::new();
        let mut warn = |w: String| warnings.push(w);

        // [trust]
        let mut pubs = Vec::new();
        for path in &cfg.trust.owner_keys {
            let bytes = read_public(path).map_err(|e| format!("[trust] owner_keys: {e}"))?;
            pubs.push((path.display().to_string(), bytes));
        }
        let files: Vec<(&str, &[u8])> = pubs
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let owner_keys =
            Arc::new(OwnerKeys::from_pub_files(&files).map_err(|e| format!("[trust] {e}"))?);

        // [pseudo]
        let pseudo_file = read_secret(resolver, &cfg.pseudo.key, &mut warn)
            .map_err(|e| format!("[pseudo] key: {e}"))?;
        let pseudo = PseudoKey::parse(pseudo_file.bytes())
            .map_err(|e| format!("[pseudo] key {}: {e}", cfg.pseudo.key))?;

        // [valkey]
        let state = state_config(&cfg, resolver, &pseudo, &mut warn)?;

        // [bundle_client]
        let fetcher = fetcher_config(&cfg, resolver, &mut warn)?;
        Fetcher::new(&fetcher).map_err(|e| format!("[bundle_client] {e}"))?;

        // [intel]: a static table is parsed now (it needs no runtime); hickory
        // is built by mg-rdns on its own runtime (§9.1.1).
        let dns = ResolverSetup::from_config(&cfg.intel)?;
        if let DnsResolverConfig::Static(path) = &cfg.intel.dns_resolver {
            warn(format!(
                "[intel] dns_resolver uses the static resolver {} (tests and the Validation Lab only)",
                path.display()
            ));
        }

        // [sdk]
        let sdk = Arc::new(SdkDir::load(&cfg.sdk.dir).map_err(|e| format!("[sdk] {e}"))?);

        // [[listeners]]
        let mut listeners = Vec::with_capacity(cfg.listeners.len());
        for l in &cfg.listeners {
            let keys = match &l.upstream_keys {
                None => None,
                Some(r) => {
                    let file = read_secret(resolver, r, &mut warn)
                        .map_err(|e| format!("listener {}: upstream_keys: {e}", l.name))?;
                    Some(
                        UpstreamKeys::parse(file.bytes())
                            .map_err(|e| format!("listener {}: upstream_keys {r}: {e}", l.name))?,
                    )
                }
            };
            let tls = if l.is_tls() {
                if let Some(key) = &l.tls_key {
                    // Only the permission warning; BoringSSL reads the file.
                    read_secret(resolver, key, &mut warn)
                        .map_err(|e| format!("listener {}: tls_key: {e}", l.name))?;
                }
                Some(crate::tls::settings(l, resolver)?)
            } else {
                None
            };
            listeners.push(ListenerSetup {
                cfg: l.clone(),
                runtime: Arc::new(ListenerRuntime::new(l, keys)),
                tls: Mutex::new(tls),
            });
        }
        upstream_key_warnings(&cfg, &mut warn);

        // [[sites]]
        let mut check_errors = Vec::new();
        let state_dir = Arc::new(StateDir::new(&cfg.state_dir));
        let mut sites = Vec::with_capacity(cfg.sites.len());
        let mut sources = Vec::with_capacity(cfg.sites.len());
        for s in &cfg.sites {
            let settings = SiteSettings::new(s, &cfg);
            let seal_file = read_secret(resolver, &s.seal_root, &mut warn)
                .map_err(|e| format!("site {}: seal_root: {e}", s.id))?;
            let seal = SealKeys::from_key_file(seal_file.bytes(), &s.id)
                .map_err(|e| format!("site {}: seal_root {}: {e}", s.id, s.seal_root))?;
            let token_file = read_secret(resolver, &s.token_keys, &mut warn)
                .map_err(|e| format!("site {}: token_keys: {e}", s.id))?;
            check_token_file(token_file.bytes(), &s.id)
                .map_err(|e| format!("site {}: token_keys {}: {e}", s.id, s.token_keys))?;
            let keys = SiteKeys { seal, token_file };

            let (initial, current) = load_lkg(&settings, &keys, &state_dir, &owner_keys, &mut warn);
            if let (Some(vb), false) = (&current, s.bootstrap_owner_zones.is_empty()) {
                let bundle_zones: BTreeSet<&String> = vb
                    .bundle
                    .cloudflare
                    .iter()
                    .flat_map(|c| &c.owner_zones)
                    .collect();
                let local: BTreeSet<&String> = s.bootstrap_owner_zones.iter().collect();
                if bundle_zones != local {
                    warn(format!(
                        "site {}: bootstrap_owner_zones {:?} differ from the bundle's owner_zones {:?}; \
                         the bundle's are in effect (I-4)",
                        s.id, local, bundle_zones
                    ));
                }
            }
            let root = Source::parse(&s.bundle_root)
                .map_err(|e| format!("site {}: bundle_root: {e}", s.id))?;
            if let Source::File(dir) = &root
                && let Err(e) = std::fs::read_dir(dir)
            {
                check_errors.push(format!(
                    "site {}: bundle_root {}: not a readable directory: {e}",
                    s.id,
                    dir.display()
                ));
            }
            sources.push(SiteSource {
                site: s.id.clone(),
                hosts: s.hosts.clone(),
                root,
                interval: Duration::from_secs(s.bundle_poll_seconds),
                current,
            });
            sites.push(Arc::new(Site::new(settings, keys, initial)));
        }

        Ok(Self {
            cfg,
            owner_keys,
            state_dir,
            sites: Arc::new(Sites::new(sites)),
            sources,
            listeners,
            state,
            fetcher,
            sdk,
            resolver: dns,
            warnings,
            check_errors,
        })
    }

    /// `(site, reason)` for every site whose LKG exists but cannot be used.
    pub fn lkg_failures(&self) -> Vec<(String, String)> {
        self.sites
            .iter()
            .filter_map(|s| {
                let rt = s.runtime();
                rt.lkg_error.clone().map(|e| (s.settings.id.clone(), e))
            })
            .collect()
    }
}

/// `StateConfig` from `[valkey]` and `K_pseudo`, validated.
fn state_config(
    cfg: &EdgeConfig,
    resolver: &CredResolver,
    pseudo: &PseudoKey,
    warn: &mut dyn FnMut(String),
) -> Result<StateConfig, String> {
    let v = &cfg.valkey;
    let mut state = match v.mode {
        ValkeyMode::Local => StateConfig::local(*pseudo.key()),
        ValkeyMode::Valkey => StateConfig::valkey(v.url.clone().unwrap_or_default(), *pseudo.key()),
    };
    if v.mode == ValkeyMode::Local && v.url.is_some() {
        warn("[valkey] url is ignored in mode = \"local\"".into());
    }
    if let Some(p) = &v.password {
        let file = read_secret(resolver, p, warn).map_err(|e| format!("[valkey] password: {e}"))?;
        let text = std::str::from_utf8(file.bytes())
            .map_err(|_| format!("[valkey] password {p}: not UTF-8"))?;
        let line = text.strip_suffix('\n').unwrap_or(text);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.contains(['\n', '\r']) {
            return Err(format!(
                "[valkey] password {p}: must be exactly one non-empty line"
            ));
        }
        state.password = Some(line.to_owned());
    }
    state.timeout_ms = v.timeout_ms;
    state.connect_timeout_ms = v.connect_timeout_ms;
    state.local_replay_authoritative = v.local_replay_authoritative;
    state.local_limiter_capacity = v.local_limiter_capacity;
    state.local_nonce_capacity = v.local_nonce_capacity;
    debug_assert!(matches!(state.mode, StateMode::Valkey | StateMode::Local));
    state.validate().map_err(|e| format!("[valkey] {e}"))?;
    Ok(state)
}

/// `[bundle_client]` files read into a `FetcherConfig`.
fn fetcher_config(
    cfg: &EdgeConfig,
    resolver: &CredResolver,
    warn: &mut dyn FnMut(String),
) -> Result<FetcherConfig, String> {
    let b = &cfg.bundle_client;
    let mut f = FetcherConfig::new(Duration::from_millis(b.timeout_ms));
    if let Some(ca) = &b.ca_file {
        f.ca_pem = Some(read_public(ca).map_err(|e| format!("[bundle_client] ca_file: {e}"))?);
    }
    if let Some(cert) = &b.client_cert {
        f.client_cert_pem =
            Some(read_public(cert).map_err(|e| format!("[bundle_client] client_cert: {e}"))?);
    }
    if let Some(key) = &b.client_key {
        let file = read_secret(resolver, key, warn)
            .map_err(|e| format!("[bundle_client] client_key: {e}"))?;
        f.client_key_pem = Some(file.bytes().to_vec());
    }
    Ok(f)
}

/// `token.keys.json` must parse for the site before any bundle names its
/// kids. `TokenKeySet::from_key_file` checks the whole file (schema, site,
/// 1-3 keys, id forms, unique kids, key encoding, `created_at`) before it
/// looks at the allowed kids, so an empty allow-list that fails only with
/// `NoActiveKid` means the file itself is valid.
fn check_token_file(json: &[u8], site: &str) -> Result<(), KeyError> {
    match TokenKeySet::from_key_file(json, site, &[]) {
        Err(KeyError::NoActiveKid) => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

/// §8.1 "上游密钥头": a loopback `cloudflare` listener without
/// `upstream_keys` in front of an origin on this host lets an SSRF in the
/// origin reach the Edge with a forged `CF-Connecting-IP`.
fn upstream_key_warnings(cfg: &EdgeConfig, warn: &mut dyn FnMut(String)) {
    for l in &cfg.listeners {
        if l.profile != ListenerProfile::Cloudflare
            || l.auth() != ListenerAuth::Loopback
            || l.upstream_keys.is_some()
        {
            continue;
        }
        for s in cfg.sites.iter().filter(|s| s.listeners.contains(&l.name)) {
            if s.origin.ip().is_loopback() {
                warn(format!(
                    "listener {} has no upstream_keys while site {}'s origin {} is on this host: \
                     an SSRF in the origin could reach the Edge with a forged CF-Connecting-IP; \
                     enable the x-mg-upstream-key header (docs/08 §2.1)",
                    l.name, s.id, s.origin
                ));
            }
        }
    }
}

/// §9.10 "on start": the site's LKG, verified and converted against the
/// artifact cache. Returns the initial runtime and, when active, the bundle
/// for the poll loop's `current`.
fn load_lkg(
    settings: &SiteSettings,
    keys: &SiteKeys,
    dir: &StateDir,
    owner_keys: &OwnerKeys,
    warn: &mut dyn FnMut(String),
) -> (SiteRuntime, Option<VerifiedBundle>) {
    let site = settings.id.as_str();
    let bytes = match dir.read_lkg(site) {
        Ok(None) => return (SiteRuntime::bootstrap(settings.bootstrap), None),
        Ok(Some(bytes)) => bytes,
        Err(e) => {
            return (
                SiteRuntime::lkg_invalid(format!("cannot read the LKG: {e}")),
                None,
            );
        }
    };
    let vb = match verify_bundle(&bytes, owner_keys, site, &settings.hosts) {
        Ok(vb) => vb,
        Err(e) => return (SiteRuntime::lkg_invalid(format!("LKG rejected: {e}")), None),
    };
    let mut artifacts = BTreeMap::new();
    for r in &vb.bundle.artifacts {
        match dir.artifact(&r.sha256) {
            Ok(Some(b)) if b.len() as u64 == r.size => {
                artifacts.insert(r.name.clone(), b);
            }
            Ok(_) => {}
            Err(e) => warn(format!(
                "site {site}: artifact cache read of {} failed: {e}",
                r.name
            )),
        }
    }
    match build_runtime(settings, keys, &vb, &artifacts) {
        Ok(rt) => {
            let m = mg_edge_core::bundle::metrics();
            m.config_version
                .with_label_values(&[site])
                .set(i64::try_from(rt.version).unwrap_or(i64::MAX));
            for name in &rt.missing_artifacts {
                m.artifact_missing.with_label_values(&[site, name]).set(1);
                warn(format!(
                    "site {site}: LKG version {} references artifact {name}, which is not in {}: \
                     its fields are MISSING until the poll loop fetches it",
                    rt.version,
                    dir.artifact_path(&artifact_sha(&vb, name))
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ));
            }
            (SiteRuntime::active(rt), Some(vb))
        }
        Err(e) => (
            SiteRuntime::lkg_invalid(format!("LKG version {} rejected: {e}", vb.bundle.version)),
            None,
        ),
    }
}

fn artifact_sha(vb: &VerifiedBundle, name: &str) -> String {
    vb.bundle
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .map(|a| a.sha256.clone())
        .unwrap_or_default()
}
