//! Edge configuration (TOML).
//!
//! ```toml
//! site_id          = "blog"
//! listen           = "127.0.0.1:8080"   # behind cloudflared on loopback
//! origin           = "127.0.0.1:8081"
//! upstream_profile = "cloudflare"       # or "direct_tls"
//! metrics_listen   = "127.0.0.1:9901"
//!
//! [server]                              # optional
//! threads = 2
//! grace_period_seconds = 10
//! ```
//!
//! Unknown keys are rejected so that typos fail loudly. In Phase 1 this local
//! file is joined by the signed site bundle pulled from the control plane
//! (`morphgate.v1.SignedBundle`); this file keeps only bootstrap settings.

use mg_core::UpstreamProfileKind;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Default seconds between SIGTERM and closing listeners' in-flight work.
/// Pingora's own default is 300 s, far longer than systemd's stop timeout.
pub const DEFAULT_GRACE_PERIOD_SECONDS: u64 = 10;

/// Default seconds the runtimes get to wind down after the grace period.
pub const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 5;

/// Upstream profiles the Edge can run with. A subset of
/// [`UpstreamProfileKind`]: other profiles are added when implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProfile {
    /// Behind Cloudflare. Phase 0/1 origin protection: Cloudflare Tunnel with
    /// `cloudflared` on the same host, so the Edge listens on loopback only.
    Cloudflare,
    /// No CDN: the Edge terminates visitor TLS itself (TLS listener: Phase 1).
    DirectTls,
}

impl From<UpstreamProfile> for UpstreamProfileKind {
    fn from(p: UpstreamProfile) -> Self {
        match p {
            UpstreamProfile::Cloudflare => Self::Cloudflare,
            UpstreamProfile::DirectTls => Self::DirectTls,
        }
    }
}

/// Process-level settings passed to Pingora.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Worker threads per service (Pingora default: 1).
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

/// Validated Edge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Site identifier: 1–64 of `[a-z0-9_-]`, starting with a letter or digit.
    pub site_id: String,
    /// Plain-HTTP listener for visitor traffic.
    pub listen: SocketAddr,
    /// Origin server the Edge proxies to (plain HTTP).
    pub origin: SocketAddr,
    pub upstream_profile: UpstreamProfile,
    /// Prometheus exposition listener (`/metrics`; any path answers). No
    /// authentication, so only loopback / private / VPN addresses are accepted.
    pub metrics_listen: SocketAddr,
    #[serde(default)]
    pub server: ServerSettings,
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

impl EdgeConfig {
    /// Reads, parses and validates a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Parses and validates TOML text.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Semantic checks that serde cannot express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));

        if !is_valid_site_id(&self.site_id) {
            return invalid(format!(
                "site_id {:?} must be 1-64 chars of [a-z0-9_-] starting with [a-z0-9]",
                self.site_id
            ));
        }
        for (name, addr) in [
            ("listen", self.listen),
            ("origin", self.origin),
            ("metrics_listen", self.metrics_listen),
        ] {
            if addr.port() == 0 {
                return invalid(format!("{name} {addr}: port 0 is not allowed"));
            }
        }
        // Phase 0 has no TLS listener and no origin-pull mTLS. The only safe
        // deployment is Cloudflare Tunnel (cloudflared on this host) or a local
        // test, so visitor traffic must arrive over loopback. Phase 1 relaxes
        // this for `direct_tls` (TLS listener) and AOP (client-cert listener).
        if !self.listen.ip().is_loopback() {
            return invalid(format!(
                "listen {}: must be a loopback address until the TLS / origin-pull \
                 listeners exist (Phase 1); run cloudflared on this host",
                self.listen
            ));
        }
        // /metrics has no authentication. The brain VM scrapes it over a
        // private network or VPN, so a public or wildcard bind is a mistake.
        if !is_internal_ip(self.metrics_listen.ip()) {
            return invalid(format!(
                "metrics_listen {}: must be a loopback, private (RFC 1918 / ULA) or \
                 CGNAT/VPN (100.64.0.0/10) address; /metrics has no authentication",
                self.metrics_listen
            ));
        }
        if self.origin.ip().is_unspecified() {
            return invalid(format!("origin {}: unspecified address", self.origin));
        }
        if self.origin == self.listen || self.origin == self.metrics_listen {
            return invalid(format!(
                "origin {} must differ from listen and metrics_listen (proxy loop)",
                self.origin
            ));
        }
        if self.metrics_listen == self.listen {
            return invalid(format!(
                "metrics_listen {} must differ from listen",
                self.metrics_listen
            ));
        }
        if let Some(t) = self.server.threads
            && !(1..=1024).contains(&t)
        {
            return invalid(format!("server.threads {t}: must be 1..=1024"));
        }
        Ok(())
    }
}

/// Loopback, RFC 1918, shared address space (100.64.0.0/10, used by
/// Tailscale-style VPNs) or IPv6 unique local. Excludes unspecified (bind to
/// all interfaces), link-local, multicast and every public address.
fn is_internal_ip(ip: IpAddr) -> bool {
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

fn is_valid_site_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        site_id = "blog"
        listen = "127.0.0.1:8080"
        origin = "127.0.0.1:8081"
        upstream_profile = "cloudflare"
        metrics_listen = "127.0.0.1:9901"
    "#;

    fn with(key: &str, value: &str) -> String {
        VALID
            .lines()
            .map(|l| {
                if l.trim_start().starts_with(&format!("{key} ")) {
                    format!("{key} = {value}")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn err(text: &str) -> String {
        EdgeConfig::from_toml_str(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_valid_config_with_defaults() {
        let cfg = EdgeConfig::from_toml_str(VALID).unwrap();
        assert_eq!(cfg.site_id, "blog");
        assert_eq!(cfg.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.origin, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(cfg.metrics_listen, "127.0.0.1:9901".parse().unwrap());
        assert_eq!(cfg.upstream_profile, UpstreamProfile::Cloudflare);
        assert_eq!(cfg.server, ServerSettings::default());
        assert_eq!(
            cfg.server.grace_period_seconds,
            DEFAULT_GRACE_PERIOD_SECONDS
        );
        assert_eq!(
            UpstreamProfileKind::from(cfg.upstream_profile),
            UpstreamProfileKind::Cloudflare
        );
    }

    #[test]
    fn parses_direct_tls_ipv6_and_server_table() {
        let text = format!(
            "{}\n[server]\nthreads = 4\ngrace_period_seconds = 3\nupgrade_sock = \"/run/mg-edge/upgrade.sock\"\n",
            with("upstream_profile", "\"direct_tls\"").replace("127.0.0.1:8080", "[::1]:8080")
        );
        let cfg = EdgeConfig::from_toml_str(&text).unwrap();
        assert_eq!(cfg.upstream_profile, UpstreamProfile::DirectTls);
        assert_eq!(cfg.listen, "[::1]:8080".parse().unwrap());
        assert_eq!(cfg.server.threads, Some(4));
        assert_eq!(cfg.server.grace_period_seconds, 3);
        assert_eq!(
            cfg.server.graceful_shutdown_timeout_seconds,
            DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS
        );
        assert_eq!(
            cfg.server.upgrade_sock.as_deref(),
            Some(Path::new("/run/mg-edge/upgrade.sock"))
        );
    }

    #[test]
    fn rejects_unknown_upstream_profile() {
        for p in ["\"cloudfront\"", "\"CLOUDFLARE\"", "\"\"", "1"] {
            let e = err(&with("upstream_profile", p));
            assert!(
                e.contains("upstream_profile") || e.contains("variant"),
                "{p}: {e}"
            );
        }
        assert!(err(&with("upstream_profile", "\"akamai\"")).contains("unknown variant"));
    }

    #[test]
    fn rejects_malformed_addresses() {
        for (key, value) in [
            ("listen", "\"localhost:8080\""),
            ("listen", "\"127.0.0.1\""),
            ("listen", "\"127.0.0.1:99999\""),
            ("origin", "\"not an address\""),
            ("origin", "8081"),
            ("metrics_listen", "\"::1:9901\""),
        ] {
            let e = err(&with(key, value));
            assert!(e.starts_with("invalid TOML"), "{key}={value}: {e}");
        }
    }

    #[test]
    fn rejects_unsafe_or_conflicting_addresses() {
        let cases = [
            ("listen", "\"0.0.0.0:8080\"", "loopback"),
            ("listen", "\"192.0.2.10:8080\"", "loopback"),
            ("listen", "\"127.0.0.1:0\"", "port 0"),
            ("origin", "\"0.0.0.0:8081\"", "unspecified"),
            ("origin", "\"127.0.0.1:8080\"", "proxy loop"),
            ("origin", "\"127.0.0.1:9901\"", "proxy loop"),
            ("metrics_listen", "\"127.0.0.1:8080\"", "must differ"),
        ];
        for (key, value, needle) in cases {
            let e = err(&with(key, value));
            assert!(e.contains(needle), "{key}={value}: {e}");
        }
    }

    /// /metrics has no authentication, so it may only listen on loopback or on
    /// a private / VPN address that the brain VM scrapes, never on all
    /// interfaces or a public address (deploy/systemd/edge.toml.example).
    #[test]
    fn metrics_listen_must_not_be_public() {
        for value in [
            "\"0.0.0.0:9901\"",
            "\"[::]:9901\"",
            "\"203.0.113.10:9901\"",
            "\"8.8.8.8:9901\"",
            "\"[2001:db8::1]:9901\"",
            "\"169.254.10.1:9901\"",
            "\"[fe80::1]:9901\"",
            "\"224.0.0.1:9901\"",
        ] {
            let e = err(&with("metrics_listen", value));
            assert!(e.contains("metrics_listen"), "{value}: {e}");
        }
        for value in [
            "\"127.0.0.1:9901\"",
            "\"[::1]:9901\"",
            "\"10.0.0.5:9901\"",
            "\"172.17.0.1:9901\"",
            "\"192.168.1.20:9901\"",
            "\"100.64.1.2:9901\"",
            "\"[fd7a:115c:a1e0::1]:9901\"",
        ] {
            let text = with("metrics_listen", value);
            assert!(EdgeConfig::from_toml_str(&text).is_ok(), "{value}");
        }
    }

    #[test]
    fn rejects_bad_site_ids_and_unknown_keys() {
        for id in [
            "\"\"",
            "\"Blog\"",
            "\"-blog\"",
            "\"blog site\"",
            "\"b/../x\"",
        ] {
            assert!(err(&with("site_id", id)).contains("site_id"), "{id}");
        }
        assert!(EdgeConfig::from_toml_str(&with("site_id", "\"my-blog_2\"")).is_ok());

        let e = err(&format!("{VALID}\nlisten_tls = \"127.0.0.1:8443\"\n"));
        assert!(e.contains("unknown field"), "{e}");
        let e = err(&format!("{VALID}\n[server]\nthreadz = 2\n"));
        assert!(e.contains("unknown field"), "{e}");
        let e = err(&format!("{VALID}\n[server]\nthreads = 0\n"));
        assert!(e.contains("server.threads"), "{e}");
    }

    #[test]
    fn missing_required_keys_fail() {
        let text: String = VALID
            .lines()
            .filter(|l| !l.contains("metrics_listen"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(err(&text).contains("metrics_listen"));
    }

    #[test]
    fn load_reports_path_on_io_error() {
        let e = EdgeConfig::load(Path::new("/nonexistent/mg-edge.toml")).unwrap_err();
        assert!(e.to_string().contains("/nonexistent/mg-edge.toml"), "{e}");
    }
}
