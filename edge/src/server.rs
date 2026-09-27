//! Builds the Pingora server from an [`EdgeConfig`].

use crate::config::EdgeConfig;
use crate::metrics::metrics;
use crate::proxy::EdgeProxy;
use mg_core::UpstreamProfileKind;
use pingora::server::Server;
use pingora::server::configuration::{Opt, ServerConf};

/// Process-level options that come from the command line rather than the file.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    /// Take over the listening sockets of a running instance (graceful upgrade).
    pub upgrade: bool,
    /// Fork into the background and write `server.pid_file` (systemd
    /// `Type=forking`, see `deploy/systemd/mg-edge.service`).
    pub daemon: bool,
}

impl RunOptions {
    /// Checks the command-line options against the configuration.
    ///
    /// Daemon mode needs an explicit `server.pid_file`: Pingora would otherwise
    /// write `/tmp/pingora.pid`, which systemd's `PIDFile=` cannot see under
    /// `PrivateTmp=` and which would clash with any other Pingora process.
    pub fn validate(&self, cfg: &EdgeConfig) -> Result<(), String> {
        if self.daemon && cfg.server.pid_file.is_none() {
            return Err("--daemon requires [server] pid_file in the configuration".into());
        }
        Ok(())
    }
}

/// Pingora `ServerConf` derived from `cfg.server`.
pub fn server_conf(cfg: &EdgeConfig) -> ServerConf {
    let mut conf = ServerConf::default();
    let s = &cfg.server;
    if let Some(threads) = s.threads {
        conf.threads = threads;
    }
    if let Some(pid) = &s.pid_file {
        conf.pid_file = pid.display().to_string();
    }
    if let Some(sock) = &s.upgrade_sock {
        conf.upgrade_sock = sock.display().to_string();
    }
    conf.grace_period_seconds = Some(s.grace_period_seconds);
    conf.graceful_shutdown_timeout_seconds = Some(s.graceful_shutdown_timeout_seconds);
    conf
}

/// Creates the server with the proxy and metrics services attached.
/// Call [`Server::run_forever`] on the result.
pub fn build(cfg: &EdgeConfig, run: RunOptions) -> Server {
    let opt = Opt {
        upgrade: run.upgrade,
        daemon: run.daemon,
        ..Opt::default()
    };
    let mut server = Server::new_with_opt_and_conf(opt, server_conf(cfg));
    server.bootstrap();

    let mut proxy = pingora::proxy::http_proxy_service_with_name(
        &server.configuration,
        EdgeProxy::new(cfg),
        "mg-edge proxy",
    );
    proxy.add_tcp(&cfg.listen.to_string());

    let mut prom = pingora_prometheus::prometheus_http_service();
    prom.add_tcp(&cfg.metrics_listen.to_string());

    let profile = UpstreamProfileKind::from(cfg.upstream_profile);
    metrics().set_info(&cfg.site_id, profile.as_str());

    server.add_service(proxy);
    server.add_service(prom);
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_conf_applies_settings() {
        let cfg = EdgeConfig::from_toml_str(
            r#"
            site_id = "blog"
            listen = "127.0.0.1:8080"
            origin = "127.0.0.1:8081"
            upstream_profile = "cloudflare"
            metrics_listen = "127.0.0.1:9901"
            [server]
            threads = 3
            pid_file = "/run/morphgate/mg-edge.pid"
            upgrade_sock = "/run/morphgate/mg-edge-upgrade.sock"
            grace_period_seconds = 7
            "#,
        )
        .unwrap();
        let conf = server_conf(&cfg);
        assert_eq!(conf.threads, 3);
        assert_eq!(conf.pid_file, "/run/morphgate/mg-edge.pid");
        assert_eq!(conf.upgrade_sock, "/run/morphgate/mg-edge-upgrade.sock");
        assert_eq!(conf.grace_period_seconds, Some(7));
        assert_eq!(conf.graceful_shutdown_timeout_seconds, Some(5));
    }

    #[test]
    fn daemon_mode_requires_a_pid_file() {
        let base = r#"
            site_id = "blog"
            listen = "127.0.0.1:8080"
            origin = "127.0.0.1:8081"
            upstream_profile = "cloudflare"
            metrics_listen = "127.0.0.1:9901"
        "#;
        let without = EdgeConfig::from_toml_str(base).unwrap();
        let with = EdgeConfig::from_toml_str(&format!(
            "{base}\n[server]\npid_file = \"/run/morphgate/mg-edge.pid\"\n"
        ))
        .unwrap();
        let daemon = RunOptions {
            daemon: true,
            ..RunOptions::default()
        };

        assert!(RunOptions::default().validate(&without).is_ok());
        assert!(daemon.validate(&with).is_ok());
        let err = daemon.validate(&without).unwrap_err();
        assert!(err.contains("pid_file"), "{err}");
    }
}
