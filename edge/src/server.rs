//! Builds the Pingora server (docs/impl/phase1-spec.md §9.1.1, §9.2): one
//! proxy service per listener, the metrics endpoint, and the background
//! services `mg-bundles`, `mg-state`, `mg-events` and `mg-rdns`.
//!
//! Everything here runs in `main()` before [`Server::run_forever`] forks:
//! only runtime-free objects are created (handles, bounded channels, the
//! `ArcSwap`ed site runtimes, TLS acceptor builders).

use crate::background::{
    BundleService, BundleWork, EventsBackground, RdnsBackground, StateBackground,
};
use crate::config::{EdgeConfig, ListenerAuth};
use crate::identity::RdnsDispatcher;
use crate::listener::CloudflareIpFilter;
use crate::metrics::metrics;
use crate::proxy::{EdgeProxy, Shared};
use crate::startup::Startup;
use mg_edge_core::events::{EventQueues, StreamWriter};
use mg_edge_core::state::{StateMode, StateService};
use pingora::server::Server;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::background::background_service;
use std::sync::{Arc, PoisonError};

/// Process-level options that come from the command line rather than the file.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    /// Take over the listening sockets of a running instance (graceful upgrade).
    pub upgrade: bool,
    /// Fork into the background and write `server.pid_file` (systemd
    /// `Type=forking`, see `deploy/systemd/mg-edge.service`).
    ///
    /// On macOS (development only) the daemon needs
    /// `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`: Pingora starts its timer
    /// thread right before `fork()`, and the Objective-C runtime then aborts
    /// the child when a system framework (hickory's DNS configuration)
    /// initializes a class. `scripts/edge-smoke.sh` sets it.
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

/// Creates the server with every service attached. Call
/// [`Server::run_forever`] on the result.
pub fn build(startup: Startup, run: RunOptions) -> Server {
    let opt = Opt {
        upgrade: run.upgrade,
        daemon: run.daemon,
        ..Opt::default()
    };
    let cfg = &startup.cfg;
    let mut server = Server::new_with_opt_and_conf(opt, server_conf(cfg));
    server.bootstrap();
    let m = metrics();
    m.set_info(&cfg.edge_id);
    m.init_static();
    for site in &cfg.sites {
        m.init_site(&site.id);
    }
    let site_ids: Vec<&str> = cfg.sites.iter().map(|s| s.id.as_str()).collect();
    for l in &startup.listeners {
        m.init_listener(
            &l.cfg.name,
            l.cfg.profile.as_str(),
            l.cfg.auth(),
            l.runtime.upstream_keys.is_some(),
            l.cfg.auth() == ListenerAuth::OriginMtls && l.cfg.cloudflare_ip_filter,
            &site_ids,
        );
    }

    // Runtime-free handles (§9.1.1 item 1); the services run them later.
    let (state_service, state) = StateService::new(startup.state.clone());
    let (queues, flusher) = EventQueues::new(&cfg.events);
    if let Err(e) = queues
        .metrics()
        .register(pingora_prometheus::prometheus::default_registry())
    {
        log::error!("event metrics: registration failed: {e}");
    }
    let (rdns, rdns_receiver) = RdnsDispatcher::new(
        cfg.intel.rdns_concurrency,
        cfg.intel.rdns_jobs_per_prefix_per_min,
        crate::background::RDNS_QUEUE_CAPACITY,
        state.clone(),
    );
    let rdns_service = RdnsBackground::new(
        rdns_receiver,
        startup.resolver.clone(),
        crate::dns::job_deadline(cfg.intel.dns_timeout_ms),
    );
    let shared = Arc::new(Shared {
        edge_id: cfg.edge_id.clone(),
        sites: Arc::clone(&startup.sites),
        state,
        k_pseudo: startup.state.k_pseudo,
        events: queues,
        stream_output: startup.state.mode == StateMode::Valkey,
        sdk: Arc::clone(&startup.sdk),
        rdns: Arc::new(rdns),
    });

    for l in &startup.listeners {
        let name = format!("mg-edge {}", l.cfg.name);
        let mut proxy = pingora::proxy::http_proxy_service_with_name(
            &server.configuration,
            EdgeProxy::new(Arc::clone(&l.runtime), Arc::clone(&shared)),
            &name,
        );
        let addr = l.cfg.bind.to_string();
        let tls = l.tls.lock().unwrap_or_else(PoisonError::into_inner).take();
        match tls {
            Some(settings) => proxy.add_tls_with_settings(&addr, None, settings),
            None => proxy.add_tcp(&addr),
        }
        if l.cfg.auth() == ListenerAuth::OriginMtls && l.cfg.cloudflare_ip_filter {
            proxy.set_connection_filter(Arc::new(CloudflareIpFilter::new(
                &l.cfg.name,
                Arc::clone(&startup.sites),
            )));
        }
        server.add_service(proxy);
    }

    let mut prom = pingora_prometheus::prometheus_http_service();
    prom.add_tcp(&cfg.metrics_listen.to_string());
    server.add_service(prom);

    let sites = startup
        .sources
        .into_iter()
        .zip(startup.sites.iter().cloned())
        .collect();
    server.add_service(background_service(
        "mg-bundles",
        BundleService::new(BundleWork {
            fetcher: startup.fetcher,
            dir: startup.state_dir,
            keys: startup.owner_keys,
            sites,
        }),
    ));
    server.add_service(background_service(
        "mg-state",
        StateBackground::new(state_service),
    ));
    let stream: Option<Arc<dyn StreamWriter>> = shared
        .stream_output
        .then(|| Arc::new(shared.state.clone()) as Arc<dyn StreamWriter>);
    server.add_service(background_service(
        "mg-events",
        EventsBackground::new(flusher, cfg.events.clone(), stream),
    ));
    server.add_service(background_service("mg-rdns", rdns_service));
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra_server: &str) -> EdgeConfig {
        let text = format!(
            "{}\n[server]\n{extra_server}\n",
            crate::config::tests::VALID
        );
        EdgeConfig::from_toml_str(&text).unwrap()
    }

    #[test]
    fn server_conf_applies_settings() {
        let c = cfg("threads = 3\npid_file = \"/run/morphgate/mg-edge.pid\"\n\
             upgrade_sock = \"/run/morphgate/mg-edge-upgrade.sock\"\ngrace_period_seconds = 7");
        let conf = server_conf(&c);
        assert_eq!(conf.threads, 3);
        assert_eq!(conf.pid_file, "/run/morphgate/mg-edge.pid");
        assert_eq!(conf.upgrade_sock, "/run/morphgate/mg-edge-upgrade.sock");
        assert_eq!(conf.grace_period_seconds, Some(7));
        assert_eq!(conf.graceful_shutdown_timeout_seconds, Some(5));
    }

    #[test]
    fn daemon_mode_requires_a_pid_file() {
        let without = cfg("");
        let with = cfg("pid_file = \"/run/morphgate/mg-edge.pid\"");
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
