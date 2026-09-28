//! `mg-edge` binary: parse flags, load `edge.toml` v1 and everything it
//! references, then run Pingora (or only check, `--check-config`).
//!
//! Exit codes: 0 success; 1 `--check-config` found a site whose LKG bundle
//! exists but cannot be used (§9.10); 2 invalid configuration, key file,
//! credential or SDK directory (for `--check-config` also a `file://`
//! bundle root that is not a readable directory, which a starting Edge only
//! logs).

use clap::Parser;
use mg_edge::config::EdgeConfig;
use mg_edge::creds::CredResolver;
use mg_edge::server::{self, RunOptions};
use mg_edge::startup::Startup;
use std::path::PathBuf;
use std::process::ExitCode;

/// MorphGate Edge reverse proxy.
///
/// Signals: SIGTERM = graceful stop (server.grace_period_seconds),
/// SIGINT = immediate stop, SIGQUIT = hand sockets to a new `--upgrade` process.
#[derive(Debug, Parser)]
#[command(name = "mg-edge", version, about)]
struct Cli {
    /// Path to the Edge TOML configuration (edge.toml v1).
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Validate the configuration, credentials, key files, SDK directory and
    /// every site's last-known-good bundle, then exit (no network access).
    #[arg(long)]
    check_config: bool,

    /// Take over the listening sockets of a running mg-edge (graceful upgrade;
    /// uses server.upgrade_sock).
    #[arg(short, long)]
    upgrade: bool,

    /// Fork into the background and write server.pid_file (for systemd
    /// Type=forking; see deploy/systemd/mg-edge.service).
    #[arg(short, long)]
    daemon: bool,
}

fn main() -> ExitCode {
    mg_edge::logging::init();
    let cli = Cli::parse();
    let path = cli.config.display().to_string();

    let cfg = match EdgeConfig::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("mg-edge: {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let run = RunOptions {
        upgrade: cli.upgrade,
        daemon: cli.daemon,
    };
    if let Err(e) = run.validate(&cfg) {
        eprintln!("mg-edge: {path}: {e}");
        return ExitCode::from(2);
    }
    let startup = match Startup::load(cfg, &CredResolver::from_env()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mg-edge: {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let lkg_failures = startup.lkg_failures();

    if cli.check_config {
        for w in &startup.warnings {
            eprintln!("mg-edge: warning: {w}");
        }
        if !startup.check_errors.is_empty() {
            for e in &startup.check_errors {
                eprintln!("mg-edge: {path}: {e}");
            }
            return ExitCode::from(2);
        }
        if !lkg_failures.is_empty() {
            for (site, why) in &lkg_failures {
                eprintln!("mg-edge: site {site}: the LKG bundle exists but cannot be used: {why}");
            }
            return ExitCode::from(1);
        }
        println!("mg-edge: {path} OK");
        return ExitCode::SUCCESS;
    }

    for w in startup.warnings.iter().chain(&startup.check_errors) {
        log::warn!("{w}");
    }
    for (site, why) in &lkg_failures {
        log::error!("site {site}: lkg_invalid: {why}");
    }
    let c = &startup.cfg;
    log::info!(
        "mg-edge {} edge_id={} listeners={} sites={} metrics={}",
        env!("CARGO_PKG_VERSION"),
        c.edge_id,
        c.listeners
            .iter()
            .map(|l| format!("{}@{}", l.name, l.bind))
            .collect::<Vec<_>>()
            .join(","),
        c.sites
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>()
            .join(","),
        c.metrics_listen
    );
    server::build(startup, run).run_forever()
}
