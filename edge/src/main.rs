//! `mg-edge` binary: parse flags, load the TOML config, run Pingora.

use clap::Parser;
use mg_edge::config::EdgeConfig;
use mg_edge::server::{self, RunOptions};
use std::path::PathBuf;
use std::process::ExitCode;

/// MorphGate Edge reverse proxy.
///
/// Signals: SIGTERM = graceful stop (server.grace_period_seconds),
/// SIGINT = immediate stop, SIGQUIT = hand sockets to a new `--upgrade` process.
#[derive(Debug, Parser)]
#[command(name = "mg-edge", version, about)]
struct Cli {
    /// Path to the Edge TOML configuration.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Validate the configuration and exit.
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let cfg = match EdgeConfig::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("mg-edge: {e}");
            return ExitCode::from(2);
        }
    };
    let run = RunOptions {
        upgrade: cli.upgrade,
        daemon: cli.daemon,
    };
    if let Err(e) = run.validate(&cfg) {
        eprintln!("mg-edge: {}: {e}", cli.config.display());
        return ExitCode::from(2);
    }
    if cli.check_config {
        println!("mg-edge: {} OK", cli.config.display());
        return ExitCode::SUCCESS;
    }

    log::info!(
        "mg-edge {} site={} profile={:?} listen={} origin={} metrics={}",
        env!("CARGO_PKG_VERSION"),
        cfg.site_id,
        cfg.upstream_profile,
        cfg.listen,
        cfg.origin,
        cfg.metrics_listen
    );
    server::build(&cfg, run).run_forever()
}
