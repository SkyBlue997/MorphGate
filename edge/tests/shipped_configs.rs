//! The configuration files shipped in the repository must stay loadable by
//! this binary, and the systemd unit must only use flags the binary accepts.
//! Nothing here opens a socket.

use mg_edge::config::EdgeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

const EDGE_BIN: &str = env!("CARGO_BIN_EXE_mg-edge");

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

const UNIT: &str = "deploy/systemd/mg-edge.service";
const UNIT_CONFIG: &str = "/etc/morphgate/edge.toml";
const EXAMPLE: &str = "deploy/systemd/edge.toml.example";

/// Values of every `Key=` line in the unit's `[Service]` section.
fn unit_values(unit: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    unit.lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .collect()
}

#[test]
fn dev_config_loads() {
    let cfg = EdgeConfig::load(&repo_path("edge/config/edge.dev.toml")).unwrap();
    assert_eq!(cfg.site_id, "dev");
    // deploy/compose's mock-origin publishes 127.0.0.1:8081.
    assert_eq!(cfg.origin, "127.0.0.1:8081".parse().unwrap());
}

#[test]
fn systemd_example_matches_the_unit() {
    let unit = std::fs::read_to_string(repo_path(UNIT)).unwrap();
    let cfg = EdgeConfig::load(&repo_path(EXAMPLE)).unwrap();

    let pid_file = unit_values(&unit, "PIDFile");
    assert_eq!(pid_file.len(), 1, "{UNIT} needs exactly one PIDFile=");
    assert_eq!(
        cfg.server.pid_file.as_deref(),
        Some(Path::new(&pid_file[0])),
        "{EXAMPLE} server.pid_file must match PIDFile= in {UNIT}"
    );

    let runtime_dir = unit_values(&unit, "RuntimeDirectory");
    assert_eq!(runtime_dir.len(), 1, "{UNIT} needs RuntimeDirectory=");
    let run_dir = Path::new("/run").join(&runtime_dir[0]);
    for (name, path) in [
        ("pid_file", cfg.server.pid_file.as_deref()),
        ("upgrade_sock", cfg.server.upgrade_sock.as_deref()),
    ] {
        let path = path.unwrap_or_else(|| panic!("{EXAMPLE} must set server.{name}"));
        assert!(
            path.starts_with(&run_dir),
            "server.{name} {} must live in {} (RuntimeDirectory=; /tmp is private)",
            path.display(),
            run_dir.display()
        );
    }

    let timeout: u64 = unit_values(&unit, "TimeoutStopSec")[0]
        .trim_end_matches('s')
        .parse()
        .unwrap();
    let stop = cfg.server.grace_period_seconds + cfg.server.graceful_shutdown_timeout_seconds;
    assert!(
        stop < timeout,
        "grace + shutdown timeout ({stop}s) must be below TimeoutStopSec ({timeout}s)"
    );
}

/// Every `mg-edge` command line in the unit, run with `--check-config` against
/// the example config, must be accepted (unknown flags exit 2).
#[test]
fn systemd_command_lines_are_accepted() {
    let unit = std::fs::read_to_string(repo_path(UNIT)).unwrap();
    let example = repo_path(EXAMPLE);
    let commands: Vec<String> = ["ExecStartPre", "ExecStart", "ExecReload"]
        .iter()
        .flat_map(|k| unit_values(&unit, k))
        .filter(|c| c.contains("/mg-edge "))
        .collect();
    assert!(
        commands.len() >= 3,
        "expected ExecStartPre, ExecStart and ExecReload to run mg-edge: {commands:?}"
    );

    for command in commands {
        let mut words = command.split_whitespace();
        words.next(); // /usr/local/bin/mg-edge
        let mut args: Vec<String> = words
            .map(|w| {
                if w == UNIT_CONFIG {
                    example.display().to_string()
                } else {
                    w.to_owned()
                }
            })
            .collect();
        if !args.iter().any(|a| a == "--check-config") {
            args.push("--check-config".into());
        }
        let out = Command::new(EDGE_BIN).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "`{command}` rejected: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn daemon_flag_without_pid_file_is_rejected() {
    let out = Command::new(EDGE_BIN)
        .arg("-d")
        .arg("--check-config")
        .arg("--config")
        .arg(repo_path("edge/config/edge.dev.toml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pid_file"));
}
