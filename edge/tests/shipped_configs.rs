//! The configuration files shipped in the repository must stay loadable by
//! this binary, and the systemd unit must only use flags, credentials and
//! paths that match the example configuration (docs/impl/phase1-spec.md
//! §8.1 last paragraph). Nothing here opens a socket.

mod common;

use common::{EDGE_BIN, fixture, repo, temp_dir};
use mg_edge::config::{CredRef, EdgeConfig};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const UNIT: &str = "deploy/systemd/mg-edge.service";
const UNIT_CONFIG: &str = "/etc/morphgate/edge.toml";
const EXAMPLE: &str = "deploy/systemd/edge.toml.example";
const DEV: &str = "edge/config/edge.dev.toml";

/// Values of every `Key=` line in the unit (comments excluded).
fn unit_values(unit: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    unit.lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .collect()
}

/// Every `cred://<name>` the configuration references.
fn credential_names(cfg: &EdgeConfig) -> BTreeSet<String> {
    let mut refs: Vec<&CredRef> = vec![&cfg.pseudo.key];
    refs.extend(cfg.valkey.password.iter());
    refs.extend(cfg.bundle_client.client_key.iter());
    for l in &cfg.listeners {
        refs.extend(l.upstream_keys.iter());
        refs.extend(l.tls_key.iter());
    }
    for s in &cfg.sites {
        refs.push(&s.token_keys);
        refs.push(&s.seal_root);
    }
    refs.into_iter()
        .filter_map(|r| match r {
            CredRef::Credential(name) => Some(name.clone()),
            CredRef::Path(_) => None,
        })
        .collect()
}

/// A sandbox where the example's absolute paths exist: the config text with
/// `/etc/morphgate`, `/var/lib/morphgate`, `/run/morphgate` and
/// `/opt/morphgate/sdk` moved under a temporary directory, the owner test key
/// as the owner key, the fixture SDK, and a credentials directory with every
/// credential the unit loads.
struct Sandbox {
    dir: PathBuf,
    config: PathBuf,
    creds: PathBuf,
}

impl Sandbox {
    fn new(example: &str) -> Self {
        let dir = temp_dir("shipped");
        let etc = dir.join("etc");
        let creds = dir.join("creds");
        std::fs::create_dir_all(etc.join("owner-keys")).unwrap();
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::copy(
            repo("testdata/phase1/keys/owner-test.pub"),
            etc.join("owner-keys/owner-2026.pub"),
        )
        .unwrap();
        for (name, src) in [
            ("mg-upstream-keys", "upstream-keys.json"),
            ("mg-blog-token-keys", "token.keys.json"),
            ("mg-blog-seal-root", "seal.root.json"),
            ("mg-pseudo-key", "pseudo.key.json"),
        ] {
            std::fs::copy(repo("testdata/phase1/keys").join(src), creds.join(name)).unwrap();
        }
        std::fs::write(creds.join("mg-valkey-password"), "not-a-real-password\n").unwrap();
        let text = example
            .replace("/etc/morphgate", &etc.display().to_string())
            .replace(
                "/var/lib/morphgate",
                &dir.join("state").display().to_string(),
            )
            .replace("/run/morphgate", &dir.join("run").display().to_string())
            .replace("/opt/morphgate/sdk", &fixture("sdk").display().to_string());
        let config = etc.join("edge.toml");
        std::fs::write(&config, text).unwrap();
        Self { dir, config, creds }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn dev_config_loads_and_checks() {
    let cfg = EdgeConfig::load(&repo(DEV)).unwrap();
    assert_eq!(cfg.edge_id, "dev");
    // deploy/compose's mock-origin publishes 127.0.0.1:8081.
    assert_eq!(cfg.sites[0].origin, "127.0.0.1:8081".parse().unwrap());
    // make edge-run: the shared test keys as credentials, and the file://
    // bundle root it creates (--check-config requires a readable directory).
    let root = Path::new("/tmp/morphgate-dev/publish");
    assert_eq!(
        cfg.sites[0].bundle_root,
        format!("file://{}/", root.display())
    );
    std::fs::create_dir_all(root.join("bundles")).unwrap();
    let out = Command::new(EDGE_BIN)
        .args(["--check-config", "--config"])
        .arg(repo(DEV))
        .env("CREDENTIALS_DIRECTORY", repo("testdata/phase1/keys"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let makefile = std::fs::read_to_string(repo("Makefile")).unwrap();
    assert!(
        makefile.contains("CREDENTIALS_DIRECTORY=$(CURDIR)/testdata/phase1/keys"),
        "make edge-run must provide the dev credentials"
    );
    assert!(
        makefile.contains("mkdir -p /tmp/morphgate-dev/publish/bundles"),
        "make edge-run must create the dev bundle root"
    );
}

#[test]
fn systemd_example_matches_the_unit() {
    let unit = std::fs::read_to_string(repo(UNIT)).unwrap();
    let cfg = EdgeConfig::load(&repo(EXAMPLE)).unwrap();

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

    let state_dir = unit_values(&unit, "StateDirectory");
    assert_eq!(state_dir.len(), 1, "{UNIT} needs StateDirectory=");
    assert_eq!(
        cfg.state_dir,
        Path::new("/var/lib").join(&state_dir[0]),
        "state_dir must be the unit's StateDirectory= (writable under ProtectSystem=strict)"
    );

    let timeout: u64 = unit_values(&unit, "TimeoutStopSec")[0]
        .trim_end_matches('s')
        .parse()
        .unwrap();
    let stop = cfg.server.grace_period_seconds + cfg.server.graceful_shutdown_timeout_seconds;
    assert!(
        stop < timeout,
        "grace + shutdown timeout ({stop}s) must be below TimeoutStopSec ({timeout}s)"
    );

    // Every cred:// name has a LoadCredential(Encrypted)= line and vice versa.
    let loaded: BTreeSet<String> = ["LoadCredential", "LoadCredentialEncrypted"]
        .iter()
        .flat_map(|k| unit_values(&unit, k))
        .map(|v| v.split(':').next().unwrap().to_owned())
        .collect();
    assert_eq!(credential_names(&cfg), loaded);
}

/// `systemctl reload` must check the new configuration before it hands the
/// sockets over: a failing check stops the reload and the old process keeps
/// serving.
#[test]
fn reload_checks_the_configuration_first() {
    let unit = std::fs::read_to_string(repo(UNIT)).unwrap();
    let reload = unit_values(&unit, "ExecReload");
    assert!(reload.len() >= 3, "{reload:?}");
    assert!(
        reload[0].contains("/mg-edge ") && reload[0].contains("--check-config"),
        "the first ExecReload= must be mg-edge --check-config: {reload:?}"
    );
    assert!(
        !reload[0].starts_with('-'),
        "a failing check must stop the reload"
    );
    assert!(reload[1].contains("kill -QUIT"), "{reload:?}");
    assert!(reload[2].contains(" -u "), "{reload:?}");
}

/// Every `mg-edge` command line in the unit, run with `--check-config` against
/// the example config (in a sandbox where its paths and credentials exist),
/// must be accepted (unknown flags exit 2).
#[test]
fn systemd_command_lines_are_accepted() {
    let unit = std::fs::read_to_string(repo(UNIT)).unwrap();
    let example = std::fs::read_to_string(repo(EXAMPLE)).unwrap();
    let sandbox = Sandbox::new(&example);
    let commands: Vec<String> = ["ExecStartPre", "ExecStart", "ExecReload"]
        .iter()
        .flat_map(|k| unit_values(&unit, k))
        .filter(|c| c.contains("/mg-edge "))
        .collect();
    assert!(
        commands.len() >= 3,
        "expected ExecStart and two ExecReload lines to run mg-edge: {commands:?}"
    );

    for command in commands {
        let mut words = command.split_whitespace();
        words.next(); // /usr/local/bin/mg-edge
        let mut args: Vec<String> = words
            .map(|w| {
                if w == UNIT_CONFIG {
                    sandbox.config.display().to_string()
                } else {
                    w.to_owned()
                }
            })
            .collect();
        if !args.iter().any(|a| a == "--check-config") {
            args.push("--check-config".into());
        }
        let out = Command::new(EDGE_BIN)
            .args(&args)
            .env("CREDENTIALS_DIRECTORY", &sandbox.creds)
            .output()
            .unwrap();
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
        .arg(repo(DEV))
        .env("CREDENTIALS_DIRECTORY", repo("testdata/phase1/keys"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pid_file"));
}
