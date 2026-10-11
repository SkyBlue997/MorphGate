//! The outbound client never goes through a proxy from the environment
//! (docs/impl/phase2-spec.md §8.4: reqwest reads `HTTP_PROXY` /
//! `HTTPS_PROXY` / `ALL_PROXY` unless the builder calls `no_proxy()`).
//!
//! Environment variables cannot be set in-process (`std::env::set_var` is
//! `unsafe` in edition 2024 and the workspace forbids `unsafe`), so the test
//! re-runs itself as a child process with the proxy variables set.

use mg_edge_core::outbound::{
    Siteverify, SiteverifyExpect, SiteverifyRequest, TurnstileSecrets, validate_siteverify_url,
};
use mg_edge_core::testkit::siteverify::{FakeSiteverify, SvReply};
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const CHILD_ENV: &str = "MG_OUTBOUND_NO_PROXY_CHILD";
const TEST_NAME: &str = "siteverify_ignores_proxy_environment";

#[test]
fn siteverify_ignores_proxy_environment() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
        return;
    }

    // A "proxy" that only counts connections and hangs up.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let counter = {
        let (connections, stop) = (Arc::clone(&connections), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match proxy.accept() {
                    Ok((mut stream, _)) => {
                        connections.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                        let _ = stream.read(&mut [0u8; 1024]);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        })
    };

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(var, &proxy_url);
    }
    let output = command.output().unwrap();
    stop.store(true, Ordering::Relaxed);
    counter.join().unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "child did not run the test"
    );
    // Exactly one connection: the control client's, never the Siteverify's.
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

fn child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mock = FakeSiteverify::start().unwrap();
        mock.set_default_reply(SvReply::success(
            "example.com",
            "login",
            "cd",
            "2026-09-21T14:13:20Z",
        ));

        // Control: a client without no_proxy() honours the variables, which
        // proves they are in effect for this process.
        let plain = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let control = plain.post(mock.url()).body("{}").send().await;
        assert!(control.is_err(), "the fake proxy never answers");
        assert!(
            mock.requests().is_empty(),
            "control request bypassed the proxy"
        );

        let sv = Siteverify::build(validate_siteverify_url(&mock.url(), true).unwrap()).unwrap();
        let secrets = TurnstileSecrets::new(vec!["s1".into()]).unwrap();
        let hostnames = vec!["example.com".to_owned()];
        let ok = |_: &str| true;
        let now = 1_790_000_000_000;
        let expect = SiteverifyExpect {
            host: "example.com",
            hostnames: &hostnames,
            action: "login",
            c_iat_ms: now,
            now_ms: now,
            deadline_ms: now + 2_000,
            cdata_ok: &ok,
        };
        let req = SiteverifyRequest {
            secrets: &secrets,
            response: "tok",
            remoteip: "203.0.113.7".parse().unwrap(),
            nonce: &[1; 16],
        };
        let verdict = sv.verify(&req, &expect).await;
        assert!(verdict.is_pass(), "{verdict:?}");
        assert_eq!(mock.requests().len(), 1, "Siteverify went direct");
    });
}
