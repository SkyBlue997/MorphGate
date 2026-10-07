//! The VictoriaLogs client never goes through a proxy from the environment
//! (spec §1.2: reqwest reads `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` even
//! without its `system-proxy` feature, so `VlClient` must call `no_proxy()`).
//!
//! Environment variables cannot be set in-process (`std::env::set_var` is
//! `unsafe` in edition 2024 and the workspace forbids `unsafe`), so the test
//! re-runs itself as a child process with the proxy variables set.

use mg_edge_core::events::{PostOutcome, Sink, VlClient, VlOptions};
use mg_edge_core::testkit::vl::FakeVl;
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const CHILD_ENV: &str = "MG_EVENTS_NO_PROXY_CHILD";
const TEST_NAME: &str = "vl_client_ignores_proxy_environment";

#[test]
fn vl_client_ignores_proxy_environment() {
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
    // Exactly one connection: the control client's, never the VlClient's.
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

fn child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let vl = FakeVl::start().unwrap();
        let url = format!("{}/insert/jsonline", vl.url());

        // Control: a client without no_proxy() honours the variables, which
        // proves they are in effect for this process.
        let plain = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let control = plain.post(&url).body("{}\n").send().await;
        assert!(control.is_err(), "the fake proxy never answers");
        assert!(
            vl.requests().is_empty(),
            "control request bypassed the proxy"
        );

        let client = VlClient::with_options(
            Some(&vl.url()),
            None,
            VlOptions {
                timeout: Duration::from_secs(2),
                backoff: Vec::new(),
            },
        )
        .unwrap();
        let outcome = client
            .post_batch(Sink::Main, b"{\"kind\":\"t\"}\n".to_vec())
            .await;
        assert_eq!(outcome, PostOutcome::Accepted { attempts: 1 });
        assert_eq!(vl.requests().len(), 1, "VlClient went direct");
    });
}
