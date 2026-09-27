//! End-to-end: run the real `mg-edge` binary against an in-process origin on
//! loopback and talk HTTP/1.1 to it. Only loopback addresses are used.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const EDGE_BIN: &str = env!("CARGO_BIN_EXE_mg-edge");

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Origin that answers every request with 200 and reports which request line
/// and `mg-*` headers it received.
fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_one(stream));
        }
    });
    addr
}

fn serve_one(mut s: TcpStream) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let seen: Vec<&str> = head
        .lines()
        .filter(|l| l.starts_with("get ") || l.starts_with("mg-") || l.starts_with("mg_"))
        .collect();
    let body = format!("origin saw: {}", seen.join(" | "));
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

struct Response {
    status: u16,
    head: String,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

fn get(addr: SocketAddr, path: &str, extra_headers: &str) -> std::io::Result<Response> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: smoke.test\r\nConnection: close\r\n{extra_headers}\r\n"
    )?;
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok(Response {
        status,
        head: head.to_string(),
        body: body.to_string(),
    })
}

/// A running `mg-edge`; killed and cleaned up on drop.
struct Edge {
    child: Child,
    config: PathBuf,
    log: PathBuf,
    listen: SocketAddr,
    metrics: SocketAddr,
}

impl Edge {
    fn start(origin: SocketAddr) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let metrics: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let tag = format!("mg-edge-smoke-{}-{}", std::process::id(), listen.port());
        let config = std::env::temp_dir().join(format!("{tag}.toml"));
        let log = std::env::temp_dir().join(format!("{tag}.log"));
        std::fs::write(
            &config,
            format!(
                "site_id = \"smoke\"\nlisten = \"{listen}\"\norigin = \"{origin}\"\n\
                 upstream_profile = \"cloudflare\"\nmetrics_listen = \"{metrics}\"\n\
                 [server]\nthreads = 1\n"
            ),
        )
        .unwrap();
        let child = Command::new(EDGE_BIN)
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("spawn mg-edge");
        let edge = Self {
            child,
            config,
            log,
            listen,
            metrics,
        };
        edge.wait_ready();
        edge
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if get(self.listen, "/__mg/healthz", "").is_ok_and(|r| r.status == 200) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        panic!("mg-edge did not become ready; log:\n{log}");
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
        let _ = std::fs::remove_file(&self.log);
    }
}

#[test]
fn edge_serves_healthz_proxies_origin_and_exposes_metrics() {
    let origin = spawn_origin();
    let edge = Edge::start(origin);

    let health = get(edge.listen, "/__mg/healthz", "").unwrap();
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "ok");
    assert_eq!(health.header("cache-control"), Some("no-store, private"));

    let reserved = get(edge.listen, "/__mg/does-not-exist", "").unwrap();
    assert_eq!(reserved.status, 404);
    assert_eq!(reserved.header("cache-control"), Some("no-store, private"));
    assert!(!reserved.body.contains("origin saw"));

    // Spellings that Cloudflare's rules normalize to /__mg/... (and exempt
    // from bot checks and caching) must not reach the origin either.
    for path in [
        "//__mg/c",
        "/%5F%5Fmg/c",
        "/x/../__mg/c",
        "/%5F%5Fmg/..%2F..%2Fsecret.txt",
    ] {
        let r = get(edge.listen, path, "").unwrap();
        assert_eq!(r.status, 404, "{path}: {}", r.head);
        assert_eq!(
            r.header("cache-control"),
            Some("no-store, private"),
            "{path}"
        );
        assert!(!r.body.contains("origin saw"), "{path} reached the origin");
    }

    let proxied = get(
        edge.listen,
        "/hello?x=1",
        "MG-Bot-Score: 0\r\nmg-verified: googlebot\r\nMG_Bot_Class: human\r\nX-Other: kept\r\n",
    )
    .unwrap();
    assert_eq!(proxied.status, 200, "{}", proxied.head);
    assert!(
        proxied
            .body
            .starts_with("origin saw: get /hello?x=1 http/1.1"),
        "{}",
        proxied.body
    );
    assert!(
        !proxied.body.contains("mg-") && !proxied.body.contains("mg_"),
        "client MG-* headers must not reach the origin: {}",
        proxied.body
    );

    let metrics = get(edge.metrics, "/metrics", "").unwrap();
    assert_eq!(metrics.status, 200);
    assert!(
        metrics
            .body
            .contains("mg_edge_requests_total{route=\"healthz\",status=\"2xx\"}"),
        "{}",
        metrics.body
    );
    assert!(metrics.body.contains("route=\"origin\",status=\"2xx\""));
    assert!(metrics.body.contains("mg_edge_info{"));
}

#[test]
fn check_config_flag_validates_and_exits() {
    let dir = std::env::temp_dir();
    let good = dir.join(format!("mg-edge-check-ok-{}.toml", std::process::id()));
    let bad = dir.join(format!("mg-edge-check-bad-{}.toml", std::process::id()));
    std::fs::write(
        &good,
        "site_id = \"s\"\nlisten = \"127.0.0.1:18080\"\norigin = \"127.0.0.1:18081\"\n\
         upstream_profile = \"direct_tls\"\nmetrics_listen = \"127.0.0.1:19901\"\n",
    )
    .unwrap();
    std::fs::write(
        &bad,
        "site_id = \"s\"\nlisten = \"127.0.0.1:18080\"\norigin = \"127.0.0.1:18081\"\n\
         upstream_profile = \"cloudfront\"\nmetrics_listen = \"127.0.0.1:19901\"\n",
    )
    .unwrap();

    let run = |path: &PathBuf| {
        Command::new(EDGE_BIN)
            .arg("--config")
            .arg(path)
            .arg("--check-config")
            .output()
            .unwrap()
    };
    let ok = run(&good);
    let err = run(&bad);
    let _ = std::fs::remove_file(&good);
    let _ = std::fs::remove_file(&bad);

    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(err.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&err.stderr).contains("unknown variant `cloudfront`"));
}
