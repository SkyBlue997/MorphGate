//! `Fetcher` over `file://` and HTTP (docs/impl/phase1-spec.md §9.10:
//! ETag / 304, same-origin redirects (<= 3), timeout, size limits,
//! `no_proxy()`; §12.1 layout).

use mg_edge_core::bundle::{
    BundleError, Fetched, Fetcher, FetcherConfig, MAX_SIGNED_BUNDLE_BYTES, Source,
};
use mg_edge_core::testkit::http::{HttpServer, Reply, sha256_hex};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const TIMEOUT: Duration = Duration::from_secs(2);

fn fetcher() -> Fetcher {
    Fetcher::new(&FetcherConfig::new(TIMEOUT)).unwrap()
}

fn http_root(server: &HttpServer) -> Source {
    Source::parse(&server.root()).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mg-bundle-fetch-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("bundles")).unwrap();
        fs::create_dir_all(dir.join("artifacts")).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn source(&self) -> Source {
        Source::parse(&format!("file://{}/", self.0.display())).unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// §9.10: `file://` roots: the ETag is the SHA-256 of the file.
#[tokio::test]
async fn file_source_uses_the_content_hash_as_etag() {
    let tmp = TempDir::new("file");
    let f = fetcher();
    let root = tmp.source();
    fs::write(tmp.path().join("bundles/blog.bundle"), b"v1").unwrap();

    let Fetched::Body { bytes, etag } = f.fetch_bundle(&root, "blog", None).await.unwrap() else {
        panic!("expected a body");
    };
    assert_eq!(bytes, b"v1");
    assert_eq!(etag, sha256_hex(b"v1"));
    assert_eq!(
        f.fetch_bundle(&root, "blog", Some(&etag)).await.unwrap(),
        Fetched::NotModified
    );
    fs::write(tmp.path().join("bundles/blog.bundle"), b"v2").unwrap();
    assert!(matches!(
        f.fetch_bundle(&root, "blog", Some(&etag)).await.unwrap(),
        Fetched::Body { bytes, .. } if bytes == b"v2"
    ));

    // Missing file: a fetch failure.
    let err = f.fetch_bundle(&root, "shop", None).await.unwrap_err();
    assert!(err.is_fetch_failure(), "{err}");

    // Oversized file.
    fs::write(
        tmp.path().join("bundles/big.bundle"),
        vec![0u8; MAX_SIGNED_BUNDLE_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        f.fetch_bundle(&root, "big", None).await,
        Err(BundleError::TooLarge { .. })
    ));

    // Site ids that would leave bundles/.
    for site in ["../blog", "a/b", ""] {
        assert!(matches!(
            f.fetch_bundle(&root, site, None).await,
            Err(BundleError::Source(_))
        ));
    }
}

#[tokio::test]
async fn file_source_artifacts() {
    let tmp = TempDir::new("file-artifacts");
    let f = fetcher();
    let root = tmp.source();
    let bytes = b"AS64500\n";
    let sha = sha256_hex(bytes);
    fs::write(tmp.path().join("artifacts").join(&sha), bytes).unwrap();
    assert_eq!(f.fetch_artifact(&root, &sha, 8).await.unwrap(), bytes);
    // Larger than the size the bundle declares.
    assert!(matches!(
        f.fetch_artifact(&root, &sha, 7).await,
        Err(BundleError::TooLarge { .. })
    ));
    // Content that does not match its name.
    let wrong = sha256_hex(b"other");
    fs::write(tmp.path().join("artifacts").join(&wrong), bytes).unwrap();
    assert!(matches!(
        f.fetch_artifact(&root, &wrong, 100).await,
        Err(BundleError::Artifact { .. })
    ));
}

/// §9.10: `If-None-Match: <last ETag>`, 304 → NotModified, the ETag is
/// returned exactly as the server sent it; the `User-Agent` is the fixed
/// `morphgate-dev-tooling` of integrator ruling I-7 (no owner identity).
#[tokio::test]
async fn http_etag_and_304() {
    let server = HttpServer::start().unwrap();
    let f = fetcher();
    let root = http_root(&server);
    server.publish_bundle("blog", b"signed-v1");

    let Fetched::Body { bytes, etag } = f.fetch_bundle(&root, "blog", None).await.unwrap() else {
        panic!("expected a body");
    };
    assert_eq!(bytes, b"signed-v1");
    assert_eq!(etag, format!("\"{}\"", sha256_hex(b"signed-v1")));
    assert_eq!(
        f.fetch_bundle(&root, "blog", Some(&etag)).await.unwrap(),
        Fetched::NotModified
    );
    // A stale ETag gets the new body.
    server.publish_bundle("blog", b"signed-v2");
    assert!(matches!(
        f.fetch_bundle(&root, "blog", Some(&etag)).await.unwrap(),
        Fetched::Body { bytes, .. } if bytes == b"signed-v2"
    ));

    let reqs = server.requests();
    assert_eq!(reqs.len(), 3);
    assert!(
        reqs.iter()
            .all(|r| r.method == "GET" && r.path == "bundles/blog.bundle")
    );
    assert_eq!(reqs[0].header("if-none-match"), None);
    assert_eq!(reqs[1].header("if-none-match"), Some(etag.as_str()));
    let ua = reqs[0].header("user-agent").unwrap();
    assert_eq!(ua, FetcherConfig::DEFAULT_USER_AGENT);
    assert_eq!(ua, "morphgate-dev-tooling");
    // No identifying or proxy-related headers.
    assert!(
        reqs.iter()
            .all(|r| r.header("referer").is_none() && r.header("from").is_none())
    );
}

#[tokio::test]
async fn http_without_etag_and_error_statuses() {
    let server = HttpServer::start().unwrap();
    let f = fetcher();
    let root = http_root(&server);
    server.set(
        "bundles/blog.bundle",
        Reply::Body {
            body: b"x".to_vec(),
            etag: None,
        },
    );
    assert_eq!(
        f.fetch_bundle(&root, "blog", None).await.unwrap(),
        Fetched::Body {
            bytes: b"x".to_vec(),
            etag: String::new()
        }
    );
    // 404, 500, and a 304 to an unconditional request are errors.
    for (status, site) in [(404, "missing"), (500, "broken"), (304, "bogus")] {
        if status != 404 {
            server.set(&format!("bundles/{site}.bundle"), Reply::Status(status));
        }
        match f.fetch_bundle(&root, site, None).await {
            Err(BundleError::Status(s)) => assert_eq!(s, status),
            other => panic!("{status}: {other:?}"),
        }
    }
}

/// §9.10: at most 3 redirects, same origin only.
#[tokio::test]
async fn http_redirects_stay_on_origin() {
    let server = HttpServer::start().unwrap();
    let other = HttpServer::start().unwrap();
    let f = fetcher();
    let root = http_root(&server);
    server.put("final/blog.bundle", b"ok".to_vec());
    let hop = |from: &str, to: &str, status: u16| {
        server.set(
            from,
            Reply::Redirect {
                status,
                location: to.to_string(),
            },
        );
    };

    // Three same-origin hops (relative and absolute Location) are followed.
    hop("bundles/blog.bundle", "/r1", 302);
    hop("r1", &server.url("r2"), 301);
    hop("r2", "/final/blog.bundle", 307);
    assert!(matches!(
        f.fetch_bundle(&root, "blog", None).await.unwrap(),
        Fetched::Body { bytes, .. } if bytes == b"ok"
    ));

    // A fourth hop is refused.
    hop("bundles/blog.bundle", "/r0", 302);
    hop("r0", "/r1", 302);
    let err = f.fetch_bundle(&root, "blog", None).await.unwrap_err();
    assert!(err.to_string().contains("redirects"), "{err}");

    // Another origin (same host, other port) is refused and never contacted.
    other.put("bundles/blog.bundle", b"evil".to_vec());
    hop(
        "bundles/blog.bundle",
        &other.url("bundles/blog.bundle"),
        302,
    );
    let err = f.fetch_bundle(&root, "blog", None).await.unwrap_err();
    assert!(err.to_string().contains("another origin"), "{err}");
    assert_eq!(other.requests().len(), 0);
}

/// §9.10: `timeout_ms` bounds a stalled server.
#[tokio::test]
async fn http_timeout() {
    let server = HttpServer::start().unwrap();
    let f = Fetcher::new(&FetcherConfig::new(Duration::from_millis(300))).unwrap();
    server.put("bundles/blog.bundle", b"late".to_vec());
    server.set_delay("bundles/blog.bundle", Duration::from_secs(5));
    let start = Instant::now();
    let err = f
        .fetch_bundle(&http_root(&server), "blog", None)
        .await
        .unwrap_err();
    assert!(matches!(err, BundleError::Timeout), "{err}");
    assert!(err.is_fetch_failure());
    assert!(start.elapsed() < Duration::from_secs(3));
}

/// Oversized responses are cut off, with or without `Content-Length`.
#[tokio::test]
async fn http_size_limits() {
    let server = HttpServer::start().unwrap();
    let f = fetcher();
    let root = http_root(&server);
    server.put("bundles/big.bundle", vec![0u8; MAX_SIGNED_BUNDLE_BYTES + 1]);
    assert!(matches!(
        f.fetch_bundle(&root, "big", None).await,
        Err(BundleError::TooLarge { .. })
    ));
    server.set(
        "bundles/stream.bundle",
        Reply::Unsized {
            total: 64 * 1024 * 1024,
        },
    );
    let start = Instant::now();
    assert!(matches!(
        f.fetch_bundle(&root, "stream", None).await,
        Err(BundleError::TooLarge { .. })
    ));
    assert!(start.elapsed() < TIMEOUT);

    // Exactly at the limit is fine.
    server.put("bundles/max.bundle", vec![1u8; MAX_SIGNED_BUNDLE_BYTES]);
    assert!(matches!(
        f.fetch_bundle(&root, "max", None).await.unwrap(),
        Fetched::Body { bytes, .. } if bytes.len() == MAX_SIGNED_BUNDLE_BYTES
    ));
}

/// §9.10: artifacts are checked against their SHA-256 and declared size.
#[tokio::test]
async fn http_artifacts() {
    let server = HttpServer::start().unwrap();
    let f = fetcher();
    let root = http_root(&server);
    let bytes = b"198.51.100.0/24\n".to_vec();
    let sha = server.publish_artifact(&bytes);
    assert_eq!(
        f.fetch_artifact(&root, &sha, bytes.len() as u64)
            .await
            .unwrap(),
        bytes
    );
    assert_eq!(server.hits(&format!("artifacts/{sha}")), 1);

    // Larger than declared.
    assert!(matches!(
        f.fetch_artifact(&root, &sha, bytes.len() as u64 - 1).await,
        Err(BundleError::TooLarge { .. })
    ));
    // Served content does not match the name.
    let wrong = sha256_hex(b"something else");
    server.put(&format!("artifacts/{wrong}"), bytes.clone());
    assert!(matches!(
        f.fetch_artifact(&root, &wrong, 100).await,
        Err(BundleError::Artifact { .. })
    ));
    // Missing.
    assert!(matches!(
        f.fetch_artifact(&root, &"0".repeat(64), 100).await,
        Err(BundleError::Status(404))
    ));
    // A name that is not a digest never reaches the server.
    let before = server.requests().len();
    for bad in ["../bundles/blog.bundle", &"A".repeat(64), ""] {
        assert!(matches!(
            f.fetch_artifact(&root, bad, 100).await,
            Err(BundleError::Artifact { .. })
        ));
    }
    assert_eq!(server.requests().len(), before);
}

/// Records every TCP connection it accepts and answers 502 (a fake proxy).
struct ProxyRecorder {
    addr: std::net::SocketAddr,
    count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ProxyRecorder {
    fn start() -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = std::sync::Arc::clone(&count);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.read(&mut [0u8; 4096]);
                let _ = stream.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                );
            }
        });
        Self { addr, count }
    }
    fn connections(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

const CHILD_ENV: &str = "MG_BUNDLE_PROXY_CHILD_TARGET";

/// §9.10 / §1.2: reqwest 0.13 reads `HTTP_PROXY` / `HTTPS_PROXY` /
/// `ALL_PROXY` whatever its features; the fetcher calls `no_proxy()`, so it
/// connects directly even when they point at a listener. Environment
/// variables cannot be set safely inside this multi-threaded test process
/// (and `unsafe` is forbidden), so the check runs in a child process: this
/// test binary re-executed for `proxy_env_child` with the variables set.
#[test]
fn proxy_environment_is_ignored() {
    let server = HttpServer::start().unwrap();
    server.put("bundles/blog.bundle", b"direct".to_vec());
    let proxy = ProxyRecorder::start();
    let proxy_url = format!("http://{}", proxy.addr);
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "proxy_env_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, server.root())
        .env("HTTP_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("REQUEST_METHOD")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The child's control request (a plain client) went to the proxy, which
    // proves the variables were in effect; the fetcher's did not.
    assert_eq!(proxy.connections(), 1, "{stdout}");
    assert_eq!(server.hits("bundles/blog.bundle"), 1);
}

#[tokio::test]
#[ignore = "child process of proxy_environment_is_ignored"]
async fn proxy_env_child() {
    let Ok(root) = std::env::var(CHILD_ENV) else {
        eprintln!("SKIPPED: run only as the child of proxy_environment_is_ignored");
        return;
    };
    let f = fetcher();
    let got = f
        .fetch_bundle(&Source::parse(&root).unwrap(), "blog", None)
        .await
        .unwrap();
    assert!(matches!(got, Fetched::Body { bytes, .. } if bytes == b"direct"));
    // Control: a client without no_proxy() honours the variables.
    let plain = reqwest::Client::builder().build().unwrap();
    let resp = plain
        .get(format!("{root}bundles/blog.bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        502,
        "control request did not use the proxy"
    );
}
