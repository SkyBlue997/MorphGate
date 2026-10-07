//! Minimal HTTP/1.1 server for bundle and artifact fetch tests: ETag /
//! If-None-Match, 304, redirects, delays (WP-C2).
//!
//! Also the helpers to build and sign test bundles with the owner test key
//! of `testdata/phase1/keys/` (RFC 8032 §7.1 test 1; test use only), shared
//! with mg-edge's integration tests.
//!
//! The server listens on `127.0.0.1:0` and runs on its own thread with its
//! own current-thread tokio runtime, so it works from synchronous tests, from
//! `#[tokio::test]` and next to an in-process Pingora server alike. Every
//! response carries `Connection: close`.

use crate::bundle::{OwnerKeys, signing_input};
use mg_proto::v1::{
    ChallengeConfig, Channel, ClearanceConfig, CloudflareSiteConfig, CrawlerPolicy, Environment,
    EventConfig, OriginHeaderConfig, Route, RouteSensitivity, ScoringConfig, SignedBundle,
    SiteBundle, UpstreamProfile, UpstreamProfileKind, challenge_config::PowBits,
};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Seed of the owner test key (`testdata/phase1/keys/owner-test.key.json`):
/// RFC 8032 §7.1 test 1 secret key. Never use outside tests.
pub const OWNER_TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Key id of the owner test key.
pub const OWNER_TEST_KID: &str = "owner-test";

/// `testdata/phase1/keys/owner-test.pub`.
pub const OWNER_TEST_PUB: &[u8] = include_bytes!("../../../testdata/phase1/keys/owner-test.pub");

/// [`OwnerKeys`] trusting only the owner test key.
pub fn owner_test_keys() -> OwnerKeys {
    OwnerKeys::from_pub_files(&[("owner-test.pub", OWNER_TEST_PUB)])
        .unwrap_or_else(|e| unreachable!("the shared owner test key is valid: {e}"))
}

/// Serializes `site`, signs `"mg-bundle-v1" || 0x00 || bundle` with the
/// Ed25519 key derived from `seed` (deterministic RFC 8032 signature) and
/// returns the `SignedBundle` bytes with `key_id = kid`.
pub fn sign_test_bundle(site: &SiteBundle, seed: &[u8; 32], kid: &str) -> Vec<u8> {
    sign_test_bytes(&site.encode_to_vec(), seed, kid)
}

/// Like [`sign_test_bundle`] for arbitrary inner bytes (tests of malformed
/// bundles that still carry a valid signature).
pub fn sign_test_bytes(bundle: &[u8], seed: &[u8; 32], kid: &str) -> Vec<u8> {
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(*seed));
    let signature = kp.sk.sign(signing_input(bundle), None);
    SignedBundle {
        bundle: bundle.to_vec(),
        key_id: kid.to_string(),
        ed25519_signature: signature.to_vec(),
    }
    .encode_to_vec()
}

/// A valid Phase 1 bundle for `site_id` behind the `cloudflare` profile: one
/// `production` environment holding every host with only the builder's
/// `default` route, token key id `<site>-t-20260927`, listener `cf-tunnel`,
/// monitor mode, and every config message filled with the §8.3 defaults.
pub fn test_site_bundle(site_id: &str, hosts: &[&str], version: u64) -> SiteBundle {
    let hosts: Vec<String> = hosts.iter().map(|h| (*h).to_string()).collect();
    // NETWORK | HTTP | RATE | IDENTITY | EDGE_TLS | EXTERNAL (bit = SignalFamily number).
    let expected_mask = (1 << 1) | (1 << 3) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10);
    SiteBundle {
        site_id: site_id.to_string(),
        version,
        created_at_ms: 1_790_000_000_000,
        upstream: Some(UpstreamProfile {
            kind: UpstreamProfileKind::Cloudflare as i32,
            expected_mask,
            ..Default::default()
        }),
        environments: vec![Environment {
            name: "production".into(),
            routes: vec![Route {
                id: "default".into(),
                name: "default".into(),
                paths: vec!["/**".into()],
                channel: Channel::Web as i32,
                sensitivity: RouteSensitivity::Low as i32,
                ..Default::default()
            }],
            hosts: hosts.clone(),
            ..Default::default()
        }],
        token_key_ids: vec![format!("{site_id}-t-20260927")],
        monitor_only: true,
        schema_version: 1,
        allowed_listeners: vec!["cf-tunnel".into()],
        challenge: Some(ChallengeConfig {
            ttl_s: 120,
            pow_bits: Some(PowBits {
                low: 14,
                medium: 16,
                high: 18,
                very_high: 20,
            }),
            fallback_ret: "/".into(),
            max_failures: 5,
            failure_window_s: 600,
            submit_rate: 30,
            submit_period_s: 60,
            submit_burst: 10,
            issue_per_ipp: 60,
            issue_per_asn: 600,
            issue_period_s: 3600,
        }),
        clearance: Some(ClearanceConfig {
            ttl_invisible_s: 1800,
            ttl_pow_s: 1800,
            session_max_s: 86_400,
            ctp_shadow: true,
        }),
        scoring: Some(ScoringConfig {
            theta_c: 0.4,
            kappa: 0.0,
            z0: [
                ("low", -2.197),
                ("medium", -1.735),
                ("high", -1.386),
                ("critical", -1.099),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            family_modes: [("edge_tls".to_string(), "shadow".to_string())].into(),
            weights: HashMap::new(),
            h_min: -4.0,
            ruleset_version: "v1".into(),
        }),
        crawler_policy: Some(CrawlerPolicy {
            purposes: HashMap::new(),
            default_action: "allow".into(),
        }),
        events: Some(EventConfig {
            allow_sample_rate: 0.1,
            access_log: true,
            stream: true,
        }),
        cloudflare: Some(CloudflareSiteConfig {
            zone: hosts.first().cloned().unwrap_or_default(),
            owner_zones: hosts.first().cloned().into_iter().collect(),
            ..Default::default()
        }),
        origin_headers: Some(OriginHeaderConfig {
            scores: true,
            reasons: false,
            session: true,
        }),
        hosts,
        ..Default::default()
    }
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// What the server answers for a path.
#[derive(Clone, Debug)]
pub enum Reply {
    /// 200 with `body`. With an `etag`, the response carries it and a
    /// request whose `If-None-Match` equals it gets 304.
    Body { body: Vec<u8>, etag: Option<String> },
    /// `status` (301 / 302 / 307 / 308) with `Location: location`.
    Redirect { status: u16, location: String },
    /// A bare status with an empty body.
    Status(u16),
    /// 200 without `Content-Length`: `total` filler bytes, then close.
    Unsized { total: usize },
}

/// A request as the server saw it.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    /// Request target without the query, leading `/` removed.
    pub path: String,
    /// Header names lower-cased, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl RecordedRequest {
    /// First value of header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    routes: HashMap<String, (Reply, Duration)>,
    requests: Vec<RecordedRequest>,
}

/// The test HTTP server. Stops when dropped.
pub struct HttpServer {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("addr", &self.addr)
            .finish()
    }
}

impl HttpServer {
    /// Binds `127.0.0.1:0` and starts serving.
    pub fn start() -> std::io::Result<Self> {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let state = Arc::new(Mutex::new(State::default()));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let thread_state = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name("mg-testkit-http".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(std_listener) else {
                        return;
                    };
                    tokio::select! {
                        () = accept_loop(listener, thread_state) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(Self {
            addr,
            state,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>/`: usable as a `bundle_root`.
    pub fn root(&self) -> String {
        format!("http://{}/", self.addr)
    }

    /// Absolute URL of `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path.trim_start_matches('/'))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answers `path` with `reply` (keeps an existing delay).
    pub fn set(&self, path: &str, reply: Reply) {
        let mut st = self.lock();
        let key = path.trim_start_matches('/').to_string();
        let delay = st.routes.get(&key).map_or(Duration::ZERO, |(_, d)| *d);
        st.routes.insert(key, (reply, delay));
    }

    /// Waits `delay` before answering `path`.
    pub fn set_delay(&self, path: &str, delay: Duration) {
        let mut st = self.lock();
        let key = path.trim_start_matches('/').to_string();
        let entry = st
            .routes
            .entry(key)
            .or_insert((Reply::Status(404), Duration::ZERO));
        entry.1 = delay;
    }

    /// Serves `body` at `path` with the strong ETag `"<sha256 hex>"`.
    pub fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
        let body = body.into();
        let etag = format!("\"{}\"", sha256_hex(&body));
        self.set(
            path,
            Reply::Body {
                body,
                etag: Some(etag),
            },
        );
    }

    /// Stops serving `path` (404).
    pub fn remove(&self, path: &str) {
        self.lock().routes.remove(path.trim_start_matches('/'));
    }

    /// Publishes a signed bundle at `bundles/<site>.bundle`.
    pub fn publish_bundle(&self, site: &str, signed: &[u8]) {
        self.put(&format!("bundles/{site}.bundle"), signed.to_vec());
    }

    /// Publishes an artifact at `artifacts/<sha256>` and returns the hash.
    pub fn publish_artifact(&self, bytes: &[u8]) -> String {
        let sha = sha256_hex(bytes);
        self.put(&format!("artifacts/{sha}"), bytes.to_vec());
        sha
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.lock().requests.clone()
    }

    /// Number of requests for `path`.
    pub fn hits(&self, path: &str) -> usize {
        let path = path.trim_start_matches('/');
        self.lock()
            .requests
            .iter()
            .filter(|r| r.path == path)
            .count()
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<Mutex<State>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve(stream, Arc::clone(&state)));
    }
}

async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let Some(req) = read_head(&mut stream).await else {
        return;
    };
    let (reply, delay) = {
        let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
        st.requests.push(req.clone());
        st.routes
            .get(&req.path)
            .cloned()
            .unwrap_or((Reply::Status(404), Duration::ZERO))
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let _ = respond(&mut stream, &req, reply).await;
    let _ = stream.shutdown().await;
}

/// Reads and parses the request head (at most 64 KiB, 5 s).
async fn read_head(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = async {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 || buf.len() > 64 * 1024 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Some(())
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .ok()??;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let target = request_line.next()?;
    let path = target
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some(RecordedRequest {
        method,
        path,
        headers,
    })
}

async fn respond(
    stream: &mut TcpStream,
    req: &RecordedRequest,
    reply: Reply,
) -> std::io::Result<()> {
    let head = |status: &str, extra: &str, len: Option<usize>| {
        let mut h = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra}");
        if let Some(len) = len {
            let _ = write!(h, "Content-Length: {len}\r\n");
        }
        h.push_str("\r\n");
        h
    };
    match reply {
        Reply::Body { body, etag } => {
            if let Some(tag) = &etag
                && req.header("if-none-match") == Some(tag.as_str())
            {
                let h = head("304 Not Modified", &format!("ETag: {tag}\r\n"), None);
                return stream.write_all(h.as_bytes()).await;
            }
            let extra = etag.map(|t| format!("ETag: {t}\r\n")).unwrap_or_default();
            let h = head("200 OK", &extra, Some(body.len()));
            stream.write_all(h.as_bytes()).await?;
            if req.method != "HEAD" {
                stream.write_all(&body).await?;
            }
            Ok(())
        }
        Reply::Redirect { status, location } => {
            let h = head(
                &format!("{status} Redirect"),
                &format!("Location: {location}\r\n"),
                Some(0),
            );
            stream.write_all(h.as_bytes()).await
        }
        Reply::Status(status) => {
            let h = head(&format!("{status} Status"), "", Some(0));
            stream.write_all(h.as_bytes()).await
        }
        Reply::Unsized { total } => {
            stream
                .write_all(head("200 OK", "", None).as_bytes())
                .await?;
            let filler = vec![b'x'; 64 * 1024];
            let mut left = total;
            while left > 0 {
                let n = left.min(filler.len());
                stream.write_all(&filler[..n]).await?;
                left -= n;
            }
            Ok(())
        }
    }
}
