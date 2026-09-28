//! Shared harness of the mg-edge integration tests (WP-E1a, reused by
//! E1b-E1d). Loopback only: an echo origin, the real `mg-edge` binary with a
//! generated `edge.toml` v1, test credentials copied from
//! `testdata/phase1/keys/` into a private `CREDENTIALS_DIRECTORY`, bundles
//! signed with the owner test key (`mg_edge_core::testkit::http`), a
//! `file://` bundle root and a raw HTTP/1.1 client.
#![allow(dead_code)]

use mg_edge_core::testkit::http::{OWNER_TEST_KID, OWNER_TEST_SEED, sha256_hex, sign_test_bundle};
use mg_proto::v1::SiteBundle;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const EDGE_BIN: &str = env!("CARGO_BIN_EXE_mg-edge");

/// The hosts of the test site "blog" (the golden bundles use the same).
pub const HOSTS: [&str; 3] = ["example.com", "www.example.com", "staging.example.com"];

pub fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

pub fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn free_addr() -> SocketAddr {
    format!("127.0.0.1:{}", free_port()).parse().unwrap()
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A fresh temporary directory (removed by [`TestEnv`]'s drop).
pub fn temp_dir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = std::env::temp_dir().join(format!(
        "mg-edge-it-{tag}-{}-{n}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// ---------------------------------------------------------------------------
// Origin

/// One request as the origin received it.
#[derive(Debug, Clone)]
pub struct Seen {
    /// The request line, e.g. `GET /a?b HTTP/1.1`.
    pub line: String,
    /// Header field lines in arrival order (names as sent).
    pub headers: Vec<(String, String)>,
    /// The request body (`Content-Length` or chunked, de-chunked).
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

/// An origin that answers every request with 200 `origin ok` and records
/// what it saw. `GET /mg-response` answers with `MG-*` headers set (the Edge
/// must strip them).
#[derive(Debug, Clone)]
pub struct Origin {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Origin {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let rec = Arc::clone(&rec);
                std::thread::spawn(move || serve(stream, &rec));
            }
        });
        Self { addr, seen }
    }

    /// Every request so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// The last request whose request line contains `needle`.
    pub fn last(&self, needle: &str) -> Option<Seen> {
        self.seen()
            .into_iter()
            .rev()
            .find(|s| s.line.contains(needle))
    }
}

fn serve(mut s: TcpStream, rec: &Mutex<Vec<Seen>>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    loop {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
        let line = lines.next().unwrap_or_default().to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.to_owned(), v.trim().to_owned()))
            .collect();
        let mut seen = Seen {
            line,
            headers,
            body: Vec::new(),
        };
        // Read a chunked or Content-Length body.
        let chunked = seen
            .header("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
        let body = if chunked {
            read_chunked(&mut s)
        } else {
            let len: usize = seen
                .header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).ok().map(|()| body)
        };
        let Some(body) = body else { return };
        seen.body = body;
        let extra = if seen.line.contains("/mg-response") {
            "MG-Session: leaked\r\nmg_bot_class: leaked\r\nX-Origin: kept\r\n"
        } else {
            ""
        };
        rec.lock().unwrap().push(seen);
        let body = "origin ok";
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        );
        if s.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

/// Reads a chunked body (no trailers expected); `None` on a framing error.
fn read_chunked(s: &mut TcpStream) -> Option<Vec<u8>> {
    fn line(s: &mut TcpStream) -> Option<String> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while !out.ends_with(b"\r\n") {
            s.read_exact(&mut byte).ok()?;
            out.push(byte[0]);
        }
        out.truncate(out.len() - 2);
        String::from_utf8(out).ok()
    }
    let mut body = Vec::new();
    loop {
        let size_line = line(s)?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            // The empty line after the last chunk (no trailers).
            return line(s)?.is_empty().then_some(body);
        }
        let mut chunk = vec![0u8; size + 2];
        s.read_exact(&mut chunk).ok()?;
        if !chunk.ends_with(b"\r\n") {
            return None;
        }
        body.extend_from_slice(&chunk[..size]);
    }
}

// ---------------------------------------------------------------------------
// Client

/// A response as the client saw it.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    pub fn has_header_prefix(&self, prefix: &str) -> bool {
        self.head
            .lines()
            .skip(1)
            .any(|l| l.len() >= prefix.len() && l[..prefix.len()].eq_ignore_ascii_case(prefix))
    }
}

/// Sends raw bytes and reads the response until the server closes.
pub fn raw(addr: SocketAddr, request: &[u8]) -> std::io::Result<Response> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(request)?;
    read_response(&mut s)
}

pub fn read_response(s: &mut impl Read) -> std::io::Result<Response> {
    // Until EOF; a reset after the response arrived (the Edge closed with
    // unread request bytes) still yields that response.
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && !raw.is_empty() => {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok(Response {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    })
}

/// `GET <path>` for `host` with extra header lines (each ending in `\r\n`).
pub fn get(addr: SocketAddr, host: &str, path: &str, headers: &str) -> Response {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{headers}\r\n");
    raw(addr, req.as_bytes()).unwrap_or_else(|e| panic!("GET {path}: {e}"))
}

/// `CF-Connecting-IP` of a cloudflare request from a client at `ip`.
pub fn cf(ip: &str) -> String {
    format!(
        "CF-Connecting-IP: {ip}\r\nCF-Ray: 8f00aa11bb22cc33-HKG\r\nCF-Visitor: {{\"scheme\":\"https\"}}\r\n"
    )
}

// ---------------------------------------------------------------------------
// Bundles

/// The standard test bundle for site "blog" (monitor mode, cloudflare,
/// owner zone example.com, listener cf-tunnel, token kid blog-t-20260927).
pub fn blog_bundle(version: u64) -> SiteBundle {
    mg_edge_core::testkit::http::test_site_bundle("blog", &HOSTS, version)
}

/// Signed with the owner test key.
pub fn sign(b: &SiteBundle) -> Vec<u8> {
    sign_test_bundle(b, &OWNER_TEST_SEED, OWNER_TEST_KID)
}

// ---------------------------------------------------------------------------
// Environment and process

/// Temporary state for one Edge: credentials, state dir, bundle root.
#[derive(Debug)]
pub struct TestEnv {
    pub dir: PathBuf,
    pub creds: PathBuf,
    pub state: PathBuf,
    /// The `file://` bundle root (`bundles/`, `artifacts/`).
    pub publish: PathBuf,
    pub origin: Origin,
    pub listen: SocketAddr,
    pub metrics: SocketAddr,
}

impl TestEnv {
    pub fn new(tag: &str) -> Self {
        let dir = temp_dir(tag);
        let creds = dir.join("creds");
        let state = dir.join("state");
        let publish = dir.join("publish");
        for d in [
            &creds,
            &state,
            &publish.join("bundles"),
            &publish.join("artifacts"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        for (name, src) in [
            ("mg-blog-token-keys", "token.keys.json"),
            ("mg-blog-token-keys-rotated", "token.keys.rotated.json"),
            ("mg-blog-seal-root", "seal.root.json"),
            ("mg-pseudo-key", "pseudo.key.json"),
            ("mg-upstream-keys", "upstream-keys.rotated.json"),
        ] {
            let to = creds.join(name);
            std::fs::copy(repo("testdata/phase1/keys").join(src), &to).unwrap();
            #[cfg(unix)]
            chmod(&to, 0o600);
        }
        Self {
            dir,
            creds,
            state,
            publish,
            origin: Origin::start(),
            listen: free_addr(),
            metrics: free_addr(),
        }
    }

    pub fn bundle_root(&self) -> String {
        format!("file://{}/", self.publish.display())
    }

    /// A v1 config: the `cf-tunnel` loopback listener on [`Self::listen`],
    /// `extra` appended verbatim (more listeners), and `site` as the
    /// `[[sites]]` table body for site "blog" (see [`Self::site`]).
    pub fn config(&self, extra: &str, site: &str) -> String {
        format!(
            r#"config_version = 1
edge_id = "edge-test"
metrics_listen = "{metrics}"
state_dir = "{state}"

[server]
threads = 1
grace_period_seconds = 0
graceful_shutdown_timeout_seconds = 1

[trust]
owner_keys = ["{owner}"]

[[listeners]]
name = "cf-tunnel"
bind = "{listen}"
profile = "cloudflare"
{extra}
[[sites]]
{site}

[pseudo]
key = "cred://mg-pseudo-key"

[valkey]
mode = "local"

[sdk]
dir = "{sdk}"
"#,
            metrics = self.metrics,
            state = self.state.display(),
            owner = repo("testdata/phase1/keys/owner-test.pub").display(),
            listen = self.listen,
            sdk = fixture("sdk").display(),
        )
    }

    /// The `[[sites]]` body of site "blog" with `extra` lines appended.
    pub fn site(&self, extra: &str) -> String {
        format!(
            r#"id = "blog"
hosts = ["example.com", "www.example.com", "staging.example.com"]
listeners = ["cf-tunnel"]
origin = "{origin}"
bundle_root = "{root}"
bundle_poll_seconds = 2
token_keys = "cred://mg-blog-token-keys"
seal_root = "cred://mg-blog-seal-root"
{extra}"#,
            origin = self.origin.addr,
            root = self.bundle_root(),
        )
    }

    /// The default config: one listener, site "blog" with `site_extra`.
    pub fn default_config(&self, site_extra: &str) -> String {
        self.config("", &self.site(site_extra))
    }

    pub fn write_config(&self, text: &str) -> PathBuf {
        let path = self.dir.join("edge.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Publishes a signed bundle under the bundle root.
    pub fn publish(&self, site: &str, signed: &[u8]) {
        let path = self.publish.join("bundles").join(format!("{site}.bundle"));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, signed).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
    }

    /// Publishes an artifact under the bundle root; returns its SHA-256.
    pub fn publish_artifact(&self, bytes: &[u8]) -> String {
        let sha = sha256_hex(bytes);
        std::fs::write(self.publish.join("artifacts").join(&sha), bytes).unwrap();
        sha
    }

    /// Writes the LKG file of `site` into the state dir.
    pub fn write_lkg(&self, site: &str, signed: &[u8]) {
        let dir = self.state.join("bundles");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{site}.bundle")), signed).unwrap();
    }

    /// Puts an artifact into the state dir's cache; returns its SHA-256.
    pub fn cache_artifact(&self, bytes: &[u8]) -> String {
        let dir = self.state.join("artifacts");
        std::fs::create_dir_all(&dir).unwrap();
        let sha = sha256_hex(bytes);
        std::fs::write(dir.join(&sha), bytes).unwrap();
        sha
    }

    /// `mg-edge --check-config` for `config`.
    pub fn check(&self, config: &Path) -> std::process::Output {
        Command::new(EDGE_BIN)
            .arg("--check-config")
            .arg("--config")
            .arg(config)
            .env("CREDENTIALS_DIRECTORY", &self.creds)
            .output()
            .unwrap()
    }

    /// Starts `mg-edge` with `config` and waits until it serves.
    pub fn spawn(&self, config: &Path) -> Edge {
        self.spawn_logging(config, "info,mg_edge=debug")
    }

    /// [`Self::spawn`] with `RUST_LOG` set to `rust_log`.
    pub fn spawn_logging(&self, config: &Path, rust_log: &str) -> Edge {
        let log = self
            .dir
            .join(format!("edge-{}.log", SEQ.fetch_add(1, Ordering::Relaxed)));
        let child = Command::new(EDGE_BIN)
            .arg("--config")
            .arg(config)
            .env("CREDENTIALS_DIRECTORY", &self.creds)
            .env("RUST_LOG", rust_log)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("spawn mg-edge");
        let edge = Edge {
            child,
            log,
            listen: self.listen,
            metrics: self.metrics,
        };
        edge.wait_ready();
        edge
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if std::env::var_os("MG_TEST_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// A running `mg-edge`; killed on drop.
#[derive(Debug)]
pub struct Edge {
    child: Child,
    pub log: PathBuf,
    pub listen: SocketAddr,
    pub metrics: SocketAddr,
}

impl Edge {
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let up =
                |a: &SocketAddr| TcpStream::connect_timeout(a, Duration::from_millis(200)).is_ok();
            if up(&self.metrics) && up(&self.listen) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("mg-edge did not become ready; log:\n{}", self.log_text());
    }

    pub fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The `/metrics` text.
    pub fn metrics_text(&self) -> String {
        get(self.metrics, "metrics", "/metrics", "").body
    }

    /// The value of the sample whose name and labels are exactly `series`
    /// (e.g. `mg_config_version{site="blog"}`), 0 when absent.
    pub fn metric(&self, series: &str) -> f64 {
        metric_value(&self.metrics_text(), series).unwrap_or(0.0)
    }

    /// Polls [`Self::metric`] until `pred` holds (panics after `secs`).
    pub fn wait_metric(&self, series: &str, secs: u64, pred: impl Fn(f64) -> bool) -> f64 {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let v = self.metric(series);
            if pred(v) {
                return v;
            }
            if Instant::now() > deadline {
                panic!(
                    "{series} = {v} did not reach the expected value; log:\n{}",
                    self.log_text()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The debug summary line the proxy logs for `request_id`.
    pub fn request_log(&self, request_id: &str) -> Option<String> {
        let needle = format!("request_id={request_id} ");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(line) = self.log_text().lines().find(|l| l.contains(&needle)) {
                return Some(line.to_owned());
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parses one sample value out of Prometheus text.
pub fn metric_value(text: &str, series: &str) -> Option<f64> {
    text.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let rest = l.strip_prefix(series)?;
        rest.strip_prefix(' ')?.trim().parse().ok()
    })
}

// ---------------------------------------------------------------------------
// Policy rules, routes and limiters for decision tests (WP-E1b)

pub mod policy {
    use mg_proto::v1 as pb;
    use pb::expr::Kind;
    use prost::Message;

    fn node(kind: Kind) -> pb::Expr {
        pb::Expr { kind: Some(kind) }
    }

    /// `field: "<path>"`.
    pub fn field(path: &str) -> pb::Expr {
        node(Kind::Field(path.into()))
    }

    /// A string literal.
    pub fn string(s: &str) -> pb::Expr {
        node(Kind::Literal(pb::Literal {
            value: Some(pb::literal::Value::StringValue(s.into())),
        }))
    }

    /// `lhs == rhs`.
    pub fn eq(lhs: pb::Expr, rhs: pb::Expr) -> pb::Expr {
        node(Kind::Compare(Box::new(pb::Compare {
            op: pb::CompareOp::Eq as i32,
            lhs: Some(Box::new(lhs)),
            rhs: Some(Box::new(rhs)),
        })))
    }

    /// `lhs in rhs` (a list).
    pub fn in_list(lhs: pb::Expr, rhs: pb::Expr) -> pb::Expr {
        node(Kind::InList(Box::new(pb::Binary {
            lhs: Some(Box::new(lhs)),
            rhs: Some(Box::new(rhs)),
        })))
    }

    /// `glob(subject, "<pattern>")`.
    pub fn glob(subject: pb::Expr, pattern: &str) -> pb::Expr {
        node(Kind::Glob(Box::new(pb::Glob {
            subject: Some(Box::new(subject)),
            pattern: pattern.into(),
        })))
    }

    /// A compiled rule (IR v1, `max_steps` computed like the Go compiler),
    /// enforce mode, full rollout.
    pub fn rule(
        id: &str,
        phase: &str,
        action: pb::Action,
        root: pb::Expr,
        params: &[(&str, &str)],
    ) -> pb::CompiledRule {
        let mut expr = pb::PolicyExpr {
            ir_version: 1,
            root: Some(root),
            fields: Vec::new(),
            max_steps: 0,
        };
        let lists = mg_core::policy::NamedLists::default();
        match mg_proto::ir::program_from_proto(&expr, &lists) {
            Err(mg_proto::ir::IrError::Steps { computed, .. }) => expr.max_steps = computed,
            other => panic!("rule {id}: unexpected IR result {other:?}"),
        }
        pb::CompiledRule {
            id: id.into(),
            phase: phase.into(),
            ir_version: 1,
            expr_ir: expr.encode_to_vec(),
            action: action as i32,
            params: params
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            mode: "enforce".into(),
            rollout_percent: 100,
            ..Default::default()
        }
    }

    /// A route (`id == name`).
    pub fn route(
        name: &str,
        paths: &[&str],
        sensitivity: pb::RouteSensitivity,
        require_clearance: bool,
        fail_closed: bool,
    ) -> pb::Route {
        pb::Route {
            id: name.into(),
            name: name.into(),
            paths: paths.iter().map(|p| (*p).to_string()).collect(),
            channel: pb::Channel::Web as i32,
            sensitivity: sensitivity as i32,
            require_clearance,
            fail_closed,
            ..Default::default()
        }
    }

    /// The builder's catch-all route.
    pub fn default_route() -> pb::Route {
        route("default", &["/**"], pb::RouteSensitivity::Low, false, false)
    }

    /// A GCRA limiter (`scope = global`, enforce).
    pub fn limiter(
        id: &str,
        routes: &[&str],
        key: &[&str],
        (rate, period_s, burst): (u32, u32, u32),
        on_exceed: &str,
        retry_after_s: u32,
    ) -> pb::RateLimit {
        pb::RateLimit {
            id: id.into(),
            key: key.iter().map(|k| (*k).to_string()).collect(),
            algorithm: "gcra".into(),
            rate,
            period_s,
            burst,
            on_exceed: on_exceed.into(),
            mode: "enforce".into(),
            route_ids: routes.iter().map(|r| (*r).to_string()).collect(),
            scope: "global".into(),
            retry_after_s,
            ..Default::default()
        }
    }
}

/// The `/metrics` sample of `series`, 0 when absent (prefix-free exact match).
pub fn metric_or_zero(text: &str, series: &str) -> f64 {
    metric_value(text, series).unwrap_or(0.0)
}

/// Waits until the debug line of the request the origin saw last for
/// `needle` is logged, and returns it.
pub fn origin_log(env: &TestEnv, edge: &Edge, needle: &str) -> String {
    let seen = env
        .origin
        .last(needle)
        .unwrap_or_else(|| panic!("the origin never saw {needle}"));
    let id = seen.header("mg-request-id").unwrap().to_owned();
    edge.request_log(&id).expect("request log line")
}

/// The debug line of a request the Edge answered itself, found by path
/// (the answer carries no request id header; bodies do).
pub fn answered_log(edge: &Edge, body: &str) -> String {
    let id = body
        .split('"')
        .find(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .or_else(|| {
            body.split(['<', '>'])
                .find(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .unwrap_or_else(|| panic!("no request id in {body}"));
    edge.request_log(id).expect("request log line")
}

// ---------------------------------------------------------------------------
// Valkey (WP-E1b): a fixture behind a fault proxy, driven by a runtime on
// its own thread so that tests can use blocking clients.

pub mod valkey {
    use mg_edge_core::testkit::valkey::{FaultMode, FaultProxy, ValkeyFixture};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    /// A Valkey server (`MG_TEST_VALKEY_URL` or a spawned `valkey-server`)
    /// behind a [`FaultProxy`]. `None` = skipped (the fixture printed why).
    pub struct Valkey {
        /// The server itself (admin connections).
        pub url: String,
        /// Random per test; use it in keys and limiter ids so parallel runs
        /// on a shared server never collide.
        pub tag: String,
        proxy: Option<Arc<FaultProxy>>,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<JoinHandle<()>>,
    }

    impl std::fmt::Debug for Valkey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Valkey").field("tag", &self.tag).finish()
        }
    }

    impl Valkey {
        pub fn start() -> Option<Self> {
            let (tx, rx) = std::sync::mpsc::channel();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let Some(fixture) = ValkeyFixture::start().await else {
                        let _ = tx.send(None);
                        return;
                    };
                    let proxy = Arc::new(FaultProxy::start(fixture.url()).await.unwrap());
                    let _ = tx.send(Some((
                        fixture.url().to_owned(),
                        fixture.site().to_owned(),
                        Arc::clone(&proxy),
                    )));
                    let _ = stopped.await;
                    drop(proxy);
                    drop(fixture);
                });
            });
            match rx.recv().ok().flatten() {
                Some((url, tag, proxy)) => Some(Self {
                    url,
                    tag,
                    proxy: Some(proxy),
                    stop: Some(stop),
                    thread: Some(thread),
                }),
                None => {
                    // The fixture runs on its own thread: re-raise its panic
                    // (MG_REQUIRE_VALKEY=1 without a server, or a proxy that
                    // cannot bind), or the test would pass as skipped.
                    if let Err(panic) = thread.join() {
                        std::panic::resume_unwind(panic);
                    }
                    None
                }
            }
        }

        fn proxy(&self) -> &FaultProxy {
            self.proxy.as_ref().unwrap()
        }

        /// `redis://127.0.0.1:<port>/` of the fault proxy (what the Edge uses).
        pub fn proxy_url(&self) -> String {
            self.proxy().url()
        }

        pub fn set_mode(&self, mode: FaultMode) {
            self.proxy().set_mode(mode);
        }

        pub fn round_trips(&self) -> u64 {
            self.proxy().round_trips()
        }

        /// A blocking admin connection to the server (not through the proxy).
        pub fn admin(&self) -> redis::Connection {
            redis::Client::open(self.url.as_str())
                .unwrap()
                .get_connection()
                .unwrap()
        }
    }

    impl Drop for Valkey {
        fn drop(&mut self) {
            self.proxy = None;
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}

/// A `testdata/phase1/artifacts/` file as a bundle `ArtifactRef` named
/// `name`, with its bytes.
pub fn testdata_artifact(name: &str, file: &str) -> (mg_proto::v1::ArtifactRef, Vec<u8>) {
    let bytes = std::fs::read(repo("testdata/phase1/artifacts").join(file)).unwrap();
    let sha = sha256_hex(&bytes);
    (
        mg_proto::v1::ArtifactRef {
            name: name.into(),
            uri: format!("artifacts/{sha}"),
            sha256: sha,
            version: String::new(),
            size: bytes.len() as u64,
        },
        bytes,
    )
}

/// The debug line of a request: forwarded ones are found through the
/// origin (`path`), answered ones through the request id in the body.
pub fn line_of(env: &TestEnv, edge: &Edge, r: &Response, path: &str) -> String {
    if r.status == 200 {
        origin_log(env, edge, path)
    } else {
        answered_log(edge, &r.body)
    }
}

/// `config` (from [`TestEnv::config`]) in Valkey mode against `url` (no
/// password), with a request-path timeout generous enough for a loaded test
/// machine.
pub fn with_valkey(config: &str, url: &str, timeout_ms: u64) -> String {
    let local = "[valkey]\nmode = \"local\"\n";
    assert!(config.contains(local));
    config.replace(
        local,
        &format!("[valkey]\nmode = \"valkey\"\nurl = \"{url}\"\ntimeout_ms = {timeout_ms}\nconnect_timeout_ms = 1000\n"),
    )
}

/// `K_pseudo` of the test credentials (`testdata/phase1/keys/pseudo.key.json`).
pub fn test_k_pseudo() -> [u8; 32] {
    let json = std::fs::read(repo("testdata/phase1/keys/pseudo.key.json")).unwrap();
    *mg_edge::creds::PseudoKey::parse(&json).unwrap().key()
}

/// `config` (from [`TestEnv::config`]) with an `[events]` table holding
/// `lines` (each a complete `key = value` line).
pub fn with_events(config: &str, lines: &str) -> String {
    let sdk = "\n[sdk]\n";
    assert!(config.contains(sdk));
    config.replacen(sdk, &format!("\n[events]\n{lines}\n[sdk]\n"), 1)
}

/// The request id in an Edge answer's body (JSON or HTML).
pub fn request_id_of(body: &str) -> Option<String> {
    body.split(['"', '<', '>'])
        .find(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// The challenge page and a solved submission (WP-E1c flow, reused by E1d).

pub mod challenge {
    use mg_core::ChallengeType;
    use serde_json::{Value, json};

    pub const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                              (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

    /// Headers of a Chrome navigation from `ip`.
    pub fn browser(ip: &str) -> String {
        format!(
            "{}User-Agent: {CHROME}\r\nAccept: text/html,application/xhtml+xml\r\n\
             Accept-Language: zh-CN,zh;q=0.9\r\nSec-Fetch-Mode: navigate\r\n\
             Sec-CH-UA: \"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\"\r\n",
            super::cf(ip)
        )
    }

    /// A challenge as the page shows it.
    #[derive(Debug, Clone)]
    pub struct Shown {
        pub c: String,
        pub ty: ChallengeType,
        pub bits: u32,
        pub ret: String,
    }

    fn attr(html: &str, name: &str) -> String {
        html.split(&format!("{name}=\""))
            .nth(1)
            .and_then(|t| t.split('"').next())
            .unwrap_or_else(|| panic!("no {name} in {html}"))
            .to_owned()
    }

    pub fn from_page(html: &str) -> Shown {
        Shown {
            c: attr(html, "data-mg-c"),
            ty: match attr(html, "data-mg-type").as_str() {
                "invisible" => ChallengeType::Invisible,
                _ => ChallengeType::Pow,
            },
            bits: attr(html, "data-mg-pow-bits").parse().unwrap(),
            ret: attr(html, "data-mg-ret").replace("&amp;", "&"),
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    /// The SDK's submission JSON for `s`, solved with the test-only
    /// reference solver.
    pub fn solved(s: &Shown, ua: &str) -> Value {
        let counter = mg_challenge::pow_solve(&s.c, s.bits, 1 << 24).expect("solvable");
        json!({"v": 1, "type": s.ty.as_str(), "c": s.c, "pow": {"counters": [counter]},
               "ret": s.ret, "ts": now_ms(), "build": "1df90640e0c5fec4",
               "env": {"v": 1, "ua": {"userAgent": ua, "brands": null, "mobile": false, "platform": "macOS"},
                       "languages": ["zh-CN"], "timeZone": "Asia/Shanghai", "graphics": null},
               "auto": {"v": 1, "webdriver": false}})
    }

    /// `mg=<json>` as the browser's form serializer writes it.
    pub fn form_body(json: &Value) -> Vec<u8> {
        let mut out = b"mg=".to_vec();
        for b in json.to_string().bytes() {
            match b {
                b' ' => out.push(b'+'),
                b'*' | b'-' | b'.' | b'_' => out.push(b),
                b if b.is_ascii_alphanumeric() => out.push(b),
                b => out.extend(format!("%{b:02X}").bytes()),
            }
        }
        out
    }

    /// The form navigation submitting `v` from `ip` to `addr`.
    pub fn submit_form(
        addr: std::net::SocketAddr,
        ip: &str,
        v: &Value,
        extra: &str,
    ) -> super::Response {
        let body = form_body(v);
        let mut req = format!(
            "POST /__mg/c HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\
             Content-Length: {}\r\n{}User-Agent: {CHROME}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nSec-Fetch-Mode: navigate\r\n\
             Accept-Language: zh-CN\r\n{extra}\r\n",
            body.len(),
            super::cf(ip)
        )
        .into_bytes();
        req.extend_from_slice(&body);
        super::raw(addr, &req).expect("POST /__mg/c")
    }

    /// The `name=value` of the response's `Set-Cookie`.
    pub fn cookie_of(r: &super::Response) -> String {
        r.header("set-cookie")
            .expect("Set-Cookie")
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }
}
