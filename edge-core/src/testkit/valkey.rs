//! Valkey fixture (`MG_TEST_VALKEY_URL`, or a spawned `valkey-server` on a
//! unix socket) and the fault-injecting TCP forwarder that also counts round
//! trips (WP-C3, spec §16). Loopback / unix sockets only.
//!
//! - [`ValkeyFixture::start`]: with `MG_TEST_VALKEY_URL`, uses that server
//!   (keys are prefixed by a random site id; nothing is ever flushed).
//!   Otherwise spawns `valkey-server` (or `redis-server`) from `PATH`,
//!   listening only on a private unix socket, and kills it on drop. Without
//!   either it prints `SKIPPED: …` and returns `None`, unless
//!   `MG_REQUIRE_VALKEY=1`, which turns the skip into a test failure.
//! - [`FaultProxy`]: a `127.0.0.1:0` TCP listener forwarding to the fixture,
//!   whose [`FaultMode`] can refuse, blackhole or reset connections, and
//!   which can add a one-way latency ([`FaultProxy::set_latency`]). It
//!   counts round trips as "client→server bursts answered by server→client
//!   bursts", per connection, so tests assert how many round trips an
//!   operation needs without `MONITOR`.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::watch;
use tokio::time::Instant;

const SKIP_NO_SERVER: &str = "no valkey-server (set MG_TEST_VALKEY_URL or install valkey)";

/// A Valkey server for one test.
pub struct ValkeyFixture {
    url: String,
    site: String,
    child: Option<Child>,
    dir: Option<PathBuf>,
}

impl fmt::Debug for ValkeyFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValkeyFixture")
            .field("site", &self.site)
            .field("spawned", &self.child.is_some())
            .finish_non_exhaustive()
    }
}

impl ValkeyFixture {
    /// See the module documentation. `None` = skipped (message printed).
    pub async fn start() -> Option<Self> {
        let site = format!("t{}", random_hex(8));
        if let Ok(url) = std::env::var("MG_TEST_VALKEY_URL")
            && !url.trim().is_empty()
        {
            return Some(Self {
                url: url.trim().to_owned(),
                site,
                child: None,
                dir: None,
            });
        }
        let Some(bin) = ["valkey-server", "redis-server"]
            .iter()
            .find_map(|b| find_in_path(b))
        else {
            return skip(SKIP_NO_SERVER);
        };
        let dir = match temp_dir() {
            Ok(d) => d,
            Err(e) => return skip(&format!("cannot create a temporary directory: {e}")),
        };
        let sock = dir.join("v.sock");
        let spawned = Command::new(&bin)
            .args(["--port", "0", "--unixsocket"])
            .arg(&sock)
            .args([
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
            ])
            .arg(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let child = match spawned {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return skip(&format!("cannot spawn {}: {e}", bin.display()));
            }
        };
        let fixture = Self {
            url: format!("unix://{}", sock.display()),
            site,
            child: Some(child),
            dir: Some(dir),
        };
        for _ in 0..200 {
            if ping_unix(&sock).await {
                return Some(fixture);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        drop(fixture);
        skip("valkey-server did not become ready within 5 s")
    }

    /// `unix:///…/v.sock` for a spawned server, else `MG_TEST_VALKEY_URL`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Random site id for this test's keys (`t<16 hex>`).
    pub fn site(&self) -> &str {
        &self.site
    }
}

impl Drop for ValkeyFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn skip<T>(why: &str) -> Option<T> {
    if std::env::var("MG_REQUIRE_VALKEY").as_deref() == Ok("1") {
        panic!("MG_REQUIRE_VALKEY=1 but {why}");
    }
    eprintln!("SKIPPED: {why}");
    None
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::fill(&mut buf).is_err() {
        // Test-only fallback: uniqueness, not secrecy, matters here.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            ^ u128::from(std::process::id());
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (seed >> ((i % 16) * 8)) as u8;
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A private directory for the socket; short enough for `sun_path`.
fn temp_dir() -> std::io::Result<PathBuf> {
    let name = format!("mgvk-{}", random_hex(6));
    let mut base = std::env::temp_dir();
    if base.join(&name).join("v.sock").as_os_str().len() > 100 {
        base = PathBuf::from("/tmp");
    }
    let dir = base.join(name);
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

async fn ping_unix(sock: &Path) -> bool {
    let Ok(mut s) = UnixStream::connect(sock).await else {
        return false;
    };
    if s.write_all(b"PING\r\n").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 7];
    matches!(
        tokio::time::timeout(Duration::from_secs(1), s.read_exact(&mut buf)).await,
        Ok(Ok(_)) if &buf == b"+PONG\r\n"
    )
}

/// Behaviour of a [`FaultProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    /// Forward everything.
    Pass,
    /// Server down: existing connections are closed, new ones are closed
    /// right after accept.
    Refuse,
    /// Network partition: nothing is forwarded in either direction (bytes are
    /// held, not dropped, as TCP would); returning to `Pass` resumes.
    Blackhole,
    /// Closes every existing connection once; new connections pass.
    ResetExisting,
}

/// Where a [`FaultProxy`] forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultTarget {
    Tcp(String),
    Unix(PathBuf),
}

impl FaultTarget {
    /// Accepts `unix:///path`, `redis+unix:///path`, `valkey+unix:///path`,
    /// `/path`, `redis://[user@]host[:port][/db]` (default port 6379),
    /// `valkey://…` and `host:port`.
    pub fn parse(target: &str) -> Option<Self> {
        let t = target.trim();
        for scheme in ["unix://", "redis+unix://", "valkey+unix://"] {
            if let Some(rest) = t.strip_prefix(scheme) {
                let path = rest.split(['?', '#']).next().unwrap_or("");
                return path
                    .starts_with('/')
                    .then(|| Self::Unix(PathBuf::from(path)));
            }
        }
        if t.starts_with('/') {
            return Some(Self::Unix(PathBuf::from(t)));
        }
        let hostport = match ["redis://", "valkey://"]
            .iter()
            .find_map(|s| t.strip_prefix(s))
        {
            Some(rest) => {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                let hostport = authority.rsplit('@').next().unwrap_or("");
                if hostport.is_empty() {
                    return None;
                }
                if has_port(hostport) {
                    hostport.to_owned()
                } else {
                    format!("{hostport}:6379")
                }
            }
            None if has_port(t) => t.to_owned(),
            None => return None,
        };
        (!hostport.contains(char::is_whitespace)).then_some(Self::Tcp(hostport))
    }
}

fn has_port(hostport: &str) -> bool {
    let port = match hostport.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && (!host.contains(':') || host.ends_with(']')) => {
            port
        }
        _ => return false,
    };
    !port.is_empty() && port.parse::<u16>().is_ok()
}

const DIR_NONE: u8 = 0;
const DIR_C2S: u8 = 1;
const DIR_S2C: u8 = 2;

struct ProxyShared {
    target: FaultTarget,
    mode: watch::Sender<FaultMode>,
    /// Bumped to close every existing connection.
    kills: watch::Sender<u64>,
    /// Added to every chunk in each direction (0 = none).
    latency_us: AtomicU64,
    round_trips: AtomicU64,
}

/// Fault-injecting forwarder on `127.0.0.1:0` (spec §16).
pub struct FaultProxy {
    addr: SocketAddr,
    shared: Arc<ProxyShared>,
    accept: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for FaultProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FaultProxy")
            .field("addr", &self.addr)
            .field("mode", &*self.shared.mode.borrow())
            .field("round_trips", &self.round_trips())
            .finish()
    }
}

impl FaultProxy {
    /// Starts forwarding to `target` (see [`FaultTarget::parse`]), e.g.
    /// [`ValkeyFixture::url`].
    pub async fn start(target: &str) -> std::io::Result<Self> {
        let target = FaultTarget::parse(target).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported fault proxy target",
            )
        })?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(ProxyShared {
            target,
            mode: watch::channel(FaultMode::Pass).0,
            kills: watch::channel(0).0,
            latency_us: AtomicU64::new(0),
            round_trips: AtomicU64::new(0),
        });
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&shared)));
        Ok(Self {
            addr,
            shared,
            accept,
        })
    }

    /// `redis://127.0.0.1:<port>/`.
    pub fn url(&self) -> String {
        format!("redis://{}/", self.addr)
    }

    pub fn set_mode(&self, mode: FaultMode) {
        if matches!(mode, FaultMode::Refuse | FaultMode::ResetExisting) {
            self.shared.kills.send_modify(|k| *k += 1);
        }
        self.shared.mode.send_replace(mode);
    }

    /// Delays every forwarded chunk by `latency` in each direction (a slow
    /// link: a round trip costs about twice `latency`); `Duration::ZERO`
    /// turns it off. Order is preserved.
    pub fn set_latency(&self, latency: Duration) {
        let us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.shared.latency_us.store(us, Ordering::Release);
    }

    /// Client→server bursts answered by a server→client burst, summed over
    /// all connections.
    pub fn round_trips(&self) -> u64 {
        self.shared.round_trips.load(Ordering::Acquire)
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.accept.abort();
        self.shared.kills.send_modify(|k| *k += 1);
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<ProxyShared>) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            // E.g. out of file descriptors: back off instead of spinning.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        if *shared.mode.borrow() == FaultMode::Refuse {
            drop(client);
            continue;
        }
        tokio::spawn(serve(client, Arc::clone(&shared)));
    }
}

async fn serve(client: TcpStream, shared: Arc<ProxyShared>) {
    let mut kills = shared.kills.subscribe();
    kills.borrow_and_update();
    let _ = client.set_nodelay(true);
    let (cr, cw) = client.into_split();
    let dir = Arc::new(AtomicU8::new(DIR_NONE));
    match &shared.target {
        FaultTarget::Tcp(addr) => {
            let Ok(server) = TcpStream::connect(addr.as_str()).await else {
                return;
            };
            let _ = server.set_nodelay(true);
            let (sr, sw) = server.into_split();
            forward(cr, cw, sr, sw, &shared, dir, kills).await;
        }
        FaultTarget::Unix(path) => {
            let Ok(server) = UnixStream::connect(path).await else {
                return;
            };
            let (sr, sw) = server.into_split();
            forward(cr, cw, sr, sw, &shared, dir, kills).await;
        }
    }
}

async fn forward<CR, CW, SR, SW>(
    cr: CR,
    cw: CW,
    sr: SR,
    sw: SW,
    shared: &Arc<ProxyShared>,
    dir: Arc<AtomicU8>,
    mut kills: watch::Receiver<u64>,
) where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    SR: AsyncRead + Unpin,
    SW: AsyncWrite + Unpin,
{
    let c2s = pump(cr, sw, DIR_C2S, shared, Arc::clone(&dir));
    let s2c = pump(sr, cw, DIR_S2C, shared, dir);
    // Either direction ending, or a kill, closes both sockets (on drop).
    tokio::select! {
        () = c2s => {}
        () = s2c => {}
        _ = kills.changed() => {}
    }
}

async fn pump<R, W>(
    mut from: R,
    mut to: W,
    direction: u8,
    shared: &Arc<ProxyShared>,
    dir: Arc<AtomicU8>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // The reader timestamps chunks as they arrive, so that the writer can
    // delay each one by the latency without delaying the next one further
    // (a constant-latency link, not a queue of sleeps).
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let reader = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if tx.send((Instant::now(), buf[..n].to_vec())).is_err() {
                return;
            }
        }
    };
    let writer = async {
        let mut mode = shared.mode.subscribe();
        while let Some((arrived, bytes)) = rx.recv().await {
            // Blackhole: hold the bytes until the mode changes. Refuse: close
            // (also covers a connection accepted just before the switch,
            // which subscribed to `kills` after the bump).
            let refused = match mode.wait_for(|m| *m != FaultMode::Blackhole).await {
                Ok(m) => *m == FaultMode::Refuse,
                Err(_) => return,
            };
            if refused {
                return;
            }
            let latency = shared.latency_us.load(Ordering::Acquire);
            if latency > 0 {
                tokio::time::sleep_until(arrived + Duration::from_micros(latency)).await;
            }
            let previous = dir.swap(direction, Ordering::AcqRel);
            if direction == DIR_S2C && previous == DIR_C2S {
                shared.round_trips.fetch_add(1, Ordering::AcqRel);
            }
            if to.write_all(&bytes).await.is_err() || to.flush().await.is_err() {
                return;
            }
        }
    };
    // Ends when the source is closed and everything read was written, or
    // when the destination fails.
    tokio::select! {
        () = writer => {}
        () = async {
            reader.await;
            // `tx` is gone: the writer drains what is left, then ends.
            std::future::pending::<()>().await
        } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        let unix = |p: &str| Some(FaultTarget::Unix(PathBuf::from(p)));
        let tcp = |a: &str| Some(FaultTarget::Tcp(a.to_owned()));
        assert_eq!(
            FaultTarget::parse("unix:///tmp/x/v.sock"),
            unix("/tmp/x/v.sock")
        );
        assert_eq!(
            FaultTarget::parse("redis+unix:///tmp/v.sock?db=1"),
            unix("/tmp/v.sock")
        );
        assert_eq!(FaultTarget::parse("/tmp/v.sock"), unix("/tmp/v.sock"));
        assert_eq!(
            FaultTarget::parse("redis://127.0.0.1:6380/0"),
            tcp("127.0.0.1:6380")
        );
        assert_eq!(
            FaultTarget::parse("redis://edge@localhost/"),
            tcp("localhost:6379")
        );
        assert_eq!(FaultTarget::parse("redis://[::1]:7000"), tcp("[::1]:7000"));
        assert_eq!(FaultTarget::parse("redis://[::1]"), tcp("[::1]:6379"));
        assert_eq!(FaultTarget::parse("127.0.0.1:6379"), tcp("127.0.0.1:6379"));
        assert_eq!(FaultTarget::parse("unix://relative"), None);
        assert_eq!(FaultTarget::parse("redis://"), None);
        assert_eq!(FaultTarget::parse("localhost"), None);
        assert_eq!(FaultTarget::parse("http://x:1"), None);
    }
}
