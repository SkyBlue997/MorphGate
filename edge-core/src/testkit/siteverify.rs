//! Loopback mock of the Turnstile siteverify endpoint
//! (docs/impl/phase2-spec.md §8.4, D-52; WP-C6): programmable responses,
//! delays and disconnects per request, and a record of the requests
//! received. Every Turnstile test uses it; no test reaches
//! `challenges.cloudflare.com`.
//!
//! The server binds `127.0.0.1:0` (or `[::1]:0`) and runs on its own thread
//! with its own current-thread runtime, so it works from synchronous tests,
//! from `#[tokio::test]` and next to a Pingora server alike; it stops when
//! the [`FakeSiteverify`] is dropped.
//!
//! Each request gets the first queued reply ([`FakeSiteverify::push_replies`]),
//! else the responder's ([`FakeSiteverify::set_responder`]), else the default
//! reply, which fails closed (`invalid-input-response`).

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Path the mock's [`FakeSiteverify::url`] points at (any path is served).
pub const MOCK_PATH: &str = "/turnstile/v0/siteverify";

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);

/// What the mock does with one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvAction {
    /// Answer with this status, optional `Content-Type` and body.
    Respond {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    /// Close the connection without answering.
    Disconnect,
    /// Never answer; hold the connection until the client gives up.
    Hang,
}

/// One programmed reply: an action after a delay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvReply {
    pub delay: Duration,
    pub action: SvAction,
}

impl SvReply {
    /// `200`, `application/json`, `body`.
    pub fn json(body: impl Into<Vec<u8>>) -> Self {
        Self::raw(200, Some("application/json"), body)
    }

    /// Any status, content type and body.
    pub fn raw(status: u16, content_type: Option<&str>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            delay: Duration::ZERO,
            action: SvAction::Respond {
                status,
                content_type: content_type.map(str::to_owned),
                body: body.into(),
            },
        }
    }

    /// `200` `{"success": false, "error-codes": codes}`.
    pub fn error_codes(codes: &[&str]) -> Self {
        Self::json(serde_json::json!({"success": false, "error-codes": codes}).to_string())
    }

    /// `200` with a successful reply.
    pub fn success(hostname: &str, action: &str, cdata: &str, challenge_ts: &str) -> Self {
        Self::json(
            serde_json::json!({
                "success": true,
                "challenge_ts": challenge_ts,
                "hostname": hostname,
                "error-codes": [],
                "action": action,
                "cdata": cdata,
            })
            .to_string(),
        )
    }

    /// `status` with an empty `text/plain` body.
    pub fn status(status: u16) -> Self {
        Self::raw(status, Some("text/plain"), Vec::new())
    }

    /// Close the connection after reading the request.
    pub fn disconnect() -> Self {
        Self {
            delay: Duration::ZERO,
            action: SvAction::Disconnect,
        }
    }

    /// Never answer.
    pub fn hang() -> Self {
        Self {
            delay: Duration::ZERO,
            action: SvAction::Hang,
        }
    }

    /// The same reply after `delay`.
    #[must_use]
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// One request as received.
#[derive(Debug, Clone)]
pub struct SvRequest {
    pub method: String,
    pub path: String,
    /// Header names lower-cased, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The reply the mock gave (or withheld).
    pub reply: SvReply,
    pub received_at: Instant,
}

impl SvRequest {
    /// First value of header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as a JSON object, if it is one.
    pub fn json(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        match serde_json::from_slice(&self.body).ok()? {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        }
    }

    /// String member `name` of the JSON body.
    pub fn field(&self, name: &str) -> Option<String> {
        self.json()?.get(name)?.as_str().map(str::to_owned)
    }

    pub fn secret(&self) -> Option<String> {
        self.field("secret")
    }

    pub fn response(&self) -> Option<String> {
        self.field("response")
    }

    pub fn remoteip(&self) -> Option<String> {
        self.field("remoteip")
    }

    pub fn idempotency_key(&self) -> Option<String> {
        self.field("idempotency_key")
    }
}

type Responder = Arc<dyn Fn(&SvRequest) -> Option<SvReply> + Send + Sync>;

struct State {
    requests: Vec<SvRequest>,
    script: VecDeque<SvReply>,
    responder: Option<Responder>,
    default: SvReply,
}

/// Loopback mock siteverify server (see the module docs).
pub struct FakeSiteverify {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    connections: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for FakeSiteverify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSiteverify")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl FakeSiteverify {
    /// Starts the mock on `127.0.0.1:0`.
    pub fn start() -> io::Result<Self> {
        Self::bind(StdTcpListener::bind(("127.0.0.1", 0))?)
    }

    /// Starts the mock on `[::1]:0` (fails where IPv6 loopback is missing).
    pub fn start_ipv6() -> io::Result<Self> {
        Self::bind(StdTcpListener::bind(("::1", 0))?)
    }

    fn bind(listener: StdTcpListener) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            requests: Vec::new(),
            script: VecDeque::new(),
            responder: None,
            default: SvReply::error_codes(&["invalid-input-response"]),
        }));
        let connections = Arc::new(AtomicUsize::new(0));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stop, stopped) = oneshot::channel::<()>();
        let (shared, conns) = (Arc::clone(&state), Arc::clone(&connections));
        let thread = std::thread::Builder::new()
            .name("fake-siteverify".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(listener) else {
                        return;
                    };
                    let accept = async {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _)) => {
                                    conns.fetch_add(1, Ordering::Relaxed);
                                    tokio::spawn(serve(stream, Arc::clone(&shared)));
                                }
                                Err(_) => tokio::time::sleep(POLL).await,
                            }
                        }
                    };
                    tokio::select! {
                        _ = stopped => {}
                        () = accept => {}
                    }
                });
            })?;
        Ok(Self {
            addr,
            state,
            connections,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// `http://127.0.0.1:<port>/turnstile/v0/siteverify` (or `[::1]`).
    pub fn url(&self) -> String {
        format!("http://{}{MOCK_PATH}", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Queues replies for the next requests, in order.
    pub fn push_replies(&self, replies: impl IntoIterator<Item = SvReply>) {
        lock(&self.state).script.extend(replies);
    }

    /// Replies still queued.
    pub fn queued(&self) -> usize {
        lock(&self.state).script.len()
    }

    /// Drops the queued replies.
    pub fn clear_replies(&self) {
        lock(&self.state).script.clear();
    }

    /// Computes the reply from the request when nothing is queued; `None`
    /// falls back to the default reply.
    pub fn set_responder(&self, f: impl Fn(&SvRequest) -> Option<SvReply> + Send + Sync + 'static) {
        lock(&self.state).responder = Some(Arc::new(f));
    }

    /// Reply used when nothing is queued and the responder declines.
    pub fn set_default_reply(&self, reply: SvReply) {
        lock(&self.state).default = reply;
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<SvRequest> {
        lock(&self.state).requests.clone()
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Waits until at least `n` requests arrived or `timeout` passed.
    pub async fn wait_for_requests(&self, n: usize, timeout: Duration) -> Vec<SvRequest> {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = self.requests();
            if requests.len() >= n || Instant::now() >= deadline {
                return requests;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Blocking form of [`FakeSiteverify::wait_for_requests`].
    pub fn wait_for_requests_blocking(&self, n: usize, timeout: Duration) -> Vec<SvRequest> {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = self.requests();
            if requests.len() >= n || Instant::now() >= deadline {
                return requests;
            }
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for FakeSiteverify {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Parsed {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

/// Serves one keep-alive connection until the client closes it.
async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let mut buf = Vec::new();
    while let Some(request) = read_request(&mut stream, &mut buf).await {
        let mut record = SvRequest {
            method: request.method,
            path: request.path,
            headers: request.headers,
            body: request.body,
            reply: SvReply::hang(),
            received_at: Instant::now(),
        };
        let reply = {
            let (queued, responder, default) = {
                let mut s = lock(&state);
                (s.script.pop_front(), s.responder.clone(), s.default.clone())
            };
            queued
                .or_else(|| responder.and_then(|f| f(&record)))
                .unwrap_or(default)
        };
        record.reply = reply.clone();
        lock(&state).requests.push(record);
        if !reply.delay.is_zero() {
            tokio::time::sleep(reply.delay).await;
        }
        match reply.action {
            SvAction::Respond {
                status,
                content_type,
                body,
            } => {
                let mut head = format!(
                    "HTTP/1.1 {status} Status\r\ncontent-length: {}\r\n",
                    body.len()
                );
                if let Some(ct) = content_type {
                    head.push_str(&format!("content-type: {ct}\r\n"));
                }
                head.push_str("\r\n");
                let mut out = head.into_bytes();
                out.extend_from_slice(&body);
                if stream.write_all(&out).await.is_err() || request.close {
                    return;
                }
            }
            SvAction::Disconnect => return,
            SvAction::Hang => {
                let mut sink = [0u8; 1024];
                while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                return;
            }
        }
    }
}

async fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<()> {
    let mut chunk = [0u8; 16 * 1024];
    match stream.read(&mut chunk).await {
        Ok(0) | Err(_) => None,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Some(())
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads one request with a `Content-Length` body (what reqwest sends for a
/// buffered body); `None` on EOF, error or an unsupported request.
async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Parsed> {
    let head_end = loop {
        if let Some(end) = find(buf, b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return None;
        }
        fill(stream, buf).await?;
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).ok()?;
    buf.drain(..head_end + 4);
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let get = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    if get("transfer-encoding").is_some() {
        return None;
    }
    let len: usize = get("content-length").map_or(Some(0), |v| v.parse().ok())?;
    if len > MAX_BODY_BYTES {
        return None;
    }
    while buf.len() < len {
        fill(stream, buf).await?;
    }
    let body: Vec<u8> = buf.drain(..len).collect();
    let close = get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    Some(Parsed {
        method,
        path,
        headers,
        body,
        close,
    })
}
