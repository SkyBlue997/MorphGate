//! Fake VictoriaLogs `/insert/jsonline` endpoint that records query
//! parameters, headers and lines, and can fail on demand (WP-C4); plus a
//! recording [`StreamWriter`] standing in for `StateHandle::xadd_batch`.
//!
//! Loopback only: the server binds `127.0.0.1:0`. It runs on its own thread
//! with its own current-thread runtime, so it works from synchronous tests,
//! from `#[tokio::test]` and next to a Pingora server alike, and it stops when
//! the [`FakeVl`] is dropped.

use crate::events::{StreamEntry, StreamWriter};
use mg_core::BoxFuture;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Largest request head accepted.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest request body accepted.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Poll step of the `wait_for_*` helpers.
const POLL: Duration = Duration::from_millis(5);

/// How the fake answers one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlReply {
    /// Respond with this status and an empty body.
    Status(u16),
    /// Read the request, never respond (until the client gives up).
    Hang,
    /// Read the request, then close the connection without a response.
    Close,
}

/// One request as received.
#[derive(Debug, Clone)]
pub struct VlRequest {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// Raw query string (no decoding), if any.
    pub query: Option<String>,
    /// Header names lower-cased, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The reply the fake gave (or withheld).
    pub reply: VlReply,
    /// When the request was complete.
    pub received_at: Instant,
}

impl VlRequest {
    /// First value of header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// Raw `name=value` pairs of the query string, in order.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.query
            .as_deref()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_owned(), v.to_owned()),
                None => (p.to_owned(), String::new()),
            })
            .collect()
    }

    /// Body lines (`\n`-separated; the empty piece after a final `\n` is
    /// not a line).
    pub fn lines(&self) -> Vec<String> {
        let text = String::from_utf8_lossy(&self.body);
        let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        lines
    }

    /// The fake answered 2xx.
    pub fn accepted(&self) -> bool {
        matches!(self.reply, VlReply::Status(200..=299))
    }
}

struct State {
    requests: Vec<VlRequest>,
    script: VecDeque<VlReply>,
    default: VlReply,
}

/// Fake VictoriaLogs server (spec §13.1 wire format; §16 test strategy).
pub struct FakeVl {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for FakeVl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeVl")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl FakeVl {
    /// Starts the server on `127.0.0.1:0`; every request is answered `200`
    /// unless replies are scripted.
    pub fn start() -> io::Result<Self> {
        let listener = StdTcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            requests: Vec::new(),
            script: VecDeque::new(),
            default: VlReply::Status(200),
        }));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stop, stopped) = oneshot::channel::<()>();
        let shared = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name("fake-vl".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(listener) else {
                        return;
                    };
                    let accept = async {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _)) => {
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
                // Dropping the runtime cancels the connection tasks.
            })?;
        Ok(Self {
            addr,
            state,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Base URL for `vl_main` / `vl_short` (`http://127.0.0.1:<port>`).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Queues replies for the next requests, in order; afterwards the default
    /// reply applies again.
    pub fn push_replies(&self, replies: impl IntoIterator<Item = VlReply>) {
        lock(&self.state).script.extend(replies);
    }

    /// Reply used when no scripted reply is queued.
    pub fn set_default_reply(&self, reply: VlReply) {
        lock(&self.state).default = reply;
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<VlRequest> {
        lock(&self.state).requests.clone()
    }

    /// Lines of every request answered 2xx, in arrival order.
    pub fn accepted_lines(&self) -> Vec<String> {
        lock(&self.state)
            .requests
            .iter()
            .filter(|r| r.accepted())
            .flat_map(VlRequest::lines)
            .collect()
    }

    /// Waits until at least `n` requests arrived or `timeout` passed; returns
    /// what arrived.
    pub async fn wait_for_requests(&self, n: usize, timeout: Duration) -> Vec<VlRequest> {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = self.requests();
            if requests.len() >= n || Instant::now() >= deadline {
                return requests;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Waits until at least `n` lines were accepted or `timeout` passed.
    pub async fn wait_for_accepted_lines(&self, n: usize, timeout: Duration) -> Vec<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let lines = self.accepted_lines();
            if lines.len() >= n || Instant::now() >= deadline {
                return lines;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Blocking form of [`FakeVl::wait_for_requests`] for synchronous tests.
    pub fn wait_for_requests_blocking(&self, n: usize, timeout: Duration) -> Vec<VlRequest> {
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

impl Drop for FakeVl {
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

struct Parsed {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

/// Serves one connection (keep-alive) until the client closes it.
async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let mut buf = Vec::new();
    while let Some(request) = read_request(&mut stream, &mut buf).await {
        let (path, query) = match request.target.split_once('?') {
            Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
            None => (request.target.clone(), None),
        };
        let reply = {
            let mut s = lock(&state);
            let reply = s.script.pop_front().unwrap_or(s.default);
            s.requests.push(VlRequest {
                method: request.method,
                path,
                query,
                headers: request.headers,
                body: request.body,
                reply,
                received_at: Instant::now(),
            });
            reply
        };
        match reply {
            VlReply::Status(code) => {
                let head = format!(
                    "HTTP/1.1 {code} {}\r\ncontent-length: 0\r\n\r\n",
                    reason(code)
                );
                if stream.write_all(head.as_bytes()).await.is_err() || request.close {
                    return;
                }
            }
            VlReply::Close => return,
            VlReply::Hang => {
                // Hold the connection until the client gives up.
                let mut sink = [0u8; 1024];
                while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                return;
            }
        }
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Reads more bytes into `buf`; `None` on EOF or error.
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

/// Takes one CRLF-terminated line from `buf`, reading as needed.
async fn read_line(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = find(buf, b"\r\n") {
            let line = String::from_utf8(buf[..end].to_vec()).ok()?;
            buf.drain(..end + 2);
            return Some(line);
        }
        if buf.len() > MAX_HEAD_BYTES {
            return None;
        }
        fill(stream, buf).await?;
    }
}

/// Takes exactly `len` bytes from `buf`, reading as needed.
async fn read_exact(stream: &mut TcpStream, buf: &mut Vec<u8>, len: usize) -> Option<Vec<u8>> {
    while buf.len() < len {
        fill(stream, buf).await?;
    }
    Some(buf.drain(..len).collect())
}

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
    let target = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let chunked = header(&headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        let mut body = Vec::new();
        loop {
            let size_line = read_line(stream, buf).await?;
            let size_hex = size_line.split(';').next()?.trim();
            let size = usize::from_str_radix(size_hex, 16).ok()?;
            if size == 0 {
                // Trailer section ends with an empty line.
                while !read_line(stream, buf).await?.is_empty() {}
                break;
            }
            if body.len() + size > MAX_BODY_BYTES {
                return None;
            }
            body.extend(read_exact(stream, buf, size).await?);
            read_exact(stream, buf, 2).await?;
        }
        body
    } else {
        let len = match header(&headers, "content-length") {
            Some(v) => v.parse::<usize>().ok()?,
            None => 0,
        };
        if len > MAX_BODY_BYTES {
            return None;
        }
        read_exact(stream, buf, len).await?
    };
    let close = header(&headers, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    Some(Parsed {
        method,
        target,
        headers,
        body,
        close,
    })
}

/// [`StreamWriter`] that records every batch (or fails on demand), for
/// flusher tests; mg-edge's own tests use the real `StateHandle`.
#[derive(Debug, Default)]
pub struct RecordingStreamWriter {
    inner: Mutex<Recorded>,
}

#[derive(Debug, Default)]
struct Recorded {
    batches: Vec<(u64, Vec<StreamEntry>)>,
    fail: bool,
    calls: u64,
}

impl RecordingStreamWriter {
    /// A writer that accepts everything.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Makes every following call fail (`true`) or succeed (`false`).
    pub fn set_fail(&self, fail: bool) {
        lock(&self.inner).fail = fail;
    }

    /// Accepted batches as `(maxlen, entries)`.
    pub fn batches(&self) -> Vec<(u64, Vec<StreamEntry>)> {
        lock(&self.inner).batches.clone()
    }

    /// Accepted entries, flattened in order.
    pub fn entries(&self) -> Vec<StreamEntry> {
        lock(&self.inner)
            .batches
            .iter()
            .flat_map(|(_, entries)| entries.iter().cloned())
            .collect()
    }

    /// Number of `xadd_batch` calls, failed ones included.
    pub fn calls(&self) -> u64 {
        lock(&self.inner).calls
    }
}

impl StreamWriter for RecordingStreamWriter {
    fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let mut inner = lock(&self.inner);
            inner.calls += 1;
            if inner.fail {
                return Err("injected failure".to_owned());
            }
            inner.batches.push((maxlen, entries));
            Ok(())
        })
    }
}
