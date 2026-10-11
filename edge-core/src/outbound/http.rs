//! [`OutboundClient`]: the Edge's only [`OutboundHttp`] implementation
//! (spec §8.4).
//!
//! * one reqwest client, built once on the background-service runtime that
//!   uses it: `no_proxy()` (reqwest would otherwise honour `HTTP_PROXY` /
//!   `HTTPS_PROXY` / `ALL_PROXY`), rustls, User-Agent [`USER_AGENT`], connect
//!   timeout 2 s, at most 8 idle connections per host, no redirects, no
//!   `Referer`;
//! * an exact-URL allowlist: any other destination is
//!   [`OutboundError::Denied`] and never reaches the network;
//! * a process-wide concurrency cap of [`MAX_CONCURRENT_REQUESTS`]: a request
//!   that finds no free slot fails at once with [`SendError::Busy`] instead of
//!   queueing (the caller maps it to `Unavailable` without counting it in the
//!   circuit breaker, §8.6);
//! * bounded request ([`MAX_REQUEST_BYTES`]) and response
//!   ([`MAX_RESPONSE_BYTES`]) bodies, and a per-request timeout capped at
//!   [`MAX_TIMEOUT_MS`].

use super::url::SiteverifyUrl;
use mg_core::challenge::{
    BoxFuture, HttpMethod, OutboundError, OutboundHttp, OutboundRequest, OutboundResponse,
};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// User-Agent of every outbound request (spec §8.4).
pub const USER_AGENT: &str = "morphgate-dev-tooling";
/// Process-wide limit on concurrent outbound requests (spec §8.4).
pub const MAX_CONCURRENT_REQUESTS: usize = 32;
/// TCP / TLS connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Idle connections kept per host.
pub const MAX_IDLE_PER_HOST: usize = 8;
/// Ceiling on [`OutboundRequest::timeout_ms`].
pub const MAX_TIMEOUT_MS: u32 = 5_000;
/// Largest request body sent.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Largest response body read; a longer one is [`SendError::ResponseTooLarge`].
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Why [`OutboundClient::send_checked`] produced no response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// All [`MAX_CONCURRENT_REQUESTS`] slots were in use; nothing was sent.
    #[error("outbound concurrency limit reached")]
    Busy,
    /// The destination is not on the allowlist; nothing was sent.
    #[error("outbound destination not allowed: {0}")]
    Denied(String),
    /// The request body exceeds [`MAX_REQUEST_BYTES`]; nothing was sent.
    #[error("outbound request body too large")]
    RequestTooLarge,
    /// The per-request timeout elapsed.
    #[error("outbound request timed out")]
    Timeout,
    /// Connection, TLS or protocol error.
    #[error("outbound transport error: {0}")]
    Transport(String),
    /// The response body exceeds [`MAX_RESPONSE_BYTES`].
    #[error("outbound response body too large")]
    ResponseTooLarge,
}

impl From<SendError> for OutboundError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::Denied(url) => Self::Denied(url),
            SendError::Timeout => Self::Timeout,
            other => Self::Transport(other.to_string()),
        }
    }
}

/// Error building the HTTP client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("outbound client: {0}")]
pub struct BuildError(String);

/// The Edge's outbound HTTP client (see the module docs).
pub struct OutboundClient {
    client: reqwest::Client,
    allowed: Vec<String>,
    permits: Arc<Semaphore>,
}

impl fmt::Debug for OutboundClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundClient")
            .field("allowed", &self.allowed)
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl OutboundClient {
    /// Builds the client; only the `allowed` URLs (exact match) can be
    /// reached. Call it on the runtime that will use the client.
    pub fn new(allowed: &[SiteverifyUrl]) -> Result<Self, BuildError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .pool_max_idle_per_host(MAX_IDLE_PER_HOST)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .build()
            .map_err(|e| BuildError(error_chain(&e)))?;
        Ok(Self {
            client,
            allowed: allowed.iter().map(|u| u.as_str().to_owned()).collect(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        })
    }

    /// Requests currently holding a concurrency slot.
    pub fn in_flight(&self) -> usize {
        MAX_CONCURRENT_REQUESTS - self.permits.available_permits()
    }

    /// Whether `url` is on the allowlist.
    pub fn allows(&self, url: &str) -> bool {
        self.allowed.iter().any(|a| a == url)
    }

    /// Sends `req` with the detailed error of [`SendError`] (the
    /// [`OutboundHttp`] impl folds it into [`OutboundError`]).
    pub async fn send_checked(&self, req: OutboundRequest) -> Result<OutboundResponse, SendError> {
        if !self.allows(&req.url) {
            return Err(SendError::Denied(req.url));
        }
        if req.body.len() > MAX_REQUEST_BYTES {
            return Err(SendError::RequestTooLarge);
        }
        let Ok(_permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Err(SendError::Busy);
        };
        let timeout_ms = req.timeout_ms.min(MAX_TIMEOUT_MS);
        if timeout_ms == 0 {
            return Err(SendError::Timeout);
        }
        let timeout = Duration::from_millis(u64::from(timeout_ms));
        match tokio::time::timeout(timeout, self.exchange(req, timeout)).await {
            Ok(result) => result,
            Err(_) => Err(SendError::Timeout),
        }
    }

    async fn exchange(
        &self,
        req: OutboundRequest,
        timeout: Duration,
    ) -> Result<OutboundResponse, SendError> {
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &req.url).timeout(timeout);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut response = builder.body(req.body).send().await.map_err(map_reqwest)?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(SendError::ResponseTooLarge);
        }
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(SendError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(OutboundResponse {
            status,
            headers,
            body,
        })
    }
}

impl OutboundHttp for OutboundClient {
    fn send(&self, req: OutboundRequest) -> BoxFuture<'_, Result<OutboundResponse, OutboundError>> {
        Box::pin(async move { self.send_checked(req).await.map_err(OutboundError::from) })
    }
}

fn map_reqwest(e: reqwest::Error) -> SendError {
    if e.is_timeout() {
        SendError::Timeout
    } else {
        SendError::Transport(error_chain(&e))
    }
}

/// `e` and its sources, joined by ": " (no request or response content).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}
