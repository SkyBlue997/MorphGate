//! The Pingora `ProxyHttp` implementation.
//!
//! Request path through the filters, and where later phases plug in:
//!
//! ```text
//! request_filter
//!   1. classify path: /__mg/* is answered here (routes.rs)
//!   2. [Phase 1] upstream authentication + trusted client IP (UpstreamProfile)
//!   3. [Phase 1] build mg_core::RequestContext, run the Decision Core
//!   4. [Phase 1] enforce: challenge / block / rate-limit responses, dry-run
//! upstream_peer            -> the configured origin
//! upstream_request_filter  -> strip client-sent MG-* headers (headers.rs);
//!                             [Phase 1] add MG-Request-Id / MG-Bot-Score / ...
//! logging                  -> metrics; [Phase 1] DecisionEvent -> VictoriaLogs
//! ```
//!
//! Pingora types stay inside this crate; the Decision Core only ever sees
//! `mg_core` types.

use crate::config::{EdgeConfig, UpstreamProfile};
use crate::headers;
use crate::metrics::metrics;
use crate::routes::{self, RouteKind};
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{Method, RequestHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// TCP connect timeout toward the origin.
pub const ORIGIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The Edge proxy service.
#[derive(Debug, Clone)]
pub struct EdgeProxy {
    origin: SocketAddr,
    upstream_profile: UpstreamProfile,
}

impl EdgeProxy {
    pub fn new(cfg: &EdgeConfig) -> Self {
        Self {
            origin: cfg.origin,
            upstream_profile: cfg.upstream_profile,
        }
    }

    /// The upstream profile this listener runs with (consumed from Phase 1).
    pub fn upstream_profile(&self) -> UpstreamProfile {
        self.upstream_profile
    }
}

/// Per-request state shared across filter callbacks.
#[derive(Debug)]
pub struct EdgeCtx {
    route: RouteKind,
    started: Instant,
}

impl EdgeCtx {
    fn new() -> Self {
        Self {
            route: RouteKind::default(),
            started: Instant::now(),
        }
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = EdgeCtx;

    fn new_ctx(&self) -> Self::CTX {
        EdgeCtx::new()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        ctx.route = routes::classify(req.uri.path());
        let Some(local) = routes::local_response(ctx.route, &req.method) else {
            return Ok(false); // proxied to the origin
        };
        let head_only = req.method == Method::HEAD;
        let header = routes::response_header(&local)?;
        session
            .write_response_header(Box::new(header), head_only)
            .await?;
        if !head_only {
            session
                .write_response_body(Some(Bytes::from_static(local.body.as_bytes())), true)
                .await?;
        }
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Plain HTTP to the origin; Edge->origin mTLS is a later option (docs/02 §8).
        let mut peer = HttpPeer::new(self.origin, false, String::new());
        peer.options.connection_timeout = Some(ORIGIN_CONNECT_TIMEOUT);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let removed = headers::strip_edge_owned(upstream_request);
        if removed > 0 {
            log::debug!("stripped {removed} client-supplied MG-* header(s)");
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session.response_written().map(|r| r.status.as_u16());
        let elapsed = ctx.started.elapsed();
        metrics().observe_request(ctx.route, status, elapsed, e.is_some());
        log::debug!(
            "{} status={:?} elapsed_us={}",
            self.request_summary(session, ctx),
            status,
            elapsed.as_micros()
        );
    }

    /// Used by Pingora in its error logs as well. Pingora's default includes
    /// the query string, which can carry tokens or personal data; ours does not.
    fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
        let req = session.req_header();
        format!(
            "{} {} route={}",
            req.method,
            req.uri.path(),
            ctx.route.metric_label()
        )
    }
}
