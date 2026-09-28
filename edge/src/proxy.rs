//! The Pingora `ProxyHttp` implementation: the request pipeline skeleton of
//! docs/impl/phase1-spec.md §1.4 (WP-E1a).
//!
//! ```text
//! request_filter
//!   0  request_id (OS CSPRNG; failure -> 503)
//!   1  listener: loopback peer / origin mTLS (handshake) / x-mg-upstream-key -> 403
//!   2  protocol limits (§9.3.1), header hygiene and trusted-header parsing (§9.3)
//!   3  Host -> site (400 / 404); listener allowed (403); oversize: enforce rejects
//!      (414 / 431 / 400), monitor / bootstrap-open forward unevaluated (I-2);
//!      site state (503, /__mg/healthz still answered); foreign CF-Worker (403)
//!   4  /__mg/*: healthz, s/<file> (SDK), c (the challenge submission,
//!      crate::mg_endpoints), everything else reserved (404)
//!   5  environment by host, route over every path view (§9.4); none for an
//!      oversize request forwarded unevaluated (I-2)
//!   6-9  active sites (WP-E1b, crate::decide::evaluate): RequestContext,
//!      clearance, crawler (rDNS jobs to mg-rdns), one state round trip
//!      (verdicts + global limiters), the Decision Core
//!  10  execution (§9.9): monitor forwards and records; enforce answers
//!      BLOCK 403, RATE_LIMIT 429, CHALLENGE (crate::challenge: 403 page or
//!      JSON with a sealed C; 308 for an http visitor's GET / HEAD; 429
//!      without a client IP), 425 for Early-Data on critical routes, or
//!      forwards.
//!      bootstrap-open / lkg_invalid_open / oversize: forwarded unevaluated
//!      (rule_id bootstrap / lkg_invalid_open / hard.oversize_skipped)
//! upstream_peer            -> the site's origin
//! connected_to_upstream    -> origin connect time (new connections)
//! upstream_request_filter  -> origin-form target, Host, MG-* / XFF / CF-* (§9.9)
//! response_filter          -> strip MG-* / MG_* from the origin's response
//! logging                  -> metrics (§13.7), events (§9.11, crate::events), debug line
//! ```
//!
//! Every hook the Edge runs is timed into `EdgeCtx::timing` for
//! `mg_edge_added_latency_seconds` (crate::metrics::Timing).
//!
//! Pingora types stay inside this crate; the Decision Core only ever sees
//! `mg_core` types. Nothing here logs a client address, cookie or key.

use crate::challenge::{self, ChallengeAnswer, ChallengeRequest};
use crate::config::ListenerProfile;
use crate::context::{Facts, TlsInfo, http_version_str};
use crate::decide::{self, DecisionRecord, Enforcement, Services};
use crate::enforce::{EdgeResponse, is_navigation};
use crate::events::{self as ev, AccessDecision, AccessNet, Finished, Unevaluated};
use crate::headers::{
    self, CloudflareForward, DecisionHeaders, OriginHeaders, as_slices, distinct_after,
    family_names, raw_headers, single_value,
};
use crate::identity::{self, RdnsDispatcher};
use crate::listener::ListenerRuntime;
use crate::metrics::{Timing, metrics};
use crate::mg_endpoints::{self, BodyReadError, BodySource, SubmitRecord};
use crate::rng::{self, OsRng};
use crate::routes::{self, RouteKind};
use crate::sdk::SdkDir;
use crate::sites::{
    BundleRuntime, RouteRuntime, Serving, Site, SiteRuntime, Sites, default_events, select_route,
};
use crate::tls::TlsFacts;
use async_trait::async_trait;
use bytes::Bytes;
use mg_core::{Action, Channel, RouteInfo, RouteSensitivity};
use mg_edge_core::events::{ACCESS_PATH_MAX_BYTES, EventQueues, EventSink};
use mg_edge_core::request::{
    OversizeKind, Reject, check_header_count, check_limits_detailed, resolve_host,
};
use mg_edge_core::state::StateHandle;
use mg_edge_core::upstream::{
    CfHeaders, ClientIp, CloudflareSite, WorkerZone, hop_by_hop, parse_cloudflare, secret_header_ok,
};
use mg_proto::v1::EventConfig;
use pingora::http::{Method, RequestHeader, ResponseHeader};
use pingora::protocols::Digest;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorSource, ErrorType, Result};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

/// TCP connect timeout toward the origin.
pub const ORIGIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The `rule_id` of oversize requests forwarded under monitor / bootstrap-open (I-2).
pub const OVERSIZE_SKIPPED_RULE: &str = "hard.oversize_skipped";

/// Handles shared by every listener's proxy (§9.1.1): runtime-free objects
/// created in `main()`; the async work behind them runs in the background
/// services.
pub struct Shared {
    pub edge_id: String,
    pub sites: Arc<Sites>,
    /// State layer (Valkey via `mg-state`, local fallback).
    pub state: StateHandle,
    /// `K_pseudo` (§9.7 verdict and limiter keys). Never logged.
    pub k_pseudo: [u8; 32],
    /// Event queues drained by `mg-events` (§9.11).
    pub events: EventQueues,
    /// `mg:ev` is written (Valkey mode); without it no entry is built.
    pub stream_output: bool,
    /// The SDK directory served under `/__mg/s/` (WP-E1c).
    pub sdk: Arc<SdkDir>,
    /// rDNS job submission to `mg-rdns` (§9.6).
    pub rdns: Arc<RdnsDispatcher>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("edge_id", &self.edge_id)
            .field("sites", &self.sites)
            .field("sdk", &self.sdk)
            .field("rdns", &self.rdns)
            .finish_non_exhaustive()
    }
}

/// The proxy service of one listener.
#[derive(Debug, Clone)]
pub struct EdgeProxy {
    listener: Arc<ListenerRuntime>,
    shared: Arc<Shared>,
}

impl EdgeProxy {
    pub fn new(listener: Arc<ListenerRuntime>, shared: Arc<Shared>) -> Self {
        Self { listener, shared }
    }

    pub fn listener(&self) -> &ListenerRuntime {
        &self.listener
    }
}

/// The request target, split for policy and re-assembled for the origin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    /// Path without the query (`*` for the asterisk form).
    pub path: String,
    /// Query without `?` (empty when absent).
    pub query: String,
    /// The authority of an absolute-form target (no scheme, no userinfo
    /// check here: `resolve_host` rejects anything but a host).
    pub absolute_authority: Option<String>,
    /// What the origin receives: always origin-form (or `*`), never the
    /// client's absolute-form URI (RFC 9112 makes an origin prefer the
    /// absolute-form authority over `Host`).
    pub origin_form: Vec<u8>,
}

impl Target {
    /// Only the path, cut to what an access record holds: the target of a
    /// request the Edge answers itself (an oversize path can be far
    /// longer).
    fn for_record(path: &str) -> Self {
        Self {
            path: crate::context::truncate_utf8(path, ACCESS_PATH_MAX_BYTES).to_owned(),
            ..Self::default()
        }
    }
}

/// Splits a raw request target (§9.4 step 1). `None`: not origin-form,
/// asterisk-form or an absolute `http(s)` URI (e.g. CONNECT's
/// authority-form), which the Edge does not serve.
pub fn parse_target(raw: &[u8]) -> Option<Target> {
    let text = String::from_utf8_lossy(raw);
    if text == "*" {
        return Some(Target {
            path: "*".into(),
            origin_form: b"*".to_vec(),
            ..Target::default()
        });
    }
    let (authority, rest) = if text.starts_with('/') {
        (None, &text[..])
    } else {
        let (scheme, after) = text.split_once("://")?;
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return None;
        }
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        (Some(after[..end].to_owned()), &after[end..])
    };
    let rest = rest.split('#').next().unwrap_or_default();
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let path = if path.is_empty() { "/" } else { path };
    let mut origin_form = path.as_bytes().to_vec();
    if rest.contains('?') {
        origin_form.push(b'?');
        origin_form.extend_from_slice(query.as_bytes());
    }
    // Keep the raw bytes of an origin-form target (non-UTF-8 included).
    if authority.is_none() && !text.contains('#') {
        origin_form = raw.to_vec();
    }
    Some(Target {
        path: path.to_owned(),
        query: query.to_owned(),
        absolute_authority: authority,
        origin_form,
    })
}

/// The decision of a request as the logs see it: the Decision Core's
/// (evaluated requests), or the rule a request was forwarded unevaluated by
/// (`bootstrap`, `lkg_invalid_open`, `hard.oversize_skipped`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSummary {
    pub rule_id: String,
    pub action: Action,
    /// monitor / bootstrap-open: the decision is only recorded.
    pub dry_run: bool,
    /// 0 without a bundle.
    pub bundle_version: u64,
}

/// The route a forwarded request was attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRoute {
    pub env: String,
    pub id: String,
    pub name: String,
    pub require_clearance: bool,
    pub fail_closed: bool,
    pub redact_path: bool,
}

/// Per-request state shared across filter callbacks. Its `Debug` never
/// shows the client address or the query string (§2.4 item 5, D-31).
pub struct EdgeCtx {
    pub started: Instant,
    pub route_kind: RouteKind,
    pub request_id: String,
    pub site: Option<Arc<Site>>,
    pub runtime: Option<Arc<SiteRuntime>>,
    /// Normalized host (§9.4 step 1).
    pub host: String,
    pub target: Target,
    /// `loopback` / `origin_mtls` / `secret_header` / `none` (§9.2).
    pub auth_method: &'static str,
    pub tls: Option<TlsFacts>,
    /// Trusted `cloudflare` headers (cloudflare listeners).
    pub cf: Option<CfHeaders>,
    pub cf_forward: CloudflareForward,
    /// Client address: `cf-connecting-ip` (cloudflare) or the TCP peer
    /// (direct_tls); `None` = unknown.
    pub client_ip: Option<IpAddr>,
    pub visitor_https: bool,
    pub websocket: bool,
    /// Exceeded protocol cap forwarded unevaluated (I-2).
    pub oversize: Option<OversizeKind>,
    pub route: Option<SelectedRoute>,
    pub decision: Option<DecisionSummary>,
    /// Arrival time, Unix ms (`RequestContext.ts_ms`).
    pub ts_ms: i64,
    /// The Decision Core's record (active sites; WP-E1d turns it into the
    /// decision event).
    pub evaluation: Option<Box<DecisionRecord>>,
    /// `MG-*` decision headers of a forwarded evaluated request.
    pub decision_headers: Option<DecisionHeaders>,
    /// How a CHALLENGE decision was answered (WP-E1c).
    pub challenge: Option<ChallengeAnswer>,
    /// A `POST /__mg/c` submission (WP-E1d turns it into the feedback and
    /// telemetry events).
    pub submission: Option<Box<SubmitRecord>>,
    /// The access record's route of a request the Edge answered without a
    /// decision (`__mg`, `__protocol`, `__site`, §13.4).
    pub access_route: Option<&'static str>,
    /// The route name the access record writes instead of the path
    /// (`redact_path` of the selected route, or of a submission's
    /// `route_class`, D-31).
    pub redact_as: Option<String>,
    /// ASN and country of a `/__mg/c` request (its context is not kept).
    pub submit_net: Option<AccessNet>,
    /// The Edge's own time and the origin connect time (§13.7).
    pub timing: Timing,
}

impl std::fmt::Debug for EdgeCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeCtx")
            .field("route_kind", &self.route_kind)
            .field("request_id", &self.request_id)
            .field("site", &self.site.as_ref().map(|s| s.settings.id.as_str()))
            .field("host", &self.host)
            .field("path", &self.target.path)
            .field("query_len", &self.target.query.len())
            .field("auth_method", &self.auth_method)
            .field("tls", &self.tls)
            .field("cf", &self.cf)
            .field("client_ip", &crate::context::redacted_ip(self.client_ip))
            .field("visitor_https", &self.visitor_https)
            .field("websocket", &self.websocket)
            .field("oversize", &self.oversize)
            .field("route", &self.route)
            .field("decision", &self.decision)
            .field("ts_ms", &self.ts_ms)
            .field("evaluation", &self.evaluation)
            .field("decision_headers", &self.decision_headers)
            .field("challenge", &self.challenge)
            .field("submission", &self.submission)
            .field("access_route", &self.access_route)
            .field("timing", &self.timing)
            .finish_non_exhaustive()
    }
}

impl EdgeCtx {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            route_kind: RouteKind::default(),
            request_id: String::new(),
            site: None,
            runtime: None,
            host: String::new(),
            target: Target::default(),
            auth_method: "none",
            tls: None,
            cf: None,
            cf_forward: CloudflareForward::default(),
            client_ip: None,
            visitor_https: true,
            websocket: false,
            oversize: None,
            route: None,
            decision: None,
            ts_ms: 0,
            evaluation: None,
            decision_headers: None,
            challenge: None,
            submission: None,
            access_route: None,
            redact_as: None,
            submit_net: None,
            timing: Timing::default(),
        }
    }
}

/// The Pingora request body as a [`BodySource`] for `/__mg/c`.
struct SessionBody<'a>(&'a mut Session);

#[async_trait]
impl BodySource for SessionBody<'_> {
    async fn chunk(&mut self) -> std::result::Result<Option<Bytes>, BodyReadError> {
        self.0.read_request_body().await.map_err(|_| BodyReadError)
    }
}

/// The route `/__mg/c` is evaluated under for `crate::context::build`: the
/// endpoint is answered before route matching (§10.1) and belongs to no
/// bundle route; the `C`'s own route (`route_class`) is what counts.
fn edge_route(env: &str) -> RouteInfo {
    RouteInfo {
        id: "__mg".into(),
        name: "__mg".into(),
        env: env.to_owned(),
        channel: Channel::Web,
        sensitivity: RouteSensitivity::Low,
        require_clearance: false,
        fail_closed: false,
    }
}

/// Wall clock, Unix ms.
fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

static FALLBACK_ROUTE: LazyLock<RouteRuntime> = LazyLock::new(RouteRuntime::fallback);

impl EdgeProxy {
    /// Answers the request with an Edge response; `Ok(true)` for
    /// `request_filter`.
    async fn answer(&self, session: &mut Session, resp: EdgeResponse) -> Result<bool> {
        resp.send(session).await?;
        Ok(true)
    }

    /// Answers before the decision step for a known site: the access record
    /// gets `route` (`__protocol` / `__site` / `__mg`) and the path, cut to
    /// what it can hold (an oversize path can be far longer).
    async fn answer_early(
        &self,
        session: &mut Session,
        ctx: &mut EdgeCtx,
        path: &str,
        route: &'static str,
        resp: EdgeResponse,
    ) -> Result<bool> {
        ctx.access_route = Some(route);
        ctx.target = Target::for_record(path);
        self.answer(session, resp).await
    }

    async fn protocol_reject(&self, session: &mut Session, reject: Reject) -> Result<bool> {
        metrics()
            .protocol_rejected
            .with_label_values(&[self.listener.name.as_str(), reject.reason()])
            .inc();
        self.answer(session, EdgeResponse::protocol(reject)).await
    }

    /// Steps 0-10 (see the module documentation).
    async fn pipeline(&self, session: &mut Session, ctx: &mut EdgeCtx) -> Result<bool> {
        let m = metrics();
        ctx.ts_ms = unix_now_ms();
        // 0. Request id from the OS CSPRNG; no fallback (§9.9).
        match rng::request_id(&OsRng) {
            Ok(id) => ctx.request_id = id,
            Err(_) => {
                m.internal_error(ctx.route_kind);
                log::error!("request id: the OS random number generator failed");
                return self
                    .answer(session, EdgeResponse::internal_unavailable())
                    .await;
            }
        }

        // 1. Listener authentication (§9.2).
        let peer = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip());
        if !self.listener.peer_allowed(peer) {
            self.listener.auth_failure("non_loopback_peer");
            return self.answer(session, EdgeResponse::forbidden()).await;
        }
        ctx.auth_method = self.listener.auth.as_str();
        if let Some(keys) = &self.listener.upstream_keys {
            let values: Vec<&[u8]> = session
                .req_header()
                .headers
                .get_all("x-mg-upstream-key")
                .iter()
                .map(|v| v.as_bytes())
                .collect();
            let presented = (values.len() == 1).then(|| values[0]);
            if !secret_header_ok(presented, keys.values()) {
                self.listener.auth_failure("bad_secret_header");
                return self.answer(session, EdgeResponse::forbidden()).await;
            }
            ctx.auth_method = "secret_header";
        }
        ctx.tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .and_then(|s| s.extension.get::<TlsFacts>())
            .cloned();

        // 2. Protocol limits (decided once the site's mode is known) and the
        //    raw inputs of hygiene.
        let req = session.req_header();
        let raw = raw_headers(req);
        let slices = as_slices(&raw);
        let Some(target) = parse_target(req.raw_path()) else {
            return self.protocol_reject(session, Reject::BadMethod).await;
        };
        let method = req.method.as_str().to_owned();
        let limits = check_limits_detailed(&method, &target.path, &target.query, &slices);

        // 3. Host -> site. More than one Host field line is malformed
        //    (RFC 9112 §3.2) and never reaches resolve_host.
        let hosts = req.headers.get_all("host").iter().count();
        let host_header = match req.headers.get("host").map(|v| v.to_str()) {
            None => None,
            Some(Ok(h)) => Some(h),
            Some(Err(_)) => return self.protocol_reject(session, Reject::BadHost).await,
        };
        let authority = (req.version == pingora::http::Version::HTTP_2)
            .then(|| req.uri.authority().map(|a| a.as_str()))
            .flatten();
        let host = if hosts > 1 {
            Err(Reject::BadHost)
        } else {
            resolve_host(host_header, authority, target.absolute_authority.as_deref())
        };
        let host = match host {
            Ok(h) => h,
            Err(reject) => return self.protocol_reject(session, reject).await,
        };
        let Some(site) = self.shared.sites.by_host(&host).cloned() else {
            m.unknown_host
                .with_label_values(&[self.listener.name.as_str()])
                .inc();
            return self.answer(session, EdgeResponse::unknown_site()).await;
        };
        let runtime = site.runtime();
        let site_id = site.settings.id.as_str();
        ctx.host = host;
        ctx.route_kind = routes::classify(&target.path);
        // From here on the request belongs to the site (its events).
        ctx.site = Some(Arc::clone(&site));
        ctx.runtime = Some(Arc::clone(&runtime));

        // Listener allowed: edge.toml, and the bundle once there is one.
        let allowed = site.settings.listeners.contains(&self.listener.name)
            && runtime
                .bundle
                .as_ref()
                .is_none_or(|b| b.allowed_listeners.contains(&self.listener.name));
        if !allowed {
            m.listener_rejected
                .with_label_values(&[self.listener.name.as_str(), site_id])
                .inc();
            let resp = EdgeResponse::forbidden();
            return self
                .answer_early(session, ctx, &target.path, ev::ROUTE_SITE, resp)
                .await;
        }

        // Header hygiene (§9.3 steps 3-5): what is removed, and the trusted
        // headers parsed before anything is removed.
        let mut removed: BTreeSet<String> = hop_by_hop(&slices).into_iter().collect();
        ctx.websocket = !removed.contains("upgrade")
            && raw.iter().any(|(n, _)| n.eq_ignore_ascii_case("upgrade"));
        let families = family_names(&raw);
        let cloudflare_cfg = runtime.bundle.as_ref().and_then(|b| b.cloudflare.as_ref());
        match self.listener.profile {
            ListenerProfile::Cloudflare => {
                let cf_site = CloudflareSite {
                    location_headers: cloudflare_cfg.is_some_and(|c| c.location_headers),
                    tier1: cloudflare_cfg.is_some_and(|c| c.tier1),
                    owner_zones: runtime.owner_zones(&site.settings),
                    pseudo_ipv4_overwrite: cloudflare_cfg.is_some_and(|c| c.pseudo_ipv4_overwrite),
                };
                let cf = parse_cloudflare(&slices, &cf_site);
                ctx.client_ip = cf.client_ip.ip();
                ctx.visitor_https = cf.visitor_https;
                ctx.cf_forward = CloudflareForward {
                    ip_country: cf_site
                        .location_headers
                        .then(|| single_value(&raw, "cf-ipcountry").map(<[u8]>::to_vec))
                        .flatten(),
                    ray: single_value(&raw, "cf-ray").map(<[u8]>::to_vec),
                    visitor: single_value(&raw, "cf-visitor").map(<[u8]>::to_vec),
                };
                ctx.cf = Some(cf);
            }
            ListenerProfile::DirectTls => {
                ctx.client_ip = peer.map(|ip| ip.to_canonical());
                ctx.visitor_https = true;
                if !families.is_empty() {
                    m.upstream_headers_stripped
                        .with_label_values(&["direct_tls"])
                        .inc();
                }
            }
        }
        removed.extend(families);
        let mut oversize = limits.err();
        if oversize.is_none() && check_header_count(distinct_after(&raw, &removed)).is_err() {
            oversize = Some(OversizeKind::HeaderCount);
        }

        let serving = runtime.serving(&site.settings);
        if let Some(kind) = oversize {
            match serving.record_only_mode() {
                Some(mode) => {
                    m.oversize
                        .with_label_values(&[site_id, kind.as_str(), mode])
                        .inc();
                    ctx.oversize = Some(kind);
                }
                None => {
                    ctx.access_route = Some(ev::ROUTE_PROTOCOL);
                    ctx.target = Target::for_record(&target.path);
                    return self.protocol_reject(session, kind.reject()).await;
                }
            }
        }

        // Site state: 503 except for the health check (§9.4 step 3).
        if matches!(serving, Serving::Unavailable) && ctx.route_kind != RouteKind::Healthz {
            m.site_unavailable.with_label_values(&[site_id]).inc();
            let resp = EdgeResponse::site_unavailable();
            return self
                .answer_early(session, ctx, &target.path, ev::ROUTE_SITE, resp)
                .await;
        }

        // A foreign zone's Worker: 403 before any decision (D-23).
        if ctx
            .cf
            .as_ref()
            .is_some_and(|cf| cf.worker == WorkerZone::Foreign)
        {
            m.cf_foreign_worker.with_label_values(&[site_id]).inc();
            let resp = EdgeResponse::forbidden();
            return self
                .answer_early(session, ctx, &target.path, ev::ROUTE_SITE, resp)
                .await;
        }

        // Missing trusted signals of requests that go on (a local health
        // check without Cloudflare headers is not an upstream problem).
        if let Some(cf) = &ctx.cf
            && ctx.route_kind != RouteKind::Healthz
        {
            for signal in &cf.missing_signals {
                m.upstream_signal_missing
                    .with_label_values(&["cloudflare", signal])
                    .inc();
            }
            if matches!(cf.client_ip, ClientIp::Unknown { .. }) {
                m.cf_connecting_ip_missing
                    .with_label_values(&[site_id])
                    .inc();
            }
        }

        // Nothing below reads the removed headers: drop them from the
        // downstream request, so neither Pingora's hop-by-hop handling nor
        // the origin sees them.
        headers::remove_names(session.req_header_mut(), &removed);

        // 4. /__mg/* (never reaches the origin).
        match ctx.route_kind {
            RouteKind::Healthz => {
                let method = &session.req_header().method;
                let is_get = method == Method::GET || method == Method::HEAD;
                let mut resp = if is_get {
                    EdgeResponse::healthz()
                } else {
                    EdgeResponse::method_not_allowed("GET, HEAD")
                };
                // Answered before any body was read (§9.9): keep the
                // connection only if there is no body Pingora would drain.
                if !session.is_body_empty() {
                    resp.close = true;
                }
                return self
                    .answer_early(session, ctx, &target.path, ev::ROUTE_EDGE, resp)
                    .await;
            }
            RouteKind::SdkFile => {
                let mut resp = mg_endpoints::sdk_file(&self.shared.sdk, &target.path, &method);
                if !session.is_body_empty() {
                    resp.close = true;
                }
                return self
                    .answer_early(session, ctx, &target.path, ev::ROUTE_EDGE, resp)
                    .await;
            }
            RouteKind::Submit => {
                ctx.access_route = Some(ev::ROUTE_EDGE);
                ctx.target = target;
                return self
                    .submit(session, ctx, &site, serving, &method, &raw, &removed)
                    .await;
            }
            RouteKind::EdgeReserved => {
                let resp = EdgeResponse::not_found();
                return self
                    .answer_early(session, ctx, &target.path, ev::ROUTE_EDGE, resp)
                    .await;
            }
            RouteKind::Origin => {}
        }

        // 5-10. Environment, route and the decision. An oversize request
        //     (I-2) is forwarded unevaluated and gets no route either: the
        //     §9.4 cost bound of route matching rests on the 8 KiB path cap,
        //     and its path may be as long as Pingora's 1 MiB header limit.
        let summary = match serving {
            Serving::Active(bundle) if ctx.oversize.is_some() => DecisionSummary {
                rule_id: OVERSIZE_SKIPPED_RULE.into(),
                action: Action::Allow,
                dry_run: true,
                bundle_version: bundle.version,
            },
            Serving::Active(bundle) => {
                let Some(env) = bundle.env_for_host(&ctx.host) else {
                    ctx.access_route = Some(ev::ROUTE_SITE);
                    ctx.target = Target::for_record(&target.path);
                    return self.no_environment(session, ctx, site_id).await;
                };
                let rm = select_route(
                    env,
                    &ctx.host,
                    &method,
                    &target.path,
                    bundle.case_insensitive_paths,
                    &FALLBACK_ROUTE,
                );
                let route = RouteInfo {
                    id: rm.route.id.clone(),
                    name: rm.route.name.clone(),
                    env: env.name.clone(),
                    channel: rm.route.channel,
                    sensitivity: rm.route.sensitivity,
                    require_clearance: rm.require_clearance,
                    fail_closed: rm.fail_closed,
                };
                ctx.route = Some(SelectedRoute {
                    env: env.name.clone(),
                    id: route.id.clone(),
                    name: route.name.clone(),
                    require_clearance: route.require_clearance,
                    fail_closed: route.fail_closed,
                    redact_path: rm.route.redact_path,
                });
                if rm.route.redact_path {
                    ctx.redact_as = Some(route.name.clone());
                }
                let ssl_version = session
                    .digest()
                    .and_then(|d| d.ssl_digest.as_ref())
                    .map(|s| s.version.as_ref());
                let http_version = http_version_str(session.req_header().version);
                let facts = self.facts(
                    ctx,
                    ssl_version,
                    http_version,
                    site_id,
                    &route,
                    bundle,
                    &method,
                    &target,
                    &raw,
                    &removed,
                );
                let services = Services {
                    state: &self.shared.state,
                    k_pseudo: &self.shared.k_pseudo,
                    rdns: &self.shared.rdns,
                };
                let rec = decide::evaluate(services, bundle, env, &facts).await;
                let summary = DecisionSummary {
                    rule_id: rec.rule_id().to_owned(),
                    action: rec.decision.action,
                    dry_run: rec.decision.dry_run,
                    bundle_version: rec.bundle_version,
                };
                let answer = match rec.enforcement {
                    Enforcement::Challenge(ty) => {
                        let (resp, how) = self.challenge(&ChallengeInput {
                            site: &site,
                            bundle,
                            ctx,
                            method: &method,
                            target: &target,
                            raw: &raw,
                            removed: &removed,
                            rec: &rec,
                            ty,
                        });
                        ctx.challenge = Some(how);
                        Some(resp)
                    }
                    e => EdgeResponse::for_enforcement(e, &ctx.request_id, || {
                        is_navigation(&crate::context::req_headers(&raw, &removed))
                    }),
                };
                if answer.is_none() {
                    ctx.decision_headers =
                        Some(DecisionHeaders::from_record(&rec, &bundle.origin_headers));
                }
                ctx.evaluation = Some(Box::new(rec));
                if let Some(resp) = answer {
                    ctx.decision = Some(summary);
                    ctx.target = target;
                    ctx.site = Some(site);
                    ctx.runtime = Some(runtime);
                    return self.answer(session, resp).await;
                }
                summary
            }
            Serving::Open { rule_id } => DecisionSummary {
                rule_id: if ctx.oversize.is_some() {
                    OVERSIZE_SKIPPED_RULE
                } else {
                    rule_id
                }
                .into(),
                action: Action::Allow,
                dry_run: true,
                bundle_version: 0,
            },
            // Answered 503 above (only the health check gets this far).
            Serving::Unavailable => {
                return self.answer(session, EdgeResponse::site_unavailable()).await;
            }
        };
        ctx.decision = Some(summary);
        ctx.target = target;
        ctx.site = Some(site);
        ctx.runtime = Some(runtime);
        Ok(false)
    }
}

/// What [`EdgeProxy::challenge`] needs about a CHALLENGE decision.
struct ChallengeInput<'a> {
    site: &'a Site,
    bundle: &'a BundleRuntime,
    ctx: &'a EdgeCtx,
    method: &'a str,
    target: &'a Target,
    raw: &'a [(String, Vec<u8>)],
    removed: &'a BTreeSet<String>,
    rec: &'a DecisionRecord,
    ty: mg_core::ChallengeType,
}

impl EdgeProxy {
    /// 503 for an active bundle without an environment for the host:
    /// `verify_bundle` makes the environments partition the site's hosts,
    /// so this is a broken bundle and fails closed.
    async fn no_environment(
        &self,
        session: &mut Session,
        ctx: &EdgeCtx,
        site_id: &str,
    ) -> Result<bool> {
        log::error!(
            "request_id={} site {site_id}: no environment serves the host",
            ctx.request_id
        );
        metrics()
            .site_unavailable
            .with_label_values(&[site_id])
            .inc();
        self.answer(session, EdgeResponse::site_unavailable()).await
    }

    /// The facts of a request for `crate::context::build` (§9.5).
    #[allow(clippy::too_many_arguments)]
    fn facts<'a>(
        &self,
        ctx: &'a EdgeCtx,
        ssl_version: Option<&'a str>,
        http_version: &'static str,
        site_id: &'a str,
        route: &'a RouteInfo,
        bundle: &BundleRuntime,
        method: &'a str,
        target: &'a Target,
        raw: &'a [(String, Vec<u8>)],
        removed: &'a BTreeSet<String>,
    ) -> Facts<'a> {
        let tls = match self.listener.profile {
            ListenerProfile::DirectTls => Some(TlsInfo {
                version: ssl_version,
                sni: ctx.tls.as_ref().and_then(|t| t.sni.as_deref()),
                alpn: ctx.tls.as_ref().and_then(|t| t.alpn.as_deref()),
            }),
            ListenerProfile::Cloudflare => None,
        };
        Facts {
            request_id: &ctx.request_id,
            ts_ms: ctx.ts_ms,
            site_id,
            route,
            profile: self.listener.profile,
            auth_method: ctx.auth_method,
            cf: ctx.cf.as_ref(),
            location_headers: bundle
                .cloudflare
                .as_ref()
                .is_some_and(|c| c.location_headers),
            client_ip: ctx.client_ip,
            tls,
            http_version,
            method,
            host: &ctx.host,
            path: &target.path,
            query: &target.query,
            raw_headers: raw,
            removed,
            expected_mask: bundle.expected_mask,
        }
    }

    /// Answers a CHALLENGE decision with a known client IP (§9.9,
    /// `crate::challenge::respond`): 308 for an http visitor's GET / HEAD,
    /// otherwise a sealed `C` in the challenge page or the JSON challenge.
    fn challenge(&self, c: &ChallengeInput<'_>) -> (EdgeResponse, ChallengeAnswer) {
        let headers = crate::context::req_headers(c.raw, c.removed);
        let http_visitor =
            self.listener.profile == ListenerProfile::Cloudflare && !c.ctx.visitor_https;
        let route_class = c.ctx.route.as_ref().map_or("default", |r| r.name.as_str());
        challenge::respond(
            &ChallengeRequest {
                sealer: &c.site.sealer,
                sdk: &self.shared.sdk,
                cfg: &c.bundle.challenge,
                site_id: &c.site.settings.id,
                request_id: &c.ctx.request_id,
                host: &c.ctx.host,
                method: c.method,
                path: &c.target.path,
                query: &c.target.query,
                origin_form: &c.target.origin_form,
                http_visitor,
                navigation: is_navigation(&headers),
                accept_language: crate::context::header(&headers, "accept-language"),
                route_class,
                ty: c.ty,
                band: c.rec.risk.score.band(),
                bind: &c.rec.bind,
                now_ms: unix_now_ms(),
            },
            &OsRng,
        )
    }

    /// `/__mg/c` (§10.1, §10.3): 404 while the site has no bundle
    /// (bootstrap-open, lkg_invalid_open), 405 for other methods, otherwise
    /// the submission flow of `crate::mg_endpoints::submit`.
    #[allow(clippy::too_many_arguments)]
    async fn submit(
        &self,
        session: &mut Session,
        ctx: &mut EdgeCtx,
        site: &Site,
        serving: Serving<'_>,
        method: &str,
        raw: &[(String, Vec<u8>)],
        removed: &BTreeSet<String>,
    ) -> Result<bool> {
        let Serving::Active(bundle) = serving else {
            return self.answer(session, EdgeResponse::not_found()).await;
        };
        if method != "POST" {
            let resp = EdgeResponse::method_not_allowed(mg_endpoints::SUBMIT_ALLOW);
            return self.answer(session, resp).await;
        }
        let site_id = site.settings.id.as_str();
        let Some(env) = bundle.env_for_host(&ctx.host) else {
            return self.no_environment(session, ctx, site_id).await;
        };
        let route = edge_route(&env.name);
        let built = {
            let ssl_version = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .map(|s| s.version.as_ref());
            let http_version = http_version_str(session.req_header().version);
            let facts = self.facts(
                ctx,
                ssl_version,
                http_version,
                site_id,
                &route,
                bundle,
                method,
                &ctx.target,
                raw,
                removed,
            );
            crate::context::build(&facts, &bundle.intel)
        };
        let bind = identity::bind_inputs(
            &built.ua,
            &built.ctx.net,
            built.ctx.edge_tls.as_ref(),
            bundle.clearance.ctp_shadow,
        );
        let submitted = {
            let s = mg_endpoints::Submit {
                request_id: &ctx.request_id,
                now_ms: unix_now_ms(),
                site_id,
                sealer: &site.sealer,
                sdk: &self.shared.sdk,
                bundle,
                env,
                host: &ctx.host,
                built: &built,
                bind: &bind,
                content_encoding: crate::context::received(raw, "content-encoding"),
            };
            mg_endpoints::submit(&self.shared.state, &OsRng, &s, &mut SessionBody(session)).await
        };
        if submitted.response.status == 503 {
            metrics().internal_error(ctx.route_kind);
        }
        // The access record of a submission for a redacting route shows
        // that route, as its decision events do (§9.11).
        ctx.redact_as = submitted
            .record
            .feedback
            .route_id
            .as_deref()
            .filter(|class| env.routes.iter().any(|r| r.name == *class && r.redact_path))
            .map(str::to_owned);
        ctx.submit_net = Some(AccessNet {
            asn: built.ctx.net.asn,
            country: built.ctx.net.country.clone(),
        });
        ctx.submission = Some(Box::new(submitted.record));
        self.answer(session, submitted.response).await
    }
}

impl EdgeProxy {
    /// `upstream_request_filter`: the origin-form target and the §9.9
    /// origin headers.
    fn origin_request(&self, upstream_request: &mut RequestHeader, ctx: &EdgeCtx) -> Result<()> {
        upstream_request.set_raw_path(&ctx.target.origin_form)?;
        let https = match self.listener.profile {
            ListenerProfile::Cloudflare => ctx.visitor_https,
            ListenerProfile::DirectTls => true,
        };
        let cloudflare =
            (self.listener.profile == ListenerProfile::Cloudflare).then_some(&ctx.cf_forward);
        OriginHeaders {
            host: &ctx.host,
            request_id: &ctx.request_id,
            client_ip: ctx.client_ip,
            https,
            cloudflare,
            websocket: ctx.websocket,
            decision: ctx.decision_headers.as_ref(),
        }
        .apply(upstream_request)
    }

    /// `logging`: the §13.7 per-request metrics and the §9.11 events of a
    /// request that belongs to a site (see `crate::events`). Runs after the
    /// debug line, which reads the evaluation this consumes.
    fn record(&self, session: &Session, ctx: &mut EdgeCtx) {
        let (Some(site), Some(runtime)) = (ctx.site.clone(), ctx.runtime.clone()) else {
            return;
        };
        let site_id = site.settings.id.as_str();
        let m = metrics();
        m.observe_timing(site_id, ctx.route_kind, &ctx.timing);
        let bundle = runtime.bundle.as_deref();
        let mut cfg: EventConfig = bundle.map_or(*DEFAULT_EVENTS, |b| b.events);
        // Without Valkey there is no mg:ev output: build no entries.
        cfg.stream &= self.shared.stream_output;
        let env = match (&ctx.evaluation, bundle) {
            (Some(rec), _) => Some(rec.ctx.env.clone()),
            (None, Some(b)) => b.env_for_host(&ctx.host).map(|e| e.name.clone()),
            (None, None) => None,
        };
        let req = session.req_header();
        let f = Finished {
            edge_id: &self.shared.edge_id,
            site: site_id,
            request_id: &ctx.request_id,
            ts_ms: ctx.ts_ms,
            method: req.method.as_str(),
            host: &ctx.host,
            path: &ctx.target.path,
            env: env.as_deref(),
            status: session.response_written().map(|r| r.status.as_u16()),
            bytes_out: session.body_bytes_sent() as u64,
            latency: ctx.started.elapsed(),
            client_ip: ctx.client_ip,
            cf_ray: ctx.cf.as_ref().and_then(|c| c.cf_ray.as_deref()),
            cfg: &cfg,
            k_pseudo: &self.shared.k_pseudo,
        };
        let redact = ctx.redact_as.as_deref();
        let mut records = Vec::with_capacity(3);
        if let Some(rec) = ctx.evaluation.take() {
            let rec = *rec;
            m.requests_total
                .with_label_values(&[
                    site_id,
                    &rec.ctx.env,
                    &rec.route.name,
                    rec.decision.action.as_str(),
                    rec.risk.bot_class.as_str(),
                ])
                .inc();
            let decision = AccessDecision {
                action: rec.decision.action,
                dry_run: rec.decision.dry_run,
            };
            let net = AccessNet {
                asn: rec.ctx.net.asn,
                country: rec.ctx.net.country.clone(),
            };
            let route = rec.route.name.clone();
            let as_org = ctx
                .cf
                .as_ref()
                .and_then(|c| c.tier1.as_ref())
                .and_then(|t| t.as_org.as_deref());
            records.extend(ev::evaluated(&f, rec, redact.is_some(), as_org));
            records.extend(ev::access(&f, &route, Some(decision), redact, &net));
        } else if let Some(summary) = &ctx.decision {
            m.requests_total
                .with_label_values(&[
                    site_id,
                    env.as_deref().unwrap_or(UNKNOWN_LABEL),
                    UNKNOWN_LABEL,
                    summary.action.as_str(),
                    mg_core::BotClass::default().as_str(),
                ])
                .inc();
            let u = Unevaluated {
                summary,
                profile: self.listener.profile,
                auth_method: ctx.auth_method,
                oversize: ctx.oversize,
                user_agent: req.headers.get("user-agent").and_then(|v| v.to_str().ok()),
                // Only record-only modes forward unevaluated: a monitor
                // bundle, or bootstrap-open / lkg_invalid_open without one,
                // which record like monitor (§9.9, I-3).
                monitor_only: bundle.is_none_or(|b| b.monitor_only),
            };
            records.extend(ev::unevaluated(&f, &u));
            let decision = AccessDecision {
                action: summary.action,
                dry_run: summary.dry_run,
            };
            let route = ctx
                .route
                .as_ref()
                .map_or(UNKNOWN_LABEL, |r| r.name.as_str());
            records.extend(ev::access(
                &f,
                route,
                Some(decision),
                redact,
                &AccessNet::default(),
            ));
        } else if let Some(route) = ctx.access_route {
            if let Some(sub) = ctx.submission.as_deref() {
                let asn = ctx.submit_net.as_ref().and_then(|n| n.asn);
                records.extend(ev::submission(&f, sub, asn));
            }
            let net = ctx.submit_net.clone().unwrap_or_default();
            records.extend(ev::access(&f, route, None, redact, &net));
        }
        for record in records {
            // A full queue counts the drop itself (mg_event_dropped_total).
            let _ = self.shared.events.try_send(record);
        }
    }
}

/// `env` / `route` label of a request without one (bootstrap, oversize).
const UNKNOWN_LABEL: &str = "-";

/// §8.3 defaults for sites without a bundle.
static DEFAULT_EVENTS: LazyLock<EventConfig> = LazyLock::new(default_events);

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = EdgeCtx;

    fn new_ctx(&self) -> Self::CTX {
        EdgeCtx::new()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let started = Instant::now();
        let answered = self.pipeline(session, ctx).await;
        ctx.timing.add_since(started);
        answered
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let started = Instant::now();
        let Some(site) = &ctx.site else {
            return Err(Error::explain(
                ErrorType::InternalError,
                "no site resolved for a forwarded request",
            ));
        };
        // Plain HTTP to the origin; Edge->origin mTLS is a later option (docs/02 §8).
        let mut peer = HttpPeer::new(site.settings.origin, false, String::new());
        peer.options.connection_timeout = Some(ORIGIN_CONNECT_TIMEOUT);
        ctx.timing.add_since(started);
        ctx.timing.peer_done = Some(Instant::now());
        Ok(Box::new(peer))
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        _digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.timing.connected(reused);
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let started = Instant::now();
        let result = self.origin_request(upstream_request, ctx);
        ctx.timing.add_since(started);
        result
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let started = Instant::now();
        headers::strip_edge_owned(upstream_response);
        ctx.timing.add_since(started);
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy {
        // Pingora's default, but the answer carries the §9.9 cache headers.
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if code > 0
            && session.response_written().is_none()
            && let Err(err) = EdgeResponse::error(code).send(session).await
        {
            log::debug!("failed to send an error response downstream: {err}");
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session.response_written().map(|r| r.status.as_u16());
        let elapsed = ctx.started.elapsed();
        metrics().observe_request(ctx.route_kind, status, elapsed, e.is_some());
        if log::log_enabled!(log::Level::Debug) {
            let tls = ctx.tls.as_ref().map(|t| {
                format!(
                    " tls_sni={} tls_alpn={}",
                    t.sni.as_deref().unwrap_or("-"),
                    t.alpn.as_deref().unwrap_or("-")
                )
            });
            let decision = ctx.evaluation.as_ref().map(|r| {
                format!(
                    " score={} class={} reasons={} token={} crawler={} hits={} enforcement={:?}",
                    r.risk.score.get(),
                    r.risk.bot_class,
                    if r.risk.top_reasons.is_empty() {
                        "-".to_string()
                    } else {
                        r.risk.top_reasons.join(",")
                    },
                    r.ctx.identity.token.status,
                    r.ctx
                        .identity
                        .crawler
                        .verification
                        .map_or("-", |v| v.as_str()),
                    r.hits_summary(),
                    r.enforcement
                )
            });
            let challenge = ctx
                .challenge
                .map(|c| format!(" challenge={c}"))
                .unwrap_or_default();
            let submission = ctx.submission.as_ref().map(|r| {
                format!(
                    " submit={} type={} reasons={}{}",
                    r.result,
                    r.feedback.challenge_type,
                    r.reasons(),
                    r.reissued
                        .map(|(band, bits)| format!(" reissued={band}/{bits}"))
                        .unwrap_or_default()
                )
            });
            log::debug!(
                "request_id={} listener={} site={} route={} rule={} action={} dry_run={} status={:?} auth={} elapsed_us={}{}{}{}{}",
                ctx.request_id,
                self.listener.name,
                ctx.site.as_ref().map_or("-", |s| s.settings.id.as_str()),
                ctx.route.as_ref().map_or("-", |r| r.name.as_str()),
                ctx.decision.as_ref().map_or("-", |d| d.rule_id.as_str()),
                ctx.decision.as_ref().map_or("-", |d| d.action.as_str()),
                ctx.decision.as_ref().is_some_and(|d| d.dry_run),
                status,
                ctx.auth_method,
                elapsed.as_micros(),
                decision.unwrap_or_default(),
                challenge,
                submission.unwrap_or_default(),
                tls.unwrap_or_default()
            );
        }
        self.record(session, ctx);
    }

    /// Used by Pingora in its error logs as well. Pingora's default includes
    /// the query string, which can carry tokens or personal data; ours does
    /// not, and it never includes a client address. A request on a
    /// `redact_path` route (whose paths carry one-time tokens, D-31) shows
    /// `/<route name>`, as its events do.
    fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
        let req = session.req_header();
        let path = match &ctx.redact_as {
            Some(route) => mg_edge_core::events::redacted_path(route),
            None => parse_target(req.raw_path())
                .map(|t| t.path)
                .unwrap_or_default(),
        };
        format!(
            "{} {} route={} request_id={}",
            req.method,
            path,
            ctx.route_kind.metric_label(),
            ctx.request_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_targets() {
        let t = parse_target(b"/a/b?x=1&y").unwrap();
        assert_eq!((t.path.as_str(), t.query.as_str()), ("/a/b", "x=1&y"));
        assert_eq!(t.origin_form, b"/a/b?x=1&y");
        assert_eq!(t.absolute_authority, None);
        let t = parse_target(b"/p%20q/").unwrap();
        assert_eq!(t.path, "/p%20q/");
        assert_eq!(t.origin_form, b"/p%20q/");
        let t = parse_target(b"/a?").unwrap();
        assert_eq!((t.path.as_str(), t.query.as_str()), ("/a", ""));
        assert_eq!(t.origin_form, b"/a?");
        // Non-UTF-8 bytes are forwarded as received.
        let t = parse_target(b"/caf\xe9").unwrap();
        assert_eq!(t.origin_form, b"/caf\xe9");
        let t = parse_target(b"*").unwrap();
        assert_eq!(
            (t.path.as_str(), t.origin_form.as_slice()),
            ("*", &b"*"[..])
        );
    }

    /// Absolute-form targets are forwarded in origin-form; their authority
    /// takes part in the Host check (§9.4 step 1).
    #[test]
    fn absolute_form_targets() {
        let t = parse_target(b"http://Example.com:8080/a/b?q=1").unwrap();
        assert_eq!(t.absolute_authority.as_deref(), Some("Example.com:8080"));
        assert_eq!((t.path.as_str(), t.query.as_str()), ("/a/b", "q=1"));
        assert_eq!(t.origin_form, b"/a/b?q=1");
        let t = parse_target(b"HTTPS://example.com").unwrap();
        assert_eq!(t.path, "/");
        assert_eq!(t.origin_form, b"/");
        let t = parse_target(b"http://example.com?x").unwrap();
        assert_eq!((t.path.as_str(), t.query.as_str()), ("/", "x"));
        assert_eq!(t.origin_form, b"/?x");
        let t = parse_target(b"http://user@evil.test/").unwrap();
        assert_eq!(t.absolute_authority.as_deref(), Some("user@evil.test"));
        for bad in [&b"example.com:443"[..], b"ftp://x/", b"", b"x"] {
            assert!(parse_target(bad).is_none(), "{bad:?}");
        }
        assert_eq!(parse_target(b"//x").unwrap().path, "//x");
    }

    /// §2.4 item 5, D-31: `Debug` of the per-request state never shows the
    /// client address or the query string.
    #[test]
    fn edge_ctx_debug_has_no_client_address_or_query() {
        let mut ctx = EdgeCtx::new();
        ctx.request_id = "0123456789abcdef0123456789abcdef".into();
        ctx.client_ip = Some("203.0.113.77".parse().unwrap());
        ctx.target = parse_target(b"/reset?token=query-secret").unwrap();
        let text = format!("{ctx:?}");
        assert!(!text.contains("203.0.113.77"), "{text}");
        assert!(!text.contains("query-secret"), "{text}");
        assert!(
            text.contains("/reset") && text.contains(&ctx.request_id),
            "{text}"
        );
        ctx.client_ip = Some("2001:db8::77".parse().unwrap());
        assert!(!format!("{ctx:?}").contains("2001:db8"));
    }

    /// §2.4 item 3: the target splitter never panics.
    #[test]
    fn random_targets_never_panic() {
        let mut s = 0x1234_5678_9abc_def0u64;
        for _ in 0..10_000 {
            let mut t = b"http://example.com/a?b#c".to_vec();
            for _ in 0..4 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let at = (s as usize) % (t.len() + 1);
                t.insert(at, (s >> 40) as u8);
            }
            let _ = parse_target(&t);
        }
    }
}
