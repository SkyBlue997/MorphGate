//! Request fixtures for the unit tests of the detectors, the scorer and the
//! engine.

use crate::context::{ConnType, EdgeTls, IpSource, Net, RequestContext, UpstreamAuthMethod};
use crate::enums::{Channel, RouteSensitivity, SignalSource, UpstreamProfileKind};
use crate::extras::{RateObservation, RequestExtras, RouteInfo};
use crate::policy::MissingSet;
use crate::ua;

pub(crate) const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// A request under construction: the context plus the owned parts of its extras.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    pub ctx: RequestContext,
    pub route: RouteInfo,
    headers: Vec<(String, String)>,
    pub query: String,
    pub rate: Vec<RateObservation>,
    pub missing: MissingSet,
    pub secure: bool,
}

impl Req {
    /// A current Chrome navigation behind Cloudflare, with every Tier 0
    /// header present, on a low-sensitivity web route.
    pub fn cloudflare_browser() -> Self {
        let mut ctx = RequestContext::new(
            "0123456789abcdef0123456789abcdef",
            "blog",
            1_790_000_000_000,
        );
        ctx.env = "production".into();
        ctx.upstream.profile = UpstreamProfileKind::Cloudflare;
        ctx.upstream.authenticated = true;
        ctx.upstream.auth_method = UpstreamAuthMethod::Loopback;
        ctx.net = Net {
            ip_source: Some(IpSource::CfConnectingIp),
            asn: Some(64500),
            country: Some("HK".into()),
            conn_type: ConnType::Unknown,
            ..Net::for_ip("203.0.113.7".parse().unwrap())
        };
        ctx.edge_tls = Some(EdgeTls {
            version: Some("TLSv1.3".into()),
            cipher: Some("AEAD-AES128-GCM-SHA256".into()),
            hello_len: Some(512),
            ..EdgeTls::default()
        });
        ctx.http.version = Some("HTTP/2".into());
        ctx.http.version_source = SignalSource::Cloudflare;
        ctx.http.method = "GET".into();
        ctx.http.host = "example.com".into();
        ctx.http.path = "/".into();
        ctx.http.user_agent = Some(CHROME_UA.into());
        ctx.identity.crawler.cf_vbot = Some(false);
        let mut req = Self {
            ctx,
            route: RouteInfo {
                id: "default".into(),
                name: "default".into(),
                env: "production".into(),
                channel: Channel::Web,
                sensitivity: RouteSensitivity::Low,
                require_clearance: false,
                fail_closed: false,
            },
            headers: Vec::new(),
            query: String::new(),
            rate: Vec::new(),
            missing: MissingSet::new([
                "tls",
                "http.header_order",
                "identity.proof",
                "identity.agent",
            ])
            .unwrap(),
            secure: true,
        };
        req.header("user-agent", CHROME_UA)
            .header(
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("accept-language", "zh-HK,zh;q=0.9,en;q=0.8")
            .header(
                "sec-ch-ua",
                r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
            )
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "none");
        req
    }

    /// The same browser connecting directly (`direct_tls`, HTTP/1.1, TLS 1.3).
    pub fn direct_browser() -> Self {
        let mut req = Self::cloudflare_browser();
        req.ctx.upstream.profile = UpstreamProfileKind::DirectTls;
        req.ctx.upstream.authenticated = false;
        req.ctx.upstream.auth_method = UpstreamAuthMethod::None;
        req.ctx.net.ip_source = Some(IpSource::TcpPeer);
        req.ctx.edge_tls = None;
        req.ctx.tls.available = true;
        req.ctx.tls.version = Some("TLSv1.3".into());
        req.ctx.http.version = Some("HTTP/1.1".into());
        req.ctx.http.version_source = SignalSource::SelfComputed;
        req.ctx.identity.crawler.cf_vbot = None;
        req.missing = MissingSet::new([
            "edge_tls",
            "identity.crawler.cf_vbot",
            "identity.crawler.cf_vbot_cat",
            "tls.ja4",
            "identity.proof",
            "identity.agent",
        ])
        .unwrap();
        req
    }

    /// Sets (or replaces) a request header; names are stored lower-case and sorted.
    pub fn header(&mut self, name: &str, value: &str) -> &mut Self {
        let name = name.to_ascii_lowercase();
        self.headers.retain(|(k, _)| *k != name);
        self.headers.push((name, value.to_string()));
        self.headers.sort();
        self
    }

    /// Removes a request header.
    pub fn without(&mut self, name: &str) -> &mut Self {
        self.headers.retain(|(k, _)| k != name);
        self
    }

    /// Sets the User-Agent in both the context and the headers.
    pub fn ua(&mut self, ua: &str) -> &mut Self {
        self.ctx.http.user_agent = (!ua.is_empty()).then(|| ua.to_string());
        if ua.is_empty() {
            self.without("user-agent")
        } else {
            self.header("user-agent", ua)
        }
    }

    /// Calls `f` with the context and the extras borrowed from this request.
    pub fn with<R>(&self, f: impl FnOnce(&RequestContext, &RequestExtras<'_>) -> R) -> R {
        let ua = ua::parse(self.ctx.http.user_agent.as_deref().unwrap_or(""));
        let extras = RequestExtras {
            route: &self.route,
            headers: &self.headers,
            query: &self.query,
            rate: &self.rate,
            missing: &self.missing,
            ua: &ua,
            secure_context: self.secure,
        };
        f(&self.ctx, &extras)
    }
}
