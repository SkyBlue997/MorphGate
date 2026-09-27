//! Per-request decision input (`morphgate.v1.RequestContext`, docs/02 §7).
//!
//! The Edge builds one [`RequestContext`] per request from the trusted parts
//! of the connection and headers (which parts are trusted depends on the
//! [`UpstreamProfileKind`] and whether the upstream authenticated). Detectors
//! only read it.
//!
//! Field paths match the policy (CEL) fields of docs/06 §2. Optional values
//! are `Option` here where the protobuf uses `""` / `0`; absent values are
//! omitted from JSON to keep event lines small. Whether a value is `ABSENT` or
//! `MISSING` (docs/03 §3.1) is recorded per signal ([`crate::SignalState`])
//! and per family ([`FamilyMask`]), not in these structs.

use crate::challenge::ProviderId;
use crate::decision::EntityVerdict;
use crate::enums::{Channel, SignalFamily, SignalSource, UnknownVariant, UpstreamProfileKind};
use crate::mask::FamilyMask;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

wire_enum! {
    /// How the upstream proved itself (docs/08 §1.2).
    #[derive(Default)]
    pub enum UpstreamAuthMethod {
        /// Tunnel: listener bound to loopback, loopback peer only.
        Loopback => "loopback",
        /// Client certificate chained to the owner's CA (AOP and other CDNs).
        OriginMtls => "origin_mtls",
        /// Rotating `x-mg-upstream-key`, alone or on top of mTLS.
        SecretHeader => "secret_header",
        /// TCP peer inside `allowed_src_cidrs` (`proxy_protocol`).
        SrcCidr => "src_cidr",
        /// `direct_tls`, or the upstream did not authenticate.
        #[default]
        None => "none",
    }
}

/// How the request reached the Edge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamInfo {
    /// Configured upstream profile of the listener / site.
    pub profile: UpstreamProfileKind,
    /// `true` only if the upstream proved itself ([`UpstreamAuthMethod`]).
    /// Upstream-supplied headers are stripped unless this is `true`.
    pub authenticated: bool,
    /// Cloudflare `Cf-Ray`, logged in every event for correlation with Cloudflare logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_ray: Option<String>,
    pub auth_method: UpstreamAuthMethod,
    /// Authenticated, but the profile's client IP header (e.g.
    /// `CF-Connecting-IP`) was absent: configuration alarm, client IP unknown,
    /// no fallback to the upstream peer address.
    #[serde(skip_serializing_if = "is_false")]
    pub client_ip_header_missing: bool,
}

wire_enum! {
    /// Coarse network type of the client IP.
    #[derive(Default)]
    pub enum ConnType {
        Datacenter => "datacenter",
        Residential => "residential",
        Mobile => "mobile",
        Education => "education",
        #[default]
        Unknown => "unknown",
    }
}

wire_enum! {
    /// Where `net.ip` came from (docs/02 §7, docs/08).
    pub enum IpSource {
        /// TCP peer address (`direct_tls`, or an unauthenticated upstream).
        TcpPeer => "tcp_peer",
        CfConnectingIp => "cf_connecting_ip",
        /// Cloudflare Pseudo IPv4 = Overwrite.
        CfConnectingIpv6 => "cf_connecting_ipv6",
        ProxyV1 => "proxy_v1",
        ProxyV2 => "proxy_v2",
        CloudfrontViewerAddress => "cloudfront_viewer_address",
        GcpAlb => "gcp_alb",
        Esa => "esa",
        Edgeone => "edgeone",
        Alicdn => "alicdn",
        TencentCdn => "tencent_cdn",
        Gateway => "gateway",
    }
}

/// Network-layer facts about the (trusted) client address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Net {
    /// Client IP as resolved by the upstream profile's trust rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// `/24` (IPv4) or `/48` (IPv6) network of `ip`, e.g. `203.0.113.0/24`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_source: Option<IpSource>,
    /// From the local IP database (authoritative).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
    /// ISO 3166-1 alpha-2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub conn_type: ConnType,
    pub tor: bool,
    /// Upstream-reported ASN (`x-mg-cf-asn`), cross-check only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_asn: Option<u32>,
    /// Upstream-reported country (`cf-ipcountry`), cross-check only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_country: Option<String>,
    /// Upstream-reported region (`cf-region-code`), cross-check only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_region: Option<String>,
    /// Upstream-reported time zone (`cf-timezone`), weak geo-consistency signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_timezone: Option<String>,
    /// Client RTT reported by the upstream (`x-mg-cf-rtt` / `x-mg-cf-quic-rtt`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
}

impl Net {
    /// A `Net` for `ip` with `ip_prefix` filled in.
    pub fn for_ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            ip_prefix: Some(Self::prefix_of(ip)),
            ..Self::default()
        }
    }

    /// The aggregation prefix used for entity keys: `/24` for IPv4, `/48` for IPv6.
    pub fn prefix_of(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{a}.{b}.{c}.0/24")
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0);
                format!("{net}/48")
            }
        }
    }
}

/// JA4 (TLS client) fingerprint with its provenance (CEL `tls.ja4`).
/// JA4+ variants are feature-gated (`ja4plus`, licence, docs/01 §9).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ja4 {
    pub value: String,
    /// Who computed it: `SelfComputed` (the Edge) or an upstream such as
    /// `Cloudfront`. Forwarded values carry less weight than self-computed ones.
    pub source: SignalSource,
    /// Computed by the Edge itself, or forwarded by an authenticated upstream.
    pub authenticated: bool,
}

impl Ja4 {
    /// Whether the value may be scored: unauthenticated values are recorded only.
    pub fn is_scorable(&self) -> bool {
        self.authenticated && !self.value.is_empty()
    }
}

/// The visitor's own TLS handshake (TLS family), as seen by the Edge or
/// forwarded by an authenticated upstream. `available == false` whenever the
/// upstream hides it: the family is `MISSING` under `cloudflare`, which is
/// neutral, never human evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tls {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<Ja4>,
}

/// Coarse TLS profile forwarded by Cloudflare as `x-mg-cf-tls-*` (EDGE_TLS
/// family, CEL `edge_tls.*`): low weight, low cap, shadow first.
///
/// `cf.tls_client_random` is deliberately absent: the Edge may use it in
/// memory as a per-visitor-connection key, but it is never stored or logged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EdgeTls {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// Cipher list hash in received order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphers_sha1: Option<String>,
    /// Extension hash. Ordering and GREASE handling are undocumented: record
    /// only, never bind or weight highly until measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_sha1: Option<String>,
    /// ClientHello length; bucketed before use, also an input of `bind.ctp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_len: Option<u32>,
}

/// HTTP-layer facts. There is deliberately no HTTP/2 frame fingerprint field
/// (deferred indefinitely).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Http {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `SelfComputed` (negotiated by the Edge) or `Cloudflare` (`x-mg-cf-http-version`).
    pub version_source: SignalSource,
    pub method: String,
    pub host: String,
    pub path: String,
    /// Query parameter names only; values are never recorded.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub query_keys: Vec<String>,
    /// `direct_tls` HTTP/1 only; empty whenever the upstream does not preserve order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub header_order: Vec<String>,
    /// Header names with set semantics (`x-mg-cf-hdr-names` under `cloudflare`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub header_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Cookie names only. Cloudflare's own cookies are never evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cookie_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `Early-Data: 1`: the request may be a 0-RTT replay.
    #[serde(skip_serializing_if = "is_false")]
    pub early_data: bool,
    /// Tier 1 `x-mg-cf-priority` (browser HTTP/2 priority), weak.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Tier 1 `x-mg-cf-accept-encoding` (value before Cloudflare rewrote it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_encoding_orig: Option<String>,
}

wire_enum! {
    /// State of the MorphGate access token presented with the request.
    #[derive(Default)]
    pub enum TokenStatus {
        #[default]
        None => "none",
        Valid => "valid",
        Expired => "expired",
        Invalid => "invalid",
        BindingMismatch => "binding_mismatch",
        Replay => "replay",
    }
}

/// Access token level, the token's `lvl` claim (docs/04 §5).
///
/// JSON form: `invisible`, `pow`, `interactive`, `interactive_a11y` or
/// `interactive_ext:{provider}`. `attested` is reserved for the later mobile
/// SDK and deliberately not representable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenLevel {
    Invisible,
    Pow,
    /// Built-in `self_hold`.
    Interactive,
    /// `pow_a11y`: same human-evidence cap as `Interactive`, shorter TTL and a
    /// stricter quota.
    InteractiveA11y,
    /// An external provider ([`ProviderId::is_external`]).
    InteractiveExt(ProviderId),
}

impl TokenLevel {
    const EXT_PREFIX: &'static str = "interactive_ext:";

    /// The level an interactive challenge solved with `provider` earns.
    pub const fn for_provider(provider: ProviderId) -> Self {
        match provider {
            ProviderId::SelfHold => Self::Interactive,
            ProviderId::PowA11y => Self::InteractiveA11y,
            p => Self::InteractiveExt(p),
        }
    }

    /// "Interactive level" covers all three interactive forms; route
    /// requirements must never exclude the accessible path.
    pub const fn is_interactive(self) -> bool {
        matches!(
            self,
            Self::Interactive | Self::InteractiveA11y | Self::InteractiveExt(_)
        )
    }
}

impl fmt::Display for TokenLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invisible => f.write_str("invisible"),
            Self::Pow => f.write_str("pow"),
            Self::Interactive => f.write_str("interactive"),
            Self::InteractiveA11y => f.write_str("interactive_a11y"),
            Self::InteractiveExt(p) => write!(f, "{}{p}", Self::EXT_PREFIX),
        }
    }
}

impl FromStr for TokenLevel {
    type Err = UnknownVariant;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || UnknownVariant {
            type_name: "TokenLevel",
            value: s.into(),
        };
        Ok(match s {
            "invisible" => Self::Invisible,
            "pow" => Self::Pow,
            "interactive" => Self::Interactive,
            "interactive_a11y" => Self::InteractiveA11y,
            _ => {
                let provider: ProviderId = s
                    .strip_prefix(Self::EXT_PREFIX)
                    .ok_or_else(unknown)?
                    .parse()
                    .map_err(|_| unknown())?;
                if !provider.is_external() {
                    return Err(unknown());
                }
                Self::InteractiveExt(provider)
            }
        })
    }
}

impl Serialize for TokenLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TokenLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

wire_enum! {
    /// Result of one binding check.
    pub enum BindResult {
        Match => "match",
        Mismatch => "mismatch",
        /// Soft binding only (`ipp`): the IP prefix changed within the same
        /// ASN. A risk signal, not a failure (docs/04 §5).
        SoftMismatch => "soft_mismatch",
    }
}

/// Per-item binding check results for the presented token (docs/04 §5).
/// `None` = not bound or not checked. `ctp` is shadow only (never enforced).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenBind {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uah: Option<BindResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipp: Option<BindResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jkt: Option<BindResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctp: Option<BindResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfp: Option<BindResult>,
}

impl TokenBind {
    /// No binding was checked.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The MorphGate access token presented with the request (CEL `identity.token`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Token {
    pub status: TokenStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<TokenLevel>,
    /// Seconds since issuance; 0 without a token (CEL `identity.token.age`).
    #[serde(rename = "age")]
    pub age_s: u32,
    #[serde(skip_serializing_if = "TokenBind::is_empty")]
    pub bind: TokenBind,
}

/// Per-request proof of possession (docs/04 §6.1, CEL `identity.proof`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Proof {
    pub valid: bool,
    /// The proof's `jti` was seen before.
    #[serde(skip_serializing_if = "is_false")]
    pub replayed: bool,
}

/// Authorised AI agent (docs/05 §3-§4, CEL `identity.agent`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Agent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// How the agent authenticated, e.g. `web_bot_auth`, `http_message_signatures`, `mtls`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Crawler verification (docs/05 §3, CEL `identity.crawler`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Crawler {
    /// The request claims to be a known crawler (UA or signature).
    #[serde(skip_serializing_if = "is_false")]
    pub claimed: bool,
    /// Claimed operator id from the crawler registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// e.g. `search`, `ai_training`, `ai_agent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Verified by MorphGate itself (signature, official IP ranges, rDNS).
    pub verified: bool,
    /// Cloudflare verified-bot flag (`x-mg-cf-vbot`). Corroboration only: it
    /// never decides a class, an allow or a block on its own. `None` when not
    /// forwarded (MISSING).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_vbot: Option<bool>,
    /// Cloudflare verified-bot category (`x-mg-cf-vbot-cat`), corroboration only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_vbot_cat: Option<String>,
}

/// Identity layer (L0, CEL `identity.*`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub token: Token,
    pub proof: Proof,
    pub agent: Agent,
    pub crawler: Crawler,
}

/// CLIENT family summary the Edge derives from the session's verified SDK
/// telemetry (docs/03 §3.6, docs/04 §7). Raw telemetry never appears here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSignals {
    /// Seconds since the last verified telemetry batch.
    pub telemetry_age_s: u32,
    /// Stable ids of automation markers, e.g. `webdriver`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub automation_flags: Vec<String>,
    /// Failed environment consistency checks, e.g. `tz_vs_ip`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_mismatches: Vec<String>,
    /// SDK tampering / execution integrity check failed.
    #[serde(skip_serializing_if = "is_false")]
    pub integrity_failed: bool,
    /// `cf-mitigated` challenges the SDK reported (docs/08 §2.8); excluded
    /// from "SDK never ran" and from MorphGate failure counts.
    #[serde(skip_serializing_if = "is_zero")]
    pub upstream_challenges: u32,
    /// IANA time zone reported by the SDK; weak geo cross-check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Everything the Decision Core knows about one request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestContext {
    pub request_id: String,
    /// Request arrival time, Unix epoch milliseconds, supplied by the host.
    /// Every time-dependent rule (verdict expiry, token age) uses this value.
    pub ts_ms: i64,
    pub site_id: String,
    pub env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    pub channel: Channel,
    pub upstream: UpstreamInfo,
    pub net: Net,
    pub tls: Tls,
    /// Present only when an authenticated Cloudflare upstream forwarded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_tls: Option<EdgeTls>,
    pub http: Http,
    pub identity: Identity,
    /// Pseudonymous session id (the clearance `sub`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Families actually present for this request.
    pub availability_mask: FamilyMask,
    /// Families this request's upstream profile is expected to supply.
    pub expected_mask: FamilyMask,
    /// `None` until the session has verified SDK telemetry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientSignals>,
    /// Near-line verdicts fetched for this request's entities. May include
    /// expired entries; judge them with [`EntityVerdict::is_active`] against
    /// `ts_ms`. Carrying them here makes every decision reproducible from its
    /// event.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verdicts: Vec<EntityVerdict>,
}

impl RequestContext {
    /// Minimal context: identifiers and the host-supplied timestamp.
    pub fn new(request_id: impl Into<String>, site_id: impl Into<String>, ts_ms: i64) -> Self {
        Self {
            request_id: request_id.into(),
            site_id: site_id.into(),
            ts_ms,
            ..Self::default()
        }
    }

    /// Whether `family` is available for this request.
    pub fn has(&self, family: SignalFamily) -> bool {
        self.availability_mask.contains(family)
    }

    /// Expected-but-unavailable families (see [`FamilyMask::absent`]).
    pub fn absent_families(&self) -> FamilyMask {
        FamilyMask::absent(self.availability_mask, self.expected_mask)
    }

    /// Verdicts that are still active at the request time.
    pub fn active_verdicts(&self) -> impl Iterator<Item = &EntityVerdict> {
        self.verdicts.iter().filter(|v| v.is_active(self.ts_ms))
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::EntityType;
    use crate::values::Score;
    use SignalFamily as F;

    fn sample() -> RequestContext {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        RequestContext {
            env: "production".into(),
            route_id: Some("login".into()),
            channel: Channel::Web,
            upstream: UpstreamInfo {
                profile: UpstreamProfileKind::Cloudflare,
                authenticated: true,
                cf_ray: Some("8f00000000000000-HKG".into()),
                auth_method: UpstreamAuthMethod::Loopback,
                client_ip_header_missing: false,
            },
            net: Net {
                ip_source: Some(IpSource::CfConnectingIp),
                asn: Some(64500),
                country: Some("HK".into()),
                conn_type: ConnType::Residential,
                upstream_asn: Some(64500),
                upstream_timezone: Some("Asia/Hong_Kong".into()),
                rtt_ms: Some(23),
                ..Net::for_ip(ip)
            },
            edge_tls: Some(EdgeTls {
                version: Some("TLSv1.3".into()),
                ext_sha1: Some("3zN0vNnT0h1r1TmXnq4B3Ic1S0c=".into()),
                hello_len: Some(512),
                ..EdgeTls::default()
            }),
            http: Http {
                version: Some("HTTP/2".into()),
                version_source: SignalSource::Cloudflare,
                method: "POST".into(),
                host: "example.com".into(),
                path: "/api/login".into(),
                query_keys: vec!["next".into()],
                header_names: vec!["accept".into(), "user-agent".into()],
                ..Http::default()
            },
            identity: Identity {
                token: Token {
                    status: TokenStatus::Valid,
                    level: Some(TokenLevel::InteractiveExt(ProviderId::Turnstile)),
                    age_s: 120,
                    bind: TokenBind {
                        uah: Some(BindResult::Match),
                        ctp: Some(BindResult::Mismatch),
                        ..TokenBind::default()
                    },
                },
                crawler: Crawler {
                    cf_vbot: Some(false),
                    ..Crawler::default()
                },
                ..Identity::default()
            },
            availability_mask: FamilyMask::of(&[F::Network, F::Http, F::EdgeTls]),
            expected_mask: FamilyMask::of(&[F::Network, F::Http, F::EdgeTls, F::External]),
            client: Some(ClientSignals {
                telemetry_age_s: 4,
                automation_flags: vec!["webdriver".into()],
                ..ClientSignals::default()
            }),
            verdicts: vec![EntityVerdict {
                entity_type: EntityType::Prefix,
                key: "203.0.113.0/24".into(),
                risk: Score::new(40),
                expires_at_ms: 1_758_000_060_000,
                site_id: EntityVerdict::ALL_SITES.into(),
                ..EntityVerdict::default()
            }],
            ..RequestContext::new("req-1", "blog", 1_758_000_000_000)
        }
    }

    #[test]
    fn serde_round_trip() {
        let ctx = sample();
        let json = serde_json::to_string(&ctx).unwrap();
        assert_eq!(serde_json::from_str::<RequestContext>(&json).unwrap(), ctx);
    }

    #[test]
    fn json_is_snake_case_and_omits_absent_values() {
        let v = serde_json::to_value(sample()).unwrap();
        assert_eq!(v["upstream"]["profile"], "cloudflare");
        assert_eq!(v["upstream"]["auth_method"], "loopback");
        assert!(v["upstream"].get("client_ip_header_missing").is_none());
        assert_eq!(v["net"]["ip"], "203.0.113.7");
        assert_eq!(v["net"]["ip_prefix"], "203.0.113.0/24");
        assert_eq!(v["net"]["ip_source"], "cf_connecting_ip");
        assert_eq!(v["net"]["conn_type"], "residential");
        assert_eq!(v["net"]["rtt_ms"], 23);
        assert_eq!(v["edge_tls"]["ext_sha1"], "3zN0vNnT0h1r1TmXnq4B3Ic1S0c=");
        assert_eq!(v["edge_tls"]["hello_len"], 512);
        assert_eq!(v["http"]["version_source"], "cloudflare");
        assert_eq!(v["identity"]["token"]["status"], "valid");
        assert_eq!(v["identity"]["token"]["level"], "interactive_ext:turnstile");
        assert_eq!(v["identity"]["token"]["age"], 120);
        assert_eq!(v["identity"]["token"]["bind"]["uah"], "match");
        assert_eq!(v["identity"]["token"]["bind"]["ctp"], "mismatch");
        assert_eq!(v["identity"]["proof"]["valid"], false);
        assert_eq!(v["identity"]["crawler"]["cf_vbot"], false);
        assert_eq!(v["client"]["automation_flags"][0], "webdriver");
        assert_eq!(v["verdicts"][0]["site_id"], "all");
        assert_eq!(v["availability_mask"], (1 << 1) | (1 << 3) | (1 << 9));
        assert!(
            v["tls"].get("ja4").is_none(),
            "absent optionals are omitted"
        );
        assert!(
            v["identity"]["crawler"].get("cf_vbot_cat").is_none(),
            "absent optionals are omitted"
        );
        assert!(
            v["http"].get("header_order").is_none(),
            "empty lists are omitted"
        );
        assert!(
            v["http"].get("early_data").is_none(),
            "false flags are omitted"
        );
    }

    #[test]
    fn partial_json_fills_defaults() {
        let ctx: RequestContext =
            serde_json::from_str(r#"{"request_id":"r","ts_ms":5,"site_id":"s"}"#).unwrap();
        assert_eq!(ctx, RequestContext::new("r", "s", 5));
        assert_eq!(ctx.upstream.auth_method, UpstreamAuthMethod::None);
        assert_eq!(ctx.identity.token.status, TokenStatus::None);
        assert!(ctx.client.is_none() && ctx.verdicts.is_empty());
    }

    #[test]
    fn absent_families_uses_masks() {
        let ctx = sample();
        assert!(ctx.has(F::EdgeTls));
        assert!(!ctx.has(F::Tls));
        assert_eq!(ctx.absent_families(), FamilyMask::of(&[F::External]));
    }

    #[test]
    fn active_verdicts_follow_request_time() {
        let mut ctx = sample();
        assert_eq!(ctx.active_verdicts().count(), 1);
        ctx.ts_ms = 1_758_000_060_000;
        assert_eq!(ctx.active_verdicts().count(), 0);
    }

    #[test]
    fn ja4_is_scored_only_when_authenticated() {
        let mut ja4 = Ja4 {
            value: "t13d1516h2_8daaf6152771_02713d6af862".into(),
            source: SignalSource::Cloudfront,
            authenticated: false,
        };
        assert!(!ja4.is_scorable());
        ja4.authenticated = true;
        assert!(ja4.is_scorable());
        ja4.value.clear();
        assert!(!ja4.is_scorable());
        let tls = Tls {
            available: true,
            ja4: Some(Ja4 {
                value: "x".into(),
                source: SignalSource::SelfComputed,
                authenticated: true,
            }),
            ..Tls::default()
        };
        let v = serde_json::to_value(&tls).unwrap();
        assert_eq!(
            v["ja4"],
            serde_json::json!({"value": "x", "source": "self", "authenticated": true})
        );
    }

    #[test]
    fn token_levels_match_docs() {
        let cases = [
            (TokenLevel::Invisible, "invisible"),
            (TokenLevel::Pow, "pow"),
            (TokenLevel::Interactive, "interactive"),
            (TokenLevel::InteractiveA11y, "interactive_a11y"),
            (
                TokenLevel::InteractiveExt(ProviderId::Turnstile),
                "interactive_ext:turnstile",
            ),
            (
                TokenLevel::InteractiveExt(ProviderId::Tencent),
                "interactive_ext:tencent",
            ),
            (
                TokenLevel::InteractiveExt(ProviderId::AliyunV2),
                "interactive_ext:aliyun_v2",
            ),
        ];
        for (level, s) in cases {
            assert_eq!(level.to_string(), s);
            assert_eq!(s.parse::<TokenLevel>().unwrap(), level);
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, format!("\"{s}\""));
            assert_eq!(serde_json::from_str::<TokenLevel>(&json).unwrap(), level);
        }
        for bad in [
            "attested",
            "interactive_ext:",
            "interactive_ext:self_hold",
            "interactive_ext:pow_a11y",
            "interactive_ext:hcaptcha",
            "INTERACTIVE",
        ] {
            assert!(bad.parse::<TokenLevel>().is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<TokenLevel>("\"attested\"").is_err());
    }

    #[test]
    fn token_level_for_provider_and_interactive_class() {
        assert_eq!(
            TokenLevel::for_provider(ProviderId::SelfHold),
            TokenLevel::Interactive
        );
        assert_eq!(
            TokenLevel::for_provider(ProviderId::PowA11y),
            TokenLevel::InteractiveA11y
        );
        assert_eq!(
            TokenLevel::for_provider(ProviderId::AliyunV2),
            TokenLevel::InteractiveExt(ProviderId::AliyunV2)
        );
        for p in ProviderId::ALL {
            assert!(TokenLevel::for_provider(*p).is_interactive());
            // Every provider's level survives a string round trip.
            let level = TokenLevel::for_provider(*p);
            assert_eq!(level.to_string().parse::<TokenLevel>().unwrap(), level);
        }
        assert!(!TokenLevel::Invisible.is_interactive());
        assert!(!TokenLevel::Pow.is_interactive());
    }

    #[test]
    fn upstream_auth_methods_match_docs() {
        let names: Vec<_> = UpstreamAuthMethod::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            names,
            [
                "loopback",
                "origin_mtls",
                "secret_header",
                "src_cidr",
                "none"
            ]
        );
        assert_eq!(UpstreamAuthMethod::default(), UpstreamAuthMethod::None);
    }

    #[test]
    fn prefixes() {
        assert_eq!(
            Net::prefix_of("192.0.2.200".parse().unwrap()),
            "192.0.2.0/24"
        );
        assert_eq!(
            Net::prefix_of("2001:db8:abcd:1234::1".parse().unwrap()),
            "2001:db8:abcd::/48"
        );
    }
}
