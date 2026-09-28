//! Upstream trust (docs/impl/phase1-spec.md §9.2, §9.3, §9.3.2; work
//! package WP-C1).
//!
//! * [`is_upstream_family`]: the known upstream header families that the
//!   Edge strips from every request before forwarding (§9.3 step 5), matched
//!   after lower-casing and mapping `_` to `-`, because CGI-style origins
//!   treat `CF_Connecting_IP` and `CF-Connecting-IP` as the same variable.
//! * [`connection_listed`] / [`hop_by_hop`]: hop-by-hop headers (§9.3
//!   step 3). A client must not be able to list `MG-Client-IP` or
//!   `X-Forwarded-For` in `Connection` and so make a proxy between the Edge
//!   and the origin delete what the Edge wrote (D-34).
//! * [`parse_cloudflare`]: the `cloudflare` trusted-header table of §9.3,
//!   applied only to requests whose upstream authenticated (§9.2). Only the
//!   exact hyphenated names are read (compared ASCII-case-insensitively, as
//!   HTTP field names are); underscore spellings are never parsed, only
//!   stripped. Every invalid value counts as missing.
//! * [`secret_header_ok`]: the `x-mg-upstream-key` check (§9.2), constant
//!   time with respect to the accepted values.
//!
//! Privacy (D-31, §2.4 item 5): nothing here logs, and the `Debug` output of
//! [`ClientIp`] (and so of [`CfHeaders`]) never shows the client address.
//! `x-mg-cf-tls-random` is validated only; its value is not kept anywhere.

use crate::request::{CiKey, is_dns_name, is_tchar};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use mg_core::{EdgeTls, IpSource};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use subtle::{Choice, ConstantTimeEq};

/// Prefixes of the known upstream header families (§9.3), in the normalized
/// form that [`is_upstream_family`] compares against.
pub const FAMILY_PREFIXES: [&str; 8] = [
    "cf-",
    "x-mg-",
    "cloudfront-",
    "ali-",
    "esa-",
    "eo-",
    "x-forwarded-",
    "mg-",
];

/// Full names of the known upstream header families (§9.3), normalized.
pub const FAMILY_NAMES: [&str; 7] = [
    "tls-ja3",
    "tls-ja4",
    "tls-hash",
    "x-forward-port",
    "forwarded",
    "true-client-ip",
    "x-real-ip",
];

/// Hop-by-hop headers removed besides `Connection` and the names it lists
/// (§9.3 step 3). `upgrade` is kept for a WebSocket upgrade ([`hop_by_hop`]).
pub const HOP_BY_HOP: [&str; 4] = ["keep-alive", "proxy-connection", "te", "upgrade"];

/// The HTTP/1 message framing fields. A `Connection` listing never removes
/// them ([`hop_by_hop`]): the proxy reads the request body by this framing
/// (Pingora 0.9 decides how to read the body from the request header as it
/// stands when the body is first read), so removing `Content-Length` or
/// `Transfer-Encoding` would make the body look empty and leave it on the
/// connection to be parsed as a second, smuggled request.
pub const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];

/// Whether `name` belongs to a known upstream header family (§9.3): after
/// ASCII lower-casing and replacing `_` with `-`, it starts with one of
/// [`FAMILY_PREFIXES`] or equals one of [`FAMILY_NAMES`]. So
/// `CF_Connecting_IP`, `X_MG_CF_ASN` and `mg_bot_score` match too.
pub fn is_upstream_family(name: &str) -> bool {
    let name = name.as_bytes();
    FAMILY_PREFIXES
        .iter()
        .any(|prefix| name.len() >= prefix.len() && eq_normalized(&name[..prefix.len()], prefix))
        || FAMILY_NAMES
            .iter()
            .any(|full| name.len() == full.len() && eq_normalized(name, full))
}

/// `raw` equals `canonical` (lower-case, hyphenated) after lower-casing `raw`
/// and mapping `_` to `-`. Both have the same length.
fn eq_normalized(raw: &[u8], canonical: &str) -> bool {
    raw.iter().zip(canonical.as_bytes()).all(|(&r, &c)| {
        let r = if r == b'_' {
            b'-'
        } else {
            r.to_ascii_lowercase()
        };
        r == c
    })
}

/// The header names listed by the request's `Connection` field(s),
/// lower-cased, distinct, in order of first appearance (§9.3 step 3).
/// Entries that are not RFC 9110 tokens are skipped (no field can have such
/// a name). The caller removes every listed header and `Connection` itself
/// before it writes the Edge's own origin headers. Use [`hop_by_hop`] for
/// the step-3 removal list: it leaves listed upstream-family names to step 5
/// so that they cannot be hidden from [`parse_cloudflare`].
pub fn connection_listed(headers: &[(&str, &[u8])]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut listed = Vec::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        for token in value.split(|&b| b == b',').map(trim_ows) {
            if token.is_empty() || !token.iter().copied().all(is_tchar) {
                continue;
            }
            // tchar is ASCII, so this cannot fail.
            let Ok(token) = std::str::from_utf8(token) else {
                continue;
            };
            let token = token.to_ascii_lowercase();
            if seen.insert(token.clone()) {
                listed.push(token);
            }
        }
    }
    listed
}

/// Every header name §9.3 step 3 removes from the client request,
/// lower-cased and distinct: `connection`, each name it lists
/// ([`connection_listed`]) and [`HOP_BY_HOP`], except that `upgrade` is kept
/// for a WebSocket upgrade (an `Upgrade` field offering `websocket` and
/// `Connection` listing `upgrade`). For such a request the caller forwards
/// `Connection: upgrade` itself; the client's `Connection` field is never
/// forwarded. Listed end-to-end names such as `host` are returned too:
/// removing those can only take away the client's own input (a request
/// whose `Host` is removed before §9.4 resolves it gets a 400), never a
/// header the Edge writes afterwards. The [`FRAMING`] fields are the
/// exception: a listing of `Content-Length` or `Transfer-Encoding` is
/// ignored, because removing them would desynchronise the request body from
/// the connection (request smuggling).
///
/// Listed upstream-family names ([`is_upstream_family`]) are the exception:
/// step 5 strips every one of them anyway, and removing them here, before
/// [`parse_cloudflare`] runs (step 4), would let a `Connection: CF-Worker`
/// hide a foreign Worker from the §9.4 step 4 check (D-23) or make any
/// trusted signal MISSING. So a Connection listing never changes what the
/// trusted-header parser sees.
pub fn hop_by_hop(headers: &[(&str, &[u8])]) -> Vec<String> {
    let listed = connection_listed(headers);
    let websocket = listed.iter().any(|name| name == "upgrade") && offers_websocket(headers);
    let mut names = vec!["connection".to_owned()];
    let extra = HOP_BY_HOP
        .iter()
        .filter(|name| !listed.iter().any(|listed| listed.as_str() == **name))
        .map(|name| (*name).to_owned());
    for name in listed.iter().cloned().chain(extra) {
        if name == "connection"
            || (websocket && name == "upgrade")
            || is_upstream_family(&name)
            || FRAMING.contains(&name.as_str())
        {
            continue;
        }
        names.push(name);
    }
    names
}

/// Whether an `Upgrade` field offers `websocket` (`protocol-name` compared
/// case-insensitively, any `/version`).
fn offers_websocket(headers: &[(&str, &[u8])]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        .flat_map(|(_, value)| value.split(|&b| b == b','))
        .map(trim_ows)
        .any(|protocol| {
            let name = protocol.split(|&b| b == b'/').next().unwrap_or(protocol);
            name.eq_ignore_ascii_case(b"websocket")
        })
}

/// Strips RFC 9110 optional whitespace (SP / HTAB) from both ends.
fn trim_ows(value: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = value.iter().position(|b| !is_ows(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !is_ows(b))
        .map_or(start, |i| i + 1);
    &value[start..end]
}

/// Cloudflare properties of the site a request is for: from the signed
/// bundle (`SiteBundle.cloudflare`, D-14), or from `edge.toml` while the
/// site is still in `bootstrap` (I-4: `bootstrap_owner_zones`, otherwise no
/// owner zones, so every `CF-Worker` is foreign).
#[derive(Debug, Clone, Copy)]
pub struct CloudflareSite<'a> {
    /// "Add visitor location headers" is confirmed on for the zone: parse
    /// `cf-ipcountry`, `cf-region-code` and `cf-timezone`.
    pub location_headers: bool,
    /// A Tier 1 forwarder (Snippet or Worker) is deployed: parse the Tier 1
    /// headers when `x-mg-cf-t1` says it ran.
    pub tier1: bool,
    /// Zones whose Worker subrequests are the owner's own.
    pub owner_zones: &'a [String],
    /// Pseudo IPv4 = Overwrite: the real address is in `cf-connecting-ipv6`.
    pub pseudo_ipv4_overwrite: bool,
}

/// The client address of a `cloudflare` request (§9.3, §9.3.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientIp {
    /// A valid address (IPv4-mapped IPv6 already turned into IPv4) and the
    /// header it came from (`cf_connecting_ip` or `cf_connecting_ipv6`).
    Known(IpAddr, IpSource),
    /// No usable `cf-connecting-ip`: the request continues with the client
    /// IP unknown (label `client_ip_unknown`, NETWORK family MISSING, one
    /// `mg_cf_connecting_ip_missing_total`). `header_missing` is the value of
    /// `upstream.client_ip_header_missing` (§9.5); [`parse_cloudflare`]
    /// always sets it to `true`, because the §9.3 table sets
    /// `client_ip_header_missing = true` for an absent and an invalid header
    /// alike (a repeated one is invalid). `false` is never produced in
    /// Phase 1 (the original draft used it for foreign Workers, which D-23
    /// now rejects with 403).
    Unknown { header_missing: bool },
}

impl ClientIp {
    /// The address, when known.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Known(ip, _) => Some(*ip),
            Self::Unknown { .. } => None,
        }
    }

    /// Where the address came from, when known.
    pub fn source(&self) -> Option<IpSource> {
        match self {
            Self::Known(_, source) => Some(*source),
            Self::Unknown { .. } => None,
        }
    }
}

/// Never prints the address (D-31).
impl fmt::Debug for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(ip, source) => {
                let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
                write!(f, "Known(<redacted {family}>, {source:?})")
            }
            Self::Unknown { header_missing } => f
                .debug_struct("Unknown")
                .field("header_missing", header_missing)
                .finish(),
        }
    }
}

/// Whose Worker sent the request (`cf-worker`, §9.3, §9.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerZone {
    /// No `cf-worker` header: not a Worker subrequest.
    None,
    /// A Worker of one of [`CloudflareSite::owner_zones`].
    Owner,
    /// Any other zone, an invalid value, or several `cf-worker` fields: the
    /// Edge answers 403 at §9.4 step 4 (D-23), before any decision.
    Foreign,
}

/// Which Tier 1 forwarder ran (`x-mg-cf-t1`, docs/08 §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier1Source {
    Snippet,
    Worker,
}

impl Tier1Source {
    /// The marker value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snippet => "snippet",
            Self::Worker => "worker",
        }
    }
}

/// Tier 1 values (§9.3), present only when the site has Tier 1 enabled and
/// the request carries a valid `x-mg-cf-t1` marker. Each field is `None`
/// (MISSING) when its header is absent or invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier1 {
    pub source: Tier1Source,
    /// `x-mg-cf-priority` → `http.priority`.
    pub priority: Option<String>,
    /// `x-mg-cf-accept-encoding` → `http.accept_encoding_orig`.
    pub accept_encoding_orig: Option<String>,
    /// `x-mg-cf-as-org`, percent-decoded → the `net.as_org` cross-check
    /// value (recorded only in Phase 1).
    pub as_org: Option<String>,
}

/// The trusted `cloudflare` headers of one authenticated request (§9.3).
/// `None` means missing or invalid; the caller maps that to MISSING per
/// §4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfHeaders {
    /// `cf-connecting-ip` (or `cf-connecting-ipv6` under Pseudo IPv4 =
    /// Overwrite) → `net.ip`, `net.ip_source`.
    pub client_ip: ClientIp,
    /// `cf-worker` → the §9.4 step 4 check.
    pub worker: WorkerZone,
    /// `cf-ray` → `upstream.cf_ray`.
    pub cf_ray: Option<String>,
    /// `cf-visitor` scheme; `true` (https) when absent or invalid. Drives the
    /// EDGE_TLS alarms here, `X-Forwarded-Proto` and the §9.9 308 redirect.
    pub visitor_https: bool,
    /// `x-mg-cf-tls-*` → `edge_tls`; `Some` when at least one field is valid.
    pub edge_tls: Option<EdgeTls>,
    /// `x-mg-cf-http-version` → `http.version` (source `cloudflare`).
    pub http_version: Option<String>,
    /// `x-mg-cf-quic-rtt` for HTTP/3, else `x-mg-cf-rtt` → `net.rtt_ms`.
    pub rtt_ms: Option<u32>,
    /// `x-mg-cf-asn` → `net.upstream_asn`.
    pub upstream_asn: Option<u32>,
    /// `cf-ipcountry` (location headers only; `XX` is missing) →
    /// `net.upstream_country`. `T1` (Tor) is kept as reported; see
    /// [`CfHeaders::is_tor`].
    pub upstream_country: Option<String>,
    /// `cf-region-code` (location headers only) → `net.upstream_region`.
    pub upstream_region: Option<String>,
    /// `cf-timezone` (location headers only) → `net.upstream_timezone`.
    pub upstream_timezone: Option<String>,
    /// `x-mg-cf-vbot` → `identity.crawler.cf_vbot`.
    pub cf_vbot: Option<bool>,
    /// `x-mg-cf-vbot-cat` → `identity.crawler.cf_vbot_cat`.
    pub cf_vbot_cat: Option<String>,
    /// `x-mg-cf-hdr-names` → `http.header_names`: distinct names
    /// (case-insensitively, first spelling kept), original case.
    pub header_names: Option<Vec<String>>,
    /// Tier 1 values; `None` when Tier 1 is off for the site or the marker is
    /// absent or invalid (all Tier 1 fields MISSING, no alarm).
    pub tier1: Option<Tier1>,
    /// `signal` label values for `mg_upstream_signal_missing_total{profile=
    /// "cloudflare", signal}`: the header name without `x-mg-cf-`, in §9.3
    /// table order. TLS signals alarm only for https visitors; the RTT alarm
    /// is for the one header that applies (`quic-rtt` for HTTP/3, else
    /// `rtt`); `vbot-cat` and Tier 1 never alarm.
    pub missing_signals: Vec<&'static str>,
}

impl CfHeaders {
    /// `cf-ipcountry: T1`, one of the two sources of `net.tor` (§4.1).
    pub fn is_tor(&self) -> bool {
        self.upstream_country.as_deref() == Some("T1")
    }
}

/// The trusted names of the §9.3 table, indexed by [`H`].
const TRUSTED: [&str; 25] = [
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ray",
    "cf-visitor",
    "cf-worker",
    "cf-ipcountry",
    "cf-region-code",
    "cf-timezone",
    "x-mg-cf-tls-version",
    "x-mg-cf-tls-cipher",
    "x-mg-cf-tls-ciphers-sha1",
    "x-mg-cf-tls-ext-sha1",
    "x-mg-cf-tls-hello-len",
    "x-mg-cf-tls-random",
    "x-mg-cf-http-version",
    "x-mg-cf-rtt",
    "x-mg-cf-quic-rtt",
    "x-mg-cf-asn",
    "x-mg-cf-vbot",
    "x-mg-cf-vbot-cat",
    "x-mg-cf-hdr-names",
    "x-mg-cf-t1",
    "x-mg-cf-priority",
    "x-mg-cf-accept-encoding",
    "x-mg-cf-as-org",
];

/// Index into [`TRUSTED`].
#[derive(Debug, Clone, Copy)]
enum H {
    ConnectingIp,
    ConnectingIpv6,
    Ray,
    Visitor,
    Worker,
    IpCountry,
    RegionCode,
    Timezone,
    TlsVersion,
    TlsCipher,
    TlsCiphersSha1,
    TlsExtSha1,
    TlsHelloLen,
    TlsRandom,
    HttpVersion,
    Rtt,
    QuicRtt,
    Asn,
    Vbot,
    VbotCat,
    HdrNames,
    T1,
    Priority,
    AcceptEncoding,
    AsOrg,
}

impl H {
    /// The `signal` label: the header name without `x-mg-cf-`.
    fn signal(self) -> &'static str {
        let name = TRUSTED[self as usize];
        name.strip_prefix("x-mg-cf-").unwrap_or(name)
    }
}

/// How often a trusted header occurred. Deliberately not `Debug`: it holds
/// raw values such as `x-mg-cf-tls-random` (D-31).
#[derive(Clone, Copy)]
enum Seen<'a> {
    Absent,
    Once(&'a [u8]),
    /// Repeated: ambiguous, so treated as invalid.
    Repeated,
}

/// The trusted headers of one request, located in a single pass (not
/// `Debug`, like [`Seen`]).
struct Trusted<'a>([Seen<'a>; TRUSTED.len()]);

impl<'a> Trusted<'a> {
    fn collect(headers: &[(&str, &'a [u8])]) -> Self {
        let mut slots = [Seen::Absent; TRUSTED.len()];
        for (name, value) in headers {
            let first = name.as_bytes().first().map(u8::to_ascii_lowercase);
            if !matches!(first, Some(b'c' | b'x')) {
                continue;
            }
            let Some(index) = TRUSTED
                .iter()
                .position(|trusted| name.eq_ignore_ascii_case(trusted))
            else {
                continue;
            };
            slots[index] = match slots[index] {
                Seen::Absent => Seen::Once(trim_ows(value)),
                Seen::Once(_) | Seen::Repeated => Seen::Repeated,
            };
        }
        Self(slots)
    }

    fn seen(&self, h: H) -> Seen<'a> {
        self.0[h as usize]
    }

    /// The value of a header that occurred exactly once.
    fn once(&self, h: H) -> Option<&'a [u8]> {
        match self.seen(h) {
            Seen::Once(value) => Some(value),
            Seen::Absent | Seen::Repeated => None,
        }
    }

    fn parse<T>(&self, h: H, parse: impl FnOnce(&'a [u8]) -> Option<T>) -> Option<T> {
        self.once(h).and_then(parse)
    }
}

/// Parses the `cloudflare` trusted headers of an authenticated request
/// (§9.3 table, §9.3.2). `headers` is every client header field line in
/// arrival order, before family stripping (step 5): either the raw request
/// or the request after removing [`hop_by_hop`] (step 3), which never
/// removes a trusted name. Do not remove every [`connection_listed`] name
/// first: a `Connection: CF-Worker` must not hide a foreign Worker. A
/// trusted header that occurs more than once is invalid (missing). Never
/// fails: invalid values are missing.
pub fn parse_cloudflare(headers: &[(&str, &[u8])], site: &CloudflareSite<'_>) -> CfHeaders {
    let t = Trusted::collect(headers);
    let mut missing_signals = Vec::new();

    let client_ip = client_ip(&t, site.pseudo_ipv4_overwrite);
    let worker = match t.seen(H::Worker) {
        Seen::Absent => WorkerZone::None,
        Seen::Repeated => WorkerZone::Foreign,
        Seen::Once(zone) => worker_zone(zone, site.owner_zones),
    };
    let cf_ray = t.parse(H::Ray, |v| {
        charset(v, 64, |b| b.is_ascii_alphanumeric() || b == b'-')
    });
    let visitor_https = t.parse(H::Visitor, visitor_scheme_https).unwrap_or(true);

    // EDGE_TLS: alarms only for https visitors (plain-http visitors have no
    // TLS handshake with Cloudflare, so the Transform Rule sets nothing).
    let mut tls_signal = |h: H, valid: bool| {
        if !valid && visitor_https {
            missing_signals.push(h.signal());
        }
    };
    let version = t.parse(H::TlsVersion, |v| {
        charset(v, 16, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
        })
    });
    tls_signal(H::TlsVersion, version.is_some());
    let cipher = t.parse(H::TlsCipher, |v| {
        charset(v, 64, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
        })
    });
    tls_signal(H::TlsCipher, cipher.is_some());
    let ciphers_sha1 = t.parse(H::TlsCiphersSha1, |v| canonical_base64(v, 20));
    tls_signal(H::TlsCiphersSha1, ciphers_sha1.is_some());
    let ext_sha1 = t.parse(H::TlsExtSha1, |v| canonical_base64(v, 20));
    tls_signal(H::TlsExtSha1, ext_sha1.is_some());
    let hello_len = t
        .parse(H::TlsHelloLen, |v| decimal(v, 65_535))
        .filter(|len| *len >= 1)
        .and_then(|len| u32::try_from(len).ok());
    tls_signal(H::TlsHelloLen, hello_len.is_some());
    // Validated only: the value never leaves this function (D-31).
    let tls_random_valid = t.parse(H::TlsRandom, |v| canonical_base64(v, 32)).is_some();
    tls_signal(H::TlsRandom, tls_random_valid);
    let edge_tls = EdgeTls {
        version,
        cipher,
        ciphers_sha1,
        ext_sha1,
        hello_len,
    };
    let edge_tls = (edge_tls != EdgeTls::default()).then_some(edge_tls);

    let http_version = t.parse(H::HttpVersion, |v| {
        ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"]
            .into_iter()
            .find(|version| v == version.as_bytes())
            .map(str::to_owned)
    });
    if http_version.is_none() {
        missing_signals.push(H::HttpVersion.signal());
    }
    let rtt_header = if http_version.as_deref() == Some("HTTP/3") {
        H::QuicRtt
    } else {
        H::Rtt
    };
    let rtt_ms = t
        .parse(rtt_header, |v| decimal(v, 60_000))
        .filter(|rtt| *rtt != 0)
        .and_then(|rtt| u32::try_from(rtt).ok());
    if rtt_ms.is_none() {
        missing_signals.push(rtt_header.signal());
    }
    let upstream_asn = t
        .parse(H::Asn, |v| decimal(v, u64::from(u32::MAX)))
        .filter(|asn| *asn >= 1)
        .and_then(|asn| u32::try_from(asn).ok());
    if upstream_asn.is_none() {
        missing_signals.push(H::Asn.signal());
    }
    let cf_vbot = t.parse(H::Vbot, |v| match v {
        b"true" => Some(true),
        b"false" => Some(false),
        _ => None,
    });
    if cf_vbot.is_none() {
        missing_signals.push(H::Vbot.signal());
    }
    let cf_vbot_cat = t.parse(H::VbotCat, |v| {
        charset(v, 64, |b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b' ' | b'(' | b')' | b'/' | b'&' | b'.' | b',' | b'_' | b'-'
                )
        })
    });
    let header_names = t.parse(H::HdrNames, header_name_set);
    if header_names.is_none() {
        missing_signals.push(H::HdrNames.signal());
    }

    let (upstream_country, upstream_region, upstream_timezone) = if site.location_headers {
        (
            t.parse(H::IpCountry, country),
            t.parse(H::RegionCode, |v| printable(v, 64)),
            t.parse(H::Timezone, |v| {
                charset(v, 64, |b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-')
                })
            }),
        )
    } else {
        (None, None, None)
    };

    let tier1_source = if site.tier1 {
        t.parse(H::T1, |v| match v {
            b"snippet" => Some(Tier1Source::Snippet),
            b"worker" => Some(Tier1Source::Worker),
            _ => None,
        })
    } else {
        None
    };
    let tier1 = tier1_source.map(|source| Tier1 {
        source,
        priority: t.parse(H::Priority, |v| {
            charset(v, 128, |b| {
                b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b',' | b'.' | b'_' | b'-')
            })
        }),
        accept_encoding_orig: t.parse(H::AcceptEncoding, |v| printable(v, 256)),
        as_org: t.parse(H::AsOrg, as_org),
    });

    CfHeaders {
        client_ip,
        worker,
        cf_ray,
        visitor_https,
        edge_tls,
        http_version,
        rtt_ms,
        upstream_asn,
        upstream_country,
        upstream_region,
        upstream_timezone,
        cf_vbot,
        cf_vbot_cat,
        header_names,
        tier1,
        missing_signals,
    }
}

/// `cf-connecting-ip`, or `cf-connecting-ipv6` first under Pseudo IPv4 =
/// Overwrite (falling back to `cf-connecting-ip` when it is absent or
/// invalid). Absent, invalid and repeated all give
/// `Unknown { header_missing: true }` (§9.3 table).
fn client_ip(t: &Trusted<'_>, pseudo_ipv4_overwrite: bool) -> ClientIp {
    if pseudo_ipv4_overwrite
        && let Some(ip) = t.parse(H::ConnectingIpv6, |v| {
            let v6: Ipv6Addr = std::str::from_utf8(v).ok()?.parse().ok()?;
            Some(IpAddr::V6(v6).to_canonical())
        })
    {
        return ClientIp::Known(ip, IpSource::CfConnectingIpv6);
    }
    match t.parse(H::ConnectingIp, strict_ip) {
        Some(ip) => ClientIp::Known(ip, IpSource::CfConnectingIp),
        None => ClientIp::Unknown {
            header_missing: true,
        },
    }
}

/// A bare IP address (no port, no brackets, no zone), IPv4-mapped IPv6
/// turned into IPv4.
fn strict_ip(value: &[u8]) -> Option<IpAddr> {
    let ip: IpAddr = std::str::from_utf8(value).ok()?.parse().ok()?;
    Some(ip.to_canonical())
}

/// `cf-worker`: a lower-case zone name of at most 253 bytes; owner zones are
/// compared case-insensitively. Anything else is foreign.
fn worker_zone(zone: &[u8], owner_zones: &[String]) -> WorkerZone {
    if is_dns_name(zone)
        && owner_zones
            .iter()
            .any(|owner| owner.as_bytes().eq_ignore_ascii_case(zone))
    {
        WorkerZone::Owner
    } else {
        WorkerZone::Foreign
    }
}

/// `cf-visitor`: `{"scheme":"http"|"https"}` of at most 64 bytes; `Some(true)`
/// for https. Unknown members are ignored so that a new Cloudflare field
/// cannot turn every http visitor into an https one.
fn visitor_scheme_https(value: &[u8]) -> Option<bool> {
    #[derive(Deserialize)]
    struct Visitor {
        scheme: String,
    }
    // Derived struct deserializers also accept a JSON array (`["http"]`);
    // only an object is a valid `cf-visitor` (OWS is already trimmed).
    if value.len() > 64 || value.first() != Some(&b'{') {
        return None;
    }
    match serde_json::from_slice::<Visitor>(value)
        .ok()?
        .scheme
        .as_str()
    {
        "https" => Some(true),
        "http" => Some(false),
        _ => None,
    }
}

/// `cf-ipcountry`: two upper-case letters, or `T1` (Tor); `XX` (no data) is
/// missing.
fn country(value: &[u8]) -> Option<String> {
    let alpha2 = value.len() == 2 && value.iter().all(u8::is_ascii_uppercase);
    ((alpha2 || value == b"T1") && value != b"XX")
        .then(|| String::from_utf8_lossy(value).into_owned())
}

/// 1–`max` bytes, each satisfying `allowed` (which must only admit ASCII).
fn charset(value: &[u8], max: usize, allowed: impl Fn(u8) -> bool) -> Option<String> {
    (!value.is_empty() && value.len() <= max && value.iter().all(|&b| b.is_ascii() && allowed(b)))
        .then(|| String::from_utf8_lossy(value).into_owned())
}

/// 1–`max` bytes of printable ASCII (`0x20..=0x7e`; OWS is already trimmed
/// at both ends).
fn printable(value: &[u8], max: usize) -> Option<String> {
    charset(value, max, |b| (0x20..=0x7e).contains(&b))
}

/// Standard-alphabet base64 (padding optional) decoding to exactly `len`
/// bytes, returned in canonical padded form so that policy lists and the
/// `ctp` binding see one spelling.
fn canonical_base64(value: &[u8], len: usize) -> Option<String> {
    if value.len() > len.div_ceil(3) * 4 {
        return None;
    }
    let bytes = STANDARD_PAD_INDIFFERENT.decode(value).ok()?;
    (bytes.len() == len).then(|| STANDARD.encode(bytes))
}

/// Canonical decimal (no sign, no leading zeros, at most 10 digits) with a
/// value ≤ `max`.
fn decimal(value: &[u8], max: u64) -> Option<u64> {
    if value.is_empty()
        || value.len() > 10
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return None;
    }
    let n = value
        .iter()
        .fold(0u64, |n, &d| n * 10 + u64::from(d - b'0'));
    (n <= max).then_some(n)
}

/// `x-mg-cf-hdr-names`: comma-separated names of 1–64 `tchar`s. Returned as
/// a set (§9.3 set semantics): distinct case-insensitively, first spelling
/// kept, at most 128 distinct names. The cap applies to the set, not to the
/// entries: Cloudflare repeats the name of a repeated field (an HTTP/2
/// browser sends every cookie as its own `cookie` field), and that must not
/// make the signal MISSING. Parsing is linear in the value length (at most
/// 8 KiB once §9.3.1 has run).
fn header_name_set(value: &[u8]) -> Option<Vec<String>> {
    const MAX_NAMES: usize = 128;
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for name in value.split(|&b| b == b',') {
        if name.is_empty() || name.len() > 64 || !name.iter().copied().all(is_tchar) {
            return None;
        }
        if seen.insert(CiKey(name)) {
            if names.len() == MAX_NAMES {
                return None;
            }
            names.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    Some(names)
}

/// `x-mg-cf-as-org`: printable-ASCII percent-encoding of a UTF-8 string of
/// 1–256 bytes without control characters (the Tier 1 forwarder uses
/// `encodeURIComponent`).
fn as_org(value: &[u8]) -> Option<String> {
    const MAX_DECODED: usize = 256;
    if value.is_empty() || value.len() > 3 * MAX_DECODED {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'%' {
            let [hi, lo, ..] = tail else { return None };
            decoded.push((hex_value(*hi)? << 4) | hex_value(*lo)?);
            rest = &tail[2..];
        } else if (0x20..=0x7e).contains(&b) {
            decoded.push(b);
            rest = tail;
        } else {
            return None;
        }
    }
    let text = String::from_utf8(decoded).ok()?;
    (text.len() <= MAX_DECODED && !text.chars().any(char::is_control)).then_some(text)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Whether `value` equals one of `accepted` (§9.2 `x-mg-upstream-key`).
///
/// Constant time with respect to the accepted values: every accepted value
/// is compared, and the comparison is between SHA-256 digests, so neither
/// the position of the first differing byte nor the length of an accepted
/// value shows in the timing. `None`, an empty value and empty accepted
/// entries never match. Pass the raw field value of a request with exactly
/// one `x-mg-upstream-key` field; treat several fields as `None`.
pub fn secret_header_ok(value: Option<&[u8]>, accepted: &[Vec<u8>]) -> bool {
    let Some(value) = value else {
        return false;
    };
    let presented = Sha256::digest(value);
    let mut ok = Choice::from(0);
    for key in accepted {
        let expected = Sha256::digest(key);
        let usable = Choice::from(u8::from(!key.is_empty()));
        ok |= expected[..].ct_eq(&presented[..]) & usable;
    }
    bool::from(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_labels_drop_the_prefix() {
        assert_eq!(H::TlsVersion.signal(), "tls-version");
        assert_eq!(H::QuicRtt.signal(), "quic-rtt");
        assert_eq!(H::HdrNames.signal(), "hdr-names");
        assert_eq!(H::ConnectingIp.signal(), "cf-connecting-ip");
    }

    #[test]
    fn trusted_table_is_normalized_and_in_the_family() {
        for name in TRUSTED {
            assert_eq!(name, name.to_ascii_lowercase());
            assert!(!name.contains('_'));
            assert!(is_upstream_family(name), "{name}");
        }
    }

    #[test]
    fn trim_ows_only_trims_space_and_tab() {
        assert_eq!(trim_ows(b" \t a b \t"), b"a b");
        assert_eq!(trim_ows(b"   "), b"");
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(trim_ows(b"\r\na\n"), b"\r\na\n");
    }

    #[test]
    fn decimal_is_canonical() {
        assert_eq!(decimal(b"0", 10), Some(0));
        assert_eq!(
            decimal(b"4294967295", u64::from(u32::MAX)),
            Some(4_294_967_295)
        );
        assert_eq!(decimal(b"4294967296", u64::from(u32::MAX)), None);
        assert_eq!(decimal(b"9999999999", u64::MAX), Some(9_999_999_999));
        for bad in [
            &b""[..],
            b"01",
            b"+1",
            b"-1",
            b"1 ",
            b"1.0",
            b"12345678901",
            b"0x1",
        ] {
            assert_eq!(decimal(bad, u64::MAX), None, "{bad:?}");
        }
    }

    #[test]
    fn as_org_decoding() {
        assert_eq!(as_org(b"Example%20Net").as_deref(), Some("Example Net"));
        assert_eq!(
            as_org(b"M%C3%BCnchen%2c%20AG").as_deref(),
            Some("München, AG")
        );
        assert_eq!(as_org(b"a+b").as_deref(), Some("a+b"));
        for bad in [
            &b""[..],
            b"%",
            b"%4",
            b"%zz",
            b"%C3",
            b"a%0Ab",
            b"a%7Fb",
            b"a\x01b",
            b"\xc3\xbc",
        ] {
            assert_eq!(as_org(bad), None, "{bad:?}");
        }
        let max = "%41".repeat(256);
        assert_eq!(as_org(max.as_bytes()).map(|s| s.len()), Some(256));
        let over = format!("{max}A");
        assert_eq!(as_org(over.as_bytes()), None);
    }

    #[test]
    fn canonical_base64_accepts_padding_or_none_and_re_pads() {
        let padded = "3zN0vNnT0h1r1TmXnq4B3Ic1S0c=";
        assert_eq!(
            canonical_base64(padded.as_bytes(), 20).as_deref(),
            Some(padded)
        );
        assert_eq!(
            canonical_base64(&padded.as_bytes()[..27], 20).as_deref(),
            Some(padded)
        );
        // Non-canonical trailing bits, URL-safe alphabet, wrong length.
        assert_eq!(canonical_base64(b"3zN0vNnT0h1r1TmXnq4B3Ic1S0d=", 20), None);
        assert_eq!(canonical_base64(b"3zN0vNnT0h1r1TmXnq4B3Ic1S0c_", 20), None);
        assert_eq!(canonical_base64(b"3zN0vNnT0h1r1TmXnq4B3Ic1", 20), None);
    }
}
