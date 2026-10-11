//! The policy field schema (docs/impl/phase1-spec.md §4.1), the per-request
//! MISSING set (§4.3) and the evaluation [`Activation`] (§4.2).
//!
//! The schema is fixed and mirrors Go `internal/policy/context.go` `Input`:
//! the same dotted CEL paths, the same types and the same size caps (the caps
//! feed the static step bound, §5.3, which the Go compiler and the Edge must
//! compute identically). Both sides test against the shared table
//! `testdata/policy-ir/fields.json` (docs/impl/phase2-spec.md §0.4, §22).
//!
//! Phase 2 (docs/impl/phase2-spec.md §4) adds `http.navigation`,
//! `identity.token.bound`, `identity.token.level_age`,
//! `identity.proof.present` and `identity.proof.replayed`; when
//! `identity.proof` is MISSING is decided by [`proof_missing`].

use super::ip::canonical_decimal;
use crate::context::{RequestContext, TokenStatus};
use crate::decision::RiskAssessment;
use crate::enums::{Channel, RouteSensitivity, SignalSource, UpstreamProfileKind};
use crate::extras::RequestExtras;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Static type of a readable schema field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldType {
    Bool,
    Int,
    Double,
    Str,
    /// `list(string)`.
    StrList,
    /// `map(string, string)` (`req.headers`).
    StrMap,
    /// `map(string, double)` (`rate`).
    DoubleMap,
}

macro_rules! field_ids {
    ($( $(#[$meta:meta])* $variant:ident => $path:literal : $ty:ident, $cap:expr; )+) => {
        /// One readable leaf, map or list of the policy schema (§4.1).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum FieldId {
            $( $(#[$meta])* $variant ),+
        }

        impl FieldId {
            /// Every field, in schema order.
            pub const ALL: &'static [FieldId] = &[$(Self::$variant),+];

            /// The field for a dotted CEL path; `None` for struct / namespace
            /// paths (`tls.ja4`, `identity`) and unknown paths.
            pub fn from_path(p: &str) -> Option<Self> {
                match p {
                    $($path => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// The dotted CEL path, e.g. `"net.ip"`.
            pub const fn path(self) -> &'static str {
                match self { $(Self::$variant => $path),+ }
            }

            pub(crate) const fn ty(self) -> FieldType {
                match self { $(Self::$variant => FieldType::$ty),+ }
            }

            /// §4.1 size cap `S(field)`: bytes for strings, entries for lists
            /// and maps, 0 for scalars.
            pub const fn size_cap(self) -> u64 {
                match self { $(Self::$variant => $cap),+ }
            }
        }
    };
}

/// Default cap of strings without their own row in §4.1.
const STR: u64 = 256;

field_ids! {
    ReqMethod => "req.method": Str, 32;
    ReqHost => "req.host": Str, 253;
    ReqPath => "req.path": Str, 8192;
    ReqQuery => "req.query": Str, 8192;
    ReqHeaders => "req.headers": StrMap, 128;
    ReqChannel => "req.channel": Str, STR;
    NetIp => "net.ip": Str, STR;
    NetAsn => "net.asn": Int, 0;
    NetCountry => "net.country": Str, STR;
    NetConnType => "net.conn_type": Str, STR;
    NetTor => "net.tor": Bool, 0;
    UpstreamProfile => "upstream.profile": Str, STR;
    UpstreamAuthenticated => "upstream.authenticated": Bool, 0;
    UpstreamAuthMethod => "upstream.auth_method": Str, STR;
    TlsJa4Value => "tls.ja4.value": Str, 36;
    TlsJa4Source => "tls.ja4.source": Str, STR;
    TlsJa4Authenticated => "tls.ja4.authenticated": Bool, 0;
    TlsVersion => "tls.version": Str, STR;
    HttpVersion => "http.version": Str, STR;
    /// Distinct header names in first-seen order (see [`HttpNs::header_order`]).
    HttpHeaderOrder => "http.header_order": StrList, 128;
    /// Phase 2: the Phase 1 navigation test (client-controlled).
    HttpNavigation => "http.navigation": Bool, 0;
    EdgeTlsVersion => "edge_tls.version": Str, STR;
    EdgeTlsCipher => "edge_tls.cipher": Str, STR;
    EdgeTlsCiphersSha1 => "edge_tls.ciphers_sha1": Str, 40;
    EdgeTlsExtSha1 => "edge_tls.ext_sha1": Str, 40;
    EdgeTlsHelloLen => "edge_tls.hello_len": Int, 0;
    TokenLevel => "identity.token.level": Str, STR;
    TokenAge => "identity.token.age": Int, 0;
    /// Phase 2: the clearance carries `cnf.jkt`.
    TokenBound => "identity.token.bound": Bool, 0;
    /// Phase 2: seconds since the level was obtained.
    TokenLevelAge => "identity.token.level_age": Int, 0;
    /// Phase 2: an `MG-Proof` header was present.
    ProofPresent => "identity.proof.present": Bool, 0;
    ProofValid => "identity.proof.valid": Bool, 0;
    /// Phase 2: the proof's `jti` was replayed or over its key's quota.
    ProofReplayed => "identity.proof.replayed": Bool, 0;
    AgentId => "identity.agent.id": Str, STR;
    AgentGrantId => "identity.agent.grant_id": Str, STR;
    CrawlerClaimed => "identity.crawler.claimed": Bool, 0;
    CrawlerOperator => "identity.crawler.operator": Str, STR;
    CrawlerPurpose => "identity.crawler.purpose": Str, STR;
    CrawlerVerified => "identity.crawler.verified": Bool, 0;
    CrawlerCfVbot => "identity.crawler.cf_vbot": Bool, 0;
    CrawlerCfVbotCat => "identity.crawler.cf_vbot_cat": Str, STR;
    RiskScore => "risk.score": Int, 0;
    RiskConfidence => "risk.confidence": Double, 0;
    RiskClass => "risk.class": Str, STR;
    RiskReasons => "risk.reasons": StrList, 32;
    RouteName => "route.name": Str, STR;
    RouteSensitivity => "route.sensitivity": Str, STR;
    RouteEnv => "route.env": Str, STR;
    Rate => "rate": DoubleMap, 64;
    Labels => "labels": StrList, 64;
}

impl fmt::Display for FieldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.path())
    }
}

/// Namespaces and struct fields of the schema (paths that are not readable
/// values themselves but can be tested with `has()` or be MISSING as a whole).
const STRUCT_PATHS: &[&str] = &[
    "req",
    "net",
    "upstream",
    "tls",
    "tls.ja4",
    "http",
    "edge_tls",
    "identity",
    "identity.token",
    "identity.proof",
    "identity.agent",
    "identity.crawler",
    "risk",
    "route",
];

/// The canonical static string of any schema path (namespace, struct field or
/// readable field), or `None` if `p` is not in the schema.
pub(crate) fn schema_path(p: &str) -> Option<&'static str> {
    FieldId::from_path(p)
        .map(FieldId::path)
        .or_else(|| STRUCT_PATHS.iter().copied().find(|s| *s == p))
}

/// A path that `has()` may test: a schema struct field or readable field of
/// depth >= 2 (`net.ip`, `tls.ja4`, `identity.proof`), never a namespace, a
/// top-level field (`rate`, `labels`) or a map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HasPath(&'static str);

impl HasPath {
    /// Validates `p`.
    pub fn new(p: &str) -> Option<Self> {
        schema_path(p).filter(|s| s.contains('.')).map(Self)
    }

    /// The dotted path.
    pub const fn path(self) -> &'static str {
        self.0
    }
}

/// A path given to [`MissingSet::new`] that is not in the schema (in the Edge
/// this is a programming error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField(pub String);

impl fmt::Display for UnknownField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown policy field path {:?}", self.0)
    }
}

impl std::error::Error for UnknownField {}

/// The fields that are MISSING on one request (§4.3).
///
/// A path `p` is MISSING iff the set holds `m` with `p == m` or `p` starting
/// with `m + "."`. Reading a MISSING field yields UNKNOWN; `has(p)` is false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MissingSet {
    /// Sorted, unique, canonical schema paths.
    paths: Vec<&'static str>,
}

impl MissingSet {
    /// Builds a set; every element must be a schema path (namespace, struct
    /// field or readable field).
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(paths: I) -> Result<Self, UnknownField> {
        let mut set = Self::default();
        for p in paths {
            set.insert(p.as_ref())?;
        }
        Ok(set)
    }

    /// Adds one path.
    pub fn insert(&mut self, path: &str) -> Result<(), UnknownField> {
        let canonical = schema_path(path).ok_or_else(|| UnknownField(path.to_string()))?;
        if let Err(i) = self.paths.binary_search(&canonical) {
            self.paths.insert(i, canonical);
        }
        Ok(())
    }

    /// Whether `path` is MISSING (it or one of its ancestors is in the set).
    pub fn is_missing(&self, path: &str) -> bool {
        self.paths.iter().any(|m| {
            path.strip_prefix(m)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
    }

    /// The paths of the set, sorted.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().copied()
    }

    /// Number of paths in the set.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether nothing is MISSING.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

// --- identity.proof availability (Phase 2 spec §4.2, §9.1, D-40, D-66) -------

/// D-40: a request that never needs an `MG-Proof`: a navigation
/// (`http.navigation`) with method GET or HEAD on which every matched route
/// has channel `web`. Its `identity.proof` is MISSING.
pub fn is_exempt_navigation(navigation: bool, method: &str, all_matched_routes_web: bool) -> bool {
    navigation && matches!(method, "GET" | "HEAD") && all_matched_routes_web
}

/// Phase 2 spec §9.1: whether the Edge verifies `MG-Proof` on a request:
/// `schema_version >= 2`, not an exempt navigation, and a matched route has
/// `proof = required` or the policy reads `identity.proof`
/// (`PolicyEvaluator::reads_field("identity.proof")`).
pub fn proof_verification_needed(
    schema_version: u32,
    exempt_navigation: bool,
    proof_required: bool,
    policy_reads_proof: bool,
) -> bool {
    schema_version >= 2 && !exempt_navigation && (proof_required || policy_reads_proof)
}

/// The part of `identity.proof` that is MISSING on a request (Phase 2 spec
/// §4.2): all of it (`"identity.proof"`) when the proof is not verified
/// (`schema_version = 1`, an exempt navigation, or nothing needs it, see
/// [`proof_verification_needed`]); only `"identity.proof.replayed"` when it
/// is verified but the `jti` replay store gave no verdict (§9.2); nothing
/// otherwise. Without an `MG-Proof` header there is no `jti` to check, so
/// `replay_checked` is `true` and `present = valid = replayed = false` are
/// ordinary values.
pub fn proof_missing(verified: bool, replay_checked: bool) -> Option<&'static str> {
    if !verified {
        Some("identity.proof")
    } else if !replay_checked {
        Some("identity.proof.replayed")
    } else {
        None
    }
}

// --- Activation (§4.2): the serde form is the conformance-fixture JSON -------

/// `req.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReqNs {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub channel: String,
}

/// `net.*`. `Debug` does not print the client IP (spec §2.4).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetNs {
    pub ip: String,
    pub asn: i64,
    pub country: String,
    pub conn_type: String,
    pub tor: bool,
}

impl fmt::Debug for NetNs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = if self.ip.is_empty() {
            ""
        } else {
            crate::REDACTED
        };
        f.debug_struct("NetNs")
            .field("ip", &ip)
            .field("asn", &self.asn)
            .field("country", &self.country)
            .field("conn_type", &self.conn_type)
            .field("tor", &self.tor)
            .finish()
    }
}

/// `upstream.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamNs {
    pub profile: String,
    pub authenticated: bool,
    pub auth_method: String,
}

/// `tls.ja4.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ja4Ns {
    pub value: String,
    pub source: String,
    pub authenticated: bool,
}

/// `tls.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsNs {
    pub ja4: Ja4Ns,
    pub version: String,
}

/// `http.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpNs {
    pub version: String,
    /// Phase 2 spec §4.1: `Sec-Fetch-Mode: navigate`, or no `Sec-Fetch-Mode`
    /// and an `Accept` with `text/html`. Client-controlled.
    pub navigation: bool,
    /// `direct_tls` HTTP/1.x only: the **distinct** header names in the
    /// order of their first occurrence, original case, at most 128. Pingora's
    /// header map folds repeated names into their first position, so the
    /// order of interleaved repeats cannot be recovered; detectors and
    /// policies must not depend on it.
    pub header_order: Vec<String>,
}

/// `edge_tls.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EdgeTlsNs {
    pub version: String,
    pub cipher: String,
    pub ciphers_sha1: String,
    pub ext_sha1: String,
    pub hello_len: i64,
}

/// `identity.token.*`. Every field is the zero value without a valid
/// clearance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokenNs {
    pub level: String,
    pub age: i64,
    /// Phase 2: the clearance carries `cnf.jkt`.
    pub bound: bool,
    /// Phase 2: `now - lat` in seconds (`now - iat` for v1 tokens).
    pub level_age: i64,
}

/// `identity.proof.*` (Phase 2 spec §4.1; MISSING per [`proof_missing`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProofNs {
    /// Phase 2: an `MG-Proof` header was present.
    pub present: bool,
    pub valid: bool,
    /// Phase 2: the `jti` was replayed or over its key's quota.
    pub replayed: bool,
}

/// `identity.agent.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentNs {
    pub id: String,
    pub grant_id: String,
}

/// `identity.crawler.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrawlerNs {
    pub claimed: bool,
    pub operator: String,
    pub purpose: String,
    pub verified: bool,
    pub cf_vbot: bool,
    pub cf_vbot_cat: String,
}

/// `identity.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityNs {
    pub token: TokenNs,
    pub proof: ProofNs,
    pub agent: AgentNs,
    pub crawler: CrawlerNs,
}

/// `risk.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RiskNs {
    pub score: i64,
    pub confidence: f64,
    /// Upper-case `BotClass` name, e.g. `IMPERSONATOR`.
    pub class: String,
    pub reasons: Vec<String>,
}

/// `route.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteNs {
    pub name: String,
    pub sensitivity: String,
    pub env: String,
}

/// The values a policy expression reads (§4.1). ABSENT values are zero
/// values; MISSING is tracked separately in [`MissingSet`]. The serde form
/// is the Activation JSON of §4.2 (keys = CEL names, omitted keys = zero).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Activation {
    pub req: ReqNs,
    pub net: NetNs,
    pub upstream: UpstreamNs,
    pub tls: TlsNs,
    pub http: HttpNs,
    pub edge_tls: EdgeTlsNs,
    pub identity: IdentityNs,
    pub risk: RiskNs,
    pub route: RouteNs,
    pub rate: BTreeMap<String, f64>,
    pub labels: Vec<String>,
}

/// Cap of `http.header_order` (§4.1: truncated when building).
const HEADER_ORDER_CAP: usize = 128;
/// Cap of `labels` (§4.1: sorted, then truncated when building).
const LABELS_CAP: usize = 64;
/// Cap of `risk.reasons`.
const REASONS_CAP: usize = 32;

/// Wire name of a proto enum value, with the zero value as `""`.
fn wire<T: fmt::Display + PartialEq + Default>(v: T) -> String {
    if v == T::default() {
        String::new()
    } else {
        v.to_string()
    }
}

impl Activation {
    /// Builds the activation of one request (§4.1 "Edge 来源" column).
    ///
    /// `risk.confidence` and the `rate` utilizations are `f32` in the
    /// pipeline; they enter the activation as the `f64` of their shortest
    /// decimal form (the number written to the event JSON), so a policy
    /// comparison such as `risk.confidence >= 0.4` behaves as it reads.
    pub fn build(ctx: &RequestContext, extras: &RequestExtras<'_>, risk: &RiskAssessment) -> Self {
        let token = &ctx.identity.token;
        let valid = token.status == TokenStatus::Valid;
        let crawler = &ctx.identity.crawler;
        let edge_tls = ctx.edge_tls.clone().unwrap_or_default();
        let ja4 = ctx.tls.ja4.clone().unwrap_or_default();

        let mut labels: Vec<String> = risk
            .labels
            .iter()
            .chain(
                ctx.active_verdicts()
                    .filter(|v| v.applies_to_site(&ctx.site_id))
                    .flat_map(|v| v.labels.iter()),
            )
            .cloned()
            .collect();
        labels.sort();
        labels.dedup();
        labels.truncate(LABELS_CAP);

        let mut rate = BTreeMap::new();
        for obs in extras.rate {
            let u = canonical_decimal(obs.utilization);
            rate.entry(obs.limiter_id.clone())
                .and_modify(|v: &mut f64| *v = v.max(u))
                .or_insert(u);
        }

        Self {
            req: ReqNs {
                method: ctx.http.method.clone(),
                host: ctx.http.host.clone(),
                path: ctx.http.path.clone(),
                query: extras.query.to_string(),
                headers: extras.headers.iter().cloned().collect(),
                channel: wire::<Channel>(extras.route.channel),
            },
            net: NetNs {
                ip: ctx.net.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                asn: i64::from(ctx.net.asn.unwrap_or(0)),
                country: ctx.net.country.clone().unwrap_or_default(),
                conn_type: ctx.net.conn_type.to_string(),
                tor: ctx.net.tor,
            },
            upstream: UpstreamNs {
                profile: wire::<UpstreamProfileKind>(ctx.upstream.profile),
                authenticated: ctx.upstream.authenticated,
                auth_method: ctx.upstream.auth_method.to_string(),
            },
            tls: TlsNs {
                ja4: Ja4Ns {
                    value: ja4.value,
                    source: wire::<SignalSource>(ja4.source),
                    authenticated: ja4.authenticated,
                },
                version: ctx.tls.version.clone().unwrap_or_default(),
            },
            http: HttpNs {
                version: ctx.http.version.clone().unwrap_or_default(),
                navigation: ctx.http.navigation,
                header_order: ctx
                    .http
                    .header_order
                    .iter()
                    .take(HEADER_ORDER_CAP)
                    .cloned()
                    .collect(),
            },
            edge_tls: EdgeTlsNs {
                version: edge_tls.version.unwrap_or_default(),
                cipher: edge_tls.cipher.unwrap_or_default(),
                ciphers_sha1: edge_tls.ciphers_sha1.unwrap_or_default(),
                ext_sha1: edge_tls.ext_sha1.unwrap_or_default(),
                hello_len: i64::from(edge_tls.hello_len.unwrap_or(0)),
            },
            identity: IdentityNs {
                token: TokenNs {
                    level: match (valid, token.level) {
                        (true, Some(level)) => level.to_string(),
                        _ => String::new(),
                    },
                    age: if valid { i64::from(token.age_s) } else { 0 },
                    bound: valid && token.bound,
                    level_age: if valid { i64::from(token.level_age) } else { 0 },
                },
                proof: ProofNs {
                    present: ctx.identity.proof.present,
                    valid: ctx.identity.proof.valid,
                    replayed: ctx.identity.proof.replayed,
                },
                agent: AgentNs {
                    id: ctx.identity.agent.id.clone().unwrap_or_default(),
                    grant_id: ctx.identity.agent.grant_id.clone().unwrap_or_default(),
                },
                crawler: CrawlerNs {
                    claimed: crawler.claimed,
                    operator: crawler.operator.clone().unwrap_or_default(),
                    purpose: crawler.purpose.clone().unwrap_or_default(),
                    verified: crawler.is_verified(),
                    cf_vbot: crawler.cf_vbot.unwrap_or(false),
                    cf_vbot_cat: crawler.cf_vbot_cat.clone().unwrap_or_default(),
                },
            },
            risk: RiskNs {
                score: i64::from(risk.score.get()),
                confidence: canonical_decimal(risk.confidence.get()),
                class: risk.bot_class.as_str().to_ascii_uppercase(),
                reasons: risk.top_reasons.iter().take(REASONS_CAP).cloned().collect(),
            },
            route: RouteNs {
                name: extras.route.name.clone(),
                sensitivity: wire::<RouteSensitivity>(extras.route.sensitivity),
                env: extras.route.env.clone(),
            },
            rate,
            labels,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_paths_round_trip_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for &f in FieldId::ALL {
            assert_eq!(FieldId::from_path(f.path()), Some(f));
            assert!(seen.insert(f.path()), "duplicate {f}");
        }
        assert_eq!(FieldId::ALL.len(), 50);
        assert_eq!(FieldId::from_path("tls.ja4"), None, "struct, not a value");
        assert_eq!(FieldId::from_path("req.headers.accept"), None, "map key");
        assert_eq!(FieldId::from_path("net"), None);
        assert_eq!(
            FieldId::from_path("identity.crawler.claimed"),
            Some(FieldId::CrawlerClaimed)
        );
    }

    /// The shared field table (Phase 2 spec §0.4, §22), read by the Go
    /// compiler's tests too: the same paths in the same order, types, caps
    /// and struct paths as this schema.
    #[test]
    fn schema_matches_shared_fields_json() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/policy-ir/fields.json")).unwrap();
        assert_eq!(doc["version"], 1);
        let type_name = |t: FieldType| match t {
            FieldType::Bool => "bool",
            FieldType::Int => "int",
            FieldType::Double => "double",
            FieldType::Str => "string",
            FieldType::StrList => "list(string)",
            FieldType::StrMap => "map(string,string)",
            FieldType::DoubleMap => "map(string,double)",
        };
        let fields = doc["fields"].as_array().unwrap();
        let paths: Vec<&str> = fields.iter().map(|f| f["path"].as_str().unwrap()).collect();
        let ours: Vec<&str> = FieldId::ALL.iter().map(|f| f.path()).collect();
        assert_eq!(ours, paths, "same fields, same order");
        for (f, id) in fields.iter().zip(FieldId::ALL) {
            assert_eq!(f["type"], type_name(id.ty()), "{id}");
            assert_eq!(f["cap"].as_u64(), Some(id.size_cap()), "{id}");
            let phase = f["phase"].as_u64().unwrap();
            assert!(phase == 1 || phase == 2, "{id}");
            if let Some(v) = f.get("value_cap") {
                assert_eq!(v.as_u64(), Some(super::super::ir::HEADER_VALUE_CAP), "{id}");
            }
        }
        let phase2: Vec<&str> = fields
            .iter()
            .filter(|f| f["phase"] == 2)
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            phase2,
            [
                "http.navigation",
                "identity.token.bound",
                "identity.token.level_age",
                "identity.proof.present",
                "identity.proof.replayed"
            ]
        );
        assert_eq!(doc["default_string_cap"].as_u64(), Some(STR));
        let structs: Vec<&str> = doc["structs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(structs, STRUCT_PATHS);
        for s in STRUCT_PATHS {
            assert!(MissingSet::new([s]).is_ok(), "{s}");
        }
    }

    /// §4.1 size caps (they feed the static step bound and must equal Go's `sizeHints`).
    #[test]
    fn size_caps_match_spec_table() {
        use FieldId as F;
        for (f, cap) in [
            (F::ReqPath, 8192),
            (F::ReqQuery, 8192),
            (F::ReqMethod, 32),
            (F::ReqHost, 253),
            (F::ReqHeaders, 128),
            (F::HttpHeaderOrder, 128),
            (F::Labels, 64),
            (F::RiskReasons, 32),
            (F::Rate, 64),
            (F::TlsJa4Value, 36),
            (F::EdgeTlsCiphersSha1, 40),
            (F::EdgeTlsExtSha1, 40),
            (F::NetIp, 256),
            (F::RouteName, 256),
            (F::RiskScore, 0),
            (F::RiskConfidence, 0),
            (F::NetTor, 0),
        ] {
            assert_eq!(f.size_cap(), cap, "{f}");
        }
    }

    #[test]
    fn has_paths() {
        for ok in [
            "net.ip",
            "tls.ja4",
            "tls.ja4.value",
            "identity.proof",
            "identity.crawler.cf_vbot",
            "req.headers",
        ] {
            assert_eq!(HasPath::new(ok).map(HasPath::path), Some(ok), "{ok}");
        }
        for bad in [
            "tls",
            "rate",
            "labels",
            "req.headers.accept",
            "net.ipx",
            "",
            "identity.",
        ] {
            assert_eq!(HasPath::new(bad), None, "{bad}");
        }
    }

    #[test]
    fn missing_set_prefix_semantics() {
        let set = MissingSet::new(["tls", "http.header_order", "identity.proof", "tls"]).unwrap();
        assert_eq!(
            set.paths().collect::<Vec<_>>(),
            ["http.header_order", "identity.proof", "tls"]
        );
        assert!(set.is_missing("tls"));
        assert!(set.is_missing("tls.ja4"));
        assert!(set.is_missing("tls.ja4.value"));
        assert!(set.is_missing("identity.proof.valid"));
        assert!(!set.is_missing("identity.token.level"));
        assert!(!set.is_missing("http.version"));
        assert!(set.is_missing("http.header_order"));
        assert!(
            !set.is_missing("tlsx"),
            "a prefix must end at a segment boundary"
        );
        let set = MissingSet::new(["edge_tls.hello_len"]).unwrap();
        assert!(
            !set.is_missing("edge_tls"),
            "a child being missing does not make the parent missing"
        );
        assert!(set.is_missing("edge_tls.hello_len"));
    }

    /// §4.3: every element must be a schema path; anything else is `UnknownField`.
    #[test]
    fn missing_set_rejects_unknown_paths() {
        for bad in [
            "tls.ja5",
            "req.headers.accept",
            "",
            "net.",
            ".net",
            "Net.ip",
            "identity.proof.valid.x",
        ] {
            assert_eq!(
                MissingSet::new([bad]),
                Err(UnknownField(bad.to_string())),
                "{bad:?}"
            );
        }
        assert!(MissingSet::new(["identity", "rate", "labels", "net.ip"]).is_ok());
    }

    /// Spec §2.4: deterministic random input never panics the MissingSet or
    /// Activation JSON parsers.
    #[test]
    fn random_inputs_do_not_panic() {
        let pieces = [
            "net",
            ".",
            "ip",
            "tls",
            "ja4",
            "{",
            "}",
            "\"",
            ":",
            ",",
            "[",
            "]",
            "\"req\"",
            "\"headers\"",
            "1",
            "-",
            "é",
            " ",
            "null",
            "true",
        ];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..10_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut s = String::new();
            for i in 0..(state % 16) {
                s.push_str(pieces[((state >> (i * 4)) % pieces.len() as u64) as usize]);
            }
            let _ = MissingSet::new([s.as_str()]);
            let _ = HasPath::new(&s);
            let _ = serde_json::from_str::<Activation>(&s);
        }
    }

    #[test]
    fn activation_json_matches_spec_example() {
        // §4.2, verbatim apart from the placeholder UA.
        let json = r#"{
          "req": {"method": "GET", "host": "example.com", "path": "/account/login", "query": "next=%2F",
                  "headers": {"accept": "text/html", "user-agent": "Mozilla/5.0"}, "channel": "web"},
          "net": {"ip": "203.0.113.7", "asn": 64500, "country": "HK", "conn_type": "unknown", "tor": false},
          "upstream": {"profile": "cloudflare", "authenticated": true, "auth_method": "loopback"},
          "tls": {"ja4": {"value": "", "source": "", "authenticated": false}, "version": ""},
          "http": {"version": "HTTP/2", "header_order": []},
          "edge_tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "ciphers_sha1": "", "ext_sha1": "", "hello_len": 512},
          "identity": {"token": {"level": "invisible", "age": 120}, "proof": {"valid": false},
                       "agent": {"id": "", "grant_id": ""},
                       "crawler": {"claimed": false, "operator": "", "purpose": "", "verified": false, "cf_vbot": false, "cf_vbot_cat": ""}},
          "risk": {"score": 12, "confidence": 0.6, "class": "HUMAN_LIKELY", "reasons": []},
          "route": {"name": "login", "sensitivity": "critical", "env": "production"},
          "rate": {"login-per-ip": 0.2},
          "labels": []
        }"#;
        let act: Activation = serde_json::from_str(json).unwrap();
        assert_eq!(act.req.headers["accept"], "text/html");
        assert_eq!(act.edge_tls.hello_len, 512);
        assert_eq!(act.rate["login-per-ip"], 0.2);
        let back: Activation = serde_json::from_value(serde_json::to_value(&act).unwrap()).unwrap();
        assert_eq!(back, act);
        assert!(
            !format!("{act:?}").contains("203.0.113.7"),
            "Debug redacts the client IP"
        );
        // Omitted keys are zero values.
        let sparse: Activation = serde_json::from_str(r#"{"net": {"asn": 7}}"#).unwrap();
        assert_eq!(sparse.net.asn, 7);
        assert_eq!(sparse.req.method, "");
        // Typos in fixtures are errors, not silent zero values.
        assert!(serde_json::from_str::<Activation>(r#"{"net": {"asnn": 7}}"#).is_err());
        assert!(serde_json::from_str::<Activation>(r#"{"rates": {}}"#).is_err());
    }
}
