//! `mg:ev` stream entries (spec §13.6) and the writer the flusher hands them to.

use super::encode::truncate_utf8;
use crate::state::StateHandle;
use mg_core::{Action, BotClass, BoxFuture, ChallengeType, ProviderId, TokenLevel, VerdictOutcome};

/// Stream key.
pub const STREAM_KEY: &str = "mg:ev";

/// Value of every entry's leading `v` field.
pub const STREAM_ENTRY_VERSION: &str = "1";

/// Writes a batch of `mg:ev` entries (§9.11, §13.6).
///
/// [`StateHandle`] implements it (ruling I-25) with
/// `StateHandle::xadd_batch`, so the Valkey I/O happens on the `mg-state`
/// runtime: one pipeline of `XADD mg:ev MAXLEN ~ <maxlen> * <field> <value>
/// …`, one command per entry, fields in [`StreamEntry::fields`] order. The
/// flusher never retries a failed batch; it counts
/// `mg_event_dropped_total{sink="stream"}`.
///
/// This is the object-safe form of `async fn xadd_batch` (the flusher holds
/// an `Arc<dyn StreamWriter>`).
pub trait StreamWriter: Send + Sync {
    fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>>;
}

/// The production writer (ruling I-25): the entries go to `mg-state` as one
/// `XADD` pipeline. In local mode, while Valkey is down or the breaker is
/// open, the batch fails with the state layer's error text (no key or entry
/// content is ever part of it), and the flusher counts the drop.
impl StreamWriter for StateHandle {
    fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let entries = entries.into_iter().map(StreamEntry::into_fields).collect();
            StateHandle::xadd_batch(self, maxlen, entries)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// One `mg:ev` entry: an ordered list of field / value pairs (§13.6).
///
/// Build it with [`StreamEntry::decision`] or [`StreamEntry::feedback`]; the
/// field order is part of the contract with the near-line consumers. Entries
/// never contain a client IP in clear or `client_conn_key`: IPs appear only as
/// the keyed hashes `ipk` / `pfk` computed by the caller (`state::kh`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    fields: Vec<(&'static str, String)>,
}

/// Inputs of a `kind decision` entry (one per non-`/__mg` request, unsampled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionEntry<'a> {
    pub site: &'a str,
    /// Unix milliseconds.
    pub ts_ms: i64,
    pub request_id: &'a str,
    /// Clearance token `sub`; `None` = no session (`""`).
    pub session: Option<&'a str>,
    /// Route name.
    pub route: &'a str,
    /// Decided action (in monitor mode: the action that would have been taken).
    pub action: Action,
    pub dry_run: bool,
    pub class: BotClass,
    /// 0..=100; larger values are clamped.
    pub score: u8,
    /// `kh(ip entity)`, the `ip` verdict key; `None` when the client IP is unknown.
    pub ipk: Option<&'a str>,
    /// `kh(prefix)`, the `prefix` verdict key; `None` when the client IP is unknown.
    pub pfk: Option<&'a str>,
    /// ASN; `None` (unknown) is written as 0.
    pub asn: Option<u32>,
    /// HTTP status sent to the client; `None` is written as 0.
    pub status: Option<u16>,
}

/// Inputs of a `kind feedback` entry (one per `POST /__mg/c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackEntry<'a> {
    pub site: &'a str,
    pub ts_ms: i64,
    pub request_id: &'a str,
    /// The challenge's `route_class` route.
    pub route: &'a str,
    pub outcome: VerdictOutcome,
    pub challenge_type: ChallengeType,
    pub pfk: Option<&'a str>,
    pub asn: Option<u32>,
}

/// Value of the leading `v` field of a Phase 2 entry (Phase 2 spec §13.1).
pub const STREAM_ENTRY_VERSION_V2: &str = "2";

/// HMAC domain of the `ph` path hash (Phase 2 spec §13.1).
pub const PATH_HASH_DOMAIN: &str = "mg-path-v1";

/// Longest `m` (request method) value, in bytes (Phase 2 spec §13.1).
pub const STREAM_METHOD_MAX_BYTES: usize = 16;

/// Longest `uf` (UA family) value, in bytes (Phase 2 spec §13.1).
pub const STREAM_UA_FAMILY_MAX_BYTES: usize = 16;

/// `ph = lower_hex(HMAC-SHA256(K_pseudo, "mg-path-v1" ‖ 0x00 ‖ site ‖ 0x00 ‖
/// p))[0..16]` (Phase 2 spec §13.1). `p` is the caller's: the
/// `rfc3986_view` path without the query, lower-cased on
/// `case_insensitive_paths` sites, and `/<route name>` for requests of a
/// `redact_path` route.
pub fn path_hash(k_pseudo: &[u8; 32], site: &str, p: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(k_pseudo)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(PATH_HASH_DOMAIN.as_bytes());
    mac.update(&[0]);
    mac.update(site.as_bytes());
    mac.update(&[0]);
    mac.update(p.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = String::with_capacity(16);
    for b in &tag[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `ct`: class of the origin response's `Content-Type` (Phase 2 spec §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentClass {
    /// `h`: `text/html`.
    Html,
    /// `a`: a static asset (`text/css`, `*/javascript`, `image/*`, `font/*`).
    Asset,
    /// `j`: `application/json` or `+json`.
    Json,
    /// `o`: anything else.
    Other,
}

impl ContentClass {
    /// The wire letter.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Html => "h",
            Self::Asset => "a",
            Self::Json => "j",
            Self::Other => "o",
        }
    }

    /// Classifies a `Content-Type` header value (parameters and case are
    /// ignored). `None`: the origin sent no `Content-Type`, which counts as
    /// [`ContentClass::Other`] (an origin response exists).
    pub fn of(content_type: Option<&str>) -> Self {
        let Some(ct) = content_type else {
            return Self::Other;
        };
        let essence = ct.split(';').next().unwrap_or("").trim();
        let essence = essence.to_ascii_lowercase();
        let Some((ty, sub)) = essence.split_once('/') else {
            return Self::Other;
        };
        match (ty, sub) {
            ("text", "html") => Self::Html,
            ("text", "css") | ("image" | "font", _) => Self::Asset,
            (_, "javascript") => Self::Asset,
            ("application", "json") => Self::Json,
            (_, s) if s.ends_with("+json") => Self::Json,
            _ => Self::Other,
        }
    }
}

/// `pf`: the `MG-Proof` result (Phase 2 spec §13.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ProofResult {
    /// `-`: not checked, or no proof.
    #[default]
    None,
    /// `v`: valid.
    Valid,
    /// `u`: valid but not bound (no `cnf.jkt` to compare with).
    Unbound,
    /// `j`: the key differs from the clearance's `cnf.jkt`.
    JktMismatch,
    /// `r`: replayed `jti`.
    Replayed,
    /// `x`: any other failure.
    Invalid,
}

impl ProofResult {
    /// The wire character.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "-",
            Self::Valid => "v",
            Self::Unbound => "u",
            Self::JktMismatch => "j",
            Self::Replayed => "r",
            Self::Invalid => "x",
        }
    }
}

/// `fam`: the client IP's address family (Phase 2 spec §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    /// The family of `ip` (an IPv4-mapped IPv6 address counts as IPv4, like
    /// `Net::entity_of`).
    pub fn of(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(_) => Self::V4,
            std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => Self::V4,
            std::net::IpAddr::V6(_) => Self::V6,
        }
    }

    /// `4` / `6`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

/// Inputs of a `kind decision` entry v2 (Phase 2 spec §13.1): the v1 fields,
/// then the v2 fields in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionEntryV2<'a> {
    /// The v1 fields, unchanged.
    pub base: DecisionEntry<'a>,
    /// `m`: the request method as received; truncated to
    /// [`STREAM_METHOD_MAX_BYTES`].
    pub method: &'a str,
    /// `ph`: from [`path_hash`]; `None` is written as `""`.
    pub path_hash: Option<&'a str>,
    /// `ct`: `None` when the Edge answered itself (no origin response).
    pub content: Option<ContentClass>,
    /// `bt`: the path is a scanner bait.
    pub bait: bool,
    /// `xs`: a cross-site / same-site subresource request
    /// (`Sec-Fetch-Site` cross-site or same-site, `Sec-Fetch-Mode` not
    /// `navigate`).
    pub cross_site: bool,
    /// `tk`: the request carried a valid clearance.
    pub token: bool,
    /// `pf`.
    pub proof: ProofResult,
    /// `uf`: `mg_core::ua::parse` family without version; truncated to
    /// [`STREAM_UA_FAMILY_MAX_BYTES`]; `None` is written as `""`.
    pub ua_family: Option<&'a str>,
    /// `fam`: `None` when the client IP is unknown.
    pub family: Option<IpFamily>,
    /// `ctype`: the challenge type when `action = challenge`; ignored (and
    /// written as `""`) for every other action.
    pub challenge_type: Option<ChallengeType>,
}

/// `outcome` of a feedback entry v2 (Phase 2 spec §13.1, §15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedbackOutcome {
    /// A provider verdict (`pass`, `fail`, `unavailable`, `misconfigured`).
    Verdict(VerdictOutcome),
    /// `renew_rebind`: a bound C was renewed from another prefix.
    RenewRebind,
}

impl FeedbackOutcome {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verdict(v) => v.as_str(),
            Self::RenewRebind => "renew_rebind",
        }
    }
}

impl From<VerdictOutcome> for FeedbackOutcome {
    fn from(v: VerdictOutcome) -> Self {
        Self::Verdict(v)
    }
}

/// Inputs of a `kind feedback` entry v2 (Phase 2 spec §13.1): `/__mg/c`
/// results, and the renewal results that count as failures or rebind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackEntryV2<'a> {
    pub site: &'a str,
    pub ts_ms: i64,
    pub request_id: &'a str,
    /// The challenge's `route_class` route.
    pub route: &'a str,
    pub outcome: FeedbackOutcome,
    pub challenge_type: ChallengeType,
    pub pfk: Option<&'a str>,
    pub asn: Option<u32>,
    /// `p`: the submitted provider (interactive only).
    pub provider: Option<ProviderId>,
    /// `ipk`: `kh(ip entity)`; `None` when the client IP is unknown.
    pub ipk: Option<&'a str>,
    /// `sess`: the new clearance's `sub`; `None` when none was issued.
    pub session: Option<&'a str>,
    /// `lvl`: the issued clearance's level.
    pub level: Option<TokenLevel>,
}

impl StreamEntry {
    /// `v 2 kind decision site ts rid sess route action dry class score ipk
    /// pfk asn status m ph ct bt xs tk pf uf fam ctype` (Phase 2 spec
    /// §13.1): the v1 fields in their order, then the v2 fields.
    pub fn decision_v2(e: &DecisionEntryV2<'_>) -> Self {
        let mut entry = Self::decision(&e.base);
        entry.fields[0].1 = STREAM_ENTRY_VERSION_V2.to_owned();
        let flag = |b: bool| if b { "1" } else { "0" }.to_owned();
        let ctype = match (e.base.action, e.challenge_type) {
            (Action::Challenge, Some(t)) if t != ChallengeType::Unspecified => t.as_str(),
            _ => "",
        };
        entry.fields.extend([
            (
                "m",
                truncate_utf8(e.method, STREAM_METHOD_MAX_BYTES).to_owned(),
            ),
            ("ph", e.path_hash.unwrap_or("").to_owned()),
            ("ct", e.content.map_or("", ContentClass::as_str).to_owned()),
            ("bt", flag(e.bait)),
            ("xs", flag(e.cross_site)),
            ("tk", flag(e.token)),
            ("pf", e.proof.as_str().to_owned()),
            (
                "uf",
                truncate_utf8(e.ua_family.unwrap_or(""), STREAM_UA_FAMILY_MAX_BYTES).to_owned(),
            ),
            ("fam", e.family.map_or("", IpFamily::as_str).to_owned()),
            ("ctype", ctype.to_owned()),
        ]);
        entry
    }

    /// `v 2 kind feedback site ts rid route outcome type pfk asn p ipk sess
    /// lvl` (Phase 2 spec §13.1).
    pub fn feedback_v2(e: &FeedbackEntryV2<'_>) -> Self {
        Self {
            fields: vec![
                ("v", STREAM_ENTRY_VERSION_V2.to_owned()),
                ("kind", "feedback".to_owned()),
                ("site", e.site.to_owned()),
                ("ts", e.ts_ms.to_string()),
                ("rid", e.request_id.to_owned()),
                ("route", e.route.to_owned()),
                ("outcome", e.outcome.as_str().to_owned()),
                ("type", e.challenge_type.as_str().to_owned()),
                ("pfk", e.pfk.unwrap_or("").to_owned()),
                ("asn", e.asn.unwrap_or(0).to_string()),
                ("p", e.provider.map_or("", |p| p.as_str()).to_owned()),
                ("ipk", e.ipk.unwrap_or("").to_owned()),
                ("sess", e.session.unwrap_or("").to_owned()),
                ("lvl", e.level.map(|l| l.to_string()).unwrap_or_default()),
            ],
        }
    }

    /// `v 1 kind decision site ts rid sess route action dry class score ipk pfk asn status`.
    pub fn decision(e: &DecisionEntry<'_>) -> Self {
        Self {
            fields: vec![
                ("v", STREAM_ENTRY_VERSION.to_owned()),
                ("kind", "decision".to_owned()),
                ("site", e.site.to_owned()),
                ("ts", e.ts_ms.to_string()),
                ("rid", e.request_id.to_owned()),
                ("sess", e.session.unwrap_or("").to_owned()),
                ("route", e.route.to_owned()),
                ("action", e.action.as_str().to_owned()),
                ("dry", if e.dry_run { "1" } else { "0" }.to_owned()),
                ("class", e.class.as_str().to_owned()),
                ("score", e.score.min(100).to_string()),
                ("ipk", e.ipk.unwrap_or("").to_owned()),
                ("pfk", e.pfk.unwrap_or("").to_owned()),
                ("asn", e.asn.unwrap_or(0).to_string()),
                ("status", e.status.unwrap_or(0).to_string()),
            ],
        }
    }

    /// `v 1 kind feedback site ts rid route outcome type pfk asn`.
    pub fn feedback(e: &FeedbackEntry<'_>) -> Self {
        Self {
            fields: vec![
                ("v", STREAM_ENTRY_VERSION.to_owned()),
                ("kind", "feedback".to_owned()),
                ("site", e.site.to_owned()),
                ("ts", e.ts_ms.to_string()),
                ("rid", e.request_id.to_owned()),
                ("route", e.route.to_owned()),
                ("outcome", e.outcome.as_str().to_owned()),
                ("type", e.challenge_type.as_str().to_owned()),
                ("pfk", e.pfk.unwrap_or("").to_owned()),
                ("asn", e.asn.unwrap_or(0).to_string()),
            ],
        }
    }

    /// Field / value pairs in `XADD` order.
    pub fn fields(&self) -> &[(&'static str, String)] {
        &self.fields
    }

    /// The pairs, for `StateHandle::xadd_batch`.
    pub fn into_fields(self) -> Vec<(&'static str, String)> {
        self.fields
    }

    /// Value of the `kind` field (`decision` / `feedback`).
    pub fn kind(&self) -> &str {
        self.get("kind").unwrap_or("")
    }

    /// Value of `field`, if present.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| *name == field)
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_entry_unknown_values_use_spec_placeholders() {
        let e = StreamEntry::decision(&DecisionEntry {
            site: "blog",
            ts_ms: 5,
            request_id: "r",
            session: None,
            route: "default",
            action: Action::Allow,
            dry_run: false,
            class: BotClass::Unknown,
            score: 250,
            ipk: None,
            pfk: None,
            asn: None,
            status: None,
        });
        assert_eq!(e.kind(), "decision");
        assert_eq!(e.get("sess"), Some(""));
        assert_eq!(e.get("ipk"), Some(""));
        assert_eq!(e.get("pfk"), Some(""));
        assert_eq!(e.get("asn"), Some("0"));
        assert_eq!(e.get("status"), Some("0"));
        assert_eq!(e.get("score"), Some("100"), "clamped to 0..=100");
        assert_eq!(e.get("dry"), Some("0"));
        assert_eq!(e.get("nope"), None);
    }
}
