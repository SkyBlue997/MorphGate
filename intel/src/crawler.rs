//! The crawler registry artifact (spec §12.3) and the verification state
//! machine with its rDNS result cache (spec §7.3).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;

use crate::artifact::ArtifactKind;
use crate::cidr::{Prefix, check_published};
use crate::error::{IntelError, check_size, quote};
use crate::ipset::IpSet;
use crate::text::{is_lower_hex_sha256, is_rfc3339};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// How an operator's claim is verified (§12.3 `verify.mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyMode {
    /// Only the published IP ranges; outside them the claim fails at once.
    IpRanges,
    /// Only reverse-then-forward DNS.
    Rdns,
    /// Published ranges first, rDNS for addresses outside them.
    IpRangesOrRdns,
}

impl VerifyMode {
    /// The artifact spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMode::IpRanges => "ip_ranges",
            VerifyMode::Rdns => "rdns",
            VerifyMode::IpRangesOrRdns => "ip_ranges_or_rdns",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        [
            VerifyMode::IpRanges,
            VerifyMode::Rdns,
            VerifyMode::IpRangesOrRdns,
        ]
        .into_iter()
        .find(|m| m.as_str() == s)
    }

    /// Whether this mode may use rDNS.
    pub fn uses_rdns(self) -> bool {
        !matches!(self, VerifyMode::IpRanges)
    }
}

/// The `purpose` values of §12.3.
pub const PURPOSES: [&str; 6] = [
    "search",
    "ai_training",
    "ai_search",
    "user_triggered",
    "archive",
    "other",
];

/// One crawler operator from the registry. Built only by
/// [`CrawlerRegistry::from_artifact`], so every instance passed validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    /// `[a-z0-9][a-z0-9_-]{0,31}`, unique within the registry.
    pub id: String,
    /// Display name.
    pub name: String,
    /// One of [`PURPOSES`].
    pub purpose: String,
    /// Case-insensitive User-Agent substrings (1–8, each 3–64 characters).
    pub ua_tokens: Vec<String>,
    /// Verification mode.
    pub mode: VerifyMode,
    /// Lower-case rDNS suffixes (non-empty when `mode` uses rDNS), each a
    /// leading `.` followed by at least two labels (ruling I-22).
    pub rdns_suffixes: Vec<String>,
    /// The operator's published ranges.
    pub cidrs: IpSet,
    /// `ua_tokens`, ASCII-lower-cased once for matching.
    ua_tokens_lower: Vec<String>,
}

/// A validated crawler registry artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlerRegistry {
    operators: Vec<Operator>,
    index: HashMap<String, usize>,
    generated_at: String,
    test: bool,
}

/// Limits of §12.3.
const MAX_CIDRS_PER_OPERATOR: usize = 20_000;
const UA_TOKENS: std::ops::RangeInclusive<usize> = 1..=8;
const UA_TOKEN_CHARS: std::ops::RangeInclusive<usize> = 3..=64;
const SUFFIX_BYTES: std::ops::RangeInclusive<usize> = 1..=253;
const MIN_V4_LEN: u8 = 16;
const MIN_V6_LEN: u8 = 32;
const KIND: &str = "mg-crawler-registry";
const SOURCE_FORMATS: [&str; 2] = ["prefixes_json", "cidr_text"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDoc {
    v: u64,
    kind: String,
    generated_at: String,
    #[serde(default)]
    test: bool,
    operators: Vec<OperatorDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorDoc {
    id: String,
    name: String,
    purpose: String,
    ua_tokens: Vec<String>,
    verify: VerifyDoc,
    cidrs: Vec<String>,
    sources: Vec<SourceDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyDoc {
    mode: String,
    rdns_suffixes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // url, creation_time and stale are informational; the parse checks their types.
struct SourceDoc {
    url: String,
    format: String,
    fetched_at: String,
    creation_time: String,
    sha256: String,
    stale: bool,
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

impl CrawlerRegistry {
    /// Parses and validates a registry artifact with every rule of §12.3
    /// (D-36), the same rules `mgctl crawler sync` applies before writing:
    ///
    /// * `v == 1`, `kind == "mg-crawler-registry"`, `generated_at` RFC 3339,
    ///   no unknown fields;
    /// * operator ids match `[a-z0-9][a-z0-9_-]{0,31}` and are unique;
    ///   `purpose` and `verify.mode` take the listed values; 1–8 `ua_tokens`
    ///   of 3–64 characters;
    /// * modes with rDNS have `rdns_suffixes`, each lower-case, 1–253 bytes,
    ///   starting with `.` and naming at least two non-empty labels after it
    ///   (`.googlebot.com`; not `googlebot.com`, `.com` or `.a..b`; I-22);
    ///   `ip_ranges` operators have `cidrs`; at most 20,000 CIDRs each;
    /// * every CIDR is a canonical network address with an IPv4 prefix of at
    ///   least /16 or an IPv6 prefix of at least /32 that intersects no
    ///   private, loopback, link-local, multicast, unspecified, CGNAT or
    ///   reserved range; documentation ranges only when `"test": true`;
    /// * `sources[].format` is `prefixes_json` or `cidr_text`, `sha256` is 64
    ///   lower-case hex characters, `fetched_at` is RFC 3339.
    ///
    /// Any violation rejects the whole artifact.
    pub fn from_artifact(json: &[u8]) -> Result<Self, IntelError> {
        check_size(
            "crawler-registry artifact",
            json.len(),
            ArtifactKind::CrawlerRegistry.max_size(),
        )?;
        let doc: RegistryDoc = serde_json::from_slice(json).map_err(|e| IntelError::json(&e))?;
        if doc.v != 1 {
            return Err(IntelError::invalid(format!("unsupported v {}", doc.v)));
        }
        if doc.kind != KIND {
            return Err(IntelError::invalid(format!(
                "kind is {}, want {KIND:?}",
                quote(&doc.kind)
            )));
        }
        if !is_rfc3339(&doc.generated_at) {
            return Err(IntelError::invalid(format!(
                "generated_at {} is not RFC 3339",
                quote(&doc.generated_at)
            )));
        }
        let mut operators = Vec::with_capacity(doc.operators.len());
        let mut index = HashMap::with_capacity(doc.operators.len());
        for (i, op) in doc.operators.into_iter().enumerate() {
            let at = format!("operators[{i}] ({})", quote(&op.id));
            let op = validate_operator(op, doc.test)
                .map_err(|e| IntelError::invalid(format!("{at}: {e}")))?;
            if index.insert(op.id.clone(), i).is_some() {
                return Err(IntelError::invalid(format!("{at}: duplicate operator id")));
            }
            operators.push(op);
        }
        Ok(Self {
            operators,
            index,
            generated_at: doc.generated_at,
            test: doc.test,
        })
    }

    /// `"test": true`: a Validation Lab / test registry that may use
    /// documentation ranges. The Edge logs a warning when it loads one.
    pub fn is_test(&self) -> bool {
        self.test
    }

    /// The artifact's `generated_at` (RFC 3339).
    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }

    /// Operators in file order.
    pub fn operators(&self) -> &[Operator] {
        &self.operators
    }

    /// The operator with this id.
    pub fn operator(&self, id: &str) -> Option<&Operator> {
        self.index.get(id).map(|&i| &self.operators[i])
    }

    /// The first operator (in file order) with a `ua_tokens` entry that is a
    /// case-insensitive (ASCII) substring of `ua`.
    pub fn match_ua(&self, ua: &str) -> Option<&Operator> {
        self.match_ua_index(ua).map(|i| &self.operators[i])
    }

    fn match_ua_index(&self, ua: &str) -> Option<usize> {
        if self.operators.is_empty() || ua.is_empty() {
            return None;
        }
        // One lower-cased copy, then linear-time substring searches: no
        // quadratic worst case on a hostile 8 KiB User-Agent.
        let ua = ua.to_ascii_lowercase();
        self.operators
            .iter()
            .position(|op| op.ua_tokens_lower.iter().any(|t| ua.contains(t.as_str())))
    }
}

/// The shape of an rDNS suffix (ruling I-22): a leading `.` followed by at
/// least two non-empty labels, so a suffix always matches on a label
/// boundary and never names a whole top-level domain (`.com`) or a bare
/// registrable name without its dot (`googlebot.com`, which would also match
/// `evilgooglebot.com`). Case and length are checked separately.
pub(crate) fn is_rdns_suffix(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('.') else {
        return false;
    };
    let mut labels = 0usize;
    for label in rest.split('.') {
        if label.is_empty() {
            return false;
        }
        labels += 1;
    }
    labels >= 2
}

fn validate_operator(op: OperatorDoc, test: bool) -> Result<Operator, String> {
    if !valid_id(&op.id) {
        return Err("id must match [a-z0-9][a-z0-9_-]{0,31}".into());
    }
    if !PURPOSES.contains(&op.purpose.as_str()) {
        return Err(format!("unknown purpose {}", quote(&op.purpose)));
    }
    if !UA_TOKENS.contains(&op.ua_tokens.len()) {
        return Err(format!("{} ua_tokens, want 1-8", op.ua_tokens.len()));
    }
    for t in &op.ua_tokens {
        if !UA_TOKEN_CHARS.contains(&t.chars().count()) {
            return Err(format!("ua_token {} must be 3-64 characters", quote(t)));
        }
    }
    let mode = VerifyMode::from_str(&op.verify.mode)
        .ok_or_else(|| format!("unknown verify.mode {}", quote(&op.verify.mode)))?;
    if mode.uses_rdns() && op.verify.rdns_suffixes.is_empty() {
        return Err(format!(
            "verify.mode {} requires rdns_suffixes",
            mode.as_str()
        ));
    }
    for s in &op.verify.rdns_suffixes {
        if !SUFFIX_BYTES.contains(&s.len()) {
            return Err(format!("rdns_suffix {} must be 1-253 bytes", quote(s)));
        }
        if s.chars().any(char::is_uppercase) {
            return Err(format!("rdns_suffix {} must be lower-case", quote(s)));
        }
        if !is_rdns_suffix(s) {
            return Err(format!(
                "rdns_suffix {} must start with '.' followed by at least two labels \
                 (e.g. .googlebot.com)",
                quote(s)
            ));
        }
    }
    if mode == VerifyMode::IpRanges && op.cidrs.is_empty() {
        return Err("verify.mode ip_ranges requires cidrs".into());
    }
    if op.cidrs.len() > MAX_CIDRS_PER_OPERATOR {
        return Err(format!(
            "{} cidrs, limit {MAX_CIDRS_PER_OPERATOR}",
            op.cidrs.len()
        ));
    }
    let mut prefixes = Vec::with_capacity(op.cidrs.len());
    for (i, c) in op.cidrs.iter().enumerate() {
        let prefix = Prefix::parse(c).map_err(|r| format!("cidrs[{i}] {}: {r}", quote(c)))?;
        check_published(prefix, MIN_V4_LEN, MIN_V6_LEN, test)
            .map_err(|r| format!("cidrs[{i}] {}: {r}", quote(c)))?;
        prefixes.push(prefix);
    }
    for (i, s) in op.sources.iter().enumerate() {
        if !SOURCE_FORMATS.contains(&s.format.as_str()) {
            return Err(format!("sources[{i}]: unknown format {}", quote(&s.format)));
        }
        if !is_lower_hex_sha256(&s.sha256) {
            return Err(format!(
                "sources[{i}]: sha256 must be 64 lower-case hex characters"
            ));
        }
        if !is_rfc3339(&s.fetched_at) {
            return Err(format!(
                "sources[{i}]: fetched_at {} is not RFC 3339",
                quote(&s.fetched_at)
            ));
        }
    }
    let ua_tokens_lower = op
        .ua_tokens
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    Ok(Operator {
        id: op.id,
        name: op.name,
        purpose: op.purpose,
        ua_tokens: op.ua_tokens,
        mode,
        rdns_suffixes: op.verify.rdns_suffixes,
        cidrs: IpSet::from_prefixes(prefixes),
        ua_tokens_lower,
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Which check produced a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyMethod {
    /// The operator's published IP ranges.
    IpRange,
    /// Reverse-then-forward DNS.
    Rdns,
}

impl VerifyMethod {
    /// Metric / event spelling: `ip_range` or `rdns`.
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMethod::IpRange => "ip_range",
            VerifyMethod::Rdns => "rdns",
        }
    }
}

/// The verification state of one request (spec §7.3 table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlerStatus {
    /// The User-Agent matches no operator.
    NotClaimed,
    /// The claim is verified.
    Verified {
        operator: String,
        purpose: String,
        method: VerifyMethod,
    },
    /// The claim is false (impersonation).
    Failed {
        operator: String,
        purpose: String,
        method: VerifyMethod,
    },
    /// rDNS is running or about to run. `outside_ranges` is true when the
    /// operator publishes ranges and the address is not in them (D-18).
    Pending {
        operator: String,
        purpose: String,
        outside_ranges: bool,
    },
    /// Cannot be decided: `"no_client_ip"` or `"dns_error"`.
    Unverifiable {
        operator: String,
        purpose: String,
        reason: &'static str,
    },
}

/// A reverse-DNS verification to run off the request path.
///
/// A job issued by [`CrawlerVerifier::check`] carries a private identity: the
/// verifier that issued it and the sequence number of the in-flight mark it
/// owns (ruling I-26). [`CrawlerVerifier::complete`] and
/// [`CrawlerVerifier::abandon`] clear that mark only while it is still this
/// job's, so a late job whose mark expired (and was replaced by a newer
/// job's) never releases the newer one: at most one job per `(ip, operator)`
/// is in flight (spec §7.3), also when jobs outlive `inflight_ttl_ms`.
#[derive(Clone, PartialEq, Eq)]
pub struct RdnsJob {
    /// The client address (canonical form).
    pub ip: IpAddr,
    /// The claimed operator.
    pub operator_id: String,
    /// The operator's `rdns_suffixes`.
    pub suffixes: Vec<String>,
    /// The issuing [`CrawlerVerifier`]'s id; 0 for a detached job.
    issuer: u64,
    /// The sequence number of the in-flight mark this job owns.
    seq: u64,
}

impl RdnsJob {
    /// A detached job, not issued by any verifier: for running
    /// [`crate::resolve_rdns`] on its own (tests, the Validation Lab).
    /// [`CrawlerVerifier::complete`] and [`CrawlerVerifier::abandon`] ignore
    /// it, so it can neither release an in-flight mark nor seed the cache.
    pub fn new(ip: IpAddr, operator_id: impl Into<String>, suffixes: Vec<String>) -> Self {
        Self {
            ip,
            operator_id: operator_id.into(),
            suffixes,
            issuer: 0,
            seq: 0,
        }
    }

    /// Whether `verifier` issued this job with [`CrawlerVerifier::check`].
    pub fn issued_by(&self, verifier: &CrawlerVerifier) -> bool {
        self.issuer != 0 && self.issuer == verifier.id
    }
}

impl fmt::Debug for RdnsJob {
    /// Never prints the client address (spec §2.4, D-31).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdnsJob")
            .field("ip", &"<redacted>")
            .field("operator_id", &self.operator_id)
            .field("suffixes", &self.suffixes)
            .field("issuer", &self.issuer)
            .field("seq", &self.seq)
            .finish()
    }
}

/// The result of [`crate::resolve_rdns`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RdnsOutcome {
    /// A forward answer contains the address.
    Pass,
    /// No matching name resolves back to the address.
    Fail,
    /// A DNS timeout or server error prevented a conclusion.
    DnsError,
}

/// rDNS cache and in-flight settings (spec §7.3). Times are milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    /// Most cached results; when full, the entry that expires first is
    /// evicted. Also bounds the number of in-flight marks. Minimum 1.
    pub capacity: usize,
    /// How long a `Pass` is cached (default 24 h).
    pub pass_ttl_ms: i64,
    /// How long a `Fail` is cached (default 1 h).
    pub fail_ttl_ms: i64,
    /// How long a `DnsError` is cached (default 5 min).
    pub error_ttl_ms: i64,
    /// After this long an unfinished job no longer blocks a new one
    /// (default 5 s).
    pub inflight_ttl_ms: i64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 100_000,
            pass_ttl_ms: 24 * 3_600_000,
            fail_ttl_ms: 3_600_000,
            error_ttl_ms: 300_000,
            inflight_ttl_ms: 5_000,
        }
    }
}

/// Crawler claim verification: registry lookups, the rDNS result cache and
/// the in-flight job set. Cheap for requests that claim no crawler (no lock);
/// claimed requests take one short mutex. All time comes from the caller.
pub struct CrawlerVerifier {
    /// Process-unique (never 0), so that a job is only ever reported to the
    /// verifier that issued it (see [`RdnsJob`]).
    id: u64,
    registry: Arc<CrawlerRegistry>,
    config: CacheConfig,
    state: Mutex<State>,
}

/// Source of [`CrawlerVerifier`] ids; 0 is reserved for detached jobs.
static NEXT_VERIFIER_ID: AtomicU64 = AtomicU64::new(1);

impl fmt::Debug for CrawlerVerifier {
    /// Sizes only: the cache is keyed by client addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("CrawlerVerifier");
        d.field("operators", &self.registry.operators.len())
            .field("config", &self.config);
        // try_lock: formatting must never block or deadlock a request.
        if let Ok(st) = self.state.try_lock() {
            d.field("cached", &st.cache.len())
                .field("inflight", &st.inflight.len());
        }
        d.finish()
    }
}

/// `(canonical client address, operator index)`.
type Key = (IpAddr, usize);

struct Timed<V> {
    value: V,
    /// Valid while `now < until`.
    until: i64,
    seq: u64,
}

/// A map whose entries expire, with an index ordered by expiry so the
/// soonest-expiring entry is found in O(log n).
struct ExpiringMap<V> {
    map: HashMap<Key, Timed<V>>,
    by_expiry: BTreeMap<(i64, u64), Key>,
}

impl<V> ExpiringMap<V> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            by_expiry: BTreeMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    /// The live value for `key`; an expired entry is removed.
    fn get(&mut self, key: &Key, now: i64) -> Option<&V> {
        let expired = match self.map.get(key) {
            None => return None,
            Some(t) => now >= t.until,
        };
        if expired {
            self.remove(key);
            return None;
        }
        self.map.get(key).map(|t| &t.value)
    }

    fn remove(&mut self, key: &Key) {
        if let Some(t) = self.map.remove(key) {
            self.by_expiry.remove(&(t.until, t.seq));
        }
    }

    /// Removes `key` only while its entry is the one inserted with `seq`
    /// (expired or not); a newer entry for the same key is left alone.
    fn remove_if_seq(&mut self, key: &Key, seq: u64) {
        if self.map.get(key).is_some_and(|t| t.seq == seq) {
            self.remove(key);
        }
    }

    /// Removes `key` from `map` only if it is still the entry indexed by
    /// `seq` (the index and the map never disagree, but a stale index entry
    /// must never delete a newer value).
    fn remove_indexed(&mut self, key: &Key, seq: u64) {
        if self.map.get(key).is_some_and(|t| t.seq == seq) {
            self.map.remove(key);
        }
    }

    /// Drops every entry that expired at `now`.
    fn purge_expired(&mut self, now: i64) {
        while let Some(entry) = self.by_expiry.first_entry() {
            let (until, seq) = *entry.key();
            if until > now {
                break;
            }
            let key = entry.remove();
            self.remove_indexed(&key, seq);
        }
    }

    /// Removes the entry that expires first; false when there is none.
    fn evict_first(&mut self) -> bool {
        match self.by_expiry.pop_first() {
            Some(((_, seq), key)) => {
                self.remove_indexed(&key, seq);
                true
            }
            None => false,
        }
    }

    fn insert(&mut self, key: Key, value: V, until: i64, seq: u64) {
        self.remove(&key);
        self.by_expiry.insert((until, seq), key);
        self.map.insert(key, Timed { value, until, seq });
    }
}

/// What [`CrawlerVerifier::probe`] found.
enum Probe {
    Cached(RdnsOutcome),
    InFlight,
    Saturated,
    /// A new in-flight mark with this sequence number.
    NewJob(u64),
}

struct State {
    cache: ExpiringMap<RdnsOutcome>,
    inflight: ExpiringMap<()>,
    seq: u64,
}

impl State {
    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
}

impl CrawlerVerifier {
    /// A verifier with an empty cache. `capacity` is raised to at least 1 and
    /// negative TTLs are treated as 0 (not cached).
    pub fn new(registry: Arc<CrawlerRegistry>, cache: CacheConfig) -> Self {
        let config = CacheConfig {
            capacity: cache.capacity.max(1),
            pass_ttl_ms: cache.pass_ttl_ms.max(0),
            fail_ttl_ms: cache.fail_ttl_ms.max(0),
            error_ttl_ms: cache.error_ttl_ms.max(0),
            inflight_ttl_ms: cache.inflight_ttl_ms.max(0),
        };
        Self {
            id: NEXT_VERIFIER_ID.fetch_add(1, Ordering::Relaxed),
            registry,
            config,
            state: Mutex::new(State {
                cache: ExpiringMap::new(),
                inflight: ExpiringMap::new(),
                seq: 0,
            }),
        }
    }

    /// The registry this verifier checks against.
    pub fn registry(&self) -> &CrawlerRegistry {
        &self.registry
    }

    /// The effective configuration (after clamping).
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    // Nothing under the lock panics, and a stale index entry can never
    // remove a newer value (`remove_indexed`), so a poisoned lock is still
    // safe to use.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Classifies one request (spec §7.3 table, top to bottom):
    ///
    /// 1. no operator's token in `ua` → `NotClaimed`;
    /// 2. no client IP → `Unverifiable { reason: "no_client_ip" }`;
    /// 3. IP in the operator's ranges → `Verified { method: IpRange }`;
    /// 4. mode `ip_ranges` → `Failed { method: IpRange }`;
    /// 5. cached rDNS result → `Verified` / `Failed { method: Rdns }` /
    ///    `Unverifiable { reason: "dns_error" }`;
    /// 6. otherwise `Pending`, plus an [`RdnsJob`] unless one for the same
    ///    `(ip, operator)` is already in flight.
    ///
    /// The caller runs the job with [`crate::resolve_rdns`] and reports it
    /// with [`CrawlerVerifier::complete`], or calls
    /// [`CrawlerVerifier::abandon`] if it will not run it.
    pub fn check(
        &self,
        ua: &str,
        ip: Option<IpAddr>,
        now_ms: i64,
    ) -> (CrawlerStatus, Option<RdnsJob>) {
        let Some(idx) = self.registry.match_ua_index(ua) else {
            return (CrawlerStatus::NotClaimed, None);
        };
        let op = &self.registry.operators[idx];
        let operator = || op.id.clone();
        let purpose = || op.purpose.clone();
        let Some(ip) = ip.map(|ip| ip.to_canonical()) else {
            let status = CrawlerStatus::Unverifiable {
                operator: operator(),
                purpose: purpose(),
                reason: "no_client_ip",
            };
            return (status, None);
        };
        if op.cidrs.contains(ip) {
            let status = CrawlerStatus::Verified {
                operator: operator(),
                purpose: purpose(),
                method: VerifyMethod::IpRange,
            };
            return (status, None);
        }
        if op.mode == VerifyMode::IpRanges {
            let status = CrawlerStatus::Failed {
                operator: operator(),
                purpose: purpose(),
                method: VerifyMethod::IpRange,
            };
            return (status, None);
        }

        let status = |outcome: Option<RdnsOutcome>| match outcome {
            Some(RdnsOutcome::Pass) => CrawlerStatus::Verified {
                operator: operator(),
                purpose: purpose(),
                method: VerifyMethod::Rdns,
            },
            Some(RdnsOutcome::Fail) => CrawlerStatus::Failed {
                operator: operator(),
                purpose: purpose(),
                method: VerifyMethod::Rdns,
            },
            Some(RdnsOutcome::DnsError) => CrawlerStatus::Unverifiable {
                operator: operator(),
                purpose: purpose(),
                reason: "dns_error",
            },
            None => CrawlerStatus::Pending {
                operator: operator(),
                purpose: purpose(),
                // Step 3 established that the address is outside the
                // ranges, so this is "does the operator publish any" (D-18).
                outside_ranges: !op.cidrs.is_empty(),
            },
        };
        match self.probe((ip, idx), now_ms) {
            Probe::Cached(outcome) => (status(Some(outcome)), None),
            Probe::InFlight | Probe::Saturated => (status(None), None),
            Probe::NewJob(seq) => {
                let job = RdnsJob {
                    ip,
                    operator_id: op.id.clone(),
                    suffixes: op.rdns_suffixes.clone(),
                    issuer: self.id,
                    seq,
                };
                (status(None), Some(job))
            }
        }
    }

    /// The locked part of [`CrawlerVerifier::check`]: cache lookup, then the
    /// in-flight mark.
    fn probe(&self, key: Key, now_ms: i64) -> Probe {
        let mut st = self.lock();
        if let Some(&outcome) = st.cache.get(&key, now_ms) {
            return Probe::Cached(outcome);
        }
        if st.inflight.get(&key, now_ms).is_some() {
            return Probe::InFlight;
        }
        st.inflight.purge_expired(now_ms);
        if st.inflight.len() >= self.config.capacity {
            // Saturated with live jobs (far beyond any sane rDNS
            // concurrency): stay Pending without a job; marks expire within
            // `inflight_ttl_ms`, so this never sticks.
            return Probe::Saturated;
        }
        let seq = st.next_seq();
        let until = now_ms.saturating_add(self.config.inflight_ttl_ms);
        st.inflight.insert(key, (), until, seq);
        Probe::NewJob(seq)
    }

    /// Records a finished job: clears its in-flight mark if the mark is still
    /// this job's (ruling I-26: a late job whose mark expired and was taken
    /// over by a newer job leaves the newer mark alone) and caches the
    /// outcome (`Pass` 24 h, `Fail` 1 h, `DnsError` 5 min by default). When
    /// the cache is full, the entry that expires first is evicted. Jobs this
    /// verifier did not issue (detached jobs, jobs of another verifier such
    /// as one replaced on a bundle reload, whose suffixes may be stale) and
    /// jobs for operators not in this verifier's registry are ignored.
    ///
    /// A `DnsError` never replaces a live `Pass` or `Fail`: it only arrives
    /// for a key that already has a conclusive result when a late job (one
    /// that outlived its in-flight mark, so a newer job ran meanwhile)
    /// reports its timeout, and that must not downgrade the newer verdict.
    pub fn complete(&self, job: &RdnsJob, outcome: RdnsOutcome, now_ms: i64) {
        let Some(key) = self.job_key(job) else {
            return;
        };
        let ttl = match outcome {
            RdnsOutcome::Pass => self.config.pass_ttl_ms,
            RdnsOutcome::Fail => self.config.fail_ttl_ms,
            RdnsOutcome::DnsError => self.config.error_ttl_ms,
        };
        let mut st = self.lock();
        st.inflight.remove_if_seq(&key, job.seq);
        if outcome == RdnsOutcome::DnsError
            && matches!(
                st.cache.get(&key, now_ms),
                Some(RdnsOutcome::Pass | RdnsOutcome::Fail)
            )
        {
            return;
        }
        st.cache.remove(&key);
        if ttl == 0 {
            return;
        }
        while st.cache.len() >= self.config.capacity && st.cache.evict_first() {}
        let seq = st.next_seq();
        st.cache
            .insert(key, outcome, now_ms.saturating_add(ttl), seq);
    }

    /// Releases the in-flight mark without caching a result (the job will
    /// not run: queue full, per-prefix limit, shutdown, or the task was
    /// cancelled). The next `check` for the same address issues a new job.
    /// Like [`CrawlerVerifier::complete`], it releases only the job's own
    /// mark (ruling I-26) and ignores jobs this verifier did not issue.
    pub fn abandon(&self, job: &RdnsJob) {
        let Some(key) = self.job_key(job) else {
            return;
        };
        self.lock().inflight.remove_if_seq(&key, job.seq);
    }

    /// The cache key of a job this verifier issued, or `None` for any other
    /// job (detached, another verifier's, or an unknown operator).
    fn job_key(&self, job: &RdnsJob) -> Option<Key> {
        if !job.issued_by(self) {
            return None;
        }
        let &idx = self.registry.index.get(&job.operator_id)?;
        Some((job.ip.to_canonical(), idx))
    }
}
