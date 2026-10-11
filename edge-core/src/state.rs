//! State layer (spec §9.7, §9.8): Valkey pipelines with the `mg_gcra` and
//! `mg_nonce_issue` Lua scripts, verdict `MGET`, the circuit breaker, and the
//! local mode (bounded GCRA table, fixed-capacity TTL nonce set).
//!
//! Implemented by work package WP-C3 (docs/impl/phase1-spec.md §15).
//!
//! # Process model (spec §9.1.1)
//!
//! [`StateService::new`] is synchronous and needs no runtime, so `mg-edge`
//! calls it in `main()` before Pingora daemonizes. It returns the service and
//! a cloneable [`StateHandle`]. The service is then run with
//! [`StateService::run`] inside the `mg-state` Pingora background service:
//! **all Valkey I/O happens on that runtime**. Proxies only talk to the
//! service through bounded channels and wait at most `timeout_ms` for a
//! reply; on a timeout, an error, an open circuit or before the service is
//! ready they fall back to the process-local tables:
//!
//! | Operation | Valkey | Local fallback |
//! |---|---|---|
//! | [`StateHandle::round_trip1`] | one pipeline: `MGET` verdicts + `EVALSHA mg_gcra` | no verdicts (except still-fresh cached ones), local GCRA table |
//! | [`StateHandle::nonce_issue`] | `EVALSHA mg_nonce_issue` after the local replay check | local replay set + local GCRA table (all-or-nothing) |
//! | [`StateHandle::record_failure`] | async `EVALSHA mg_gcra` by one consumer | local GCRA table |
//! | [`StateHandle::xadd_batch`] | one pipeline of `XADD mg:ev MAXLEN ~ n *` | error (the caller counts a drop) |
//! | [`StateHandle::local_check`] | never | local GCRA table (`scope = local`) |
//! | [`StateHandle::round_trip1_v2`] (Phase 2) | as `round_trip1`, plus `EVALSHA mg_jti` after the local `jti` check | as `round_trip1`; the local `jti` verdict only under the §9.2 conditions |
//! | [`StateHandle::nonce_issue_v2`] (Phase 2) | `EVALSHA mg_nonce_issue` v2 after the local nonce and token checks | local nonce and token sets + local GCRA table (all-or-nothing) |
//!
//! Phase 2 (docs/impl/phase2-spec.md §9.2, §14; WP-C5) adds the second pair
//! as new entry points; the Phase 1 calls keep their behaviour until the
//! stage 2 switch (§2.3). The Edge loads all four scripts at connect time.
//!
//! # Circuit breaker
//!
//! A round trip that fails or misses its deadline counts as a failure; only a
//! success within `timeout_ms` resets the count (the async failure consumer
//! waits longer, and its slow successes must not keep a Valkey that is too
//! slow for requests from tripping the breaker). After 5 consecutive failures
//! the connection is dropped (a blackholed TCP connection would otherwise
//! stall later requests) and Valkey is not used for 1 s. Recovery is probed with `PING` + `SCRIPT LOAD` on a fresh
//! connection; every failed probe doubles the wait up to 30 s. A later trip
//! continues the doubling unless the circuit stayed closed for at least 30 s,
//! which restarts it at 1 s. `XADD` failures do not move the breaker.
//!
//! # Replay set
//!
//! The in-process replay set is authoritative (with
//! `local_replay_authoritative`) only for challenges issued after the
//! process started *and* after the set was last full: a nonce presented while
//! the set was full could not be recorded, so its replay must not be judged
//! fresh later (§9.7 rule 3, D-35).
//!
//! # Keys
//!
//! Every key part that identifies a person is pseudonymized with the
//! owner-level key `K_pseudo` ([`kh`], D-06); plaintext dimension values
//! (client IP entities, prefixes) only exist in memory and are never logged or
//! printed by `Debug`.
//!
//! # Metrics
//!
//! This module registers (in the default prometheus registry, spec §13.7):
//! `mg_valkey_rtt_seconds`, `mg_valkey_errors_total{op}`,
//! `mg_state_mode{mode}`, `mg_state_local_overflow_total{table}`,
//! `mg_state_async_dropped_total` and `mg_verdict_parse_errors_total`
//! (the latter through [`parse_verdict`]). `mg-edge` must not register these
//! names again.

pub mod builtin;
mod health;
mod local;
mod metrics;
mod service;
mod valkey;
mod verdicts;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use mg_core::gcra::{GcraOutcome, GcraParams};
use sha2::Sha256;

pub use service::{StateHandle, StateService, StateStatus};

/// `mg_gcra` v1 (spec §9.7), byte-for-byte as specified.
pub const MG_GCRA_LUA: &str = include_str!("state/lua/mg_gcra.lua");
/// `mg_nonce_issue` v1 (spec §9.7, D-37), byte-for-byte as specified.
pub const MG_NONCE_ISSUE_LUA: &str = include_str!("state/lua/mg_nonce_issue.lua");
/// `mg_nonce_issue` v2 (Phase 2 spec §14.2), byte-for-byte as specified:
/// the nonce, then at most one provider-token replay key, then the issuance
/// quotas (all-or-nothing).
pub const MG_NONCE_ISSUE_V2_LUA: &str = include_str!("state/lua/mg_nonce_issue_v2.lua");
/// `mg_jti` v1 (Phase 2 spec §9.2, §14.2), byte-for-byte as specified.
pub const MG_JTI_LUA: &str = include_str!("state/lua/mg_jti.lua");

/// HMAC domain of entity keys (`mg:v:*` verdict keys, `mg:ev` `ipk` / `pfk`).
pub const ENTITY_DOMAIN: &str = "mg-ent-v1";
/// HMAC domain of limiter keys (`mg:rl:*`).
pub const LIMITER_DOMAIN: &str = "mg-rl-v1";
/// HMAC domain of the per-key part `kj` of `mg:jti:*` / `mg:jc:*` (Phase 2
/// spec §9.2): `kj = kh("mg-jti-v1", "jkt", jkt)`.
pub const JTI_DOMAIN: &str = "mg-jti-v1";
/// Value of an unknown `ip` / `ip_prefix` / `asn` dimension: one shared
/// fallback bucket, never skipped (D-23).
pub const UNKNOWN_DIM: &str = "?";
/// `dims` of a limiter's overflow bucket in the local GCRA table (§9.7).
pub const OVERFLOW_DIMS: &str = "~overflow";
/// The events stream (§13.6).
pub const EVENT_STREAM_KEY: &str = "mg:ev";

/// Capacity of the async failure-count channel (§9.7).
pub const FAILURE_QUEUE_CAPACITY: usize = 1024;
/// Capacity of the proxy -> `mg-state` request channel. A full queue is
/// treated like a Valkey timeout (local fallback).
pub const REQUEST_QUEUE_CAPACITY: usize = 4096;
/// Verdict cache lifetime, including "no verdict" results (§9.7).
pub const VERDICT_CACHE_TTL_MS: u64 = 2_000;
/// Verdict cache capacity (§9.7).
pub const VERDICT_CACHE_CAPACITY: usize = 50_000;
/// Verdict values longer than this are ignored (counted as parse errors).
pub const MAX_VERDICT_BYTES: usize = 4096;

/// Upper bound of [`NonceIssue::ttl_ms`] (a sealed challenge lives for
/// minutes; this only keeps a bad value from pinning replay entries forever
/// or overflowing the script's `PX` argument).
pub const MAX_NONCE_TTL_MS: u64 = 86_400_000;

/// `edge.toml` `[valkey]` defaults (spec §8.1).
pub const DEFAULT_TIMEOUT_MS: u64 = 10;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 500;
pub const DEFAULT_LOCAL_LIMITER_CAPACITY: usize = 200_000;
pub const DEFAULT_LOCAL_NONCE_CAPACITY: usize = 200_000;
/// `[valkey] local_jti_capacity` default (Phase 2 spec §10.1).
pub const DEFAULT_LOCAL_JTI_CAPACITY: usize = 100_000;
/// `[valkey] local_rp_capacity` default (Phase 2 spec §10.1).
pub const DEFAULT_LOCAL_RP_CAPACITY: usize = 10_000;

/// `mg:jti:*` lifetime (Phase 2 spec §9.2): `SET … NX EX 40`.
pub const JTI_TTL_S: u64 = 40;
/// Window of the per-key `jti` counter `mg:jc:*` (Phase 2 spec §9.2).
pub const JTI_COUNTER_WINDOW_MS: u64 = 60_000;
/// `jti`s per session key and counter window; beyond it every proof of that
/// key counts as a replay of that key (Phase 2 spec §9.2).
pub const JTI_PER_KEY_LIMIT: u32 = 600;
/// A proof's `iat` may be at most this far ahead of `now` (Phase 2 spec
/// §6.7); the local `jti` verdict uses it in its start-time rule (§9.2).
pub const JTI_IAT_SKEW_S: i64 = 5;
/// Lifetime of a provider-token replay key `mg:rp:*` (Phase 2 spec §14.1).
pub const TOKEN_REPLAY_TTL_MS: u64 = 300_000;

/// `kh(domain, type, value) = lower_hex(HMAC-SHA256(K_pseudo, domain ‖ 0x00 ‖
/// type ‖ 0x00 ‖ value))[0..32]` (spec §9.7; KAT `kat.json` `entity_key`).
pub fn kh(k_pseudo: &[u8; 32], domain: &str, typ: &str, value: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(k_pseudo)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(typ.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    let tag = mac.finalize().into_bytes();
    lower_hex(&tag[..16])
}

/// Entity key of an `ip` (value: `Net::entity_of`) or `prefix` (value:
/// `Net::prefix_of`) verdict, also used as `ipk` / `pfk` in `mg:ev` (§13.6).
pub fn entity_key(k_pseudo: &[u8; 32], typ: &str, value: &str) -> String {
    kh(k_pseudo, ENTITY_DOMAIN, typ, value)
}

/// `mg:v:{site}:{type}:{key}` (`site` = [`mg_core::EntityVerdict::ALL_SITES`]
/// for shared verdicts).
pub fn verdict_key(site: &str, typ: &str, key: &str) -> String {
    format!("mg:v:{site}:{typ}:{key}")
}

/// `mg:n:{site}:{nonce_hex}`.
pub fn nonce_key(site: &str, nonce: &[u8; 16]) -> String {
    format!("mg:n:{site}:{}", lower_hex(nonce))
}

/// `kj = kh("mg-jti-v1", "jkt", jkt)` of a session key's 43-character JWK
/// thumbprint (Phase 2 spec §9.2). The thumbprint itself never appears in a
/// key, a log line or `Debug` output (§2.4 item 10).
pub fn jti_key_hash(k_pseudo: &[u8; 32], jkt: &str) -> String {
    kh(k_pseudo, JTI_DOMAIN, "jkt", jkt)
}

/// `mg:jti:{site}:{kj}:{jti}` (Phase 2 spec §14.1).
pub fn jti_key(site: &str, kj: &str, jti: &str) -> String {
    format!("mg:jti:{site}:{kj}:{jti}")
}

/// `mg:jc:{site}:{kj}`: the per-key `jti` counter (Phase 2 spec §14.1).
pub fn jti_count_key(site: &str, kj: &str) -> String {
    format!("mg:jc:{site}:{kj}")
}

/// `th = lower_hex(SHA-256(token))[0..32]` of a provider token (Phase 2 spec
/// §14.1).
pub fn token_hash(token: &str) -> String {
    use sha2::Digest as _;
    lower_hex(&Sha256::digest(token.as_bytes())[..16])
}

/// `mg:rp:{site}:{provider}:{th}` (Phase 2 spec §14.1); `th` from
/// [`token_hash`].
pub fn replay_key(site: &str, provider: &str, th: &str) -> String {
    format!("mg:rp:{site}:{provider}:{th}")
}

/// Limiter `dims`: `name=value` pairs in the limiter's declared key order,
/// joined by `&`; `None` (unknown) becomes [`UNKNOWN_DIM`] (§9.7).
///
/// The caller decides which dimensions skip the limiter instead (a `session`
/// dimension without a valid clearance, an `asn` dimension on a site without
/// a `geoip-asn` artifact).
pub fn dims(parts: &[(&str, Option<&str>)]) -> String {
    let mut out = String::new();
    for (i, (name, value)) in parts.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value.unwrap_or(UNKNOWN_DIM));
    }
    out
}

/// Parses a verdict value read by [`StateHandle::round_trip1`]; invalid JSON
/// is ignored and counted in `mg_verdict_parse_errors_total` (§9.7).
pub fn parse_verdict(raw: &str) -> Option<mg_core::EntityVerdict> {
    match serde_json::from_str(raw) {
        Ok(v) => Some(v),
        Err(_) => {
            metrics::get().verdict_parse_errors.inc();
            None
        }
    }
}

/// One limiter bucket: `mg:rl:{site}:{limiter}:{kh("mg-rl-v1", limiter, dims)}`.
#[derive(Clone, PartialEq, Eq)]
pub struct LimiterKey {
    pub site: String,
    pub limiter: String,
    /// Plaintext dimensions per §9.7 (`?` for unknown); built with [`dims`].
    /// Never logged: it can hold a client IP.
    pub dims: String,
}

impl LimiterKey {
    pub fn new(
        site: impl Into<String>,
        limiter: impl Into<String>,
        dims: impl Into<String>,
    ) -> Self {
        Self {
            site: site.into(),
            limiter: limiter.into(),
            dims: dims.into(),
        }
    }

    /// The Valkey key of this bucket.
    pub fn redis_key(&self, k_pseudo: &[u8; 32]) -> String {
        format!(
            "mg:rl:{}:{}:{}",
            self.site,
            self.limiter,
            kh(k_pseudo, LIMITER_DOMAIN, &self.limiter, &self.dims)
        )
    }
}

impl fmt::Debug for LimiterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LimiterKey")
            .field("site", &self.site)
            .field("limiter", &self.limiter)
            .field("dims", &"<redacted>")
            .finish()
    }
}

/// One GCRA check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitCheck {
    pub key: LimiterKey,
    /// From [`GcraParams::new`] (bounded by §8.2). Out-of-range values are
    /// clamped so that neither the Rust nor the Lua arithmetic can overflow;
    /// a clamped check that could never pass still never passes.
    pub params: GcraParams,
    /// Requests consumed (Phase 1: 1; 0 counts as 1).
    pub cost: u32,
    /// `true`: store the new TAT when allowed; `false`: check only.
    /// Ignored by [`StateHandle::nonce_issue`], whose quotas are written iff
    /// all of them allow (as `mg_nonce_issue` does).
    pub write: bool,
}

/// Round trip 1 of a request (§9.7 table): verdict keys (read with `MGET`)
/// and the request's global limiters (one `EVALSHA mg_gcra`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RoundTrip1 {
    /// Built with [`verdict_key`], in the order of §9.7 (ip, prefix, asn,
    /// session, then shared `all` keys).
    pub verdict_keys: Vec<String>,
    /// Global limiters only; `scope = local` limiters use
    /// [`StateHandle::local_check`].
    pub limits: Vec<LimitCheck>,
}

impl fmt::Debug for RoundTrip1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoundTrip1")
            .field("verdict_keys", &self.verdict_keys.len())
            .field("limits", &self.limits)
            .finish()
    }
}

/// Result of [`StateHandle::round_trip1`]; one entry per requested item, in
/// request order.
#[derive(Clone, PartialEq, Eq)]
pub struct RoundTrip1Result {
    /// Raw verdict JSON (`None`: no verdict, or unknown in local mode). Parse
    /// with [`parse_verdict`].
    pub verdicts: Vec<Option<String>>,
    /// One outcome per [`RoundTrip1::limits`] entry. For Valkey outcomes,
    /// `new_tat_us` is expressed on the Edge clock (the script stored the
    /// state already; the value is informational).
    pub limits: Vec<GcraOutcome>,
    /// Where the limiter outcomes came from.
    pub mode: StateMode,
}

impl fmt::Debug for RoundTrip1Result {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self.verdicts.iter().filter(|v| v.is_some()).count();
        f.debug_struct("RoundTrip1Result")
            .field("verdicts_present", &present)
            .field("verdicts", &self.verdicts.len())
            .field("limits", &self.limits)
            .field("mode", &self.mode)
            .finish()
    }
}

/// Round trip 2 of `POST /__mg/c` (§9.7, D-37): the sealed challenge's nonce
/// plus the issuance quotas (`mg.clr.issue.ipp`, `mg.clr.issue.asn`).
#[derive(Clone, PartialEq, Eq)]
pub struct NonceIssue {
    pub site: String,
    pub nonce: [u8; 16],
    /// `exp_ms − now_ms + 60000` (§9.7 key table); clamped to
    /// `1..=MAX_NONCE_TTL_MS`.
    pub ttl_ms: u64,
    pub limits: Vec<LimitCheck>,
}

impl fmt::Debug for NonceIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceIssue")
            .field("site", &self.site)
            .field("nonce", &"<redacted>")
            .field("ttl_ms", &self.ttl_ms)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Outcome of [`StateHandle::nonce_issue`].
///
/// `Fresh` / `Unavailable` carry the issuance-quota outcomes (from Valkey, or
/// from the local table when Valkey gave no answer); `Unavailable` = no
/// authoritative replay check (§9.7 rules 3-4): the caller answers 429
/// `ic.replay_unavailable` on `fail_closed` routes and otherwise issues with
/// `ic.replay_unchecked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceResult {
    /// The nonce was used before (`ic.nonce_reused`); no quota was consumed.
    Reused,
    Fresh {
        limits: Vec<GcraOutcome>,
    },
    Unavailable {
        limits: Vec<GcraOutcome>,
    },
}

/// A provider token's replay key in `mg_nonce_issue` v2 (Phase 2 spec
/// §14.1, §14.2): `mg:rp:{site}:{provider}:{th}`, kept for
/// [`TOKEN_REPLAY_TTL_MS`]. Only the token's hash is held.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenReplay {
    /// Provider id (`turnstile`).
    pub provider: String,
    /// [`token_hash`] of the token.
    pub token_hash: String,
}

impl TokenReplay {
    /// The replay key of `token` (never stored itself).
    pub fn new(provider: impl Into<String>, token: &str) -> Self {
        Self {
            provider: provider.into(),
            token_hash: token_hash(token),
        }
    }
}

impl fmt::Debug for TokenReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenReplay")
            .field("provider", &self.provider)
            .field("token_hash", &"<redacted>")
            .finish()
    }
}

/// Round trip 2 of `POST /__mg/c` v2 and `POST /__mg/c/renew` (Phase 2 spec
/// §14.2, §14.3): the sealed challenge's nonce, the provider token's replay
/// key (`p = turnstile`) and the issuance quotas. A renewal sends only the
/// nonce (`replay: None`, no limits).
#[derive(Clone, PartialEq, Eq)]
pub struct NonceIssueV2 {
    pub site: String,
    pub nonce: [u8; 16],
    /// `exp_ms − now_ms + 60000`; clamped to `1..=MAX_NONCE_TTL_MS`.
    pub ttl_ms: u64,
    pub replay: Option<TokenReplay>,
    pub limits: Vec<LimitCheck>,
}

impl fmt::Debug for NonceIssueV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceIssueV2")
            .field("site", &self.site)
            .field("nonce", &"<redacted>")
            .field("ttl_ms", &self.ttl_ms)
            .field("replay", &self.replay)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Outcome of [`StateHandle::nonce_issue_v2`] (Phase 2 spec §14.2, §14.4).
///
/// As [`NonceResult`], plus [`NonceResultV2::TokenReused`]: the provider
/// token was presented before (`ic.ts_dup`); the nonce **is** consumed, no
/// quota is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceResultV2 {
    /// The nonce was used before (`ic.nonce_reused`); nothing else changed.
    Reused,
    /// The provider token was used before; the nonce is consumed.
    TokenReused,
    Fresh {
        limits: Vec<GcraOutcome>,
    },
    /// No authoritative replay check (Phase 1 spec §9.7 rules 3-4).
    Unavailable {
        limits: Vec<GcraOutcome>,
    },
}

/// The `MG-Proof` replay check of a request (Phase 2 spec §9.2), part of
/// [`RoundTrip1V2`]. Only for proofs that passed §6.7.
#[derive(Clone, PartialEq, Eq)]
pub struct JtiCheck {
    pub site: String,
    /// [`jti_key_hash`] of the proof key's thumbprint.
    pub kj: String,
    /// The proof's 22-character `jti`, verbatim.
    pub jti: String,
    /// The proof's `iat` (Unix seconds).
    pub iat_s: i64,
}

impl JtiCheck {
    /// Computes `kj` from the thumbprint `jkt`.
    pub fn new(
        site: impl Into<String>,
        k_pseudo: &[u8; 32],
        jkt: &str,
        jti: impl Into<String>,
        iat_s: i64,
    ) -> Self {
        Self {
            site: site.into(),
            kj: jti_key_hash(k_pseudo, jkt),
            jti: jti.into(),
            iat_s,
        }
    }

    /// `mg:jti:{site}:{kj}:{jti}`.
    pub fn key(&self) -> String {
        jti_key(&self.site, &self.kj, &self.jti)
    }

    /// `mg:jc:{site}:{kj}`.
    pub fn count_key(&self) -> String {
        jti_count_key(&self.site, &self.kj)
    }
}

impl fmt::Debug for JtiCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JtiCheck")
            .field("site", &self.site)
            .field("kj", &"<redacted>")
            .field("jti", &"<redacted>")
            .field("iat_s", &self.iat_s)
            .finish()
    }
}

/// Result of a [`JtiCheck`] (Phase 2 spec §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiOutcome {
    /// First use of this `jti`.
    Fresh,
    /// `proof.replay`: the `jti` was used before.
    Replayed,
    /// The key exceeded [`JTI_PER_KEY_LIMIT`] proofs per window; treated as
    /// a replay of this key only (not a global overflow).
    KeyQuota,
    /// No authoritative answer: "replay store unavailable".
    Unavailable,
}

impl JtiOutcome {
    /// [`JtiOutcome::Replayed`] or [`JtiOutcome::KeyQuota`].
    pub fn is_replay(self) -> bool {
        matches!(self, Self::Replayed | Self::KeyQuota)
    }
}

/// Round trip 1 of a Phase 2 request (Phase 2 spec §14.3): as
/// [`RoundTrip1`], plus `EVALSHA mg_jti` in the same pipeline when the
/// request carries a valid proof.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RoundTrip1V2 {
    pub verdict_keys: Vec<String>,
    pub limits: Vec<LimitCheck>,
    pub jti: Option<JtiCheck>,
}

impl fmt::Debug for RoundTrip1V2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoundTrip1V2")
            .field("verdict_keys", &self.verdict_keys.len())
            .field("limits", &self.limits)
            .field("jti", &self.jti)
            .finish()
    }
}

/// Result of [`StateHandle::round_trip1_v2`].
#[derive(Clone, PartialEq, Eq)]
pub struct RoundTrip1V2Result {
    /// As [`RoundTrip1Result::verdicts`].
    pub verdicts: Vec<Option<String>>,
    /// As [`RoundTrip1Result::limits`].
    pub limits: Vec<GcraOutcome>,
    /// Where the limiter outcomes came from.
    pub mode: StateMode,
    /// `Some` iff [`RoundTrip1V2::jti`] was set.
    pub jti: Option<JtiOutcome>,
}

impl fmt::Debug for RoundTrip1V2Result {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self.verdicts.iter().filter(|v| v.is_some()).count();
        f.debug_struct("RoundTrip1V2Result")
            .field("verdicts_present", &present)
            .field("verdicts", &self.verdicts.len())
            .field("limits", &self.limits)
            .field("mode", &self.mode)
            .field("jti", &self.jti)
            .finish()
    }
}

/// Configured mode (`edge.toml` `[valkey] mode`), and the source of a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StateMode {
    Valkey,
    Local,
}

impl StateMode {
    /// Metric label (`mg_state_mode{mode}`) and config value.
    pub fn as_str(self) -> &'static str {
        match self {
            StateMode::Valkey => "valkey",
            StateMode::Local => "local",
        }
    }
}

/// Circuit-breaker tuning. The defaults are the spec's values (§9.7:
/// 5 consecutive failures, open 1 s, doubling up to 30 s); they are not
/// `edge.toml` settings and only tests change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub base_open_ms: u64,
    pub max_open_ms: u64,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            base_open_ms: 1_000,
            max_open_ms: 30_000,
        }
    }
}

/// `edge.toml` `[valkey]` (spec §8.1) plus the resolved pseudonymization key.
#[derive(Clone)]
pub struct StateConfig {
    pub mode: StateMode,
    /// Required for [`StateMode::Valkey`]: `redis://[user@]host[:port][/db]`
    /// (or `unix:///path`, as the tests use). Must not contain a password.
    /// `rediss://` is rejected by [`StateConfig::validate`]: the redis
    /// client is built without TLS support.
    pub url: Option<String>,
    /// The ACL user's password (from `cred://`); never logged.
    pub password: Option<String>,
    /// Per round trip, measured from the proxy's submission.
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    /// `true` only when exactly one Edge serves these sites (§9.7 rule 3).
    pub local_replay_authoritative: bool,
    pub local_limiter_capacity: usize,
    pub local_nonce_capacity: usize,
    /// `[valkey] local_jti_capacity` (Phase 2 spec §9.2, §10.1): the
    /// in-process `MG-Proof` `jti` set and its per-key counters.
    pub local_jti_capacity: usize,
    /// `[valkey] local_rp_capacity` (Phase 2 spec §14.4): the in-process
    /// provider-token replay set.
    pub local_rp_capacity: usize,
    /// `K_pseudo` (`pseudo.key.json`, §12.7).
    pub k_pseudo: [u8; 32],
    /// Unix ms at which this process started: sealed challenges issued
    /// earlier are never judged by the in-process replay set alone (D-35).
    pub process_start_ms: i64,
    pub breaker: BreakerConfig,
}

impl StateConfig {
    /// Local mode with the `edge.toml` defaults; `process_start_ms` = now.
    pub fn local(k_pseudo: [u8; 32]) -> Self {
        Self {
            mode: StateMode::Local,
            url: None,
            password: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            local_replay_authoritative: false,
            local_limiter_capacity: DEFAULT_LOCAL_LIMITER_CAPACITY,
            local_nonce_capacity: DEFAULT_LOCAL_NONCE_CAPACITY,
            local_jti_capacity: DEFAULT_LOCAL_JTI_CAPACITY,
            local_rp_capacity: DEFAULT_LOCAL_RP_CAPACITY,
            k_pseudo,
            process_start_ms: unix_now_ms(),
            breaker: BreakerConfig::default(),
        }
    }

    /// Valkey mode with the `edge.toml` defaults.
    pub fn valkey(url: impl Into<String>, k_pseudo: [u8; 32]) -> Self {
        Self {
            mode: StateMode::Valkey,
            url: Some(url.into()),
            ..Self::local(k_pseudo)
        }
    }

    /// Checks what `mg-edge --check-config` can check without the network:
    /// the URL parses and carries no password, timeouts and capacities are
    /// non-zero.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.timeout_ms == 0 || self.connect_timeout_ms == 0 {
            return Err(StateError::Config("timeouts must be >= 1 ms".into()));
        }
        if self.local_limiter_capacity == 0
            || self.local_nonce_capacity == 0
            || self.local_jti_capacity == 0
            || self.local_rp_capacity == 0
        {
            return Err(StateError::Config("local capacities must be >= 1".into()));
        }
        let b = &self.breaker;
        if b.failure_threshold == 0 || b.base_open_ms == 0 || b.max_open_ms < b.base_open_ms {
            return Err(StateError::Config(
                "invalid circuit breaker settings".into(),
            ));
        }
        if self.mode == StateMode::Valkey {
            valkey::connection_info(self).map(|_| ())
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for StateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateConfig")
            .field("mode", &self.mode)
            .field("url_set", &self.url.is_some())
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("timeout_ms", &self.timeout_ms)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field(
                "local_replay_authoritative",
                &self.local_replay_authoritative,
            )
            .field("local_limiter_capacity", &self.local_limiter_capacity)
            .field("local_nonce_capacity", &self.local_nonce_capacity)
            .field("local_jti_capacity", &self.local_jti_capacity)
            .field("local_rp_capacity", &self.local_rp_capacity)
            .field("k_pseudo", &"<redacted>")
            .field("process_start_ms", &self.process_start_ms)
            .field("breaker", &self.breaker)
            .finish()
    }
}

/// Errors of the state layer. Messages never contain key material, client
/// IPs or the Valkey password.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// Local mode, not connected yet, or the circuit is open.
    #[error("valkey unavailable")]
    Unavailable,
    #[error("valkey round trip timed out")]
    Timeout,
    #[error("state request queue full")]
    Overloaded,
    #[error("valkey error: {0}")]
    Valkey(String),
    #[error("unexpected valkey reply: {0}")]
    Reply(&'static str),
    #[error("invalid state configuration: {0}")]
    Config(String),
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Wall clock in Unix microseconds (0 before the epoch).
pub(crate) fn unix_now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Wall clock in Unix milliseconds (0 before the epoch).
pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dims_joins_in_declared_order_and_marks_unknown() {
        assert_eq!(dims(&[]), "");
        assert_eq!(dims(&[("ip", Some("203.0.113.7"))]), "ip=203.0.113.7");
        assert_eq!(dims(&[("ip", None)]), "ip=?");
        assert_eq!(
            dims(&[
                ("ip_prefix", Some("203.0.113.0/24")),
                ("route", Some("api"))
            ]),
            "ip_prefix=203.0.113.0/24&route=api"
        );
    }

    #[test]
    fn key_formats() {
        let k = [7u8; 32];
        assert_eq!(verdict_key("blog", "asn", "64500"), "mg:v:blog:asn:64500");
        let mut nonce = [0u8; 16];
        nonce[15] = 0xab;
        assert_eq!(
            nonce_key("blog", &nonce),
            "mg:n:blog:000000000000000000000000000000ab"
        );
        let lk = LimiterKey::new("blog", "login-per-ip", "ip=?");
        let key = lk.redis_key(&k);
        let expected_kh = kh(&k, LIMITER_DOMAIN, "login-per-ip", "ip=?");
        assert_eq!(key, format!("mg:rl:blog:login-per-ip:{expected_kh}"));
        assert_eq!(expected_kh.len(), 32);
        assert!(
            expected_kh
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn debug_never_prints_dims_nonce_or_secrets() {
        let lk = LimiterKey::new("blog", "l", "ip=203.0.113.7");
        assert!(!format!("{lk:?}").contains("203.0.113.7"));
        let ni = NonceIssue {
            site: "blog".into(),
            nonce: [0xcd; 16],
            ttl_ms: 1,
            limits: vec![],
        };
        assert!(!format!("{ni:?}").contains("cdcd"));
        let mut cfg = StateConfig::valkey("redis://edge@127.0.0.1:6379/0", [0x5a; 32]);
        cfg.password = Some("hunter2-secret".into());
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("90, 90"));
        assert!(!dbg.contains("127.0.0.1"));
        let r = RoundTrip1Result {
            verdicts: vec![Some("{\"key\":\"secret-session\"}".into())],
            limits: vec![],
            mode: StateMode::Local,
        };
        assert!(!format!("{r:?}").contains("secret-session"));
    }

    #[test]
    fn validate_config() {
        let k = [1u8; 32];
        assert!(StateConfig::local(k).validate().is_ok());
        assert!(
            StateConfig::valkey("redis://edge@127.0.0.1:6379/0", k)
                .validate()
                .is_ok()
        );
        assert!(
            StateConfig::valkey("unix:///tmp/v.sock", k)
                .validate()
                .is_ok()
        );
        let mut no_url = StateConfig::local(k);
        no_url.mode = StateMode::Valkey;
        assert!(no_url.validate().is_err());
        assert!(StateConfig::valkey("not a url", k).validate().is_err());
        assert!(
            StateConfig::valkey("rediss://edge@127.0.0.1/", k)
                .validate()
                .is_err()
        );
        let with_pw = StateConfig::valkey("redis://edge:pw@127.0.0.1:6379/0", k);
        assert!(matches!(with_pw.validate(), Err(StateError::Config(m)) if !m.contains("pw@")));
        let mut zero = StateConfig::local(k);
        zero.timeout_ms = 0;
        assert!(zero.validate().is_err());
        let mut cap = StateConfig::local(k);
        cap.local_nonce_capacity = 0;
        assert!(cap.validate().is_err());
    }

    #[test]
    fn parse_verdict_counts_errors() {
        let before = metrics::get().verdict_parse_errors.get();
        assert!(parse_verdict("not json").is_none());
        assert!(metrics::get().verdict_parse_errors.get() > before);
        let ok = r#"{"type":"ip","key":"k","risk":80,"expires_at_ms":1,"source":"owner","version":"1","site_id":"blog"}"#;
        assert!(parse_verdict(ok).is_some());
    }
}
