//! Clearance tokens: PASETO v4.local in the `__Host-mg_clr` cookie (spec
//! §6.5, §6.6, docs/04 §5).
//!
//! ```json
//! {"v":1,"kid":"blog-t-20260927","sid":"blog","env":"production",
//!  "sub":"<base64url 16 random bytes>","sst":1790000000,"lvl":"invisible","iat":1790000000,"exp":1790001800,
//!  "bind":{"uah":"…","ipp":"…","ipa":"…"},"rb":"medium","jti":"<base64url 16 random bytes>"}
//! ```
//!
//! * `ruc` (I-30): `true` on a token issued with `ic.replay_unchecked`,
//!   when the replay store could not vouch for the challenge's nonce
//!   (spec §9.7 rule 4); omitted otherwise. `fail_closed` routes do not
//!   accept such a token (the Edge re-challenges); a present `ruc` must be
//!   `true`, so every token has exactly one encoding of "checked";
//! * footer `{"kid":"<kid>"}` (plaintext, authenticated) selects the key;
//! * implicit assertion `"mg-clr-v1" ‖ 0x00 ‖ site_id` binds the token to
//!   its site without spending bytes on it;
//! * only `pasetors::version4::LocalToken::{encrypt, decrypt}` is used; the
//!   claims (with Unix-second `iat` / `exp` / `sst`, D-29) are checked here,
//!   not by pasetors' ISO 8601 claim rules.
//!
//! Phase 2 (docs/impl/phase2-spec.md §6.8, D-46) adds claims `v = 2`:
//!
//! ```json
//! {"v":2,"kid":"blog-t-20261012","sid":"blog","env":"production","sub":"…","sst":1790000000,
//!  "lvl":"interactive","iat":1790000000,"exp":1790001800,"lat":1790000000,
//!  "cnf":{"jkt":"<43-char thumbprint>"},
//!  "bind":{"uah":"…","ipp":"…","ipa":"…"},"rb":"medium","jti":"…"}
//! ```
//!
//! * `lat` (required in v2, absent in v1): when the level was earned, Unix
//!   seconds, `sst ≤ lat ≤ iat`; it survives refreshes;
//! * `cnf` (optional in v2, absent in v1): exactly `{"jkt": <thumbprint>}`,
//!   the SDK session key the token is bound to;
//! * both versions verify; [`mint`] still writes v1 only, [`mint_v2`] picks
//!   the version by the rule of §6.8 and [`mint_refresh`] renews a token;
//! * the script-readable status cookie `__Host-mg_st=<iat>.<exp>.<b>`
//!   ([`status_cookie_value`]) accompanies the token when the bundle has
//!   `schema_version = 2`.

use crate::b64;
use crate::bind::{BindCheck, BindInputs, Bound, compare};
use crate::json::ObjectOnly;
use crate::jwk::{is_jkt, jkt_eq};
use crate::keys::TokenKeySet;
use crate::rng::{Rng, random_array};
use mg_core::{BindResult, RiskBand, TokenLevel, TokenStatus};
use pasetors::keys::SymmetricKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::{LocalToken, V4};
use pasetors::{Local, errors::Error as PasetoError};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Name of the clearance cookie.
pub const COOKIE_NAME: &str = "__Host-mg_clr";
/// Longest accepted token.
pub const MAX_TOKEN_LEN: usize = 1024;
/// Longest token lifetime, `exp − iat`.
pub const MAX_TOKEN_LIFETIME_S: i64 = 86_400;
/// Tolerated clock difference for `iat` between Edges.
pub const TOKEN_CLOCK_SKEW_S: i64 = 5;
/// Only the first 16 KiB of `Cookie` headers are searched (spec §6.6).
pub const MAX_COOKIE_BYTES: usize = 16 * 1024;
/// At most this many clearance cookies are tried per request.
pub const MAX_COOKIE_CANDIDATES: usize = 2;

/// Name of the script-readable status cookie (Phase 2 spec §6.8, D-46).
pub const STATUS_COOKIE_NAME: &str = "__Host-mg_st";
/// Claims version of Phase 1 tokens.
pub const CLAIMS_V1: u32 = 1;
/// Claims version with `lat` and the optional `cnf` (Phase 2 spec §6.8).
pub const CLAIMS_V2: u32 = 2;

const MAX_FOOTER_LEN: usize = 128;
const IMPLICIT_DOMAIN: &[u8] = b"mg-clr-v1";

/// The claims of a clearance token, v1 or v2. `Debug` omits `sub`, `jti`,
/// the binding hashes and the `cnf` thumbprint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearanceClaims {
    /// [`CLAIMS_V1`] or [`CLAIMS_V2`].
    pub v: u32,
    pub kid: String,
    pub sid: String,
    pub env: String,
    /// Pseudonymous session id, base64url of 16 random bytes.
    pub sub: String,
    /// Session start, Unix seconds (D-29).
    pub sst: i64,
    pub lvl: TokenLevel,
    /// Issued at, Unix seconds.
    pub iat: i64,
    /// Expires at, Unix seconds.
    pub exp: i64,
    /// v2 only (required there): when the level was earned, Unix seconds,
    /// `sst ≤ lat ≤ iat`. `None` in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lat: Option<i64>,
    /// v2 only (optional): the session key the token is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Cnf>,
    pub bind: ClearanceBind,
    /// Risk band at issuance.
    pub rb: RiskBand,
    /// Token id, base64url of 16 random bytes.
    pub jti: String,
    /// Issued without a replay check (I-30, `ic.replay_unchecked`); the
    /// claim is omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ruc: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl fmt::Debug for ClearanceClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClearanceClaims")
            .field("v", &self.v)
            .field("kid", &self.kid)
            .field("sid", &self.sid)
            .field("env", &self.env)
            .field("sst", &self.sst)
            .field("lvl", &self.lvl)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("lat", &self.lat)
            .field("cnf", &self.cnf)
            .field("bind", &self.bind)
            .field("rb", &self.rb)
            .field("ruc", &self.ruc)
            .finish_non_exhaustive() // sub and jti deliberately omitted
    }
}

impl ClearanceClaims {
    /// When the level was earned: `lat`, or `iat` for a v1 token (which is
    /// never refreshed, so it earned its level when it was issued).
    pub fn level_at(&self) -> i64 {
        self.lat.unwrap_or(self.iat)
    }

    /// The bound session key's thumbprint, if any.
    pub fn cnf_jkt(&self) -> Option<&str> {
        self.cnf.as_ref().map(|c| c.jkt.as_str())
    }
}

/// The confirmation claim of a v2 token (§6.8): exactly one member, the
/// 43-character thumbprint of the SDK session key. `Debug` does not print it
/// (spec §2.4 item 10).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cnf {
    pub jkt: String,
}

impl fmt::Debug for Cnf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cnf(..)")
    }
}

/// Token bindings: unpadded base64url of the 16-byte hashes (spec §6.4).
/// `uah` and `ipp` are required; `ipa` and `ctp` are omitted when not bound.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearanceBind {
    pub uah: String,
    pub ipp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipa: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctp: Option<String>,
}

impl ClearanceBind {
    /// The bindings of the current request, or `None` without an `ipp`
    /// (no token is issued for an unknown client IP, D-23).
    pub fn from_inputs(current: &BindInputs) -> Option<Self> {
        Some(Self {
            uah: b64::encode(&current.uah),
            ipp: b64::encode(&current.ipp?),
            ipa: current.ipa.map(|h| b64::encode(&h)),
            ctp: current.ctp.map(|h| b64::encode(&h)),
        })
    }

    /// Decoded hashes; `None` if `uah` or `ipp` is not a 16-byte hash or a
    /// present `ipa` / `ctp` is malformed.
    fn decode(&self) -> Option<Bound> {
        let optional = |h: &Option<String>| match h {
            None => Some(None),
            Some(s) => b64::decode_array::<16>(s).map(Some),
        };
        Some(Bound {
            uah: Some(b64::decode_array::<16>(&self.uah)?),
            ipp: Some(b64::decode_array::<16>(&self.ipp)?),
            ipa: optional(&self.ipa)?,
            ctp: optional(&self.ctp)?,
        })
    }
}

impl fmt::Debug for ClearanceBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClearanceBind")
            .field("ipa", &self.ipa.is_some())
            .field("ctp", &self.ctp.is_some())
            .finish_non_exhaustive() // hashes identify the client
    }
}

/// What to put into a new token.
pub struct MintParams<'a> {
    /// Environment of the request.
    pub env: &'a str,
    /// `(sub, sst)` carried over by [`reusable_session`], or `None` for a new
    /// session.
    pub session: Option<(&'a str, i64)>,
    pub lvl: TokenLevel,
    pub now_s: i64,
    /// Lifetime; 1..=86 400 s.
    pub ttl_s: u32,
    pub bind: ClearanceBind,
    pub rb: RiskBand,
    /// The replay store could not vouch for the challenge's nonce
    /// (`ic.replay_unchecked`, spec §9.7 rule 4): the token carries
    /// `ruc: true` (I-30).
    pub replay_unchecked: bool,
}

impl fmt::Debug for MintParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintParams")
            .field("env", &self.env)
            .field("reused_session", &self.session.is_some())
            .field("lvl", &self.lvl)
            .field("now_s", &self.now_s)
            .field("ttl_s", &self.ttl_s)
            .field("bind", &self.bind)
            .field("rb", &self.rb)
            .field("replay_unchecked", &self.replay_unchecked)
            .finish()
    }
}

/// Why a token could not be minted or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("token longer than 1024 characters")]
    TooLong,
    /// Missing, overlong or malformed `{"kid": …}` footer.
    #[error("malformed token footer")]
    Footer,
    /// The kid is not (or no longer) allowed by the site's bundle.
    #[error("unknown or retired token kid")]
    UnknownKid,
    #[error("token does not decrypt")]
    Decrypt,
    /// Undecodable or invalid claims: unknown fields, `v`, kid vs footer,
    /// malformed `bind`, `sub` or `jti`, unknown `lvl`, a `ruc` other than
    /// `true`.
    #[error("invalid token claims")]
    Claims,
    #[error("token belongs to another site")]
    Site,
    #[error("token belongs to another environment")]
    Env,
    /// A hard binding failure ([`BindCheck::hard_failure`]). `verify` never
    /// returns it; callers that fold the binding check into an error use it
    /// so that [`TokenError::status`] yields `binding_mismatch`.
    #[error("token binding mismatch")]
    Binding,
    /// `sst > iat`, `exp <= iat` or `exp − iat > 86 400`, or a lifetime out of
    /// range when minting.
    #[error("invalid token lifetime")]
    Lifetime,
    /// `iat` more than 5 s in the future.
    #[error("token issued in the future")]
    NotYetValid,
    #[error("token expired")]
    Expired,
    #[error("random number generator failed")]
    Rng,
}

impl TokenError {
    /// The `identity.token.status` of a presented token that failed with
    /// this error (spec §6.5): an unknown or retired kid and expiry are
    /// `expired` (ABSENT, no added risk), a hard binding failure is
    /// `binding_mismatch`, everything else `invalid`.
    pub fn status(&self) -> TokenStatus {
        match self {
            Self::UnknownKid | Self::Expired => TokenStatus::Expired,
            Self::Binding => TokenStatus::BindingMismatch,
            Self::TooLong
            | Self::Footer
            | Self::Decrypt
            | Self::Claims
            | Self::Site
            | Self::Env
            | Self::Lifetime
            | Self::NotYetValid
            | Self::Rng => TokenStatus::Invalid,
        }
    }
}

/// The footer, the only plaintext part of a token.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Footer<'a> {
    #[serde(borrow)]
    kid: std::borrow::Cow<'a, str>,
}

/// Claims as decoded, before `lvl` is interpreted: an unknown level is
/// checked last (after expiry) as spec §6.5 orders it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaims {
    v: u32,
    kid: String,
    sid: String,
    env: String,
    sub: String,
    sst: i64,
    lvl: String,
    iat: i64,
    exp: i64,
    /// Absent, or an integer (`null` is rejected here); which version needs
    /// it is checked by `verify_inner`.
    #[serde(default, deserialize_with = "some_i64")]
    lat: Option<i64>,
    #[serde(default, deserialize_with = "some_cnf")]
    cnf: Option<Cnf>,
    bind: ObjectOnly<ClearanceBind>,
    rb: RiskBand,
    jti: String,
    /// Absent, or a JSON boolean (`null` and other types are rejected
    /// here); `false` is rejected by `verify_inner`.
    #[serde(default, deserialize_with = "some_bool")]
    ruc: Option<bool>,
}

/// A present `ruc` must be a boolean; `Option<bool>` alone would take
/// `null` for "absent".
fn some_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}

/// A present `lat` must be an integer, never `null`.
fn some_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    i64::deserialize(d).map(Some)
}

/// A present `cnf` must be an object with exactly `jkt`, never `null`.
fn some_cnf<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Cnf>, D::Error> {
    ObjectOnly::<Cnf>::deserialize(d).map(|c| Some(c.0))
}

/// Mints a v1 token with the active key of `keys`. Draws `sub` (new sessions
/// only) and then `jti` from `rng`; the PASETO nonce comes from the OS RNG
/// inside pasetors. Returns the token and its claims.
///
/// Unchanged in Phase 2 (spec §2.3); v2 tokens come from [`mint_v2`] and
/// [`mint_refresh`].
pub fn mint(
    keys: &TokenKeySet,
    site_id: &str,
    p: &MintParams<'_>,
    rng: &dyn Rng,
) -> Result<(String, ClearanceClaims), TokenError> {
    mint_inner(keys, site_id, p, None, rng)
}

/// What [`mint_v2`] puts into a token beyond [`MintParams`] (Phase 2 spec
/// §6.8).
pub struct MintV2Params<'a> {
    pub base: MintParams<'a>,
    /// The thumbprint of the session key that signed the submission, for
    /// `cnf.jkt` (43 characters); `None` for an unbound token.
    pub cnf_jkt: Option<&'a str>,
    /// When the level was earned; `None` means now (`lat = iat`).
    pub lat: Option<i64>,
    /// The bundle has `schema_version = 2`. When false the token is v1 and
    /// `cnf_jkt` / `lat` are dropped (D-66: a schema 1 Edge accepts v2
    /// submissions but issues v1 tokens only).
    pub allow_v2: bool,
}

impl fmt::Debug for MintV2Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintV2Params")
            .field("base", &self.base)
            .field("bound", &self.cnf_jkt.is_some())
            .field("lat", &self.lat)
            .field("allow_v2", &self.allow_v2)
            .finish()
    }
}

/// The v2-only claims of a token being minted.
struct V2Extra {
    lat: i64,
    cnf: Option<Cnf>,
}

/// Mints a token by the version rule of §6.8: v2 when `allow_v2` and the
/// token has a `cnf`, a level other than `invisible` / `pow`, or a `lat`
/// other than its `iat`; v1 otherwise. A v2 `lat` must satisfy
/// `sst ≤ lat ≤ now` ([`TokenError::Lifetime`]) and `cnf_jkt` must be a
/// 43-character thumbprint ([`TokenError::Claims`]).
pub fn mint_v2(
    keys: &TokenKeySet,
    site_id: &str,
    p: &MintV2Params<'_>,
    rng: &dyn Rng,
) -> Result<(String, ClearanceClaims), TokenError> {
    let now = p.base.now_s;
    let lat = p.lat.unwrap_or(now);
    let needs_v2 = p.cnf_jkt.is_some()
        || !matches!(p.base.lvl, TokenLevel::Invisible | TokenLevel::Pow)
        || lat != now;
    if !p.allow_v2 || !needs_v2 {
        return mint_inner(keys, site_id, &p.base, None, rng);
    }
    if lat > now {
        return Err(TokenError::Lifetime);
    }
    let cnf = match p.cnf_jkt {
        Some(jkt) if is_jkt(jkt) => Some(Cnf {
            jkt: jkt.to_owned(),
        }),
        Some(_) => return Err(TokenError::Claims),
        None => None,
    };
    mint_inner(keys, site_id, &p.base, Some(V2Extra { lat, cnf }), rng)
}

/// Renews a verified token (§6.8 "刷新", `POST /__mg/r`): a v2 token with
/// `exp = min(now + ttl_s, sst + session_max_s)`, `iat = now`, a new `jti`
/// and the `kid` of the active key; `sub`, `sst`, `lat` (`iat` of a v1
/// token), `lvl`, `cnf`, `rb`, `bind`, `sid`, `env` and `ruc` are copied.
///
/// The caller has already run `refresh_check` (D-47: which levels refresh,
/// `ruc`, `cnf` and binding rules) and applies the 60 s rule (`too_old`)
/// itself; this function only refuses what would not verify: `old` from
/// another site ([`TokenError::Site`]), a `ttl_s` outside `1..=86 400`, a
/// session already past `sst + session_max_s` or a `lat` after `now`
/// ([`TokenError::Lifetime`]), malformed copied claims
/// ([`TokenError::Claims`]).
pub fn mint_refresh(
    keys: &TokenKeySet,
    site_id: &str,
    old: &ClearanceClaims,
    now_s: i64,
    ttl_s: u32,
    session_max_s: u32,
    rng: &dyn Rng,
) -> Result<(String, ClearanceClaims), TokenError> {
    if old.sid != site_id {
        return Err(TokenError::Site);
    }
    let ttl = i64::from(ttl_s);
    if !(1..=MAX_TOKEN_LIFETIME_S).contains(&ttl) {
        return Err(TokenError::Lifetime);
    }
    let by_ttl = now_s.checked_add(ttl).ok_or(TokenError::Lifetime)?;
    let by_session = old
        .sst
        .checked_add(i64::from(session_max_s))
        .ok_or(TokenError::Lifetime)?;
    let exp = by_ttl.min(by_session);
    let lat = old.level_at();
    if exp <= now_s || old.sst > lat || lat > now_s {
        return Err(TokenError::Lifetime);
    }
    if old.cnf.as_ref().is_some_and(|c| !is_jkt(&c.jkt)) {
        return Err(TokenError::Claims);
    }
    let jti = random_id(rng)?;
    let (kid, _) = keys.active();
    let claims = ClearanceClaims {
        v: CLAIMS_V2,
        kid: kid.to_owned(),
        sid: old.sid.clone(),
        env: old.env.clone(),
        sub: old.sub.clone(),
        sst: old.sst,
        lvl: old.lvl,
        iat: now_s,
        exp,
        lat: Some(lat),
        cnf: old.cnf.clone(),
        bind: old.bind.clone(),
        rb: old.rb,
        jti,
        ruc: old.ruc,
    };
    if claims.bind.decode().is_none() || !is_random_id(&claims.sub) {
        return Err(TokenError::Claims);
    }
    let token = encrypt(keys, site_id, &claims)?;
    Ok((token, claims))
}

fn mint_inner(
    keys: &TokenKeySet,
    site_id: &str,
    p: &MintParams<'_>,
    v2: Option<V2Extra>,
    rng: &dyn Rng,
) -> Result<(String, ClearanceClaims), TokenError> {
    let ttl = i64::from(p.ttl_s);
    if !(1..=MAX_TOKEN_LIFETIME_S).contains(&ttl) {
        return Err(TokenError::Lifetime);
    }
    let exp = p.now_s.checked_add(ttl).ok_or(TokenError::Lifetime)?;
    if p.bind.decode().is_none() {
        return Err(TokenError::Claims);
    }
    let (sub, sst) = match p.session {
        Some((sub, sst)) => {
            if !is_random_id(sub) {
                return Err(TokenError::Claims);
            }
            if sst > p.now_s {
                return Err(TokenError::Lifetime);
            }
            (sub.to_owned(), sst)
        }
        None => (random_id(rng)?, p.now_s),
    };
    if v2.as_ref().is_some_and(|x| x.lat < sst) {
        return Err(TokenError::Lifetime);
    }
    let jti = random_id(rng)?;
    let (kid, _) = keys.active();
    let (v, lat, cnf) = match v2 {
        Some(x) => (CLAIMS_V2, Some(x.lat), x.cnf),
        None => (CLAIMS_V1, None, None),
    };
    let claims = ClearanceClaims {
        v,
        kid: kid.to_owned(),
        sid: site_id.to_owned(),
        env: p.env.to_owned(),
        sub,
        sst,
        lvl: p.lvl,
        iat: p.now_s,
        exp,
        lat,
        cnf,
        bind: p.bind.clone(),
        rb: p.rb,
        jti,
        ruc: p.replay_unchecked,
    };
    let token = encrypt(keys, site_id, &claims)?;
    Ok((token, claims))
}

/// Encrypts `claims` with the active key and the footer of its kid.
fn encrypt(
    keys: &TokenKeySet,
    site_id: &str,
    claims: &ClearanceClaims,
) -> Result<String, TokenError> {
    let (kid, key) = keys.active();
    let payload = serde_json::to_vec(claims).map_err(|_| TokenError::Claims)?;
    let footer = serde_json::to_vec(&Footer { kid: kid.into() }).map_err(|_| TokenError::Footer)?;
    if footer.len() > MAX_FOOTER_LEN {
        return Err(TokenError::Footer);
    }
    let key = SymmetricKey::<V4>::from(key).map_err(|_| TokenError::Claims)?;
    let token = LocalToken::encrypt(
        &key,
        &payload,
        Some(&footer),
        Some(&implicit_assertion(site_id)),
    )
    .map_err(|e| match e {
        PasetoError::Csprng => TokenError::Rng,
        _ => TokenError::Claims,
    })?;
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::TooLong);
    }
    Ok(token)
}

/// Verifies a token for `site_id` in `env` at `now_s` (spec §6.5, checks in
/// order): length, footer, kid in the allowed set, decryption with the
/// implicit assertion, claims (`v` ∈ {1, 2} with the Phase 2 rules of §6.8:
/// v1 without `lat` / `cnf`, v2 with `lat` and an optional `cnf.jkt` of 43
/// characters; kid, site, env, `bind.uah` / `bind.ipp`, `sub` / `jti` as
/// base64url of 16 bytes, `ruc` absent or `true`), `sst ≤ iat ≤ now + 5`,
/// `sst ≤ lat ≤ iat`, `iat < exp ≤ iat + 86 400`, `exp > now`, `lvl`.
///
/// Bindings are compared separately with [`check_clearance_bind`].
pub fn verify(
    keys: &TokenKeySet,
    site_id: &str,
    env: &str,
    token: &str,
    now_s: i64,
) -> Result<ClearanceClaims, TokenError> {
    verify_inner(keys, site_id, env, token, now_s, true)
}

/// Same checks as `verify` except expiry; for `sub` / `sst` reuse only (§6.5).
pub fn verify_ignoring_expiry(
    keys: &TokenKeySet,
    site_id: &str,
    env: &str,
    token: &str,
    now_s: i64,
) -> Result<ClearanceClaims, TokenError> {
    verify_inner(keys, site_id, env, token, now_s, false)
}

fn verify_inner(
    keys: &TokenKeySet,
    site_id: &str,
    env: &str,
    token: &str,
    now_s: i64,
    check_expiry: bool,
) -> Result<ClearanceClaims, TokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::TooLong);
    }
    let footer_bytes = footer_of(token).ok_or(TokenError::Footer)?;
    let ObjectOnly(footer) = serde_json::from_slice::<ObjectOnly<Footer<'_>>>(&footer_bytes)
        .map_err(|_| TokenError::Footer)?;
    let key = keys.get(&footer.kid).ok_or(TokenError::UnknownKid)?;
    let key = SymmetricKey::<V4>::from(key).map_err(|_| TokenError::Decrypt)?;
    let untrusted =
        UntrustedToken::<Local, V4>::try_from(token).map_err(|_| TokenError::Decrypt)?;
    // Passing the footer makes pasetors compare it with the one it
    // authenticates, so the kid used above is the authenticated one.
    let trusted = LocalToken::decrypt(
        &key,
        &untrusted,
        Some(&footer_bytes),
        Some(&implicit_assertion(site_id)),
    )
    .map_err(|_| TokenError::Decrypt)?;

    let ObjectOnly(raw) = serde_json::from_str::<ObjectOnly<RawClaims>>(trusted.payload())
        .map_err(|_| TokenError::Claims)?;
    if raw.kid != footer.kid {
        return Err(TokenError::Claims);
    }
    // Phase 2 spec §6.8: v1 is exactly the Phase 1 payload; v2 requires
    // `lat` and may carry a well-formed `cnf`.
    let version_ok = match raw.v {
        CLAIMS_V1 => raw.lat.is_none() && raw.cnf.is_none(),
        CLAIMS_V2 => raw.lat.is_some() && raw.cnf.as_ref().is_none_or(|c| is_jkt(&c.jkt)),
        _ => false,
    };
    if !version_ok {
        return Err(TokenError::Claims);
    }
    if raw.sid != site_id {
        return Err(TokenError::Site);
    }
    if raw.env != env {
        return Err(TokenError::Env);
    }
    let ObjectOnly(bind) = raw.bind;
    if bind.decode().is_none() || !is_random_id(&raw.sub) || !is_random_id(&raw.jti) {
        return Err(TokenError::Claims);
    }
    // `mint` omits a false `ruc`: an explicit `false` is not a token it
    // wrote (I-30).
    if raw.ruc == Some(false) {
        return Err(TokenError::Claims);
    }
    if raw.sst > raw.iat {
        return Err(TokenError::Lifetime);
    }
    if raw.lat.is_some_and(|lat| lat < raw.sst || lat > raw.iat) {
        return Err(TokenError::Lifetime);
    }
    if raw.iat > now_s.saturating_add(TOKEN_CLOCK_SKEW_S) {
        return Err(TokenError::NotYetValid);
    }
    let lifetime = i128::from(raw.exp) - i128::from(raw.iat);
    if lifetime <= 0 || lifetime > i128::from(MAX_TOKEN_LIFETIME_S) {
        return Err(TokenError::Lifetime);
    }
    if check_expiry && raw.exp <= now_s {
        return Err(TokenError::Expired);
    }
    let lvl: TokenLevel = raw.lvl.parse().map_err(|_| TokenError::Claims)?;
    Ok(ClearanceClaims {
        v: raw.v,
        kid: raw.kid,
        sid: raw.sid,
        env: raw.env,
        sub: raw.sub,
        sst: raw.sst,
        lvl,
        iat: raw.iat,
        exp: raw.exp,
        lat: raw.lat,
        cnf: raw.cnf,
        bind,
        rb: raw.rb,
        jti: raw.jti,
        ruc: raw.ruc == Some(true),
    })
}

/// (sub, sst) to carry into a new token, or None (§6.5).
///
/// `prev` must have passed [`verify_ignoring_expiry`] for this site and
/// environment (it may have expired). The session continues only if `uah`
/// matches, `ipp` matches or soft-mismatches, and the session is at most
/// `session_max_s` old; otherwise a new session starts, so a session can
/// neither move to another browser nor be renewed forever.
pub fn reusable_session(
    prev: &ClearanceClaims,
    bind: &BindCheck,
    now_s: i64,
    session_max_s: u32,
) -> Option<(String, i64)> {
    let bound = bind.uah == BindResult::Match
        && matches!(bind.ipp, BindResult::Match | BindResult::SoftMismatch);
    let age = i128::from(now_s) - i128::from(prev.sst);
    (bound && (0..=i128::from(session_max_s)).contains(&age)).then(|| (prev.sub.clone(), prev.sst))
}

/// Compares a verified token's bindings with the current request (spec
/// §6.4). A malformed binding (impossible after [`verify`]) never matches.
pub fn check_clearance_bind(claims: &ClearanceClaims, current: &BindInputs) -> BindCheck {
    let bound = claims.bind.decode().unwrap_or(Bound {
        uah: None,
        ipp: None,
        ipa: None,
        ctp: None,
    });
    compare(&bound, current)
}

/// The `Set-Cookie` value for a new token: `__Host-mg_clr=<token>;
/// Max-Age=<n>; Path=/; Secure; HttpOnly; SameSite=Lax`. Only for the
/// success response of `/__mg/c`, never on an origin response.
pub fn set_cookie_value(token: &str, max_age_s: u32) -> String {
    format!("{COOKIE_NAME}={token}; Max-Age={max_age_s}; Path=/; Secure; HttpOnly; SameSite=Lax")
}

/// The value of the status cookie `__Host-mg_st` (Phase 2 spec §6.8, D-46):
/// `<iat>.<exp>.<b>` with the token's Unix seconds and `b` = `1` when the
/// token has a `cnf`, else `0`. It holds no level and no secret; the SDK
/// reads it to schedule refreshes, the Edge never decides on it.
pub fn status_cookie_value(iat: i64, exp: i64, bound: bool) -> String {
    format!("{iat}.{exp}.{}", u8::from(bound))
}

/// The `Set-Cookie` value of the status cookie, written right after the
/// `__Host-mg_clr` one with the same `Max-Age` (schema 2 bundles only):
/// `__Host-mg_st=<iat>.<exp>.<b>; Max-Age=<n>; Path=/; Secure; SameSite=Lax`,
/// deliberately without `HttpOnly`.
pub fn status_set_cookie_value(claims: &ClearanceClaims, max_age_s: u32) -> String {
    let value = status_cookie_value(claims.iat, claims.exp, claims.cnf.is_some());
    format!("{STATUS_COOKIE_NAME}={value}; Max-Age={max_age_s}; Path=/; Secure; SameSite=Lax")
}

/// [`reusable_session`] with the Phase 2 rule of §6.8: the session also
/// continues only if the new submission's key `jkt` equals the old token's
/// `cnf.jkt`, or the old token has no `cnf`. A changed or missing key starts
/// a new session. (The near-line session verdict of §6.8 is the Edge's
/// check.)
pub fn reusable_session_v2(
    prev: &ClearanceClaims,
    bind: &BindCheck,
    now_s: i64,
    session_max_s: u32,
    jkt: Option<&str>,
) -> Option<(String, i64)> {
    let same_key = match (prev.cnf_jkt(), jkt) {
        (None, _) => true,
        (Some(old), Some(new)) => jkt_eq(old, new),
        (Some(_), None) => false,
    };
    same_key
        .then(|| reusable_session(prev, bind, now_s, session_max_s))
        .flatten()
}

/// The values of the `__Host-mg_clr` cookies in `Cookie` headers, in order,
/// at most two (spec §6.6). Only the first 16 KiB of all headers together
/// are searched; a pair cut by that limit is ignored. Pairs are split on
/// `;` and trimmed; the name must equal [`COOKIE_NAME`] exactly.
///
/// The caller verifies the candidates and uses the first `valid` one, else
/// the status of the first.
pub fn clearance_cookies<'a>(cookie_headers: &[&'a str]) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut budget = MAX_COOKIE_BYTES;
    'headers: for &header in cookie_headers {
        if budget == 0 {
            break;
        }
        let window = header.len().min(budget);
        let truncated = window < header.len();
        budget -= window;
        let bytes = &header.as_bytes()[..window];
        let mut start = 0;
        loop {
            let end = match bytes[start..].iter().position(|&b| b == b';') {
                Some(i) => start + i,
                // The last pair of a cut header may be incomplete.
                None if truncated => break,
                None => window,
            };
            // `start` and `end` sit next to ASCII ';' or at the end of the
            // header, so both are char boundaries.
            let pair = header[start..end].trim_matches([' ', '\t']);
            if let Some((COOKIE_NAME, value)) = pair.split_once('=') {
                found.push(value);
                if found.len() == MAX_COOKIE_CANDIDATES {
                    break 'headers;
                }
            }
            if end >= window {
                break;
            }
            start = end + 1;
        }
    }
    found
}

/// `"mg-clr-v1" ‖ 0x00 ‖ site_id`.
fn implicit_assertion(site_id: &str) -> Vec<u8> {
    [IMPLICIT_DOMAIN, &[0], site_id.as_bytes()].concat()
}

/// The decoded footer of `v4.local.<payload>.<footer>`; `None` if the token
/// does not have exactly these four parts or the footer is empty or too long.
fn footer_of(token: &str) -> Option<Vec<u8>> {
    let mut parts = token.split('.');
    let (Some("v4"), Some("local"), Some(_), Some(footer), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    if footer.len() > b64::encoded_len(MAX_FOOTER_LEN) {
        return None;
    }
    b64::decode(footer).filter(|f| !f.is_empty() && f.len() <= MAX_FOOTER_LEN)
}

/// base64url of 16 random bytes (`sub`, `jti`).
fn random_id(rng: &dyn Rng) -> Result<String, TokenError> {
    let bytes: [u8; 16] = random_array(rng).map_err(|_| TokenError::Rng)?;
    Ok(b64::encode(&bytes))
}

/// Whether `s` has the shape of [`random_id`]: canonical unpadded base64url
/// of exactly 16 bytes. `sub` leaves the token as `MG-Session`, a limiter key
/// and the id of a reused session, so its shape is checked on every path.
fn is_random_id(s: &str) -> bool {
    b64::decode_array::<16>(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_value_format() {
        assert_eq!(
            set_cookie_value("v4.local.x.y", 1800),
            "__Host-mg_clr=v4.local.x.y; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn footer_parsing() {
        assert_eq!(
            footer_of("v4.local.AAAA.eyJraWQiOiJhIn0").as_deref(),
            Some(br#"{"kid":"a"}"#.as_slice())
        );
        for bad in [
            "",
            "v4.local.AAAA",
            "v4.local.AAAA.",
            "v4.public.AAAA.eyJraWQiOiJhIn0",
            "v3.local.AAAA.eyJraWQiOiJhIn0",
            "v4.local.AAAA.eyJraWQiOiJhIn0.x",
            "v4.local.AAAA.eyJraWQiOiJhIn0=",
        ] {
            assert_eq!(footer_of(bad), None, "{bad:?}");
        }
        let long = format!("v4.local.AAAA.{}", b64::encode(&[b'a'; 129]));
        assert_eq!(footer_of(&long), None);
    }

    #[test]
    fn status_mapping() {
        use TokenStatus as S;
        let cases = [
            (TokenError::UnknownKid, S::Expired),
            (TokenError::Expired, S::Expired),
            (TokenError::Binding, S::BindingMismatch),
            (TokenError::TooLong, S::Invalid),
            (TokenError::Footer, S::Invalid),
            (TokenError::Decrypt, S::Invalid),
            (TokenError::Claims, S::Invalid),
            (TokenError::Site, S::Invalid),
            (TokenError::Env, S::Invalid),
            (TokenError::Lifetime, S::Invalid),
            (TokenError::NotYetValid, S::Invalid),
            (TokenError::Rng, S::Invalid),
        ];
        for (e, s) in cases {
            assert_eq!(e.status(), s, "{e:?}");
        }
    }

    #[test]
    fn bind_from_inputs_requires_ipp() {
        let mut inputs = BindInputs {
            uah: [1; 16],
            ipp: None,
            ipa: Some([2; 16]),
            ctp: None,
        };
        assert!(ClearanceBind::from_inputs(&inputs).is_none());
        inputs.ipp = Some([3; 16]);
        let b = ClearanceBind::from_inputs(&inputs).unwrap();
        assert_eq!(b.uah, b64::encode(&[1; 16]));
        assert_eq!(b.ipa.as_deref(), Some(b64::encode(&[2; 16]).as_str()));
        assert_eq!(b.ctp, None);
        assert_eq!(
            serde_json::to_string(&b).unwrap(),
            format!(
                r#"{{"uah":"{}","ipp":"{}","ipa":"{}"}}"#,
                b64::encode(&[1; 16]),
                b64::encode(&[3; 16]),
                b64::encode(&[2; 16])
            )
        );
        assert_eq!(
            format!("{b:?}"),
            "ClearanceBind { ipa: true, ctp: false, .. }"
        );
    }
}
