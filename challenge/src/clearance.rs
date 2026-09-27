//! Clearance tokens: PASETO v4.local in the `__Host-mg_clr` cookie (spec
//! §6.5, §6.6, docs/04 §5).
//!
//! ```json
//! {"v":1,"kid":"blog-t-20260927","sid":"blog","env":"production",
//!  "sub":"<base64url 16 random bytes>","sst":1790000000,"lvl":"invisible","iat":1790000000,"exp":1790001800,
//!  "bind":{"uah":"…","ipp":"…","ipa":"…"},"rb":"medium","jti":"<base64url 16 random bytes>"}
//! ```
//!
//! * footer `{"kid":"<kid>"}` (plaintext, authenticated) selects the key;
//! * implicit assertion `"mg-clr-v1" ‖ 0x00 ‖ site_id` binds the token to
//!   its site without spending bytes on it;
//! * only `pasetors::version4::LocalToken::{encrypt, decrypt}` is used; the
//!   claims (with Unix-second `iat` / `exp` / `sst`, D-29) are checked here,
//!   not by pasetors' ISO 8601 claim rules.

use crate::b64;
use crate::bind::{BindCheck, BindInputs, Bound, compare};
use crate::json::ObjectOnly;
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

const CLAIMS_VERSION: u32 = 1;
const MAX_FOOTER_LEN: usize = 128;
const IMPLICIT_DOMAIN: &[u8] = b"mg-clr-v1";

/// The claims of a clearance token. `Debug` omits `sub`, `jti` and the
/// binding hashes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearanceClaims {
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
    pub bind: ClearanceBind,
    /// Risk band at issuance.
    pub rb: RiskBand,
    /// Token id, base64url of 16 random bytes.
    pub jti: String,
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
            .field("bind", &self.bind)
            .field("rb", &self.rb)
            .finish_non_exhaustive() // sub and jti deliberately omitted
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
    /// malformed `bind`, `sub` or `jti`, unknown `lvl`.
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
    bind: ObjectOnly<ClearanceBind>,
    rb: RiskBand,
    jti: String,
}

/// Mints a token with the active key of `keys`. Draws `sub` (new sessions
/// only) and then `jti` from `rng`; the PASETO nonce comes from the OS RNG
/// inside pasetors. Returns the token and its claims.
pub fn mint(
    keys: &TokenKeySet,
    site_id: &str,
    p: &MintParams<'_>,
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
    let jti = random_id(rng)?;
    let (kid, key) = keys.active();
    let claims = ClearanceClaims {
        v: CLAIMS_VERSION,
        kid: kid.to_owned(),
        sid: site_id.to_owned(),
        env: p.env.to_owned(),
        sub,
        sst,
        lvl: p.lvl,
        iat: p.now_s,
        exp,
        bind: p.bind.clone(),
        rb: p.rb,
        jti,
    };
    let payload = serde_json::to_vec(&claims).map_err(|_| TokenError::Claims)?;
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
    Ok((token, claims))
}

/// Verifies a token for `site_id` in `env` at `now_s` (spec §6.5, checks in
/// order): length, footer, kid in the allowed set, decryption with the
/// implicit assertion, claims (`v`, kid, site, env, `bind.uah` / `bind.ipp`,
/// and `sub` / `jti` as base64url of 16 bytes), `sst ≤ iat ≤ now + 5`,
/// `iat < exp ≤ iat + 86 400`, `exp > now`, `lvl`.
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
    if raw.v != CLAIMS_VERSION || raw.kid != footer.kid {
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
    if raw.sst > raw.iat {
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
        bind,
        rb: raw.rb,
        jti: raw.jti,
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
