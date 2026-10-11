//! `MG-Proof` verification (docs/impl/phase2-spec.md §6.7, D-40): the
//! compact ES256 JWS with header `{alg, typ: "mg-proof+jwt", jwk}` and payload
//! `{htm, htu, iat, jti}`, checked cheapest first (`proof.malformed`,
//! `unbound`, `jkt`, `htm`, `htu`, `iat`, `sig`).
//!
//! ```text
//! MG-Proof = B64(header) "." B64(payload) "." B64(sig)      ≤ 4096 bytes, unpadded base64url
//! header   = {"alg":"ES256","typ":"mg-proof+jwt","jwk":{"kty":"EC","crv":"P-256","x":…,"y":…}}
//! payload  = {"htm":<≤ 32 bytes>,"htu":<≤ 2048 bytes>,"iat":<Unix s>,"jti":<22 chars, 16 bytes>}
//! signed   = ASCII of B64(header) "." B64(payload)
//! ```
//!
//! Member order is free; duplicate and unknown members are rejected. There is
//! no `ath` (the clearance cookie is HttpOnly), no `bh` and no server nonce
//! (D-40, D-55). The Edge does the `jti` replay check (§9.2) after
//! [`verify_proof`] succeeds.
//!
//! Nothing here prints the header, the key or the `jti` (spec §2.4 item 10).

use crate::b64;
use crate::json::ObjectOnly;
use crate::jwk::{Jwk, SessionKey, jkt_eq, jwk_thumbprint};
use mg_core::paths::cloudflare_view;
use serde::Deserialize;
use std::fmt;

/// Longest accepted header value.
pub const MAX_PROOF_LEN: usize = 4096;
/// Longest `htm`.
pub const MAX_HTM_LEN: usize = 32;
/// Longest `htu`.
pub const MAX_HTU_LEN: usize = 2048;
/// A proof may be this many seconds old.
pub const PROOF_MAX_AGE_S: i64 = 30;
/// A proof may be this many seconds in the future.
pub const PROOF_MAX_FUTURE_S: i64 = 5;
/// Length of `jti` in unpadded base64url (16 bytes).
pub const JTI_B64_LEN: usize = 22;

const ALG: &str = "ES256";
const TYP: &str = "mg-proof+jwt";

/// The request a proof is checked against.
#[derive(Clone, Copy)]
pub struct ProofRequest<'a> {
    /// The method string as received (case-sensitive).
    pub method: &'a str,
    /// The effective scheme: `https` from an authenticated `CF-Visitor`
    /// (`cloudflare` profile) or on `direct_tls`; anything else fails `htu`.
    pub scheme: &'a str,
    /// The normalized request host (Phase 1 spec §9.4): lower-case, no port,
    /// no trailing dot.
    pub host: &'a str,
    /// The raw request path without the query.
    pub path: &'a str,
    /// Now, Unix seconds.
    pub now_s: i64,
    /// The `cnf.jkt` of the request's valid clearance; `None` when there is
    /// no valid clearance or it has no `cnf`.
    pub expected_jkt: Option<&'a str>,
}

impl fmt::Debug for ProofRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofRequest")
            .field("method", &self.method)
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("now_s", &self.now_s)
            .field("bound", &self.expected_jkt.is_some())
            .finish_non_exhaustive() // path may be sensitive; jkt identifies the session
    }
}

/// A proof that passed every check of §6.7. The `jti` replay check and the
/// per-key quota are the Edge's (§9.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedProof {
    pub jti: [u8; 16],
    pub iat: i64,
}

impl VerifiedProof {
    /// The `jti` as it appeared in the proof (22 characters), the text the
    /// replay key of §9.2 uses.
    pub fn jti_text(&self) -> String {
        b64::encode(&self.jti)
    }
}

impl fmt::Debug for VerifiedProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedProof")
            .field("iat", &self.iat)
            .finish_non_exhaustive()
    }
}

/// The first failed check of §6.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ProofError {
    /// Format, size, base64url, JSON (duplicate or unknown members, types),
    /// `alg` / `typ`, JWK members and lengths, `htm` / `htu` / `jti` shape.
    #[error("malformed proof")]
    Malformed,
    /// The request has no valid clearance with `cnf.jkt`.
    #[error("no key-bound clearance for the proof")]
    Unbound,
    /// The proof's key is not the clearance's `cnf.jkt`.
    #[error("proof key does not match the clearance")]
    Jkt,
    #[error("proof method does not match the request")]
    Htm,
    #[error("proof URL does not match the request")]
    Htu,
    /// `iat < now − 30` or `iat > now + 5`.
    #[error("proof time out of range")]
    Iat,
    /// Signature not 64 bytes, invalid, or the point is not on the curve.
    #[error("proof signature invalid")]
    Sig,
}

impl ProofError {
    /// The reason code of events and of `mg_proof_verify_total{result}`
    /// (without the prefix): `proof.malformed` … `proof.sig`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed => "proof.malformed",
            Self::Unbound => "proof.unbound",
            Self::Jkt => "proof.jkt",
            Self::Htm => "proof.htm",
            Self::Htu => "proof.htu",
            Self::Iat => "proof.iat",
            Self::Sig => "proof.sig",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    jwk: ObjectOnly<Jwk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
}

/// A proof after step 1: well-formed, nothing compared yet.
struct Parsed<'h> {
    jwk: Jwk,
    payload: Payload,
    jti: [u8; 16],
    /// `B64(header) "." B64(payload)`.
    signing_input: &'h str,
    sig: Vec<u8>,
}

/// Step 1: format, size and JSON.
fn parse(header: &str) -> Result<Parsed<'_>, ProofError> {
    use ProofError::Malformed;
    if header.len() > MAX_PROOF_LEN {
        return Err(Malformed);
    }
    let (signing_input, sig_b64) = header.rsplit_once('.').ok_or(Malformed)?;
    let (header_b64, payload_b64) = signing_input.split_once('.').ok_or(Malformed)?;
    if payload_b64.contains('.') {
        return Err(Malformed);
    }
    let header_json = b64::decode(header_b64).ok_or(Malformed)?;
    let payload_json = b64::decode(payload_b64).ok_or(Malformed)?;
    // The signature must be base64url here; its length is checked in step 7.
    let sig = b64::decode(sig_b64).ok_or(Malformed)?;
    let ObjectOnly(head) =
        serde_json::from_slice::<ObjectOnly<Header>>(&header_json).map_err(|_| Malformed)?;
    let ObjectOnly(payload) =
        serde_json::from_slice::<ObjectOnly<Payload>>(&payload_json).map_err(|_| Malformed)?;
    if head.alg != ALG || head.typ != TYP {
        return Err(Malformed);
    }
    let ObjectOnly(jwk) = head.jwk;
    // JWK members and lengths (§6.5); the point itself is checked in step 7.
    SessionKey::from_jwk(&jwk).map_err(|_| Malformed)?;
    if payload.htm.len() > MAX_HTM_LEN || payload.htu.len() > MAX_HTU_LEN {
        return Err(Malformed);
    }
    if payload.jti.len() != JTI_B64_LEN {
        return Err(Malformed);
    }
    let jti = b64::decode_array::<16>(&payload.jti).ok_or(Malformed)?;
    Ok(Parsed {
        jwk,
        payload,
        jti,
        signing_input,
        sig,
    })
}

/// Verifies an `MG-Proof` header value against the request (§6.7). Checks
/// run in order and the first failure is returned:
///
/// 1. format, size, JSON → [`ProofError::Malformed`];
/// 2. no `expected_jkt` → [`ProofError::Unbound`] (no curve operation);
/// 3. thumbprint of the JWK's `x` / `y` text ≠ `expected_jkt` →
///    [`ProofError::Jkt`] (SHA-256 only);
/// 4. `htm` ≠ the request method, case-sensitive → [`ProofError::Htm`];
/// 5. `htu` → [`ProofError::Htu`]: `https` on both sides, RFC 3986 host
///    without userinfo normalized like the request host (port and IP
///    literals compared as is), and the path before the first `?` or `#`
///    equal to the request path, both through
///    [`mg_core::paths::cloudflare_view`];
/// 6. `iat` outside `now − 30 ..= now + 5` → [`ProofError::Iat`];
/// 7. ES256 signature (64-byte `r || s`, point on the curve) →
///    [`ProofError::Sig`].
pub fn verify_proof(header: &str, req: &ProofRequest<'_>) -> Result<VerifiedProof, ProofError> {
    let p = parse(header)?;
    let expected = req.expected_jkt.ok_or(ProofError::Unbound)?;
    if !jkt_eq(&jwk_thumbprint(&p.jwk.x, &p.jwk.y), expected) {
        return Err(ProofError::Jkt);
    }
    if p.payload.htm != req.method {
        return Err(ProofError::Htm);
    }
    if !htu_matches(&p.payload.htu, req) {
        return Err(ProofError::Htu);
    }
    let iat = p.payload.iat;
    if iat < req.now_s.saturating_sub(PROOF_MAX_AGE_S)
        || iat > req.now_s.saturating_add(PROOF_MAX_FUTURE_S)
    {
        return Err(ProofError::Iat);
    }
    if !signature_ok(&p) {
        return Err(ProofError::Sig);
    }
    Ok(VerifiedProof { jti: p.jti, iat })
}

/// The session key of a well-formed proof whose signature verifies, without
/// any other check (binding, method, URL, time). Only for the in-place
/// recovery of §9.1: after [`verify_proof`] failed with
/// [`ProofError::Unbound`] or [`ProofError::Jkt`], the Edge may attach a
/// `pow` C bound to this key (`bind.jkt`). It costs one ECDSA verification,
/// so the Edge calls it only after its rate limiters.
pub fn proof_signing_key(header: &str) -> Option<SessionKey> {
    let p = parse(header).ok()?;
    let key = SessionKey::from_jwk(&p.jwk).ok()?;
    key.verify_raw(p.signing_input.as_bytes(), &p.sig)
        .then_some(key)
}

fn signature_ok(p: &Parsed<'_>) -> bool {
    SessionKey::from_jwk(&p.jwk).is_ok_and(|key| key.verify_raw(p.signing_input.as_bytes(), &p.sig))
}

/// Step 5: `https://<host><path>[?…][#…]` against the request.
fn htu_matches(htu: &str, req: &ProofRequest<'_>) -> bool {
    if req.scheme != "https" {
        return false;
    }
    let Some(rest) = htu.strip_prefix("https://") else {
        return false;
    };
    // RFC 3986: the authority ends at the first '/', '?' or '#'.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return false; // userinfo
    }
    // Normalized like the request host (Phase 1 spec §9.4): ASCII lower-case
    // and one trailing dot removed. A port stays, so it never matches the
    // normalized request host, which has none.
    let lower = authority.to_ascii_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    if host.is_empty() || host != req.host {
        return false;
    }
    let path = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    path.starts_with('/') && cloudflare_view(path) == cloudflare_view(req.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(host: &'a str, path: &'a str) -> ProofRequest<'a> {
        ProofRequest {
            method: "GET",
            scheme: "https",
            host,
            path,
            now_s: 0,
            expected_jkt: Some("x"),
        }
    }

    #[test]
    fn htu_rules() {
        let r = req("example.com", "/a/b");
        for ok in [
            "https://example.com/a/b",
            "https://EXAMPLE.com/a/b",
            "https://example.com./a/b",
            "https://example.com/a/b?x=1#f",
            "https://example.com/a/b#f?x",
            "https://example.com/a/./b",
            "https://example.com/a//b",
            "https://example.com/a/c/../b",
        ] {
            assert!(htu_matches(ok, &r), "{ok}");
        }
        for bad in [
            "http://example.com/a/b",
            "HTTPS://example.com/a/b",
            "https://example.com:443/a/b",
            "https://u@example.com/a/b",
            "https://u:p@example.com/a/b",
            "https://example.org/a/b",
            "https://example.com/a/b/",
            "https://example.com/a%2Fb",
            "https://example.com",
            "https://example.com?/a/b",
            "https:///a/b",
            "//example.com/a/b",
            "/a/b",
            "",
        ] {
            assert!(!htu_matches(bad, &r), "{bad}");
        }
        let mut over_http = r;
        over_http.scheme = "http";
        assert!(!htu_matches("https://example.com/a/b", &over_http));
        assert!(htu_matches(
            "https://[2001:db8::1]/",
            &req("[2001:db8::1]", "/")
        ));
        assert!(htu_matches(
            "https://[2001:DB8::1]/",
            &req("[2001:db8::1]", "/")
        ));
    }

    #[test]
    fn reason_codes_and_debug() {
        let all = [
            (ProofError::Malformed, "proof.malformed"),
            (ProofError::Unbound, "proof.unbound"),
            (ProofError::Jkt, "proof.jkt"),
            (ProofError::Htm, "proof.htm"),
            (ProofError::Htu, "proof.htu"),
            (ProofError::Iat, "proof.iat"),
            (ProofError::Sig, "proof.sig"),
        ];
        for (e, code) in all {
            assert_eq!(e.reason_code(), code);
        }
        let v = VerifiedProof {
            jti: [0xab; 16],
            iat: 7,
        };
        assert_eq!(format!("{v:?}"), "VerifiedProof { iat: 7, .. }");
        assert_eq!(v.jti_text().len(), JTI_B64_LEN);
        let r = ProofRequest {
            expected_jkt: Some("SECRET-JKT"),
            path: "/secret-path",
            ..req("example.com", "/")
        };
        let s = format!("{r:?}");
        assert!(!s.contains("SECRET") && !s.contains("secret"), "{s}");
    }

    #[test]
    fn malformed_shapes() {
        let r = req("example.com", "/");
        for bad in ["", ".", "..", "a.b", "a.b.c.d", "e30.e30.", "e30.e30.AA"] {
            assert_eq!(verify_proof(bad, &r), Err(ProofError::Malformed), "{bad:?}");
        }
        assert_eq!(
            verify_proof(&"A".repeat(MAX_PROOF_LEN + 1), &r),
            Err(ProofError::Malformed)
        );
        assert!(proof_signing_key("a.b.c").is_none());
    }
}
