//! `MG-Proof` on routes (docs/impl/phase2-spec.md §9.1, §9.2, §6.7, D-40,
//! D-41; WP-E2b).
//!
//! * **Reading** ([`header`]): the `MG-Proof` field lines of the request as
//!   received, before header hygiene removes the `mg-` family (the header is
//!   never forwarded). More than one line, or a value that is not UTF-8, is
//!   malformed.
//! * **Exempt requests** ([`exempt`]): a GET / HEAD navigation on which every
//!   matched route is a `web` route (D-40), and a CORS preflight (`OPTIONS`
//!   with `Access-Control-Request-Method`). Their `identity.proof` is
//!   MISSING and no proof is required.
//! * **When verified**: `schema_version = 2`, not exempt, and a matched route
//!   has `proof = required` or a rule reads `identity.proof`
//!   (`mg_core::policy::proof_verification_needed`). Otherwise the header is
//!   not parsed and `identity.proof` is MISSING.
//! * **Verification** ([`verify`]): `mg_challenge::verify_proof` with the
//!   `cnf.jkt` of the request's valid clearance as `expected_jkt`, cheap
//!   checks first; a proof that passes gets its `jti` checked in round trip
//!   1 ([`ProofCheck::jti`], `mg_edge_core::state::JtiCheck`).
//! * **Outcome** ([`ProofOutcome`]): the policy fields `identity.proof.{present,
//!   valid, replayed}`, the `pf` letter of `mg:ev`, and
//!   `mg_proof_verify_total{result}` (`missing` only for a request that a
//!   `proof = required` route requires a proof of).
//!
//! Nothing here logs the header, the key, its thumbprint or the `jti`
//! (§2.4 item 10).

use crate::metrics::metrics;
use mg_challenge::{ProofError, ProofRequest, SessionKey, VerifiedProof, proof_signing_key};
use mg_edge_core::events::ProofResult;
use mg_edge_core::state::{JtiCheck, JtiOutcome};

/// The request header (lower-case).
pub const HEADER: &str = "mg-proof";
/// `rule_id` of the 403 `mg_proof_required` substitution (§9.1).
pub const PROOF_REQUIRED_RULE: &str = "edge.proof_required";
/// `rule_id` of the 429 for a `proof = required`, `fail_closed` route whose
/// `jti` replay store is unavailable (§9.1).
pub const PROOF_UNCHECKED_RULE: &str = "edge.proof_replay_unavailable";
/// `Retry-After` of that 429.
pub const PROOF_UNCHECKED_RETRY_S: u32 = 5;

/// `result` values of `mg_proof_verify_total` (§9.1).
pub const RESULTS: [&str; 11] = [
    "valid",
    "missing",
    "malformed",
    "unbound",
    "jkt",
    "htm",
    "htu",
    "iat",
    "sig",
    "replay",
    "unchecked",
];

/// A session key's thumbprint (`jkt`). Never printed (§2.4 item 10).
#[derive(Clone, PartialEq, Eq)]
pub struct Thumbprint(pub String);

impl std::fmt::Debug for Thumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Thumbprint(<redacted>)")
    }
}

impl Thumbprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `MG-Proof` field lines of a request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProofHeader<'a> {
    Absent,
    One(&'a str),
    /// More than one line, or not UTF-8.
    Malformed,
}

impl std::fmt::Debug for ProofHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Absent => "Absent",
            Self::One(_) => "One(<redacted>)",
            Self::Malformed => "Malformed",
        })
    }
}

impl ProofHeader<'_> {
    pub fn present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// Reads `MG-Proof` from the field lines as received (see the module
/// documentation).
pub fn header(raw: &[(String, Vec<u8>)]) -> ProofHeader<'_> {
    let mut lines = raw.iter().filter(|(n, _)| n.eq_ignore_ascii_case(HEADER));
    match (lines.next(), lines.next()) {
        (None, _) => ProofHeader::Absent,
        (Some((_, v)), None) => {
            std::str::from_utf8(v).map_or(ProofHeader::Malformed, ProofHeader::One)
        }
        (Some(_), Some(_)) => ProofHeader::Malformed,
    }
}

/// A request that never needs a proof (see the module documentation):
/// `mg_core::policy::is_exempt_navigation`, or a CORS preflight. `headers`
/// is the sorted `req.headers` list.
pub fn exempt(
    navigation: bool,
    method: &str,
    all_routes_web: bool,
    headers: &[(String, String)],
) -> bool {
    mg_core::policy::is_exempt_navigation(navigation, method, all_routes_web)
        || (method == "OPTIONS"
            && crate::context::header(headers, "access-control-request-method").is_some())
}

/// Where a verified proof stands before its `jti` is checked.
#[derive(Clone, PartialEq, Eq)]
pub enum ProofCheck {
    /// No `MG-Proof` header.
    Absent,
    /// The first failed check of §6.7.
    Failed(ProofError),
    /// Passed §6.7; the `jti` check is still to come.
    Passed {
        proof: VerifiedProof,
        /// The clearance's `cnf.jkt` (equal to the proof key's thumbprint).
        jkt: String,
    },
}

impl std::fmt::Debug for ProofCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Failed(e) => write!(f, "Failed({})", e.reason_code()),
            Self::Passed { proof, .. } => f
                .debug_struct("Passed")
                .field("proof", proof)
                .finish_non_exhaustive(),
        }
    }
}

/// What [`verify`] compares a proof with.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    /// The visitor used https (`direct_tls`, or an authenticated
    /// `CF-Visitor` https).
    pub https: bool,
    /// The normalized request host.
    pub host: &'a str,
    /// The raw request path without the query.
    pub path: &'a str,
    pub now_s: i64,
}

/// Verifies the request's proof (§6.7) against the valid clearance's
/// `cnf.jkt`.
pub fn verify(h: ProofHeader<'_>, req: &Request<'_>, cnf_jkt: Option<&str>) -> ProofCheck {
    let value = match h {
        ProofHeader::Absent => return ProofCheck::Absent,
        ProofHeader::Malformed => return ProofCheck::Failed(ProofError::Malformed),
        ProofHeader::One(v) => v,
    };
    let pr = ProofRequest {
        method: req.method,
        scheme: if req.https { "https" } else { "http" },
        host: req.host,
        path: req.path,
        now_s: req.now_s,
        expected_jkt: cnf_jkt,
    };
    match mg_challenge::verify_proof(value, &pr) {
        Ok(proof) => ProofCheck::Passed {
            proof,
            // verify_proof only passes with an expected thumbprint.
            jkt: cnf_jkt.unwrap_or_default().to_owned(),
        },
        Err(e) => ProofCheck::Failed(e),
    }
}

impl ProofCheck {
    /// The round trip 1 `jti` check of a proof that passed (§9.2).
    pub fn jti(&self, site: &str, k_pseudo: &[u8; 32]) -> Option<JtiCheck> {
        match self {
            Self::Passed { proof, jkt } => Some(JtiCheck::new(
                site,
                k_pseudo,
                jkt,
                proof.jti_text(),
                proof.iat,
            )),
            _ => None,
        }
    }

    /// The outcome once the `jti` check answered (`None`: no check ran).
    pub fn outcome(&self, jti: Option<JtiOutcome>) -> ProofOutcome {
        match self {
            Self::Absent => ProofOutcome::Absent,
            Self::Failed(e) => ProofOutcome::Failed(*e),
            Self::Passed { .. } => match jti {
                Some(JtiOutcome::Fresh) => ProofOutcome::Valid,
                Some(JtiOutcome::Replayed | JtiOutcome::KeyQuota) => ProofOutcome::Replayed,
                Some(JtiOutcome::Unavailable) | None => ProofOutcome::Unchecked,
            },
        }
    }
}

/// The result of a request's proof (see the module documentation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProofOutcome {
    /// Not verified: schema 1, an exempt request, or nothing needs it.
    #[default]
    NotVerified,
    /// Verified, no `MG-Proof` header.
    Absent,
    Failed(ProofError),
    /// Passed §6.7 and the `jti` is fresh.
    Valid,
    /// The `jti` was used before, or the key is over its quota (§9.2).
    Replayed,
    /// Passed §6.7, but the `jti` replay store gave no answer: counts as
    /// valid, `identity.proof.replayed` is MISSING (§9.1).
    Unchecked,
}

impl ProofOutcome {
    /// The proof was verified (`identity.proof` is not MISSING).
    pub fn verified(self) -> bool {
        self != Self::NotVerified
    }

    /// `identity.proof.valid`: §6.7 passed and the `jti` is not a replay
    /// (an unchecked `jti` counts as passed, §9.1).
    pub fn valid(self) -> bool {
        matches!(self, Self::Valid | Self::Unchecked)
    }

    /// `identity.proof.{present, valid, replayed}` (`replayed` is MISSING for
    /// [`ProofOutcome::Unchecked`]; every field is MISSING when not verified).
    pub fn fields(self, present: bool) -> mg_core::Proof {
        mg_core::Proof {
            present,
            valid: self.valid(),
            replayed: self == Self::Replayed,
        }
    }

    /// `pf` of `mg:ev` (§13.1).
    pub fn stream(self) -> ProofResult {
        match self {
            Self::NotVerified | Self::Absent => ProofResult::None,
            Self::Valid | Self::Unchecked => ProofResult::Valid,
            Self::Replayed => ProofResult::Replayed,
            Self::Failed(ProofError::Unbound) => ProofResult::Unbound,
            Self::Failed(ProofError::Jkt) => ProofResult::JktMismatch,
            Self::Failed(_) => ProofResult::Invalid,
        }
    }

    /// The `result` of `mg_proof_verify_total` (§9.1); `None` for nothing to
    /// count (not verified; no header on a request no route requires a
    /// proof of).
    pub fn metric_result(self, required: bool) -> Option<&'static str> {
        Some(match self {
            Self::NotVerified => return None,
            Self::Absent if !required => return None,
            Self::Absent => "missing",
            Self::Valid => "valid",
            Self::Replayed => "replay",
            Self::Unchecked => "unchecked",
            Self::Failed(e) => e.reason_code().trim_start_matches("proof."),
        })
    }

    /// The debug log's view: `-` (not verified), `absent`, or the metric
    /// result.
    pub fn label(self) -> &'static str {
        match self {
            Self::NotVerified => "-",
            Self::Absent => "absent",
            other => other.metric_result(true).unwrap_or("-"),
        }
    }

    /// Counts `mg_proof_verify_total{result}`.
    pub fn count(self, required: bool) {
        if let Some(result) = self.metric_result(required) {
            metrics().proof_verify.with_label_values(&[result]).inc();
        }
    }

    /// In-place recovery is possible for this failure (§9.1): the key was
    /// cleared or replaced (`proof.unbound`, `proof.jkt`).
    pub fn recoverable(self) -> bool {
        matches!(self, Self::Failed(ProofError::Unbound | ProofError::Jkt))
    }
}

/// The session key of the request's proof when its signature verifies
/// (§9.1 in-place recovery; one ECDSA verification, so only after the
/// limiters).
pub fn signing_key(h: ProofHeader<'_>) -> Option<SessionKey> {
    match h {
        ProofHeader::One(v) => proof_signing_key(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(lines: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        lines
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
            .collect()
    }

    #[test]
    fn header_lines() {
        assert_eq!(header(&raw(&[("Accept", b"*/*")])), ProofHeader::Absent);
        assert_eq!(
            header(&raw(&[("MG-Proof", b"a.b.c")])),
            ProofHeader::One("a.b.c")
        );
        assert_eq!(
            header(&raw(&[("mg-proof", b"a.b.c")])),
            ProofHeader::One("a.b.c")
        );
        assert_eq!(
            header(&raw(&[("MG-Proof", b"a"), ("mg-proof", b"b")])),
            ProofHeader::Malformed
        );
        assert_eq!(
            header(&raw(&[("MG-Proof", b"\xff")])),
            ProofHeader::Malformed
        );
        // Debug never shows the value.
        assert!(!format!("{:?}", ProofHeader::One("secret.proof.value")).contains("secret"));
    }

    #[test]
    fn exempt_requests() {
        let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert!(exempt(true, "GET", true, &[]));
        assert!(exempt(true, "HEAD", true, &[]));
        assert!(
            !exempt(true, "POST", true, &[]),
            "a form POST is not exempt"
        );
        assert!(
            !exempt(true, "GET", false, &[]),
            "an api route is never exempt"
        );
        assert!(!exempt(false, "GET", true, &[]));
        let preflight = h(&[("access-control-request-method", "POST")]);
        assert!(exempt(false, "OPTIONS", false, &preflight));
        assert!(!exempt(false, "OPTIONS", false, &[]));
    }

    #[test]
    fn outcomes_map_to_fields_stream_and_metric() {
        use ProofOutcome as O;
        assert!(!O::NotVerified.verified());
        assert_eq!(O::NotVerified.metric_result(true), None);
        assert_eq!(O::Absent.metric_result(false), None);
        assert_eq!(O::Absent.metric_result(true), Some("missing"));
        assert_eq!(O::Absent.fields(false), mg_core::Proof::default());
        assert_eq!(O::Valid.metric_result(false), Some("valid"));
        assert!(O::Valid.valid() && O::Unchecked.valid());
        assert!(!O::Replayed.valid());
        assert!(O::Replayed.fields(true).replayed);
        assert_eq!(O::Unchecked.metric_result(true), Some("unchecked"));
        assert_eq!(O::Replayed.metric_result(true), Some("replay"));
        for (e, label, pf) in [
            (ProofError::Malformed, "malformed", ProofResult::Invalid),
            (ProofError::Unbound, "unbound", ProofResult::Unbound),
            (ProofError::Jkt, "jkt", ProofResult::JktMismatch),
            (ProofError::Htm, "htm", ProofResult::Invalid),
            (ProofError::Htu, "htu", ProofResult::Invalid),
            (ProofError::Iat, "iat", ProofResult::Invalid),
            (ProofError::Sig, "sig", ProofResult::Invalid),
        ] {
            assert_eq!(O::Failed(e).metric_result(false), Some(label));
            assert!(RESULTS.contains(&label));
            assert_eq!(O::Failed(e).stream(), pf);
            assert_eq!(
                O::Failed(e).recoverable(),
                matches!(e, ProofError::Unbound | ProofError::Jkt)
            );
        }
        assert_eq!(O::Valid.stream(), ProofResult::Valid);
        assert_eq!(O::Unchecked.stream(), ProofResult::Valid);
        assert_eq!(O::Replayed.stream(), ProofResult::Replayed);
        assert_eq!(O::Absent.stream(), ProofResult::None);
        assert_eq!(O::NotVerified.stream(), ProofResult::None);
    }

    #[test]
    fn check_outcomes_follow_the_jti_answer() {
        let passed = ProofCheck::Passed {
            proof: VerifiedProof {
                jti: [7; 16],
                iat: 1_790_000_000,
            },
            jkt: "k".repeat(43),
        };
        assert_eq!(passed.outcome(Some(JtiOutcome::Fresh)), ProofOutcome::Valid);
        assert_eq!(
            passed.outcome(Some(JtiOutcome::Replayed)),
            ProofOutcome::Replayed
        );
        assert_eq!(
            passed.outcome(Some(JtiOutcome::KeyQuota)),
            ProofOutcome::Replayed
        );
        assert_eq!(
            passed.outcome(Some(JtiOutcome::Unavailable)),
            ProofOutcome::Unchecked
        );
        let j = passed.jti("blog", &[1; 32]).unwrap();
        assert_eq!(j.jti.len(), 22);
        assert!(!format!("{passed:?}").contains("kkkk"));
        assert_eq!(ProofCheck::Absent.outcome(None), ProofOutcome::Absent);
        assert!(ProofCheck::Absent.jti("blog", &[1; 32]).is_none());
    }
}
