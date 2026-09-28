//! Challenge issuance (docs/impl/phase1-spec.md §6.2, §6.3, §9.9, §10.2,
//! D-08, D-23, D-27, D-32; WP-E1c).
//!
//! A CHALLENGE decision of an enforce site with a known client IP is
//! answered by [`respond`]:
//!
//! 1. a `cloudflare` visitor on http with GET / HEAD gets a 308 to https
//!    (the `__Host-` clearance cookie needs Secure, D-32) and
//!    `mg_https_redirect_total{site}`;
//! 2. otherwise a sealed challenge `C` is issued ([`issue`]) and answered
//!    with the 403 challenge page (navigation requests) or the JSON
//!    challenge (everything else), and `mg_challenge_total{type,
//!    provider="none", result="issued"}` is counted.
//!
//! An unknown client IP never gets here: the execution layer answers 429
//! (`hard.client_ip_unknown`, D-23), so every `C` binds `uah` and `ipp`.
//!
//! # The sealed claims (§6.2)
//!
//! `v = 1`, `kid = e<epoch of now>`, a fresh 16-byte `nonce`, the site, the
//! selected route's name as `route_class`, `type` `invisible` or `pow`
//! (an `interactive` decision is issued as `pow`, D-08), the pre-challenge
//! risk band, `attempt_no = 0`, `iat = now`, `exp = now + ttl_s` (at most
//! 120 s), `ui_seed = 0`, `pow = {sha256-hashcash-v1, difficulty}`,
//! `ret_hash(ret)` and the request's bindings (`uah`, `ipp`; `ipa` with a
//! non-zero ASN; `ctp` under `ctp_shadow` with all four Cloudflare inputs).
//!
//! # Difficulty (§6.3, D-27, I-10)
//!
//! `invisible` uses `pow_bits.low`; `pow` uses `pow_bits[risk_band]`. The
//! new `C` attached to a failed submission is always `pow`, one band up
//! (`RiskBand::after_failure`: `very_high` stays `very_high`), with that
//! band's difficulty ([`crate::mg_endpoints`]).
//!
//! # Return path (§9.9)
//!
//! GET / HEAD: the raw `path[?query]` when it passes `validate_ret` (at
//! most 512 bytes, same-origin, outside `/__mg`); otherwise, and for every
//! other method, the bundle's `fallback_ret`.

use crate::enforce::EdgeResponse;
use crate::metrics::metrics;
use crate::pages::{self, Page, PageState, Shown};
use crate::routes::RouteKind;
use crate::sdk::SdkDir;
use mg_challenge::{
    BindInputs, POW_ALG, Rng, SealError, Sealer, epoch_kid, epoch_no, random_nonce, ret_hash,
    validate_ret,
};
use mg_core::{ChallengeBind, ChallengeType, PowParams, RiskBand, SealedChallengeClaims};
use mg_proto::v1::ChallengeConfig;
use mg_proto::v1::challenge_config::PowBits;
use std::fmt;

/// Shortest and longest `C` lifetime (§8.2 `challenge.ttl_s`, §6.1).
pub const MIN_TTL_S: u32 = 10;
pub const MAX_TTL_S: u32 = 120;

/// The `provider` label of `mg_challenge_total` in Phase 1.
pub const PROVIDER_NONE: &str = "none";

/// §8.3 default difficulties.
const DEFAULT_POW_BITS: PowBits = PowBits {
    low: 14,
    medium: 16,
    high: 18,
    very_high: 20,
};

/// The bundle's `pow_bits` (the §8.3 defaults when the message is absent).
pub fn pow_bits(cfg: &ChallengeConfig) -> PowBits {
    cfg.pow_bits.unwrap_or(DEFAULT_POW_BITS)
}

/// The type a `C` is issued as: `invisible` stays, everything else is
/// `pow` (D-08: no interactive challenge in Phase 1).
pub fn issued_type(t: ChallengeType) -> ChallengeType {
    match t {
        ChallengeType::Invisible => ChallengeType::Invisible,
        _ => ChallengeType::Pow,
    }
}

/// The difficulty of a `C` (§6.3): `invisible` → `low`; `pow` → the risk
/// band's.
pub fn difficulty(bits: &PowBits, ty: ChallengeType, band: RiskBand) -> u32 {
    if ty == ChallengeType::Invisible {
        return bits.low;
    }
    match band {
        RiskBand::Low => bits.low,
        RiskBand::Medium => bits.medium,
        RiskBand::High => bits.high,
        RiskBand::VeryHigh => bits.very_high,
    }
}

/// The bundle's `fallback_ret` (validated by `verify_bundle`; `/` if a
/// hand-made bundle carries an invalid one).
pub fn fallback_ret(cfg: &ChallengeConfig) -> &str {
    if validate_ret(&cfg.fallback_ret).is_ok() {
        &cfg.fallback_ret
    } else {
        "/"
    }
}

/// The return path sealed into a new `C` (see the module documentation).
pub fn challenge_ret(method: &str, path: &str, query: &str, fallback: &str) -> String {
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        let ret = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        if validate_ret(&ret).is_ok() {
            return ret;
        }
    }
    fallback.to_owned()
}

/// What [`issue`] seals.
#[derive(Clone, Copy)]
pub struct IssueRequest<'a> {
    pub sealer: &'a Sealer,
    /// The §9.4-normalized host (the `aad` covers it, I-18).
    pub host: &'a str,
    /// The selected route's name.
    pub route_class: &'a str,
    /// `invisible` or `pow` ([`issued_type`]).
    pub ty: ChallengeType,
    pub band: RiskBand,
    pub bits: u32,
    /// `challenge.ttl_s`, clamped to 10..=120.
    pub ttl_s: u32,
    /// A validated return path.
    pub ret: &'a str,
    /// The current request's bindings; `ipp` must be present (D-23).
    pub bind: &'a BindInputs,
    pub now_ms: i64,
}

impl fmt::Debug for IssueRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssueRequest")
            .field("host", &self.host)
            .field("route_class", &self.route_class)
            .field("ty", &self.ty)
            .field("band", &self.band)
            .field("bits", &self.bits)
            .field("bind", self.bind)
            .finish_non_exhaustive()
    }
}

/// An issued challenge. `Debug` never prints `C` (§2.4 item 5).
#[derive(Clone, PartialEq, Eq)]
pub struct Issued {
    pub c: String,
    pub ty: ChallengeType,
    pub bits: u32,
    pub band: RiskBand,
    pub ret: String,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field("c_len", &self.c.len())
            .field("ty", &self.ty)
            .field("bits", &self.bits)
            .field("band", &self.band)
            .finish_non_exhaustive()
    }
}

impl Issued {
    /// How the page and the JSON answers show it.
    pub fn shown(&self) -> Shown<'_> {
        Shown {
            c: &self.c,
            ty: self.ty,
            bits: self.bits,
        }
    }
}

/// Why no `C` could be issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// The OS random number generator failed (503, §9.9).
    Rng,
    /// The claims were refused (a malformed route name in a hand-made
    /// bundle, a missing `ipp`): a configuration or programming error.
    Seal(SealError),
}

/// Builds and seals the claims of a new `C` (§6.2).
pub fn issue(req: &IssueRequest<'_>, rng: &dyn Rng) -> Result<Issued, IssueError> {
    let nonce = random_nonce(rng).map_err(|_| IssueError::Rng)?;
    let ttl_ms = i64::from(req.ttl_s.clamp(MIN_TTL_S, MAX_TTL_S)) * 1000;
    let hash = |h: Option<[u8; 16]>| h.map(|h| h.to_vec());
    let claims = SealedChallengeClaims {
        v: SealedChallengeClaims::VERSION,
        kid: epoch_kid(epoch_no(req.now_ms)),
        nonce,
        site: req.sealer.site_id().to_owned(),
        route_class: req.route_class.to_owned(),
        challenge_type: req.ty,
        providers: Vec::new(),
        risk_band: req.band,
        attempt_no: 0,
        iat_ms: req.now_ms,
        exp_ms: req.now_ms.saturating_add(ttl_ms),
        ui_seed: 0,
        pow: Some(PowParams {
            alg: POW_ALG.to_owned(),
            difficulty: req.bits,
        }),
        ret_hash: ret_hash(req.ret).to_vec(),
        bind: ChallengeBind {
            uah: Some(req.bind.uah.to_vec()),
            ipp: hash(req.bind.ipp),
            ipa: hash(req.bind.ipa),
            ctp: hash(req.bind.ctp),
            jkt: None,
            tfp: None,
        },
    };
    let c = req
        .sealer
        .seal(&claims, req.host, rng)
        .map_err(|e| match e {
            SealError::Rng => IssueError::Rng,
            other => IssueError::Seal(other),
        })?;
    Ok(Issued {
        c,
        ty: req.ty,
        bits: req.bits,
        band: req.band,
        ret: req.ret.to_owned(),
    })
}

/// Counts `mg_challenge_total{type, provider="none", result}`.
pub fn count(ty: ChallengeType, result: &str) {
    metrics()
        .challenge
        .with_label_values(&[ty.as_str(), PROVIDER_NONE, result])
        .inc();
}

/// A CHALLENGE decision to answer (see the module documentation).
#[derive(Clone, Copy)]
pub struct ChallengeRequest<'a> {
    pub sealer: &'a Sealer,
    pub sdk: &'a SdkDir,
    pub cfg: &'a ChallengeConfig,
    pub site_id: &'a str,
    pub request_id: &'a str,
    /// §9.4-normalized.
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    /// What the origin would have received (for the 308 target).
    pub origin_form: &'a [u8],
    /// `cloudflare` profile and `CF-Visitor` scheme http.
    pub http_visitor: bool,
    /// §9.9 navigation request: the page, otherwise JSON.
    pub navigation: bool,
    pub accept_language: Option<&'a str>,
    /// The selected route's name.
    pub route_class: &'a str,
    /// The decision's type.
    pub ty: ChallengeType,
    /// The pre-challenge risk band (`RiskAssessment.score.band()`).
    pub band: RiskBand,
    pub bind: &'a BindInputs,
    pub now_ms: i64,
}

impl fmt::Debug for ChallengeRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeRequest")
            .field("site_id", &self.site_id)
            .field("request_id", &self.request_id)
            .field("host", &self.host)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("route_class", &self.route_class)
            .field("ty", &self.ty)
            .field("band", &self.band)
            .finish_non_exhaustive()
    }
}

/// What [`respond`] did (for the request log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeAnswer {
    /// 308 to https (D-32).
    HttpsRedirect,
    /// A `C` of this type and difficulty was issued.
    Issued { ty: ChallengeType, bits: u32 },
    /// 503: the RNG failed, or the claims could not be sealed.
    Unavailable,
}

impl fmt::Display for ChallengeAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpsRedirect => f.write_str("https_redirect"),
            Self::Issued { ty, bits } => write!(f, "issued:{ty}/{bits}"),
            Self::Unavailable => f.write_str("unavailable"),
        }
    }
}

/// 503 when no `C` (or no CSP nonce) could be produced (§9.9): counted in
/// `mg_edge_request_errors_total{route="origin"}` (a CHALLENGE answers a
/// request bound for the origin), never answered without a `C`.
fn unavailable() -> (EdgeResponse, ChallengeAnswer) {
    metrics().internal_error(RouteKind::Origin);
    (
        EdgeResponse::internal_unavailable(),
        ChallengeAnswer::Unavailable,
    )
}

/// Answers a CHALLENGE decision (see the module documentation).
pub fn respond(req: &ChallengeRequest<'_>, rng: &dyn Rng) -> (EdgeResponse, ChallengeAnswer) {
    let get_or_head =
        req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD");
    if req.http_visitor && get_or_head {
        metrics()
            .https_redirect
            .with_label_values(&[req.site_id])
            .inc();
        return (
            pages::https_redirect(req.host, req.origin_form),
            ChallengeAnswer::HttpsRedirect,
        );
    }
    let ty = issued_type(req.ty);
    let bits = difficulty(&pow_bits(req.cfg), ty, req.band);
    let ret = challenge_ret(req.method, req.path, req.query, fallback_ret(req.cfg));
    let issued = issue(
        &IssueRequest {
            sealer: req.sealer,
            host: req.host,
            route_class: req.route_class,
            ty,
            band: req.band,
            bits,
            ttl_s: req.cfg.ttl_s,
            ret: &ret,
            bind: req.bind,
            now_ms: req.now_ms,
        },
        rng,
    );
    let issued = match issued {
        Ok(i) => i,
        Err(e) => {
            if let IssueError::Seal(err) = &e {
                log::error!(
                    "request_id={} site {}: challenge not sealed: {err}",
                    req.request_id,
                    req.site_id
                );
            } else {
                log::error!(
                    "request_id={} challenge: the OS random number generator failed",
                    req.request_id
                );
            }
            return unavailable();
        }
    };
    let resp = if req.navigation {
        let Ok(nonce) = pages::csp_nonce(rng) else {
            log::error!(
                "request_id={} challenge page: the OS random number generator failed",
                req.request_id
            );
            return unavailable();
        };
        pages::challenge_page(
            req.sdk,
            &Page {
                lang: pages::page_lang(req.accept_language),
                nonce: &nonce,
                request_id: req.request_id,
                ret: &issued.ret,
                state: PageState::Challenge,
                challenge: Some(issued.shown()),
            },
        )
    } else {
        pages::challenge_json(req.request_id, issued.shown(), &issued.ret)
    };
    count(ty, "issued");
    (resp, ChallengeAnswer::Issued { ty, bits })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_challenge::{SealKeys, check_challenge_bind};
    use mg_core::BindResult;
    use std::path::Path;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    /// 2026-09-27T12:00:00Z.
    const NOW: i64 = 1_790_510_400_000;

    fn sealer() -> Sealer {
        let json = std::fs::read(crate::test_support::repo(
            "testdata/phase1/keys/seal.root.json",
        ))
        .unwrap();
        Sealer::new("blog", SealKeys::from_key_file(&json, "blog").unwrap())
    }

    fn sdk() -> SdkDir {
        SdkDir::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk")).unwrap()
    }

    fn cfg() -> ChallengeConfig {
        crate::sites::default_challenge()
    }

    fn bind() -> BindInputs {
        BindInputs {
            uah: mg_challenge::uah("chrome", 131),
            ipp: Some(mg_challenge::ipp("198.51.100.0/24")),
            ipa: mg_challenge::ipa(64500),
            ctp: None,
        }
    }

    #[derive(Debug)]
    struct Failing;
    impl Rng for Failing {
        fn fill(&self, _dst: &mut [u8]) -> Result<(), mg_challenge::RngError> {
            Err(mg_challenge::RngError)
        }
    }

    /// §6.3 / D-27: invisible → low; pow → the band's; D-08: interactive
    /// is issued as pow.
    #[test]
    fn difficulty_rules() {
        let bits = pow_bits(&cfg());
        use RiskBand::*;
        for band in [Low, Medium, High, VeryHigh] {
            assert_eq!(difficulty(&bits, ChallengeType::Invisible, band), 14);
        }
        assert_eq!(difficulty(&bits, ChallengeType::Pow, Low), 14);
        assert_eq!(difficulty(&bits, ChallengeType::Pow, Medium), 16);
        assert_eq!(difficulty(&bits, ChallengeType::Pow, High), 18);
        assert_eq!(difficulty(&bits, ChallengeType::Pow, VeryHigh), 20);
        assert_eq!(issued_type(ChallengeType::Interactive), ChallengeType::Pow);
        assert_eq!(
            issued_type(ChallengeType::Invisible),
            ChallengeType::Invisible
        );
        assert_eq!(issued_type(ChallengeType::Unspecified), ChallengeType::Pow);
        let absent = ChallengeConfig {
            pow_bits: None,
            ..cfg()
        };
        assert_eq!(pow_bits(&absent).very_high, 20);
    }

    /// §9.9: GET / HEAD keep their path (and query) when valid; other
    /// methods and invalid or overlong paths get `fallback_ret`.
    #[test]
    fn return_paths() {
        assert_eq!(challenge_ret("GET", "/a/b", "x=1", "/"), "/a/b?x=1");
        assert_eq!(challenge_ret("HEAD", "/a", "", "/"), "/a");
        assert_eq!(challenge_ret("POST", "/a", "", "/home"), "/home");
        assert_eq!(challenge_ret("GET", "//evil.test/", "", "/"), "/");
        assert_eq!(challenge_ret("GET", "/__mg/c", "", "/"), "/");
        assert_eq!(challenge_ret("GET", "/%5F%5Fmg/c", "", "/"), "/");
        assert_eq!(
            challenge_ret("GET", &format!("/{}", "a".repeat(512)), "", "/"),
            "/"
        );
        assert_eq!(challenge_ret("GET", "*", "", "/f"), "/f");
        let bad = ChallengeConfig {
            fallback_ret: "https://evil.test/".into(),
            ..cfg()
        };
        assert_eq!(fallback_ret(&bad), "/");
        assert_eq!(fallback_ret(&cfg()), "/");
    }

    /// §6.2: the sealed claims open for the same host and type and carry
    /// the request's bindings, band, route and return path.
    #[test]
    fn issued_challenges_open_with_the_right_claims() {
        let s = sealer();
        let b = bind();
        let i = issue(
            &IssueRequest {
                sealer: &s,
                host: "example.com",
                route_class: "login",
                ty: ChallengeType::Pow,
                band: RiskBand::High,
                bits: 18,
                ttl_s: 90,
                ret: "/account/login",
                bind: &b,
                now_ms: NOW,
            },
            &crate::rng::OsRng,
        )
        .unwrap();
        assert!(i.c.len() <= mg_challenge::MAX_C_LEN);
        assert!(!format!("{i:?}").contains(&i.c));
        let claims = s
            .open(&i.c, "example.com", ChallengeType::Pow, NOW + 1000)
            .unwrap();
        assert_eq!(claims.route_class, "login");
        assert_eq!(claims.risk_band, RiskBand::High);
        assert_eq!(claims.pow.as_ref().unwrap().difficulty, 18);
        assert_eq!(claims.exp_ms - claims.iat_ms, 90_000);
        assert_eq!(claims.attempt_no, 0);
        assert_eq!(claims.ret_hash, ret_hash("/account/login").to_vec());
        let check = check_challenge_bind(&claims.bind, &b);
        assert_eq!(
            (check.uah, check.ipp),
            (BindResult::Match, BindResult::Match)
        );
        // Another host, another type: does not open.
        assert!(
            s.open(&i.c, "www.example.com", ChallengeType::Pow, NOW)
                .is_err()
        );
        assert!(
            s.open(&i.c, "example.com", ChallengeType::Invisible, NOW)
                .is_err()
        );
        // The lifetime is capped at 120 s.
        let long = issue(
            &IssueRequest {
                sealer: &s,
                host: "example.com",
                route_class: "login",
                ty: ChallengeType::Invisible,
                band: RiskBand::Low,
                bits: 14,
                ttl_s: 100_000,
                ret: "/",
                bind: &b,
                now_ms: NOW,
            },
            &crate::rng::OsRng,
        )
        .unwrap();
        let claims = s
            .open(&long.c, "example.com", ChallengeType::Invisible, NOW)
            .unwrap();
        assert_eq!(claims.exp_ms - claims.iat_ms, 120_000);
    }

    fn issue_req<'a>(s: &'a Sealer, b: &'a BindInputs) -> IssueRequest<'a> {
        IssueRequest {
            sealer: s,
            host: "example.com",
            route_class: "login",
            ty: ChallengeType::Pow,
            band: RiskBand::Low,
            bits: 14,
            ttl_s: 120,
            ret: "/",
            bind: b,
            now_ms: NOW,
        }
    }

    /// D-23: without `ipp` nothing is sealed; an RNG failure is an error.
    #[test]
    fn issue_errors() {
        let s = sealer();
        let mut b = bind();
        assert_eq!(issue(&issue_req(&s, &b), &Failing), Err(IssueError::Rng));
        b.ipp = None;
        assert!(matches!(
            issue(&issue_req(&s, &b), &crate::rng::OsRng),
            Err(IssueError::Seal(_))
        ));
        let b = bind();
        let bad_route = IssueRequest {
            route_class: "Not A Route",
            ..issue_req(&s, &b)
        };
        assert!(matches!(
            issue(&bad_route, &crate::rng::OsRng),
            Err(IssueError::Seal(_))
        ));
        // A host that cannot have been sealed.
        let no_host = IssueRequest {
            host: "",
            ..issue_req(&s, &b)
        };
        assert!(matches!(
            issue(&no_host, &crate::rng::OsRng),
            Err(IssueError::Seal(_))
        ));
    }

    fn request<'a>(
        s: &'a Sealer,
        sdk: &'a SdkDir,
        cfg: &'a ChallengeConfig,
        b: &'a BindInputs,
    ) -> ChallengeRequest<'a> {
        ChallengeRequest {
            sealer: s,
            sdk,
            cfg,
            site_id: "blog",
            request_id: ID,
            host: "example.com",
            method: "GET",
            path: "/members/a",
            query: "x=1",
            origin_form: b"/members/a?x=1",
            http_visitor: false,
            navigation: true,
            accept_language: Some("zh-CN,zh;q=0.9"),
            route_class: "members",
            ty: ChallengeType::Invisible,
            band: RiskBand::Medium,
            bind: b,
            now_ms: NOW,
        }
    }

    #[test]
    fn answers() {
        let (s, sdk, cfg, b) = (sealer(), sdk(), cfg(), bind());
        let base = request(&s, &sdk, &cfg, &b);

        // Navigation: the page, with a C that opens for this host.
        let (r, a) = respond(&base, &crate::rng::OsRng);
        assert_eq!(
            a,
            ChallengeAnswer::Issued {
                ty: ChallengeType::Invisible,
                bits: 14
            }
        );
        assert_eq!(r.status, 403);
        let html = r.body_text();
        assert!(html.contains("<html lang=\"zh-CN\">"));
        assert!(html.contains("data-mg-ret=\"/members/a?x=1\""));
        let c = html
            .split("data-mg-c=\"")
            .nth(1)
            .and_then(|t| t.split('"').next())
            .unwrap();
        let claims = s
            .open(c, "example.com", ChallengeType::Invisible, NOW)
            .unwrap();
        assert_eq!(claims.route_class, "members");
        assert_eq!(claims.risk_band, RiskBand::Medium);

        // JSON for everything else; interactive is issued as pow at the
        // band's difficulty.
        let (r, a) = respond(
            &ChallengeRequest {
                navigation: false,
                ty: ChallengeType::Interactive,
                ..base
            },
            &crate::rng::OsRng,
        );
        assert_eq!(
            a,
            ChallengeAnswer::Issued {
                ty: ChallengeType::Pow,
                bits: 16
            }
        );
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(v["type"], "pow");
        assert_eq!(v["pow"]["bits"], 16);
        assert_eq!(v["ret"], "/members/a?x=1");
        assert!(r.headers.contains(&("MG-Challenge", "pow".to_string())));

        // D-32: an http visitor's GET / HEAD is redirected, a POST challenged.
        let (r, a) = respond(
            &ChallengeRequest {
                http_visitor: true,
                ..base
            },
            &crate::rng::OsRng,
        );
        assert_eq!((r.status, a), (308, ChallengeAnswer::HttpsRedirect));
        assert_eq!(
            r.header().unwrap().headers["location"],
            "https://example.com/members/a?x=1"
        );
        let (r, _) = respond(
            &ChallengeRequest {
                http_visitor: true,
                method: "POST",
                ..base
            },
            &crate::rng::OsRng,
        );
        assert_eq!(r.status, 403);

        // §9.9: RNG failure is a 503 counted as an Edge error, never a
        // challenge without a C (the page's CSP nonce included).
        let errors = || {
            metrics()
                .errors
                .with_label_values(&[RouteKind::Origin.metric_label()])
                .get()
        };
        let before = errors();
        let (r, a) = respond(&base, &Failing);
        assert_eq!((r.status, a), (503, ChallengeAnswer::Unavailable));
        assert!(!r.body_text().contains("mg_challenge"));
        let json_only = OnlyFirst::default();
        let (r, a) = respond(&base, &json_only);
        assert_eq!(
            (r.status, a),
            (503, ChallengeAnswer::Unavailable),
            "the C is sealed, the nonce of its page is not"
        );
        assert!(errors() >= before + 2);
    }

    /// An RNG that serves the first `n` fills (the C's nonce and xnonce),
    /// then fails (the page's CSP nonce).
    #[derive(Debug, Default)]
    struct OnlyFirst(std::sync::atomic::AtomicUsize);
    impl Rng for OnlyFirst {
        fn fill(&self, dst: &mut [u8]) -> Result<(), mg_challenge::RngError> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 2 {
                crate::rng::OsRng.fill(dst)
            } else {
                Err(mg_challenge::RngError)
            }
        }
    }
}
