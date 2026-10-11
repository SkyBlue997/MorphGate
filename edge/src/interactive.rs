//! Interactive challenges in the Edge (docs/impl/phase2-spec.md §7, D-41,
//! D-42, D-44, D-50, D-67; WP-E2a). The pure parts (provider selection, the
//! hard checks and the score, failure escalation) are mg-core's
//! (`mg_core::providers`); the sealed `C`, PoW v2, `ui_seed` and the session
//! keys are mg-challenge's. This module holds what the Edge adds:
//!
//! * [`seal`]: the claims of an interactive `C` (§7.1): type `interactive`,
//!   the providers, a non-zero random `ui_seed` (or the inherited one of a
//!   renewal), PoW v2 with the bundle's `pow_bits[band]`, `pow_k` and
//!   `a11y_bits`, a 600 s lifetime, and the bindings (`jkt` only for a key
//!   the request proved);
//! * [`ix_value`]: the plain parameters `ix` that travel with the `C`
//!   (§7.2, D-44): everything in it is recomputed from the `C` on
//!   submission, so a client gains nothing by changing it;
//! * the built-in in-process limiters `mg.ix.issue` and `mg.c.renew`
//!   ([`two_tier`]) and the Valkey quota `mg.a11y.issue` ([`a11y_checks`]),
//!   each with an ip entity tier and an ipp tier (D-67, §7.9);
//! * [`a11y_pref`]: the `__Host-mg_a11y=1` cookie (§9.5), read only for the
//!   provider order.

use crate::challenge::IssueError;
use crate::metrics::metrics;
use crate::sites::InteractiveRuntime;
use mg_challenge::{
    BindInputs, POW_ALG_V2, Rng, SealError, Sealer, bind_hash, epoch_kid, epoch_no, random_nonce,
    ui_params,
};
use mg_core::gcra::{GcraOutcome, GcraParams};
use mg_core::providers::MIN_ELAPSED_MARGIN_MS;
use mg_core::{
    ChallengeBind, ChallengeType, IxMode, Net, PowParams, ProviderId, RiskBand,
    SealedChallengeClaims, SelectionInput, min_elapsed_ms, select_providers,
};
use mg_edge_core::state::builtin::ClientDims;
use mg_edge_core::state::{LimitCheck, LimiterKey, StateHandle, dims};
use serde_json::{Value, json};
use std::net::IpAddr;

/// Lifetime of every interactive `C` (§6.1, D-42).
pub const LIFETIME_MS: i64 = SealedChallengeClaims::MAX_INTERACTIVE_LIFETIME_MS;
/// Most renewals in one chain (§7.4).
pub const MAX_RENEW_NO: u32 = SealedChallengeClaims::MAX_RENEW_NO;

/// `mg.ix.issue`: interactive `C` issued (and renewed) per ip entity.
pub const IX_ISSUE: &str = "mg.ix.issue";
/// Its ipp tier (4x, counted only).
pub const IX_ISSUE_PREFIX: &str = "mg.ix.issue.prefix";
/// `mg.c.renew`: renewals per ip entity.
pub const RENEW: &str = "mg.c.renew";
/// Its ipp tier (4x).
pub const RENEW_PREFIX: &str = "mg.c.renew.prefix";
/// `mg.a11y.issue`: `interactive_a11y` clearances per ip entity.
pub const A11Y_ISSUE: &str = "mg.a11y.issue";
/// Its ipp tier.
pub const A11Y_ISSUE_PREFIX: &str = "mg.a11y.issue.prefix";

/// The accessibility preference cookie (§9.5).
pub const A11Y_COOKIE: &str = "__Host-mg_a11y";
/// Its lifetime: one year.
pub const A11Y_COOKIE_MAX_AGE_S: u32 = 31_536_000;

/// `Set-Cookie` of the accessibility preference (§9.5): value `1`,
/// `HttpOnly; Secure; SameSite=Lax; Path=/`, one year.
pub fn a11y_set_cookie() -> String {
    format!(
        "{A11Y_COOKIE}=1; Max-Age={A11Y_COOKIE_MAX_AGE_S}; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
}

/// `Set-Cookie` that deletes the accessibility preference (§9.5).
pub fn a11y_delete_cookie() -> String {
    format!("{A11Y_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")
}

/// The `name=value` pairs of `Cookie` header values.
fn cookie_pairs<S: AsRef<str>>(headers: &[S]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .flat_map(|h| h.as_ref().split(';'))
        .map(|pair| match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v.trim()),
            None => (pair.trim(), ""),
        })
}

/// The request carries `__Host-mg_a11y=1` (§9.5): exact name (cookie names
/// are case-sensitive) and value. `headers` are the request's `Cookie`
/// header values (`crate::context::Built::cookies`).
pub fn a11y_pref<S: AsRef<str>>(headers: &[S]) -> bool {
    cookie_pairs(headers).any(|(n, v)| n == A11Y_COOKIE && v == "1")
}

/// The request carries the cookie at all (it is deleted after a
/// `self_hold` success, §9.5).
pub fn has_a11y_cookie<S: AsRef<str>>(headers: &[S]) -> bool {
    cookie_pairs(headers).any(|(n, _)| n == A11Y_COOKIE)
}

/// The `pow` of a new interactive `C` (§7.1): PoW v2, `pow_bits[band]` per
/// `self_hold` sub-puzzle, `pow_k` sub-puzzles, `a11y_bits` per `pow_a11y`
/// sub-puzzle.
pub fn pow_params(cfg: &InteractiveRuntime, band: RiskBand) -> PowParams {
    let b = &cfg.pow_bits;
    PowParams {
        alg: POW_ALG_V2.to_owned(),
        difficulty: match band {
            RiskBand::Low => b.low,
            RiskBand::Medium => b.medium,
            RiskBand::High => b.high,
            RiskBand::VeryHigh => b.very_high,
        },
        k: cfg.pow_k,
        a11y_difficulty: cfg.a11y_bits,
    }
}

/// The providers of a new interactive `C` (§5.4). Phase 2's Turnstile is
/// wired by WP-E2c; until then only the built-in providers are offered.
pub fn providers(
    cfg: &InteractiveRuntime,
    host: &str,
    route_id: &str,
    attempt_no: u32,
    a11y_pref: bool,
) -> Vec<ProviderId> {
    select_providers(&SelectionInput {
        country_geo: None,
        country_cf: None,
        route_id,
        redact_path: false,
        host,
        attempt_no,
        escalate_after: cfg.escalate_after,
        a11y_pref,
        turnstile: None,
    })
}

/// What [`seal`] puts into an interactive `C`.
#[derive(Clone)]
pub struct Seal<'a> {
    pub sealer: &'a Sealer,
    /// The §9.4-normalized host (the `aad` covers it).
    pub host: &'a str,
    pub route_class: &'a str,
    pub band: RiskBand,
    /// 1-based (§5.3).
    pub attempt_no: u32,
    pub renew_no: u32,
    pub providers: Vec<ProviderId>,
    /// `None`: a fresh random one; `Some`: inherited (a renewal keeps the
    /// hold time and the button position, §7.4).
    pub ui_seed: Option<u64>,
    pub pow: PowParams,
    /// `ret_hash` of the return path (a renewal only knows the hash).
    pub ret_hash: [u8; 16],
    /// The current request's bindings; `ipp` must be present (D-23).
    pub bind: &'a BindInputs,
    /// The thumbprint of a session key the request proved (D-41).
    pub jkt: Option<&'a str>,
    pub now_ms: i64,
}

impl std::fmt::Debug for Seal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seal")
            .field("host", &self.host)
            .field("route_class", &self.route_class)
            .field("band", &self.band)
            .field("attempt_no", &self.attempt_no)
            .field("renew_no", &self.renew_no)
            .field("providers", &self.providers)
            .field("bound", &self.jkt.is_some())
            .finish_non_exhaustive()
    }
}

/// A random non-zero `ui_seed` (§7.1: drawn again when 0).
fn random_ui_seed(rng: &dyn Rng) -> Result<u64, IssueError> {
    for _ in 0..8 {
        let mut b = [0u8; 8];
        rng.fill(&mut b).map_err(|_| IssueError::Rng)?;
        let seed = u64::from_be_bytes(b);
        if seed != 0 {
            return Ok(seed);
        }
    }
    Err(IssueError::Rng)
}

/// Seals an interactive `C` (§7.1); returns it and its claims.
pub fn seal(req: &Seal<'_>, rng: &dyn Rng) -> Result<(String, SealedChallengeClaims), IssueError> {
    let nonce = random_nonce(rng).map_err(|_| IssueError::Rng)?;
    let ui_seed = match req.ui_seed {
        Some(seed) if seed != 0 => seed,
        _ => random_ui_seed(rng)?,
    };
    let hash = |h: Option<[u8; 16]>| h.map(|h| h.to_vec());
    let claims = SealedChallengeClaims {
        v: SealedChallengeClaims::VERSION,
        kid: epoch_kid(epoch_no(req.now_ms)),
        nonce,
        site: req.sealer.site_id().to_owned(),
        route_class: req.route_class.to_owned(),
        challenge_type: ChallengeType::Interactive,
        providers: req.providers.clone(),
        risk_band: req.band,
        attempt_no: req.attempt_no.max(1),
        iat_ms: req.now_ms,
        exp_ms: req.now_ms.saturating_add(LIFETIME_MS),
        ui_seed,
        pow: Some(req.pow.clone()),
        ret_hash: req.ret_hash.to_vec(),
        bind: ChallengeBind {
            uah: Some(req.bind.uah.to_vec()),
            ipp: hash(req.bind.ipp),
            ipa: hash(req.bind.ipa),
            ctp: hash(req.bind.ctp),
            jkt: req.jkt.map(|j| bind_hash("jkt", j).to_vec()),
            tfp: None,
        },
        renew_no: req.renew_no,
    };
    let c = req
        .sealer
        .seal(&claims, req.host, rng)
        .map_err(|e| match e {
            SealError::Rng => IssueError::Rng,
            other => IssueError::Seal(other),
        })?;
    Ok((c, claims))
}

/// Whether the `C`'s `jkt` binding is the thumbprint `jkt` (D-41).
pub fn jkt_matches(claims: &SealedChallengeClaims, jkt: &str) -> bool {
    claims
        .bind
        .jkt
        .as_deref()
        .is_some_and(|b| b == bind_hash("jkt", jkt).as_slice())
}

/// The plain parameters `ix` of an interactive `C` (§7.2): `hold_ms` and
/// `offset` from `ui_params(ui_seed)`, `pow`, `attempt`, `exp_ms` and
/// `bound` from the claims, `now_ms = C.iat`, `min_ms = hold_ms +
/// min_pow_ms + 250`, `a11y_min_ms`, `a11y_first` (`providers[0] =
/// pow_a11y`) and `a11y_quota` (`mg.a11y.issue` exceeded). At most 1024
/// bytes serialized (no `turnstile` member before WP-E2c).
pub fn ix_value(
    claims: &SealedChallengeClaims,
    cfg: &InteractiveRuntime,
    a11y_quota: bool,
) -> Value {
    let ui = ui_params(claims.ui_seed);
    let pow = claims.pow.clone().unwrap_or_default();
    let providers: Vec<&str> = claims.providers.iter().map(|p| p.as_str()).collect();
    json!({
        "v": 1,
        "providers": providers,
        "hold_ms": ui.required_hold_ms,
        "offset": [ui.offset_x_px, ui.offset_y_px],
        "min_ms": min_elapsed_ms(IxMode::Hold, ui.required_hold_ms, cfg.min_pow_ms, cfg.a11y_min_ms),
        "a11y_min_ms": cfg.a11y_min_ms,
        "pow": {
            "alg": POW_ALG_V2,
            "k": pow.k,
            "bits": pow.difficulty,
            "a11y_bits": pow.a11y_difficulty,
        },
        "attempt": claims.attempt_no,
        "now_ms": claims.iat_ms,
        "exp_ms": claims.exp_ms,
        "bound": claims.bind.jkt.is_some(),
        "a11y_first": claims.providers.first() == Some(&ProviderId::PowA11y),
        "a11y_quota": a11y_quota,
    })
}

/// `min_ms` of [`ix_value`] for documentation and tests: the hold plus the
/// PoW floor plus the margin of §7.7.
pub fn min_ms(required_hold_ms: u32, min_pow_ms: u32) -> u32 {
    required_hold_ms
        .saturating_add(min_pow_ms)
        .saturating_add(MIN_ELAPSED_MARGIN_MS)
}

/// The outcome of a built-in in-process limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Allowed,
    /// 429 with this `Retry-After`.
    Limited {
        retry_after_s: u32,
    },
}

/// `Retry-After` (whole seconds, at least 1) of an exceeded outcome.
pub fn retry_after_s(o: &GcraOutcome) -> u32 {
    u32::try_from(o.retry_after_us.div_ceil(1_000_000))
        .unwrap_or(u32::MAX)
        .max(1)
}

fn local(
    state: &StateHandle,
    site: &str,
    id: &str,
    d: String,
    params: GcraParams,
    now_us: u64,
) -> GcraOutcome {
    let o = state.local_check(
        &LimitCheck {
            key: LimiterKey::new(site, id, d),
            params,
            cost: 1,
            write: true,
        },
        now_us,
    );
    if !o.allowed {
        metrics().ratelimit_exceeded.with_label_values(&[id]).inc();
    }
    o
}

/// A two-tier in-process limiter (D-67): the ip entity tier `ids.0` with
/// `params.0`, the ipp tier `ids.1` with `params.1` (4x). The ip entity
/// tier always decides; the ipp tier decides only with `prefix_enforces`
/// (`mg.c.renew`) and is otherwise only counted (`mg.ix.issue`, §7.1).
pub fn two_tier(
    state: &StateHandle,
    site: &str,
    ids: (&str, &str),
    ip: IpAddr,
    params: (GcraParams, GcraParams),
    prefix_enforces: bool,
    now_us: u64,
) -> Gate {
    let entity = Net::entity_of(ip);
    let prefix = Net::prefix_of(ip);
    let a = local(
        state,
        site,
        ids.0,
        dims(&[("ip", Some(&entity))]),
        params.0,
        now_us,
    );
    let b = local(
        state,
        site,
        ids.1,
        dims(&[("ip_prefix", Some(&prefix))]),
        params.1,
        now_us,
    );
    if !a.allowed {
        return Gate::Limited {
            retry_after_s: retry_after_s(&a),
        };
    }
    if prefix_enforces && !b.allowed {
        return Gate::Limited {
            retry_after_s: retry_after_s(&b),
        };
    }
    Gate::Allowed
}

/// `mg.ix.issue` for one interactive `C` (§7.1, §7.9): 429 when the ip
/// entity is over its limit; the ipp tier is only counted.
pub fn issue_gate(
    state: &StateHandle,
    site: &str,
    cfg: &InteractiveRuntime,
    ip: IpAddr,
    now_us: u64,
) -> Gate {
    two_tier(
        state,
        site,
        (IX_ISSUE, IX_ISSUE_PREFIX),
        ip,
        (cfg.issue, cfg.issue_ipp),
        false,
        now_us,
    )
}

/// `mg.c.renew` (§7.4 step 2): both tiers decide.
pub fn renew_gate(
    state: &StateHandle,
    site: &str,
    cfg: &InteractiveRuntime,
    ip: IpAddr,
    now_us: u64,
) -> Gate {
    two_tier(
        state,
        site,
        (RENEW, RENEW_PREFIX),
        ip,
        (cfg.renew, cfg.renew_ipp),
        true,
        now_us,
    )
}

/// `mg.a11y.issue`, both tiers (§7.9): checked in round trip 1 of every
/// interactive submission (`write = false`), written with the nonce in
/// round trip 2 when `p = pow_a11y` (`write = true`).
pub fn a11y_checks(
    site: &str,
    cfg: &InteractiveRuntime,
    c: &ClientDims<'_>,
    write: bool,
) -> Vec<LimitCheck> {
    let check = |id: &str, d: String, params: GcraParams| LimitCheck {
        key: LimiterKey::new(site, id, d),
        params,
        cost: 1,
        write,
    };
    vec![
        check(A11Y_ISSUE, dims(&[("ip", c.ip_entity)]), cfg.a11y_ip),
        check(
            A11Y_ISSUE_PREFIX,
            dims(&[("ip_prefix", c.ip_prefix)]),
            cfg.a11y_ipp,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_challenge::SealKeys;

    /// 2026-09-27T12:00:00Z.
    const NOW: i64 = 1_790_510_400_000;

    pub(crate) fn cfg() -> InteractiveRuntime {
        let b = mg_edge_core::testkit::http::test_site_bundle_v2("blog", &["example.com"], 1);
        let ix = b.challenge.unwrap().interactive.unwrap();
        InteractiveRuntime::from_proto(&ix).unwrap()
    }

    fn sealer() -> Sealer {
        let json = std::fs::read(crate::test_support::repo(
            "testdata/phase1/keys/seal.root.json",
        ))
        .unwrap();
        Sealer::new("blog", SealKeys::from_key_file(&json, "blog").unwrap())
    }

    fn bind() -> BindInputs {
        BindInputs {
            uah: mg_challenge::uah("chrome", 131),
            ipp: Some(mg_challenge::ipp("198.51.100.0/24")),
            ipa: mg_challenge::ipa(64500),
            ctp: None,
        }
    }

    /// §7.1 / §7.2: the sealed claims and `ix` agree, and `ix` is within
    /// 1024 bytes.
    #[test]
    fn sealed_interactive_challenge_and_its_ix() {
        let (s, b, c) = (sealer(), bind(), cfg());
        let jkt = mg_challenge::testkit::TestSessionKey::from_label("a").thumbprint();
        let req = Seal {
            sealer: &s,
            host: "example.com",
            route_class: "login",
            band: RiskBand::High,
            attempt_no: 1,
            renew_no: 0,
            providers: providers(&c, "example.com", "login", 1, false),
            ui_seed: None,
            pow: pow_params(&c, RiskBand::High),
            ret_hash: mg_challenge::ret_hash("/account/login"),
            bind: &b,
            jkt: Some(&jkt),
            now_ms: NOW,
        };
        let (token, claims) = seal(&req, &crate::rng::OsRng).unwrap();
        let opened = s
            .open(&token, "example.com", ChallengeType::Interactive, NOW + 1)
            .unwrap();
        assert_eq!(opened, claims);
        assert_ne!(claims.ui_seed, 0);
        assert_eq!(claims.exp_ms - claims.iat_ms, 600_000);
        assert_eq!(
            claims.providers,
            vec![ProviderId::SelfHold, ProviderId::PowA11y]
        );
        let pow = claims.pow.as_ref().unwrap();
        assert_eq!(
            (pow.alg.as_str(), pow.difficulty, pow.k, pow.a11y_difficulty),
            (POW_ALG_V2, 18, 8, 17)
        );
        assert!(jkt_matches(&claims, &jkt));
        assert!(!jkt_matches(
            &claims,
            &mg_challenge::testkit::TestSessionKey::from_label("b").thumbprint()
        ));

        let ix = ix_value(&claims, &c, false);
        let ui = ui_params(claims.ui_seed);
        assert_eq!(ix["v"], 1);
        assert_eq!(ix["providers"], json!(["self_hold", "pow_a11y"]));
        assert_eq!(ix["hold_ms"], ui.required_hold_ms);
        assert_eq!(ix["offset"], json!([ui.offset_x_px, ui.offset_y_px]));
        assert_eq!(ix["min_ms"], min_ms(ui.required_hold_ms, c.min_pow_ms));
        assert_eq!(ix["a11y_min_ms"], 2000);
        assert_eq!(
            ix["pow"],
            json!({"alg": POW_ALG_V2, "k": 8, "bits": 18, "a11y_bits": 17})
        );
        assert_eq!(
            (ix["attempt"].as_u64(), ix["now_ms"].as_i64()),
            (Some(1), Some(NOW))
        );
        assert_eq!(ix["exp_ms"].as_i64(), Some(NOW + 600_000));
        assert_eq!(
            (ix["bound"].as_bool(), ix["a11y_first"].as_bool()),
            (Some(true), Some(false))
        );
        assert!(ix.to_string().len() <= 1024);
        // The inherited seed of a renewal stays.
        let renewed = seal(
            &Seal {
                ui_seed: Some(claims.ui_seed),
                renew_no: 1,
                ..req.clone()
            },
            &crate::rng::OsRng,
        )
        .unwrap()
        .1;
        assert_eq!((renewed.ui_seed, renewed.renew_no), (claims.ui_seed, 1));
    }

    /// §5.4 through the Edge: escalation and the preference cookie move
    /// `pow_a11y` first, which `ix.a11y_first` shows.
    #[test]
    fn provider_order() {
        let c = cfg();
        assert_eq!(
            providers(&c, "example.com", "r", 1, false)[0],
            ProviderId::SelfHold
        );
        assert_eq!(
            providers(&c, "example.com", "r", 3, false)[0],
            ProviderId::PowA11y
        );
        assert_eq!(
            providers(&c, "example.com", "r", 1, true)[0],
            ProviderId::PowA11y
        );
    }

    #[test]
    fn a11y_cookie() {
        assert!(a11y_pref(&["a=b; __Host-mg_a11y=1"]));
        assert!(a11y_pref(&["a=b", "__Host-mg_a11y=1;c=d"]));
        assert!(!a11y_pref(&["__Host-mg_a11y=0"]));
        assert!(
            !a11y_pref(&["__host-mg_a11y=1"]),
            "cookie names are case-sensitive"
        );
        assert!(has_a11y_cookie(&["x=1;__Host-mg_a11y=0"]));
        assert!(!has_a11y_cookie(&["x=__Host-mg_a11y"]));
        assert!(
            a11y_set_cookie()
                .starts_with("__Host-mg_a11y=1; Max-Age=31536000; Path=/; Secure; HttpOnly")
        );
        assert!(a11y_delete_cookie().contains("Max-Age=0"));
    }

    /// D-67: the ip entity tier of `mg.ix.issue` decides, its ipp tier is
    /// only counted; both tiers of `mg.c.renew` decide.
    #[test]
    fn two_tier_limiters() {
        use mg_edge_core::state::{StateConfig, StateService};
        let (_svc, state) = StateService::new(StateConfig::local([7; 32]));
        let one = GcraParams::new(1, 3600, 1).unwrap();
        let many = GcraParams::new(1000, 1, 1000).unwrap();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let other: IpAddr = "198.51.100.8".parse().unwrap();
        let now = 1_000_000_000_000u64;
        let ids = ("t.a", "t.a.prefix");
        assert_eq!(
            two_tier(&state, "s", ids, ip, (one, many), false, now),
            Gate::Allowed
        );
        assert!(matches!(
            two_tier(&state, "s", ids, ip, (one, many), false, now),
            Gate::Limited { .. }
        ));
        // The prefix tier alone never refuses when it is only counted.
        let ids = ("t.b", "t.b.prefix");
        assert_eq!(
            two_tier(&state, "s", ids, ip, (many, one), false, now),
            Gate::Allowed
        );
        assert_eq!(
            two_tier(&state, "s", ids, other, (many, one), false, now),
            Gate::Allowed
        );
        let ids = ("t.c", "t.c.prefix");
        assert_eq!(
            two_tier(&state, "s", ids, ip, (many, one), true, now),
            Gate::Allowed
        );
        assert!(matches!(
            two_tier(&state, "s", ids, other, (many, one), true, now),
            Gate::Limited { .. }
        ));
    }
}
