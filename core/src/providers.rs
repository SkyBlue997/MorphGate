//! Built-in interactive providers and the pure functions around them
//! (docs/impl/phase2-spec.md §5, WP-R4):
//!
//! * [`SelfHold`] and [`PowA11y`], the built-in [`InteractiveChallengeProvider`]s.
//!   They need no network: [`InteractiveChallengeProvider::prepare`] returns an
//!   empty [`ChallengeSpec`] (the Edge assembles the plain parameters `ix`,
//!   §7.2) and `verify` passes; the sealed `C`, its nonce, the bindings, the
//!   PoW and [`assess_interaction`] carry the actual checks;
//! * [`select_providers`]: which providers an interactive `C` offers (§5.4);
//! * [`min_elapsed_ms`] and [`assess_interaction`]: the hard checks and the
//!   soft score of an interactive submission (§5.5, §7.7, §7.8);
//! * [`next_challenge_after_failure`]: the `C` attached to a failure (§5.3, D-50);
//! * [`refresh_check`]: whether `POST /__mg/r` may refresh a clearance (§5.7, D-47).
//!
//! Everything here is pure: time, telemetry and decisions arrive as data.

use crate::challenge::{
    A11yAlternative, BindingChecks, BoxFuture, ChallengeSpec, InteractionKind,
    InteractiveChallengeProvider, IssueCtx, NonceBinding, OutboundHttp, ProviderCaps,
    ProviderError, ProviderId, ProviderSubmission, ProviderVerdict, VerdictOutcome, VerifyCtx,
};
use crate::context::{BindResult, TokenBind, TokenLevel};
use crate::decision::{Decision, EvalMode, InteractionSummary};
use crate::enums::{Action, ChallengeType};
use crate::policy::{challenge_rank, level_rank};
use crate::sealed::SealedChallengeClaims;
use crate::telemetry::{A11yMode, InputModality, IxMode, IxTelemetry};
use crate::values::RiskBand;
use std::collections::BTreeMap;
use std::fmt;

// --- built-in providers -------------------------------------------------------

/// Largest accepted age of a built-in result: the interactive `C` lifetime.
const BUILTIN_MAX_AGE_S: u32 = (SealedChallengeClaims::MAX_INTERACTIVE_LIFETIME_MS / 1000) as u32;

fn builtin_caps(kind: InteractionKind, alternatives: Vec<A11yAlternative>) -> ProviderCaps {
    ProviderCaps {
        interaction_kind: kind,
        cognitive_test: false,
        drag_required: false,
        a11y_alternatives: alternatives,
        denied_regions: Vec::new(),
        // The result is tied to our nonce only by the sealed C around it.
        nonce_binding: NonceBinding::WrapperOnly,
        requires_outbound_verify: false,
        max_token_age_s: BUILTIN_MAX_AGE_S,
        third_party_origins: Vec::new(),
        unit_cost: None,
    }
}

/// `prepare` of a built-in provider: no parameters (spec §7.2: `ix` is
/// assembled by the Edge from `C`).
fn builtin_spec(provider: ProviderId) -> ChallengeSpec {
    ChallengeSpec {
        provider,
        params: BTreeMap::new(),
    }
}

/// `verify` of a built-in provider: no network; `Pass` with every binding
/// check set for a submission of this provider, `Fail` otherwise. The hard
/// checks and the score are [`assess_interaction`]'s.
fn builtin_verdict(provider: ProviderId, submission: &ProviderSubmission) -> ProviderVerdict {
    if submission.provider != provider {
        return ProviderVerdict::new(VerdictOutcome::Fail, "provider_mismatch");
    }
    ProviderVerdict {
        outcome: VerdictOutcome::Pass,
        binding: BindingChecks::ALL_OK,
        provider_ts_ms: None,
        provider_risk: None,
        features: BTreeMap::new(),
        reason_codes: Vec::new(),
        replay_key: None,
        latency_us: 0,
    }
}

/// The built-in press-and-hold provider `self_hold` (docs/09 §2; single
/// activation per D-65). Issues `interactive` clearances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHold {
    caps: ProviderCaps,
}

impl SelfHold {
    pub fn new() -> Self {
        Self {
            caps: builtin_caps(
                InteractionKind::PressAndHold,
                vec![A11yAlternative::SingleActivation, A11yAlternative::PowA11y],
            ),
        }
    }
}

impl Default for SelfHold {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveChallengeProvider for SelfHold {
    fn id(&self) -> ProviderId {
        ProviderId::SelfHold
    }

    fn capabilities(&self) -> &ProviderCaps {
        &self.caps
    }

    fn prepare(&self, _ctx: &IssueCtx<'_>) -> Result<ChallengeSpec, ProviderError> {
        Ok(builtin_spec(ProviderId::SelfHold))
    }

    fn verify<'a>(
        &'a self,
        _ctx: &'a VerifyCtx<'a>,
        submission: &'a ProviderSubmission,
        _http: &'a dyn OutboundHttp,
    ) -> BoxFuture<'a, ProviderVerdict> {
        Box::pin(std::future::ready(builtin_verdict(
            ProviderId::SelfHold,
            submission,
        )))
    }
}

/// The built-in accessible proof of work `pow_a11y` (docs/09 §3): no
/// interaction beyond choosing it. Issues `interactive_a11y` clearances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowA11y {
    caps: ProviderCaps,
}

impl PowA11y {
    pub fn new() -> Self {
        Self {
            caps: builtin_caps(InteractionKind::NonInteractive, Vec::new()),
        }
    }
}

impl Default for PowA11y {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveChallengeProvider for PowA11y {
    fn id(&self) -> ProviderId {
        ProviderId::PowA11y
    }

    fn capabilities(&self) -> &ProviderCaps {
        &self.caps
    }

    fn prepare(&self, _ctx: &IssueCtx<'_>) -> Result<ChallengeSpec, ProviderError> {
        Ok(builtin_spec(ProviderId::PowA11y))
    }

    fn verify<'a>(
        &'a self,
        _ctx: &'a VerifyCtx<'a>,
        submission: &'a ProviderSubmission,
        _http: &'a dyn OutboundHttp,
    ) -> BoxFuture<'a, ProviderVerdict> {
        Box::pin(std::future::ready(builtin_verdict(
            ProviderId::PowA11y,
            submission,
        )))
    }
}

// --- provider selection (§5.4) ------------------------------------------------

wire_enum! {
    /// When Turnstile is offered (`ProviderConfig.selection`).
    pub enum Selection {
        /// On every interactive `C`.
        First => "first",
        /// Only once `attempt_no > escalate_after`.
        EscalateAfterFail => "escalate_after_fail",
    }
}

/// The site's Turnstile configuration as it applies to one request (§5.4).
#[derive(Debug, Clone, Copy)]
pub struct TurnstileChoice<'a> {
    pub selection: Selection,
    /// Empty: every route.
    pub route_ids: &'a [String],
    /// Exact FQDNs of the widget; the request host must be one of them.
    pub hostnames: &'a [String],
    /// ISO 3166-1 alpha-2 countries that never get Turnstile (D-70: empty by default).
    pub denied_countries: &'a [String],
    /// Enabled, secret present, health `Healthy` or `Degraded` (§8.6).
    pub usable: bool,
}

/// Input of [`select_providers`] (§5.4).
#[derive(Debug, Clone, Copy)]
pub struct SelectionInput<'a> {
    /// GeoLite2 country of the client IP (`None`: unknown or no artifact).
    pub country_geo: Option<&'a str>,
    /// Authenticated `cf-ipcountry` (cloudflare profile, location headers on;
    /// `XX`, `T1` and malformed values are `None`, §8.1).
    pub country_cf: Option<&'a str>,
    pub route_id: &'a str,
    /// Any matched route has `redact_path`.
    pub redact_path: bool,
    /// Normalized request host (Phase 1 spec §9.4).
    pub host: &'a str,
    /// `attempt_no` of the `C` being issued, 1-based.
    pub attempt_no: u32,
    /// `N` of D-50 (`interactive.escalate_after`).
    pub escalate_after: u32,
    /// Cookie `__Host-mg_a11y=1` (§9.5).
    pub a11y_pref: bool,
    /// `None`: the site has no Turnstile provider.
    pub turnstile: Option<TurnstileChoice<'a>>,
}

/// Rule 2 of §5.4: whether Turnstile may be offered on this request at all
/// (configured and usable; route; no `redact_path`; host; countries). The
/// Edge re-runs it on renewals and submissions (§7.4, §7.5).
pub fn turnstile_eligible(input: &SelectionInput<'_>) -> bool {
    let Some(ts) = input.turnstile else {
        return false;
    };
    ts.usable
        && (ts.route_ids.is_empty() || ts.route_ids.iter().any(|r| r == input.route_id))
        && !input.redact_path
        && ts
            .hostnames
            .iter()
            .any(|h| h.eq_ignore_ascii_case(input.host))
        && country_allowed(ts.denied_countries, input.country_geo, input.country_cf)
}

/// §5.4 rule 2, countries (D-70): no restriction while `denied` is empty;
/// otherwise the country must be known and neither source may be denied (a
/// disagreement between the sources denies when either one matches).
fn country_allowed(denied: &[String], geo: Option<&str>, cf: Option<&str>) -> bool {
    if denied.is_empty() {
        return true;
    }
    let known: Vec<&str> = [geo, cf]
        .into_iter()
        .flatten()
        .filter(|c| !c.is_empty())
        .collect();
    !known.is_empty()
        && known
            .iter()
            .all(|c| !denied.iter().any(|d| d.eq_ignore_ascii_case(c)))
}

/// Moves `p` (if present) to index `at`.
fn move_to(list: &mut Vec<ProviderId>, p: ProviderId, at: usize) {
    if let Some(i) = list.iter().position(|x| *x == p) {
        list.remove(i);
        list.insert(at.min(list.len()), p);
    }
}

/// The providers an interactive `C` offers, first = default (§5.4). Always
/// contains `self_hold` and `pow_a11y` (accessibility), in this order unless:
///
/// 1. Turnstile is eligible ([`turnstile_eligible`]) and its selection is
///    `first`, or `escalate_after_fail` with `attempt_no > escalate_after`:
///    `turnstile` goes first;
/// 2. `attempt_no > escalate_after`: `pow_a11y` moves before `self_hold`
///    (after an inserted `turnstile`);
/// 3. `a11y_pref`: `pow_a11y` moves to the front.
pub fn select_providers(input: &SelectionInput<'_>) -> Vec<ProviderId> {
    let mut list = vec![ProviderId::SelfHold, ProviderId::PowA11y];
    let escalated = input.attempt_no > input.escalate_after;
    if let Some(ts) = input.turnstile
        && turnstile_eligible(input)
        && (ts.selection == Selection::First || escalated)
    {
        list.insert(0, ProviderId::Turnstile);
    }
    if escalated {
        let at = list
            .iter()
            .position(|p| *p == ProviderId::SelfHold)
            .unwrap_or(0);
        move_to(&mut list, ProviderId::PowA11y, at);
    }
    if input.a11y_pref {
        move_to(&mut list, ProviderId::PowA11y, 0);
    }
    list
}

// --- interaction assessment (§5.5, §7.7, §7.8) ----------------------------------

/// Expected hashes per millisecond of a desktop browser; `pow_too_fast`
/// compares `pow.ms` with `k * 2^bits / DESKTOP_HASHES_PER_MS` (§5.5).
pub const DESKTOP_HASHES_PER_MS: u64 = 4_000;

/// Margin of the server-side time window of `hold` / `single` (§7.7).
pub const MIN_ELAPSED_MARGIN_MS: u32 = 250;
/// Longest accepted `hold.ms` (§7.7).
pub const MAX_HOLD_MS: u32 = 30_000;

/// Hard-check reasons of §7.7 (the `ic.*` reason codes of §7.5).
pub mod reason {
    /// `ix` missing or its `mode` does not fit the provider.
    pub const IX_MODE: &str = "ic.ix_mode";
    /// `trusted = 0` in `hold` / `single`.
    pub const NO_TRUSTED_INPUT: &str = "ic.no_trusted_input";
    /// `hold.ms` (or `single.wait_ms`) below 95 % of the required hold.
    pub const HOLD_SHORT: &str = "ic.hold_short";
    /// `hold.ms` above 30 s.
    pub const HOLD_LONG: &str = "ic.hold_long";
    /// The server-side time window ([`super::min_elapsed_ms`], §7.5 step 6).
    pub const TOO_FAST: &str = "ic.too_fast";
    /// `enforce`: `t_pass <= score < t_block`.
    pub const SCORE_HIGH: &str = "ic.score_high";
    /// `enforce`: `score >= t_block` (429).
    pub const SCORE_BLOCK: &str = "ic.score_block";
}

/// The soft features of §7.8 (`InteractionSummary.features` keys) and their
/// initial weights. `prior` is the risk-band prior of [`band_prior`].
pub const FEATURE_WEIGHTS: &[(&str, f32)] = &[
    ("no_pre_move", 0.15),
    ("straight_long", 0.15),
    ("fast_target", 0.10),
    ("zero_jitter", 0.20),
    ("untrusted", 0.20),
    ("hidden", 0.10),
    ("pow_too_fast", 0.20),
    ("ts_fallback", 0.05),
    ("touch_natural", -0.10),
];

fn weight(key: &str) -> f32 {
    FEATURE_WEIGHTS
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0.0, |(_, w)| *w)
}

/// The `prior` feature of §7.8: low 0, medium 0.05, high 0.10, very_high 0.15.
pub const fn band_prior(band: RiskBand) -> f32 {
    match band {
        RiskBand::Low => 0.0,
        RiskBand::Medium => 0.05,
        RiskBand::High => 0.10,
        RiskBand::VeryHigh => 0.15,
    }
}

/// `interactive.scoring_mode` (D-49): `shadow` (Phase 2 default) or `enforce`
/// with the owner's thresholds (`0 < t_pass < t_block <= 1`, checked by the
/// bundle builder and the Edge).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScoringMode {
    Shadow,
    Enforce { t_pass: f32, t_block: f32 },
}

impl ScoringMode {
    /// The event form (`InteractionSummary.mode`).
    pub const fn eval_mode(self) -> EvalMode {
        match self {
            Self::Shadow => EvalMode::Shadow,
            Self::Enforce { .. } => EvalMode::Enforce,
        }
    }
}

wire_enum! {
    /// What an interactive submission earns after the assessment (§5.5).
    pub enum IxOutcome {
        Pass => "pass",
        /// A failure that counts (`ic.*` hard check or `ic.score_high`); a new
        /// `C` is attached.
        Retry => "retry",
        /// `enforce` only: 429 (`ic.score_block`).
        Block => "block",
    }
}

/// Input of [`assess_interaction`] (§5.5).
#[derive(Debug, Clone, Copy)]
pub struct InteractionInput<'a> {
    /// The submitted provider: `self_hold`, `pow_a11y` or `turnstile`.
    pub provider: ProviderId,
    /// The parsed `t.ix` (§7.6); `None` when the submission has none, which
    /// only `pow_a11y` may do (§7.7).
    pub telemetry: Option<&'a IxTelemetry>,
    /// §6.3, recomputed from `ui_seed`.
    pub required_hold_ms: u32,
    /// Server clock: body read complete − `C.iat`.
    pub elapsed_ms: u32,
    /// Difficulty of the submitted provider (`pow.difficulty` or `pow.a11y_difficulty`).
    pub pow_bits: u32,
    pub pow_k: u32,
    pub risk_band: RiskBand,
    pub mode: ScoringMode,
}

/// Result of [`assess_interaction`].
#[derive(Debug, Clone, PartialEq)]
pub struct InteractionAssessment {
    /// The first failed hard check of §7.7 ([`reason`]); never `ic.too_fast`,
    /// which the Edge checks earlier with [`min_elapsed_ms`].
    pub hard_failure: Option<&'static str>,
    /// `0..=1` (§7.8).
    pub score: f32,
    /// The features that fired, with their weights.
    pub features: BTreeMap<&'static str, f32>,
    pub a11y_mode: A11yMode,
    pub input_modality: InputModality,
    pub outcome: IxOutcome,
}

impl InteractionAssessment {
    /// The `ix` of the `kind=feedback` event (spec §3.3). `hold_ms` is the
    /// reported `hold.ms`, or `single.wait_ms` in `single` mode.
    pub fn summary(&self, input: &InteractionInput<'_>) -> InteractionSummary {
        let t = input.telemetry;
        let hold_ms = t
            .and_then(|t| t.hold.map(|h| h.ms).or_else(|| t.single.map(|s| s.wait_ms)))
            .unwrap_or(0);
        InteractionSummary {
            mode: input.mode.eval_mode(),
            score: self.score,
            a11y_mode: self.a11y_mode,
            input_modality: self.input_modality,
            hold_ms,
            required_hold_ms: input.required_hold_ms,
            elapsed_ms: input.elapsed_ms,
            features: self
                .features
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            act_ms: t.map_or(0, |t| t.act_ms),
        }
    }
}

/// The server-side minimum time of §7.7 (§7.5 step 6): `hold` and `single`:
/// `required_hold_ms + min_pow_ms + 250`; `pow_only` (also a submission
/// without `ix`): `a11y_min_ms`; `external`: 0 (the provider's widget sets
/// its own pace). Saturates.
pub fn min_elapsed_ms(
    mode: IxMode,
    required_hold_ms: u32,
    min_pow_ms: u32,
    a11y_min_ms: u32,
) -> u32 {
    match mode {
        IxMode::Hold | IxMode::Single => required_hold_ms
            .saturating_add(min_pow_ms)
            .saturating_add(MIN_ELAPSED_MARGIN_MS),
        IxMode::PowOnly => a11y_min_ms,
        IxMode::External => 0,
    }
}

/// `x >= 0.95 * required`, exactly.
fn at_least_95_percent(x: u32, required: u32) -> bool {
    u64::from(x) * 100 >= u64::from(required) * 95
}

/// The hard checks of §7.7 except the time window, in table order.
fn hard_check(input: &InteractionInput<'_>) -> Option<&'static str> {
    let mode_fits = |m: IxMode| match input.provider {
        ProviderId::SelfHold => matches!(m, IxMode::Hold | IxMode::Single),
        ProviderId::PowA11y => m == IxMode::PowOnly,
        ProviderId::Turnstile => m == IxMode::External,
        _ => false,
    };
    let Some(t) = input.telemetry else {
        // Only pow_a11y may come without ix.
        return (input.provider != ProviderId::PowA11y).then_some(reason::IX_MODE);
    };
    if !mode_fits(t.mode) {
        return Some(reason::IX_MODE);
    }
    if matches!(t.mode, IxMode::Hold | IxMode::Single) && t.trusted < 1 {
        return Some(reason::NO_TRUSTED_INPUT);
    }
    match t.mode {
        IxMode::Hold => match t.hold {
            None => Some(reason::HOLD_SHORT),
            Some(h) if !at_least_95_percent(h.ms, input.required_hold_ms) => {
                Some(reason::HOLD_SHORT)
            }
            Some(h) if h.ms > MAX_HOLD_MS => Some(reason::HOLD_LONG),
            Some(_) => None,
        },
        IxMode::Single => match t.single {
            Some(s) if at_least_95_percent(s.wait_ms, input.required_hold_ms) => None,
            _ => Some(reason::HOLD_SHORT),
        },
        IxMode::PowOnly | IxMode::External => None,
    }
}

/// `pow.ms` (a `logBucket`: the value is below `2^bucket`) is more than ten
/// times below the expected `k * 2^bits / DESKTOP_HASHES_PER_MS`, for every
/// value the bucket stands for. The top bucket is open-ended: never fires.
fn pow_too_fast(ms_bucket: u8, bits: u32, k: u32) -> bool {
    if ms_bucket >= IxTelemetry::MAX_BUCKET {
        return false;
    }
    let upper_ms = 1u128 << ms_bucket;
    let expected_hashes = u128::from(k) << bits.min(64);
    upper_ms * 10 * u128::from(DESKTOP_HASHES_PER_MS) <= expected_hashes
}

/// The soft features of §7.8 that fire for `t`. `single` and `pow_only` never
/// get pointer features: missing pointer data is neutral (docs/09 §11).
fn features(input: &InteractionInput<'_>) -> BTreeMap<&'static str, f32> {
    let mut out = BTreeMap::new();
    let mut fire = |key: &'static str, on: bool| {
        if on {
            out.insert(key, weight(key));
        }
    };
    if let Some(t) = input.telemetry {
        let hold = t.mode == IxMode::Hold;
        let mouse = t.modality == InputModality::Mouse;
        let mouse_pen = matches!(t.modality, InputModality::Mouse | InputModality::Pen);
        let touch = t.modality == InputModality::Touch;
        if hold && mouse_pen {
            if let Some(pre) = t.pre {
                fire("no_pre_move", pre.moves == 0);
                fire("fast_target", pre.to_target_ms <= 7);
                // >= 0.9 straight over >= 512 px.
                fire(
                    "straight_long",
                    mouse && pre.straight >= 9 && pre.path_px >= 10,
                );
            }
            if let Some(h) = t.hold {
                fire(
                    "zero_jitter",
                    h.ms >= 1_000 && h.jitter_px == 0 && h.moves == 0,
                );
            }
        }
        if hold && touch {
            fire(
                "touch_natural",
                t.hold.is_some_and(|h| h.pressure_var || h.contact_var),
            );
        }
        if matches!(t.mode, IxMode::Hold | IxMode::Single) {
            fire("untrusted", t.trusted < IxTelemetry::MAX_TRUSTED);
        }
        fire("hidden", t.page.is_some_and(|p| p.vis_during > 0));
        fire(
            "pow_too_fast",
            t.pow
                .is_some_and(|p| pow_too_fast(p.ms, input.pow_bits, input.pow_k)),
        );
        fire("ts_fallback", t.fallback.is_some());
    }
    let prior = band_prior(input.risk_band);
    if prior != 0.0 {
        out.insert("prior", prior);
    }
    out
}

/// Assesses an interactive submission (§5.5): the hard checks of §7.7
/// (except `ic.too_fast`, see [`min_elapsed_ms`]) and the soft score of §7.8.
///
/// `Shadow`: the outcome follows the hard checks only (`Pass` or `Retry`);
/// the score and the features are only recorded. `Enforce`: a passing
/// submission with `score < t_pass` passes, `t_pass <= score < t_block` is
/// `Retry` (`ic.score_high`) and anything else `Block` (`ic.score_block`).
pub fn assess_interaction(input: &InteractionInput<'_>) -> InteractionAssessment {
    let hard_failure = hard_check(input);
    let features = features(input);
    let score = features.values().sum::<f32>().clamp(0.0, 1.0);
    let (a11y_mode, input_modality) = match input.telemetry {
        Some(t) => (
            match t.mode {
                IxMode::Single => A11yMode::Single,
                IxMode::PowOnly => A11yMode::PowOnly,
                IxMode::Hold | IxMode::External => A11yMode::None,
            },
            t.modality,
        ),
        None if input.provider == ProviderId::PowA11y => (A11yMode::PowOnly, InputModality::None),
        None => (A11yMode::None, InputModality::None),
    };
    let outcome = match (hard_failure, input.mode) {
        (Some(_), _) => IxOutcome::Retry,
        (None, ScoringMode::Shadow) => IxOutcome::Pass,
        (None, ScoringMode::Enforce { t_pass, t_block }) => {
            if score < t_pass {
                IxOutcome::Pass
            } else if score < t_block {
                IxOutcome::Retry
            } else {
                IxOutcome::Block
            }
        }
    };
    InteractionAssessment {
        hard_failure,
        score,
        features,
        a11y_mode,
        input_modality,
        outcome,
    }
}

// --- failure escalation (§5.3, D-50) ---------------------------------------------

/// `(type, band, attempt_no)` of the `C` attached to a failure response
/// (§5.3, D-50):
///
/// | previous `C` | interactive available | result |
/// |---|---|---|
/// | `invisible` / `pow` | yes | `(interactive, after_failure(band), 1)` |
/// | `invisible` / `pow` | no | `(pow, after_failure(band), 0)` (D-27) |
/// | `interactive` | yes | `(interactive, after_failure(band), prev_attempt + 1)` |
/// | `interactive` | no | `(pow, after_failure(band), 0)` (§5.1) |
///
/// Other types are never sealed and are treated like `pow`. The number of
/// attempts is capped by the failure quotas `mg.c.fail` /
/// `mg.c.fail.prefix`, not here.
pub fn next_challenge_after_failure(
    prev: ChallengeType,
    prev_band: RiskBand,
    prev_attempt: u32,
    interactive_available: bool,
) -> (ChallengeType, RiskBand, u32) {
    let band = prev_band.after_failure();
    match (prev, interactive_available) {
        (_, false) => (ChallengeType::Pow, band, 0),
        (ChallengeType::Interactive, true) => (
            ChallengeType::Interactive,
            band,
            prev_attempt.saturating_add(1).max(1),
        ),
        (_, true) => (ChallengeType::Interactive, band, 1),
    }
}

// --- clearance refresh (§5.7, D-47) ------------------------------------------------

/// The per-level refresh caps of `ClearanceConfig` (§3.2): `now - lat` at
/// most this many seconds; 0 means the level never refreshes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefreshLimits {
    /// `refresh_max_interactive_s`.
    pub interactive_s: u64,
    /// `refresh_max_ext_s` (`interactive_ext:*`).
    pub interactive_ext_s: u64,
    /// `refresh_max_pow_s` (0: pow tokens never refresh).
    pub pow_s: u64,
}

impl RefreshLimits {
    /// `refresh_max_s` of [`RefreshInput`] for `level`: `interactive_a11y`
    /// and `invisible` never refresh (D-47).
    pub const fn max_for(&self, level: TokenLevel) -> u64 {
        match level {
            TokenLevel::Interactive => self.interactive_s,
            TokenLevel::InteractiveExt(_) => self.interactive_ext_s,
            TokenLevel::Pow => self.pow_s,
            TokenLevel::InteractiveA11y | TokenLevel::Invisible => 0,
        }
    }
}

/// Input of [`refresh_check`] (§5.7).
#[derive(Debug, Clone, Copy)]
pub struct RefreshInput<'a> {
    pub level: TokenLevel,
    /// The clearance carries `ruc` (I-30).
    pub ruc: bool,
    /// `cnf.jkt` present and the request's `MG-Proof` matched it.
    pub bound: bool,
    /// The clearance's binding results (Phase 1 spec §6.4): `uah` and `ipp`
    /// must both be `match`.
    pub bind: TokenBind,
    /// `now - lat`.
    pub level_age_s: u64,
    /// [`RefreshLimits::max_for`] the level; 0 = this level never refreshes.
    pub refresh_max_s: u64,
    /// The Decision Core outcome for `select_route(env, GET, "/")` (§9.3).
    pub decision: &'a Decision,
}

/// Why [`refresh_check`] refused (`mg_token_refresh_total{result}`, §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshDenied {
    /// `refresh_max_s = 0`.
    NotRefreshable,
    Ruc,
    NotBound,
    /// `uah` not `match`, or `ipp` not `match` (a soft mismatch included).
    Binding,
    TooOld,
    /// The decision demands a challenge above the clearance's level.
    ChallengeRequired(ChallengeType),
    /// The decision is BLOCK or RATE_LIMIT.
    Blocked,
}

impl RefreshDenied {
    /// The `result` label of `mg_token_refresh_total` (§9.3).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRefreshable => "not_refreshable",
            Self::Ruc => "ruc",
            Self::NotBound => "not_bound",
            Self::Binding => "binding",
            Self::TooOld => "too_old",
            Self::ChallengeRequired(_) => "challenge",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for RefreshDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a clearance may be refreshed (§5.7, D-47). The first rule that
/// holds refuses:
///
/// 1. `refresh_max_s = 0` → `NotRefreshable`;
/// 2. `ruc` → `Ruc`;
/// 3. not bound → `NotBound`;
/// 4. `uah` or `ipp` not `match` (soft mismatch included, else every refresh
///    would rebind the clearance to a new prefix) → `Binding`;
/// 5. `level_age_s > refresh_max_s` → `TooOld`;
/// 6. the decision is BLOCK or RATE_LIMIT → `Blocked`;
/// 7. the decision is a CHALLENGE ranked above the level (D-20) →
///    `ChallengeRequired(type)`.
pub fn refresh_check(input: &RefreshInput<'_>) -> Result<(), RefreshDenied> {
    let is_match = |b: Option<BindResult>| b == Some(BindResult::Match);
    if input.refresh_max_s == 0 {
        return Err(RefreshDenied::NotRefreshable);
    }
    if input.ruc {
        return Err(RefreshDenied::Ruc);
    }
    if !input.bound {
        return Err(RefreshDenied::NotBound);
    }
    if !is_match(input.bind.uah) || !is_match(input.bind.ipp) {
        return Err(RefreshDenied::Binding);
    }
    if input.level_age_s > input.refresh_max_s {
        return Err(RefreshDenied::TooOld);
    }
    let d = input.decision;
    match d.action {
        Action::Block | Action::RateLimit => Err(RefreshDenied::Blocked),
        Action::Challenge if challenge_rank(d.challenge_type) > level_rank(input.level) => {
            Err(RefreshDenied::ChallengeRequired(d.challenge_type))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
