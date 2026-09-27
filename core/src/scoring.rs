//! Scorer v1: the family-capped log-odds model of docs/03 §4.1 with the
//! Phase 1 parameters of docs/impl/phase1-spec.md §5.7.
//!
//! ```text
//! c_s      = λ_src(s) · w_s · confidence_s · value_s          (PRESENT signals only)
//! C_f      = clip( Σ_{s∈f} c_s , L_f , U_f )
//! z        = z0(route) + Σ_{f active} max(C_f, 0) + max( Σ_{f active} min(C_f, 0) , h_min )
//!                      + Σ_e β_e · min(4, max(0, logit(R_e / 100)))
//! score    = round(100 · sigmoid(z)), then the hard floors (crawler failed 90, scanner 85)
//! shadow   = the same with shadow families counted as active
//! ```

use crate::classify::{LABEL_SCANNER, derive_with_ua};
use crate::context::RequestContext;
use crate::decision::RiskAssessment;
use crate::detectors::default_weight;
use crate::enums::{
    EntityType, RouteSensitivity, SignalFamily, SignalSource, SignalState, UpstreamProfileKind,
};
use crate::extras::RequestExtras;
use crate::pipeline::Scorer;
use crate::signal::Signal;
use crate::values::{Confidence, Score};
use std::collections::BTreeMap;

/// How a signal family takes part in scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FamilyMode {
    /// Scored.
    Active,
    /// Only counted in `shadow_score`; signals are marked `shadow`.
    Shadow,
    /// Ignored entirely.
    Off,
}

/// Scorer parameters (`SiteBundle.scoring`, §8.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ScoringConfig {
    /// Confidence threshold of the matrix and of `HUMAN_LIKELY` (0.4).
    pub theta_c: f32,
    /// Coverage ceiling κ; `None` = profile default (`direct_tls` 1.0, otherwise 0.9).
    pub kappa: Option<f32>,
    /// Route prior `z0` by sensitivity, Low..Critical.
    pub z0: [f32; 4],
    /// Family modes; a family not listed keeps its default (EDGE_TLS shadow,
    /// every other family active), so an incomplete map can never switch the
    /// shadow family on by omission.
    pub family_modes: BTreeMap<SignalFamily, FamilyMode>,
    /// Signal id -> weight `w_s` override.
    pub weights: BTreeMap<String, f32>,
    /// Floor of the summed negative (human) family contributions (-4.0).
    pub h_min: f32,
    /// `RiskAssessment.ruleset_version` (`"v1"` when empty).
    pub ruleset_version: String,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            theta_c: 0.4,
            kappa: None,
            z0: [-2.197, -1.735, -1.386, -1.099],
            family_modes: BTreeMap::from([(SignalFamily::EdgeTls, FamilyMode::Shadow)]),
            weights: BTreeMap::new(),
            h_min: -4.0,
            ruleset_version: "v1".to_string(),
        }
    }
}

impl ScoringConfig {
    /// The mode of `family` (see [`ScoringConfig::family_modes`]).
    pub fn family_mode(&self, family: SignalFamily) -> FamilyMode {
        self.family_modes
            .get(&family)
            .copied()
            .unwrap_or(match family {
                SignalFamily::EdgeTls => FamilyMode::Shadow,
                _ => FamilyMode::Active,
            })
    }
}

/// Family clip interval `[L_f, U_f]` (docs/03 §4.1).
pub(crate) fn family_bounds(f: SignalFamily) -> (f64, f64) {
    match f {
        SignalFamily::Network => (-1.5, 1.5),
        SignalFamily::Tls => (-2.5, 2.5),
        SignalFamily::EdgeTls => (-1.0, 1.0),
        SignalFamily::Http | SignalFamily::Rate => (-2.0, 2.0),
        SignalFamily::Identity => (-1.5, 2.0),
        SignalFamily::External => (0.0, 1.0),
        SignalFamily::Client | SignalFamily::Behavior | SignalFamily::Reputation => (-3.0, 3.0),
        SignalFamily::Unspecified => (0.0, 0.0),
    }
}

/// Coverage weight `A_f`; families without one (EDGE_TLS, EXTERNAL and the
/// families without Phase 1 detectors) do not enter the confidence.
fn coverage_weight(f: SignalFamily) -> f64 {
    match f {
        SignalFamily::Network | SignalFamily::Http => 1.0,
        SignalFamily::Tls | SignalFamily::Identity => 1.5,
        SignalFamily::Rate => 0.5,
        _ => 0.0,
    }
}

/// Source coefficient λ: inputs the Edge computed itself 1.0, forwarded ones 0.8.
fn lambda(source: SignalSource) -> f64 {
    match source {
        SignalSource::Unspecified | SignalSource::SelfComputed | SignalSource::Sdk => 1.0,
        _ => 0.8,
    }
}

/// Verdict weight β_e (spec §5.7; types without Phase 1 verdicts per docs/03 §4.1).
fn verdict_beta(t: EntityType) -> f64 {
    match t {
        EntityType::Session => 0.6,
        EntityType::Device | EntityType::Account => 0.5,
        EntityType::FpCluster => 0.4,
        EntityType::Ip => 0.3,
        EntityType::Prefix | EntityType::Asn => 0.2,
        EntityType::Agent | EntityType::Unspecified => 0.0,
    }
}

const FAMILIES: usize = 11;

fn sigmoid_score(z: f64) -> u32 {
    let p = 1.0 / (1.0 + (-z).exp());
    let s = (100.0 * p).round();
    if s.is_nan() {
        0
    } else {
        s.clamp(0.0, 100.0) as u32
    }
}

/// The v1 scorer.
#[derive(Debug, Clone)]
pub struct ScorerV1 {
    cfg: ScoringConfig,
    modes: [FamilyMode; FAMILIES],
}

impl ScorerV1 {
    /// A scorer with `cfg`; non-finite numbers in it fall back to the defaults.
    pub fn new(mut cfg: ScoringConfig) -> Self {
        let d = ScoringConfig::default();
        if !cfg.theta_c.is_finite() {
            cfg.theta_c = d.theta_c;
        }
        for (z, dz) in cfg.z0.iter_mut().zip(d.z0) {
            if !z.is_finite() {
                *z = dz;
            }
        }
        if !cfg.h_min.is_finite() || cfg.h_min > 0.0 {
            cfg.h_min = d.h_min;
        }
        cfg.kappa = cfg
            .kappa
            .filter(|k| k.is_finite() && *k > 0.0)
            .map(|k| k.min(1.0));
        cfg.weights.retain(|_, w| w.is_finite());
        if cfg.ruleset_version.is_empty() {
            cfg.ruleset_version = d.ruleset_version;
        }
        let mut modes = [FamilyMode::Active; FAMILIES];
        for (i, m) in modes.iter_mut().enumerate() {
            if let Some(f) = SignalFamily::from_proto(i as i32) {
                *m = cfg.family_mode(f);
            }
        }
        Self { cfg, modes }
    }

    /// The configuration in effect.
    pub fn config(&self) -> &ScoringConfig {
        &self.cfg
    }

    fn mode(&self, f: SignalFamily) -> FamilyMode {
        self.modes
            .get(f.to_proto() as usize)
            .copied()
            .unwrap_or(FamilyMode::Off)
    }

    fn weight(&self, id: &str) -> f64 {
        f64::from(
            self.cfg
                .weights
                .get(id)
                .copied()
                .unwrap_or_else(|| default_weight(id)),
        )
    }

    fn z0(&self, s: RouteSensitivity) -> f64 {
        let i = match s {
            RouteSensitivity::Unspecified | RouteSensitivity::Low => 0,
            RouteSensitivity::Medium => 1,
            RouteSensitivity::High => 2,
            RouteSensitivity::Critical => 3,
        };
        f64::from(self.cfg.z0[i])
    }

    fn kappa(&self, profile: UpstreamProfileKind) -> f64 {
        f64::from(self.cfg.kappa.unwrap_or(match profile {
            UpstreamProfileKind::DirectTls => 1.0,
            _ => 0.9,
        }))
    }

    /// `Σ_e β_e · min(4, max(0, logit(R_e/100)))` over the highest-risk active
    /// verdict of each entity type that applies to the site. Never negative:
    /// a verdict can only raise risk (D-10).
    fn verdict_term(&self, ctx: &RequestContext) -> (f64, Vec<(String, f64)>) {
        let mut worst: BTreeMap<EntityType, u8> = BTreeMap::new();
        for v in ctx
            .active_verdicts()
            .filter(|v| v.applies_to_site(&ctx.site_id))
        {
            let r = worst.entry(v.entity_type).or_insert(0);
            *r = (*r).max(v.risk.get());
        }
        let mut total = 0.0;
        let mut reasons = Vec::new();
        for (t, r) in worst {
            let x = if r >= 100 {
                4.0
            } else if r == 0 {
                0.0
            } else {
                let p = f64::from(r) / 100.0;
                (p / (1.0 - p)).ln().clamp(0.0, 4.0)
            };
            let c = verdict_beta(t) * x;
            if c > 0.0 {
                total += c;
                reasons.push((format!("verdict.{t}"), c));
            }
        }
        (total, reasons)
    }

    /// `z0 + Σ positive C_f + max(Σ negative C_f, h_min)` over `sums`.
    fn combine(
        &self,
        z0: f64,
        sums: &[f64; FAMILIES],
        include: impl Fn(SignalFamily) -> bool,
    ) -> f64 {
        let (mut pos, mut neg) = (0.0, 0.0);
        for f in SignalFamily::ALL.iter().copied().filter(|&f| include(f)) {
            let (lo, hi) = family_bounds(f);
            let c = sums[f.to_proto() as usize].clamp(lo, hi);
            if c > 0.0 {
                pos += c;
            } else {
                neg += c;
            }
        }
        z0 + pos + neg.max(f64::from(self.cfg.h_min))
    }

    /// `κ · Σ A_f cov_f / Σ A_f` over the families with at least one
    /// non-MISSING signal (active families only; EXTERNAL never counts).
    fn confidence(&self, ctx: &RequestContext, signals: &[Signal]) -> f32 {
        let mut counted = [0u32; FAMILIES];
        let mut present = [0u32; FAMILIES];
        for s in signals {
            if s.shadow || self.mode(s.family) != FamilyMode::Active {
                continue;
            }
            let i = s.family.to_proto() as usize;
            match s.state {
                SignalState::Present => {
                    counted[i] += 1;
                    present[i] += 1;
                }
                SignalState::Absent => counted[i] += 1,
                _ => {}
            }
        }
        let (mut num, mut den) = (0.0, 0.0);
        for f in SignalFamily::ALL.iter().copied() {
            let i = f.to_proto() as usize;
            let a = coverage_weight(f);
            if counted[i] == 0 || a == 0.0 {
                continue;
            }
            num += a * f64::from(present[i]) / f64::from(counted[i]);
            den += a;
        }
        if den == 0.0 {
            return 0.0;
        }
        (self.kappa(ctx.upstream.profile) * num / den) as f32
    }
}

impl Scorer for ScorerV1 {
    /// Marks every signal of a shadow or off family as `shadow`, so the event
    /// shows it was not scored.
    fn annotate(&self, signals: &mut [Signal]) {
        for s in signals {
            if self.mode(s.family) != FamilyMode::Active {
                s.shadow = true;
            }
        }
    }

    fn score(
        &self,
        ctx: &RequestContext,
        extras: &RequestExtras<'_>,
        signals: &[Signal],
    ) -> RiskAssessment {
        let mut active = [0.0f64; FAMILIES];
        let mut all = [0.0f64; FAMILIES];
        let mut contributions: Vec<(String, f64)> = Vec::new();
        for s in signals.iter().filter(|s| s.state == SignalState::Present) {
            let mode = self.mode(s.family);
            if mode == FamilyMode::Off {
                continue;
            }
            let c = lambda(s.source)
                * self.weight(&s.id)
                * f64::from(s.confidence.get())
                * f64::from(s.value.get());
            let i = s.family.to_proto() as usize;
            all[i] += c;
            if mode == FamilyMode::Active && !s.shadow {
                active[i] += c;
                if c != 0.0 {
                    let reason = if s.reason_code.is_empty() {
                        &s.id
                    } else {
                        &s.reason_code
                    };
                    contributions.push((reason.to_string(), c));
                }
            }
        }

        let z0 = self.z0(extras.route.sensitivity);
        let (verdicts, verdict_reasons) = self.verdict_term(ctx);
        contributions.extend(verdict_reasons);
        let z = self.combine(z0, &active, |f| self.mode(f) == FamilyMode::Active) + verdicts;
        let z_shadow = self.combine(z0, &all, |f| self.mode(f) != FamilyMode::Off) + verdicts;

        let confidence = Confidence::new(self.confidence(ctx, signals));
        let floors = |mut s: u32, labels: &[String]| {
            if ctx.identity.crawler.is_failed() {
                s = s.max(90);
            }
            if labels.iter().any(|l| l == LABEL_SCANNER) {
                s = s.max(85);
            }
            Score::new(s)
        };
        // The class and labels depend on the score, the floors on the labels:
        // verdict labels (the only source of `scanner`) do not depend on it.
        let verdict_labels = crate::classify::verdict_labels(ctx);
        let score = floors(sigmoid_score(z), &verdict_labels);
        let shadow_score = floors(sigmoid_score(z_shadow), &verdict_labels);
        let (bot_class, labels) =
            derive_with_ua(ctx, signals, extras.ua, score, confidence, self.cfg.theta_c);

        RiskAssessment {
            score,
            confidence,
            bot_class,
            labels,
            top_reasons: top_reasons(contributions),
            model_version: "v1".to_string(),
            ruleset_version: self.cfg.ruleset_version.clone(),
            shadow_score,
        }
    }
}

/// The 5 reason codes with the largest `|contribution|`: automation evidence
/// (positive) first, then human evidence; ties by reason code.
fn top_reasons(mut contributions: Vec<(String, f64)>) -> Vec<String> {
    contributions.sort_by(|(ra, a), (rb, b)| {
        (*b > 0.0)
            .cmp(&(*a > 0.0))
            .then(b.abs().total_cmp(&a.abs()))
            .then_with(|| ra.cmp(rb))
    });
    let mut out: Vec<String> = Vec::with_capacity(5);
    for (r, _) in contributions {
        if out.len() == 5 {
            break;
        }
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

#[cfg(test)]
mod tests;
