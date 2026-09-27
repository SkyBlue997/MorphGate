//! Range-checked scalar newtypes.
//!
//! Constructors clamp instead of failing: a detector bug must never be able to
//! push a value outside the range the scorer assumes. `NaN` becomes the neutral
//! value. Deserialization goes through the same clamping constructors.

use serde::{Deserialize, Serialize};

/// Clamps `v` into `[lo, hi]`, mapping `NaN` to `neutral`.
fn clamp_f32(v: f32, lo: f32, hi: f32, neutral: f32) -> f32 {
    if v.is_nan() { neutral } else { v.clamp(lo, hi) }
}

/// Signal value in `[-1, 1]`: `> 0` is automation evidence, `< 0` human evidence.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
#[serde(from = "f32", into = "f32")]
pub struct Evidence(f32);

impl Evidence {
    /// Neither human nor automation evidence.
    pub const NEUTRAL: Self = Self(0.0);

    /// Clamps into `[-1, 1]`; `NaN` becomes `0`.
    pub fn new(v: f32) -> Self {
        Self(clamp_f32(v, -1.0, 1.0, 0.0))
    }

    /// The raw value.
    pub const fn get(self) -> f32 {
        self.0
    }
}

impl From<f32> for Evidence {
    fn from(v: f32) -> Self {
        Self::new(v)
    }
}

impl From<Evidence> for f32 {
    fn from(v: Evidence) -> Self {
        v.0
    }
}

/// Confidence or coverage in `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
#[serde(from = "f32", into = "f32")]
pub struct Confidence(f32);

impl Confidence {
    /// No confidence.
    pub const ZERO: Self = Self(0.0);
    /// Full confidence.
    pub const FULL: Self = Self(1.0);

    /// Clamps into `[0, 1]`; `NaN` becomes `0`.
    pub fn new(v: f32) -> Self {
        Self(clamp_f32(v, 0.0, 1.0, 0.0))
    }

    /// The raw value.
    pub const fn get(self) -> f32 {
        self.0
    }
}

impl From<f32> for Confidence {
    fn from(v: f32) -> Self {
        Self::new(v)
    }
}

impl From<Confidence> for f32 {
    fn from(v: Confidence) -> Self {
        v.0
    }
}

/// Risk score `0..=100`; higher means more likely automated or abusive.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(from = "u32", into = "u32")]
pub struct Score(u8);

impl Score {
    /// Lowest score.
    pub const MIN: Self = Self(0);
    /// Highest score.
    pub const MAX: Self = Self(100);

    /// Saturates at 100.
    pub const fn new(v: u32) -> Self {
        Self(if v > 100 { 100 } else { v as u8 })
    }

    /// The raw value.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The default treatment band of docs/03 §5.1.
    pub const fn band(self) -> RiskBand {
        match self.0 {
            0..=29 => RiskBand::Low,
            30..=59 => RiskBand::Medium,
            60..=84 => RiskBand::High,
            _ => RiskBand::VeryHigh,
        }
    }
}

impl From<u32> for Score {
    fn from(v: u32) -> Self {
        Self::new(v)
    }
}

impl From<Score> for u32 {
    fn from(v: Score) -> Self {
        u32::from(v.0)
    }
}

wire_enum! {
    /// Score band used by the default treatment matrix (docs/03 §5.1) and sealed
    /// into challenges as `risk_band` to pick PoW difficulty (docs/09).
    pub enum RiskBand {
        /// 0–29
        Low => "low",
        /// 30–59
        Medium => "medium",
        /// 60–84
        High => "high",
        /// 85–100
        VeryHigh => "very_high",
    }
}

impl RiskBand {
    /// Band sealed into the new challenge attached after a failed
    /// `/__mg/c` submission (spec §6.3, D-27): one band up, capped at
    /// `High`, and never below the failed challenge's band, so `VeryHigh`
    /// stays `VeryHigh` (the PoW difficulty never drops after a failure).
    pub const fn after_failure(self) -> Self {
        match self {
            Self::Low => Self::Medium,
            Self::Medium | Self::High => Self::High,
            Self::VeryHigh => Self::VeryHigh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.3 / D-27: escalation after a failed submission never lowers the band.
    #[test]
    fn risk_band_after_failure() {
        use RiskBand::*;
        for (band, next) in [
            (Low, Medium),
            (Medium, High),
            (High, High),
            (VeryHigh, VeryHigh),
        ] {
            assert_eq!(band.after_failure(), next, "{band:?}");
            assert!(band.after_failure() >= band);
        }
    }

    #[test]
    fn evidence_clamps_and_neutralises_nan() {
        assert_eq!(Evidence::new(3.0).get(), 1.0);
        assert_eq!(Evidence::new(-7.5).get(), -1.0);
        assert_eq!(Evidence::new(0.25).get(), 0.25);
        assert_eq!(Evidence::new(f32::NAN), Evidence::NEUTRAL);
        assert_eq!(Evidence::new(f32::INFINITY).get(), 1.0);
    }

    #[test]
    fn confidence_clamps_and_neutralises_nan() {
        assert_eq!(Confidence::new(1.5), Confidence::FULL);
        assert_eq!(Confidence::new(-0.1), Confidence::ZERO);
        assert_eq!(Confidence::new(f32::NAN), Confidence::ZERO);
        assert_eq!(Confidence::new(0.4).get(), 0.4);
    }

    #[test]
    fn deserialization_clamps_too() {
        let e: Evidence = serde_json::from_str("-4.0").unwrap();
        assert_eq!(e.get(), -1.0);
        let c: Confidence = serde_json::from_str("9").unwrap();
        assert_eq!(c, Confidence::FULL);
        let s: Score = serde_json::from_str("250").unwrap();
        assert_eq!(s, Score::MAX);
    }

    #[test]
    fn score_saturates_and_bands_match_docs() {
        assert_eq!(Score::new(1000).get(), 100);
        assert_eq!(Score::new(0).band(), RiskBand::Low);
        assert_eq!(Score::new(29).band(), RiskBand::Low);
        assert_eq!(Score::new(30).band(), RiskBand::Medium);
        assert_eq!(Score::new(59).band(), RiskBand::Medium);
        assert_eq!(Score::new(60).band(), RiskBand::High);
        assert_eq!(Score::new(84).band(), RiskBand::High);
        assert_eq!(Score::new(85).band(), RiskBand::VeryHigh);
        assert_eq!(Score::MAX.band(), RiskBand::VeryHigh);
    }

    #[test]
    fn serde_uses_plain_numbers_and_names() {
        assert_eq!(serde_json::to_string(&Score::new(42)).unwrap(), "42");
        assert_eq!(serde_json::to_string(&Evidence::new(0.5)).unwrap(), "0.5");
        assert_eq!(
            serde_json::to_string(&RiskBand::VeryHigh).unwrap(),
            "\"very_high\""
        );
    }
}
