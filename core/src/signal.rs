//! Detector output (docs/03 §3).

use crate::enums::{SignalFamily, SignalSource, SignalState};
use crate::values::{Confidence, Evidence};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// One piece of evidence produced by a [`crate::Detector`].
///
/// `value` and `confidence` are range-checked newtypes, so a `Signal` can never
/// carry an out-of-range number. Identifiers are usually `&'static str`
/// literals, hence `Cow`: building a signal on the hot path does not allocate.
///
/// `state` says whether the detector had its input (docs/03 §3.1): only
/// `Present` signals carry evidence; `Absent` and `Missing` signals are
/// recorded with value 0 for coverage accounting and drift analysis.
///
/// ```
/// use mg_core::{Signal, SignalFamily, SignalSource, SignalState};
/// let s = Signal::new("tls.ua_family_mismatch", SignalFamily::Tls, 1.7, 0.9)
///     .with_reason("ua_chrome_ja4_curl")
///     .with_source(SignalSource::SelfComputed);
/// assert_eq!(s.value.get(), 1.0); // clamped
/// assert_eq!(s.state, SignalState::Present);
/// assert!(s.is_scored());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// Stable dotted identifier, e.g. `tls.ua_family_mismatch`.
    pub id: Cow<'static, str>,
    /// Family used for per-family capping and availability accounting.
    pub family: SignalFamily,
    /// `[-1, 1]`; `> 0` automation evidence, `< 0` human evidence.
    pub value: Evidence,
    /// `[0, 1]`.
    pub confidence: Confidence,
    /// Stable internal reason code. Never shown to visitors.
    #[serde(default, skip_serializing_if = "str::is_empty")]
    pub reason_code: Cow<'static, str>,
    /// `Present`, `Absent` or `Missing`.
    #[serde(default)]
    pub state: SignalState,
    /// Where the detector's input came from (`self`, `cloudflare`, `sdk`, ...).
    #[serde(default, skip_serializing_if = "is_unspecified_source")]
    pub source: SignalSource,
    /// The family or detector runs in shadow: logged, never scored.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shadow: bool,
}

fn is_unspecified_source(s: &SignalSource) -> bool {
    *s == SignalSource::Unspecified
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Signal {
    /// Builds a `Present` signal, clamping `value` to `[-1, 1]` and
    /// `confidence` to `[0, 1]` (`NaN` becomes `0` for both).
    ///
    /// In debug builds, panics if `id` is not a valid signal id
    /// (see [`Signal::is_valid_id`]).
    pub fn new(
        id: impl Into<Cow<'static, str>>,
        family: SignalFamily,
        value: f32,
        confidence: f32,
    ) -> Self {
        let id = id.into();
        debug_assert!(Self::is_valid_id(&id), "invalid signal id {id:?}");
        Self {
            id,
            family,
            value: Evidence::new(value),
            confidence: Confidence::new(confidence),
            reason_code: Cow::Borrowed(""),
            state: SignalState::Present,
            source: SignalSource::Unspecified,
            shadow: false,
        }
    }

    /// A value-less signal recording that the detector's input is `state`
    /// (`Absent` or `Missing`). Value and confidence are 0.
    pub fn without_input(
        id: impl Into<Cow<'static, str>>,
        family: SignalFamily,
        state: SignalState,
    ) -> Self {
        debug_assert!(
            matches!(state, SignalState::Absent | SignalState::Missing),
            "without_input needs Absent or Missing, got {state}"
        );
        Self {
            state,
            ..Self::new(id, family, 0.0, 0.0)
        }
    }

    /// Sets the reason code.
    #[must_use]
    pub fn with_reason(mut self, reason_code: impl Into<Cow<'static, str>>) -> Self {
        self.reason_code = reason_code.into();
        self
    }

    /// Sets the input provenance.
    #[must_use]
    pub fn with_source(mut self, source: SignalSource) -> Self {
        self.source = source;
        self
    }

    /// Marks the signal as shadow (logged, not scored).
    #[must_use]
    pub fn in_shadow(mut self) -> Self {
        self.shadow = true;
        self
    }

    /// Whether the scorer may use this signal: `Present` and not shadow.
    pub fn is_scored(&self) -> bool {
        self.state == SignalState::Present && !self.shadow
    }

    /// `value × confidence`: the un-weighted contribution of this signal.
    /// Always 0 for signals that are not [`Signal::is_scored`].
    pub fn weighted_value(&self) -> f32 {
        if self.is_scored() {
            self.value.get() * self.confidence.get()
        } else {
            0.0
        }
    }

    /// Signal ids are 1–64 bytes of `[a-z0-9_.]`, containing at least one `.`
    /// and neither starting nor ending with one (`<area>.<name>`).
    pub fn is_valid_id(id: &str) -> bool {
        (1..=64).contains(&id.len())
            && id.contains('.')
            && !id.starts_with('.')
            && !id.ends_with('.')
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clamps_value_and_confidence() {
        let s = Signal::new("net.datacenter_asn", SignalFamily::Network, 2.0, -1.0);
        assert_eq!(s.value.get(), 1.0);
        assert_eq!(s.confidence.get(), 0.0);

        let s = Signal::new("client.trusted_input", SignalFamily::Client, -1.5, 7.0);
        assert_eq!(s.value.get(), -1.0);
        assert_eq!(s.confidence.get(), 1.0);

        let s = Signal::new("http.odd", SignalFamily::Http, f32::NAN, f32::NAN);
        assert_eq!((s.value.get(), s.confidence.get()), (0.0, 0.0));
    }

    #[test]
    fn weighted_value_multiplies() {
        let s = Signal::new("rate.burst", SignalFamily::Rate, 0.5, 0.5);
        assert!((s.weighted_value() - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn only_present_non_shadow_signals_are_scored() {
        let s = Signal::new("edge_tls.rare_cipher", SignalFamily::EdgeTls, 0.5, 1.0);
        assert!(s.is_scored());
        let shadow = s.clone().in_shadow();
        assert!(!shadow.is_scored());
        assert_eq!(shadow.weighted_value(), 0.0);

        let missing =
            Signal::without_input("tls.ja4_family", SignalFamily::Tls, SignalState::Missing);
        assert_eq!(missing.state, SignalState::Missing);
        assert_eq!((missing.value.get(), missing.confidence.get()), (0.0, 0.0));
        assert!(!missing.is_scored());
        let absent =
            Signal::without_input("client.sdk_ran", SignalFamily::Client, SignalState::Absent);
        assert!(absent.state.counts_toward_coverage() && !absent.is_scored());
    }

    #[test]
    fn serde_round_trip_and_shape() {
        let s = Signal::new("edge_tls.rare_cipher", SignalFamily::EdgeTls, 0.3, 0.5)
            .with_reason("cf_cipher_rare")
            .with_source(SignalSource::Cloudflare)
            .in_shadow();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            json,
            r#"{"id":"edge_tls.rare_cipher","family":"edge_tls","value":0.3,"confidence":0.5,"reason_code":"cf_cipher_rare","state":"present","source":"cloudflare","shadow":true}"#
        );
        assert_eq!(serde_json::from_str::<Signal>(&json).unwrap(), s);

        let plain = Signal::new("http.odd", SignalFamily::Http, 0.1, 0.1);
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"id":"http.odd","family":"http","value":0.1,"confidence":0.1,"state":"present"}"#,
            "unspecified source and shadow=false are omitted"
        );
    }

    #[test]
    fn deserialize_clamps_untrusted_input() {
        let s: Signal =
            serde_json::from_str(r#"{"id":"x.y","family":"http","value":9,"confidence":-3}"#)
                .unwrap();
        assert_eq!((s.value.get(), s.confidence.get()), (1.0, 0.0));
        assert!(s.reason_code.is_empty());
        // A line without a state is not evidence.
        assert_eq!(s.state, SignalState::Unspecified);
        assert!(!s.is_scored());
    }

    #[test]
    fn id_validation() {
        assert!(Signal::is_valid_id("tls.ua_family_mismatch"));
        assert!(Signal::is_valid_id("edge_tls.hello_len.bucket3"));
        assert!(!Signal::is_valid_id(""));
        assert!(!Signal::is_valid_id("nodot"));
        assert!(!Signal::is_valid_id(".leading"));
        assert!(!Signal::is_valid_id("trailing."));
        assert!(!Signal::is_valid_id("Upper.case"));
        assert!(!Signal::is_valid_id("has space.x"));
        assert!(!Signal::is_valid_id(&format!("a.{}", "b".repeat(64))));
    }
}
