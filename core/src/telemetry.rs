//! Interaction telemetry `t.ix` v1 of an interactive submission
//! (docs/impl/phase2-spec.md §7.6), in its quantized native form.
//!
//! The SDK quantizes every value before sending it; edge-core holds the one
//! parser and re-serializer (spec §15.2, D-62) and produces an
//! [`IxTelemetry`]. This module only defines the types, their bounds and a
//! range check: there is no JSON here. Nothing in it is a raw coordinate,
//! trajectory, key value or cross-site identifier (docs/09 §10).
//!
//! Quantization (spec §7.6):
//!
//! * counts, pixel distances, speeds and most durations are `logBucket`
//!   values `0..=31` (`sdk/web/src/behavior.ts`), stored as [`Bucket`];
//! * `straight`, `offset` and `pressure` use 0.1 steps, stored as tenths
//!   ([`Tenths`], [`SignedTenths`]);
//! * `hold.ms` and `single.wait_ms` have 10 ms resolution and a 60 000 ms
//!   cap; `act_ms` has 100 ms resolution and a 600 000 ms cap.
//!
//! The decoder in edge-core rejects or drops values outside these bounds;
//! [`IxTelemetry::check`] states them once for both sides.

use std::fmt;

/// A `logBucket` value, `0..=MAX_BUCKET`.
pub type Bucket = u8;
/// A value in 0.1 steps, stored as tenths (`7` is `0.7`).
pub type Tenths = u8;
/// A signed value in 0.1 steps, stored as tenths (`-2` is `-0.2`).
pub type SignedTenths = i8;

wire_enum! {
    /// How the visitor completed the control (`t.ix.mode`, spec §7.6, D-65).
    pub enum IxMode {
        /// Pointer press-and-hold.
        Hold => "hold",
        /// Single activation: keyboard, a screen-reader click, a short press or
        /// "can't hold?".
        Single => "single",
        /// `pow_a11y`: no interaction beyond choosing it.
        PowOnly => "pow_only",
        /// An external provider widget (Turnstile).
        External => "external",
    }
}

wire_enum! {
    /// Input type (`t.ix.modality`); in `single` mode, the last input's type.
    #[derive(Default)]
    pub enum InputModality {
        Mouse => "mouse",
        Touch => "touch",
        Pen => "pen",
        Keyboard => "keyboard",
        Mixed => "mixed",
        #[default]
        None => "none",
    }
}

wire_enum! {
    /// Accessibility path of an interactive submission (spec §5.5, D-65).
    #[derive(Default)]
    pub enum A11yMode {
        #[default]
        None => "none",
        Single => "single",
        PowOnly => "pow_only",
    }
}

wire_enum! {
    /// Language of the challenge page (`t.ix.locale`, spec §12.7).
    pub enum IxLocale {
        ZhCn => "zh-CN",
        En => "en",
    }
}

wire_enum! {
    /// Where the SDK keeps its session key (`t.ix.ks`, spec §12.4, D-45).
    pub enum KeyStore {
        Idb => "idb",
        Local => "local",
        Memory => "memory",
        /// WebCrypto is unavailable.
        None => "none",
    }
}

wire_enum! {
    /// Why the SDK fell back from Turnstile (`t.ix.fallback`, spec §8.3).
    pub enum IxFallback {
        TsUnsupported => "ts_unsupported",
        TsLoadTimeout => "ts_load_timeout",
        TsError => "ts_error",
        TsConfig => "ts_config",
    }
}

wire_enum! {
    /// PoW implementation used by the SDK (`t.ix.pow.impl`).
    pub enum PowImpl {
        Js => "js",
        Wasm => "wasm",
    }
}

/// Pointer movement before the press (`t.ix.pre`; pointer modes only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IxPre {
    pub moves: Bucket,
    pub path_px: Bucket,
    /// Straightness of the path, `0..=10` tenths.
    pub straight: Tenths,
    /// px/s.
    pub speed_mean: Bucket,
    /// px/s.
    pub speed_sd: Bucket,
    pub dir_changes: Bucket,
    pub render_to_input_ms: Bucket,
    pub to_target_ms: Bucket,
}

/// The hold itself (`t.ix.hold`; pointer modes only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IxHold {
    /// Reported hold duration, 10 ms resolution, `0..=MAX_HOLD_MS`.
    pub ms: u32,
    /// Press position relative to the control, `-10..=10` tenths per axis.
    pub offset: [SignedTenths; 2],
    pub jitter_px: Bucket,
    pub moves: Bucket,
    /// Holds aborted by `pointercancel` on this C, `0..=MAX_SMALL_COUNT`.
    pub cancels: u8,
    /// `0..=10` tenths.
    pub pressure: Tenths,
    /// The pressure varied during the hold.
    pub pressure_var: bool,
    /// The contact area varied during the hold.
    pub contact_var: bool,
}

/// Single activation (`t.ix.single`; `single` mode only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IxSingle {
    /// Activation to completion, 10 ms resolution, `0..=MAX_HOLD_MS`.
    pub wait_ms: u32,
}

/// Page state (`t.ix.page`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IxPage {
    /// Times the page was hidden while it was open.
    pub vis: Bucket,
    /// Times the page was hidden while the control was `HOLDING`, `WAITING`
    /// or `POW`, `0..=MAX_SMALL_COUNT`.
    pub vis_during: u8,
    pub focus: Bucket,
    /// ms.
    pub frame_mean: Bucket,
    /// ms.
    pub frame_sd: Bucket,
}

/// The PoW run (`t.ix.pow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IxPow {
    pub ms: Bucket,
    pub worker: bool,
    pub pow_impl: PowImpl,
}

/// `t.ix` v1 (spec §7.6), quantized. `pre` and `hold` appear only in
/// pointer modes and `single` only in `single` mode; the decoder drops
/// unknown fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IxTelemetry {
    /// Schema version; [`IxTelemetry::VERSION`].
    pub v: u8,
    pub mode: IxMode,
    pub modality: InputModality,
    pub locale: IxLocale,
    pub ks: KeyStore,
    /// `SDK_VERSION`: 1 to 16 characters of `[0-9A-Za-z.+-]`.
    pub sv: String,
    pub fallback: Option<IxFallback>,
    /// Share of `isTrusted` input events: 0 none, 1 below half, 2 below all, 3 all.
    pub trusted: u8,
    /// First activation to submission, 100 ms resolution, `0..=MAX_ACT_MS`.
    pub act_ms: u32,
    pub pre: Option<IxPre>,
    pub hold: Option<IxHold>,
    pub single: Option<IxSingle>,
    pub page: Option<IxPage>,
    pub pow: Option<IxPow>,
}

/// The first field of an [`IxTelemetry`] outside its bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IxRangeError(pub &'static str);

impl fmt::Display for IxRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t.ix field {} out of range", self.0)
    }
}

impl std::error::Error for IxRangeError {}

impl IxTelemetry {
    /// The only `t.ix` version.
    pub const VERSION: u8 = 1;
    /// Largest `logBucket` value.
    pub const MAX_BUCKET: Bucket = 31;
    /// Largest value of the 0.1-step fields, in tenths (1.0).
    pub const MAX_TENTHS: u8 = 10;
    /// Cap of `hold.ms` and `single.wait_ms`.
    pub const MAX_HOLD_MS: u32 = 60_000;
    /// Resolution of `hold.ms` and `single.wait_ms`.
    pub const HOLD_RESOLUTION_MS: u32 = 10;
    /// Cap of `act_ms`.
    pub const MAX_ACT_MS: u32 = 600_000;
    /// Resolution of `act_ms`.
    pub const ACT_RESOLUTION_MS: u32 = 100;
    /// Cap of `hold.cancels` and `page.vis_during`.
    pub const MAX_SMALL_COUNT: u8 = 15;
    /// Largest `trusted` bucket.
    pub const MAX_TRUSTED: u8 = 3;
    /// Longest `sv`.
    pub const MAX_SV_LEN: usize = 16;

    /// Checks every bound of spec §7.6 and returns the first field outside
    /// it. Presence rules (`pre` / `hold` / `single` per mode) are the
    /// decoder's; the hard checks of spec §7.7 are the Decision Core's.
    pub fn check(&self) -> Result<(), IxRangeError> {
        let bucket = |b: Bucket, name| ok(b <= Self::MAX_BUCKET, name);
        let tenths = |t: Tenths, name| ok(t <= Self::MAX_TENTHS, name);
        let held = |ms: u32, name| {
            ok(
                ms <= Self::MAX_HOLD_MS && ms.is_multiple_of(Self::HOLD_RESOLUTION_MS),
                name,
            )
        };
        ok(self.v == Self::VERSION, "v")?;
        ok(is_valid_sv(&self.sv), "sv")?;
        ok(self.trusted <= Self::MAX_TRUSTED, "trusted")?;
        ok(
            self.act_ms <= Self::MAX_ACT_MS && self.act_ms.is_multiple_of(Self::ACT_RESOLUTION_MS),
            "act_ms",
        )?;
        if let Some(p) = &self.pre {
            bucket(p.moves, "pre.moves")?;
            bucket(p.path_px, "pre.path_px")?;
            tenths(p.straight, "pre.straight")?;
            bucket(p.speed_mean, "pre.speed_mean")?;
            bucket(p.speed_sd, "pre.speed_sd")?;
            bucket(p.dir_changes, "pre.dir_changes")?;
            bucket(p.render_to_input_ms, "pre.render_to_input_ms")?;
            bucket(p.to_target_ms, "pre.to_target_ms")?;
        }
        if let Some(h) = &self.hold {
            held(h.ms, "hold.ms")?;
            let offset_ok = h
                .offset
                .iter()
                .all(|o| o.unsigned_abs() <= Self::MAX_TENTHS);
            ok(offset_ok, "hold.offset")?;
            bucket(h.jitter_px, "hold.jitter_px")?;
            bucket(h.moves, "hold.moves")?;
            ok(h.cancels <= Self::MAX_SMALL_COUNT, "hold.cancels")?;
            tenths(h.pressure, "hold.pressure")?;
        }
        if let Some(s) = &self.single {
            held(s.wait_ms, "single.wait_ms")?;
        }
        if let Some(p) = &self.page {
            bucket(p.vis, "page.vis")?;
            ok(p.vis_during <= Self::MAX_SMALL_COUNT, "page.vis_during")?;
            bucket(p.focus, "page.focus")?;
            bucket(p.frame_mean, "page.frame_mean")?;
            bucket(p.frame_sd, "page.frame_sd")?;
        }
        if let Some(p) = &self.pow {
            bucket(p.ms, "pow.ms")?;
        }
        Ok(())
    }
}

fn ok(cond: bool, name: &'static str) -> Result<(), IxRangeError> {
    if cond {
        Ok(())
    } else {
        Err(IxRangeError(name))
    }
}

/// `[0-9A-Za-z.+-]{1,16}`.
fn is_valid_sv(sv: &str) -> bool {
    (1..=IxTelemetry::MAX_SV_LEN).contains(&sv.len())
        && sv
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example object of spec §7.6, quantized.
    fn example() -> IxTelemetry {
        IxTelemetry {
            v: 1,
            mode: IxMode::Hold,
            modality: InputModality::Mouse,
            locale: IxLocale::ZhCn,
            ks: KeyStore::Idb,
            sv: "0.3.0".into(),
            fallback: None,
            trusted: 3,
            act_ms: 2_300,
            pre: Some(IxPre {
                moves: 5,
                path_px: 9,
                straight: 7,
                speed_mean: 6,
                speed_sd: 4,
                dir_changes: 3,
                render_to_input_ms: 11,
                to_target_ms: 9,
            }),
            hold: Some(IxHold {
                ms: 1_910,
                offset: [1, -2],
                jitter_px: 2,
                moves: 3,
                cancels: 0,
                pressure: 5,
                pressure_var: false,
                contact_var: false,
            }),
            single: Some(IxSingle { wait_ms: 1_880 }),
            page: Some(IxPage {
                vis: 0,
                vis_during: 0,
                focus: 0,
                frame_mean: 4,
                frame_sd: 1,
            }),
            pow: Some(IxPow {
                ms: 8,
                worker: true,
                pow_impl: PowImpl::Js,
            }),
        }
    }

    #[test]
    fn spec_example_is_in_range() {
        assert_eq!(example().check(), Ok(()));
        let minimal = IxTelemetry {
            mode: IxMode::PowOnly,
            modality: InputModality::None,
            pre: None,
            hold: None,
            single: None,
            page: None,
            pow: None,
            act_ms: 0,
            trusted: 0,
            ..example()
        };
        assert_eq!(minimal.check(), Ok(()));
    }

    #[test]
    fn every_bound_has_a_counterexample() {
        type Mutation = fn(&mut IxTelemetry);
        let cases: [(&str, Mutation); 26] = [
            ("v", |t| t.v = 2),
            ("sv", |t| t.sv = String::new()),
            ("sv", |t| t.sv = "x".repeat(17)),
            ("sv", |t| t.sv = "0.3.0 beta".into()),
            ("trusted", |t| t.trusted = 4),
            ("act_ms", |t| t.act_ms = 600_100),
            ("act_ms", |t| t.act_ms = 2_350),
            ("pre.moves", |t| t.pre.as_mut().unwrap().moves = 32),
            ("pre.path_px", |t| t.pre.as_mut().unwrap().path_px = 32),
            ("pre.straight", |t| t.pre.as_mut().unwrap().straight = 11),
            ("pre.speed_mean", |t| {
                t.pre.as_mut().unwrap().speed_mean = 32
            }),
            ("pre.speed_sd", |t| t.pre.as_mut().unwrap().speed_sd = 32),
            ("pre.dir_changes", |t| {
                t.pre.as_mut().unwrap().dir_changes = 32
            }),
            ("pre.render_to_input_ms", |t| {
                t.pre.as_mut().unwrap().render_to_input_ms = 32
            }),
            ("pre.to_target_ms", |t| {
                t.pre.as_mut().unwrap().to_target_ms = 32
            }),
            ("hold.ms", |t| t.hold.as_mut().unwrap().ms = 60_010),
            ("hold.ms", |t| t.hold.as_mut().unwrap().ms = 1_915),
            ("hold.offset", |t| {
                t.hold.as_mut().unwrap().offset = [0, -11]
            }),
            ("hold.jitter_px", |t| {
                t.hold.as_mut().unwrap().jitter_px = 32
            }),
            ("hold.cancels", |t| t.hold.as_mut().unwrap().cancels = 16),
            ("hold.pressure", |t| t.hold.as_mut().unwrap().pressure = 11),
            ("single.wait_ms", |t| {
                t.single.as_mut().unwrap().wait_ms = 60_001
            }),
            ("page.vis", |t| t.page.as_mut().unwrap().vis = 32),
            ("page.vis_during", |t| {
                t.page.as_mut().unwrap().vis_during = 16
            }),
            ("page.frame_sd", |t| t.page.as_mut().unwrap().frame_sd = 32),
            ("pow.ms", |t| t.pow.as_mut().unwrap().ms = 32),
        ];
        for (field, mutate) in cases {
            let mut t = example();
            mutate(&mut t);
            assert_eq!(t.check(), Err(IxRangeError(field)), "{field}");
        }
        // Upper bounds themselves are fine.
        let mut t = example();
        t.sv = "1.2.3-rc.1+b.20".into();
        t.act_ms = IxTelemetry::MAX_ACT_MS;
        t.hold.as_mut().unwrap().ms = IxTelemetry::MAX_HOLD_MS;
        t.hold.as_mut().unwrap().offset = [-10, 10];
        t.hold.as_mut().unwrap().cancels = 15;
        t.page.as_mut().unwrap().vis_during = 15;
        t.pow.as_mut().unwrap().ms = 31;
        assert_eq!(t.check(), Ok(()));
    }

    #[test]
    fn wire_names() {
        let modes: Vec<_> = IxMode::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(modes, ["hold", "single", "pow_only", "external"]);
        let modalities: Vec<_> = InputModality::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            modalities,
            ["mouse", "touch", "pen", "keyboard", "mixed", "none"]
        );
        assert_eq!(A11yMode::default().as_str(), "none");
        assert_eq!("zh-CN".parse::<IxLocale>(), Ok(IxLocale::ZhCn));
        assert!("zh-cn".parse::<IxLocale>().is_err());
        let ks: Vec<_> = KeyStore::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(ks, ["idb", "local", "memory", "none"]);
        let fb: Vec<_> = IxFallback::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            fb,
            ["ts_unsupported", "ts_load_timeout", "ts_error", "ts_config"]
        );
        assert_eq!(PowImpl::Wasm.to_string(), "wasm");
    }
}
