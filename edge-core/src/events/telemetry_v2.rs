//! The single Phase 2 telemetry decoder (docs/impl/phase2-spec.md §7.6,
//! §9.4, §12.8, §15.2; D-62): the `t` string of a `/__mg/c` v2 submission
//! (and of `/__mg/r`) with its `env`, `auto` and interaction telemetry
//! `ix`, the behavior summary, and the `POST /__mg/t` report bodies.
//!
//! Everything here is attacker-controlled JSON. It is parsed under the body
//! rules of the endpoints (UTF-8, nesting at most 16 levels, no repeated
//! object key, a size limit), checked against a fixed schema, and only the
//! typed result is ever stored: [`ChallengeTelemetry::to_value`],
//! [`BehaviorSummary::to_value`] and [`TelemetryReport::to_value`] are the
//! canonical re-serializations for `kind=telemetry` (unknown fields dropped,
//! no `ua.userAgent`). `ix` becomes a [`mg_core::IxTelemetry`] within the
//! bounds of [`mg_core::IxTelemetry::check`].
//!
//! Readings of the spec that the shared samples
//! (`testdata/phase2/samples/telemetry/`) fix:
//!
//! * `t`: a whole-`t` failure (size, JSON rules, not an object) rejects the
//!   submission (`ic.body`); an `ix` that does not fit §7.6 only drops `ix`
//!   ([`ChallengeTelemetry::ix_rejected`]); an invalid `env` / `auto` is
//!   dropped as in Phase 1. A `null` member counts as absent.
//! * `ix`: every scalar of the top level and of a present section is
//!   required; `fallback` may be absent or `null`; `pre` and `hold` are kept
//!   only in `hold` mode and `single` only in `single` mode (in other modes
//!   they are dropped); the 0.1-step values must be multiples of 0.1 and
//!   are re-serialized like `JSON.stringify` writes them (`1`, `0.7`).
//! * Behavior summary: every member of a present section is required; the
//!   count arrays have exactly 16 (`ptr.speed`, `ptr.curv`, `keys.iki`) or
//!   8 (`scroll.speed`) items; the 2048-byte limit applies to the summary's
//!   compact JSON as received.
//! * Reports: any report that does not fit its schema rejects the whole
//!   request (400), except a `cache_hit` under `/__mg/s/`, which is dropped
//!   ([`ReportEntry::Dropped`], counted as `invalid`). Paths are page paths:
//!   `/…`, at most 512 bytes, no query, fragment or control character.
//!
//! # Privacy (§2.4 item 10)
//!
//! The content of `t`, of `ix` and of `/__mg/t` reports never appears in
//! logs or `Debug` output: the types here print only which parts are
//! present.

use super::telemetry::{TelemetryAuto, TelemetryEnv};
use mg_core::telemetry::{
    InputModality, IxFallback, IxHold, IxLocale, IxMode, IxPage, IxPow, IxPre, IxSingle,
    IxTelemetry, KeyStore, PowImpl,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Deepest JSON nesting accepted (the top-level value is depth 1).
pub const TELEMETRY_MAX_DEPTH: usize = 16;
/// Largest `t` (bytes of its JSON text), §7.5.
pub const T_MAX_BYTES: usize = 2048;
/// Largest behavior summary (bytes of its compact JSON), §12.8.
pub const BEHAVIOR_MAX_BYTES: usize = 2048;
/// Largest `POST /__mg/t` body, §9.4.
pub const REPORT_BODY_MAX_BYTES: usize = 16 * 1024;
/// Most reports per `POST /__mg/t` request, §9.4.
pub const MAX_REPORTS: usize = 8;
/// Longest report path / page, §9.4.
pub const REPORT_PATH_MAX_BYTES: usize = 512;
/// Largest `upstream_challenge.count`, §9.4.
pub const MAX_UPSTREAM_COUNT: u8 = 100;

/// Why a telemetry input was rejected. Messages never quote the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    #[error("telemetry larger than its limit")]
    TooLarge,
    #[error("telemetry is not UTF-8")]
    Utf8,
    #[error("telemetry is not valid JSON")]
    Json,
    #[error("telemetry nested deeper than 16 levels")]
    Depth,
    #[error("telemetry repeats an object key")]
    DuplicateKey,
    #[error("telemetry is not a JSON object")]
    NotObject,
    /// A schema rule; the name of the offending member.
    #[error("telemetry field {0} does not fit its schema")]
    Schema(&'static str),
}

// ---------------------------------------------------------------------------
// Strict JSON

/// Deserializes any JSON value, failing on a repeated object key or on
/// nesting deeper than [`TELEMETRY_MAX_DEPTH`].
struct Checked {
    depth: usize,
}

const DEPTH_ERROR: &str = "mg: nesting too deep";
const DUPLICATE_ERROR: &str = "mg: duplicate key";

impl<'de> DeserializeSeed<'de> for Checked {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Checked {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= TELEMETRY_MAX_DEPTH {
            return Err(de::Error::custom(DEPTH_ERROR));
        }
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Checked {
            depth: self.depth + 1,
        })? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= TELEMETRY_MAX_DEPTH {
            return Err(de::Error::custom(DEPTH_ERROR));
        }
        let mut seen = BTreeSet::new();
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(DUPLICATE_ERROR));
            }
            let v = map.next_value_seed(Checked {
                depth: self.depth + 1,
            })?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parses `bytes` (at most `max` of them) under the JSON body rules of the
/// Phase 2 endpoints: UTF-8, nesting at most 16 levels, no repeated key.
pub fn strict_json(bytes: &[u8], max: usize) -> Result<Value, TelemetryError> {
    if bytes.len() > max {
        return Err(TelemetryError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| TelemetryError::Utf8)?;
    let mut d = serde_json::Deserializer::from_str(text);
    let v = Checked { depth: 0 }.deserialize(&mut d).map_err(|e| {
        let msg = e.to_string();
        if msg.contains(DEPTH_ERROR) || msg.contains("recursion limit") {
            TelemetryError::Depth
        } else if msg.contains(DUPLICATE_ERROR) {
            TelemetryError::DuplicateKey
        } else {
            TelemetryError::Json
        }
    })?;
    d.end().map_err(|_| TelemetryError::Json)?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Typed readers

type Field<T> = Result<T, TelemetryError>;

fn member<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

fn required<'a>(o: &'a Map<String, Value>, key: &str, name: &'static str) -> Field<&'a Value> {
    member(o, key).ok_or(TelemetryError::Schema(name))
}

fn uint<T: TryFrom<u64>>(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<T> {
    required(o, key, name)?
        .as_u64()
        .and_then(|n| T::try_from(n).ok())
        .ok_or(TelemetryError::Schema(name))
}

fn bucket(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<u8> {
    let b: u8 = uint(o, key, name)?;
    if b > IxTelemetry::MAX_BUCKET {
        return Err(TelemetryError::Schema(name));
    }
    Ok(b)
}

fn flag01(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<bool> {
    match uint::<u8>(o, key, name)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TelemetryError::Schema(name)),
    }
}

fn boolean(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<bool> {
    required(o, key, name)?
        .as_bool()
        .ok_or(TelemetryError::Schema(name))
}

fn string<'a>(o: &'a Map<String, Value>, key: &str, name: &'static str) -> Field<&'a str> {
    required(o, key, name)?
        .as_str()
        .ok_or(TelemetryError::Schema(name))
}

fn wire<T: FromStr>(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<T> {
    string(o, key, name)?
        .parse()
        .map_err(|_| TelemetryError::Schema(name))
}

/// A 0.1-step value, as tenths in `min..=max`.
fn tenths_of(v: &Value, min: i32, max: i32, name: &'static str) -> Field<i32> {
    let n = v.as_f64().ok_or(TelemetryError::Schema(name))?;
    let scaled = n * 10.0;
    let rounded = scaled.round();
    if (scaled - rounded).abs() > 1e-6 || rounded < f64::from(min) || rounded > f64::from(max) {
        return Err(TelemetryError::Schema(name));
    }
    // In range of i32 by the check above.
    Ok(rounded as i32)
}

fn tenths(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<u8> {
    let t = tenths_of(
        required(o, key, name)?,
        0,
        i32::from(IxTelemetry::MAX_TENTHS),
        name,
    )?;
    u8::try_from(t).map_err(|_| TelemetryError::Schema(name))
}

fn section<'a>(
    o: &'a Map<String, Value>,
    key: &str,
    name: &'static str,
) -> Field<Option<&'a Map<String, Value>>> {
    match member(o, key) {
        None => Ok(None),
        Some(v) => v.as_object().map(Some).ok_or(TelemetryError::Schema(name)),
    }
}

/// Tenths as `JSON.stringify` writes them: an integer when whole.
fn tenths_value(t: i32) -> Value {
    if t % 10 == 0 {
        Value::from(t / 10)
    } else {
        Number::from_f64(f64::from(t) / 10.0).map_or(Value::Null, Value::Number)
    }
}

// ---------------------------------------------------------------------------
// t.ix (§7.6)

/// Decodes `t.ix` v1 (§7.6) into the quantized native form; the bounds are
/// those of [`IxTelemetry::check`].
pub fn ix_from_value(v: &Value) -> Result<IxTelemetry, TelemetryError> {
    let o = v.as_object().ok_or(TelemetryError::Schema("ix"))?;
    let version: u8 = uint(o, "v", "v")?;
    if version != IxTelemetry::VERSION {
        return Err(TelemetryError::Schema("v"));
    }
    let mode: IxMode = wire(o, "mode", "mode")?;
    let fallback = match member(o, "fallback") {
        None => None,
        Some(f) => Some(
            f.as_str()
                .and_then(|s| IxFallback::from_str(s).ok())
                .ok_or(TelemetryError::Schema("fallback"))?,
        ),
    };
    let pre = match (mode, section(o, "pre", "pre")?) {
        (IxMode::Hold, Some(p)) => Some(IxPre {
            moves: bucket(p, "moves", "pre.moves")?,
            path_px: bucket(p, "path_px", "pre.path_px")?,
            straight: tenths(p, "straight", "pre.straight")?,
            speed_mean: bucket(p, "speed_mean", "pre.speed_mean")?,
            speed_sd: bucket(p, "speed_sd", "pre.speed_sd")?,
            dir_changes: bucket(p, "dir_changes", "pre.dir_changes")?,
            render_to_input_ms: bucket(p, "render_to_input_ms", "pre.render_to_input_ms")?,
            to_target_ms: bucket(p, "to_target_ms", "pre.to_target_ms")?,
        }),
        _ => None,
    };
    let hold = match (mode, section(o, "hold", "hold")?) {
        (IxMode::Hold, Some(h)) => {
            let offset = required(h, "offset", "hold.offset")?
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or(TelemetryError::Schema("hold.offset"))?;
            let max = i32::from(IxTelemetry::MAX_TENTHS);
            let axis = |v: &Value| {
                tenths_of(v, -max, max, "hold.offset").and_then(|t| {
                    i8::try_from(t).map_err(|_| TelemetryError::Schema("hold.offset"))
                })
            };
            Some(IxHold {
                ms: uint(h, "ms", "hold.ms")?,
                offset: [axis(&offset[0])?, axis(&offset[1])?],
                jitter_px: bucket(h, "jitter_px", "hold.jitter_px")?,
                moves: bucket(h, "moves", "hold.moves")?,
                cancels: uint(h, "cancels", "hold.cancels")?,
                pressure: tenths(h, "pressure", "hold.pressure")?,
                pressure_var: flag01(h, "pressure_var", "hold.pressure_var")?,
                contact_var: flag01(h, "contact_var", "hold.contact_var")?,
            })
        }
        _ => None,
    };
    let single = match (mode, section(o, "single", "single")?) {
        (IxMode::Single, Some(s)) => Some(IxSingle {
            wait_ms: uint(s, "wait_ms", "single.wait_ms")?,
        }),
        _ => None,
    };
    let page = match section(o, "page", "page")? {
        Some(p) => Some(IxPage {
            vis: bucket(p, "vis", "page.vis")?,
            vis_during: uint(p, "vis_during", "page.vis_during")?,
            focus: bucket(p, "focus", "page.focus")?,
            frame_mean: bucket(p, "frame_mean", "page.frame_mean")?,
            frame_sd: bucket(p, "frame_sd", "page.frame_sd")?,
        }),
        None => None,
    };
    let pow = match section(o, "pow", "pow")? {
        Some(p) => Some(IxPow {
            ms: bucket(p, "ms", "pow.ms")?,
            worker: boolean(p, "worker", "pow.worker")?,
            pow_impl: wire::<PowImpl>(p, "impl", "pow.impl")?,
        }),
        None => None,
    };
    let ix = IxTelemetry {
        v: version,
        mode,
        modality: wire::<InputModality>(o, "modality", "modality")?,
        locale: wire::<IxLocale>(o, "locale", "locale")?,
        ks: wire::<KeyStore>(o, "ks", "ks")?,
        sv: string(o, "sv", "sv")?.to_owned(),
        fallback,
        trusted: uint(o, "trusted", "trusted")?,
        act_ms: uint(o, "act_ms", "act_ms")?,
        pre,
        hold,
        single,
        page,
        pow,
    };
    ix.check().map_err(|e| TelemetryError::Schema(e.0))?;
    Ok(ix)
}

/// The canonical JSON form of `ix` (§7.6 field names, schema order).
pub fn ix_to_value(ix: &IxTelemetry) -> Value {
    let mut o = Map::new();
    o.insert("v".into(), json!(ix.v));
    o.insert("mode".into(), json!(ix.mode.as_str()));
    o.insert("modality".into(), json!(ix.modality.as_str()));
    o.insert("locale".into(), json!(ix.locale.as_str()));
    o.insert("ks".into(), json!(ix.ks.as_str()));
    o.insert("sv".into(), json!(ix.sv));
    o.insert(
        "fallback".into(),
        ix.fallback.map_or(Value::Null, |f| json!(f.as_str())),
    );
    o.insert("trusted".into(), json!(ix.trusted));
    o.insert("act_ms".into(), json!(ix.act_ms));
    if let Some(p) = &ix.pre {
        o.insert(
            "pre".into(),
            json!({
                "moves": p.moves,
                "path_px": p.path_px,
                "straight": tenths_value(i32::from(p.straight)),
                "speed_mean": p.speed_mean,
                "speed_sd": p.speed_sd,
                "dir_changes": p.dir_changes,
                "render_to_input_ms": p.render_to_input_ms,
                "to_target_ms": p.to_target_ms,
            }),
        );
    }
    if let Some(h) = &ix.hold {
        o.insert(
            "hold".into(),
            json!({
                "ms": h.ms,
                "offset": [
                    tenths_value(i32::from(h.offset[0])),
                    tenths_value(i32::from(h.offset[1])),
                ],
                "jitter_px": h.jitter_px,
                "moves": h.moves,
                "cancels": h.cancels,
                "pressure": tenths_value(i32::from(h.pressure)),
                "pressure_var": u8::from(h.pressure_var),
                "contact_var": u8::from(h.contact_var),
            }),
        );
    }
    if let Some(s) = &ix.single {
        o.insert("single".into(), json!({ "wait_ms": s.wait_ms }));
    }
    if let Some(p) = &ix.page {
        o.insert(
            "page".into(),
            json!({
                "vis": p.vis,
                "vis_during": p.vis_during,
                "focus": p.focus,
                "frame_mean": p.frame_mean,
                "frame_sd": p.frame_sd,
            }),
        );
    }
    if let Some(p) = &ix.pow {
        o.insert(
            "pow".into(),
            json!({ "ms": p.ms, "worker": p.worker, "impl": p.pow_impl.as_str() }),
        );
    }
    Value::Object(o)
}

// ---------------------------------------------------------------------------
// t (§7.5, §15.2)

/// The decoded `t` of a submission: `env` and `auto` (Phase 1 schema) and
/// `ix` (§7.6), each optional.
#[derive(Clone, PartialEq)]
pub struct ChallengeTelemetry {
    pub env: Option<TelemetryEnv>,
    pub auto: Option<TelemetryAuto>,
    pub ix: Option<IxTelemetry>,
    /// `t` carried an `ix` that does not fit §7.6 (it was dropped).
    pub ix_rejected: bool,
}

impl fmt::Debug for ChallengeTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeTelemetry")
            .field("env", &self.env.is_some())
            .field("auto", &self.auto.is_some())
            .field("ix", &self.ix.is_some())
            .field("ix_rejected", &self.ix_rejected)
            .finish()
    }
}

impl ChallengeTelemetry {
    /// Decodes the content of `t` (at most [`T_MAX_BYTES`]). `Err` rejects
    /// the whole `t` (the submission fails with `ic.body`).
    pub fn parse(t: &str) -> Result<Self, TelemetryError> {
        let value = strict_json(t.as_bytes(), T_MAX_BYTES)?;
        let o = value.as_object().ok_or(TelemetryError::NotObject)?;
        let (ix, ix_rejected) = match member(o, "ix") {
            None => (None, false),
            Some(v) => match ix_from_value(v) {
                Ok(ix) => (Some(ix), false),
                Err(_) => (None, true),
            },
        };
        Ok(Self {
            env: member(o, "env").and_then(TelemetryEnv::from_value),
            auto: member(o, "auto").and_then(TelemetryAuto::from_value),
            ix,
            ix_rejected,
        })
    }

    /// No `env`, `auto` or `ix`: a `kind=telemetry` record is not written
    /// (as I-32).
    pub fn is_empty(&self) -> bool {
        self.env.is_none() && self.auto.is_none() && self.ix.is_none()
    }

    /// The canonical form for `kind=telemetry` (§15.2): the present parts
    /// only, `env` without `ua.userAgent`.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        if let Some(env) = &self.env {
            o.insert("env".into(), env.to_value());
        }
        if let Some(auto) = &self.auto {
            o.insert("auto".into(), auto.to_value());
        }
        if let Some(ix) = &self.ix {
            o.insert("ix".into(), ix_to_value(ix));
        }
        Value::Object(o)
    }
}

// ---------------------------------------------------------------------------
// Behavior summary (§12.8)

/// The schema version of a behavior summary.
pub const BEHAVIOR_SCHEMA_VERSION: u64 = 1;

/// `ptr`: pointer speed and curvature histograms, pauses.
#[derive(Clone, PartialEq, Eq)]
pub struct BehaviorPtr {
    pub speed: [u16; 16],
    pub curv: [u16; 16],
    pub pauses: u8,
}

/// `keys`: inter-key interval histogram (never key values).
#[derive(Clone, PartialEq, Eq)]
pub struct BehaviorKeys {
    pub iki: [u16; 16],
}

/// `scroll`: distance bucket and speed histogram.
#[derive(Clone, PartialEq, Eq)]
pub struct BehaviorScroll {
    pub dist: u8,
    pub speed: [u16; 8],
}

/// `touch`: whether contact area / pressure varied.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BehaviorTouch {
    pub area_var: bool,
    pub pressure_var: bool,
}

/// `form`: fill time and paste buckets (never form content).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BehaviorForm {
    pub fill_ms: u8,
    pub paste: u8,
}

/// A behavior summary v1 (§12.8): `logBucket` values and bucket counts
/// only.
#[derive(Clone, PartialEq, Eq)]
pub struct BehaviorSummary {
    pub ptr: Option<BehaviorPtr>,
    pub keys: Option<BehaviorKeys>,
    pub scroll: Option<BehaviorScroll>,
    pub touch: Option<BehaviorTouch>,
    pub focus: Option<u8>,
    pub vis: Option<u8>,
    pub form: Option<BehaviorForm>,
}

/// `Debug` that names the type only: summaries are visitor telemetry.
macro_rules! opaque_debug {
    ($($t:ident),*) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($t)).finish_non_exhaustive()
            }
        }
    )*};
}

opaque_debug!(
    BehaviorSummary,
    BehaviorPtr,
    BehaviorKeys,
    BehaviorScroll,
    BehaviorTouch,
    BehaviorForm
);

fn counts<const N: usize>(
    o: &Map<String, Value>,
    key: &str,
    name: &'static str,
) -> Field<[u16; N]> {
    let items = required(o, key, name)?
        .as_array()
        .filter(|a| a.len() == N)
        .ok_or(TelemetryError::Schema(name))?;
    let mut out = [0u16; N];
    for (slot, v) in out.iter_mut().zip(items) {
        *slot = v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(TelemetryError::Schema(name))?;
    }
    Ok(out)
}

fn optional_bucket(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<Option<u8>> {
    match member(o, key) {
        None => Ok(None),
        Some(_) => bucket(o, key, name).map(Some),
    }
}

impl BehaviorSummary {
    /// Decodes a summary from its JSON bytes (at most
    /// [`BEHAVIOR_MAX_BYTES`]).
    pub fn from_json(bytes: &[u8]) -> Result<Self, TelemetryError> {
        Self::from_value(&strict_json(bytes, BEHAVIOR_MAX_BYTES)?)
    }

    /// Decodes an already parsed summary; its compact JSON must fit
    /// [`BEHAVIOR_MAX_BYTES`].
    pub fn from_value(v: &Value) -> Result<Self, TelemetryError> {
        let size = serde_json::to_vec(v).map_or(usize::MAX, |b| b.len());
        if size > BEHAVIOR_MAX_BYTES {
            return Err(TelemetryError::TooLarge);
        }
        let o = v.as_object().ok_or(TelemetryError::NotObject)?;
        if required(o, "v", "v")?.as_u64() != Some(BEHAVIOR_SCHEMA_VERSION) {
            return Err(TelemetryError::Schema("v"));
        }
        Ok(Self {
            ptr: match section(o, "ptr", "ptr")? {
                Some(p) => Some(BehaviorPtr {
                    speed: counts(p, "speed", "ptr.speed")?,
                    curv: counts(p, "curv", "ptr.curv")?,
                    pauses: bucket(p, "pauses", "ptr.pauses")?,
                }),
                None => None,
            },
            keys: match section(o, "keys", "keys")? {
                Some(k) => Some(BehaviorKeys {
                    iki: counts(k, "iki", "keys.iki")?,
                }),
                None => None,
            },
            scroll: match section(o, "scroll", "scroll")? {
                Some(s) => Some(BehaviorScroll {
                    dist: bucket(s, "dist", "scroll.dist")?,
                    speed: counts(s, "speed", "scroll.speed")?,
                }),
                None => None,
            },
            touch: match section(o, "touch", "touch")? {
                Some(t) => Some(BehaviorTouch {
                    area_var: flag01(t, "area_var", "touch.area_var")?,
                    pressure_var: flag01(t, "pressure_var", "touch.pressure_var")?,
                }),
                None => None,
            },
            focus: optional_bucket(o, "focus", "focus")?,
            vis: optional_bucket(o, "vis", "vis")?,
            form: match section(o, "form", "form")? {
                Some(f) => Some(BehaviorForm {
                    fill_ms: bucket(f, "fill_ms", "form.fill_ms")?,
                    paste: bucket(f, "paste", "form.paste")?,
                }),
                None => None,
            },
        })
    }

    /// The canonical form for `kind=telemetry` (present sections only).
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("v".into(), json!(BEHAVIOR_SCHEMA_VERSION));
        if let Some(p) = &self.ptr {
            o.insert(
                "ptr".into(),
                json!({ "speed": p.speed, "curv": p.curv, "pauses": p.pauses }),
            );
        }
        if let Some(k) = &self.keys {
            o.insert("keys".into(), json!({ "iki": k.iki }));
        }
        if let Some(s) = &self.scroll {
            o.insert("scroll".into(), json!({ "dist": s.dist, "speed": s.speed }));
        }
        if let Some(t) = &self.touch {
            o.insert(
                "touch".into(),
                json!({
                    "area_var": u8::from(t.area_var),
                    "pressure_var": u8::from(t.pressure_var),
                }),
            );
        }
        if let Some(f) = self.focus {
            o.insert("focus".into(), json!(f));
        }
        if let Some(v) = self.vis {
            o.insert("vis".into(), json!(v));
        }
        if let Some(f) = &self.form {
            o.insert(
                "form".into(),
                json!({ "fill_ms": f.fill_ms, "paste": f.paste }),
            );
        }
        Value::Object(o)
    }
}

// ---------------------------------------------------------------------------
// POST /__mg/t reports (§9.4)

/// The `kind` of a report (the `kind` label of
/// `mg_telemetry_reports_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportKind {
    UpstreamChallenge,
    CacheHit,
    Behavior,
    SwIntercept,
    KeyUnavailable,
}

impl ReportKind {
    /// Every kind.
    pub const ALL: [ReportKind; 5] = [
        Self::UpstreamChallenge,
        Self::CacheHit,
        Self::Behavior,
        Self::SwIntercept,
        Self::KeyUnavailable,
    ];

    /// The wire / label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamChallenge => "upstream_challenge",
            Self::CacheHit => "cache_hit",
            Self::Behavior => "behavior",
            Self::SwIntercept => "sw_intercept",
            Self::KeyUnavailable => "key_unavailable",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// `upstream_challenge.scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamScope {
    Navigation,
    ProtectedFetch,
    MgEndpoint,
}

impl UpstreamScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Navigation => "navigation",
            Self::ProtectedFetch => "protected_fetch",
            Self::MgEndpoint => "mg_endpoint",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Navigation, Self::ProtectedFetch, Self::MgEndpoint]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// `key_unavailable.reason` (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUnavailableReason {
    NoIdb,
    NoStorage,
    NoWebcrypto,
}

impl KeyUnavailableReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoIdb => "no_idb",
            Self::NoStorage => "no_storage",
            Self::NoWebcrypto => "no_webcrypto",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::NoIdb, Self::NoStorage, Self::NoWebcrypto]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// One accepted report of a `POST /__mg/t` body (§9.4). Paths are raw page
/// paths; the Edge matches them against the routes and applies
/// `redact_path` before writing them (§9.4 step 6).
#[derive(Clone, PartialEq, Eq)]
pub enum TelemetryReport {
    UpstreamChallenge {
        scope: UpstreamScope,
        path: String,
        count: u8,
    },
    CacheHit {
        path: String,
    },
    Behavior {
        page: String,
        summary: BehaviorSummary,
    },
    SwIntercept {
        path: String,
    },
    KeyUnavailable {
        reason: KeyUnavailableReason,
    },
}

impl fmt::Debug for TelemetryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryReport")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl TelemetryReport {
    pub fn kind(&self) -> ReportKind {
        match self {
            Self::UpstreamChallenge { .. } => ReportKind::UpstreamChallenge,
            Self::CacheHit { .. } => ReportKind::CacheHit,
            Self::Behavior { .. } => ReportKind::Behavior,
            Self::SwIntercept { .. } => ReportKind::SwIntercept,
            Self::KeyUnavailable { .. } => ReportKind::KeyUnavailable,
        }
    }

    /// The path the Edge matches against its routes (`path` or `page`).
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::UpstreamChallenge { path, .. }
            | Self::CacheHit { path }
            | Self::SwIntercept { path } => Some(path),
            Self::Behavior { page, .. } => Some(page),
            Self::KeyUnavailable { .. } => None,
        }
    }

    /// The canonical form of the report for `kind=telemetry`; `path`
    /// replaces the report's path or page (the redacted form, §9.4 step 6).
    pub fn to_value(&self, path: Option<&str>) -> Value {
        let p = |own: &str| json!(path.unwrap_or(own));
        match self {
            Self::UpstreamChallenge {
                scope,
                path: own,
                count,
            } => json!({
                "kind": self.kind().as_str(),
                "scope": scope.as_str(),
                "path": p(own),
                "count": count,
            }),
            Self::CacheHit { path: own } | Self::SwIntercept { path: own } => {
                json!({ "kind": self.kind().as_str(), "path": p(own) })
            }
            Self::Behavior { page, summary } => json!({
                "kind": self.kind().as_str(),
                "page": p(page),
                "summary": summary.to_value(),
            }),
            Self::KeyUnavailable { reason } => {
                json!({ "kind": self.kind().as_str(), "reason": reason.as_str() })
            }
        }
    }
}

/// One report of a request, in request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportEntry {
    Report(TelemetryReport),
    /// Fits the request's rules but is not recorded (a `cache_hit` under
    /// `/__mg/s/`); counted as `invalid` (§9.4).
    Dropped(ReportKind),
}

/// A page path of a report: `/…`, at most 512 bytes, no query, fragment or
/// control character.
fn page_path(o: &Map<String, Value>, key: &str, name: &'static str) -> Field<String> {
    let p = string(o, key, name)?;
    let ok = p.starts_with('/')
        && p.len() <= REPORT_PATH_MAX_BYTES
        && !p.chars().any(|c| c == '?' || c == '#' || c.is_control());
    if ok {
        Ok(p.to_owned())
    } else {
        Err(TelemetryError::Schema(name))
    }
}

fn report(v: &Value) -> Field<ReportEntry> {
    let o = v.as_object().ok_or(TelemetryError::Schema("reports"))?;
    let kind = string(o, "kind", "kind")
        .ok()
        .and_then(ReportKind::parse)
        .ok_or(TelemetryError::Schema("kind"))?;
    let r = match kind {
        ReportKind::UpstreamChallenge => {
            let count: u8 = uint(o, "count", "count")?;
            if !(1..=MAX_UPSTREAM_COUNT).contains(&count) {
                return Err(TelemetryError::Schema("count"));
            }
            TelemetryReport::UpstreamChallenge {
                scope: string(o, "scope", "scope")
                    .ok()
                    .and_then(UpstreamScope::parse)
                    .ok_or(TelemetryError::Schema("scope"))?,
                path: page_path(o, "path", "path")?,
                count,
            }
        }
        ReportKind::CacheHit => {
            let path = page_path(o, "path", "path")?;
            if !path.starts_with("/__mg/") {
                return Err(TelemetryError::Schema("path"));
            }
            if path.starts_with("/__mg/s/") {
                return Ok(ReportEntry::Dropped(kind));
            }
            TelemetryReport::CacheHit { path }
        }
        ReportKind::Behavior => TelemetryReport::Behavior {
            page: page_path(o, "page", "page")?,
            summary: BehaviorSummary::from_value(required(o, "summary", "summary")?)
                .map_err(|_| TelemetryError::Schema("summary"))?,
        },
        ReportKind::SwIntercept => {
            let path = page_path(o, "path", "path")?;
            if !path.starts_with("/__mg/") {
                return Err(TelemetryError::Schema("path"));
            }
            TelemetryReport::SwIntercept { path }
        }
        ReportKind::KeyUnavailable => TelemetryReport::KeyUnavailable {
            reason: string(o, "reason", "reason")
                .ok()
                .and_then(KeyUnavailableReason::parse)
                .ok_or(TelemetryError::Schema("reason"))?,
        },
    };
    Ok(ReportEntry::Report(r))
}

/// Decodes a `POST /__mg/t` body (§9.4). `Err` is the 400
/// `mg_bad_request` of step 4; otherwise one entry per report, in order.
pub fn parse_reports(body: &[u8]) -> Result<Vec<ReportEntry>, TelemetryError> {
    let value = strict_json(body, REPORT_BODY_MAX_BYTES)?;
    let o = value.as_object().ok_or(TelemetryError::NotObject)?;
    if required(o, "v", "v")?.as_u64() != Some(1) {
        return Err(TelemetryError::Schema("v"));
    }
    let reports = required(o, "reports", "reports")?
        .as_array()
        .filter(|r| (1..=MAX_REPORTS).contains(&r.len()))
        .ok_or(TelemetryError::Schema("reports"))?;
    let mut out = Vec::with_capacity(reports.len());
    let (mut upstream, mut cache) = (0, 0);
    for r in reports {
        let entry = report(r)?;
        let kind = match &entry {
            ReportEntry::Report(r) => r.kind(),
            ReportEntry::Dropped(k) => *k,
        };
        match kind {
            ReportKind::UpstreamChallenge => upstream += 1,
            ReportKind::CacheHit => cache += 1,
            _ => {}
        }
        if upstream > 1 || cache > 1 {
            return Err(TelemetryError::Schema("reports"));
        }
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_rules() {
        assert!(strict_json(b"{}", 2).is_ok());
        assert_eq!(strict_json(b"{} ", 2), Err(TelemetryError::TooLarge));
        assert_eq!(strict_json(b"\xff", 8), Err(TelemetryError::Utf8));
        assert_eq!(strict_json(b"{", 8), Err(TelemetryError::Json));
        assert_eq!(strict_json(b"{} {}", 8), Err(TelemetryError::Json));
        assert_eq!(
            strict_json(br#"{"a":1,"a":2}"#, 64),
            Err(TelemetryError::DuplicateKey)
        );
        assert_eq!(
            strict_json(br#"{"a":{"b":1,"b":1}}"#, 64),
            Err(TelemetryError::DuplicateKey)
        );
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(strict_json(deep(16).as_bytes(), 1024).is_ok());
        assert_eq!(
            strict_json(deep(17).as_bytes(), 1024),
            Err(TelemetryError::Depth)
        );
        assert_eq!(
            strict_json(deep(200).as_bytes(), 1024),
            Err(TelemetryError::Depth)
        );
    }

    #[test]
    fn tenths_are_quantized() {
        assert_eq!(tenths_of(&json!(0.7), 0, 10, "x"), Ok(7));
        assert_eq!(tenths_of(&json!(1), 0, 10, "x"), Ok(10));
        assert_eq!(tenths_of(&json!(-0.2), -10, 10, "x"), Ok(-2));
        assert!(tenths_of(&json!(0.75), 0, 10, "x").is_err());
        assert!(tenths_of(&json!(1.1), 0, 10, "x").is_err());
        assert!(tenths_of(&json!(-0.1), 0, 10, "x").is_err());
        assert!(tenths_of(&json!("0.5"), 0, 10, "x").is_err());
        assert!(tenths_of(&json!(1e300), 0, 10, "x").is_err());
        assert_eq!(tenths_value(10), json!(1));
        assert_eq!(tenths_value(-10), json!(-1));
        assert_eq!(tenths_value(7), json!(0.7));
        assert_eq!(tenths_value(0), json!(0));
    }

    #[test]
    fn debug_never_prints_content() {
        let t = ChallengeTelemetry::parse(
            r#"{"ix":{"v":1,"mode":"external","modality":"touch","locale":"en","ks":"idb","sv":"9.9.9-secret","trusted":3,"act_ms":1500}}"#,
        )
        .unwrap();
        assert!(t.ix.is_some());
        assert!(!format!("{t:?}").contains("secret"));
        let r = parse_reports(
            br#"{"v":1,"reports":[{"kind":"cache_hit","path":"/__mg/secret-path"}]}"#,
        )
        .unwrap();
        assert!(!format!("{r:?}").contains("secret"));
    }
}
