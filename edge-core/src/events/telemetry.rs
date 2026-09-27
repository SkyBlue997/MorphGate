//! Typed, bounded re-serialization of the Web SDK's `env` and `auto`
//! summaries (spec §9.11 "遥测", §10.3, §13.5; D-31).
//!
//! The challenge submission carries `EnvSummary` (`sdk/web/src/env.ts`) and
//! `AutomationSummary` (`sdk/web/src/automation.ts`), both schema `v = 1`.
//! They are attacker-controlled JSON, so the Edge never stores them as given:
//! it parses them into the typed structures below, which
//!
//! * keep only the fields the SDK schema defines (unknown fields are dropped),
//! * truncate every string to [`TELEMETRY_MAX_STRING_BYTES`] bytes (on a
//!   character boundary) and every array to [`TELEMETRY_MAX_ARRAY_ITEMS`] items,
//! * have a fixed shape whose nesting depth is at most 4
//!   (`env.ua.brands[i].brand`),
//! * map a field of the wrong type to `null` (the SDK itself reports a probe
//!   it could not read as `null`).
//!
//! The input as a whole fails to parse (and the caller omits `env` / `auto`)
//! when it is larger than [`TELEMETRY_MAX_INPUT_BYTES`], not JSON, not an
//! object, or its `v` is not the integer 1.
//!
//! The `Serialize` impls are the canonical re-serialization for
//! `kind=telemetry` (§13.5): fields in schema order, absent values as `null`,
//! and **without `ua.userAgent`** (the Edge already has the request's
//! `User-Agent`; the SDK copy is only compared with it in §10.3 step 8, see
//! [`TelemetryEnv::user_agent`]).

use super::encode::truncate_utf8;
use serde::Serialize;
use serde_json::{Map, Number, Value};

/// `EnvSummary.v` understood by this parser.
pub const ENV_SCHEMA_VERSION: u64 = 1;
/// `AutomationSummary.v` understood by this parser.
pub const AUTOMATION_SCHEMA_VERSION: u64 = 1;
/// Longest string kept, in bytes (§9.11).
pub const TELEMETRY_MAX_STRING_BYTES: usize = 256;
/// Most array items kept (§9.11).
pub const TELEMETRY_MAX_ARRAY_ITEMS: usize = 16;
/// Largest input accepted by `from_json` (the whole `/__mg/c` body is at most
/// 8 KiB, §10.3).
pub const TELEMETRY_MAX_INPUT_BYTES: usize = 16 * 1024;

/// Sanitized `EnvSummary` (schema v1).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryEnv {
    /// Always [`ENV_SCHEMA_VERSION`].
    pub v: u64,
    pub ua: TelemetryUa,
    pub languages: Option<Vec<String>>,
    pub time_zone: Option<String>,
    pub utc_offset_min: Option<Number>,
    pub screen: Option<TelemetryScreen>,
    pub viewport: Option<TelemetryViewport>,
    pub dpr: Option<Number>,
    pub cores: Option<Number>,
    pub memory_gb: Option<Number>,
    pub touch: TelemetryTouch,
    pub storage: TelemetryStorage,
    /// Reserved by the SDK (always `null` in v1); anything sent is discarded.
    pub graphics: (),
}

/// `EnvSummary.ua`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryUa {
    /// `navigator.userAgent` as reported (truncated). Kept for the §10.3
    /// step 8 comparison, **never serialized** into telemetry.
    #[serde(skip_serializing)]
    pub user_agent: Option<String>,
    pub brands: Option<Vec<Brand>>,
    pub mobile: Option<bool>,
    pub platform: Option<String>,
}

/// One low-entropy UA Client Hints brand.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Brand {
    pub brand: String,
    pub version: String,
}

/// `EnvSummary.screen`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryScreen {
    pub width: Option<Number>,
    pub height: Option<Number>,
    pub avail_width: Option<Number>,
    pub avail_height: Option<Number>,
    pub color_depth: Option<Number>,
}

/// `EnvSummary.viewport`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TelemetryViewport {
    pub width: Option<Number>,
    pub height: Option<Number>,
}

/// `EnvSummary.touch`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryTouch {
    pub max_touch_points: Option<Number>,
    pub coarse_pointer: Option<bool>,
}

/// `EnvSummary.storage`: whether each storage API was reachable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryStorage {
    pub cookies: Option<bool>,
    pub local: Option<bool>,
    pub session: Option<bool>,
    pub indexed_db: Option<bool>,
}

/// Sanitized `AutomationSummary` (schema v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetryAuto {
    /// Always [`AUTOMATION_SCHEMA_VERSION`].
    pub v: u64,
    /// `navigator.webdriver`; `None` = missing / not a boolean.
    pub webdriver: Option<bool>,
}

impl TelemetryEnv {
    /// Parses `env` bytes; `None` means "treat `env` as absent" (§10.3).
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        Self::from_value(&parse_bounded(bytes)?)
    }

    /// Parses an already-decoded `env` value (e.g. a field of the submission
    /// JSON); `None` means "treat `env` as absent".
    pub fn from_value(value: &Value) -> Option<Self> {
        let obj = versioned_object(value, ENV_SCHEMA_VERSION)?;
        let ua = obj.get("ua").and_then(Value::as_object);
        let screen = obj.get("screen").and_then(Value::as_object);
        let viewport = obj.get("viewport").and_then(Value::as_object);
        let touch = obj.get("touch").and_then(Value::as_object);
        let storage = obj.get("storage").and_then(Value::as_object);
        Some(Self {
            v: ENV_SCHEMA_VERSION,
            ua: ua.map_or_else(TelemetryUa::default, |ua| TelemetryUa {
                user_agent: string(ua.get("userAgent")),
                brands: ua.get("brands").and_then(Value::as_array).map(|list| {
                    list.iter()
                        .filter_map(Value::as_object)
                        .take(TELEMETRY_MAX_ARRAY_ITEMS)
                        .map(|b| Brand {
                            brand: string(b.get("brand")).unwrap_or_default(),
                            version: string(b.get("version")).unwrap_or_default(),
                        })
                        .collect()
                }),
                mobile: boolean(ua.get("mobile")),
                platform: string(ua.get("platform")),
            }),
            languages: obj.get("languages").and_then(Value::as_array).map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .take(TELEMETRY_MAX_ARRAY_ITEMS)
                    .map(bounded)
                    .collect()
            }),
            time_zone: string(obj.get("timeZone")),
            utc_offset_min: number(obj.get("utcOffsetMin")),
            screen: screen.map(|s| TelemetryScreen {
                width: number(s.get("width")),
                height: number(s.get("height")),
                avail_width: number(s.get("availWidth")),
                avail_height: number(s.get("availHeight")),
                color_depth: number(s.get("colorDepth")),
            }),
            viewport: viewport.map(|v| TelemetryViewport {
                width: number(v.get("width")),
                height: number(v.get("height")),
            }),
            dpr: number(obj.get("dpr")),
            cores: number(obj.get("cores")),
            memory_gb: number(obj.get("memoryGb")),
            touch: touch.map_or_else(TelemetryTouch::default, |t| TelemetryTouch {
                max_touch_points: number(t.get("maxTouchPoints")),
                coarse_pointer: boolean(t.get("coarsePointer")),
            }),
            storage: storage.map_or_else(TelemetryStorage::default, |s| TelemetryStorage {
                cookies: boolean(s.get("cookies")),
                local: boolean(s.get("local")),
                session: boolean(s.get("session")),
                indexed_db: boolean(s.get("indexedDb")),
            }),
            graphics: (),
        })
    }

    /// `ua.userAgent` as the SDK reported it (bounded), for the §10.3 step 8
    /// prefix check against the request's `User-Agent`.
    pub fn user_agent(&self) -> Option<&str> {
        self.ua.user_agent.as_deref()
    }

    /// The canonical telemetry form (§13.5), for the `env` field of a
    /// `kind=telemetry` body.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

impl TelemetryAuto {
    /// Parses `auto` bytes; `None` means "treat `auto` as absent".
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        Self::from_value(&parse_bounded(bytes)?)
    }

    /// Parses an already-decoded `auto` value.
    pub fn from_value(value: &Value) -> Option<Self> {
        let obj = versioned_object(value, AUTOMATION_SCHEMA_VERSION)?;
        Some(Self {
            v: AUTOMATION_SCHEMA_VERSION,
            webdriver: boolean(obj.get("webdriver")),
        })
    }

    /// The canonical telemetry form (§13.5).
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

fn parse_bounded(bytes: &[u8]) -> Option<Value> {
    if bytes.len() > TELEMETRY_MAX_INPUT_BYTES {
        return None;
    }
    // serde_json limits recursion (128 levels), so deep nesting is an error,
    // not a stack overflow.
    serde_json::from_slice(bytes).ok()
}

fn versioned_object(value: &Value, version: u64) -> Option<&Map<String, Value>> {
    let obj = value.as_object()?;
    (obj.get("v")?.as_u64()? == version).then_some(obj)
}

fn bounded(s: &str) -> String {
    truncate_utf8(s, TELEMETRY_MAX_STRING_BYTES).to_owned()
}

fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(bounded)
}

fn boolean(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

/// JSON numbers are always finite. The value is rebuilt from its `u64` /
/// `i64` / `f64` reading rather than cloned, so the output stays bounded even
/// if feature unification ever enabled serde_json's `arbitrary_precision`
/// (which would keep up to ~16 KiB of attacker-supplied digits verbatim).
fn number(value: Option<&Value>) -> Option<Number> {
    let Some(Value::Number(n)) = value else {
        return None;
    };
    if let Some(u) = n.as_u64() {
        Some(u.into())
    } else if let Some(i) = n.as_i64() {
        Some(i.into())
    } else {
        n.as_f64().and_then(Number::from_f64)
    }
}
