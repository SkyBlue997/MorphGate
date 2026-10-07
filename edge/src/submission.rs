//! The body of `POST /__mg/c` (docs/impl/phase1-spec.md §10.3, §9.11,
//! ruling I-28): media type, form decoding, the strict JSON rules and the
//! typed submission.
//!
//! * **Media type**: `application/x-www-form-urlencoded` (a navigation
//!   submission) or `application/json` (fetch); type and subtype are
//!   case-insensitive, parameters are allowed, a `charset` parameter must be
//!   `utf-8` (case-insensitive, optionally quoted), other parameters are
//!   ignored ([`media_kind`]).
//! * **Form**: exactly one field `mg`; `+` decodes to a space (the browser's
//!   serializer writes spaces, e.g. inside the User-Agent, as `+`, I-28) and
//!   `%XX` to a byte; a malformed escape, another field or a repeated `mg`
//!   is an error; the decoded value must be UTF-8 ([`decode_form`]).
//! * **JSON**: UTF-8, nesting depth at most 16, no repeated key in any
//!   object, unknown top-level fields ignored ([`parse_submission`]).
//! * **Fields**: `v` = 1; `type` `invisible` | `pow`; `c` at most 1024
//!   characters; `pow.counters` exactly one integer in `0..2^53`; `ret` a
//!   string (checked against the sealed hash later, step 7); `ts` a number;
//!   `build` `[0-9a-f]{16}` (`0000000000000000` = unknown build, I-28).
//! * **`env` / `auto`**: optional; parsed into the SDK's schema
//!   (`sdk/web/src/env.ts`, `automation.ts`, `v = 1`) where every probe may
//!   be `null` (no result, I-28), unknown fields are dropped, strings are cut
//!   to 256 bytes and arrays to 16 items. Anything else in them makes that
//!   part absent, never the submission invalid (§10.3, §9.11).
//!
//! Every failure is the reason `ic.body`; the caller answers with the uniform
//! failure. Nothing here logs or keeps the submitted values beyond the typed
//! result.

use mg_core::ChallengeType;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fmt;

/// Longest body read (§10.3 step 3).
pub const MAX_BODY: usize = 8192;
/// Deepest JSON nesting accepted (the top-level object is depth 1).
pub const MAX_DEPTH: usize = 16;
/// Longest `c` (characters; `C` is base64url, §6.2).
pub const MAX_C: usize = 1024;
/// `counters[0] < 2^53` (a JavaScript safe integer, §6.3).
pub const MAX_COUNTER: u64 = 1 << 53;
/// String cap of the typed `env` (§9.11).
pub const MAX_ENV_STRING: usize = 256;
/// Array cap of the typed `env` (§9.11).
pub const MAX_ENV_ITEMS: usize = 16;

/// How the body is encoded: a form navigation or a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// `application/x-www-form-urlencoded` (answers: 303 / HTML).
    Form,
    /// `application/json` (answers: JSON).
    Json,
}

/// Why a body was refused (always `ic.body` to the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    MediaType,
    Charset,
    Form,
    Utf8,
    Json,
    Depth,
    DuplicateKey,
    Field(&'static str),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MediaType => f.write_str("unsupported media type"),
            Self::Charset => f.write_str("charset is not utf-8"),
            Self::Form => f.write_str("the form is not exactly one mg field"),
            Self::Utf8 => f.write_str("not UTF-8"),
            Self::Json => f.write_str("not a JSON object"),
            Self::Depth => f.write_str("JSON nested deeper than 16"),
            Self::DuplicateKey => f.write_str("JSON object with a repeated key"),
            Self::Field(name) => write!(f, "field {name} is missing or invalid"),
        }
    }
}

/// OWS (RFC 9110: space and horizontal tab).
fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// The media type of a `Content-Type` value (see the module
/// documentation). `None` for a missing header is the caller's business.
pub fn media_kind(content_type: &str) -> Result<MediaKind, BodyError> {
    let mut parts = content_type.split(';');
    let media = trim_ows(parts.next().unwrap_or_default());
    let kind = if media.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        MediaKind::Form
    } else if media.eq_ignore_ascii_case("application/json") {
        MediaKind::Json
    } else {
        return Err(BodyError::MediaType);
    };
    for param in parts {
        let param = trim_ows(param);
        if param.is_empty() {
            continue;
        }
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        if !trim_ows(name).eq_ignore_ascii_case("charset") {
            continue;
        }
        let value = trim_ows(value);
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        if !value.eq_ignore_ascii_case("utf-8") {
            return Err(BodyError::Charset);
        }
    }
    Ok(kind)
}

/// `application/x-www-form-urlencoded` byte decoding: `+` is a space,
/// `%XX` a byte; a `%` without two hex digits is an error.
fn form_decode(part: &[u8]) -> Result<Vec<u8>, BodyError> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(part.len());
    let mut i = 0;
    while i < part.len() {
        match part[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = part.get(i + 1).copied().and_then(hex);
                let lo = part.get(i + 2).copied().and_then(hex);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(BodyError::Form);
                };
                out.push(hi << 4 | lo);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    Ok(out)
}

/// The value of the only form field `mg` (see the module documentation).
/// Empty sequences between `&` are skipped, as the WHATWG parser does.
pub fn decode_form(body: &[u8]) -> Result<String, BodyError> {
    let mut value = None;
    for pair in body.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        let (name, v) = match pair.iter().position(|b| *b == b'=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, &b""[..]),
        };
        if form_decode(name)? != b"mg" || value.is_some() {
            return Err(BodyError::Form);
        }
        value = Some(form_decode(v)?);
    }
    let value = value.ok_or(BodyError::Form)?;
    String::from_utf8(value).map_err(|_| BodyError::Utf8)
}

// ---------------------------------------------------------------------------
// Strict JSON: depth and duplicate keys

/// Deserializes any JSON value, failing on a repeated object key or on
/// nesting deeper than [`MAX_DEPTH`].
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
        Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
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
        if self.depth >= MAX_DEPTH {
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
        if self.depth >= MAX_DEPTH {
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

/// Parses `text` under the JSON rules of §10.3 into a value.
pub fn strict_json(text: &str) -> Result<Value, BodyError> {
    let mut d = serde_json::Deserializer::from_str(text);
    let v = Checked { depth: 0 }.deserialize(&mut d).map_err(|e| {
        let msg = e.to_string();
        if msg.contains(DEPTH_ERROR) || msg.contains("recursion limit") {
            BodyError::Depth
        } else if msg.contains(DUPLICATE_ERROR) {
            BodyError::DuplicateKey
        } else {
            BodyError::Json
        }
    })?;
    d.end().map_err(|_| BodyError::Json)?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// The typed submission

/// A decoded submission (§10.3).
#[derive(Clone, PartialEq)]
pub struct Submission {
    /// `invisible` or `pow`: the type the `aad` is computed with.
    pub ty: ChallengeType,
    /// `C` exactly as received (the PoW prefix hashes it, I-18).
    pub c: String,
    pub counter: u64,
    pub ret: String,
    /// Client clock (ms); a feature only.
    pub ts: f64,
    pub build: String,
    pub env: Option<EnvSummary>,
    pub auto: Option<AutomationSummary>,
}

impl fmt::Debug for Submission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never C (§2.4 item 5), nor the return path (it may carry tokens).
        f.debug_struct("Submission")
            .field("ty", &self.ty)
            .field("c_len", &self.c.len())
            .field("build", &self.build)
            .field("env", &self.env.is_some())
            .field("auto", &self.auto)
            .finish_non_exhaustive()
    }
}

fn is_build(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses and checks the submission JSON (see the module documentation).
pub fn parse_submission(text: &str) -> Result<Submission, BodyError> {
    let Value::Object(mut top) = strict_json(text)? else {
        return Err(BodyError::Json);
    };
    let field = |name: &'static str| BodyError::Field(name);
    if top.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(field("v"));
    }
    let ty = match top.get("type").and_then(Value::as_str) {
        Some("invisible") => ChallengeType::Invisible,
        Some("pow") => ChallengeType::Pow,
        _ => return Err(field("type")),
    };
    let c = match top.remove("c") {
        Some(Value::String(c)) if c.len() <= MAX_C => c,
        _ => return Err(field("c")),
    };
    let counter = match top
        .get("pow")
        .and_then(Value::as_object)
        .and_then(|p| p.get("counters"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([n]) => n
            .as_u64()
            .filter(|n| *n < MAX_COUNTER)
            .ok_or(field("pow.counters"))?,
        _ => return Err(field("pow.counters")),
    };
    let ret = match top.remove("ret") {
        Some(Value::String(r)) => r,
        _ => return Err(field("ret")),
    };
    let ts = top.get("ts").and_then(Value::as_f64).ok_or(field("ts"))?;
    let build = match top.remove("build") {
        Some(Value::String(b)) if is_build(&b) => b,
        _ => return Err(field("build")),
    };
    let env = top.remove("env").and_then(EnvSummary::from_value);
    let auto = top.remove("auto").and_then(AutomationSummary::from_value);
    Ok(Submission {
        ty,
        c,
        counter,
        ret,
        ts,
        build,
        env,
        auto,
    })
}

// ---------------------------------------------------------------------------
// env / auto (the SDK schema, v = 1)

/// Cuts `s` to at most `max` bytes on a char boundary.
fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn cut_opt(s: &mut Option<String>) {
    if let Some(s) = s {
        cut(s, MAX_ENV_STRING);
    }
}

/// A finite number (JSON has no other).
fn finite(v: &mut Option<f64>) {
    if v.is_some_and(|x| !x.is_finite()) {
        *v = None;
    }
}

/// `{brand, version}` of the low-entropy UA Client Hints.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Brand {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `env.ua`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UaSummary {
    /// `navigator.userAgent` (truncated by the SDK); compared with the
    /// `User-Agent` header (§10.3 step 8), never written to telemetry.
    #[serde(rename = "userAgent", default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brands: Option<Vec<Brand>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// `env.screen`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Screen {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avail_width: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avail_height: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_depth: Option<f64>,
}

/// `env.viewport`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Viewport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<f64>,
}

/// `env.touch`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Touch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_touch_points: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coarse_pointer: Option<bool>,
}

/// `env.storage`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Storage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookies: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed_db: Option<bool>,
}

/// The SDK's `EnvSummary` (`sdk/web/src/env.ts`, `v = 1`). Every probe may
/// be `null` (I-28); `graphics` (always `null` in Phase 1) and unknown
/// fields are dropped. Serialized for `kind=telemetry` (§13.5) through
/// [`EnvSummary::for_telemetry`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvSummary {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ua: Option<UaSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<Screen>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewport: Option<Viewport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpr: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touch: Option<Touch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<Storage>,
}

impl EnvSummary {
    /// The typed summary of an `env` value; `None` when it does not fit the
    /// schema or `v != 1` (the submission then has no `env`).
    pub fn from_value(v: Value) -> Option<Self> {
        let mut env: Self = serde_json::from_value(v).ok()?;
        (env.v == 1).then_some(())?;
        env.bound();
        Some(env)
    }

    /// Applies the §9.11 caps: strings ≤ 256 bytes, arrays ≤ 16 items.
    fn bound(&mut self) {
        if let Some(ua) = &mut self.ua {
            cut_opt(&mut ua.user_agent);
            cut_opt(&mut ua.platform);
            if let Some(brands) = &mut ua.brands {
                brands.truncate(MAX_ENV_ITEMS);
                for b in brands {
                    cut_opt(&mut b.brand);
                    cut_opt(&mut b.version);
                }
            }
        }
        if let Some(langs) = &mut self.languages {
            langs.truncate(MAX_ENV_ITEMS);
            for l in langs {
                cut(l, MAX_ENV_STRING);
            }
        }
        cut_opt(&mut self.time_zone);
        for n in [
            &mut self.utc_offset_min,
            &mut self.dpr,
            &mut self.cores,
            &mut self.memory_gb,
        ] {
            finite(n);
        }
    }

    /// The submitted `navigator.userAgent`, if any.
    pub fn user_agent(&self) -> Option<&str> {
        self.ua.as_ref()?.user_agent.as_deref()
    }

    /// The summary as `kind=telemetry` carries it: without `ua.userAgent`
    /// (§13.5; the header is already in the decision events).
    pub fn for_telemetry(&self) -> Self {
        let mut env = self.clone();
        if let Some(ua) = &mut env.ua {
            ua.user_agent = None;
        }
        env
    }
}

/// The SDK's `AutomationSummary` (`sdk/web/src/automation.ts`, `v = 1`);
/// `webdriver` is `null` when the property is missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationSummary {
    pub v: u32,
    #[serde(default)]
    pub webdriver: Option<bool>,
}

impl AutomationSummary {
    /// The typed summary of an `auto` value; `None` when it does not fit
    /// the schema or `v != 1`.
    pub fn from_value(v: Value) -> Option<Self> {
        let auto: Self = serde_json::from_value(v).ok()?;
        (auto.v == 1).then_some(auto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = "AAECAwQFBgcICQoLDA0ODw";

    fn body(extra: &str) -> String {
        format!(
            r#"{{"v":1,"type":"pow","c":"{C}","pow":{{"counters":[38467]}},"ret":"/account/login","ts":1790000000123,"build":"0123456789abcdef"{extra}}}"#
        )
    }

    /// What `sdk/web/src/challenge.ts` sends: `URLSearchParams([["mg", json]])`.
    fn urlencode(json: &str) -> Vec<u8> {
        let mut out = b"mg=".to_vec();
        for b in json.bytes() {
            match b {
                b' ' => out.push(b'+'),
                b'*' | b'-' | b'.' | b'_' => out.push(b),
                b if b.is_ascii_alphanumeric() => out.push(b),
                b => out.extend(format!("%{b:02X}").bytes()),
            }
        }
        out
    }

    #[test]
    fn media_types() {
        use MediaKind::*;
        for (ct, want) in [
            ("application/x-www-form-urlencoded", Ok(Form)),
            ("Application/X-WWW-Form-URLEncoded", Ok(Form)),
            ("application/x-www-form-urlencoded; charset=UTF-8", Ok(Form)),
            (
                "application/x-www-form-urlencoded;charset=\"utf-8\"",
                Ok(Form),
            ),
            ("application/json", Ok(Json)),
            ("application/json ; foo=bar; ;", Ok(Json)),
            ("application/json; charset=utf-8; boundary=x", Ok(Json)),
            (
                "application/json; charset=iso-8859-1",
                Err(BodyError::Charset),
            ),
            ("application/json; charset", Err(BodyError::Charset)),
            (
                "application/json; charset=utf-8; charset=latin1",
                Err(BodyError::Charset),
            ),
            ("text/plain", Err(BodyError::MediaType)),
            ("multipart/form-data; boundary=x", Err(BodyError::MediaType)),
            ("application/jsonx", Err(BodyError::MediaType)),
            ("", Err(BodyError::MediaType)),
        ] {
            assert_eq!(media_kind(ct), want, "{ct}");
        }
    }

    /// I-28: `+` is a space; the SDK's form body round-trips.
    #[test]
    fn form_decoding() {
        let json = body(r#","env":{"v":1,"ua":{"userAgent":"Mozilla/5.0 (X11; Linux x86_64)"}}"#);
        let decoded = decode_form(&urlencode(&json)).unwrap();
        assert_eq!(decoded, json);
        let s = parse_submission(&decoded).unwrap();
        assert_eq!(
            s.env.unwrap().user_agent(),
            Some("Mozilla/5.0 (X11; Linux x86_64)")
        );
        assert_eq!(decode_form(b"mg=a+b%2Bc%20d").unwrap(), "a b+c d");
        assert_eq!(decode_form(b"&mg=x&").unwrap(), "x");
        assert_eq!(
            decode_form(b"m%67=x").unwrap(),
            "x",
            "the name is decoded too"
        );
        assert_eq!(decode_form(b"mg=").unwrap(), "");
        for bad in [
            &b""[..],
            b"mg=a&mg=b",
            b"mg=a&x=1",
            b"x=1",
            b"mg=%zz",
            b"mg=%4",
            b"mg=%",
            b"mg=%C3%28",
            b"&&",
        ] {
            assert!(decode_form(bad).is_err(), "{bad:?}");
        }
        assert_eq!(decode_form(b"mg=%2B&").unwrap(), "+");
        // `mg` without `=` is the field with an empty value.
        assert_eq!(decode_form(b"mg").unwrap(), "");
    }

    #[test]
    fn a_valid_submission() {
        let s = parse_submission(&body(r#","extra":{"x":[1,2]}"#)).unwrap();
        assert_eq!(s.ty, ChallengeType::Pow);
        assert_eq!(s.c, C);
        assert_eq!(s.counter, 38467);
        assert_eq!(s.ret, "/account/login");
        assert_eq!(s.build, "0123456789abcdef");
        assert!(s.env.is_none() && s.auto.is_none());
        let s =
            parse_submission(&body("").replace("\"pow\",\"c\"", "\"invisible\",\"c\"")).unwrap();
        assert_eq!(s.ty, ChallengeType::Invisible);
        // I-28: the unknown build of a dev copy of the SDK.
        let s =
            parse_submission(&body("").replace("0123456789abcdef", "0000000000000000")).unwrap();
        assert_eq!(s.build, "0000000000000000");
        // Debug never shows C or the return path.
        let text = format!("{s:?}");
        assert!(
            !text.contains(C) && !text.contains("/account/login"),
            "{text}"
        );
    }

    #[test]
    fn field_rules() {
        let ok = body("");
        for (from, to) in [
            ("\"v\":1", "\"v\":2"),
            ("\"v\":1", "\"v\":1.0"),
            ("\"v\":1,", ""),
            ("\"pow\",\"c\"", "\"interactive\",\"c\""),
            ("\"pow\",\"c\"", "1,\"c\""),
            ("[38467]", "[]"),
            ("[38467]", "[1,2]"),
            ("[38467]", "[-1]"),
            ("[38467]", "[1.5]"),
            ("[38467]", "[\"1\"]"),
            ("[38467]", "[9007199254740992]"),
            ("\"ret\":\"/account/login\"", "\"ret\":1"),
            (
                "\"build\":\"0123456789abcdef\"",
                "\"build\":\"0123456789ABCDEF\"",
            ),
            ("\"build\":\"0123456789abcdef\"", "\"build\":\"0123\""),
            ("\"ts\":1790000000123", "\"ts\":\"x\""),
        ] {
            assert!(ok.contains(from), "{from}");
            let bad = ok.replacen(from, to, 1);
            assert!(parse_submission(&bad).is_err(), "{bad}");
        }
        let long_c = ok.replace(C, &"A".repeat(MAX_C + 1));
        assert_eq!(parse_submission(&long_c), Err(BodyError::Field("c")));
        let max_c = ok.replace(C, &"A".repeat(MAX_C));
        assert!(parse_submission(&max_c).is_ok());
        assert!(parse_submission("[1]").is_err());
        assert!(parse_submission("").is_err());
        assert!(
            parse_submission(&format!("{ok} x")).is_err(),
            "trailing data"
        );
        let top = parse_submission(&ok.replace("[38467]", "[9007199254740991]")).unwrap();
        assert_eq!(top.counter, MAX_COUNTER - 1);
    }

    /// §10.3: a repeated key anywhere and nesting deeper than 16 are `ic.body`.
    #[test]
    fn duplicate_keys_and_depth() {
        let dup = body(r#","ret":"/other""#);
        assert_eq!(parse_submission(&dup), Err(BodyError::DuplicateKey));
        let nested = body(r#","env":{"v":1,"ua":{"mobile":true,"mobile":false}}"#);
        assert_eq!(parse_submission(&nested), Err(BodyError::DuplicateKey));
        // Depth: the top-level object is 1; 15 more levels are fine.
        let deep = |n: usize| body(&format!(r#","x":{}{}"#, "[".repeat(n), "]".repeat(n)));
        assert!(parse_submission(&deep(15)).is_ok());
        assert_eq!(parse_submission(&deep(16)), Err(BodyError::Depth));
        assert_eq!(parse_submission(&deep(500)), Err(BodyError::Depth));
    }

    /// I-28: every probe may be null; unknown fields are dropped; a part
    /// that does not fit the schema is absent, not a failure.
    #[test]
    fn env_and_auto() {
        let env = r#","env":{"v":1,"ua":{"userAgent":null,"brands":null,"mobile":null,"platform":null},
            "languages":null,"timeZone":null,"utcOffsetMin":null,"screen":null,"viewport":null,
            "dpr":null,"cores":null,"memoryGb":null,"touch":{"maxTouchPoints":null,"coarsePointer":null},
            "storage":{"cookies":null,"local":true,"session":true,"indexedDb":false},"graphics":null,
            "future":{"x":1}},"auto":{"v":1,"webdriver":null}"#;
        let s = parse_submission(&body(env)).unwrap();
        let e = s.env.unwrap();
        assert_eq!(e.user_agent(), None);
        assert_eq!(e.storage.unwrap().local, Some(true));
        assert_eq!(
            s.auto,
            Some(AutomationSummary {
                v: 1,
                webdriver: None
            })
        );

        let full = r#","env":{"v":1,"ua":{"userAgent":"UA","brands":[{"brand":"Chromium","version":"131"}],"mobile":false,"platform":"macOS"},
            "languages":["zh-CN","en"],"timeZone":"Asia/Shanghai","utcOffsetMin":480,
            "screen":{"width":1512,"height":982,"availWidth":1510,"availHeight":950,"colorDepth":30},
            "viewport":{"width":1510,"height":860},"dpr":2,"cores":10,"memoryGb":8,
            "touch":{"maxTouchPoints":0,"coarsePointer":false},
            "storage":{"cookies":true,"local":true,"session":true,"indexedDb":true},"graphics":null},
            "auto":{"v":1,"webdriver":true}"#;
        let s = parse_submission(&body(full)).unwrap();
        let e = s.env.unwrap();
        assert_eq!(e.user_agent(), Some("UA"));
        assert_eq!(e.screen.as_ref().unwrap().avail_width, Some(1510.0));
        assert_eq!(s.auto.unwrap().webdriver, Some(true));
        // Telemetry drops ua.userAgent and keeps the rest.
        let t = serde_json::to_value(e.for_telemetry()).unwrap();
        assert!(t["ua"].get("userAgent").is_none());
        assert_eq!(t["ua"]["platform"], "macOS");
        assert_eq!(t["timeZone"], "Asia/Shanghai");

        // Schema mismatches make the part absent.
        for bad in [
            r#","env":{"v":2}"#,
            r#","env":{"v":1,"ua":{"userAgent":5}}"#,
            r#","env":{"v":1,"languages":"zh"}"#,
            r#","env":"x""#,
            r#","env":null"#,
        ] {
            let s = parse_submission(&body(bad)).unwrap();
            assert!(s.env.is_none(), "{bad}");
        }
        for bad in [
            r#","auto":{"v":1,"webdriver":"yes"}"#,
            r#","auto":{"v":2,"webdriver":true}"#,
            r#","auto":[]"#,
        ] {
            let s = parse_submission(&body(bad)).unwrap();
            assert!(s.auto.is_none(), "{bad}");
        }
    }

    #[test]
    fn env_caps() {
        let long = "é".repeat(300);
        let langs: Vec<String> = (0..40).map(|i| format!("\"l{i}\"")).collect();
        let env = format!(
            r#","env":{{"v":1,"ua":{{"userAgent":"{long}"}},"languages":[{}],"timeZone":"{long}"}}"#,
            langs.join(",")
        );
        let e = parse_submission(&body(&env)).unwrap().env.unwrap();
        let ua = e.user_agent().unwrap();
        assert!(ua.len() <= MAX_ENV_STRING && long.starts_with(ua));
        assert_eq!(e.languages.unwrap().len(), MAX_ENV_ITEMS);
        assert!(e.time_zone.unwrap().len() <= MAX_ENV_STRING);
    }

    /// §2.4 item 3: the body parsers never panic (10,000 xorshift inputs
    /// each: random bytes and mutations of a real submission).
    #[test]
    fn random_bodies_never_panic() {
        let seed = urlencode(&body(
            r#","env":{"v":1,"ua":{"userAgent":"a b"}},"auto":{"v":1,"webdriver":false}"#,
        ));
        let json = body(r#","env":{"v":1,"languages":["x"]}"#).into_bytes();
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        const ALPHABET: &[u8] = b"%+&=mg{}[]\",:0123456789aF\\ \xff\xc3";
        for i in 0..10_000 {
            let base = if i % 2 == 0 { &seed } else { &json };
            let mut t = if i % 5 == 0 {
                let len = (next() % 256) as usize;
                (0..len).map(|_| (next() >> 16) as u8).collect()
            } else {
                base.clone()
            };
            for _ in 0..4 {
                if t.is_empty() {
                    break;
                }
                let r = next();
                let at = (r as usize) % t.len();
                t[at] = ALPHABET[(r >> 40) as usize % ALPHABET.len()];
            }
            let _ = decode_form(&t).map(|j| parse_submission(&j));
            if let Ok(text) = std::str::from_utf8(&t) {
                let _ = parse_submission(text);
                let _ = media_kind(text);
            }
        }
    }
}
