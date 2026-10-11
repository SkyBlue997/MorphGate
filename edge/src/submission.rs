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
//! Phase 2 (docs/impl/phase2-spec.md §7.4, §7.5, WP-E2a):
//!
//! * **Submission v2** (`v = 2`): `type` `invisible` | `pow` |
//!   `interactive`; `p` (the provider, interactive only; empty or absent
//!   otherwise); `pp` a string of at most 4096 bytes; `t` a string of at most
//!   2048 bytes holding a JSON object (`env`, `auto`, `ix`, parsed by
//!   `mg_edge_core::events::telemetry_v2`, the single implementation of
//!   §15.2; a `t` that is not an object fails the submission); 1-8
//!   `pow.counters`; `ts` an integer `0..2^53`; `jwk` an object and `sig` a
//!   string, both required (I-45: their content is checked later, `ic.sig`).
//!   Top-level `env` / `auto` are ignored in v2.
//! * **Renewal** (`POST /__mg/c/renew`, [`parse_renew`]): `{"v": 2, "c",
//!   "jwk", "ts", "sig"}` under the same JSON rules.
//!
//! Every failure is the reason `ic.body`; the caller answers with the uniform
//! failure. Nothing here logs or keeps the submitted values beyond the typed
//! result.

use mg_challenge::{SessionKey, SubmissionFields, renew_message, submission_message};
use mg_core::{ChallengeType, IxTelemetry};
use mg_edge_core::events::{ChallengeTelemetry, T_MAX_BYTES, TelemetryAuto, TelemetryEnv};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
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
/// Most `pow.counters` of a v2 submission (PoW v2 sub-puzzles).
pub const MAX_COUNTERS: usize = 8;
/// Longest `pp` (bytes), Phase 2 spec §7.5.
pub const MAX_PP: usize = 4096;
/// Longest `t` (bytes), Phase 2 spec §7.5.
pub const MAX_T: usize = T_MAX_BYTES;
/// Longest `sig` accepted before verification (86 characters when valid).
pub const MAX_SIG: usize = 256;
/// Largest `ts` of a v2 submission or a renewal (exclusive): `2^53`.
pub const MAX_TS: u64 = 1 << 53;

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

/// A decoded submission (§10.3; v2: Phase 2 spec §7.5).
#[derive(Clone, PartialEq)]
pub struct Submission {
    /// 1 (Phase 1) or 2.
    pub v: u8,
    /// `invisible`, `pow` or (v2) `interactive`: the type the `aad` is
    /// computed with.
    pub ty: ChallengeType,
    /// `C` exactly as received (the PoW prefix hashes it, I-18).
    pub c: String,
    /// v1: exactly one; v2: 1-8.
    pub counters: Vec<u64>,
    pub ret: String,
    /// Client clock (ms); a feature only (v2: an integer, signed).
    pub ts: f64,
    pub build: String,
    /// v1: the top-level `env` / `auto`; v2: those of `t`. Parsed by
    /// edge-core's single telemetry implementation (Phase 2 spec §15.2).
    pub env: Option<TelemetryEnv>,
    pub auto: Option<TelemetryAuto>,
    /// v2 only (empty in v1).
    pub v2: Option<SubmissionV2>,
}

/// The v2 members of a submission (Phase 2 spec §7.5).
#[derive(Clone, PartialEq)]
pub struct SubmissionV2 {
    /// The provider id (interactive; empty otherwise).
    pub p: String,
    /// The provider's token (Turnstile) or empty.
    pub pp: String,
    /// `t` as received (its UTF-8 bytes are signed).
    pub t: String,
    /// `ts` as the integer that is signed.
    pub ts: u64,
    /// The `jwk` object, re-serialized (its content is checked at step 8).
    pub jwk: String,
    pub sig: String,
    /// `t.ix` (§7.6), when present and valid.
    pub ix: Option<IxTelemetry>,
    /// `t.ix` was present but did not fit §7.6 (it was dropped).
    pub ix_rejected: bool,
}

impl fmt::Debug for SubmissionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the key, the signature, the provider token or the telemetry
        // (§2.4 item 10).
        f.debug_struct("SubmissionV2")
            .field("p", &self.p)
            .field("pp_len", &self.pp.len())
            .field("t_len", &self.t.len())
            .field("ix", &self.ix.is_some())
            .field("ix_rejected", &self.ix_rejected)
            .finish_non_exhaustive()
    }
}

impl Submission {
    /// `counters[0]` (v1 has exactly one).
    pub fn counter(&self) -> u64 {
        self.counters.first().copied().unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for Submission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never C (§2.4 item 5), nor the return path (it may carry tokens).
        f.debug_struct("Submission")
            .field("v", &self.v)
            .field("ty", &self.ty)
            .field("p", &self.v2.as_ref().map(|v| v.p.as_str()))
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
    let v = match top.get("v").and_then(Value::as_u64) {
        Some(1) => 1u8,
        Some(2) => 2,
        _ => return Err(field("v")),
    };
    let ty = match top.get("type").and_then(Value::as_str) {
        Some("invisible") => ChallengeType::Invisible,
        Some("pow") => ChallengeType::Pow,
        Some("interactive") if v == 2 => ChallengeType::Interactive,
        _ => return Err(field("type")),
    };
    let c = match top.remove("c") {
        Some(Value::String(c)) if c.len() <= MAX_C => c,
        _ => return Err(field("c")),
    };
    let counters: Vec<u64> = match top
        .get("pow")
        .and_then(Value::as_object)
        .and_then(|p| p.get("counters"))
        .and_then(Value::as_array)
    {
        Some(list)
            if (v == 1 && list.len() == 1)
                || (v == 2 && (1..=MAX_COUNTERS).contains(&list.len())) =>
        {
            list.iter()
                .map(|n| n.as_u64().filter(|n| *n < MAX_COUNTER))
                .collect::<Option<_>>()
                .ok_or(field("pow.counters"))?
        }
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
    if v == 1 {
        let env = top.remove("env").and_then(|v| TelemetryEnv::from_value(&v));
        let auto = top
            .remove("auto")
            .and_then(|v| TelemetryAuto::from_value(&v));
        return Ok(Submission {
            v,
            ty,
            c,
            counters,
            ret,
            ts,
            build,
            env,
            auto,
            v2: None,
        });
    }
    let ts_int = top
        .get("ts")
        .and_then(Value::as_u64)
        .filter(|t| *t < MAX_TS)
        .ok_or(field("ts"))?;
    let string =
        |top: &mut Map<String, Value>, name: &'static str, max: usize| match top.remove(name) {
            None => Ok(String::new()),
            Some(Value::String(s)) if s.len() <= max => Ok(s),
            Some(_) => Err(field(name)),
        };
    let p = string(&mut top, "p", 32)?;
    if (ty == ChallengeType::Interactive) == p.is_empty() {
        return Err(field("p"));
    }
    let pp = string(&mut top, "pp", MAX_PP)?;
    let t = string(&mut top, "t", MAX_T)?;
    let jwk = match top.remove("jwk") {
        Some(j @ Value::Object(_)) => serde_json::to_string(&j).map_err(|_| field("jwk"))?,
        _ => return Err(field("jwk")),
    };
    let sig = match top.remove("sig") {
        Some(Value::String(s)) if s.len() <= MAX_SIG => s,
        _ => return Err(field("sig")),
    };
    // `t`: one JSON object; its parts as in §15.2.
    let (env, auto, ix, ix_rejected) = if t.is_empty() {
        (None, None, None, false)
    } else {
        let tel = ChallengeTelemetry::parse(&t).map_err(|_| field("t"))?;
        (tel.env, tel.auto, tel.ix, tel.ix_rejected)
    };
    Ok(Submission {
        v,
        ty,
        c,
        counters,
        ret,
        ts,
        build,
        env,
        auto,
        v2: Some(SubmissionV2 {
            p,
            pp,
            t,
            ts: ts_int,
            jwk,
            sig,
            ix,
            ix_rejected,
        }),
    })
}

/// The session key of a v2 submission or a renewal (`jwk`, Phase 2 spec
/// §6.5); `None` when it is not exactly the four members of a P-256 key
/// (I-45: `ic.sig`).
pub fn session_key(jwk: &str) -> Option<SessionKey> {
    SessionKey::from_jwk_json(jwk.as_bytes()).ok()
}

/// Whether `key` signed the v2 submission `sub` (`mg-sub-v2`, Phase 2 spec
/// §6.6); always false for a v1 submission.
pub fn submission_signature_ok(sub: &Submission, key: &SessionKey) -> bool {
    let Some(v2) = &sub.v2 else {
        return false;
    };
    let msg = submission_message(&SubmissionFields {
        c: &sub.c,
        ty: sub.ty.as_str(),
        p: &v2.p,
        pp: &v2.pp,
        t: &v2.t,
        counters: &sub.counters,
        ret: &sub.ret,
        ts: v2.ts,
        build: &sub.build,
    });
    key.verify_es256(&msg, &v2.sig)
}

/// Whether `key` signed the renewal `r` (`mg-renew-v1`, Phase 2 spec §6.6).
pub fn renew_signature_ok(r: &Renewal, key: &SessionKey) -> bool {
    key.verify_es256(&renew_message(&r.c, r.ts), &r.sig)
}

/// A decoded renewal (`POST /__mg/c/renew`, Phase 2 spec §7.4).
#[derive(Clone, PartialEq, Eq)]
pub struct Renewal {
    /// `C` exactly as received.
    pub c: String,
    /// The `jwk` object, re-serialized (checked at step 5 / 6).
    pub jwk: String,
    pub ts: u64,
    pub sig: String,
}

impl fmt::Debug for Renewal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Renewal")
            .field("c_len", &self.c.len())
            .finish_non_exhaustive()
    }
}

/// Parses a renewal body: `{"v": 2, "c", "jwk", "ts", "sig"}` under the
/// JSON rules of §10.3 (unknown top-level fields ignored).
pub fn parse_renew(text: &str) -> Result<Renewal, BodyError> {
    let Value::Object(mut top) = strict_json(text)? else {
        return Err(BodyError::Json);
    };
    let field = |name: &'static str| BodyError::Field(name);
    if top.get("v").and_then(Value::as_u64) != Some(2) {
        return Err(field("v"));
    }
    let c = match top.remove("c") {
        Some(Value::String(c)) if c.len() <= MAX_C => c,
        _ => return Err(field("c")),
    };
    let ts = top
        .get("ts")
        .and_then(Value::as_u64)
        .filter(|t| *t < MAX_TS)
        .ok_or(field("ts"))?;
    let jwk = match top.remove("jwk") {
        Some(j @ Value::Object(_)) => serde_json::to_string(&j).map_err(|_| field("jwk"))?,
        _ => return Err(field("jwk")),
    };
    let sig = match top.remove("sig") {
        Some(Value::String(s)) if s.len() <= MAX_SIG => s,
        _ => return Err(field("sig")),
    };
    Ok(Renewal { c, jwk, ts, sig })
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
        assert_eq!(s.counters, vec![38467]);
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
        assert_eq!(top.counter(), MAX_COUNTER - 1);
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

    /// I-28: every probe may be null; unknown fields are dropped; a field
    /// of the wrong type is null, a part that does not fit the schema is
    /// absent, never a failure (edge-core's single implementation, §15.2).
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
        assert_eq!(e.storage.local, Some(true));
        assert_eq!(s.auto.unwrap().webdriver, None);

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
        assert_eq!(s.auto.unwrap().webdriver, Some(true));
        // Telemetry drops ua.userAgent and keeps the rest.
        let t = e.to_value();
        assert!(t["ua"].get("userAgent").is_none());
        assert_eq!(t["ua"]["platform"], "macOS");
        assert_eq!(t["timeZone"], "Asia/Shanghai");
        assert_eq!(t["screen"]["availWidth"], 1510);

        // A wrong field type is null; a wrong version or shape drops the part.
        let s = parse_submission(&body(
            r#","env":{"v":1,"ua":{"userAgent":5},"languages":"zh"}"#,
        ))
        .unwrap();
        let e = s.env.unwrap();
        assert_eq!((e.user_agent(), e.languages.as_ref()), (None, None));
        for bad in [r#","env":{"v":2}"#, r#","env":"x""#, r#","env":null"#] {
            let s = parse_submission(&body(bad)).unwrap();
            assert!(s.env.is_none(), "{bad}");
        }
        for bad in [r#","auto":{"v":2,"webdriver":true}"#, r#","auto":[]"#] {
            let s = parse_submission(&body(bad)).unwrap();
            assert!(s.auto.is_none(), "{bad}");
        }
        let s = parse_submission(&body(r#","auto":{"v":1,"webdriver":"yes"}"#)).unwrap();
        assert_eq!(s.auto.unwrap().webdriver, None);
    }

    #[test]
    fn env_caps() {
        use mg_edge_core::events::{TELEMETRY_MAX_ARRAY_ITEMS, TELEMETRY_MAX_STRING_BYTES};
        let long = "é".repeat(300);
        let langs: Vec<String> = (0..40).map(|i| format!("\"l{i}\"")).collect();
        let env = format!(
            r#","env":{{"v":1,"ua":{{"userAgent":"{long}"}},"languages":[{}],"timeZone":"{long}"}}"#,
            langs.join(",")
        );
        let e = parse_submission(&body(&env)).unwrap().env.unwrap();
        let ua = e.user_agent().unwrap();
        assert!(ua.len() <= TELEMETRY_MAX_STRING_BYTES && long.starts_with(ua));
        assert_eq!(e.languages.unwrap().len(), TELEMETRY_MAX_ARRAY_ITEMS);
        assert!(e.time_zone.unwrap().len() <= TELEMETRY_MAX_STRING_BYTES);
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

    /// Phase 2 spec §2.4 item 9: the v2 and renewal parsers and the
    /// signature checks never panic (10,000 xorshift edits of the shared
    /// valid samples, and random bytes).
    #[test]
    fn random_v2_bodies_never_panic() {
        let dir = crate::test_support::repo("testdata/phase2/samples/submissions/valid");
        let seeds: Vec<Vec<u8>> = ["interactive-self-hold.json", "pow.json", "renew.json"]
            .iter()
            .map(|f| std::fs::read(dir.join(f)).unwrap())
            .collect();
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        const ALPHABET: &[u8] = b"{}[]\",:0123456789aFx\\ -_.\xff\xc3";
        for i in 0..10_000 {
            let mut t = if i % 7 == 0 {
                let len = (next() % 512) as usize;
                (0..len).map(|_| (next() >> 16) as u8).collect()
            } else {
                seeds[i % seeds.len()].clone()
            };
            for _ in 0..(1 + next() % 4) {
                if t.is_empty() {
                    break;
                }
                let r = next();
                let at = (r as usize) % t.len();
                t[at] = ALPHABET[(r >> 40) as usize % ALPHABET.len()];
            }
            let Ok(text) = std::str::from_utf8(&t) else {
                continue;
            };
            if let Ok(sub) = parse_submission(text)
                && let Some(key) = sub.v2.as_ref().and_then(|v| session_key(&v.jwk))
            {
                let _ = submission_signature_ok(&sub, &key);
            }
            if let Ok(r) = parse_renew(text)
                && let Some(key) = session_key(&r.jwk)
            {
                let _ = renew_signature_ok(&r, &key);
            }
        }
    }

    /// The shared samples of `testdata/phase2/samples/submissions/` (Phase 2
    /// spec §7.4, §7.5, I-45): every `ok` body parses and its signature
    /// verifies, every `ic.body` body is refused by the parser, every
    /// `ic.sig` body parses but its key or signature does not verify.
    #[test]
    fn phase2_submission_samples() {
        let dir = crate::test_support::repo("testdata/phase2/samples/submissions");
        let cases: Value =
            serde_json::from_slice(&std::fs::read(dir.join("cases.json")).unwrap()).unwrap();
        let mut seen = 0;
        for case in cases["cases"].as_array().unwrap() {
            let file = case["file"].as_str().unwrap();
            let expect = case["expect"].as_str().unwrap();
            let renew = case["endpoint"] == "/__mg/c/renew";
            let bytes = std::fs::read(dir.join(file)).unwrap();
            if bytes.len() > MAX_BODY {
                assert_eq!(expect, "ic.body", "{file}");
                seen += 1;
                continue;
            }
            let text = String::from_utf8(bytes).unwrap();
            let text = text.strip_suffix('\n').unwrap_or(&text);
            let verified = if renew {
                parse_renew(text)
                    .map(|r| session_key(&r.jwk).is_some_and(|k| renew_signature_ok(&r, &k)))
            } else {
                parse_submission(text).map(|s| {
                    let jwk = s.v2.as_ref().map(|v| v.jwk.clone()).unwrap_or_default();
                    session_key(&jwk).is_some_and(|k| submission_signature_ok(&s, &k))
                })
            };
            match expect {
                "ok" => assert_eq!(verified, Ok(true), "{file}"),
                "ic.sig" => assert_eq!(verified, Ok(false), "{file}"),
                "ic.body" => assert!(verified.is_err(), "{file}: {verified:?}"),
                other => panic!("{file}: unknown expectation {other}"),
            }
            seen += 1;
        }
        assert!(seen >= 30, "{seen}");
        // The parsed parts of a valid interactive submission.
        let text = std::fs::read_to_string(dir.join("valid/interactive-self-hold.json")).unwrap();
        let s = parse_submission(text.trim_end()).unwrap();
        let v2 = s.v2.as_ref().unwrap();
        assert_eq!(
            (s.v, s.ty, v2.p.as_str()),
            (2, ChallengeType::Interactive, "self_hold")
        );
        assert_eq!(s.counters.len(), 8);
        assert_eq!(
            v2.ix.as_ref().map(|ix| ix.mode),
            Some(mg_core::IxMode::Hold)
        );
        let text = format!("{s:?}");
        assert!(
            !text.contains(&v2.sig) && !text.contains("rrXA79"),
            "{text}"
        );
    }
}
