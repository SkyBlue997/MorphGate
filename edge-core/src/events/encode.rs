//! Pure encodings shared by every event kind (spec §9.11, §13.2–§13.5): the
//! JSON-line envelope, the decision sampling rule and path redaction.

use mg_core::{Action, RouteSensitivity};
use serde::Serialize;
use std::borrow::Cow;

/// Envelope keys, always the first four keys of a line (§13.2, D-16).
const ENVELOPE_KEYS: [&str; 4] = ["kind", "site", "ts", "msg"];

/// Builds one JSON line: `{"kind":…,"site":…,"ts":…,"msg":…, <body fields>}`.
///
/// * The envelope keys come first, in that order (§13.2); VictoriaLogs uses
///   `kind` and `site` as stream fields, `ts` (Unix ms) as the time field and
///   `msg` as the message field (§13.1).
/// * An object `body` contributes its fields after the envelope; a body field
///   named like an envelope key is dropped, so a line never has duplicate
///   keys. A `null` body contributes nothing; any other value is written
///   under `"body"`.
/// * The result has no trailing newline and, being compact JSON, no raw
///   newline anywhere (strings are escaped).
pub fn envelope(kind: &str, site: &str, ts_ms: i64, msg: &str, body: serde_json::Value) -> String {
    let mut out = Vec::with_capacity(128);
    out.push(b'{');
    write_pair(&mut out, "kind", &kind);
    out.push(b',');
    write_pair(&mut out, "site", &site);
    out.push(b',');
    write_pair(&mut out, "ts", &ts_ms);
    out.push(b',');
    write_pair(&mut out, "msg", &msg);
    match body {
        serde_json::Value::Object(map) => {
            for (key, value) in map.iter() {
                if ENVELOPE_KEYS.contains(&key.as_str()) {
                    continue;
                }
                out.push(b',');
                write_pair(&mut out, key, value);
            }
        }
        serde_json::Value::Null => {}
        other => {
            out.push(b',');
            write_pair(&mut out, "body", &other);
        }
    }
    out.push(b'}');
    // serde_json only emits UTF-8; the lossy conversion never replaces anything.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn write_pair<T: Serialize + ?Sized>(out: &mut Vec<u8>, key: &str, value: &T) {
    write_json(out, key);
    out.push(b':');
    write_json(out, value);
}

/// Appends `value` as JSON. Strings, numbers and `serde_json::Value` cannot
/// fail to serialize into a `Vec`; `null` is written if one ever did.
fn write_json<T: Serialize + ?Sized>(out: &mut Vec<u8>, value: &T) {
    let mark = out.len();
    if serde_json::to_writer(&mut *out, value).is_err() {
        out.truncate(mark);
        out.extend_from_slice(b"null");
    }
}

/// Inputs of the `kind=decision` sampling rule (§9.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleInputs {
    /// The decided action (in monitor mode: the action that would have been taken).
    pub action: Action,
    /// Sensitivity of the selected route.
    pub sensitivity: RouteSensitivity,
    /// A matching rule asked for `force_log`.
    pub force_log: bool,
    /// Some hit is `missing_input`, `eval_error` or `dry_run`.
    pub flagged_hit: bool,
    /// The site ran in monitor mode (global or site-level) for this request.
    pub monitor: bool,
}

/// Sampling rate of one decision event (§9.11): 1 when the action is not
/// ALLOW / TAG / LOG, the route is high / critical, `force_log` is set, a hit
/// is `missing_input` / `eval_error` / `dry_run`, or the site is in monitor
/// mode and the recorded action is not ALLOW; otherwise
/// `events.allow_sample_rate`, clamped to 0..=1 (NaN keeps everything).
/// The returned value is what the event records as `sample_rate`.
pub fn decision_sample_rate(inputs: &SampleInputs, allow_sample_rate: f32) -> f32 {
    let always = !inputs.action.reaches_origin()
        || matches!(
            inputs.sensitivity,
            RouteSensitivity::High | RouteSensitivity::Critical
        )
        || inputs.force_log
        || inputs.flagged_hit
        || (inputs.monitor && inputs.action != Action::Allow);
    if always || allow_sample_rate.is_nan() {
        1.0
    } else {
        allow_sample_rate.clamp(0.0, 1.0)
    }
}

/// Whether to keep an event sampled at `rate`, given a uniform random `draw`
/// (the caller's RNG). `rate >= 1` always keeps, `rate <= 0` never does.
pub fn sample_keep(rate: f32, draw: u32) -> bool {
    if rate.is_nan() || rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }
    (f64::from(draw) + 0.5) < f64::from(rate) * 4_294_967_296.0
}

/// Maximum `path` length of a `kind=access` record in bytes (§13.4).
pub const ACCESS_PATH_MAX_BYTES: usize = 1024;

/// `/<route name>`: the path written in place of the real one when the route
/// has `redact_path` (D-31, §9.11). Applies to the decision event's
/// `ctx.http.path` (whose `query_keys` the caller clears) and to the access
/// record's `path`.
pub fn redacted_path(route_name: &str) -> String {
    format!("/{route_name}")
}

/// The `path` of a `kind=access` record (§13.4): `/<route>` when
/// `redact_route` is set, otherwise the request path without any query
/// string, truncated to [`ACCESS_PATH_MAX_BYTES`] on a character boundary.
pub fn access_path<'a>(path: &'a str, redact_route: Option<&str>) -> Cow<'a, str> {
    if let Some(route) = redact_route {
        return Cow::Owned(redacted_path(route));
    }
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    Cow::Borrowed(truncate_utf8(path, ACCESS_PATH_MAX_BYTES))
}

/// Longest prefix of `s` that is at most `max` bytes and ends on a character
/// boundary.
pub(crate) fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        assert_eq!(truncate_utf8("abc", 5), "abc");
        assert_eq!(truncate_utf8("abc", 2), "ab");
        // "é" is 2 bytes: cutting at 2 would split it.
        assert_eq!(truncate_utf8("aé", 2), "a");
        assert_eq!(truncate_utf8("日本", 4), "日");
        assert_eq!(truncate_utf8("日本", 0), "");
    }

    #[test]
    fn sample_keep_edges() {
        assert!(sample_keep(1.0, u32::MAX));
        assert!(sample_keep(f32::NAN, 0));
        assert!(!sample_keep(0.0, 0));
        assert!(!sample_keep(-1.0, 0));
        assert!(sample_keep(0.5, 0));
        assert!(!sample_keep(0.5, u32::MAX));
        // Roughly the requested fraction over a uniform sweep.
        let kept = (0..10_000u32)
            .filter(|i| sample_keep(0.1, i.wrapping_mul(429_497)))
            .count();
        assert!((900..=1100).contains(&kept), "{kept}");
    }
}
