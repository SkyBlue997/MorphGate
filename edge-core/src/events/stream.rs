//! `mg:ev` stream entries (spec §13.6) and the writer the flusher hands them to.

use crate::state::StateHandle;
use mg_core::{Action, BotClass, BoxFuture, ChallengeType, VerdictOutcome};

/// Stream key.
pub const STREAM_KEY: &str = "mg:ev";

/// Value of every entry's leading `v` field.
pub const STREAM_ENTRY_VERSION: &str = "1";

/// Writes a batch of `mg:ev` entries (§9.11, §13.6).
///
/// [`StateHandle`] implements it (ruling I-25) with
/// `StateHandle::xadd_batch`, so the Valkey I/O happens on the `mg-state`
/// runtime: one pipeline of `XADD mg:ev MAXLEN ~ <maxlen> * <field> <value>
/// …`, one command per entry, fields in [`StreamEntry::fields`] order. The
/// flusher never retries a failed batch; it counts
/// `mg_event_dropped_total{sink="stream"}`.
///
/// This is the object-safe form of `async fn xadd_batch` (the flusher holds
/// an `Arc<dyn StreamWriter>`).
pub trait StreamWriter: Send + Sync {
    fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>>;
}

/// The production writer (ruling I-25): the entries go to `mg-state` as one
/// `XADD` pipeline. In local mode, while Valkey is down or the breaker is
/// open, the batch fails with the state layer's error text (no key or entry
/// content is ever part of it), and the flusher counts the drop.
impl StreamWriter for StateHandle {
    fn xadd_batch(
        &self,
        maxlen: u64,
        entries: Vec<StreamEntry>,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let entries = entries.into_iter().map(StreamEntry::into_fields).collect();
            StateHandle::xadd_batch(self, maxlen, entries)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// One `mg:ev` entry: an ordered list of field / value pairs (§13.6).
///
/// Build it with [`StreamEntry::decision`] or [`StreamEntry::feedback`]; the
/// field order is part of the contract with the near-line consumers. Entries
/// never contain a client IP in clear or `client_conn_key`: IPs appear only as
/// the keyed hashes `ipk` / `pfk` computed by the caller (`state::kh`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    fields: Vec<(&'static str, String)>,
}

/// Inputs of a `kind decision` entry (one per non-`/__mg` request, unsampled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionEntry<'a> {
    pub site: &'a str,
    /// Unix milliseconds.
    pub ts_ms: i64,
    pub request_id: &'a str,
    /// Clearance token `sub`; `None` = no session (`""`).
    pub session: Option<&'a str>,
    /// Route name.
    pub route: &'a str,
    /// Decided action (in monitor mode: the action that would have been taken).
    pub action: Action,
    pub dry_run: bool,
    pub class: BotClass,
    /// 0..=100; larger values are clamped.
    pub score: u8,
    /// `kh(ip entity)`, the `ip` verdict key; `None` when the client IP is unknown.
    pub ipk: Option<&'a str>,
    /// `kh(prefix)`, the `prefix` verdict key; `None` when the client IP is unknown.
    pub pfk: Option<&'a str>,
    /// ASN; `None` (unknown) is written as 0.
    pub asn: Option<u32>,
    /// HTTP status sent to the client; `None` is written as 0.
    pub status: Option<u16>,
}

/// Inputs of a `kind feedback` entry (one per `POST /__mg/c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackEntry<'a> {
    pub site: &'a str,
    pub ts_ms: i64,
    pub request_id: &'a str,
    /// The challenge's `route_class` route.
    pub route: &'a str,
    pub outcome: VerdictOutcome,
    pub challenge_type: ChallengeType,
    pub pfk: Option<&'a str>,
    pub asn: Option<u32>,
}

impl StreamEntry {
    /// `v 1 kind decision site ts rid sess route action dry class score ipk pfk asn status`.
    pub fn decision(e: &DecisionEntry<'_>) -> Self {
        Self {
            fields: vec![
                ("v", STREAM_ENTRY_VERSION.to_owned()),
                ("kind", "decision".to_owned()),
                ("site", e.site.to_owned()),
                ("ts", e.ts_ms.to_string()),
                ("rid", e.request_id.to_owned()),
                ("sess", e.session.unwrap_or("").to_owned()),
                ("route", e.route.to_owned()),
                ("action", e.action.as_str().to_owned()),
                ("dry", if e.dry_run { "1" } else { "0" }.to_owned()),
                ("class", e.class.as_str().to_owned()),
                ("score", e.score.min(100).to_string()),
                ("ipk", e.ipk.unwrap_or("").to_owned()),
                ("pfk", e.pfk.unwrap_or("").to_owned()),
                ("asn", e.asn.unwrap_or(0).to_string()),
                ("status", e.status.unwrap_or(0).to_string()),
            ],
        }
    }

    /// `v 1 kind feedback site ts rid route outcome type pfk asn`.
    pub fn feedback(e: &FeedbackEntry<'_>) -> Self {
        Self {
            fields: vec![
                ("v", STREAM_ENTRY_VERSION.to_owned()),
                ("kind", "feedback".to_owned()),
                ("site", e.site.to_owned()),
                ("ts", e.ts_ms.to_string()),
                ("rid", e.request_id.to_owned()),
                ("route", e.route.to_owned()),
                ("outcome", e.outcome.as_str().to_owned()),
                ("type", e.challenge_type.as_str().to_owned()),
                ("pfk", e.pfk.unwrap_or("").to_owned()),
                ("asn", e.asn.unwrap_or(0).to_string()),
            ],
        }
    }

    /// Field / value pairs in `XADD` order.
    pub fn fields(&self) -> &[(&'static str, String)] {
        &self.fields
    }

    /// The pairs, for `StateHandle::xadd_batch`.
    pub fn into_fields(self) -> Vec<(&'static str, String)> {
        self.fields
    }

    /// Value of the `kind` field (`decision` / `feedback`).
    pub fn kind(&self) -> &str {
        self.get("kind").unwrap_or("")
    }

    /// Value of `field`, if present.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| *name == field)
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_entry_unknown_values_use_spec_placeholders() {
        let e = StreamEntry::decision(&DecisionEntry {
            site: "blog",
            ts_ms: 5,
            request_id: "r",
            session: None,
            route: "default",
            action: Action::Allow,
            dry_run: false,
            class: BotClass::Unknown,
            score: 250,
            ipk: None,
            pfk: None,
            asn: None,
            status: None,
        });
        assert_eq!(e.kind(), "decision");
        assert_eq!(e.get("sess"), Some(""));
        assert_eq!(e.get("ipk"), Some(""));
        assert_eq!(e.get("pfk"), Some(""));
        assert_eq!(e.get("asn"), Some("0"));
        assert_eq!(e.get("status"), Some("0"));
        assert_eq!(e.get("score"), Some("100"), "clamped to 0..=100");
        assert_eq!(e.get("dry"), Some("0"));
        assert_eq!(e.get("nope"), None);
    }
}
