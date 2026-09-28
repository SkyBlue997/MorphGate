//! DNS for crawler verification: the resolver trait, the static resolver used
//! by tests and the Validation Lab, and the reverse-then-forward rDNS check
//! (spec §7.3, §7.4).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use mg_core::BoxFuture;
use serde::Deserialize;

use crate::crawler::{RdnsJob, RdnsOutcome, is_rdns_suffix};
use crate::error::{IntelError, quote};

/// A failed DNS query.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// The query did not complete in time.
    #[error("DNS timeout")]
    Timeout,
    /// Authoritative "no such record": NXDOMAIN, or NOERROR without answers.
    #[error("no records")]
    NoRecords,
    /// Any other failure (SERVFAIL, REFUSED, transport errors). Never map
    /// these to `NoRecords`: a transient failure would then be cached as a
    /// verification failure (spec §9.6). The text is for logs, so it must not
    /// contain the queried name or address (a PTR name spells the client IP,
    /// D-31): use a fixed description such as the response code.
    #[error("DNS server error: {0}")]
    Server(String),
}

/// Asynchronous DNS lookups. The Edge implements this with hickory (and
/// enforces a per-query timeout, spec §9.6); [`StaticResolver`] serves a fixed
/// table.
pub trait DnsResolver: Send + Sync {
    /// PTR lookup for `ip`; the names may carry a trailing dot.
    fn reverse(&self, ip: IpAddr) -> BoxFuture<'_, Result<Vec<String>, DnsError>>;
    /// A and AAAA lookup. [`resolve_rdns`] passes fully-qualified, lower-case
    /// names with a trailing dot (e.g. `crawl-1.googlebot.com.`) so a
    /// resolver's search domains never apply.
    fn forward(&self, name: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, DnsError>>;
}

/// At most this many PTR names are considered (spec §7.3).
pub const MAX_PTR_NAMES: usize = 5;

/// Longest DNS name, in bytes, without the trailing dot.
const MAX_NAME_LEN: usize = 253;

/// Runs the rDNS verification for a job: one PTR query, then a forward query
/// for each of at most [`MAX_PTR_NAMES`] names that ends with one of the
/// job's suffixes on a label boundary (case-insensitive, the name's trailing
/// dot ignored). A suffix is a leading `.` and at least two labels (ruling
/// I-22): `.googlebot.com` matches `crawl-1.googlebot.com` but neither
/// `googlebot.com` nor `evilgooglebot.com`; a suffix of any other shape
/// matches nothing.
///
/// * a forward answer contains the job's address → `Pass`;
/// * otherwise, any `Timeout` / `Server` error → `DnsError`;
/// * otherwise (PTR `NoRecords`, no matching name, forward answers without the
///   address or `NoRecords`) → `Fail`.
///
/// So at most 1 PTR and 5 forward queries run. Per-query timeouts belong to
/// the resolver; the caller bounds the whole future (spec §9.6).
pub async fn resolve_rdns(job: &RdnsJob, resolver: &dyn DnsResolver) -> RdnsOutcome {
    let ip = job.ip.to_canonical();
    let names = match resolver.reverse(ip).await {
        Ok(names) => names,
        Err(DnsError::NoRecords) => return RdnsOutcome::Fail,
        Err(DnsError::Timeout | DnsError::Server(_)) => return RdnsOutcome::DnsError,
    };
    let mut seen = HashSet::new();
    let mut saw_error = false;
    for raw in names.iter().take(MAX_PTR_NAMES) {
        let Some(name) = normalize_name(raw) else {
            continue;
        };
        if !job.suffixes.iter().any(|s| suffix_matches(&name, s)) || !seen.insert(name.clone()) {
            continue;
        }
        match resolver.forward(&format!("{name}.")).await {
            Ok(addrs) => {
                if addrs.iter().any(|a| a.to_canonical() == ip) {
                    return RdnsOutcome::Pass;
                }
            }
            Err(DnsError::NoRecords) => {}
            Err(DnsError::Timeout | DnsError::Server(_)) => saw_error = true,
        }
    }
    if saw_error {
        RdnsOutcome::DnsError
    } else {
        RdnsOutcome::Fail
    }
}

/// Lower-cases a DNS name and drops one trailing dot. Returns `None` for
/// names that cannot be valid host names (empty, empty labels, too long).
fn normalize_name(raw: &str) -> Option<String> {
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.split('.').any(str::is_empty) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Label-boundary suffix match (ruling I-22). `name` is normalised
/// (lower-case, no trailing dot, no empty labels); `suffix` must have the
/// registry shape ([`is_rdns_suffix`]: leading `.`, at least two labels), or
/// nothing matches, so a job built by hand with a bare `googlebot.com` or a
/// one-label `.com` fails closed. The suffix's leading dot is the label
/// separator, and at least one label of `name` must precede it.
pub(crate) fn suffix_matches(name: &str, suffix: &str) -> bool {
    is_rdns_suffix(suffix)
        && name.len() > suffix.len()
        && name.as_bytes()[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// A resolver that answers from a fixed JSON table (tests and the Validation
/// Lab; the Edge's `dns_resolver = "static:<path>"`):
///
/// ```json
/// {"v": 1,
///  "ptr": {"198.51.100.7": ["crawl-198-51-100-7.googlebot.com."]},
///  "a":   {"crawl-198-51-100-7.googlebot.com": ["198.51.100.7"]}}
/// ```
///
/// `a` holds both IPv4 and IPv6 answers. Names match case-insensitively with
/// or without a trailing dot; addresses match in canonical form. Anything not
/// in the table is `NoRecords`.
pub struct StaticResolver {
    ptr: HashMap<IpAddr, Vec<String>>,
    forward: HashMap<String, Vec<IpAddr>>,
}

impl fmt::Debug for StaticResolver {
    /// Sizes only: the table maps addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticResolver")
            .field("ptr_entries", &self.ptr.len())
            .field("a_entries", &self.forward.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticDoc {
    v: u64,
    #[serde(default)]
    ptr: HashMap<String, Vec<String>>,
    #[serde(default)]
    a: HashMap<String, Vec<String>>,
}

impl StaticResolver {
    /// Parses the JSON table. Keys of `ptr` and values of `a` must be IP
    /// addresses; keys of `a` must be valid names.
    pub fn from_json(json: &[u8]) -> Result<Self, IntelError> {
        let doc: StaticDoc = serde_json::from_slice(json).map_err(|e| IntelError::json(&e))?;
        if doc.v != 1 {
            return Err(IntelError::invalid(format!("unsupported v {}", doc.v)));
        }
        let mut ptr = HashMap::with_capacity(doc.ptr.len());
        for (key, names) in doc.ptr {
            let ip: IpAddr = key.parse().map_err(|_| {
                IntelError::invalid(format!("ptr key {} is not an IP address", quote(&key)))
            })?;
            ptr.entry(ip.to_canonical())
                .or_insert_with(Vec::new)
                .extend(names);
        }
        let mut forward = HashMap::with_capacity(doc.a.len());
        for (key, values) in doc.a {
            let name = normalize_name(&key).ok_or_else(|| {
                IntelError::invalid(format!("a key {} is not a DNS name", quote(&key)))
            })?;
            let mut addrs = Vec::with_capacity(values.len());
            for v in &values {
                let ip: IpAddr = v.parse().map_err(|_| {
                    IntelError::invalid(format!(
                        "a[{}] value {} is not an IP address",
                        quote(&key),
                        quote(v)
                    ))
                })?;
                addrs.push(ip);
            }
            forward.entry(name).or_insert_with(Vec::new).extend(addrs);
        }
        Ok(Self { ptr, forward })
    }

    fn reverse_now(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr
            .get(&ip.to_canonical())
            .cloned()
            .ok_or(DnsError::NoRecords)
    }

    fn forward_now(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        normalize_name(name)
            .and_then(|n| self.forward.get(&n).cloned())
            .ok_or(DnsError::NoRecords)
    }
}

impl DnsResolver for StaticResolver {
    fn reverse(&self, ip: IpAddr) -> BoxFuture<'_, Result<Vec<String>, DnsError>> {
        Box::pin(std::future::ready(self.reverse_now(ip)))
    }

    fn forward(&self, name: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, DnsError>> {
        Box::pin(std::future::ready(self.forward_now(name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §7.3 / I-22: suffixes match only on a label boundary, and only
    /// suffixes of the registry shape (leading `.`, at least two labels)
    /// match at all.
    #[test]
    fn suffix_matching() {
        let cases = [
            ("crawl-1.googlebot.com", ".googlebot.com", true),
            ("a.b.googlebot.com", ".googlebot.com", true),
            ("crawl-1.googlebot.com", ".GoogleBot.com", true),
            ("x.search.msn.com", ".search.msn.com", true),
            ("googlebot.com", ".googlebot.com", false),
            ("evilgooglebot.com", ".googlebot.com", false),
            ("crawl.evilgooglebot.com", ".googlebot.com", false),
            ("crawl.googlebot.com.evil.test", ".googlebot.com", false),
            ("msn.com", ".search.msn.com", false),
            ("xsearch.msn.com", ".search.msn.com", false),
            // Not the registry shape: never matches, fails closed.
            ("googlebot.com", "googlebot.com", false),
            ("evilgooglebot.com", "googlebot.com", false),
            ("crawl.googlebot.com", "googlebot.com", false),
            ("crawl-1.googlebot.com", ".googlebot.com.", false),
            ("crawl-1.googlebot.com", ".com", false),
            ("crawl-1.googlebot.com", "com", false),
            ("a..googlebot.com", "..googlebot.com", false),
            ("x.com", ".", false),
            ("x.com", "", false),
        ];
        for (name, suffix, want) in cases {
            assert_eq!(suffix_matches(name, suffix), want, "{name} vs {suffix}");
        }
    }

    #[test]
    fn name_normalization() {
        assert_eq!(
            normalize_name("Crawl.GoogleBot.COM.").as_deref(),
            Some("crawl.googlebot.com")
        );
        assert_eq!(normalize_name("a.b").as_deref(), Some("a.b"));
        for bad in ["", ".", "..", "a..b", ".a.b", "a.b..", &"a".repeat(254)] {
            assert_eq!(normalize_name(bad), None, "{bad:?}");
        }
    }
}
