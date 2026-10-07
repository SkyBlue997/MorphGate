//! Application logging (docs/impl/phase1-spec.md D-31, §2.4 item 5, §9.11):
//! `env_logger` behind a filter that keeps client addresses, cookies and keys
//! out of the logs at every level.
//!
//! mg-edge's own messages never contain a client IP. Pingora's do in a few
//! places: a failed TLS handshake is logged as `Downstream handshake error
//! from <peer>: …` (on a `direct_tls` listener the peer is the visitor), and
//! the critical file-descriptor mismatch messages print the peer too. Every
//! record from those Pingora modules has its IP addresses replaced by
//! `<redacted>` before it is written; other records pass through unchanged
//! (they carry listen and origin addresses that operators need).
//!
//! Pingora's `debug` and `trace` records are dropped altogether
//! ([`suppressed`]): they dump whole requests (the parsed request, the header
//! sent to the origin, the raw buffer of a request its parser rejected), with
//! `Cookie`, `CF-Connecting-IP`, `MG-Client-IP` and `x-mg-upstream-key`
//! values that no pattern-based redaction can reliably find. mg-edge's own
//! debug output (`mg_edge=debug`) is unaffected.

use log::{Level, Log, Metadata, Record};
use std::net::{IpAddr, SocketAddr};

/// Log targets whose messages may contain a client address.
const REDACTED_TARGETS: [&str; 2] = [
    "pingora_core::services::listening",
    "pingora_core::protocols",
];

/// What replaces an address.
pub const REDACTED: &str = "<redacted>";

/// `env_logger` with address redaction for `REDACTED_TARGETS`.
#[derive(Debug)]
pub struct RedactingLogger {
    inner: env_logger::Logger,
}

/// Whether a record is never written, whatever `RUST_LOG` says: Pingora's
/// `debug` / `trace` output (see the module documentation).
pub fn suppressed(target: &str, level: Level) -> bool {
    level > Level::Info && target.starts_with("pingora")
}

impl Log for RedactingLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        !suppressed(metadata.target(), metadata.level()) && self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if suppressed(record.target(), record.level()) || !self.inner.matches(record) {
            return;
        }
        if REDACTED_TARGETS
            .iter()
            .any(|t| record.target().starts_with(t))
        {
            let redacted = redact_ips(&record.args().to_string());
            self.inner.log(
                &Record::builder()
                    .args(format_args!("{redacted}"))
                    .level(record.level())
                    .target(record.target())
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .build(),
            );
        } else {
            self.inner.log(record);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// Installs the logger (`RUST_LOG`, default `info`). Call once, first thing
/// in `main()`.
pub fn init() {
    let inner =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let max = inner.filter();
    if log::set_boxed_logger(Box::new(RedactingLogger { inner })).is_ok() {
        log::set_max_level(max);
    }
}

/// Replaces every IPv4 / IPv6 address (with or without port or brackets) in
/// `msg` by [`REDACTED`].
pub fn redact_ips(msg: &str) -> String {
    let is_addr_char = |c: char| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '[' | ']' | '%');
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(start) = rest.find(is_addr_char) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let len = tail.find(|c: char| !is_addr_char(c)).unwrap_or(tail.len());
        let token = &tail[..len];
        // "1.2.3.4:5:" (the address, then the message's own ':') and similar.
        let core = token.trim_end_matches([':', '.', ']']);
        let core = if token[core.len()..].starts_with(']') {
            &token[..=core.len()]
        } else {
            core
        };
        if is_address(core) {
            out.push_str(REDACTED);
            out.push_str(&token[core.len()..]);
        } else {
            out.push_str(token);
        }
        rest = &tail[len..];
    }
    out.push_str(rest);
    out
}

fn is_address(s: &str) -> bool {
    if s.parse::<SocketAddr>().is_ok() || s.parse::<IpAddr>().is_ok() {
        return true;
    }
    s.strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .is_some_and(|v| v.parse::<IpAddr>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_addresses_in_pingora_messages() {
        for (msg, want) in [
            (
                "Downstream handshake error from 198.51.100.7:54321: TLSHandshakeFailure",
                "Downstream handshake error from <redacted>: TLSHandshakeFailure",
            ),
            (
                "Downstream handshake error from [2001:db8::7]:443: bad",
                "Downstream handshake error from <redacted>: bad",
            ),
            (
                "Crit: FD mismatch: fd: 7, addr: 127.0.0.1:8080, peer: 203.0.113.9:1234",
                "Crit: FD mismatch: fd: 7, addr: <redacted>, peer: <redacted>",
            ),
            ("peer 2001:db8::1 gone", "peer <redacted> gone"),
            ("peer [::1] gone", "peer <redacted> gone"),
        ] {
            assert_eq!(redact_ips(msg), want, "{msg}");
        }
    }

    /// Pingora's debug / trace records carry whole requests: never written.
    #[test]
    fn pingora_debug_and_trace_records_are_suppressed() {
        for target in [
            "pingora_proxy",
            "pingora_proxy::proxy_h1",
            "pingora_core::protocols::http::v1::client",
            "pingora_core::services::listening",
        ] {
            assert!(suppressed(target, Level::Debug), "{target}");
            assert!(suppressed(target, Level::Trace), "{target}");
            for level in [Level::Info, Level::Warn, Level::Error] {
                assert!(!suppressed(target, level), "{target} {level}");
            }
        }
        for level in [Level::Trace, Level::Debug, Level::Info] {
            assert!(!suppressed("mg_edge::proxy", level));
            assert!(!suppressed("mg_edge_core::bundle", level));
        }
    }

    #[test]
    fn leaves_other_text_alone() {
        for msg in [
            "Downstream handshake timeout",
            "fd: 12 at 10:00:00, id deadbeef, 1.2 MiB",
            "error: a.b.c",
            "",
            "ünïcödé 1.2.3",
        ] {
            assert_eq!(redact_ips(msg), msg);
        }
    }

    #[test]
    fn random_messages_never_panic() {
        let mut s = 0x0123_4567_89ab_cdefu64;
        let alphabet = ['1', '9', 'a', 'f', '.', ':', '[', ']', '%', ' ', 'x', 'é'];
        for _ in 0..10_000 {
            let mut msg = String::new();
            for _ in 0..24 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                msg.push(alphabet[(s % alphabet.len() as u64) as usize]);
            }
            let _ = redact_ips(&msg);
        }
    }
}
