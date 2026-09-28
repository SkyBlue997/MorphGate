//! The BoringSSL side of the JA4 spike (docs/impl/phase1-spec.md §15
//! WP-J1; ADR-0002 decision 4): a select-certificate callback on the
//! listener's context computes the JA4 of the raw ClientHello and keeps it in
//! the connection's ex_data; `EdgeTlsAccept::handshake_complete_callback`
//! reads it into `TlsFacts` ([`ja4_of`]).
//!
//! * Installed only on `direct_tls` listeners with `ja4_spike = true`
//!   ([`install`]).
//! * Never fails a handshake: a ClientHello that does not parse leaves no JA4
//!   and the handshake goes on (BoringSSL judges the message itself).
//! * BoringSSL runs the callback once per connection, on the first
//!   ClientHello, before it decides on resumption: resumed handshakes are
//!   fingerprinted too (their `pre_shared_key` extension changes the JA4,
//!   see ADR-0002), the second ClientHello after a HelloRetryRequest is not.
//! * Cost per handshake: one parse of the message body (no heap allocation
//!   below 128 cipher suites and 128 extensions), two SHA-256 over the hex
//!   lists (under 1 KiB for real clients; about 40 KiB, some 80 µs in a
//!   release build, for the largest ClientHello BoringSSL accepts, 16 KiB of
//!   cipher suites), and the 36-byte box BoringSSL's ex_data slot holds.

use super::ja4::{self, Ja4};
use pingora::tls::ssl::{ClientHello, SelectCertError, Ssl, SslContextBuilder, SslRef};
use std::any::Any;
use std::sync::OnceLock;

/// What the ex_data slot holds.
type Slot = Ja4;

/// The ex_data slot index. boring's `ex_data::Index` type is not re-exported
/// through Pingora, so the index is kept behind `Any` and recovered by the
/// type of its constructor (`Ssl::new_ex_index::<Slot>`).
static SLOT: OnceLock<Box<dyn Any + Send + Sync>> = OnceLock::new();

/// The slot index, if [`install`] created it.
fn index<I, E>(_constructor: fn() -> Result<I, E>) -> Option<I>
where
    I: Copy + Send + Sync + 'static,
{
    SLOT.get()?.downcast_ref::<I>().copied()
}

/// The slot index, created on first use (process-wide, like every BoringSSL
/// ex_data index).
fn create_index<I, E>(constructor: fn() -> Result<I, E>) -> Result<I, E>
where
    I: Copy + Send + Sync + 'static,
{
    if let Some(i) = index(constructor) {
        return Ok(i);
    }
    let i = constructor()?;
    // A concurrent first call keeps its own index; both are valid slots, the
    // stored one is used from now on.
    let _ = SLOT.set(Box::new(i));
    Ok(index(constructor).unwrap_or(i))
}

/// Installs the select-certificate callback on a listener's context.
/// Fails only if BoringSSL cannot allocate an ex_data index.
pub(crate) fn install(ctx: &mut SslContextBuilder) -> Result<(), String> {
    let idx = create_index(Ssl::new_ex_index::<Slot>)
        .map_err(|e| format!("cannot allocate an SSL ex_data index: {e}"))?;
    ctx.set_select_certificate_callback(move |mut hello: ClientHello<'_>| {
        if let Some(v) = compute(hello.as_bytes()) {
            hello.ssl_mut().set_ex_data(idx, v);
        }
        Ok::<(), SelectCertError>(())
    });
    Ok(())
}

/// The JA4 of a ClientHello body; `None` if it does not parse. The parser
/// does not panic (random-input tests, §2.4 item 3); should it ever, the
/// panic must not unwind into BoringSSL, which would abort the process.
pub fn compute(body: &[u8]) -> Option<Ja4> {
    match std::panic::catch_unwind(|| ja4::ja4(body)) {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            log::debug!("ja4_spike: no JA4: {e}");
            None
        }
        Err(_) => {
            log::error!("ja4_spike: the JA4 parser panicked; the handshake continues without JA4");
            None
        }
    }
}

/// The JA4 the select-certificate callback stored for this connection
/// (`None` on listeners without `ja4_spike`).
pub(crate) fn ja4_of(ssl: &SslRef) -> Option<Ja4> {
    ssl.ex_data(index(Ssl::new_ex_index::<Slot>)?).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ja4::tests::{Hello, alpn, ext, sigalgs, sni, versions};

    #[test]
    fn compute_returns_the_fingerprint_or_nothing() {
        let body = Hello {
            legacy_version: 0x0303,
            ciphers: vec![0x1301, 0x1302],
            extensions: Some(vec![
                sni("edge.test"),
                versions(&[0x0304]),
                alpn(&[b"http/1.1"]),
                sigalgs(&[0x0403]),
                ext(0x0033),
            ]),
        }
        .body();
        let v = compute(&body).unwrap();
        assert!(v.as_str().starts_with("t13d0205h1_"), "{v}");
        assert_eq!(compute(&body[..40]), None);
        assert_eq!(compute(&[]), None);
    }

    #[test]
    fn the_slot_index_is_created_once() {
        let a = create_index(Ssl::new_ex_index::<Slot>).unwrap();
        let b = create_index(Ssl::new_ex_index::<Slot>).unwrap();
        let c = index(Ssl::new_ex_index::<Slot>).unwrap();
        assert_eq!((a.as_raw(), b.as_raw()), (c.as_raw(), c.as_raw()));
        // An index of another slot type never matches the stored one.
        assert!(index(Ssl::new_ex_index::<u64>).is_none());
    }
}
