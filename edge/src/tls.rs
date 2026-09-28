//! TLS listeners (docs/impl/phase1-spec.md §9.2): `direct_tls` and
//! `cloudflare` + `origin_mtls`.
//!
//! Both are built with `TlsSettings::with_callbacks(EdgeTlsAccept)` and then
//! configured through `DerefMut` on the BoringSSL acceptor builder
//! (certificate chain, private key, ALPN `h2` / `http/1.1`, client
//! verification). Pingora calls `handshake_complete_callback` only for
//! settings made this way; its return value ([`TlsFacts`]: SNI and ALPN)
//! reaches the request filters through `SslDigest.extension`. WP-J1 extends
//! the same structure (JA4); there is no second construction path.
//!
//! `origin_mtls` requires a client certificate that chains to `client_ca`
//! (`PEER | FAIL_IF_NO_PEER_CERT`); a failed handshake closes the
//! connection. BoringSSL calls the verification callback once per
//! certificate of the chain and stops at the first callback that returns
//! `false`, so counting `untrusted_ca` on that first failure counts each
//! failed handshake exactly once, whichever depth the chain breaks at.

use crate::config::{CredRef, ListenerAuth, ListenerConfig};
use crate::creds::CredResolver;
use crate::metrics::metrics;
use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ssl::{NameType, SslFiletype, SslVerifyMode};
use std::any::Any;
use std::sync::Arc;

/// Facts from the TLS handshake that the request path uses (§9.5 `tls`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsFacts {
    /// The SNI host name, if the client sent one.
    pub sni: Option<String>,
    /// The negotiated ALPN protocol (`h2`, `http/1.1`).
    pub alpn: Option<String>,
}

/// The TLS accept callbacks of every Edge TLS listener.
#[derive(Debug, Default)]
pub struct EdgeTlsAccept;

#[async_trait]
impl TlsAccept for EdgeTlsAccept {
    /// The certificate is configured on the context; nothing to select.
    async fn certificate_callback(&self, _ssl: &mut TlsRef) {}

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(Arc::new(facts(ssl)))
    }
}

/// SNI and ALPN of a completed handshake.
pub fn facts(ssl: &TlsRef) -> TlsFacts {
    TlsFacts {
        sni: ssl.servername(NameType::HOST_NAME).map(str::to_owned),
        alpn: ssl
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
    }
}

/// The TLS settings of a TLS listener (`origin_mtls` or `direct_tls`).
/// Fails on unreadable or invalid certificate, key or CA files.
pub fn settings(l: &ListenerConfig, resolver: &CredResolver) -> Result<TlsSettings, String> {
    let at = |what: &str, e: &dyn std::fmt::Display| format!("listener {}: {what}: {e}", l.name);
    let cert = l
        .tls_cert
        .as_ref()
        .ok_or_else(|| at("tls_cert", &"missing"))?;
    let key_ref: &CredRef = l
        .tls_key
        .as_ref()
        .ok_or_else(|| at("tls_key", &"missing"))?;
    let key = resolver.resolve(key_ref).map_err(|e| at("tls_key", &e))?;

    let mut s =
        TlsSettings::with_callbacks(Box::new(EdgeTlsAccept)).map_err(|e| at("TLS settings", &e))?;
    s.set_certificate_chain_file(cert)
        .map_err(|e| at(&format!("tls_cert {}", cert.display()), &e))?;
    // The error stack never contains key bytes, only the file and reason.
    s.set_private_key_file(&key, SslFiletype::PEM)
        .map_err(|e| at(&format!("tls_key {key_ref}"), &e))?;
    s.check_private_key()
        .map_err(|e| at("tls_key does not match tls_cert", &e))?;
    s.enable_h2();

    if l.auth() == ListenerAuth::OriginMtls {
        let ca = l
            .client_ca
            .as_ref()
            .ok_or_else(|| at("client_ca", &"missing"))?;
        s.set_ca_file(ca)
            .map_err(|e| at(&format!("client_ca {}", ca.display()), &e))?;
        let listener = l.name.clone();
        let profile = l.profile.as_str();
        s.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |preverify_ok, _ctx| {
                if !preverify_ok {
                    // The first `false` ends verification: one count per
                    // failed handshake.
                    metrics()
                        .upstream_auth_failures
                        .with_label_values(&[listener.as_str(), profile, "untrusted_ca"])
                        .inc();
                }
                preverify_ok
            },
        );
    }
    Ok(s)
}
