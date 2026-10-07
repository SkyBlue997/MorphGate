//! Fetching bundles and artifacts from `file://` or HTTP(S) roots (§9.10,
//! §12.1).

use super::util::{hex_lower, is_sha256_hex, is_site_id, sha256};
use super::{BundleError, MAX_SIGNED_BUNDLE_BYTES};
use reqwest::header::{ETAG, HeaderValue, IF_NONE_MATCH};
use reqwest::{StatusCode, Url};
use std::fmt;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Redirects followed per request, all within the original origin (§9.10).
const MAX_REDIRECTS: usize = 3;

/// Artifact downloads may take longer than a bundle fetch: the total
/// deadline is `timeout` plus one second per MiB of the expected size (the
/// connect and per-read timeouts stay at `timeout`).
const ARTIFACT_BYTES_PER_SECOND: u64 = 1024 * 1024;

/// Where a site's bundles and artifacts are published (`bundle_root` in
/// edge.toml, §8.1): the directory that contains `bundles/` and `artifacts/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A local directory (`file:///srv/mg/`).
    File(PathBuf),
    /// An HTTP(S) base URL ending in `/`.
    Http(Url),
}

impl Source {
    /// Parses and checks a `bundle_root` (§8.1): it ends with `/`; `file://`
    /// has no host and an absolute path; `https://` and `http://` have a
    /// host and no credentials, query or fragment; `http://` (no transport
    /// security) is only accepted with a loopback, RFC 1918, ULA or
    /// 100.64.0.0/10 IP literal, never a name.
    pub fn parse(root: &str) -> Result<Self, BundleError> {
        let err =
            |why: &str| BundleError::Source(format!("{why}: {:?}", super::verify::printable(root)));
        if !root.ends_with('/') {
            return Err(err("must end with '/'"));
        }
        let url = Url::parse(root).map_err(|_| err("not a URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(err("must not contain credentials"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(err("must not have a query or fragment"));
        }
        match url.scheme() {
            "file" => {
                if url.host().is_some() {
                    return Err(err("file:// must not name a host"));
                }
                let path = url.to_file_path().map_err(|()| err("not a local path"))?;
                if !path.is_absolute() {
                    return Err(err("file:// path must be absolute"));
                }
                Ok(Self::File(path))
            }
            "https" => {
                if url.host().is_none() {
                    return Err(err("missing host"));
                }
                Ok(Self::Http(url))
            }
            "http" => {
                // host_str() brackets IPv6 literals; a name does not parse as an address.
                let ip = url
                    .host_str()
                    .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
                    .and_then(|h| h.parse::<IpAddr>().ok());
                match ip {
                    Some(ip) if is_internal_ip(ip) => Ok(Self::Http(url)),
                    _ => Err(err(
                        "http:// is only allowed to a loopback, private (RFC 1918 / ULA) or \
                         100.64.0.0/10 address; use https://",
                    )),
                }
            }
            _ => Err(err("scheme must be file, https or http")),
        }
    }
}

/// Loopback, RFC 1918, 100.64.0.0/10 or IPv6 unique local (the edge.toml
/// `metrics_listen` rule). Also the rule for `http://` event sinks
/// (`[events] vl_main` / `vl_short`, §8.1).
pub(crate) fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_internal_ip(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unique_local(),
        },
    }
}

/// `[bundle_client]` of edge.toml (§8.1), with files already read by the
/// caller (credentials are resolved in `main()`).
#[derive(Clone)]
pub struct FetcherConfig {
    /// Connect timeout, per-read timeout and total deadline of a bundle
    /// request (`timeout_ms`).
    pub timeout: Duration,
    /// `User-Agent` of every request.
    pub user_agent: String,
    /// PEM CA bundle for `https://` roots (`ca_file`). When set, only these
    /// roots are trusted; otherwise the platform verifier is used.
    pub ca_pem: Option<Vec<u8>>,
    /// PEM client certificate chain for mTLS (`client_cert`).
    pub client_cert_pem: Option<Vec<u8>>,
    /// PEM private key of the client certificate (`client_key`).
    pub client_key_pem: Option<Vec<u8>>,
}

impl FetcherConfig {
    /// Default `User-Agent`. Integrator ruling I-7 (which overrides the
    /// `mg-edge/<version>` of §9.10 and §2.4 item 7): every outbound request
    /// uses this fixed string and never carries owner identity. Same value as
    /// the event sink's (`events::USER_AGENT`).
    pub const DEFAULT_USER_AGENT: &'static str = "morphgate-dev-tooling";

    /// No CA override, no client certificate, the default `User-Agent`.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            user_agent: Self::DEFAULT_USER_AGENT.to_string(),
            ca_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
        }
    }
}

impl fmt::Debug for FetcherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetcherConfig")
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "<set>"))
            .field(
                "client_cert_pem",
                &self.client_cert_pem.as_ref().map(|_| "<set>"),
            )
            .field(
                "client_key_pem",
                &self.client_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Result of a conditional bundle fetch.
#[derive(Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The ETag still matches (HTTP 304, or a `file://` bundle whose SHA-256
    /// equals the ETag passed in).
    NotModified,
    /// New content. `etag` is the response's `ETag` as returned (empty if
    /// the server sent none), or the lower-hex SHA-256 for `file://`.
    Body { bytes: Vec<u8>, etag: String },
}

impl fmt::Debug for Fetched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotModified => f.write_str("NotModified"),
            Self::Body { bytes, etag } => f
                .debug_struct("Body")
                .field("bytes", &bytes.len())
                .field("etag", etag)
                .finish(),
        }
    }
}

/// Bundle and artifact fetcher shared by every site's poll loop.
///
/// The HTTP client never uses a proxy (`ClientBuilder::no_proxy`: reqwest
/// would otherwise honour `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`), follows
/// at most 3 redirects and only within the original origin, and sends no
/// `Referer`.
pub struct Fetcher {
    client: reqwest::Client,
    timeout: Duration,
    user_agent: String,
}

impl fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetcher")
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Builds the HTTP client. Fails on an unparsable CA or client
    /// certificate, or when only one of certificate and key is given.
    pub fn new(cfg: &FetcherConfig) -> Result<Self, BundleError> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .user_agent(cfg.user_agent.as_str())
            .connect_timeout(cfg.timeout)
            .read_timeout(cfg.timeout)
            .redirect(same_origin_redirects())
            .referer(false);
        if let Some(ca) = &cfg.ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(ca)
                .map_err(|e| BundleError::Client(format!("ca_file: {}", error_chain(&e))))?;
            if certs.is_empty() {
                return Err(BundleError::Client("ca_file: no certificate found".into()));
            }
            builder = builder.tls_certs_only(certs);
        }
        match (&cfg.client_cert_pem, &cfg.client_key_pem) {
            (Some(cert), Some(key)) => {
                let mut pem = cert.clone();
                pem.push(b'\n');
                pem.extend_from_slice(key);
                // The error text of a PEM parser never contains key bytes.
                let identity = reqwest::Identity::from_pem(&pem).map_err(|e| {
                    BundleError::Client(format!("client certificate: {}", error_chain(&e)))
                })?;
                builder = builder.identity(identity);
            }
            (None, None) => {}
            _ => {
                return Err(BundleError::Client(
                    "client_cert and client_key must be set together".into(),
                ));
            }
        }
        let client = builder
            .build()
            .map_err(|e| BundleError::Client(error_chain(&e)))?;
        Ok(Self {
            client,
            timeout: cfg.timeout,
            user_agent: cfg.user_agent.clone(),
        })
    }

    /// Fetches `<root>bundles/<site>.bundle` (at most
    /// [`MAX_SIGNED_BUNDLE_BYTES`]). With `etag`, HTTP sends
    /// `If-None-Match: <etag>` and `file://` compares it with the SHA-256 of
    /// the file.
    pub async fn fetch_bundle(
        &self,
        root: &Source,
        site: &str,
        etag: Option<&str>,
    ) -> Result<Fetched, BundleError> {
        if !is_site_id(site) {
            return Err(BundleError::Source(format!(
                "invalid site id {:?}",
                super::verify::printable(site)
            )));
        }
        let rel = format!("bundles/{site}.bundle");
        let limit = MAX_SIGNED_BUNDLE_BYTES as u64;
        match root {
            Source::File(dir) => {
                let bytes = read_file(dir.join(&rel), limit, "signed bundle").await?;
                let tag = hex_lower(&sha256(&bytes));
                if etag == Some(tag.as_str()) {
                    return Ok(Fetched::NotModified);
                }
                Ok(Fetched::Body { bytes, etag: tag })
            }
            Source::Http(base) => {
                let url = join(base, &rel)?;
                let mut req = self.client.get(url).timeout(self.timeout);
                if let Some(tag) = etag.filter(|t| !t.is_empty()) {
                    let value = HeaderValue::from_str(tag).map_err(|_| {
                        BundleError::Fetch("stored ETag is not a header value".into())
                    })?;
                    req = req.header(IF_NONE_MATCH, value);
                }
                let resp = req.send().await.map_err(map_reqwest)?;
                match resp.status() {
                    StatusCode::NOT_MODIFIED if etag.is_some() => Ok(Fetched::NotModified),
                    StatusCode::OK => {
                        let etag = resp
                            .headers()
                            .get(ETAG)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let bytes = read_body(resp, limit, "signed bundle").await?;
                        Ok(Fetched::Body { bytes, etag })
                    }
                    other => Err(BundleError::Status(other.as_u16())),
                }
            }
        }
    }

    /// Fetches `<root>artifacts/<sha256_hex>`, at most `max_size` bytes, and
    /// checks that its SHA-256 is `sha256_hex`.
    pub async fn fetch_artifact(
        &self,
        root: &Source,
        sha256_hex: &str,
        max_size: u64,
    ) -> Result<Vec<u8>, BundleError> {
        if !is_sha256_hex(sha256_hex) {
            return Err(BundleError::Artifact {
                sha256: super::verify::printable(sha256_hex),
                reason: "not a lower-case SHA-256 hex digest".into(),
            });
        }
        let rel = format!("artifacts/{sha256_hex}");
        let bytes = match root {
            Source::File(dir) => read_file(dir.join(&rel), max_size, "artifact").await?,
            Source::Http(base) => {
                let deadline =
                    self.timeout + Duration::from_secs(max_size / ARTIFACT_BYTES_PER_SECOND);
                let resp = self
                    .client
                    .get(join(base, &rel)?)
                    .timeout(deadline)
                    .send()
                    .await
                    .map_err(map_reqwest)?;
                if resp.status() != StatusCode::OK {
                    return Err(BundleError::Status(resp.status().as_u16()));
                }
                read_body(resp, max_size, "artifact").await?
            }
        };
        if hex_lower(&sha256(&bytes)) != sha256_hex {
            return Err(BundleError::Artifact {
                sha256: sha256_hex.to_string(),
                reason: "content does not match its SHA-256".into(),
            });
        }
        Ok(bytes)
    }
}

/// Only same-origin redirects, at most [`MAX_REDIRECTS`] (§9.10).
fn same_origin_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        // `previous` holds every URL requested so far, the original first.
        let origin_ok = attempt
            .previous()
            .first()
            .is_some_and(|first| first.origin() == attempt.url().origin());
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error(format!("more than {MAX_REDIRECTS} redirects"))
        } else if !origin_ok {
            attempt.error("redirect to another origin refused")
        } else {
            attempt.follow()
        }
    })
}

fn join(base: &Url, rel: &str) -> Result<Url, BundleError> {
    base.join(rel)
        .map_err(|e| BundleError::Source(format!("cannot join {rel:?}: {e}")))
}

/// Reads a response body, failing as soon as it exceeds `limit` bytes.
async fn read_body(
    mut resp: reqwest::Response,
    limit: u64,
    what: &'static str,
) -> Result<Vec<u8>, BundleError> {
    let too_large = || BundleError::TooLarge { what, limit };
    let declared = resp.content_length().unwrap_or(0);
    if declared > limit {
        return Err(too_large());
    }
    let mut out = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
    while let Some(chunk) = resp.chunk().await.map_err(map_reqwest)? {
        if (out.len() + chunk.len()) as u64 > limit {
            return Err(too_large());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Reads a local file of at most `limit` bytes on the blocking pool.
async fn read_file(path: PathBuf, limit: u64, what: &'static str) -> Result<Vec<u8>, BundleError> {
    tokio::task::spawn_blocking(move || read_file_capped(&path, limit, what))
        .await
        .map_err(|e| BundleError::Fetch(format!("file read task failed: {e}")))?
}

pub(crate) fn read_file_capped(
    path: &Path,
    limit: u64,
    what: &'static str,
) -> Result<Vec<u8>, BundleError> {
    let file = std::fs::File::open(path)?;
    let mut out = Vec::new();
    file.take(limit + 1).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(BundleError::TooLarge { what, limit });
    }
    Ok(out)
}

fn map_reqwest(e: reqwest::Error) -> BundleError {
    if e.is_timeout() {
        BundleError::Timeout
    } else {
        BundleError::Fetch(error_chain(&e))
    }
}

/// `e` and its sources, `": "`-separated (reqwest keeps the useful part,
/// such as "redirect to another origin refused", in the source chain).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !msg.contains(&text) {
            msg.push_str(": ");
            msg.push_str(&text);
        }
        source = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_rules() {
        assert_eq!(
            Source::parse("file:///srv/mg/").unwrap(),
            Source::File(PathBuf::from("/srv/mg/"))
        );
        for ok in [
            "https://brain.example/mg/",
            "http://127.0.0.1:8081/",
            "http://10.0.0.5/mg/",
            "http://192.168.1.2/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",
            "http://[::1]:9000/",
            "http://[fd00::1]/",
        ] {
            assert!(matches!(Source::parse(ok), Ok(Source::Http(_))), "{ok}");
        }
        for bad in [
            "",
            "/srv/mg/",
            "file:///srv/mg",
            "file://host/srv/mg/",
            "https://brain.example/mg",
            "https://user:pw@brain.example/",
            "https://brain.example/?x=1/",
            "https://brain.example/#x/",
            "http://brain.example/",
            "http://localhost/",
            "http://8.8.8.8/",
            "http://169.254.1.1/",
            "http://[2001:db8::1]/",
            "http://[::ffff:8.8.8.8]/",
            "ftp://10.0.0.1/",
        ] {
            assert!(Source::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_debug_redacts_key() {
        let mut cfg = FetcherConfig::new(Duration::from_secs(1));
        cfg.client_key_pem = Some(b"-----BEGIN PRIVATE KEY-----secret".to_vec());
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("<redacted>") && !dbg.contains("secret"),
            "{dbg}"
        );
    }

    /// A throwaway self-signed certificate (public part only; the key was
    /// discarded), used as a `ca_file`.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBtDCCAVugAwIBAgIUAPjag+JLbihGsrP4vkuTvDlQh0swCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkTW9ycGhHYXRlIHRlc3QgQ0EgKHB1YmxpYyBwYXJ0IG9ubHkp
MCAXDTI2MDkyNzE2MTM0OFoYDzIxMjYwOTAzMTYxMzQ4WjAvMS0wKwYDVQQDDCRN
b3JwaEdhdGUgdGVzdCBDQSAocHVibGljIHBhcnQgb25seSkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASD9qwNI7YuljuPCRiRPwGtLXdh8VjMKPTgaTv8aPaujD73
NGb2i9AjdDM147AUneFQa4qBlThq6w5FvB/m/P6So1MwUTAdBgNVHQ4EFgQUTNTC
hwzMJ2cHu/Ms0+Q0HQMIrsQwHwYDVR0jBBgwFoAUTNTChwzMJ2cHu/Ms0+Q0HQMI
rsQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB4VEQiKYQYEvXv
EeGTHfsm9rZlkTnbZ/0UVLxG/4slMAIgcbeT3bgSpA57ppai1qkTtniOoftOHZcz
9Kncx4clqgU=
-----END CERTIFICATE-----
";

    #[test]
    fn private_ca_is_accepted() {
        let mut cfg = FetcherConfig::new(Duration::from_secs(1));
        cfg.ca_pem = Some(TEST_CA_PEM.as_bytes().to_vec());
        Fetcher::new(&cfg).unwrap();
    }

    #[test]
    fn client_config_errors() {
        let mut cfg = FetcherConfig::new(Duration::from_secs(1));
        cfg.client_cert_pem = Some(b"x".to_vec());
        assert!(matches!(Fetcher::new(&cfg), Err(BundleError::Client(_))));
        let mut cfg = FetcherConfig::new(Duration::from_secs(1));
        cfg.ca_pem = Some(b"not a pem".to_vec());
        assert!(matches!(Fetcher::new(&cfg), Err(BundleError::Client(_))));
    }
}
