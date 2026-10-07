//! VictoriaLogs `/insert/jsonline` client (spec §13.1) with the §9.11 retry
//! schedule.

use super::{EventsError, Sink};
use reqwest::Url;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Outbound User-Agent. Integrator ruling I-7 (which overrides the
/// `mg-edge/<version>` of §13.1 and §2.4 item 7): every outbound request uses
/// this fixed string and never carries owner identity.
pub const USER_AGENT: &str = "morphgate-dev-tooling";

/// Path appended to a sink's base URL.
pub const JSONLINE_PATH: &str = "insert/jsonline";

/// Query string of every insert (§13.1, D-16): stream fields, time field and
/// message field of the envelope written by [`super::envelope`].
pub const JSONLINE_QUERY: &str = "_stream_fields=kind,site&_time_field=ts&_msg_field=msg";

/// `Content-Type` of every insert (§13.1).
pub const JSONLINE_CONTENT_TYPE: &str = "application/stream+json";

/// Per-attempt timeout (§13.1: a request that takes longer counts as failed
/// and is retried).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Waits before the 1st, 2nd and 3rd retry (§9.11). A batch is attempted at
/// most `1 + RETRY_BACKOFF.len()` times, then dropped.
pub const RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_millis(200),
    Duration::from_secs(1),
    Duration::from_secs(5),
];

/// Response bytes read (and discarded) per insert so the connection can be
/// reused; anything beyond is not read.
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// Timing knobs of a [`VlClient`]. Production uses [`VlOptions::default`]
/// (the §9.11 / §13.1 values); tests shorten them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlOptions {
    /// Per-attempt timeout, connect included.
    pub timeout: Duration,
    /// Wait before each retry; its length is the number of retries.
    pub backoff: Vec<Duration>,
}

impl Default for VlOptions {
    fn default() -> Self {
        Self {
            timeout: REQUEST_TIMEOUT,
            backoff: RETRY_BACKOFF.to_vec(),
        }
    }
}

/// Result of posting one batch to one sink, retries included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostOutcome {
    /// 2xx on attempt number `attempts` (1-based).
    Accepted { attempts: u32 },
    /// A non-retryable status (4xx other than 429, 1xx, 3xx): dropped at once.
    Rejected { status: u16 },
    /// 429, 5xx, timeout or transport error on every attempt.
    Failed { attempts: u32 },
    /// No URL is configured for this sink; nothing was sent.
    NoEndpoint,
}

/// HTTP client for the two VictoriaLogs sinks (§13.1).
///
/// Built with `no_proxy()` (reqwest otherwise reads `HTTP_PROXY` /
/// `HTTPS_PROXY` / `ALL_PROXY` even without its `system-proxy` feature,
/// §1.2), no redirects, HTTP/1.1, and the fixed [`USER_AGENT`]. Create it on
/// the runtime that runs the flusher (the `mg-events` service, §9.1.1).
#[derive(Clone)]
pub struct VlClient {
    http: reqwest::Client,
    main: Option<Url>,
    short: Option<Url>,
    backoff: Arc<[Duration]>,
}

impl fmt::Debug for VlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Endpoint URLs are validated to carry no credentials.
        f.debug_struct("VlClient")
            .field("main", &self.main.as_ref().map(Url::as_str))
            .field("short", &self.short.as_ref().map(Url::as_str))
            .field("retries", &self.backoff.len())
            .finish()
    }
}

impl VlClient {
    /// Client with the production timeout and retry schedule. `main` /
    /// `short` are base URLs such as `http://10.0.0.5:9428`.
    pub fn new(main: Option<&str>, short: Option<&str>) -> Result<Self, EventsError> {
        Self::with_options(main, short, VlOptions::default())
    }

    /// Client with explicit timing (tests).
    pub fn with_options(
        main: Option<&str>,
        short: Option<&str>,
        options: VlOptions,
    ) -> Result<Self, EventsError> {
        let parse = |key: &str, url: Option<&str>| {
            url.map(endpoint_url)
                .transpose()
                .map_err(|e| EventsError::Config(format!("{key}: {e}")))
        };
        let main = parse("vl_main", main)?;
        let short = parse("vl_short", short)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .timeout(options.timeout)
            .connect_timeout(options.timeout)
            .build()
            .map_err(|e| EventsError::Client(e.to_string()))?;
        Ok(Self {
            http,
            main,
            short,
            backoff: options.backoff.into(),
        })
    }

    /// The client for `[events]`, or `None` when neither URL is set.
    pub fn from_config(cfg: &super::EventsConfig) -> Result<Option<Self>, EventsError> {
        if cfg.vl_main.is_none() && cfg.vl_short.is_none() {
            return Ok(None);
        }
        Self::new(cfg.vl_main.as_deref(), cfg.vl_short.as_deref()).map(Some)
    }

    /// Full insert URL of `sink` (base + `insert/jsonline` + query), if configured.
    pub fn endpoint(&self, sink: Sink) -> Option<&Url> {
        match sink {
            Sink::Main => self.main.as_ref(),
            Sink::Short => self.short.as_ref(),
        }
    }

    /// Posts one `jsonline` body (§13.1), retrying per §9.11: 2xx is
    /// accepted; 429, 5xx, timeouts and transport errors are retried after
    /// 200 ms, 1 s and 5 s; any other status drops the batch at once.
    pub async fn post_batch(&self, sink: Sink, body: Vec<u8>) -> PostOutcome {
        let Some(url) = self.endpoint(sink) else {
            return PostOutcome::NoEndpoint;
        };
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            match self.attempt(url, body.clone()).await {
                Attempt::Accepted => return PostOutcome::Accepted { attempts },
                Attempt::Rejected(status) => return PostOutcome::Rejected { status },
                Attempt::Retryable => {}
            }
            let Some(wait) = self.backoff.get(attempts as usize - 1) else {
                return PostOutcome::Failed { attempts };
            };
            tokio::time::sleep(*wait).await;
        }
    }

    async fn attempt(&self, url: &Url, body: Vec<u8>) -> Attempt {
        let sent = self
            .http
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, JSONLINE_CONTENT_TYPE)
            .body(body)
            .send()
            .await;
        let mut response = match sent {
            Ok(response) => response,
            // Connect / timeout / transport errors: the batch may be fine,
            // the path to VictoriaLogs is not.
            Err(_) => return Attempt::Retryable,
        };
        let status = response.status();
        let mut drained = 0usize;
        while drained < MAX_DRAIN_BYTES {
            match response.chunk().await {
                Ok(Some(chunk)) => drained += chunk.len(),
                _ => break,
            }
        }
        if status.is_success() {
            Attempt::Accepted
        } else if status.as_u16() == 429 || status.is_server_error() {
            Attempt::Retryable
        } else {
            Attempt::Rejected(status.as_u16())
        }
    }
}

enum Attempt {
    Accepted,
    Retryable,
    Rejected(u16),
}

/// Validates a sink base URL and returns its insert URL.
///
/// Rules: `http` or `https`, a host, no credentials (secrets never live in
/// `edge.toml`, and the URL may appear in diagnostics), no query or fragment.
/// Decision events carry client IPs and paths, so `http://` (no transport
/// security) is only accepted with a loopback, RFC 1918, ULA or
/// 100.64.0.0/10 IP literal, never a name: the `bundle_root` rule of §8.1.
/// A base path is kept (`http://h/vl` -> `http://h/vl/insert/jsonline?…`).
pub(crate) fn endpoint_url(base: &str) -> Result<Url, String> {
    let mut url = Url::parse(base).map_err(|e| format!("invalid URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, got {}",
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("URL has no host".into());
    }
    if url.scheme() == "http" {
        // host_str() brackets IPv6 literals; a name does not parse as an address.
        let internal = url
            .host_str()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(crate::bundle::is_internal_ip);
        if !internal {
            return Err(
                "http:// is only allowed to a loopback, private (RFC 1918 / ULA) or \
                 100.64.0.0/10 address; use https://"
                    .into(),
            );
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not contain credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL must not contain a query or fragment".into());
    }
    let path = format!("{}/{JSONLINE_PATH}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    url.set_query(Some(JSONLINE_QUERY));
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_appends_path_and_query() {
        let cases = [
            (
                "http://10.0.0.5:9428",
                "http://10.0.0.5:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
            (
                "http://10.0.0.5:9428/",
                "http://10.0.0.5:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
            (
                "https://vl.internal/logs/",
                "https://vl.internal/logs/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
            (
                "http://127.0.0.1:9428",
                "http://127.0.0.1:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
            (
                "http://[fd00::5]:9428",
                "http://[fd00::5]:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
            (
                "http://100.64.0.9:9428",
                "http://100.64.0.9:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg",
            ),
        ];
        for (base, want) in cases {
            assert_eq!(endpoint_url(base).unwrap().as_str(), want, "{base}");
        }
    }

    #[test]
    fn endpoint_url_rejects_bad_bases() {
        for bad in [
            "",
            "10.0.0.5:9428",
            "file:///tmp/x",
            "http://u@10.0.0.5/",
            "http://u:p@10.0.0.5/",
            "http://10.0.0.5/?a=b",
            "http://10.0.0.5/#x",
            // §8.1: plaintext only to internal addresses, never to a name.
            "http://203.0.113.5:9428",
            "http://[2001:db8::5]:9428",
            "http://vl.internal:9428",
            "http://localhost:9428",
        ] {
            assert!(endpoint_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn default_options_are_the_spec_schedule() {
        let o = VlOptions::default();
        assert_eq!(o.timeout, Duration::from_secs(5));
        assert_eq!(
            o.backoff,
            vec![
                Duration::from_millis(200),
                Duration::from_secs(1),
                Duration::from_secs(5)
            ]
        );
    }

    #[test]
    fn from_config_without_urls_is_none() {
        let cfg = super::super::EventsConfig::default();
        assert!(VlClient::from_config(&cfg).unwrap().is_none());
        let cfg = super::super::EventsConfig {
            vl_short: Some("http://127.0.0.1:9429".into()),
            ..cfg
        };
        let client = VlClient::from_config(&cfg).unwrap().unwrap();
        assert!(client.endpoint(Sink::Main).is_none());
        assert!(client.endpoint(Sink::Short).is_some());
        assert!(!format!("{client:?}").is_empty());
    }
}
