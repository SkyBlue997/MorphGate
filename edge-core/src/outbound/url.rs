//! The siteverify destination check (spec §8.4, §10.1): the production URL is
//! always accepted; a loopback mock URL only when the caller allows test
//! destinations (mg-edge passes `MG_EDGE_TEST_OUTBOUND=1`, WP-E2c). Anything
//! else is refused, so a configuration mistake never silently widens egress.

use std::fmt;

/// The only production siteverify endpoint (spec §8.4).
pub const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Longest accepted test-destination URL, in bytes.
pub const MAX_TEST_URL_BYTES: usize = 256;

/// A validated siteverify destination: [`SITEVERIFY_URL`], or a loopback
/// mock (`http://127.0.0.1:<port>/…` or `http://[::1]:<port>/…`) accepted
/// because the caller allowed test destinations.
#[derive(Clone, PartialEq, Eq)]
pub struct SiteverifyUrl {
    url: String,
    is_override: bool,
}

impl SiteverifyUrl {
    /// The production destination, [`SITEVERIFY_URL`].
    pub fn production() -> Self {
        Self {
            url: SITEVERIFY_URL.to_owned(),
            is_override: false,
        }
    }

    /// The URL as configured.
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Whether this is a non-default (loopback test) destination; mg-edge
    /// sets `mg_outbound_override{target="siteverify"}` and logs a WARN for
    /// it (spec §8.4).
    pub fn is_override(&self) -> bool {
        self.is_override
    }
}

impl Default for SiteverifyUrl {
    fn default() -> Self {
        Self::production()
    }
}

impl fmt::Debug for SiteverifyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SiteverifyUrl").field(&self.url).finish()
    }
}

impl fmt::Display for SiteverifyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

/// Why a siteverify URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    /// A loopback URL without permission for test destinations.
    #[error(
        "turnstile_siteverify_url: a loopback test destination is accepted only with MG_EDGE_TEST_OUTBOUND=1"
    )]
    TestDestinationNotAllowed,
    /// Neither the production URL nor a well-formed loopback URL.
    #[error(
        "turnstile_siteverify_url must be {SITEVERIFY_URL}, or (tests only) http://127.0.0.1:<port>/<path> or http://[::1]:<port>/<path>"
    )]
    NotAllowed,
}

/// Validates a configured siteverify URL (spec §8.4).
///
/// [`SITEVERIFY_URL`] (exact bytes) is always accepted. Otherwise the URL must
/// be `http://127.0.0.1:<port>/<path>` or `http://[::1]:<port>/<path>` with an
/// explicit port in 1..=65535 (no leading zero), a path of
/// `[A-Za-z0-9._~/-]` characters starting with `/`, no query, fragment or
/// user info, at most [`MAX_TEST_URL_BYTES`] bytes, and
/// `allow_test_destinations` must be true.
pub fn validate_siteverify_url(
    url: &str,
    allow_test_destinations: bool,
) -> Result<SiteverifyUrl, UrlError> {
    if url == SITEVERIFY_URL {
        return Ok(SiteverifyUrl::production());
    }
    if !is_loopback_url(url) {
        return Err(UrlError::NotAllowed);
    }
    if !allow_test_destinations {
        return Err(UrlError::TestDestinationNotAllowed);
    }
    Ok(SiteverifyUrl {
        url: url.to_owned(),
        is_override: true,
    })
}

fn is_loopback_url(url: &str) -> bool {
    if url.len() > MAX_TEST_URL_BYTES {
        return false;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let Some(rest) = rest
        .strip_prefix("127.0.0.1:")
        .or_else(|| rest.strip_prefix("[::1]:"))
    else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (port, path) = rest.split_at(slash);
    valid_port(port) && valid_path(path)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u32>().is_ok_and(|p| (1..=65_535).contains(&p))
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-'))
        && !path.split('/').any(|seg| seg == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_url_is_always_accepted() {
        for allow in [false, true] {
            let u = validate_siteverify_url(SITEVERIFY_URL, allow).unwrap();
            assert!(!u.is_override());
            assert_eq!(u.as_str(), SITEVERIFY_URL);
        }
        assert_eq!(SiteverifyUrl::default(), SiteverifyUrl::production());
    }

    #[test]
    fn loopback_needs_permission() {
        for url in [
            "http://127.0.0.1:8080/turnstile/v0/siteverify",
            "http://[::1]:1/x",
            "http://127.0.0.1:65535/",
        ] {
            assert_eq!(
                validate_siteverify_url(url, false),
                Err(UrlError::TestDestinationNotAllowed),
                "{url}"
            );
            let u = validate_siteverify_url(url, true).unwrap();
            assert!(u.is_override());
            assert_eq!(u.to_string(), url);
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for url in [
            "",
            "https://challenges.cloudflare.com/turnstile/v0/siteverify/",
            "https://challenges.cloudflare.com/turnstile/v0/siteverify?x=1",
            "HTTPS://challenges.cloudflare.com/turnstile/v0/siteverify",
            "http://challenges.cloudflare.com/turnstile/v0/siteverify",
            "https://example.com/turnstile/v0/siteverify",
            "https://127.0.0.1:8080/x",
            "http://localhost:8080/x",
            "http://127.0.0.2:8080/x",
            "http://127.0.0.1/x",
            "http://127.0.0.1:/x",
            "http://127.0.0.1:0/x",
            "http://127.0.0.1:080/x",
            "http://127.0.0.1:65536/x",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/x?y",
            "http://127.0.0.1:8080/x#y",
            "http://127.0.0.1:8080/../x",
            "http://127.0.0.1:8080/a b",
            "http://127.0.0.1:8080@evil.example/x",
            "http://user@127.0.0.1:8080/x",
            "http://[::1]/x",
            "http://[0:0:0:0:0:0:0:1]:8080/x",
            "http://[::ffff:127.0.0.1]:8080/x",
            "http://2130706433:8080/x",
        ] {
            for allow in [false, true] {
                assert_eq!(
                    validate_siteverify_url(url, allow),
                    Err(UrlError::NotAllowed),
                    "{url} allow={allow}"
                );
            }
        }
        let long = format!("http://127.0.0.1:8080/{}", "a".repeat(MAX_TEST_URL_BYTES));
        assert_eq!(
            validate_siteverify_url(&long, true),
            Err(UrlError::NotAllowed)
        );
    }
}
