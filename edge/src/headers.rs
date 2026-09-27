//! Request header hygiene toward the origin.
//!
//! The Edge is the only party allowed to send `MG-*` headers to the origin
//! (`MG-Request-Id`, `MG-Bot-Score`, `MG-Bot-Class`, `MG-Verified`,
//! `MG-Session`; docs/02 §8). Any such header arriving from the client,
//! including the `MG_*` spelling that CGI-style origins treat as the same
//! name, is removed before forwarding, so the origin can trust them once Phase 1 sets
//! them. Stripping untrusted upstream header families (`cf-*`, `x-mg-*`,
//! `X-Forwarded-*`, ...) depends on upstream authentication and arrives with
//! the UpstreamProfile implementation in Phase 1.

use pingora::http::RequestHeader;

/// Case-insensitive prefix of Edge-owned request headers (the `mg_` spelling
/// is matched too, see [`is_edge_owned`]).
pub const EDGE_OWNED_PREFIX: &str = "mg-";

/// Whether `name` is an Edge-owned header: `MG-*` in any case, and also
/// `MG_*`, because CGI-style origins (PHP, WSGI, Rack) map `-` and `_` to the
/// same `HTTP_MG_*` variable.
pub fn is_edge_owned(name: &str) -> bool {
    match name.as_bytes() {
        [m, g, sep, ..] => {
            m.eq_ignore_ascii_case(&b'm')
                && g.eq_ignore_ascii_case(&b'g')
                && matches!(sep, b'-' | b'_')
        }
        _ => false,
    }
}

/// Removes every Edge-owned header from `req`; returns how many names were removed.
pub fn strip_edge_owned(req: &mut RequestHeader) -> usize {
    let owned: Vec<_> = req
        .headers
        .keys()
        .filter(|name| is_edge_owned(name.as_str()))
        .cloned()
        .collect();
    for name in &owned {
        req.remove_header(name);
    }
    owned.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_edge_owned_names() {
        assert!(is_edge_owned("mg-bot-score"));
        assert!(is_edge_owned("MG-Request-Id"));
        assert!(is_edge_owned("Mg-"));
        assert!(!is_edge_owned("x-mg-cf-asn"));
        assert!(!is_edge_owned("mgx-foo"));
        assert!(!is_edge_owned("mg"));
        assert!(!is_edge_owned(""));
    }

    /// CGI-style origins (PHP, WSGI, Rack) expose both `MG-Bot-Score` and
    /// `MG_Bot_Score` as `HTTP_MG_BOT_SCORE`, so the underscore spelling is
    /// just as much a spoof of an Edge-owned header.
    #[test]
    fn underscore_spellings_are_edge_owned_too() {
        assert!(is_edge_owned("mg_bot_score"));
        assert!(is_edge_owned("MG_Verified"));
        assert!(!is_edge_owned("mgx_foo"));
        assert!(!is_edge_owned("x_mg_foo"));

        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("MG_Bot_Score", "0").unwrap();
        req.insert_header("mg_verified", "googlebot").unwrap();
        req.insert_header("Accept", "*/*").unwrap();
        assert_eq!(strip_edge_owned(&mut req), 2);
        assert!(req.headers.get("mg_bot_score").is_none());
        assert!(req.headers.get("mg_verified").is_none());
        assert_eq!(req.headers["accept"], "*/*");
    }

    #[test]
    fn strips_spoofed_headers_and_keeps_others() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Host", "blog.example.com").unwrap();
        req.insert_header("MG-Bot-Score", "0").unwrap();
        req.append_header("mg-verified", "googlebot").unwrap();
        req.append_header("mg-verified", "bingbot").unwrap();
        req.insert_header("x-mg-cf-asn", "64500").unwrap();
        req.insert_header("Accept", "*/*").unwrap();

        assert_eq!(strip_edge_owned(&mut req), 2);
        assert!(req.headers.get("mg-bot-score").is_none());
        assert!(req.headers.get("mg-verified").is_none());
        assert_eq!(req.headers["host"], "blog.example.com");
        assert_eq!(req.headers["x-mg-cf-asn"], "64500");
        assert_eq!(req.headers["accept"], "*/*");
        assert_eq!(strip_edge_owned(&mut req), 0);
    }
}
