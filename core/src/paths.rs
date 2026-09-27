//! Request-path views shared by the Edge and the challenge code.
//!
//! Cloudflare matches its rules against a *normalized* path but forwards the
//! raw one, and origin frameworks decode, fold and trim paths in their own
//! ways. Two decisions therefore look at several views of one path
//! (docs/impl/phase1-spec.md §9.4, §10.1):
//!
//! * **`/__mg` ownership** ([`is_reserved`]): the raw path and both of
//!   Cloudflare's normalizations ([`rfc3986_view`], [`cloudflare_view`]). Any
//!   spelling that Cloudflare's `/__mg/` skip and cache rules can match is
//!   answered by the Edge and never reaches the origin.
//! * **Route matching** ([`route_candidates`]): the same three views plus the
//!   aggressive [`decoded_view`], each with and without a trailing slash, so
//!   that `/Account/Login/`, `/account%2Flogin` or `/account/login;x` cannot
//!   fall through to a less sensitive route than `/account/login`.
//!
//! Pure string functions: no allocation when a path needs no rewriting.
//! Callers pass the path without its query string.

use std::borrow::Cow;

/// Reserved path prefix of the Edge's own endpoints.
pub const EDGE_PREFIX: &str = "/__mg";

/// Whether `path` (without query) is in the Edge's reserved namespace: its
/// raw form, its RFC 3986 form or its Cloudflare form is `/__mg` or starts
/// with `/__mg/`. Matching is case-sensitive, like Cloudflare's rules.
pub fn is_reserved(path: &str) -> bool {
    let in_namespace = |p: &str| {
        p.strip_prefix(EDGE_PREFIX)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    in_namespace(path) || in_namespace(&rfc3986_view(path)) || in_namespace(&cloudflare_view(path))
}

/// The path as Cloudflare's "RFC 3986" URL normalization sees it: percent-encoded
/// unreserved characters decoded, then dot segments removed.
pub fn rfc3986_view(path: &str) -> Cow<'_, str> {
    if !path.contains(['%', '.']) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(remove_dot_segments(&decode_unreserved(path)))
}

/// The path as Cloudflare's default ("Cloudflare") URL normalization sees it:
/// unreserved characters decoded, `\` turned into `/`, runs of `/` merged,
/// then dot segments removed.
pub fn cloudflare_view(path: &str) -> Cow<'_, str> {
    if !path.contains(['%', '.', '\\']) && !path.contains("//") {
        return Cow::Borrowed(path);
    }
    let decoded = decode_unreserved(path).replace('\\', "/");
    Cow::Owned(remove_dot_segments(&merge_slashes(&decoded)))
}

/// The most aggressive reading an origin might apply: every `%XX` escape
/// decoded (including `%2F`, `%5C`, `%3B`; invalid UTF-8 becomes U+FFFD), `\`
/// turned into `/`, `;` path parameters removed from every segment
/// (`/a;x/b` -> `/a/b`), runs of `/` merged, then dot segments removed.
/// Used for route matching only, never for `/__mg` ownership.
pub fn decoded_view(path: &str) -> Cow<'_, str> {
    if !path.contains(['%', '.', '\\', ';']) && !path.contains("//") {
        return Cow::Borrowed(path);
    }
    let decoded = decode_all(path).replace('\\', "/");
    let without_params: Vec<&str> = decoded
        .split('/')
        .map(|segment| segment.split_once(';').map_or(segment, |(head, _)| head))
        .collect();
    Cow::Owned(remove_dot_segments(&merge_slashes(
        &without_params.join("/"),
    )))
}

/// The distinct strings a route pattern is matched against (spec §9.4): the
/// raw path, [`rfc3986_view`], [`cloudflare_view`] and [`decoded_view`], each
/// also with its trailing slash toggled (`/a` <-> `/a/`; never for `/`), all
/// lower-cased when `case_insensitive` is set. Order: raw first, then the
/// views in the order above, each followed by its toggled form; duplicates
/// are dropped (the first occurrence is kept).
pub fn route_candidates(path: &str, case_insensitive: bool) -> Vec<String> {
    let views = [
        Cow::Borrowed(path),
        rfc3986_view(path),
        cloudflare_view(path),
        decoded_view(path),
    ];
    let mut out: Vec<String> = Vec::with_capacity(8);
    let mut push = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for view in views {
        let base = if case_insensitive {
            view.to_lowercase()
        } else {
            view.into_owned()
        };
        let toggled = toggle_trailing_slash(&base);
        push(base);
        if let Some(t) = toggled {
            push(t);
        }
    }
    out
}

/// `/a/` -> `/a`, `/a` -> `/a/`; `None` for `/`, the empty string and
/// non-absolute paths such as `*`.
fn toggle_trailing_slash(path: &str) -> Option<String> {
    if !path.starts_with('/') || path == "/" {
        return None;
    }
    Some(match path.strip_suffix('/') {
        Some(trimmed) => trimmed.to_string(),
        None => format!("{path}/"),
    })
}

fn merge_slashes(path: &str) -> String {
    let mut merged = String::with_capacity(path.len());
    for c in path.chars() {
        if !(c == '/' && merged.ends_with('/')) {
            merged.push(c);
        }
    }
    merged
}

/// Parses the `%XX` escape starting at `bytes[i]`, if any.
fn escape_at(bytes: &[u8], i: usize) -> Option<(u8, &str)> {
    if bytes.get(i) != Some(&b'%') {
        return None;
    }
    let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
    u8::from_str_radix(hex, 16).ok().map(|b| (b, hex))
}

/// Decodes `%XX` escapes of RFC 3986 unreserved characters
/// (`A-Z a-z 0-9 - . _ ~`) and upper-cases the hex digits of all other escapes.
fn decode_unreserved(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match escape_at(bytes, i) {
            Some((b, _)) if b.is_ascii_alphanumeric() || b"-._~".contains(&b) => out.push(b),
            Some((_, hex)) => {
                out.push(b'%');
                out.extend(hex.to_ascii_uppercase().bytes());
            }
            None => {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
        }
        i += 3;
    }
    // Only ASCII bytes were decoded, so valid UTF-8 input stays valid.
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes every valid `%XX` escape; invalid escapes stay as they are.
fn decode_all(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some((b, _)) = escape_at(bytes, i) {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// RFC 3986 §5.2.4 `remove_dot_segments` for absolute paths; other inputs
/// (`*`, empty) are returned unchanged.
fn remove_dot_segments(path: &str) -> String {
    let Some(rest) = path.strip_prefix('/') else {
        return path.to_string();
    };
    let mut out: Vec<&str> = Vec::new();
    let mut trailing_slash = false;
    for segment in rest.split('/') {
        trailing_slash = matches!(segment, "." | "..");
        match segment {
            "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = format!("/{}", out.join("/"));
    if trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_on_raw_path() {
        for path in [
            "/__mg",
            "/__mg/",
            "/__mg/healthz",
            "/__mg/healthz/extra",
            "/__mg/c",
        ] {
            assert!(is_reserved(path), "{path}");
        }
        for path in ["/", "/__mgx", "/blog/__mg/healthz"] {
            assert!(!is_reserved(path), "{path}");
        }
    }

    /// Every spelling that Cloudflare's `starts_with(http.request.uri.path,
    /// "/__mg/")` rules can match is reserved.
    #[test]
    fn normalized_spellings_of_the_namespace_are_reserved() {
        for path in [
            "//__mg/c",
            "///__mg/healthz",
            "/%5F%5Fmg/c",
            "/%5f%5fmg/c",
            "/_%5Fmg/",
            "/%5F%5F%6D%67/c",
            "/./__mg/c",
            "/%2e/__mg/c",
            "/x/../__mg/c",
            "/x/%2E%2E/__mg/c",
            "/\\__mg/c",
            "/__mg/./healthz",
            "/__mg/..%2F..%2Fadmin",
            "/a//../__mg/x",
            "/__mg//../x",
            "/__mg/%2e%2e",
        ] {
            assert!(is_reserved(path), "{path}");
        }
    }

    #[test]
    fn lookalikes_are_not_reserved() {
        for path in [
            "/__mg%2Fc",
            "/__MG/c",
            "/x/__mg/c",
            "/__mgx/c",
            "/%5F%5Fmgx",
            "/__mg_/",
            "/a/b/../c",
            "/%7Euser/",
            "/assets//app.js",
            "*",
            "",
        ] {
            assert!(!is_reserved(path), "{path}");
        }
    }

    #[test]
    fn cloudflare_views() {
        assert_eq!(cloudflare_view("/a//b/./c/../%7E%41%2f"), "/a/b/~A%2F");
        assert_eq!(rfc3986_view("/a//b/./c/../%7E%41%2f"), "/a//b/~A%2F");
        assert_eq!(cloudflare_view("/a/b/.."), "/a/");
        assert_eq!(cloudflare_view("/.."), "/");
        assert_eq!(rfc3986_view("/%zz/%4"), "/%zz/%4");
        assert_eq!(rfc3986_view("/caf%C3%A9"), "/caf%C3%A9");
        assert!(matches!(cloudflare_view("/plain/path"), Cow::Borrowed(_)));
    }

    #[test]
    fn decoded_view_decodes_everything() {
        assert_eq!(decoded_view("/account%2Flogin"), "/account/login");
        assert_eq!(decoded_view("/account%5Clogin"), "/account/login");
        assert_eq!(
            decoded_view("/account/login;jsessionid=1"),
            "/account/login"
        );
        assert_eq!(decoded_view("/account;x/login"), "/account/login");
        assert_eq!(decoded_view("/account/login%3Bx"), "/account/login");
        assert_eq!(decoded_view("/a/%2e%2e/account//login"), "/account/login");
        assert_eq!(decoded_view("/caf%C3%A9"), "/café");
        assert_eq!(decoded_view("/%zz"), "/%zz");
        assert_eq!(decoded_view("/%ff"), "/\u{fffd}");
        assert!(matches!(decoded_view("/plain/path"), Cow::Borrowed(_)));
    }

    #[test]
    fn route_candidates_cover_bypass_spellings() {
        let has =
            |path: &str, ci: bool, want: &str| route_candidates(path, ci).iter().any(|c| c == want);
        assert!(has("/account/login/", false, "/account/login"));
        assert!(has("/account%2Flogin", false, "/account/login"));
        assert!(has("/account/login;x", false, "/account/login"));
        assert!(has("//account/./login", false, "/account/login"));
        assert!(has("/Account/Login", true, "/account/login"));
        assert!(!has("/Account/Login", false, "/account/login"));
        assert!(has("/api", false, "/api/"));
    }

    #[test]
    fn route_candidates_are_deduplicated_and_ordered() {
        assert_eq!(
            route_candidates("/a", false),
            vec!["/a".to_string(), "/a/".to_string()]
        );
        assert_eq!(route_candidates("/", false), vec!["/".to_string()]);
        assert_eq!(route_candidates("*", false), vec!["*".to_string()]);
        let c = route_candidates("/A%2fB/", true);
        assert_eq!(c[0], "/a%2fb/");
        assert!(c.contains(&"/a/b".to_string()));
        let mut dedup = c.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), c.len());
    }

    /// Deterministic random inputs never panic (spec §2.4).
    #[test]
    fn random_inputs_do_not_panic() {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let alphabet = b"/%.;\\aA_~2fF5cC3bBe";
        for _ in 0..10_000 {
            let mut s = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 24) as usize;
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                s.push(alphabet[(state % alphabet.len() as u64) as usize] as char);
            }
            let _ = is_reserved(&s);
            let _ = route_candidates(&s, state & 1 == 0);
        }
    }
}
