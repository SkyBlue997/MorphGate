//! The one glob implementation, used by the policy `glob()` function and by
//! route path patterns (docs/impl/phase1-spec.md §5.3, §9.4).
//!
//! Syntax (identical to `control-plane/internal/policy/funcs.go` `glob`):
//! `*` matches any run of characters except `/`; a run of two or more `*` is
//! one `**`, which matches any run including `/`; `?` matches exactly one
//! character except `/`; every other character matches itself. No classes,
//! no escapes. Case-sensitive, by Unicode scalar value. Matching is a
//! dynamic program over (subject character, pattern token): linear in
//! `|subject| * |pattern|`, no backtracking blow-up.

use std::fmt;

/// Longest accepted pattern, in bytes.
pub const MAX_GLOB_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(char),
    /// `?`
    One,
    /// `*`
    Star,
    /// `**` (or any longer run of stars)
    DoubleStar,
}

impl Tok {
    fn is_star(self) -> bool {
        matches!(self, Self::Star | Self::DoubleStar)
    }
}

/// A pattern that [`Glob::new`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobError {
    /// The empty pattern.
    Empty,
    /// Longer than [`MAX_GLOB_LEN`] bytes.
    TooLong,
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("glob: empty pattern"),
            Self::TooLong => write!(f, "glob: pattern longer than {MAX_GLOB_LEN} bytes"),
        }
    }
}

impl std::error::Error for GlobError {}

/// A compiled glob pattern.
#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: String,
    /// Tokens after the literal prefix.
    rest: Vec<Tok>,
    /// Characters before the first `*` or `?`.
    prefix: String,
    wildcards: usize,
}

impl Glob {
    /// Compiles `pattern`.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        if pattern.len() > MAX_GLOB_LEN {
            return Err(GlobError::TooLong);
        }
        let mut toks = Vec::with_capacity(pattern.len());
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            toks.push(match c {
                '*' if chars.peek() == Some(&'*') => {
                    while chars.peek() == Some(&'*') {
                        chars.next();
                    }
                    Tok::DoubleStar
                }
                '*' => Tok::Star,
                '?' => Tok::One,
                c => Tok::Lit(c),
            });
        }
        let prefix_len = toks.iter().take_while(|t| matches!(t, Tok::Lit(_))).count();
        let prefix: String = toks[..prefix_len]
            .iter()
            .filter_map(|t| match t {
                Tok::Lit(c) => Some(*c),
                _ => None,
            })
            .collect();
        let rest = toks.split_off(prefix_len);
        let wildcards = rest.iter().filter(|t| !matches!(t, Tok::Lit(_))).count();
        Ok(Self {
            pattern: pattern.to_string(),
            rest,
            prefix,
            wildcards,
        })
    }

    /// The source pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Characters before the first `*` or `?` (the whole pattern if it has no wildcard).
    pub fn literal_prefix(&self) -> &str {
        &self.prefix
    }

    /// Number of wildcards: each `*`, each `?`, and each run of `**` counted once.
    pub fn wildcard_count(&self) -> usize {
        self.wildcards
    }

    /// Whether `s` matches. The literal prefix is compared first; the dynamic
    /// program only runs on the remainder.
    pub fn matches(&self, s: &str) -> bool {
        let Some(rest) = s.strip_prefix(self.prefix.as_str()) else {
            return false;
        };
        let toks = &self.rest;
        if toks.is_empty() {
            return rest.is_empty();
        }
        // reach[j]: the characters consumed so far can be matched by toks[..j].
        let mut reach = vec![false; toks.len() + 1];
        let mut next = vec![false; toks.len() + 1];
        reach[0] = true;
        close_stars(toks, &mut reach);
        for c in rest.chars() {
            next.iter_mut().for_each(|r| *r = false);
            let mut any = false;
            for (j, t) in toks.iter().enumerate() {
                if !reach[j] {
                    continue;
                }
                match *t {
                    Tok::Lit(l) if l == c => {
                        next[j + 1] = true;
                        any = true;
                    }
                    Tok::One if c != '/' => {
                        next[j + 1] = true;
                        any = true;
                    }
                    Tok::Star if c != '/' => {
                        next[j] = true;
                        any = true;
                    }
                    Tok::DoubleStar => {
                        next[j] = true;
                        any = true;
                    }
                    _ => {}
                }
            }
            if !any {
                return false;
            }
            std::mem::swap(&mut reach, &mut next);
            close_stars(toks, &mut reach);
        }
        reach[toks.len()]
    }
}

/// A star may match the empty string: propagate reachability across stars.
fn close_stars(toks: &[Tok], reach: &mut [bool]) {
    for (j, t) in toks.iter().enumerate() {
        if reach[j] && t.is_star() {
            reach[j + 1] = true;
        }
    }
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Glob").field(&self.pattern).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(s: &str, p: &str) -> bool {
        Glob::new(p).unwrap().matches(s)
    }

    /// `funcs_test.go` `TestGlob`, case for case.
    #[test]
    fn matches_go_reference_table() {
        for (s, p, want) in [
            ("/admin", "/admin", true),
            ("/admin/", "/admin", false),
            ("/admin/users", "/admin/*", true),
            ("/admin/users/1", "/admin/*", false),
            ("/admin/users/1", "/admin/**", true),
            ("/admin", "/admin/**", false),
            ("/admin/", "/admin/**", true),
            ("/api/v1/login", "/api/*/login", true),
            ("/api/v1/x/login", "/api/*/login", false),
            ("/api/v1/x/login", "/api/**/login", true),
            ("/a.js", "/*.js", true),
            ("/a/b.js", "/*.js", false),
            ("/a/b.js", "/**.js", true),
            ("/ab", "/a?", true),
            ("/a/", "/a?", false),
            ("/A", "/a", false),
            ("", "**", true),
            ("", "*", true),
            ("/日本/語", "/*/?", true),
            (
                "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
                "/*a*a*a*a*a*a*a*a*a*a*c",
                false,
            ),
        ] {
            assert_eq!(glob(s, p), want, "glob({s:?}, {p:?})");
        }
        assert_eq!(Glob::new(""), Err(GlobError::Empty));
    }

    #[test]
    fn star_runs_and_question_marks() {
        assert!(glob("/a/b/c", "/***"), "a run of 3 stars is **");
        assert!(glob("/a/b/c", "/a/***/c"));
        assert!(!glob("/a/b", "/a/*/?"));
        assert!(glob("/a/bc", "/a/*?"));
        assert!(!glob("/a/", "/a/?"));
        assert!(
            glob("/a/é", "/a/?"),
            "? is one Unicode scalar, not one byte"
        );
        assert!(!glob("/a/éé", "/a/?"));
        assert!(glob("x", "?"));
        assert!(!glob("", "?"));
        assert!(glob("/x/", "/*/"));
        assert!(glob("//", "/*/"), "* matches the empty run");
        assert!(glob("abc", "abc"));
        assert!(!glob("abcd", "abc"));
        assert!(!glob("ab", "abc"));
        assert!(glob("/a/b/c/d.txt", "/**/*.txt"));
        assert!(!glob("/a/b/c/d.txt", "/*/*.txt"));
    }

    #[test]
    fn literal_prefix_and_wildcard_count() {
        for (p, prefix, count) in [
            ("/account/login", "/account/login", 0),
            ("/api/**", "/api/", 1),
            ("/api/*/x/?", "/api/", 2),
            ("/a?/*/**", "/a", 3),
            ("/a/***/b/**", "/a/", 2),
            ("*", "", 1),
            ("?abc", "", 1),
            ("/日本/*", "/日本/", 1),
        ] {
            let g = Glob::new(p).unwrap();
            assert_eq!(g.literal_prefix(), prefix, "{p}");
            assert_eq!(g.wildcard_count(), count, "{p}");
            assert_eq!(g.pattern(), p);
        }
    }

    #[test]
    fn length_limit() {
        assert!(Glob::new(&"a".repeat(MAX_GLOB_LEN)).is_ok());
        assert_eq!(
            Glob::new(&"a".repeat(MAX_GLOB_LEN + 1)),
            Err(GlobError::TooLong)
        );
    }

    /// A reference backtracking matcher on small inputs agrees with the DP.
    #[test]
    fn agrees_with_naive_matcher() {
        fn naive(s: &[char], p: &[char]) -> bool {
            match p.first() {
                None => s.is_empty(),
                Some('*') if p.get(1) == Some(&'*') => {
                    let mut i = 1;
                    while p.get(i) == Some(&'*') {
                        i += 1;
                    }
                    (0..=s.len()).any(|k| naive(&s[k..], &p[i..]))
                }
                Some('*') => (0..=s.len())
                    .take_while(|&k| k == 0 || s[k - 1] != '/')
                    .any(|k| naive(&s[k..], &p[1..])),
                Some('?') => s.first().is_some_and(|c| *c != '/') && naive(&s[1..], &p[1..]),
                Some(c) => s.first() == Some(c) && naive(&s[1..], &p[1..]),
            }
        }
        let alphabet = ['a', 'b', '/', '*', '?'];
        let mut state: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let plen = (next() % 7 + 1) as usize;
            let slen = (next() % 8) as usize;
            let p: String = (0..plen).map(|_| alphabet[(next() % 5) as usize]).collect();
            let s: String = (0..slen).map(|_| alphabet[(next() % 3) as usize]).collect();
            let sc: Vec<char> = s.chars().collect();
            let pc: Vec<char> = p.chars().collect();
            assert_eq!(glob(&s, &p), naive(&sc, &pc), "glob({s:?}, {p:?})");
        }
    }
}
