//! Environment and route selection (§9.4 steps 5-6, D-25).
//!
//! Routes are the security boundary for `require_clearance` and `critical`,
//! and origin frameworks often hand `/Account/Login/`, `/account%2Flogin` and
//! `/account/login;x` to the same handler. So a route is matched against
//! every path view of `mg_core::paths::route_candidates` (raw, RFC 3986,
//! Cloudflare, fully decoded without parameters; each also with the trailing
//! slash toggled; lower-cased under `case_insensitive_paths`):
//!
//! 1. for each candidate, the first route in declared order whose hosts,
//!    methods and any pattern match (methods ASCII case-insensitively: the
//!    bundle's are upper-case, and origin frameworks such as Werkzeug and
//!    Django normalize the case of the method they dispatch on, so `post`
//!    must select a POST-only route just like `POST`; and a route that lists
//!    `GET` also admits `HEAD`, see [`method_admits`]);
//! 2. of those, the most sensitive one is selected (ties: declared first);
//! 3. `require_clearance` and `fail_closed` are the OR over every route found
//!    in step 1, not only the selected one.
//!
//! Route matching does not go through the policy evaluator; the §8.2 caps
//! (≤ 64 routes, ≤ 16 patterns of ≤ 128 bytes with ≤ 4 wildcards) and the
//! 8 KiB path limit bound the work, and each distinct candidate is matched
//! once.

use super::convert::{EnvRuntime, RouteRuntime};

/// The route a request is attributed to.
#[derive(Debug, Clone, Copy)]
pub struct RouteMatch<'a> {
    /// The selected (most sensitive) route.
    pub route: &'a RouteRuntime,
    /// OR over every route matched by some candidate.
    pub require_clearance: bool,
    /// OR over every route matched by some candidate.
    pub fail_closed: bool,
}

/// The environment whose hosts contain `host` (the bundle's environments
/// partition the site's hosts).
pub fn select_env<'a>(envs: &'a [EnvRuntime], host: &str) -> Option<&'a EnvRuntime> {
    envs.iter().find(|e| e.hosts.iter().any(|h| h == host))
}

/// Selects the route of a request (see the module documentation). `path`
/// excludes the query string. `fallback` is used when nothing matches (the
/// builder's catch-all makes that impossible for mgctl-built bundles).
pub fn select_route<'a>(
    env: &'a EnvRuntime,
    host: &str,
    method: &str,
    path: &str,
    case_insensitive: bool,
    fallback: &'a RouteRuntime,
) -> RouteMatch<'a> {
    let candidates = mg_core::paths::route_candidates(path, case_insensitive);
    let eligible: Vec<&RouteRuntime> = env
        .routes
        .iter()
        .filter(|r| r.hosts.is_empty() || r.hosts.iter().any(|h| h == host))
        .filter(|r| r.methods.is_empty() || r.methods.iter().any(|m| method_admits(m, method)))
        .collect();

    let mut selected: Option<(usize, &RouteRuntime)> = None;
    let mut require_clearance = false;
    let mut fail_closed = false;
    for candidate in &candidates {
        let Some((pos, route)) = eligible
            .iter()
            .enumerate()
            .find(|(_, r)| r.patterns.iter().any(|g| g.matches(candidate)))
        else {
            continue;
        };
        require_clearance |= route.require_clearance;
        fail_closed |= route.fail_closed;
        let better = match selected {
            None => true,
            Some((best_pos, best)) => {
                route.sensitivity > best.sensitivity
                    || (route.sensitivity == best.sensitivity && pos < best_pos)
            }
        };
        if better {
            selected = Some((pos, route));
        }
    }
    match selected {
        Some((_, route)) => RouteMatch {
            route,
            require_clearance,
            fail_closed,
        },
        None => RouteMatch {
            route: env
                .routes
                .iter()
                .find(|r| r.id == "default")
                .unwrap_or(fallback),
            require_clearance: false,
            fail_closed: false,
        },
    }
}

/// Whether a route that lists `route_method` admits a request `method`:
/// ASCII case-insensitively, and `GET` also admits `HEAD`. RFC 9110 §9.3.2
/// makes `HEAD` a `GET` without the content, and origin frameworks (Flask,
/// Django, Rails, Express, Go's `http.ServeMux` patterns) run the `GET`
/// handler for it; without this a `HEAD` of a `GET`-only `require_clearance`
/// or `critical` route would fall through to the default route and reach
/// that handler unchallenged and without the route's limiters.
fn method_admits(route_method: &str, method: &str) -> bool {
    route_method.eq_ignore_ascii_case(method)
        || (route_method.eq_ignore_ascii_case("GET") && method.eq_ignore_ascii_case("HEAD"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::policy::Glob;
    use mg_core::{Channel, RouteSensitivity};

    fn route(name: &str, paths: &[&str], sensitivity: RouteSensitivity) -> RouteRuntime {
        RouteRuntime {
            id: name.into(),
            name: name.into(),
            hosts: Vec::new(),
            methods: Vec::new(),
            channel: Channel::Web,
            sensitivity,
            fail_closed: sensitivity == RouteSensitivity::Critical,
            require_clearance: sensitivity == RouteSensitivity::Critical,
            redact_path: false,
            patterns: paths.iter().map(|p| Glob::new(p).unwrap()).collect(),
        }
    }

    fn env(routes: Vec<RouteRuntime>) -> EnvRuntime {
        EnvRuntime {
            name: "production".into(),
            hosts: vec!["example.com".into()],
            routes,
            rules: Vec::new(),
            limiters: Vec::new(),
            automation_allowlist_only: false,
            core: crate::decide::build_core(
                Vec::new(),
                Default::default(),
                &crate::sites::default_scoring(),
                &crate::sites::default_crawler_policy(),
            ),
        }
    }

    fn pick<'a>(e: &'a EnvRuntime, method: &str, path: &str, ci: bool) -> RouteMatch<'a> {
        static FALLBACK: std::sync::LazyLock<RouteRuntime> =
            std::sync::LazyLock::new(RouteRuntime::fallback);
        select_route(e, "example.com", method, path, ci, &FALLBACK)
    }

    fn site() -> EnvRuntime {
        let mut login = route(
            "login",
            &["/account/login", "/api/login"],
            RouteSensitivity::Critical,
        );
        login.methods = vec!["GET".into(), "POST".into()];
        env(vec![
            login,
            route("reset", &["/account/reset/**"], RouteSensitivity::High),
            route("api", &["/api/**"], RouteSensitivity::Medium),
            route("default", &["/**"], RouteSensitivity::Low),
        ])
    }

    /// §9.4 example: every spelling an origin may treat as the login page
    /// selects the critical route.
    #[test]
    fn login_spellings_select_the_critical_route() {
        let e = site();
        for path in [
            "/account/login",
            "/account/login/",
            "/account%2Flogin",
            "/account/login;jsessionid=1",
            "//account/./login",
            "/account/x/../login",
            "/%61ccount/login",
        ] {
            let m = pick(&e, "GET", path, false);
            assert_eq!(m.route.name, "login", "{path}");
            assert!(m.require_clearance && m.fail_closed, "{path}");
        }
        // Case only matters without case_insensitive_paths.
        assert_eq!(
            pick(&e, "GET", "/Account/Login", false).route.name,
            "default"
        );
        assert_eq!(pick(&e, "GET", "/Account/Login", true).route.name, "login");
        assert_eq!(pick(&e, "GET", "/ACCOUNT/LOGIN/", true).route.name, "login");
    }

    #[test]
    fn methods_and_hosts_restrict_routes() {
        let e = site();
        // login is GET / POST only: a PUT falls through to the next matches.
        assert_eq!(
            pick(&e, "PUT", "/account/login", false).route.name,
            "default"
        );
        assert_eq!(pick(&e, "DELETE", "/api/login", false).route.name, "api");
        // Method names are compared ASCII case-insensitively: frameworks such
        // as Werkzeug (Flask) and Django upper- / lower-case the method
        // before dispatching, so a lower-case `post` must not fall through
        // from a critical POST route to the default one (D-25's reasoning).
        for method in ["post", "Post", "gEt"] {
            let m = pick(&e, method, "/account/login", false);
            assert_eq!(m.route.name, "login", "{method}");
            assert!(m.require_clearance && m.fail_closed, "{method}");
        }
        assert_eq!(
            pick(&e, "put", "/account/login", false).route.name,
            "default"
        );
        // A GET route also takes HEAD (the origin runs its GET handler), so
        // HEAD cannot reach a GET-only critical route unchallenged.
        for method in ["HEAD", "head"] {
            let m = pick(&e, method, "/account/login", false);
            assert_eq!(m.route.name, "login", "{method}");
            assert!(m.require_clearance && m.fail_closed, "{method}");
        }
        let mut post_only = route("post-only", &["/submit"], RouteSensitivity::Critical);
        post_only.methods = vec!["POST".into()];
        let e2 = env(vec![
            post_only,
            route("default", &["/**"], RouteSensitivity::Low),
        ]);
        assert_eq!(pick(&e2, "HEAD", "/submit", false).route.name, "default");
        assert_eq!(pick(&e2, "GET", "/submit", false).route.name, "default");

        let mut only_admin = route("admin", &["/**"], RouteSensitivity::High);
        only_admin.hosts = vec!["admin.example.com".into()];
        let e = env(vec![
            only_admin,
            route("default", &["/**"], RouteSensitivity::Low),
        ]);
        static FALLBACK: std::sync::LazyLock<RouteRuntime> =
            std::sync::LazyLock::new(RouteRuntime::fallback);
        let m = select_route(&e, "example.com", "GET", "/x", false, &FALLBACK);
        assert_eq!(m.route.name, "default");
        let m = select_route(&e, "admin.example.com", "GET", "/x", false, &FALLBACK);
        assert_eq!(m.route.name, "admin");
    }

    /// Different views can hit different routes: the most sensitive wins,
    /// and the flags are the OR over all of them.
    #[test]
    fn most_sensitive_match_wins_and_flags_are_ored() {
        let mut raw_only = route("raw", &["/a%2Fb"], RouteSensitivity::Medium);
        raw_only.require_clearance = true;
        let mut decoded = route("decoded", &["/a/b"], RouteSensitivity::High);
        decoded.fail_closed = true;
        let e = env(vec![
            raw_only,
            decoded,
            route("default", &["/**"], RouteSensitivity::Low),
        ]);
        let m = pick(&e, "GET", "/a%2Fb", false);
        assert_eq!(m.route.name, "decoded");
        assert!(m.require_clearance, "OR includes the medium route's flag");
        assert!(m.fail_closed);

        // Equal sensitivity: the one declared first.
        let e = env(vec![
            route("first", &["/x/"], RouteSensitivity::High),
            route("second", &["/x"], RouteSensitivity::High),
        ]);
        assert_eq!(pick(&e, "GET", "/x", false).route.name, "first");
    }

    #[test]
    fn no_match_uses_default_or_fallback() {
        let e = env(vec![route("only", &["/only"], RouteSensitivity::High)]);
        let m = pick(&e, "GET", "/other", false);
        assert_eq!(m.route.name, "default");
        assert_eq!(m.route.sensitivity, RouteSensitivity::Low);
        assert!(!m.require_clearance && !m.fail_closed);
    }

    #[test]
    fn env_by_host() {
        let prod = env(Vec::new());
        let mut staging = env(Vec::new());
        staging.name = "staging".into();
        staging.hosts = vec!["staging.example.com".into()];
        let envs = [prod, staging];
        assert_eq!(select_env(&envs, "example.com").unwrap().name, "production");
        assert_eq!(
            select_env(&envs, "staging.example.com").unwrap().name,
            "staging"
        );
        assert!(select_env(&envs, "other.example.com").is_none());
    }
}
