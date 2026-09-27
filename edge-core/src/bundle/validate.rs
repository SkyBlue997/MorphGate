//! Structural and bound checks of a verified `SiteBundle` (§8.2 "WP-C2 在
//! Edge 加载配置包时对进入配置包的项再做一遍", §8.3, §9.10).
//!
//! The builder (mgctl, WP-G2) runs the same rules on the site YAML; the Edge
//! repeats every rule whose input is inside the bundle so that a buggy or
//! hand-made bundle cannot put the Edge outside the ranges the rest of the
//! code (GCRA arithmetic in Lua doubles, PoW difficulty, token lifetimes,
//! route matching cost) relies on. Any violation rejects the whole bundle.
//!
//! Rules that need other inputs stay with the caller: the version ordering,
//! the listener profiles, the token key ids against `token.keys.json`, and
//! the conversion of rules / IR (`max_steps`) / artifacts (§9.10).
//!
//! Messages that are absent as a whole (`challenge`, `clearance`, `scoring`,
//! `crawler_policy`, `events`, `origin_headers`) are valid: the Edge fills in
//! the §8.3 defaults for them. Present messages are checked field by field.

use super::util::{
    is_dns_name, is_kid, is_limiter_id, is_listener_name, is_method, is_route_name, is_sha256_hex,
};
use super::verify::printable;
use super::{BundleError, artifact_limit};
use mg_core::gcra::GcraParams;
use mg_proto::v1::{
    Action, ChallengeConfig, ChallengeType, Channel, ClearanceConfig, CompiledRule, CrawlerPolicy,
    Environment, EventConfig, RateLimit, Route, RouteSensitivity, ScoringConfig, SiteBundle,
    UpstreamProfileKind,
};
use std::collections::{BTreeMap, BTreeSet};

/// Environment names (§8.2).
const ENVIRONMENT_NAMES: &[&str] = &["production", "staging", "test", "dev"];
/// Declared routes per environment (§8.2) ...
const MAX_ROUTES: usize = 64;
/// ... plus the catch-all the builder appends (§8.3).
const DEFAULT_ROUTE_ID: &str = "default";
const MAX_LIMITERS: usize = 64;
const MAX_PATTERNS: usize = 16;
const MAX_PATTERN_BYTES: usize = 128;
const MAX_WILDCARDS: usize = 4;
const MAX_LIST_ENTRIES: usize = 10_000;
const MAX_LIST_ENTRY_BYTES: usize = 256;
const MAX_RET_BYTES: usize = 512;
const LIMITER_KEYS: &[&str] = &["ip", "ip_prefix", "asn", "session", "route"];
const RULE_PARAMS: &[&str] = &["type", "label", "limiter", "retry_after_s"];
const CRAWLER_PURPOSES: &[&str] = &[
    "search",
    "ai_training",
    "ai_search",
    "user_triggered",
    "archive",
    "other",
];
const SIGNAL_FAMILIES: &[&str] = &[
    "network",
    "tls",
    "http",
    "client",
    "behavior",
    "reputation",
    "rate",
    "identity",
    "edge_tls",
    "external",
];
const SENSITIVITIES: &[&str] = &["low", "medium", "high", "critical"];

type Result<T = ()> = std::result::Result<T, BundleError>;

fn fail(field: impl Into<String>, reason: impl Into<String>) -> Result {
    Err(BundleError::invalid(field, reason))
}

fn ensure(ok: bool, field: impl FnOnce() -> String, reason: &str) -> Result {
    if ok { Ok(()) } else { fail(field(), reason) }
}

/// Every rule of this module, in field order.
pub(crate) fn check_bounds(b: &SiteBundle) -> Result {
    ensure(b.version >= 1, || "version".into(), "must be >= 1")?;
    ensure(
        b.not_before_ms >= 0,
        || "not_before_ms".into(),
        "must be >= 0",
    )?;
    check_upstream(b)?;
    check_unique_names(&b.allowed_listeners, "allowed_listeners", is_listener_name)?;
    ensure(
        !b.token_key_ids.is_empty(),
        || "token_key_ids".into(),
        "must name at least the active key",
    )?;
    check_unique_names(&b.token_key_ids, "token_key_ids", is_kid)?;
    check_environments(b)?;
    if let Some(c) = &b.challenge {
        check_challenge(c)?;
    }
    if let Some(c) = &b.clearance {
        check_clearance(c)?;
    }
    if let Some(s) = &b.scoring {
        check_scoring(s)?;
    }
    if let Some(p) = &b.crawler_policy {
        check_crawler_policy(p)?;
    }
    if let Some(e) = &b.events {
        check_events(e)?;
    }
    check_lists(b)?;
    check_artifacts(b)
}

fn check_upstream(b: &SiteBundle) -> Result {
    let Some(up) = &b.upstream else {
        return fail("upstream", "missing");
    };
    let kind = UpstreamProfileKind::try_from(up.kind);
    let cloudflare = match kind {
        Ok(UpstreamProfileKind::Cloudflare) => true,
        Ok(UpstreamProfileKind::DirectTls) => false,
        _ => {
            return fail(
                "upstream.kind",
                "must be cloudflare or direct_tls in Phase 1",
            );
        }
    };
    match (&b.cloudflare, cloudflare) {
        (Some(cf), true) => {
            for (i, zone) in cf.owner_zones.iter().enumerate() {
                ensure(
                    is_dns_name(zone),
                    || format!("cloudflare.owner_zones[{i}]"),
                    "must be a lower-case DNS name",
                )?;
            }
            Ok(())
        }
        (None, true) => fail("cloudflare", "required for the cloudflare profile"),
        (Some(_), false) => fail("cloudflare", "only allowed for the cloudflare profile"),
        (None, false) => Ok(()),
    }
}

fn check_unique_names(names: &[String], field: &str, valid: fn(&str) -> bool) -> Result {
    let mut seen = BTreeSet::new();
    for (i, name) in names.iter().enumerate() {
        ensure(valid(name), || format!("{field}[{i}]"), "invalid name")?;
        ensure(seen.insert(name), || format!("{field}[{i}]"), "duplicate")?;
    }
    Ok(())
}

fn check_environments(b: &SiteBundle) -> Result {
    ensure(
        !b.environments.is_empty(),
        || "environments".into(),
        "at least one environment is required",
    )?;
    let site_hosts: BTreeSet<&str> = b.hosts.iter().map(String::as_str).collect();
    let mut env_names = BTreeSet::new();
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for (i, env) in b.environments.iter().enumerate() {
        let at = |f: &str| format!("environments[{i}].{f}");
        ensure(
            ENVIRONMENT_NAMES.contains(&env.name.as_str()),
            || at("name"),
            "must be production, staging, test or dev",
        )?;
        ensure(
            env_names.insert(env.name.as_str()),
            || at("name"),
            "duplicate",
        )?;
        ensure(!env.hosts.is_empty(), || at("hosts"), "must not be empty")?;
        for host in &env.hosts {
            ensure(
                site_hosts.contains(host.as_str()),
                || at("hosts"),
                "host is not one of the site's hosts",
            )?;
            // A host in two environments (or twice in one) breaks the partition.
            ensure(
                covered.insert(host.as_str()),
                || at("hosts"),
                "host belongs to more than one environment",
            )?;
        }
        check_env(env, b.case_insensitive_paths, &at)?;
    }
    ensure(
        covered.len() == site_hosts.len(),
        || "environments".into(),
        "environment hosts must cover every site host",
    )
}

fn check_env(env: &Environment, case_insensitive: bool, at: &dyn Fn(&str) -> String) -> Result {
    let env_hosts: BTreeSet<&str> = env.hosts.iter().map(String::as_str).collect();
    let declared = match env.routes.last() {
        Some(last) if env.routes.len() == MAX_ROUTES + 1 && is_builder_default(last) => MAX_ROUTES,
        _ => env.routes.len(),
    };
    ensure(
        declared <= MAX_ROUTES,
        || at("routes"),
        "more than 64 routes",
    )?;
    let mut route_ids = BTreeSet::new();
    let mut route_names = BTreeSet::new();
    for (j, route) in env.routes.iter().enumerate() {
        let at = |f: &str| at(&format!("routes[{j}].{f}"));
        check_route(route, &env_hosts, case_insensitive, &at)?;
        ensure(
            route_names.insert(route.name.as_str()),
            || at("name"),
            "duplicate",
        )?;
        route_ids.insert(route.id.as_str());
    }

    ensure(
        env.rate_limits.len() <= MAX_LIMITERS,
        || at("rate_limits"),
        "more than 64 rate limiters",
    )?;
    let mut limiter_ids = BTreeSet::new();
    for (j, rl) in env.rate_limits.iter().enumerate() {
        let at = |f: &str| at(&format!("rate_limits[{j}].{f}"));
        check_rate_limit(rl, &route_ids, &at)?;
        ensure(limiter_ids.insert(rl.id.as_str()), || at("id"), "duplicate")?;
    }

    for (j, rule) in env.rules.iter().enumerate() {
        check_rule(rule, &|f: &str| at(&format!("rules[{j}].{f}")))?;
    }
    Ok(())
}

/// The route the builder appends (§8.3): `{id: "default", paths: ["/**"]}`.
fn is_builder_default(r: &Route) -> bool {
    r.id == DEFAULT_ROUTE_ID && r.paths == ["/**"]
}

fn check_route(
    r: &Route,
    env_hosts: &BTreeSet<&str>,
    case_insensitive: bool,
    at: &dyn Fn(&str) -> String,
) -> Result {
    ensure(
        is_route_name(&r.name),
        || at("name"),
        "must match [a-z0-9_-]{1,32}",
    )?;
    // §8.3: Route.id = Route.name; limiters reference routes by id.
    ensure(r.id == r.name, || at("id"), "must equal the route name")?;
    for host in &r.hosts {
        ensure(
            env_hosts.contains(host.as_str()),
            || at("hosts"),
            "host is not one of the environment's hosts",
        )?;
    }
    // The deprecated path_glob counts as one more pattern (config.proto).
    let patterns: Vec<&str> = r
        .paths
        .iter()
        .map(String::as_str)
        .chain((!r.path_glob.is_empty()).then_some(r.path_glob.as_str()))
        .collect();
    ensure(
        (1..=MAX_PATTERNS).contains(&patterns.len()),
        || at("paths"),
        "must have 1 to 16 patterns",
    )?;
    for p in patterns {
        check_pattern(p).or_else(|reason| fail(at("paths"), reason))?;
        // §8.2 / D-25: `case_insensitive_paths` patterns are stored
        // lower-cased. The Edge lower-cases every path view before matching,
        // so an upper-case pattern would never match anything: a critical
        // route would silently fall through to a less sensitive one.
        ensure(
            !case_insensitive || !p.bytes().any(|c| c.is_ascii_uppercase()),
            || at("paths"),
            "patterns must be lower-case when case_insensitive_paths is set",
        )?;
    }
    for m in &r.methods {
        ensure(
            is_method(m),
            || at("methods"),
            "must be an upper-case HTTP method",
        )?;
    }
    ensure(
        Channel::try_from(r.channel).is_ok_and(|c| c != Channel::Unspecified),
        || at("channel"),
        "must be web, api or mobile",
    )?;
    ensure(
        RouteSensitivity::try_from(r.sensitivity).is_ok_and(|s| s != RouteSensitivity::Unspecified),
        || at("sensitivity"),
        "must be low, medium, high or critical",
    )
}

/// §8.2 route pattern: starts with `/`, visible ASCII only, <= 128 bytes,
/// at most 4 wildcards (a run of `*` counts once, each `?` counts once).
fn check_pattern(p: &str) -> std::result::Result<(), &'static str> {
    if !p.starts_with('/') {
        return Err("pattern must start with '/'");
    }
    if p.len() > MAX_PATTERN_BYTES {
        return Err("pattern longer than 128 bytes");
    }
    if !p.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("pattern must be visible ASCII");
    }
    if wildcard_count(p) > MAX_WILDCARDS {
        return Err("pattern has more than 4 wildcards");
    }
    Ok(())
}

fn wildcard_count(p: &str) -> usize {
    let mut count = 0;
    let mut prev_star = false;
    for c in p.bytes() {
        match c {
            b'*' if !prev_star => count += 1,
            b'?' => count += 1,
            _ => {}
        }
        prev_star = c == b'*';
    }
    count
}

/// §8.2 limiter numbers, shared by the site's limiters and the built-in
/// `mg.c.*` / `mg.clr.issue.*` limiters of `challenge` (§9.8).
fn check_gcra(rate: u32, period_s: u32, burst: u32) -> std::result::Result<(), &'static str> {
    if rate < 1 {
        return Err("rate must be >= 1");
    }
    if !(1..=86_400).contains(&period_s) {
        return Err("period must be 1..=86400 s");
    }
    if !(1..=100_000).contains(&burst) {
        return Err("burst must be 1..=100000");
    }
    if GcraParams::new(rate, period_s, burst).is_none() {
        return Err("interval x burst exceeds 7 days (or the interval rounds to 0)");
    }
    Ok(())
}

fn check_rate_limit(
    rl: &RateLimit,
    route_ids: &BTreeSet<&str>,
    at: &dyn Fn(&str) -> String,
) -> Result {
    ensure(
        is_limiter_id(&rl.id) && !rl.id.starts_with("mg."),
        || at("id"),
        "must match [a-z0-9][a-z0-9_.-]{0,63} and not start with \"mg.\"",
    )?;
    ensure(rl.algorithm == "gcra", || at("algorithm"), "must be gcra")?;
    check_gcra(rl.rate, rl.period_s, rl.burst).or_else(|reason| fail(at("rate"), reason))?;
    ensure(!rl.key.is_empty(), || at("key"), "must not be empty")?;
    let mut keys = BTreeSet::new();
    for k in &rl.key {
        ensure(
            LIMITER_KEYS.contains(&k.as_str()),
            || at("key"),
            "must be ip, ip_prefix, asn, session or route",
        )?;
        ensure(
            keys.insert(k.as_str()),
            || at("key"),
            "duplicate key component",
        )?;
    }
    for id in rl
        .route_ids
        .iter()
        .chain((!rl.route_id.is_empty()).then_some(&rl.route_id))
    {
        ensure(
            route_ids.contains(id.as_str()),
            || at("route_ids"),
            "names a route that does not exist in this environment",
        )?;
    }
    // Empty scope / mode mean the documented defaults (config.proto: zero
    // values are defaults): global and enforce, the stricter choices.
    ensure(
        matches!(rl.scope.as_str(), "" | "global" | "local"),
        || at("scope"),
        "must be global or local",
    )?;
    ensure(
        matches!(rl.mode.as_str(), "" | "enforce" | "dry_run"),
        || at("mode"),
        "must be enforce or dry_run",
    )?;
    match rl.on_exceed.as_str() {
        "signal" => ensure(
            rl.signal_weight.is_finite() && rl.signal_weight > 0.0 && rl.signal_weight <= 2.0,
            || at("signal_weight"),
            "must be in (0, 2]",
        ),
        "challenge" => ensure(
            matches!(
                ChallengeType::try_from(rl.challenge_type),
                Ok(ChallengeType::Invisible | ChallengeType::Pow)
            ),
            || at("challenge_type"),
            "must be invisible or pow",
        ),
        "rate_limit" | "block" => Ok(()),
        _ => fail(
            at("on_exceed"),
            "must be signal, challenge, rate_limit or block",
        ),
    }
}

fn check_rule(r: &CompiledRule, at: &dyn Fn(&str) -> String) -> Result {
    ensure(!r.id.is_empty(), || at("id"), "must not be empty")?;
    match Action::try_from(r.action) {
        Ok(Action::Tarpit) => {
            return fail(at("action"), "tarpit is not supported in Phase 1 (D-09)");
        }
        Ok(Action::Unspecified) | Err(_) => return fail(at("action"), "unknown action"),
        Ok(_) => {}
    }
    ensure(r.ir_version == 1, || at("ir_version"), "must be 1")?;
    ensure(
        !r.expr_ir.is_empty(),
        || at("expr_ir"),
        "policy IR unavailable",
    )?;
    // Disabled rules never enter a bundle (D-19).
    ensure(
        matches!(r.mode.as_str(), "enforce" | "dry_run"),
        || at("mode"),
        "must be enforce or dry_run",
    )?;
    ensure(
        r.rollout_percent <= 100,
        || at("rollout_percent"),
        "must be 0..=100",
    )?;
    for key in r.params.keys() {
        ensure(
            RULE_PARAMS.contains(&key.as_str()),
            || at("params"),
            "only type, label, limiter and retry_after_s are allowed",
        )?;
    }
    Ok(())
}

fn check_challenge(c: &ChallengeConfig) -> Result {
    let at = |f: &str| format!("challenge.{f}");
    ensure(
        (10..=120).contains(&c.ttl_s),
        || at("ttl_s"),
        "must be 10..=120",
    )?;
    let Some(bits) = &c.pow_bits else {
        return fail(at("pow_bits"), "missing");
    };
    for (name, v) in [
        ("low", bits.low),
        ("medium", bits.medium),
        ("high", bits.high),
        ("very_high", bits.very_high),
    ] {
        ensure(
            (8..=24).contains(&v),
            || at(&format!("pow_bits.{name}")),
            "must be 8..=24",
        )?;
    }
    check_ret(&c.fallback_ret).or_else(|reason| fail(at("fallback_ret"), reason))?;
    ensure(
        (1..=1000).contains(&c.max_failures),
        || at("max_failures"),
        "must be 1..=1000",
    )?;
    ensure(
        (60..=86_400).contains(&c.failure_window_s),
        || at("failure_window_s"),
        "must be 60..=86400",
    )?;
    // The built-in limiters of §9.8 must be valid GCRA parameters as well.
    let limiters = [
        ("submit", c.submit_rate, c.submit_period_s, c.submit_burst),
        (
            "mg.c.fail",
            c.max_failures,
            c.failure_window_s,
            c.max_failures,
        ),
        (
            "mg.c.fail.prefix",
            c.max_failures.saturating_mul(4),
            c.failure_window_s,
            c.max_failures.saturating_mul(4),
        ),
        (
            "issue_per_ipp",
            c.issue_per_ipp,
            c.issue_period_s,
            c.issue_per_ipp,
        ),
        (
            "issue_per_asn",
            c.issue_per_asn,
            c.issue_period_s,
            c.issue_per_asn,
        ),
    ];
    for (name, rate, period, burst) in limiters {
        check_gcra(rate, period, burst).or_else(|reason| fail(at(name), reason))?;
    }
    Ok(())
}

/// The return-path rules of §6.4 (`validate_ret`), applied to
/// `challenge.fallback_ret`.
fn check_ret(ret: &str) -> std::result::Result<(), &'static str> {
    if ret.len() > MAX_RET_BYTES {
        return Err("longer than 512 bytes");
    }
    if !ret.starts_with('/') || ret.starts_with("//") || ret.starts_with("/\\") {
        return Err("must be a local absolute path");
    }
    if ret
        .bytes()
        .any(|c| c < 0x20 || c == 0x7f || c == b'\\' || c == b'#')
    {
        return Err("contains a control character, '\\' or '#'");
    }
    let path = ret.split_once('?').map_or(ret, |(p, _)| p);
    if mg_core::paths::is_reserved(path) {
        return Err("points into the Edge's /__mg namespace");
    }
    Ok(())
}

fn check_clearance(c: &ClearanceConfig) -> Result {
    let at = |f: &str| format!("clearance.{f}");
    for (name, ttl) in [
        ("ttl_invisible_s", c.ttl_invisible_s),
        ("ttl_pow_s", c.ttl_pow_s),
    ] {
        ensure(
            (60..=86_400).contains(&ttl),
            || at(name),
            "must be 60..=86400",
        )?;
    }
    let longest = c.ttl_invisible_s.max(c.ttl_pow_s);
    ensure(
        c.session_max_s >= longest && c.session_max_s <= 30 * 86_400,
        || at("session_max_s"),
        "must be between the longest token TTL and 30 days",
    )
}

fn check_scoring(s: &ScoringConfig) -> Result {
    let at = |f: &str| format!("scoring.{f}");
    for (name, v) in [
        ("theta_c", s.theta_c),
        ("kappa", s.kappa),
        ("h_min", s.h_min),
    ] {
        ensure(v.is_finite(), || at(name), "must be a finite number")?;
    }
    for (k, v) in &s.z0 {
        ensure(
            SENSITIVITIES.contains(&k.as_str()),
            || at("z0"),
            "keys must be low, medium, high or critical",
        )?;
        ensure(v.is_finite(), || at("z0"), "values must be finite")?;
    }
    for (k, v) in &s.family_modes {
        ensure(
            SIGNAL_FAMILIES.contains(&k.as_str()),
            || at("family_modes"),
            "keys must be signal family names",
        )?;
        ensure(
            matches!(v.as_str(), "active" | "shadow" | "off"),
            || at("family_modes"),
            "values must be active, shadow or off",
        )?;
    }
    for v in s.weights.values() {
        ensure(v.is_finite(), || at("weights"), "values must be finite")?;
    }
    Ok(())
}

fn check_crawler_policy(p: &CrawlerPolicy) -> Result {
    let action = |v: &str| matches!(v, "allow" | "block");
    ensure(
        action(&p.default_action),
        || "crawler_policy.default_action".into(),
        "must be allow or block",
    )?;
    for (purpose, v) in &p.purposes {
        ensure(
            CRAWLER_PURPOSES.contains(&purpose.as_str()) && action(v),
            || format!("crawler_policy.purposes[{}]", printable(purpose)),
            "must map a known purpose to allow or block",
        )?;
    }
    Ok(())
}

fn check_events(e: &EventConfig) -> Result {
    ensure(
        (0.0..=1.0).contains(&e.allow_sample_rate),
        || "events.allow_sample_rate".into(),
        "must be in [0, 1]",
    )
}

fn check_lists(b: &SiteBundle) -> Result {
    for (name, list) in &b.lists {
        let at = || format!("lists[{}]", printable(name));
        ensure(
            is_limiter_id(name),
            at,
            "name must match [a-z0-9][a-z0-9_.-]{0,63}",
        )?;
        ensure(
            list.entries.len() <= MAX_LIST_ENTRIES,
            at,
            "more than 10000 entries",
        )?;
        ensure(
            list.entries.iter().all(|e| e.len() <= MAX_LIST_ENTRY_BYTES),
            at,
            "an entry is longer than 256 bytes",
        )?;
    }
    Ok(())
}

fn check_artifacts(b: &SiteBundle) -> Result {
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, a) in b.artifacts.iter().enumerate() {
        let at = |f: &str| format!("artifacts[{i}].{f}");
        let Some(limit) = artifact_limit(&a.name) else {
            return fail(at("name"), "unknown artifact name");
        };
        ensure(
            names.insert(&a.name, i).is_none(),
            || at("name"),
            "duplicate",
        )?;
        ensure(
            is_sha256_hex(&a.sha256),
            || at("sha256"),
            "must be 64 lower-case hex digits",
        )?;
        ensure(
            a.uri == format!("artifacts/{}", a.sha256),
            || at("uri"),
            "must be \"artifacts/<sha256>\"",
        )?;
        // Only the §12.1 upper limit: an empty text list (§12.4) is a valid
        // 0-byte artifact; empty files of the other kinds fail to parse in
        // the caller.
        ensure(
            a.size <= limit,
            || at("size"),
            "larger than the artifact kind's limit",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_count_star_runs_once() {
        assert_eq!(wildcard_count("/a/b"), 0);
        assert_eq!(wildcard_count("/**"), 1);
        assert_eq!(wildcard_count("/***"), 1);
        assert_eq!(wildcard_count("/*/*"), 2);
        assert_eq!(wildcard_count("/*?*"), 3);
        assert_eq!(wildcard_count("/?/?/?/?"), 4);
        assert!(check_pattern("/a/**/b/*/c?/d*").is_ok());
        assert!(check_pattern("/a/**/b/*/c?/d*/e?").is_err());
    }

    #[test]
    fn patterns() {
        assert!(check_pattern("/").is_ok());
        assert!(check_pattern("a").is_err());
        assert!(check_pattern("/a b").is_err());
        assert!(check_pattern("/é").is_err());
        assert!(check_pattern(&format!("/{}", "a".repeat(127))).is_ok());
        assert!(check_pattern(&format!("/{}", "a".repeat(128))).is_err());
    }

    #[test]
    fn return_paths() {
        for ok in ["/", "/a?b=c", "/__mgx", "/a/__mg"] {
            assert!(check_ret(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a",
            "//evil.example",
            "/\\evil.example",
            "/a\\b",
            "/a#b",
            "/a\nb",
            "/a\x7fb",
            "/__mg",
            "/__mg/c",
            "/%5f_mg/c",
            "/x/../__mg/s",
            "/__mg?x",
        ] {
            assert!(check_ret(bad).is_err(), "{bad:?}");
        }
        assert!(check_ret(&format!("/{}", "a".repeat(511))).is_ok());
        assert!(check_ret(&format!("/{}", "a".repeat(512))).is_err());
    }

    #[test]
    fn gcra_bounds() {
        assert!(check_gcra(20, 60, 5).is_ok());
        assert!(check_gcra(0, 60, 5).is_err());
        assert!(check_gcra(1, 0, 1).is_err());
        assert!(check_gcra(1, 86_401, 1).is_err());
        assert!(check_gcra(1, 86_400, 0).is_err());
        assert!(check_gcra(100_000, 1, 100_001).is_err());
        // interval 86400 s x burst 8 = 8 days > 7 days.
        assert!(check_gcra(1, 86_400, 8).is_err());
        assert!(check_gcra(1, 86_400, 7).is_ok());
    }
}
