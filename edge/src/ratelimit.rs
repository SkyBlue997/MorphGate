//! Rate limiters and entity verdicts of a request (docs/impl/phase1-spec.md
//! §9.7, §9.8, D-23, D-24; WP-E1b).
//!
//! * The limiters of the request's environment whose `route_ids` are empty
//!   or contain the selected route apply, in bundle order. Each gets its
//!   bucket key `mg:rl:{site}:{limiter}:{kh(dims)}` from its declared
//!   dimensions ([`limiter_dims`]): `ip` is the ip entity (`Net::entity_of`:
//!   the address for IPv4, the /64 for IPv6), `ip_prefix` the /24 or /48,
//!   `route` the route name. An unknown `ip`, `ip_prefix` or `asn` is the
//!   shared fallback value `?`: every request without a client IP shares one
//!   bucket and is never exempt (D-23). Only two things skip a limiter: a
//!   `session` dimension without a valid clearance, and an `asn` dimension
//!   on a site without a usable GeoLite2 ASN database.
//! * `scope = global` limiters and the verdict `MGET` share ONE round trip
//!   ([`StateHandle::round_trip1`], local fallback inside); `scope = local`
//!   limiters only use the in-process table.
//! * Each limiter yields a `RateObservation` (utilization, exceeded, GCRA
//!   wait, action, dry run) for the Decision Core; an exceeded one counts
//!   `mg_ratelimit_exceeded_total{limiter}`, dry-run limiters included.
//! * Verdict keys, in order: ip, prefix, asn, session, then with
//!   `share_ip_verdicts` the shared `mg:v:all:{ip,prefix,asn}` keys; a key
//!   whose input is unknown is not read (a verdict can only raise risk,
//!   D-10). Values are parsed with `state::parse_verdict`, which counts
//!   `mg_verdict_parse_errors_total`.

use crate::metrics::metrics;
use crate::sites::{EnvRuntime, LimiterDim, LimiterScope, LimiterSpec};
use mg_core::gcra::GcraOutcome;
use mg_core::{EntityVerdict, Net, RateObservation};
use mg_edge_core::state::{
    LimitCheck, LimiterKey, RoundTrip1, StateHandle, StateMode, dims, entity_key, parse_verdict,
    verdict_key,
};
use std::net::IpAddr;

/// Who a request is, for limiter keys and verdicts. Its `Debug` never shows
/// the client address (D-31).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Subject<'a> {
    pub ip: Option<IpAddr>,
    /// Known and not 0.
    pub asn: Option<u32>,
    /// The site has a usable GeoLite2 ASN database.
    pub asn_available: bool,
    /// The valid clearance's `sub`.
    pub session: Option<&'a str>,
    /// The selected route's name.
    pub route: &'a str,
}

impl std::fmt::Debug for Subject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subject")
            .field("ip", &crate::context::redacted_ip(self.ip))
            .field("asn", &self.asn)
            .field("asn_available", &self.asn_available)
            .field("session", &self.session.map(|_| crate::logging::REDACTED))
            .field("route", &self.route)
            .finish()
    }
}

/// Whether `spec` applies to the selected route.
pub fn applies(spec: &LimiterSpec, route_id: &str) -> bool {
    spec.route_ids.is_empty() || spec.route_ids.iter().any(|r| r == route_id)
}

/// The `dims` of `spec` for `s` (§9.7), or `None` when the limiter is
/// skipped for this request (see the module documentation).
pub fn limiter_dims(spec: &LimiterSpec, s: &Subject<'_>) -> Option<String> {
    let entity = s.ip.map(Net::entity_of);
    let prefix = s.ip.map(Net::prefix_of);
    let asn = s.asn.map(|a| a.to_string());
    let mut parts: Vec<(&str, Option<&str>)> = Vec::with_capacity(spec.dims.len());
    for dim in &spec.dims {
        let value = match dim {
            LimiterDim::Ip => entity.as_deref(),
            LimiterDim::IpPrefix => prefix.as_deref(),
            LimiterDim::Asn if !s.asn_available => return None,
            LimiterDim::Asn => asn.as_deref(),
            LimiterDim::Session => Some(s.session?),
            LimiterDim::Route => Some(s.route),
        };
        parts.push((dim.as_str(), value));
    }
    Some(dims(&parts))
}

/// The verdict keys of `s` in §9.7 order.
pub fn verdict_keys(k_pseudo: &[u8; 32], site: &str, s: &Subject<'_>, share: bool) -> Vec<String> {
    let ip = s.ip.map(|ip| {
        (
            entity_key(k_pseudo, "ip", &Net::entity_of(ip)),
            entity_key(k_pseudo, "prefix", &Net::prefix_of(ip)),
        )
    });
    let asn = s.asn.filter(|a| *a != 0).map(|a| a.to_string());
    let network = |site: &str, keys: &mut Vec<String>| {
        if let Some((ip, prefix)) = &ip {
            keys.push(verdict_key(site, "ip", ip));
            keys.push(verdict_key(site, "prefix", prefix));
        }
        if let Some(asn) = &asn {
            keys.push(verdict_key(site, "asn", asn));
        }
    };
    let mut keys = Vec::with_capacity(7);
    network(site, &mut keys);
    if let Some(sub) = s.session {
        keys.push(verdict_key(site, "session", sub));
    }
    if share {
        network(EntityVerdict::ALL_SITES, &mut keys);
    }
    keys
}

/// The state of a request after the round trip.
#[derive(Debug, Clone, Default)]
pub struct StateOutcome {
    /// One per applied limiter, in bundle order (`RequestExtras::rate`).
    pub rate: Vec<RateObservation>,
    /// Parsed verdicts (`RequestContext::verdicts`).
    pub verdicts: Vec<EntityVerdict>,
    /// Where the global limiters were counted (`None`: no round trip).
    pub mode: Option<StateMode>,
}

/// One limiter observation from its GCRA outcome.
fn observe(spec: &LimiterSpec, o: &GcraOutcome) -> RateObservation {
    if !o.allowed {
        metrics()
            .ratelimit_exceeded
            .with_label_values(&[spec.id.as_str()])
            .inc();
    }
    RateObservation {
        limiter_id: spec.id.clone(),
        utilization: o.utilization(&spec.params),
        exceeded: !o.allowed,
        retry_after_ms: o.retry_after_us.div_ceil(1000),
        action: spec.on_exceed,
        dry_run: spec.dry_run,
    }
}

/// What [`run`] works on.
#[derive(Debug, Clone, Copy)]
pub struct Plan<'a> {
    pub site: &'a str,
    pub env: &'a EnvRuntime,
    /// The selected route's id.
    pub route_id: &'a str,
    pub subject: Subject<'a>,
    /// `SiteBundle.share_ip_verdicts`.
    pub share_ip_verdicts: bool,
    /// Edge clock for `scope = local` limiters.
    pub now_us: u64,
}

/// Runs the request's limiters and reads its verdicts (see the module
/// documentation): at most one state round trip.
pub async fn run(state: &StateHandle, k_pseudo: &[u8; 32], plan: &Plan<'_>) -> StateOutcome {
    let Plan {
        site,
        env,
        route_id,
        subject,
        share_ip_verdicts,
        now_us,
    } = *plan;
    // (limiter, check) in bundle order.
    let planned: Vec<(&LimiterSpec, LimitCheck)> = env
        .limiters
        .iter()
        .filter(|spec| applies(spec, route_id))
        .filter_map(|spec| {
            let dims = limiter_dims(spec, &subject)?;
            Some((
                spec,
                LimitCheck {
                    key: LimiterKey::new(site, spec.id.as_str(), dims),
                    params: spec.params,
                    cost: 1,
                    write: true,
                },
            ))
        })
        .collect();
    let verdict_keys = verdict_keys(k_pseudo, site, &subject, share_ip_verdicts);
    let global: Vec<LimitCheck> = planned
        .iter()
        .filter(|(spec, _)| spec.scope == LimiterScope::Global)
        .map(|(_, c)| c.clone())
        .collect();

    let mut out = StateOutcome::default();
    let mut global_outcomes = Vec::new().into_iter();
    if !global.is_empty() || !verdict_keys.is_empty() {
        let n = global.len();
        let r = state
            .round_trip1(RoundTrip1 {
                verdict_keys,
                limits: global,
            })
            .await;
        out.mode = Some(r.mode);
        out.verdicts = r
            .verdicts
            .iter()
            .flatten()
            .filter_map(|raw| parse_verdict(raw))
            .collect();
        if r.limits.len() == n {
            global_outcomes = r.limits.into_iter();
        } else {
            // A reply that does not match the request is a state-layer bug:
            // count every global limiter as exceeded rather than exempt.
            log::error!(
                "state round trip returned {} limiter outcomes for {n} limiters",
                r.limits.len()
            );
        }
    }
    for (spec, check) in &planned {
        let outcome = match spec.scope {
            LimiterScope::Local => state.local_check(check, now_us),
            LimiterScope::Global => global_outcomes.next().unwrap_or(GcraOutcome {
                allowed: false,
                retry_after_us: spec.params.dvt_us(),
                tat_minus_now_us: spec.params.dvt_us(),
                new_tat_us: None,
            }),
        };
        out.rate.push(observe(spec, &outcome));
    }
    out
}

/// Wall clock, Unix µs (limiter checks on the Edge clock, §9.7).
pub fn unix_now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::LimiterAction;
    use mg_core::gcra::GcraParams;
    use mg_edge_core::state::{StateConfig, StateService};

    fn spec(id: &str, dims: &[LimiterDim], routes: &[&str], scope: LimiterScope) -> LimiterSpec {
        LimiterSpec {
            id: id.into(),
            dims: dims.to_vec(),
            params: GcraParams::new(1, 60, 1).unwrap(),
            on_exceed: LimiterAction::RateLimit { retry_after_s: 0 },
            dry_run: false,
            route_ids: routes.iter().map(|r| (*r).to_string()).collect(),
            scope,
        }
    }

    fn subject<'a>(ip: Option<&str>, session: Option<&'a str>) -> Subject<'a> {
        Subject {
            ip: ip.map(|s| s.parse().unwrap()),
            asn: None,
            asn_available: true,
            session,
            route: "login",
        }
    }

    /// §9.7 / D-24: `ip` is the entity (IPv6 /64), unknown values are `?`,
    /// dimensions keep their declared order.
    #[test]
    fn dims_follow_the_spec() {
        use LimiterDim::*;
        let s = spec("x", &[Ip, IpPrefix, Asn, Route], &[], LimiterScope::Global);
        assert_eq!(
            limiter_dims(&s, &subject(Some("2001:db8:abcd:12::1"), None)).unwrap(),
            "ip=2001:db8:abcd:12::/64&ip_prefix=2001:db8:abcd::/48&asn=?&route=login"
        );
        assert_eq!(
            limiter_dims(&s, &subject(Some("::ffff:203.0.113.7"), None)).unwrap(),
            "ip=203.0.113.7&ip_prefix=203.0.113.0/24&asn=?&route=login"
        );
        // D-23: an unknown client IP shares the `?` bucket, never skipped.
        assert_eq!(
            limiter_dims(&s, &subject(None, None)).unwrap(),
            "ip=?&ip_prefix=?&asn=?&route=login"
        );
        let mut known = subject(Some("192.0.2.1"), None);
        known.asn = Some(64496);
        assert_eq!(
            limiter_dims(&spec("a", &[Asn], &[], LimiterScope::Global), &known).unwrap(),
            "asn=64496"
        );
        // Skips: session without a clearance, asn without a database.
        let session = spec("s", &[Session, Ip], &[], LimiterScope::Global);
        assert_eq!(
            limiter_dims(&session, &subject(Some("192.0.2.1"), None)),
            None
        );
        assert_eq!(
            limiter_dims(
                &session,
                &subject(Some("192.0.2.1"), Some("AAAAAAAAAAAAAAAAAAAAAA"))
            )
            .unwrap(),
            "session=AAAAAAAAAAAAAAAAAAAAAA&ip=192.0.2.1"
        );
        let mut no_db = known;
        no_db.asn_available = false;
        assert_eq!(
            limiter_dims(&spec("a", &[Asn], &[], LimiterScope::Global), &no_db),
            None
        );
        // Route filters.
        assert!(applies(&spec("r", &[Ip], &[], LimiterScope::Global), "api"));
        assert!(applies(
            &spec("r", &[Ip], &["login"], LimiterScope::Global),
            "login"
        ));
        assert!(!applies(
            &spec("r", &[Ip], &["login"], LimiterScope::Global),
            "api"
        ));
    }

    /// §2.4 item 5: `Debug` of a subject (and so of a plan) never shows the
    /// client address.
    #[test]
    fn debug_output_has_no_client_address() {
        for ip in ["203.0.113.77", "2001:db8:abcd:12::99"] {
            let s = subject(Some(ip), Some("AAAAAAAAAAAAAAAAAAAAAA"));
            let text = format!("{s:?}");
            assert!(!text.contains(ip), "{text}");
            assert!(
                !text.contains("203.0.113") && !text.contains("2001:db8"),
                "{text}"
            );
            assert!(text.contains("route"), "{text}");
        }
    }

    #[test]
    fn verdict_key_order_and_inputs() {
        let k = [1u8; 32];
        let mut s = subject(Some("203.0.113.7"), Some("SUB"));
        s.asn = Some(64500);
        let keys = verdict_keys(&k, "blog", &s, true);
        let ip = entity_key(&k, "ip", "203.0.113.7");
        let prefix = entity_key(&k, "prefix", "203.0.113.0/24");
        assert_eq!(
            keys,
            [
                format!("mg:v:blog:ip:{ip}"),
                format!("mg:v:blog:prefix:{prefix}"),
                "mg:v:blog:asn:64500".to_string(),
                "mg:v:blog:session:SUB".to_string(),
                format!("mg:v:all:ip:{ip}"),
                format!("mg:v:all:prefix:{prefix}"),
                "mg:v:all:asn:64500".to_string(),
            ]
        );
        // Unknown inputs are not read; no sharing without the switch.
        assert!(verdict_keys(&k, "blog", &subject(None, None), true).is_empty());
        assert_eq!(
            verdict_keys(&k, "blog", &subject(None, Some("SUB")), false),
            ["mg:v:blog:session:SUB"]
        );
        // IPv6: the ip entity is the /64.
        let v6 = verdict_keys(
            &k,
            "blog",
            &subject(Some("2001:db8:abcd:12::99"), None),
            false,
        );
        assert_eq!(
            v6[0],
            format!(
                "mg:v:blog:ip:{}",
                entity_key(&k, "ip", "2001:db8:abcd:12::/64")
            )
        );
    }

    fn env(limiters: Vec<LimiterSpec>) -> EnvRuntime {
        EnvRuntime {
            name: "production".into(),
            hosts: vec!["example.com".into()],
            routes: Vec::new(),
            rules: Vec::new(),
            limiters,
            automation_allowlist_only: false,
            core: crate::decide::build_core(
                Vec::new(),
                Default::default(),
                &crate::sites::default_scoring(),
                &crate::sites::default_crawler_policy(),
            ),
        }
    }

    /// Local mode end to end: observations in bundle order, the second
    /// request over the limit, the `?` bucket shared by unknown IPs, route
    /// filters and skipped limiters.
    #[test]
    fn local_mode_observations() {
        use LimiterDim::*;
        let (_service, state) = StateService::new(StateConfig::local([3; 32]));
        let mut dry = spec("dry", &[Ip], &[], LimiterScope::Local);
        dry.dry_run = true;
        dry.on_exceed = LimiterAction::Signal { weight: 1.0 };
        let e = env(vec![
            spec("per-ip", &[Ip], &["login"], LimiterScope::Global),
            spec("other-route", &[Ip], &["api"], LimiterScope::Global),
            spec("per-session", &[Session], &[], LimiterScope::Global),
            dry,
        ]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let run_once = |s: Subject<'_>| {
            let plan = Plan {
                site: "blog",
                env: &e,
                route_id: "login",
                subject: s,
                share_ip_verdicts: false,
                now_us: unix_now_us(),
            };
            rt.block_on(run(&state, &[3; 32], &plan))
        };
        let first = run_once(subject(None, None));
        let ids: Vec<&str> = first.rate.iter().map(|o| o.limiter_id.as_str()).collect();
        assert_eq!(ids, ["per-ip", "dry"]);
        assert!(first.rate.iter().all(|o| !o.exceeded));
        assert_eq!(first.mode, Some(StateMode::Local));
        assert!(first.verdicts.is_empty());
        let second = run_once(subject(None, None));
        assert!(second.rate.iter().all(|o| o.exceeded), "{:?}", second.rate);
        assert_eq!(second.rate[0].utilization, 1.0);
        assert!(second.rate[0].retry_after_ms > 0);
        assert!(second.rate[1].dry_run);
        // A known IP has its own bucket.
        let other = run_once(subject(Some("198.51.100.7"), None));
        assert!(other.rate.iter().all(|o| !o.exceeded));
        // Two IPv6 addresses of one /64 share it.
        let a = run_once(subject(Some("2001:db8:1:2::a"), None));
        let b = run_once(subject(Some("2001:db8:1:2::b"), None));
        assert!(!a.rate[0].exceeded && b.rate[0].exceeded);
        let c = run_once(subject(Some("2001:db8:1:3::a"), None));
        assert!(!c.rate[0].exceeded);
    }
}
