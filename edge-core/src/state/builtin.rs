//! Built-in limiters of the `POST /__mg/c` flow (spec §9.8, D-28, D-37):
//! ids, keys and parameter shapes, built from the bundle's
//! `ChallengeConfig`, so that `mg-edge` only picks the client's dimensions.
//!
//! | id | key | rate / period, burst |
//! |---|---|---|
//! | `mg.c.submit` | `ip_prefix` | `submit_rate / submit_period_s`, `submit_burst` |
//! | `mg.c.fail` | `ip` (ip entity) | `max_failures / failure_window_s`, `max_failures` |
//! | `mg.c.fail.prefix` | `ip_prefix` | `4 × max_failures / failure_window_s`, `4 × max_failures` |
//! | `mg.clr.issue.ipp` | `ip_prefix` | `issue_per_ipp / issue_period_s`, `issue_per_ipp` |
//! | `mg.clr.issue.asn` | `asn` | `issue_per_asn / issue_period_s`, `issue_per_asn`; skipped without a `geoip-asn` artifact |
//!
//! Unknown dimensions use the shared fallback bucket `?` (D-23; `/__mg/c`
//! answers 429 `ic.no_client_ip` before any limiter when the client IP is
//! unknown, but the keys stay well defined).

use mg_core::gcra::GcraParams;

use super::{LimitCheck, LimiterKey, StateError, dims};

pub const SUBMIT: &str = "mg.c.submit";
pub const FAIL: &str = "mg.c.fail";
pub const FAIL_PREFIX: &str = "mg.c.fail.prefix";
pub const ISSUE_IPP: &str = "mg.clr.issue.ipp";
pub const ISSUE_ASN: &str = "mg.clr.issue.asn";

/// Validated parameters of the built-in limiters, from the bundle's
/// `ChallengeConfig`. Construction fails (instead of silently dropping a
/// limiter) when any of them is outside the GCRA bounds (§8.2 rejects such
/// bundles before they get here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeLimits {
    pub submit: GcraParams,
    pub fail: GcraParams,
    pub fail_prefix: GcraParams,
    pub issue_ipp: GcraParams,
    pub issue_asn: GcraParams,
}

impl TryFrom<&mg_proto::v1::ChallengeConfig> for ChallengeLimits {
    type Error = StateError;

    fn try_from(c: &mg_proto::v1::ChallengeConfig) -> Result<Self, StateError> {
        let p = |what: &str, rate: u32, period: u32, burst: u32| {
            GcraParams::new(rate, period, burst).ok_or_else(|| {
                StateError::Config(format!("challenge {what} limiter parameters out of range"))
            })
        };
        let prefix_failures = c.max_failures.saturating_mul(4);
        Ok(Self {
            submit: p("submit", c.submit_rate, c.submit_period_s, c.submit_burst)?,
            fail: p(
                "failure",
                c.max_failures,
                c.failure_window_s,
                c.max_failures,
            )?,
            fail_prefix: p(
                "prefix failure",
                prefix_failures,
                c.failure_window_s,
                prefix_failures,
            )?,
            issue_ipp: p(
                "ipp issuance",
                c.issue_per_ipp,
                c.issue_period_s,
                c.issue_per_ipp,
            )?,
            issue_asn: p(
                "asn issuance",
                c.issue_per_asn,
                c.issue_period_s,
                c.issue_per_asn,
            )?,
        })
    }
}

/// The submitting client's key parts. `None` = unknown (`?`).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientDims<'a> {
    /// `Net::entity_of(ip)`.
    pub ip_entity: Option<&'a str>,
    /// `Net::prefix_of(ip)`.
    pub ip_prefix: Option<&'a str>,
    /// GeoLite2 ASN; `None` or 0 = unknown.
    pub asn: Option<u32>,
    /// The site has a usable `geoip-asn` artifact; without it the ASN quota
    /// is skipped for every request.
    pub asn_available: bool,
}

impl std::fmt::Debug for ClientDims<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientDims")
            .field("ip_entity", &self.ip_entity.map(|_| "<redacted>"))
            .field("ip_prefix", &self.ip_prefix.map(|_| "<redacted>"))
            .field("asn", &self.asn)
            .field("asn_available", &self.asn_available)
            .finish()
    }
}

impl ClientDims<'_> {
    fn asn_value(&self) -> Option<String> {
        self.asn.filter(|a| *a != 0).map(|a| a.to_string())
    }
}

fn limit(site: &str, id: &str, d: String, params: GcraParams, write: bool) -> LimitCheck {
    LimitCheck {
        key: LimiterKey::new(site, id, d),
        params,
        cost: 1,
        write,
    }
}

impl ChallengeLimits {
    /// `mg.c.submit` (per ip prefix).
    pub fn submit(&self, site: &str, c: &ClientDims<'_>, write: bool) -> LimitCheck {
        limit(
            site,
            SUBMIT,
            dims(&[("ip_prefix", c.ip_prefix)]),
            self.submit,
            write,
        )
    }

    /// `mg.c.fail` (per ip entity).
    pub fn fail(&self, site: &str, c: &ClientDims<'_>, write: bool) -> LimitCheck {
        limit(site, FAIL, dims(&[("ip", c.ip_entity)]), self.fail, write)
    }

    /// `mg.c.fail.prefix` (per ip prefix, 4 × `max_failures`).
    pub fn fail_prefix(&self, site: &str, c: &ClientDims<'_>, write: bool) -> LimitCheck {
        limit(
            site,
            FAIL_PREFIX,
            dims(&[("ip_prefix", c.ip_prefix)]),
            self.fail_prefix,
            write,
        )
    }

    /// `mg.clr.issue.ipp`.
    pub fn issue_ipp(&self, site: &str, c: &ClientDims<'_>, write: bool) -> LimitCheck {
        limit(
            site,
            ISSUE_IPP,
            dims(&[("ip_prefix", c.ip_prefix)]),
            self.issue_ipp,
            write,
        )
    }

    /// `mg.clr.issue.asn`; `None` when the site has no `geoip-asn` artifact.
    pub fn issue_asn(&self, site: &str, c: &ClientDims<'_>, write: bool) -> Option<LimitCheck> {
        if !c.asn_available {
            return None;
        }
        let asn = c.asn_value();
        Some(limit(
            site,
            ISSUE_ASN,
            dims(&[("asn", asn.as_deref())]),
            self.issue_asn,
            write,
        ))
    }

    /// Round trip 1 of `POST /__mg/c` (§9.7): `mg.c.submit` (write 1), then
    /// the check-only `mg.c.fail`, `mg.c.fail.prefix`, `mg.clr.issue.ipp`
    /// and (if available) `mg.clr.issue.asn`, in this order.
    pub fn submit_round_trip(&self, site: &str, c: &ClientDims<'_>) -> Vec<LimitCheck> {
        let mut v = vec![
            self.submit(site, c, true),
            self.fail(site, c, false),
            self.fail_prefix(site, c, false),
            self.issue_ipp(site, c, false),
        ];
        v.extend(self.issue_asn(site, c, false));
        v
    }

    /// Issuance quotas for [`super::NonceIssue::limits`] (round trip 2).
    pub fn issuance(&self, site: &str, c: &ClientDims<'_>) -> Vec<LimitCheck> {
        let mut v = vec![self.issue_ipp(site, c, true)];
        v.extend(self.issue_asn(site, c, true));
        v
    }

    /// What [`super::StateHandle::record_failure`] records after a failure
    /// that counts (§9.8): `mg.c.fail` and `mg.c.fail.prefix`, write 1.
    pub fn failures(&self, site: &str, c: &ClientDims<'_>) -> Vec<LimitCheck> {
        vec![self.fail(site, c, true), self.fail_prefix(site, c, true)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §8.3 defaults: max_failures 5 / 600 s, submit 30 / 60 s burst 10,
    /// issue 60 per ipp and 600 per ASN per 3600 s.
    fn config() -> mg_proto::v1::ChallengeConfig {
        mg_proto::v1::ChallengeConfig {
            max_failures: 5,
            failure_window_s: 600,
            submit_rate: 30,
            submit_period_s: 60,
            submit_burst: 10,
            issue_per_ipp: 60,
            issue_per_asn: 600,
            issue_period_s: 3600,
            ..Default::default()
        }
    }

    fn defaults() -> ChallengeLimits {
        ChallengeLimits::try_from(&config()).unwrap()
    }

    #[test]
    fn shapes_follow_the_spec_table() {
        let l = defaults();
        let c = ClientDims {
            ip_entity: Some("203.0.113.7"),
            ip_prefix: Some("203.0.113.0/24"),
            asn: Some(64500),
            asn_available: true,
        };
        let rt = l.submit_round_trip("blog", &c);
        let ids: Vec<&str> = rt.iter().map(|x| x.key.limiter.as_str()).collect();
        assert_eq!(ids, [SUBMIT, FAIL, FAIL_PREFIX, ISSUE_IPP, ISSUE_ASN]);
        let writes: Vec<bool> = rt.iter().map(|x| x.write).collect();
        assert_eq!(writes, [true, false, false, false, false]);
        assert_eq!(rt[0].key.dims, "ip_prefix=203.0.113.0/24");
        assert_eq!(rt[0].params, GcraParams::new(30, 60, 10).unwrap());
        assert_eq!(rt[1].key.dims, "ip=203.0.113.7");
        assert_eq!(rt[1].params, GcraParams::new(5, 600, 5).unwrap());
        assert_eq!(rt[2].key.dims, "ip_prefix=203.0.113.0/24");
        assert_eq!(rt[2].params, GcraParams::new(20, 600, 20).unwrap());
        assert_eq!(rt[3].params, GcraParams::new(60, 3600, 60).unwrap());
        assert_eq!(rt[4].key.dims, "asn=64500");
        assert_eq!(rt[4].params, GcraParams::new(600, 3600, 600).unwrap());
        let issue = l.issuance("blog", &c);
        assert!(issue.len() == 2 && issue.iter().all(|x| x.write));
        let fails = l.failures("blog", &c);
        let ids: Vec<&str> = fails.iter().map(|x| x.key.limiter.as_str()).collect();
        assert_eq!(ids, [FAIL, FAIL_PREFIX]);
        assert!(fails.iter().all(|x| x.write));
    }

    #[test]
    fn unknown_dimensions_use_the_fallback_bucket_and_asn_can_be_skipped() {
        let l = defaults();
        let unknown = ClientDims {
            asn: Some(0),
            asn_available: true,
            ..ClientDims::default()
        };
        let rt = l.submit_round_trip("blog", &unknown);
        assert_eq!(rt[0].key.dims, "ip_prefix=?");
        assert_eq!(rt[1].key.dims, "ip=?");
        assert_eq!(rt[4].key.dims, "asn=?", "ASN 0 is unknown");
        let no_artifact = ClientDims {
            asn_available: false,
            ..unknown
        };
        assert_eq!(l.submit_round_trip("blog", &no_artifact).len(), 4);
        assert_eq!(l.issuance("blog", &no_artifact).len(), 1);
        let with_ip = ClientDims {
            ip_entity: Some("198.51.100.1"),
            ..unknown
        };
        assert!(!format!("{with_ip:?}").contains("198.51"));
    }

    #[test]
    fn out_of_range_parameters_are_an_error_not_a_missing_limiter() {
        for broken in [
            mg_proto::v1::ChallengeConfig {
                submit_rate: 0,
                ..config()
            },
            mg_proto::v1::ChallengeConfig {
                max_failures: 0,
                ..config()
            },
            mg_proto::v1::ChallengeConfig {
                issue_period_s: 0,
                ..config()
            },
            mg_proto::v1::ChallengeConfig {
                issue_per_asn: 0,
                ..config()
            },
        ] {
            assert!(matches!(
                ChallengeLimits::try_from(&broken),
                Err(StateError::Config(_))
            ));
        }
    }
}
