//! `POST /__mg/c/renew`: renewal and first binding of an interactive `C`
//! (docs/impl/phase2-spec.md §7.4, D-41, D-42; WP-E2a).
//!
//! The SDK binds every unbound interactive `C` to its session key before
//! the visitor acts (D-41), and renews a `C` that is about to expire while
//! the visitor has not acted yet (D-42). The checks run in this order; the
//! first failure decides, and every answer is JSON:
//!
//! | # | Check | Answer |
//! |---|---|---|
//! | 0 | client IP unknown | 429, `Retry-After: 5` (`no_client_ip`) |
//! | 1 | `Early-Data` | 425 (`too_early`) |
//! | 2 | `mg.c.renew` (in-process, both tiers decide) | 429 (`ic.rate_limited`) |
//! | 3 | body: JSON (`charset` utf-8), at most 8 KiB, [`crate::submission::parse_renew`] | failure without a `C` (`ic.body`, counted) |
//! | 4 | `Sealer::open_for_renew` | expired over an hour ago: failure without a `C`, not counted (`ic.c_expired`); otherwise failure without a `C` (`ic.c_invalid` / `ic.c_kid`, counted) |
//! | 4a | interactive unavailable (§5.1) | failure with a `pow` `C` (`ic.interactive_unavailable`, not counted) |
//! | 4b | not a first binding (`renew_no ≥ 1`): `mg.ix.issue` | 429 (`ic.rate_limited`) |
//! | 5 | `uah`; a bound `C`'s `jkt` equals the key's thumbprint; an unbound `C`'s `ipp` matches (soft included); a bound `C` may change prefix (`renew_rebind`) | `ic.bind_uah` / `ic.bind_jkt` / `ic.bind_ipp`: failure with an escalated `C`, counted |
//! | 6 | the renewal signature (`mg-renew-v1`, §6.6) | `ic.sig`: failure with an escalated `C`, counted |
//! | 7 | consume the old nonce (`mg_nonce_issue` v2, nonce only) | used: failure **without** a `C`, not counted (`ic.nonce_reused`); replay store unavailable: 429, `Retry-After: 5` |
//! | 8 | expired, or `renew_no = 6` | failure with a fresh chain's `C` (`renew_no = 0`, same `ui_seed`, `ret`, band, attempt), not counted (`ic.c_expired` / `ic.renew_cap`) |
//! | 9 | — | 200 `{"v": 2, "challenge", "ix"}`: the renewed `C` (`renew_no + 1`, new nonce and times, the current request's bindings, `jkt` = the key) |
//!
//! A `C` is renewed at most once (step 7 consumes its nonce before any new
//! `C` exists), so one `C` never forks into several. The nonce of every
//! interactive `C` is kept until the `C` can no longer be opened for a
//! renewal ([`interactive_nonce_ttl_ms`]).
//!
//! The results are counted in `mg_challenge_renew_total{result}`.

use crate::challenge::{self, IssueError, Issued};
use crate::context;
use crate::enforce::EdgeResponse;
use crate::interactive::{self, Gate};
use crate::metrics::metrics;
use crate::mg_endpoints::{
    BODY_DEADLINE, BodyRead, BodySource, RETRY_S, Submit, read_body, reason,
};
use crate::pages;
use crate::submission::{self, MAX_BODY, MediaKind, media_kind};
use mg_challenge::{RENEW_MAX_EXPIRED_MS, RenewOpenError, Rng, check_challenge_bind};
use mg_core::{
    BindResult, ChallengeType, Net, ProviderId, SealedChallengeClaims,
    next_challenge_after_failure, turnstile_eligible,
};
use mg_edge_core::state::builtin::ClientDims;
use mg_edge_core::state::{NonceIssueV2, NonceResultV2, StateHandle};

/// `Allow` of `/__mg/c/renew`.
pub const RENEW_ALLOW: &str = "POST";

/// How long the nonce of an interactive `C` is kept (Phase 2 spec §7.4,
/// §14.1): until the `C` can no longer be opened for a renewal
/// (`exp + RENEW_MAX_EXPIRED_MS`), plus the usual 60 s. With only `exp +
/// 60 s` an expired `C` could be renewed again once its nonce key lapsed,
/// and a solved `C` renewed after its submission.
pub fn interactive_nonce_ttl_ms(claims: &SealedChallengeClaims, now_ms: i64) -> u64 {
    let ttl = claims
        .exp_ms
        .saturating_add(RENEW_MAX_EXPIRED_MS)
        .saturating_add(crate::mg_endpoints::NONCE_TTL_SLACK_MS)
        .saturating_sub(now_ms)
        .max(1);
    u64::try_from(ttl).unwrap_or(1)
}

/// What one renewal did.
#[derive(Debug)]
pub struct Renewed {
    pub response: EdgeResponse,
    /// The `result` of `mg_challenge_renew_total`.
    pub result: &'static str,
    /// The deciding `ic.*` code (debug log), `None` on success.
    pub code: Option<&'static str>,
    /// The `kind=feedback` of a counted failure or a rebind (Phase 2 spec
    /// §15.1); `None` for every other result.
    pub feedback: Option<RenewFeedback>,
}

/// A renewal's `kind=feedback` (Phase 2 spec §15.1): the old `C`'s route,
/// type, attempt, renewal number, binding and first provider, and the
/// reason; `rebind` for a bound `C` renewed from another prefix.
#[derive(Debug, Clone, PartialEq)]
pub struct RenewFeedback {
    pub feedback: mg_core::ChallengeResult,
    pub rebind: bool,
}

/// The feedback of a renewal of `claims` (when it was opened).
fn renew_feedback(
    s: &Submit<'_>,
    claims: Option<&SealedChallengeClaims>,
    code: Option<&'static str>,
    rebind: bool,
) -> RenewFeedback {
    let mut fb = mg_core::ChallengeResult {
        request_id: s.request_id.to_owned(),
        site_id: s.site_id.to_owned(),
        challenge_type: ChallengeType::Unspecified,
        outcome: Some(if rebind {
            mg_core::VerdictOutcome::Pass
        } else {
            mg_core::VerdictOutcome::Fail
        }),
        reason_codes: code.map(|c| vec![c.to_owned()]).unwrap_or_default(),
        cf_ray: s.built.ctx.upstream.cf_ray.clone(),
        ..mg_core::ChallengeResult::default()
    };
    if let Some(c) = claims {
        fb.route_id = Some(c.route_class.clone());
        fb.challenge_type = c.challenge_type;
        fb.provider_id = c.providers.first().copied();
        fb.risk_band = Some(c.risk_band);
        fb.attempt_no = c.attempt_no;
        fb.renew_no = c.renew_no;
        fb.bound = c.bind.jkt.is_some();
    }
    RenewFeedback {
        feedback: fb,
        rebind,
    }
}

enum Stop {
    /// 429 with `Retry-After`.
    Limited {
        result: &'static str,
        code: &'static str,
        retry_after_s: u32,
    },
    TooEarly,
    /// The uniform failure; `reissue`: attach a `C` (§5.3 escalated, or a
    /// fresh chain for step 8).
    Failed {
        result: &'static str,
        code: &'static str,
        reissue: Reissue,
    },
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reissue {
    None,
    /// §5.3 / §7.1: escalated type, band and attempt.
    Escalated,
    /// §7.4 step 8: a new chain of the same `C`.
    NewChain,
}

struct Flow<'a, 's> {
    s: &'a Submit<'s>,
    state: &'a StateHandle,
    rng: &'a dyn Rng,
    entity: String,
    prefix: String,
    body_done: bool,
    claims: Option<SealedChallengeClaims>,
    /// The key's thumbprint once the signature verified.
    jkt: Option<String>,
    rebind: bool,
    /// When [`renew`] started (the wall clock is read once, by the caller).
    started: std::time::Instant,
}

impl Flow<'_, '_> {
    /// `Submit::now_ms` advanced by the time the flow has taken.
    fn clock(&self) -> i64 {
        let elapsed = i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX);
        self.s.now_ms.saturating_add(elapsed)
    }

    fn dims(&self) -> ClientDims<'_> {
        ClientDims {
            ip_entity: Some(&self.entity),
            ip_prefix: Some(&self.prefix),
            asn: self.s.built.ctx.net.asn,
            asn_available: self.s.bundle.intel.has_asn(),
        }
    }

    async fn run(&mut self, body: &mut dyn BodySource) -> Result<Issued, Stop> {
        let s = self.s;
        let bundle = s.bundle;
        // 0. Client IP (D-23).
        let Some(ip) = s.built.ctx.net.ip else {
            return Err(Stop::Limited {
                result: "no_client_ip",
                code: reason::NO_CLIENT_IP,
                retry_after_s: RETRY_S,
            });
        };
        self.entity = Net::entity_of(ip);
        self.prefix = Net::prefix_of(ip);
        // 1. 0-RTT.
        if s.built.ctx.http.early_data {
            return Err(Stop::TooEarly);
        }
        let Some(cfg) = &bundle.interactive else {
            // Schema 1 bundles answer 404 before this (D-66).
            return Err(Stop::Unavailable);
        };
        let now_us = |ms: i64| u64::try_from(ms).unwrap_or(0).saturating_mul(1000);
        // 2. mg.c.renew.
        if let Gate::Limited { retry_after_s } =
            interactive::renew_gate(self.state, s.site_id, cfg, ip, now_us(s.now_ms))
        {
            return Err(Stop::Limited {
                result: "rate_limited",
                code: reason::RATE_LIMITED,
                retry_after_s,
            });
        }
        // 3. The body.
        let body_fail = || {
            Err(Stop::Failed {
                result: "body",
                code: reason::BODY,
                reissue: Reissue::None,
            })
        };
        let headers = &s.built.headers;
        if s.content_encoding || context::header(headers, "content-encoding").is_some() {
            return body_fail();
        }
        if let Some(len) = context::header(headers, "content-length") {
            match len.trim().parse::<u64>() {
                Ok(n) if n <= MAX_BODY as u64 => {}
                _ => return body_fail(),
            }
        }
        if context::header(headers, "content-type").map(media_kind) != Some(Ok(MediaKind::Json)) {
            return body_fail();
        }
        let bytes = match read_body(body, MAX_BODY, BODY_DEADLINE).await {
            BodyRead::Complete(b) => {
                self.body_done = true;
                b
            }
            _ => return body_fail(),
        };
        let Ok(renewal) = String::from_utf8(bytes)
            .map_err(|_| submission::BodyError::Utf8)
            .and_then(|t| submission::parse_renew(&t))
        else {
            return body_fail();
        };
        let now_ms = self.clock();

        // 4. Open the C, expired allowed (up to an hour).
        let (claims, expired) = match s.sealer.open_for_renew(&renewal.c, s.host, now_ms) {
            Ok(opened) => opened,
            Err(RenewOpenError::TooOld) => {
                return Err(Stop::Failed {
                    result: "expired",
                    code: reason::C_EXPIRED,
                    reissue: Reissue::None,
                });
            }
            Err(RenewOpenError::Open(e)) => {
                return Err(Stop::Failed {
                    result: "invalid",
                    code: e.reason_code(),
                    reissue: Reissue::None,
                });
            }
        };
        self.claims = Some(claims);
        let Some(claims) = &self.claims else {
            return Err(Stop::Unavailable);
        };
        // 4a. Interactive challenges unavailable: a pow C.
        if !bundle.interactive_available {
            return Err(Stop::Failed {
                result: "interactive_unavailable",
                code: reason::INTERACTIVE_UNAVAILABLE,
                reissue: Reissue::Escalated,
            });
        }
        // 4b. mg.ix.issue, except for the first binding.
        if claims.renew_no >= 1
            && let Gate::Limited { retry_after_s } =
                interactive::issue_gate(self.state, s.site_id, cfg, ip, now_us(now_ms))
        {
            return Err(Stop::Limited {
                result: "rate_limited",
                code: reason::RATE_LIMITED,
                retry_after_s,
            });
        }
        let fail = |result, code| {
            Err(Stop::Failed {
                result,
                code,
                reissue: Reissue::Escalated,
            })
        };
        // 5. Bindings.
        let check = check_challenge_bind(&claims.bind, s.bind);
        if check.uah != BindResult::Match {
            return fail("binding", reason::BIND_UAH);
        }
        let Some(key) = submission::session_key(&renewal.jwk) else {
            return fail("sig", reason::SIG);
        };
        let bound = claims.bind.jkt.is_some();
        if bound && !interactive::jkt_matches(claims, key.thumbprint()) {
            return fail("binding", reason::BIND_JKT);
        }
        match check.ipp {
            BindResult::Match => {}
            BindResult::SoftMismatch if !bound => {}
            _ if bound => self.rebind = true,
            _ => return fail("binding", reason::BIND_IPP),
        }
        // 6. The renewal signature.
        if !submission::renew_signature_ok(&renewal, &key) {
            return fail("sig", reason::SIG);
        }
        self.jkt = Some(key.thumbprint().to_owned());
        // 7. Consume the old nonce: a C renews into at most one new C.
        let nonce = self
            .state
            .nonce_issue_v2(
                NonceIssueV2 {
                    site: s.site_id.to_owned(),
                    nonce: claims.nonce,
                    ttl_ms: interactive_nonce_ttl_ms(claims, now_ms),
                    replay: None,
                    limits: Vec::new(),
                },
                now_ms,
                claims.iat_ms,
            )
            .await;
        match nonce {
            NonceResultV2::Fresh { .. } => {}
            NonceResultV2::Reused | NonceResultV2::TokenReused => {
                return Err(Stop::Failed {
                    result: "nonce_reused",
                    code: reason::NONCE_REUSED,
                    reissue: Reissue::None,
                });
            }
            NonceResultV2::Unavailable { .. } => {
                return Err(Stop::Limited {
                    result: "unavailable",
                    code: reason::REPLAY_UNAVAILABLE,
                    retry_after_s: RETRY_S,
                });
            }
        }
        // 8. Expired, or the end of the chain: a new chain.
        if expired || claims.renew_no >= interactive::MAX_RENEW_NO {
            let (result, code) = if expired {
                ("expired", reason::C_EXPIRED)
            } else {
                ("cap", reason::RENEW_CAP)
            };
            return Err(Stop::Failed {
                result,
                code,
                reissue: Reissue::NewChain,
            });
        }
        // 9. The renewed C.
        let issued = self
            .chain(claims, claims.renew_no + 1, now_ms)
            .map_err(|_| Stop::Unavailable)?;
        challenge::count_issued(&issued, "renewed");
        Ok(issued)
    }

    /// A `C` continuing `old`'s chain (§7.4 steps 8 and 9): its type, band,
    /// attempt, `ret`, `ui_seed` and PoW; its providers without an external
    /// one that the current request no longer qualifies for (§5.4 rule 2);
    /// the current request's bindings and the verified key.
    fn chain(
        &self,
        old: &SealedChallengeClaims,
        renew_no: u32,
        now_ms: i64,
    ) -> Result<Issued, IssueError> {
        let s = self.s;
        let Some(cfg) = &s.bundle.interactive else {
            return Err(IssueError::Rng);
        };
        // Phase 2 offers no external provider before WP-E2c, so §5.4 rule 2
        // removes any (there is no Turnstile configuration to be eligible
        // for).
        let providers = if renew_no == 0 {
            interactive::providers(
                cfg,
                s.host,
                &old.route_class,
                old.attempt_no,
                interactive::a11y_pref(&s.built.cookies),
            )
        } else {
            let eligible = |p: &ProviderId| {
                !p.is_external()
                    || turnstile_eligible(&mg_core::SelectionInput {
                        country_geo: None,
                        country_cf: None,
                        route_id: &old.route_class,
                        redact_path: false,
                        host: s.host,
                        attempt_no: old.attempt_no,
                        escalate_after: cfg.escalate_after,
                        a11y_pref: false,
                        turnstile: None,
                    })
            };
            old.providers.iter().copied().filter(eligible).collect()
        };
        let mut ret_hash = [0u8; 16];
        if old.ret_hash.len() == 16 {
            ret_hash.copy_from_slice(&old.ret_hash);
        }
        challenge::issue_interactive(
            &interactive::Seal {
                sealer: s.sealer,
                host: s.host,
                route_class: &old.route_class,
                band: old.risk_band,
                attempt_no: old.attempt_no,
                renew_no,
                providers,
                ui_seed: Some(old.ui_seed),
                pow: old.pow.clone().unwrap_or_default(),
                ret_hash,
                bind: s.bind,
                jkt: self.jkt.as_deref(),
                now_ms,
            },
            cfg,
            "",
            false,
            self.rng,
        )
    }

    /// The escalated `C` of a failure (§5.3, §7.1): from step 4a on.
    fn escalated(&self, now_ms: i64) -> Result<Issued, Stop> {
        let s = self.s;
        let Some(old) = &self.claims else {
            return Err(Stop::Unavailable);
        };
        let bundle = s.bundle;
        let (ty, band, attempt_no) = next_challenge_after_failure(
            old.challenge_type,
            old.risk_band,
            old.attempt_no,
            bundle.interactive_available,
        );
        let mut ret_hash = [0u8; 16];
        if old.ret_hash.len() == 16 {
            ret_hash.copy_from_slice(&old.ret_hash);
        }
        let issued = match (ty, &bundle.interactive) {
            (ChallengeType::Interactive, Some(cfg)) => challenge::issue_interactive(
                &interactive::Seal {
                    sealer: s.sealer,
                    host: s.host,
                    route_class: &old.route_class,
                    band,
                    attempt_no,
                    renew_no: 0,
                    providers: interactive::providers(
                        cfg,
                        s.host,
                        &old.route_class,
                        attempt_no,
                        interactive::a11y_pref(&s.built.cookies),
                    ),
                    ui_seed: None,
                    pow: interactive::pow_params(cfg, band),
                    ret_hash,
                    bind: s.bind,
                    jkt: None,
                    now_ms,
                },
                cfg,
                "",
                false,
                self.rng,
            ),
            _ => challenge::issue_with_ret_hash(
                s.sealer,
                s.host,
                &old.route_class,
                band,
                &s.bundle.challenge,
                ret_hash,
                s.bind,
                now_ms,
                self.rng,
            ),
        };
        let issued = issued.map_err(|_| Stop::Unavailable)?;
        challenge::count_issued(&issued, "reissued");
        Ok(issued)
    }
}

/// Runs `POST /__mg/c/renew` for an active schema 2 site (see the module
/// documentation) and counts `mg_challenge_renew_total`.
pub async fn renew(
    state: &StateHandle,
    rng: &dyn Rng,
    s: &Submit<'_>,
    body: &mut dyn BodySource,
) -> Renewed {
    let mut flow = Flow {
        s,
        state,
        rng,
        entity: String::new(),
        prefix: String::new(),
        body_done: false,
        claims: None,
        jkt: None,
        rebind: false,
        started: std::time::Instant::now(),
    };
    let (mut response, result, code) = match flow.run(body).await {
        Ok(issued) => (
            pages::renewed_json(issued.shown()),
            if flow.rebind { "rebind" } else { "ok" },
            None,
        ),
        Err(stop) => answer(&flow, stop),
    };
    response.close = !flow.body_done;
    metrics().challenge_renew.with_label_values(&[result]).inc();
    // §15.1: only counted failures and rebinds write kind=feedback.
    let feedback = if result == "rebind" {
        Some(renew_feedback(s, flow.claims.as_ref(), None, true))
    } else if code.is_some_and(crate::mg_endpoints::counts_as_failure) && response.status != 429 {
        Some(renew_feedback(s, flow.claims.as_ref(), code, false))
    } else {
        None
    };
    Renewed {
        response,
        result,
        code,
        feedback,
    }
}

/// The answer to a stop (counting a failure where §7.4 says so).
fn answer(flow: &Flow<'_, '_>, stop: Stop) -> (EdgeResponse, &'static str, Option<&'static str>) {
    let s = flow.s;
    match stop {
        Stop::Unavailable => (EdgeResponse::internal_unavailable(), "unavailable", None),
        Stop::TooEarly => (
            pages::too_early_json(),
            "too_early",
            Some(reason::TOO_EARLY),
        ),
        Stop::Limited {
            result,
            code,
            retry_after_s,
        } => (
            pages::rate_limited_json(s.request_id, retry_after_s),
            result,
            Some(code),
        ),
        Stop::Failed {
            result,
            code,
            reissue,
        } => {
            if crate::mg_endpoints::counts_as_failure(code) {
                let failures = s.bundle.challenge_limits.failures(s.site_id, &flow.dims());
                let _ = flow.state.record_failure(failures);
            }
            let now_ms = flow.clock();
            let new = match reissue {
                Reissue::None => None,
                Reissue::Escalated => match flow.escalated(now_ms) {
                    Ok(n) => Some(n),
                    Err(_) => {
                        return (
                            EdgeResponse::internal_unavailable(),
                            "unavailable",
                            Some(code),
                        );
                    }
                },
                Reissue::NewChain => {
                    let chained = flow.claims.as_ref().map(|old| flow.chain(old, 0, now_ms));
                    match chained {
                        Some(Ok(n)) => {
                            challenge::count_issued(&n, "renewed");
                            Some(n)
                        }
                        _ => {
                            return (
                                EdgeResponse::internal_unavailable(),
                                "unavailable",
                                Some(code),
                            );
                        }
                    }
                }
            };
            (
                pages::failed_json(s.request_id, new.as_ref().map(Issued::shown)),
                result,
                Some(code),
            )
        }
    }
}
