//! Turnstile submissions and renewals in process (docs/impl/phase2-spec.md
//! §7.4, §7.5 steps 5, 12, 13, §8.5, §8.6; WP-E2c): every row of the §8.5
//! table against WP-C6's loopback mock siteverify, the shadow mode, the
//! token replay key, the re-check of §5.4 rule 2 on submissions and
//! renewals, and the circuit breaker. No test reaches any other host
//! (D-52).

use super::*;
use crate::turnstile::tests::{DirectVerifier, chrono_like, provider};
use crate::turnstile::{Countries, Offer, SiteTurnstile};
use mg_challenge::{SealKeys, parse_epoch_kid, turnstile_cdata_for};
use mg_edge_core::outbound::{
    BreakerState, DisabledReason, Siteverify, SiteverifyUrl, TurnstileSecrets,
    validate_siteverify_url,
};
use mg_edge_core::testkit::siteverify::{FakeSiteverify, SvReply};

/// `t` of a Turnstile submission (the `external` mode of §7.6).
const EXTERNAL_T: &str = r#"{"ix":{"v":1,"mode":"external","modality":"touch","locale":"en","ks":"idb","sv":"0.3.0","fallback":null,"trusted":3,"act_ms":1500}}"#;

/// The v2 test site with Turnstile (`first`, `mode`, hostnames
/// example.com / www.example.com, every route).
fn ts_bundle(mode: &str) -> pb::SiteBundle {
    let mut b = v2_bundle();
    let mut p = provider();
    p.mode = mode.into();
    b.providers = vec![p];
    b
}

fn tune_ts(b: &mut pb::SiteBundle, f: impl FnOnce(&mut pb::ProviderConfig)) {
    f(&mut b.providers[0]);
}

/// The site's secret, its breaker and the mock siteverify.
struct Ts {
    site: SiteTurnstile,
    mock: FakeSiteverify,
    url: SiteverifyUrl,
    keys: SealKeys,
}

impl Ts {
    fn new(secrets: &[&str]) -> Self {
        let mock = FakeSiteverify::start().unwrap();
        let url = validate_siteverify_url(&mock.url(), true).unwrap();
        let secrets = (!secrets.is_empty())
            .then(|| TurnstileSecrets::new(secrets.iter().map(|s| (*s).to_owned()).collect()))
            .map(Result::unwrap);
        // A per-test site id keeps the breakers' gauges apart.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            site: SiteTurnstile::new(&format!("blog-ts-{n}"), secrets),
            mock,
            url,
            keys: crate::test_support::keys().seal,
        }
    }

    fn offer<'a>(&'a self, f: &'a Fixture, now: i64) -> Option<Offer<'a>> {
        Offer::new(&f.bundle, &self.site, &self.keys, now)
    }

    /// An interactive `C` offering Turnstile first (members, returning to
    /// `/members/a`), issued at `iat` for `req`.
    fn c(&self, f: &Fixture, req: &Req, attempt: u32, iat: i64) -> (String, SealedChallengeClaims) {
        let cfg = f.bundle.interactive.as_ref().unwrap();
        let built = req.built("production");
        let bind = bind_of(&built);
        let sel = interactive::Selecting {
            host: HOST,
            route_id: "members",
            redact_path: false,
            countries: Countries::default(),
            a11y_pref: false,
            turnstile: self.offer(f, iat),
        };
        let providers = interactive::providers(cfg, &sel, attempt);
        assert_eq!(providers[0], ProviderId::Turnstile, "offered first");
        interactive::seal(
            &interactive::Seal {
                sealer: &f.sealer,
                host: HOST,
                route_class: "members",
                band: RiskBand::Low,
                attempt_no: attempt,
                renew_no: 0,
                providers,
                ui_seed: None,
                pow: interactive::pow_params(cfg, RiskBand::Low),
                ret_hash: ret_hash("/members/a"),
                bind: &bind,
                jkt: None,
                now_ms: iat,
            },
            &OsRng,
        )
        .unwrap()
    }

    /// The reply `cdata` siteverify echoes for `claims`.
    fn cdata(&self, claims: &SealedChallengeClaims) -> String {
        turnstile_cdata_for(
            &self.keys,
            "blog",
            parse_epoch_kid(&claims.kid).unwrap(),
            &claims.nonce,
        )
    }

    /// A passing siteverify reply for `claims`, solved now.
    fn pass(&self, claims: &SealedChallengeClaims) -> SvReply {
        SvReply::success(HOST, "members", &self.cdata(claims), &chrono_like(now_ms()))
    }

    fn run(&self, f: &Fixture, req: &Req, v: &Value, now: i64) -> Submitted {
        let env = f.bundle.env_for_host(&req.host).unwrap();
        let built = req.built(&env.name);
        let bind = bind_of(&built);
        rt().block_on(async {
            let verifier = DirectVerifier(Siteverify::build(self.url.clone()).unwrap());
            let s = Submit {
                request_id: ID,
                now_ms: now,
                site_id: "blog",
                sealer: &f.sealer,
                sdk: &f.sdk,
                bundle: &f.bundle,
                env,
                host: &req.host,
                built: &built,
                bind: &bind,
                content_encoding: false,
                turnstile: self.offer(f, now),
                verifier: &verifier,
            };
            let mut body = Chunks(vec![Bytes::from(v.to_string())]);
            submit(&f.state, &OsRng, &s, &mut body).await
        })
    }

    fn renew(&self, f: &Fixture, req: &Req, v: &Value, now: i64) -> Renewed {
        let env = f.bundle.env_for_host(&req.host).unwrap();
        let built = req.built(&env.name);
        let bind = bind_of(&built);
        let s = Submit {
            request_id: ID,
            now_ms: now,
            site_id: "blog",
            sealer: &f.sealer,
            sdk: &f.sdk,
            bundle: &f.bundle,
            env,
            host: &req.host,
            built: &built,
            bind: &bind,
            content_encoding: false,
            turnstile: self.offer(f, now),
            verifier: &crate::turnstile::NoVerifier,
        };
        let mut body = Chunks(vec![Bytes::from(v.to_string())]);
        rt().block_on(renew(&f.state, &OsRng, &s, &mut body))
    }
}

/// A signed v2 Turnstile submission of `c` with `token` (`pp`).
fn ts_body(k: &TestSessionKey, c: &str, token: &str) -> Value {
    let counters = pow_solve_v2(c, 8, 2, 1 << 24).unwrap();
    let ts = 1_790_000_000_123u64;
    let sig = k.sign_submission(&mg_challenge::SubmissionFields {
        c,
        ty: "interactive",
        p: "turnstile",
        pp: token,
        t: EXTERNAL_T,
        counters: &counters,
        ret: "/members/a",
        ts,
        build: BUILD,
    });
    json!({"v": 2, "type": "interactive", "c": c, "p": "turnstile", "pp": token, "t": EXTERNAL_T,
           "pow": {"counters": counters}, "ret": "/members/a", "ts": ts, "build": BUILD,
           "jwk": k.jwk_value(), "sig": sig})
}

/// Whether the client's failures so far reached `max_failures = 1`: the
/// next submission is 429 before its body (an `ic.body` otherwise).
fn limited(f: &Fixture, req: &Req) -> bool {
    run(f, req, &mut Chunks(vec![Bytes::from_static(b"{}")]))
        .response
        .status
        == 429
}

fn one_failure(mut b: pb::SiteBundle) -> pb::SiteBundle {
    b.challenge.as_mut().unwrap().max_failures = 1;
    b
}

/// The providers of the `C` attached to a failure.
fn new_providers(f: &Fixture, out: &Submitted, now: i64) -> Vec<ProviderId> {
    let (c, _) = new_c(&out.response);
    open_ix(f, &c, now).providers
}

/// §7.5 step 13, §8.4, §8.5 first row: a passing siteverify earns
/// `interactive_ext:turnstile`; siteverify got the secret, the token, the
/// client IP and the nonce's idempotency key; the token's replay key then
/// refuses the same token on another `C` (`ic.ts_dup`, counted, no second
/// siteverify call).
#[test]
fn pass_earns_interactive_ext_and_the_token_is_spent() {
    let f = fixture(&ts_bundle("enforce"));
    assert!(f.bundle.turnstile.is_some());
    let ts = Ts::new(&["sec-current"]);
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let (c, claims) = ts.c(&f, &req, 1, now - 3_000);
    ts.mock.push_replies([ts.pass(&claims)]);
    let out = ts.run(&f, &req, &ts_body(&k, &c, "tok-pass-1"), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    let token = token_claims(&f, &out.response, now / 1000);
    assert_eq!(token.lvl, TokenLevel::InteractiveExt(ProviderId::Turnstile));
    assert_eq!(
        token.exp - token.iat,
        i64::from(f.bundle.clearance.ttl_interactive_ext_s)
    );
    assert_eq!(token.cnf_jkt(), Some(k.thumbprint().as_str()));
    let fb = &out.record.feedback;
    let p = fb.provider.as_ref().unwrap();
    assert_eq!(
        (p.id, p.outcome, p.mode),
        (
            ProviderId::Turnstile,
            VerdictOutcome::Pass,
            mg_core::EvalMode::Enforce
        )
    );
    assert_eq!(
        fb.lvl,
        Some(TokenLevel::InteractiveExt(ProviderId::Turnstile))
    );
    assert_eq!(out.record.provider, "turnstile");
    assert_eq!(
        fb.ix.as_ref().unwrap().a11y_mode,
        mg_core::A11yMode::None,
        "external"
    );
    let seen = ts.mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].secret().as_deref(), Some("sec-current"));
    assert_eq!(seen[0].response().as_deref(), Some("tok-pass-1"));
    assert_eq!(seen[0].remoteip().as_deref(), Some(IP));
    assert_eq!(
        seen[0].idempotency_key().unwrap(),
        mg_challenge::idempotency_key(&claims.nonce, false)
    );
    assert_eq!(seen[0].header("user-agent"), Some("morphgate-dev-tooling"));

    // The same token on another C: ic.ts_dup from the Edge's own replay
    // set, no siteverify call; that C's nonce is consumed.
    let (c2, _) = ts.c(&f, &req, 1, now - 3_000);
    let out = ts.run(&f, &req, &ts_body(&k, &c2, "tok-pass-1"), now);
    assert_eq!(reasons(&out)[0], "ic.ts_dup");
    assert_eq!(ts.mock.requests().len(), 1, "no call for a spent token");
    let out = ts.run(&f, &req, &ts_body(&k, &c2, "tok-other"), now);
    assert_eq!(reasons(&out)[0], reason::NONCE_REUSED);
    // Counted under enforce.
    let f1 = fixture(&one_failure(ts_bundle("enforce")));
    let (c, claims) = ts.c(&f1, &req, 1, now - 3_000);
    ts.mock.push_replies([ts.pass(&claims)]);
    let ok = ts.run(&f1, &req, &ts_body(&k, &c, "tok-dup"), now);
    assert_eq!(ok.response.status, 200);
    let (c3, _) = ts.c(&f1, &req, 1, now - 3_000);
    let out = ts.run(&f1, &req, &ts_body(&k, &c3, "tok-dup"), now);
    assert_eq!(reasons(&out)[0], "ic.ts_dup");
    assert!(limited(&f1, &req), "counted under enforce");
}

/// §8.5: every failing row under `enforce`: `ic.ts_*` counts, the new `C`
/// may offer Turnstile again; `bad-request`, a rejected secret, 5xx,
/// transport errors and malformed replies are `Unavailable` /
/// `Misconfigured`: not counted, the feedback outcome says so, and the new
/// `C` offers no Turnstile.
#[test]
fn every_row_of_the_mapping_under_enforce() {
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let ts_now = chrono_like(now_ms());
    type Row = (
        &'static str,
        fn(&Ts, &SealedChallengeClaims, &str) -> Vec<SvReply>,
        &'static str,
        bool,
    );
    let rows: Vec<Row> = vec![
        (
            "hostname",
            |_, c, ts| vec![SvReply::success("www.example.com", "members", &cd(c), ts)],
            "ic.ts_hostname",
            true,
        ),
        (
            "action",
            |_, c, ts| vec![SvReply::success(HOST, "login", &cd(c), ts)],
            "ic.ts_action",
            true,
        ),
        (
            "cdata",
            |_, _, ts| vec![SvReply::success(HOST, "members", &"A".repeat(43), ts)],
            "ic.ts_cdata",
            true,
        ),
        (
            "time",
            |_, c, _| {
                vec![SvReply::success(
                    HOST,
                    "members",
                    &cd(c),
                    "2020-01-01T00:00:00Z",
                )]
            },
            "ic.ts_time",
            true,
        ),
        (
            "invalid-input-response",
            |_, _, _| vec![SvReply::error_codes(&["invalid-input-response"])],
            "ic.ts_fail",
            true,
        ),
        (
            "missing-input-response",
            |_, _, _| vec![SvReply::error_codes(&["missing-input-response"])],
            "ic.ts_fail",
            true,
        ),
        (
            "timeout-or-duplicate",
            |_, _, _| vec![SvReply::error_codes(&["timeout-or-duplicate"])],
            "ic.ts_dup",
            true,
        ),
        (
            "bad-request",
            |_, _, _| vec![SvReply::error_codes(&["bad-request"])],
            "ic.provider_unavailable",
            false,
        ),
        (
            "internal-error twice",
            |_, _, _| {
                vec![
                    SvReply::error_codes(&["internal-error"]),
                    SvReply::error_codes(&["internal-error"]),
                ]
            },
            "ic.provider_unavailable",
            false,
        ),
        (
            "5xx twice",
            |_, _, _| vec![SvReply::status(502), SvReply::status(503)],
            "ic.provider_unavailable",
            false,
        ),
        (
            "disconnect twice",
            |_, _, _| vec![SvReply::disconnect(), SvReply::disconnect()],
            "ic.provider_unavailable",
            false,
        ),
        (
            "not json",
            |_, _, _| vec![SvReply::raw(200, Some("text/html"), "<html>")],
            "ic.provider_unavailable",
            false,
        ),
        (
            "403",
            |_, _, _| vec![SvReply::status(403)],
            "ic.provider_unavailable",
            false,
        ),
        (
            "missing-input-secret",
            |_, _, _| vec![SvReply::error_codes(&["missing-input-secret"])],
            "ic.provider_misconfigured",
            false,
        ),
        (
            "invalid-input-secret",
            |_, _, _| vec![SvReply::error_codes(&["invalid-input-secret"])],
            "ic.provider_misconfigured",
            false,
        ),
    ];
    fn cd(c: &SealedChallengeClaims) -> String {
        turnstile_cdata_for(
            &crate::test_support::keys().seal,
            "blog",
            parse_epoch_kid(&c.kid).unwrap(),
            &c.nonce,
        )
    }
    for (i, (name, replies, code, counted)) in rows.into_iter().enumerate() {
        let f = fixture(&one_failure(ts_bundle("enforce")));
        let ts = Ts::new(&["sec-current"]);
        let (c, claims) = ts.c(&f, &req, 1, now - 3_000);
        ts.mock.push_replies(replies(&ts, &claims, &ts_now));
        let out = ts.run(&f, &req, &ts_body(&k, &c, &format!("tok-row-{i}")), now);
        assert_eq!(out.response.status, 403, "{name}");
        assert_eq!(reasons(&out)[0], code, "{name}");
        let p = out.record.feedback.provider.as_ref().unwrap();
        let unavailable = !counted;
        if unavailable {
            let want = if code == "ic.provider_misconfigured" {
                VerdictOutcome::Misconfigured
            } else {
                VerdictOutcome::Unavailable
            };
            assert_eq!(p.outcome, want, "{name}");
            assert_eq!(out.record.feedback.outcome, Some(want), "{name}");
            assert!(
                !new_providers(&f, &out, now).contains(&ProviderId::Turnstile),
                "{name}: the new C falls back"
            );
        } else {
            assert_eq!(p.outcome, VerdictOutcome::Fail, "{name}");
            assert!(
                new_providers(&f, &out, now).contains(&ProviderId::Turnstile),
                "{name}: enforce keeps offering it"
            );
        }
        assert_eq!(limited(&f, &req), counted, "{name}: counted");
        if code == "ic.provider_misconfigured" {
            // §8.6: disabled at once; nothing offers it any more.
            assert_eq!(
                ts.site.breaker().state(now_ms()),
                BreakerState::Disabled(DisabledReason::Misconfigured),
                "{name}"
            );
            assert!(!ts.offer(&f, now_ms()).unwrap().usable);
        }
    }
}

/// §8.4: a rejected current secret is retried with the previous one (its
/// own idempotency key); the previous one passing is a pass.
#[test]
fn previous_secret_during_a_rotation() {
    let f = fixture(&ts_bundle("enforce"));
    let ts = Ts::new(&["sec-new", "sec-old"]);
    let req = Req::json();
    let now = now_ms();
    let (c, claims) = ts.c(&f, &req, 1, now - 3_000);
    ts.mock.push_replies([
        SvReply::error_codes(&["invalid-input-secret"]),
        ts.pass(&claims),
    ]);
    let out = ts.run(&f, &req, &ts_body(&key("a"), &c, "tok-rot"), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    let seen = ts.mock.requests();
    assert_eq!(
        (seen[0].secret().as_deref(), seen[1].secret().as_deref()),
        (Some("sec-new"), Some("sec-old"))
    );
    assert_eq!(
        seen[1].idempotency_key().unwrap(),
        mg_challenge::idempotency_key(&claims.nonce, true)
    );
}

/// §8.5 shadow: a pass still earns `interactive_ext:turnstile`; failures
/// and unavailability are not counted and the new `C` offers no Turnstile
/// (the visitor falls back to `self_hold`).
#[test]
fn shadow_passes_and_only_falls_back() {
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let f = fixture(&one_failure(ts_bundle("shadow")));
    let ts = Ts::new(&["sec"]);
    let (c, claims) = ts.c(&f, &req, 1, now - 3_000);
    ts.mock.push_replies([ts.pass(&claims)]);
    let out = ts.run(&f, &req, &ts_body(&k, &c, "tok-sh-1"), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    assert_eq!(
        token_claims(&f, &out.response, now / 1000).lvl,
        TokenLevel::InteractiveExt(ProviderId::Turnstile)
    );
    assert_eq!(
        out.record.feedback.provider.as_ref().unwrap().mode,
        mg_core::EvalMode::Shadow
    );
    for (i, reply) in [
        SvReply::success(HOST, "members", &"B".repeat(43), &chrono_like(now_ms())),
        SvReply::error_codes(&["timeout-or-duplicate"]),
        SvReply::error_codes(&["bad-request"]),
    ]
    .into_iter()
    .enumerate()
    {
        let (c, _) = ts.c(&f, &req, 1, now - 3_000);
        ts.mock.push_replies([reply]);
        let out = ts.run(&f, &req, &ts_body(&k, &c, &format!("tok-sh-f{i}")), now);
        assert_eq!(out.response.status, 403);
        let new = new_providers(&f, &out, now);
        assert_eq!(new, vec![ProviderId::SelfHold, ProviderId::PowA11y], "{i}");
        assert_eq!(new_c(&out.response).1.get("turnstile"), None);
    }
    assert!(!limited(&f, &req), "nothing counted in shadow");
}

/// §7.5 step 5 / §5.4 rule 2 on the submission: a `C` that offered
/// Turnstile under the old bundle, submitted where the request no longer
/// qualifies (D-70: a `denied_countries` list with an unknown country;
/// another route list; the provider disabled), fails with
/// `ic.provider_not_offered`, not counted, without any siteverify call; the
/// new `C` has no Turnstile.
#[test]
fn submission_rechecks_rule_2() {
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let ts = Ts::new(&["sec"]);
    let issuing = fixture(&ts_bundle("enforce"));
    let mut denied = ts_bundle("enforce");
    tune_ts(&mut denied, |p| p.denied_countries = vec!["CN".into()]);
    let mut routes = ts_bundle("enforce");
    tune_ts(&mut routes, |p| p.route_ids = vec!["login".into()]);
    let mut off = ts_bundle("enforce");
    tune_ts(&mut off, |p| p.enabled = false);
    for (i, b) in [denied, routes, off].into_iter().enumerate() {
        let f = fixture(&one_failure(b));
        let (c, _) = ts.c(&issuing, &req, 1, now - 3_000);
        let out = ts.run(&f, &req, &ts_body(&k, &c, &format!("tok-r2-{i}")), now);
        assert_eq!(reasons(&out)[0], reason::PROVIDER_NOT_OFFERED, "{i}");
        assert!(!new_providers(&f, &out, now).contains(&ProviderId::Turnstile));
        assert!(!limited(&f, &req), "{i}: not counted");
    }
    assert!(ts.mock.requests().is_empty(), "no siteverify call");
    // Without a usable secret (here: none) the same holds.
    let none = Ts::new(&[]);
    let f = fixture(&ts_bundle("enforce"));
    let (c, _) = ts.c(&issuing, &req, 1, now - 3_000);
    let out = none.run(&f, &req, &ts_body(&k, &c, "tok-r2-none"), now);
    assert_eq!(reasons(&out)[0], reason::PROVIDER_NOT_OFFERED);
}

/// §7.4: a renewal keeps Turnstile (with the new nonce's `cData`) while the
/// request qualifies and drops it otherwise; a new chain selects again.
#[test]
fn renewal_rechecks_rule_2() {
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let ts = Ts::new(&["sec"]);
    let f = fixture(&ts_bundle("enforce"));
    let (c, _) = ts.c(&f, &req, 1, now - 1_000);
    let r = ts.renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!(r.response.status, 200, "{:?}", r.code);
    let v = body_json(&r.response);
    let claims = open_ix(&f, v["challenge"].as_str().unwrap(), now);
    assert_eq!(claims.providers[0], ProviderId::Turnstile);
    let t = &v["ix"]["turnstile"];
    assert_eq!(t["cdata"], ts.cdata(&claims));
    assert_eq!(t["action"], "members");
    assert_eq!(t["lang"], "zh-cn", "Accept-Language zh-CN");
    assert_eq!(t["sitekey"], "0x4AAAAAAAtest-sitekey");

    let mut denied = ts_bundle("enforce");
    tune_ts(&mut denied, |p| p.denied_countries = vec!["CN".into()]);
    let fd = fixture(&denied);
    let (c, _) = ts.c(&f, &req, 1, now - 1_000);
    let r = ts.renew(&fd, &req, &renew_body(&k, &c), now);
    assert_eq!(r.response.status, 200, "{:?}", r.code);
    let v = body_json(&r.response);
    let claims = open_ix(&fd, v["challenge"].as_str().unwrap(), now);
    assert_eq!(
        claims.providers,
        vec![ProviderId::SelfHold, ProviderId::PowA11y]
    );
    assert!(v["ix"].get("turnstile").is_none());
}

/// §8.6: five unavailable verifications within a minute open the circuit;
/// the provider is then not offered (nor verified) until it half-opens.
#[test]
fn breaker_opens_after_five_unavailable() {
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let f = fixture(&ts_bundle("enforce"));
    let ts = Ts::new(&["sec"]);
    ts.mock.set_default_reply(SvReply::status(503));
    for i in 0..5 {
        let (c, _) = ts.c(&f, &req, 1, now - 3_000);
        let out = ts.run(&f, &req, &ts_body(&k, &c, &format!("tok-br-{i}")), now);
        assert_eq!(reasons(&out)[0], reason::PROVIDER_UNAVAILABLE, "{i}");
    }
    assert!(matches!(
        ts.site.breaker().state(now_ms()),
        BreakerState::Open { .. }
    ));
    let offer = ts.offer(&f, now_ms()).unwrap();
    assert!(!offer.usable);
    let cfg = f.bundle.interactive.as_ref().unwrap();
    let sel = interactive::Selecting {
        host: HOST,
        route_id: "members",
        redact_path: false,
        countries: Countries::default(),
        a11y_pref: false,
        turnstile: Some(offer),
    };
    assert!(!interactive::providers(cfg, &sel, 1).contains(&ProviderId::Turnstile));
    assert_eq!(ts.mock.requests().len(), 10, "one retry each");
}

/// The page language picks the widget language; the `ix` with Turnstile
/// stays within 1024 bytes (§7.2).
#[test]
fn ix_turnstile_member() {
    let f = fixture(&ts_bundle("enforce"));
    let ts = Ts::new(&["sec"]);
    let now = now_ms();
    let (_, claims) = ts.c(&f, &Req::json(), 1, now);
    let cfg = f.bundle.interactive.as_ref().unwrap();
    let ix = interactive::ix_value(
        &claims,
        cfg,
        false,
        Some(&interactive::IxTurnstile {
            offer: ts.offer(&f, now).unwrap(),
            lang: crate::turnstile::widget_lang("en"),
        }),
    );
    assert_eq!(ix["providers"][0], "turnstile");
    assert_eq!(ix["turnstile"]["lang"], "en");
    assert_eq!(ix["turnstile"]["cdata"], ts.cdata(&claims));
    assert!(ix.to_string().len() <= 1024, "{}", ix.to_string().len());
    // Without Turnstile in the C, no member even with an offer.
    let (_, mut plain) = ts.c(&f, &Req::json(), 1, now);
    plain.providers = vec![ProviderId::SelfHold, ProviderId::PowA11y];
    let ix = interactive::ix_value(
        &plain,
        cfg,
        false,
        Some(&interactive::IxTurnstile {
            offer: ts.offer(&f, now).unwrap(),
            lang: "en",
        }),
    );
    assert!(ix.get("turnstile").is_none());
}
