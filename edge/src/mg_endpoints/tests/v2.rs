//! Unit tests of the Phase 2 submission (`POST /__mg/c` v2, spec §7.5) and
//! of `POST /__mg/c/renew` (§7.4), in process against the local state layer.
//! The end-to-end tests through the binary are in
//! `edge/tests/interactive_flow.rs`.

use super::*;
use crate::interactive;
use crate::renew::{Renewed, renew};
use mg_challenge::testkit::TestSessionKey;
use mg_challenge::{bind_hash, pow_solve_v2, ret_hash, ui_params};
use mg_edge_core::testkit::http::test_site_bundle_v2;

/// The Phase 2 test site: [`super::test_bundle`]'s routes and quotas in a
/// schema 2 bundle with interactive challenges enabled, PoW v2 at 8 bits
/// with 2 sub-puzzles (`pow_a11y` 12 bits), no minimum PoW or a11y time.
fn v2_bundle() -> pb::SiteBundle {
    let v1 = test_bundle();
    let mut b = test_site_bundle_v2("blog", &HOSTS, 1);
    b.monitor_only = false;
    b.environments = v1.environments;
    let c = b.challenge.as_mut().unwrap();
    let old = v1.challenge.unwrap();
    c.max_failures = old.max_failures;
    c.submit_rate = old.submit_rate;
    c.submit_burst = old.submit_burst;
    c.pow_bits = old.pow_bits;
    c.fallback_ret = old.fallback_ret;
    let ix = c.interactive.as_mut().unwrap();
    ix.enabled = true;
    ix.pow_bits = Some(pb::challenge_config::PowBits {
        low: 8,
        medium: 8,
        high: 8,
        very_high: 9,
    });
    ix.pow_k = 2;
    ix.a11y_bits = 12;
    ix.a11y_min_ms = 0;
    b
}

/// A fixture whose local replay set vouches for challenges issued before it
/// was created (the tests seal them in the past).
fn fixture(b: &pb::SiteBundle) -> Fixture {
    Fixture::with_state(b, |cfg| cfg.process_start_ms = 0)
}

fn tune_ix(b: &mut pb::SiteBundle, f: impl FnOnce(&mut pb::InteractiveConfig)) {
    f(b.challenge.as_mut().unwrap().interactive.as_mut().unwrap());
}

fn key(label: &str) -> TestSessionKey {
    TestSessionKey::from_label(label)
}

/// An interactive `C` for `req` on `members`, returning to `/members/a`.
fn ix_c(
    f: &Fixture,
    req: &Req,
    jkt: Option<&str>,
    attempt: u32,
    renew_no: u32,
    iat: i64,
) -> (String, SealedChallengeClaims) {
    let cfg = f.bundle.interactive.as_ref().unwrap();
    let built = req.built("production");
    let bind = bind_of(&built);
    interactive::seal(
        &interactive::Seal {
            sealer: &f.sealer,
            host: HOST,
            route_class: "members",
            band: RiskBand::Low,
            attempt_no: attempt,
            renew_no,
            providers: interactive::providers(
                cfg,
                &interactive::Selecting::builtin(HOST, "members", false),
                attempt,
            ),
            ui_seed: None,
            pow: interactive::pow_params(cfg, RiskBand::Low),
            ret_hash: ret_hash("/members/a"),
            bind: &bind,
            jkt,
            now_ms: iat,
        },
        &OsRng,
    )
    .unwrap()
}

/// `t` with the interactive telemetry of `mode` (§7.6), held / waited for
/// `ms`.
fn t_of(mode: &str, ms: u32) -> String {
    // The SDK reports 10 ms steps (§7.6).
    let ms = ms.div_ceil(10) * 10;
    let ix = match mode {
        "hold" => {
            json!({"v": 1, "mode": "hold", "modality": "mouse", "locale": "zh-CN", "ks": "idb",
            "sv": "0.3.0", "fallback": null, "trusted": 3, "act_ms": 2300,
            "pre": {"moves": 5, "path_px": 9, "straight": 0.7, "speed_mean": 6, "speed_sd": 4,
                    "dir_changes": 3, "render_to_input_ms": 11, "to_target_ms": 9},
            "hold": {"ms": ms, "offset": [0.1, -0.2], "jitter_px": 2, "moves": 3, "cancels": 0,
                     "pressure": 0.5, "pressure_var": 0, "contact_var": 0},
            "page": {"vis": 0, "vis_during": 0, "focus": 0, "frame_mean": 4, "frame_sd": 1},
            "pow": {"ms": 8, "worker": true, "impl": "js"}})
        }
        "single" => json!({"v": 1, "mode": "single", "modality": "keyboard", "locale": "en",
            "ks": "local", "sv": "0.3.0", "fallback": null, "trusted": 3, "act_ms": 2000,
            "single": {"wait_ms": ms},
            "page": {"vis": 1, "vis_during": 0, "focus": 2, "frame_mean": 4, "frame_sd": 1},
            "pow": {"ms": 9, "worker": true, "impl": "wasm"}}),
        other => panic!("{other}"),
    };
    json!({"ix": ix}).to_string()
}

/// A signed v2 submission of `c` (PoW v2 for interactive, v1 otherwise).
#[allow(clippy::too_many_arguments)]
fn v2_body(
    k: &TestSessionKey,
    c: &str,
    ty: ChallengeType,
    p: &str,
    t: &str,
    ret: &str,
    bits: u32,
    n: usize,
) -> Value {
    let counters = if ty == ChallengeType::Interactive {
        pow_solve_v2(c, bits, n, 1 << 24).unwrap()
    } else {
        vec![pow_solve(c, bits, 1 << 24).unwrap()]
    };
    let ts = 1_790_000_000_123u64;
    let sig = k.sign_submission(&mg_challenge::SubmissionFields {
        c,
        ty: ty.as_str(),
        p,
        pp: "",
        t,
        counters: &counters,
        ret,
        ts,
        build: BUILD,
    });
    json!({"v": 2, "type": ty.as_str(), "c": c, "p": p, "pp": "", "t": t,
           "pow": {"counters": counters}, "ret": ret, "ts": ts, "build": BUILD,
           "jwk": k.jwk_value(), "sig": sig})
}

/// A hold submission of an interactive `C` with its required hold.
fn hold_body(k: &TestSessionKey, c: &str, claims: &SealedChallengeClaims) -> Value {
    let hold = ui_params(claims.ui_seed).required_hold_ms;
    v2_body(
        k,
        c,
        ChallengeType::Interactive,
        "self_hold",
        &t_of("hold", hold),
        "/members/a",
        8,
        2,
    )
}

fn renew_body(k: &TestSessionKey, c: &str) -> Value {
    let ts = 1_790_000_000_456u64;
    json!({"v": 2, "c": c, "jwk": k.jwk_value(), "ts": ts, "sig": k.sign_renew(c, ts)})
}

fn run_renew(f: &Fixture, req: &Req, v: &Value, now: i64) -> Renewed {
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
        turnstile: None,
        verifier: &crate::turnstile::NoVerifier,
    };
    let mut body = Chunks(vec![Bytes::from(v.to_string())]);
    rt().block_on(renew(&f.state, &OsRng, &s, &mut body))
}

fn run_json_at(f: &Fixture, req: &Req, v: &Value, now: i64) -> Submitted {
    run_at(
        f,
        req,
        &mut Chunks(vec![Bytes::from(v.to_string())]),
        now,
        &OsRng,
    )
}

/// The `C` and `ix` of a JSON answer.
fn new_c(r: &EdgeResponse) -> (String, Value) {
    let v = body_json(r);
    (v["challenge"].as_str().unwrap().to_owned(), v["ix"].clone())
}

fn open_ix(f: &Fixture, c: &str, now: i64) -> SealedChallengeClaims {
    f.sealer
        .open(c, HOST, ChallengeType::Interactive, now)
        .unwrap()
}

fn set_cookies(r: &EdgeResponse) -> Vec<&str> {
    r.headers
        .iter()
        .filter(|(n, _)| *n == "Set-Cookie")
        .map(|(_, v)| v.as_str())
        .collect()
}

/// §7.5: a `self_hold` submission (hold mode) earns an `interactive` v2
/// token bound to the key (`cnf.jkt`, `lat`), the status cookie after the
/// clearance cookie, the fetch answer with `now_ms`, and the feedback's
/// interaction summary.
#[test]
fn self_hold_earns_a_bound_interactive_token() {
    let f = fixture(&v2_bundle());
    assert!(f.bundle.interactive_available);
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let (c, claims) = ix_c(&f, &req, Some(&k.thumbprint()), 1, 1, now - 3_000);
    let out = run_json_at(&f, &req, &hold_body(&k, &c, &claims), now);
    let r = &out.response;
    assert_eq!(r.status, 200, "{} {:?}", r.body_text(), reasons(&out));
    let v = body_json(r);
    assert_eq!((v["ok"].as_bool(), v["v"].as_u64()), (Some(true), Some(2)));
    let token = token_claims(&f, r, now / 1000);
    assert_eq!(token.v, mg_challenge::CLAIMS_V2);
    assert_eq!(token.lvl, TokenLevel::Interactive);
    assert_eq!(token.cnf_jkt(), Some(k.thumbprint().as_str()));
    assert_eq!(token.lat, Some(token.iat));
    assert_eq!(token.exp - token.iat, 1800);
    let cookies = set_cookies(r);
    assert!(cookies[0].starts_with("__Host-mg_clr="));
    assert_eq!(
        cookies[1],
        format!(
            "__Host-mg_st={}.{}.1; Max-Age=1800; Path=/; Secure; SameSite=Lax",
            token.iat, token.exp
        )
    );
    assert_eq!(cookies.len(), 2, "no accessibility cookie to delete");
    let fb = &out.record.feedback;
    assert_eq!(
        (fb.challenge_type, fb.lvl),
        (ChallengeType::Interactive, Some(TokenLevel::Interactive))
    );
    assert_eq!((fb.attempt_no, fb.renew_no, fb.bound), (1, 1, true));
    let ix = fb.ix.as_ref().unwrap();
    assert_eq!(
        ix.required_hold_ms,
        ui_params(claims.ui_seed).required_hold_ms
    );
    assert!(ix.elapsed_ms >= 3_000);
    assert_eq!(out.record.provider, "self_hold");
    assert!(out.record.telemetry.as_ref().unwrap().ix.is_some());
}

/// D-65 single activation earns `interactive`; `pow_a11y` without `ix`
/// earns `interactive_a11y` and sets `__Host-mg_a11y`; a later `self_hold`
/// success deletes it (§9.5).
#[test]
fn single_activation_pow_a11y_and_the_preference_cookie() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let wait = ui_params(claims.ui_seed).required_hold_ms;
    let body = v2_body(
        &k,
        &c,
        ChallengeType::Interactive,
        "self_hold",
        &t_of("single", wait),
        "/members/a",
        8,
        2,
    );
    let out = run_json_at(&f, &req, &body, now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    assert_eq!(
        token_claims(&f, &out.response, now / 1000).lvl,
        TokenLevel::Interactive
    );
    assert_eq!(
        out.record.feedback.ix.as_ref().unwrap().a11y_mode,
        mg_core::A11yMode::Single
    );

    let (c, _) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let body = v2_body(
        &k,
        &c,
        ChallengeType::Interactive,
        "pow_a11y",
        "",
        "/members/a",
        12,
        2,
    );
    let out = run_json_at(&f, &req, &body, now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    let token = token_claims(&f, &out.response, now / 1000);
    assert_eq!(token.lvl, TokenLevel::InteractiveA11y);
    assert_eq!(token.exp - token.iat, 900, "ttl_interactive_a11y_s");
    let cookies = set_cookies(&out.response);
    assert_eq!(cookies.len(), 3);
    assert_eq!(cookies[2], interactive::a11y_set_cookie());
    assert_eq!(out.record.provider, "pow_a11y");

    // self_hold with the cookie: deleted.
    let with_cookie = Req::json().with("Cookie", "x=1; __Host-mg_a11y=1");
    let (c, claims) = ix_c(&f, &with_cookie, None, 1, 0, now - 3_000);
    let out = run_json_at(&f, &with_cookie, &hold_body(&k, &c, &claims), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    assert_eq!(
        set_cookies(&out.response)[2],
        interactive::a11y_delete_cookie()
    );
}

/// §7.5 steps 5-11: the provider, the time window, the key binding, the
/// signature, PoW v2 and the hard checks; each failure attaches an
/// interactive `C` one attempt up (§5.3).
#[test]
fn interactive_failures() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let (a, b) = (key("a"), key("b"));
    let check = |body: &Value, code: &str| {
        let out = run_json_at(&f, &req, body, now);
        assert_eq!(out.response.status, 403, "{code}");
        assert_eq!(reasons(&out)[0], code);
        assert!(counts_as_failure(code), "{code}");
        let (c, ix) = new_c(&out.response);
        let claims = open_ix(&f, &c, now);
        assert_eq!(
            (claims.attempt_no, ix["attempt"].as_u64()),
            (2, Some(2)),
            "{code}"
        );
        out
    };
    // 5. A provider not in C.providers.
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let hold = ui_params(claims.ui_seed).required_hold_ms;
    let body = v2_body(
        &a,
        &c,
        ChallengeType::Interactive,
        "turnstile",
        &t_of("hold", hold),
        "/members/a",
        8,
        2,
    );
    check(&body, reason::PROVIDER_NOT_OFFERED);
    // 6. Too fast: the C was issued just now.
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 100);
    check(&hold_body(&a, &c, &claims), reason::TOO_FAST);
    // 7. A C bound to another key; a bound C submitted as v1.
    let (c, claims) = ix_c(&f, &req, Some(&a.thumbprint()), 1, 1, now - 3_000);
    let out = check(&hold_body(&b, &c, &claims), reason::BIND_JKT);
    assert_eq!(
        new_c(&out.response).1["bound"],
        false,
        "the signature was not checked"
    );
    // 8. A signature over something else; a jwk that is not a P-256 key.
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let mut body = hold_body(&a, &c, &claims);
    body["ret"] = json!("/members/b");
    check(&body, reason::SIG);
    let mut body = hold_body(&a, &c, &claims);
    body["jwk"]["ext"] = json!(true);
    check(&body, reason::SIG);
    // 9. PoW v2: the wrong number of counters, unsolved counters. The
    //    signature passed: the new C is bound to the key (no binding renewal).
    let mut body = hold_body(&a, &c, &claims);
    body["pow"]["counters"] = json!([0]);
    let t = body["t"].as_str().unwrap().to_owned();
    let sig = a.sign_submission(&mg_challenge::SubmissionFields {
        c: &c,
        ty: "interactive",
        p: "self_hold",
        pp: "",
        t: &t,
        counters: &[0],
        ret: "/members/a",
        ts: 1_790_000_000_123,
        build: BUILD,
    });
    body["sig"] = json!(sig);
    let out = check(&body, reason::POW);
    let (new, ix) = new_c(&out.response);
    assert_eq!(ix["bound"], true);
    assert!(interactive::jkt_matches(
        &open_ix(&f, &new, now),
        &a.thumbprint()
    ));
    // 11. Hard checks.
    let body = v2_body(
        &a,
        &c,
        ChallengeType::Interactive,
        "self_hold",
        &t_of("hold", hold / 2),
        "/members/a",
        8,
        2,
    );
    check(&body, reason::HOLD_SHORT);
    let mut t: Value = serde_json::from_str(&t_of("hold", hold)).unwrap();
    t["ix"]["trusted"] = json!(0);
    let body = v2_body(
        &a,
        &c,
        ChallengeType::Interactive,
        "self_hold",
        &t.to_string(),
        "/members/a",
        8,
        2,
    );
    check(&body, reason::NO_TRUSTED_INPUT);
    let body = v2_body(
        &a,
        &c,
        ChallengeType::Interactive,
        "pow_a11y",
        &t_of("hold", hold),
        "/members/a",
        12,
        2,
    );
    check(&body, reason::IX_MODE);
    let body = v2_body(
        &a,
        &c,
        ChallengeType::Interactive,
        "self_hold",
        "",
        "/members/a",
        8,
        2,
    );
    check(&body, reason::IX_MODE);
    // After all these failures the original C is still unused (no nonce
    // was consumed before step 12).
    let out = run_json_at(&f, &req, &hold_body(&a, &c, &claims), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    // ...and only once.
    let out = run_json_at(&f, &req, &hold_body(&a, &c, &claims), now);
    assert_eq!(reasons(&out)[0], reason::NONCE_REUSED);
}

/// §7.9: over `mg.a11y.issue` a `pow_a11y` submission is a failure that is
/// not counted, consumes no nonce and attaches a `C` with `a11y_quota`.
#[test]
fn a11y_quota() {
    let mut b = v2_bundle();
    tune_ix(&mut b, |ix| {
        ix.a11y_issue_per_ip = 1;
        ix.a11y_issue_per_ipp = 1;
    });
    let f = fixture(&b);
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let a11y = |c: &str| {
        v2_body(
            &k,
            c,
            ChallengeType::Interactive,
            "pow_a11y",
            "",
            "/members/a",
            12,
            2,
        )
    };
    let (c, _) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    assert_eq!(run_json_at(&f, &req, &a11y(&c), now).response.status, 200);
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let out = run_json_at(&f, &req, &a11y(&c), now);
    assert_eq!(reasons(&out)[0], reason::A11Y_QUOTA);
    assert!(!counts_as_failure(reason::A11Y_QUOTA));
    let (_, ix) = new_c(&out.response);
    assert_eq!(ix["a11y_quota"], true);
    // The nonce is still fresh: the same C passes with self_hold.
    let out = run_json_at(&f, &req, &hold_body(&k, &c, &claims), now);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
}

/// §5.1 / §7.5 step 4a: with interactive challenges unavailable an
/// interactive submission fails (not counted) with a `pow` `C`.
#[test]
fn interactive_unavailable_attaches_a_pow_challenge() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let mut off = v2_bundle();
    tune_ix(&mut off, |ix| ix.enabled = false);
    let f2 = fixture(&off);
    assert!(!f2.bundle.interactive_available);
    let out = run_json_at(&f2, &req, &hold_body(&key("a"), &c, &claims), now);
    assert_eq!(reasons(&out)[0], reason::INTERACTIVE_UNAVAILABLE);
    assert!(!counts_as_failure(reason::INTERACTIVE_UNAVAILABLE));
    let v = body_json(&out.response);
    assert_eq!(v["type"], "pow");
    assert!(v.get("ix").is_none() && v["pow"]["bits"].is_u64());
    let _ = f;
}

/// D-50: with interactive challenges available a failed `pow` submission
/// gets an interactive `C` (attempt 1); beyond `escalate_after` attempts
/// `pow_a11y` comes first.
#[test]
fn failures_escalate_to_interactive() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let (c, bits) = challenge_for(
        &f,
        &req,
        ChallengeType::Pow,
        RiskBand::Low,
        "members",
        "/members/a",
        now,
    );
    let mut body = solved(&c, ChallengeType::Pow, bits, "/members/a", json!({}));
    body["ret"] = json!("/members/b");
    let out = run_json_at(&f, &req, &body, now);
    assert_eq!(reasons(&out)[0], reason::RET);
    let (new, ix) = new_c(&out.response);
    let claims = open_ix(&f, &new, now);
    assert_eq!((claims.attempt_no, claims.risk_band), (1, RiskBand::Medium));
    assert_eq!(ix["providers"], json!(["self_hold", "pow_a11y"]));
    // attempt 3 > escalate_after (2).
    let (c, claims) = ix_c(&f, &req, None, 2, 0, now - 100);
    let out = run_json_at(&f, &req, &hold_body(&key("a"), &c, &claims), now);
    assert_eq!(reasons(&out)[0], reason::TOO_FAST);
    let (_, ix) = new_c(&out.response);
    assert_eq!(ix["attempt"], 3);
    assert_eq!(ix["providers"], json!(["pow_a11y", "self_hold"]));
    assert_eq!(ix["a11y_first"], true);
}

/// D-66 / §6.8: a v2 submission of a `pow` C earns a v2 token with `cnf`
/// in a schema 2 bundle, and a v1 token without the status cookie in a
/// schema 1 bundle.
#[test]
fn v2_submissions_of_pow_challenges() {
    let now = now_ms();
    let k = key("a");
    for (bundle, phase2) in [(v2_bundle(), true), (test_bundle(), false)] {
        let f = fixture(&bundle);
        let req = Req::json();
        let (c, bits) = challenge_for(
            &f,
            &req,
            ChallengeType::Pow,
            RiskBand::Low,
            "members",
            "/members/a",
            now,
        );
        let body = v2_body(&k, &c, ChallengeType::Pow, "", "", "/members/a", bits, 1);
        let out = run_json_at(&f, &req, &body, now);
        assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
        let token = token_claims(&f, &out.response, now / 1000);
        assert_eq!(token.lvl, TokenLevel::Pow);
        let cookies = set_cookies(&out.response);
        if phase2 {
            assert_eq!(token.v, mg_challenge::CLAIMS_V2);
            assert_eq!(token.cnf_jkt(), Some(k.thumbprint().as_str()));
            assert!(cookies[1].starts_with("__Host-mg_st=") && cookies[1].contains(".1;"));
        } else {
            assert_eq!(token.v, mg_challenge::CLAIMS_V1);
            assert!(token.cnf.is_none() && token.lat.is_none());
            assert_eq!(cookies.len(), 1, "no status cookie in schema 1");
        }
    }
    // A pow C bound to a key (D-41) refuses a v1 submission.
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let built = req.built("production");
    let bind = bind_of(&built);
    let jkt = k.thumbprint();
    let c = issue(
        &IssueRequest {
            sealer: &f.sealer,
            host: HOST,
            route_class: "members",
            ty: ChallengeType::Pow,
            band: RiskBand::Low,
            bits: 8,
            ttl_s: 120,
            ret: "/members/a",
            bind: &bind,
            jkt: Some(&jkt),
            now_ms: now,
        },
        &OsRng,
    )
    .unwrap()
    .c;
    let out = run_json_at(
        &f,
        &req,
        &solved(&c, ChallengeType::Pow, 8, "/members/a", json!({})),
        now,
    );
    assert_eq!(reasons(&out)[0], reason::BIND_JKT);
    let out = run_json_at(
        &f,
        &req,
        &v2_body(&k, &c, ChallengeType::Pow, "", "", "/members/a", 8, 1),
        now,
    );
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
}

/// §6.8: the session continues with the same key only, and never under an
/// active near-line session verdict.
#[test]
fn session_carry_over_needs_the_same_key() {
    let f = fixture(&v2_bundle());
    let now = now_ms();
    let (a, b) = (key("a"), key("b"));
    let req = Req::json();
    let (c, claims) = ix_c(&f, &req, None, 1, 0, now - 3_000);
    let out = run_json_at(&f, &req, &hold_body(&a, &c, &claims), now);
    let first = token_claims(&f, &out.response, now / 1000);
    let cookie = set_cookies(&out.response)[0]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let again = Req::json().with("Cookie", &cookie);
    let (c, claims) = ix_c(&f, &again, None, 1, 0, now - 3_000);
    let out = run_json_at(&f, &again, &hold_body(&a, &c, &claims), now);
    assert_eq!(
        token_claims(&f, &out.response, now / 1000).sub,
        first.sub,
        "same key: same session"
    );
    let (c, claims) = ix_c(&f, &again, None, 1, 0, now - 3_000);
    let out = run_json_at(&f, &again, &hold_body(&b, &c, &claims), now);
    assert_ne!(
        token_claims(&f, &out.response, now / 1000).sub,
        first.sub,
        "another key: a new session"
    );
}

// ---------------------------------------------------------------------------
// POST /__mg/c/renew (§7.4)

/// D-41 first binding and D-42 renewals: the renewed `C` keeps type, band,
/// attempt, `ret` and `ui_seed`, gets a new nonce and times, binds the key,
/// and the old `C` is spent: it neither renews nor submits again.
#[test]
fn renewal_binds_and_spends_the_old_challenge() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let (c, old) = ix_c(&f, &req, None, 1, 0, now - 1_000);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!((r.response.status, r.result), (200, "ok"), "{:?}", r.code);
    let v = body_json(&r.response);
    assert_eq!(v["v"], 2);
    let (new, ix) = (v["challenge"].as_str().unwrap(), v["ix"].clone());
    let claims = open_ix(&f, new, now);
    assert_eq!(claims.renew_no, 1);
    assert_eq!(
        (claims.ui_seed, claims.attempt_no, claims.risk_band),
        (old.ui_seed, old.attempt_no, old.risk_band)
    );
    assert_eq!(
        (claims.ret_hash.clone(), claims.pow.clone()),
        (old.ret_hash.clone(), old.pow.clone())
    );
    assert_ne!(claims.nonce, old.nonce);
    assert!(claims.iat_ms >= now && claims.exp_ms - claims.iat_ms == 600_000);
    assert_eq!(
        claims.bind.jkt.as_deref(),
        Some(bind_hash("jkt", &k.thumbprint()).as_slice())
    );
    assert_eq!(
        (ix["bound"].as_bool(), ix["now_ms"].as_i64()),
        (Some(true), Some(claims.iat_ms))
    );
    // The old C is spent.
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!(
        (r.response.status, r.result, r.code),
        (403, "nonce_reused", Some(reason::NONCE_REUSED))
    );
    assert!(
        body_json(&r.response).get("challenge").is_none(),
        "never a second C"
    );
    let out = run_json_at(&f, &req, &hold_body(&k, &c, &old), now + 3_000);
    assert_eq!(reasons(&out)[0], reason::NONCE_REUSED);
    // The renewed C works, signed with the same key only.
    let out = run_json_at(&f, &req, &hold_body(&key("b"), new, &claims), now + 3_000);
    assert_eq!(reasons(&out)[0], reason::BIND_JKT);
    let out = run_json_at(&f, &req, &hold_body(&k, new, &claims), now + 3_000);
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
}

/// §7.4 step 8: a chain ends after 6 renewals, and an expired `C` (at most
/// an hour) renews into a new chain; older than that is `ic.c_expired`
/// without a `C`.
#[test]
fn renewal_cap_and_expiry() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let jkt = k.thumbprint();
    let (c, old) = ix_c(&f, &req, Some(&jkt), 1, 6, now - 1_000);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!((r.result, r.code), ("cap", Some(reason::RENEW_CAP)));
    let claims = open_ix(
        &f,
        body_json(&r.response)["challenge"].as_str().unwrap(),
        now,
    );
    assert_eq!((claims.renew_no, claims.ui_seed), (0, old.ui_seed));
    // Expired (a sleeping tab).
    let (c, old) = ix_c(&f, &req, Some(&jkt), 1, 2, now - 700_000);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!((r.result, r.code), ("expired", Some(reason::C_EXPIRED)));
    let claims = open_ix(
        &f,
        body_json(&r.response)["challenge"].as_str().unwrap(),
        now,
    );
    assert_eq!((claims.renew_no, claims.ui_seed), (0, old.ui_seed));
    assert!(claims.iat_ms >= now);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!(r.result, "nonce_reused", "an expired C renews once too");
    // Expired over an hour ago: reload.
    let (c, _) = ix_c(&f, &req, Some(&jkt), 1, 0, now - 600_000 - 3_600_001);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!((r.response.status, r.result), (403, "expired"));
    assert!(body_json(&r.response).get("challenge").is_none());
}

/// §7.4 steps 3, 5, 6: the body, the bindings and the signature; a bound
/// `C` may change prefix (`rebind`), an unbound one may not.
#[test]
fn renewal_checks() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let other_prefix = {
        let mut r = Req::json();
        r.ip = Some("203.0.113.9".into());
        r
    };
    let now = now_ms();
    let (a, b) = (key("a"), key("b"));
    let (c, _) = ix_c(&f, &req, None, 1, 0, now - 1_000);
    let r = run_renew(&f, &req, &json!({"v": 2, "c": c}), now);
    assert_eq!((r.result, r.code), ("body", Some(reason::BODY)));
    assert!(body_json(&r.response).get("challenge").is_none());
    let mut body = renew_body(&a, &c);
    body["ts"] = json!(5);
    let r = run_renew(&f, &req, &body, now);
    assert_eq!((r.result, r.code), ("sig", Some(reason::SIG)));
    let attempt = |r: &Renewed| {
        open_ix(
            &f,
            body_json(&r.response)["challenge"].as_str().unwrap(),
            now,
        )
        .attempt_no
    };
    assert_eq!(attempt(&r), 2, "an escalated C");
    let r = run_renew(&f, &other_prefix, &renew_body(&a, &c), now);
    assert_eq!((r.result, r.code), ("binding", Some(reason::BIND_IPP)));
    let (bound, _) = ix_c(&f, &req, Some(&a.thumbprint()), 1, 1, now - 1_000);
    let r = run_renew(&f, &req, &renew_body(&b, &bound), now);
    assert_eq!((r.result, r.code), ("binding", Some(reason::BIND_JKT)));
    let r = run_renew(&f, &other_prefix, &renew_body(&a, &bound), now);
    assert_eq!((r.response.status, r.result), (200, "rebind"));
    // The renewed C binds the new prefix.
    let new = body_json(&r.response)["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims = open_ix(&f, &new, now);
    let check = check_challenge_bind(&claims.bind, &bind_of(&other_prefix.built("production")));
    assert_eq!(check.ipp, BindResult::Match);
    // Not JSON.
    let mut form = Req::new(CHROME, "application/x-www-form-urlencoded");
    form.ip = req.ip.clone();
    let r = run_renew(&f, &form, &renew_body(&a, &c), now);
    assert_eq!(r.result, "body");
}

/// §7.4 steps 2 and 4b: `mg.c.renew`, and `mg.ix.issue` except for the
/// first binding.
#[test]
fn renewal_limiters() {
    let mut b = v2_bundle();
    tune_ix(&mut b, |ix| {
        ix.issue_rate = 1;
        ix.issue_period_s = 3600;
        ix.issue_burst = 1;
    });
    let f = fixture(&b);
    let req = Req::json();
    let now = now_ms();
    let k = key("a");
    let jkt = k.thumbprint();
    // First bindings never count against mg.ix.issue.
    for _ in 0..3 {
        let (c, _) = ix_c(&f, &req, None, 1, 0, now - 1_000);
        assert_eq!(run_renew(&f, &req, &renew_body(&k, &c), now).result, "ok");
    }
    let (c, _) = ix_c(&f, &req, Some(&jkt), 1, 1, now - 1_000);
    assert_eq!(run_renew(&f, &req, &renew_body(&k, &c), now).result, "ok");
    let (c, _) = ix_c(&f, &req, Some(&jkt), 1, 1, now - 1_000);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!((r.response.status, r.result), (429, "rate_limited"));
    assert!(header(&r.response, "Retry-After").is_some());
    assert_eq!(header(&r.response, "MG-Error"), Some("mg_rate_limited"));

    let mut b = v2_bundle();
    tune_ix(&mut b, |ix| {
        ix.renew_rate = 1;
        ix.renew_period_s = 3600;
        ix.renew_burst = 1;
    });
    let f = fixture(&b);
    let (c, _) = ix_c(&f, &req, None, 1, 0, now - 1_000);
    assert_eq!(run_renew(&f, &req, &renew_body(&k, &c), now).result, "ok");
    let (c, _) = ix_c(&f, &req, None, 1, 0, now - 1_000);
    assert_eq!(
        run_renew(&f, &req, &renew_body(&k, &c), now).result,
        "rate_limited"
    );
}

/// §7.4 step 4a, step 0, step 7 (D-35: a C from before this process in
/// local mode), and §5.1 for a renewal.
#[test]
fn renewal_unavailable_cases() {
    let now = now_ms();
    let k = key("a");
    let req = Req::json();
    let mut off = v2_bundle();
    tune_ix(&mut off, |ix| ix.enabled = false);
    let on = fixture(&v2_bundle());
    let (c, _) = ix_c(&on, &req, None, 1, 0, now - 1_000);
    let f = fixture(&off);
    let r = run_renew(&f, &req, &renew_body(&k, &c), now);
    assert_eq!(
        (r.result, r.code),
        (
            "interactive_unavailable",
            Some(reason::INTERACTIVE_UNAVAILABLE)
        )
    );
    assert_eq!(body_json(&r.response)["type"], "pow");
    // No client IP.
    let mut anonymous = Req::json();
    anonymous.ip = None;
    let r = run_renew(&on, &anonymous, &renew_body(&k, &c), now);
    assert_eq!((r.response.status, r.result), (429, "no_client_ip"));
    // Early-Data.
    let early = Req::json().with("Early-Data", "1");
    assert_eq!(
        run_renew(&on, &early, &renew_body(&k, &c), now).result,
        "too_early"
    );
    // A C issued before this process started (local mode, D-35): 429.
    let restarted = Fixture::with_state(&v2_bundle(), |cfg| cfg.process_start_ms = now);
    let (old, _) = ix_c(&restarted, &req, None, 1, 0, now - 1_000);
    let r = run_renew(&restarted, &req, &renew_body(&k, &old), now);
    assert_eq!((r.response.status, r.result), (429, "unavailable"));
    assert_eq!(header(&r.response, "Retry-After"), Some("5"));
}

/// The nonce of an interactive `C` lives until the `C` can no longer be
/// opened for a renewal (§7.4: one `C`, one new `C`).
#[test]
fn interactive_nonce_ttl() {
    let f = fixture(&v2_bundle());
    let req = Req::json();
    let now = now_ms();
    let (_, claims) = ix_c(&f, &req, None, 1, 0, now);
    let ttl = crate::renew::interactive_nonce_ttl_ms(&claims, now);
    assert_eq!(ttl, 600_000 + 3_600_000 + 60_000);
    assert_eq!(
        crate::renew::interactive_nonce_ttl_ms(&claims, now + 10_000_000),
        1
    );
}

/// D-41's known boundary: an unbound interactive `C` submitted from another
/// /24 of the same ASN only records `ic.bind_ipp_soft`; a bound one needs
/// its key whatever the prefix.
#[test]
fn unbound_interactive_soft_prefix_mismatch() {
    let f = fixture(&v2_bundle());
    let cfg = f.bundle.interactive.clone().unwrap();
    let req = Req::json();
    let current = bind_of(&req.built("production"));
    let sealed_bind = BindInputs {
        ipp: Some(mg_challenge::ipp("203.0.113.0/24")),
        ipa: mg_challenge::ipa(64500),
        ..current
    };
    let same_asn = BindInputs {
        ipa: mg_challenge::ipa(64500),
        ..current
    };
    let now = now_ms();
    let k = key("a");
    let seal = |jkt: Option<&str>| {
        interactive::seal(
            &interactive::Seal {
                sealer: &f.sealer,
                host: HOST,
                route_class: "members",
                band: RiskBand::Low,
                attempt_no: 1,
                renew_no: u32::from(jkt.is_some()),
                providers: interactive::providers(
                    &cfg,
                    &interactive::Selecting::builtin(HOST, "members", false),
                    1,
                ),
                ui_seed: None,
                pow: interactive::pow_params(&cfg, RiskBand::Low),
                ret_hash: ret_hash("/members/a"),
                bind: &sealed_bind,
                jkt,
                now_ms: now - 3_000,
            },
            &OsRng,
        )
        .unwrap()
    };
    let (c, claims) = seal(None);
    let body = Bytes::from(hold_body(&k, &c, &claims).to_string());
    let out = run_bound(
        &f,
        &req,
        &mut Chunks(vec![body]),
        now,
        &OsRng,
        Some(same_asn),
    );
    assert_eq!(out.response.status, 200, "{:?}", reasons(&out));
    assert_eq!(reasons(&out), ["ic.bind_ipp_soft"]);
    let (c, claims) = seal(Some(&key("b").thumbprint()));
    let body = Bytes::from(hold_body(&k, &c, &claims).to_string());
    let out = run_bound(
        &f,
        &req,
        &mut Chunks(vec![body]),
        now,
        &OsRng,
        Some(same_asn),
    );
    assert_eq!(reasons(&out)[0], reason::BIND_JKT);
}

mod turnstile;
