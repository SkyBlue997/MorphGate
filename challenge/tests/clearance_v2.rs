//! Clearance tokens v2 (Phase 2 spec §6.8, D-46, D-47): the version rule of
//! `mint_v2`, v1 / v2 round trips, the claims rules of `verify` (v1 with
//! `lat` or `cnf`, v2 without `lat`, malformed `cnf`), `mint_refresh` and the
//! fields it copies, the status cookie, `sub` reuse across a key change and
//! `Debug`.

mod common;

use common::{TestRng, bindings, read};
use mg_challenge::{
    CLAIMS_V1, CLAIMS_V2, ClearanceBind, ClearanceClaims, MintParams, MintV2Params,
    STATUS_COOKIE_NAME, TokenError, TokenKeySet, check_clearance_bind, mint, mint_refresh, mint_v2,
    reusable_session, reusable_session_v2, status_cookie_value, status_set_cookie_value, verify,
    verify_ignoring_expiry,
};
use mg_core::{ProviderId, RiskBand, TokenLevel, TokenStatus};
use pasetors::keys::SymmetricKey;
use pasetors::version4::{LocalToken, V4};
use serde_json::{Value, json};

const SITE: &str = "blog";
const ENV: &str = "production";
const NOW: i64 = 1_790_000_000;
const OLD_KID: &str = "blog-t-20260927";
const NEW_KID: &str = "blog-t-20260928";
const JKT: &str = "L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOc";
const JKT_OTHER: &str = "ApFIcH5tuZyflooVd5naGmHD0Skd3zfu7rEJK_OyjkY";

fn keys(allowed: &[&str]) -> TokenKeySet {
    let allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
    TokenKeySet::from_key_file(&read("keys/token.keys.rotated.json"), SITE, &allowed).unwrap()
}

fn base<'a>(lvl: TokenLevel) -> MintParams<'a> {
    MintParams {
        env: ENV,
        session: None,
        lvl,
        now_s: NOW,
        ttl_s: 1800,
        bind: ClearanceBind::from_inputs(&bindings()).unwrap(),
        rb: RiskBand::High,
        replay_unchecked: false,
    }
}

fn v2<'a>(lvl: TokenLevel, cnf_jkt: Option<&'a str>) -> MintV2Params<'a> {
    MintV2Params {
        base: base(lvl),
        cnf_jkt,
        lat: None,
        allow_v2: true,
    }
}

fn mint2(p: &MintV2Params<'_>) -> Result<(String, ClearanceClaims), TokenError> {
    mint_v2(&keys(&[OLD_KID]), SITE, p, &TestRng::new(7))
}

fn verify_old(token: &str, now: i64) -> Result<ClearanceClaims, TokenError> {
    verify(&keys(&[OLD_KID]), SITE, ENV, token, now)
}

/// A token with arbitrary claims under the key of `OLD_KID`, as `mint`
/// encrypts it.
fn forge(claims: &Value) -> String {
    let key: Vec<u8> = (0x20..0x40).collect();
    let key = SymmetricKey::<V4>::from(&key).unwrap();
    let footer = serde_json::to_vec(&json!({ "kid": OLD_KID })).unwrap();
    let implicit = [b"mg-clr-v1".as_slice(), &[0], SITE.as_bytes()].concat();
    LocalToken::encrypt(
        &key,
        &serde_json::to_vec(claims).unwrap(),
        Some(&footer),
        Some(&implicit),
    )
    .unwrap()
}

#[test]
fn v2_round_trip_and_payload() {
    let (token, claims) = mint2(&v2(TokenLevel::Interactive, Some(JKT))).unwrap();
    assert_eq!(claims.v, CLAIMS_V2);
    assert_eq!((claims.lat, claims.cnf_jkt()), (Some(NOW), Some(JKT)));
    assert_eq!(claims.level_at(), NOW);
    assert_eq!(verify_old(&token, NOW), Ok(claims.clone()));
    // The documented member order (§6.8): lat and cnf after exp.
    let text = serde_json::to_string(&claims).unwrap();
    let order: Vec<usize> = [
        "\"v\"", "\"kid\"", "\"sid\"", "\"env\"", "\"sub\"", "\"sst\"", "\"lvl\"", "\"iat\"",
        "\"exp\"", "\"lat\"", "\"cnf\"", "\"bind\"", "\"rb\"", "\"jti\"",
    ]
    .iter()
    .map(|k| text.find(k).unwrap_or_else(|| panic!("{k} in {text}")))
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
    assert!(
        text.contains(&format!(r#""cnf":{{"jkt":"{JKT}"}}"#)),
        "{text}"
    );
    // Every interactive level round-trips.
    for lvl in [
        TokenLevel::InteractiveA11y,
        TokenLevel::InteractiveExt(ProviderId::Turnstile),
    ] {
        let (t, c) = mint2(&v2(lvl, None)).unwrap();
        assert_eq!((c.v, c.cnf.is_none()), (CLAIMS_V2, true));
        assert_eq!(verify_old(&t, NOW).unwrap().lvl, lvl);
    }
}

/// §6.8 "签发哪个版本": v2 with a `cnf`, an interactive level or
/// `lat ≠ iat`; v1 otherwise and whenever the bundle is schema 1.
#[test]
fn version_rule() {
    /// (case, level, cnf_jkt, lat, allow_v2, expected version)
    type Row<'a> = (&'a str, TokenLevel, Option<&'a str>, Option<i64>, bool, u32);
    #[rustfmt::skip]
    let rows: [Row<'_>; 9] = [
        ("pow, unbound",            TokenLevel::Pow,         None,      None,            true,  CLAIMS_V1),
        ("invisible, unbound",      TokenLevel::Invisible,   None,      Some(NOW),       true,  CLAIMS_V1),
        ("pow, bound",              TokenLevel::Pow,         Some(JKT), None,            true,  CLAIMS_V2),
        ("invisible, bound",        TokenLevel::Invisible,   Some(JKT), None,            true,  CLAIMS_V2),
        ("interactive, unbound",    TokenLevel::Interactive, None,      None,            true,  CLAIMS_V2),
        ("pow, earlier lat",        TokenLevel::Pow,         None,      Some(NOW - 60),  true,  CLAIMS_V2),
        ("schema 1, bound",         TokenLevel::Pow,         Some(JKT), None,            false, CLAIMS_V1),
        ("schema 1, interactive",   TokenLevel::Interactive, None,      None,            false, CLAIMS_V1),
        ("schema 1, earlier lat",   TokenLevel::Pow,         None,      Some(NOW - 60),  false, CLAIMS_V1),
    ];
    for (name, lvl, cnf_jkt, lat, allow_v2, want) in rows {
        let mut p = v2(lvl, cnf_jkt);
        p.lat = lat;
        p.allow_v2 = allow_v2;
        // An earlier lat needs a session that started no later.
        let sub = "AAAAAAAAAAAAAAAAAAAAAA";
        if lat.is_some_and(|l| l < NOW) {
            p.base.session = Some((sub, NOW - 3_600));
        }
        let (token, claims) = mint2(&p).unwrap();
        assert_eq!(claims.v, want, "{name}");
        if want == CLAIMS_V1 {
            assert_eq!((claims.lat, claims.cnf.is_none()), (None, true), "{name}");
        } else {
            assert_eq!(claims.lat, Some(lat.unwrap_or(NOW)), "{name}");
            assert_eq!(claims.cnf_jkt(), cnf_jkt, "{name}");
        }
        assert_eq!(verify_old(&token, NOW), Ok(claims), "{name}");
    }
    // `mint` is unchanged: always v1.
    let (_, c) = mint(
        &keys(&[OLD_KID]),
        SITE,
        &base(TokenLevel::Interactive),
        &TestRng::new(1),
    )
    .unwrap();
    assert_eq!((c.v, c.lat, c.cnf.is_none()), (CLAIMS_V1, None, true));
}

#[test]
fn mint_v2_refuses_what_verify_would_reject() {
    for bad in [
        "",
        "short",
        &JKT[..42],
        &format!("{JKT}A"),
        "L4dd7awNurWUQc4fTCqCUVBTgWLzOpDFXjyWVZ9LxOd",
    ] {
        assert_eq!(
            mint2(&v2(TokenLevel::Pow, Some(bad))).unwrap_err(),
            TokenError::Claims,
            "{bad:?}"
        );
    }
    let mut p = v2(TokenLevel::Interactive, None);
    p.lat = Some(NOW + 1);
    assert_eq!(
        mint2(&p).unwrap_err(),
        TokenError::Lifetime,
        "lat after iat"
    );
    p.lat = Some(NOW - 1);
    assert_eq!(
        mint2(&p).unwrap_err(),
        TokenError::Lifetime,
        "lat before sst"
    );
    p.base.session = Some(("AAAAAAAAAAAAAAAAAAAAAA", NOW - 1));
    assert!(mint2(&p).is_ok(), "sst = lat");
}

/// §6.8 "版本" and "校验": the forged variants are `invalid`.
#[test]
fn verify_version_rules() {
    let (_, good) = mint2(&v2(TokenLevel::Interactive, Some(JKT))).unwrap();
    let good = serde_json::to_value(&good).unwrap();
    let (_, v1) = mint(
        &keys(&[OLD_KID]),
        SITE,
        &base(TokenLevel::Pow),
        &TestRng::new(3),
    )
    .unwrap();
    let v1 = serde_json::to_value(&v1).unwrap();
    assert!(verify_old(&forge(&good), NOW).is_ok());
    assert!(verify_old(&forge(&v1), NOW).is_ok());

    type Edit = fn(&mut Value);
    let v1_cases: [(&str, Edit, TokenError); 3] = [
        ("v1 with lat", |c| c["lat"] = json!(NOW), TokenError::Claims),
        (
            "v1 with cnf",
            |c| c["cnf"] = json!({"jkt": JKT}),
            TokenError::Claims,
        ),
        (
            "v1 with null lat",
            |c| c["lat"] = Value::Null,
            TokenError::Claims,
        ),
    ];
    let v2_cases: [(&str, Edit, TokenError); 14] = [
        (
            "v2 without lat",
            |c| drop(c.as_object_mut().unwrap().remove("lat")),
            TokenError::Claims,
        ),
        ("lat null", |c| c["lat"] = Value::Null, TokenError::Claims),
        (
            "lat string",
            |c| c["lat"] = json!("1790000000"),
            TokenError::Claims,
        ),
        ("lat float", |c| c["lat"] = json!(1.5), TokenError::Claims),
        ("cnf null", |c| c["cnf"] = Value::Null, TokenError::Claims),
        ("cnf empty", |c| c["cnf"] = json!({}), TokenError::Claims),
        (
            "cnf extra member",
            |c| c["cnf"]["x"] = json!(1),
            TokenError::Claims,
        ),
        ("cnf array", |c| c["cnf"] = json!([JKT]), TokenError::Claims),
        (
            "cnf jkt 42 chars",
            |c| c["cnf"]["jkt"] = json!(&JKT[..42]),
            TokenError::Claims,
        ),
        (
            "cnf jkt padded",
            |c| c["cnf"]["jkt"] = json!(format!("{JKT}=")),
            TokenError::Claims,
        ),
        ("v 3", |c| c["v"] = json!(3), TokenError::Claims),
        (
            "lat after iat",
            |c| c["lat"] = json!(NOW + 1),
            TokenError::Lifetime,
        ),
        (
            "lat before sst",
            |c| c["lat"] = json!(NOW - 1),
            TokenError::Lifetime,
        ),
        (
            "v 1 with v2 members",
            |c| c["v"] = json!(1),
            TokenError::Claims,
        ),
    ];
    for (base, cases) in [(&v1, &v1_cases[..]), (&good, &v2_cases[..])] {
        for (name, edit, want) in cases {
            let mut c = base.clone();
            edit(&mut c);
            let got = verify_old(&forge(&c), NOW).unwrap_err();
            assert_eq!(got, *want, "{name}");
            assert_eq!(got.status(), TokenStatus::Invalid, "{name}");
        }
    }
    // v2 without cnf and with an earlier lat is fine.
    let mut c = good.clone();
    c.as_object_mut().unwrap().remove("cnf");
    c["sst"] = json!(NOW - 100);
    c["lat"] = json!(NOW - 100);
    let claims = verify_old(&forge(&c), NOW).unwrap();
    assert_eq!((claims.cnf.is_none(), claims.lat), (true, Some(NOW - 100)));
}

/// §6.8 "刷新": copied fields, new `kid`, `jti`, `iat` and `exp`.
#[test]
fn refresh_copies_and_renews() {
    let mut p = v2(TokenLevel::Interactive, Some(JKT));
    p.base.replay_unchecked = false;
    let (_, old) = mint2(&p).unwrap();
    // The key rotated in between: the new token is signed with token_key_ids[0].
    let rotated = keys(&[NEW_KID, OLD_KID]);
    let later = NOW + 1_500;
    let (token, new) =
        mint_refresh(&rotated, SITE, &old, later, 1800, 86_400, &TestRng::new(9)).unwrap();
    assert_eq!(new.v, CLAIMS_V2);
    assert_eq!(new.kid, NEW_KID);
    assert_ne!(new.jti, old.jti);
    assert_eq!((new.iat, new.exp), (later, later + 1800));
    assert_eq!(
        (
            &new.sub, new.sst, new.lat, new.lvl, &new.cnf, new.rb, &new.bind, &new.sid, &new.env,
            new.ruc
        ),
        (
            &old.sub,
            old.sst,
            Some(NOW),
            old.lvl,
            &old.cnf,
            old.rb,
            &old.bind,
            &old.sid,
            &old.env,
            old.ruc
        )
    );
    assert_eq!(verify(&rotated, SITE, ENV, &token, later), Ok(new.clone()));
    // A refresh of the refresh keeps the original lat.
    let (_, again) = mint_refresh(
        &rotated,
        SITE,
        &new,
        later + 1_000,
        1800,
        86_400,
        &TestRng::new(10),
    )
    .unwrap();
    assert_eq!(again.lat, Some(NOW));

    // exp is capped by the session's maximum age.
    let (_, capped) =
        mint_refresh(&rotated, SITE, &old, later, 1800, 1_600, &TestRng::new(11)).unwrap();
    assert_eq!(capped.exp, NOW + 1_600);
    // No 60 s rule here (the Edge applies it): one second left still refreshes.
    let (_, short) =
        mint_refresh(&rotated, SITE, &old, later, 1800, 1_501, &TestRng::new(12)).unwrap();
    assert_eq!(short.exp - later, 1);
    // A session at or past its maximum age, a bad ttl, another site.
    for (now, ttl, max, want) in [
        (later, 1800, 1_500, TokenError::Lifetime),
        (later, 0, 86_400, TokenError::Lifetime),
        (later, 86_401, 86_400, TokenError::Lifetime),
        (NOW - 1, 1800, 86_400, TokenError::Lifetime),
    ] {
        assert_eq!(
            mint_refresh(&rotated, SITE, &old, now, ttl, max, &TestRng::new(13)).unwrap_err(),
            want,
            "{now} {ttl} {max}"
        );
    }
    assert_eq!(
        mint_refresh(
            &rotated,
            "shop",
            &old,
            later,
            1800,
            86_400,
            &TestRng::new(14)
        )
        .unwrap_err(),
        TokenError::Site
    );
    // A v1 token refreshes into v2 with lat = its iat.
    let (_, v1) = mint(
        &keys(&[OLD_KID]),
        SITE,
        &base(TokenLevel::Pow),
        &TestRng::new(15),
    )
    .unwrap();
    let (t, from_v1) =
        mint_refresh(&rotated, SITE, &v1, later, 600, 86_400, &TestRng::new(16)).unwrap();
    assert_eq!(
        (from_v1.v, from_v1.lat, from_v1.cnf.is_none()),
        (CLAIMS_V2, Some(NOW), true)
    );
    assert!(verify(&rotated, SITE, ENV, &t, later).is_ok());
    // An `ruc` token stays marked (refresh_check refuses it before this).
    let mut ruc = v2(TokenLevel::Pow, Some(JKT));
    ruc.base.replay_unchecked = true;
    let (_, ruc_old) = mint2(&ruc).unwrap();
    let (_, ruc_new) = mint_refresh(
        &rotated,
        SITE,
        &ruc_old,
        later,
        600,
        86_400,
        &TestRng::new(17),
    )
    .unwrap();
    assert!(ruc_new.ruc);
}

#[test]
fn status_cookie() {
    assert_eq!(
        status_cookie_value(1_790_000_000, 1_790_001_800, true),
        "1790000000.1790001800.1"
    );
    assert_eq!(status_cookie_value(1, 2, false), "1.2.0");
    let (_, bound) = mint2(&v2(TokenLevel::Interactive, Some(JKT))).unwrap();
    let (_, unbound) = mint2(&v2(TokenLevel::Interactive, None)).unwrap();
    assert_eq!(
        status_set_cookie_value(&bound, 1800),
        format!(
            "{STATUS_COOKIE_NAME}={NOW}.{}.1; Max-Age=1800; Path=/; Secure; SameSite=Lax",
            NOW + 1800
        )
    );
    let v = status_set_cookie_value(&unbound, 60);
    assert!(
        v.starts_with(&format!("__Host-mg_st={NOW}.{}.0;", NOW + 1800)),
        "{v}"
    );
    assert!(!v.contains("HttpOnly") && !v.contains("interactive"), "{v}");
}

/// §6.8 "sub / sst 复用": a changed key starts a new session.
#[test]
fn session_reuse_requires_the_same_key() {
    const MAX: u32 = 86_400;
    let k = keys(&[OLD_KID]);
    let (bound_token, _) = mint2(&v2(TokenLevel::Interactive, Some(JKT))).unwrap();
    let (unbound_token, _) = mint2(&v2(TokenLevel::Interactive, None)).unwrap();
    let later = NOW + 3_600;
    for (token, jkt, reuse) in [
        (&bound_token, Some(JKT), true),
        (&bound_token, Some(JKT_OTHER), false),
        (&bound_token, None, false),
        (&unbound_token, Some(JKT), true),
        (&unbound_token, None, true),
    ] {
        let prev = verify_ignoring_expiry(&k, SITE, ENV, token, later).unwrap();
        let check = check_clearance_bind(&prev, &bindings());
        let got = reusable_session_v2(&prev, &check, later, MAX, jkt);
        assert_eq!(got.is_some(), reuse, "{jkt:?} on {:?}", prev.cnf.is_some());
        if reuse {
            assert_eq!(got, reusable_session(&prev, &check, later, MAX));
        }
    }
    // The Phase 1 rules still apply: an expired session is not carried over.
    let prev = verify_ignoring_expiry(&k, SITE, ENV, &bound_token, later).unwrap();
    let check = check_clearance_bind(&prev, &bindings());
    assert_eq!(
        reusable_session_v2(&prev, &check, NOW + i64::from(MAX) + 1, MAX, Some(JKT)),
        None
    );
}

#[test]
fn debug_hides_the_key_binding() {
    let (token, claims) = mint2(&v2(TokenLevel::Interactive, Some(JKT))).unwrap();
    let p = v2(TokenLevel::Interactive, Some(JKT));
    let dbg = format!("{claims:?} {p:?} {:?}", claims.cnf);
    for secret in [
        JKT,
        claims.sub.as_str(),
        claims.jti.as_str(),
        token.as_str(),
    ] {
        assert!(!dbg.contains(secret), "{secret} in {dbg}");
    }
    assert!(
        dbg.contains("lat: Some(") && dbg.contains("bound: true"),
        "{dbg}"
    );
}
