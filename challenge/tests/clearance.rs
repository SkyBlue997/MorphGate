//! Clearance tokens and cookies (spec §6.5, §6.6, §6.8): mint / verify
//! round trips, per-check failures and their `TokenStatus`, key rotation,
//! RNG failure, the `sub` / `sst` reuse truth table and cookie parsing.
//!
//! Tokens with invalid claims are forged here with pasetors and the test
//! key of `testdata/phase1/keys/token.keys.json` (bytes 0x20..0x3f).

mod common;

use common::{FailAfter, FailingRng, TestRng, bindings, read};
use mg_challenge::{
    BindInputs, COOKIE_NAME, ClearanceBind, ClearanceClaims, MAX_COOKIE_BYTES, MAX_TOKEN_LEN,
    MintParams, TokenError, TokenKeySet, check_clearance_bind, clearance_cookies, ipa, ipp, mint,
    reusable_session, set_cookie_value, uah, verify, verify_ignoring_expiry,
};
use mg_core::{BindResult, RiskBand, TokenLevel, TokenStatus};
use pasetors::keys::SymmetricKey;
use pasetors::version4::{LocalToken, V4};
use serde_json::{Value, json};

const SITE: &str = "blog";
const ENV: &str = "production";
const NOW: i64 = 1_790_000_000;
const OLD_KID: &str = "blog-t-20260927";
const NEW_KID: &str = "blog-t-20260928";

fn keys(allowed: &[&str]) -> TokenKeySet {
    let allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
    TokenKeySet::from_key_file(&read("keys/token.keys.rotated.json"), SITE, &allowed).unwrap()
}

fn params<'a>(bind: &BindInputs) -> MintParams<'a> {
    MintParams {
        env: ENV,
        session: None,
        lvl: TokenLevel::Pow,
        now_s: NOW,
        ttl_s: 1800,
        bind: ClearanceBind::from_inputs(bind).unwrap(),
        rb: RiskBand::Medium,
        replay_unchecked: false,
    }
}

fn mint_default() -> (String, ClearanceClaims) {
    mint(
        &keys(&[OLD_KID]),
        SITE,
        &params(&bindings()),
        &TestRng::new(1),
    )
    .unwrap()
}

/// Edits forged claims.
type Mutation = dyn Fn(&mut Value);

/// A token with arbitrary claims, encrypted like `mint` does (footer kid,
/// implicit assertion of `site`) with the key of `OLD_KID`.
fn forge(claims: &Value, footer_kid: &str, site: &str) -> String {
    let key: Vec<u8> = (0x20..0x40).collect();
    let key = SymmetricKey::<V4>::from(&key).unwrap();
    let footer = serde_json::to_vec(&json!({ "kid": footer_kid })).unwrap();
    let implicit = [b"mg-clr-v1".as_slice(), &[0], site.as_bytes()].concat();
    LocalToken::encrypt(
        &key,
        &serde_json::to_vec(claims).unwrap(),
        Some(&footer),
        Some(&implicit),
    )
    .unwrap()
}

/// The claims `mint` would produce, as JSON, for forging variants.
fn claims_json() -> Value {
    let (_, claims) = mint_default();
    serde_json::to_value(&claims).unwrap()
}

fn verify_old(token: &str, now: i64) -> Result<ClearanceClaims, TokenError> {
    verify(&keys(&[OLD_KID]), SITE, ENV, token, now)
}

#[test]
fn mint_verify_round_trip() {
    let (token, claims) = mint_default();
    assert!(token.starts_with("v4.local.") && token.len() <= MAX_TOKEN_LEN);
    assert_eq!(verify_old(&token, NOW), Ok(claims.clone()));
    assert_eq!(
        (
            claims.v,
            claims.kid.as_str(),
            claims.sid.as_str(),
            claims.env.as_str()
        ),
        (1, OLD_KID, SITE, ENV)
    );
    assert_eq!((claims.iat, claims.exp, claims.sst), (NOW, NOW + 1800, NOW));
    assert_eq!((claims.lvl, claims.rb), (TokenLevel::Pow, RiskBand::Medium));
    for id in [&claims.sub, &claims.jti] {
        assert_eq!(id.len(), 22, "base64url of 16 bytes");
    }
    assert_ne!(claims.sub, claims.jti);

    // The payload is the documented JSON (spec §6.5), keys in order, and
    // the bindings are the kat.json hashes of the example.
    let json = serde_json::to_string(&claims).unwrap();
    let order: Vec<usize> = [
        "\"v\"", "\"kid\"", "\"sid\"", "\"env\"", "\"sub\"", "\"sst\"", "\"lvl\"", "\"iat\"",
        "\"exp\"", "\"bind\"", "\"rb\"", "\"jti\"",
    ]
    .iter()
    .map(|k| json.find(k).unwrap())
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{json}");
    // A checked token has no `ruc` claim (I-30: omitted by default).
    assert!(!claims.ruc);
    assert!(!json.contains("\"ruc\""), "{json}");
    assert!(
        json.contains(
            r#""bind":{"uah":"iXRgjCj6tPt2cFcPqeHr_A","ipp":"JxTqJG6DMjc-DDCAwG3WYw","ipa":"3jB742LLBC_uwzOiZPFFLg"}"#
        ),
        "{json}"
    );
    // The footer names the kid in plaintext.
    let footer = token.rsplit('.').next().unwrap();
    use base64::Engine as _;
    let footer = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(footer)
        .unwrap();
    assert_eq!(footer, br#"{"kid":"blog-t-20260927"}"#);
    // Each level round-trips.
    for lvl in [
        TokenLevel::Invisible,
        TokenLevel::Pow,
        TokenLevel::Interactive,
    ] {
        let mut p = params(&bindings());
        p.lvl = lvl;
        let (t, _) = mint(&keys(&[OLD_KID]), SITE, &p, &TestRng::new(2)).unwrap();
        assert_eq!(verify_old(&t, NOW).unwrap().lvl, lvl);
    }
}

#[test]
fn site_env_expiry_and_tampering() {
    let (token, claims) = mint_default();
    // Another site: the implicit assertion differs, so it does not decrypt.
    let err = verify(&keys(&[OLD_KID]), "shop", ENV, &token, NOW).unwrap_err();
    assert_eq!(err, TokenError::Decrypt);
    assert_eq!(err.status(), TokenStatus::Invalid);
    // Another environment.
    let err = verify(&keys(&[OLD_KID]), SITE, "staging", &token, NOW).unwrap_err();
    assert_eq!(err, TokenError::Env);
    assert_eq!(err.status(), TokenStatus::Invalid);
    // Expiry: valid until exp - 1.
    assert!(verify_old(&token, claims.exp - 1).is_ok());
    let err = verify_old(&token, claims.exp).unwrap_err();
    assert_eq!(err, TokenError::Expired);
    assert_eq!(err.status(), TokenStatus::Expired);
    assert_eq!(
        verify_ignoring_expiry(&keys(&[OLD_KID]), SITE, ENV, &token, claims.exp + 86_400),
        Ok(claims.clone())
    );
    // Any changed character fails; none yields `valid`.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
    for i in 0..token.len() {
        let mut t = token.clone().into_bytes();
        t[i] = *alphabet.iter().find(|&&a| a != t[i]).unwrap();
        let t = String::from_utf8(t).unwrap();
        let err = verify_old(&t, NOW).expect_err(&format!("char {i}"));
        assert_ne!(err.status(), TokenStatus::Valid);
        assert!(verify_old(&token[..i], NOW).is_err(), "prefix {i}");
    }
}

#[test]
fn key_rotation_and_unknown_kids() {
    let (token, _) = mint_default(); // signed with OLD_KID
    // Verify-only (not first) kid still verifies.
    assert!(verify(&keys(&[NEW_KID, OLD_KID]), SITE, ENV, &token, NOW).is_ok());
    // New active kid signs.
    let (new_token, claims) = mint(
        &keys(&[NEW_KID, OLD_KID]),
        SITE,
        &params(&bindings()),
        &TestRng::new(3),
    )
    .unwrap();
    assert_eq!(claims.kid, NEW_KID);
    assert!(verify(&keys(&[NEW_KID]), SITE, ENV, &new_token, NOW).is_ok());
    // A retired kid (no longer in token_key_ids) is `expired`, not `invalid`.
    let err = verify(&keys(&[NEW_KID]), SITE, ENV, &token, NOW).unwrap_err();
    assert_eq!(err, TokenError::UnknownKid);
    assert_eq!(err.status(), TokenStatus::Expired);
    // A kid nobody ever had: also expired.
    let forged = forge(&claims_json(), "blog-t-20990101", SITE);
    let err = verify_old(&forged, NOW).unwrap_err();
    assert_eq!(
        (err, err.status()),
        (TokenError::UnknownKid, TokenStatus::Expired)
    );
    // A known kid in the footer but encrypted with another key: invalid.
    let other_key = forge(&claims_json(), NEW_KID, SITE);
    let err = verify(&keys(&[NEW_KID]), SITE, ENV, &other_key, NOW).unwrap_err();
    assert_eq!(
        (err, err.status()),
        (TokenError::Decrypt, TokenStatus::Invalid)
    );
}

#[test]
fn forged_claims_are_invalid() {
    let base = claims_json();
    let variant = |f: &dyn Fn(&mut Value)| {
        let mut c = base.clone();
        f(&mut c);
        forge(&c, OLD_KID, SITE)
    };
    // Sanity: the unmodified forgery verifies.
    assert!(verify_old(&variant(&|_| {}), NOW).is_ok());

    let cases: [(&str, TokenError, &Mutation); 21] = [
        // sub and jti are base64url of 16 random bytes (§6.5); sub becomes
        // MG-Session, a limiter key and the reused session id.
        ("sub with CRLF", TokenError::Claims, &|c| {
            c["sub"] = json!("x\r\nSet-Cookie: a=b")
        }),
        ("empty sub", TokenError::Claims, &|c| c["sub"] = json!("")),
        ("15-byte sub", TokenError::Claims, &|c| {
            c["sub"] = json!("AAAAAAAAAAAAAAAAAAAA")
        }),
        ("padded jti", TokenError::Claims, &|c| {
            c["jti"] = json!("AAAAAAAAAAAAAAAAAAAAAA==")
        }),
        ("empty jti", TokenError::Claims, &|c| c["jti"] = json!("")),
        ("exp - iat > 86400", TokenError::Lifetime, &|c| {
            c["exp"] = json!(NOW + 86_401)
        }),
        ("exp == iat", TokenError::Lifetime, &|c| {
            c["exp"] = json!(NOW)
        }),
        ("exp before iat", TokenError::Lifetime, &|c| {
            c["exp"] = json!(NOW - 10)
        }),
        ("sst > iat", TokenError::Lifetime, &|c| {
            c["sst"] = json!(NOW + 1)
        }),
        ("iat > now + 5", TokenError::NotYetValid, &|c| {
            c["iat"] = json!(NOW + 6);
            c["sst"] = json!(NOW + 6);
            c["exp"] = json!(NOW + 1806);
        }),
        ("missing bind.ipp", TokenError::Claims, &|c| {
            c["bind"].as_object_mut().unwrap().remove("ipp");
        }),
        ("missing bind.uah", TokenError::Claims, &|c| {
            c["bind"].as_object_mut().unwrap().remove("uah");
        }),
        ("15-byte bind.ipp", TokenError::Claims, &|c| {
            c["bind"]["ipp"] = json!("JxTqJG6DMjc-DDCAwG3W")
        }),
        ("padded bind.uah", TokenError::Claims, &|c| {
            c["bind"]["uah"] = json!("iXRgjCj6tPt2cFcPqeHr_A==")
        }),
        ("malformed bind.ipa", TokenError::Claims, &|c| {
            c["bind"]["ipa"] = json!("!")
        }),
        ("v = 2", TokenError::Claims, &|c| c["v"] = json!(2)),
        ("claims kid != footer kid", TokenError::Claims, &|c| {
            c["kid"] = json!(NEW_KID)
        }),
        ("unknown field", TokenError::Claims, &|c| {
            c["admin"] = json!(true)
        }),
        ("unknown bind field", TokenError::Claims, &|c| {
            c["bind"]["jkt"] = json!("x")
        }),
        ("unknown level", TokenError::Claims, &|c| {
            c["lvl"] = json!("attested")
        }),
        ("other site in claims", TokenError::Site, &|c| {
            c["sid"] = json!("shop")
        }),
    ];
    for (name, want, f) in cases {
        let err = verify_old(&variant(f), NOW).expect_err(name);
        assert_eq!(err, want, "{name}");
        assert_eq!(err.status(), TokenStatus::Invalid, "{name}");
    }
    // iat exactly 5 s ahead is tolerated.
    let skewed = variant(&|c| {
        c["iat"] = json!(NOW + 5);
        c["sst"] = json!(NOW + 5);
        c["exp"] = json!(NOW + 1805);
    });
    assert!(verify_old(&skewed, NOW).is_ok());
    // exp - iat == 86400 is the maximum.
    assert!(verify_old(&variant(&|c| c["exp"] = json!(NOW + 86_400)), NOW).is_ok());
    // An unknown level is only reported after expiry (spec §6.5 order).
    let future_level = variant(&|c| c["lvl"] = json!("attested"));
    assert_eq!(
        verify_old(&future_level, NOW + 1800),
        Err(TokenError::Expired)
    );
    // Extreme times do not overflow.
    let extreme = variant(&|c| {
        c["sst"] = json!(i64::MIN);
        c["iat"] = json!(i64::MIN);
        c["exp"] = json!(i64::MAX);
    });
    assert_eq!(verify_old(&extreme, NOW), Err(TokenError::Lifetime));
    // Not JSON at all.
    let key: Vec<u8> = (0x20..0x40).collect();
    let not_json = LocalToken::encrypt(
        &SymmetricKey::<V4>::from(&key).unwrap(),
        b"not json",
        Some(br#"{"kid":"blog-t-20260927"}"#),
        Some(&[b"mg-clr-v1".as_slice(), &[0], b"blog"].concat()),
    )
    .unwrap();
    assert_eq!(verify_old(&not_json, NOW), Err(TokenError::Claims));
}

/// I-30: a token issued with `ic.replay_unchecked` carries `ruc: true` as
/// its last claim; a checked one omits it. A present `ruc` must be the
/// boolean `true`: `false` (never minted), `null` and other types are
/// invalid claims, like any other unexpected value.
#[test]
fn replay_unchecked_claim() {
    let k = keys(&[OLD_KID]);
    let mut p = params(&bindings());
    p.replay_unchecked = true;
    let (token, claims) = mint(&k, SITE, &p, &TestRng::new(9)).unwrap();
    assert!(claims.ruc);
    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.ends_with(r#","ruc":true}"#), "{json}");
    assert_eq!(verify_old(&token, NOW), Ok(claims.clone()));
    assert!(verify_old(&token, NOW).unwrap().ruc);
    assert!(
        verify_ignoring_expiry(&k, SITE, ENV, &token, NOW + 7200)
            .unwrap()
            .ruc
    );
    assert!(format!("{claims:?} {p:?}").contains("ruc: true"));
    assert!(format!("{p:?}").contains("replay_unchecked: true"));

    let base = claims_json();
    assert!(base.get("ruc").is_none(), "{base}");
    let variant = |ruc: Value| {
        let mut c = base.clone();
        c["ruc"] = ruc;
        forge(&c, OLD_KID, SITE)
    };
    assert!(verify_old(&variant(json!(true)), NOW).unwrap().ruc);
    assert!(!verify_old(&forge(&base, OLD_KID, SITE), NOW).unwrap().ruc);
    for bad in [
        json!(false),
        Value::Null,
        json!("true"),
        json!(1),
        json!([true]),
        json!({}),
    ] {
        let err = verify_old(&variant(bad.clone()), NOW).expect_err(&bad.to_string());
        assert_eq!(
            (err, err.status()),
            (TokenError::Claims, TokenStatus::Invalid),
            "{bad}"
        );
    }
    // A repeated claim is invalid too.
    let key: Vec<u8> = (0x20..0x40).collect();
    let text = serde_json::to_string(&base).unwrap();
    let twice = format!("{},\"ruc\":true,\"ruc\":true}}", &text[..text.len() - 1]);
    let repeated = LocalToken::encrypt(
        &SymmetricKey::<V4>::from(&key).unwrap(),
        twice.as_bytes(),
        Some(br#"{"kid":"blog-t-20260927"}"#),
        Some(&[b"mg-clr-v1".as_slice(), &[0], b"blog"].concat()),
    )
    .unwrap();
    assert_eq!(verify_old(&repeated, NOW), Err(TokenError::Claims));
}

#[test]
fn footer_and_length_checks() {
    let (token, _) = mint_default();
    assert_eq!(
        verify_old(&"v".repeat(MAX_TOKEN_LEN + 1), NOW),
        Err(TokenError::TooLong)
    );
    // No footer.
    let without = token.rsplit_once('.').unwrap().0;
    assert_eq!(verify_old(without, NOW), Err(TokenError::Footer));
    for bad in ["", "v4.local", "v4.public.AAAA.AAAA", "garbage"] {
        assert_eq!(verify_old(bad, NOW), Err(TokenError::Footer), "{bad:?}");
    }
    // Footer with an extra field, or not a JSON object with a string kid.
    let head = without;
    for footer in [
        json!({"kid": OLD_KID, "x": 1}),
        json!({"kid": 1}),
        json!([OLD_KID]),
        json!({}),
    ] {
        use base64::Engine as _;
        let f = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&footer).unwrap());
        assert_eq!(
            verify_old(&format!("{head}.{f}"), NOW),
            Err(TokenError::Footer),
            "{footer}"
        );
    }
    // A footer of more than 128 bytes.
    let long_kid = "k".repeat(130);
    let long = forge(&claims_json(), &long_kid, SITE);
    assert_eq!(verify_old(&long, NOW), Err(TokenError::Footer));
    // Exactly 128 bytes (`{"kid":"` + 118 + `"}`) is a well-formed footer
    // (its kid is simply unknown); 129 bytes is not.
    let at_limit = forge(&claims_json(), &"k".repeat(118), SITE);
    assert_eq!(verify_old(&at_limit, NOW), Err(TokenError::UnknownKid));
    let over = forge(&claims_json(), &"k".repeat(119), SITE);
    assert_eq!(verify_old(&over, NOW), Err(TokenError::Footer));
    // Exactly MAX_TOKEN_LEN characters passes the length check.
    let head = format!("v4.local.{}", "A".repeat(MAX_TOKEN_LEN - 9));
    assert_eq!(head.len(), MAX_TOKEN_LEN);
    assert_eq!(verify_old(&head, NOW), Err(TokenError::Footer));
    assert_eq!(
        verify_old(&format!("{head}A"), NOW),
        Err(TokenError::TooLong)
    );
    // Payload not decodable by pasetors (the footer is fine).
    let bad_payload = format!("v4.local.!!!!.{}", token.rsplit('.').next().unwrap());
    assert_eq!(verify_old(&bad_payload, NOW), Err(TokenError::Decrypt));
}

#[test]
fn mint_parameter_checks_and_rng_failure() {
    let k = keys(&[OLD_KID]);
    let run = |f: &dyn Fn(&mut MintParams<'_>)| {
        let mut p = params(&bindings());
        f(&mut p);
        mint(&k, SITE, &p, &TestRng::new(4)).map(|(_, c)| c)
    };
    assert_eq!(run(&|p| p.ttl_s = 0), Err(TokenError::Lifetime));
    assert_eq!(run(&|p| p.ttl_s = 86_401), Err(TokenError::Lifetime));
    assert_eq!(run(&|p| p.ttl_s = 86_400).unwrap().exp, NOW + 86_400);
    assert_eq!(run(&|p| p.now_s = i64::MAX), Err(TokenError::Lifetime));
    assert_eq!(
        run(&|p| p.bind.ipp = "short".into()),
        Err(TokenError::Claims)
    );
    assert_eq!(
        run(&|p| p.bind.ctp = Some("x".into())),
        Err(TokenError::Claims)
    );
    assert_eq!(
        run(&|p| p.session = Some(("not-an-id", NOW))),
        Err(TokenError::Claims)
    );
    assert_eq!(
        run(&|p| p.session = Some(("AAAAAAAAAAAAAAAAAAAAAA", NOW + 1))),
        Err(TokenError::Lifetime)
    );

    // RNG failures: before sub, before jti, and jti of a reused session.
    let p = params(&bindings());
    assert_eq!(
        mint(&k, SITE, &p, &FailingRng).unwrap_err(),
        TokenError::Rng
    );
    assert_eq!(
        mint(&k, SITE, &p, &FailAfter::new(1)).unwrap_err(),
        TokenError::Rng
    );
    let mut reuse = params(&bindings());
    reuse.session = Some(("AAAAAAAAAAAAAAAAAAAAAA", NOW - 60));
    assert_eq!(
        mint(&k, SITE, &reuse, &FailingRng).unwrap_err(),
        TokenError::Rng
    );
    let (_, c) = mint(&k, SITE, &reuse, &FailAfter::new(1)).unwrap();
    assert_eq!(
        (c.sub.as_str(), c.sst),
        ("AAAAAAAAAAAAAAAAAAAAAA", NOW - 60)
    );

    // A token that would exceed 1024 characters is refused, never issued.
    let long_env = "e".repeat(300);
    let mut p = params(&bindings());
    p.env = &long_env;
    assert!(mint(&k, SITE, &p, &TestRng::new(5)).is_ok());
    let longer_env = "e".repeat(400);
    p.env = &longer_env;
    assert_eq!(
        mint(&k, SITE, &p, &TestRng::new(5)).unwrap_err(),
        TokenError::TooLong
    );
}

/// `(sub, sst)` reuse truth table (spec §6.5, §6.8).
#[test]
fn session_reuse_truth_table() {
    const MAX: u32 = 86_400;
    let k = keys(&[OLD_KID]);
    let (token, first) = mint_default();
    let later = NOW + 3_600; // the token (1800 s) has expired by then
    let prev = verify_ignoring_expiry(&k, SITE, ENV, &token, later).unwrap();
    assert_eq!(
        verify(&k, SITE, ENV, &token, later),
        Err(TokenError::Expired)
    );

    let other_net = BindInputs {
        ipp: Some(ipp("198.51.100.0/24")),
        ..bindings()
    };
    let other_net_other_asn = BindInputs {
        ipp: Some(ipp("198.51.100.0/24")),
        ipa: ipa(64501),
        ..bindings()
    };
    let other_ua = BindInputs {
        uah: uah("firefox", 128),
        ..bindings()
    };
    let asn_zero = BindInputs {
        ipp: Some(ipp("198.51.100.0/24")),
        ipa: ipa(0),
        ..bindings()
    };
    #[rustfmt::skip]
    let rows: [(&str, BindInputs, i64, bool); 8] = [
        ("valid, same request",       bindings(),          NOW + 60,                 true),
        ("expired token",             bindings(),          later,                    true),
        ("uah differs",               other_ua,            later,                    false),
        ("ipp hard failure",          other_net_other_asn, later,                    false),
        ("ipp soft failure",          other_net,           later,                    true),
        ("ASN 0 now: hard",           asn_zero,            later,                    false),
        ("session exactly at max",    bindings(),          NOW + i64::from(MAX),     true),
        ("session beyond max",        bindings(),          NOW + i64::from(MAX) + 1, false),
    ];
    for (name, current, now, reuse) in rows {
        let check = check_clearance_bind(&prev, &current);
        let got = reusable_session(&prev, &check, now, MAX);
        let want = reuse.then(|| (first.sub.clone(), first.sst));
        assert_eq!(got, want, "{name}");
    }
    // Another environment: verify_ignoring_expiry already refuses it.
    assert_eq!(
        verify_ignoring_expiry(&k, SITE, "staging", &token, later),
        Err(TokenError::Env)
    );
    // A session start in the future is not carried over.
    let check = check_clearance_bind(&prev, &bindings());
    assert_eq!(reusable_session(&prev, &check, prev.sst - 1, MAX), None);

    // Minting with the reused session keeps sub and sst, renews the rest.
    let (sub, sst) = reusable_session(&prev, &check, later, MAX).unwrap();
    let mut p = params(&bindings());
    p.session = Some((&sub, sst));
    p.now_s = later;
    let (renewed, claims) = mint(&k, SITE, &p, &TestRng::new(6)).unwrap();
    assert_eq!((claims.sub.as_str(), claims.sst), (first.sub.as_str(), NOW));
    assert_eq!((claims.iat, claims.exp), (later, later + 1800));
    assert_ne!(claims.jti, first.jti);
    assert!(verify(&k, SITE, ENV, &renewed, later).is_ok());
}

#[test]
fn clearance_binding_check() {
    let (token, _) = mint_default();
    let claims = verify_old(&token, NOW).unwrap();
    let check = check_clearance_bind(&claims, &bindings());
    assert_eq!(
        (check.uah, check.ipp, check.ctp, check.hard_failure()),
        (BindResult::Match, BindResult::Match, None, false)
    );
    // Current IP unknown: soft only if the ASN is known and equal.
    let no_ip = BindInputs {
        ipp: None,
        ..bindings()
    };
    assert_eq!(
        check_clearance_bind(&claims, &no_ip).ipp,
        BindResult::SoftMismatch
    );
    let no_ip_no_asn = BindInputs {
        ipp: None,
        ipa: None,
        ..bindings()
    };
    let check = check_clearance_bind(&claims, &no_ip_no_asn);
    assert_eq!(check.ipp, BindResult::Mismatch);
    assert!(check.hard_failure());
    // A token minted without ASN (ASN 0 at issuance) never soft-matches.
    let mut p = params(&BindInputs {
        ipa: ipa(0),
        ..bindings()
    });
    p.lvl = TokenLevel::Invisible;
    let (t, _) = mint(&keys(&[OLD_KID]), SITE, &p, &TestRng::new(7)).unwrap();
    let claims = verify_old(&t, NOW).unwrap();
    assert_eq!(claims.bind.ipa, None);
    let moved = BindInputs {
        ipp: Some(ipp("198.51.100.0/24")),
        ..bindings()
    };
    assert_eq!(
        check_clearance_bind(&claims, &moved).ipp,
        BindResult::Mismatch
    );
    // ctp is compared when both sides have it, and never fails the check.
    let tls = mg_challenge::ctp("TLSv1.3", "TLS_AES_128_GCM_SHA256", "x", 600);
    let p = params(&BindInputs {
        ctp: Some(tls),
        ..bindings()
    });
    let (t, _) = mint(&keys(&[OLD_KID]), SITE, &p, &TestRng::new(8)).unwrap();
    let claims = verify_old(&t, NOW).unwrap();
    let other_tls = BindInputs {
        ctp: Some(mg_challenge::ctp("TLSv1.2", "x", "y", 600)),
        ..bindings()
    };
    let check = check_clearance_bind(&claims, &other_tls);
    assert_eq!(check.ctp, Some(BindResult::Mismatch));
    assert!(!check.hard_failure());
    assert_eq!(check_clearance_bind(&claims, &bindings()).ctp, None);
}

#[test]
fn cookie_candidates() {
    let n = COOKIE_NAME;
    // Several Cookie headers, whitespace, other cookies.
    assert_eq!(
        clearance_cookies(&[
            "a=1; b=2",
            &format!("  {n}=tok1 ;c=3"),
            &format!("{n}=tok2")
        ]),
        ["tok1", "tok2"]
    );
    // Repeated names: at most two candidates, in order.
    let many = format!("{n}=a; {n}=b; {n}=c");
    assert_eq!(clearance_cookies(&[&many]), ["a", "b"]);
    // Exact name only.
    let similar = format!("{n}2=x; x{n}=y; {}=z; {n} =w; {n}", n.to_lowercase());
    assert!(clearance_cookies(&[&similar]).is_empty());
    // The value is everything after the first '='; an empty value is a
    // candidate (and will not verify).
    assert_eq!(clearance_cookies(&[&format!("{n}=a=b")]), ["a=b"]);
    assert_eq!(clearance_cookies(&[&format!("{n}=")]), [""]);
    assert!(clearance_cookies(&[]).is_empty());
    assert!(clearance_cookies(&["", ";;;", " ; "]).is_empty());
}

#[test]
fn cookie_search_stops_at_16_kib() {
    let n = COOKIE_NAME;
    let pair = format!("{n}=tok");
    // Filler so that the pair ends exactly at the limit: found.
    let filler = "f=".to_string() + &"x".repeat(MAX_COOKIE_BYTES - pair.len() - 4) + "; ";
    let at_limit = format!("{filler}{pair}");
    assert_eq!(at_limit.len(), MAX_COOKIE_BYTES);
    assert_eq!(clearance_cookies(&[&at_limit]), ["tok"]);
    // One byte more: the pair is cut by the limit and ignored.
    let over = format!("x{at_limit}");
    assert!(clearance_cookies(&[&over]).is_empty());
    // The limit counts all headers together.
    let first = "x".repeat(MAX_COOKIE_BYTES - 4);
    assert!(clearance_cookies(&[&first, &pair]).is_empty());
    assert_eq!(
        clearance_cookies(&[&"x".repeat(MAX_COOKIE_BYTES - pair.len()), &pair]),
        ["tok"]
    );
    // Later headers are not read at all.
    let full = "y".repeat(MAX_COOKIE_BYTES);
    assert!(clearance_cookies(&[&full, &pair]).is_empty());
    // A multi-byte character straddling the limit does not panic.
    let mut straddle = "é".repeat(MAX_COOKIE_BYTES / 2);
    straddle.insert(0, 'x');
    assert!(clearance_cookies(&[&straddle]).is_empty());
    // A valid token in the second header is found.
    let (token, _) = mint_default();
    let cookie = format!("a=1; {n}={token}");
    assert_eq!(clearance_cookies(&["b=2", &cookie]), [token.as_str()]);
    assert!(verify_old(clearance_cookies(&[&cookie])[0], NOW).is_ok());
}

#[test]
fn set_cookie_header() {
    let (token, claims) = mint_default();
    let v = set_cookie_value(&token, (claims.exp - NOW) as u32);
    assert_eq!(
        v,
        format!("__Host-mg_clr={token}; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax")
    );
    assert_eq!(
        clearance_cookies(&[v.split(';').next().unwrap()]),
        [token.as_str()]
    );
}

#[test]
fn debug_output_hides_session_and_bindings() {
    let (token, claims) = mint_default();
    let p = MintParams {
        session: Some((&claims.sub, claims.sst)),
        ..params(&bindings())
    };
    let dbg = format!("{claims:?} {p:?} {:?}", bindings());
    for secret in [
        claims.sub.as_str(),
        claims.jti.as_str(),
        claims.bind.uah.as_str(),
        claims.bind.ipp.as_str(),
        claims.bind.ipa.as_deref().unwrap(),
        token.as_str(),
    ] {
        assert!(!dbg.contains(secret), "{secret} in {dbg}");
    }
    assert!(
        dbg.contains(OLD_KID) && dbg.contains("reused_session: true"),
        "{dbg}"
    );
    // Errors carry no token material either.
    let err = verify_old(&token[..token.len() - 3], NOW).unwrap_err();
    assert!(!format!("{err:?} {err}").contains("v4.local"));
}
