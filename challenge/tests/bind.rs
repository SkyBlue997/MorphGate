//! Binding comparison truth table and return-path validation (spec §6.4,
//! §6.8).

mod common;

use mg_challenge::{BindInputs, RetError, check_challenge_bind, ipa, ipp, uah, validate_ret};
use mg_core::{BindResult, ChallengeBind};

use BindResult::{Match, Mismatch, SoftMismatch};

const CHROME: fn() -> [u8; 16] = || uah("chrome", 131);
const NET_A: &str = "203.0.113.0/24";
const NET_B: &str = "198.51.100.0/24";

fn sealed(ipp_net: Option<&str>, asn: u32, ctp: Option<[u8; 16]>) -> ChallengeBind {
    ChallengeBind {
        uah: Some(CHROME().to_vec()),
        ipp: ipp_net.map(|n| ipp(n).to_vec()),
        ipa: ipa(asn).map(|h| h.to_vec()),
        ctp: ctp.map(|h| h.to_vec()),
        ..ChallengeBind::default()
    }
}

fn current(ua: [u8; 16], net: Option<&str>, asn: u32, ctp: Option<[u8; 16]>) -> BindInputs {
    BindInputs {
        uah: ua,
        ipp: net.map(ipp),
        ipa: ipa(asn),
        ctp,
    }
}

/// `(name, sealed ASN, current UA, current prefix, current ASN, uah, ipp)`.
type Row = (
    &'static str,
    u32,
    [u8; 16],
    Option<&'static str>,
    u32,
    BindResult,
    BindResult,
);

/// `(uah, ipp)` for a challenge sealed from NET_A in `sealed_asn` and
/// presented as described.
#[test]
fn binding_truth_table() {
    let firefox = uah("firefox", 128);
    #[rustfmt::skip]
    let rows: [Row; 12] = [
        // name,                          sealed ASN, UA,       current net, current ASN, uah, ipp
        ("same everything",               64500, CHROME(), Some(NET_A), 64500, Match,    Match),
        ("same prefix, ASN now unknown",  64500, CHROME(), Some(NET_A), 0,     Match,    Match),
        ("other UA",                      64500, firefox,  Some(NET_A), 64500, Mismatch, Match),
        ("new prefix, same ASN",          64500, CHROME(), Some(NET_B), 64500, Match,    SoftMismatch),
        ("new prefix, other ASN",         64500, CHROME(), Some(NET_B), 64501, Match,    Mismatch),
        ("new prefix, ASN now 0",         64500, CHROME(), Some(NET_B), 0,     Match,    Mismatch),
        ("new prefix, ASN not bound",     0,     CHROME(), Some(NET_B), 64500, Match,    Mismatch),
        ("new prefix, ASN 0 both times",  0,     CHROME(), Some(NET_B), 0,     Match,    Mismatch),
        ("IP now unknown, same ASN",      64500, CHROME(), None,        64500, Match,    SoftMismatch),
        ("IP now unknown, ASN unknown",   64500, CHROME(), None,        0,     Match,    Mismatch),
        ("IP now unknown, ASN not bound", 0,     CHROME(), None,        64500, Match,    Mismatch),
        ("other UA and other ASN",        64500, firefox,  Some(NET_B), 64501, Mismatch, Mismatch),
    ];
    for (name, sealed_asn, ua, net, asn, want_uah, want_ipp) in rows {
        let check = check_challenge_bind(
            &sealed(Some(NET_A), sealed_asn, None),
            &current(ua, net, asn, None),
        );
        assert_eq!((check.uah, check.ipp), (want_uah, want_ipp), "{name}");
        assert_eq!(
            check.hard_failure(),
            want_uah == Mismatch || want_ipp == Mismatch,
            "{name}"
        );
        assert_eq!(check.ctp, None, "{name}: ctp absent on both sides");
    }
}

#[test]
fn ctp_is_recorded_only() {
    let t1 = mg_challenge::ctp("TLSv1.3", "TLS_AES_128_GCM_SHA256", "abc=", 512);
    let t2 = mg_challenge::ctp("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "abc=", 512);
    let run = |s: Option<[u8; 16]>, c: Option<[u8; 16]>| {
        check_challenge_bind(
            &sealed(Some(NET_A), 64500, s),
            &current(CHROME(), Some(NET_A), 64500, c),
        )
    };
    assert_eq!(run(Some(t1), Some(t1)).ctp, Some(Match));
    let changed = run(Some(t1), Some(t2));
    assert_eq!(changed.ctp, Some(Mismatch));
    assert!(!changed.hard_failure(), "ctp never fails a check");
    assert_eq!(run(Some(t1), None).ctp, None);
    assert_eq!(run(None, Some(t1)).ctp, None);
}

#[test]
fn missing_or_malformed_sealed_hashes_fail_closed() {
    let cur = current(CHROME(), Some(NET_A), 64500, None);
    // No ipp sealed: even with a matching ASN this is a hard mismatch.
    let check = check_challenge_bind(&sealed(None, 64500, None), &cur);
    assert_eq!(check.ipp, Mismatch);
    // No uah sealed.
    let mut s = sealed(Some(NET_A), 64500, None);
    s.uah = None;
    assert_eq!(check_challenge_bind(&s, &cur).uah, Mismatch);
    // Wrong lengths never match, even as a prefix.
    let mut s = sealed(Some(NET_A), 64500, None);
    s.uah = Some(CHROME()[..15].to_vec());
    s.ipp = Some([ipp(NET_A).as_slice(), &[0]].concat());
    let check = check_challenge_bind(&s, &cur);
    assert_eq!(check.uah, Mismatch);
    // A malformed sealed ipp counts as missing: hard, even with an equal ASN.
    assert_eq!(check.ipp, Mismatch);
    let mut s = sealed(Some(NET_A), 64500, None);
    s.ipa = Some(vec![]);
    let cur_b = current(CHROME(), Some(NET_B), 64500, None);
    assert_eq!(check_challenge_bind(&s, &cur_b).ipp, Mismatch);
}

#[test]
fn return_paths_accepted() {
    for ok in [
        "/",
        "/account/login",
        "/account/login?next=%2Fcart",
        "/search?q=a+b&x=1",
        "/a/b/c.html",
        "/%E4%B8%AD",
        "/__mgx",
        "/x/__mg/c",
        "/p?/__mg/c",
        "/p?q=//evil.example",
        "/Café",
    ] {
        assert_eq!(validate_ret(ok), Ok(()), "{ok:?}");
    }
    let max = format!("/{}", "a".repeat(511));
    assert_eq!(validate_ret(&max), Ok(()));
}

#[test]
fn return_paths_rejected() {
    let cases: &[(&str, RetError)] = &[
        ("", RetError::NotRooted),
        ("account", RetError::NotRooted),
        ("https://evil.example/", RetError::NotRooted),
        ("?x=1", RetError::NotRooted),
        ("//evil.example", RetError::SchemeRelative),
        ("//__mg/c", RetError::SchemeRelative),
        ("/\\evil.example", RetError::SchemeRelative),
        ("/a\\b", RetError::Backslash),
        ("/a#frag", RetError::Fragment),
        ("/a?b#c", RetError::Fragment),
        ("/a\tb", RetError::ControlChar),
        ("/a\r\nSet-Cookie: x=y", RetError::ControlChar),
        ("/a\u{7f}", RetError::ControlChar),
        ("/a\0", RetError::ControlChar),
        ("/__mg", RetError::Reserved),
        ("/__mg/c", RetError::Reserved),
        ("/__mg/c?x=1", RetError::Reserved),
        ("/%5F%5Fmg/c?x=1", RetError::Reserved),
        ("/%5f%5fmg/c", RetError::Reserved),
        ("/a/../__mg/c", RetError::Reserved),
        ("/./__mg/s/mg.js", RetError::Reserved),
        ("/a/%2e%2e/__mg/c", RetError::Reserved),
    ];
    for (bad, want) in cases {
        assert_eq!(validate_ret(bad), Err(*want), "{bad:?}");
    }
    let long = format!("/{}", "a".repeat(512));
    assert_eq!(validate_ret(&long), Err(RetError::TooLong));
}

#[test]
fn ret_rejections_match_edge_ownership() {
    // Whatever validate_ret accepts is never answered by the Edge itself:
    // the same function decides /__mg ownership (spec §6.4, §10.1).
    for p in ["/__mg", "/__mg/", "/%5F_mg/c", "/a/./../__mg/x"] {
        assert!(mg_core::paths::is_reserved(p), "{p}");
        assert_eq!(validate_ret(p), Err(RetError::Reserved), "{p}");
    }
}
