//! `mg:ev` v2 entries (docs/impl/phase2-spec.md §13.1; WP-C5 tests in §17):
//! `StreamEntry::decision_v2` / `feedback_v2` reproduce every line of
//! `testdata/phase2/samples/mg-ev-v2.txt` field for field and in order, and
//! `path_hash` / `entity_key` give the sample's `ph` / `ipk` / `pfk`.

use std::str::FromStr;

use mg_core::{Action, BotClass, ChallengeType, ProviderId, TokenLevel, VerdictOutcome};
use mg_edge_core::events::{
    ContentClass, DecisionEntry, DecisionEntryV2, FeedbackEntryV2, FeedbackOutcome, IpFamily,
    ProofResult, StreamEntry, path_hash,
};
use mg_edge_core::state::entity_key;

const SAMPLES: &str = include_str!("../../testdata/phase2/samples/mg-ev-v2.txt");

/// `K_pseudo` of `testdata/phase1/kat.json` (bytes 0x00..0x1f).
const K: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// The sample lines as (field, value) lists.
fn samples() -> Vec<Vec<(String, String)>> {
    SAMPLES
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len() % 2, 0, "{line}");
            parts
                .chunks_exact(2)
                .map(|p| (p[0].to_owned(), p[1].to_owned()))
                .collect()
        })
        .collect()
}

fn value<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn opt(v: &str) -> Option<&str> {
    (!v.is_empty()).then_some(v)
}

fn flag(v: &str) -> bool {
    match v {
        "0" => false,
        "1" => true,
        other => panic!("not a flag: {other}"),
    }
}

fn content(v: &str) -> Option<ContentClass> {
    match v {
        "" => None,
        "h" => Some(ContentClass::Html),
        "a" => Some(ContentClass::Asset),
        "j" => Some(ContentClass::Json),
        "o" => Some(ContentClass::Other),
        other => panic!("ct {other}"),
    }
}

fn proof(v: &str) -> ProofResult {
    match v {
        "-" => ProofResult::None,
        "v" => ProofResult::Valid,
        "u" => ProofResult::Unbound,
        "j" => ProofResult::JktMismatch,
        "r" => ProofResult::Replayed,
        "x" => ProofResult::Invalid,
        other => panic!("pf {other}"),
    }
}

fn family(v: &str) -> Option<IpFamily> {
    match v {
        "" => None,
        "4" => Some(IpFamily::V4),
        "6" => Some(IpFamily::V6),
        other => panic!("fam {other}"),
    }
}

fn decision(f: &[(String, String)]) -> StreamEntry {
    let v = |n| value(f, n);
    let base = DecisionEntry {
        site: v("site"),
        ts_ms: v("ts").parse().unwrap(),
        request_id: v("rid"),
        session: opt(v("sess")),
        route: v("route"),
        action: Action::from_str(v("action")).unwrap(),
        dry_run: flag(v("dry")),
        class: BotClass::from_str(v("class")).unwrap(),
        score: v("score").parse().unwrap(),
        ipk: opt(v("ipk")),
        pfk: opt(v("pfk")),
        asn: Some(v("asn").parse().unwrap()).filter(|a| *a != 0),
        status: Some(v("status").parse().unwrap()).filter(|s| *s != 0),
    };
    StreamEntry::decision_v2(&DecisionEntryV2 {
        base,
        method: v("m"),
        path_hash: opt(v("ph")),
        content: content(v("ct")),
        bait: flag(v("bt")),
        cross_site: flag(v("xs")),
        token: flag(v("tk")),
        proof: proof(v("pf")),
        ua_family: opt(v("uf")),
        family: family(v("fam")),
        challenge_type: opt(v("ctype")).map(|t| ChallengeType::from_str(t).unwrap()),
    })
}

fn feedback(f: &[(String, String)]) -> StreamEntry {
    let v = |n| value(f, n);
    let outcome = match v("outcome") {
        "renew_rebind" => FeedbackOutcome::RenewRebind,
        o => FeedbackOutcome::Verdict(VerdictOutcome::from_str(o).unwrap()),
    };
    StreamEntry::feedback_v2(&FeedbackEntryV2 {
        site: v("site"),
        ts_ms: v("ts").parse().unwrap(),
        request_id: v("rid"),
        route: v("route"),
        outcome,
        challenge_type: ChallengeType::from_str(v("type")).unwrap(),
        pfk: opt(v("pfk")),
        asn: Some(v("asn").parse().unwrap()).filter(|a| *a != 0),
        provider: opt(v("p")).map(|p| ProviderId::from_str(p).unwrap()),
        ipk: opt(v("ipk")),
        session: opt(v("sess")),
        level: opt(v("lvl")).map(|l| TokenLevel::from_str(l).unwrap()),
    })
}

/// §13.1: the writer's field order and values equal every sample line.
#[test]
fn entries_match_the_samples_field_for_field() {
    let lines = samples();
    assert!(lines.len() >= 15);
    let (mut decisions, mut feedbacks) = (0, 0);
    for fields in &lines {
        assert_eq!(value(fields, "v"), "2");
        let built = match value(fields, "kind") {
            "decision" => {
                decisions += 1;
                decision(fields)
            }
            "feedback" => {
                feedbacks += 1;
                feedback(fields)
            }
            other => panic!("kind {other}"),
        };
        let got: Vec<(String, String)> = built
            .fields()
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.clone()))
            .collect();
        assert_eq!(&got, fields);
    }
    assert!(decisions >= 11 && feedbacks >= 6);
}

/// The sample's `ph` values are `path_hash` under the KAT `K_pseudo`, and
/// its `ipk` / `pfk` the Phase 1 entity keys (IPv4, and IPv6 /64 and /48).
#[test]
fn path_hash_and_entity_keys_match_the_samples() {
    let paths = [
        "/articles/hello",
        "/api/save",
        "/account/login",
        "/.env",
        "/",
        "/reset",
        "/assets/app.css",
        "/api/item/7",
        "/api/save",
        "/api/save",
        "/api/save",
    ];
    let lines = samples();
    for (fields, p) in lines.iter().zip(paths) {
        assert_eq!(value(fields, "ph"), path_hash(&K, "blog", p), "{p}");
        assert_eq!(value(fields, "ph").len(), 16);
    }
    let v4 = &lines[0];
    assert_eq!(value(v4, "ipk"), entity_key(&K, "ip", "203.0.113.7"));
    assert_eq!(value(v4, "pfk"), entity_key(&K, "prefix", "203.0.113.0/24"));
    let v6 = &lines[2];
    assert_eq!(value(v6, "fam"), "6");
    assert_eq!(
        value(v6, "ipk"),
        entity_key(&K, "ip", "2001:db8:abcd:12::/64")
    );
    assert_eq!(
        value(v6, "pfk"),
        entity_key(&K, "prefix", "2001:db8:abcd::/48")
    );
    // Domain separation: the site is part of the hash.
    assert_ne!(path_hash(&K, "blog", "/"), path_hash(&K, "shop", "/"));
}

fn base() -> DecisionEntry<'static> {
    DecisionEntry {
        site: "blog",
        ts_ms: 1,
        request_id: "r",
        session: None,
        route: "default",
        action: Action::Allow,
        dry_run: false,
        class: BotClass::Unknown,
        score: 0,
        ipk: None,
        pfk: None,
        asn: None,
        status: None,
    }
}

fn v2(base: DecisionEntry<'static>) -> DecisionEntryV2<'static> {
    DecisionEntryV2 {
        base,
        method: "GET",
        path_hash: None,
        content: None,
        bait: false,
        cross_site: false,
        token: false,
        proof: ProofResult::None,
        ua_family: None,
        family: None,
        challenge_type: None,
    }
}

/// Bounds and placeholders of §13.1: `m` and `uf` at most 16 bytes (on a
/// character boundary), `ctype` only for `action = challenge`, the v1 field
/// order unchanged in front.
#[test]
fn bounds_and_placeholders() {
    let mut e = v2(base());
    e.method = "VERYLONGMETHODNAME-0123";
    e.ua_family = Some("ééééééééé");
    e.challenge_type = Some(ChallengeType::Pow);
    let entry = StreamEntry::decision_v2(&e);
    assert_eq!(entry.get("m"), Some("VERYLONGMETHODNA"));
    assert_eq!(entry.get("uf"), Some("éééééééé"));
    assert_eq!(entry.get("ctype"), Some(""), "only for challenges");
    assert_eq!(entry.get("pf"), Some("-"));
    assert_eq!(entry.get("ct"), Some(""));
    assert_eq!(entry.get("fam"), Some(""));
    let names: Vec<&str> = entry.fields().iter().map(|(n, _)| *n).collect();
    let v1: Vec<&str> = StreamEntry::decision(&base())
        .fields()
        .iter()
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(names[..v1.len()], v1[..]);
    assert_eq!(
        names[v1.len()..],
        [
            "m", "ph", "ct", "bt", "xs", "tk", "pf", "uf", "fam", "ctype"
        ]
    );
    let mut challenged = base();
    challenged.action = Action::Challenge;
    let mut e = v2(challenged);
    e.challenge_type = Some(ChallengeType::Interactive);
    assert_eq!(
        StreamEntry::decision_v2(&e).get("ctype"),
        Some("interactive")
    );
    e.challenge_type = Some(ChallengeType::Unspecified);
    assert_eq!(StreamEntry::decision_v2(&e).get("ctype"), Some(""));
}

#[test]
fn content_classes_and_families() {
    for (ct, class) in [
        ("text/html; charset=utf-8", ContentClass::Html),
        ("TEXT/HTML", ContentClass::Html),
        ("text/css", ContentClass::Asset),
        ("application/javascript", ContentClass::Asset),
        ("text/javascript", ContentClass::Asset),
        ("image/webp", ContentClass::Asset),
        ("font/woff2", ContentClass::Asset),
        ("application/json", ContentClass::Json),
        ("application/problem+json", ContentClass::Json),
        ("text/plain", ContentClass::Other),
        ("garbage", ContentClass::Other),
        ("", ContentClass::Other),
    ] {
        assert_eq!(ContentClass::of(Some(ct)), class, "{ct}");
    }
    assert_eq!(ContentClass::of(None), ContentClass::Other);
    assert_eq!(IpFamily::of("203.0.113.7".parse().unwrap()), IpFamily::V4);
    assert_eq!(
        IpFamily::of("::ffff:203.0.113.7".parse().unwrap()),
        IpFamily::V4
    );
    assert_eq!(IpFamily::of("2001:db8::1".parse().unwrap()), IpFamily::V6);
}
