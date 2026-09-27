//! Wire round-trips for the generated types, plus the contract tests that keep
//! `mg-core`'s native types in lock-step with the protobuf contract: enum
//! numbers and names, JSON field names, and the sealed-challenge claims.

use mg_proto::v1;
use prost::Message;
use serde_json::Value;

include!(concat!(env!("OUT_DIR"), "/proto_fields.rs"));

fn decision_event() -> v1::DecisionEvent {
    v1::DecisionEvent {
        ctx: Some(v1::RequestContext {
            request_id: "01J9ZQ".into(),
            ts_ms: 1_758_000_000_123,
            site_id: "blog".into(),
            env: "production".into(),
            route_id: "login".into(),
            channel: v1::Channel::Web as i32,
            upstream: Some(v1::UpstreamInfo {
                profile: v1::UpstreamProfileKind::Cloudflare as i32,
                authenticated: true,
                cf_ray: "8f00000000000000-HKG".into(),
                auth_method: "loopback".into(),
                client_ip_header_missing: false,
            }),
            net: Some(v1::Net {
                ip: "203.0.113.7".into(),
                ip_prefix: "203.0.113.0/24".into(),
                ip_source: "cf_connecting_ip".into(),
                asn: 64500,
                country: "HK".into(),
                upstream_asn: 64500,
                upstream_timezone: "Asia/Hong_Kong".into(),
                rtt_ms: 23,
                ..Default::default()
            }),
            tls: Some(v1::Tls {
                available: false,
                ..Default::default()
            }),
            edge_tls: Some(v1::EdgeTls {
                version: "TLSv1.3".into(),
                ext_sha1: "3zN0vNnT0h1r1TmXnq4B3Ic1S0c=".into(),
                hello_len: 512,
                ..Default::default()
            }),
            http: Some(v1::Http {
                version: "HTTP/2".into(),
                version_source: v1::SignalSource::Cloudflare as i32,
                method: "POST".into(),
                host: "blog.example.com".into(),
                path: "/login".into(),
                query_keys: vec!["next".into()],
                header_names: vec!["accept".into(), "user-agent".into()],
                ..Default::default()
            }),
            identity: Some(v1::Identity {
                token: Some(v1::identity::Token {
                    status: "none".into(),
                    ..Default::default()
                }),
                crawler: Some(v1::identity::Crawler {
                    cf_vbot: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            session_id: String::new(),
            availability_mask: (1 << 1) | (1 << 3) | (1 << 9),
            expected_mask: (1 << 1) | (1 << 3) | (1 << 9) | (1 << 10),
            client: None,
            verdicts: vec![v1::EntityVerdict {
                r#type: v1::EntityType::Asn as i32,
                key: "64500".into(),
                risk: 40,
                site_id: "all".into(),
                ..Default::default()
            }],
        }),
        signals: vec![
            v1::Signal {
                id: "http.missing_accept_language".into(),
                family: v1::SignalFamily::Http as i32,
                value: 0.4,
                confidence: 0.8,
                reason_code: "no_accept_language".into(),
                state: v1::SignalState::Present as i32,
                source: v1::SignalSource::Cloudflare as i32,
                shadow: false,
            },
            v1::Signal {
                id: "tls.ja4_family".into(),
                family: v1::SignalFamily::Tls as i32,
                state: v1::SignalState::Missing as i32,
                ..Default::default()
            },
        ],
        risk: Some(v1::RiskAssessment {
            score: 71,
            confidence: 0.55,
            bot_class: v1::BotClass::AutomationLikely as i32,
            top_reasons: vec!["no_accept_language".into()],
            shadow_score: 74,
            ..Default::default()
        }),
        decision: Some(v1::Decision {
            action: v1::Action::Challenge as i32,
            challenge_type: v1::ChallengeType::Interactive as i32,
            provider_id: "self_hold".into(),
            status: 403,
            ..Default::default()
        }),
        latency_us: 180,
        sample_rate: 1.0,
        edge_id: "edge-a".into(),
        bundle_version: 7,
        monitor_only: true,
    }
}

#[test]
fn decision_event_round_trip() {
    let ev = decision_event();
    let bytes = ev.encode_to_vec();
    let back = v1::DecisionEvent::decode(bytes.as_slice()).expect("decode");
    assert_eq!(back, ev);
    assert_eq!(back.decision.unwrap().action(), v1::Action::Challenge);
    assert_eq!(back.signals[1].state(), v1::SignalState::Missing);
    let ctx = back.ctx.unwrap();
    assert_eq!(
        ctx.upstream.unwrap().profile(),
        v1::UpstreamProfileKind::Cloudflare
    );
    // proto3 `optional`: an explicit false survives and differs from "not forwarded".
    let crawler = ctx.identity.unwrap().crawler.unwrap();
    assert_eq!(crawler.cf_vbot, Some(false));
    let unset = v1::identity::Crawler::default();
    assert_ne!(unset.encode_to_vec(), crawler.encode_to_vec());
}

#[test]
fn challenge_result_round_trip() {
    let r = v1::ChallengeResult {
        request_id: "01J9ZR".into(),
        site_id: "blog".into(),
        route_id: "login".into(),
        r#type: v1::ChallengeType::Interactive as i32,
        provider_id: "turnstile".into(),
        outcome: "pass".into(),
        lvl: "interactive_ext:turnstile".into(),
        attempt_no: 1,
        solve_ms: 2_300,
        risk_band: "high".into(),
        reason_codes: vec!["turnstile_ok".into()],
        cf_ray: "8f00000000000001-HKG".into(),
    };
    let back = v1::ChallengeResult::decode(r.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.r#type(), v1::ChallengeType::Interactive);
}

#[test]
fn signed_bundle_round_trip() {
    let bundle = v1::SiteBundle {
        site_id: "blog".into(),
        version: 7,
        created_at_ms: 1_758_000_000_000,
        upstream: Some(v1::UpstreamProfile {
            kind: v1::UpstreamProfileKind::Cloudflare as i32,
            tunnel_loopback_only: true,
            expected_mask: (1 << 1) | (1 << 3) | (1 << 9),
            ..Default::default()
        }),
        environments: vec![v1::Environment {
            name: "production".into(),
            routes: vec![v1::Route {
                id: "login".into(),
                name: "login".into(),
                hosts: vec!["blog.example.com".into()],
                path_glob: "/login".into(),
                methods: vec!["POST".into()],
                channel: v1::Channel::Web as i32,
                sensitivity: v1::RouteSensitivity::Critical as i32,
                fail_closed: true,
            }],
            rules: vec![v1::CompiledRule {
                id: "r1".into(),
                phase: "bot".into(),
                expr_source: "risk.score >= 85".into(),
                ir_version: 1,
                expr_ir: vec![0x01, 0x02, 0x03],
                action: v1::Action::Block as i32,
                params: [("status".to_string(), "403".to_string())].into(),
                mode: "dry_run".into(),
                rollout_percent: 100,
                ..Default::default()
            }],
            ..Default::default()
        }],
        providers: vec![v1::ProviderConfig {
            id: "turnstile".into(),
            enabled: true,
            denied_countries: vec!["CN".into()],
            fallback: "self_hold".into(),
            mode: "shadow".into(),
            ..Default::default()
        }],
        monitor_only: true,
        not_before_ms: 1_758_000_300_000,
        ..Default::default()
    };
    let signed = v1::SignedBundle {
        bundle: bundle.encode_to_vec(),
        key_id: "cfg-2026-09".into(),
        ed25519_signature: vec![0xAB; 64],
    };

    let wire = signed.encode_to_vec();
    let back = v1::SignedBundle::decode(wire.as_slice()).expect("decode signed");
    assert_eq!(back, signed);
    // The signature covers exactly these bytes, so they must decode back to the bundle.
    let inner = v1::SiteBundle::decode(back.bundle.as_slice()).expect("decode bundle");
    assert_eq!(inner, bundle);
}

#[test]
fn unknown_enum_values_are_tolerated() {
    // Forward compatibility: a newer producer may add enum values.
    let mut ev = decision_event();
    ev.decision.as_mut().unwrap().action = 99;
    ev.signals[0].state = 42;
    let back = v1::DecisionEvent::decode(ev.encode_to_vec().as_slice()).unwrap();
    let decision = back.decision.unwrap();
    assert_eq!(decision.action, 99);
    assert_eq!(
        decision.action(),
        v1::Action::Unspecified,
        "unknown -> default"
    );
    assert_eq!(mg_core::Action::from_proto(99), None);
    assert_eq!(back.signals[0].state(), v1::SignalState::Unspecified);
    assert_eq!(mg_core::SignalState::from_proto(42), None);
}

/// For every number in a generous range, `mg-core` and the generated enum agree on
/// whether it exists and, if so, on its name.
macro_rules! assert_enum_contract {
    ($core:ty, $proto:ty) => {{
        for n in -1..64 {
            let core = <$core>::from_proto(n);
            let proto = <$proto>::try_from(n).ok();
            match (core, proto) {
                (Some(c), Some(p)) => assert_eq!(
                    c.proto_name(),
                    p.as_str_name(),
                    "{} value {n}",
                    stringify!($core)
                ),
                (None, None) => {}
                (c, p) => panic!(
                    "{}: number {n} is {c:?} in mg-core but {p:?} in proto",
                    stringify!($core)
                ),
            }
        }
        for &v in <$core>::ALL {
            assert_eq!(
                <$proto>::from_str_name(&v.proto_name()).map(|p| p as i32),
                Some(v.to_proto())
            );
        }
    }};
}

#[test]
fn core_enums_match_proto_enums() {
    assert_enum_contract!(mg_core::Channel, v1::Channel);
    assert_enum_contract!(mg_core::UpstreamProfileKind, v1::UpstreamProfileKind);
    assert_enum_contract!(mg_core::SignalSource, v1::SignalSource);
    assert_enum_contract!(mg_core::SignalState, v1::SignalState);
    assert_enum_contract!(mg_core::SignalFamily, v1::SignalFamily);
    assert_enum_contract!(mg_core::BotClass, v1::BotClass);
    assert_enum_contract!(mg_core::Action, v1::Action);
    assert_enum_contract!(mg_core::ChallengeType, v1::ChallengeType);
    assert_enum_contract!(mg_core::EntityType, v1::EntityType);
    assert_enum_contract!(mg_core::RouteSensitivity, v1::RouteSensitivity);
}

#[test]
fn family_mask_bits_match_proto_numbers() {
    use mg_core::{FamilyMask, SignalFamily};
    let ev = decision_event();
    let ctx = ev.ctx.unwrap();
    let mask = FamilyMask::from_bits_truncate(ctx.availability_mask);
    assert_eq!(
        mask,
        FamilyMask::of(&[
            SignalFamily::Network,
            SignalFamily::Http,
            SignalFamily::EdgeTls
        ])
    );
    assert_eq!(mask.bits(), ctx.availability_mask);
}

// --- JSON field names: mg-core's event JSON uses exactly the proto field names ---

/// Field names of `message` and, for message-typed fields, their message type.
fn proto_fields(message: &str) -> Vec<(&'static str, &'static str)> {
    let fields: Vec<_> = PROTO_FIELDS
        .iter()
        .filter(|(m, _, _)| *m == message)
        .map(|&(_, f, t)| (f, t))
        .collect();
    assert!(!fields.is_empty(), "no proto message {message}");
    fields
}

/// Checks that every key of `json` (recursively) is a field of `message`. With
/// `complete`, also that every proto field appears, so `json` must come from a
/// fully populated value.
fn assert_json_matches_proto(message: &str, json: &Value, complete: bool, path: &str) {
    let obj = json
        .as_object()
        .unwrap_or_else(|| panic!("{path}: expected an object for {message}, got {json}"));
    let fields = proto_fields(message);
    for (key, value) in obj {
        let Some(&(_, ty)) = fields.iter().find(|(f, _)| f == key) else {
            panic!("{path}.{key}: mg-core JSON field is not a field of proto {message}");
        };
        if ty.is_empty() {
            continue;
        }
        match value {
            Value::Array(items) => {
                assert!(!complete || !items.is_empty(), "{path}.{key}: empty list");
                for (i, item) in items.iter().enumerate() {
                    assert_json_matches_proto(ty, item, complete, &format!("{path}.{key}[{i}]"));
                }
            }
            _ => assert_json_matches_proto(ty, value, complete, &format!("{path}.{key}")),
        }
    }
    if complete {
        for (field, _) in fields {
            assert!(
                obj.contains_key(field),
                "{path}: proto {message}.{field} has no counterpart in the mg-core JSON"
            );
        }
    }
}

/// A `DecisionEvent` with every optional value set, every list non-empty and
/// every flag true, so that its JSON shows every field.
fn full_core_event() -> mg_core::DecisionEvent {
    use mg_core::challenge::ProviderId;
    use mg_core::*;

    let verdict = EntityVerdict {
        entity_type: EntityType::Ip,
        key: "203.0.113.7".into(),
        risk: Score::new(50),
        labels: vec!["scanner".into()],
        reasons: vec!["burst".into()],
        expires_at_ms: 2,
        source: "nearline.scanner".into(),
        version: "1".into(),
        site_id: "blog".into(),
    };
    let ctx = RequestContext {
        request_id: "r".into(),
        ts_ms: 1,
        site_id: "blog".into(),
        env: "production".into(),
        route_id: Some("login".into()),
        channel: Channel::Web,
        upstream: UpstreamInfo {
            profile: UpstreamProfileKind::Cloudflare,
            authenticated: true,
            cf_ray: Some("ray".into()),
            auth_method: UpstreamAuthMethod::Loopback,
            client_ip_header_missing: true,
        },
        net: Net {
            ip: Some("203.0.113.7".parse().unwrap()),
            ip_prefix: Some("203.0.113.0/24".into()),
            ip_source: Some(IpSource::CfConnectingIp),
            asn: Some(64500),
            as_org: Some("Example".into()),
            country: Some("HK".into()),
            conn_type: ConnType::Residential,
            tor: true,
            upstream_asn: Some(64500),
            upstream_country: Some("HK".into()),
            upstream_region: Some("HCW".into()),
            upstream_timezone: Some("Asia/Hong_Kong".into()),
            rtt_ms: Some(20),
        },
        tls: Tls {
            available: true,
            version: Some("TLSv1.3".into()),
            sni: Some("blog.example.com".into()),
            alpn: Some("h2".into()),
            ja4: Some(Ja4 {
                value: "t13d".into(),
                source: SignalSource::SelfComputed,
                authenticated: true,
            }),
        },
        edge_tls: Some(EdgeTls {
            version: Some("TLSv1.3".into()),
            cipher: Some("AEAD-AES128-GCM-SHA256".into()),
            ciphers_sha1: Some("c".into()),
            ext_sha1: Some("e".into()),
            hello_len: Some(512),
        }),
        http: Http {
            version: Some("HTTP/2".into()),
            version_source: SignalSource::Cloudflare,
            method: "POST".into(),
            host: "blog.example.com".into(),
            path: "/login".into(),
            query_keys: vec!["next".into()],
            header_order: vec!["host".into()],
            header_names: vec!["host".into()],
            user_agent: Some("Mozilla/5.0".into()),
            cookie_names: vec!["__Host-mg_clr".into()],
            body_size: Some(42),
            content_type: Some("application/json".into()),
            early_data: true,
            priority: Some("u=0, i".into()),
            accept_encoding_orig: Some("gzip, br, zstd".into()),
        },
        identity: Identity {
            token: Token {
                status: TokenStatus::Valid,
                level: Some(TokenLevel::for_provider(ProviderId::SelfHold)),
                age_s: 60,
                bind: TokenBind {
                    uah: Some(BindResult::Match),
                    ipp: Some(BindResult::Match),
                    jkt: Some(BindResult::Match),
                    ctp: Some(BindResult::Mismatch),
                    tfp: Some(BindResult::Match),
                },
            },
            proof: Proof {
                valid: true,
                replayed: true,
            },
            agent: Agent {
                id: Some("agt_qa".into()),
                grant_id: Some("grt_1".into()),
                method: Some("http_message_signatures".into()),
            },
            crawler: Crawler {
                claimed: true,
                operator: Some("google".into()),
                purpose: Some("search".into()),
                verified: true,
                cf_vbot: Some(true),
                cf_vbot_cat: Some("Search Engine Crawler".into()),
            },
        },
        session_id: Some("s".into()),
        availability_mask: FamilyMask::ALL,
        expected_mask: FamilyMask::ALL,
        client: Some(ClientSignals {
            telemetry_age_s: 3,
            automation_flags: vec!["webdriver".into()],
            env_mismatches: vec!["tz_vs_ip".into()],
            integrity_failed: true,
            upstream_challenges: 1,
            timezone: Some("Asia/Hong_Kong".into()),
        }),
        verdicts: vec![verdict],
    };
    DecisionEvent {
        ctx,
        signals: vec![
            Signal::new("edge_tls.rare_cipher", SignalFamily::EdgeTls, 0.3, 0.5)
                .with_reason("cf_cipher_rare")
                .with_source(SignalSource::Cloudflare)
                .in_shadow(),
        ],
        risk: RiskAssessment {
            score: Score::new(71),
            confidence: Confidence::new(0.5),
            bot_class: BotClass::AutomationLikely,
            labels: vec!["scanner".into()],
            top_reasons: vec!["cf_cipher_rare".into()],
            model_version: "m1".into(),
            ruleset_version: "r1".into(),
            shadow_score: Score::new(74),
        },
        decision: Decision {
            action: Action::Challenge,
            challenge_type: ChallengeType::Interactive,
            provider_id: Some(ProviderId::SelfHold),
            status: Some(403),
            retry_after_s: Some(30),
            rule_id: Some("login-high-risk".into()),
            dry_run: true,
        },
        latency_us: 180,
        sample_rate: 0.5,
        edge_id: "edge-a".into(),
        bundle_version: 7,
        monitor_only: true,
    }
}

#[test]
fn core_event_json_uses_proto_field_names() {
    let full = serde_json::to_value(full_core_event()).unwrap();
    assert_json_matches_proto("morphgate.v1.DecisionEvent", &full, true, "event");

    // Sparse values omit fields, but whatever they emit must still be proto names.
    let sparse = mg_core::DecisionEvent::from_json_line(r#"{"ctx":{"request_id":"r"}}"#).unwrap();
    let sparse = serde_json::to_value(sparse).unwrap();
    assert_json_matches_proto("morphgate.v1.DecisionEvent", &sparse, false, "event");
}

#[test]
fn core_challenge_result_json_uses_proto_field_names() {
    use mg_core::challenge::{ProviderId, VerdictOutcome};
    let r = mg_core::ChallengeResult {
        request_id: "r".into(),
        site_id: "blog".into(),
        route_id: Some("login".into()),
        challenge_type: mg_core::ChallengeType::Interactive,
        provider_id: Some(ProviderId::Turnstile),
        outcome: Some(VerdictOutcome::Fail),
        lvl: Some(mg_core::TokenLevel::for_provider(ProviderId::Turnstile)),
        attempt_no: 2,
        solve_ms: Some(900),
        risk_band: Some(mg_core::RiskBand::Medium),
        reason_codes: vec!["hostname_mismatch".into()],
        cf_ray: Some("ray".into()),
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_json_matches_proto("morphgate.v1.ChallengeResult", &json, true, "result");
}

// --- Sealed challenge claims: the native struct maps 1:1 onto the proto message ---

fn claims_to_proto(c: &mg_core::SealedChallengeClaims) -> v1::SealedChallengeClaims {
    // Exhaustive destructuring and construction: adding a field on either side
    // without mapping it fails to compile.
    let mg_core::SealedChallengeClaims {
        v,
        kid,
        nonce,
        site,
        route_class,
        challenge_type,
        providers,
        risk_band,
        attempt_no,
        iat_ms,
        exp_ms,
        ui_seed,
        pow,
        ret_hash,
        bind,
    } = c;
    let mg_core::ChallengeBind {
        uah,
        ipp,
        jkt,
        ctp,
        tfp,
    } = bind;
    v1::SealedChallengeClaims {
        v: *v,
        kid: kid.clone(),
        nonce: nonce.to_vec(),
        site: site.clone(),
        route_class: route_class.clone(),
        r#type: challenge_type.to_proto(),
        providers: providers.iter().map(|p| p.to_string()).collect(),
        risk_band: risk_band.to_string(),
        attempt_no: *attempt_no,
        iat: *iat_ms,
        exp: *exp_ms,
        ui_seed: *ui_seed,
        pow: pow.as_ref().map(|p| v1::sealed_challenge_claims::Pow {
            alg: p.alg.clone(),
            difficulty: p.difficulty,
        }),
        ret: ret_hash.clone(),
        bind: Some(v1::sealed_challenge_claims::Bind {
            uah: uah.clone(),
            ipp: ipp.clone(),
            jkt: jkt.clone(),
            ctp: ctp.clone(),
            tfp: tfp.clone(),
        }),
    }
}

fn claims_from_proto(p: v1::SealedChallengeClaims) -> Option<mg_core::SealedChallengeClaims> {
    let bind = p.bind.unwrap_or_default();
    Some(mg_core::SealedChallengeClaims {
        v: p.v,
        kid: p.kid,
        nonce: p.nonce.try_into().ok()?,
        site: p.site,
        route_class: p.route_class,
        challenge_type: mg_core::ChallengeType::from_proto(p.r#type)?,
        providers: p
            .providers
            .iter()
            .map(|s| s.parse().ok())
            .collect::<Option<_>>()?,
        risk_band: p.risk_band.parse().ok()?,
        attempt_no: p.attempt_no,
        iat_ms: p.iat,
        exp_ms: p.exp,
        ui_seed: p.ui_seed,
        pow: p.pow.map(|w| mg_core::PowParams {
            alg: w.alg,
            difficulty: w.difficulty,
        }),
        ret_hash: p.ret,
        bind: mg_core::ChallengeBind {
            uah: bind.uah,
            ipp: bind.ipp,
            jkt: bind.jkt,
            ctp: bind.ctp,
            tfp: bind.tfp,
        },
    })
}

#[test]
fn sealed_challenge_claims_round_trip_with_binding_presence() {
    use mg_core::challenge::ProviderId;
    let claims = mg_core::SealedChallengeClaims {
        v: mg_core::SealedChallengeClaims::VERSION,
        kid: "blog-e20360".into(),
        nonce: [0x11; 16],
        site: "blog".into(),
        route_class: "login".into(),
        challenge_type: mg_core::ChallengeType::Interactive,
        providers: vec![
            ProviderId::Turnstile,
            ProviderId::SelfHold,
            ProviderId::PowA11y,
        ],
        risk_band: mg_core::RiskBand::VeryHigh,
        attempt_no: 3,
        iat_ms: 1_790_000_000_000,
        exp_ms: 1_790_000_600_000,
        ui_seed: u64::MAX,
        pow: Some(mg_core::PowParams {
            alg: "sha256".into(),
            difficulty: 20,
        }),
        ret_hash: vec![0xEE; 32],
        bind: mg_core::ChallengeBind {
            uah: Some(vec![1; 32]),
            ipp: None,         // client IP unknown: not bound
            jkt: Some(vec![]), // bound to an (empty) value: must stay distinguishable
            ctp: Some(vec![4; 32]),
            tfp: None,
        },
    };
    assert_eq!(claims.check(1_790_000_000_500), Ok(()));

    let wire = claims_to_proto(&claims).encode_to_vec();
    let decoded = v1::SealedChallengeClaims::decode(wire.as_slice()).unwrap();
    let bind = decoded.bind.clone().unwrap();
    assert_eq!(bind.ipp, None);
    assert_eq!(bind.jkt, Some(vec![]));
    assert_eq!(decoded.providers, ["turnstile", "self_hold", "pow_a11y"]);
    assert_eq!(decoded.r#type(), v1::ChallengeType::Interactive);
    assert_eq!(claims_from_proto(decoded), Some(claims.clone()));

    // A wrong-length nonce never becomes claims.
    let mut bad = claims_to_proto(&claims);
    bad.nonce.pop();
    assert_eq!(claims_from_proto(bad), None);
}

#[test]
fn sealed_challenge_envelope_round_trip() {
    let envelope = v1::SealedChallenge {
        v: 1,
        kid: "blog-e20360".into(),
        xnonce: vec![0x22; 24],
        ct: vec![0x33; 80],
    };
    let back = v1::SealedChallenge::decode(envelope.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back, envelope);
    // The claims and the envelope are distinct messages with fixed field sets.
    assert_eq!(proto_fields("morphgate.v1.SealedChallenge").len(), 4);
    assert_eq!(proto_fields("morphgate.v1.SealedChallengeClaims").len(), 15);
    assert_eq!(
        proto_fields("morphgate.v1.SealedChallengeClaims.Bind").len(),
        5
    );
}
