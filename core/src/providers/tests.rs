//! Tests of the built-in providers and the functions of
//! docs/impl/phase2-spec.md §5 (WP-R4, §17).

use super::*;
use crate::challenge::{
    BindingMac, OutboundError, OutboundRequest, OutboundResponse, UnavailablePolicy,
};
use crate::telemetry::{
    IxFallback, IxHold, IxLocale, IxPage, IxPow, IxPre, IxSingle, KeyStore, PowImpl,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};

// --- helpers --------------------------------------------------------------------

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

struct NoMac;
impl BindingMac for NoMac {
    fn mac(&self, _: &'static str, _: &[&[u8]]) -> [u8; 32] {
        [0; 32]
    }
}

/// An `OutboundHttp` that fails the test if a built-in provider uses it.
struct NoNetwork;
impl OutboundHttp for NoNetwork {
    fn send(&self, _: OutboundRequest) -> BoxFuture<'_, Result<OutboundResponse, OutboundError>> {
        panic!("built-in providers never call out");
    }
}

fn issue_ctx(binder: &dyn BindingMac) -> IssueCtx<'_> {
    IssueCtx {
        site_id: "blog",
        host: "example.com",
        route_class: "login",
        nonce: [7; 16],
        attempt_no: 1,
        iat_ms: 1_790_000_000_000,
        exp_ms: 1_790_000_600_000,
        risk_band: RiskBand::High,
        ui_seed: 42,
        country: Some("CN"),
        binder,
    }
}

fn verify_ctx(binder: &dyn BindingMac) -> VerifyCtx<'_> {
    VerifyCtx {
        site_id: "blog",
        host: "example.com",
        route_class: "login",
        nonce: [7; 16],
        iat_ms: 1_790_000_000_000,
        now_ms: 1_790_000_003_000,
        deadline_ms: 1_790_000_008_000,
        client_ip: None,
        binder,
    }
}

fn submission(provider: ProviderId) -> ProviderSubmission {
    ProviderSubmission {
        provider,
        token: "x".into(),
        fields: BTreeMap::new(),
    }
}

// --- built-in providers ---------------------------------------------------------

/// §17 WP-R4: `prepare` returns an empty spec, `verify` passes without the
/// network; the defaults of D-51 hold.
#[test]
fn builtin_providers() {
    let providers: [(
        &dyn InteractiveChallengeProvider,
        ProviderId,
        InteractionKind,
    ); 2] = [
        (
            &SelfHold::new(),
            ProviderId::SelfHold,
            InteractionKind::PressAndHold,
        ),
        (
            &PowA11y::default(),
            ProviderId::PowA11y,
            InteractionKind::NonInteractive,
        ),
    ];
    for (p, id, kind) in providers {
        assert_eq!(p.id(), id);
        let caps = p.capabilities();
        assert_eq!(caps.interaction_kind, kind);
        assert!(
            !caps.cognitive_test && !caps.drag_required,
            "WCAG 3.3.8 / 2.5.7"
        );
        assert!(!caps.requires_outbound_verify);
        assert!(caps.third_party_origins.is_empty(), "§2.4 item 12");
        assert!(caps.denied_regions.is_empty());
        assert!(caps.is_usable_in(None) && caps.is_usable_in(Some("CN")));
        assert_eq!(caps.unit_cost, None);
        assert_eq!(caps.max_token_age_s, 600);

        let spec = p.prepare(&issue_ctx(&NoMac)).unwrap();
        assert_eq!(spec.provider, id);
        assert!(spec.params.is_empty(), "§7.2: ix is assembled by the Edge");

        let ctx = verify_ctx(&NoMac);
        let v = block_on(p.verify(&ctx, &submission(id), &NoNetwork));
        assert!(v.is_pass(), "{id}");
        assert_eq!(v.binding, BindingChecks::ALL_OK);
        let other = if id == ProviderId::SelfHold {
            ProviderId::PowA11y
        } else {
            ProviderId::SelfHold
        };
        let v = block_on(p.verify(&ctx, &submission(other), &NoNetwork));
        assert_eq!(v.outcome, VerdictOutcome::Fail);
        assert!(!v.is_pass());

        assert_eq!(
            p.on_unavailable("login"),
            UnavailablePolicy::UseProvider(ProviderId::SelfHold)
        );
        assert_eq!(p.health(), crate::challenge::ProviderHealth::Healthy);
    }
    assert_eq!(
        SelfHold::new().capabilities().a11y_alternatives,
        [A11yAlternative::SingleActivation, A11yAlternative::PowA11y],
        "D-65"
    );
    assert_eq!(
        TokenLevel::for_provider(SelfHold::new().id()),
        TokenLevel::Interactive
    );
    assert_eq!(
        TokenLevel::for_provider(PowA11y::new().id()),
        TokenLevel::InteractiveA11y
    );
}

// --- select_providers (§5.4) ------------------------------------------------------

use ProviderId::{PowA11y as A11y, SelfHold as Hold, Turnstile as Ts};

struct Ts_ {
    selection: Selection,
    route_ids: Vec<String>,
    hostnames: Vec<String>,
    denied: Vec<String>,
    usable: bool,
}

impl Ts_ {
    fn first() -> Self {
        Self {
            selection: Selection::First,
            route_ids: Vec::new(),
            hostnames: vec!["example.com".into(), "www.example.com".into()],
            denied: Vec::new(),
            usable: true,
        }
    }
    fn choice(&self) -> TurnstileChoice<'_> {
        TurnstileChoice {
            selection: self.selection,
            route_ids: &self.route_ids,
            hostnames: &self.hostnames,
            denied_countries: &self.denied,
            usable: self.usable,
        }
    }
}

fn sel_input<'a>(ts: Option<&'a Ts_>) -> SelectionInput<'a> {
    SelectionInput {
        country_geo: Some("HK"),
        country_cf: Some("HK"),
        route_id: "login",
        redact_path: false,
        host: "example.com",
        attempt_no: 1,
        escalate_after: 2,
        a11y_pref: false,
        turnstile: ts.map(Ts_::choice),
    }
}

#[test]
fn selection_without_turnstile() {
    let base = sel_input(None);
    assert_eq!(select_providers(&base), [Hold, A11y]);
    assert!(!turnstile_eligible(&base));
    // attempt_no > N puts pow_a11y first; at N it does not.
    for (attempt, want) in [
        (1, [Hold, A11y]),
        (2, [Hold, A11y]),
        (3, [A11y, Hold]),
        (9, [A11y, Hold]),
    ] {
        let i = SelectionInput {
            attempt_no: attempt,
            ..base
        };
        assert_eq!(select_providers(&i), want, "attempt {attempt}");
    }
    let pref = SelectionInput {
        a11y_pref: true,
        ..base
    };
    assert_eq!(select_providers(&pref), [A11y, Hold]);
}

#[test]
fn selection_with_turnstile() {
    let first = Ts_::first();
    let base = sel_input(Some(&first));
    assert_eq!(select_providers(&base), [Ts, Hold, A11y]);
    let escalated = SelectionInput {
        attempt_no: 3,
        ..base
    };
    assert_eq!(select_providers(&escalated), [Ts, A11y, Hold]);
    let pref = SelectionInput {
        a11y_pref: true,
        ..base
    };
    assert_eq!(select_providers(&pref), [A11y, Ts, Hold]);
    let pref_escalated = SelectionInput {
        a11y_pref: true,
        attempt_no: 3,
        ..base
    };
    assert_eq!(select_providers(&pref_escalated), [A11y, Ts, Hold]);

    // escalate_after_fail: only once attempt_no > N.
    let esc = Ts_ {
        selection: Selection::EscalateAfterFail,
        ..Ts_::first()
    };
    for (attempt, want) in [
        (1, vec![Hold, A11y]),
        (2, vec![Hold, A11y]),
        (3, vec![Ts, A11y, Hold]),
    ] {
        let i = SelectionInput {
            attempt_no: attempt,
            ..sel_input(Some(&esc))
        };
        assert_eq!(select_providers(&i), want, "attempt {attempt}");
        assert!(turnstile_eligible(&i), "eligibility ignores the selection");
    }
}

/// §5.4 rule 2: every condition that keeps Turnstile out.
#[test]
fn turnstile_eligibility_rules() {
    let check = |ts: &Ts_, edit: &dyn Fn(&mut SelectionInput<'_>), want: bool, what: &str| {
        let mut i = sel_input(Some(ts));
        edit(&mut i);
        assert_eq!(turnstile_eligible(&i), want, "{what}");
        let list = select_providers(&i);
        assert_eq!(list.contains(&Ts), want, "{what}");
        assert!(
            list.contains(&Hold) && list.contains(&A11y),
            "{what}: built-ins always"
        );
        assert_eq!(list.len(), if want { 3 } else { 2 }, "{what}");
    };
    let first = Ts_::first();
    check(&first, &|_| {}, true, "baseline");
    check(
        &Ts_ {
            usable: false,
            ..Ts_::first()
        },
        &|_| {},
        false,
        "not usable",
    );
    check(&first, &|i| i.turnstile = None, false, "not configured");
    check(&first, &|i| i.redact_path = true, false, "redact_path");
    // Hosts: exact, case-insensitive; no suffix match.
    check(&first, &|i| i.host = "WWW.Example.COM", true, "host case");
    check(
        &first,
        &|i| i.host = "shop.example.com",
        false,
        "other host",
    );
    check(
        &first,
        &|i| i.host = "example.com.evil.test",
        false,
        "suffix",
    );
    check(
        &Ts_ {
            hostnames: vec![],
            ..Ts_::first()
        },
        &|_| {},
        false,
        "no hostnames",
    );
    // Routes.
    let routes = Ts_ {
        route_ids: vec!["signup".into(), "login".into()],
        ..Ts_::first()
    };
    check(&routes, &|_| {}, true, "listed route");
    check(
        &routes,
        &|i| i.route_id = "checkout",
        false,
        "unlisted route",
    );
    check(
        &routes,
        &|i| i.route_id = "Login",
        false,
        "route ids are exact",
    );
}

/// §5.4 rule 2, countries (D-70): every combination of the two sources.
#[test]
fn turnstile_country_rules() {
    let open = Ts_::first();
    let deny_cn = Ts_ {
        denied: vec!["CN".into()],
        ..Ts_::first()
    };
    let cases: [(Option<&str>, Option<&str>, bool, bool); 10] = [
        // (geo, cf, open, deny CN)
        (Some("HK"), Some("HK"), true, true),
        (Some("CN"), Some("CN"), true, false),
        (Some("cn"), None, true, false),
        (None, Some("CN"), true, false),
        // Sources disagree: either one denies.
        (Some("HK"), Some("CN"), true, false),
        (Some("CN"), Some("HK"), true, false),
        // One source known and allowed.
        (Some("JP"), None, true, true),
        (None, Some("JP"), true, true),
        // Unknown: offered only while nothing is denied.
        (None, None, true, false),
        (Some(""), None, true, false),
    ];
    for (geo, cf, want_open, want_deny) in cases {
        for (ts, want) in [(&open, want_open), (&deny_cn, want_deny)] {
            let i = SelectionInput {
                country_geo: geo,
                country_cf: cf,
                ..sel_input(Some(ts))
            };
            assert_eq!(
                turnstile_eligible(&i),
                want,
                "geo {geo:?} cf {cf:?} denied {:?}",
                ts.denied
            );
        }
    }
}

// --- min_elapsed_ms and the hard checks (§5.5, §7.7) --------------------------------

#[test]
fn min_elapsed_boundaries() {
    assert_eq!(min_elapsed_ms(IxMode::Hold, 1_834, 0, 2_000), 2_084);
    assert_eq!(min_elapsed_ms(IxMode::Single, 1_834, 300, 2_000), 2_384);
    assert_eq!(min_elapsed_ms(IxMode::PowOnly, 1_834, 300, 2_000), 2_000);
    assert_eq!(min_elapsed_ms(IxMode::PowOnly, 1_834, 300, 0), 0);
    assert_eq!(min_elapsed_ms(IxMode::External, 1_834, 300, 2_000), 0);
    assert_eq!(
        min_elapsed_ms(IxMode::Hold, u32::MAX, 5_000, 0),
        u32::MAX,
        "saturates"
    );
    // The 250 ms window: an elapsed time of exactly the minimum passes.
    let min = min_elapsed_ms(IxMode::Hold, 1_200, 0, 0);
    assert_eq!(min, 1_450);
    assert!(1_450 >= min && 1_449 < min);
    // §7.2: ix.min_ms = hold_ms + min_pow_ms + 250, the same number.
    assert_eq!(
        min_elapsed_ms(IxMode::Single, 2_500, 5_000, 0),
        2_500 + 5_000 + 250
    );
}

fn tel(mode: IxMode, modality: InputModality) -> IxTelemetry {
    IxTelemetry {
        v: 1,
        mode,
        modality,
        locale: IxLocale::ZhCn,
        ks: KeyStore::Idb,
        sv: "0.3.0".into(),
        fallback: None,
        trusted: 3,
        act_ms: 2_300,
        pre: None,
        hold: None,
        single: None,
        page: None,
        pow: None,
    }
}

/// A natural mouse hold: no feature fires.
fn mouse_hold(ms: u32) -> IxTelemetry {
    IxTelemetry {
        pre: Some(IxPre {
            moves: 5,
            path_px: 9,
            straight: 7,
            speed_mean: 6,
            speed_sd: 4,
            dir_changes: 3,
            render_to_input_ms: 11,
            to_target_ms: 9,
        }),
        hold: Some(IxHold {
            ms,
            offset: [1, -2],
            jitter_px: 2,
            moves: 3,
            cancels: 0,
            pressure: 5,
            pressure_var: false,
            contact_var: false,
        }),
        page: Some(IxPage {
            vis: 0,
            vis_during: 0,
            focus: 0,
            frame_mean: 4,
            frame_sd: 1,
        }),
        pow: Some(IxPow {
            ms: 13,
            worker: true,
            pow_impl: PowImpl::Js,
        }),
        ..tel(IxMode::Hold, InputModality::Mouse)
    }
}

fn single(wait_ms: u32) -> IxTelemetry {
    IxTelemetry {
        single: Some(IxSingle { wait_ms }),
        ..tel(IxMode::Single, InputModality::Keyboard)
    }
}

fn input<'a>(provider: ProviderId, t: Option<&'a IxTelemetry>) -> InteractionInput<'a> {
    InteractionInput {
        provider,
        telemetry: t,
        required_hold_ms: 2_000,
        elapsed_ms: 2_500,
        pow_bits: 16,
        pow_k: 8,
        risk_band: RiskBand::Low,
        mode: ScoringMode::Shadow,
    }
}

fn hard(provider: ProviderId, t: Option<&IxTelemetry>) -> Option<&'static str> {
    assess_interaction(&input(provider, t)).hard_failure
}

#[test]
fn hard_check_ix_mode() {
    use IxMode::*;
    let fits = [
        (Hold, ProviderId::SelfHold),
        (Single, ProviderId::SelfHold),
        (PowOnly, ProviderId::PowA11y),
        (External, ProviderId::Turnstile),
    ];
    for mode in IxMode::ALL {
        for provider in [
            ProviderId::SelfHold,
            ProviderId::PowA11y,
            ProviderId::Turnstile,
            ProviderId::Tencent,
        ] {
            let t = match mode {
                Hold => mouse_hold(2_000),
                Single => single(2_000),
                m => tel(*m, InputModality::None),
            };
            let got = hard(provider, Some(&t));
            if fits.contains(&(*mode, provider)) {
                assert_eq!(got, None, "{mode} {provider}");
            } else {
                assert_eq!(got, Some(reason::IX_MODE), "{mode} {provider}");
            }
        }
    }
    // Only pow_a11y may come without ix.
    assert_eq!(hard(ProviderId::PowA11y, None), None);
    assert_eq!(hard(ProviderId::SelfHold, None), Some(reason::IX_MODE));
    assert_eq!(hard(ProviderId::Turnstile, None), Some(reason::IX_MODE));
}

#[test]
fn hard_check_trusted() {
    for t in [mouse_hold(2_000), single(2_000)] {
        for (trusted, want) in [(0, Some(reason::NO_TRUSTED_INPUT)), (1, None), (3, None)] {
            let t = IxTelemetry {
                trusted,
                ..t.clone()
            };
            assert_eq!(
                hard(ProviderId::SelfHold, Some(&t)),
                want,
                "{} {trusted}",
                t.mode
            );
        }
    }
    // Not checked for pow_only / external.
    let t = IxTelemetry {
        trusted: 0,
        ..tel(IxMode::PowOnly, InputModality::None)
    };
    assert_eq!(hard(ProviderId::PowA11y, Some(&t)), None);
}

/// `0.95 × required_hold_ms <= hold.ms <= 30000` (required 2000: 1900).
#[test]
fn hard_check_hold_bounds() {
    for (ms, want) in [
        (0, Some(reason::HOLD_SHORT)),
        (1_890, Some(reason::HOLD_SHORT)),
        (1_900, None),
        (2_000, None),
        (30_000, None),
        (30_010, Some(reason::HOLD_LONG)),
        (60_000, Some(reason::HOLD_LONG)),
    ] {
        assert_eq!(
            hard(ProviderId::SelfHold, Some(&mouse_hold(ms))),
            want,
            "{ms}"
        );
    }
    // An odd required time: 95 % of 1201 is 1140.95, so 1140 is short and 1150 passes.
    for (ms, want) in [(1_140, Some(reason::HOLD_SHORT)), (1_150, None)] {
        let t = mouse_hold(ms);
        let i = InteractionInput {
            required_hold_ms: 1_201,
            ..input(ProviderId::SelfHold, Some(&t))
        };
        assert_eq!(assess_interaction(&i).hard_failure, want, "{ms}");
    }
    // Hold mode without its hold object fails closed.
    let t = IxTelemetry {
        hold: None,
        ..mouse_hold(2_000)
    };
    assert_eq!(
        hard(ProviderId::SelfHold, Some(&t)),
        Some(reason::HOLD_SHORT)
    );
}

/// `single.wait_ms >= 0.95 × required_hold_ms`; no upper bound.
#[test]
fn hard_check_single_bounds() {
    for (ms, want) in [
        (0, Some(reason::HOLD_SHORT)),
        (1_890, Some(reason::HOLD_SHORT)),
        (1_900, None),
        (60_000, None),
    ] {
        assert_eq!(hard(ProviderId::SelfHold, Some(&single(ms))), want, "{ms}");
    }
    let t = IxTelemetry {
        single: None,
        ..single(2_000)
    };
    assert_eq!(
        hard(ProviderId::SelfHold, Some(&t)),
        Some(reason::HOLD_SHORT)
    );
}

#[test]
fn hard_check_never_reports_too_fast() {
    let t = mouse_hold(2_000);
    let a = assess_interaction(&InteractionInput {
        elapsed_ms: 0,
        ..input(ProviderId::SelfHold, Some(&t))
    });
    assert_eq!(a.hard_failure, None, "the time window is min_elapsed_ms's");
    assert_eq!(a.outcome, IxOutcome::Pass);
}

// --- soft features (§7.8) ----------------------------------------------------------

fn feats(provider: ProviderId, t: &IxTelemetry) -> Vec<&'static str> {
    assess_interaction(&input(provider, Some(t)))
        .features
        .into_keys()
        .collect()
}

#[test]
fn natural_inputs_score_zero() {
    let t = mouse_hold(2_000);
    let a = assess_interaction(&input(ProviderId::SelfHold, Some(&t)));
    assert!(a.features.is_empty(), "{:?}", a.features);
    assert_eq!(a.score, 0.0);
    assert_eq!(a.a11y_mode, A11yMode::None);
    assert_eq!(a.input_modality, InputModality::Mouse);
}

/// A scripted mouse hold: every pointer feature fires.
fn robotic(modality: InputModality) -> IxTelemetry {
    let mut t = mouse_hold(2_000);
    t.modality = modality;
    t.trusted = 2;
    let pre = t.pre.as_mut().unwrap();
    pre.moves = 0;
    pre.straight = 9;
    pre.path_px = 10;
    pre.to_target_ms = 7;
    let hold = t.hold.as_mut().unwrap();
    hold.jitter_px = 0;
    hold.moves = 0;
    t
}

#[test]
fn pointer_features_by_modality() {
    assert_eq!(
        feats(ProviderId::SelfHold, &robotic(InputModality::Mouse)),
        [
            "fast_target",
            "no_pre_move",
            "straight_long",
            "untrusted",
            "zero_jitter"
        ]
    );
    // straight_long is mouse only.
    assert_eq!(
        feats(ProviderId::SelfHold, &robotic(InputModality::Pen)),
        ["fast_target", "no_pre_move", "untrusted", "zero_jitter"]
    );
    // Touch has no hover and screen-reader / switch touches are still:
    // neither fast_target nor zero_jitter (nor any other pointer feature).
    let mut touch = robotic(InputModality::Touch);
    assert_eq!(feats(ProviderId::SelfHold, &touch), ["untrusted"]);
    touch.hold.as_mut().unwrap().pressure_var = true;
    assert_eq!(
        feats(ProviderId::SelfHold, &touch),
        ["touch_natural", "untrusted"]
    );
    touch.trusted = 3;
    let a = assess_interaction(&input(ProviderId::SelfHold, Some(&touch)));
    assert_eq!(
        a.features.keys().copied().collect::<Vec<_>>(),
        ["touch_natural"]
    );
    assert_eq!(a.score, 0.0, "a negative sum is clamped to 0");
    touch.hold.as_mut().unwrap().pressure_var = false;
    touch.hold.as_mut().unwrap().contact_var = true;
    assert_eq!(feats(ProviderId::SelfHold, &touch), ["touch_natural"]);
    // Keyboard / mixed holds get no pointer features.
    for m in [
        InputModality::Keyboard,
        InputModality::Mixed,
        InputModality::None,
    ] {
        assert_eq!(
            feats(ProviderId::SelfHold, &robotic(m)),
            ["untrusted"],
            "{m}"
        );
    }
}

#[test]
fn pointer_feature_thresholds() {
    let base = mouse_hold(2_000);
    let with = |f: &dyn Fn(&mut IxTelemetry)| {
        let mut t = base.clone();
        f(&mut t);
        feats(ProviderId::SelfHold, &t)
    };
    assert_eq!(
        with(&|t| t.pre.as_mut().unwrap().to_target_ms = 8),
        Vec::<&str>::new()
    );
    assert_eq!(
        with(&|t| t.pre.as_mut().unwrap().to_target_ms = 7),
        ["fast_target"]
    );
    assert_eq!(
        with(&|t| {
            let p = t.pre.as_mut().unwrap();
            p.straight = 9;
            p.path_px = 9;
        }),
        Vec::<&str>::new(),
        "< 512 px"
    );
    assert_eq!(
        with(&|t| {
            let p = t.pre.as_mut().unwrap();
            p.straight = 8;
            p.path_px = 12;
        }),
        Vec::<&str>::new(),
        "< 0.9 straight"
    );
    // zero_jitter needs a hold of at least 1 s with no movement at all.
    let still = |ms: u32, jitter: u8, moves: u8| {
        with(&|t| {
            let h = t.hold.as_mut().unwrap();
            h.ms = ms;
            h.jitter_px = jitter;
            h.moves = moves;
        })
    };
    assert_eq!(still(1_000, 0, 0), ["zero_jitter"]);
    assert_eq!(still(990, 0, 0), Vec::<&str>::new());
    assert_eq!(still(2_000, 1, 0), Vec::<&str>::new());
    assert_eq!(still(2_000, 0, 1), Vec::<&str>::new());
    // Missing pointer data is neutral.
    assert_eq!(with(&|t| t.pre = None), Vec::<&str>::new());
}

/// `single` and `pow_only` never get pointer features; choosing an
/// accessible path never scores by itself.
#[test]
fn accessible_paths_get_no_pointer_features() {
    // Pointer data that would fire everything in hold mode.
    let r = robotic(InputModality::Mouse);
    let s = IxTelemetry {
        mode: IxMode::Single,
        single: Some(IxSingle { wait_ms: 2_000 }),
        trusted: 3,
        ..r.clone()
    };
    let a = assess_interaction(&input(ProviderId::SelfHold, Some(&s)));
    assert!(a.features.is_empty(), "{:?}", a.features);
    assert_eq!(a.a11y_mode, A11yMode::Single);
    let s = IxTelemetry { trusted: 2, ..s };
    assert_eq!(feats(ProviderId::SelfHold, &s), ["untrusted"]);

    let p = IxTelemetry {
        mode: IxMode::PowOnly,
        trusted: 0,
        ..r
    };
    let a = assess_interaction(&input(ProviderId::PowA11y, Some(&p)));
    assert!(
        a.features.is_empty(),
        "untrusted is not counted in pow_only: {:?}",
        a.features
    );
    assert_eq!(a.a11y_mode, A11yMode::PowOnly);
    assert_eq!(a.outcome, IxOutcome::Pass);
    // Without ix at all.
    let a = assess_interaction(&input(ProviderId::PowA11y, None));
    assert_eq!(
        (a.a11y_mode, a.input_modality),
        (A11yMode::PowOnly, InputModality::None)
    );
    assert_eq!((a.score, a.hard_failure), (0.0, None));
}

#[test]
fn hidden_uses_vis_during_only() {
    for mode in [
        IxMode::Hold,
        IxMode::Single,
        IxMode::PowOnly,
        IxMode::External,
    ] {
        let mut t = match mode {
            IxMode::Hold => mouse_hold(2_000),
            IxMode::Single => single(2_000),
            m => tel(m, InputModality::None),
        };
        t.page = Some(IxPage {
            vis: 31,
            vis_during: 0,
            focus: 31,
            frame_mean: 0,
            frame_sd: 0,
        });
        let provider = match mode {
            IxMode::Hold | IxMode::Single => ProviderId::SelfHold,
            IxMode::PowOnly => ProviderId::PowA11y,
            IxMode::External => ProviderId::Turnstile,
        };
        assert_eq!(feats(provider, &t), Vec::<&str>::new(), "{mode}: vis alone");
        t.page.as_mut().unwrap().vis_during = 1;
        assert_eq!(feats(provider, &t), ["hidden"], "{mode}");
    }
}

/// `pow_too_fast`: k = 8, 16 bits → 8 · 65536 / 4000 ≈ 131 ms expected; more
/// than 10× faster means below ~13 ms for every value of the bucket.
#[test]
fn pow_too_fast_and_fallback() {
    let with_pow = |bucket: u8, provider: ProviderId, mut t: IxTelemetry| {
        t.pow = Some(IxPow {
            ms: bucket,
            worker: true,
            pow_impl: PowImpl::Wasm,
        });
        feats(provider, &t)
    };
    // Bucket 3: < 8 ms; 8 · 10 · 4000 = 320000 <= 524288 → fires.
    assert_eq!(
        with_pow(3, ProviderId::SelfHold, mouse_hold(2_000)),
        ["pow_too_fast"]
    );
    // Bucket 4: < 16 ms might be 15 ms, not 10× faster → neutral.
    assert_eq!(
        with_pow(4, ProviderId::SelfHold, mouse_hold(2_000)),
        Vec::<&str>::new()
    );
    assert_eq!(
        with_pow(
            0,
            ProviderId::PowA11y,
            tel(IxMode::PowOnly, InputModality::None)
        ),
        ["pow_too_fast"]
    );
    assert_eq!(
        with_pow(
            31,
            ProviderId::PowA11y,
            tel(IxMode::PowOnly, InputModality::None)
        ),
        Vec::<&str>::new()
    );
    // Uses the submitted provider's difficulty: 24 bits → ~33.5 s expected.
    let t = IxTelemetry {
        pow: Some(IxPow {
            ms: 10,
            worker: true,
            pow_impl: PowImpl::Js,
        }),
        ..tel(IxMode::PowOnly, InputModality::None)
    };
    let a = assess_interaction(&InteractionInput {
        pow_bits: 24,
        ..input(ProviderId::PowA11y, Some(&t))
    });
    assert!(a.features.contains_key("pow_too_fast"));
    // Extreme parameters do not overflow.
    let a = assess_interaction(&InteractionInput {
        pow_bits: u32::MAX,
        pow_k: u32::MAX,
        ..input(ProviderId::PowA11y, Some(&t))
    });
    assert!(a.features.contains_key("pow_too_fast"));

    let t = IxTelemetry {
        fallback: Some(IxFallback::TsLoadTimeout),
        ..mouse_hold(2_000)
    };
    assert_eq!(feats(ProviderId::SelfHold, &t), ["ts_fallback"]);
}

#[test]
fn prior_and_score_sum() {
    let t = robotic(InputModality::Mouse);
    for (band, prior) in [
        (RiskBand::Low, 0.0),
        (RiskBand::Medium, 0.05),
        (RiskBand::High, 0.10),
        (RiskBand::VeryHigh, 0.15),
    ] {
        let a = assess_interaction(&InteractionInput {
            risk_band: band,
            ..input(ProviderId::SelfHold, Some(&t))
        });
        assert_eq!(
            a.features.get("prior").copied().unwrap_or(0.0),
            prior,
            "{band}"
        );
        assert!(
            (a.score - (0.8 + prior)).abs() < 1e-6,
            "{band}: {}",
            a.score
        );
    }
    let t = IxTelemetry {
        trusted: 2,
        ..single(2_000)
    };
    let a = assess_interaction(&InteractionInput {
        risk_band: RiskBand::High,
        ..input(ProviderId::SelfHold, Some(&t))
    });
    assert!((a.score - 0.30).abs() < 1e-6, "{}", a.score);
    // Every feature key is one of the §7.8 table.
    let keys: Vec<_> = FEATURE_WEIGHTS.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), 9);
    for k in a.features.keys() {
        assert!(keys.contains(k) || *k == "prior", "{k}");
    }
}

// --- shadow and enforce (§5.5, §7.8) --------------------------------------------------

#[test]
fn shadow_never_changes_the_outcome() {
    let mut t = robotic(InputModality::Mouse);
    t.page = Some(IxPage {
        vis_during: 2,
        ..IxPage::default()
    });
    t.fallback = Some(IxFallback::TsError);
    t.pow.as_mut().unwrap().ms = 0;
    let a = assess_interaction(&input(ProviderId::SelfHold, Some(&t)));
    assert_eq!(a.features.len(), 8);
    assert_eq!(a.score, 1.0, "1.15, clamped");
    assert_eq!(
        a.outcome,
        IxOutcome::Pass,
        "shadow: the score is only recorded"
    );
    let t = mouse_hold(100);
    let a = assess_interaction(&input(ProviderId::SelfHold, Some(&t)));
    assert_eq!(a.outcome, IxOutcome::Retry, "hard checks still apply");
}

#[test]
fn enforce_thresholds() {
    let enforce = ScoringMode::Enforce {
        t_pass: 0.3,
        t_block: 0.6,
    };
    // untrusted (0.2) + prior: low 0, medium 0.05, high 0.10, very_high 0.15
    // plus hidden (0.1) where set.
    let score_of = |band: RiskBand, hidden: bool| {
        let mut t = IxTelemetry {
            trusted: 2,
            ..single(2_000)
        };
        if hidden {
            t.page = Some(IxPage {
                vis_during: 1,
                ..IxPage::default()
            });
        }
        assess_interaction(&InteractionInput {
            risk_band: band,
            mode: enforce,
            ..input(ProviderId::SelfHold, Some(&t))
        })
    };
    let a = score_of(RiskBand::Medium, false);
    assert!((a.score - 0.25).abs() < 1e-6);
    assert_eq!(a.outcome, IxOutcome::Pass);
    let a = score_of(RiskBand::Medium, true);
    assert!((a.score - 0.35).abs() < 1e-6);
    assert_eq!(a.outcome, IxOutcome::Retry, "t_pass <= score < t_block");
    let robotic = robotic(InputModality::Mouse);
    let a = assess_interaction(&InteractionInput {
        mode: enforce,
        ..input(ProviderId::SelfHold, Some(&robotic))
    });
    assert_eq!(a.outcome, IxOutcome::Block);
    // A hard failure is Retry even with a low score.
    let t = mouse_hold(100);
    let a = assess_interaction(&InteractionInput {
        mode: enforce,
        ..input(ProviderId::SelfHold, Some(&t))
    });
    assert_eq!(
        (a.hard_failure, a.outcome),
        (Some(reason::HOLD_SHORT), IxOutcome::Retry)
    );
    assert_eq!(enforce.eval_mode(), EvalMode::Enforce);
    assert_eq!(ScoringMode::Shadow.eval_mode(), EvalMode::Shadow);
}

#[test]
fn exact_threshold_boundaries() {
    // A score of exactly 0.2 (untrusted, low band).
    let t = IxTelemetry {
        trusted: 2,
        ..single(2_000)
    };
    let run = |t_pass: f32, t_block: f32| {
        assess_interaction(&InteractionInput {
            mode: ScoringMode::Enforce { t_pass, t_block },
            ..input(ProviderId::SelfHold, Some(&t))
        })
        .outcome
    };
    assert_eq!(run(0.21, 0.5), IxOutcome::Pass);
    assert_eq!(run(0.2, 0.5), IxOutcome::Retry, "score == t_pass");
    assert_eq!(run(0.1, 0.21), IxOutcome::Retry);
    assert_eq!(run(0.1, 0.2), IxOutcome::Block, "score == t_block");
}

#[test]
fn summary_for_the_event() {
    let t = IxTelemetry {
        trusted: 2,
        ..mouse_hold(1_910)
    };
    let i = InteractionInput {
        required_hold_ms: 1_834,
        elapsed_ms: 2_610,
        risk_band: RiskBand::Medium,
        ..input(ProviderId::SelfHold, Some(&t))
    };
    let s = assess_interaction(&i).summary(&i);
    assert_eq!(s.mode, EvalMode::Shadow);
    assert_eq!(
        (s.hold_ms, s.required_hold_ms, s.elapsed_ms, s.act_ms),
        (1_910, 1_834, 2_610, 2_300)
    );
    assert_eq!(s.input_modality, InputModality::Mouse);
    assert_eq!(s.a11y_mode, A11yMode::None);
    assert_eq!(
        s.features.keys().map(String::as_str).collect::<Vec<_>>(),
        ["prior", "untrusted"]
    );
    assert!((s.score - 0.25).abs() < 1e-6);
    // single: hold_ms is the wait time.
    let t = single(2_050);
    let i = input(ProviderId::SelfHold, Some(&t));
    assert_eq!(assess_interaction(&i).summary(&i).hold_ms, 2_050);
    let i = input(ProviderId::PowA11y, None);
    let s = assess_interaction(&i).summary(&i);
    assert_eq!(
        (s.hold_ms, s.act_ms, s.a11y_mode),
        (0, 0, A11yMode::PowOnly)
    );
}

// --- next_challenge_after_failure (§5.3) -------------------------------------------------

#[test]
fn escalation_table() {
    use ChallengeType::*;
    use RiskBand::*;
    for band in RiskBand::ALL {
        let up = band.after_failure();
        assert_eq!(
            next_challenge_after_failure(Invisible, *band, 0, true),
            (Interactive, up, 1)
        );
        assert_eq!(
            next_challenge_after_failure(Pow, *band, 0, true),
            (Interactive, up, 1)
        );
        assert_eq!(
            next_challenge_after_failure(Invisible, *band, 0, false),
            (Pow, up, 0),
            "D-27"
        );
        assert_eq!(
            next_challenge_after_failure(Pow, *band, 0, false),
            (Pow, up, 0)
        );
        assert_eq!(
            next_challenge_after_failure(Interactive, *band, 1, true),
            (Interactive, up, 2)
        );
        assert_eq!(
            next_challenge_after_failure(Interactive, *band, 4, true),
            (Interactive, up, 5)
        );
        assert_eq!(
            next_challenge_after_failure(Interactive, *band, 3, false),
            (Pow, up, 0),
            "§5.1"
        );
    }
    assert_eq!(
        next_challenge_after_failure(Interactive, Low, 1, true).1,
        Medium
    );
    assert_eq!(
        next_challenge_after_failure(Interactive, VeryHigh, 1, true).1,
        VeryHigh
    );
    assert_eq!(
        next_challenge_after_failure(Interactive, High, u32::MAX, true).2,
        u32::MAX,
        "saturates"
    );
    assert_eq!(
        next_challenge_after_failure(Interactive, High, 0, true).2,
        1
    );
}

// --- refresh_check (§5.7) ---------------------------------------------------------------

fn matched() -> TokenBind {
    TokenBind {
        uah: Some(BindResult::Match),
        ipp: Some(BindResult::Match),
        ..TokenBind::default()
    }
}

fn refresh(
    edit: impl FnOnce(&mut RefreshInput<'_>),
    decision: &Decision,
) -> Result<(), RefreshDenied> {
    let mut i = RefreshInput {
        level: TokenLevel::Interactive,
        ruc: false,
        bound: true,
        bind: matched(),
        level_age_s: 3_600,
        refresh_max_s: 14_400,
        decision,
    };
    edit(&mut i);
    refresh_check(&i)
}

#[test]
fn refresh_branches() {
    let allow = Decision::allow();
    assert_eq!(refresh(|_| {}, &allow), Ok(()));
    let tag = Decision {
        action: Action::Tag,
        ..Decision::default()
    };
    assert_eq!(refresh(|_| {}, &tag), Ok(()));
    assert_eq!(
        refresh(|i| i.refresh_max_s = 0, &allow),
        Err(RefreshDenied::NotRefreshable)
    );
    assert_eq!(refresh(|i| i.ruc = true, &allow), Err(RefreshDenied::Ruc));
    assert_eq!(
        refresh(|i| i.bound = false, &allow),
        Err(RefreshDenied::NotBound)
    );
    for (uah, ipp) in [
        (Some(BindResult::Mismatch), Some(BindResult::Match)),
        (Some(BindResult::Match), Some(BindResult::SoftMismatch)),
        (Some(BindResult::Match), Some(BindResult::Mismatch)),
        (None, Some(BindResult::Match)),
        (Some(BindResult::Match), None),
    ] {
        assert_eq!(
            refresh(
                |i| i.bind = TokenBind {
                    uah,
                    ipp,
                    ..TokenBind::default()
                },
                &allow
            ),
            Err(RefreshDenied::Binding),
            "{uah:?} {ipp:?}"
        );
    }
    assert_eq!(
        refresh(|i| i.level_age_s = 14_400, &allow),
        Ok(()),
        "boundary"
    );
    assert_eq!(
        refresh(|i| i.level_age_s = 14_401, &allow),
        Err(RefreshDenied::TooOld)
    );
    let block = Decision {
        action: Action::Block,
        status: Some(403),
        ..Decision::default()
    };
    let limited = Decision {
        action: Action::RateLimit,
        status: Some(429),
        retry_after_s: Some(5),
        ..Decision::default()
    };
    assert_eq!(refresh(|_| {}, &block), Err(RefreshDenied::Blocked));
    assert_eq!(refresh(|_| {}, &limited), Err(RefreshDenied::Blocked));
    // D-20 comparison: a challenge at or below the level does not stop a refresh.
    for t in [
        ChallengeType::Invisible,
        ChallengeType::Pow,
        ChallengeType::Interactive,
    ] {
        assert_eq!(refresh(|_| {}, &Decision::challenge(t)), Ok(()), "{t}");
    }
    let pow = |i: &mut RefreshInput<'_>| i.level = TokenLevel::Pow;
    assert_eq!(
        refresh(pow, &Decision::challenge(ChallengeType::Pow)),
        Ok(())
    );
    assert_eq!(
        refresh(pow, &Decision::challenge(ChallengeType::Interactive)),
        Err(RefreshDenied::ChallengeRequired(ChallengeType::Interactive))
    );
    // The first matching rule wins.
    assert_eq!(
        refresh(
            |i| {
                i.ruc = true;
                i.bound = false;
                i.level_age_s = u64::MAX;
            },
            &block
        ),
        Err(RefreshDenied::Ruc)
    );
    let labels: Vec<_> = [
        RefreshDenied::NotRefreshable,
        RefreshDenied::Ruc,
        RefreshDenied::NotBound,
        RefreshDenied::Binding,
        RefreshDenied::TooOld,
        RefreshDenied::ChallengeRequired(ChallengeType::Pow),
        RefreshDenied::Blocked,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        labels,
        [
            "not_refreshable",
            "ruc",
            "not_bound",
            "binding",
            "too_old",
            "challenge",
            "blocked"
        ],
        "§9.3 metric labels"
    );
}

#[test]
fn refresh_limits_per_level() {
    let l = RefreshLimits {
        interactive_s: 14_400,
        interactive_ext_s: 7_200,
        pow_s: 3_600,
    };
    assert_eq!(l.max_for(TokenLevel::Interactive), 14_400);
    assert_eq!(
        l.max_for(TokenLevel::InteractiveExt(ProviderId::Turnstile)),
        7_200
    );
    assert_eq!(l.max_for(TokenLevel::Pow), 3_600);
    assert_eq!(l.max_for(TokenLevel::InteractiveA11y), 0, "D-47: never");
    assert_eq!(l.max_for(TokenLevel::Invisible), 0, "D-47: never");
    let allow = Decision::allow();
    for level in [TokenLevel::InteractiveA11y, TokenLevel::Invisible] {
        assert_eq!(
            refresh(
                |i| {
                    i.level = level;
                    i.refresh_max_s = l.max_for(level);
                },
                &allow
            ),
            Err(RefreshDenied::NotRefreshable),
            "{level}"
        );
    }
    let no_pow = RefreshLimits { pow_s: 0, ..l };
    assert_eq!(
        refresh(
            |i| {
                i.level = TokenLevel::Pow;
                i.refresh_max_s = no_pow.max_for(TokenLevel::Pow);
            },
            &allow
        ),
        Err(RefreshDenied::NotRefreshable)
    );
}

/// Seeded random inputs never panic and keep the invariants (built-ins always
/// offered, score in 0..=1, outcome consistent with the hard checks).
#[test]
fn random_inputs_keep_invariants() {
    let mut s: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let countries = [
        None,
        Some(""),
        Some("CN"),
        Some("HK"),
        Some("cn"),
        Some("XX"),
    ];
    let hosts = ["example.com", "EXAMPLE.com", "x.test", ""];
    let ts = Ts_ {
        denied: vec!["CN".into()],
        ..Ts_::first()
    };
    for _ in 0..10_000 {
        let r = next();
        let i = SelectionInput {
            country_geo: countries[(r % 6) as usize],
            country_cf: countries[((r >> 3) % 6) as usize],
            route_id: ["login", "x"][((r >> 6) & 1) as usize],
            redact_path: (r >> 7) & 1 == 1,
            host: hosts[((r >> 8) % 4) as usize],
            attempt_no: ((r >> 10) % 8) as u32,
            escalate_after: ((r >> 13) % 6) as u32,
            a11y_pref: (r >> 16) & 1 == 1,
            turnstile: ((r >> 17) & 1 == 1).then(|| ts.choice()),
        };
        let list = select_providers(&i);
        assert!(list.contains(&Hold) && list.contains(&A11y));
        assert_eq!(
            list.contains(&Ts),
            turnstile_eligible(&i),
            "selection first"
        );
        let mut dedup = list.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), list.len());

        let r2 = next();
        let modes = IxMode::ALL;
        let modalities = InputModality::ALL;
        let mut t = mouse_hold((r2 % 6_001) as u32 * 10);
        t.mode = modes[(r2 >> 13) as usize % modes.len()];
        t.modality = modalities[(r2 >> 16) as usize % modalities.len()];
        t.trusted = ((r2 >> 20) % 4) as u8;
        t.single = ((r2 >> 22) & 1 == 1).then_some(IxSingle {
            wait_ms: ((r2 >> 23) % 6_001) as u32 * 10,
        });
        t.pow = Some(IxPow {
            ms: ((r2 >> 36) % 32) as u8,
            worker: false,
            pow_impl: PowImpl::Js,
        });
        let providers = [
            ProviderId::SelfHold,
            ProviderId::PowA11y,
            ProviderId::Turnstile,
        ];
        let input = InteractionInput {
            provider: providers[((r2 >> 40) % 3) as usize],
            telemetry: ((r2 >> 42) & 7 != 0).then_some(&t),
            required_hold_ms: 1_200 + ((r2 >> 45) % 1_301) as u32,
            elapsed_ms: (r2 >> 32) as u32,
            pow_bits: ((r2 >> 50) % 40) as u32,
            pow_k: ((r2 >> 56) % 10) as u32,
            risk_band: RiskBand::ALL[((r2 >> 60) % 4) as usize],
            mode: if (r2 >> 62) & 1 == 1 {
                ScoringMode::Shadow
            } else {
                ScoringMode::Enforce {
                    t_pass: 0.3,
                    t_block: 0.7,
                }
            },
        };
        let a = assess_interaction(&input);
        assert!((0.0..=1.0).contains(&a.score));
        if a.hard_failure.is_some() {
            assert_eq!(a.outcome, IxOutcome::Retry);
        } else if input.mode == ScoringMode::Shadow {
            assert_eq!(a.outcome, IxOutcome::Pass);
        }
        assert_ne!(a.hard_failure, Some(reason::TOO_FAST));
        let _ = a.summary(&input);
    }
}
