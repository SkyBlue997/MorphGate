//! Circuit breaker and automatic disabling (docs/impl/phase2-spec.md §8.6;
//! WP-C6): opening after 5 consecutive `Unavailable` within 60 s, the
//! doubled open periods, the single half-open trial, `disabled`, the gauge,
//! and `Siteverify::verify_with_breaker` against the loopback mock.

use mg_core::{ProviderHealth, ProviderId, VerdictOutcome};
use mg_edge_core::outbound::{
    BreakerSignal, BreakerState, CircuitBreaker, DisabledReason, OPEN_BASE_MS, OPEN_MAX_MS,
    Refusal, Siteverify, SiteverifyExpect, SiteverifyRequest, TurnstileSecrets, VerifyReason,
    validate_siteverify_url,
};
use mg_edge_core::testkit::siteverify::{FakeSiteverify, SvReply};

const T0: i64 = 1_790_000_000_000;

fn record(b: &CircuitBreaker, signal: BreakerSignal, now: i64) {
    b.admit(now).expect("admitted").record(signal, now);
}

/// Value of `name{labels}` as the default registry exports it (text
/// exposition format, which is stable whichever prometheus features the
/// workspace build unifies); `None` when absent.
fn scraped(name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    use prometheus::Encoder as _;
    let mut text = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&prometheus::gather(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(name)?.strip_prefix('{')?;
        let (set, value) = rest.split_once("} ")?;
        labels
            .iter()
            .all(|(k, v)| set.split(',').any(|p| p == format!("{k}=\"{v}\"")))
            .then(|| value.parse().unwrap())
    })
}

fn gauge(site: &str, state: &str) -> f64 {
    scraped(
        "mg_provider_state",
        &[("site", site), ("provider", "turnstile"), ("state", state)],
    )
    .unwrap_or(-1.0)
}

#[test]
fn five_consecutive_unavailable_within_60s_open() {
    let b = CircuitBreaker::new("breaker-open", ProviderId::Turnstile);
    assert_eq!(b.state(T0), BreakerState::Healthy);
    assert_eq!(gauge("breaker-open", "healthy"), 1.0);
    for i in 0..4 {
        record(&b, BreakerSignal::Unavailable, T0 + i * 10_000);
    }
    assert_eq!(b.state(T0 + 40_000), BreakerState::Healthy);
    record(&b, BreakerSignal::Unavailable, T0 + 60_000);
    assert_eq!(
        b.state(T0 + 60_000),
        BreakerState::Open {
            until_ms: T0 + 60_000 + OPEN_BASE_MS
        }
    );
    assert!(!b.usable(T0 + 60_001));
    assert!(matches!(b.admit(T0 + 60_001), Err(Refusal::Open)));
    assert_eq!(
        b.health(T0 + 60_001),
        ProviderHealth::Disabled("circuit_open".into())
    );
    assert_eq!(gauge("breaker-open", "open"), 1.0);
    assert_eq!(gauge("breaker-open", "healthy"), 0.0);
}

#[test]
fn a_success_or_a_slow_run_does_not_open() {
    let b = CircuitBreaker::new("breaker-run", ProviderId::Turnstile);
    for i in 0..4 {
        record(&b, BreakerSignal::Unavailable, T0 + i);
    }
    record(&b, BreakerSignal::Healthy, T0 + 5);
    for i in 0..4 {
        record(&b, BreakerSignal::Unavailable, T0 + 10 + i);
    }
    assert_eq!(b.state(T0 + 20), BreakerState::Healthy, "run was reset");

    // Five in a row, but spread over more than 60 s.
    let b = CircuitBreaker::new("breaker-slow", ProviderId::Turnstile);
    for i in 0..5 {
        record(&b, BreakerSignal::Unavailable, T0 + i * 20_000);
    }
    assert_eq!(b.state(T0 + 80_000), BreakerState::Healthy);
    // At 81 s the 20 s entry has aged out (40, 60, 80, 81: four); one more
    // within the window opens it.
    record(&b, BreakerSignal::Unavailable, T0 + 81_000);
    assert_eq!(b.state(T0 + 81_000), BreakerState::Healthy);
    record(&b, BreakerSignal::Unavailable, T0 + 82_000);
    assert!(matches!(b.state(T0 + 82_000), BreakerState::Open { .. }));

    // Neutral results (busy, pre-check) never count.
    let b = CircuitBreaker::new("breaker-neutral", ProviderId::Turnstile);
    for i in 0..20 {
        record(&b, BreakerSignal::Neutral, T0 + i);
    }
    assert_eq!(b.state(T0 + 20), BreakerState::Healthy);
}

#[test]
fn half_open_allows_one_trial_and_backs_off() {
    let b = CircuitBreaker::new("breaker-half", ProviderId::Turnstile);
    let open = |b: &CircuitBreaker, at: i64| {
        for i in 0..5 {
            record(b, BreakerSignal::Unavailable, at + i);
        }
    };
    open(&b, T0);
    let opened = T0 + 4;
    assert!(matches!(
        b.state(opened + OPEN_BASE_MS - 1),
        BreakerState::Open { .. }
    ));
    let mut now = opened + OPEN_BASE_MS;
    assert_eq!(b.state(now), BreakerState::HalfOpen);
    assert!(b.usable(now));
    assert_eq!(b.health(now), ProviderHealth::Degraded("half_open".into()));
    assert_eq!(gauge("breaker-half", "half_open"), 1.0);

    // Re-open periods double: 60, 120, 240, then 300 s at most.
    let mut period = OPEN_BASE_MS;
    for _ in 0..6 {
        let trial = b.admit(now).unwrap();
        assert!(trial.is_trial());
        assert!(matches!(b.admit(now), Err(Refusal::TrialInFlight)));
        trial.record(BreakerSignal::Unavailable, now);
        period = (period * 2).min(OPEN_MAX_MS);
        assert_eq!(
            b.state(now),
            BreakerState::Open {
                until_ms: now + period
            }
        );
        now += period;
        assert_eq!(b.state(now), BreakerState::HalfOpen);
    }
    assert_eq!(period, OPEN_MAX_MS);

    // A dropped (cancelled) trial frees the slot; a neutral one too.
    drop(b.admit(now).unwrap());
    let trial = b.admit(now).unwrap();
    trial.record(BreakerSignal::Neutral, now);
    assert_eq!(b.state(now), BreakerState::HalfOpen);

    // A successful trial closes the breaker and resets the backoff.
    b.admit(now).unwrap().record(BreakerSignal::Healthy, now);
    assert_eq!(b.state(now), BreakerState::Healthy);
    assert_eq!(gauge("breaker-half", "healthy"), 1.0);
    open(&b, now + 1);
    assert_eq!(
        b.state(now + 5),
        BreakerState::Open {
            until_ms: now + 5 + OPEN_BASE_MS
        }
    );
}

#[test]
fn late_results_do_not_change_an_open_breaker() {
    let b = CircuitBreaker::new("breaker-late", ProviderId::Turnstile);
    let early = b.admit(T0).unwrap();
    for i in 0..5 {
        record(&b, BreakerSignal::Unavailable, T0 + i);
    }
    early.record(BreakerSignal::Healthy, T0 + 10);
    assert!(matches!(b.state(T0 + 10), BreakerState::Open { .. }));
}

#[test]
fn misconfigured_disables_until_reset() {
    let b = CircuitBreaker::new("breaker-disabled", ProviderId::Turnstile);
    record(&b, BreakerSignal::Misconfigured, T0);
    assert_eq!(
        b.state(T0 + 10 * OPEN_MAX_MS),
        BreakerState::Disabled(DisabledReason::Misconfigured)
    );
    assert!(!b.usable(T0 + 1));
    assert_eq!(
        b.admit(T0 + 1).err(),
        Some(Refusal::Disabled(DisabledReason::Misconfigured))
    );
    assert_eq!(
        b.health(T0),
        ProviderHealth::Disabled("misconfigured".into())
    );
    assert_eq!(gauge("breaker-disabled", "disabled"), 1.0);
    b.reset();
    assert_eq!(b.state(T0 + 2), BreakerState::Healthy);
    assert_eq!(gauge("breaker-disabled", "disabled"), 0.0);

    b.disable(DisabledReason::NoSecret);
    assert_eq!(b.health(T0), ProviderHealth::Disabled("no_secret".into()));
    assert!(!b.usable(T0));
    // A half-open trial that reports Misconfigured disables too.
    b.reset();
    for i in 0..5 {
        record(&b, BreakerSignal::Unavailable, T0 + i);
    }
    let now = T0 + 4 + OPEN_BASE_MS;
    b.admit(now)
        .unwrap()
        .record(BreakerSignal::Misconfigured, now);
    assert_eq!(
        b.state(now),
        BreakerState::Disabled(DisabledReason::Misconfigured)
    );
    assert!(format!("{b:?}").contains("breaker-disabled"));
}

#[tokio::test]
async fn verify_with_breaker_counts_only_provider_failures() {
    let mock = FakeSiteverify::start().unwrap();
    let sv = Siteverify::build(validate_siteverify_url(&mock.url(), true).unwrap()).unwrap();
    let secrets = TurnstileSecrets::new(vec!["s1".into()]).unwrap();
    let hostnames = vec!["example.com".to_owned()];
    let ok = |_: &str| true;
    let b = CircuitBreaker::new("breaker-verify", ProviderId::Turnstile);
    let verify = |token: &'static str| {
        let (sv, secrets, hostnames, b) = (&sv, &secrets, &hostnames, &b);
        async move {
            let expect = SiteverifyExpect {
                host: "example.com",
                hostnames,
                action: "login",
                c_iat_ms: T0,
                now_ms: T0 + 1_000,
                deadline_ms: T0 + 6_000,
                cdata_ok: &ok,
            };
            let req = SiteverifyRequest {
                secrets,
                response: token,
                remoteip: "198.51.100.4".parse().unwrap(),
                nonce: &[7; 16],
            };
            sv.verify_with_breaker(b, &req, &expect).await
        }
    };

    // Pre-check failures are neutral.
    for _ in 0..6 {
        let r = verify("bad token").await;
        assert_eq!(r.reason, VerifyReason::Precheck);
    }
    assert_eq!(b.state(T0), BreakerState::Healthy);

    // Fail replies (the provider answered) are healthy.
    mock.set_default_reply(SvReply::error_codes(&["timeout-or-duplicate"]));
    for _ in 0..6 {
        assert_eq!(verify("tok").await.verdict.outcome, VerdictOutcome::Fail);
    }
    assert_eq!(b.state(T0), BreakerState::Healthy);

    // Five Unavailable (each after its retry) open it ...
    mock.set_default_reply(SvReply::status(503));
    for _ in 0..5 {
        let r = verify("tok").await;
        assert_eq!(r.verdict.outcome, VerdictOutcome::Unavailable);
        assert_eq!(r.requests, 2);
    }
    assert!(matches!(b.state(T0 + 1_000), BreakerState::Open { .. }));
    // ... and then nothing is sent.
    let before = mock.requests().len();
    let r = verify("tok").await;
    assert_eq!(r.verdict.outcome, VerdictOutcome::Unavailable);
    assert_eq!(r.reason, VerifyReason::Busy);
    assert_eq!(r.requests, 0);
    assert_eq!(mock.requests().len(), before);

    // Misconfigured disables.
    b.reset();
    mock.set_default_reply(SvReply::error_codes(&["invalid-input-secret"]));
    let r = verify("tok").await;
    assert_eq!(r.verdict.outcome, VerdictOutcome::Misconfigured);
    assert_eq!(
        b.state(T0),
        BreakerState::Disabled(DisabledReason::Misconfigured)
    );
    let before = mock.requests().len();
    assert_eq!(verify("tok").await.reason, VerifyReason::Busy);
    assert_eq!(mock.requests().len(), before);
}
