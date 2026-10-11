//! Per-(site, provider) circuit breaker and automatic disabling (spec §8.6).
//!
//! ```text
//!            5 consecutive Unavailable within 60 s
//!  healthy ───────────────────────────────────────> open (30 s, doubled on every re-open, ≤ 300 s)
//!     ^                                               │ expires
//!     │ trial succeeds                                v
//!     └──────────────────────────────────────────── half_open (one trial verification)
//!                                                     │ trial Unavailable -> open again
//!  any state ── Misconfigured ──> disabled(misconfigured)   (until reset())
//!  any state ── disable(NoSecret) ──> disabled(no_secret)  (set by mg-edge)
//! ```
//!
//! The state lives in process memory and is lost on restart (A1 SH-11).
//! Time is passed in as Unix milliseconds. Every change updates
//! `mg_provider_state{site, provider, state}`.

use super::metrics;
use mg_core::{ProviderHealth, ProviderId};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Consecutive `Unavailable` results that open the breaker.
pub const FAILURE_THRESHOLD: usize = 5;
/// Window in which those results must fall.
pub const FAILURE_WINDOW_MS: i64 = 60_000;
/// First open period.
pub const OPEN_BASE_MS: i64 = 30_000;
/// Longest open period.
pub const OPEN_MAX_MS: i64 = 300_000;

/// Why a provider is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledReason {
    /// siteverify rejected the secret (`missing-input-secret`, or
    /// `invalid-input-secret` after the previous-secret retry).
    Misconfigured,
    /// The bundle enables the provider but `edge.toml` has no credential
    /// for it (spec §8.2; set by mg-edge).
    NoSecret,
}

impl DisabledReason {
    /// `misconfigured` / `no_secret`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Misconfigured => "misconfigured",
            Self::NoSecret => "no_secret",
        }
    }
}

/// Health state of one (site, provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Healthy,
    /// Open until `until_ms`.
    Open {
        until_ms: i64,
    },
    /// One trial verification may run.
    HalfOpen,
    Disabled(DisabledReason),
}

impl BreakerState {
    /// The `state` label of `mg_provider_state`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Open { .. } => "open",
            Self::HalfOpen => "half_open",
            Self::Disabled(_) => "disabled",
        }
    }
}

const STATE_LABELS: [&str; 4] = ["healthy", "open", "half_open", "disabled"];

/// What a verification tells the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerSignal {
    /// The provider answered (`Pass` or `Fail`).
    Healthy,
    /// `Unavailable` that counts (transport, timeout, 5xx, malformed …).
    Unavailable,
    /// `Misconfigured`: disable at once.
    Misconfigured,
    /// Not about the provider's health (local pre-check, concurrency limit).
    Neutral,
}

/// Why [`CircuitBreaker::admit`] refused a verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Open,
    /// Half-open and the one trial verification is already running.
    TrialInFlight,
    Disabled(DisabledReason),
}

struct Inner {
    state: BreakerState,
    /// Times of the current run of consecutive `Unavailable` results.
    failures: VecDeque<i64>,
    /// Length of the next open period.
    next_open_ms: i64,
    trial_in_flight: bool,
}

/// Circuit breaker of one (site, provider) (see the module docs).
pub struct CircuitBreaker {
    site: String,
    provider: ProviderId,
    inner: Mutex<Inner>,
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        f.debug_struct("CircuitBreaker")
            .field("site", &self.site)
            .field("provider", &self.provider)
            .field("state", &inner.state)
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    /// A healthy breaker; sets its gauge.
    pub fn new(site: impl Into<String>, provider: ProviderId) -> Self {
        let b = Self {
            site: site.into(),
            provider,
            inner: Mutex::new(Inner {
                state: BreakerState::Healthy,
                failures: VecDeque::with_capacity(FAILURE_THRESHOLD),
                next_open_ms: OPEN_BASE_MS,
                trial_in_flight: false,
            }),
        };
        b.publish(BreakerState::Healthy);
        b
    }

    pub fn site(&self) -> &str {
        &self.site
    }

    pub fn provider(&self) -> ProviderId {
        self.provider
    }

    /// Current state; an open breaker whose period ended turns half-open.
    pub fn state(&self, now_ms: i64) -> BreakerState {
        let mut inner = self.lock();
        self.advance(&mut inner, now_ms);
        inner.state
    }

    /// Whether the provider may be offered (spec §8.2 "usable": not
    /// disabled and not open). Half-open counts as usable so that a trial
    /// verification can happen.
    pub fn usable(&self, now_ms: i64) -> bool {
        matches!(
            self.state(now_ms),
            BreakerState::Healthy | BreakerState::HalfOpen
        )
    }

    /// The state as an [`mg_core::ProviderHealth`]: healthy → `Healthy`,
    /// half-open → `Degraded("half_open")`, open → `Disabled("circuit_open")`,
    /// disabled → `Disabled(<reason>)`; usable exactly when `Healthy` or
    /// `Degraded` (spec §5.4).
    pub fn health(&self, now_ms: i64) -> ProviderHealth {
        match self.state(now_ms) {
            BreakerState::Healthy => ProviderHealth::Healthy,
            BreakerState::HalfOpen => ProviderHealth::Degraded("half_open".into()),
            BreakerState::Open { .. } => ProviderHealth::Disabled("circuit_open".into()),
            BreakerState::Disabled(r) => ProviderHealth::Disabled(r.as_str().into()),
        }
    }

    /// Admits one verification. Healthy: always. Half-open: only the first
    /// caller (the trial) until its result is recorded or its [`Admission`]
    /// is dropped. Open or disabled: refused.
    pub fn admit(&self, now_ms: i64) -> Result<Admission<'_>, Refusal> {
        let mut inner = self.lock();
        self.advance(&mut inner, now_ms);
        match inner.state {
            BreakerState::Healthy => Ok(Admission {
                breaker: self,
                trial: false,
                done: false,
            }),
            BreakerState::HalfOpen if !inner.trial_in_flight => {
                inner.trial_in_flight = true;
                Ok(Admission {
                    breaker: self,
                    trial: true,
                    done: false,
                })
            }
            BreakerState::HalfOpen => Err(Refusal::TrialInFlight),
            BreakerState::Open { .. } => Err(Refusal::Open),
            BreakerState::Disabled(r) => Err(Refusal::Disabled(r)),
        }
    }

    /// Disables the provider until [`CircuitBreaker::reset`] (logs an ERROR
    /// for `Misconfigured`).
    pub fn disable(&self, reason: DisabledReason) {
        let mut inner = self.lock();
        self.set_disabled(&mut inner, reason);
    }

    /// Back to healthy with a fresh backoff: mg-edge calls it when the
    /// bundle version changes or the credentials are reloaded (spec §8.6).
    pub fn reset(&self) {
        let mut inner = self.lock();
        inner.failures.clear();
        inner.next_open_ms = OPEN_BASE_MS;
        inner.trial_in_flight = false;
        self.transition(&mut inner, BreakerState::Healthy);
    }

    fn record(&self, trial: bool, signal: BreakerSignal, now_ms: i64) {
        let mut inner = self.lock();
        if trial {
            inner.trial_in_flight = false;
        }
        self.advance(&mut inner, now_ms);
        if signal == BreakerSignal::Misconfigured {
            self.set_disabled(&mut inner, DisabledReason::Misconfigured);
            return;
        }
        match (inner.state, signal) {
            (BreakerState::Healthy, BreakerSignal::Healthy) => inner.failures.clear(),
            (BreakerState::Healthy, BreakerSignal::Unavailable) => {
                inner
                    .failures
                    .retain(|&t| now_ms.saturating_sub(t) <= FAILURE_WINDOW_MS);
                inner.failures.push_back(now_ms);
                if inner.failures.len() >= FAILURE_THRESHOLD {
                    self.open(&mut inner, now_ms);
                }
            }
            (BreakerState::HalfOpen, BreakerSignal::Healthy) if trial => {
                inner.failures.clear();
                inner.next_open_ms = OPEN_BASE_MS;
                self.transition(&mut inner, BreakerState::Healthy);
            }
            (BreakerState::HalfOpen, BreakerSignal::Unavailable) if trial => {
                inner.next_open_ms = (inner.next_open_ms * 2).min(OPEN_MAX_MS);
                self.open(&mut inner, now_ms);
            }
            // Neutral results, late results of verifications admitted before
            // the state changed, and anything while disabled: no change.
            _ => {}
        }
    }

    fn open(&self, inner: &mut Inner, now_ms: i64) {
        inner.failures.clear();
        let until_ms = now_ms.saturating_add(inner.next_open_ms);
        log::warn!(
            "outbound: {} circuit for site {} open for {} s",
            self.provider,
            self.site,
            inner.next_open_ms / 1000
        );
        self.transition(inner, BreakerState::Open { until_ms });
    }

    fn set_disabled(&self, inner: &mut Inner, reason: DisabledReason) {
        if inner.state != BreakerState::Disabled(reason) {
            log::error!(
                "outbound: {} disabled for site {} ({}) until the bundle or the credentials change",
                self.provider,
                self.site,
                reason.as_str()
            );
        }
        inner.failures.clear();
        self.transition(inner, BreakerState::Disabled(reason));
    }

    fn advance(&self, inner: &mut Inner, now_ms: i64) {
        if let BreakerState::Open { until_ms } = inner.state
            && now_ms >= until_ms
        {
            inner.trial_in_flight = false;
            self.transition(inner, BreakerState::HalfOpen);
        }
    }

    fn transition(&self, inner: &mut Inner, to: BreakerState) {
        let changed = inner.state.label() != to.label();
        inner.state = to;
        if changed {
            self.publish(to);
        }
    }

    fn publish(&self, state: BreakerState) {
        let gauge = &metrics::get().provider_state;
        for label in STATE_LABELS {
            gauge
                .with_label_values(&[self.site.as_str(), self.provider.as_str(), label])
                .set(i64::from(label == state.label()));
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Permission for one verification from [`CircuitBreaker::admit`]. Record
/// its result with [`Admission::record`]; dropping it unrecorded (a
/// cancelled request) only frees the half-open trial slot.
#[must_use = "record the verification result"]
pub struct Admission<'a> {
    breaker: &'a CircuitBreaker,
    trial: bool,
    done: bool,
}

impl fmt::Debug for Admission<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admission")
            .field("trial", &self.trial)
            .finish_non_exhaustive()
    }
}

impl Admission<'_> {
    /// Whether this is the half-open trial.
    pub fn is_trial(&self) -> bool {
        self.trial
    }

    /// Records the verification result.
    pub fn record(mut self, signal: BreakerSignal, now_ms: i64) {
        self.done = true;
        self.breaker.record(self.trial, signal, now_ms);
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if self.trial && !self.done {
            self.breaker.lock().trial_in_flight = false;
        }
    }
}
