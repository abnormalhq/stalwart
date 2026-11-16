/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

pub mod config;
pub mod input;
pub mod ledger;
pub mod provider;

use config::{MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, RuntimeConfig, ValidatedConfig, reserved_cost};
use input::extract;
use ledger::{LedgerKey, Reservation, ReservationLedger, ReserveOutcome};
use provider::{HttpProvider, ModelResult, Provider, Verdict};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::Semaphore;

pub const MAX_CONCURRENT_CLASSIFICATIONS: usize = 4;
pub const WORKFLOW_DEADLINE: Duration = Duration::from_millis(1500);
const SPAM_CONFIDENCE_THRESHOLD: u8 = 80;
const MAX_SCORE_POINTS: u8 = 5;

pub struct AiSpamRuntime {
    config: Arc<RuntimeConfig>,
    provider: Option<Arc<dyn Provider>>,
    ledger: Option<Arc<dyn ReservationLedger>>,
    permits: Arc<Semaphore>,
    counters: Arc<Counters>,
}

impl AiSpamRuntime {
    pub fn new(config: RuntimeConfig, ledger: Option<Arc<dyn ReservationLedger>>) -> Self {
        let provider = config
            .validated()
            .and_then(|config| HttpProvider::new(config).ok());
        Self::with_provider_and_limiter(
            config,
            ledger,
            provider.map(|provider| Arc::new(provider) as Arc<dyn Provider>),
            process_permits(),
        )
    }

    #[cfg(test)]
    pub fn with_provider(
        config: RuntimeConfig,
        ledger: Option<Arc<dyn ReservationLedger>>,
        provider: Option<Arc<dyn Provider>>,
    ) -> Self {
        Self::with_provider_and_limiter(
            config,
            ledger,
            provider,
            Arc::new(Semaphore::new(MAX_CONCURRENT_CLASSIFICATIONS)),
        )
    }

    fn with_provider_and_limiter(
        config: RuntimeConfig,
        ledger: Option<Arc<dyn ReservationLedger>>,
        provider: Option<Arc<dyn Provider>>,
        permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            provider,
            ledger,
            permits,
            counters: Arc::new(Counters::default()),
        }
    }

    pub async fn classify(&self, message: &mail_parser::Message<'_>) -> ClassifyOutcome {
        if !self.config.is_enabled() {
            return self.neutral(NeutralReason::Disabled);
        }
        let Some(config) = self.config.validated() else {
            return self.neutral(NeutralReason::NotReady);
        };
        let Some(ledger) = self.ledger.as_ref() else {
            return self.neutral(NeutralReason::NotReady);
        };
        let Some(provider) = self.provider.as_ref() else {
            return self.neutral(NeutralReason::NotReady);
        };

        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.counters.overloaded.fetch_add(1, Ordering::Relaxed);
                return self.neutral(NeutralReason::Overloaded);
            }
        };
        self.counters.attempts.fetch_add(1, Ordering::Relaxed);
        let result = tokio::time::timeout(WORKFLOW_DEADLINE, async {
            let input = extract(message).map_err(|_| NeutralReason::InvalidInput)?;
            if input.as_str().is_empty() {
                return Err(NeutralReason::InvalidInput);
            }
            let cost = reserved_cost(config.pricing).ok_or(NeutralReason::NotReady)?;
            let reservation = Reservation {
                requests: 1,
                input_tokens: MAX_INPUT_TOKENS,
                output_tokens: MAX_OUTPUT_TOKENS,
                cost_micros: cost,
            };
            let key = LedgerKey {
                server_id: config.server_id.clone(),
                billing_period: config.billing_period.clone(),
            };
            match ledger.reserve(key, config.budgets, reservation).await {
                ReserveOutcome::Reserved => {}
                ReserveOutcome::Exhausted => return Err(NeutralReason::BudgetExhausted),
                ReserveOutcome::Unavailable => return Err(NeutralReason::LedgerUnavailable),
            }
            provider
                .classify(input.as_str())
                .await
                .map_err(|_| NeutralReason::ProviderUnavailable)
        })
        .await;
        drop(permit);

        let outcome = match result {
            Ok(Ok(result)) => ClassifyOutcome::Evidence(evidence(config.score_cap, result)),
            Ok(Err(reason)) => self.neutral(reason),
            Err(_) => self.neutral(NeutralReason::Deadline),
        };
        if matches!(outcome, ClassifyOutcome::Evidence(_)) {
            self.counters.classified.fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    pub fn aggregate_counters(&self) -> AggregateCounters {
        AggregateCounters {
            attempts: self.counters.attempts.load(Ordering::Relaxed),
            classified: self.counters.classified.load(Ordering::Relaxed),
            neutral: self.counters.neutral.load(Ordering::Relaxed),
            overloaded: self.counters.overloaded.load(Ordering::Relaxed),
        }
    }

    fn neutral(&self, reason: NeutralReason) -> ClassifyOutcome {
        self.counters.neutral.fetch_add(1, Ordering::Relaxed);
        ClassifyOutcome::Neutral(reason)
    }
}

#[derive(Default)]
struct Counters {
    attempts: AtomicU64,
    classified: AtomicU64,
    neutral: AtomicU64,
    overloaded: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AggregateCounters {
    pub attempts: u64,
    pub classified: u64,
    pub neutral: u64,
    pub overloaded: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NeutralReason {
    Disabled,
    NotReady,
    Overloaded,
    InvalidInput,
    BudgetExhausted,
    LedgerUnavailable,
    ProviderUnavailable,
    Deadline,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClassifyOutcome {
    Evidence(AiEvidence),
    Neutral(NeutralReason),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AiEvidence(u8);

impl AiEvidence {
    pub fn points(self) -> u8 {
        self.0
    }

    pub fn add_to_score(self, score: f32) -> f32 {
        if self.0 == 0 || !score.is_finite() {
            return score;
        }
        let sum = score + f32::from(self.0);
        if sum.is_finite() { sum } else { f32::MAX }
    }
}

fn evidence(cap: u8, result: ModelResult) -> AiEvidence {
    let points = if result.verdict == Verdict::Spam
        && result.confidence >= SPAM_CONFIDENCE_THRESHOLD
    {
        (u16::from(cap.min(MAX_SCORE_POINTS)) * u16::from(result.confidence.min(100)) / 100) as u8
    } else {
        0
    };
    AiEvidence(points.min(cap).min(MAX_SCORE_POINTS))
}

fn process_permits() -> Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_CLASSIFICATIONS)))
        .clone()
}

#[cfg(test)]
mod tests;
