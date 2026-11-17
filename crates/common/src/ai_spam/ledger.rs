/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::ai_spam::config::Budgets;
use std::{future::Future, ops::Deref, pin::Pin, sync::Arc};
use store::{
    Deserialize, Store, Subspace, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};

struct LedgerBytes(Vec<u8>);

impl Deref for LedgerBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserialize for LedgerBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

pub type LedgerFuture<'a> = Pin<Box<dyn Future<Output = ReserveOutcome> + Send + 'a>>;

pub trait ReservationLedger: Send + Sync {
    fn reserve<'a>(
        &'a self,
        key: LedgerKey,
        budgets: Budgets,
        reservation: Reservation,
    ) -> LedgerFuture<'a>;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LedgerKey {
    pub server_id: String,
    pub billing_period: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveOutcome {
    Reserved,
    Exhausted,
    Unavailable,
}

pub struct StoreLedger {
    store: Arc<Store>,
}

impl StoreLedger {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub async fn rollover_period(
        &self,
        server_id: &str,
        expected_period: Option<&str>,
        next_period: &str,
    ) -> ReserveOutcome {
        if self.store.is_none() || self.store.is_ephemeral() {
            return ReserveOutcome::Unavailable;
        }
        if !valid_server_id(server_id) {
            return ReserveOutcome::Unavailable;
        }
        let class = period_class(server_id);
        let key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: class.clone(),
        };
        let previous = match self.store.get_value::<LedgerBytes>(key).await {
            Ok(value) => value,
            Err(_) => return ReserveOutcome::Unavailable,
        };
        let control = match previous.as_deref().map(decode_period).transpose() {
            Ok(control) => control,
            Err(()) => return ReserveOutcome::Unavailable,
        };
        let previous_version = control.as_ref().map_or(0, |value| value.version);
        let Some(next) = next_period_control(control.as_ref(), expected_period, next_period) else {
            return ReserveOutcome::Unavailable;
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(
            class.clone(),
            previous
                .as_deref()
                .map_or(AssertValue::None, |_| AssertValue::U64(previous_version)),
        );
        batch.set(class, encode_period(next));
        match self.store.write_batch(&mut batch).await {
            Ok(_) => ReserveOutcome::Reserved,
            Err(_) => ReserveOutcome::Unavailable,
        }
    }
}

impl ReservationLedger for StoreLedger {
    fn reserve<'a>(
        &'a self,
        key: LedgerKey,
        budgets: Budgets,
        reservation: Reservation,
    ) -> LedgerFuture<'a> {
        Box::pin(async move {
            if self.store.is_none() || self.store.is_ephemeral() {
                return ReserveOutcome::Unavailable;
            }
            if !valid_server_id(&key.server_id) || !valid_period(&key.billing_period) {
                return ReserveOutcome::Unavailable;
            }
            let period_control = match self
                .store
                .get_value::<LedgerBytes>(ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: period_class(&key.server_id),
                })
                .await
            {
                Ok(Some(value)) => match decode_period(&value) {
                    Ok(control) => control,
                    Err(()) => return ReserveOutcome::Unavailable,
                },
                Ok(None) | Err(_) => return ReserveOutcome::Unavailable,
            };
            if period_control.period != key.billing_period {
                return ReserveOutcome::Unavailable;
            }
            let class = ledger_class(&key);
            let value_key = ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: class.clone(),
            };
            let previous = match self.store.get_value::<LedgerBytes>(value_key).await {
                Ok(value) => value,
                Err(_) => return ReserveOutcome::Unavailable,
            };
            let snapshot = match previous.as_deref().map(decode).transpose() {
                Ok(snapshot) => snapshot.unwrap_or_default(),
                Err(()) => return ReserveOutcome::Unavailable,
            };
            let Some(next) = snapshot.reserve(reservation, budgets) else {
                return ReserveOutcome::Exhausted;
            };
            let plan =
                reservation_write_plan(&key, &period_control, previous.as_deref(), snapshot, next);
            let mut batch = BatchBuilder::new();
            plan.apply(&mut batch);
            match self.store.write_batch(&mut batch).await {
                Ok(_) => ReserveOutcome::Reserved,
                Err(_) => ReserveOutcome::Unavailable,
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) requests: u64,
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) cost_micros: u64,
    pub(super) version: u64,
}

impl Snapshot {
    fn reserve(self, reservation: Reservation, budgets: Budgets) -> Option<Self> {
        let next = Self {
            requests: self.requests.checked_add(reservation.requests)?,
            input_tokens: self.input_tokens.checked_add(reservation.input_tokens)?,
            output_tokens: self.output_tokens.checked_add(reservation.output_tokens)?,
            cost_micros: self.cost_micros.checked_add(reservation.cost_micros)?,
            version: self.version.checked_add(1)?,
        };
        (next.requests <= budgets.requests
            && next.input_tokens <= budgets.input_tokens
            && next.output_tokens <= budgets.output_tokens
            && next.cost_micros <= budgets.cost_micros)
            .then_some(next)
    }
}

fn ledger_class(key: &LedgerKey) -> ValueClass {
    let mut bytes = b"community-ai-spam-ledger\0v1\0".to_vec();
    bytes.extend_from_slice(&(key.server_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(key.server_id.as_bytes());
    bytes.extend_from_slice(&(key.billing_period.len() as u32).to_be_bytes());
    bytes.extend_from_slice(key.billing_period.as_bytes());
    ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: bytes,
    })
}

pub(super) struct ReservationWritePlan {
    pub(super) period_class: ValueClass,
    pub(super) period_assertion: AssertValue,
    pub(super) ledger_class: ValueClass,
    pub(super) ledger_assertion: AssertValue,
    pub(super) ledger_value: Vec<u8>,
}

impl ReservationWritePlan {
    pub(super) fn apply(self, batch: &mut BatchBuilder) {
        batch.assert_value(self.period_class, self.period_assertion);
        batch.assert_value(self.ledger_class.clone(), self.ledger_assertion);
        batch.set(self.ledger_class, self.ledger_value);
    }
}

pub(super) fn reservation_write_plan(
    key: &LedgerKey,
    period_control: &PeriodControl,
    previous_ledger_value: Option<&[u8]>,
    previous_snapshot: Snapshot,
    next_snapshot: Snapshot,
) -> ReservationWritePlan {
    ReservationWritePlan {
        period_class: period_class(&key.server_id),
        period_assertion: AssertValue::U64(period_control.version),
        ledger_class: ledger_class(key),
        ledger_assertion: previous_ledger_value.map_or(AssertValue::None, |_| {
            AssertValue::U64(previous_snapshot.version)
        }),
        ledger_value: encode(next_snapshot),
    }
}

pub(super) fn valid_server_id(server_id: &str) -> bool {
    (1..=128).contains(&server_id.len())
        && server_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

fn period_class(server_id: &str) -> ValueClass {
    let mut bytes = b"community-ai-spam-period-control\0v1\0".to_vec();
    bytes.extend_from_slice(&(server_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(server_id.as_bytes());
    ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: bytes,
    })
}

pub(super) fn encode(snapshot: Snapshot) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(41);
    bytes.push(1);
    for value in [
        snapshot.requests,
        snapshot.input_tokens,
        snapshot.output_tokens,
        snapshot.cost_micros,
        snapshot.version,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

pub(super) fn decode(bytes: &[u8]) -> Result<Snapshot, ()> {
    if bytes.len() != 41 || bytes[0] != 1 {
        return Err(());
    }
    let value = |index: usize| -> Result<u64, ()> {
        let start = 1 + index * 8;
        let bytes: [u8; 8] = bytes
            .get(start..start + 8)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        Ok(u64::from_be_bytes(bytes))
    };
    Ok(Snapshot {
        requests: value(0)?,
        input_tokens: value(1)?,
        output_tokens: value(2)?,
        cost_micros: value(3)?,
        version: value(4)?,
    })
}

#[derive(Debug)]
pub(super) struct PeriodControl {
    pub(super) period: String,
    pub(super) version: u64,
}

impl PeriodControl {
    pub(super) fn new(period: &str, version: u64) -> Option<Self> {
        valid_period(period).then(|| Self {
            period: period.to_owned(),
            version,
        })
    }
}

pub(super) fn next_period_control(
    current: Option<&PeriodControl>,
    expected_period: Option<&str>,
    next_period: &str,
) -> Option<PeriodControl> {
    if !valid_period(next_period)
        || expected_period.is_some_and(|period| !valid_period(period))
        || current.map(|control| control.period.as_str()) != expected_period
        || current.is_some_and(|control| next_period <= control.period.as_str())
    {
        return None;
    }
    let version = match current {
        Some(control) => control.version.checked_add(1)?,
        None => 0,
    };
    PeriodControl::new(next_period, version)
}

pub(super) fn encode_period(control: PeriodControl) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(13 + control.period.len());
    bytes.push(1);
    bytes.extend_from_slice(&(control.period.len() as u32).to_be_bytes());
    bytes.extend_from_slice(control.period.as_bytes());
    bytes.extend_from_slice(&control.version.to_be_bytes());
    bytes
}

pub(super) fn decode_period(bytes: &[u8]) -> Result<PeriodControl, ()> {
    if bytes.len() < 13 || bytes[0] != 1 {
        return Err(());
    }
    let len = u32::from_be_bytes(bytes[1..5].try_into().map_err(|_| ())?) as usize;
    if bytes.len() != 5 + len + 8 {
        return Err(());
    }
    let period = std::str::from_utf8(&bytes[5..5 + len]).map_err(|_| ())?;
    let version = u64::from_be_bytes(bytes[5 + len..].try_into().map_err(|_| ())?);
    PeriodControl::new(period, version).ok_or(())
}

fn valid_period(period: &str) -> bool {
    let bytes = period.as_bytes();
    let month = period.get(5..).and_then(|value| value.parse::<u8>().ok());
    bytes.len() == 7
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..].iter().all(u8::is_ascii_digit)
        && month.is_some_and(|value| (1..=12).contains(&value))
}
