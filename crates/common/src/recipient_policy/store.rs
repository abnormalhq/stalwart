// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    PolicyActor, RecipientPolicyAcknowledgment, RecipientPolicyCommand, RecipientPolicyError,
    RecipientPolicyRecord, apply_transition, valid_address, valid_digest, valid_domain,
};
use ::store::{
    Store, Subspace, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use std::future::Future;

pub(super) struct RecipientPolicyStore;

impl RecipientPolicyStore {
    pub(super) async fn apply(
        store: &Store,
        command: &RecipientPolicyCommand,
        digest: &str,
        actor: PolicyActor,
        now: u64,
    ) -> Result<RecipientPolicyAcknowledgment, RecipientPolicyError> {
        ensure_durable(store)?;
        let current = load_record(store, &command.address).await?;
        let next = apply_transition(current.clone(), command, digest, actor, now)?;
        if current.as_ref() == Some(&next) {
            return Ok(next.acknowledgment);
        }

        let record_json =
            serde_json::to_string(&next).map_err(|_| RecipientPolicyError::TemporaryFailure)?;
        let revision_value = next.revision.to_string();
        let revision_key = revision_key(&command.address);
        let mut batch = BatchBuilder::new();
        match current.as_ref() {
            Some(record) => {
                let old_revision = record.revision.to_string();
                batch.assert_value(
                    revision_key.clone(),
                    AssertValue::Hash(::store::xxhash_rust::xxh3::xxh3_64(old_revision.as_bytes())),
                );
            }
            None => {
                batch.assert_value(revision_key.clone(), ());
            }
        }
        batch
            .set(record_key(&command.address), record_json)
            .set(revision_key, revision_value);

        if store.write_batch(&mut batch).await.is_err() {
            let persisted = load_record(store, &command.address).await?;
            if persisted.as_ref().is_some_and(|record| {
                record.revision == next.revision && record.digest == next.digest
            }) {
                return Ok(persisted.unwrap().acknowledgment);
            }
            return Err(RecipientPolicyError::TemporaryFailure);
        }

        let persisted = load_record(store, &command.address).await?;
        if persisted.as_ref() != Some(&next) {
            return Err(RecipientPolicyError::TemporaryFailure);
        }
        Ok(persisted.unwrap().acknowledgment)
    }

    pub(super) async fn read(
        store: &Store,
        address: &str,
    ) -> Result<Option<RecipientPolicyRecord>, RecipientPolicyError> {
        ensure_durable(store)?;
        load_record(store, address).await
    }
}

async fn load_record(
    store: &Store,
    address: &str,
) -> Result<Option<RecipientPolicyRecord>, RecipientPolicyError> {
    load_record_with(address, |key| async move {
        store
            .get_value_fresh::<String>(ValueKey::from(key))
            .await
            .map_err(|_| RecipientPolicyError::TemporaryFailure)
    })
    .await
}

const MAX_RECORD_READ_ATTEMPTS: usize = 3;

async fn load_record_with<F, Fut>(
    address: &str,
    mut read_value: F,
) -> Result<Option<RecipientPolicyRecord>, RecipientPolicyError>
where
    F: FnMut(ValueClass) -> Fut,
    Fut: Future<Output = Result<Option<String>, RecipientPolicyError>>,
{
    for _ in 0..MAX_RECORD_READ_ATTEMPTS {
        let record = read_value(record_key(address)).await?;
        let revision = read_value(revision_key(address)).await?;
        let record = record
            .map(|record| validate_record(address, &record))
            .transpose()?;
        let revision = revision
            .map(|revision| {
                revision
                    .parse::<u64>()
                    .map_err(|_| RecipientPolicyError::TemporaryFailure)
            })
            .transpose()?;

        match (record, revision) {
            (None, None) => return Ok(None),
            (Some(record), Some(revision)) if record.revision == revision => {
                return Ok(Some(record));
            }
            _ => {}
        }
    }
    Err(RecipientPolicyError::TemporaryFailure)
}

fn validate_record(
    address: &str,
    serialized: &str,
) -> Result<RecipientPolicyRecord, RecipientPolicyError> {
    let record: RecipientPolicyRecord =
        serde_json::from_str(serialized).map_err(|_| RecipientPolicyError::TemporaryFailure)?;
    if record.address != address
        || !valid_address(&record.address)
        || !valid_domain(&record.domain)
        || !valid_digest(&record.digest)
        || record.schema_version != super::POLICY_SCHEMA_VERSION
        || !record.scope.is_valid()
        || record.acknowledgment.schema_version != super::POLICY_SCHEMA_VERSION
        || record.acknowledgment.address != record.address
        || record.acknowledgment.scope != record.scope
        || record.acknowledgment.remote_account_id != record.remote_account_id
        || record.acknowledgment.account_generation != record.account_generation
        || record.acknowledgment.revision != record.revision
        || record.acknowledgment.digest != record.digest
        || record.acknowledgment.state != record.state
        || record.domain
            != address
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or_default()
    {
        return Err(RecipientPolicyError::TemporaryFailure);
    }
    Ok(record)
}

fn ensure_durable(store: &Store) -> Result<(), RecipientPolicyError> {
    if !durable_backend(store.is_none(), store.is_ephemeral()) {
        Err(RecipientPolicyError::TemporaryFailure)
    } else {
        Ok(())
    }
}

fn durable_backend(is_none: bool, is_ephemeral: bool) -> bool {
    !is_none && !is_ephemeral
}

fn record_key(address: &str) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: format!("mail.masked-recipient-policy.v1/record/{address}").into_bytes(),
    })
}

fn revision_key(address: &str) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: format!("mail.masked-recipient-policy.v1/revision/{address}").into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail_capabilities::TenantServerScope;
    use std::{collections::VecDeque, future::ready};

    const ADDRESS: &str = "masked@example.test";

    fn record(revision: u64) -> RecipientPolicyRecord {
        let scope = TenantServerScope {
            tenant_id: "tenant-a".to_string(),
            server_id: "server-a".to_string(),
            placement_generation: 3,
            server_generation: 2,
        };
        let digest = "a".repeat(64);
        let state = super::super::RecipientPolicyState::Reserved;
        let acknowledgment = RecipientPolicyAcknowledgment {
            schema_version: super::super::POLICY_SCHEMA_VERSION,
            address: ADDRESS.to_string(),
            scope: scope.clone(),
            remote_account_id: "account-a".to_string(),
            account_generation: 5,
            revision,
            digest: digest.clone(),
            state,
            acknowledged_at: 100,
        };
        RecipientPolicyRecord {
            schema_version: super::super::POLICY_SCHEMA_VERSION,
            address: ADDRESS.to_string(),
            scope,
            remote_account_id: "account-a".to_string(),
            account_generation: 5,
            domain: "example.test".to_string(),
            revision,
            state,
            disabled_by: None,
            expires_at: None,
            digest,
            acknowledgment,
        }
    }

    async fn load_pairs(
        address: &str,
        pairs: Vec<(Option<String>, Option<String>)>,
    ) -> (
        Result<Option<RecipientPolicyRecord>, RecipientPolicyError>,
        usize,
    ) {
        let mut values: VecDeque<Option<String>> = pairs
            .into_iter()
            .flat_map(|(record, revision)| [record, revision])
            .collect();
        let mut reads = 0;
        let result = load_record_with(address, |_| {
            reads += 1;
            ready(Ok(values.pop_front().expect("test read pair is complete")))
        })
        .await;
        (result, reads)
    }

    #[test]
    fn ephemeral_and_missing_stores_cannot_produce_durable_acknowledgments() {
        assert_eq!(
            ensure_durable(&Store::None),
            Err(RecipientPolicyError::TemporaryFailure)
        );
        assert!(!durable_backend(false, true));
    }

    #[tokio::test]
    async fn retries_mixed_record_and_revision_then_returns_a_consistent_pair() {
        let old = record(1);
        let current = record(2);
        let (loaded, reads) = load_pairs(
            ADDRESS,
            vec![
                (
                    Some(serde_json::to_string(&old).unwrap()),
                    Some("2".to_string()),
                ),
                (
                    Some(serde_json::to_string(&current).unwrap()),
                    Some("2".to_string()),
                ),
            ],
        )
        .await;

        assert_eq!(loaded, Ok(Some(current)));
        assert_eq!(reads, 4);
    }

    #[tokio::test]
    async fn retries_first_creation_with_only_the_revision_key_then_reads_the_record() {
        let current = record(1);
        let (loaded, reads) = load_pairs(
            ADDRESS,
            vec![
                (None, Some("1".to_string())),
                (
                    Some(serde_json::to_string(&current).unwrap()),
                    Some("1".to_string()),
                ),
            ],
        )
        .await;

        assert_eq!(loaded, Ok(Some(current)));
        assert_eq!(reads, 4);
    }

    #[tokio::test]
    async fn none_none_is_a_valid_absent_record() {
        let (loaded, reads) = load_pairs(ADDRESS, vec![(None, None)]).await;

        assert_eq!(loaded, Ok(None));
        assert_eq!(reads, 2);
    }

    #[tokio::test]
    async fn sustained_record_revision_churn_fails_after_three_pairs() {
        let pairs = (1..=MAX_RECORD_READ_ATTEMPTS as u64)
            .map(|revision| {
                (
                    Some(serde_json::to_string(&record(revision)).unwrap()),
                    Some((revision + 1).to_string()),
                )
            })
            .collect();
        let (loaded, reads) = load_pairs(ADDRESS, pairs).await;

        assert_eq!(loaded, Err(RecipientPolicyError::TemporaryFailure));
        assert_eq!(reads, MAX_RECORD_READ_ATTEMPTS * 2);
    }

    #[tokio::test]
    async fn malformed_record_revision_address_scope_and_ack_fail_without_retry() {
        let valid = record(1);
        let mut bad_ack = valid.clone();
        bad_ack.acknowledgment.digest = "b".repeat(64);
        let mut bad_address = valid.clone();
        bad_address.address = "INVALID".to_string();
        let mut bad_scope = valid.clone();
        bad_scope.scope.tenant_id.clear();
        bad_scope.acknowledgment.scope = bad_scope.scope.clone();

        let bad_records = [
            "{".to_string(),
            serde_json::to_string(&bad_ack).unwrap(),
            serde_json::to_string(&bad_address).unwrap(),
            serde_json::to_string(&bad_scope).unwrap(),
        ];
        for serialized in bad_records {
            let (loaded, reads) = load_pairs(
                ADDRESS,
                vec![
                    (Some(serialized), Some("1".to_string())),
                    (
                        Some(serde_json::to_string(&valid).unwrap()),
                        Some("1".to_string()),
                    ),
                ],
            )
            .await;
            assert_eq!(loaded, Err(RecipientPolicyError::TemporaryFailure));
            assert_eq!(reads, 2);
        }

        let (loaded, reads) = load_pairs(
            ADDRESS,
            vec![
                (
                    Some(serde_json::to_string(&valid).unwrap()),
                    Some("bad".to_string()),
                ),
                (
                    Some(serde_json::to_string(&valid).unwrap()),
                    Some("1".to_string()),
                ),
            ],
        )
        .await;
        assert_eq!(loaded, Err(RecipientPolicyError::TemporaryFailure));
        assert_eq!(reads, 2);
    }
}
