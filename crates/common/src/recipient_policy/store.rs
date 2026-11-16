// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    PolicyActor, RecipientPolicyAcknowledgment, RecipientPolicyCommand, RecipientPolicyError,
    RecipientPolicyRecord, apply_transition, valid_address, valid_digest, valid_domain,
};
use ::store::{
    Store, Subspace, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};

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
    let record = store
        .get_value_fresh::<String>(ValueKey::from(record_key(address)))
        .await
        .map_err(|_| RecipientPolicyError::TemporaryFailure)?;
    let revision = store
        .get_value_fresh::<String>(ValueKey::from(revision_key(address)))
        .await
        .map_err(|_| RecipientPolicyError::TemporaryFailure)?;
    match (record, revision) {
        (None, None) => Ok(None),
        (Some(record), Some(revision)) => {
            let record: RecipientPolicyRecord = serde_json::from_str(&record)
                .map_err(|_| RecipientPolicyError::TemporaryFailure)?;
            let revision = revision
                .parse::<u64>()
                .map_err(|_| RecipientPolicyError::TemporaryFailure)?;
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
                || record.revision != revision
                || record.acknowledgment.revision != revision
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
            Ok(Some(record))
        }
        _ => Err(RecipientPolicyError::TemporaryFailure),
    }
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

    #[test]
    fn ephemeral_and_missing_stores_cannot_produce_durable_acknowledgments() {
        assert_eq!(
            ensure_durable(&Store::None),
            Err(RecipientPolicyError::TemporaryFailure)
        );
        assert!(!durable_backend(false, true));
    }
}
