/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use super::*;
use registry::{schema::prelude::ObjectType, types::EnumImpl};
use std::future::Future;
use store::write::assert::AssertValue;
use store::write::{AssignedIds, MergeResult, PendingId, RegistryClass, ValueClass};

const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 1000;
const MAX_RESTORE_MAILBOXES: usize = 128;
const MAX_CLEANUP_CANDIDATES: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountLifecycleState {
    Live,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AccountLifecycleControl {
    scope: RecoveryScope,
    store_account_id: u32,
    state: AccountLifecycleState,
    pending_restores: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
struct CaptureLifecycleControl {
    scope: Option<RecoveryScope>,
    capture_id: String,
    lock: Option<LifecycleLock>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum LifecycleLock {
    Restore { operation_id: String },
    Purge { operation_id: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountLifecycleSummary {
    pub scope: RecoveryScope,
    pub state: AccountLifecycleState,
    pub pending_restores: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleOperationSummary {
    pub kind: LifecycleOperationKind,
    pub operation_id: String,
    pub pending: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LifecycleOperationKind {
    Restore,
    Purge,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleSummary {
    pub capture_id: String,
    pub capture_state: Option<ManifestState>,
    pub deleted_at: Option<u64>,
    pub active_operation: Option<LifecycleOperationSummary>,
    pub tombstone: Option<PurgeTombstone>,
}

#[derive(Clone, Debug)]
pub struct RestoreRequest {
    pub source: VerifiedAccountMapping,
    pub destination: VerifiedAccountMapping,
    pub capture_id: String,
    pub operation_id: String,
    pub actor: String,
    pub reason: String,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativeAccountAssertion {
    account_id: u32,
    registry_revision: u64,
}

impl AuthoritativeAccountAssertion {
    /// Construct from the revision hash of registry Account `account_id`, read from the same Store.
    pub fn new(account_id: u32, registry_revision: u64) -> Result<Self> {
        if account_id == 0 {
            return Err(RecoveryError::Invalid("authoritative account assertion"));
        }
        Ok(Self {
            account_id,
            registry_revision,
        })
    }

    pub fn append_to(&self, batch: &mut BatchBuilder) {
        batch.with_account_id(0).assert_value(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Account.to_id(),
                item_id: u64::from(self.account_id),
            }),
            AssertValue::Hash(self.registry_revision),
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMailboxUid {
    pub mailbox_id: u32,
    pub uid: PendingId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRestoreIds {
    document_id: PendingId,
    thread_id: PendingId,
    mailbox_uids: Vec<PendingMailboxUid>,
}

impl PendingRestoreIds {
    pub fn new(
        document_id: PendingId,
        thread_id: PendingId,
        mailbox_uids: Vec<PendingMailboxUid>,
    ) -> Result<Self> {
        if document_id.slot().is_none()
            || matches!(thread_id, PendingId::Assigned(0))
            || mailbox_uids.is_empty()
            || mailbox_uids.len() > MAX_RESTORE_MAILBOXES
            || mailbox_uids.iter().any(|uid| uid.mailbox_id == 0)
            || mailbox_uids.iter().any(|uid| uid.uid.slot().is_none())
        {
            return Err(RecoveryError::Invalid("pending restore slots"));
        }
        for (index, uid) in mailbox_uids.iter().enumerate() {
            if mailbox_uids[..index]
                .iter()
                .any(|previous| previous.mailbox_id == uid.mailbox_id)
            {
                return Err(RecoveryError::Invalid("duplicate restore mailbox"));
            }
        }
        Ok(Self {
            document_id,
            thread_id,
            mailbox_uids,
        })
    }

    pub fn document_id(&self) -> PendingId {
        self.document_id
    }

    pub fn thread_id(&self) -> PendingId {
        self.thread_id
    }

    pub fn mailbox_uids(&self) -> &[PendingMailboxUid] {
        &self.mailbox_uids
    }

    fn resolve(&self, ids: &AssignedIds) -> Option<RestoreResult> {
        let result = RestoreResult {
            document_id: self.document_id.resolve(ids),
            thread_id: self.thread_id.resolve(ids),
            mailbox_uids: self
                .mailbox_uids
                .iter()
                .map(|uid| RestoredMailboxUid {
                    mailbox_id: uid.mailbox_id,
                    uid: uid.uid.resolve(ids),
                })
                .collect(),
        };
        (result.document_id != 0
            && result.thread_id != 0
            && result.mailbox_uids.iter().all(|uid| uid.uid != 0))
        .then_some(result)
    }
}

pub trait RestoreImporter: Send + Sync {
    type Pending: Send;

    /// Read registry Account from the same transactional Store and return its exact revision
    /// assertion. Return an error if that same-store relationship cannot be verified.
    fn live_account_assertion<'a>(
        &'a self,
        destination: &'a VerifiedAccountMapping,
    ) -> impl Future<Output = Result<AuthoritativeAccountAssertion>> + Send;

    /// Decode the original payload with `source_keys.decode_bounded` before parsing RFC822, then
    /// append email_ingest_into operations. Never use cached account() or email_ingest.
    fn prepare<'a>(
        &'a self,
        payload: &'a [u8],
        source_keys: &'a BlobKeyring,
        manifest: &'a Manifest,
        destination: &'a VerifiedAccountMapping,
        batch: &'a mut BatchBuilder,
    ) -> impl Future<Output = Result<(Self::Pending, PendingRestoreIds)>> + Send;

    fn committed<'a>(
        &'a self,
        pending: Self::Pending,
        assigned_ids: &'a AssignedIds,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreResult {
    pub document_id: u32,
    pub thread_id: u32,
    pub mailbox_uids: Vec<RestoredMailboxUid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoredMailboxUid {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RestoreJobState {
    Pending,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RestoreJob {
    scope: RecoveryScope,
    capture_id: String,
    operation_id: String,
    store_account_id: u32,
    actor: String,
    reason: String,
    requested_at: u64,
    state: RestoreJobState,
    result: Option<RestoreResult>,
    failure_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RestoreOutcome {
    Pending,
    Completed { result: RestoreResult },
    Failed { code: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeTombstone {
    pub scope: RecoveryScope,
    pub capture_id: String,
    pub operation_id: String,
    pub actor: String,
    pub reason: String,
    #[serde(default)]
    pub deleted_at: Option<u64>,
    pub purged_at: u64,
}

#[derive(Clone, Debug)]
pub struct PurgeRequest {
    pub scope: RecoveryScope,
    pub capture_id: String,
    pub operation_id: String,
    pub actor: String,
    pub reason: String,
    pub now: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PurgeJob {
    scope: RecoveryScope,
    capture_id: String,
    operation_id: String,
    actor: String,
    reason: String,
    requested_at: u64,
    cleanup: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PurgeOutcome {
    Purged { tombstone: PurgeTombstone },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupReport {
    pub examined: usize,
    pub skipped: usize,
    pub purged_capture_ids: Vec<String>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl RecoveryEngine {
    pub async fn activate_account(&self, account: &VerifiedAccountMapping) -> Result<()> {
        let scope = account.scope();
        if !valid_recovery_scope(scope) || account.store_account_id() == 0 {
            return Err(RecoveryError::Invalid("account lifecycle binding"));
        }
        let key = account_lifecycle_key(scope)?;
        let index_key = account_capture_index_key(scope)?;
        let index_current = self.account_capture_index(scope).await?;
        let current = self.read::<AccountLifecycleControl>(&key).await?;
        match current {
            Some((control, _))
                if control.scope == *scope
                    && control.store_account_id == account.store_account_id()
                    && control.state == AccountLifecycleState::Live =>
            {
                index_current.map(|_| ()).ok_or(RecoveryError::Conflict(
                    "live account is missing its capture index",
                ))
            }
            Some((control, _)) if control.state == AccountLifecycleState::Retired => {
                Err(RecoveryError::Conflict("account generation is retired"))
            }
            Some(_) => Err(RecoveryError::Conflict(
                "account lifecycle binding mismatch",
            )),
            None => {
                let control = AccountLifecycleControl {
                    scope: scope.clone(),
                    store_account_id: account.store_account_id(),
                    state: AccountLifecycleState::Live,
                    pending_restores: 0,
                };
                let (index, index_bytes) = index_current.unwrap_or_else(|| {
                    (
                        ScopeCaptureIndex {
                            scope: scope.clone(),
                            captures: Vec::new(),
                        },
                        Vec::new(),
                    )
                });
                let mut batch = BatchBuilder::new();
                self.append_cas(&mut batch, &key, None, &control)?;
                self.append_cas(
                    &mut batch,
                    &index_key,
                    (!index_bytes.is_empty()).then_some(&index_bytes),
                    &index,
                )?;
                ensure_single_segment(&batch)?;
                self.metadata.write_batch(&mut batch).await?;
                Ok(())
            }
        }
    }

    pub async fn retire_account(&self, scope: &RecoveryScope) -> Result<()> {
        if !valid_recovery_scope(scope) {
            return Err(RecoveryError::Invalid("account lifecycle scope"));
        }
        let key = account_lifecycle_key(scope)?;
        let (mut control, previous) = self
            .read::<AccountLifecycleControl>(&key)
            .await?
            .ok_or(RecoveryError::Invalid("account lifecycle is not activated"))?;
        if control.scope != *scope {
            return Err(RecoveryError::Conflict("account lifecycle scope mismatch"));
        }
        if control.state == AccountLifecycleState::Retired {
            return Ok(());
        }
        if control.pending_restores != 0 {
            return Err(RecoveryError::InProgress);
        }
        control.state = AccountLifecycleState::Retired;
        self.cas_write(&key, Some(&previous), &control).await
    }

    pub async fn account_lifecycle_status(
        &self,
        scope: &RecoveryScope,
    ) -> Result<Option<AccountLifecycleSummary>> {
        if !valid_recovery_scope(scope) {
            return Err(RecoveryError::Invalid("account lifecycle scope"));
        }
        let key = account_lifecycle_key(scope)?;
        Ok(self
            .read::<AccountLifecycleControl>(&key)
            .await?
            .map(|(control, _)| AccountLifecycleSummary {
                scope: control.scope,
                state: control.state,
                pending_restores: control.pending_restores,
            }))
    }

    pub async fn lifecycle_summary(
        &self,
        scope: &RecoveryScope,
        capture_id: &str,
    ) -> Result<Option<LifecycleSummary>> {
        validate_capture_id(capture_id)?;
        if !valid_recovery_scope(scope) {
            return Err(RecoveryError::Invalid("lifecycle scope"));
        }
        let manifest_key = scoped_key(b"manifest", scope, capture_id)?;
        let control_key = capture_lifecycle_key(scope, capture_id)?;
        let tombstone_key = scoped_key(b"tombstone", scope, capture_id)?;
        let manifest = self.read::<Manifest>(&manifest_key).await?;
        let control = self
            .read::<CaptureLifecycleControl>(&control_key)
            .await?
            .map(|(record, _)| record);
        let tombstone = self
            .read::<PurgeTombstone>(&tombstone_key)
            .await?
            .map(|(record, _)| record);
        if manifest.is_none() && control.is_none() && tombstone.is_none() {
            return Ok(None);
        }
        let active_operation = control.and_then(|record| {
            record.lock.map(|lock| match lock {
                LifecycleLock::Restore { operation_id } => LifecycleOperationSummary {
                    kind: LifecycleOperationKind::Restore,
                    operation_id,
                    pending: true,
                },
                LifecycleLock::Purge { operation_id } => LifecycleOperationSummary {
                    kind: LifecycleOperationKind::Purge,
                    operation_id,
                    pending: true,
                },
            })
        });
        Ok(Some(LifecycleSummary {
            capture_id: capture_id.to_string(),
            capture_state: manifest
                .as_ref()
                .map(|(manifest, _)| manifest.state.clone()),
            deleted_at: manifest
                .as_ref()
                .and_then(|(manifest, _)| manifest.deleted_at),
            active_operation,
            tombstone,
        }))
    }

    pub async fn restore<I: RestoreImporter>(
        &self,
        request: RestoreRequest,
        source_keys: &BlobKeyring,
        importer: &I,
    ) -> Result<RestoreOutcome> {
        validate_restore_request(&request)?;
        if request.source.scope() != request.destination.scope()
            || request.source.store_account_id() != request.destination.store_account_id()
        {
            return Err(RecoveryError::Invalid(
                "cross-account restore is not supported",
            ));
        }
        let scope = request.source.scope().clone();
        let job_key = operation_key(
            b"restore-job",
            &scope,
            &request.capture_id,
            &request.operation_id,
        )?;
        let existing_job = self.read::<RestoreJob>(&job_key).await?;
        let resuming = if let Some((job, _)) = &existing_job {
            let replay = replay_restore(job, &request)?;
            if job.state != RestoreJobState::Pending {
                return Ok(replay);
            }
            true
        } else {
            false
        };

        let manifest_key = scoped_key(b"manifest", &scope, &request.capture_id)?;
        let (manifest, manifest_bytes) = self
            .read::<Manifest>(&manifest_key)
            .await?
            .ok_or(RecoveryError::NotFound)?;
        if manifest.scope != scope
            || manifest.source_account_id != request.source.store_account_id()
            || manifest.capture_id != request.capture_id
            || manifest.state != ManifestState::Preserved
        {
            return Err(RecoveryError::Conflict("capture is not restorable"));
        }
        let account_key = account_lifecycle_key(&scope)?;
        let (mut account, account_bytes) = self
            .read::<AccountLifecycleControl>(&account_key)
            .await?
            .ok_or(RecoveryError::Invalid(
                "live account binding is not activated",
            ))?;
        if account.scope != scope
            || account.store_account_id != request.destination.store_account_id()
            || account.state != AccountLifecycleState::Live
        {
            return Err(RecoveryError::Conflict("account generation is not live"));
        }
        if resuming {
            if account.pending_restores == 0 {
                return Err(RecoveryError::Conflict(
                    "pending restore gate is inconsistent",
                ));
            }
        } else {
            account.pending_restores = account
                .pending_restores
                .checked_add(1)
                .ok_or(RecoveryError::Conflict("pending restore count overflow"))?;
        }

        let lifecycle_key = capture_lifecycle_key(&scope, &request.capture_id)?;
        let (mut lifecycle, lifecycle_bytes) =
            match self.read::<CaptureLifecycleControl>(&lifecycle_key).await? {
                Some((record, bytes)) => (record, Some(bytes)),
                None => (
                    CaptureLifecycleControl {
                        scope: Some(scope.clone()),
                        capture_id: request.capture_id.clone(),
                        lock: None,
                    },
                    None,
                ),
            };
        if lifecycle
            .scope
            .as_ref()
            .is_some_and(|stored| stored != &scope)
            || lifecycle.capture_id != request.capture_id
        {
            return Err(RecoveryError::Conflict("capture lifecycle scope mismatch"));
        }
        if let Some(lock) = &lifecycle.lock {
            match lock {
                LifecycleLock::Restore { operation_id }
                    if operation_id == &request.operation_id && resuming => {}
                _ => return Err(RecoveryError::Conflict("capture lifecycle is busy")),
            }
        } else if resuming {
            return Err(RecoveryError::Conflict("pending restore lock is missing"));
        }
        let job = existing_job.map(|(job, _)| job).unwrap_or(RestoreJob {
            scope: scope.clone(),
            capture_id: request.capture_id.clone(),
            operation_id: request.operation_id.clone(),
            store_account_id: request.destination.store_account_id(),
            actor: request.actor.clone(),
            reason: request.reason.clone(),
            requested_at: request.now,
            state: RestoreJobState::Pending,
            result: None,
            failure_code: None,
        });
        if !resuming {
            lifecycle.scope = Some(scope.clone());
            lifecycle.capture_id = request.capture_id.clone();
            lifecycle.lock = Some(LifecycleLock::Restore {
                operation_id: request.operation_id.clone(),
            });
            let mut reservation = BatchBuilder::new();
            append_assert(&mut reservation, &account_key, Some(&account_bytes))?;
            append_assert_optional(&mut reservation, &lifecycle_key, lifecycle_bytes.as_ref())?;
            append_assert(&mut reservation, &manifest_key, Some(&manifest_bytes))?;
            reservation
                .with_account_id(0)
                .assert_value(value_class(&job_key), ());
            reservation.with_account_id(0).set(
                value_class(&account_key),
                encode_record(&account, next_record_revision(Some(&account_bytes))?)?,
            );
            reservation.with_account_id(0).set(
                value_class(&lifecycle_key),
                encode_record(
                    &lifecycle,
                    next_record_revision(lifecycle_bytes.as_deref())?,
                )?,
            );
            reservation
                .with_account_id(0)
                .set(value_class(&job_key), encode_record(&job, 1)?);
            ensure_single_segment(&reservation)?;
            if let Err(error) = self.metadata.write_batch(&mut reservation).await {
                if let Some((stored, _)) = self.read::<RestoreJob>(&job_key).await? {
                    return replay_restore(&stored, &request);
                }
                return Err(error.into());
            }
        }

        let (current_account, current_account_bytes) = self
            .read::<AccountLifecycleControl>(&account_key)
            .await?
            .ok_or(RecoveryError::Invalid("account lifecycle disappeared"))?;
        let (current_lifecycle, current_lifecycle_bytes) = self
            .read::<CaptureLifecycleControl>(&lifecycle_key)
            .await?
            .ok_or(RecoveryError::Conflict("capture lifecycle disappeared"))?;
        let (current_job, current_job_bytes) = self
            .read::<RestoreJob>(&job_key)
            .await?
            .ok_or(RecoveryError::Conflict("restore job disappeared"))?;
        if current_job.state != RestoreJobState::Pending {
            return replay_restore(&current_job, &request);
        }
        if current_account.state != AccountLifecycleState::Live
            || current_account.pending_restores == 0
            || current_account.store_account_id != request.destination.store_account_id()
            || current_lifecycle.lock
                != Some(LifecycleLock::Restore {
                    operation_id: request.operation_id.clone(),
                })
            || current_job.scope != scope
            || current_job.capture_id != request.capture_id
            || current_job.operation_id != request.operation_id
        {
            return Err(RecoveryError::Conflict("restore reservation changed"));
        }
        let mut batch = BatchBuilder::new();
        append_assert(&mut batch, &job_key, Some(&current_job_bytes))?;
        append_assert(&mut batch, &account_key, Some(&current_account_bytes))?;
        append_assert(&mut batch, &lifecycle_key, Some(&current_lifecycle_bytes))?;
        append_assert(&mut batch, &manifest_key, Some(&manifest_bytes))?;
        let live_account_assertion =
            match importer.live_account_assertion(&request.destination).await {
                Ok(assertion) if assertion.account_id == request.destination.store_account_id() => {
                    assertion
                }
                Ok(_) => {
                    self.abort_restore(&request, "account_assertion_mismatch")
                        .await?;
                    return Err(RecoveryError::Conflict("account assertion mismatch"));
                }
                Err(error) => {
                    self.abort_restore(&request, "account_unavailable").await?;
                    return Err(error);
                }
            };
        live_account_assertion.append_to(&mut batch);

        let payload = match self.get_payload(&scope, &request.capture_id).await {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                self.abort_restore(&request, "payload_unavailable").await?;
                return Err(RecoveryError::BlobMissing);
            }
            Err(error) => {
                self.abort_restore(&request, "payload_unavailable").await?;
                return Err(error);
            }
        };
        let (pending, pending_ids) = match importer
            .prepare(
                &payload,
                source_keys,
                &manifest,
                &request.destination,
                &mut batch,
            )
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                self.abort_restore(&request, "import_prepare_failed")
                    .await?;
                return Err(error);
            }
        };
        if batch.has_commit_points() || batch.is_large_batch() {
            self.abort_restore(&request, "restore_batch_too_large")
                .await?;
            return Err(RecoveryError::BatchTooLarge);
        }
        let receipt_ids = pending_ids.clone();
        let receipt_scope = scope.clone();
        let receipt_capture = request.capture_id.clone();
        let receipt_operation = request.operation_id.clone();
        let mut completed_account = current_account;
        completed_account.pending_restores -= 1;
        let mut completed_lifecycle = current_lifecycle;
        completed_lifecycle.lock = None;
        batch
            .with_account_id(0)
            .set(
                value_class(&account_key),
                encode_record(
                    &completed_account,
                    next_record_revision(Some(&current_account_bytes))?,
                )?,
            )
            .with_account_id(0)
            .set(
                value_class(&lifecycle_key),
                encode_record(
                    &completed_lifecycle,
                    next_record_revision(Some(&current_lifecycle_bytes))?,
                )?,
            );
        let job_class = value_class(&job_key);
        let expected_revision = record_revision(&current_job_bytes)?;
        batch
            .with_account_id(0)
            .merge_fnc(job_class, move |assigned, previous| {
                let Some(previous) = previous else {
                    return Err(trc::StoreEvent::AssertValueFailed.into_err());
                };
                let mut stored: RestoreJob =
                    serde_json::from_slice(&previous[..previous.len().saturating_sub(8)])
                        .map_err(|_| trc::StoreEvent::DataCorruption.into_err())?;
                let stored_revision = stored_record_revision(previous)?;
                if stored_revision != expected_revision
                    || stored.scope != receipt_scope
                    || stored.capture_id != receipt_capture
                    || stored.operation_id != receipt_operation
                    || stored.state != RestoreJobState::Pending
                {
                    return Err(trc::StoreEvent::AssertValueFailed.into_err());
                }
                stored.state = RestoreJobState::Completed;
                stored.result = Some(
                    receipt_ids
                        .resolve(assigned)
                        .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())?,
                );
                stored.failure_code = None;
                let revision = stored_revision
                    .checked_add(1)
                    .filter(|revision| *revision <= MAX_SAFE_INTEGER)
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())?;
                Ok(MergeResult::Update(encode_record_for_store(
                    &stored, revision,
                )?))
            });
        if batch.has_commit_points() || batch.is_large_batch() {
            self.abort_restore(&request, "restore_batch_too_large")
                .await?;
            return Err(RecoveryError::BatchTooLarge);
        }
        let assigned_ids = match self.metadata.write_batch(&mut batch).await {
            Ok(ids) => ids,
            Err(error) => {
                if let Some((stored, _)) = self.read::<RestoreJob>(&job_key).await? {
                    if let RestoreOutcome::Completed { result } = replay_restore(&stored, &request)?
                    {
                        return Ok(RestoreOutcome::Completed { result });
                    }
                }
                return Err(error.into());
            }
        };
        let result = pending_ids
            .resolve(&assigned_ids)
            .ok_or(RecoveryError::Conflict("assigned restore IDs are invalid"))?;
        importer.committed(pending, &assigned_ids).await;
        Ok(RestoreOutcome::Completed { result })
    }

    async fn abort_restore(&self, request: &RestoreRequest, failure_code: &str) -> Result<()> {
        let scope = request.source.scope();
        let account_key = account_lifecycle_key(scope)?;
        let lifecycle_key = capture_lifecycle_key(scope, &request.capture_id)?;
        let job_key = operation_key(
            b"restore-job",
            scope,
            &request.capture_id,
            &request.operation_id,
        )?;
        let (mut account, account_bytes) = self
            .read::<AccountLifecycleControl>(&account_key)
            .await?
            .ok_or(RecoveryError::Conflict("restore account gate disappeared"))?;
        let (mut lifecycle, lifecycle_bytes) = self
            .read::<CaptureLifecycleControl>(&lifecycle_key)
            .await?
            .ok_or(RecoveryError::Conflict("restore lifecycle disappeared"))?;
        let (mut job, job_bytes) = self
            .read::<RestoreJob>(&job_key)
            .await?
            .ok_or(RecoveryError::Conflict("restore job disappeared"))?;
        if job.state == RestoreJobState::Failed {
            return Ok(());
        }
        if job.state != RestoreJobState::Pending
            || lifecycle.lock
                != Some(LifecycleLock::Restore {
                    operation_id: request.operation_id.clone(),
                })
            || account.pending_restores == 0
        {
            return Err(RecoveryError::Conflict(
                "restore abort lost its reservation",
            ));
        }
        account.pending_restores -= 1;
        lifecycle.lock = None;
        job.state = RestoreJobState::Failed;
        job.result = None;
        job.failure_code = Some(failure_code.to_string());
        let mut batch = BatchBuilder::new();
        append_assert(&mut batch, &account_key, Some(&account_bytes))?;
        append_assert(&mut batch, &lifecycle_key, Some(&lifecycle_bytes))?;
        append_assert(&mut batch, &job_key, Some(&job_bytes))?;
        batch
            .with_account_id(0)
            .set(
                value_class(&account_key),
                encode_record(&account, next_record_revision(Some(&account_bytes))?)?,
            )
            .with_account_id(0)
            .set(
                value_class(&lifecycle_key),
                encode_record(&lifecycle, next_record_revision(Some(&lifecycle_bytes))?)?,
            )
            .with_account_id(0)
            .set(
                value_class(&job_key),
                encode_record(&job, next_record_revision(Some(&job_bytes))?)?,
            );
        ensure_single_segment(&batch)?;
        self.metadata.write_batch(&mut batch).await?;
        Ok(())
    }

    pub async fn purge(&self, request: PurgeRequest) -> Result<PurgeOutcome> {
        validate_purge_request(&request)?;
        self.purge_internal(request, false, None).await
    }

    pub async fn cleanup_expired(
        &self,
        scope: &RecoveryScope,
        now: u64,
        grace_seconds: u64,
        limit: usize,
        after_capture_id: Option<&str>,
    ) -> Result<CleanupReport> {
        if !valid_recovery_scope(scope)
            || now == 0
            || now > MAX_SAFE_INTEGER
            || grace_seconds == 0
            || grace_seconds > MAX_SAFE_INTEGER
            || limit == 0
            || limit > MAX_CLEANUP_CANDIDATES
        {
            return Err(RecoveryError::Invalid("staging cleanup bounds"));
        }
        if let Some(cursor) = after_capture_id {
            validate_capture_id(cursor)?;
        }
        let (index, _) = self.required_account_capture_index(scope).await?;
        if index.captures.len() > MAX_ITEMS_PER_SCOPE {
            return Err(RecoveryError::Conflict(
                "account capture index exceeds capture bound",
            ));
        }
        let start = after_capture_id.map_or(0, |cursor| {
            index
                .captures
                .partition_point(|capture_id| capture_id.as_str() <= cursor)
        });
        let end = start.saturating_add(limit).min(index.captures.len());
        let candidates = index.captures[start..end].to_vec();
        let has_more = end < index.captures.len();
        let next_cursor = has_more.then(|| candidates.last().cloned()).flatten();
        let mut report = CleanupReport {
            examined: 0,
            skipped: 0,
            purged_capture_ids: Vec::new(),
            next_cursor,
            has_more,
        };
        for capture_id in candidates {
            report.examined += 1;
            let manifest_key = scoped_key(b"manifest", scope, &capture_id)?;
            let Some((manifest, _)) = self.read::<Manifest>(&manifest_key).await? else {
                report.skipped += 1;
                continue;
            };
            let cleanup_operation = cleanup_operation_id(&capture_id);
            let pending_cleanup = manifest.state == ManifestState::Purging
                && self
                    .read::<CaptureLifecycleControl>(&capture_lifecycle_key(scope, &capture_id)?)
                    .await?
                    .is_some_and(|(control, _)| {
                        control.lock
                            == Some(LifecycleLock::Purge {
                                operation_id: cleanup_operation.clone(),
                            })
                    });
            if !pending_cleanup {
                let eligible_at = manifest
                    .created_at
                    .checked_add(grace_seconds)
                    .ok_or(RecoveryError::Invalid("cleanup grace overflow"))?;
                let old_staging = manifest.state == ManifestState::Staging && eligible_at <= now;
                let expired_preserved = manifest.state == ManifestState::Preserved
                    && manifest.deleted_at.is_some()
                    && manifest.expires_at <= now;
                if manifest.scope != *scope || !(old_staging || expired_preserved) {
                    report.skipped += 1;
                    continue;
                }
                let hold_key = scoped_key(b"hold", scope, "")?;
                let Some((hold, _)) = self.read::<HoldControl>(&hold_key).await? else {
                    report.skipped += 1;
                    continue;
                };
                if hold.scope != *scope || hold.active {
                    report.skipped += 1;
                    continue;
                }
            }
            let request = PurgeRequest {
                scope: scope.clone(),
                capture_id: capture_id.clone(),
                operation_id: cleanup_operation,
                actor: "message-recovery-cleanup".to_string(),
                reason: "expired verified staging copy cleanup".to_string(),
                now,
            };
            match self
                .purge_internal(request, true, Some(grace_seconds))
                .await
            {
                Ok(PurgeOutcome::Purged { .. }) => report.purged_capture_ids.push(capture_id),
                Err(
                    RecoveryError::Conflict(_) | RecoveryError::Held | RecoveryError::InProgress,
                ) => {
                    report.skipped += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    }

    async fn purge_internal(
        &self,
        request: PurgeRequest,
        cleanup: bool,
        grace_seconds: Option<u64>,
    ) -> Result<PurgeOutcome> {
        let scope = &request.scope;
        let tombstone_key = scoped_key(b"tombstone", scope, &request.capture_id)?;
        if let Some((tombstone, _)) = self.read::<PurgeTombstone>(&tombstone_key).await? {
            return replay_purge(&tombstone, &request);
        }
        let job_key = operation_key(
            b"purge-job",
            scope,
            &request.capture_id,
            &request.operation_id,
        )?;
        let existing_job = self.read::<PurgeJob>(&job_key).await?;
        if let Some((job, _)) = &existing_job {
            if !purge_job_matches(job, &request, cleanup) {
                return Err(RecoveryError::Conflict("purge operation identifier reused"));
            }
        } else {
            let manifest_key = scoped_key(b"manifest", scope, &request.capture_id)?;
            let (mut manifest, manifest_bytes) = self
                .read::<Manifest>(&manifest_key)
                .await?
                .ok_or(RecoveryError::NotFound)?;
            if manifest.scope != request.scope || manifest.capture_id != request.capture_id {
                return Err(RecoveryError::Conflict("purge capture scope mismatch"));
            }
            let (index, _) = self.required_account_capture_index(scope).await?;
            if !index.captures.contains(&request.capture_id) {
                return Err(RecoveryError::Conflict(
                    "capture missing from account index",
                ));
            }
            if cleanup {
                let grace = grace_seconds.ok_or(RecoveryError::Invalid("cleanup grace"))?;
                let eligible_at = manifest
                    .created_at
                    .checked_add(grace)
                    .ok_or(RecoveryError::Invalid("cleanup grace overflow"))?;
                let old_staging =
                    manifest.state == ManifestState::Staging && eligible_at <= request.now;
                let expired_preserved = manifest.state == ManifestState::Preserved
                    && manifest.deleted_at.is_some()
                    && manifest.expires_at <= request.now;
                if !(old_staging || expired_preserved) {
                    return Err(RecoveryError::Conflict(
                        "staging capture is not cleanup eligible",
                    ));
                }
            } else if manifest.state != ManifestState::Preserved {
                return Err(RecoveryError::Conflict("capture is not purgeable"));
            }
            let hold_key = scoped_key(b"hold", scope, "")?;
            let (mut hold, hold_bytes) = self
                .read::<HoldControl>(&hold_key)
                .await?
                .ok_or(RecoveryError::Invalid("hold state not synchronized"))?;
            if hold.scope != request.scope || hold.active {
                return Err(RecoveryError::Held);
            }
            if hold.pending_purges != 0 {
                return Err(RecoveryError::InProgress);
            }
            hold.pending_purges = hold
                .pending_purges
                .checked_add(1)
                .ok_or(RecoveryError::Conflict("pending purge count overflow"))?;
            let lifecycle_key = capture_lifecycle_key(scope, &request.capture_id)?;
            let (mut lifecycle, lifecycle_bytes) =
                match self.read::<CaptureLifecycleControl>(&lifecycle_key).await? {
                    Some((record, bytes)) => (record, Some(bytes)),
                    None => (
                        CaptureLifecycleControl {
                            scope: Some(scope.clone()),
                            capture_id: request.capture_id.clone(),
                            lock: None,
                        },
                        None,
                    ),
                };
            if lifecycle
                .scope
                .as_ref()
                .is_some_and(|stored| stored != scope)
                || lifecycle.capture_id != request.capture_id
                || lifecycle.lock.is_some()
            {
                return Err(RecoveryError::Conflict("capture lifecycle is busy"));
            }
            lifecycle.scope = Some(scope.clone());
            lifecycle.capture_id = request.capture_id.clone();
            lifecycle.lock = Some(LifecycleLock::Purge {
                operation_id: request.operation_id.clone(),
            });
            manifest.state = ManifestState::Purging;
            let job = PurgeJob {
                scope: scope.clone(),
                capture_id: request.capture_id.clone(),
                operation_id: request.operation_id.clone(),
                actor: request.actor.clone(),
                reason: request.reason.clone(),
                requested_at: request.now,
                cleanup,
            };
            let ledger_key = quota_key(scope)?;
            let ledger = self
                .read::<ScopeLedger>(&ledger_key)
                .await?
                .ok_or(RecoveryError::Conflict("capture quota reservation missing"))?;
            if !ledger
                .0
                .captures
                .iter()
                .any(|capture| capture == &request.capture_id)
            {
                return Err(RecoveryError::Conflict("capture missing from quota ledger"));
            }
            let mut batch = BatchBuilder::new();
            append_assert(&mut batch, &manifest_key, Some(&manifest_bytes))?;
            append_assert(&mut batch, &hold_key, Some(&hold_bytes))?;
            append_assert_optional(&mut batch, &lifecycle_key, lifecycle_bytes.as_ref())?;
            append_assert(&mut batch, &ledger_key, Some(&ledger.1))?;
            append_assert(&mut batch, &job_key, None)?;
            append_assert(&mut batch, &tombstone_key, None)?;
            batch
                .with_account_id(0)
                .set(
                    value_class(&manifest_key),
                    encode_record(&manifest, next_record_revision(Some(&manifest_bytes))?)?,
                )
                .with_account_id(0)
                .set(
                    value_class(&hold_key),
                    encode_record(&hold, next_record_revision(Some(&hold_bytes))?)?,
                )
                .with_account_id(0)
                .set(
                    value_class(&lifecycle_key),
                    encode_record(
                        &lifecycle,
                        next_record_revision(lifecycle_bytes.as_deref())?,
                    )?,
                )
                .with_account_id(0)
                .set(value_class(&job_key), encode_record(&job, 1)?);
            ensure_single_segment(&batch)?;
            if let Err(error) = self.metadata.write_batch(&mut batch).await {
                if self.read::<PurgeJob>(&job_key).await?.is_none() {
                    return Err(error.into());
                }
            }
        }

        let manifest_key = scoped_key(b"manifest", scope, &request.capture_id)?;
        let Some((manifest, _)) = self.read::<Manifest>(&manifest_key).await? else {
            return Err(RecoveryError::Conflict("purging manifest disappeared"));
        };
        let lifecycle_key = capture_lifecycle_key(scope, &request.capture_id)?;
        let (lifecycle, _) = self
            .read::<CaptureLifecycleControl>(&lifecycle_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge lifecycle disappeared"))?;
        let (job, _) = self
            .read::<PurgeJob>(&job_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge job disappeared"))?;
        if manifest.state != ManifestState::Purging
            || lifecycle.lock
                != Some(LifecycleLock::Purge {
                    operation_id: request.operation_id.clone(),
                })
            || !purge_job_matches(&job, &request, cleanup)
        {
            return Err(RecoveryError::Conflict("purge reservation changed"));
        }
        self.blobs.delete_blob(&manifest.recovery_blob_key).await?;
        if self
            .blobs
            .get_raw_blob(&manifest.recovery_blob_key)
            .await?
            .is_some()
        {
            return Err(RecoveryError::BlobMismatch);
        }
        self.finish_purge(&request, &manifest, &job_key, &tombstone_key)
            .await
    }

    async fn finish_purge(
        &self,
        request: &PurgeRequest,
        manifest: &Manifest,
        job_key: &[u8],
        tombstone_key: &[u8],
    ) -> Result<PurgeOutcome> {
        let scope = &request.scope;
        let manifest_key = scoped_key(b"manifest", scope, &request.capture_id)?;
        let lifecycle_key = capture_lifecycle_key(scope, &request.capture_id)?;
        let hold_key = scoped_key(b"hold", scope, "")?;
        let ledger_key = quota_key(scope)?;
        let (current_manifest, manifest_bytes) = self
            .read::<Manifest>(&manifest_key)
            .await?
            .ok_or(RecoveryError::Conflict("purging manifest disappeared"))?;
        let (mut lifecycle, lifecycle_bytes) = self
            .read::<CaptureLifecycleControl>(&lifecycle_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge lifecycle disappeared"))?;
        let (mut hold, hold_bytes) = self
            .read::<HoldControl>(&hold_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge hold state disappeared"))?;
        let (mut ledger, ledger_bytes) = self
            .read::<ScopeLedger>(&ledger_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge ledger disappeared"))?;
        let index_key = account_capture_index_key(scope)?;
        let (mut index, index_bytes) = self.required_account_capture_index(scope).await?;
        let (job, job_bytes) = self
            .read::<PurgeJob>(job_key)
            .await?
            .ok_or(RecoveryError::Conflict("purge job disappeared"))?;
        if current_manifest.state != ManifestState::Purging
            || current_manifest.capture_id != manifest.capture_id
            || current_manifest.recovery_blob_key != manifest.recovery_blob_key
            || lifecycle.lock
                != Some(LifecycleLock::Purge {
                    operation_id: request.operation_id.clone(),
                })
            || hold.scope != *scope
            || hold.active
            || hold.pending_purges == 0
            || !purge_job_matches(&job, request, job.cleanup)
            || !ledger
                .captures
                .iter()
                .any(|capture| capture == &request.capture_id)
            || !index
                .captures
                .iter()
                .any(|capture| capture == &request.capture_id)
        {
            return Err(RecoveryError::Conflict("purge finalization state changed"));
        }
        let removed_count = ledger.captures.len();
        ledger
            .captures
            .retain(|capture| capture != &request.capture_id);
        if removed_count - ledger.captures.len() != 1 {
            return Err(RecoveryError::Conflict(
                "quota ledger capture count mismatch",
            ));
        }
        let index_capture_count = index.captures.len();
        index
            .captures
            .retain(|capture| capture != &request.capture_id);
        if index_capture_count - index.captures.len() != 1 {
            return Err(RecoveryError::Conflict(
                "account capture index count mismatch",
            ));
        }
        ledger.charged_bytes = ledger
            .charged_bytes
            .checked_sub(current_manifest.stored_size)
            .ok_or(RecoveryError::Conflict("quota ledger underflow"))?;
        hold.pending_purges -= 1;
        lifecycle.lock = None;
        #[cfg(test)]
        if self
            .purge_finalization_fault
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(RecoveryError::Conflict("injected purge finalization fault"));
        }
        let tombstone = PurgeTombstone {
            scope: scope.clone(),
            capture_id: request.capture_id.clone(),
            operation_id: request.operation_id.clone(),
            actor: request.actor.clone(),
            reason: request.reason.clone(),
            deleted_at: current_manifest.deleted_at,
            purged_at: request.now,
        };
        let mut batch = BatchBuilder::new();
        append_assert(&mut batch, &manifest_key, Some(&manifest_bytes))?;
        append_assert(&mut batch, &lifecycle_key, Some(&lifecycle_bytes))?;
        append_assert(&mut batch, &hold_key, Some(&hold_bytes))?;
        append_assert(&mut batch, &ledger_key, Some(&ledger_bytes))?;
        append_assert(&mut batch, &index_key, Some(&index_bytes))?;
        append_assert(&mut batch, job_key, Some(&job_bytes))?;
        append_assert(&mut batch, tombstone_key, None)?;
        batch
            .with_account_id(0)
            .clear(value_class(&manifest_key))
            .with_account_id(0)
            .clear(value_class(job_key))
            .with_account_id(0)
            .set(
                value_class(&lifecycle_key),
                encode_record(&lifecycle, next_record_revision(Some(&lifecycle_bytes))?)?,
            )
            .with_account_id(0)
            .set(
                value_class(&hold_key),
                encode_record(&hold, next_record_revision(Some(&hold_bytes))?)?,
            )
            .with_account_id(0)
            .set(
                value_class(&ledger_key),
                encode_record(&ledger, next_record_revision(Some(&ledger_bytes))?)?,
            )
            .with_account_id(0)
            .set(
                value_class(&index_key),
                encode_record(&index, next_record_revision(Some(&index_bytes))?)?,
            )
            .with_account_id(0)
            .set(value_class(tombstone_key), encode_record(&tombstone, 1)?);
        ensure_single_segment(&batch)?;
        self.metadata.write_batch(&mut batch).await?;
        Ok(PurgeOutcome::Purged { tombstone })
    }
}

fn account_lifecycle_key(scope: &RecoveryScope) -> Result<Vec<u8>> {
    scoped_key(b"account-lifecycle", scope, "")
}

fn capture_lifecycle_key(scope: &RecoveryScope, capture_id: &str) -> Result<Vec<u8>> {
    scoped_key(b"lifecycle", scope, capture_id)
}

fn operation_key(
    kind: &[u8],
    scope: &RecoveryScope,
    capture_id: &str,
    operation_id: &str,
) -> Result<Vec<u8>> {
    validate_capture_id(capture_id)?;
    validate_operation_id(operation_id)?;
    let suffix = hash_hex(format!("{capture_id}\0{operation_id}").as_bytes());
    scoped_key(kind, scope, &suffix)
}

fn validate_capture_id(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RecoveryError::Invalid("capture identifier"));
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_OPERATION_ID_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RecoveryError::Invalid("operation identifier"));
    }
    Ok(())
}

fn validate_actor_reason(actor: &str, reason: &str) -> Result<()> {
    if actor.is_empty()
        || actor.len() > MAX_ACTOR_BYTES
        || actor.trim() != actor
        || actor.bytes().any(|byte| byte.is_ascii_control())
        || reason.trim() != reason
        || reason.len() < 3
        || reason.len() > MAX_REASON_BYTES
        || reason.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RecoveryError::Invalid("actor or reason"));
    }
    Ok(())
}

fn validate_restore_request(request: &RestoreRequest) -> Result<()> {
    if !valid_recovery_scope(request.source.scope())
        || !valid_recovery_scope(request.destination.scope())
        || request.source.store_account_id() == 0
        || request.destination.store_account_id() == 0
        || request.now == 0
        || request.now > MAX_SAFE_INTEGER
    {
        return Err(RecoveryError::Invalid("restore request"));
    }
    validate_capture_id(&request.capture_id)?;
    validate_operation_id(&request.operation_id)?;
    validate_actor_reason(&request.actor, &request.reason)
}

fn validate_purge_request(request: &PurgeRequest) -> Result<()> {
    if !valid_recovery_scope(&request.scope) || request.now == 0 || request.now > MAX_SAFE_INTEGER {
        return Err(RecoveryError::Invalid("purge request"));
    }
    validate_capture_id(&request.capture_id)?;
    validate_operation_id(&request.operation_id)?;
    validate_actor_reason(&request.actor, &request.reason)
}

fn replay_restore(job: &RestoreJob, request: &RestoreRequest) -> Result<RestoreOutcome> {
    if job.scope != *request.source.scope()
        || job.capture_id != request.capture_id
        || job.operation_id != request.operation_id
        || job.store_account_id != request.destination.store_account_id()
        || job.actor != request.actor
        || job.reason != request.reason
    {
        return Err(RecoveryError::Conflict(
            "restore operation identifier reused",
        ));
    }
    match (&job.state, &job.result, &job.failure_code) {
        (RestoreJobState::Pending, None, None) => Ok(RestoreOutcome::Pending),
        (RestoreJobState::Completed, Some(result), None) => Ok(RestoreOutcome::Completed {
            result: result.clone(),
        }),
        (RestoreJobState::Failed, None, Some(code)) => {
            Ok(RestoreOutcome::Failed { code: code.clone() })
        }
        _ => Err(RecoveryError::Conflict("stored restore job is invalid")),
    }
}

fn replay_purge(tombstone: &PurgeTombstone, request: &PurgeRequest) -> Result<PurgeOutcome> {
    if tombstone.scope != request.scope
        || tombstone.capture_id != request.capture_id
        || tombstone.operation_id != request.operation_id
        || tombstone.actor != request.actor
        || tombstone.reason != request.reason
    {
        return Err(RecoveryError::Conflict("purge operation identifier reused"));
    }
    Ok(PurgeOutcome::Purged {
        tombstone: tombstone.clone(),
    })
}

fn purge_job_matches(job: &PurgeJob, request: &PurgeRequest, cleanup: bool) -> bool {
    job.scope == request.scope
        && job.capture_id == request.capture_id
        && job.operation_id == request.operation_id
        && job.actor == request.actor
        && job.reason == request.reason
        && job.cleanup == cleanup
}

fn cleanup_operation_id(capture_id: &str) -> String {
    format!("stage-cleanup-{capture_id}")
}

fn append_assert(batch: &mut BatchBuilder, key: &[u8], previous: Option<&Vec<u8>>) -> Result<()> {
    match previous {
        Some(bytes) => {
            batch
                .with_account_id(0)
                .assert_value(value_class(key), record_revision(bytes)?);
        }
        None => {
            batch.with_account_id(0).assert_value(value_class(key), ());
        }
    }
    Ok(())
}

fn append_assert_optional(
    batch: &mut BatchBuilder,
    key: &[u8],
    previous: Option<&Vec<u8>>,
) -> Result<()> {
    if previous.is_some() {
        append_assert(batch, key, previous)
    } else {
        batch.with_account_id(0).assert_value(value_class(key), ());
        Ok(())
    }
}

fn ensure_single_segment(batch: &BatchBuilder) -> Result<()> {
    if batch.has_commit_points() || batch.is_large_batch() {
        return Err(RecoveryError::BatchTooLarge);
    }
    Ok(())
}

fn stored_record_revision(bytes: &[u8]) -> trc::Result<u64> {
    bytes
        .get(bytes.len().saturating_sub(8)..)
        .filter(|tail| tail.len() == 8)
        .and_then(|tail| tail.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())
}

fn encode_record_for_store<T: Serialize>(value: &T, revision: u64) -> trc::Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| trc::StoreEvent::DataCorruption.into_err())?;
    if bytes.len() + 8 > MAX_RECORD_BYTES || revision == 0 || revision > MAX_SAFE_INTEGER {
        return Err(trc::StoreEvent::DataCorruption.into_err());
    }
    bytes.extend_from_slice(&revision.to_be_bytes());
    Ok(bytes)
}
