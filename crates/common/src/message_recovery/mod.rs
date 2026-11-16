/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::mail_capabilities::{ScopedMailAccount, TenantServerScope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use store::{
    BlobStore, Store, Subspace,
    write::assert::AssertValue,
    write::{
        AnyClass, AnyKey, BatchBuilder, ValueClass,
        blob_codec::{BlobEncryption, BlobFormat, BlobKeyring, BlobOpts},
    },
};
use types::{collection::Collection, field::Field};

mod lifecycle;
#[cfg(test)]
mod tests;
pub use lifecycle::*;

const PREFIX: &[u8] = b"abnormal-retention:v1:";
const MAX_RECORD_BYTES: usize = 1_048_576;
const MAX_BLOB_BYTES: usize = 134_217_728;
const MAX_ITEMS_PER_SCOPE: usize = 4096;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub enum RecoveryError {
    Store(trc::Error),
    Serialization(serde_json::Error),
    Invalid(&'static str),
    Conflict(&'static str),
    InProgress,
    NotFound,
    BatchTooLarge,
    Held,
    QuotaExceeded,
    BlobMissing,
    BlobMismatch,
}

impl From<trc::Error> for RecoveryError {
    fn from(value: trc::Error) -> Self {
        Self::Store(value)
    }
}

impl From<serde_json::Error> for RecoveryError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

pub type Result<T> = std::result::Result<T, RecoveryError>;

pub type RecoveryScope = ScopedMailAccount;

#[derive(Clone, Debug)]
pub struct VerifiedAccountMapping {
    scope: RecoveryScope,
    store_account_id: u32,
}

impl VerifiedAccountMapping {
    /// Construct only from the current, verified Mail account binding and its Stalwart account mapping.
    pub fn from_verified_binding(scope: RecoveryScope, store_account_id: u32) -> Result<Self> {
        if !valid_recovery_scope(&scope) || store_account_id == 0 {
            return Err(RecoveryError::Invalid("verified account binding"));
        }
        Ok(Self {
            scope,
            store_account_id,
        })
    }

    pub fn scope(&self) -> &RecoveryScope {
        &self.scope
    }

    pub fn store_account_id(&self) -> u32 {
        self.store_account_id
    }
}

fn valid_scope_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_server_scope(scope: &TenantServerScope) -> bool {
    scope.is_valid() && valid_scope_id(&scope.tenant_id) && valid_scope_id(&scope.server_id)
}

fn valid_recovery_scope(scope: &RecoveryScope) -> bool {
    scope.is_valid()
        && valid_scope_id(&scope.tenant_id)
        && valid_scope_id(&scope.server_id)
        && valid_scope_id(&scope.account_id)
}

fn server_scope(scope: &RecoveryScope) -> TenantServerScope {
    TenantServerScope {
        tenant_id: scope.tenant_id.clone(),
        server_id: scope.server_id.clone(),
        placement_generation: scope.placement_generation,
        server_generation: scope.server_generation,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub recovery_enabled: bool,
    pub recovery_days: Option<u16>,
    pub quota_bytes: Option<u64>,
    pub acknowledgment: String,
    pub reason: String,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        if !self.recovery_enabled {
            if self.recovery_days.is_some()
                || self.quota_bytes.is_some()
                || !self.acknowledgment.is_empty()
                || !self.reason.is_empty()
            {
                return Err(RecoveryError::Invalid(
                    "disabled policy must not retain enabled settings",
                ));
            }
            return Ok(());
        }
        if !matches!(self.recovery_days, Some(1..=3650))
            || !matches!(self.quota_bytes, Some(1..=MAX_SAFE_INTEGER))
            || self.acknowledgment.trim() != self.acknowledgment.as_str()
            || self.reason.trim() != self.reason.as_str()
            || self.acknowledgment.trim().len() < 12
            || self.acknowledgment.len() > 1000
            || self.reason.trim().len() < 3
            || self.reason.len() > 1000
            || self.acknowledgment.bytes().any(|b| b.is_ascii_control())
            || self.reason.bytes().any(|b| b.is_ascii_control())
        {
            return Err(RecoveryError::Invalid(
                "enabled policy requires bounded recovery days, quota, acknowledgment and reason",
            ));
        }
        Ok(())
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            recovery_enabled: false,
            recovery_days: None,
            quota_bytes: None,
            acknowledgment: String::new(),
            reason: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureMetadata {
    pub operation_id: String,
    pub cause: String,
    pub received_at: Option<u64>,
    pub folders: Vec<String>,
    pub keywords: Vec<String>,
}

impl CaptureMetadata {
    fn validate(&self) -> Result<()> {
        if self.operation_id.is_empty()
            || self.operation_id.len() > 128
            || self.operation_id.bytes().any(|b| b.is_ascii_control())
            || self.cause.is_empty()
            || self.cause.len() > 128
            || self.cause.bytes().any(|b| b.is_ascii_control())
            || self
                .received_at
                .is_some_and(|t| t == 0 || t > MAX_SAFE_INTEGER)
            || self.folders.len() > 128
            || self.keywords.len() > 64
            || self
                .folders
                .iter()
                .chain(&self.keywords)
                .any(|v| v.is_empty() || v.len() > 128 || v.bytes().any(|b| b.is_ascii_control()))
        {
            return Err(RecoveryError::Invalid("capture metadata"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManifestState {
    Copying,
    Staging,
    Preserved,
    Purging,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub capture_id: String,
    pub capture_operation_id: String,
    pub scope: RecoveryScope,
    pub state: ManifestState,
    pub original_blob_key: Vec<u8>,
    pub recovery_blob_key: Vec<u8>,
    pub source_account_id: u32,
    pub source_collection: u8,
    pub source_document_id: u32,
    pub source_revision: u64,
    pub created_at: u64,
    #[serde(default)]
    pub deleted_at: Option<u64>,
    pub expires_at: u64,
    pub cause: String,
    pub folders: Vec<String>,
    pub keywords: Vec<String>,
    pub received_at: Option<u64>,
    pub size: u64,
    pub stored_size: u64,
    pub sha256: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub hold_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRecord {
    pub scope: TenantServerScope,
    pub desired_revision: u64,
    pub digest: String,
    pub policy: Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HoldControl {
    scope: RecoveryScope,
    epoch: u64,
    active: bool,
    #[serde(default)]
    pending_purges: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
struct ScopeLedger {
    charged_bytes: u64,
    captures: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SourceAssertion {
    pub account_id: u32,
    pub collection: Collection,
    pub document_id: u32,
    /// Use Field::ARCHIVE and the MessageData change_id from the captured metadata.
    pub revision_property: u8,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct CaptureRequest {
    pub account: VerifiedAccountMapping,
    pub metadata: CaptureMetadata,
    pub original_blob_key: Vec<u8>,
    pub source: SourceAssertion,
    pub now: u64,
}

pub struct RecoveryEngine {
    metadata: Store,
    blobs: BlobStore,
    options: BlobOpts,
    keys: BlobKeyring,
    recovery_key_id: u32,
    #[cfg(test)]
    purge_finalization_fault: std::sync::atomic::AtomicBool,
}

struct RawBytes(Vec<u8>);

impl store::Deserialize for RawBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

impl RecoveryEngine {
    /// The caller must inject a separately configured recovery BlobStore and key domain.
    /// This constructor cannot prove backend independence; a distinct key ID alone is not proof.
    pub fn new(
        metadata: Store,
        blobs: BlobStore,
        options: BlobOpts,
        keys: BlobKeyring,
    ) -> Result<Self> {
        Self::new_inner(metadata, blobs, options, keys, false)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        metadata: Store,
        blobs: BlobStore,
        options: BlobOpts,
        keys: BlobKeyring,
    ) -> Result<Self> {
        Self::new_inner(metadata, blobs, options, keys, true)
    }

    fn new_inner(
        metadata: Store,
        blobs: BlobStore,
        options: BlobOpts,
        keys: BlobKeyring,
        allow_ephemeral: bool,
    ) -> Result<Self> {
        if metadata.is_none()
            || !metadata.same_instance(&metadata)
            || (!allow_ephemeral && matches!(&metadata, Store::Ephemeral(_)))
        {
            return Err(RecoveryError::Invalid(
                "metadata store must support atomic transactions",
            ));
        }
        let key = match &options.encryption {
            BlobEncryption::Key(key) => key,
            BlobEncryption::None => {
                return Err(RecoveryError::Invalid(
                    "recovery blob encryption is required",
                ));
            }
            BlobEncryption::Unavailable(_) => {
                return Err(RecoveryError::Invalid(
                    "recovery encryption key is unavailable",
                ));
            }
        };
        if keys.get(key.id()).is_none() {
            return Err(RecoveryError::Invalid(
                "recovery keyring does not contain configured key",
            ));
        }
        let recovery_key_id = key.id();
        Ok(Self {
            metadata,
            blobs,
            options,
            keys,
            recovery_key_id,
            #[cfg(test)]
            purge_finalization_fault: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_purge_finalization(&self) {
        self.purge_finalization_fault
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn set_policy(
        &self,
        scope: TenantServerScope,
        desired_revision: u64,
        expected_digest: &str,
        policy: Policy,
    ) -> Result<PolicyRecord> {
        if !valid_server_scope(&scope) {
            return Err(RecoveryError::Invalid("policy scope"));
        }
        if desired_revision == 0 || desired_revision > MAX_SAFE_INTEGER {
            return Err(RecoveryError::Invalid("desired policy revision"));
        }
        policy.validate()?;
        let digest = policy_digest(&policy)?;
        if expected_digest != digest {
            return Err(RecoveryError::Invalid("policy digest mismatch"));
        }
        let key = scoped_key(b"policy", &scope, "")?;
        let current = self.read::<PolicyRecord>(&key).await?;
        if let Some((existing, _)) = &current {
            if existing.scope != scope
                || existing.desired_revision == 0
                || existing.desired_revision > MAX_SAFE_INTEGER
                || policy_digest(&existing.policy)? != existing.digest
            {
                return Err(RecoveryError::Conflict(
                    "stored policy scope or digest mismatch",
                ));
            }
            if desired_revision == existing.desired_revision {
                if existing.digest == digest && existing.policy == policy {
                    return Ok(existing.clone());
                }
                return Err(RecoveryError::Conflict(
                    "desired policy revision was reused",
                ));
            }
            if desired_revision < existing.desired_revision {
                return Err(RecoveryError::Conflict("stale desired policy revision"));
            }
        }
        let record = PolicyRecord {
            scope,
            desired_revision,
            digest,
            policy,
        };
        self.cas_write(&key, current.as_ref().map(|(_, r)| r), &record)
            .await?;
        Ok(record)
    }

    pub async fn policy_status(&self, scope: &TenantServerScope) -> Result<Option<PolicyRecord>> {
        if !valid_server_scope(scope) {
            return Err(RecoveryError::Invalid("policy scope"));
        }
        let key = scoped_key(b"policy", scope, "")?;
        let Some((record, _)) = self.read::<PolicyRecord>(&key).await? else {
            return Ok(None);
        };
        if record.scope != *scope
            || record.desired_revision == 0
            || record.desired_revision > MAX_SAFE_INTEGER
            || !record.policy.validate().is_ok()
            || policy_digest(&record.policy)? != record.digest
        {
            return Err(RecoveryError::Conflict("stored policy is invalid"));
        }
        Ok(Some(record))
    }

    pub async fn sync_hold(&self, scope: RecoveryScope, epoch: u64, active: bool) -> Result<()> {
        if !valid_recovery_scope(&scope) {
            return Err(RecoveryError::Invalid("hold scope"));
        }
        if epoch == 0 || epoch > MAX_SAFE_INTEGER {
            return Err(RecoveryError::Invalid("hold epoch"));
        }
        let key = scoped_key(b"hold", &scope, "")?;
        let old = self.read::<HoldControl>(&key).await?;
        let mut hold = old.as_ref().map_or(
            HoldControl {
                scope: scope.clone(),
                epoch: 0,
                active: false,
                pending_purges: 0,
            },
            |(h, _)| h.clone(),
        );
        if hold.pending_purges != 0 {
            return Err(RecoveryError::InProgress);
        }
        if epoch == hold.epoch && active == hold.active {
            return Ok(());
        }
        if epoch <= hold.epoch {
            return Err(RecoveryError::Conflict("hold epoch must increase"));
        }
        hold.epoch = epoch;
        hold.active = active;
        self.cas_write(&key, old.as_ref().map(|(_, r)| r), &hold)
            .await
    }

    pub async fn prepare_capture(
        &self,
        request: CaptureRequest,
        source: &BlobStore,
        source_keys: &BlobKeyring,
    ) -> Result<PreparedCapture> {
        let scope = request.account.scope.clone();
        if !valid_recovery_scope(&scope)
            || request.account.store_account_id == 0
            || request.account.store_account_id != request.source.account_id
        {
            return Err(RecoveryError::Invalid(
                "source account does not match verified binding",
            ));
        }
        request.metadata.validate()?;
        if request.original_blob_key.is_empty()
            || request.original_blob_key.len() > 1024
            || request.now == 0
            || request.now > MAX_SAFE_INTEGER
            || request.source.collection != Collection::Email
            || request.source.revision_property != u8::from(Field::ARCHIVE)
        {
            return Err(RecoveryError::Invalid("capture source"));
        }
        let server_scope = server_scope(&scope);
        let policy_key = scoped_key(b"policy", &server_scope, "")?;
        let (policy, policy_bytes) = self
            .read::<PolicyRecord>(&policy_key)
            .await?
            .ok_or(RecoveryError::Invalid("no recovery policy"))?;
        policy.policy.validate()?;
        if policy.scope != server_scope
            || policy.desired_revision == 0
            || policy.desired_revision > MAX_SAFE_INTEGER
            || policy_digest(&policy.policy)? != policy.digest
        {
            return Err(RecoveryError::Conflict(
                "stored policy scope or digest mismatch",
            ));
        }
        if !policy.policy.recovery_enabled {
            return Err(RecoveryError::Invalid("recovery is disabled"));
        }
        let hold_key = scoped_key(b"hold", &scope, "")?;
        let (hold, hold_bytes) = self
            .read::<HoldControl>(&hold_key)
            .await?
            .ok_or(RecoveryError::Invalid("hold state not synchronized"))?;
        if hold.active {
            return Err(RecoveryError::Held);
        }
        let raw = source
            .get_raw_blob(&request.original_blob_key)
            .await?
            .ok_or(RecoveryError::BlobMissing)?;
        if raw.len() > MAX_BLOB_BYTES {
            return Err(RecoveryError::Invalid("source blob too large"));
        }
        let source_format =
            BlobFormat::of(&raw).ok_or(RecoveryError::Invalid("source blob encoding"))?;
        if source_format.key_id == Some(self.recovery_key_id) {
            return Err(RecoveryError::Invalid(
                "recovery key must differ from source key",
            ));
        }
        source_keys.decode_bounded(&request.original_blob_key, raw.clone(), MAX_BLOB_BYTES)?;
        let checksum = digest_hex(&raw);
        let storage_key = recovery_blob_key(&scope, &request.metadata.operation_id)?;
        let encoded_size = self.options.encode(&storage_key, &raw)?.len() as u64;
        let retention_days = policy.policy.recovery_days.ok_or(RecoveryError::Invalid(
            "enabled policy has no retention period",
        ))?;
        let capture_id = hash_hex(
            &[
                scope_hash(&scope)?.as_bytes(),
                request.metadata.operation_id.as_bytes(),
            ]
            .concat(),
        );
        let manifest_key = scoped_key(b"manifest", &scope, &capture_id)?;
        let tombstone_key = scoped_key(b"tombstone", &scope, &capture_id)?;
        if self.read::<PurgeTombstone>(&tombstone_key).await?.is_some() {
            return Err(RecoveryError::Conflict("capture was permanently purged"));
        }
        let existing = self.read::<Manifest>(&manifest_key).await?;
        let mut registered_writer = false;
        if let Some((manifest, _)) = &existing {
            if manifest.state == ManifestState::Copying {
                return Err(RecoveryError::InProgress);
            }
            if manifest.state != ManifestState::Staging
                || manifest.scope != scope
                || manifest.capture_operation_id != request.metadata.operation_id
                || manifest.original_blob_key != request.original_blob_key
                || manifest.source_revision != request.source.revision
                || manifest.source_account_id != request.source.account_id
                || manifest.source_collection != request.source.collection as u8
                || manifest.source_document_id != request.source.document_id
                || manifest.cause != request.metadata.cause
                || manifest.received_at != request.metadata.received_at
                || manifest.folders != request.metadata.folders
                || manifest.keywords != request.metadata.keywords
                || manifest.policy_revision != policy.desired_revision
                || manifest.policy_digest != policy.digest
                || manifest.hold_epoch != hold.epoch
                || manifest.sha256 != checksum
                || manifest.recovery_blob_key != storage_key
                || manifest.stored_size != encoded_size
            {
                return Err(RecoveryError::Conflict(
                    "capture already has a terminal or different manifest",
                ));
            }
        } else {
            if self.blobs.get_raw_blob(&storage_key).await?.is_some() {
                return Err(RecoveryError::Conflict("unowned recovery blob key exists"));
            }
            let ledger_key = quota_key(&scope)?;
            let ledger_old = self.read::<ScopeLedger>(&ledger_key).await?;
            let mut ledger = ledger_old
                .as_ref()
                .map_or_else(ScopeLedger::default, |(v, _)| v.clone());
            let quota = policy
                .policy
                .quota_bytes
                .ok_or(RecoveryError::Invalid("enabled policy has no quota"))?;
            if encoded_size > quota.saturating_sub(ledger.charged_bytes)
                || ledger.captures.len() >= MAX_ITEMS_PER_SCOPE
            {
                return Err(RecoveryError::QuotaExceeded);
            }
            ledger.charged_bytes = ledger
                .charged_bytes
                .checked_add(encoded_size)
                .ok_or(RecoveryError::QuotaExceeded)?;
            ledger.captures.push(capture_id.clone());
            let manifest = Manifest {
                capture_id: capture_id.clone(),
                capture_operation_id: request.metadata.operation_id.clone(),
                scope: scope.clone(),
                state: ManifestState::Copying,
                original_blob_key: request.original_blob_key.clone(),
                recovery_blob_key: storage_key.clone(),
                source_account_id: request.source.account_id,
                source_collection: request.source.collection as u8,
                source_document_id: request.source.document_id,
                source_revision: request.source.revision,
                created_at: request.now,
                deleted_at: None,
                expires_at: 0,
                cause: request.metadata.cause.clone(),
                folders: request.metadata.folders.clone(),
                keywords: request.metadata.keywords.clone(),
                received_at: request.metadata.received_at,
                size: raw.len() as u64,
                stored_size: encoded_size,
                sha256: checksum.clone(),
                policy_revision: policy.desired_revision,
                policy_digest: policy.digest.clone(),
                hold_epoch: hold.epoch,
            };
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(0)
                .assert_value(value_class(&policy_key), record_revision(&policy_bytes)?);
            batch
                .with_account_id(0)
                .assert_value(value_class(&hold_key), record_revision(&hold_bytes)?);
            let old_ledger_bytes = ledger_old.as_ref().map(|(_, bytes)| bytes.as_slice());
            let ledger_revision = next_record_revision(old_ledger_bytes)?;
            if let Some(bytes) = old_ledger_bytes {
                batch
                    .with_account_id(0)
                    .assert_value(value_class(&ledger_key), record_revision(bytes)?);
            } else {
                batch
                    .with_account_id(0)
                    .assert_value(value_class(&ledger_key), ());
            }
            batch
                .with_account_id(0)
                .assert_value(value_class(&manifest_key), ());
            batch
                .with_account_id(0)
                .assert_value(value_class(&tombstone_key), ());
            batch.set(
                value_class(&ledger_key),
                encode_record(&ledger, ledger_revision)?,
            );
            batch.set(value_class(&manifest_key), encode_record(&manifest, 1)?);
            if batch.has_commit_points() || batch.is_large_batch() {
                return Err(RecoveryError::BatchTooLarge);
            }
            if let Err(error) = self.metadata.write_batch(&mut batch).await {
                if self
                    .read::<Manifest>(&manifest_key)
                    .await?
                    .is_some_and(|(current, _)| current.state == ManifestState::Copying)
                {
                    return Err(RecoveryError::InProgress);
                }
                return Err(error.into());
            }
            registered_writer = true;
        }
        let (staging, staging_bytes) = self
            .read::<Manifest>(&manifest_key)
            .await?
            .ok_or(RecoveryError::Conflict("staging manifest disappeared"))?;
        if staging.policy_revision != policy.desired_revision
            || staging.policy_digest != policy.digest
            || staging.hold_epoch != hold.epoch
        {
            return Err(RecoveryError::Conflict(
                "policy or hold changed after reservation",
            ));
        }
        if registered_writer {
            self.blobs
                .put_blob(&storage_key, &raw, &self.options)
                .await?;
        }
        let stored = self
            .blobs
            .get_raw_blob(&storage_key)
            .await?
            .ok_or(RecoveryError::BlobMissing)?;
        let format = BlobFormat::of(&stored).ok_or(RecoveryError::BlobMismatch)?;
        if format.key_id != Some(self.recovery_key_id) {
            return Err(RecoveryError::BlobMismatch);
        }
        let stored_size = stored.len() as u64;
        let decoded = self
            .keys
            .decode_bounded(&storage_key, stored, MAX_BLOB_BYTES)?;
        if stored_size != encoded_size || decoded != raw || digest_hex(&decoded) != checksum {
            return Err(RecoveryError::BlobMismatch);
        }
        let (mut ready, ready_bytes) = if registered_writer {
            let mut staged = staging.clone();
            staged.state = ManifestState::Staging;
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(0)
                .assert_value(value_class(&policy_key), record_revision(&policy_bytes)?)
                .assert_value(value_class(&hold_key), record_revision(&hold_bytes)?)
                .assert_value(value_class(&manifest_key), record_revision(&staging_bytes)?);
            batch.with_account_id(0).set(
                value_class(&manifest_key),
                encode_record(&staged, next_record_revision(Some(&staging_bytes))?)?,
            );
            if batch.has_commit_points() || batch.is_large_batch() {
                return Err(RecoveryError::BatchTooLarge);
            }
            self.metadata.write_batch(&mut batch).await?;
            self.read::<Manifest>(&manifest_key)
                .await?
                .ok_or(RecoveryError::Conflict("staging manifest disappeared"))?
        } else {
            (staging, staging_bytes)
        };
        if ready.state != ManifestState::Staging {
            return Err(RecoveryError::Conflict("capture is not verified staging"));
        }
        ready.state = ManifestState::Preserved;
        Ok(PreparedCapture {
            policy_key,
            hold_key,
            manifest_key,
            policy_record_revision: record_revision(&policy_bytes)?,
            hold_revision: record_revision(&hold_bytes)?,
            manifest_revision: record_revision(&ready_bytes)?,
            source: request.source,
            manifest: ready,
            retention_days,
        })
    }

    pub async fn get(&self, scope: &RecoveryScope, id: &str) -> Result<Option<Manifest>> {
        if !valid_recovery_scope(scope) {
            return Err(RecoveryError::Invalid("recovery scope"));
        }
        let key = scoped_key(b"manifest", scope, id)?;
        Ok(self.read::<Manifest>(&key).await?.map(|(m, _)| m))
    }

    pub async fn get_payload(&self, scope: &RecoveryScope, id: &str) -> Result<Option<Vec<u8>>> {
        let Some(manifest) = self.get(scope, id).await? else {
            return Ok(None);
        };
        if manifest.state != ManifestState::Preserved {
            return Ok(None);
        }
        if manifest.size > MAX_BLOB_BYTES as u64
            || manifest.stored_size > MAX_BLOB_BYTES as u64 + 65_536
        {
            return Err(RecoveryError::Invalid(
                "recovery payload exceeds retrieval bound",
            ));
        }
        let stored = self
            .blobs
            .get_raw_blob(&manifest.recovery_blob_key)
            .await?
            .ok_or(RecoveryError::BlobMissing)?;
        let format = BlobFormat::of(&stored).ok_or(RecoveryError::BlobMismatch)?;
        if format.key_id != Some(self.recovery_key_id) {
            return Err(RecoveryError::BlobMismatch);
        }
        if stored.len() as u64 != manifest.stored_size {
            return Err(RecoveryError::BlobMismatch);
        }
        let decoded =
            self.keys
                .decode_bounded(&manifest.recovery_blob_key, stored, MAX_BLOB_BYTES)?;
        if decoded.len() as u64 != manifest.size || digest_hex(&decoded) != manifest.sha256 {
            return Err(RecoveryError::BlobMismatch);
        }
        Ok(Some(decoded))
    }

    pub async fn list(
        &self,
        scope: &RecoveryScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Manifest>> {
        if !valid_recovery_scope(scope) {
            return Err(RecoveryError::Invalid("recovery scope"));
        }
        if limit == 0 || limit > 100 || offset > MAX_ITEMS_PER_SCOPE {
            return Err(RecoveryError::Invalid("list bounds"));
        }
        let key = quota_key(scope)?;
        let ledger = self
            .read::<ScopeLedger>(&key)
            .await?
            .map(|(v, _)| v)
            .unwrap_or_default();
        let mut out = Vec::with_capacity(limit);
        let mut matched = 0usize;
        for id in ledger.captures.iter().rev() {
            let Some(item) = self.get(scope, id).await? else {
                continue;
            };
            if matched < offset {
                matched += 1;
                continue;
            }
            out.push(item);
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    async fn read<T: for<'de> Deserialize<'de>>(&self, key: &[u8]) -> Result<Option<(T, Vec<u8>)>> {
        let raw = self
            .metadata
            .get_value::<RawBytes>(any_key(key))
            .await?
            .map(|value| value.0);
        raw.map(|bytes| {
            let value = decode_record(&bytes)?;
            Ok((value, bytes))
        })
        .transpose()
    }

    async fn cas_write<T: Serialize>(
        &self,
        key: &[u8],
        previous: Option<&Vec<u8>>,
        value: &T,
    ) -> Result<()> {
        let mut batch = BatchBuilder::new();
        self.append_cas(&mut batch, key, previous, value)?;
        self.metadata.write_batch(&mut batch).await?;
        Ok(())
    }

    fn append_cas<T: Serialize>(
        &self,
        batch: &mut BatchBuilder,
        key: &[u8],
        previous: Option<&Vec<u8>>,
        value: &T,
    ) -> Result<()> {
        let class = value_class(key);
        let revision = next_record_revision(previous.map(Vec::as_slice))?;
        if let Some(bytes) = previous {
            batch
                .with_account_id(0)
                .assert_value(class.clone(), record_revision(bytes)?);
        } else {
            batch.with_account_id(0).assert_value(class.clone(), ());
        }
        batch.set(class, encode_record(value, revision)?);
        Ok(())
    }
}

pub struct PreparedCapture {
    policy_key: Vec<u8>,
    hold_key: Vec<u8>,
    manifest_key: Vec<u8>,
    policy_record_revision: u64,
    hold_revision: u64,
    manifest_revision: u64,
    source: SourceAssertion,
    manifest: Manifest,
    retention_days: u16,
}

impl PreparedCapture {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Append immediately before source destruction; callers must keep the complete deletion in this same segment.
    pub fn append_to_delete_batch(&self, batch: &mut BatchBuilder, deleted_at: u64) -> Result<()> {
        if deleted_at == 0 || deleted_at > MAX_SAFE_INTEGER {
            return Err(RecoveryError::Invalid("deletion timestamp"));
        }
        if batch.has_commit_points() || batch.is_large_batch() {
            return Err(RecoveryError::Conflict(
                "append recovery barrier before batch reaches a commit split",
            ));
        }
        let expires_at = deleted_at
            .checked_add(u64::from(self.retention_days) * 86_400)
            .filter(|expires_at| *expires_at <= MAX_SAFE_INTEGER)
            .ok_or(RecoveryError::Invalid("recovery expiry overflow"))?;
        let mut preserved = self.manifest.clone();
        preserved.state = ManifestState::Preserved;
        preserved.deleted_at = Some(deleted_at);
        preserved.expires_at = expires_at;
        let preserved_revision = self
            .manifest_revision
            .checked_add(1)
            .ok_or(RecoveryError::Invalid("manifest revision overflow"))?;
        batch
            .with_account_id(0)
            .assert_value(value_class(&self.policy_key), self.policy_record_revision)
            .assert_value(value_class(&self.hold_key), self.hold_revision)
            .assert_value(value_class(&self.manifest_key), self.manifest_revision);
        batch
            .with_account_id(self.source.account_id)
            .with_collection(self.source.collection)
            .with_document(self.source.document_id)
            .assert_value(
                ValueClass::Property(self.source.revision_property),
                AssertValue::U64(self.source.revision),
            );
        if batch.is_large_batch() {
            return Err(RecoveryError::Conflict(
                "recovery assertions would split the commit segment",
            ));
        }
        batch.with_account_id(0).set(
            value_class(&self.manifest_key),
            encode_record(&preserved, preserved_revision)?,
        );
        if batch.is_large_batch() {
            return Err(RecoveryError::Conflict(
                "recovery barrier would cross a commit split",
            ));
        }
        batch
            .with_account_id(self.source.account_id)
            .with_collection(self.source.collection)
            .with_document(self.source.document_id);
        Ok(())
    }
}

fn value_class(key: &[u8]) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: key.to_vec(),
    })
}
fn any_key(key: &[u8]) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::System,
        key: key.to_vec(),
    }
}
fn record_revision(bytes: &[u8]) -> Result<u64> {
    let tail = bytes
        .get(bytes.len().saturating_sub(8)..)
        .ok_or(RecoveryError::Invalid("record revision"))?;
    if tail.len() != 8 {
        return Err(RecoveryError::Invalid("record revision"));
    }
    Ok(u64::from_be_bytes(
        tail.try_into()
            .map_err(|_| RecoveryError::Invalid("record revision"))?,
    ))
}
fn next_record_revision(previous: Option<&[u8]>) -> Result<u64> {
    let revision = match previous {
        Some(bytes) => record_revision(bytes)?.checked_add(1),
        None => Some(1),
    }
    .filter(|revision| *revision <= MAX_SAFE_INTEGER)
    .ok_or(RecoveryError::Invalid("record revision overflow"))?;
    Ok(revision)
}
fn encode_record<T: Serialize>(value: &T, revision: u64) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() + 8 > MAX_RECORD_BYTES {
        return Err(RecoveryError::Invalid("record too large"));
    }
    bytes.extend_from_slice(&revision.to_be_bytes());
    Ok(bytes)
}
fn decode_record<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < 9 || bytes.len() > MAX_RECORD_BYTES {
        return Err(RecoveryError::Invalid("record size"));
    }
    Ok(serde_json::from_slice(&bytes[..bytes.len() - 8])?)
}
fn scope_hash<T: Serialize>(scope: &T) -> Result<String> {
    Ok(digest_hex(&serde_json::to_vec(scope)?))
}
fn scoped_key<T: Serialize>(kind: &[u8], scope: &T, suffix: &str) -> Result<Vec<u8>> {
    if suffix.len() > 128 {
        return Err(RecoveryError::Invalid("key suffix"));
    }
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(kind);
    key.push(b':');
    key.extend_from_slice(scope_hash(scope)?.as_bytes());
    key.push(b':');
    key.extend_from_slice(suffix.as_bytes());
    Ok(key)
}
fn recovery_blob_key(scope: &RecoveryScope, operation: &str) -> Result<Vec<u8>> {
    let id = hash_hex(&[scope_hash(scope)?.as_bytes(), operation.as_bytes()].concat());
    Ok([PREFIX, b"blob:", id.as_bytes()].concat())
}
fn quota_key(scope: &RecoveryScope) -> Result<Vec<u8>> {
    scoped_key(b"quota", &scope.tenant_id, "")
}
fn digest_hex(bytes: &[u8]) -> String {
    hash_hex(bytes)
}
fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn policy_digest(policy: &Policy) -> Result<String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DigestPolicy<'a> {
        schema_version: u8,
        recovery_enabled: bool,
        recovery_days: Option<u16>,
        quota_bytes: Option<u64>,
        acknowledgment: &'a str,
        reason: &'a str,
    }
    let canonical = DigestPolicy {
        schema_version: 1,
        recovery_enabled: policy.recovery_enabled,
        recovery_days: policy.recovery_days,
        quota_bytes: policy.quota_bytes,
        acknowledgment: &policy.acknowledgment,
        reason: &policy.reason,
    };
    Ok(digest_hex(&serde_json::to_vec(&canonical)?))
}
