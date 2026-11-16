/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use super::*;
use registry::schema::enums::{CompressionAlgo, SymmetricCipher};
use registry::{schema::prelude::ObjectType, types::EnumImpl};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use store::{
    BlobStore, Store, ValueKey,
    backend::ephemeral::EphemeralStore,
    write::{
        AssignedIds, PendingId, RegistryClass, Slot,
        blob_codec::{BLOB_KEY_LEN, BlobKey},
    },
};
use tokio::sync::{Notify, Semaphore, mpsc};
use xxhash_rust::xxh3::xxh3_64;

fn scope() -> RecoveryScope {
    RecoveryScope {
        tenant_id: "tenant-1".into(),
        server_id: "server-1".into(),
        placement_generation: 3,
        server_generation: 2,
        account_id: "7".into(),
        account_generation: 1,
    }
}

fn enabled_policy() -> Policy {
    Policy {
        recovery_enabled: true,
        recovery_days: Some(30),
        quota_bytes: Some(1_000_000),
        acknowledgment: "I authorize recovery retention".into(),
        reason: "Compliance record retention".into(),
    }
}

async fn set_policy(
    engine: &RecoveryEngine,
    scope: TenantServerScope,
    desired_revision: u64,
    policy: Policy,
) -> Result<PolicyRecord> {
    let digest = policy_digest(&policy)?;
    engine
        .set_policy(scope, desired_revision, &digest, policy)
        .await
}

struct LifecycleFixture {
    engine: Arc<RecoveryEngine>,
    metadata: Store,
    source_blobs: BlobStore,
    recovery_blobs: BlobStore,
    source_keys: Arc<BlobKeyring>,
    recovery_key: Arc<BlobKey>,
    account: VerifiedAccountMapping,
    source_blob_key: Vec<u8>,
    message: Vec<u8>,
}

async fn lifecycle_fixture() -> LifecycleFixture {
    let metadata = EphemeralStore::open();
    let source_blobs = BlobStore::Store(EphemeralStore::open());
    let recovery_blobs = BlobStore::Store(EphemeralStore::open());
    let source_key = Arc::new(BlobKey::new(
        1,
        SymmetricCipher::Aes256Gcm,
        &[1; BLOB_KEY_LEN],
    ));
    let recovery_key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let source_keys = Arc::new(BlobKeyring::new(vec![source_key.clone()]));
    let recovery_keys = BlobKeyring::new(vec![recovery_key.clone()]);
    let message = b"From: restore@example.test\r\nTo: user@example.test\r\nSubject: recovery\r\n\r\nOriginal message.\r\n".to_vec();
    let source_blob_key = b"source-message-key".to_vec();
    source_blobs
        .put_blob(
            &source_blob_key,
            &message,
            &BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(source_key)),
        )
        .await
        .unwrap();

    let engine = Arc::new(
        RecoveryEngine::new_for_test(
            metadata.clone(),
            recovery_blobs.clone(),
            BlobOpts::new(
                CompressionAlgo::None,
                BlobEncryption::Key(recovery_key.clone()),
            ),
            recovery_keys,
        )
        .unwrap(),
    );
    let recovery_scope = scope();
    let account = VerifiedAccountMapping::from_verified_binding(recovery_scope.clone(), 7).unwrap();
    set_policy(&engine, server_scope(&recovery_scope), 1, enabled_policy())
        .await
        .unwrap();
    engine
        .sync_hold(recovery_scope.clone(), 1, false)
        .await
        .unwrap();
    engine.activate_account(&account).await.unwrap();

    let account_record = b"verified-registry-account-record".to_vec();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(0)
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Account.to_id(),
                item_id: 7,
            }),
            account_record,
        )
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(Field::ARCHIVE.into()),
            1u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut batch).await.unwrap();

    LifecycleFixture {
        engine,
        metadata,
        source_blobs,
        recovery_blobs,
        source_keys,
        recovery_key,
        account,
        source_blob_key,
        message,
    }
}

#[cfg(feature = "recovery-test-sqlite")]
struct PersistentLifecycleFixture {
    root: std::path::PathBuf,
    metadata_path: std::path::PathBuf,
    source_path: std::path::PathBuf,
    recovery_path: std::path::PathBuf,
    engine: Arc<RecoveryEngine>,
    metadata: Store,
    source_blobs: BlobStore,
    recovery_blobs: BlobStore,
    source_keys: Arc<BlobKeyring>,
    recovery_key: Arc<BlobKey>,
    account: VerifiedAccountMapping,
    source_blob_key: Vec<u8>,
    message: Vec<u8>,
}

#[cfg(feature = "recovery-test-sqlite")]
async fn open_test_sqlite(path: &std::path::Path) -> Store {
    let mut config = registry::schema::structs::SqliteStore::default();
    config.path = path.to_string_lossy().into_owned();
    let store = store::backend::sqlite::SqliteStore::open(config).unwrap();
    store.create_tables().await.unwrap();
    store
}

#[cfg(feature = "recovery-test-sqlite")]
async fn persistent_lifecycle_fixture() -> PersistentLifecycleFixture {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "stalwart-recovery-test-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let metadata_path = root.join("metadata.sqlite");
    let source_path = root.join("source.sqlite");
    let recovery_path = root.join("recovery.sqlite");
    let metadata = open_test_sqlite(&metadata_path).await;
    let source_store = open_test_sqlite(&source_path).await;
    let recovery_store = open_test_sqlite(&recovery_path).await;
    let source_blobs = BlobStore::Store(source_store);
    let recovery_blobs = BlobStore::Store(recovery_store);

    let source_key = Arc::new(BlobKey::new(
        1,
        SymmetricCipher::Aes256Gcm,
        &[1; BLOB_KEY_LEN],
    ));
    let recovery_key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let source_keys = Arc::new(BlobKeyring::new(vec![source_key.clone()]));
    let recovery_keys = BlobKeyring::new(vec![recovery_key.clone()]);
    let message = b"From: persistent@example.test\r\nTo: user@example.test\r\nSubject: recovery\r\n\r\nPersistent original.\r\n".to_vec();
    let source_blob_key = b"persistent-source-message-key".to_vec();
    source_blobs
        .put_blob(
            &source_blob_key,
            &message,
            &BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(source_key)),
        )
        .await
        .unwrap();

    let engine = Arc::new(
        RecoveryEngine::new(
            metadata.clone(),
            recovery_blobs.clone(),
            BlobOpts::new(
                CompressionAlgo::None,
                BlobEncryption::Key(recovery_key.clone()),
            ),
            recovery_keys,
        )
        .unwrap(),
    );
    let recovery_scope = scope();
    let account = VerifiedAccountMapping::from_verified_binding(recovery_scope.clone(), 7).unwrap();
    set_policy(&engine, server_scope(&recovery_scope), 1, enabled_policy())
        .await
        .unwrap();
    engine
        .sync_hold(recovery_scope.clone(), 1, false)
        .await
        .unwrap();

    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(Field::ARCHIVE.into()),
            1u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut source_batch).await.unwrap();

    PersistentLifecycleFixture {
        root,
        metadata_path,
        source_path,
        recovery_path,
        engine,
        metadata,
        source_blobs,
        recovery_blobs,
        source_keys,
        recovery_key,
        account,
        source_blob_key,
        message,
    }
}

#[cfg(feature = "recovery-test-sqlite")]
fn persistent_capture_request(
    fixture: &PersistentLifecycleFixture,
    operation_id: &str,
    now: u64,
) -> CaptureRequest {
    CaptureRequest {
        account: fixture.account.clone(),
        metadata: CaptureMetadata {
            operation_id: operation_id.to_string(),
            cause: "expunge".into(),
            received_at: Some(9),
            folders: vec!["Inbox".into()],
            keywords: vec!["$seen".into()],
        },
        original_blob_key: fixture.source_blob_key.clone(),
        source: SourceAssertion {
            account_id: fixture.account.store_account_id(),
            collection: Collection::Email,
            document_id: 42,
            revision_property: Field::ARCHIVE.into(),
            revision: 1,
        },
        now,
    }
}

#[cfg(feature = "recovery-test-sqlite")]
#[tokio::test]
async fn file_sqlite_capture_state_survives_engine_restart() {
    let fixture = persistent_lifecycle_fixture().await;
    let request = persistent_capture_request(&fixture, "sqlite-restart", 10);
    fixture.engine.fail_after_next_attempt_upload();
    assert!(matches!(
        fixture
            .engine
            .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
            .await,
        Err(RecoveryError::InProgress)
    ));
    let capture_id = hash_hex(
        &[
            scope_hash(&fixture.account.scope).unwrap().as_bytes(),
            request.metadata.operation_id.as_bytes(),
        ]
        .concat(),
    );
    let pending = fixture
        .engine
        .get(&fixture.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, ManifestState::Copying);
    assert_eq!(pending.copy_attempts.len(), 1);
    assert_eq!(pending.copy_attempts[0].state, CopyAttemptState::Writing);
    let abandoned_key = pending.copy_attempts[0].blob_key.clone();
    let abandoned_bytes = fixture
        .recovery_blobs
        .get_raw_blob(&abandoned_key)
        .await
        .unwrap()
        .unwrap();
    let pending_ledger = fixture
        .engine
        .read::<ScopeLedger>(&quota_key(&fixture.account.scope).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        pending_ledger.charged_bytes,
        pending.copy_attempts[0].stored_size
    );
    let blocked_purge = PurgeRequest {
        scope: fixture.account.scope.clone(),
        capture_id: capture_id.clone(),
        operation_id: "sqlite-purge".into(),
        actor: "test".into(),
        reason: "test".into(),
        now: 11,
    };
    assert!(matches!(
        fixture.engine.purge(blocked_purge.clone()).await,
        Err(RecoveryError::InProgress)
    ));

    let expected_message = fixture.message.clone();
    let source_blob_key = fixture.source_blob_key.clone();
    let PersistentLifecycleFixture {
        root,
        metadata_path,
        source_path,
        recovery_path,
        engine,
        metadata,
        source_blobs,
        recovery_blobs,
        source_keys,
        recovery_key,
        ..
    } = fixture;
    drop(engine);
    drop(metadata);
    drop(source_blobs);
    drop(recovery_blobs);

    let metadata = open_test_sqlite(&metadata_path).await;
    let source_blobs = BlobStore::Store(open_test_sqlite(&source_path).await);
    let recovery_blobs = BlobStore::Store(open_test_sqlite(&recovery_path).await);
    let restarted = RecoveryEngine::new(
        metadata.clone(),
        recovery_blobs.clone(),
        BlobOpts::new(
            CompressionAlgo::None,
            BlobEncryption::Key(recovery_key.clone()),
        ),
        BlobKeyring::new(vec![recovery_key.clone()]),
    )
    .unwrap();
    let prepared = restarted
        .prepare_capture(request.clone(), &source_blobs, &source_keys)
        .await
        .unwrap();
    assert_eq!(prepared.manifest().capture_id, capture_id);
    assert_eq!(prepared.manifest().copy_attempts.len(), 2);
    let winner_id = prepared.manifest().selected_attempt_id.unwrap();
    let winner_key = prepared.manifest().recovery_blob_key.clone();
    assert_ne!(winner_key, abandoned_key);
    let winner_bytes = recovery_blobs
        .get_raw_blob(&winner_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovery_blobs
            .get_raw_blob(&abandoned_key)
            .await
            .unwrap()
            .unwrap(),
        abandoned_bytes
    );
    let recovered_source = BlobKeyring::new(vec![recovery_key.clone()])
        .decode_bounded(&winner_key, winner_bytes.clone(), MAX_BLOB_BYTES)
        .unwrap();
    assert_eq!(
        source_keys
            .decode_bounded(&source_blob_key, recovered_source, MAX_BLOB_BYTES)
            .unwrap(),
        expected_message
    );
    assert!(matches!(
        restarted.purge(blocked_purge.clone()).await,
        Err(RecoveryError::InProgress)
    ));

    let mut stale_delete = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut stale_delete, 20)
        .unwrap();
    stale_delete.clear(ValueClass::Property(Field::ARCHIVE.into()));
    let abandoned_key_id = BlobFormat::of(&abandoned_bytes).unwrap().key_id.unwrap();
    let (after_late_completion, _) = restarted
        .finish_copy_attempt(&request.account.scope, &capture_id, 1, abandoned_key_id)
        .await
        .unwrap();
    assert_eq!(after_late_completion.selected_attempt_id, Some(winner_id));
    assert_eq!(after_late_completion.recovery_blob_key, winner_key);
    assert_eq!(
        after_late_completion.copy_attempts[0].state,
        CopyAttemptState::Cleaned
    );
    assert!(
        recovery_blobs
            .get_raw_blob(&abandoned_key)
            .await
            .unwrap()
            .is_none()
    );
    let ledger_after_cleanup = restarted
        .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        ledger_after_cleanup.charged_bytes,
        after_late_completion
            .copy_attempts
            .iter()
            .find(|attempt| attempt.id == winner_id)
            .unwrap()
            .stored_size
    );
    restarted
        .cleanup_unselected_copy_attempts(&request.account.scope, &capture_id)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        ledger_after_cleanup.charged_bytes
    );
    assert!(
        restarted
            .metadata
            .write_batch(&mut stale_delete)
            .await
            .is_err()
    );
    assert_eq!(
        restarted
            .get(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Staging
    );
    assert_eq!(
        email_payload(&restarted.metadata, request.source.document_id).await,
        Some(1u64.to_be_bytes().to_vec())
    );

    let current = restarted
        .prepare_capture(request.clone(), &source_blobs, &source_keys)
        .await
        .unwrap();
    let mut late_assertion = BatchBuilder::new();
    current
        .append_to_delete_batch(&mut late_assertion, 20)
        .unwrap();
    late_assertion
        .with_account_id(request.source.account_id)
        .with_collection(request.source.collection)
        .with_document(request.source.document_id)
        .assert_value(
            ValueClass::Property(request.source.revision_property),
            store::write::assert::AssertValue::U64(999),
        );
    late_assertion.clear(ValueClass::Property(Field::ARCHIVE.into()));
    assert!(
        restarted
            .metadata
            .write_batch(&mut late_assertion)
            .await
            .is_err()
    );
    assert_eq!(
        restarted
            .get(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Staging
    );
    assert_eq!(
        email_payload(&restarted.metadata, request.source.document_id).await,
        Some(1u64.to_be_bytes().to_vec())
    );
    let mut deletion = BatchBuilder::new();
    current.append_to_delete_batch(&mut deletion, 20).unwrap();
    deletion.clear(ValueClass::Property(Field::ARCHIVE.into()));
    restarted.metadata.write_batch(&mut deletion).await.unwrap();
    assert!(
        email_payload(&restarted.metadata, request.source.document_id)
            .await
            .is_none()
    );
    let recovered = restarted
        .get_payload(&request.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        source_keys
            .decode_bounded(&source_blob_key, recovered, MAX_BLOB_BYTES)
            .unwrap(),
        expected_message
    );
    let tombstone = match restarted
        .purge(PurgeRequest {
            now: 30,
            ..blocked_purge
        })
        .await
        .unwrap()
    {
        PurgeOutcome::Purged { tombstone } => tombstone,
    };
    assert_eq!(tombstone.deleted_at, Some(20));
    let tombstone_json = serde_json::to_string(&tombstone).unwrap();
    assert!(!tombstone_json.contains(&String::from_utf8_lossy(&abandoned_key).to_string()));
    assert!(!tombstone_json.contains(&String::from_utf8_lossy(&winner_key).to_string()));
    assert!(
        restarted
            .get(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restarted
            .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        0
    );

    drop(restarted);
    drop(metadata);
    drop(source_blobs);
    drop(recovery_blobs);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "recovery-test-sqlite")]
#[tokio::test]
async fn file_sqlite_concurrent_capture_claims_charge_once() {
    let fixture = persistent_lifecycle_fixture().await;
    let request = persistent_capture_request(&fixture, "sqlite-concurrent", 10);
    let (first, second) = tokio::join!(
        fixture.engine.prepare_capture(
            request.clone(),
            &fixture.source_blobs,
            &fixture.source_keys
        ),
        fixture.engine.prepare_capture(
            request.clone(),
            &fixture.source_blobs,
            &fixture.source_keys
        )
    );
    assert!(first.is_ok() || second.is_ok());
    let capture_id = hash_hex(
        &[
            scope_hash(&fixture.account.scope).unwrap().as_bytes(),
            request.metadata.operation_id.as_bytes(),
        ]
        .concat(),
    );
    let manifest = fixture
        .engine
        .get(&fixture.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert!((1..=2).contains(&manifest.copy_attempts.len()));
    let attempt_ids = manifest
        .copy_attempts
        .iter()
        .map(|attempt| attempt.id)
        .collect::<std::collections::HashSet<_>>();
    let attempt_keys = manifest
        .copy_attempts
        .iter()
        .map(|attempt| attempt.blob_key.clone())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(attempt_ids.len(), manifest.copy_attempts.len());
    assert_eq!(attempt_keys.len(), manifest.copy_attempts.len());
    assert_eq!(
        manifest
            .copy_attempts
            .iter()
            .filter(|attempt| attempt.state == CopyAttemptState::Selected)
            .count(),
        1
    );
    assert!(
        manifest
            .copy_attempts
            .iter()
            .any(|attempt| Some(attempt.id) == manifest.selected_attempt_id)
    );
    let ledger = fixture
        .engine
        .read::<ScopeLedger>(&quota_key(&fixture.account.scope).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(ledger.captures, vec![capture_id]);
    assert_eq!(
        ledger.charged_bytes,
        manifest
            .copy_attempts
            .iter()
            .filter(|attempt| attempt.state != CopyAttemptState::Cleaned)
            .map(|attempt| attempt.stored_size)
            .sum::<u64>()
    );
    drop(fixture);
}

#[cfg(feature = "recovery-test-sqlite")]
#[tokio::test]
async fn file_sqlite_unknown_attempts_consume_capacity_and_quota() {
    let fixture = persistent_lifecycle_fixture().await;
    let request = persistent_capture_request(&fixture, "sqlite-attempt-limit", 10);
    for _ in 0..MAX_COPY_ATTEMPTS {
        fixture.engine.fail_after_next_attempt_upload();
        assert!(matches!(
            fixture
                .engine
                .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
                .await,
            Err(RecoveryError::InProgress)
        ));
    }
    let capture_id = hash_hex(
        &[
            scope_hash(&fixture.account.scope).unwrap().as_bytes(),
            request.metadata.operation_id.as_bytes(),
        ]
        .concat(),
    );
    let manifest = fixture
        .engine
        .get(&fixture.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(manifest.copy_attempts.len(), MAX_COPY_ATTEMPTS);
    let distinct_keys = manifest
        .copy_attempts
        .iter()
        .map(|attempt| attempt.blob_key.clone())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(distinct_keys.len(), MAX_COPY_ATTEMPTS);
    assert!(
        manifest
            .copy_attempts
            .iter()
            .all(|attempt| attempt.state == CopyAttemptState::Writing)
    );
    let charged = manifest
        .copy_attempts
        .iter()
        .map(|attempt| attempt.stored_size)
        .sum::<u64>();
    let ledger = fixture
        .engine
        .read::<ScopeLedger>(&quota_key(&fixture.account.scope).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(ledger.charged_bytes, charged);
    assert!(matches!(
        fixture
            .engine
            .prepare_capture(request, &fixture.source_blobs, &fixture.source_keys)
            .await,
        Err(RecoveryError::InProgress)
    ));
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&quota_key(&fixture.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        charged
    );
    drop(fixture);
}

#[cfg(feature = "recovery-test-sqlite")]
#[tokio::test]
async fn file_sqlite_attempt_cleanup_reserves_hold_and_resumes_after_restart() {
    let fixture = persistent_lifecycle_fixture().await;
    let request = persistent_capture_request(&fixture, "sqlite-cleanup-race", 10);
    fixture.engine.fail_after_next_attempt_upload();
    assert!(matches!(
        fixture
            .engine
            .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
            .await,
        Err(RecoveryError::InProgress)
    ));
    let prepared = fixture
        .engine
        .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
        .await
        .unwrap();
    let mut source_delete = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut source_delete, 11)
        .unwrap();
    source_delete
        .with_account_id(request.source.account_id)
        .with_collection(request.source.collection)
        .with_document(request.source.document_id)
        .clear(ValueClass::Property(Field::ARCHIVE.into()));
    fixture
        .metadata
        .write_batch(&mut source_delete)
        .await
        .unwrap();
    let capture_id = hash_hex(
        &[
            scope_hash(&request.account.scope).unwrap().as_bytes(),
            request.metadata.operation_id.as_bytes(),
        ]
        .concat(),
    );
    let manifest = fixture
        .engine
        .get(&request.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    let charged_before_cleanup = manifest
        .copy_attempts
        .iter()
        .map(|attempt| attempt.stored_size)
        .sum::<u64>();
    let abandoned = manifest
        .copy_attempts
        .iter()
        .find(|attempt| attempt.id == 1)
        .unwrap();
    let abandoned_key = abandoned.blob_key.clone();
    let abandoned_key_id = BlobFormat::of(
        &fixture
            .recovery_blobs
            .get_raw_blob(&abandoned_key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .key_id
    .unwrap();
    fixture.engine.fail_after_next_attempt_cleanup_reservation();
    assert!(matches!(
        fixture
            .engine
            .finish_copy_attempt(&request.account.scope, &capture_id, 1, abandoned_key_id,)
            .await,
        Err(RecoveryError::InProgress)
    ));
    let reserved = fixture
        .engine
        .get(&request.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reserved.copy_attempts[0].state, CopyAttemptState::Cleaning);
    assert_eq!(
        fixture
            .engine
            .lifecycle_summary(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .unwrap()
            .active_operation
            .unwrap()
            .kind,
        LifecycleOperationKind::AttemptCleanup
    );
    assert!(matches!(
        fixture
            .engine
            .purge(PurgeRequest {
                scope: request.account.scope.clone(),
                capture_id: capture_id.clone(),
                operation_id: "cleanup-race-purge".into(),
                actor: "test".into(),
                reason: "race test".into(),
                now: 12,
            })
            .await,
        Err(RecoveryError::InProgress)
    ));
    let importer =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    fixture
        .engine
        .activate_account(&fixture.account)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .engine
            .restore(
                restore_request(&fixture.account, &capture_id, "cleanup-race-restore"),
                &fixture.source_keys,
                &importer,
            )
            .await,
        Err(RecoveryError::Conflict(_) | RecoveryError::InProgress | RecoveryError::Held)
    ));
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 0);
    let hold_key = scoped_key(b"hold", &request.account.scope, "").unwrap();
    assert_eq!(
        fixture
            .engine
            .read::<HoldControl>(&hold_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .pending_purges,
        1
    );
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        charged_before_cleanup
    );
    assert!(matches!(
        fixture
            .engine
            .sync_hold(request.account.scope.clone(), 1, false)
            .await,
        Err(RecoveryError::InProgress)
    ));
    assert!(matches!(
        fixture
            .engine
            .sync_hold(request.account.scope.clone(), 2, true)
            .await,
        Err(RecoveryError::InProgress)
    ));

    fixture.engine.fail_after_next_attempt_cleanup_delete();
    let interrupted = fixture
        .engine
        .cleanup_expired(&request.account.scope, 20, 100, 100, None)
        .await
        .unwrap();
    assert_eq!(interrupted.cleaned_attempts, 0);
    assert_eq!(interrupted.skipped, 1);
    assert!(
        fixture
            .recovery_blobs
            .get_raw_blob(&abandoned_key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .engine
            .read::<HoldControl>(&hold_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .pending_purges,
        1
    );
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        charged_before_cleanup
    );
    assert_eq!(
        fixture
            .engine
            .lifecycle_summary(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .unwrap()
            .active_operation
            .unwrap()
            .kind,
        LifecycleOperationKind::AttemptCleanup
    );

    let PersistentLifecycleFixture {
        root,
        metadata_path,
        recovery_path,
        engine,
        metadata,
        source_blobs,
        recovery_blobs,
        recovery_key,
        ..
    } = fixture;
    drop(engine);
    drop(metadata);
    drop(source_blobs);
    drop(recovery_blobs);

    let metadata = open_test_sqlite(&metadata_path).await;
    let recovery_blobs = BlobStore::Store(open_test_sqlite(&recovery_path).await);
    let restarted = RecoveryEngine::new(
        metadata.clone(),
        recovery_blobs.clone(),
        BlobOpts::new(
            CompressionAlgo::None,
            BlobEncryption::Key(recovery_key.clone()),
        ),
        BlobKeyring::new(vec![recovery_key]),
    )
    .unwrap();
    let resumed = restarted
        .cleanup_expired(&request.account.scope, 20, 100, 100, None)
        .await
        .unwrap();
    assert_eq!(resumed.cleaned_attempts, 1);
    assert_eq!(resumed.skipped, 0);
    assert_eq!(
        restarted
            .read::<HoldControl>(&hold_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .pending_purges,
        0
    );
    assert!(
        restarted
            .lifecycle_summary(&request.account.scope, &capture_id)
            .await
            .unwrap()
            .unwrap()
            .active_operation
            .is_none()
    );
    restarted
        .sync_hold(request.account.scope.clone(), 1, false)
        .await
        .unwrap();
    let settled = restarted
        .get(&request.account.scope, &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.copy_attempts[0].state, CopyAttemptState::Cleaned);
    let ledger = restarted
        .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        ledger.charged_bytes,
        settled
            .copy_attempts
            .iter()
            .find(|attempt| attempt.state == CopyAttemptState::Selected)
            .unwrap()
            .stored_size
    );
    let repeated = restarted
        .cleanup_expired(&request.account.scope, 20, 100, 100, None)
        .await
        .unwrap();
    assert_eq!(repeated.cleaned_attempts, 0);
    assert_eq!(
        restarted
            .read::<ScopeLedger>(&quota_key(&request.account.scope).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        ledger.charged_bytes
    );

    drop(restarted);
    drop(metadata);
    drop(recovery_blobs);
    std::fs::remove_dir_all(root).unwrap();
}

fn capture_request(fixture: &LifecycleFixture, operation_id: &str, now: u64) -> CaptureRequest {
    CaptureRequest {
        account: fixture.account.clone(),
        metadata: CaptureMetadata {
            operation_id: operation_id.to_string(),
            cause: "expunge".into(),
            received_at: Some(9),
            folders: vec!["Inbox".into()],
            keywords: vec!["$seen".into()],
        },
        original_blob_key: fixture.source_blob_key.clone(),
        source: SourceAssertion {
            account_id: fixture.account.store_account_id(),
            collection: Collection::Email,
            document_id: 42,
            revision_property: Field::ARCHIVE.into(),
            revision: 1,
        },
        now,
    }
}

async fn preserve_fixture_capture(
    fixture: &LifecycleFixture,
    operation_id: &str,
    staging_at: u64,
    deleted_at: u64,
) -> String {
    let prepared = fixture
        .engine
        .prepare_capture(
            capture_request(fixture, operation_id, staging_at),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    let capture_id = prepared.manifest().capture_id.clone();
    let mut batch = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut batch, deleted_at)
        .unwrap();
    batch
        .with_account_id(fixture.account.store_account_id())
        .with_collection(Collection::Email)
        .with_document(42)
        .clear(ValueClass::Property(Field::ARCHIVE.into()));
    fixture.metadata.write_batch(&mut batch).await.unwrap();
    capture_id
}

struct TestRestoreImporter {
    metadata: Store,
    expected_message: Vec<u8>,
    mailbox_ids: Vec<u32>,
    prepare_calls: Arc<AtomicUsize>,
    committed_calls: Arc<AtomicUsize>,
    committed_results: Arc<Mutex<Vec<RestoreResult>>>,
    stale_assertion: Arc<AtomicBool>,
    panic_after_commit: Arc<AtomicBool>,
    force_split: Arc<AtomicBool>,
    prepare_gate: Option<(mpsc::UnboundedSender<()>, Arc<Semaphore>)>,
    live_assertion_gate: Option<(Arc<Notify>, Arc<Semaphore>)>,
}

struct TestRestorePending {
    document_slot: Slot,
    thread_slot: Slot,
    mailbox_slots: Vec<(u32, Slot)>,
    decoded_message: Vec<u8>,
    committed_calls: Arc<AtomicUsize>,
    committed_results: Arc<Mutex<Vec<RestoreResult>>>,
    panic_after_commit: Arc<AtomicBool>,
}

impl TestRestoreImporter {
    fn new(metadata: Store, expected_message: Vec<u8>, mailbox_ids: Vec<u32>) -> Self {
        Self {
            metadata,
            expected_message,
            mailbox_ids,
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            committed_calls: Arc::new(AtomicUsize::new(0)),
            committed_results: Arc::new(Mutex::new(Vec::new())),
            stale_assertion: Arc::new(AtomicBool::new(false)),
            panic_after_commit: Arc::new(AtomicBool::new(false)),
            force_split: Arc::new(AtomicBool::new(false)),
            prepare_gate: None,
            live_assertion_gate: None,
        }
    }

    fn stale_next_account_assertion(&self) {
        self.stale_assertion.store(true, Ordering::SeqCst);
    }
}

impl RestoreImporter for TestRestoreImporter {
    type Pending = TestRestorePending;

    fn live_account_assertion<'a>(
        &'a self,
        destination: &'a VerifiedAccountMapping,
    ) -> impl Future<Output = Result<AuthoritativeAccountAssertion>> + Send {
        async move {
            if let Some((entered, gate)) = &self.live_assertion_gate {
                entered.notify_one();
                gate.acquire()
                    .await
                    .map_err(|_| RecoveryError::Conflict("test assertion gate closed"))?
                    .forget();
            }
            let record = self
                .metadata
                .get_value::<RawBytes>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                    object_id: ObjectType::Account.to_id(),
                    item_id: u64::from(destination.store_account_id()),
                })))
                .await?
                .ok_or(RecoveryError::Invalid("live registry account is missing"))?;
            let mut revision = xxh3_64(&record.0);
            if self.stale_assertion.swap(false, Ordering::SeqCst) {
                revision = revision.wrapping_add(1);
            }
            AuthoritativeAccountAssertion::new(destination.store_account_id(), revision)
        }
    }

    fn prepare<'a>(
        &'a self,
        payload: &'a [u8],
        source_keys: &'a BlobKeyring,
        manifest: &'a Manifest,
        destination: &'a VerifiedAccountMapping,
        batch: &'a mut BatchBuilder,
    ) -> impl Future<Output = Result<(Self::Pending, PendingRestoreIds)>> + Send {
        async move {
            let decoded_message = source_keys.decode_bounded(
                &manifest.original_blob_key,
                payload.to_vec(),
                MAX_BLOB_BYTES,
            )?;
            if decoded_message != self.expected_message {
                return Err(RecoveryError::BlobMismatch);
            }
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if let Some((entered, gate)) = &self.prepare_gate {
                let _ = entered.send(());
                gate.acquire()
                    .await
                    .map_err(|_| RecoveryError::Conflict("test prepare gate closed"))?
                    .forget();
            }

            let account_id = destination.store_account_id();
            let document_slot = batch.reserve_document_id(account_id, Collection::Email);
            let thread_slot = batch.reserve_document_id(account_id, Collection::Thread);
            let uid_range = batch.reserve_uids(account_id, self.mailbox_ids.iter().copied());
            let mailbox_slots = self
                .mailbox_ids
                .iter()
                .copied()
                .zip(uid_range.iter())
                .collect::<Vec<_>>();

            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .create_document(document_slot)
                .set(
                    ValueClass::Property(Field::ARCHIVE.into()),
                    decoded_message.clone(),
                );
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Thread)
                .create_document(thread_slot);
            if self.force_split.swap(false, Ordering::SeqCst) {
                batch.add_commit_point();
            }

            let mailbox_uids = mailbox_slots
                .iter()
                .map(|(mailbox_id, slot)| PendingMailboxUid {
                    mailbox_id: *mailbox_id,
                    uid: PendingId::Slot(*slot),
                })
                .collect();
            let pending_ids = PendingRestoreIds::new(
                PendingId::Slot(document_slot),
                PendingId::Slot(thread_slot),
                mailbox_uids,
            )?;
            Ok((
                TestRestorePending {
                    document_slot,
                    thread_slot,
                    mailbox_slots,
                    decoded_message,
                    committed_calls: self.committed_calls.clone(),
                    committed_results: self.committed_results.clone(),
                    panic_after_commit: self.panic_after_commit.clone(),
                },
                pending_ids,
            ))
        }
    }

    fn committed<'a>(
        &'a self,
        pending: Self::Pending,
        assigned_ids: &'a AssignedIds,
    ) -> impl Future<Output = ()> + Send {
        async move {
            let result = RestoreResult {
                document_id: PendingId::Slot(pending.document_slot).resolve(assigned_ids),
                thread_id: PendingId::Slot(pending.thread_slot).resolve(assigned_ids),
                mailbox_uids: pending
                    .mailbox_slots
                    .iter()
                    .map(|(mailbox_id, slot)| RestoredMailboxUid {
                        mailbox_id: *mailbox_id,
                        uid: PendingId::Slot(*slot).resolve(assigned_ids),
                    })
                    .collect(),
            };
            assert!(result.document_id > 0);
            assert!(result.thread_id > 0);
            assert!(result.mailbox_uids.iter().all(|uid| uid.uid > 0));
            assert!(!pending.decoded_message.is_empty());
            pending.committed_results.lock().unwrap().push(result);
            pending.committed_calls.fetch_add(1, Ordering::SeqCst);
            if pending.panic_after_commit.swap(false, Ordering::SeqCst) {
                panic!("injected post-commit callback panic");
            }
        }
    }
}

fn restore_request(
    account: &VerifiedAccountMapping,
    capture_id: &str,
    operation_id: &str,
) -> RestoreRequest {
    RestoreRequest {
        source: account.clone(),
        destination: account.clone(),
        capture_id: capture_id.to_string(),
        operation_id: operation_id.to_string(),
        actor: "test-operator".into(),
        reason: "requested restore test".into(),
        now: 500,
    }
}

fn purge_request(
    scope: &RecoveryScope,
    capture_id: &str,
    operation_id: &str,
    now: u64,
) -> PurgeRequest {
    PurgeRequest {
        scope: scope.clone(),
        capture_id: capture_id.to_string(),
        operation_id: operation_id.to_string(),
        actor: "test-operator".into(),
        reason: "requested purge test".into(),
        now,
    }
}

async fn email_payload(metadata: &Store, document_id: u32) -> Option<Vec<u8>> {
    metadata
        .get_value::<RawBytes>(ValueKey {
            account_id: 7,
            collection: Collection::Email as u8,
            document_id,
            class: ValueClass::Property(Field::ARCHIVE.into()),
        })
        .await
        .unwrap()
        .map(|value| value.0)
}

fn synthetic_manifest(
    scope: RecoveryScope,
    capture_id: String,
    state: ManifestState,
    created_at: u64,
    deleted_at: Option<u64>,
    expires_at: u64,
    stored_size: u64,
) -> Manifest {
    let source_account_id = scope.account_id.parse().unwrap();
    Manifest {
        capture_operation_id: format!("capture-op-{capture_id}"),
        capture_id: capture_id.clone(),
        scope,
        state,
        original_blob_key: format!("original-{capture_id}").into_bytes(),
        recovery_blob_key: format!("recovery-{capture_id}").into_bytes(),
        stored_recovery_key_id: Some(2),
        source_account_id,
        source_collection: Collection::Email as u8,
        source_document_id: 42,
        source_revision: 1,
        created_at,
        deleted_at,
        expires_at,
        cause: "cleanup test".into(),
        folders: vec!["Inbox".into()],
        keywords: vec!["$seen".into()],
        received_at: Some(1),
        size: stored_size,
        stored_size,
        sha256: "a".repeat(64),
        policy_revision: 1,
        policy_digest: "b".repeat(64),
        hold_epoch: 1,
        copy_attempts: Vec::new(),
        selected_attempt_id: None,
    }
}

#[tokio::test]
async fn ephemeral_assertions_do_not_roll_back_earlier_mutations() {
    let metadata = EphemeralStore::open();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(91)
        .with_collection(Collection::Email)
        .with_document(1)
        .set(ValueClass::Property(250), b"already applied".to_vec())
        .assert_value(ValueClass::Property(251), AssertValue::Some);

    assert!(metadata.write_batch(&mut batch).await.is_err());
    assert_eq!(
        metadata
            .get_value::<RawBytes>(ValueKey {
                account_id: 91,
                collection: Collection::Email as u8,
                document_id: 1,
                class: ValueClass::Property(250),
            })
            .await
            .unwrap()
            .map(|value| value.0),
        Some(b"already applied".to_vec())
    );
}

#[tokio::test]
async fn restore_commits_new_email_uid_slots_and_durable_replay_receipt() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-capture", 100, 110).await;
    let importer = TestRestoreImporter::new(
        fixture.metadata.clone(),
        fixture.message.clone(),
        vec![11, 12],
    );
    let request = restore_request(&fixture.account, &capture_id, "restore-op-1");

    let first = fixture
        .engine
        .restore(request.clone(), &fixture.source_keys, &importer)
        .await
        .unwrap();
    let RestoreOutcome::Completed { result } = &first else {
        panic!("restore did not complete")
    };
    assert!(result.document_id > 0);
    assert!(result.thread_id > 0);
    assert_eq!(
        result
            .mailbox_uids
            .iter()
            .map(|uid| uid.mailbox_id)
            .collect::<Vec<_>>(),
        vec![11, 12]
    );
    assert!(result.mailbox_uids.iter().all(|uid| uid.uid > 0));
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        email_payload(&fixture.metadata, result.document_id).await,
        Some(fixture.message.clone())
    );

    let replay = fixture
        .engine
        .restore(request, &fixture.source_keys, &importer)
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .engine
            .account_lifecycle_status(fixture.account.scope())
            .await
            .unwrap()
            .unwrap()
            .pending_restores,
        0
    );
}

#[tokio::test]
async fn pending_restore_resumes_after_interruption_without_double_counting_gate() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-pending", 100, 110).await;
    let entered = Arc::new(Notify::new());
    let gate = Arc::new(Semaphore::new(0));
    let mut interrupted_mut =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    interrupted_mut.live_assertion_gate = Some((entered.clone(), gate));
    let interrupted = Arc::new(interrupted_mut);
    let request = restore_request(&fixture.account, &capture_id, "restore-resume");
    let engine = fixture.engine.clone();
    let keys = fixture.source_keys.clone();
    let importer = interrupted.clone();
    let notify = entered.notified();
    let task = tokio::spawn(async move { engine.restore(request, &keys, importer.as_ref()).await });
    notify.await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(interrupted.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .engine
            .account_lifecycle_status(fixture.account.scope())
            .await
            .unwrap()
            .unwrap()
            .pending_restores,
        1
    );

    let resumed =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    assert!(matches!(
        fixture
            .engine
            .restore(
                restore_request(&fixture.account, &capture_id, "restore-resume"),
                &fixture.source_keys,
                &resumed,
            )
            .await
            .unwrap(),
        RestoreOutcome::Completed { .. }
    ));
    assert_eq!(resumed.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .engine
            .account_lifecycle_status(fixture.account.scope())
            .await
            .unwrap()
            .unwrap()
            .pending_restores,
        0
    );
}

#[tokio::test]
async fn concurrent_restore_attempts_commit_only_one_import_and_retirement_is_fenced() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-concurrent", 100, 110).await;
    let mut importer =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    let (prepare_entered, mut prepare_entered_rx) = mpsc::unbounded_channel();
    let prepare_gate = Arc::new(Semaphore::new(0));
    importer.prepare_gate = Some((prepare_entered, prepare_gate.clone()));
    let importer = Arc::new(importer);
    let request = restore_request(&fixture.account, &capture_id, "restore-concurrent-op");

    let engine_one = fixture.engine.clone();
    let keys_one = fixture.source_keys.clone();
    let importer_one = importer.clone();
    let request_one = request.clone();
    let one = tokio::spawn(async move {
        engine_one
            .restore(request_one, &keys_one, importer_one.as_ref())
            .await
    });
    let engine_two = fixture.engine.clone();
    let keys_two = fixture.source_keys.clone();
    let importer_two = importer.clone();
    let request_two = request.clone();
    let two = tokio::spawn(async move {
        engine_two
            .restore(request_two, &keys_two, importer_two.as_ref())
            .await
    });

    prepare_entered_rx.recv().await.unwrap();
    prepare_entered_rx.recv().await.unwrap();
    assert!(matches!(
        fixture.engine.retire_account(fixture.account.scope()).await,
        Err(RecoveryError::InProgress)
    ));
    assert!(
        fixture
            .engine
            .purge(PurgeRequest {
                scope: fixture.account.scope().clone(),
                capture_id: capture_id.clone(),
                operation_id: "purge-racing-restore".into(),
                actor: "test-operator".into(),
                reason: "concurrency exclusion test".into(),
                now: 120,
            })
            .await
            .is_err()
    );
    let mut conflicting = restore_request(&fixture.account, &capture_id, "different-op");
    conflicting.now = 120;
    assert!(
        fixture
            .engine
            .restore(conflicting, &fixture.source_keys, importer.as_ref())
            .await
            .is_err()
    );
    prepare_gate.add_permits(2);

    let first = one.await.unwrap().unwrap();
    let second = two.await.unwrap().unwrap();
    assert_eq!(first, second);
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 2);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 1);
    let committed_results = importer.committed_results.lock().unwrap();
    assert_eq!(committed_results.len(), 1);
    let result = match first {
        RestoreOutcome::Completed { result } => result,
        _ => panic!("concurrent restore did not complete"),
    };
    let mut created_documents = Vec::new();
    for document_id in 1..=8 {
        if email_payload(&fixture.metadata, document_id)
            .await
            .is_some()
        {
            created_documents.push(document_id);
        }
    }
    assert_eq!(created_documents, vec![result.document_id]);

    fixture
        .engine
        .retire_account(fixture.account.scope())
        .await
        .unwrap();
    let retired_attempt = restore_request(&fixture.account, &capture_id, "after-retirement");
    assert!(
        fixture
            .engine
            .restore(retired_attempt, &fixture.source_keys, importer.as_ref())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn account_generation_mismatch_and_stale_live_account_cas_do_not_import() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-scope-check", 100, 110).await;
    let importer =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    let mut wrong_account = restore_request(&fixture.account, &capture_id, "wrong-account");
    wrong_account.destination =
        VerifiedAccountMapping::from_verified_binding(fixture.account.scope().clone(), 8).unwrap();
    assert!(
        fixture
            .engine
            .restore(wrong_account, &fixture.source_keys, &importer)
            .await
            .is_err()
    );

    let mut changed_generation = fixture.account.scope().clone();
    changed_generation.server_generation += 1;
    let mut wrong_generation = restore_request(&fixture.account, &capture_id, "wrong-generation");
    wrong_generation.destination =
        VerifiedAccountMapping::from_verified_binding(changed_generation, 7).unwrap();
    assert!(
        fixture
            .engine
            .restore(wrong_generation, &fixture.source_keys, &importer)
            .await
            .is_err()
    );
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 0);

    importer.stale_next_account_assertion();
    assert!(
        fixture
            .engine
            .restore(
                restore_request(&fixture.account, &capture_id, "stale-account-cas"),
                &fixture.source_keys,
                &importer,
            )
            .await
            .is_err()
    );
    let gate = fixture
        .engine
        .account_lifecycle_status(fixture.account.scope())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gate.pending_restores, 1);
    let summary = fixture
        .engine
        .lifecycle_summary(fixture.account.scope(), &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert!(summary.active_operation.unwrap().pending);
    let mut created_documents = Vec::new();
    for document_id in 1..=8 {
        if email_payload(&fixture.metadata, document_id)
            .await
            .is_some()
        {
            created_documents.push(document_id);
        }
    }
    assert!(created_documents.is_empty());
}

#[tokio::test]
async fn restore_replay_after_postcommit_callback_panic_returns_durable_ids() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-callback-panic", 100, 110).await;
    let importer = Arc::new(TestRestoreImporter::new(
        fixture.metadata.clone(),
        fixture.message.clone(),
        vec![11],
    ));
    importer.panic_after_commit.store(true, Ordering::SeqCst);
    let request = restore_request(&fixture.account, &capture_id, "callback-panic-op");
    let engine = fixture.engine.clone();
    let keys = fixture.source_keys.clone();
    let callback_importer = importer.clone();
    let callback_request = request.clone();
    let task = tokio::spawn(async move {
        engine
            .restore(callback_request, &keys, callback_importer.as_ref())
            .await
    });
    assert!(task.await.unwrap_err().is_panic());
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 1);

    let replay = fixture
        .engine
        .restore(request, &fixture.source_keys, importer.as_ref())
        .await
        .unwrap();
    assert!(matches!(replay, RestoreOutcome::Completed { .. }));
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_restore_ids_require_fresh_slots_and_mailbox_uids() {
    let mut batch = BatchBuilder::new();
    let document_slot = batch.reserve_document_id(7, Collection::Email);
    let thread_slot = batch.reserve_document_id(7, Collection::Thread);
    let uid_slot = batch.reserve_uid(7, 11);
    assert!(
        PendingRestoreIds::new(
            PendingId::Assigned(1),
            PendingId::Assigned(2),
            vec![PendingMailboxUid {
                mailbox_id: 11,
                uid: PendingId::Assigned(3),
            }],
        )
        .is_err()
    );
    assert!(
        PendingRestoreIds::new(
            PendingId::Slot(document_slot),
            PendingId::Slot(thread_slot),
            Vec::new(),
        )
        .is_err()
    );
    assert!(
        PendingRestoreIds::new(
            PendingId::Slot(document_slot),
            PendingId::Slot(thread_slot),
            vec![PendingMailboxUid {
                mailbox_id: 11,
                uid: PendingId::Slot(uid_slot),
            }],
        )
        .is_ok()
    );
}

#[tokio::test]
async fn corrupt_recovery_copy_fails_restore_without_import_or_gate_leak() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-corrupt", 100, 110).await;
    let manifest = fixture
        .engine
        .get(fixture.account.scope(), &capture_id)
        .await
        .unwrap()
        .unwrap();
    fixture
        .recovery_blobs
        .put_blob(
            &manifest.recovery_blob_key,
            b"corrupted recovery bytes",
            &BlobOpts::new(
                CompressionAlgo::None,
                BlobEncryption::Key(fixture.recovery_key.clone()),
            ),
        )
        .await
        .unwrap();
    let importer =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);

    assert!(
        fixture
            .engine
            .restore(
                restore_request(&fixture.account, &capture_id, "corrupt-restore-op"),
                &fixture.source_keys,
                &importer,
            )
            .await
            .is_err()
    );
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .engine
            .account_lifecycle_status(fixture.account.scope())
            .await
            .unwrap()
            .unwrap()
            .pending_restores,
        0
    );
    assert!(matches!(
        fixture
            .engine
            .lifecycle_summary(fixture.account.scope(), &capture_id)
            .await
            .unwrap()
            .unwrap()
            .active_operation,
        None
    ));
    for document_id in 1..=8 {
        assert!(
            email_payload(&fixture.metadata, document_id)
                .await
                .is_none()
        );
    }
}

#[tokio::test]
async fn restore_rejects_split_import_batch_before_any_document_write() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "restore-split", 100, 110).await;
    let importer =
        TestRestoreImporter::new(fixture.metadata.clone(), fixture.message.clone(), vec![11]);
    importer.force_split.store(true, Ordering::SeqCst);
    let request = restore_request(&fixture.account, &capture_id, "split-restore-op");

    assert!(matches!(
        fixture
            .engine
            .restore(request.clone(), &fixture.source_keys, &importer)
            .await,
        Err(RecoveryError::BatchTooLarge)
    ));
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(importer.committed_calls.load(Ordering::SeqCst), 0);
    for document_id in 1..=8 {
        assert!(
            email_payload(&fixture.metadata, document_id)
                .await
                .is_none()
        );
    }
    assert_eq!(
        fixture
            .engine
            .account_lifecycle_status(fixture.account.scope())
            .await
            .unwrap()
            .unwrap()
            .pending_restores,
        0
    );
    assert_eq!(
        fixture
            .engine
            .restore(request, &fixture.source_keys, &importer)
            .await
            .unwrap(),
        RestoreOutcome::Failed {
            code: "restore_batch_too_large".into(),
        }
    );
    assert_eq!(importer.prepare_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn active_hold_rejects_purge_without_erasing_the_copy() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "purge-held", 100, 110).await;
    let manifest = fixture
        .engine
        .get(fixture.account.scope(), &capture_id)
        .await
        .unwrap()
        .unwrap();
    fixture
        .engine
        .sync_hold(fixture.account.scope().clone(), 2, true)
        .await
        .unwrap();

    assert!(matches!(
        fixture
            .engine
            .purge(purge_request(
                fixture.account.scope(),
                &capture_id,
                "held-purge-op",
                120,
            ))
            .await,
        Err(RecoveryError::Held)
    ));
    assert_eq!(
        fixture
            .engine
            .get(fixture.account.scope(), &capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Preserved
    );
    assert!(
        fixture
            .recovery_blobs
            .get_raw_blob(&manifest.recovery_blob_key)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn purge_retries_after_blob_deletion_and_releases_quota_once() {
    let fixture = lifecycle_fixture().await;
    let capture_id = preserve_fixture_capture(&fixture, "purge-retry", 100, 110).await;
    let manifest = fixture
        .engine
        .get(fixture.account.scope(), &capture_id)
        .await
        .unwrap()
        .unwrap();
    let request = purge_request(fixture.account.scope(), &capture_id, "purge-retry-op", 120);
    let ledger_key = quota_key(fixture.account.scope()).unwrap();
    let index_key = account_capture_index_key(fixture.account.scope()).unwrap();
    let before = fixture
        .engine
        .read::<ScopeLedger>(&ledger_key)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(before.captures, vec![capture_id.clone()]);
    assert_eq!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&index_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .captures,
        vec![capture_id.clone()]
    );
    let charged_before = before.charged_bytes;

    fixture.engine.fail_next_purge_finalization();
    assert!(fixture.engine.purge(request.clone()).await.is_err());
    assert!(
        fixture
            .recovery_blobs
            .get_raw_blob(&manifest.recovery_blob_key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .engine
            .get(fixture.account.scope(), &capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Purging
    );
    let pending_hold = fixture
        .engine
        .read::<HoldControl>(&scoped_key(b"hold", fixture.account.scope(), "").unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(pending_hold.pending_purges, 1);
    assert!(matches!(
        fixture
            .engine
            .sync_hold(fixture.account.scope().clone(), 2, true)
            .await,
        Err(RecoveryError::InProgress)
    ));
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&ledger_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        charged_before
    );

    let PurgeOutcome::Purged { tombstone } = fixture.engine.purge(request.clone()).await.unwrap();
    assert_eq!(tombstone.capture_id, capture_id);
    assert_eq!(tombstone.deleted_at, Some(110));
    assert!(
        fixture
            .engine
            .read::<Manifest>(
                &scoped_key(b"manifest", fixture.account.scope(), &capture_id).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let after = fixture
        .engine
        .read::<ScopeLedger>(&ledger_key)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(after.captures.is_empty());
    assert_eq!(after.charged_bytes, 0);
    assert!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&index_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .captures
            .is_empty()
    );
    assert_eq!(
        fixture
            .engine
            .read::<HoldControl>(&scoped_key(b"hold", fixture.account.scope(), "").unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .pending_purges,
        0
    );

    let serialized_tombstone = serde_json::to_string(&tombstone).unwrap();
    assert!(!serialized_tombstone.contains("source-message-key"));
    assert!(!serialized_tombstone.contains("Original message"));
    assert!(!serialized_tombstone.contains("Inbox"));
    assert!(!serialized_tombstone.contains("$seen"));
    assert_eq!(
        fixture.engine.purge(request).await.unwrap(),
        PurgeOutcome::Purged { tombstone }
    );
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&ledger_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        0
    );
}

#[test]
fn policy_requires_explicit_acknowledgment_and_bounds() {
    assert!(enabled_policy().validate().is_ok());
    let mut invalid = enabled_policy();
    invalid.acknowledgment.clear();
    assert!(invalid.validate().is_err());
    let mut noncanonical = enabled_policy();
    noncanonical.reason = " Compliance record retention ".into();
    assert!(noncanonical.validate().is_err());
    assert!(Policy::default().validate().is_ok());
}

#[test]
fn policy_digest_matches_mail_canonical_fixture() {
    assert_eq!(
        policy_digest(&enabled_policy()).unwrap(),
        "a18615c3750741649e054eab7cba3bd15ae0f6370131103bb5ad58594e8c3552"
    );
}

#[test]
fn account_scope_identifiers_are_bounded() {
    let mut oversized = scope();
    oversized.account_id = "a".repeat(257);
    assert!(!valid_recovery_scope(&oversized));
    assert!(VerifiedAccountMapping::from_verified_binding(oversized, 7).is_err());
    let mut oversized_server = server_scope(&scope());
    oversized_server.server_id = "s".repeat(257);
    assert!(!valid_server_scope(&oversized_server));
}

#[tokio::test]
async fn policy_desired_revision_replay_skip_and_conflicts_are_explicit() {
    let metadata = EphemeralStore::open();
    let blobs = BlobStore::Store(EphemeralStore::open());
    let key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let keys = BlobKeyring::new(vec![key.clone()]);
    let engine = RecoveryEngine::new_for_test(
        metadata,
        blobs,
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(key)),
        keys,
    )
    .unwrap();
    let scope = server_scope(&scope());
    let policy = enabled_policy();
    let digest = policy_digest(&policy).unwrap();

    let first = engine
        .set_policy(scope.clone(), 4, &digest, policy.clone())
        .await
        .unwrap();
    assert_eq!(first.desired_revision, 4);
    let policy_key = scoped_key(b"policy", &scope, "").unwrap();
    let (_, first_bytes) = engine
        .read::<PolicyRecord>(&policy_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record_revision(&first_bytes).unwrap(), 1);
    assert_eq!(
        engine
            .set_policy(scope.clone(), 4, &digest, policy.clone())
            .await
            .unwrap(),
        first
    );
    let (_, replay_bytes) = engine
        .read::<PolicyRecord>(&policy_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record_revision(&replay_bytes).unwrap(), 1);

    let skipped = engine
        .set_policy(scope.clone(), 7, &digest, policy.clone())
        .await
        .unwrap();
    assert_eq!(skipped.desired_revision, 7);
    let (_, skipped_bytes) = engine
        .read::<PolicyRecord>(&policy_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record_revision(&skipped_bytes).unwrap(), 2);
    assert!(
        engine
            .set_policy(scope.clone(), 6, &digest, policy.clone())
            .await
            .is_err()
    );

    let mut conflicting = policy.clone();
    conflicting.reason = "Different compliance reason".into();
    let conflicting_digest = policy_digest(&conflicting).unwrap();
    assert!(
        engine
            .set_policy(scope.clone(), 7, &conflicting_digest, conflicting)
            .await
            .is_err()
    );
    let wrong_digest = "0".repeat(64);
    assert!(
        engine
            .set_policy(scope, 8, &wrong_digest, policy)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn encrypted_capture_is_staged_then_appended_with_source_revision_barrier() {
    let metadata = EphemeralStore::open();
    let source_blobs = BlobStore::Store(EphemeralStore::open());
    let recovery_blobs = BlobStore::Store(EphemeralStore::open());
    let source_key = Arc::new(BlobKey::new(
        1,
        SymmetricCipher::Aes256Gcm,
        &[1; BLOB_KEY_LEN],
    ));
    let recovery_key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let source_keys = BlobKeyring::new(vec![source_key.clone()]);
    let recovery_keys = BlobKeyring::new(vec![recovery_key.clone()]);
    let source_opts = BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(source_key));
    let recovery_opts = BlobOpts::new(
        CompressionAlgo::None,
        BlobEncryption::Key(recovery_key.clone()),
    );
    let source_key_bytes = b"source-key".to_vec();
    let payload = b"opaque encoded source blob";
    source_blobs
        .put_blob(&source_key_bytes, payload, &source_opts)
        .await
        .unwrap();
    let engine = RecoveryEngine::new_for_test(
        metadata.clone(),
        recovery_blobs.clone(),
        recovery_opts,
        recovery_keys,
    )
    .unwrap();
    let scope = scope();
    set_policy(&engine, server_scope(&scope), 3, enabled_policy())
        .await
        .unwrap();
    engine.sync_hold(scope.clone(), 1, false).await.unwrap();
    let request = CaptureRequest {
        account: VerifiedAccountMapping::from_verified_binding(scope.clone(), 7).unwrap(),
        metadata: CaptureMetadata {
            operation_id: "op-1".into(),
            cause: "jmap-destroy".into(),
            received_at: Some(9),
            folders: vec!["inbox".into()],
            keywords: vec!["$seen".into()],
        },
        original_blob_key: source_key_bytes,
        source: SourceAssertion {
            account_id: 7,
            collection: Collection::Email,
            document_id: 42,
            revision_property: Field::ARCHIVE.into(),
            revision: 1,
        },
        now: 100,
    };
    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(request.source.revision_property),
            1u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut source_batch).await.unwrap();
    let prepared = engine
        .prepare_capture(request.clone(), &source_blobs, &source_keys)
        .await
        .unwrap();
    let mut delete_batch = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut delete_batch, 105)
        .unwrap();
    delete_batch.clear(ValueClass::Property(request.source.revision_property));
    metadata.write_batch(&mut delete_batch).await.unwrap();
    assert_eq!(
        engine
            .get(&scope, &prepared.manifest().capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Preserved
    );
    let raw_source = source_blobs
        .get_raw_blob(&request.original_blob_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        engine
            .get_payload(&scope, &prepared.manifest().capture_id)
            .await
            .unwrap()
            .unwrap(),
        raw_source
    );
    metadata.danger_destroy_account(7).await.unwrap();
    assert!(
        metadata
            .get_value::<RawBytes>(ValueKey {
                account_id: 7,
                collection: Collection::Email as u8,
                document_id: 42,
                class: ValueClass::Property(request.source.revision_property),
            })
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine
            .get(&scope, &prepared.manifest().capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Preserved
    );
    assert_eq!(
        engine
            .get_payload(&scope, &prepared.manifest().capture_id)
            .await
            .unwrap()
            .unwrap(),
        raw_source
    );
    let missing_copy = RecoveryEngine::new_for_test(
        metadata.clone(),
        BlobStore::Store(EphemeralStore::open()),
        BlobOpts::new(
            CompressionAlgo::None,
            BlobEncryption::Key(recovery_key.clone()),
        ),
        BlobKeyring::new(vec![recovery_key.clone()]),
    )
    .unwrap();
    assert!(matches!(
        missing_copy
            .get_payload(&scope, &prepared.manifest().capture_id)
            .await,
        Err(RecoveryError::BlobMissing)
    ));
    recovery_blobs
        .put_blob(
            &prepared.manifest().recovery_blob_key,
            b"corrupt",
            &BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(recovery_key)),
        )
        .await
        .unwrap();
    assert!(
        engine
            .get_payload(&scope, &prepared.manifest().capture_id)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_hold_epoch_change_invalidates_a_prepared_delete() {
    let metadata = EphemeralStore::open();
    let src = BlobStore::Store(EphemeralStore::open());
    let dst = BlobStore::Store(EphemeralStore::open());
    let a = Arc::new(BlobKey::new(
        1,
        SymmetricCipher::Aes256Gcm,
        &[1; BLOB_KEY_LEN],
    ));
    let b = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let ak = BlobKeyring::new(vec![a.clone()]);
    let bk = BlobKeyring::new(vec![b.clone()]);
    src.put_blob(
        b"source",
        b"raw",
        &BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(a)),
    )
    .await
    .unwrap();
    let e = RecoveryEngine::new_for_test(
        metadata.clone(),
        dst,
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(b)),
        bk,
    )
    .unwrap();
    let s = scope();
    set_policy(&e, server_scope(&s), 1, enabled_policy())
        .await
        .unwrap();
    e.sync_hold(s.clone(), 1, false).await.unwrap();
    let source_revision_property = Field::ARCHIVE.into();
    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(source_revision_property),
            1u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut source_batch).await.unwrap();
    let request = CaptureRequest {
        account: VerifiedAccountMapping::from_verified_binding(s.clone(), 7).unwrap(),
        metadata: CaptureMetadata {
            operation_id: "race".into(),
            cause: "expunge".into(),
            received_at: None,
            folders: vec![],
            keywords: vec![],
        },
        original_blob_key: b"source".to_vec(),
        source: SourceAssertion {
            account_id: 7,
            collection: Collection::Email,
            document_id: 42,
            revision_property: source_revision_property,
            revision: 1,
        },
        now: 10,
    };
    let prepared = e.prepare_capture(request, &src, &ak).await.unwrap();
    e.sync_hold(s, 2, true).await.unwrap();
    let mut batch = BatchBuilder::new();
    prepared.append_to_delete_batch(&mut batch, 11).unwrap();
    assert!(metadata.write_batch(&mut batch).await.is_err());
}

#[tokio::test]
async fn disabled_policy_rejects_capture_before_source_access() {
    let metadata = EphemeralStore::open();
    let recovery_blobs = BlobStore::Store(EphemeralStore::open());
    let recovery_key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let recovery_keys = BlobKeyring::new(vec![recovery_key.clone()]);
    let engine = RecoveryEngine::new_for_test(
        metadata,
        recovery_blobs,
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(recovery_key)),
        recovery_keys,
    )
    .unwrap();
    let scope = scope();
    set_policy(&engine, server_scope(&scope), 1, Policy::default())
        .await
        .unwrap();
    let request = CaptureRequest {
        account: VerifiedAccountMapping::from_verified_binding(scope, 7).unwrap(),
        metadata: CaptureMetadata {
            operation_id: "disabled".into(),
            cause: "expunge".into(),
            received_at: None,
            folders: Vec::new(),
            keywords: Vec::new(),
        },
        original_blob_key: b"missing-source".to_vec(),
        source: SourceAssertion {
            account_id: 7,
            collection: Collection::Email,
            document_id: 42,
            revision_property: Field::ARCHIVE.into(),
            revision: u64::MAX,
        },
        now: 10,
    };
    let source_blobs = BlobStore::Store(EphemeralStore::open());
    let source_keys = BlobKeyring::default();
    assert!(matches!(
        engine
            .prepare_capture(request, &source_blobs, &source_keys)
            .await,
        Err(RecoveryError::Invalid("recovery is disabled"))
    ));
}

#[tokio::test]
async fn account_gate_requires_activation_and_never_reactivates_retired_generation() {
    let metadata = EphemeralStore::open();
    let key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let engine = RecoveryEngine::new_for_test(
        metadata,
        BlobStore::Store(EphemeralStore::open()),
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(key.clone())),
        BlobKeyring::new(vec![key]),
    )
    .unwrap();
    let scope = scope();
    let mapping = VerifiedAccountMapping::from_verified_binding(scope.clone(), 7).unwrap();

    assert!(engine.retire_account(&scope).await.is_err());
    engine.activate_account(&mapping).await.unwrap();
    engine.retire_account(&scope).await.unwrap();
    assert!(engine.activate_account(&mapping).await.is_err());
    let status = engine
        .account_lifecycle_status(&scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.state, AccountLifecycleState::Retired);
    assert_eq!(status.pending_restores, 0);
}

#[tokio::test]
async fn hold_sync_replay_and_activation_are_rejected_while_a_purge_is_pending() {
    let metadata = EphemeralStore::open();
    let key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let engine = RecoveryEngine::new_for_test(
        metadata,
        BlobStore::Store(EphemeralStore::open()),
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(key.clone())),
        BlobKeyring::new(vec![key]),
    )
    .unwrap();
    let scope = scope();
    engine.sync_hold(scope.clone(), 1, false).await.unwrap();
    let key = scoped_key(b"hold", &scope, "").unwrap();
    let (mut hold, bytes) = engine.read::<HoldControl>(&key).await.unwrap().unwrap();
    hold.pending_purges = 1;
    engine.cas_write(&key, Some(&bytes), &hold).await.unwrap();
    assert!(matches!(
        engine.sync_hold(scope.clone(), 1, false).await,
        Err(RecoveryError::InProgress)
    ));
    assert!(matches!(
        engine.sync_hold(scope, 2, true).await,
        Err(RecoveryError::InProgress)
    ));
}

#[tokio::test]
async fn source_cas_conflict_keeps_the_recovery_manifest_staging() {
    let metadata = EphemeralStore::open();
    let source = BlobStore::Store(EphemeralStore::open());
    let destination = BlobStore::Store(EphemeralStore::open());
    let source_key = Arc::new(BlobKey::new(
        1,
        SymmetricCipher::Aes256Gcm,
        &[1; BLOB_KEY_LEN],
    ));
    let recovery_key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let source_keys = BlobKeyring::new(vec![source_key.clone()]);
    let recovery_keys = BlobKeyring::new(vec![recovery_key.clone()]);
    let original_key = b"cas-source".to_vec();
    source
        .put_blob(
            &original_key,
            b"payload",
            &BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(source_key)),
        )
        .await
        .unwrap();
    let engine = RecoveryEngine::new_for_test(
        metadata.clone(),
        destination,
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(recovery_key)),
        recovery_keys,
    )
    .unwrap();
    let scope = scope();
    set_policy(&engine, server_scope(&scope), 1, enabled_policy())
        .await
        .unwrap();
    engine.sync_hold(scope.clone(), 1, false).await.unwrap();
    let source_revision_property = Field::ARCHIVE.into();
    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(source_revision_property),
            1u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut source_batch).await.unwrap();
    let request = CaptureRequest {
        account: VerifiedAccountMapping::from_verified_binding(scope.clone(), 7).unwrap(),
        metadata: CaptureMetadata {
            operation_id: "cas".into(),
            cause: "expunge".into(),
            received_at: None,
            folders: vec![],
            keywords: vec![],
        },
        original_blob_key: original_key,
        source: SourceAssertion {
            account_id: 7,
            collection: Collection::Email,
            document_id: 42,
            revision_property: source_revision_property,
            revision: 1,
        },
        now: 10,
    };
    let mut mismatched = request.clone();
    mismatched.account = VerifiedAccountMapping::from_verified_binding(scope.clone(), 8).unwrap();
    assert!(
        engine
            .prepare_capture(mismatched, &source, &source_keys)
            .await
            .is_err()
    );
    let prepared = engine
        .prepare_capture(request.clone(), &source, &source_keys)
        .await
        .unwrap();
    let mut changed_retry = request.clone();
    changed_retry.metadata.cause = "different-source-cause".into();
    assert!(
        engine
            .prepare_capture(changed_retry, &source, &source_keys)
            .await
            .is_err()
    );
    let mut changed = BatchBuilder::new();
    changed
        .with_account_id(7)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(source_revision_property),
            2u64.to_be_bytes().to_vec(),
        );
    metadata.write_batch(&mut changed).await.unwrap();
    let mut delete_batch = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut delete_batch, 11)
        .unwrap();
    assert!(metadata.write_batch(&mut delete_batch).await.is_err());
    assert_eq!(
        engine
            .get(&scope, &prepared.manifest().capture_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Staging
    );

    let mut missing = request.clone();
    missing.metadata.operation_id = "missing-source".into();
    missing.original_blob_key = b"absent".to_vec();
    assert!(matches!(
        engine.prepare_capture(missing, &source, &source_keys).await,
        Err(RecoveryError::BlobMissing)
    ));

    let mut reduced_quota = enabled_policy();
    reduced_quota.quota_bytes = Some(1);
    set_policy(&engine, server_scope(&scope), 2, reduced_quota)
        .await
        .unwrap();
    let mut over_quota = request;
    over_quota.metadata.operation_id = "over-quota".into();
    over_quota.source.revision = 2;
    assert!(matches!(
        engine
            .prepare_capture(over_quota, &source, &source_keys)
            .await,
        Err(RecoveryError::QuotaExceeded)
    ));
}

#[test]
fn unencrypted_or_unavailable_recovery_keys_are_rejected() {
    let metadata = EphemeralStore::open();
    let blobs = BlobStore::Store(EphemeralStore::open());
    assert!(
        RecoveryEngine::new_for_test(
            metadata.clone(),
            blobs.clone(),
            BlobOpts::PLAIN,
            BlobKeyring::default()
        )
        .is_err()
    );
    assert!(
        RecoveryEngine::new_for_test(
            metadata,
            blobs,
            BlobOpts::new(CompressionAlgo::None, BlobEncryption::Unavailable(9)),
            BlobKeyring::default()
        )
        .is_err()
    );
}

#[test]
fn recovery_engine_rejects_nontransactional_metadata_stores() {
    let key = Arc::new(BlobKey::new(
        2,
        SymmetricCipher::Aes256Gcm,
        &[2; BLOB_KEY_LEN],
    ));
    let options = BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(key.clone()));
    let keys = BlobKeyring::new(vec![key]);

    assert!(
        RecoveryEngine::new(
            Store::None,
            BlobStore::Store(EphemeralStore::open()),
            options.clone(),
            keys.clone(),
        )
        .is_err()
    );
    assert!(
        RecoveryEngine::new(
            EphemeralStore::open(),
            BlobStore::Store(EphemeralStore::open()),
            options,
            keys,
        )
        .is_err()
    );
}

#[tokio::test]
async fn delayed_same_operation_capture_retry_starts_retention_at_deletion_barrier() {
    let fixture = lifecycle_fixture().await;
    let first = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "delayed-delete", 10),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    assert_eq!(first.manifest().created_at, 10);
    assert_eq!(first.manifest().deleted_at, None);
    assert_eq!(first.manifest().expires_at, 0);

    let retry = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "delayed-delete", 100),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    assert_eq!(retry.manifest().created_at, 10);
    assert_eq!(retry.manifest().expires_at, 0);
    let capture_id = retry.manifest().capture_id.clone();

    let mut batch = BatchBuilder::new();
    retry.append_to_delete_batch(&mut batch, 200).unwrap();
    batch
        .with_account_id(fixture.account.store_account_id())
        .with_collection(Collection::Email)
        .with_document(42)
        .clear(ValueClass::Property(Field::ARCHIVE.into()));
    fixture.metadata.write_batch(&mut batch).await.unwrap();

    let preserved = fixture
        .engine
        .get(fixture.account.scope(), &capture_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.created_at, 10);
    assert_eq!(preserved.deleted_at, Some(200));
    assert_eq!(preserved.expires_at, 200 + 30 * 86_400);
}

#[tokio::test]
async fn retained_recovery_key_allows_staging_retry_and_preserved_read_after_rotation() {
    let fixture = lifecycle_fixture().await;
    let request = capture_request(&fixture, "key-rotation", 10);
    let first = fixture
        .engine
        .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
        .await
        .unwrap();
    let capture_id = first.manifest().capture_id.clone();
    let blob_key = first.manifest().recovery_blob_key.clone();
    assert_eq!(first.manifest().stored_recovery_key_id, Some(2));
    let source_payload = fixture
        .source_blobs
        .get_raw_blob(&fixture.source_blob_key)
        .await
        .unwrap()
        .unwrap();
    let old_blob = fixture
        .recovery_blobs
        .get_raw_blob(&blob_key)
        .await
        .unwrap()
        .unwrap();

    let new_key = Arc::new(BlobKey::new(
        3,
        SymmetricCipher::Aes256Gcm,
        &[3; BLOB_KEY_LEN],
    ));
    let rotated = RecoveryEngine::new_for_test(
        fixture.metadata.clone(),
        fixture.recovery_blobs.clone(),
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(new_key.clone())),
        BlobKeyring::new(vec![fixture.recovery_key.clone(), new_key.clone()]),
    )
    .unwrap();
    let retry = rotated
        .prepare_capture(request.clone(), &fixture.source_blobs, &fixture.source_keys)
        .await
        .unwrap();
    assert_eq!(retry.manifest().stored_recovery_key_id, Some(2));
    assert_eq!(
        fixture
            .recovery_blobs
            .get_raw_blob(&blob_key)
            .await
            .unwrap()
            .unwrap(),
        old_blob
    );

    let unavailable = RecoveryEngine::new_for_test(
        fixture.metadata.clone(),
        fixture.recovery_blobs.clone(),
        BlobOpts::new(CompressionAlgo::None, BlobEncryption::Key(new_key.clone())),
        BlobKeyring::new(vec![new_key]),
    )
    .unwrap();
    assert!(matches!(
        unavailable
            .prepare_capture(request, &fixture.source_blobs, &fixture.source_keys,)
            .await,
        Err(RecoveryError::BlobMismatch)
    ));

    let mut delete_batch = BatchBuilder::new();
    retry.append_to_delete_batch(&mut delete_batch, 11).unwrap();
    delete_batch
        .with_account_id(fixture.account.store_account_id())
        .with_collection(Collection::Email)
        .with_document(42)
        .clear(ValueClass::Property(Field::ARCHIVE.into()));
    fixture
        .metadata
        .write_batch(&mut delete_batch)
        .await
        .unwrap();
    assert_eq!(
        rotated
            .get_payload(fixture.account.scope(), &capture_id)
            .await
            .unwrap(),
        Some(source_payload)
    );
    assert!(matches!(
        unavailable
            .get_payload(fixture.account.scope(), &capture_id)
            .await,
        Err(RecoveryError::BlobMismatch)
    ));

    fixture
        .recovery_blobs
        .put_blob(&blob_key, &fixture.message, &BlobOpts::PLAIN)
        .await
        .unwrap();
    assert!(matches!(
        rotated
            .get_payload(fixture.account.scope(), &capture_id)
            .await,
        Err(RecoveryError::BlobMismatch)
    ));
}

#[tokio::test]
async fn old_staging_cleanup_cas_invalidates_prepared_source_deletion() {
    let fixture = lifecycle_fixture().await;
    let prepared = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "staging-cleanup", 10),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    let capture_id = prepared.manifest().capture_id.clone();

    let report = fixture
        .engine
        .cleanup_expired(fixture.account.scope(), 20, 5, 100, None)
        .await
        .unwrap();
    assert_eq!(report.purged_capture_ids, vec![capture_id.clone()]);
    assert!(
        fixture
            .engine
            .get(fixture.account.scope(), &capture_id)
            .await
            .unwrap()
            .is_none()
    );

    let mut prepared_delete = BatchBuilder::new();
    prepared
        .append_to_delete_batch(&mut prepared_delete, 21)
        .unwrap();
    prepared_delete
        .with_account_id(fixture.account.store_account_id())
        .with_collection(Collection::Email)
        .with_document(42)
        .clear(ValueClass::Property(Field::ARCHIVE.into()));
    assert!(
        fixture
            .metadata
            .write_batch(&mut prepared_delete)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .metadata
            .get_value::<RawBytes>(ValueKey {
                account_id: fixture.account.store_account_id(),
                collection: Collection::Email as u8,
                document_id: 42,
                class: ValueClass::Property(Field::ARCHIVE.into()),
            })
            .await
            .unwrap()
            .map(|value| value.0),
        Some(1u64.to_be_bytes().to_vec())
    );
}

#[tokio::test]
async fn cleanup_skips_copying_and_expired_preserved_records_under_hold() {
    let fixture = lifecycle_fixture().await;
    let scope = fixture.account.scope().clone();
    let copying_id = "1".repeat(64);
    let copying = synthetic_manifest(
        scope.clone(),
        copying_id.clone(),
        ManifestState::Copying,
        1,
        None,
        0,
        50,
    );
    fixture
        .engine
        .cas_write(
            &scoped_key(b"manifest", &scope, &copying_id).unwrap(),
            None,
            &copying,
        )
        .await
        .unwrap();
    let ledger_key = quota_key(&scope).unwrap();
    fixture
        .engine
        .cas_write(
            &ledger_key,
            None,
            &ScopeLedger {
                charged_bytes: 50,
                captures: vec![copying_id.clone()],
            },
        )
        .await
        .unwrap();
    let index_key = account_capture_index_key(&scope).unwrap();
    let (mut index, index_bytes) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    index.captures.push(copying_id.clone());
    fixture
        .engine
        .cas_write(&index_key, Some(&index_bytes), &index)
        .await
        .unwrap();

    let copying_report = fixture
        .engine
        .cleanup_expired(&scope, 1000, 5, 100, None)
        .await
        .unwrap();
    assert_eq!(copying_report.skipped, 1);
    assert!(copying_report.purged_capture_ids.is_empty());
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&ledger_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        50
    );

    let held_id = "2".repeat(64);
    let expired = synthetic_manifest(
        scope.clone(),
        held_id.clone(),
        ManifestState::Preserved,
        1,
        Some(10),
        20,
        75,
    );
    fixture
        .engine
        .cas_write(
            &scoped_key(b"manifest", &scope, &held_id).unwrap(),
            None,
            &expired,
        )
        .await
        .unwrap();
    let (_, ledger_bytes) = fixture
        .engine
        .read::<ScopeLedger>(&ledger_key)
        .await
        .unwrap()
        .unwrap();
    fixture
        .engine
        .cas_write(
            &ledger_key,
            Some(&ledger_bytes),
            &ScopeLedger {
                charged_bytes: 125,
                captures: vec![copying_id.clone(), held_id.clone()],
            },
        )
        .await
        .unwrap();
    let index_key = account_capture_index_key(&scope).unwrap();
    let (mut index, index_bytes) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    index.captures.push(held_id.clone());
    fixture
        .engine
        .cas_write(&index_key, Some(&index_bytes), &index)
        .await
        .unwrap();
    fixture
        .engine
        .sync_hold(scope.clone(), 2, true)
        .await
        .unwrap();

    let held_report = fixture
        .engine
        .cleanup_expired(&scope, 1000, 5, 100, None)
        .await
        .unwrap();
    assert_eq!(held_report.skipped, 2);
    assert!(held_report.purged_capture_ids.is_empty());
    assert_eq!(
        fixture
            .engine
            .get(&scope, &held_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManifestState::Preserved
    );
    assert_eq!(
        fixture
            .engine
            .read::<ScopeLedger>(&ledger_key)
            .await
            .unwrap()
            .unwrap()
            .0
            .charged_bytes,
        125
    );
}

#[tokio::test]
async fn cleanup_cursor_reaches_old_expired_records_and_excludes_other_scopes() {
    let fixture = lifecycle_fixture().await;
    let scope = fixture.account.scope().clone();
    let mut captures = Vec::new();
    for index in 0..230 {
        let capture_id = format!("{index:064x}");
        let mut record_scope = scope.clone();
        if index == 10 {
            record_scope.account_id = "8".into();
        }
        let (deleted_at, expires_at) = if index < 120 {
            (Some(100), 200)
        } else {
            (Some(1000), 2000)
        };
        let manifest = synthetic_manifest(
            record_scope.clone(),
            capture_id.clone(),
            ManifestState::Preserved,
            50,
            deleted_at,
            expires_at,
            1,
        );
        fixture
            .engine
            .cas_write(
                &scoped_key(b"manifest", &record_scope, &capture_id).unwrap(),
                None,
                &manifest,
            )
            .await
            .unwrap();
        captures.push(capture_id);
    }
    fixture
        .engine
        .cas_write(
            &quota_key(&scope).unwrap(),
            None,
            &ScopeLedger {
                charged_bytes: 230,
                captures,
            },
        )
        .await
        .unwrap();
    let index_key = account_capture_index_key(&scope).unwrap();
    let (mut index, index_bytes) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    index.captures = (0..230)
        .filter(|index| *index != 10)
        .map(|index| format!("{index:064x}"))
        .collect();
    fixture
        .engine
        .cas_write(&index_key, Some(&index_bytes), &index)
        .await
        .unwrap();

    let first = fixture
        .engine
        .cleanup_expired(&scope, 1000, 10, 100, None)
        .await
        .unwrap();
    assert_eq!(first.examined, 100);
    assert_eq!(first.purged_capture_ids.len(), 100);
    assert_eq!(first.skipped, 0);
    assert!(first.has_more);
    assert_eq!(
        first.next_cursor.as_deref(),
        Some(format!("{:064x}", 100).as_str())
    );

    let second = fixture
        .engine
        .cleanup_expired(&scope, 1000, 10, 100, first.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(second.examined, 100);
    assert_eq!(second.purged_capture_ids.len(), 19);
    assert_eq!(second.skipped, 81);
    assert!(second.has_more);
    assert_eq!(
        second.next_cursor.as_deref(),
        Some(format!("{:064x}", 200).as_str())
    );

    let last = fixture
        .engine
        .cleanup_expired(&scope, 1000, 10, 100, second.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(last.examined, 29);
    assert!(last.purged_capture_ids.is_empty());
    assert_eq!(last.skipped, 29);
    assert!(!last.has_more);
    assert_eq!(last.next_cursor, None);
}

#[tokio::test]
async fn account_capture_index_bounds_listing_and_cleanup_for_interleaved_accounts() {
    let fixture = lifecycle_fixture().await;
    let scope_a = fixture.account.scope().clone();
    let mut scope_b = scope_a.clone();
    scope_b.account_id = "8".into();
    let account_b = VerifiedAccountMapping::from_verified_binding(scope_b.clone(), 8).unwrap();
    fixture
        .engine
        .sync_hold(scope_b.clone(), 1, false)
        .await
        .unwrap();

    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(8)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(Field::ARCHIVE.into()),
            1u64.to_be_bytes().to_vec(),
        );
    fixture
        .metadata
        .write_batch(&mut source_batch)
        .await
        .unwrap();

    let mut total_charged = 0;
    let first_a = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "account-a-1", 10),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    total_charged += first_a.manifest().stored_size;
    let first_a_id = first_a.manifest().capture_id.clone();

    for index in 0..20 {
        let mut request = capture_request(&fixture, &format!("account-b-{index}"), 20 + index);
        request.account = account_b.clone();
        request.source.account_id = 8;
        let prepared = fixture
            .engine
            .prepare_capture(request, &fixture.source_blobs, &fixture.source_keys)
            .await
            .unwrap();
        total_charged += prepared.manifest().stored_size;
    }

    let second_a = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "account-a-2", 11),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    total_charged += second_a.manifest().stored_size;
    let second_a_id = second_a.manifest().capture_id.clone();

    for index in 20..40 {
        let mut request = capture_request(&fixture, &format!("account-b-{index}"), 40 + index);
        request.account = account_b.clone();
        request.source.account_id = 8;
        let prepared = fixture
            .engine
            .prepare_capture(request, &fixture.source_blobs, &fixture.source_keys)
            .await
            .unwrap();
        total_charged += prepared.manifest().stored_size;
    }

    let ledger = fixture
        .engine
        .read::<ScopeLedger>(&quota_key(&scope_a).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(ledger.captures.len(), 42);
    assert_eq!(ledger.charged_bytes, total_charged);
    let mut expected_account_a_ids = vec![first_a_id, second_a_id.clone()];
    expected_account_a_ids.sort_unstable();
    assert_eq!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&account_capture_index_key(&scope_a).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .captures,
        expected_account_a_ids
    );
    assert_eq!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&account_capture_index_key(&scope_b).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .captures
            .len(),
        40
    );

    fixture.engine.reset_read_count();
    let listed = fixture.engine.list_page(&scope_a, None, 1).await.unwrap();
    assert!(listed.items.is_empty());
    assert!(listed.has_more);
    assert!(listed.next_cursor.is_some());
    assert_eq!(fixture.engine.read_count(), 2);

    fixture.engine.reset_read_count();
    let cleanup = fixture
        .engine
        .cleanup_expired(&scope_a, 20, 100, 100, None)
        .await
        .unwrap();
    assert_eq!(cleanup.examined, 2);
    assert!(cleanup.purged_capture_ids.is_empty());
    assert_eq!(fixture.engine.read_count(), 3);
}

#[tokio::test]
async fn tenant_capture_limit_and_byte_charge_remain_aggregate_across_account_indexes() {
    let fixture = lifecycle_fixture().await;
    let scope_a = fixture.account.scope().clone();
    let mut scope_b = scope_a.clone();
    scope_b.account_id = "8".into();
    let account_b = VerifiedAccountMapping::from_verified_binding(scope_b.clone(), 8).unwrap();
    fixture
        .engine
        .sync_hold(scope_b.clone(), 1, false)
        .await
        .unwrap();

    let mut source_batch = BatchBuilder::new();
    source_batch
        .with_account_id(8)
        .with_collection(Collection::Email)
        .with_document(42)
        .set(
            ValueClass::Property(Field::ARCHIVE.into()),
            1u64.to_be_bytes().to_vec(),
        );
    fixture
        .metadata
        .write_batch(&mut source_batch)
        .await
        .unwrap();

    let captures = (0..MAX_ITEMS_PER_SCOPE - 1)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let split = MAX_ITEMS_PER_SCOPE / 2;
    let (_, account_a_index_revision) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&account_capture_index_key(&scope_a).unwrap())
        .await
        .unwrap()
        .unwrap();
    fixture
        .engine
        .cas_write(
            &account_capture_index_key(&scope_a).unwrap(),
            Some(&account_a_index_revision),
            &ScopeCaptureIndex {
                scope: scope_a.clone(),
                captures: captures[..split].to_vec(),
            },
        )
        .await
        .unwrap();
    fixture
        .engine
        .cas_write(
            &account_capture_index_key(&scope_b).unwrap(),
            None,
            &ScopeCaptureIndex {
                scope: scope_b.clone(),
                captures: captures[split..].to_vec(),
            },
        )
        .await
        .unwrap();
    fixture
        .engine
        .cas_write(
            &quota_key(&scope_a).unwrap(),
            None,
            &ScopeLedger {
                charged_bytes: 321,
                captures,
            },
        )
        .await
        .unwrap();

    let added = fixture
        .engine
        .prepare_capture(
            capture_request(&fixture, "aggregate-limit-a", 20),
            &fixture.source_blobs,
            &fixture.source_keys,
        )
        .await
        .unwrap();
    let expected_bytes = 321 + added.manifest().stored_size;
    let mut request_b = capture_request(&fixture, "aggregate-limit-b", 21);
    request_b.account = account_b;
    request_b.source.account_id = 8;
    assert!(matches!(
        fixture
            .engine
            .prepare_capture(request_b, &fixture.source_blobs, &fixture.source_keys)
            .await,
        Err(RecoveryError::QuotaExceeded)
    ));

    let ledger = fixture
        .engine
        .read::<ScopeLedger>(&quota_key(&scope_a).unwrap())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(ledger.captures.len(), MAX_ITEMS_PER_SCOPE);
    assert_eq!(ledger.charged_bytes, expected_bytes);
    assert_eq!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&account_capture_index_key(&scope_b).unwrap())
            .await
            .unwrap()
            .unwrap()
            .0
            .captures
            .len(),
        MAX_ITEMS_PER_SCOPE - 1 - split
    );
}

#[tokio::test]
async fn ephemeral_account_capture_index_cas_race_keeps_one_writer() {
    let fixture = lifecycle_fixture().await;
    let scope = fixture.account.scope().clone();
    let index_key = account_capture_index_key(&scope).unwrap();
    let initial = ScopeCaptureIndex {
        scope: scope.clone(),
        captures: vec![format!("{:064x}", 1)],
    };
    let (_, revision) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    fixture
        .engine
        .cas_write(&index_key, Some(&revision), &initial)
        .await
        .unwrap();
    let (_, revision) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    let left = ScopeCaptureIndex {
        captures: vec![initial.captures[0].clone(), format!("{:064x}", 2)],
        ..initial.clone()
    };
    let right = ScopeCaptureIndex {
        captures: vec![initial.captures[0].clone(), format!("{:064x}", 3)],
        ..initial
    };
    let mut left_batch = BatchBuilder::new();
    fixture
        .engine
        .append_cas(&mut left_batch, &index_key, Some(&revision), &left)
        .unwrap();
    let mut right_batch = BatchBuilder::new();
    fixture
        .engine
        .append_cas(&mut right_batch, &index_key, Some(&revision), &right)
        .unwrap();

    let (left_result, right_result) = tokio::join!(
        fixture.metadata.write_batch(&mut left_batch),
        fixture.metadata.write_batch(&mut right_batch)
    );
    assert_ne!(left_result.is_ok(), right_result.is_ok());
    let expected = if left_result.is_ok() { left } else { right };
    assert_eq!(
        fixture
            .engine
            .read::<ScopeCaptureIndex>(&index_key)
            .await
            .unwrap()
            .unwrap()
            .0,
        expected
    );
}

#[tokio::test]
async fn empty_account_page_does_not_probe_large_tenant_ledger() {
    let fixture = lifecycle_fixture().await;
    let mut other_scope = fixture.account.scope().clone();
    other_scope.account_id = "8".into();
    let other = VerifiedAccountMapping::from_verified_binding(other_scope.clone(), 8).unwrap();
    fixture.engine.activate_account(&other).await.unwrap();
    fixture
        .engine
        .cas_write(
            &quota_key(fixture.account.scope()).unwrap(),
            None,
            &ScopeLedger {
                charged_bytes: 123,
                captures: (0..MAX_ITEMS_PER_SCOPE)
                    .map(|index| format!("{index:064x}"))
                    .collect(),
            },
        )
        .await
        .unwrap();

    fixture.engine.reset_read_count();
    let page = fixture
        .engine
        .list_page(&other_scope, None, 100)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert!(!page.has_more);
    assert_eq!(page.next_cursor, None);
    assert_eq!(fixture.engine.read_count(), 1);
}

#[tokio::test]
async fn capture_page_cursor_advances_across_nonvisible_index_slots() {
    let fixture = lifecycle_fixture().await;
    let scope = fixture.account.scope().clone();
    let ids = (0..MAX_ITEMS_PER_SCOPE)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let index_key = account_capture_index_key(&scope).unwrap();
    let (_, revision) = fixture
        .engine
        .read::<ScopeCaptureIndex>(&index_key)
        .await
        .unwrap()
        .unwrap();
    fixture
        .engine
        .cas_write(
            &index_key,
            Some(&revision),
            &ScopeCaptureIndex {
                scope: scope.clone(),
                captures: ids.clone(),
            },
        )
        .await
        .unwrap();

    for chunk in ids.chunks(100) {
        let mut batch = BatchBuilder::new();
        for capture_id in chunk {
            let manifest = synthetic_manifest(
                scope.clone(),
                capture_id.clone(),
                ManifestState::Copying,
                1,
                None,
                0,
                1,
            );
            batch.with_account_id(0).set(
                value_class(&scoped_key(b"manifest", &scope, capture_id).unwrap()),
                encode_record(&manifest, 1).unwrap(),
            );
        }
        fixture.metadata.write_batch(&mut batch).await.unwrap();
    }

    fixture.engine.reset_read_count();
    let first = fixture.engine.list_page(&scope, None, 100).await.unwrap();
    assert!(first.items.is_empty());
    assert!(first.has_more);
    assert_eq!(first.next_cursor.as_deref(), Some(ids[99].as_str()));
    assert_eq!(fixture.engine.read_count(), 101);

    fixture.engine.reset_read_count();
    let second = fixture
        .engine
        .list_page(&scope, first.next_cursor.as_deref(), 100)
        .await
        .unwrap();
    assert!(second.items.is_empty());
    assert!(second.has_more);
    assert_eq!(second.next_cursor.as_deref(), Some(ids[199].as_str()));
    assert_eq!(fixture.engine.read_count(), 101);
}
