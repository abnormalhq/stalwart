/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use super::*;
use registry::schema::enums::{CompressionAlgo, SymmetricCipher};
use std::sync::Arc;
use store::{
    BlobStore, ValueKey,
    backend::ephemeral::EphemeralStore,
    write::blob_codec::{BLOB_KEY_LEN, BlobKey},
};

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
    let engine = RecoveryEngine::new(
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
    let engine = RecoveryEngine::new(
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
    prepared.append_to_delete_batch(&mut delete_batch).unwrap();
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
            .get_value::<Vec<u8>>(ValueKey {
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
    let missing_copy = RecoveryEngine::new(
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
    let e = RecoveryEngine::new(
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
    prepared.append_to_delete_batch(&mut batch).unwrap();
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
    let engine = RecoveryEngine::new(
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
    let engine = RecoveryEngine::new(
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
    prepared.append_to_delete_batch(&mut delete_batch).unwrap();
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
        RecoveryEngine::new(
            metadata.clone(),
            blobs.clone(),
            BlobOpts::PLAIN,
            BlobKeyring::default()
        )
        .is_err()
    );
    assert!(
        RecoveryEngine::new(
            metadata,
            blobs,
            BlobOpts::new(CompressionAlgo::None, BlobEncryption::Unavailable(9)),
            BlobKeyring::default()
        )
        .is_err()
    );
}
