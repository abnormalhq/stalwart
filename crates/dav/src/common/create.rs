/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::{DavError, Result};
use common::{GroupwareResources, Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use std::{future::Future, sync::Arc};
use store::{
    Store, Subspace,
    write::{AnyClass, AnyKey, AssignedIds, BatchBuilder, ValueClass},
};
use types::collection::SyncCollection;

const DAV_FENCE_PREFIX: [u8; 5] = [0x02, b'D', b'A', b'V', 0x01];

#[cfg(test)]
static TEST_PREPARE_BARRIER: std::sync::Mutex<
    Option<(Arc<tokio::sync::Barrier>, std::sync::atomic::AtomicUsize)>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn set_test_prepare_barrier(participants: usize) {
    *TEST_PREPARE_BARRIER.lock().expect("test barrier mutex") = Some((
        Arc::new(tokio::sync::Barrier::new(participants)),
        std::sync::atomic::AtomicUsize::new(participants),
    ));
}

#[cfg(test)]
async fn wait_test_prepare_barrier() {
    let barrier = {
        let mut hook = TEST_PREPARE_BARRIER.lock().expect("test barrier mutex");
        match hook.take() {
            Some((barrier, remaining)) => {
                let last = remaining.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1;
                if !last {
                    *hook = Some((barrier.clone(), remaining));
                }
                Some(barrier)
            }
            None => None,
        }
    };
    if let Some(barrier) = barrier {
        tokio::time::timeout(std::time::Duration::from_secs(10), barrier.wait())
            .await
            .expect("timed out waiting for DAV create test barrier");
    }
}

pub(crate) struct DavCreateFence {
    key: Vec<u8>,
    generation: Option<u64>,
}

impl DavCreateFence {
    pub(crate) async fn prepare(
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        collection: SyncCollection,
    ) -> trc::Result<(Arc<GroupwareResources>, Self)> {
        let fence = Self::read(server.store(), account_id, collection).await?;
        let resources = server
            .fetch_groupware_resources_at(
                access_token.account_id(),
                account_id,
                collection,
                u64::MAX,
            )
            .await?;

        #[cfg(test)]
        wait_test_prepare_barrier().await;

        Ok((resources, fence))
    }

    async fn read(store: &Store, account_id: u32, collection: SyncCollection) -> trc::Result<Self> {
        let key = fence_key(account_id, collection);
        let generation = store
            .get_value::<u64>(AnyKey {
                subspace: Subspace::System,
                key: key.clone(),
            })
            .await?;

        Ok(Self { key, generation })
    }

    pub(crate) async fn commit(&self, server: &Server, batch: BatchBuilder) -> Result<AssignedIds> {
        self.commit_with(batch, |batch| server.commit_batch(batch))
            .await
    }

    async fn commit_with<F, Fut>(&self, mut batch: BatchBuilder, commit: F) -> Result<AssignedIds>
    where
        F: FnOnce(BatchBuilder) -> Fut,
        Fut: Future<Output = trc::Result<AssignedIds>>,
    {
        if batch.has_commit_points() {
            return Err(DavError::Internal(
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("DAV fence refuses a pre-split batch"),
            ));
        }

        let next_generation = self
            .generation
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("DAV namespace fence overflow")
            })?;
        let class = ValueClass::Any(AnyClass {
            subspace: Subspace::System,
            key: self.key.clone(),
        });
        match self.generation {
            Some(generation) => batch.assert_value(class.clone(), generation),
            None => batch.assert_value(class.clone(), ()),
        };
        batch.set(class, next_generation.to_be_bytes());

        match commit(batch).await {
            Ok(assigned_ids) => Ok(assigned_ids),
            Err(err) if err.is_assertion_failure() => Err(DavError::Internal(err)),
            Err(err) => Err(err.into()),
        }
    }
}

fn fence_key(account_id: u32, collection: SyncCollection) -> Vec<u8> {
    let mut key = Vec::with_capacity(DAV_FENCE_PREFIX.len() + 5);
    key.extend_from_slice(&DAV_FENCE_PREFIX);
    key.extend_from_slice(&account_id.to_be_bytes());
    key.push(u8::from(collection));
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs::DataStore;
    #[cfg(feature = "test-rocks")]
    use registry::schema::structs::RocksDbStore;
    #[cfg(not(any(feature = "test-postgres", feature = "test-rocks")))]
    use registry::schema::structs::SqliteStore as SqliteConfig;
    #[cfg(feature = "test-postgres")]
    use registry::schema::structs::{PostgreSqlStore, SecretKeyOptional};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use store::{
        ValueKey,
        query::log::Query,
        write::{AnyClass, BatchBuilder, LogCollection, ValueClass},
    };
    use types::collection::{Collection, SyncCollection};

    static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);
    #[cfg(feature = "test-postgres")]
    static POSTGRES_TABLES_CREATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    const TEST_TIMEOUT: Duration = Duration::from_secs(45);

    enum TestBackend {
        #[cfg(not(any(feature = "test-postgres", feature = "test-rocks")))]
        Sqlite,
        #[cfg(feature = "test-rocks")]
        RocksDb,
        #[cfg(feature = "test-postgres")]
        PostgreSql { port: u16 },
    }

    struct TestDb {
        path: Option<PathBuf>,
        backend: TestBackend,
        id_base: u32,
    }

    impl TestDb {
        fn new() -> Self {
            #[cfg(feature = "test-postgres")]
            {
                return Self::postgres();
            }
            #[cfg(all(not(feature = "test-postgres"), feature = "test-rocks"))]
            {
                return Self::rocksdb();
            }
            #[cfg(not(any(feature = "test-postgres", feature = "test-rocks")))]
            Self::sqlite()
        }

        fn next_id_base() -> u32 {
            let process = std::process::id() % 1_000_000;
            let sequence = (NEXT_DB_ID.fetch_add(1, Ordering::Relaxed) % 100) as u32;
            process
                .saturating_mul(1000)
                .saturating_add(sequence.saturating_mul(100))
        }

        fn id(&self, offset: u32) -> u32 {
            self.id_base.saturating_add(offset)
        }

        #[cfg(not(any(feature = "test-postgres", feature = "test-rocks")))]
        fn sqlite() -> Self {
            Self::local(TestBackend::Sqlite)
        }

        #[cfg(any(feature = "test-rocks", not(feature = "test-postgres")))]
        fn local(backend: TestBackend) -> Self {
            let id_base = Self::next_id_base();
            let path = std::env::temp_dir().join(format!(
                "dav-fence-{}-{}",
                std::process::id(),
                NEXT_DB_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self {
                path: Some(path),
                backend,
                id_base,
            }
        }

        #[cfg(feature = "test-rocks")]
        fn rocksdb() -> Self {
            Self::local(TestBackend::RocksDb)
        }

        #[cfg(feature = "test-postgres")]
        fn postgres() -> Self {
            assert_eq!(
                std::env::var("STALWART_DAV_FENCE_POSTGRES").as_deref(),
                Ok("loopback"),
                "set STALWART_DAV_FENCE_POSTGRES=loopback to opt into the local PostgreSQL contract"
            );
            let port = std::env::var("STALWART_DAV_FENCE_POSTGRES_PORT")
                .expect("set the explicit loopback PostgreSQL test port")
                .parse::<u16>()
                .expect("parse loopback PostgreSQL test port");
            assert_ne!(port, 0, "PostgreSQL test port must be nonzero");
            Self {
                path: None,
                backend: TestBackend::PostgreSql { port },
                id_base: Self::next_id_base(),
            }
        }

        async fn open(&self) -> Store {
            let config = match &self.backend {
                #[cfg(not(any(feature = "test-postgres", feature = "test-rocks")))]
                TestBackend::Sqlite => DataStore::Sqlite(SqliteConfig {
                    path: self
                        .path
                        .as_ref()
                        .expect("SQLite test path")
                        .to_string_lossy()
                        .into_owned(),
                    pool_workers: Some(2),
                    pool_max_connections: Some(4),
                }),
                #[cfg(feature = "test-rocks")]
                TestBackend::RocksDb => {
                    let mut config = RocksDbStore::default();
                    config.path = self
                        .path
                        .as_ref()
                        .expect("RocksDB test path")
                        .to_string_lossy()
                        .into_owned();
                    DataStore::RocksDb(config)
                }
                #[cfg(feature = "test-postgres")]
                TestBackend::PostgreSql { port } => {
                    let mut config = PostgreSqlStore::default();
                    config.host = "127.0.0.1".to_string();
                    config.port = u64::from(*port);
                    config.database = "dav_fence_test".to_string();
                    config.auth_username = Some("postgres".to_string());
                    config.auth_secret = SecretKeyOptional::None;
                    config.connect_timeout =
                        Some(registry::schema::prelude::Duration(Duration::from_secs(3)));
                    config.response_timeout =
                        Some(registry::schema::prelude::Duration(Duration::from_secs(5)));
                    config.pool_max_connections = Some(4);
                    DataStore::PostgreSql(config)
                }
            };
            let store = tokio::time::timeout(TEST_TIMEOUT, Store::build(config))
                .await
                .expect("timed out opening DAV fence test store")
                .expect("open selected DAV fence test store");
            #[cfg(feature = "test-postgres")]
            if matches!(&self.backend, TestBackend::PostgreSql { .. }) {
                POSTGRES_TABLES_CREATED
                    .get_or_init(|| async {
                        tokio::time::timeout(TEST_TIMEOUT, store.create_tables())
                            .await
                            .expect("timed out creating PostgreSQL DAV fence tables")
                            .expect("create PostgreSQL DAV fence tables");
                    })
                    .await;
            } else {
                tokio::time::timeout(TEST_TIMEOUT, store.create_tables())
                    .await
                    .expect("timed out creating DAV fence test tables")
                    .expect("create selected DAV fence test tables");
            }
            #[cfg(not(feature = "test-postgres"))]
            tokio::time::timeout(TEST_TIMEOUT, store.create_tables())
                .await
                .expect("timed out creating DAV fence test tables")
                .expect("create selected DAV fence test tables");
            store
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            if let Some(path) = &self.path {
                let _ = fs::remove_dir_all(path);
            }
        }
    }

    fn resource_batch(
        account_id: u32,
        collection: Collection,
        sync_collection: SyncCollection,
        document_id: u32,
    ) -> BatchBuilder {
        let archive = ValueKey::archive(account_id, collection, document_id);
        let mut batch = BatchBuilder::new_atomic();
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .with_document(document_id)
            .set(archive.class, b"dav-resource".to_vec())
            .log_item_insert(sync_collection, None)
            .add(ValueClass::Quota, 1);
        batch
    }

    async fn commit_to_store(
        fence: &DavCreateFence,
        store: &Store,
        batch: BatchBuilder,
    ) -> Result<AssignedIds> {
        let store = store.clone();
        fence
            .commit_with(batch, move |mut batch| async move {
                store.write_batch(&mut batch).await
            })
            .await
    }

    fn large_resource_batch(account_id: u32, first_document_id: u32, count: u32) -> BatchBuilder {
        let mut batch = BatchBuilder::new_atomic();
        for document_id in first_document_id..first_document_id + count {
            let archive = ValueKey::archive(account_id, Collection::CalendarEvent, document_id);
            batch
                .with_account_id(account_id)
                .with_collection(Collection::CalendarEvent)
                .with_document(document_id)
                .set(archive.class, b"dav-resource".to_vec())
                .log_item_insert(SyncCollection::Calendar, None)
                .add(ValueClass::Quota, 1)
                .commit_point();
        }
        batch
    }

    async fn quota(store: &Store, account_id: u32) -> i64 {
        store
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Quota,
            })
            .await
            .expect("read account quota")
    }

    async fn calendar_log_count(store: &Store, account_id: u32) -> usize {
        store
            .changes(
                account_id,
                LogCollection::Sync(SyncCollection::Calendar),
                Query::All,
            )
            .await
            .expect("read calendar change log")
            .changes
            .len()
    }

    fn is_assertion_failure(result: &Result<AssignedIds>) -> bool {
        matches!(result, Err(DavError::Internal(err)) if err.is_assertion_failure())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_first_insert_rolls_back_losing_resource_log_and_quota() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let db = TestDb::new();
            let store = db.open().await;
            let account_id = db.id(7);
            let first_document_id = db.id(41);
            let second_document_id = db.id(42);
            let first = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read first absent fence");
            let second = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read competing absent fence");
            let first_store = store.clone();
            let second_store = store.clone();
            let (first_result, second_result) = tokio::time::timeout(TEST_TIMEOUT, async {
                tokio::join!(
                    first.commit_with(
                        resource_batch(
                            account_id,
                            Collection::CalendarEvent,
                            SyncCollection::Calendar,
                            first_document_id,
                        ),
                        |mut batch| async move { first_store.write_batch(&mut batch).await },
                    ),
                    second.commit_with(
                        resource_batch(
                            account_id,
                            Collection::CalendarEvent,
                            SyncCollection::Calendar,
                            second_document_id,
                        ),
                        |mut batch| async move { second_store.write_batch(&mut batch).await },
                    )
                )
            })
            .await
            .expect("timed out racing first writers");

            assert_ne!(first_result.is_ok(), second_result.is_ok());
            assert!(is_assertion_failure(if first_result.is_err() {
                &first_result
            } else {
                &second_result
            }));
            let first_resource = store
                .key_exists(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    first_document_id,
                ))
                .await
                .expect("read first resource");
            let second_resource = store
                .key_exists(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    second_document_id,
                ))
                .await
                .expect("read second resource");
            assert_ne!(first_resource, second_resource);
            assert_eq!(calendar_log_count(&store, account_id).await, 1);
            assert_eq!(quota(&store, account_id).await, 1);
            assert_eq!(
                DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                    .await
                    .expect("read committed fence")
                    .generation,
                Some(1)
            );
        })
        .await
        .expect("DAV fence contract test timed out");
    }

    #[tokio::test]
    async fn pre_split_batch_is_rejected_before_commit() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            use std::sync::atomic::{AtomicBool, Ordering};

            let db = TestDb::new();
            let store = db.open().await;
            let account_id = db.id(8);
            let document_id = db.id(43);
            let fence = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read fence for pre-split rejection");
            let archive = ValueKey::archive(account_id, Collection::CalendarEvent, document_id);
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::CalendarEvent)
                .with_document(document_id)
                .set(archive.class.clone(), b"must-not-commit".to_vec())
                .add_commit_point();
            assert!(batch.has_commit_points());

            let called = Arc::new(AtomicBool::new(false));
            let called_in_commit = called.clone();
            let result = fence
                .commit_with(batch, move |_| async move {
                    called_in_commit.store(true, Ordering::SeqCst);
                    Ok(AssignedIds::default())
                })
                .await;

            assert!(result.is_err());
            assert!(!called.load(Ordering::SeqCst));
            assert!(
                !store
                    .key_exists(archive)
                    .await
                    .expect("read resource after pre-split rejection")
            );
            assert_eq!(calendar_log_count(&store, account_id).await, 0);
            assert_eq!(quota(&store, account_id).await, 0);
        })
        .await
        .expect("pre-split fence test timed out");
    }

    #[tokio::test]
    async fn stale_large_atomic_batch_rolls_back_resources_log_and_quota() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            const LARGE_RESOURCE_COUNT: u32 = 1100;

            let db = TestDb::new();
            let store = db.open().await;
            let account_id = db.id(9);
            let stale = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read stale fence");
            let winner = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read winning fence");
            assert!(
                commit_to_store(
                    &winner,
                    &store,
                    resource_batch(
                        account_id,
                        Collection::CalendarEvent,
                        SyncCollection::Calendar,
                        db.id(50),
                    ),
                )
                .await
                .is_ok()
            );

            let first_document_id = db.id(100);
            let batch = large_resource_batch(account_id, first_document_id, LARGE_RESOURCE_COUNT);
            assert!(!batch.has_commit_points());
            let result = commit_to_store(&stale, &store, batch).await;
            assert!(is_assertion_failure(&result));

            for document_id in first_document_id..first_document_id + LARGE_RESOURCE_COUNT {
                assert!(
                    !store
                        .key_exists(ValueKey::archive(
                            account_id,
                            Collection::CalendarEvent,
                            document_id,
                        ))
                        .await
                        .expect("read resource after stale large batch"),
                    "resource {document_id} survived the stale large transaction"
                );
            }
            assert_eq!(calendar_log_count(&store, account_id).await, 1);
            assert_eq!(quota(&store, account_id).await, 1);
            assert_eq!(
                DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                    .await
                    .expect("read winning generation")
                    .generation,
                Some(1)
            );
        })
        .await
        .expect("stale large DAV fence test timed out");
    }

    #[tokio::test]
    async fn stale_fence_fails_after_delay_and_rolls_back_batch() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let db = TestDb::new();
            let store = db.open().await;
            let account_id = db.id(8);
            let winner_document_id = db.id(51);
            let loser_document_id = db.id(52);
            let stale = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read stale snapshot");
            let winner = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read competing snapshot");
            assert!(
                commit_to_store(
                    &winner,
                    &store,
                    resource_batch(
                        account_id,
                        Collection::CalendarEvent,
                        SyncCollection::Calendar,
                        winner_document_id,
                    ),
                )
                .await
                .is_ok()
            );
            tokio::time::sleep(Duration::from_millis(75)).await;

            let stale_result = commit_to_store(
                &stale,
                &store,
                resource_batch(
                    account_id,
                    Collection::CalendarEvent,
                    SyncCollection::Calendar,
                    loser_document_id,
                ),
            )
            .await;
            assert!(is_assertion_failure(&stale_result));
            assert!(
                !store
                    .key_exists(ValueKey::archive(
                        account_id,
                        Collection::CalendarEvent,
                        loser_document_id,
                    ))
                    .await
                    .expect("read losing resource")
            );
            assert_eq!(calendar_log_count(&store, account_id).await, 1);
            assert_eq!(quota(&store, account_id).await, 1);
        })
        .await
        .expect("DAV fence contract test timed out");
    }

    #[tokio::test]
    async fn fence_survives_reopen_and_resource_delete_recreate() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let db = TestDb::new();
            let account_id = db.id(9);
            let document_id = db.id(61);
            let store = db.open().await;
            let first = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read initial fence");
            assert!(
                commit_to_store(
                    &first,
                    &store,
                    resource_batch(
                        account_id,
                        Collection::CalendarEvent,
                        SyncCollection::Calendar,
                        document_id,
                    ),
                )
                .await
                .is_ok()
            );
            drop(store);

            let store = db.open().await;
            let reloaded = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read reopened fence");
            assert_eq!(reloaded.generation, Some(1));
            let archive = ValueKey::archive(account_id, Collection::CalendarEvent, document_id);
            let mut delete = BatchBuilder::new();
            delete
                .with_account_id(account_id)
                .with_collection(Collection::CalendarEvent)
                .with_document(document_id)
                .clear(archive.class.clone())
                .log_item_delete(SyncCollection::Calendar, None)
                .add(ValueClass::Quota, -1);
            store
                .write_batch(&mut delete)
                .await
                .expect("delete resource");
            assert!(
                !store
                    .key_exists(ValueKey::archive(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                    ))
                    .await
                    .expect("read deleted resource")
            );

            let recreate = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read persistent fence before recreate");
            assert!(
                commit_to_store(
                    &recreate,
                    &store,
                    resource_batch(
                        account_id,
                        Collection::CalendarEvent,
                        SyncCollection::Calendar,
                        document_id,
                    ),
                )
                .await
                .is_ok()
            );
            assert_eq!(
                DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                    .await
                    .expect("read recreated fence")
                    .generation,
                Some(2)
            );
        })
        .await
        .expect("DAV fence contract test timed out");
    }

    #[tokio::test]
    async fn account_and_collection_fences_are_independent() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let db = TestDb::new();
            let store = db.open().await;
            let account_a = db.id(10);
            let account_b = db.id(11);
            for (account_id, collection, object_collection, document_id) in [
                (
                    account_a,
                    SyncCollection::Calendar,
                    Collection::CalendarEvent,
                    db.id(71),
                ),
                (
                    account_b,
                    SyncCollection::Calendar,
                    Collection::CalendarEvent,
                    db.id(72),
                ),
                (
                    account_a,
                    SyncCollection::AddressBook,
                    Collection::ContactCard,
                    db.id(73),
                ),
            ] {
                let fence = DavCreateFence::read(&store, account_id, collection)
                    .await
                    .expect("read independent fence");
                assert!(
                    commit_to_store(
                        &fence,
                        &store,
                        resource_batch(account_id, object_collection, collection, document_id),
                    )
                    .await
                    .is_ok()
                );
            }
            for (account_id, collection) in [
                (account_a, SyncCollection::Calendar),
                (account_b, SyncCollection::Calendar),
                (account_a, SyncCollection::AddressBook),
            ] {
                assert_eq!(
                    DavCreateFence::read(&store, account_id, collection)
                        .await
                        .expect("read independent generation")
                        .generation,
                    Some(1)
                );
            }
        })
        .await
        .expect("DAV fence contract test timed out");
    }

    #[tokio::test]
    async fn overflow_fails_closed_without_batch_side_effects() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let db = TestDb::new();
            let store = db.open().await;
            let account_id = db.id(12);
            let document_id = db.id(81);
            let class = ValueClass::Any(AnyClass {
                subspace: Subspace::System,
                key: fence_key(account_id, SyncCollection::Calendar),
            });
            let mut seed = BatchBuilder::new();
            seed.set(class, u64::MAX.to_be_bytes());
            store
                .write_batch(&mut seed)
                .await
                .expect("seed max generation");

            let fence = DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                .await
                .expect("read max generation");
            let result = commit_to_store(
                &fence,
                &store,
                resource_batch(
                    account_id,
                    Collection::CalendarEvent,
                    SyncCollection::Calendar,
                    document_id,
                ),
            )
            .await;
            assert!(result.is_err());
            assert!(
                !store
                    .key_exists(ValueKey::archive(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                    ))
                    .await
                    .expect("read resource after overflow")
            );
            assert_eq!(calendar_log_count(&store, account_id).await, 0);
            assert_eq!(quota(&store, account_id).await, 0);
            assert_eq!(
                DavCreateFence::read(&store, account_id, SyncCollection::Calendar)
                    .await
                    .expect("read unchanged max generation")
                    .generation,
                Some(u64::MAX)
            );
        })
        .await
        .expect("DAV fence contract test timed out");
    }
}
