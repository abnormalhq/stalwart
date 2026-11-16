/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::{
    Caches, Core, Data, Inner, Server,
    config::storage::Storage,
    manager::boot::{IpcReceivers, build_ipc},
    network::SessionStream,
};
use arc_swap::ArcSwap;
use registry::schema::{
    prelude::Object,
    properties::{ObjectType, Property},
    structs::{Account, DataStore, Domain, SqliteStore, UserAccount},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use store::{
    RegistryStore,
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
};
use types::id::Id;

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

pub struct ServerFixture {
    pub server: Server,
    _swap_receiver: crate::cache::swap::SwapReceiver,
    _directories: Vec<Arc<TestDirectory>>,
}

impl ServerFixture {
    pub async fn new() -> Self {
        let directory = Arc::new(TestDirectory::new());
        let data_path = directory.0.join("data.sqlite3");
        let registry_path = directory.0.join("registry.json");
        Self::build(data_path, registry_path, vec![directory]).await
    }

    pub async fn new_with_shared_primary(&self) -> Self {
        let config_directory = Arc::new(TestDirectory::new());
        let mut directories = self._directories.clone();
        directories.push(config_directory.clone());
        Self::build(
            self._directories[0].0.join("data.sqlite3"),
            config_directory.0.join("registry.json"),
            directories,
        )
        .await
    }

    async fn build(
        data_path: PathBuf,
        registry_path: PathBuf,
        directories: Vec<Arc<TestDirectory>>,
    ) -> Self {
        let data_store = DataStore::Sqlite(SqliteStore {
            path: data_path.to_string_lossy().into_owned(),
            pool_workers: Some(2),
            pool_max_connections: Some(4),
        });
        std::fs::write(
            &registry_path,
            serde_json::to_vec(&data_store).expect("serialize local SQLite config"),
        )
        .expect("write local SQLite config");

        let registry = RegistryStore::init(registry_path, false)
            .await
            .expect("initialize local SQLite registry");
        let mut bootstrap = Bootstrap::new(registry).await;
        let storage = Storage::parse(&mut bootstrap).await;
        let core: Arc<Core> = Arc::from(Core::parse(&mut bootstrap, storage).await);
        let data = Data::parse(&mut bootstrap).await;
        let (cache, swap_receiver) = Caches::parse(&mut bootstrap, &core.storage).await;

        let (ipc, receivers) = build_ipc(false);
        close_ipc_receivers(receivers);

        let inner = Arc::new(Inner {
            shared_core: ArcSwap::new(core.clone()),
            data,
            cache,
            ipc,
        });

        Self {
            server: Server { inner, core },
            _swap_receiver: swap_receiver,
            _directories: directories,
        }
    }

    pub async fn create_user_account(&self, name: &str, domain_name: &str) -> u32 {
        let registry = &self.server.core.storage.registry;
        let domain_id = match registry
            .first_primary_key(
                ObjectType::Domain.into(),
                &[
                    (Property::Name, domain_name.as_bytes()),
                    (Property::Aliases, domain_name.as_bytes()),
                ],
            )
            .await
            .expect("lookup test domain")
        {
            Some((_, domain)) => domain.id().document_id(),
            None => {
                let domain = Object::from(Domain {
                    name: domain_name.to_string(),
                    ..Default::default()
                });
                match registry
                    .write(RegistryWrite::insert(&domain))
                    .await
                    .expect("insert test domain")
                {
                    RegistryWriteResult::Success(id) => id.document_id(),
                    result => panic!("failed to insert test domain: {result:?}"),
                }
            }
        };

        let account = Object::from(Account::User(UserAccount {
            name: name.to_string(),
            domain_id: Id::from(domain_id),
            ..Default::default()
        }));
        match registry
            .write(RegistryWrite::insert(&account))
            .await
            .expect("insert test account")
        {
            RegistryWriteResult::Success(id) => id.document_id(),
            result => panic!("failed to insert test account: {result:?}"),
        }
    }
}

impl SessionStream for tokio::io::DuplexStream {
    fn is_tls(&self) -> bool {
        false
    }

    fn tls_version_and_cipher(
        &self,
    ) -> (
        std::borrow::Cow<'static, str>,
        std::borrow::Cow<'static, str>,
    ) {
        (
            std::borrow::Cow::Borrowed(""),
            std::borrow::Cow::Borrowed(""),
        )
    }
}

fn close_ipc_receivers(mut receivers: IpcReceivers) {
    if let Some(receiver) = receivers.push_rx.as_mut() {
        receiver.close();
    }
    if let Some(receiver) = receivers.queue_rx.as_mut() {
        receiver.close();
    }
    if let Some(receiver) = receivers.report_rx.as_mut() {
        receiver.close();
    }
    if let Some(receiver) = receivers.broadcast_rx.as_mut() {
        receiver.close();
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "stalwart-server-fixture-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        Self(directory)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
