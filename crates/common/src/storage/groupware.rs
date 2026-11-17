/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use store::{
    Store, Subspace,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use types::collection::SyncCollection;

const DAV_FENCE_PREFIX: [u8; 5] = [0x02, b'D', b'A', b'V', 0x01];

#[derive(Clone)]
pub struct GroupwareCreateGeneration {
    key: Vec<u8>,
    generation: Option<u64>,
}

impl GroupwareCreateGeneration {
    pub async fn read_primary(
        store: &Store,
        account_id: u32,
        collection: SyncCollection,
    ) -> trc::Result<Self> {
        let key = generation_key(account_id, collection);
        let generation = store
            .get_value::<u64>(AnyKey {
                subspace: Subspace::System,
                key: key.clone(),
            })
            .await?;

        Ok(Self { key, generation })
    }

    pub fn append_to_batch(&self, batch: &mut BatchBuilder) -> trc::Result<()> {
        if batch.has_commit_points() {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Groupware generation refuses a pre-split batch"));
        }

        let next_generation = self
            .generation
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Groupware namespace generation overflow")
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

        Ok(())
    }

    pub fn current_generation(&self) -> Option<u64> {
        self.generation
    }
}

fn generation_key(account_id: u32, collection: SyncCollection) -> Vec<u8> {
    let mut key = Vec::with_capacity(DAV_FENCE_PREFIX.len() + 5);
    key.extend_from_slice(&DAV_FENCE_PREFIX);
    key.extend_from_slice(&account_id.to_be_bytes());
    key.push(u8::from(collection));
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_key_preserves_dav_prefix_account_and_collection_encoding() {
        let account_id = 0x01020304;
        let key = generation_key(account_id, SyncCollection::Calendar);

        assert_eq!(&key[..5], &[0x02, b'D', b'A', b'V', 0x01]);
        assert_eq!(&key[5..9], &account_id.to_be_bytes());
        assert_eq!(key[9], u8::from(SyncCollection::Calendar));
    }

    #[test]
    fn append_rejects_pre_split_batches() {
        let generation = GroupwareCreateGeneration {
            key: vec![0x02, b'D', b'A', b'V', 0x01],
            generation: None,
        };
        let mut batch = BatchBuilder::new();
        batch
            .set(
                ValueClass::Any(AnyClass {
                    subspace: Subspace::System,
                    key: vec![0],
                }),
                vec![1],
            )
            .add_commit_point();
        assert_eq!(batch.commit_point_count(), 1);

        assert!(generation.append_to_batch(&mut batch).is_err());
        assert_eq!(batch.commit_point_count(), 1);
    }
}
