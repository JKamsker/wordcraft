//! In-memory storage (`memory:`), for tests and demos; nothing survives a restart.

use std::collections::BTreeMap;

use tokio::sync::RwLock;

use super::{DocPath, Entry, Storage, StorageError};

#[derive(Default)]
pub struct MemoryStorage {
    files: RwLock<BTreeMap<DocPath, (Vec<u8>, chrono::DateTime<chrono::Utc>)>>,
}

#[async_trait::async_trait]
impl Storage for MemoryStorage {
    fn describe(&self) -> String {
        "memory (not persisted)".into()
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        let files = self.files.read().await;
        Ok(files
            .iter()
            .take(super::MAX_LIST_ENTRIES)
            .map(|(p, (b, m))| Entry { path: p.to_string(), size: b.len() as u64, modified: Some(*m) })
            .collect())
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        let files = self.files.read().await;
        let (bytes, _) = files.get(path).ok_or_else(|| StorageError::NotFound(path.to_string()))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()));
        }
        Ok(bytes.clone())
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.files.write().await.insert(path.clone(), (bytes, chrono::Utc::now()));
        Ok(())
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        self.files.write().await.remove(path).map(|_| ()).ok_or_else(|| StorageError::NotFound(path.to_string()))
    }
}
