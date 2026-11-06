//! A view of another storage limited to one folder, for per-user storage (`--per-user-storage`):
//! every path is mapped under the prefix and listings show only that folder, with the prefix
//! stripped, so handlers work unchanged and a user never sees or reaches another user's files.

use super::{DocPath, Entry, SharedStorage, Storage, StorageError};

pub struct ScopedStorage {
    inner: SharedStorage,
    /// A valid [`DocPath`] such as `users/abc`, without a trailing `/`.
    prefix: String,
}

impl ScopedStorage {
    /// Fails when `prefix` is not a valid [`DocPath`].
    pub fn new(inner: SharedStorage, prefix: &str) -> Result<Self, StorageError> {
        let prefix = DocPath::parse(prefix)?.as_str().to_string();
        Ok(Self { inner, prefix })
    }

    fn map(&self, path: &DocPath) -> Result<DocPath, StorageError> {
        DocPath::parse(&format!("{}/{}", self.prefix, path.as_str()))
    }
}

#[async_trait::async_trait]
impl Storage for ScopedStorage {
    fn describe(&self) -> String {
        format!("{} (your folder)", self.inner.describe())
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        let start = format!("{}/", self.prefix);
        Ok(self
            .inner
            .list()
            .await?
            .into_iter()
            .filter_map(|e| {
                let rest = e.path.strip_prefix(&start)?.to_string();
                Some(Entry { path: rest, ..e })
            })
            .collect())
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        self.inner.get(&self.map(path)?, max_bytes).await.map_err(|e| self.unmap(e, path))
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.inner.put(&self.map(path)?, bytes).await.map_err(|e| self.unmap(e, path))
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        self.inner.delete(&self.map(path)?).await.map_err(|e| self.unmap(e, path))
    }
}

impl ScopedStorage {
    /// Reports errors with the user's own path, not the prefixed one.
    fn unmap(&self, e: StorageError, path: &DocPath) -> StorageError {
        match e {
            StorageError::NotFound(_) => StorageError::NotFound(path.to_string()),
            StorageError::TooLarge(_) => StorageError::TooLarge(path.to_string()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::storage::memory::MemoryStorage;

    #[tokio::test]
    async fn users_see_only_their_folder() {
        let inner: SharedStorage = Arc::new(MemoryStorage::default());
        let a = ScopedStorage::new(inner.clone(), "users/a").unwrap();
        let b = ScopedStorage::new(inner.clone(), "users/b").unwrap();
        let p = DocPath::parse("notes/plan.docx").unwrap();
        a.put(&p, b"A".to_vec()).await.unwrap();
        assert_eq!(a.get(&p, 10).await.unwrap(), b"A");
        assert!(matches!(b.get(&p, 10).await, Err(StorageError::NotFound(m)) if m == "notes/plan.docx"));
        assert!(b.list().await.unwrap().is_empty());
        assert_eq!(a.list().await.unwrap()[0].path, "notes/plan.docx");
        assert_eq!(inner.list().await.unwrap()[0].path, "users/a/notes/plan.docx");
        assert!(b.delete(&p).await.is_err());
        assert!(ScopedStorage::new(inner, "../x").is_err());
    }
}
