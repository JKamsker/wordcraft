//! Where documents live. Every backend implements [`Storage`] over validated [`DocPath`]s.
//!
//! Backends: [`local`] (a directory), [`memory`] (tests and demos), [`object`] (S3, Azure Blob,
//! Google Cloud Storage via `object_store`), [`ftp`] (FTP/FTPS) and [`smb`] (SMB2/3 shares).
//! [`open`] builds one from a storage URL (see `config`).

pub mod ftp;
pub mod local;
pub mod memory;
pub mod object;
pub mod path;
pub mod smb;

use std::sync::Arc;

pub use path::DocPath;

/// One stored file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Entry {
    /// The path relative to the storage root, `/`-separated.
    pub path: String,
    pub size: u64,
    /// Last modification, when the backend reports one.
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("too large: {0}")]
    TooLarge(String),
    #[error("invalid storage configuration: {0}")]
    Config(String),
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// A document store. Implementations must never panic, must treat every path and byte as
/// hostile, and must keep each operation inside the configured root/prefix.
#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    /// A short description for logs and the file browser, without secrets
    /// (`directory /srv/docs`, `s3 bucket docs/prefix`, `ftp host:21/docs`).
    fn describe(&self) -> String;
    /// Every file under the root, recursively, in any order. Backends cap the count at
    /// [`MAX_LIST_ENTRIES`] and skip names that are not valid [`DocPath`]s.
    async fn list(&self) -> Result<Vec<Entry>, StorageError>;
    /// The file's bytes; [`StorageError::NotFound`] when there is none. Refuses files over `max_bytes`.
    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError>;
    /// Creates or replaces the file, creating parent folders as needed.
    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError>;
    /// Removes the file; [`StorageError::NotFound`] when there is none.
    async fn delete(&self, path: &DocPath) -> Result<(), StorageError>;
}

/// The most entries a listing returns.
pub const MAX_LIST_ENTRIES: usize = 10_000;

pub type SharedStorage = Arc<dyn Storage>;

/// Opens the backend a storage URL names: `s3://`, `az://`/`azure://`, `gs://`, `ftp://`,
/// `ftps://`, `smb://`, `memory:`, `dir://`/`file://` or a plain directory path.
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("s3" | "az" | "azure" | "abfs" | "abfss" | "gs") => object::open(url),
        Some("ftp" | "ftps") => ftp::open(url),
        Some("smb") => smb::open(url),
        Some("dir" | "file") => local::open(url.split_once("://").map(|(_, p)| p).unwrap_or(url)),
        Some(other) => Err(StorageError::Config(format!("unknown storage scheme {other}://"))),
        None if url == "memory:" => Ok(Arc::new(memory::MemoryStorage::default())),
        None => local::open(url),
    }
}
