//! FTP and FTPS (`ftp://user@host:21/folder`, `ftps://…`); the password comes from `WORDCRAFT_FTP_PASSWORD`.

use super::{SharedStorage, StorageError};

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    Err(StorageError::Config(format!("backend not built yet: {}", url.split("://").next().unwrap_or(""))))
}
