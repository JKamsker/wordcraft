//! SMB2/3 shares (`smb://user@host/share/folder`); the password comes from `WORDCRAFT_SMB_PASSWORD`.

use super::{SharedStorage, StorageError};

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    Err(StorageError::Config(format!("backend not built yet: {}", url.split("://").next().unwrap_or(""))))
}
