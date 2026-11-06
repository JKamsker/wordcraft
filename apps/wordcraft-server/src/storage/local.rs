//! A directory on this machine (`dir:///srv/docs`, `file:///srv/docs` or a plain path).

use super::{SharedStorage, StorageError};

/// Opens the directory backend for `root` (a path, not a URL).
pub fn open(root: &str) -> Result<SharedStorage, StorageError> {
    Err(StorageError::Config(format!("backend not built yet: {root}")))
}
