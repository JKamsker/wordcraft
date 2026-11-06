//! S3 (`s3://bucket/prefix`), Azure Blob (`az://container/prefix`) and Google Cloud Storage (`gs://bucket/prefix`) through `object_store`.

use super::{SharedStorage, StorageError};

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    Err(StorageError::Config(format!("backend not built yet: {}", url.split("://").next().unwrap_or(""))))
}
