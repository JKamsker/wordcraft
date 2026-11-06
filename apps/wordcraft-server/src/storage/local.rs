//! A directory on this machine (`dir:///srv/docs`, `file:///srv/docs` or a plain path).
//!
//! Every [`DocPath`] is joined under the root one segment at a time, and every existing segment is
//! checked with `symlink_metadata`: a symbolic link anywhere in the path is refused, so a link
//! planted inside the root cannot lead outside it. Writes go to a hidden temporary file in the same
//! folder and are renamed into place, so a reader never sees a half-written document. Hidden files
//! (names starting with `.`), symbolic links and names that are not valid [`DocPath`]s are left out
//! of listings.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::path::MAX_DEPTH;
use super::{DocPath, Entry, MAX_LIST_ENTRIES, SharedStorage, Storage, StorageError};

/// Prefix of the temporary files [`LocalStorage::put`] writes before renaming them into place.
const TEMP_PREFIX: &str = ".wordcraft-tmp-";
/// The most folders one listing reads, so a huge tree cannot keep a request busy forever.
const MAX_LIST_DIRS: usize = 10_000;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Opens the directory backend for `root` (a path, not a URL), creating the folder if missing.
pub fn open(root: &str) -> Result<SharedStorage, StorageError> {
    Ok(Arc::new(LocalStorage::new(root)?))
}

/// Documents stored as files under one directory.
#[derive(Debug)]
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    /// Creates `root` when missing and resolves it to an absolute path.
    pub fn new(root: &str) -> Result<Self, StorageError> {
        if root.trim().is_empty() {
            return Err(StorageError::Config("empty directory path".into()));
        }
        let root = PathBuf::from(root);
        std::fs::create_dir_all(&root).map_err(|e| StorageError::Config(format!("cannot create {}: {e}", root.display())))?;
        let root = root.canonicalize().map_err(|e| StorageError::Config(format!("cannot resolve {}: {e}", root.display())))?;
        if !root.is_dir() {
            return Err(StorageError::Config(format!("{} is not a directory", root.display())));
        }
        Ok(Self { root })
    }

    /// The resolved root directory.
    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Joins `path` under the root, refusing a symbolic link or a non-folder in any parent segment.
    /// With `create`, missing parent folders are made. Returns the file's full path.
    async fn resolve(&self, path: &DocPath, create: bool) -> Result<PathBuf, StorageError> {
        let mut full = self.root.clone();
        let parent = path.parent();
        if !parent.is_empty() {
            for seg in parent.split('/') {
                full.push(seg);
                match tokio::fs::symlink_metadata(&full).await {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(StorageError::InvalidPath(format!("{path}: a folder in the path is a symbolic link")));
                    }
                    Ok(meta) if meta.is_dir() => {}
                    Ok(_) => return Err(StorageError::InvalidPath(format!("{path}: a folder in the path is a file"))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !create {
                            return Err(StorageError::NotFound(path.to_string()));
                        }
                        match tokio::fs::create_dir(&full).await {
                            Ok(()) => {}
                            // Another request made it meanwhile: check it again.
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                let meta = tokio::fs::symlink_metadata(&full).await.map_err(|e| io_error(path, &e))?;
                                if !meta.is_dir() || meta.file_type().is_symlink() {
                                    return Err(StorageError::InvalidPath(format!("{path}: a folder in the path is not a folder")));
                                }
                            }
                            Err(e) => return Err(io_error(path, &e)),
                        }
                    }
                    Err(e) => return Err(io_error(path, &e)),
                }
            }
        }
        full.push(path.file_name());
        Ok(full)
    }

    /// The metadata of the file itself, refusing a symbolic link or a folder.
    async fn file_meta(path: &DocPath, full: &Path) -> Result<std::fs::Metadata, StorageError> {
        let meta = tokio::fs::symlink_metadata(full).await.map_err(|e| io_error(path, &e))?;
        if meta.file_type().is_symlink() {
            return Err(StorageError::InvalidPath(format!("{path}: is a symbolic link")));
        }
        if !meta.is_file() {
            return Err(StorageError::NotFound(path.to_string()));
        }
        Ok(meta)
    }
}

/// Maps an I/O error; the message names the document path, never the absolute file path.
fn io_error(path: &DocPath, e: &std::io::Error) -> StorageError {
    match e.kind() {
        std::io::ErrorKind::NotFound => StorageError::NotFound(path.to_string()),
        _ => StorageError::Backend(format!("{path}: {e}")),
    }
}

fn modified(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
    meta.modified().ok().map(chrono::DateTime::<chrono::Utc>::from)
}

#[async_trait::async_trait]
impl Storage for LocalStorage {
    fn describe(&self) -> String {
        format!("directory {}", self.root.display())
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        let mut out = Vec::new();
        // (folder on disk, its path relative to the root, its depth in segments)
        let mut stack: Vec<(PathBuf, String, usize)> = vec![(self.root.clone(), String::new(), 0)];
        let mut dirs_read = 0usize;
        while let Some((dir, rel, depth)) = stack.pop() {
            dirs_read = dirs_read.saturating_add(1);
            if dirs_read > MAX_LIST_DIRS {
                log::warn!("listing stopped after {MAX_LIST_DIRS} folders");
                break;
            }
            let mut reader = match tokio::fs::read_dir(&dir).await {
                Ok(r) => r,
                // The root must be readable; a subfolder that vanished or is unreadable is skipped.
                Err(e) if depth == 0 => return Err(StorageError::Backend(format!("cannot read the storage folder: {e}"))),
                Err(e) => {
                    log::debug!("skipping unreadable folder {rel}: {e}");
                    continue;
                }
            };
            loop {
                let entry = match reader.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("stopped reading folder {rel}: {e}");
                        break;
                    }
                };
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
                if name.starts_with('.') {
                    continue;
                }
                let Ok(file_type) = entry.file_type().await else { continue };
                if file_type.is_symlink() {
                    continue;
                }
                let child = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                let Ok(doc) = DocPath::parse(&child) else { continue };
                let child_depth = depth.saturating_add(1);
                if file_type.is_dir() {
                    // Files inside it would be one segment deeper.
                    if child_depth < MAX_DEPTH {
                        stack.push((entry.path(), doc.to_string(), child_depth));
                    }
                } else if file_type.is_file() {
                    let Ok(meta) = entry.metadata().await else { continue };
                    out.push(Entry { path: doc.to_string(), size: meta.len(), modified: modified(&meta) });
                    if out.len() >= MAX_LIST_ENTRIES {
                        log::warn!("listing capped at {MAX_LIST_ENTRIES} files");
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        let full = self.resolve(path, false).await?;
        let meta = Self::file_meta(path, &full).await?;
        if meta.len() > max_bytes {
            return Err(StorageError::TooLarge(format!("{path}: {} bytes", meta.len())));
        }
        let file = tokio::fs::File::open(&full).await.map_err(|e| io_error(path, &e))?;
        // The file may grow between the check and the read: never read more than the limit.
        let cap = usize::try_from(meta.len()).unwrap_or(usize::MAX).min(64 * 1024 * 1024);
        let mut bytes = Vec::with_capacity(cap);
        file.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes).await.map_err(|e| io_error(path, &e))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()));
        }
        Ok(bytes)
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        if path.segments().any(|s| s.starts_with(TEMP_PREFIX)) {
            return Err(StorageError::InvalidPath(format!("{path}: reserved name")));
        }
        let full = self.resolve(path, true).await?;
        match tokio::fs::symlink_metadata(&full).await {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(StorageError::InvalidPath(format!("{path}: is a symbolic link")));
            }
            Ok(meta) if meta.is_dir() => return Err(StorageError::InvalidPath(format!("{path}: is a folder"))),
            _ => {}
        }
        let Some(folder) = full.parent() else {
            return Err(StorageError::Backend(format!("{path}: no parent folder")));
        };
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let temp = folder.join(format!("{TEMP_PREFIX}{}-{n}-{nanos}", std::process::id()));
        let write = async {
            let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
            file.write_all(&bytes).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temp, &full).await
        };
        if let Err(e) = write.await {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(StorageError::Backend(format!("{path}: {e}")));
        }
        Ok(())
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        let full = self.resolve(path, false).await?;
        Self::file_meta(path, &full).await?;
        tokio::fs::remove_file(&full).await.map_err(|e| io_error(path, &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LocalStorage) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStorage::new(dir.path().join("docs").to_str().unwrap()).unwrap();
        (dir, store)
    }

    fn p(s: &str) -> DocPath {
        DocPath::parse(s).unwrap()
    }

    #[tokio::test]
    async fn round_trip_with_nested_folders() {
        let (_dir, s) = store();
        assert!(s.root().is_dir(), "root is created");
        s.put(&p("a.docx"), b"one".to_vec()).await.unwrap();
        s.put(&p("x/y/z/b.docx"), b"two!".to_vec()).await.unwrap();
        assert_eq!(s.get(&p("x/y/z/b.docx"), 100).await.unwrap(), b"two!");
        let mut list = s.list().await.unwrap();
        list.sort_by(|a, b| a.path.cmp(&b.path));
        let paths: Vec<_> = list.iter().map(|e| (e.path.as_str(), e.size)).collect();
        assert_eq!(paths, [("a.docx", 3), ("x/y/z/b.docx", 4)]);
        assert!(list.iter().all(|e| e.modified.is_some()));
        // Replace, then delete.
        s.put(&p("a.docx"), b"replaced".to_vec()).await.unwrap();
        assert_eq!(s.get(&p("a.docx"), 100).await.unwrap(), b"replaced");
        s.delete(&p("a.docx")).await.unwrap();
        assert!(matches!(s.get(&p("a.docx"), 100).await, Err(StorageError::NotFound(_))));
        assert!(matches!(s.delete(&p("a.docx")).await, Err(StorageError::NotFound(_))));
        assert!(matches!(s.get(&p("nope/a.docx"), 100).await, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn put_is_atomic_and_leaves_no_temp_files() {
        let (_dir, s) = store();
        s.put(&p("f/doc.docx"), vec![7; 10_000]).await.unwrap();
        s.put(&p("f/doc.docx"), vec![8; 5]).await.unwrap();
        let names: Vec<_> = std::fs::read_dir(s.root().join("f")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, ["doc.docx"]);
        assert_eq!(s.get(&p("f/doc.docx"), 100).await.unwrap(), vec![8; 5]);
        // A leftover temp file from a crash is hidden and its name cannot be written.
        std::fs::write(s.root().join(format!("{TEMP_PREFIX}1-2-3")), b"partial").unwrap();
        assert_eq!(s.list().await.unwrap().len(), 1);
        assert!(matches!(s.put(&p(&format!("{TEMP_PREFIX}x")), vec![]).await, Err(StorageError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn get_refuses_files_over_the_limit() {
        let (_dir, s) = store();
        s.put(&p("big.docx"), vec![0; 100]).await.unwrap();
        assert!(matches!(s.get(&p("big.docx"), 99).await, Err(StorageError::TooLarge(_))));
        assert_eq!(s.get(&p("big.docx"), 100).await.unwrap().len(), 100);
    }

    #[tokio::test]
    async fn a_folder_is_not_a_file() {
        let (_dir, s) = store();
        s.put(&p("dir/a.docx"), vec![1]).await.unwrap();
        assert!(matches!(s.get(&p("dir"), 100).await, Err(StorageError::NotFound(_))));
        assert!(matches!(s.put(&p("dir"), vec![1]).await, Err(StorageError::InvalidPath(_))));
        assert!(matches!(s.put(&p("dir/a.docx/b.docx"), vec![1]).await, Err(StorageError::InvalidPath(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symbolic_links_are_skipped_and_refused() {
        let (dir, s) = store();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret.docx"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, s.root().join("linkdir")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.docx"), s.root().join("link.docx")).unwrap();
        s.put(&p("real.docx"), b"ok".to_vec()).await.unwrap();

        let list = s.list().await.unwrap();
        assert_eq!(list.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["real.docx"]);
        for path in ["link.docx", "linkdir/secret.docx"] {
            assert!(matches!(s.get(&p(path), 100).await, Err(StorageError::InvalidPath(_))), "{path}");
            assert!(matches!(s.delete(&p(path)).await, Err(StorageError::InvalidPath(_))), "{path}");
            assert!(matches!(s.put(&p(path), b"x".to_vec()).await, Err(StorageError::InvalidPath(_))), "{path}");
        }
        assert_eq!(std::fs::read(outside.join("secret.docx")).unwrap(), b"secret");
    }

    #[tokio::test]
    async fn listing_skips_hidden_and_invalid_names() {
        let (_dir, s) = store();
        std::fs::write(s.root().join(".hidden"), b"h").unwrap();
        std::fs::write(s.root().join("bad:name.docx"), b"b").unwrap();
        std::fs::write(s.root().join("good.docx"), b"g").unwrap();
        let list = s.list().await.unwrap();
        assert_eq!(list.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["good.docx"]);
    }
}
