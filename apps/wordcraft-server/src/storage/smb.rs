//! SMB2/3 shares (`smb://[domain;]user@host[:port]/share/folder`); the password comes from
//! `WORDCRAFT_SMB_PASSWORD`.
//!
//! Uses the pure-Rust `smb` client with NTLM authentication; signing and encryption are used when
//! the server offers them. One authenticated client is kept and reused; an operation that fails on
//! the connection itself drops it, and one on a reused client is retried once on a fresh one.
//!
//! The client library is young and has panic paths on malformed server replies, so every operation
//! runs in its own task: a panic there becomes a [`StorageError::Backend`] instead of reaching the
//! server. Every operation is bounded by a timeout, and every name the server returns is hostile.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use smb::{
    Client, ClientConfig, ConnectionConfig, CreateOptions, DirAccessMask, Directory, FileAccessMask, FileAttributes, FileCreateArgs,
    FileDirectoryInformation, FileDispositionInformation, GetLen, ReadAt, Resource, UncPath, WriteAt,
};
use tokio::sync::Mutex;

use super::ftp::{checked_segments, parse_host_port, percent_decode};
use super::path::MAX_DEPTH;
use super::{DocPath, Entry, MAX_LIST_ENTRIES, SharedStorage, Storage, StorageError};

/// The environment variable holding the SMB password.
pub const PASSWORD_ENV: &str = "WORDCRAFT_SMB_PASSWORD";
/// How long connecting, negotiating and authenticating may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one storage operation (including a transfer or a whole listing) may take.
const OP_TIMEOUT: Duration = Duration::from_secs(120);
/// The most folders one listing visits.
const MAX_LIST_DIRS: usize = 2_000;
/// The size of each read and write request (every SMB2 server accepts 64 KiB).
const CHUNK: usize = 64 * 1024;

// NTSTATUS values (MS-ERREF 2.3).
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    let password = std::env::var(PASSWORD_ENV).ok();
    let config = Config::parse(url, password)?;
    Ok(Arc::new(SmbStorage { config: Arc::new(config), client: Mutex::new(None) }))
}

/// What a storage URL says, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    host: String,
    port: u16,
    domain: Option<String>,
    user: String,
    password: String,
    share: String,
    /// Folder segments under the share.
    base: Vec<String>,
}

impl Config {
    fn parse(url: &str, password: Option<String>) -> Result<Self, StorageError> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| config_err("expected smb://user@host/share/folder"))?;
        if !scheme.eq_ignore_ascii_case("smb") {
            return Err(config_err("expected an smb:// URL"));
        }
        if rest.contains(['?', '#']) {
            return Err(config_err("SMB URLs take no query or fragment"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i + 1..).unwrap_or("")),
            None => (rest, ""),
        };
        let (userinfo, hostport) = authority.rsplit_once('@').ok_or_else(|| config_err("a user name is required: smb://[domain;]user@host/share"))?;
        if userinfo.contains(':') {
            return Err(config_err(&format!("put the password in {PASSWORD_ENV}, not in the URL")));
        }
        let (domain, user) = match userinfo.split_once(';') {
            Some((d, u)) => (Some(percent_decode(d)?), percent_decode(u)?),
            None => (None, percent_decode(userinfo)?),
        };
        let name_ok = |s: &str| !s.is_empty() && s.len() <= 256 && !s.contains(['\\', '/', '@', ';', ':']);
        if !name_ok(&user) || domain.as_deref().is_some_and(|d| !name_ok(d)) {
            return Err(config_err("invalid user or domain name"));
        }
        let (host, port) = parse_host_port(hostport, 445).map_err(|e| config_err(&e.to_string()))?;
        let decoded = percent_decode(path)?;
        let segments = checked_segments(&decoded)?;
        let (share, base) = segments.split_first().ok_or_else(|| config_err("missing share name: smb://user@host/share"))?;
        if share.len() > 80 || share.contains(['"', '*', '?', '<', '>', '|', ':', '[', ']', '+', '=', ',', ';']) {
            return Err(config_err("invalid share name"));
        }
        let password = match password {
            Some(p) if p.chars().any(char::is_control) => {
                return Err(config_err(&format!("{PASSWORD_ENV} contains control characters")));
            }
            Some(p) => p,
            None => String::new(),
        };
        Ok(Self { host, port, domain, user, password, share: (*share).to_string(), base: base.iter().map(|s| (*s).to_string()).collect() })
    }

    /// The share-relative name (`base\a\b.docx`) of `rel` (a `/`-separated relative path).
    fn name(&self, rel: &str) -> String {
        self.base.iter().map(String::as_str).chain(rel.split('/').filter(|s| !s.is_empty())).collect::<Vec<_>>().join("\\")
    }

    fn share_path(&self) -> Result<UncPath, StorageError> {
        UncPath::new(&self.host).and_then(|p| p.with_share(&self.share)).map_err(|e| config_err(&format!("invalid share path: {e}")))
    }

    fn path(&self, rel: &str) -> Result<UncPath, StorageError> {
        let name = self.name(rel);
        let share = self.share_path()?;
        Ok(if name.is_empty() { share } else { share.with_path(&name) })
    }

    fn user_name(&self) -> String {
        match &self.domain {
            Some(d) => format!("{d}\\{}", self.user),
            None => self.user.clone(),
        }
    }
}

fn config_err(why: &str) -> StorageError {
    StorageError::Config(format!("smb: {why}"))
}

/// An operation's failure, and whether the client is still usable afterwards.
struct Failure {
    error: StorageError,
    /// The connection failed (not just an error status): drop the client and maybe retry.
    broken: bool,
}

impl From<StorageError> for Failure {
    fn from(error: StorageError) -> Self {
        Self { error, broken: false }
    }
}

/// The NTSTATUS an error carries, when it is a status reply from the server.
fn status_of(e: &smb::Error) -> Option<u32> {
    match e {
        smb::Error::ReceivedErrorMessage(status, _) | smb::Error::UnexpectedMessageStatus(status) => Some(*status),
        _ => None,
    }
}

fn is_not_found(status: u32) -> bool {
    matches!(
        status,
        STATUS_OBJECT_NAME_NOT_FOUND
            | STATUS_OBJECT_PATH_NOT_FOUND
            | STATUS_NO_SUCH_FILE
            | STATUS_FILE_IS_A_DIRECTORY
            | STATUS_NOT_A_DIRECTORY
            | STATUS_DELETE_PENDING
    )
}

/// Maps a client error; `not_found` turns "no such file/path" statuses into [`StorageError::NotFound`].
fn smb_failure(e: smb::Error, what: &str, not_found: Option<&str>) -> Failure {
    match status_of(&e) {
        Some(status) if is_not_found(status) && not_found.is_some() => StorageError::NotFound(not_found.unwrap_or_default().to_string()).into(),
        Some(_) => StorageError::Backend(format!("smb {what}: {e}")).into(),
        None => {
            let broken = !matches!(e, smb::Error::InvalidArgument(_) | smb::Error::MissingPermissions(_));
            Failure { error: StorageError::Backend(format!("smb {what}: {e}")), broken }
        }
    }
}

/// FILETIME (100 ns ticks since 1601) as UTC; `None` for zero or out-of-range values.
fn file_time(ticks: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    const SECS_1601_TO_1970: i64 = 11_644_473_600;
    if ticks == 0 {
        return None;
    }
    let secs = i64::try_from(ticks / 10_000_000).ok()?.checked_sub(SECS_1601_TO_1970)?;
    let nanos = u32::try_from(ticks % 10_000_000).ok()?.checked_mul(100)?;
    chrono::DateTime::from_timestamp(secs, nanos)
}

pub struct SmbStorage {
    config: Arc<Config>,
    client: Mutex<Option<Arc<Client>>>,
}

impl SmbStorage {
    async fn connect(config: &Config) -> Result<Arc<Client>, StorageError> {
        let client = Client::new(ClientConfig {
            // DFS referrals would send us to other servers than the one configured.
            dfs: false,
            connection: ConnectionConfig { port: Some(config.port), timeout: Some(CONNECT_TIMEOUT), ..Default::default() },
            ..Default::default()
        });
        let share = config.share_path()?;
        let user = config.user_name();
        let password = config.password.clone();
        let attempt = async move {
            client
                .share_connect(&share, &user, password)
                .await
                .map(|()| client)
                .map_err(|e| StorageError::Backend(format!("smb: connecting to {}: {e}", share)))
        };
        let client = isolated(CONNECT_TIMEOUT, attempt).await??;
        Ok(Arc::new(client))
    }

    /// Runs `op` with the shared client, connecting when needed, in its own task within [`OP_TIMEOUT`].
    async fn run<T, F, Fut>(&self, op: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: Fn(Arc<Client>, Arc<Config>) -> Fut,
        Fut: Future<Output = Result<T, Failure>> + Send + 'static,
    {
        let mut slot = self.client.lock().await;
        let mut reused = slot.is_some();
        loop {
            let client = match slot.take() {
                Some(c) => c,
                None => Self::connect(&self.config).await?,
            };
            match isolated(OP_TIMEOUT, op(Arc::clone(&client), Arc::clone(&self.config))).await {
                Ok(Ok(value)) => {
                    *slot = Some(client);
                    return Ok(value);
                }
                Ok(Err(Failure { error, broken: false })) => {
                    *slot = Some(client);
                    return Err(error);
                }
                Ok(Err(Failure { error, broken: true })) => {
                    close_in_background(client);
                    if reused {
                        reused = false;
                        continue;
                    }
                    return Err(error);
                }
                // A timeout or a panic in the client: drop it, without a retry.
                Err(error) => {
                    close_in_background(client);
                    return Err(error);
                }
            }
        }
    }
}

/// Runs `fut` in its own task with a timeout, so a panic or a hang in the client library becomes an error.
async fn isolated<T: Send + 'static>(limit: Duration, fut: impl Future<Output = T> + Send + 'static) -> Result<T, StorageError> {
    let task = tokio::spawn(fut);
    let abort = task.abort_handle();
    match tokio::time::timeout(limit, task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(join)) if join.is_panic() => Err(StorageError::Backend("smb: the client failed unexpectedly".into())),
        Ok(Err(join)) => Err(StorageError::Backend(format!("smb: {join}"))),
        Err(_) => {
            abort.abort();
            Err(StorageError::Backend("smb: operation timed out".into()))
        }
    }
}

fn close_in_background(client: Arc<Client>) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(5), client.close()).await;
    });
}

#[async_trait::async_trait]
impl Storage for SmbStorage {
    fn describe(&self) -> String {
        let c = &self.config;
        let host = if c.host.contains(':') { format!("[{}]", c.host) } else { c.host.clone() };
        let port = if c.port == 445 { String::new() } else { format!(":{}", c.port) };
        let mut out = format!("smb {host}{port}/{}", c.share);
        for seg in &c.base {
            out.push('/');
            out.push_str(seg);
        }
        out
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        self.run(list_all).await
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        let path = path.clone();
        self.run(move |client, config| get_file(client, config, path.clone(), max_bytes)).await
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        let path = path.clone();
        let bytes = Arc::new(bytes);
        self.run(move |client, config| put_file(client, config, path.clone(), Arc::clone(&bytes))).await
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        let path = path.clone();
        self.run(move |client, config| delete_file(client, config, path.clone())).await
    }
}

async fn open_dir(client: &Client, config: &Config, rel: &str) -> Result<Arc<Directory>, smb::Error> {
    let access = DirAccessMask::new().with_list_directory(true).with_synchronize(true);
    let target = config.path(rel).map_err(|e| smb::Error::InvalidArgument(e.to_string()))?;
    match client.create_file(&target, &FileCreateArgs::make_open_existing(access.into())).await? {
        Resource::Directory(d) => Ok(Arc::new(d)),
        other => {
            close_resource(other).await;
            Err(smb::Error::UnexpectedMessageStatus(STATUS_NOT_A_DIRECTORY))
        }
    }
}

async fn close_resource(resource: Resource) {
    let _ = match &resource {
        Resource::File(f) => f.close().await,
        Resource::Directory(d) => d.close().await,
        Resource::Pipe(p) => p.close().await,
    };
}

async fn list_all(client: Arc<Client>, config: Arc<Config>) -> Result<Vec<Entry>, Failure> {
    let mut entries = Vec::new();
    // (document-relative folder, depth)
    let mut pending = vec![(String::new(), 0usize)];
    let mut visited = 0usize;
    while let Some((folder, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_LIST_DIRS {
            break;
        }
        let dir = match open_dir(&client, &config, &folder).await {
            Ok(d) => d,
            // The base folder is created by the first save; until then there is nothing to list.
            Err(e) if depth == 0 && !config.base.is_empty() && status_of(&e).is_some_and(is_not_found) => {
                return Ok(entries);
            }
            Err(e) => {
                let failure = smb_failure(e, "list", None);
                // A sub-folder that vanished or is unreadable is skipped; the root must be readable.
                if !failure.broken && depth > 0 {
                    continue;
                }
                return Err(failure);
            }
        };
        let mut found = Vec::new();
        let mut failed = None;
        match Directory::query::<FileDirectoryInformation>(&dir, "*").await {
            Ok(mut stream) => {
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(info) => found.push(info),
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                    if found.len() > MAX_LIST_ENTRIES {
                        break;
                    }
                }
            }
            Err(e) => failed = Some(e),
        }
        let _ = dir.close().await;
        if let Some(e) = failed {
            let failure = smb_failure(e, "list", None);
            if failure.broken || depth == 0 {
                return Err(failure);
            }
            continue;
        }
        for info in found {
            let name = info.file_name.to_string();
            if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
                continue;
            }
            let rel = if folder.is_empty() { name } else { format!("{folder}/{name}") };
            if info.file_attributes.directory() {
                if depth + 1 < MAX_DEPTH && DocPath::parse(&rel).is_ok() {
                    pending.push((rel, depth + 1));
                }
            } else if let Ok(path) = DocPath::parse(&rel) {
                entries.push(Entry { path: path.to_string(), size: info.end_of_file, modified: file_time(*info.last_write_time) });
                if entries.len() >= MAX_LIST_ENTRIES {
                    return Ok(entries);
                }
            }
        }
    }
    Ok(entries)
}

async fn open_file(client: &Client, config: &Config, path: &DocPath, args: &FileCreateArgs) -> Result<smb::File, Failure> {
    let target = config.path(path.as_str())?;
    match client.create_file(&target, args).await {
        Ok(Resource::File(f)) => Ok(f),
        // A folder (or anything else) by that name is not a document.
        Ok(other) => {
            close_resource(other).await;
            Err(StorageError::NotFound(path.to_string()).into())
        }
        Err(e) => Err(smb_failure(e, "open", Some(path.as_str()))),
    }
}

async fn get_file(client: Arc<Client>, config: Arc<Config>, path: DocPath, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));
    let file = open_file(&client, &config, &path, &args).await?;
    let result = read_bounded(&file, &path, max_bytes).await;
    let _ = file.close().await;
    result
}

async fn read_bounded(file: &smb::File, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let len = file.get_len().await.map_err(|e| smb_failure(e, "read", None))?;
    if len > max_bytes {
        return Err(StorageError::TooLarge(path.to_string()).into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0).min(CHUNK * 16));
    let mut buf = vec![0u8; CHUNK];
    let mut offset = 0u64;
    loop {
        let n = file.read_at(&mut buf, offset).await.map_err(|e| smb_failure(e, "read", None))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        offset = offset.saturating_add(n as u64);
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()).into());
        }
        if offset >= len {
            break;
        }
    }
    Ok(bytes)
}

async fn put_file(client: Arc<Client>, config: Arc<Config>, path: DocPath, bytes: Arc<Vec<u8>>) -> Result<(), Failure> {
    let args = FileCreateArgs::make_overwrite(FileAttributes::new(), CreateOptions::new().with_non_directory_file(true));
    let file = match open_file(&client, &config, &path, &args).await {
        Ok(f) => f,
        // A missing folder: create the parents (base folder included) and try again.
        Err(Failure { error: StorageError::NotFound(_), .. }) => {
            make_parents(&client, &config, &path).await?;
            open_file(&client, &config, &path, &args).await?
        }
        Err(f) => return Err(f),
    };
    let result = write_all(&file, &bytes).await;
    let closed = file.close().await;
    result?;
    closed.map_err(|e| smb_failure(e, "close", None))
}

async fn write_all(file: &smb::File, bytes: &[u8]) -> Result<(), Failure> {
    let mut offset = 0usize;
    while let Some(chunk) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        let chunk = chunk.get(..CHUNK.min(chunk.len())).unwrap_or(chunk);
        let n = file.write_at(chunk, offset as u64).await.map_err(|e| smb_failure(e, "write", None))?;
        if n == 0 {
            return Err(StorageError::Backend("smb write: the server accepted no bytes".into()).into());
        }
        offset = offset.saturating_add(n);
    }
    Ok(())
}

async fn make_parents(client: &Client, config: &Config, path: &DocPath) -> Result<(), Failure> {
    let args = FileCreateArgs::make_create_new(FileAttributes::new().with_directory(true), CreateOptions::new().with_directory_file(true));
    // Folders of the base, then of the document's own parent.
    let mut folders: Vec<String> = Vec::new();
    let all: Vec<&str> = config.base.iter().map(String::as_str).chain(path.parent().split('/').filter(|s| !s.is_empty())).collect();
    for i in 1..=all.len() {
        folders.push(all.get(..i).unwrap_or(&[]).join("\\"));
    }
    let share = config.share_path()?;
    for folder in folders {
        match client.create_file(&share.clone().with_path(&folder), &args).await {
            Ok(resource) => close_resource(resource).await,
            Err(e) if status_of(&e) == Some(STATUS_OBJECT_NAME_COLLISION) => {}
            Err(e) => return Err(smb_failure(e, "create folder", None)),
        }
    }
    Ok(())
}

async fn delete_file(client: Arc<Client>, config: Arc<Config>, path: DocPath) -> Result<(), Failure> {
    let access = FileAccessMask::new().with_delete(true).with_file_read_attributes(true).with_synchronize(true);
    let args = FileCreateArgs { options: CreateOptions::new().with_non_directory_file(true), ..FileCreateArgs::make_open_existing(access) };
    let file = open_file(&client, &config, &path, &args).await?;
    let result = file.set_info(FileDispositionInformation::default()).await.map_err(|e| smb_failure(e, "delete", Some(path.as_str())));
    let closed = file.close().await;
    result?;
    closed.map_err(|e| smb_failure(e, "close", None))
}

#[cfg(test)]
mod tests;
