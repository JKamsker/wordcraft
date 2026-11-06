//! FTP and FTPS (`ftp://user@host:21/folder`, `ftps://…`); the password comes from `WORDCRAFT_FTP_PASSWORD`.
//!
//! `ftps://` is explicit TLS (`AUTH TLS` on the normal port, then `PBSZ 0` / `PROT P`), verified
//! against the system's root certificates through rustls with the ring provider. Transfers are
//! passive and binary. The folder in the URL is relative to the login directory; a doubled slash
//! (`ftp://host//srv/docs`) makes it absolute.
//!
//! One control connection is kept and reused; an operation that fails on the connection itself
//! (not with an FTP reply) drops it, and an operation on a reused connection that turns out to be
//! dead is retried once on a fresh one. Every connection attempt and every operation is bounded by
//! a timeout, and every name the server returns is treated as hostile.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use suppaftp::list::ListParser;
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::tokio_rustls::TlsConnector;
use suppaftp::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use suppaftp::types::FileType;
use suppaftp::{FtpError, Status};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use super::path::MAX_DEPTH;
use super::{DocPath, Entry, MAX_LIST_ENTRIES, SharedStorage, Storage, StorageError};

/// The environment variable holding the FTP password.
pub const PASSWORD_ENV: &str = "WORDCRAFT_FTP_PASSWORD";
/// How long resolving, connecting, the TLS handshake and logging in may take together.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one storage operation (including a transfer or a whole listing) may take.
const OP_TIMEOUT: Duration = Duration::from_secs(120);
/// The most folders one listing visits, so a hostile server cannot keep it walking forever.
const MAX_LIST_DIRS: usize = 2_000;

type Conn = AsyncRustlsFtpStream;

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    let password = std::env::var(PASSWORD_ENV).ok();
    let config = Config::parse(url, password)?;
    let tls = if config.secure { Some(tls_config()?) } else { None };
    Ok(Arc::new(FtpStorage { config, tls, conn: Mutex::new(None) }))
}

/// What a storage URL says, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    secure: bool,
    host: String,
    port: u16,
    user: String,
    password: String,
    /// The folder every document path is joined under: `""`, `"docs/"` or `"/srv/docs/"`.
    base: String,
}

impl Config {
    fn parse(url: &str, password: Option<String>) -> Result<Self, StorageError> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| config_err("expected ftp://host/folder"))?;
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "ftp" => false,
            "ftps" => true,
            _ => return Err(config_err("expected an ftp:// or ftps:// URL")),
        };
        if rest.contains(['?', '#']) {
            return Err(config_err("FTP URLs take no query or fragment"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i + 1..).unwrap_or("")),
            None => (rest, ""),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let user = match userinfo {
            Some(u) if u.contains(':') => {
                return Err(config_err(&format!("put the password in {PASSWORD_ENV}, not in the URL")));
            }
            Some(u) => {
                let user = percent_decode(u)?;
                if user.is_empty() {
                    return Err(config_err("empty user name"));
                }
                user
            }
            None => "anonymous".to_string(),
        };
        let (host, port) = parse_host_port(hostport, 21)?;
        let base = parse_base(path)?;
        let password = match password {
            Some(p) if p.chars().any(char::is_control) => {
                return Err(config_err(&format!("{PASSWORD_ENV} contains control characters")));
            }
            Some(p) => p,
            None if user == "anonymous" => "anonymous@".to_string(),
            None => String::new(),
        };
        Ok(Self { secure, host, port, user, password, base })
    }

    /// The remote name of a document.
    fn remote(&self, rel: &str) -> String {
        format!("{}{rel}", self.base)
    }

    /// The remote name of the listing root (`""` lists the login directory).
    fn root(&self) -> String {
        match self.base.as_str() {
            "/" => "/".to_string(),
            b => b.trim_end_matches('/').to_string(),
        }
    }
}

fn config_err(why: &str) -> StorageError {
    StorageError::Config(format!("ftp: {why}"))
}

/// Splits `host[:port]` or `[v6]:port`; the host is returned without brackets.
pub(super) fn parse_host_port(hostport: &str, default_port: u16) -> Result<(String, u16), StorageError> {
    let bad = |why: &str| StorageError::Config(format!("{why}: {:?}", hostport.chars().take(80).collect::<String>()));
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| bad("unclosed '[' in host"))?;
        match after {
            "" => (h, None),
            a => (h, Some(a.strip_prefix(':').ok_or_else(|| bad("expected ':' after ']'"))?)),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    if host.is_empty() {
        return Err(bad("missing host"));
    }
    if host.len() > 253 || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')) {
        return Err(bad("invalid host"));
    }
    let port = match port {
        None => default_port,
        Some(p) => match p.parse::<u16>() {
            Ok(0) | Err(_) => return Err(bad("invalid port")),
            Ok(p) => p,
        },
    };
    Ok((host.to_string(), port))
}

/// The URL path as a base folder prefix. `""` → `""`, `docs/x` → `docs/x/`, `/srv` → `/srv/`.
fn parse_base(path: &str) -> Result<String, StorageError> {
    let decoded = percent_decode(path)?;
    let absolute = decoded.starts_with('/');
    let segments = checked_segments(&decoded)?;
    let mut base = if absolute { "/".to_string() } else { String::new() };
    for seg in segments {
        base.push_str(seg);
        base.push('/');
    }
    Ok(base)
}

/// The non-empty segments of a configured folder, refusing `.`/`..`, control characters and backslashes.
pub(super) fn checked_segments(path: &str) -> Result<Vec<&str>, StorageError> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() > MAX_DEPTH {
        return Err(StorageError::Config("storage folder too deep".into()));
    }
    for seg in &segments {
        if *seg == "." || *seg == ".." || seg.chars().any(|c| c.is_control() || c == '\\') {
            return Err(StorageError::Config(format!("invalid storage folder segment {:?}", seg.chars().take(80).collect::<String>())));
        }
    }
    Ok(segments)
}

/// Decodes `%XX` escapes; refuses malformed escapes, invalid UTF-8 and control characters.
pub(super) fn percent_decode(s: &str) -> Result<String, StorageError> {
    let bad = || StorageError::Config(format!("invalid escape in URL: {:?}", s.chars().take(80).collect::<String>()));
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(bad)?;
            let hex = std::str::from_utf8(hex).map_err(|_| bad())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| bad())?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| bad())?;
    if decoded.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(decoded)
}

/// rustls with the ring provider and the system's root certificates.
fn tls_config() -> Result<Arc<ClientConfig>, StorageError> {
    let provider = Arc::new(suppaftp::tokio_rustls::rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    let found = rustls_native_certs::load_native_certs();
    let (added, _ignored) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        return Err(config_err("ftps: no system root certificates found"));
    }
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| config_err(&format!("ftps: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// An operation's failure, and whether the control connection is still usable afterwards.
struct Failure {
    error: StorageError,
    state: ConnState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// A negative FTP reply: the connection is fine.
    Usable,
    /// The connection itself failed: drop it, and retry once if it was a reused one.
    Broken,
    /// The connection is left in an unknown state: drop it, without a retry.
    Discard,
}

impl Failure {
    fn reply(error: StorageError) -> Self {
        Self { error, state: ConnState::Usable }
    }

    fn broken(error: StorageError) -> Self {
        Self { error, state: ConnState::Broken }
    }
}

/// Maps a suppaftp error; `not_found` turns a 550 reply into [`StorageError::NotFound`].
fn ftp_failure(e: FtpError, what: &str, not_found: Option<&str>) -> Failure {
    match e {
        FtpError::UnexpectedResponse(resp) => {
            let error = match (resp.status, not_found) {
                (Status::FileUnavailable, Some(p)) => StorageError::NotFound(p.to_string()),
                (status, _) => StorageError::Backend(format!(
                    "ftp {what}: {} {}",
                    status.code(),
                    String::from_utf8_lossy(resp.body.get(..resp.body.len().min(200)).unwrap_or(&[])).trim()
                )),
            };
            Failure::reply(error)
        }
        other => Failure::broken(StorageError::Backend(format!("ftp {what}: {other}"))),
    }
}

type OpFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;

pub struct FtpStorage {
    config: Config,
    tls: Option<Arc<ClientConfig>>,
    conn: Mutex<Option<Conn>>,
}

impl FtpStorage {
    async fn connect(&self) -> Result<Conn, StorageError> {
        let cfg = &self.config;
        let attempt = async {
            let addrs: Vec<_> = tokio::net::lookup_host((cfg.host.as_str(), cfg.port))
                .await
                .map_err(|e| StorageError::Backend(format!("ftp: resolving {}: {e}", cfg.host)))?
                .collect();
            let mut last = None;
            let mut stream = None;
            for addr in addrs.into_iter().take(8) {
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            let stream = stream.ok_or_else(|| {
                StorageError::Backend(format!(
                    "ftp: connecting to {}:{}: {}",
                    cfg.host,
                    cfg.port,
                    last.map(|e| e.to_string()).unwrap_or_else(|| "no address".into())
                ))
            })?;
            let mut conn = Conn::connect_with_stream(stream).await.map_err(|e| StorageError::Backend(format!("ftp: greeting: {e}")))?;
            // Open data connections to the control connection's peer, never to the address a
            // PASV reply names: that keeps NATed servers working and stops a hostile server from
            // pointing data connections at other hosts.
            conn.set_passive_nat_workaround(true);
            if let Some(tls) = &self.tls {
                let connector = AsyncRustlsConnector::from(TlsConnector::from(Arc::clone(tls)));
                conn = conn.into_secure(connector, &cfg.host).await.map_err(|e| StorageError::Backend(format!("ftps: {e}")))?;
            }
            conn.login(cfg.user.as_str(), cfg.password.as_str()).await.map_err(|e| match e {
                FtpError::UnexpectedResponse(r) => StorageError::Backend(format!("ftp: login as {} refused ({})", cfg.user, r.status.code())),
                other => StorageError::Backend(format!("ftp: login: {other}")),
            })?;
            conn.transfer_type(FileType::Binary).await.map_err(|e| StorageError::Backend(format!("ftp: TYPE I: {e}")))?;
            Ok(conn)
        };
        tokio::time::timeout(CONNECT_TIMEOUT, attempt)
            .await
            .map_err(|_| StorageError::Backend(format!("ftp: connecting to {}:{} timed out", cfg.host, cfg.port)))?
    }

    /// Runs `op` on the shared connection, connecting when needed, within [`OP_TIMEOUT`].
    async fn run<T, F>(&self, op: F) -> Result<T, StorageError>
    where
        F: for<'a> Fn(&'a mut Conn, &'a Config) -> OpFuture<'a, T>,
    {
        let mut slot = self.conn.lock().await;
        let mut reused = slot.is_some();
        loop {
            let mut conn = match slot.take() {
                Some(c) => c,
                None => self.connect().await?,
            };
            let outcome = tokio::time::timeout(OP_TIMEOUT, op(&mut conn, &self.config)).await;
            match outcome {
                Ok(Ok(value)) => {
                    *slot = Some(conn);
                    return Ok(value);
                }
                Ok(Err(Failure { error, state: ConnState::Usable })) => {
                    *slot = Some(conn);
                    return Err(error);
                }
                Ok(Err(Failure { error, state: ConnState::Discard })) => return Err(error),
                Ok(Err(Failure { error, state: ConnState::Broken })) => {
                    // The connection is unusable; a cached one may simply have gone stale.
                    if reused {
                        reused = false;
                        continue;
                    }
                    return Err(error);
                }
                Err(_) => return Err(StorageError::Backend("ftp: operation timed out".into())),
            }
        }
    }
}

#[async_trait::async_trait]
impl Storage for FtpStorage {
    fn describe(&self) -> String {
        let c = &self.config;
        let scheme = if c.secure { "ftps" } else { "ftp" };
        let host = if c.host.contains(':') { format!("[{}]", c.host) } else { c.host.clone() };
        format!("{scheme} {host}:{}/{}", c.port, c.base.trim_start_matches('/').trim_end_matches('/'))
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        self.run(|conn, cfg| Box::pin(list_all(conn, cfg))).await
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        self.run(|conn, cfg| {
            let path = path.clone();
            Box::pin(async move { get_file(conn, cfg, &path, max_bytes).await })
        })
        .await
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        let bytes = Arc::new(bytes);
        self.run(|conn, cfg| {
            let (path, bytes) = (path.clone(), Arc::clone(&bytes));
            Box::pin(async move { put_file(conn, cfg, &path, &bytes).await })
        })
        .await
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        self.run(|conn, cfg| {
            let path = path.clone();
            Box::pin(async move { conn.rm(cfg.remote(path.as_str())).await.map_err(|e| ftp_failure(e, "delete", Some(path.as_str()))) })
        })
        .await
    }
}

/// Reads one directory, preferring MLSD and falling back to LIST when the server lacks it.
async fn read_dir(conn: &mut Conn, dir: &str, use_mlsd: &mut bool) -> Result<Vec<suppaftp::list::File>, Failure> {
    let target = if dir.is_empty() { None } else { Some(dir) };
    if *use_mlsd {
        match conn.mlsd(target).await {
            Ok(lines) => return Ok(lines.iter().filter_map(|l| ListParser::parse_mlsd(l).ok()).collect()),
            Err(FtpError::UnexpectedResponse(r)) if matches!(r.status.code(), 500 | 501 | 502 | 504) => *use_mlsd = false,
            Err(e) => return Err(ftp_failure(e, "MLSD", None)),
        }
    }
    let lines = conn.list(target).await.map_err(|e| ftp_failure(e, "LIST", None))?;
    Ok(lines.iter().filter_map(|l| ListParser::parse_posix(l).or_else(|_| ListParser::parse_dos(l)).ok()).collect())
}

async fn list_all(conn: &mut Conn, cfg: &Config) -> Result<Vec<Entry>, Failure> {
    let mut entries = Vec::new();
    let mut use_mlsd = true;
    // (remote folder, document-relative prefix, depth of the folder)
    let mut pending = vec![(cfg.root(), String::new(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, prefix, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_LIST_DIRS {
            break;
        }
        let files = match read_dir(conn, &dir, &mut use_mlsd).await {
            Ok(f) => f,
            // A sub-folder that vanished or is unreadable is skipped; the root must be readable.
            Err(f) if f.state == ConnState::Usable && depth > 0 => continue,
            Err(f) => return Err(f),
        };
        for file in files {
            let name = file.name();
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                continue;
            }
            let rel = format!("{prefix}{name}");
            if file.is_directory() {
                if depth + 1 < MAX_DEPTH && DocPath::parse(&rel).is_ok() {
                    let remote = if dir.is_empty() || dir == "/" { format!("{dir}{name}") } else { format!("{dir}/{name}") };
                    pending.push((remote, format!("{rel}/"), depth + 1));
                }
            } else if file.is_file()
                && let Ok(path) = DocPath::parse(&rel)
            {
                let modified = Some(chrono::DateTime::<chrono::Utc>::from(file.modified())).filter(|m| m.timestamp() > 0);
                entries.push(Entry { path: path.to_string(), size: file.size() as u64, modified });
                if entries.len() >= MAX_LIST_ENTRIES {
                    return Ok(entries);
                }
            }
        }
    }
    Ok(entries)
}

async fn get_file(conn: &mut Conn, cfg: &Config, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let remote = cfg.remote(path.as_str());
    match conn.size(&remote).await {
        Ok(size) if size as u64 > max_bytes => return Err(Failure::reply(StorageError::TooLarge(path.to_string()))),
        Ok(_) => {}
        Err(FtpError::UnexpectedResponse(r)) if r.status == Status::FileUnavailable => {
            return Err(Failure::reply(StorageError::NotFound(path.to_string())));
        }
        // SIZE is optional (RFC 3659); the bounded read below still enforces the limit.
        Err(FtpError::UnexpectedResponse(_) | FtpError::BadResponse) => {}
        Err(e) => return Err(ftp_failure(e, "SIZE", None)),
    }
    let mut stream = conn.retr_as_stream(&remote).await.map_err(|e| ftp_failure(e, "RETR", Some(path.as_str())))?;
    let mut bytes = Vec::new();
    let limit = max_bytes.saturating_add(1);
    (&mut stream).take(limit).read_to_end(&mut bytes).await.map_err(|e| Failure::broken(StorageError::Backend(format!("ftp RETR: {e}"))))?;
    if bytes.len() as u64 > max_bytes {
        // The transfer was cut short and the control connection is left mid-transfer: drop it,
        // but do not retry, since the file itself is the problem.
        drop(stream);
        return Err(Failure { error: StorageError::TooLarge(path.to_string()), state: ConnState::Discard });
    }
    stream.finish().await.map_err(|e| ftp_failure(e, "RETR", Some(path.as_str())))?;
    Ok(bytes)
}

async fn put_file(conn: &mut Conn, cfg: &Config, path: &DocPath, bytes: &[u8]) -> Result<(), Failure> {
    let remote = cfg.remote(path.as_str());
    let mut reader = bytes;
    match conn.put_file(&remote, &mut reader).await {
        Ok(_) => return Ok(()),
        // 550/553: most likely a missing folder; create the parents and try again.
        Err(FtpError::UnexpectedResponse(r)) if matches!(r.status.code(), 550 | 553) && !path.parent().is_empty() => {}
        Err(e) => return Err(ftp_failure(e, "STOR", None)),
    }
    let mut folder = String::new();
    for seg in path.parent().split('/') {
        folder.push_str(seg);
        match conn.mkdir(cfg.remote(&folder)).await {
            // An existing folder answers 550 (or similar); STOR reports what really failed.
            Ok(()) | Err(FtpError::UnexpectedResponse(_)) => {}
            Err(e) => return Err(ftp_failure(e, "MKD", None)),
        }
        folder.push('/');
    }
    let mut reader = bytes;
    conn.put_file(&remote, &mut reader).await.map(|_| ()).map_err(|e| ftp_failure(e, "STOR", None))
}

#[cfg(test)]
mod tests;
