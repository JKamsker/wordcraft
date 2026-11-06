//! S3 (`s3://bucket/prefix`), Azure Blob (`az://container/prefix`) and Google Cloud Storage (`gs://bucket/prefix`) through `object_store`.
//!
//! URL forms (credentials never come from the URL; they come from the standard environment that
//! `object_store`'s `from_env()` builders read, such as `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`,
//! `AZURE_STORAGE_ACCOUNT_NAME`/`AZURE_STORAGE_ACCOUNT_KEY`/`AZURE_STORAGE_SAS_KEY` and
//! `GOOGLE_SERVICE_ACCOUNT`):
//!
//! - `s3://bucket/optional/prefix?region=eu-central-1&endpoint=http://localhost:9000&allow_http=true&path_style=true`
//!   (also S3-compatible stores such as MinIO).
//! - `az://container/prefix?account=NAME&endpoint=…&allow_http=true&emulator=true` (`azure://` is the
//!   same; `emulator=true` targets Azurite), and `abfs://container@account.dfs.core.windows.net/prefix`.
//! - `gs://bucket/prefix`.
//!
//! Unknown query options are refused, so a typo never silently falls back to a default.

use std::sync::Arc;

use futures_util::StreamExt;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};

use super::{DocPath, Entry, SharedStorage, Storage, StorageError};

/// A bucket or container (under an optional key prefix) as a document store.
pub struct ObjectStorage {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
    description: String,
}

impl ObjectStorage {
    /// Wraps `store`, keeping every key under `prefix`. `description` is shown in logs and must hold no secrets.
    pub fn new(store: Arc<dyn ObjectStore>, prefix: Path, description: String) -> Self {
        Self { store, prefix, description }
    }

    /// The object key for `path`: the prefix, then the path's segments verbatim.
    fn key(&self, path: &DocPath) -> Result<Path, StorageError> {
        let joined = if self.prefix.as_ref().is_empty() { path.as_str().to_string() } else { format!("{}/{}", self.prefix.as_ref(), path.as_str()) };
        Path::parse(joined).map_err(|_| StorageError::InvalidPath(path.to_string()))
    }

    /// The document path of a listed key, when it lies under the prefix and is a valid [`DocPath`].
    fn doc_path(&self, location: &Path) -> Option<DocPath> {
        let parts = location.prefix_match(&self.prefix)?;
        let relative = parts.map(|p| p.as_ref().to_string()).collect::<Vec<_>>().join("/");
        DocPath::parse(&relative).ok()
    }
}

/// Maps an `object_store` error; the message names the document, not the store's credentials.
fn backend_error(path: &str, err: object_store::Error) -> StorageError {
    match err {
        object_store::Error::NotFound { .. } => StorageError::NotFound(path.to_string()),
        other => StorageError::Backend(format!("{path}: {}", redact(&other.to_string()))),
    }
}

/// Keeps error messages short and drops query strings, which may carry SAS tokens or signatures.
fn redact(message: &str) -> String {
    let mut out = String::with_capacity(message.len().min(400));
    let mut in_query = false;
    for c in message.chars().take(400) {
        if c == '?' {
            in_query = true;
            out.push_str("?…");
            continue;
        }
        if in_query && (c.is_whitespace() || matches!(c, ')' | '"' | '\'' | ',')) {
            in_query = false;
        }
        if !in_query {
            out.push(c);
        }
    }
    out
}

#[async_trait::async_trait]
impl Storage for ObjectStorage {
    fn describe(&self) -> String {
        self.description.clone()
    }

    async fn list(&self) -> Result<Vec<Entry>, StorageError> {
        let prefix = (!self.prefix.as_ref().is_empty()).then_some(&self.prefix);
        let mut stream = self.store.list(prefix);
        let mut entries = Vec::new();
        while let Some(item) = stream.next().await {
            let meta = item.map_err(|e| backend_error("listing", e))?;
            if let Some(path) = self.doc_path(&meta.location) {
                entries.push(Entry { path: path.to_string(), size: meta.size, modified: Some(meta.last_modified) });
                if entries.len() >= super::MAX_LIST_ENTRIES {
                    break;
                }
            }
        }
        Ok(entries)
    }

    async fn get(&self, path: &DocPath, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
        let key = self.key(path)?;
        let meta = self.store.head(&key).await.map_err(|e| backend_error(path.as_str(), e))?;
        if meta.size > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()));
        }
        let result = self.store.get(&key).await.map_err(|e| backend_error(path.as_str(), e))?;
        // The object may have been replaced between `head` and `get`: check again.
        if result.meta.size > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()));
        }
        let bytes = result.bytes().await.map_err(|e| backend_error(path.as_str(), e))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::TooLarge(path.to_string()));
        }
        Ok(bytes.to_vec())
    }

    async fn put(&self, path: &DocPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        let key = self.key(path)?;
        self.store.put(&key, PutPayload::from(bytes)).await.map_err(|e| backend_error(path.as_str(), e))?;
        Ok(())
    }

    async fn delete(&self, path: &DocPath) -> Result<(), StorageError> {
        let key = self.key(path)?;
        // Object stores delete missing keys silently; the trait reports them.
        self.store.head(&key).await.map_err(|e| backend_error(path.as_str(), e))?;
        self.store.delete(&key).await.map_err(|e| backend_error(path.as_str(), e))
    }
}

/// Opens the backend for `url` (its scheme already matched this backend).
pub fn open(url: &str) -> Result<SharedStorage, StorageError> {
    let spec = parse(url)?;
    // reqwest is built without a bundled crypto provider; use ring for every TLS client in the
    // process. An error means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let description = spec.describe();
    let store: Arc<dyn ObjectStore> = match spec.kind {
        Kind::S3 { region, endpoint, allow_http, path_style } => {
            let mut b = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(&spec.bucket);
            if let Some(region) = region {
                b = b.with_region(region);
            }
            if let Some(endpoint) = endpoint {
                b = b.with_endpoint(endpoint);
            }
            if let Some(allow) = allow_http {
                b = b.with_allow_http(allow);
            }
            if let Some(path_style) = path_style {
                b = b.with_virtual_hosted_style_request(!path_style);
            }
            Arc::new(b.build().map_err(|e| config_error("s3", e))?)
        }
        Kind::Azure { account, endpoint, allow_http, emulator } => {
            let mut b = object_store::azure::MicrosoftAzureBuilder::from_env().with_container_name(&spec.bucket);
            if let Some(account) = account {
                b = b.with_account(account);
            }
            if let Some(endpoint) = endpoint {
                b = b.with_endpoint(endpoint);
            }
            if let Some(allow) = allow_http {
                b = b.with_allow_http(allow);
            }
            if let Some(emulator) = emulator {
                b = b.with_use_emulator(emulator);
            }
            Arc::new(b.build().map_err(|e| config_error("azure", e))?)
        }
        Kind::Gcs => {
            let b = object_store::gcp::GoogleCloudStorageBuilder::from_env().with_bucket_name(&spec.bucket);
            Arc::new(b.build().map_err(|e| config_error("gs", e))?)
        }
    };
    Ok(Arc::new(ObjectStorage::new(store, spec.prefix, description)))
}

fn config_error(scheme: &str, err: object_store::Error) -> StorageError {
    StorageError::Config(format!("{scheme}: {}", redact(&err.to_string())))
}

/// A parsed object storage URL.
#[derive(Debug, PartialEq)]
struct Spec {
    kind: Kind,
    /// The bucket (S3, GCS) or container (Azure).
    bucket: String,
    prefix: Path,
}

#[derive(Debug, PartialEq)]
enum Kind {
    S3 { region: Option<String>, endpoint: Option<String>, allow_http: Option<bool>, path_style: Option<bool> },
    Azure { account: Option<String>, endpoint: Option<String>, allow_http: Option<bool>, emulator: Option<bool> },
    Gcs,
}

impl Spec {
    fn describe(&self) -> String {
        let place = if self.prefix.as_ref().is_empty() { self.bucket.clone() } else { format!("{}/{}", self.bucket, self.prefix.as_ref()) };
        let at = |endpoint: &Option<String>| endpoint.as_deref().and_then(endpoint_host).map(|h| format!(" at {h}")).unwrap_or_default();
        match &self.kind {
            Kind::S3 { endpoint, .. } => format!("s3 bucket {place}{}", at(endpoint)),
            Kind::Azure { account, endpoint, emulator, .. } => {
                let account = account.as_deref().map(|a| format!(" (account {a})")).unwrap_or_default();
                let emulator = if *emulator == Some(true) { " (emulator)" } else { "" };
                format!("azure container {place}{account}{emulator}{}", at(endpoint))
            }
            Kind::Gcs => format!("gs bucket {place}"),
        }
    }
}

/// `host[:port]` of an endpoint URL, for descriptions.
fn endpoint_host(endpoint: &str) -> Option<String> {
    let u = url::Url::parse(endpoint).ok()?;
    let host = u.host_str()?;
    Some(match u.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn cfg(message: impl Into<String>) -> StorageError {
    StorageError::Config(message.into())
}

fn parse_bool(key: &str, value: &str) -> Result<bool, StorageError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(cfg(format!("option {key} must be true or false"))),
    }
}

/// Checks an `endpoint` option: an http(s) URL without credentials, query or fragment.
fn parse_endpoint(value: &str) -> Result<String, StorageError> {
    let u = url::Url::parse(value).map_err(|_| cfg("option endpoint must be an http:// or https:// URL"))?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err(cfg("option endpoint must be an http:// or https:// URL"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(cfg("option endpoint must not contain credentials; set them in the environment"));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(cfg("option endpoint must not have a query or fragment"));
    }
    Ok(value.trim_end_matches('/').to_string())
}

/// Bucket and container names: letters, digits, `-`, `_` and `.` only.
fn check_bucket(name: &str) -> Result<(), StorageError> {
    if name.is_empty() {
        return Err(cfg("the URL names no bucket or container"));
    }
    if name.len() > 255 || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(cfg("invalid bucket or container name"));
    }
    Ok(())
}

/// Parses an object storage URL without contacting the store.
fn parse(raw: &str) -> Result<Spec, StorageError> {
    let u = url::Url::parse(raw.trim()).map_err(|_| cfg("not a valid storage URL"))?;
    let scheme = u.scheme().to_ascii_lowercase();
    if u.fragment().is_some() {
        return Err(cfg("storage URL must not have a fragment"));
    }
    if u.port().is_some() {
        return Err(cfg("storage URL must not have a port; use the endpoint option"));
    }
    let host = u.host_str().unwrap_or("").to_string();

    let (bucket, account_from_host) = if matches!(scheme.as_str(), "abfs" | "abfss") {
        // abfs://container@account.dfs.core.windows.net/prefix
        if u.password().is_some() {
            return Err(cfg("storage URL must not contain credentials; set them in the environment"));
        }
        let container = u.username().to_string();
        let account = host
            .strip_suffix(".dfs.core.windows.net")
            .or_else(|| host.strip_suffix(".blob.core.windows.net"))
            .filter(|a| !a.is_empty() && !a.contains('.'))
            .ok_or_else(|| cfg("abfs URL must look like abfs://container@account.dfs.core.windows.net/prefix"))?;
        (container, Some(account.to_string()))
    } else {
        if !u.username().is_empty() || u.password().is_some() {
            return Err(cfg("storage URL must not contain credentials; set them in the environment"));
        }
        (host, None)
    };
    check_bucket(&bucket)?;

    let prefix = Path::from_url_path(u.path()).map_err(|_| cfg("invalid key prefix in storage URL"))?;
    if u.path().trim_matches('/').contains("//") {
        return Err(cfg("invalid key prefix in storage URL"));
    }

    let mut region = None;
    let mut endpoint = None;
    let mut allow_http = None;
    let mut path_style = None;
    let mut account = account_from_host;
    let mut emulator = None;
    let is_s3 = scheme == "s3";
    let is_azure = matches!(scheme.as_str(), "az" | "azure" | "abfs" | "abfss");
    for (key, value) in u.query_pairs() {
        let key = key.as_ref();
        let value = value.as_ref();
        let slot_taken = || cfg(format!("option {key} given twice"));
        match key {
            "region" if is_s3 => {
                if value.is_empty() {
                    return Err(cfg("option region is empty"));
                }
                if region.replace(value.to_string()).is_some() {
                    return Err(slot_taken());
                }
            }
            "endpoint" if is_s3 || is_azure => {
                if endpoint.replace(parse_endpoint(value)?).is_some() {
                    return Err(slot_taken());
                }
            }
            "allow_http" if is_s3 || is_azure => {
                if allow_http.replace(parse_bool(key, value)?).is_some() {
                    return Err(slot_taken());
                }
            }
            "path_style" if is_s3 => {
                if path_style.replace(parse_bool(key, value)?).is_some() {
                    return Err(slot_taken());
                }
            }
            "account" if is_azure => {
                if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(cfg("option account must be a storage account name"));
                }
                if account.replace(value.to_string()).is_some() {
                    return Err(slot_taken());
                }
            }
            "emulator" if is_azure => {
                if emulator.replace(parse_bool(key, value)?).is_some() {
                    return Err(slot_taken());
                }
            }
            other => {
                let shown: String = other.chars().take(40).collect();
                return Err(cfg(format!("unknown option {shown:?} for {scheme}:// storage")));
            }
        }
    }

    let kind = match scheme.as_str() {
        "s3" => Kind::S3 { region, endpoint, allow_http, path_style },
        "az" | "azure" | "abfs" | "abfss" => Kind::Azure { account, endpoint, allow_http, emulator },
        "gs" => Kind::Gcs,
        other => return Err(cfg(format!("unknown object storage scheme {other}://"))),
    };
    Ok(Spec { kind, bucket, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn doc(p: &str) -> DocPath {
        DocPath::parse(p).unwrap()
    }

    fn storage(store: &Arc<InMemory>, prefix: &str) -> ObjectStorage {
        ObjectStorage::new(store.clone(), Path::parse(prefix).unwrap(), "test".into())
    }

    #[tokio::test]
    async fn round_trip_under_prefix() {
        let mem = Arc::new(InMemory::new());
        let s = storage(&mem, "team/docs");
        s.put(&doc("reports/q3 [draft].docx"), b"hello".to_vec()).await.unwrap();
        s.put(&doc("a.txt"), b"x".to_vec()).await.unwrap();
        assert_eq!(s.get(&doc("reports/q3 [draft].docx"), 100).await.unwrap(), b"hello");
        // Keys are stored verbatim under the prefix.
        mem.head(&Path::parse("team/docs/reports/q3 [draft].docx").unwrap()).await.unwrap();
        let mut list = s.list().await.unwrap();
        list.sort_by(|a, b| a.path.cmp(&b.path));
        let names: Vec<_> = list.iter().map(|e| (e.path.as_str(), e.size)).collect();
        assert_eq!(names, [("a.txt", 1), ("reports/q3 [draft].docx", 5)]);
        assert!(list.iter().all(|e| e.modified.is_some()));
        s.put(&doc("a.txt"), b"replaced".to_vec()).await.unwrap();
        assert_eq!(s.get(&doc("a.txt"), 100).await.unwrap(), b"replaced");
        s.delete(&doc("a.txt")).await.unwrap();
        assert!(matches!(s.get(&doc("a.txt"), 100).await, Err(StorageError::NotFound(_))));
        assert_eq!(s.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prefix_isolation() {
        let mem = Arc::new(InMemory::new());
        mem.put(&Path::parse("other/secret.docx").unwrap(), PutPayload::from(b"no".to_vec())).await.unwrap();
        mem.put(&Path::parse("team/docsX/near.docx").unwrap(), PutPayload::from(b"no".to_vec())).await.unwrap();
        mem.put(&Path::parse("team/docs/mine.docx").unwrap(), PutPayload::from(b"yes".to_vec())).await.unwrap();
        // A key under the prefix that is not a valid DocPath is skipped.
        mem.put(&Path::parse("team/docs/bad:name.docx").unwrap(), PutPayload::from(b"?".to_vec())).await.unwrap();
        let s = storage(&mem, "team/docs");
        let list = s.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].path, "mine.docx");
        assert!(matches!(s.get(&doc("secret.docx"), 100).await, Err(StorageError::NotFound(_))));

        // No prefix: everything valid is listed.
        let root = storage(&mem, "");
        assert_eq!(root.list().await.unwrap().len(), 3);
        assert_eq!(root.get(&doc("team/docs/mine.docx"), 100).await.unwrap(), b"yes");
    }

    #[tokio::test]
    async fn refuses_too_large() {
        let mem = Arc::new(InMemory::new());
        let s = storage(&mem, "p");
        s.put(&doc("big.bin"), vec![0; 1000]).await.unwrap();
        assert!(matches!(s.get(&doc("big.bin"), 999).await, Err(StorageError::TooLarge(_))));
        assert_eq!(s.get(&doc("big.bin"), 1000).await.unwrap().len(), 1000);
    }

    #[tokio::test]
    async fn not_found_maps() {
        let mem = Arc::new(InMemory::new());
        let s = storage(&mem, "p");
        assert!(matches!(s.get(&doc("none.docx"), 100).await, Err(StorageError::NotFound(_))));
        assert!(matches!(s.delete(&doc("none.docx")).await, Err(StorageError::NotFound(_))));
    }

    #[test]
    fn parses_s3() {
        let spec = parse("s3://bucket/optional/prefix?region=eu-central-1&endpoint=http://localhost:9000&allow_http=true&path_style=true").unwrap();
        assert_eq!(spec.bucket, "bucket");
        assert_eq!(spec.prefix.as_ref(), "optional/prefix");
        assert_eq!(
            spec.kind,
            Kind::S3 {
                region: Some("eu-central-1".into()),
                endpoint: Some("http://localhost:9000".into()),
                allow_http: Some(true),
                path_style: Some(true)
            }
        );
        assert_eq!(spec.describe(), "s3 bucket bucket/optional/prefix at localhost:9000");
        let bare = parse("s3://bucket").unwrap();
        assert_eq!(bare.prefix.as_ref(), "");
        assert_eq!(bare.describe(), "s3 bucket bucket");
        assert_eq!(parse("s3://b/with%20space/").unwrap().prefix.as_ref(), "with space");
    }

    #[test]
    fn parses_azure_and_gcs() {
        for scheme in ["az", "azure"] {
            let spec = parse(&format!("{scheme}://docs/pre?account=acct&emulator=true&allow_http=1")).unwrap();
            assert_eq!(spec.bucket, "docs");
            assert_eq!(spec.prefix.as_ref(), "pre");
            assert_eq!(spec.kind, Kind::Azure { account: Some("acct".into()), endpoint: None, allow_http: Some(true), emulator: Some(true) });
            assert_eq!(spec.describe(), "azure container docs/pre (account acct) (emulator)");
        }
        let abfs = parse("abfs://docs@acct.dfs.core.windows.net/x/y").unwrap();
        assert_eq!(abfs.bucket, "docs");
        assert_eq!(abfs.prefix.as_ref(), "x/y");
        assert!(matches!(abfs.kind, Kind::Azure { account: Some(ref a), .. } if a == "acct"));
        let gs = parse("gs://bucket/p").unwrap();
        assert_eq!(gs.kind, Kind::Gcs);
        assert_eq!(gs.describe(), "gs bucket bucket/p");
    }

    #[test]
    fn rejects_bad_urls() {
        let bad = [
            "s3://",
            "s3:///prefix",
            "gs://",
            "az://?account=a",
            "s3://bucket?unknown=1",
            "s3://bucket?region=a&region=b",
            "s3://bucket?account=a",
            "s3://bucket?allow_http=maybe",
            "s3://bucket?endpoint=ftp://x",
            "s3://bucket?endpoint=not a url",
            "s3://bucket?endpoint=http://user:pw@minio:9000",
            "s3://key:secret@bucket/p",
            "s3://bucket:9000/p",
            "s3://bucket/a/%00/b",
            "s3://bucket/a//b",
            "s3://bucket#frag",
            "s3://bu cket/p",
            "s3://b%2Fx/p",
            "gs://bucket?region=x",
            "az://docs?account=bad-name!",
            "az://docs?emulator=yes&emulator=no",
            "abfs://acct.dfs.core.windows.net/p",
            "abfs://docs@example.com/p",
            "abfs://docs:pw@acct.dfs.core.windows.net/p",
            "http://bucket/p",
            "garbage",
            "",
            "s3",
            "://",
            "s3://\u{0}/x",
            "s3://bucket/a\u{1}b",
        ];
        for raw in bad {
            assert!(matches!(parse(raw), Err(StorageError::Config(_))), "{raw:?} must be a Config error");
            assert!(matches!(open(raw), Err(StorageError::Config(_))), "{raw:?} must not open");
        }
    }

    #[test]
    fn hostile_urls_never_panic() {
        let junk = ["s3://%", "s3://b/%ff%fe", "az://c@/p", "abfs://@.dfs.core.windows.net", "gs://b/?=&=&", "s3://b/?\u{1F600}=1"];
        for raw in junk {
            let _ = parse(raw);
        }
        let long = format!("s3://{}/p", "a".repeat(10_000));
        assert!(parse(&long).is_err());
    }

    #[tokio::test]
    async fn opens_s3_without_network() {
        // Building a client only reads configuration; nothing is contacted.
        let s = open("s3://bucket/pre?region=us-east-1&endpoint=http://127.0.0.1:9&allow_http=true&path_style=true").unwrap();
        assert_eq!(s.describe(), "s3 bucket bucket/pre at 127.0.0.1:9");
    }

    #[test]
    fn redacts_query_strings() {
        let msg = redact("request to https://acct.blob.core.windows.net/c/x?sig=SECRET&se=1 failed (403)");
        assert!(!msg.contains("SECRET"), "{msg}");
        assert!(msg.contains("failed (403)"));
    }
}
