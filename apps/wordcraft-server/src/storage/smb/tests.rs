use super::*;

#[test]
fn parses_urls() {
    let c = Config::parse("smb://CORP;alice@files.example.com/Team/docs/2026", Some("pw".into())).unwrap();
    assert_eq!(
        c,
        Config {
            host: "files.example.com".into(),
            port: 445,
            domain: Some("CORP".into()),
            user: "alice".into(),
            password: "pw".into(),
            share: "Team".into(),
            base: vec!["docs".into(), "2026".into()],
        }
    );
    assert_eq!(c.user_name(), "CORP\\alice");
    assert_eq!(c.name("a/b.docx"), "docs\\2026\\a\\b.docx");
    assert_eq!(c.name(""), "docs\\2026");

    let c = Config::parse("SMB://bob@[::1]:1445/share/", None).unwrap();
    assert_eq!((c.host.as_str(), c.port, c.user_name().as_str(), c.share.as_str()), ("::1", 1445, "bob", "share"));
    assert!(c.base.is_empty());
    assert_eq!(c.name("x.docx"), "x.docx");
    assert_eq!(c.name(""), "");
    let c = Config::parse("smb://first%20last@host/my%20share", None).unwrap();
    assert_eq!((c.user.as_str(), c.share.as_str()), ("first last", "my share"));
}

#[test]
fn describe_hides_the_password() {
    let storage =
        SmbStorage { config: Arc::new(Config::parse("smb://alice@nas/Docs/team", Some("secret".into())).unwrap()), client: Mutex::new(None) };
    assert_eq!(storage.describe(), "smb nas/Docs/team");
    let storage =
        SmbStorage { config: Arc::new(Config::parse("smb://alice@nas:1445/Docs", Some("secret".into())).unwrap()), client: Mutex::new(None) };
    assert_eq!(storage.describe(), "smb nas:1445/Docs");
}

#[test]
fn hostile_urls_are_refused_without_panicking() {
    let deep = format!("smb://u@h/share/{}", "a/".repeat(MAX_DEPTH + 1));
    for url in [
        "smb://",
        "smb://host/share",
        "smb://@host/share",
        "smb://;u@host/share",
        "smb://d;@host/share",
        "smb://u:pw@host/share",
        "smb://u@host",
        "smb://u@host/",
        "smb://u@/share",
        "smb://u@host:0/share",
        "smb://u@host:70000/share",
        "smb://u@host/share/../x",
        "smb://u@host/share/a%00b",
        "smb://u@host/share/a%",
        "smb://u@host/sh*re",
        "smb://u@host/share?x=1",
        "smb://u@host/share#x",
        "smb://u@[::1/share",
        "smb://u%5cx@host/share",
        "ftp://u@host/share",
        deep.as_str(),
    ] {
        assert!(Config::parse(url, None).is_err(), "{url:?} must be refused");
    }
    assert!(Config::parse("smb://u@h/s", Some("a\nb".into())).is_err());
    for n in 0u32..2000 {
        let s: String = (0..(n % 23)).map(|i| char::from_u32((n.wrapping_mul(37).wrapping_add(i * 11)) % 128).unwrap_or('a')).collect();
        let _ = Config::parse(&format!("smb://{s}"), None);
        let _ = Config::parse(&format!("smb://u@h/{s}"), None);
    }
}

#[test]
fn converts_file_times() {
    assert_eq!(file_time(0), None);
    // 1970-01-01T00:00:00Z
    assert_eq!(file_time(116_444_736_000_000_000).map(|t| t.timestamp()), Some(0));
    assert_eq!(file_time(116_444_736_000_000_000 + 15).map(|t| t.timestamp_subsec_nanos()), Some(1_500));
    let _ = file_time(u64::MAX);
    let _ = file_time(1);
}

#[test]
fn maps_not_found_statuses() {
    let f = smb_failure(smb::Error::UnexpectedMessageStatus(STATUS_OBJECT_NAME_NOT_FOUND), "open", Some("a.docx"));
    assert!(matches!(f.error, StorageError::NotFound(_)) && !f.broken);
    let f = smb_failure(smb::Error::UnexpectedMessageStatus(STATUS_OBJECT_PATH_NOT_FOUND), "open", None);
    assert!(matches!(f.error, StorageError::Backend(_)) && !f.broken);
    let f = smb_failure(smb::Error::IoError(std::io::Error::other("reset")), "open", Some("a.docx"));
    assert!(matches!(f.error, StorageError::Backend(_)) && f.broken);
}

#[tokio::test]
async fn a_panicking_operation_is_an_error() {
    let r: Result<(), StorageError> = isolated(Duration::from_secs(5), async {
        let v: Vec<u8> = Vec::new();
        let i = v.len() + 3;
        let _ = v[i];
    })
    .await;
    assert!(matches!(r, Err(StorageError::Backend(_))));
    let r = isolated(Duration::from_millis(50), tokio::time::sleep(Duration::from_secs(10))).await;
    assert!(matches!(r, Err(StorageError::Backend(_))));
}

#[tokio::test]
async fn unreachable_server_is_an_error_not_a_hang() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let storage = open(&format!("smb://u@127.0.0.1:{port}/share")).unwrap();
    assert!(matches!(storage.list().await, Err(StorageError::Backend(_))));
}

/// A round trip against a real SMB server. Run with a share you can write to, for example Samba:
///
/// ```text
/// WORDCRAFT_SMB_TEST_URL='smb://user@127.0.0.1/share/wordcraft-test' WORDCRAFT_SMB_PASSWORD=… \
///   cargo test -p wordcraft-server smb_round_trip -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs an SMB server: set WORDCRAFT_SMB_TEST_URL and WORDCRAFT_SMB_PASSWORD"]
async fn smb_round_trip() {
    let url = std::env::var("WORDCRAFT_SMB_TEST_URL").expect("WORDCRAFT_SMB_TEST_URL");
    let storage = open(&url).unwrap();
    // A base folder that does not exist yet lists as empty.
    let fresh = open(&format!("{}/not-created-yet-{}", url.trim_end_matches('/'), std::process::id())).unwrap();
    assert!(fresh.list().await.unwrap().is_empty());
    let top = DocPath::parse("top.docx").unwrap();
    let nested = DocPath::parse("reports/2026/q3 summary.docx").unwrap();
    let payload: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();

    storage.put(&top, b"hello".to_vec()).await.unwrap();
    storage.put(&nested, payload.clone()).await.unwrap();
    assert_eq!(storage.get(&top, 100).await.unwrap(), b"hello");
    assert_eq!(storage.get(&nested, 1 << 20).await.unwrap(), payload);
    storage.put(&top, b"hi".to_vec()).await.unwrap();
    assert_eq!(storage.get(&top, 100).await.unwrap(), b"hi");

    let listed: Vec<(String, u64)> = storage.list().await.unwrap().into_iter().map(|e| (e.path, e.size)).collect();
    assert!(listed.contains(&("top.docx".to_string(), 2)), "{listed:?}");
    assert!(listed.contains(&("reports/2026/q3 summary.docx".to_string(), payload.len() as u64)), "{listed:?}");

    assert!(matches!(storage.get(&nested, 1000).await, Err(StorageError::TooLarge(_))));
    let missing = DocPath::parse("nope/missing.docx").unwrap();
    assert!(matches!(storage.get(&missing, 100).await, Err(StorageError::NotFound(_))));
    assert!(matches!(storage.delete(&missing).await, Err(StorageError::NotFound(_))));
    storage.delete(&top).await.unwrap();
    storage.delete(&nested).await.unwrap();
    assert!(matches!(storage.get(&top, 100).await, Err(StorageError::NotFound(_))));
}
