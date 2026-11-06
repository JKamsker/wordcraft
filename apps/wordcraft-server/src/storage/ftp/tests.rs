use super::*;

#[test]
fn parses_urls() {
    let c = Config::parse("ftp://alice@files.example.com:2121/team/docs", Some("pw".into())).unwrap();
    assert_eq!(
        c,
        Config {
            secure: false,
            host: "files.example.com".into(),
            port: 2121,
            user: "alice".into(),
            password: "pw".into(),
            base: "team/docs/".into(),
        }
    );
    assert_eq!(c.remote("a/b.docx"), "team/docs/a/b.docx");
    assert_eq!(c.root(), "team/docs");

    let c = Config::parse("FTPS://host", None).unwrap();
    assert!(c.secure);
    assert_eq!((c.port, c.user.as_str(), c.password.as_str(), c.base.as_str()), (21, "anonymous", "anonymous@", ""));
    assert_eq!(c.remote("x.docx"), "x.docx");
    assert_eq!(c.root(), "");

    let c = Config::parse("ftp://u%40corp@[::1]:21//srv/docs/", None).unwrap();
    assert_eq!((c.host.as_str(), c.user.as_str(), c.base.as_str(), c.root().as_str()), ("::1", "u@corp", "/srv/docs/", "/srv/docs"));
    let c = Config::parse("ftp://h//", None).unwrap();
    assert_eq!((c.base.as_str(), c.root().as_str(), c.remote("a").as_str()), ("/", "/", "/a"));
}

#[test]
fn describe_hides_the_password() {
    let storage =
        FtpStorage { config: Config::parse("ftp://alice@host:2121/docs", Some("secret".into())).unwrap(), tls: None, conn: Mutex::new(None) };
    assert_eq!(storage.describe(), "ftp host:2121/docs");
    assert!(!storage.describe().contains("secret"));
}

#[test]
fn hostile_urls_are_refused_without_panicking() {
    let deep = format!("ftp://h/{}", "a/".repeat(MAX_DEPTH + 1));
    for url in [
        "ftp://",
        "ftp:///docs",
        "ftp://:21/",
        "ftp://h:0/",
        "ftp://h:99999/",
        "ftp://h:x/",
        "ftp://u:pw@h/",
        "ftp://@h/",
        "ftp://h/../etc",
        "ftp://h/a/./b",
        "ftp://h/a%0d%0aDELE%20x",
        "ftp://h/a%",
        "ftp://h/a%zz",
        "ftp://h/a%ff",
        "ftp://h/a\\b",
        "ftp://h/?x",
        "ftp://h/#x",
        "ftp://[::1/",
        "ftp://[::1]x/",
        "ftp://h\u{0}/",
        "ftp://h st/",
        "http://h/",
        "ftp:h",
        deep.as_str(),
    ] {
        assert!(Config::parse(url, None).is_err(), "{url:?} must be refused");
    }
    assert!(Config::parse("ftp://u@h/", Some("a\r\nb".into())).is_err());
    // Arbitrary bytes never panic.
    for n in 0u32..2000 {
        let s: String = (0..(n % 23)).map(|i| char::from_u32((n.wrapping_mul(31).wrapping_add(i * 7)) % 128).unwrap_or('a')).collect();
        let _ = Config::parse(&format!("ftp://{s}"), None);
        let _ = Config::parse(&format!("ftp://h/{s}"), None);
    }
}

/// Starts an in-process anonymous FTP server over a fresh temporary folder.
async fn start_server() -> (u16, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("wordcraft-ftp-test-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let root = dir.clone();
    let server = libunftp::ServerBuilder::new(Box::new(move || unftp_sbe_fs::Filesystem::new(root.clone()).unwrap()))
        // Below Linux's ephemeral range (32768–60999), so a passive port never collides with an outbound socket.
        .passive_ports(20000..=29999)
        .build()
        .unwrap();
    // The server gets its own runtime and thread, apart from the client under test.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = server.listen(format!("127.0.0.1:{port}")).await;
        });
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (port, dir)
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// libunftp (this test's in-process server, not production) now and then drops a STOR data
/// connection with a reset or broken pipe; the same client code against vsftpd stores every file.
/// Uploads retry that one failure so the test checks the backend, not libunftp's race.
async fn put_retrying(storage: &dyn Storage, path: &DocPath, bytes: Vec<u8>) {
    for _ in 0..4 {
        match storage.put(path, bytes.clone()).await {
            Err(StorageError::Backend(e)) if e.starts_with("ftp STOR: Connection error") => continue,
            other => return other.unwrap(),
        }
    }
    storage.put(path, bytes).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn round_trips_against_an_ftp_server() {
    let (port, dir) = start_server().await;
    let storage = open(&format!("ftp://127.0.0.1:{port}/")).unwrap();
    assert_eq!(storage.describe(), format!("ftp 127.0.0.1:{port}/"));

    let top = DocPath::parse("top.docx").unwrap();
    let nested = DocPath::parse("reports/2026/q3 summary.docx").unwrap();
    // Binary bytes must survive unchanged (no ASCII-mode CRLF conversion).
    let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).chain(b"\n\r\n".iter().copied()).collect();

    put_retrying(&*storage, &top, b"hello".to_vec()).await;
    put_retrying(&*storage, &nested, payload.clone()).await;
    assert!(dir.join("reports/2026/q3 summary.docx").is_file());

    assert_eq!(storage.get(&top, 100).await.unwrap(), b"hello");
    assert_eq!(storage.get(&nested, 1 << 20).await.unwrap(), payload);
    // Replacing a file.
    put_retrying(&*storage, &top, b"hello again".to_vec()).await;
    assert_eq!(storage.get(&top, 100).await.unwrap(), b"hello again");

    let mut listed: Vec<(String, u64)> = storage.list().await.unwrap().into_iter().map(|e| (e.path, e.size)).collect();
    listed.sort();
    assert_eq!(listed, vec![("reports/2026/q3 summary.docx".to_string(), payload.len() as u64), ("top.docx".to_string(), 11)]);

    assert!(matches!(storage.get(&nested, 1000).await, Err(StorageError::TooLarge(_))));
    // The connection still works after a refusal.
    assert_eq!(storage.get(&top, 100).await.unwrap(), b"hello again");

    let missing = DocPath::parse("nope/missing.docx").unwrap();
    assert!(matches!(storage.get(&missing, 100).await, Err(StorageError::NotFound(_))));
    assert!(matches!(storage.delete(&missing).await, Err(StorageError::NotFound(_))));

    storage.delete(&top).await.unwrap();
    assert!(matches!(storage.get(&top, 100).await, Err(StorageError::NotFound(_))));
    assert!(matches!(storage.delete(&top).await, Err(StorageError::NotFound(_))));
    let listed: Vec<String> = storage.list().await.unwrap().into_iter().map(|e| e.path).collect();
    assert_eq!(listed, vec!["reports/2026/q3 summary.docx".to_string()]);

    // A base folder keeps every operation under it.
    let scoped = open(&format!("ftp://127.0.0.1:{port}/reports")).unwrap();
    let listed: Vec<String> = scoped.list().await.unwrap().into_iter().map(|e| e.path).collect();
    assert_eq!(listed, vec!["2026/q3 summary.docx".to_string()]);
    put_retrying(&*scoped, &DocPath::parse("new/inner.docx").unwrap(), b"x".to_vec()).await;
    assert!(dir.join("reports/new/inner.docx").is_file());

    // A folder with nothing in it lists as empty.
    let empty = open(&format!("ftp://127.0.0.1:{port}/reports/new/none")).unwrap();
    std::fs::create_dir_all(dir.join("reports/new/none")).unwrap();
    assert!(empty.list().await.unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unreachable_server_is_an_error_not_a_hang() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let storage = open(&format!("ftp://127.0.0.1:{port}/")).unwrap();
    assert!(matches!(storage.list().await, Err(StorageError::Backend(_))));
}
