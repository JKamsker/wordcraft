//! Server storage: documents opened from and saved to the WordCraft server (`wordcraft-server`).
//!
//! The server serves this app at `<base>/app/` and the documents at `<base>/api/files/<path>`, so
//! every request goes to `../api/files/<path>` relative to the page, each path segment
//! percent-encoded:
//!
//! - `GET` answers the document's bytes (404 when there is none).
//! - `PUT` with the raw bytes as the body stores it and answers 204.
//! - A failure answers 400, 404, 413 or 502 with a text body saying why.
//!
//! The mode is on when the URL has `?file=<path>` (open that stored document) or `?new=<path>`
//! (start a blank document whose first Save stores `<path>`; a blank `?new` is
//! `Document.docx`, and a name without an extension gets `.docx`), and no host bridge
//! (`?host=parent`, `data-host`) is active: a host page keeps the files then. `?file=` wins over
//! `?new=`. A path is untrusted input: one the server would refuse (`..`, a backslash, an empty
//! segment, too long or too deep) turns the mode off with a message.
//!
//! The document opens as a dropped file under its own name. Save writes it back under that name,
//! and Save As and the exports write into the same folder: `?file=reports/q3.docx`, then Save As
//! `q4.docx`, stores `reports/q4.docx`. A save is a PUT that finishes later
//! ([`AsyncSaves`](wordcraft_ui_egui::async_saves::AsyncSaves)): the document shows saved at once,
//! goes back to unsaved if the server refuses it, and the leave-page guard warns while one is in
//! flight. The status bar says how each save went.

/// The largest document taken from the server, refused before it is copied.
pub(crate) const MAX_OPEN_BYTES: u64 = 512 << 20;
/// The path a blank `?new` saves to.
pub(crate) const DEFAULT_NEW: &str = "Document.docx";
/// The documents API, relative to the page at `<base>/app/`.
const API_BASE: &str = "../api/files/";
/// The longest path accepted, in bytes (as the server's).
const MAX_PATH_BYTES: usize = 1024;
/// The deepest folder nesting accepted (as the server's).
const MAX_DEPTH: usize = 16;
/// The longest path segment, in bytes (as the server's).
const MAX_SEGMENT_BYTES: usize = 255;
/// The most characters of a server's error text shown to the user.
const MAX_ERROR_CHARS: usize = 200;

/// What the URL asks of the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Activation {
    /// `?file=`: open this stored document.
    Open(String),
    /// `?new=`: a blank document whose first Save stores this path.
    New(String),
}

impl Activation {
    /// The validated document path.
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Open(p) | Self::New(p) => p,
        }
    }
}

/// The mode the `?file=` and `?new=` values ask for: `None` when neither is present, an error
/// when the path is one the server would refuse.
pub(crate) fn activation(file: Option<&str>, new: Option<&str>) -> Option<Result<Activation, String>> {
    if let Some(file) = file {
        return Some(validate_path(file).map(Activation::Open));
    }
    let new = new?.trim();
    let raw = if new.is_empty() { DEFAULT_NEW } else { new };
    Some(validate_path(raw).and_then(|path| {
        let (_, name) = split(&path);
        // A name without an extension saves as a Word document.
        if name.trim_start_matches('.').contains('.') { Ok(path) } else { validate_path(&format!("{path}.docx")) }
    }))
    .map(|r| r.map(Activation::New))
}

/// `raw` as a document path the server takes: relative, `/`-separated, no empty, `.` or `..`
/// segment, no backslash, control or reserved character, no segment starting or ending with
/// whitespace, within the server's length and depth limits. Leading and trailing `/` are dropped.
pub(crate) fn validate_path(raw: &str) -> Result<String, String> {
    let shown: String = raw.chars().take(80).collect();
    let bad = |why: &str| format!("{why}: {shown:?}");
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        return Err(bad("empty path"));
    }
    if trimmed.len() > MAX_PATH_BYTES {
        return Err(bad("path too long"));
    }
    for (depth, seg) in trimmed.split('/').enumerate() {
        if depth >= MAX_DEPTH {
            return Err(bad("path too deep"));
        }
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(bad("empty, '.' or '..' segment"));
        }
        if seg.len() > MAX_SEGMENT_BYTES {
            return Err(bad("segment too long"));
        }
        if seg != seg.trim() {
            return Err(bad("segment starts or ends with whitespace"));
        }
        if seg.chars().any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
            return Err(bad("forbidden character"));
        }
    }
    Ok(trimmed.to_string())
}

/// A validated path's folder (`""` at the root) and file name.
pub(crate) fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// Where a save named `name` goes: its file name (the app may pass a path) in `folder`, validated.
pub(crate) fn join(folder: &str, name: &str) -> Result<String, String> {
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if name.is_empty() {
        return Err("empty file name".into());
    }
    if folder.is_empty() { validate_path(name) } else { validate_path(&format!("{folder}/{name}")) }
}

/// `segment` percent-encoded for a URL path: everything but the unreserved characters
/// (`A–Z a–z 0–9 - . _ ~`) as `%XX` of its UTF-8 bytes.
pub(crate) fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The API URL of a validated document path, relative to the page.
pub(crate) fn api_url(path: &str) -> String {
    let segments: Vec<String> = path.split('/').map(encode_segment).collect();
    format!("{API_BASE}{}", segments.join("/"))
}

/// A refused request in words: the HTTP status and the first line of the server's text, cut short.
pub(crate) fn describe_failure(status: u16, body: &str) -> String {
    let line: String = body.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").chars().take(MAX_ERROR_CHARS).collect();
    if line.is_empty() { format!("the server answered HTTP {status}") } else { format!("the server answered HTTP {status}: {line}") }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::Server;

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;
    use std::rc::Rc;

    use wasm_bindgen::JsCast as _;
    use wordcraft_ui_egui::async_saves::{AsyncSaves, SaveOutcome};
    use wordcraft_ui_egui::{Inbox, Services, WordApp};

    use super::{Activation, MAX_OPEN_BYTES, activation, api_url, describe_failure, join, split};

    type Messages = Rc<RefCell<Vec<String>>>;

    /// Server storage for this page ([`super`]).
    pub(crate) struct Server {
        activation: Activation,
    }

    impl Server {
        /// The mode the URL asks for: `None` without `?file=` or `?new=`, an error for a path
        /// the server would refuse. The caller checks that no host bridge is active.
        pub(crate) fn detect(param: impl Fn(&str) -> Option<String>) -> Option<Result<Self, String>> {
            let file = param("file");
            let new = param("new");
            activation(file.as_deref(), new.as_deref()).map(|r| r.map(|activation| Self { activation }))
        }

        /// Save, Save As and the exports PUT to the document's folder on the server instead of
        /// downloading. Each is an asynchronous save (`saves`): the app takes the document back to
        /// unsaved if the server refuses it.
        pub(crate) fn connect(&self, services: &mut Services, saves: AsyncSaves, messages: Messages, ctx: egui::Context) {
            let putter = Rc::new(Putter { folder: split(self.activation.path()).0.to_string(), saves: saves.clone(), messages, ctx });
            let save = putter.clone();
            services.host_save = Some(Box::new(move |name: &str, bytes: &[u8], _save_as: bool| save.put(name, bytes)));
            services.download = Some(Box::new(move |name: &str, bytes: &[u8]| putter.put(name, bytes)));
            services.async_saves = Some(saves);
        }

        /// `?new=`: the blank document takes the path's file name, so its first Save stores the
        /// path. Called once the app's first document is in place.
        pub(crate) fn prepare(&self, app: &mut WordApp) {
            if let Activation::New(path) = &self.activation {
                app.session.path = Some(std::path::PathBuf::from(split(path).1));
            }
        }

        /// `?file=`: fetch the document and open it like a dropped file, under its own name.
        pub(crate) fn open(&self, inbox: Inbox, ctx: egui::Context, messages: Messages) {
            let Activation::Open(path) = &self.activation else { return };
            let path = path.clone();
            messages.borrow_mut().push(format!("Opening {path} from the server…"));
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_document(&path).await {
                    Ok(bytes) => {
                        let name = split(&path).1.to_string();
                        inbox.lock().unwrap_or_else(|e| e.into_inner()).push((name, bytes));
                    }
                    Err(e) => {
                        log::error!("couldn't open {path} from the server: {e}");
                        messages.borrow_mut().push(format!("Couldn't open {path} from the server: {e}"));
                    }
                }
                ctx.request_repaint();
            });
        }
    }

    /// Writes saves to the server.
    struct Putter {
        /// The opened document's folder: every save goes there.
        folder: String,
        saves: AsyncSaves,
        messages: Messages,
        ctx: egui::Context,
    }

    impl Putter {
        /// Start a PUT of `bytes` as `name` in the folder. An error means nothing was sent; once
        /// sent, the save's ticket says how it went.
        fn put(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
            let js = |e: wasm_bindgen::JsValue| format!("{e:?}");
            let path = join(&self.folder, name)?;
            let window = web_sys::window().ok_or("no window")?;
            let headers = web_sys::Headers::new().map_err(js)?;
            headers.set("Content-Type", crate::web::mime_for(&path)).map_err(js)?;
            let init = web_sys::RequestInit::new();
            init.set_method("PUT");
            init.set_headers(&headers);
            init.set_body(&js_sys::Uint8Array::from(bytes));
            let request = window.fetch_with_str_and_init(&api_url(&path), &init);
            let ticket = self.saves.start();
            let saves = self.saves.clone();
            let messages = self.messages.clone();
            let ctx = self.ctx.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let outcome = match response(request).await {
                    Ok(_) => SaveOutcome::Saved,
                    Err(e) => SaveOutcome::Failed(e),
                };
                // The page's message comes after the app's own report of a failed save.
                messages.borrow_mut().push(match &outcome {
                    SaveOutcome::Saved => format!("Saved to server: {path}"),
                    SaveOutcome::Failed(e) => format!("Save failed: {path}: {e}"),
                    SaveOutcome::Cancelled => format!("Save cancelled: {path}"),
                });
                match &outcome {
                    SaveOutcome::Saved => log::info!("saved {path} to the server"),
                    _ => log::error!("saving {path} to the server failed: {outcome:?}"),
                }
                saves.finish(ticket, outcome);
                ctx.request_repaint();
            });
            Ok(())
        }
    }

    /// The response a request's promise ends with, if the server accepted it (2xx).
    async fn response(promise: js_sys::Promise) -> Result<web_sys::Response, String> {
        let value = wasm_bindgen_futures::JsFuture::from(promise).await.map_err(|e| format!("the server couldn't be reached: {e:?}"))?;
        let response: web_sys::Response = value.dyn_into().map_err(|_| "not a response".to_string())?;
        if response.ok() {
            return Ok(response);
        }
        let status = response.status();
        let body = match response.text() {
            Ok(p) => wasm_bindgen_futures::JsFuture::from(p).await.ok().and_then(|v| v.as_string()).unwrap_or_default(),
            Err(_) => String::new(),
        };
        Err(describe_failure(status, &body))
    }

    /// The stored document's bytes, refusing one over [`MAX_OPEN_BYTES`] before it is read when
    /// the server says its length, and after otherwise.
    async fn fetch_document(path: &str) -> Result<Vec<u8>, String> {
        let js = |e: wasm_bindgen::JsValue| format!("{e:?}");
        let window = web_sys::window().ok_or("no window")?;
        let init = web_sys::RequestInit::new();
        init.set_method("GET");
        // Always the stored file as it is now, never a cached copy from before a save.
        init.set_cache(web_sys::RequestCache::NoStore);
        let response = response(window.fetch_with_str_and_init(&api_url(path), &init)).await?;
        let too_big = || format!("the document is over the {} MiB limit", MAX_OPEN_BYTES >> 20);
        let declared = response.headers().get("content-length").ok().flatten().and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > MAX_OPEN_BYTES) {
            return Err(too_big());
        }
        let buffer = wasm_bindgen_futures::JsFuture::from(response.array_buffer().map_err(js)?).await.map_err(js)?;
        let array = js_sys::Uint8Array::new(&buffer);
        if u64::from(array.length()) > MAX_OPEN_BYTES {
            return Err(too_big());
        }
        Ok(array.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_needs_file_or_new() {
        assert_eq!(activation(None, None), None);
        assert_eq!(activation(Some("reports/q3.docx"), None), Some(Ok(Activation::Open("reports/q3.docx".into()))));
        // `?file=` wins over `?new=`.
        assert_eq!(activation(Some("a.docx"), Some("b.docx")), Some(Ok(Activation::Open("a.docx".into()))));
        assert_eq!(activation(None, Some("")), Some(Ok(Activation::New(DEFAULT_NEW.into()))));
        assert_eq!(activation(None, Some("  ")), Some(Ok(Activation::New(DEFAULT_NEW.into()))));
        assert_eq!(activation(None, Some("notes/todo.odt")), Some(Ok(Activation::New("notes/todo.odt".into()))));
        assert_eq!(activation(None, Some("notes/todo")), Some(Ok(Activation::New("notes/todo.docx".into()))));
        assert_eq!(activation(None, Some(".hidden")), Some(Ok(Activation::New(".hidden.docx".into()))));
        assert!(matches!(activation(Some(""), None), Some(Err(_))));
        assert!(matches!(activation(Some("../etc/passwd"), None), Some(Err(_))));
        assert!(matches!(activation(None, Some("a/../b")), Some(Err(_))));
    }

    #[test]
    fn paths_the_server_refuses_are_refused() {
        let deep = vec!["d"; MAX_DEPTH + 1].join("/");
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        let long_segment = "s".repeat(MAX_SEGMENT_BYTES + 1);
        for raw in [
            "",
            "/",
            "..",
            "a/../b",
            "./a",
            "a//b",
            "a\\b",
            "c:x",
            "a\0b",
            "a\nb",
            " a",
            "a ",
            "a?b",
            "a|b",
            "a*b",
            "a\"b",
            "a<b",
            deep.as_str(),
            long.as_str(),
            long_segment.as_str(),
        ] {
            assert!(validate_path(raw).is_err(), "{raw:?} should be refused");
        }
        let deepest = vec!["d"; MAX_DEPTH].join("/");
        assert_eq!(validate_path(&deepest), Ok(deepest.clone()));
        assert_eq!(validate_path("/reports/q3.docx/"), Ok("reports/q3.docx".into()));
        assert_eq!(validate_path("Ünïcode földer/rapport été.docx"), Ok("Ünïcode földer/rapport été.docx".into()));
    }

    #[test]
    fn a_hostile_path_never_panics() {
        for raw in ["\u{10FFFF}", "é".repeat(600).as_str(), "/".repeat(5000).as_str(), "\u{0}/\u{0}", "%2e%2e/x"] {
            let _ = validate_path(raw);
            let _ = activation(Some(raw), None);
            let _ = activation(None, Some(raw));
            let _ = join(raw, raw);
            let _ = encode_segment(raw);
        }
    }

    #[test]
    fn saves_go_into_the_opened_folder() {
        assert_eq!(split("reports/2026/q3.docx"), ("reports/2026", "q3.docx"));
        assert_eq!(split("q3.docx"), ("", "q3.docx"));
        // Save writes the opened file back; Save As a new name stays in the folder.
        assert_eq!(join("reports/2026", "q3.docx"), Ok("reports/2026/q3.docx".into()));
        assert_eq!(join("reports/2026", "q4.pdf"), Ok("reports/2026/q4.pdf".into()));
        assert_eq!(join("", "q3.docx"), Ok("q3.docx".into()));
        // Only the name counts: a path handed over can't leave the folder.
        assert_eq!(join("reports", "../../etc/passwd"), Ok("reports/passwd".into()));
        assert_eq!(join("reports", "C:\\Users\\me\\x.docx"), Ok("reports/x.docx".into()));
        assert!(join("reports", "..").is_err());
        assert!(join("reports", "").is_err());
        assert!(join("reports", "a/").is_err());
    }

    #[test]
    fn segments_are_percent_encoded() {
        assert_eq!(encode_segment("q3.docx"), "q3.docx");
        assert_eq!(encode_segment("my report #1 (final)%.docx"), "my%20report%20%231%20%28final%29%25.docx");
        assert_eq!(encode_segment("été"), "%C3%A9t%C3%A9");
        assert_eq!(encode_segment("a~b_c-d"), "a~b_c-d");
        assert_eq!(api_url("reports/my q3.docx"), "../api/files/reports/my%20q3.docx");
        assert_eq!(api_url("a&b=c/d+e"), "../api/files/a%26b%3Dc/d%2Be");
    }

    #[test]
    fn failures_say_what_the_server_said() {
        assert_eq!(describe_failure(404, ""), "the server answered HTTP 404");
        assert_eq!(describe_failure(413, "\n  document too large \nmore"), "the server answered HTTP 413: document too large");
        let long = "x".repeat(10_000);
        assert_eq!(describe_failure(502, &long).len(), "the server answered HTTP 502: ".len() + MAX_ERROR_CHARS);
    }
}
