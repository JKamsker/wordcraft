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
//!
//! Sign-in (the server's OpenID Connect or basic sign-in): on start the page asks
//! `GET ../api/me` who is signed in. A signed-in user's name (at most [`MAX_AUTHOR_CHARS`])
//! signs this visit's comments and tracked changes, as a host page's `?author=` does, without
//! replacing the name stored as the browser's own preference. No sign-in on the server
//! (`mode: none`), an answer that isn't JSON or is over [`MAX_JSON_BYTES`], or a network error
//! leaves the author alone and is only logged. When a request answers 401 (the session is missing
//! or expired) the status bar says to open the sign-in page (`../auth/login`, given as an absolute
//! URL) in a new tab, sign in and save again: the document stays open and unsaved, so nothing is
//! lost. A 403 says the account may not use this document store. Opening `?file=` that answers
//! 401 with `{"error":"unauthenticated"}` before anything is edited sends the page to
//! `../auth/login?next=<the app's path and query>` instead, at most once a minute
//! ([`LOGIN_RETRY_MS`], kept in `sessionStorage`) so a sign-in that doesn't stick can't loop.

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

/// The server's sign-in page, relative to the page (the server's `auth/login` from `<base>/app/`).
/// Always this fixed path: a login link in a server answer is not followed.
pub(crate) const LOGIN_PATH: &str = "../auth/login";
/// The largest `/api/me` answer, or 401 body, that is parsed; anything longer is ignored.
pub(crate) const MAX_JSON_BYTES: usize = 64 << 10;
/// The longest user name taken for comments and tracked changes (as `?author=`).
pub(crate) const MAX_AUTHOR_CHARS: usize = 200;
/// The longest `next=` (the app's own path and query) sent to the sign-in page.
const MAX_NEXT_BYTES: usize = 2048;
/// A second automatic sign-in within this many milliseconds is not made, so a sign-in that does
/// not stick can't loop.
pub(crate) const LOGIN_RETRY_MS: f64 = 60_000.0;

/// The parts of `GET ../api/me` WordCraft uses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Me {
    /// `oidc`, `basic` or `none`.
    pub(crate) mode: String,
    pub(crate) authenticated: bool,
    /// The signed-in user's display name, as the server sent it.
    pub(crate) name: Option<String>,
}

/// `/api/me`'s JSON, read as hostile input: too long, not JSON or not an object is an error; a
/// missing or mistyped field is left empty.
pub(crate) fn parse_me(body: &str) -> Result<Me, String> {
    if body.len() > MAX_JSON_BYTES {
        return Err(format!("the answer is over {} KiB", MAX_JSON_BYTES >> 10));
    }
    let value: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
    let object = value.as_object().ok_or("not a JSON object")?;
    let mode = object.get("mode").and_then(serde_json::Value::as_str).unwrap_or("").chars().take(16).collect();
    let authenticated = object.get("authenticated").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let name = object.get("user").and_then(|u| u.get("name")).and_then(serde_json::Value::as_str).map(str::to_string);
    Ok(Me { mode, authenticated, name })
}

/// The name that signs this visit's comments and tracked changes: the signed-in user's, without
/// control characters, trimmed and at most [`MAX_AUTHOR_CHARS`]. `None` when nobody is signed
/// in, the server has no sign-in (`mode: none`) or the name is blank.
pub(crate) fn signed_in_author(me: &Me) -> Option<String> {
    if !me.authenticated || me.mode == "none" {
        return None;
    }
    let clean: String = me.name.as_deref()?.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let name: String = clean.trim().chars().take(MAX_AUTHOR_CHARS).collect();
    let name = name.trim_end();
    (!name.is_empty()).then(|| name.to_string())
}

/// Whether a refusal is the server's "sign in first" answer: 401 with
/// `{"error":"unauthenticated"}`.
pub(crate) fn wants_sign_in(status: u16, body: &str) -> bool {
    status == 401
        && body.len() <= MAX_JSON_BYTES
        && serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .is_some_and(|v| v.get("error").and_then(serde_json::Value::as_str) == Some("unauthenticated"))
}

/// The sign-in page's absolute URL: [`LOGIN_PATH`] resolved against the page's URL
/// (`https://host/base/app/?file=x` gives `https://host/base/auth/login`). `None` for a page URL
/// without `scheme://`.
pub(crate) fn login_url(page_href: &str) -> Option<String> {
    let page = page_href.split(['?', '#']).next().unwrap_or("");
    let scheme_end = page.find("://")?.checked_add(3)?;
    let after_scheme = page.get(scheme_end..)?;
    let path_start = scheme_end.checked_add(after_scheme.find('/').unwrap_or(after_scheme.len()))?;
    let origin = page.get(..path_start)?;
    let path = page.get(path_start..)?;
    // The page's folder, then `..`: one folder up, never above the root.
    let folder = path.rfind('/').and_then(|i| path.get(..i)).unwrap_or("");
    let parent = folder.rfind('/').and_then(|i| folder.get(..i)).unwrap_or("");
    let rest = LOGIN_PATH.trim_start_matches("../");
    Some(format!("{origin}{parent}/{rest}"))
}

/// Where the page goes to sign in before anything is loaded: [`LOGIN_PATH`] with `next=` the app's
/// own path and query, so the server can bring the user back. Only a plain absolute path is sent
/// (never a URL with a host); anything else, or one too long, goes without `next`.
pub(crate) fn login_redirect(pathname: &str, search: &str) -> String {
    let next = format!("{pathname}{search}");
    let plain = pathname.starts_with('/') && !pathname.starts_with("//") && !next.chars().any(|c| c == '\\' || c.is_control());
    if plain && next.len() <= MAX_NEXT_BYTES { format!("{LOGIN_PATH}?next={}", encode_segment(&next)) } else { LOGIN_PATH.to_string() }
}

/// Whether to send the page to sign in now, given when it last did (`sessionStorage`, in ms).
pub(crate) fn may_redirect(last_ms: Option<f64>, now_ms: f64) -> bool {
    last_ms.is_none_or(|last| !(now_ms - last).is_finite() || now_ms - last >= LOGIN_RETRY_MS || now_ms < last)
}

/// What a request was for, which says what to do after signing in again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Opening `?file=`.
    Open,
    /// A Save, Save As or export.
    Save,
    /// Asking who is signed in (`/api/me`).
    Check,
}

/// A request that didn't succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No answer, or one that isn't usable, in words.
    Other(String),
    /// The server answered with this status and text.
    Refused { status: u16, body: String },
}

/// A failed request in words. A 401 says how to sign in again (in a new tab, so the document
/// stays open and unsaved), a 403 that this account may not use the store, anything else what
/// the server said. `page_href` is the page's URL, to give the sign-in page's absolute URL.
pub(crate) fn failure_message(action: Action, failure: &Failure, page_href: Option<&str>) -> String {
    let (status, body) = match failure {
        Failure::Other(e) => return e.clone(),
        Failure::Refused { status, body } => (*status, body.as_str()),
    };
    let then = match action {
        Action::Open => "then reload this page",
        Action::Save => "then save again",
        Action::Check => "then save as usual",
    };
    match status {
        401 if wants_sign_in(status, body) => {
            let login = page_href.and_then(login_url).unwrap_or_else(|| "the server's sign-in page (auth/login)".into());
            let opening = if action == Action::Check { "you are not signed in" } else { "your sign-in has expired" };
            format!("{opening} — open {login} in a new tab, sign in, {then}")
        }
        401 => format!("the server wants you to sign in again (HTTP 401) — open this page in a new tab, sign in, {then}"),
        403 => "this account may not use this document store (HTTP 403)".into(),
        _ => describe_failure(status, body),
    }
}

/// `text` cut to at most `max` bytes, at a character boundary.
pub(crate) fn truncate_bytes(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::Server;

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use wasm_bindgen::JsCast as _;
    use wordcraft_ui_egui::async_saves::{AsyncSaves, SaveOutcome};
    use wordcraft_ui_egui::{Inbox, Services, WordApp};

    use super::{
        Action, Activation, Failure, MAX_JSON_BYTES, MAX_OPEN_BYTES, Me, activation, api_url, failure_message, join, login_redirect, may_redirect,
        parse_me, signed_in_author, split, truncate_bytes, wants_sign_in,
    };

    type Messages = Rc<RefCell<Vec<String>>>;

    /// Who is signed in, relative to the page.
    const ME_URL: &str = "../api/me";
    /// The `sessionStorage` key holding when the page last went to sign in on its own.
    const REDIRECT_KEY: &str = "wordcraft.server.login-redirect";

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

        /// Ask the server who is signed in (`../api/me`). A signed-in user's name lands in
        /// `author` for the page to sign this visit's comments and tracked changes with; "not
        /// signed in" is a status message; anything else (no sign-in on the server, an older
        /// server, a network error) is only logged.
        pub(crate) fn check_sign_in(&self, author: Rc<RefCell<Option<String>>>, messages: Messages, ctx: egui::Context) {
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_me().await {
                    Ok(me) => match signed_in_author(&me) {
                        Some(name) => {
                            log::info!("server: signed in ({})", me.mode);
                            *author.borrow_mut() = Some(name);
                        }
                        None => log::info!("server: no signed-in name (mode {:?}, signed in: {})", me.mode, me.authenticated),
                    },
                    Err(failure @ Failure::Refused { status: 401, .. }) => {
                        let message = failure_message(Action::Check, &failure, page_href().as_deref());
                        log::warn!("server: {message}");
                        messages.borrow_mut().push(capitalize(&message));
                    }
                    Err(e) => log::info!("server: who is signed in is unknown: {e:?}"),
                }
                ctx.request_repaint();
            });
        }

        /// `?file=`: fetch the document and open it like a dropped file, under its own name. When
        /// the server wants a sign-in first and the page has no unsaved changes (`dirty`), the page
        /// goes to the sign-in page, which brings it back here.
        pub(crate) fn open(&self, inbox: Inbox, ctx: egui::Context, messages: Messages, dirty: Rc<Cell<bool>>) {
            let Activation::Open(path) = &self.activation else { return };
            let path = path.clone();
            messages.borrow_mut().push(format!("Opening {path} from the server…"));
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_document(&path).await {
                    Ok(bytes) => {
                        let name = split(&path).1.to_string();
                        inbox.lock().unwrap_or_else(|e| e.into_inner()).push((name, bytes));
                    }
                    Err(failure) => {
                        let signing_in =
                            matches!(&failure, Failure::Refused { status, body } if wants_sign_in(*status, body)) && !dirty.get() && go_to_sign_in();
                        let e = failure_message(Action::Open, &failure, page_href().as_deref());
                        log::error!("couldn't open {path} from the server: {e}");
                        messages.borrow_mut().push(if signing_in {
                            "Signing in to the server…".to_string()
                        } else {
                            format!("Couldn't open {path} from the server: {e}")
                        });
                    }
                }
                ctx.request_repaint();
            });
        }
    }

    /// The page's URL.
    fn page_href() -> Option<String> {
        web_sys::window()?.location().href().ok()
    }

    /// `text` with its first letter capitalised, to stand as a sentence.
    fn capitalize(text: &str) -> String {
        let mut chars = text.chars();
        chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default()
    }

    /// Send the page to the sign-in page, unless it did so within the last minute (a sign-in that
    /// doesn't stick must not loop). Whether it went.
    fn go_to_sign_in() -> bool {
        let Some(window) = web_sys::window() else { return false };
        let storage = window.session_storage().ok().flatten();
        let now = js_sys::Date::now();
        let last = storage.as_ref().and_then(|s| s.get_item(REDIRECT_KEY).ok().flatten()).and_then(|v| v.parse::<f64>().ok());
        if !may_redirect(last, now) {
            log::warn!("server: sign-in was just tried; not going to the sign-in page again");
            return false;
        }
        // Without storage there is no loop guard, so no automatic sign-in either.
        let Some(storage) = storage else { return false };
        if storage.set_item(REDIRECT_KEY, &now.to_string()).is_err() {
            return false;
        }
        let location = window.location();
        let target = login_redirect(&location.pathname().unwrap_or_default(), &location.search().unwrap_or_default());
        match location.set_href(&target) {
            Ok(()) => true,
            Err(e) => {
                log::error!("server: couldn't go to the sign-in page: {e:?}");
                false
            }
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
                // A refused save (an expired sign-in included) leaves the document unsaved.
                let outcome = match response(request).await {
                    Ok(_) => SaveOutcome::Saved,
                    Err(failure) => SaveOutcome::Failed(failure_message(Action::Save, &failure, page_href().as_deref())),
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

    /// The response a request's promise ends with, if the server accepted it (2xx). A refusal
    /// keeps at most [`MAX_JSON_BYTES`] of the server's text.
    async fn response(promise: js_sys::Promise) -> Result<web_sys::Response, Failure> {
        let value =
            wasm_bindgen_futures::JsFuture::from(promise).await.map_err(|e| Failure::Other(format!("the server couldn't be reached: {e:?}")))?;
        let response: web_sys::Response = value.dyn_into().map_err(|_| Failure::Other("not a response".to_string()))?;
        if response.ok() {
            return Ok(response);
        }
        let status = response.status();
        let body = match response.text() {
            Ok(p) => wasm_bindgen_futures::JsFuture::from(p).await.ok().and_then(|v| v.as_string()).unwrap_or_default(),
            Err(_) => String::new(),
        };
        Err(Failure::Refused { status, body: truncate_bytes(body, MAX_JSON_BYTES) })
    }

    /// The length the server declares for a response, if it does.
    fn declared_length(response: &web_sys::Response) -> Option<u64> {
        response.headers().get("content-length").ok().flatten().and_then(|v| v.trim().parse::<u64>().ok())
    }

    /// `GET ../api/me`, never from the cache. The request is same-origin, so the session cookie
    /// goes with it (fetch's default credentials).
    async fn fetch_me() -> Result<Me, Failure> {
        let other = |e: wasm_bindgen::JsValue| Failure::Other(format!("{e:?}"));
        let window = web_sys::window().ok_or_else(|| Failure::Other("no window".into()))?;
        let init = web_sys::RequestInit::new();
        init.set_method("GET");
        init.set_cache(web_sys::RequestCache::NoStore);
        let response = response(window.fetch_with_str_and_init(ME_URL, &init)).await?;
        let too_big = || Failure::Other(format!("the answer is over {} KiB", MAX_JSON_BYTES >> 10));
        if declared_length(&response).is_some_and(|n| n > MAX_JSON_BYTES as u64) {
            return Err(too_big());
        }
        let text = wasm_bindgen_futures::JsFuture::from(response.text().map_err(other)?).await.map_err(other)?;
        let text = text.as_string().ok_or_else(|| Failure::Other("not text".into()))?;
        parse_me(&text).map_err(Failure::Other)
    }

    /// The stored document's bytes, refusing one over [`MAX_OPEN_BYTES`] before it is read when
    /// the server says its length, and after otherwise.
    async fn fetch_document(path: &str) -> Result<Vec<u8>, Failure> {
        let js = |e: wasm_bindgen::JsValue| Failure::Other(format!("{e:?}"));
        let window = web_sys::window().ok_or_else(|| Failure::Other("no window".into()))?;
        let init = web_sys::RequestInit::new();
        init.set_method("GET");
        // Always the stored file as it is now, never a cached copy from before a save.
        init.set_cache(web_sys::RequestCache::NoStore);
        let response = response(window.fetch_with_str_and_init(&api_url(path), &init)).await?;
        let too_big = || Failure::Other(format!("the document is over the {} MiB limit", MAX_OPEN_BYTES >> 20));
        if declared_length(&response).is_some_and(|n| n > MAX_OPEN_BYTES) {
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
    fn me_is_parsed_as_hostile_json() {
        let me = parse_me(
            r#"{"mode":"oidc","authenticated":true,"user":{"id":"u1","name":"Grace Hopper","email":null,"groups":["staff"]},"logout":"auth/logout"}"#,
        )
        .unwrap();
        assert_eq!(me, Me { mode: "oidc".into(), authenticated: true, name: Some("Grace Hopper".into()) });
        let anonymous = parse_me(r#"{"mode":"none","authenticated":false,"user":null,"logout":null}"#).unwrap();
        assert_eq!(anonymous, Me { mode: "none".into(), authenticated: false, name: None });
        // Mistyped fields are left empty, not trusted.
        let odd = parse_me(r#"{"mode":7,"authenticated":"yes","user":{"name":["x"]}}"#).unwrap();
        assert_eq!(odd, Me::default());
        for bad in ["", "<html>sign in</html>", "[1,2]", "null", "\"{\"", "{\"mode\":"] {
            assert!(parse_me(bad).is_err(), "{bad:?} should be refused");
        }
        // Oversized and deeply nested answers are refused without trouble.
        let huge = format!(r#"{{"mode":"oidc","authenticated":true,"user":{{"name":"{}"}}}}"#, "a".repeat(MAX_JSON_BYTES));
        assert!(parse_me(&huge).is_err());
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(parse_me(&deep).is_err());
        assert!(!wants_sign_in(401, &deep));
        let _ = parse_me("{\"user\":{\"name\":\"\u{10FFFF}\\ud800\"}}");
    }

    #[test]
    fn the_signed_in_name_signs_the_work() {
        let me = |mode: &str, authenticated: bool, name: Option<&str>| Me { mode: mode.into(), authenticated, name: name.map(str::to_string) };
        assert_eq!(signed_in_author(&me("oidc", true, Some("  Grace Hopper "))), Some("Grace Hopper".into()));
        assert_eq!(signed_in_author(&me("basic", true, Some("rob"))), Some("rob".into()));
        assert_eq!(signed_in_author(&me("oidc", false, Some("Grace"))), None);
        assert_eq!(signed_in_author(&me("none", true, Some("Grace"))), None);
        assert_eq!(signed_in_author(&me("oidc", true, None)), None);
        assert_eq!(signed_in_author(&me("oidc", true, Some(" \t\n "))), None);
        assert_eq!(signed_in_author(&me("oidc", true, Some("Grace\nHopper\u{0}"))), Some("Grace Hopper".into()));
        let long = signed_in_author(&me("oidc", true, Some(&"é".repeat(1000)))).unwrap();
        assert_eq!(long.chars().count(), MAX_AUTHOR_CHARS);
    }

    #[test]
    fn the_sign_in_page_is_next_to_the_app() {
        assert_eq!(login_url("https://docs.example.org/app/?file=a.docx#x").as_deref(), Some("https://docs.example.org/auth/login"));
        assert_eq!(login_url("https://example.org:8443/craft/app/?new=").as_deref(), Some("https://example.org:8443/craft/auth/login"));
        assert_eq!(login_url("https://example.org/craft/app/index.html").as_deref(), Some("https://example.org/craft/auth/login"));
        // `..` never climbs above the root.
        assert_eq!(login_url("http://localhost:8080/").as_deref(), Some("http://localhost:8080/auth/login"));
        assert_eq!(login_url("http://localhost:8080").as_deref(), Some("http://localhost:8080/auth/login"));
        assert_eq!(login_url("about:blank"), None);
        assert_eq!(login_url(""), None);
        for raw in ["://", "a://?/", "é://é/é/é", "x://h/?a/b/c", "\u{10FFFF}://"] {
            let _ = login_url(raw);
        }
    }

    #[test]
    fn the_sign_in_redirect_comes_back_to_the_document() {
        assert_eq!(login_redirect("/app/", "?file=reports/q3.docx"), "../auth/login?next=%2Fapp%2F%3Ffile%3Dreports%2Fq3.docx");
        assert_eq!(login_redirect("/craft/app/", ""), "../auth/login?next=%2Fcraft%2Fapp%2F");
        // Never a URL with a host, never something odd or too long.
        assert_eq!(login_redirect("//evil.example/app/", "?file=a"), LOGIN_PATH);
        assert_eq!(login_redirect("https://evil.example/", ""), LOGIN_PATH);
        assert_eq!(login_redirect("", "?file=a"), LOGIN_PATH);
        assert_eq!(login_redirect("/app/", "?file=a\\b"), LOGIN_PATH);
        assert_eq!(login_redirect("/app/", &format!("?file={}", "a".repeat(MAX_NEXT_BYTES))), LOGIN_PATH);
        // One automatic sign-in a minute.
        assert!(may_redirect(None, 1_000.0));
        assert!(!may_redirect(Some(1_000.0), 1_000.0 + LOGIN_RETRY_MS - 1.0));
        assert!(may_redirect(Some(1_000.0), 1_000.0 + LOGIN_RETRY_MS));
        assert!(may_redirect(Some(5_000.0), 1_000.0), "a clock that went back doesn't block it for good");
        assert!(may_redirect(Some(f64::NAN), 1_000.0));
    }

    #[test]
    fn refusals_say_how_to_sign_in_again() {
        let page = Some("https://docs.example.org/app/?file=a.docx");
        let expired = Failure::Refused { status: 401, body: r#"{"error":"unauthenticated","login":"auth/login"}"#.into() };
        assert_eq!(
            failure_message(Action::Save, &expired, page),
            "your sign-in has expired — open https://docs.example.org/auth/login in a new tab, sign in, then save again"
        );
        assert_eq!(
            failure_message(Action::Open, &expired, page),
            "your sign-in has expired — open https://docs.example.org/auth/login in a new tab, sign in, then reload this page"
        );
        assert!(failure_message(Action::Check, &expired, page).starts_with("you are not signed in — open https://docs.example.org/auth/login"));
        // The server's own login link is never used.
        let elsewhere = Failure::Refused { status: 401, body: r#"{"error":"unauthenticated","login":"https://evil.example/"}"#.into() };
        assert!(!failure_message(Action::Save, &elsewhere, page).contains("evil"));
        assert!(failure_message(Action::Save, &expired, None).contains("the server's sign-in page (auth/login)"));
        // A 401 that isn't the server's sign-in answer (basic sign-in) still says to sign in.
        let basic = Failure::Refused { status: 401, body: "Unauthorized".into() };
        assert!(!wants_sign_in(401, "Unauthorized"));
        assert!(failure_message(Action::Save, &basic, page).contains("sign in, then save again"));
        assert!(!wants_sign_in(403, r#"{"error":"unauthenticated"}"#));
        let forbidden = Failure::Refused { status: 403, body: "forbidden".into() };
        assert_eq!(failure_message(Action::Save, &forbidden, page), "this account may not use this document store (HTTP 403)");
        let missing = Failure::Refused { status: 404, body: "no such document".into() };
        assert_eq!(failure_message(Action::Open, &missing, page), "the server answered HTTP 404: no such document");
        assert_eq!(failure_message(Action::Save, &Failure::Other("offline".into()), page), "offline");
    }

    #[test]
    fn refusal_bodies_are_cut_at_a_character() {
        assert_eq!(truncate_bytes("abc".into(), 10), "abc");
        assert_eq!(truncate_bytes("ééé".into(), 3), "é");
        assert_eq!(truncate_bytes("ééé".into(), 0), "");
        assert_eq!(truncate_bytes("x".repeat(MAX_JSON_BYTES + 5), MAX_JSON_BYTES).len(), MAX_JSON_BYTES);
    }

    #[test]
    fn failures_say_what_the_server_said() {
        assert_eq!(describe_failure(404, ""), "the server answered HTTP 404");
        assert_eq!(describe_failure(413, "\n  document too large \nmore"), "the server answered HTTP 413: document too large");
        let long = "x".repeat(10_000);
        assert_eq!(describe_failure(502, &long).len(), "the server answered HTTP 502: ".len() + MAX_ERROR_CHARS);
    }
}
