//! The HTTP surface. The wasm client relies on the `/api/files` contract; keep it stable.
//!
//! | Route | Does |
//! |---|---|
//! | `GET /` | server-rendered file browser (no JavaScript) |
//! | `POST /upload` | multipart form: `file`, optional `folder`; redirects to `./` |
//! | `POST /delete` | form field `path`; redirects to `./` |
//! | `GET /app` | redirects to `app/` |
//! | `GET /app/…` | the web build from `--web-root` |
//! | `GET /api/files` | `{"storage": "…", "files": [{"path", "size", "modified"}]}` |
//! | `GET /api/files/{path}` | the bytes (`application/octet-stream`), 404 when missing |
//! | `PUT /api/files/{path}` | stores the raw body; 204 |
//! | `DELETE /api/files/{path}` | removes the file; 204 |
//!
//! Errors: invalid path 400, missing 404, too large 413, storage failure 502 (detail logged, not
//! returned). Every response carries `X-Content-Type-Options: nosniff`. Writes from another site
//! (`Sec-Fetch-Site` other than `same-origin`/`none`) are refused with 403, so a page elsewhere
//! cannot use the browser's remembered credentials to change documents.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Form, Multipart, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use tower::ServiceExt as _;
use tower_http::services::ServeDir;

use crate::auth::BasicAuth;
use crate::html;
use crate::storage::{DocPath, SharedStorage, StorageError};

/// What every handler shares.
pub struct AppState {
    pub storage: SharedStorage,
    /// The largest document accepted (request body) or served.
    pub max_bytes: u64,
    /// The web build served at `/app/`.
    pub web_root: PathBuf,
    pub auth: Option<BasicAuth>,
}

type Shared = Arc<AppState>;

/// The browser page's policy: no scripts, no external anything, forms only to this server.
const BROWSER_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Builds the router.
pub fn router(state: AppState) -> Router {
    let limit = usize::try_from(state.max_bytes).unwrap_or(usize::MAX);
    let state = Arc::new(state);
    Router::new()
        .route("/", get(browser))
        .route("/upload", post(upload_form))
        .route("/delete", post(delete_form))
        .route("/app", get(app_redirect))
        .route("/app/", get(app_static))
        .route("/app/{*rest}", get(app_static))
        .route("/api/files", get(list_files))
        .route("/api/files/{*path}", get(get_file).put(put_file).delete(delete_file))
        .layer(DefaultBodyLimit::max(limit))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Auth, cross-site write refusal and the `nosniff` header, around every route.
async fn guard(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let mut resp = if let Some(auth) = &state.auth
        && !auth.accepts(req.headers().get(header::AUTHORIZATION).map(HeaderValue::as_bytes))
    {
        let mut r = (StatusCode::UNAUTHORIZED, "authentication required\n").into_response();
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"WordCraft\", charset=\"UTF-8\""));
        r
    } else if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) && is_cross_site(req.headers()) {
        (StatusCode::FORBIDDEN, "cross-site requests may not change documents\n").into_response()
    } else {
        next.run(req).await
    };
    resp.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

fn is_cross_site(headers: &HeaderMap) -> bool {
    headers.get("sec-fetch-site").is_some_and(|v| !matches!(v.as_bytes(), b"same-origin" | b"none"))
}

/// A storage error as an HTTP response.
struct ApiError(StorageError);

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self.0 {
            StorageError::InvalidPath(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            StorageError::NotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            StorageError::TooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, self.0.to_string()),
            StorageError::Config(_) | StorageError::Backend(_) => {
                log::error!("{}", self.0);
                (StatusCode::BAD_GATEWAY, "storage backend error".to_string())
            }
        };
        (status, [(header::CACHE_CONTROL, "no-store")], format!("{body}\n")).into_response()
    }
}

fn doc_path(raw: &str) -> Result<DocPath, ApiError> {
    Ok(DocPath::parse(raw)?)
}

async fn sorted_list(state: &AppState) -> Result<Vec<crate::storage::Entry>, StorageError> {
    let mut files = state.storage.list().await?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

async fn list_files(State(state): State<Shared>) -> Result<Response, ApiError> {
    let files = sorted_list(&state).await?;
    let body = serde_json::json!({ "storage": state.storage.describe(), "files": files });
    Ok(([(header::CACHE_CONTROL, "no-store")], axum::Json(body)).into_response())
}

/// `attachment` with an ASCII fallback name and the exact UTF-8 name (RFC 6266).
fn content_disposition(name: &str) -> HeaderValue {
    let ascii: String = name.chars().map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' }).collect();
    let value = format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{}", html::encode_component(name));
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

async fn get_file(State(state): State<Shared>, Path(raw): Path<String>) -> Result<Response, ApiError> {
    let path = doc_path(&raw)?;
    let bytes = state.storage.get(&path, state.max_bytes).await?;
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::CONTENT_DISPOSITION, content_disposition(path.file_name())),
        ],
        bytes,
    )
        .into_response())
}

async fn put_file(State(state): State<Shared>, Path(raw): Path<String>, body: Bytes) -> Result<StatusCode, ApiError> {
    let path = doc_path(&raw)?;
    state.storage.put(&path, Vec::from(body)).await?;
    log::info!("saved {}", path.as_str());
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_file(State(state): State<Shared>, Path(raw): Path<String>) -> Result<StatusCode, ApiError> {
    let path = doc_path(&raw)?;
    state.storage.delete(&path).await?;
    log::info!("deleted {path}");
    Ok(StatusCode::NO_CONTENT)
}

async fn browser(State(state): State<Shared>) -> Response {
    let (status, page) = match sorted_list(&state).await {
        Ok(files) => (StatusCode::OK, html::browser(&state.storage.describe(), Ok(&files))),
        Err(e) => {
            log::error!("listing failed: {e}");
            (StatusCode::BAD_GATEWAY, html::browser(&state.storage.describe(), Err("the storage backend reported an error")))
        }
    };
    (status, [(header::CONTENT_SECURITY_POLICY, BROWSER_CSP), (header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

#[derive(serde::Deserialize)]
struct DeleteForm {
    path: String,
}

async fn delete_form(State(state): State<Shared>, Form(form): Form<DeleteForm>) -> Result<Redirect, ApiError> {
    let path = doc_path(&form.path)?;
    state.storage.delete(&path).await?;
    log::info!("deleted {path}");
    Ok(Redirect::to("./"))
}

async fn upload_form(State(state): State<Shared>, mut multipart: Multipart) -> Result<Redirect, Response> {
    let bad = |e: axum::extract::multipart::MultipartError| (e.status(), e.body_text()).into_response();
    let mut folder = String::new();
    let mut file: Option<(String, Bytes)> = None;
    while let Some(field) = multipart.next_field().await.map_err(bad)? {
        match field.name() {
            Some("folder") => folder = field.text().await.map_err(bad)?,
            Some("file") => {
                let name = field.file_name().unwrap_or_default().to_string();
                let bytes = field.bytes().await.map_err(bad)?;
                file = Some((name, bytes));
            }
            _ => {}
        }
    }
    let Some((name, bytes)) = file else {
        return Err((StatusCode::BAD_REQUEST, "no file in the upload\n").into_response());
    };
    // Some browsers send a full client path; keep only the last part.
    let name = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let folder = folder.trim().trim_matches('/');
    let raw = if folder.is_empty() { name.to_string() } else { format!("{folder}/{name}") };
    let path = doc_path(&raw).map_err(IntoResponse::into_response)?;
    if bytes.len() as u64 > state.max_bytes {
        return Err(ApiError(StorageError::TooLarge(path.to_string())).into_response());
    }
    state.storage.put(&path, Vec::from(bytes)).await.map_err(|e| ApiError(e).into_response())?;
    log::info!("uploaded {path}");
    Ok(Redirect::to("./"))
}

/// `/app` → `app/` (relative, keeping the query), so relative URLs inside the app resolve.
async fn app_redirect(uri: Uri) -> Redirect {
    match uri.query() {
        Some(q) => Redirect::temporary(&format!("app/?{q}")),
        None => Redirect::temporary("app/"),
    }
}

async fn app_static(State(state): State<Shared>, req: Request) -> Response {
    let rest = req.uri().path().strip_prefix("/app").unwrap_or("/");
    let rest = if rest.is_empty() { "/" } else { rest };
    if rest == "/" && !tokio::fs::try_exists(state.web_root.join("index.html")).await.unwrap_or(false) {
        let page = html::app_missing(&state.web_root.display().to_string());
        return (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, "no-store")], Html(page)).into_response();
    }
    let Ok(uri) = rest.parse::<Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    let mut resp = match ServeDir::new(&state.web_root).oneshot(Request::from_parts(parts, body)).await {
        Ok(r) => r.map(Body::new),
        Err(never) => match never {},
    };
    // Revalidate on every load so a rebuilt app is picked up.
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStorage;
    use base64::Engine as _;

    const LIMIT: u64 = 1024;

    fn app_with(storage: SharedStorage, web_root: PathBuf, auth: Option<&str>) -> Router {
        router(AppState { storage, max_bytes: LIMIT, web_root, auth: auth.map(BasicAuth::new) })
    }

    fn app() -> Router {
        app_with(Arc::new(MemoryStorage::default()), PathBuf::from("/nonexistent-web-root"), None)
    }

    async fn send(app: &Router, method: &str, uri: &str, body: impl Into<Body>) -> Response {
        let req = Request::builder().method(method).uri(uri).body(body.into()).unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn text(resp: Response) -> String {
        String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
    }

    async fn api_round_trip(app: Router) {
        let r = send(&app, "PUT", "/api/files/reports/q3%20final.docx", "hello").await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let r = send(&app, "GET", "/api/files/reports/q3%20final.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(r.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment"));
        assert_eq!(text(r).await, "hello");

        let r = send(&app, "GET", "/api/files", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&text(r).await).unwrap();
        assert!(json["storage"].is_string());
        assert_eq!(json["files"][0]["path"], "reports/q3 final.docx");
        assert_eq!(json["files"][0]["size"], 5);
        assert!(json["files"][0].get("modified").is_some());

        let r = send(&app, "DELETE", "/api/files/reports/q3%20final.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let r = send(&app, "GET", "/api/files/reports/q3%20final.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = send(&app, "DELETE", "/api/files/reports/q3%20final.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = send(&app, "GET", "/api/files", Body::empty()).await;
        let json: serde_json::Value = serde_json::from_str(&text(r).await).unwrap();
        assert_eq!(json["files"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn api_round_trip_in_memory() {
        api_round_trip(app()).await;
    }

    #[tokio::test]
    async fn api_round_trip_in_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::local::open(dir.path().to_str().unwrap()).unwrap();
        api_round_trip(app_with(storage, dir.path().join("web"), None)).await;
    }

    #[tokio::test]
    async fn hostile_paths_are_bad_requests() {
        let app = app();
        for uri in ["/api/files/..%2F..%2Fetc%2Fpasswd", "/api/files/a%5Cb.docx", "/api/files/a/../b", "/api/files/%00", "/api/files/a%3Ab"] {
            let r = send(&app, "PUT", uri, "x").await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "PUT {uri}");
            let r = send(&app, "GET", uri, Body::empty()).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "GET {uri}");
        }
    }

    #[tokio::test]
    async fn bodies_over_the_limit_are_refused() {
        let app = app();
        let r = send(&app, "PUT", "/api/files/big.docx", vec![0u8; LIMIT as usize + 1]).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let r = send(&app, "PUT", "/api/files/ok.docx", vec![0u8; LIMIT as usize]).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn files_over_the_limit_are_not_served() {
        let storage: SharedStorage = Arc::new(MemoryStorage::default());
        storage.put(&DocPath::parse("big.docx").unwrap(), vec![0; LIMIT as usize + 1]).await.unwrap();
        let r = send(&app_with(storage, PathBuf::new(), None), "GET", "/api/files/big.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn auth_is_required_and_accepted() {
        let app = app_with(Arc::new(MemoryStorage::default()), PathBuf::new(), Some("ann:pw"));
        for uri in ["/", "/api/files", "/app/", "/api/files/a.docx"] {
            let r = send(&app, "GET", uri, Body::empty()).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(r.headers()[header::WWW_AUTHENTICATE], "Basic realm=\"WordCraft\", charset=\"UTF-8\"");
        }
        let good = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("ann:pw"));
        let bad = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("ann:nope"));
        let with = |value: &str| Request::builder().uri("/api/files").header(header::AUTHORIZATION, value).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(with(&bad)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(app.clone().oneshot(with(&good)).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cross_site_writes_are_refused() {
        let app = app();
        let req = Request::builder().method("PUT").uri("/api/files/a.docx").header("sec-fetch-site", "cross-site").body(Body::from("x")).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
        let req = Request::builder().method("PUT").uri("/api/files/a.docx").header("sec-fetch-site", "same-origin").body(Body::from("x")).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn browser_escapes_names_and_uses_relative_links() {
        let storage: SharedStorage = Arc::new(MemoryStorage::default());
        storage.put(&DocPath::parse("R&D/Ann's notes.docx").unwrap(), b"x".to_vec()).await.unwrap();
        let r = send(&app_with(storage, PathBuf::new(), None), "GET", "/", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'none'"));
        let page = text(r).await;
        assert!(page.contains("<td class=\"name\">Ann&#39;s notes.docx</td>"), "{page}");
        assert!(page.contains("<td class=\"folder\">R&amp;D</td>"));
        assert!(page.contains("href=\"app/?file=R%26D%2FAnn%27s%20notes.docx\""));
        assert!(page.contains("href=\"api/files/R%26D/Ann%27s%20notes.docx\""));
        assert!(page.contains("value=\"R&amp;D/Ann&#39;s notes.docx\""));
        assert!(!page.contains("Ann's"));
        assert!(!page.contains("<script"));
        assert!(!page.contains("href=\"/"), "links must be relative");
    }

    #[tokio::test]
    async fn upload_and_delete_forms() {
        let app = app();
        let boundary = "XyZboundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"folder\"\r\n\r\n/team/\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"C:\\fakepath\\plan.docx\"\r\n\
             Content-Type: application/octet-stream\r\n\r\nPLAN\r\n--{boundary}--\r\n"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/upload")
            .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body))
            .unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()[header::LOCATION], "./");
        let r = send(&app, "GET", "/api/files/team/plan.docx", Body::empty()).await;
        assert_eq!(text(r).await, "PLAN");

        let req = Request::builder()
            .method("POST")
            .uri("/delete")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("path=team%2Fplan.docx"))
            .unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()[header::LOCATION], "./");
        let r = send(&app, "GET", "/api/files/team/plan.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);

        let req = Request::builder()
            .method("POST")
            .uri("/delete")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("path=..%2Fx"))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn web_app_is_served_with_a_fallback_page() {
        let app = app();
        let r = send(&app, "GET", "/app?file=a.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(r.headers()[header::LOCATION], "app/?file=a.docx");
        let r = send(&app, "GET", "/app/", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(text(r).await.contains("trunk build --release"));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<!doctype html><title>app</title>").unwrap();
        std::fs::write(dir.path().join("app_bg.wasm"), b"\0asm").unwrap();
        let app = app_with(Arc::new(MemoryStorage::default()), dir.path().to_path_buf(), None);
        let r = send(&app, "GET", "/app/?file=a.docx", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(text(r).await.contains("<title>app</title>"));
        let r = send(&app, "GET", "/app/app_bg.wasm", Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/wasm");
        let r = send(&app, "GET", "/app/..%2Findex.html", Body::empty()).await;
        assert_ne!(r.status(), StatusCode::OK);
    }
}
