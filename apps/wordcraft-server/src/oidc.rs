//! OpenID Connect sign-in (Authorization Code flow with PKCE), for running the server behind an
//! identity provider such as Authentik, Keycloak or Entra ID.
//!
//! | Route | Does |
//! |---|---|
//! | `GET /auth/login?next=<relative path>` | starts a sign-in: 302 to the provider |
//! | `GET /auth/callback` | the redirect URI: checks the answer, creates a session, 302 to `next` |
//! | `POST /auth/logout` | ends the session and, when the provider supports it, its session too |
//!
//! Every other route then needs the `wordcraft_session` cookie or `Authorization: Bearer <access
//! token>` (checked at the provider's userinfo endpoint). Sessions, pending sign-ins and the bearer
//! cache live in memory, each capped and pruned; a restart signs everyone out.
//!
//! Nothing here logs a token, code, secret or cookie value.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;
use serde_json::Value;
use sha2::Digest as _;
use url::Url;

use crate::config::{OidcConfig, is_loopback_http};
use crate::html;

/// The session cookie.
pub const SESSION_COOKIE: &str = "wordcraft_session";
/// Binds a pending sign-in to the browser that started it.
pub const LOGIN_COOKIE: &str = "wordcraft_login";
/// How long a started sign-in stays valid.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// The most sign-ins in progress at once; the oldest is dropped beyond it.
const MAX_PENDING: usize = 1_000;
/// The most sessions at once; the one closest to expiry is dropped beyond it.
const MAX_SESSIONS: usize = 10_000;
/// How long a bearer token check is cached.
const BEARER_TTL: Duration = Duration::from_secs(60);
/// The most cached bearer token checks.
const MAX_BEARER_CACHE: usize = 1_000;
/// The largest discovery, token, userinfo or JWKS response read.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// The longest token or cookie header looked at.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Allowed clock difference with the provider for `exp`, `iat` and `nbf`.
const CLOCK_SKEW_SECS: i64 = 120;
/// Every request to the provider.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The shortest time between two JWKS downloads (a new `kid` triggers one).
const JWKS_REFRESH: Duration = Duration::from_secs(10);
/// The most keys kept from a JWKS.
const MAX_JWKS_KEYS: usize = 64;
/// The most groups kept for a user.
const MAX_GROUPS: usize = 256;
/// The longest name, e-mail or group kept, in characters.
const MAX_CLAIM_CHARS: usize = 256;
/// The policy for pages this module renders: no scripts, no forms.
pub const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A signed-in user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The provider's `sub`.
    pub id: String,
    /// `name`, else `preferred_username`, else `email`, else `sub`.
    pub name: String,
    pub email: Option<String>,
    /// Whether the provider did not say the e-mail is unverified (`email_verified: false`).
    pub email_verified: bool,
    pub groups: Vec<String>,
}

impl User {
    /// The `user` object of `/api/me`.
    pub fn to_json(&self) -> Value {
        serde_json::json!({ "id": self.id, "name": self.name, "email": self.email, "groups": self.groups })
    }

    /// The user's storage folder (`users/<id>`) with `--per-user-storage`. The `sub` is used as is
    /// when it is short and plain lower-case ASCII; anything else (upper case could collide on a
    /// case-insensitive file system, other characters may be refused by a backend) is replaced by
    /// `h-` and its SHA-256 in hex. A plain `sub` never starts with `h-`, so the two cannot collide.
    pub fn folder(&self) -> String {
        let plain = !self.id.is_empty()
            && self.id.len() <= 128
            && !self.id.starts_with("h-")
            && !self.id.starts_with(['-', '.'])
            && self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if plain {
            format!("users/{}", self.id)
        } else {
            let hex: String = sha256(self.id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
            format!("users/h-{hex}")
        }
    }
}

/// What discovery found.
#[derive(Debug, Clone)]
struct Metadata {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Option<Url>,
    end_session_endpoint: Option<Url>,
    jwks_uri: Option<Url>,
}

struct Pending {
    nonce: String,
    verifier: String,
    next: String,
    created: Instant,
}

struct Session {
    user: Arc<User>,
    id_token: String,
    expires: Instant,
}

#[derive(Default)]
struct Jwks {
    keys: Vec<Value>,
    fetched: Option<Instant>,
}

/// The sign-in state shared by every request.
pub struct Oidc {
    config: OidcConfig,
    meta: Metadata,
    http: reqwest::Client,
    redirect_uri: String,
    pending: Mutex<HashMap<String, Pending>>,
    /// Keyed by the SHA-256 of the cookie value.
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// Keyed by the SHA-256 of the token; `None` caches a refusal.
    bearer: Mutex<HashMap<[u8; 32], (Option<Arc<User>>, Instant)>>,
    jwks: tokio::sync::Mutex<Jwks>,
}

/// A refused sign-in: what the browser sees, and what the log gets (never a secret).
struct Refusal {
    status: StatusCode,
    title: &'static str,
    message: String,
    log: String,
}

impl Refusal {
    fn bad(message: &str, log: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, title: "Sign-in failed", message: message.into(), log: log.into() }
    }

    fn provider(log: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            title: "Sign-in failed",
            message: "The sign-in provider's answer could not be accepted. Try again, or ask the administrator to check the server log.".into(),
            log: log.into(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(sha2::Sha256::digest(data).as_slice()).unwrap_or_default()
}

/// 32 bytes from the operating system's CSPRNG, base64url.
fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("no random numbers: {e}"))?;
    Ok(B64.encode(bytes))
}

/// Compares without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Whether `url` may be used as a provider endpoint: https, or http to localhost when the issuer
/// itself is http to localhost (development and tests).
fn endpoint_allowed(url: &Url, issuer: &Url) -> bool {
    url.scheme() == "https" || (is_loopback_http(issuer) && is_loopback_http(url))
}

/// Reads at most [`MAX_RESPONSE_BYTES`] of a response and parses it as JSON.
async fn read_json(mut resp: reqwest::Response) -> Result<(u16, Value), String> {
    let status = resp.status().as_u16();
    if resp.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
        return Err(format!("HTTP {status}: response too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("reading the response: {}", e.without_url()))? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(format!("HTTP {status}: response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    let json = serde_json::from_slice(&body).map_err(|_| format!("HTTP {status}: the response is not JSON"))?;
    Ok((status, json))
}

async fn send_json(req: reqwest::RequestBuilder) -> Result<(u16, Value), String> {
    let resp = req.send().await.map_err(|e| format!("request failed: {}", e.without_url()))?;
    read_json(resp).await
}

/// A string claim, capped at [`MAX_CLAIM_CHARS`].
fn claim_str(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?.trim();
    (!s.is_empty()).then(|| s.chars().take(MAX_CLAIM_CHARS).collect())
}

/// Builds the user from the userinfo response (preferred) and the ID token claims.
fn build_user(id_claims: &Value, info: Option<&Value>) -> Result<User, String> {
    let pick = |key: &str| info.and_then(|i| claim_str(i, key)).or_else(|| claim_str(id_claims, key));
    let sub = id_claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 255).ok_or("no valid sub claim")?;
    let email = pick("email");
    let email_verified =
        info.and_then(|i| i.get("email_verified")).or_else(|| id_claims.get("email_verified")).and_then(Value::as_bool) != Some(false);
    let name =
        pick("name").or_else(|| pick("preferred_username")).or_else(|| email.clone()).unwrap_or_else(|| sub.chars().take(MAX_CLAIM_CHARS).collect());
    let groups_claim = info.and_then(|i| i.get("groups")).or_else(|| id_claims.get("groups"));
    let groups = match groups_claim {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .filter(|g| !g.is_empty())
            .take(MAX_GROUPS)
            .map(|g| g.chars().take(MAX_CLAIM_CHARS).collect())
            .collect(),
        Some(Value::String(g)) if !g.is_empty() => vec![g.chars().take(MAX_CLAIM_CHARS).collect()],
        _ => Vec::new(),
    };
    Ok(User { id: sub.to_string(), name, email, email_verified, groups })
}

/// Splits a compact JWS into its header, claims, signing input and signature.
fn decode_jwt(token: &str) -> Result<(Value, Value, &str, Vec<u8>), String> {
    if token.len() > MAX_TOKEN_BYTES * 4 {
        return Err("ID token too large".into());
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err("the ID token is not a compact JWS".into());
    };
    let decode = |part: &str| B64.decode(part.trim_end_matches('=')).map_err(|_| "the ID token is not base64url".to_string());
    let header: Value = serde_json::from_slice(&decode(h)?).map_err(|_| "the ID token header is not JSON")?;
    let claims: Value = serde_json::from_slice(&decode(p)?).map_err(|_| "the ID token claims are not JSON")?;
    if !claims.is_object() || !header.is_object() {
        return Err("the ID token is not a JSON object".into());
    }
    let signing_input = token.get(..h.len().saturating_add(p.len()).saturating_add(1)).ok_or("malformed ID token")?;
    Ok((header, claims, signing_input, decode(s)?))
}

/// Checks the ID token claims (OIDC Core 3.1.3.7), except the signature.
fn check_claims(claims: &Value, issuer: &str, client_id: &str, nonce: &str, now: i64) -> Result<(), String> {
    let iss = claims.get("iss").and_then(Value::as_str).unwrap_or_default();
    if iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err("the ID token's iss is not the issuer".into());
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&client_id) {
        return Err("the ID token's aud does not contain the client ID".into());
    }
    match claims.get("azp").and_then(Value::as_str) {
        Some(azp) if azp != client_id => return Err("the ID token's azp is not the client ID".into()),
        None if audiences.len() > 1 => return Err("the ID token has several audiences and no azp".into()),
        _ => {}
    }
    let time = |key: &str| claims.get(key).and_then(Value::as_i64);
    let exp = time("exp").ok_or("the ID token has no exp")?;
    if exp.saturating_add(CLOCK_SKEW_SECS) < now {
        return Err("the ID token has expired".into());
    }
    let iat = time("iat").ok_or("the ID token has no iat")?;
    if iat.saturating_sub(CLOCK_SKEW_SECS) > now {
        return Err("the ID token was issued in the future".into());
    }
    if time("nbf").is_some_and(|nbf| nbf.saturating_sub(CLOCK_SKEW_SECS) > now) {
        return Err("the ID token is not valid yet".into());
    }
    let given = claims.get("nonce").and_then(Value::as_str).unwrap_or_default();
    if !constant_time_eq(given.as_bytes(), nonce.as_bytes()) {
        return Err("the ID token's nonce does not match".into());
    }
    Ok(())
}

/// Whether `jwk` verifies `sig` over `input` with `alg`.
fn verify_with_jwk(jwk: &Value, alg: &str, input: &[u8], sig: &[u8]) -> bool {
    use ring::signature;
    if jwk.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") || jwk.get("alg").and_then(Value::as_str).is_some_and(|a| a != alg) {
        return false;
    }
    let field = |key: &str| jwk.get(key).and_then(Value::as_str).and_then(|s| B64.decode(s.trim_end_matches('=')).ok());
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
    let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
    let rsa: Option<&signature::RsaParameters> = match alg {
        "RS256" => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => Some(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => Some(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => Some(&signature::RSA_PSS_2048_8192_SHA512),
        _ => None,
    };
    if let Some(params) = rsa {
        let (Some(n), Some(e)) = (field("n"), field("e")) else { return false };
        return kty == "RSA" && signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(params, input, sig).is_ok();
    }
    let (ec, len): (&'static dyn signature::VerificationAlgorithm, usize) = match (alg, crv) {
        ("ES256", "P-256") => (&signature::ECDSA_P256_SHA256_FIXED, 32),
        ("ES384", "P-384") => (&signature::ECDSA_P384_SHA384_FIXED, 48),
        _ => return false,
    };
    let (Some(x), Some(y)) = (field("x"), field("y")) else { return false };
    if kty != "EC" || x.len() != len || y.len() != len {
        return false;
    }
    let mut point = Vec::with_capacity(1 + 2 * len);
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    signature::UnparsedPublicKey::new(ec, point).verify(input, sig).is_ok()
}

/// A `next` value as a path relative to the server root, or `None` when it could leave the site
/// (or is otherwise odd). A path starting with one `/` is an absolute path on the public URL's
/// origin (the browser's `location.pathname`, which the web app sends) and must lie under
/// `root` (the public URL's path, ending in `/`), which is removed.
fn sanitize_next(raw: &str, root: &str) -> Option<String> {
    let s = if raw.starts_with('/') && !raw.starts_with("//") { raw.strip_prefix(root)? } else { raw };
    if s.len() > 2048 || !s.is_ascii() || s.starts_with('/') || s.contains('\\') || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let path = s.split(['?', '#']).next().unwrap_or_default();
    // A colon before the first `/`, `?` or `#` would be a scheme (`javascript:`, `https:`).
    if path.contains(':') || path.contains("//") || path.starts_with("auth/") || path == "auth" {
        return None;
    }
    let dots = |seg: &str| matches!(seg.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | "..");
    if path.split('/').any(dots) {
        return None;
    }
    Some(s.to_string())
}

/// `./` or `../` repeated so that a link from `path` reaches the server root.
pub fn root_prefix(path: &str) -> String {
    let depth = path.trim_start_matches('/').matches('/').count();
    if depth == 0 { "./".into() } else { "../".repeat(depth) }
}

/// The value of cookie `name`, from any `Cookie` header.
fn get_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter(|v| v.len() <= MAX_TOKEN_BYTES)
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

/// The first value of `key` in a query string.
fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()).find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}

/// A page for the browser.
fn page(status: StatusCode, title: &str, message: &str, link: Option<(&str, &str)>) -> Response {
    let body = html::notice(title, message, link);
    (status, [(header::CONTENT_SECURITY_POLICY, PAGE_CSP), (header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
}

fn redirect(status: StatusCode, location: &str) -> Response {
    let mut resp = status.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The answer to a request without a valid sign-in: 401 JSON for the API (and anything but a page
/// load), otherwise a redirect to the sign-in that comes back to the same page.
pub fn unauthenticated(method: &Method, uri: &Uri) -> Response {
    let path = uri.path();
    if path == "/api" || path.starts_with("/api/") || !matches!(*method, Method::GET | Method::HEAD) {
        let body = serde_json::json!({ "error": "unauthenticated", "login": "auth/login" });
        return (StatusCode::UNAUTHORIZED, [(header::CACHE_CONTROL, "no-store")], axum::Json(body)).into_response();
    }
    let here = match uri.query() {
        Some(q) => format!("{}?{q}", path.trim_start_matches('/')),
        None => path.trim_start_matches('/').to_string(),
    };
    let location = if here.is_empty() {
        format!("{}auth/login", root_prefix(path))
    } else {
        format!("{}auth/login?next={}", root_prefix(path), html::encode_component(&here))
    };
    redirect(StatusCode::FOUND, &location)
}

impl Oidc {
    /// Fetches the provider's discovery document and checks it.
    pub async fn discover(config: OidcConfig) -> Result<Self, String> {
        let issuer_url = Url::parse(&config.issuer).map_err(|e| format!("issuer: {e}"))?;
        let mut builder = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("wordcraft-server/", env!("CARGO_PKG_VERSION")));
        if is_loopback_http(&issuer_url) {
            // A proxy cannot reach this machine's loopback.
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(|e| format!("HTTP client: {e}"))?;
        let url = format!("{}/.well-known/openid-configuration", config.issuer.trim_end_matches('/'));
        let (status, doc) =
            send_json(http.get(&url).header(reqwest::header::ACCEPT, "application/json")).await.map_err(|e| format!("discovery at {url}: {e}"))?;
        if status != 200 {
            return Err(format!("discovery at {url}: HTTP {status}"));
        }
        let issuer = doc.get("issuer").and_then(Value::as_str).ok_or_else(|| format!("discovery at {url}: no issuer"))?;
        if issuer.trim_end_matches('/') != config.issuer.trim_end_matches('/') {
            return Err(format!("discovery at {url}: the issuer is {issuer:?}, not {:?} (check --oidc-issuer)", config.issuer));
        }
        let endpoint = |key: &str| -> Result<Option<Url>, String> {
            let Some(raw) = doc.get(key).and_then(Value::as_str) else { return Ok(None) };
            let u = Url::parse(raw).map_err(|e| format!("discovery: {key}: {e}"))?;
            if !endpoint_allowed(&u, &issuer_url) {
                return Err(format!("discovery: {key} must be https"));
            }
            Ok(Some(u))
        };
        let required = |key: &str| endpoint(key).and_then(|u| u.ok_or_else(|| format!("discovery: no {key}")));
        let meta = Metadata {
            issuer: issuer.to_string(),
            authorization_endpoint: required("authorization_endpoint")?,
            token_endpoint: required("token_endpoint")?,
            userinfo_endpoint: endpoint("userinfo_endpoint")?,
            end_session_endpoint: endpoint("end_session_endpoint")?,
            jwks_uri: endpoint("jwks_uri")?,
        };
        if meta.jwks_uri.is_none() {
            log::warn!("the provider publishes no jwks_uri: ID token signatures are not checked, only TLS to the token endpoint protects them");
        }
        if let Some(methods) = doc.get("code_challenge_methods_supported").and_then(Value::as_array)
            && !methods.iter().any(|m| m == "S256")
        {
            log::warn!("the provider does not list PKCE S256 support; sign-in may fail");
        }
        let redirect_uri = format!("{}auth/callback", config.public_url);
        Ok(Self {
            config,
            meta,
            http,
            redirect_uri,
            pending: Mutex::default(),
            sessions: Mutex::default(),
            bearer: Mutex::default(),
            jwks: tokio::sync::Mutex::default(),
        })
    }

    pub fn per_user_storage(&self) -> bool {
        self.config.per_user_storage
    }

    pub fn issuer(&self) -> &str {
        &self.meta.issuer
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The origin forms may additionally be sent to (the sign-out redirect to the provider).
    pub fn end_session_origin(&self) -> Option<String> {
        self.meta.end_session_endpoint.as_ref().map(|u| u.origin().ascii_serialization())
    }

    /// A `Set-Cookie` value. Every cookie is HttpOnly and SameSite=Lax (sent on the provider's
    /// top-level redirect back), Secure when the public URL is https.
    fn cookie(&self, name: &str, value: &str, path: &str, max_age: u64) -> Option<HeaderValue> {
        let secure = if self.config.public_url.scheme() == "https" { "; Secure" } else { "" };
        HeaderValue::from_str(&format!("{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")).ok()
    }

    fn root_path(&self) -> &str {
        self.config.public_url.path()
    }

    fn login_cookie_path(&self) -> String {
        format!("{}auth/", self.root_path())
    }

    fn with_cookie(mut resp: Response, cookie: Option<HeaderValue>) -> Response {
        if let Some(c) = cookie {
            resp.headers_mut().append(header::SET_COOKIE, c);
        }
        resp
    }

    /// `GET /auth/login`.
    pub fn login(&self, query: Option<&str>) -> Response {
        let next = query_param(query, "next").and_then(|n| sanitize_next(&n, self.root_path())).unwrap_or_default();
        let (state, nonce, verifier) = match (random_token(), random_token(), random_token()) {
            (Ok(s), Ok(n), Ok(v)) => (s, n, v),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                log::error!("sign-in: {e}");
                return page(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in failed", "The server could not start a sign-in.", None);
            }
        };
        let challenge = B64.encode(sha256(verifier.as_bytes()));
        let mut url = self.meta.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        {
            let mut pending = lock(&self.pending);
            pending.retain(|_, p| p.created.elapsed() < LOGIN_TTL);
            while pending.len() >= MAX_PENDING {
                let Some(oldest) = pending.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| k.clone()) else { break };
                pending.remove(&oldest);
            }
            pending.insert(state.clone(), Pending { nonce, verifier, next, created: Instant::now() });
        }
        let cookie = self.cookie(LOGIN_COOKIE, &state, &self.login_cookie_path(), LOGIN_TTL.as_secs());
        Self::with_cookie(redirect(StatusCode::FOUND, url.as_str()), cookie)
    }

    /// `GET /auth/callback`.
    pub async fn callback(&self, headers: &HeaderMap, query: Option<&str>) -> Response {
        let clear = self.cookie(LOGIN_COOKIE, "", &self.login_cookie_path(), 0);
        let resp = match self.finish_login(headers, query).await {
            Ok((token, next)) => {
                let max_age = self.config.session_hours.saturating_mul(3600);
                let session = self.cookie(SESSION_COOKIE, &token, self.root_path(), max_age);
                Self::with_cookie(redirect(StatusCode::FOUND, &format!("../{next}")), session)
            }
            Err(r) => {
                log::warn!("sign-in refused: {}", r.log);
                page(r.status, r.title, &r.message, Some(("Try again", "login")))
            }
        };
        Self::with_cookie(resp, clear)
    }

    async fn finish_login(&self, headers: &HeaderMap, query: Option<&str>) -> Result<(String, String), Refusal> {
        if let Some(error) = query_param(query, "error") {
            let detail = query_param(query, "error_description").unwrap_or_default();
            let short = |s: &str| s.chars().filter(|c| !c.is_control()).take(300).collect::<String>();
            let (error, detail) = (short(&error), short(&detail));
            let message = if detail.is_empty() {
                format!("The sign-in provider said: {error}")
            } else {
                format!("The sign-in provider said: {error}: {detail}")
            };
            return Err(Refusal {
                status: StatusCode::FORBIDDEN,
                title: "Sign-in was not completed",
                message,
                log: format!("provider error {error:?}"),
            });
        }
        let (Some(code), Some(state)) = (query_param(query, "code"), query_param(query, "state")) else {
            return Err(Refusal::bad("The sign-in answer is incomplete.", "callback without code or state"));
        };
        // The state must be the one this browser was given (login CSRF), and is used once.
        let Some(cookie) = get_cookie(headers, LOGIN_COOKIE).filter(|c| !c.is_empty()) else {
            return Err(Refusal::bad(
                "This sign-in was started in another browser or has expired. Start again.",
                "callback without the login cookie",
            ));
        };
        if !constant_time_eq(cookie.as_bytes(), state.as_bytes()) {
            return Err(Refusal::bad(
                "This sign-in was started in another browser or has expired. Start again.",
                "callback state does not match the login cookie",
            ));
        }
        let pending = self.take_pending(&state);
        let Some(pending) = pending.filter(|p| p.created.elapsed() < LOGIN_TTL) else {
            return Err(Refusal::bad("This sign-in has expired or was already used. Start again.", "callback state unknown, expired or replayed"));
        };

        // The code for tokens, directly at the token endpoint (over TLS).
        let req = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", &code)
                .append_pair("redirect_uri", &self.redirect_uri)
                .append_pair("code_verifier", &pending.verifier);
            let mut req = self.http.post(self.meta.token_endpoint.clone()).header(reqwest::header::ACCEPT, "application/json");
            match &self.config.client_secret {
                Some(secret) => {
                    // client_secret_basic: both parts form-encoded first (RFC 6749 2.3.1).
                    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                    req = req.basic_auth(enc(&self.config.client_id), Some(enc(secret)));
                }
                None => {
                    form.append_pair("client_id", &self.config.client_id);
                }
            }
            req.header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(form.finish())
        };
        let (status, tokens) = send_json(req).await.map_err(|e| Refusal::provider(format!("token endpoint: {e}")))?;
        if status != 200 {
            let error = tokens.get("error").and_then(Value::as_str).unwrap_or("?").chars().take(80).collect::<String>();
            return Err(Refusal::provider(format!("token endpoint: HTTP {status} ({error})")));
        }
        let id_token = tokens.get("id_token").and_then(Value::as_str).ok_or_else(|| Refusal::provider("token endpoint: no id_token"))?;
        let access_token = tokens.get("access_token").and_then(Value::as_str);

        let claims = self.validate_id_token(id_token, &pending.nonce).await.map_err(Refusal::provider)?;
        let info = match (&self.meta.userinfo_endpoint, access_token) {
            (Some(_), Some(at)) => {
                let info = self.userinfo(at).await.map_err(|e| Refusal::provider(format!("userinfo: {e}")))?;
                if info.get("sub").and_then(Value::as_str) != claims.get("sub").and_then(Value::as_str) {
                    return Err(Refusal::provider("userinfo: sub differs from the ID token"));
                }
                Some(info)
            }
            _ => None,
        };
        let user = build_user(&claims, info.as_ref()).map_err(Refusal::provider)?;
        if !self.allowed(&user) {
            return Err(Refusal {
                status: StatusCode::FORBIDDEN,
                title: "Access denied",
                message: format!(
                    "You are signed in as {}, but this account may not use these documents. Ask the administrator for access.",
                    user.name
                ),
                log: "the user is not in the allowed groups or e-mails".into(),
            });
        }
        let token = random_token().map_err(|e| Refusal::provider(e.to_string()))?;
        self.create_session(&token, user, id_token);
        Ok((token, pending.next))
    }

    fn take_pending(&self, state: &str) -> Option<Pending> {
        lock(&self.pending).remove(state)
    }

    /// Decodes the ID token, checks its signature when the provider publishes keys, and its claims.
    async fn validate_id_token(&self, token: &str, nonce: &str) -> Result<Value, String> {
        let (header, claims, input, sig) = decode_jwt(token)?;
        self.verify_signature(&header, input.as_bytes(), &sig).await?;
        check_claims(&claims, &self.meta.issuer, &self.config.client_id, nonce, chrono::Utc::now().timestamp())?;
        Ok(claims)
    }

    /// Signature check.
    ///
    /// OIDC Core 3.1.3.7 (6): an ID token received directly from the token endpoint over TLS may
    /// rely on TLS server validation in place of its signature, which is what happens here when
    /// the provider publishes no `jwks_uri` (every endpoint is https; see `endpoint_allowed`).
    /// When it does, the signature must verify (RS*, PS*, ES256/ES384 against the JWKS, or HS*
    /// with the client secret) and `alg: none` is refused, as defence in depth.
    async fn verify_signature(&self, header: &Value, input: &[u8], sig: &[u8]) -> Result<(), String> {
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
        if let Some(hash) = match alg {
            "HS256" => Some(ring::hmac::HMAC_SHA256),
            "HS384" => Some(ring::hmac::HMAC_SHA384),
            "HS512" => Some(ring::hmac::HMAC_SHA512),
            _ => None,
        } {
            let secret = self.config.client_secret.as_deref().ok_or("an HS* ID token needs a client secret")?;
            let key = ring::hmac::Key::new(hash, secret.as_bytes());
            return ring::hmac::verify(&key, input, sig).map_err(|_| "the ID token signature is invalid".to_string());
        }
        let Some(jwks_uri) = &self.meta.jwks_uri else { return Ok(()) };
        if alg.is_empty() || alg == "none" {
            return Err("the ID token is not signed".into());
        }
        let kid = header.get("kid").and_then(Value::as_str);
        let matches = |k: &Value| kid.is_none_or(|kid| k.get("kid").and_then(Value::as_str) == Some(kid));
        let mut jwks = self.jwks.lock().await;
        let stale = jwks.fetched.is_none_or(|t| t.elapsed() >= JWKS_REFRESH);
        if stale && !jwks.keys.iter().any(matches) {
            jwks.fetched = Some(Instant::now());
            let (status, doc) = send_json(self.http.get(jwks_uri.clone())).await.map_err(|e| format!("JWKS: {e}"))?;
            if status != 200 {
                return Err(format!("JWKS: HTTP {status}"));
            }
            let keys = doc.get("keys").and_then(Value::as_array).ok_or("JWKS: no keys")?;
            jwks.keys = keys.iter().take(MAX_JWKS_KEYS).cloned().collect();
        }
        if jwks.keys.iter().filter(|k| matches(k)).any(|k| verify_with_jwk(k, alg, input, sig)) {
            Ok(())
        } else {
            Err(format!("the ID token signature ({alg}) does not verify with the provider's keys"))
        }
    }

    /// The userinfo response for an access token.
    async fn userinfo(&self, access_token: &str) -> Result<Value, String> {
        let endpoint = self.meta.userinfo_endpoint.clone().ok_or("no userinfo endpoint")?;
        let req = self.http.get(endpoint).bearer_auth(access_token).header(reqwest::header::ACCEPT, "application/json");
        let (status, info) = send_json(req).await?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        if !info.is_object() {
            return Err("not a JSON object".into());
        }
        Ok(info)
    }

    /// The group and e-mail allowlists: with neither, everyone the provider signs in is allowed;
    /// otherwise a user must be in one allowed group or have one allowed (not unverified) e-mail.
    fn allowed(&self, user: &User) -> bool {
        let c = &self.config;
        if c.allowed_groups.is_empty() && c.allowed_emails.is_empty() {
            return true;
        }
        let group = user.groups.iter().any(|g| c.allowed_groups.contains(g));
        let email = user.email_verified && user.email.as_ref().is_some_and(|e| c.allowed_emails.contains(&e.to_lowercase()));
        group || email
    }

    fn create_session(&self, token: &str, user: User, id_token: &str) {
        let lifetime = Duration::from_secs(self.config.session_hours.saturating_mul(3600));
        let now = Instant::now();
        let expires = now.checked_add(lifetime).unwrap_or(now);
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| s.expires > now);
        while sessions.len() >= MAX_SESSIONS {
            let Some(first) = sessions.iter().min_by_key(|(_, s)| s.expires).map(|(k, _)| *k) else { break };
            sessions.remove(&first);
        }
        // No names or ids in the log: they are personal details.
        log::info!("signed in: session created");
        sessions.insert(sha256(token.as_bytes()), Session { user: Arc::new(user), id_token: id_token.to_string(), expires });
    }

    /// The signed-in user for a request: its session cookie, or a bearer access token.
    /// A bearer token decides on its own (no fallback to the cookie); other `Authorization`
    /// schemes are ignored.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Option<Arc<User>> {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
            .map(|t| t.trim().to_string());
        if let Some(token) = bearer {
            return self.bearer(&token).await;
        }
        let cookie = get_cookie(headers, SESSION_COOKIE)?;
        let key = sha256(cookie.as_bytes());
        let mut sessions = lock(&self.sessions);
        match sessions.get(&key) {
            Some(s) if s.expires > Instant::now() => Some(s.user.clone()),
            Some(_) => {
                sessions.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Checks a bearer access token at the userinfo endpoint (cached for [`BEARER_TTL`]). Any
    /// access token the provider accepts there is taken, so the allowlists are what limit it.
    async fn bearer(&self, token: &str) -> Option<Arc<User>> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || self.meta.userinfo_endpoint.is_none() {
            return None;
        }
        let key = sha256(token.as_bytes());
        if let Some(cached) = self.cached_bearer(&key) {
            return cached;
        }
        let user = match self.userinfo(token).await {
            Ok(info) => build_user(&info, None).ok().filter(|u| self.allowed(u)).map(Arc::new),
            Err(e) => {
                log::debug!("bearer token refused: {e}");
                None
            }
        };
        let mut cache = lock(&self.bearer);
        cache.retain(|_, (_, at)| at.elapsed() < BEARER_TTL);
        while cache.len() >= MAX_BEARER_CACHE {
            let Some(oldest) = cache.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k) else { break };
            cache.remove(&oldest);
        }
        cache.insert(key, (user.clone(), Instant::now()));
        user
    }

    fn cached_bearer(&self, key: &[u8; 32]) -> Option<Option<Arc<User>>> {
        let cache = lock(&self.bearer);
        let (user, at) = cache.get(key)?;
        (at.elapsed() < BEARER_TTL).then(|| user.clone())
    }

    /// `POST /auth/logout`.
    pub fn logout(&self, headers: &HeaderMap) -> Response {
        let session = get_cookie(headers, SESSION_COOKIE).and_then(|c| lock(&self.sessions).remove(&sha256(c.as_bytes())));
        let location = match (&self.meta.end_session_endpoint, &session) {
            (Some(end), Some(s)) => {
                let mut url = end.clone();
                url.query_pairs_mut()
                    .append_pair("id_token_hint", &s.id_token)
                    .append_pair("post_logout_redirect_uri", self.config.public_url.as_str())
                    .append_pair("client_id", &self.config.client_id);
                url.to_string()
            }
            _ => "../".to_string(),
        };
        if session.is_some() {
            log::info!("signed out: session ended");
        }
        let clear = self.cookie(SESSION_COOKIE, "", self.root_path(), 0);
        Self::with_cookie(redirect(StatusCode::SEE_OTHER, &location), clear)
    }
}

#[cfg(test)]
mod tests;
