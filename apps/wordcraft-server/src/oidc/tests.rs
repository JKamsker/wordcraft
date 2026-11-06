//! Sign-in tests against an in-process mock provider (axum on 127.0.0.1:0): discovery, authorize,
//! token (ES256-signed, unsigned or tampered ID tokens with configurable claims), userinfo, JWKS
//! and end-session. No network beyond loopback.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Form, Query, Request, State};
use axum::routing::{get, post};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use tower::ServiceExt as _;

use super::*;
use crate::http::{AppState, router};
use crate::storage::SharedStorage;
use crate::storage::memory::MemoryStorage;

const CLIENT_ID: &str = "wordcraft";
const SECRET: &str = "s3cret&=x";
const PUBLIC: &str = "https://docs.example.com/wc/";

#[derive(Clone, Copy, PartialEq)]
enum Sign {
    Es256,
    Tampered,
    None,
}

struct Mock {
    base: String,
    issuer: String,
    discovery_issuer: String,
    with_jwks: bool,
    secret: Option<String>,
    key: EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    sign: Mutex<Sign>,
    /// The profile the next /authorize signs in.
    profile: Mutex<Value>,
    /// Merged into the next ID tokens' claims (`null` removes a claim).
    overrides: Mutex<Value>,
    codes: Mutex<HashMap<String, (String, String, String, Value)>>,
    tokens: Mutex<HashMap<String, Value>>,
    counter: AtomicU32,
}

impl Mock {
    fn jwt(&self, claims: &Value) -> String {
        let sign = *lock(&self.sign);
        let header =
            if sign == Sign::None { serde_json::json!({"alg": "none"}) } else { serde_json::json!({"alg": "ES256", "kid": "k1", "typ": "JWT"}) };
        let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
        match sign {
            Sign::None => format!("{input}."),
            Sign::Es256 | Sign::Tampered => {
                let mut sig = self.key.sign(&self.rng, input.as_bytes()).unwrap().as_ref().to_vec();
                if sign == Sign::Tampered {
                    sig[5] ^= 1;
                }
                format!("{input}.{}", B64.encode(sig))
            }
        }
    }
}

async fn discovery(State(m): State<Arc<Mock>>) -> axum::Json<Value> {
    let b = &m.base;
    let mut doc = serde_json::json!({
        "issuer": m.discovery_issuer,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/token"),
        "userinfo_endpoint": format!("{b}/userinfo"),
        "end_session_endpoint": format!("{b}/end-session"),
        "code_challenge_methods_supported": ["S256"],
    });
    if m.with_jwks {
        doc["jwks_uri"] = format!("{b}/jwks").into();
    }
    axum::Json(doc)
}

async fn authorize(State(m): State<Arc<Mock>>, Query(q): Query<HashMap<String, String>>) -> Response {
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(q["scope"].split(' ').any(|s| s == "openid"));
    let code = format!("code-{}", m.counter.fetch_add(1, Ordering::SeqCst));
    let profile = lock(&m.profile).clone();
    lock(&m.codes).insert(code.clone(), (q["nonce"].clone(), q["code_challenge"].clone(), q["redirect_uri"].clone(), profile));
    let mut back = Url::parse(&q["redirect_uri"]).unwrap();
    back.query_pairs_mut().append_pair("code", &code).append_pair("state", &q["state"]);
    redirect(StatusCode::FOUND, back.as_str())
}

async fn token(State(m): State<Arc<Mock>>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> Response {
    let refuse = |why: &str| (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": why}))).into_response();
    match &m.secret {
        Some(secret) => {
            let basic = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Basic ")).unwrap_or_default();
            let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(basic).unwrap_or_default()).unwrap_or_default();
            let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            if decoded != format!("{}:{}", enc(CLIENT_ID), enc(secret)) || f.contains_key("client_secret") {
                return refuse("invalid_client");
            }
        }
        None if f.get("client_id").map(String::as_str) != Some(CLIENT_ID) => return refuse("invalid_client"),
        None => {}
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return refuse("unsupported_grant_type");
    }
    let Some((nonce, challenge, redirect_uri, profile)) = f.get("code").and_then(|c| lock(&m.codes).remove(c)) else {
        return refuse("invalid_grant");
    };
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    if B64.encode(sha256(verifier.as_bytes())) != challenge || f.get("redirect_uri") != Some(&redirect_uri) {
        return refuse("invalid_grant");
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({"iss": m.issuer, "aud": CLIENT_ID, "sub": profile["sub"], "exp": now + 300, "iat": now, "nonce": nonce});
    if let Value::Object(o) = &*lock(&m.overrides) {
        for (k, v) in o {
            if v.is_null() {
                claims.as_object_mut().unwrap().remove(k);
            } else {
                claims[k] = v.clone();
            }
        }
    }
    let access = format!("at-{}", m.counter.fetch_add(1, Ordering::SeqCst));
    lock(&m.tokens).insert(access.clone(), profile);
    axum::Json(serde_json::json!({"access_token": access, "token_type": "Bearer", "id_token": m.jwt(&claims)})).into_response()
}

async fn userinfo(State(m): State<Arc<Mock>>, headers: HeaderMap) -> Response {
    let token = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
    match lock(&m.tokens).get(token) {
        Some(profile) => axum::Json(profile.clone()).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn jwks(State(m): State<Arc<Mock>>) -> axum::Json<Value> {
    let public = m.key.public_key().as_ref();
    axum::Json(serde_json::json!({"keys": [
        {"kty": "RSA", "kid": "other", "n": "AQAB", "e": "AQAB"},
        {"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256", "x": B64.encode(&public[1..33]), "y": B64.encode(&public[33..65])},
    ]}))
}

#[derive(Default)]
struct Opts {
    with_jwks: bool,
    secret: bool,
    per_user: bool,
    groups: Vec<String>,
    emails: Vec<String>,
    wrong_discovery_issuer: bool,
}

struct Env {
    app: Router,
    mock: Arc<Mock>,
    storage: SharedStorage,
    http: reqwest::Client,
}

fn profile(sub: &str, name: &str, email: &str, groups: &[&str]) -> Value {
    serde_json::json!({"sub": sub, "name": name, "preferred_username": sub, "email": email, "email_verified": true, "groups": groups})
}

async fn start_mock(opts: &Opts) -> Arc<Mock> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let issuer = format!("{base}/realms/test/");
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let mock = Arc::new(Mock {
        discovery_issuer: if opts.wrong_discovery_issuer { format!("{base}/realms/other/") } else { issuer.clone() },
        base,
        issuer,
        with_jwks: opts.with_jwks,
        secret: opts.secret.then(|| SECRET.to_string()),
        key,
        rng,
        sign: Mutex::new(if opts.with_jwks { Sign::Es256 } else { Sign::None }),
        profile: Mutex::new(profile("ann-1", "Ann <Admin>", "Ann@Example.com", &["editors"])),
        overrides: Mutex::new(serde_json::json!({})),
        codes: Mutex::default(),
        tokens: Mutex::default(),
        counter: AtomicU32::new(1),
    });
    let routes = Router::new()
        .route("/realms/test/.well-known/openid-configuration", get(discovery))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/jwks", get(jwks))
        .route("/end-session", get(|| async { "signed out" }))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, routes).await });
    mock
}

fn oidc_config(mock: &Mock, opts: &Opts) -> OidcConfig {
    OidcConfig {
        // Configured without the trailing slash discovery reports: normalised.
        issuer: mock.issuer.trim_end_matches('/').to_string(),
        client_id: CLIENT_ID.into(),
        client_secret: opts.secret.then(|| SECRET.to_string()),
        public_url: Url::parse(PUBLIC).unwrap(),
        scopes: "openid profile email".into(),
        allowed_groups: opts.groups.clone(),
        allowed_emails: opts.emails.clone(),
        per_user_storage: opts.per_user,
        session_hours: 12,
    }
}

async fn setup(opts: Opts) -> Env {
    let mock = start_mock(&opts).await;
    let oidc = Oidc::discover(oidc_config(&mock, &opts)).await.unwrap();
    assert_eq!(oidc.redirect_uri(), "https://docs.example.com/wc/auth/callback");
    let storage: SharedStorage = Arc::new(MemoryStorage::default());
    let app = router(AppState {
        storage: storage.clone(),
        max_bytes: 1 << 20,
        web_root: PathBuf::from("/nonexistent"),
        auth: None,
        oidc: Some(Arc::new(oidc)),
    });
    let http = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    Env { app, mock, storage, http }
}

fn set_cookie(resp: &Response, name: &str) -> Option<String> {
    resp.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with(&format!("{name}="))).map(String::from)
}

fn cookie_value(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().split_once('=').unwrap().1.to_string()
}

fn location(resp: &Response) -> String {
    resp.headers()[header::LOCATION].to_str().unwrap().to_string()
}

async fn body(resp: Response) -> String {
    String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

impl Env {
    async fn send(&self, method: &str, uri: &str, cookie: Option<&str>, payload: impl Into<Body>) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.app.clone().oneshot(req.body(payload.into()).unwrap()).await.unwrap()
    }

    /// Starts a sign-in and follows the provider's redirect: the callback URI (path and query on
    /// this server) and the login cookie.
    async fn authorize(&self, next: &str) -> (String, String) {
        let r = self.send("GET", &format!("/auth/login?next={}", html::encode_component(next)), None, Body::empty()).await;
        assert_eq!(r.status(), StatusCode::FOUND);
        let login = set_cookie(&r, LOGIN_COOKIE).unwrap();
        assert!(
            login.contains("HttpOnly") && login.contains("SameSite=Lax") && login.contains("Secure") && login.contains("Path=/wc/auth/"),
            "{login}"
        );
        let to_provider = location(&r);
        assert!(to_provider.starts_with(&format!("{}/authorize?", self.mock.base)), "{to_provider}");
        let back = self.http.get(&to_provider).send().await.unwrap();
        assert_eq!(back.status().as_u16(), 302);
        let back = back.headers()["location"].to_str().unwrap().to_string();
        let path = back.strip_prefix("https://docs.example.com/wc").unwrap().to_string();
        (path, format!("{LOGIN_COOKIE}={}", cookie_value(&login)))
    }

    /// A full sign-in; the callback response.
    async fn sign_in(&self, next: &str) -> Response {
        let (callback, cookie) = self.authorize(next).await;
        self.send("GET", &callback, Some(&cookie), Body::empty()).await
    }

    /// A full sign-in that must succeed; the session cookie for requests.
    async fn session(&self) -> String {
        let r = self.sign_in("").await;
        assert_eq!(r.status(), StatusCode::FOUND, "{}", body(r).await);
        format!("{SESSION_COOKIE}={}", cookie_value(&set_cookie(&r, SESSION_COOKIE).unwrap()))
    }

    async fn json(&self, uri: &str, cookie: Option<&str>) -> (StatusCode, Value) {
        let r = self.send("GET", uri, cookie, Body::empty()).await;
        (r.status(), serde_json::from_str(&body(r).await).unwrap())
    }
}

#[tokio::test]
async fn full_sign_in_files_and_sign_out() {
    let env = setup(Opts { with_jwks: true, secret: true, ..Opts::default() }).await;
    let r = env.sign_in("app/?file=a.docx").await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(location(&r), "../app/?file=a.docx");
    let session = set_cookie(&r, SESSION_COOKIE).unwrap();
    for attr in ["HttpOnly", "SameSite=Lax", "Secure", "Path=/wc/", "Max-Age=43200"] {
        assert!(session.contains(attr), "{session} lacks {attr}");
    }
    assert!(set_cookie(&r, LOGIN_COOKIE).unwrap().contains("Max-Age=0"), "the login cookie is cleared");
    let cookie = format!("{SESSION_COOKIE}={}", cookie_value(&session));

    let (status, me) = env.json("/api/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        me,
        serde_json::json!({"mode": "oidc", "authenticated": true,
            "user": {"id": "ann-1", "name": "Ann <Admin>", "email": "Ann@Example.com", "groups": ["editors"]}, "logout": "auth/logout"})
    );

    let r = env.send("PUT", "/api/files/a.docx", Some(&cookie), "hello").await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = env.send("GET", "/api/files/a.docx", Some(&cookie), Body::empty()).await;
    assert_eq!(body(r).await, "hello");
    let (_, list) = env.json("/api/files", Some(&cookie)).await;
    assert_eq!(list["files"][0]["path"], "a.docx");

    let r = env.send("GET", "/", Some(&cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::OK);
    let csp = r.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
    assert!(csp.contains(&format!("form-action 'self' {}", env.mock.base)), "{csp}");
    let page = body(r).await;
    assert!(page.contains("Signed in as <strong>Ann &lt;Admin&gt;</strong>"), "{page}");
    assert!(page.contains("action=\"auth/logout\""));

    let r = env.send("POST", "/auth/logout", Some(&cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let to = Url::parse(&location(&r)).unwrap();
    assert_eq!(to.path(), "/end-session");
    let q: HashMap<String, String> = to.query_pairs().into_owned().collect();
    assert_eq!(q["post_logout_redirect_uri"], PUBLIC);
    assert_eq!(q["id_token_hint"].split('.').count(), 3);
    assert!(set_cookie(&r, SESSION_COOKIE).unwrap().contains("Max-Age=0"));
    let (status, _) = env.json("/api/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the session is gone after sign-out");
    // Signing out without a session goes back to the start.
    let r = env.send("POST", "/auth/logout", None, Body::empty()).await;
    assert_eq!(location(&r), "../");
}

#[tokio::test]
async fn unauthenticated_requests() {
    let env = setup(Opts { with_jwks: true, ..Opts::default() }).await;
    for uri in ["/api/files", "/api/me", "/api/files/a.docx"] {
        let (status, json) = env.json(uri, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(json, serde_json::json!({"error": "unauthenticated", "login": "auth/login"}));
    }
    let (status, _) = env.json("/api/me", Some(&format!("{SESSION_COOKIE}=forged"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for (uri, to) in [
        ("/", "./auth/login"),
        ("/app/?file=a%20b.docx", "../auth/login?next=app%2F%3Ffile%3Da%2520b.docx"),
        ("/app/pkg/x.js", "../../auth/login?next=app%2Fpkg%2Fx.js"),
        ("/app", "./auth/login?next=app"),
    ] {
        let r = env.send("GET", uri, None, Body::empty()).await;
        assert_eq!(r.status(), StatusCode::FOUND, "{uri}");
        assert_eq!(location(&r), to, "{uri}");
    }
    let r = env.send("POST", "/upload", None, Body::empty()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(env.storage.list().await.unwrap().is_empty());
    // The `next` from the redirect comes back after signing in, and so does the web app's
    // absolute one (`location.pathname` under the public path /wc/).
    let r = env.sign_in("app/?file=a%20b.docx").await;
    assert_eq!(location(&r), "../app/?file=a%20b.docx");
    let r = env.sign_in("/wc/app/?file=reports/q3.docx").await;
    assert_eq!(location(&r), "../app/?file=reports/q3.docx");
}

#[tokio::test]
async fn state_and_login_cookie_are_checked() {
    let env = setup(Opts { with_jwks: true, ..Opts::default() }).await;
    // No login cookie (another browser started the sign-in).
    let (callback, _) = env.authorize("").await;
    let r = env.send("GET", &callback, None, Body::empty()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie(&r, SESSION_COOKIE).is_none());
    // A login cookie from a different sign-in.
    let (callback, _) = env.authorize("").await;
    let (_, other_cookie) = env.authorize("").await;
    let r = env.send("GET", &callback, Some(&other_cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // A state tampered with, cookie to match.
    let (callback, _) = env.authorize("").await;
    let forged = format!("{}x", callback);
    let state = query_param(Url::parse(&format!("http://h{forged}")).unwrap().query(), "state").unwrap();
    let r = env.send("GET", &forged, Some(&format!("{LOGIN_COOKIE}={state}")), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Replay: a completed callback cannot be used again.
    let (callback, cookie) = env.authorize("").await;
    let r = env.send("GET", &callback, Some(&cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    let r = env.send("GET", &callback, Some(&cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie(&r, SESSION_COOKIE).is_none());
    // Incomplete answers.
    let r = env.send("GET", "/auth/callback", Some(&cookie), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // The provider's error is shown, escaped.
    let r = env.send("GET", "/auth/callback?error=access_denied&error_description=%3Cscript%3Ex%3C%2Fscript%3E", None, Body::empty()).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(r.headers()[header::CONTENT_SECURITY_POLICY], PAGE_CSP);
    let page = body(r).await;
    assert!(page.contains("access_denied: &lt;script&gt;x&lt;/script&gt;"), "{page}");
    assert!(!page.contains("<script"));
}

#[tokio::test]
async fn bad_id_tokens_are_refused() {
    let env = setup(Opts { with_jwks: true, ..Opts::default() }).await;
    let now = chrono::Utc::now().timestamp();
    for (why, overrides, sign) in [
        ("wrong aud", serde_json::json!({"aud": "someone-else"}), Sign::Es256),
        ("several aud without azp", serde_json::json!({"aud": [CLIENT_ID, "other"]}), Sign::Es256),
        ("wrong azp", serde_json::json!({"azp": "other"}), Sign::Es256),
        ("wrong iss", serde_json::json!({"iss": "https://evil.example.com/"}), Sign::Es256),
        ("expired", serde_json::json!({"exp": now - 3600}), Sign::Es256),
        ("no exp", serde_json::json!({"exp": null}), Sign::Es256),
        ("issued in the future", serde_json::json!({"iat": now + 3600}), Sign::Es256),
        ("nonce mismatch", serde_json::json!({"nonce": "not-the-nonce"}), Sign::Es256),
        ("no nonce", serde_json::json!({"nonce": null}), Sign::Es256),
        ("tampered signature", serde_json::json!({}), Sign::Tampered),
        ("unsigned while the provider publishes keys", serde_json::json!({}), Sign::None),
    ] {
        *lock(&env.mock.overrides) = overrides;
        *lock(&env.mock.sign) = sign;
        let r = env.sign_in("").await;
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY, "{why}");
        assert!(set_cookie(&r, SESSION_COOKIE).is_none(), "{why}");
    }
    // Several audiences with the right azp, and a token within the clock skew, are fine.
    *lock(&env.mock.overrides) = serde_json::json!({"aud": [CLIENT_ID, "other"], "azp": CLIENT_ID, "exp": now - 30});
    *lock(&env.mock.sign) = Sign::Es256;
    assert_eq!(env.sign_in("").await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn without_jwks_tls_stands_in_for_the_signature() {
    // Public client (no secret) and a provider without jwks_uri: an unsigned token from the token
    // endpoint is accepted, its claims still checked.
    let env = setup(Opts::default()).await;
    let cookie = env.session().await;
    let (status, me) = env.json("/api/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["user"]["id"], "ann-1");
    *lock(&env.mock.overrides) = serde_json::json!({"nonce": "x"});
    assert_eq!(env.sign_in("").await.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn next_values_are_neutralised() {
    for bad in [
        "//evil.example.com/",
        "/\\evil.example.com",
        "\\\\evil",
        "https://evil.example.com/",
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "app/\nSet-Cookie:x",
        "app/\t/x",
        "../../etc",
        "app/%2e%2e/%2E%2E/x",
        "a//b",
        "auth/login",
        "/auth/logout",
        "é",
    ] {
        assert_eq!(sanitize_next(bad, "/"), None, "{bad:?}");
        assert_eq!(sanitize_next(bad, "/wc/"), None, "{bad:?}");
    }
    assert_eq!(sanitize_next("app/?file=a.docx", "/").as_deref(), Some("app/?file=a.docx"));
    assert_eq!(sanitize_next("/app/", "/").as_deref(), Some("app/"));
    // Absolute paths (the web app sends location.pathname) must lie under the public path.
    assert_eq!(sanitize_next("/wc/app/?file=a.docx", "/wc/").as_deref(), Some("app/?file=a.docx"));
    assert_eq!(sanitize_next("/other/app/", "/wc/"), None);
    assert_eq!(sanitize_next("/wc//evil.example.com", "/wc/"), None);
    assert_eq!(sanitize_next("app/?next=https://x", "/").as_deref(), Some("app/?next=https://x"));
    assert_eq!(sanitize_next("", "/").as_deref(), Some(""));
    assert_eq!(root_prefix("/"), "./");
    assert_eq!(root_prefix("/app/x/y"), "../../");
}

#[tokio::test]
async fn open_redirects_are_neutralised_end_to_end() {
    let env = setup(Opts { with_jwks: true, ..Opts::default() }).await;
    for next in ["//evil.example.com/", "https://evil.example.com/", "/\\evil.example.com"] {
        let r = env.sign_in(next).await;
        assert_eq!(r.status(), StatusCode::FOUND);
        assert_eq!(location(&r), "../", "{next}");
    }
}

#[tokio::test]
async fn group_allowlist() {
    let env = setup(Opts { with_jwks: true, groups: vec!["admins".into(), "editors".into()], ..Opts::default() }).await;
    assert_eq!(env.sign_in("").await.status(), StatusCode::FOUND);
    *lock(&env.mock.profile) = profile("bob-2", "Bob", "bob@example.com", &["readers"]);
    let r = env.sign_in("").await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie(&r, SESSION_COOKIE).is_none());
    assert!(body(r).await.contains("Access denied"));
    *lock(&env.mock.profile) = serde_json::json!({"sub": "carl-3", "name": "Carl"});
    assert_eq!(env.sign_in("").await.status(), StatusCode::FORBIDDEN, "no groups claim at all");
}

#[tokio::test]
async fn email_allowlist() {
    let env = setup(Opts { with_jwks: true, emails: vec!["ann@example.com".into()], ..Opts::default() }).await;
    assert_eq!(env.sign_in("").await.status(), StatusCode::FOUND, "matched case-insensitively");
    let mut unverified = profile("ann-1", "Ann", "ann@example.com", &[]);
    unverified["email_verified"] = false.into();
    *lock(&env.mock.profile) = unverified;
    assert_eq!(env.sign_in("").await.status(), StatusCode::FORBIDDEN, "an unverified e-mail does not count");
    *lock(&env.mock.profile) = profile("bob-2", "Bob", "bob@example.com", &["editors"]);
    assert_eq!(env.sign_in("").await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn per_user_storage_isolates_users() {
    let env = setup(Opts { with_jwks: true, per_user: true, ..Opts::default() }).await;
    let ann = env.session().await;
    *lock(&env.mock.profile) = profile("Bob/../../Ann", "Bob", "bob@example.com", &[]);
    let bob = env.session().await;

    assert_eq!(env.send("PUT", "/api/files/plan.docx", Some(&ann), "ann's plan").await.status(), StatusCode::NO_CONTENT);
    assert_eq!(env.send("PUT", "/api/files/notes/b.docx", Some(&bob), "bob's").await.status(), StatusCode::NO_CONTENT);

    let (_, list) = env.json("/api/files", Some(&bob)).await;
    let paths: Vec<&str> = list["files"].as_array().unwrap().iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["notes/b.docx"]);
    let r = env.send("GET", "/api/files/plan.docx", Some(&bob), Body::empty()).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(env.send("DELETE", "/api/files/plan.docx", Some(&bob), Body::empty()).await.status(), StatusCode::NOT_FOUND);
    let r = env.send("GET", "/api/files/plan.docx", Some(&ann), Body::empty()).await;
    assert_eq!(body(r).await, "ann's plan");
    assert!(!body(env.send("GET", "/", Some(&bob), Body::empty()).await).await.contains("plan.docx"));

    let mut stored: Vec<String> = env.storage.list().await.unwrap().into_iter().map(|e| e.path).collect();
    stored.sort();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0], "users/ann-1/plan.docx");
    assert!(stored[1].starts_with("users/h-") && stored[1].ends_with("/notes/b.docx"), "{stored:?}");
}

#[tokio::test]
async fn bearer_tokens() {
    let env = setup(Opts { with_jwks: true, ..Opts::default() }).await;
    lock(&env.mock.tokens).insert("api-token-1".into(), profile("svc-9", "Robot", "robot@example.com", &["bots"]));
    let with = |token: &str| Request::builder().uri("/api/me").header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap();
    let r = env.app.clone().oneshot(with("api-token-1")).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let me: Value = serde_json::from_str(&body(r).await).unwrap();
    assert_eq!(me["user"]["id"], "svc-9");
    assert_eq!(me["user"]["groups"], serde_json::json!(["bots"]));
    // Cached: still accepted after the provider forgets it, for up to a minute.
    lock(&env.mock.tokens).remove("api-token-1");
    assert_eq!(env.app.clone().oneshot(with("api-token-1")).await.unwrap().status(), StatusCode::OK);
    for bad in ["nope", ""] {
        assert_eq!(env.app.clone().oneshot(with(bad)).await.unwrap().status(), StatusCode::UNAUTHORIZED, "{bad:?}");
    }
    let basic = Request::builder().uri("/api/me").header(header::AUTHORIZATION, "Basic YTpi").body(Body::empty()).unwrap();
    assert_eq!(env.app.clone().oneshot(basic).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    // Another scheme does not hide the session cookie; a bad bearer token is not rescued by one.
    let cookie = env.session().await;
    let with_cookie = |auth: &str| {
        Request::builder().uri("/api/me").header(header::AUTHORIZATION, auth).header(header::COOKIE, &cookie).body(Body::empty()).unwrap()
    };
    assert_eq!(env.app.clone().oneshot(with_cookie("Basic YTpi")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(env.app.clone().oneshot(with_cookie("Bearer nope")).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discovery_issuer_mismatch_is_refused() {
    let opts = Opts { wrong_discovery_issuer: true, ..Opts::default() };
    let mock = start_mock(&opts).await;
    let Err(e) = Oidc::discover(oidc_config(&mock, &opts)).await else { panic!("accepted a mismatched issuer") };
    assert!(e.contains("issuer"), "{e}");
    // Nothing listens there: discovery fails cleanly.
    let mut config = oidc_config(&mock, &opts);
    config.issuer = "http://127.0.0.1:1/realms/none".into();
    assert!(Oidc::discover(config).await.is_err());
}

#[test]
fn claims_and_users() {
    let now = 1_700_000_000;
    let good = serde_json::json!({"iss": "https://i.example/", "aud": "c", "exp": now + 10, "iat": now, "nonce": "n", "sub": "s"});
    assert!(check_claims(&good, "https://i.example", "c", "n", now).is_ok());
    assert!(check_claims(&good, "https://i.example", "c", "m", now).is_err());
    assert!(check_claims(&good, "https://j.example", "c", "n", now).is_err());
    assert!(check_claims(&good, "https://i.example", "d", "n", now).is_err());
    assert!(check_claims(&good, "https://i.example", "c", "n", now + 10 + CLOCK_SKEW_SECS + 1).is_err());
    for junk in ["", "a.b", "a.b.c.d", "!!.!!.!!", "e30.W10.", "bnVsbA.e30."] {
        assert!(decode_jwt(junk).is_err(), "{junk:?}");
    }
    let claims = serde_json::json!({"sub": "s", "email": "e@x"});
    let u = build_user(&claims, None).unwrap();
    assert_eq!((u.name.as_str(), u.email.as_deref()), ("e@x", Some("e@x")));
    let u =
        build_user(&serde_json::json!({"sub": "s"}), Some(&serde_json::json!({"sub": "s", "preferred_username": "pu", "groups": "one"}))).unwrap();
    assert_eq!((u.name.as_str(), u.groups.clone()), ("pu", vec!["one".to_string()]));
    assert!(build_user(&serde_json::json!({"sub": ""}), None).is_err());
    let user = |id: &str| User { id: id.into(), name: String::new(), email: None, email_verified: true, groups: vec![] };
    assert_eq!(user("1b2c-3d_e").folder(), "users/1b2c-3d_e");
    for odd in ["ABC", "a/b", "..", "h-abc", "-x", "é", &"a".repeat(200)] {
        let f = user(odd).folder();
        assert!(f.starts_with("users/h-") && f.len() == "users/h-".len() + 64, "{odd:?} → {f}");
    }
}
