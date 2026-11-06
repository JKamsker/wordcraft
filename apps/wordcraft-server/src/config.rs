//! Command-line and environment configuration (hand-rolled; see [`USAGE`]).

use std::net::SocketAddr;
use std::path::PathBuf;

/// The default listen address: this machine only.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8780";
/// The default storage: a `documents` folder in the working directory.
pub const DEFAULT_STORAGE: &str = "dir://./documents";
/// The default web build folder (`trunk build --release` in `apps/wordcraft-web`).
pub const DEFAULT_WEB_ROOT: &str = "dist/web";
/// The default largest document accepted or served: 256 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

pub const USAGE: &str = "\
wordcraft-server: serves the WordCraft web app and stores its documents

USAGE:
    wordcraft-server [OPTIONS]

OPTIONS:
    --listen <addr>      Address to listen on [default: 127.0.0.1:8780]
    --storage <url>      Where documents live [default: dir://./documents; env WORDCRAFT_STORAGE]
                           dir:///srv/docs | file:///srv/docs | /srv/docs   a directory
                           memory:                                          in memory (lost on exit)
                           s3://bucket/prefix  az://container/prefix  gs://bucket/prefix
                           ftp://user@host:21/folder  ftps://...  smb://user@host/share/folder
    --web-root <dir>     The web build to serve at /app/ [default: dist/web]
    --max-bytes <n>      Largest document accepted or served, in bytes; K, M and G suffixes
                         are binary multiples [default: 256M]
    --auth <user:pass>   Require HTTP Basic auth on every route [env WORDCRAFT_SERVER_AUTH;
                         prefer the environment: arguments are visible to other users]
    -h, --help           Print this help

OPENID CONNECT (sign in with Authentik, Keycloak, Entra ID...; not with --auth):
    --oidc-issuer <url>          The provider's issuer URL [env WORDCRAFT_OIDC_ISSUER], e.g.
                                 https://auth.example.com/application/o/wordcraft/
    --oidc-client-id <id>        The client ID [env WORDCRAFT_OIDC_CLIENT_ID]
                                 The client secret comes only from WORDCRAFT_OIDC_CLIENT_SECRET
                                 (leave it unset for a public client: PKCE only)
    --public-url <url>           The URL users open, e.g. https://docs.example.com/ (required with
                                 OIDC; the redirect URI is <url>auth/callback) [env WORDCRAFT_PUBLIC_URL]
    --oidc-scopes <scopes>       Space-separated, must include openid [default: openid profile email;
                                 env WORDCRAFT_OIDC_SCOPES]
    --oidc-allowed-groups <a,b>  Only members of one of these groups may sign in (the groups claim)
                                 [env WORDCRAFT_OIDC_ALLOWED_GROUPS]
    --oidc-allowed-emails <a,b>  Only these e-mail addresses may sign in [env WORDCRAFT_OIDC_ALLOWED_EMAILS]
                                 With both lists, matching either one is enough.
    --per-user-storage           Each user sees only their own folder users/<id>/ of the storage
                                 [env WORDCRAFT_PER_USER_STORAGE=1]
    --session-hours <n>          How long a sign-in lasts, 1 to 720 [default: 12; env WORDCRAFT_SESSION_HOURS]

ENVIRONMENT:
    WORDCRAFT_LOG        error | warn | info | debug | trace [default: info]
";

/// The default OpenID Connect scopes.
pub const DEFAULT_OIDC_SCOPES: &str = "openid profile email";
/// The default sign-in lifetime.
pub const DEFAULT_SESSION_HOURS: u64 = 12;
/// The longest sign-in lifetime accepted: 30 days.
pub const MAX_SESSION_HOURS: u64 = 720;

/// OpenID Connect sign-in settings.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The issuer as configured, without a trailing slash (compared with slash normalisation only).
    pub issuer: String,
    pub client_id: String,
    /// `None` for a public client (PKCE only).
    pub client_secret: Option<String>,
    /// The URL users open, ending in `/`.
    pub public_url: url::Url,
    /// Space-separated; always contains `openid`.
    pub scopes: String,
    pub allowed_groups: Vec<String>,
    /// Lower-cased.
    pub allowed_emails: Vec<String>,
    pub per_user_storage: bool,
    pub session_hours: u64,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .field("public_url", &self.public_url.as_str())
            .field("scopes", &self.scopes)
            .field("allowed_groups", &self.allowed_groups)
            .field("allowed_emails", &self.allowed_emails)
            .field("per_user_storage", &self.per_user_storage)
            .field("session_hours", &self.session_hours)
            .finish()
    }
}

/// Whether `url` is plain `http` to this machine (allowed for development and tests only).
pub fn is_loopback_http(url: &url::Url) -> bool {
    url.scheme() == "http"
        && match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
}

/// What the server runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub storage: String,
    pub web_root: PathBuf,
    pub max_bytes: u64,
    /// `user:password` for HTTP Basic auth.
    pub auth: Option<String>,
    /// OpenID Connect sign-in (never together with `auth`).
    pub oidc: Option<OidcConfig>,
}

/// The parse result.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Run(Box<Config>),
    Help,
}

/// Parses `args` (without the program name); `env` looks up environment variables.
pub fn parse(args: impl IntoIterator<Item = String>, env: impl Fn(&str) -> Option<String>) -> Result<Command, String> {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut storage = env("WORDCRAFT_STORAGE").filter(|s| !s.trim().is_empty());
    let mut web_root = PathBuf::from(DEFAULT_WEB_ROOT);
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let mut auth = env("WORDCRAFT_SERVER_AUTH").filter(|s| !s.is_empty());
    let nonempty = |k: &str| env(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut issuer = nonempty("WORDCRAFT_OIDC_ISSUER");
    let mut client_id = nonempty("WORDCRAFT_OIDC_CLIENT_ID");
    let client_secret = env("WORDCRAFT_OIDC_CLIENT_SECRET").filter(|s| !s.is_empty());
    let mut public_url = nonempty("WORDCRAFT_PUBLIC_URL");
    let mut scopes = nonempty("WORDCRAFT_OIDC_SCOPES");
    let mut groups = nonempty("WORDCRAFT_OIDC_ALLOWED_GROUPS");
    let mut emails = nonempty("WORDCRAFT_OIDC_ALLOWED_EMAILS");
    let mut per_user = match nonempty("WORDCRAFT_PER_USER_STORAGE") {
        Some(v) => parse_bool("WORDCRAFT_PER_USER_STORAGE", &v)?,
        None => false,
    };
    let mut session_hours = nonempty("WORDCRAFT_SESSION_HOURS");

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        if matches!(flag.as_str(), "-h" | "--help") {
            return Ok(Command::Help);
        }
        let mut value = || inline.clone().or_else(|| args.next()).ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => listen = value()?,
            "--storage" => storage = Some(value()?),
            "--web-root" => web_root = PathBuf::from(value()?),
            "--max-bytes" => max_bytes = parse_bytes(&value()?)?,
            "--auth" => auth = Some(value()?),
            "--oidc-issuer" => issuer = Some(value()?),
            "--oidc-client-id" => client_id = Some(value()?),
            "--public-url" => public_url = Some(value()?),
            "--oidc-scopes" => scopes = Some(value()?),
            "--oidc-allowed-groups" => groups = Some(value()?),
            "--oidc-allowed-emails" => emails = Some(value()?),
            "--session-hours" => session_hours = Some(value()?),
            "--per-user-storage" => per_user = inline.as_deref().map(|v| parse_bool("--per-user-storage", v)).transpose()?.unwrap_or(true),
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }

    let listen = listen.parse::<SocketAddr>().map_err(|e| format!("--listen {listen:?}: {e}"))?;
    if let Some(a) = &auth {
        match a.split_once(':') {
            Some((user, pass)) if !user.is_empty() && !pass.is_empty() => {}
            _ => return Err("--auth must be user:password with neither part empty".into()),
        }
    }
    let oidc = match issuer {
        None => {
            if client_id.is_some() || per_user || groups.is_some() || emails.is_some() {
                return Err("the OpenID Connect options need --oidc-issuer".into());
            }
            None
        }
        Some(issuer) => {
            if auth.is_some() {
                return Err("--auth and --oidc-issuer cannot be used together: pick one way to sign in".into());
            }
            let issuer_url = url::Url::parse(&issuer).map_err(|e| format!("--oidc-issuer {issuer:?}: {e}"))?;
            if issuer_url.scheme() != "https" && !is_loopback_http(&issuer_url) {
                return Err("--oidc-issuer must be an https:// URL (http:// only for localhost)".into());
            }
            if issuer_url.query().is_some() || issuer_url.fragment().is_some() {
                return Err("--oidc-issuer must not have a query or fragment".into());
            }
            let client_id = client_id.filter(|c| !c.trim().is_empty()).ok_or("--oidc-client-id is required with --oidc-issuer")?;
            let raw_public = public_url.ok_or("--public-url is required with --oidc-issuer (the redirect URI is <public url>auth/callback)")?;
            let mut public = url::Url::parse(&raw_public).map_err(|e| format!("--public-url {raw_public:?}: {e}"))?;
            if !matches!(public.scheme(), "http" | "https") || public.host().is_none() {
                return Err("--public-url must be an http:// or https:// URL".into());
            }
            if public.query().is_some() || public.fragment().is_some() || !public.username().is_empty() || public.password().is_some() {
                return Err("--public-url must not have credentials, a query or a fragment".into());
            }
            // The path becomes the cookie Path attribute.
            if public.path().contains([';', ',']) {
                return Err("--public-url must not contain ; or , in its path".into());
            }
            if !public.path().ends_with('/') {
                let path = format!("{}/", public.path());
                public.set_path(&path);
            }
            let scopes = scopes.unwrap_or_else(|| DEFAULT_OIDC_SCOPES.into());
            let scopes = scopes.split_whitespace().collect::<Vec<_>>().join(" ");
            if !scopes.split(' ').any(|s| s == "openid") {
                return Err("--oidc-scopes must include openid".into());
            }
            let session_hours = match session_hours {
                Some(raw) => raw.trim().parse::<u64>().map_err(|_| format!("--session-hours {raw:?} is not a number"))?,
                None => DEFAULT_SESSION_HOURS,
            };
            if !(1..=MAX_SESSION_HOURS).contains(&session_hours) {
                return Err(format!("--session-hours must be between 1 and {MAX_SESSION_HOURS}"));
            }
            Some(OidcConfig {
                issuer: issuer.trim_end_matches('/').to_string(),
                client_id: client_id.trim().to_string(),
                client_secret,
                public_url: public,
                scopes,
                allowed_groups: split_list(groups.as_deref()),
                allowed_emails: split_list(emails.as_deref()).into_iter().map(|e| e.to_lowercase()).collect(),
                per_user_storage: per_user,
                session_hours,
            })
        }
    };
    Ok(Command::Run(Box::new(Config { listen, storage: storage.unwrap_or_else(|| DEFAULT_STORAGE.into()), web_root, max_bytes, auth, oidc })))
}

/// `a, b,,c` → `["a", "b", "c"]`.
fn split_list(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

fn parse_bool(name: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(format!("{name} {raw:?} is not true or false")),
    }
}

/// `1048576`, `512K`, `256M`, `1G` (binary multiples).
fn parse_bytes(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    let (digits, mult) = match s.char_indices().last() {
        Some((i, 'k' | 'K')) => (&s[..i], 1u64 << 10),
        Some((i, 'm' | 'M')) => (&s[..i], 1 << 20),
        Some((i, 'g' | 'G')) => (&s[..i], 1 << 30),
        _ => (s, 1),
    };
    let n = digits.parse::<u64>().map_err(|_| format!("--max-bytes {raw:?} is not a size"))?;
    let bytes = n.checked_mul(mult).ok_or_else(|| format!("--max-bytes {raw:?} is too large"))?;
    if bytes == 0 {
        return Err("--max-bytes must be more than 0".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(|s| s.to_string()), |_| None)
    }

    #[test]
    fn defaults() {
        let Command::Run(c) = run(&[]).unwrap() else { panic!("help") };
        assert_eq!(c.listen.to_string(), DEFAULT_LISTEN);
        assert_eq!(c.storage, DEFAULT_STORAGE);
        assert_eq!(c.web_root, PathBuf::from("dist/web"));
        assert_eq!(c.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(c.auth, None);
    }

    #[test]
    fn flags_and_env() {
        let Command::Run(c) = run(&["--listen", "0.0.0.0:9000", "--storage=memory:", "--max-bytes", "2M", "--auth", "a:b:c"]).unwrap() else {
            panic!("help")
        };
        assert_eq!(c.listen.port(), 9000);
        assert_eq!(c.storage, "memory:");
        assert_eq!(c.max_bytes, 2 << 20);
        assert_eq!(c.auth.as_deref(), Some("a:b:c"));

        let env = |k: &str| match k {
            "WORDCRAFT_STORAGE" => Some("s3://b/p".to_string()),
            "WORDCRAFT_SERVER_AUTH" => Some("u:p".to_string()),
            _ => None,
        };
        let Command::Run(c) = parse(Vec::new(), env).unwrap() else { panic!("help") };
        assert_eq!(c.storage, "s3://b/p");
        assert_eq!(c.auth.as_deref(), Some("u:p"));
        assert_eq!(run(&["--help"]).unwrap(), Command::Help);
    }

    #[test]
    fn bad_input_is_an_error() {
        for args in [
            &["--listen"][..],
            &["--listen", "nope"],
            &["--bogus"],
            &["--max-bytes", "0"],
            &["--max-bytes", "99999999999G"],
            &["--max-bytes", "x"],
            &["--auth", "nopassword"],
            &["--auth", ":p"],
            &["--max-bytes", "é"],
        ] {
            assert!(run(args).is_err(), "{args:?}");
        }
    }

    const OIDC: [&str; 6] = [
        "--oidc-issuer",
        "https://auth.example.com/application/o/wordcraft/",
        "--oidc-client-id",
        "wc",
        "--public-url",
        "https://docs.example.com/wc",
    ];

    fn oidc(extra: &[&str]) -> Result<Command, String> {
        run(&[&OIDC[..], extra].concat())
    }

    #[test]
    fn oidc_flags_and_env() {
        let Command::Run(c) =
            oidc(&["--oidc-allowed-groups", "editors, admins,", "--oidc-allowed-emails", "Ann@Example.com", "--per-user-storage"]).unwrap()
        else {
            panic!("help")
        };
        let o = c.oidc.unwrap();
        assert_eq!(o.issuer, "https://auth.example.com/application/o/wordcraft");
        assert_eq!(o.client_id, "wc");
        assert_eq!(o.client_secret, None);
        assert_eq!(o.public_url.as_str(), "https://docs.example.com/wc/");
        assert_eq!(o.scopes, DEFAULT_OIDC_SCOPES);
        assert_eq!(o.allowed_groups, ["editors", "admins"]);
        assert_eq!(o.allowed_emails, ["ann@example.com"]);
        assert!(o.per_user_storage);
        assert_eq!(o.session_hours, DEFAULT_SESSION_HOURS);
        assert_eq!(c.auth, None);

        let env = |k: &str| {
            let v = match k {
                "WORDCRAFT_OIDC_ISSUER" => "http://127.0.0.1:9000/",
                "WORDCRAFT_OIDC_CLIENT_ID" => "id",
                "WORDCRAFT_OIDC_CLIENT_SECRET" => "top-secret",
                "WORDCRAFT_PUBLIC_URL" => "http://localhost:8780/",
                "WORDCRAFT_OIDC_SCOPES" => "openid  groups",
                "WORDCRAFT_SESSION_HOURS" => "2",
                "WORDCRAFT_PER_USER_STORAGE" => "true",
                _ => return None,
            };
            Some(v.to_string())
        };
        let Command::Run(c) = parse(Vec::new(), env).unwrap() else { panic!("help") };
        let o = c.oidc.unwrap();
        assert_eq!(o.issuer, "http://127.0.0.1:9000");
        assert_eq!(o.client_secret.as_deref(), Some("top-secret"));
        assert_eq!(o.scopes, "openid groups");
        assert_eq!(o.session_hours, 2);
        assert!(o.per_user_storage);
        assert!(!format!("{o:?}").contains("top-secret"));
    }

    #[test]
    fn oidc_bad_input_is_an_error() {
        // --auth and OIDC are exclusive, also when Basic auth comes from the environment.
        assert!(oidc(&["--auth", "a:b"]).unwrap_err().contains("cannot be used together"));
        let env = |k: &str| (k == "WORDCRAFT_SERVER_AUTH").then(|| "a:b".to_string());
        assert!(parse(OIDC.iter().map(|s| s.to_string()), env).is_err());
        // The public URL is required.
        assert!(run(&OIDC[..4]).unwrap_err().contains("--public-url"));
        // openid must be requested.
        assert!(oidc(&["--oidc-scopes", "profile email"]).unwrap_err().contains("openid"));
        for extra in [
            &["--session-hours", "0"][..],
            &["--session-hours", "721"],
            &["--session-hours", "x"],
            &["--oidc-issuer", "http://auth.example.com/"],
            &["--oidc-issuer", "not a url"],
            &["--oidc-issuer", "https://auth.example.com/?x=1"],
            &["--oidc-client-id", " "],
            &["--public-url", "ftp://docs.example.com/"],
            &["--public-url", "https://docs.example.com/?q"],
            &["--per-user-storage=maybe"],
        ] {
            assert!(oidc(extra).is_err(), "{extra:?}");
        }
        // OIDC options without an issuer.
        assert!(run(&["--oidc-client-id", "x"]).is_err());
        assert!(run(&["--per-user-storage"]).is_err());
        assert!(run(&["--oidc-issuer", "https://auth.example.com/", "--public-url", "https://d.example.com/"]).is_err());
    }
}
