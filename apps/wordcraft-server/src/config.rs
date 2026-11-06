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

ENVIRONMENT:
    WORDCRAFT_LOG        error | warn | info | debug | trace [default: info]
";

/// What the server runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub storage: String,
    pub web_root: PathBuf,
    pub max_bytes: u64,
    /// `user:password` for HTTP Basic auth.
    pub auth: Option<String>,
}

/// The parse result.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Run(Config),
    Help,
}

/// Parses `args` (without the program name); `env` looks up environment variables.
pub fn parse(args: impl IntoIterator<Item = String>, env: impl Fn(&str) -> Option<String>) -> Result<Command, String> {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut storage = env("WORDCRAFT_STORAGE").filter(|s| !s.trim().is_empty());
    let mut web_root = PathBuf::from(DEFAULT_WEB_ROOT);
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let mut auth = env("WORDCRAFT_SERVER_AUTH").filter(|s| !s.is_empty());

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
    Ok(Command::Run(Config { listen, storage: storage.unwrap_or_else(|| DEFAULT_STORAGE.into()), web_root, max_bytes, auth }))
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
}
