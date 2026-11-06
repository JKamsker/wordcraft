//! WordCraft server: hosts the web build (`apps/wordcraft-web`, built with trunk into `dist/web`)
//! and stores the documents it opens and saves in a pluggable backend.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

mod auth;
mod config;
mod html;
mod http;
mod storage;

use std::process::ExitCode;

use config::Command;

/// Logs to stderr at the level `WORDCRAFT_LOG` names (default `info`).
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            eprintln!("{now} {:<5} {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn init_logging() {
    let level = match std::env::var("WORDCRAFT_LOG").unwrap_or_default().to_ascii_lowercase().as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        "off" => log::LevelFilter::Off,
        _ => log::LevelFilter::Info,
    };
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}

/// Resolves on Ctrl-C (and SIGTERM on Unix).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::warn!("cannot listen for Ctrl-C: {e}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                log::warn!("cannot listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
    log::info!("shutting down");
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    let config = match config::parse(std::env::args().skip(1), |k| std::env::var(k).ok()) {
        Ok(Command::Run(c)) => c,
        Ok(Command::Help) => {
            print!("{}", config::USAGE);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("wordcraft-server: {e}");
            return ExitCode::from(2);
        }
    };
    let storage = match storage::open(&config.storage) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wordcraft-server: cannot open storage: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("wordcraft-server: cannot listen on {}: {e}", config.listen);
            return ExitCode::FAILURE;
        }
    };
    let addr = listener.local_addr().unwrap_or(config.listen);
    log::info!("storage: {}", storage.describe());
    if !config.web_root.join("index.html").is_file() {
        log::warn!("no index.html in {}: build the web app with `trunk build --release` in apps/wordcraft-web", config.web_root.display());
    }
    if config.auth.is_none() && !addr.ip().is_loopback() {
        log::warn!("listening on {addr} without --auth: anyone who can reach it can read and change the documents");
    }
    log::info!("WordCraft server on http://{addr}/ (web app at http://{addr}/app/)");
    let app = http::router(http::AppState {
        storage,
        max_bytes: config.max_bytes,
        web_root: config.web_root,
        auth: config.auth.as_deref().map(auth::BasicAuth::new),
    });
    if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await {
        log::error!("server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
