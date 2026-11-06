//! WordCraft server: hosts the web build (`apps/wordcraft-web`, built with trunk into `dist/web`)
//! and stores the documents it opens and saves in a pluggable backend.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

#[allow(dead_code)]
mod storage;

fn main() {
    eprintln!("wordcraft-server: in progress");
}
