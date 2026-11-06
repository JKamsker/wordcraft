//! Optional HTTP Basic auth on every route.
//!
//! Browsers remember the credentials after the first prompt and send them with the web app's own
//! same-origin `fetch` calls, so the wasm client needs no login code. Use it behind TLS (a reverse
//! proxy) when the server is reachable from other machines: Basic auth is not encryption.

use base64::Engine as _;

/// The longest `Authorization` header looked at.
const MAX_HEADER_BYTES: usize = 4096;

/// The expected `user:password`.
#[derive(Clone)]
pub struct BasicAuth {
    expected: Vec<u8>,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BasicAuth(<redacted>)")
    }
}

impl BasicAuth {
    pub fn new(user_password: &str) -> Self {
        Self { expected: user_password.as_bytes().to_vec() }
    }

    /// Whether an `Authorization` header value carries the expected credentials.
    pub fn accepts(&self, header: Option<&[u8]>) -> bool {
        let Some(header) = header else { return false };
        if header.len() > MAX_HEADER_BYTES {
            return false;
        }
        let Some(encoded) = header.strip_prefix(b"Basic ").or_else(|| header.strip_prefix(b"basic ")) else { return false };
        let encoded = encoded.trim_ascii();
        let Ok(given) = base64::engine::general_purpose::STANDARD.decode(encoded) else { return false };
        constant_time_eq(&given, &self.expected)
    }
}

/// Compares without an early exit, so the time taken does not reveal how much matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(user_pass: &str) -> Vec<u8> {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(user_pass)).into_bytes()
    }

    #[test]
    fn checks_credentials() {
        let auth = BasicAuth::new("ann:s3cret");
        assert!(auth.accepts(Some(&header("ann:s3cret"))));
        assert!(!auth.accepts(Some(&header("ann:s3cre"))));
        assert!(!auth.accepts(Some(&header("ann:s3crett"))));
        assert!(!auth.accepts(Some(&header("bob:s3cret"))));
        assert!(!auth.accepts(Some(b"Bearer abc")));
        assert!(!auth.accepts(Some(b"Basic !!!")));
        assert!(!auth.accepts(Some(&vec![b'a'; MAX_HEADER_BYTES + 1])));
        assert!(!auth.accepts(None));
        assert!(!format!("{auth:?}").contains("s3cret"));
    }
}
