//! Validated document paths: the only paths a backend ever sees.
//!
//! A path comes from the browser (URL, form field), so it is hostile: a [`DocPath`] is a relative,
//! `/`-separated path with no empty, `.` or `..` segment, no backslash, no control characters and
//! no leading or trailing whitespace in a segment, within [`MAX_PATH_BYTES`] and [`MAX_DEPTH`].
//! Backends join it under their own root, so it can never escape that root.

use std::fmt;

use super::StorageError;

/// The longest path accepted, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// The deepest folder nesting accepted.
pub const MAX_DEPTH: usize = 16;
/// The longest single segment, in bytes (most file systems allow 255).
pub const MAX_SEGMENT_BYTES: usize = 255;

/// A validated relative document path such as `reports/2026/q3.docx`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DocPath(String);

impl DocPath {
    /// Validates `raw` (leading and trailing `/` are ignored).
    pub fn parse(raw: &str) -> Result<Self, StorageError> {
        let bad = |why: &str| StorageError::InvalidPath(format!("{why}: {:?}", raw.chars().take(80).collect::<String>()));
        let trimmed = raw.trim_matches('/');
        if trimmed.is_empty() {
            return Err(bad("empty path"));
        }
        if trimmed.len() > MAX_PATH_BYTES {
            return Err(bad("path too long"));
        }
        let mut depth = 0usize;
        for seg in trimmed.split('/') {
            depth += 1;
            if depth > MAX_DEPTH {
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
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments, outermost first.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The last segment (the file name).
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The folder part (`""` at the root).
    pub fn parent(&self) -> &str {
        self.0.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
    }
}

impl fmt::Display for DocPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_paths() {
        assert_eq!(DocPath::parse("a.docx").unwrap().as_str(), "a.docx");
        assert_eq!(DocPath::parse("/x/y z/a.docx/").unwrap().as_str(), "x/y z/a.docx");
        assert_eq!(DocPath::parse("x/y/a.docx").unwrap().parent(), "x/y");
        assert_eq!(DocPath::parse("x/y/a.docx").unwrap().file_name(), "a.docx");
    }

    #[test]
    fn rejects_hostile_paths() {
        let deep = "a/".repeat(MAX_DEPTH + 1);
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        for raw in ["", "/", "..", "a/../b", "./a", "a//b", "a\\b", "c:x", "a\0b", "a\nb", " a", "a ", deep.as_str(), long.as_str()] {
            assert!(DocPath::parse(raw).is_err(), "{raw:?} must be refused");
        }
    }
}
