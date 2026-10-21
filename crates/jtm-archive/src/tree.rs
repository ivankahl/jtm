//! Walking an extracted install tree, failing on anything that cannot be read.
//!
//! Checks over an install, such as "every link points inside" or "this bin dir holds a file",
//! are only as strong as their walk: an entry skipped because it could not be read is one the
//! check never saw. So every read error here is returned, with the path it happened on, and
//! never treated as an empty directory.

use std::fmt;
use std::fs::{self, FileType};
use std::io;
use std::path::{Path, PathBuf};

/// One entry in a directory. `kind` describes the entry itself, never a link's target.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub kind: FileType,
}

/// A directory or entry that could not be read.
#[derive(Debug)]
pub struct ReadError {
    pub path: PathBuf,
    pub source: io::Error,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The entries of `dir`, sorted by path.
pub fn entries(dir: &Path) -> Result<Vec<Entry>, ReadError> {
    let failed = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ReadError { path, source }
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(failed(dir))? {
        let entry = entry.map_err(failed(dir))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(failed(&path))?;
        entries.push(Entry { path, kind });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Calls `visit` on every entry under `root`, depth first. A directory is visited before it
/// is read, so `visit` may make it readable; links are never followed.
pub fn walk<E: From<ReadError>>(
    root: &Path,
    mut visit: impl FnMut(&Entry) -> Result<(), E>,
) -> Result<(), E> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in entries(&dir)? {
            visit(&entry)?;
            if entry.kind.is_dir() {
                pending.push(entry.path);
            }
        }
    }
    Ok(())
}

/// `path` relative to `root` and `/`-separated, for messages: `.` for `root` itself, and
/// `path` unchanged when it is not under `root`.
pub fn display_rel(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    if rel.as_os_str().is_empty() {
        return ".".to_owned();
    }
    rel.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests;
