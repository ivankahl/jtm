//! `state/trust.json`: the highest index and keys file sequences seen, for rollback protection
//! (SPEC.md sections 9 and 14).
//!
//! ```json
//! {
//!   "format": 1,
//!   "keys_files": { "java": { "sequence": 7, "sha256": "..." } },
//!   "indices": { "java": { "linux-x64": { "sequence": 412, "sha256": "...", "source": "remote" } } }
//! }
//! ```
//!
//! The file holds no keys. Company keys live in the user config (`plugins.<name>.signing_keys`)
//! and the anchors are compiled into jtm. A file written by an earlier jtm may still hold the
//! `keys` list that `jtm trust add` kept; it is ignored on load and dropped on the next write.
//!
//! The file lives in the user's data directory, which project files cannot touch. Updates take
//! an exclusive lock on `trust.json.lock`, re-read the file, and replace it atomically, so
//! parallel jtm processes never lose each other's writes or lower a recorded sequence.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The only `trust.json` format this build reads and writes.
pub const TRUST_FORMAT: u64 = 1;

/// Where an index copy came from. It decides whether an expired index is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// The snapshot embedded in the jtm binary.
    Embedded,
    /// A verified copy jtm saved in its cache. Its expiry is judged by the source it was
    /// saved from.
    Cache,
    /// The canonical remote named in the plugin manifest.
    Remote,
    /// A configured `index_url` override, `[mirrors]` rewrite or local path.
    Mirror,
}

impl SourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            SourceKind::Embedded => "embedded",
            SourceKind::Cache => "cache",
            SourceKind::Remote => "remote",
            SourceKind::Mirror => "mirror",
        }
    }
}

/// The newest copy of a signed file seen so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seen {
    pub sequence: u64,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Where the accepted copy came from. Absent for keys files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceKind>,
}

/// The contents of `trust.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustState {
    /// Newest keys file seen per plugin. First-party plugins share one file, recorded under
    /// each of them.
    pub keys_files: BTreeMap<String, Seen>,
    /// Highest sequence seen per plugin, then per platform.
    pub indices: BTreeMap<String, BTreeMap<String, Seen>>,
}

impl TrustState {
    /// The newest index seen for `plugin` on `platform`.
    pub fn seen_index(&self, plugin: &str, platform: &str) -> Option<&Seen> {
        self.indices.get(plugin)?.get(platform)
    }

    /// Records an accepted index, keeping whichever copy has the higher sequence.
    pub fn record_index(&mut self, plugin: &str, platform: &str, seen: Seen) -> bool {
        let slot = self
            .indices
            .entry(plugin.to_owned())
            .or_default()
            .entry(platform.to_owned());
        record(slot, seen)
    }

    /// Records an accepted keys file for `plugin`.
    pub fn record_keys_file(&mut self, plugin: &str, seen: Seen) -> bool {
        match self.keys_files.get(plugin) {
            Some(old) if old.sequence >= seen.sequence => false,
            _ => {
                self.keys_files.insert(plugin.to_owned(), seen);
                true
            }
        }
    }

    /// Parses `trust.json`. `path` is only used in messages.
    pub fn parse(text: &[u8], path: &Path) -> Result<TrustState> {
        let corrupt = |message: String| Error::State {
            path: path.to_path_buf(),
            message,
        };
        let raw: RawTrust = serde_json::from_slice(text).map_err(|e| corrupt(e.to_string()))?;
        if raw.format != TRUST_FORMAT {
            return Err(corrupt(format!(
                "format {} is not supported; this jtm reads format {TRUST_FORMAT}",
                raw.format
            )));
        }
        Ok(TrustState {
            keys_files: raw.keys_files,
            indices: raw.indices,
        })
    }

    /// Serialises the state as pretty JSON with a trailing newline.
    pub fn to_json(&self) -> Vec<u8> {
        let raw = RawTrust {
            format: TRUST_FORMAT,
            _old_keys: IgnoredAny,
            keys_files: self.keys_files.clone(),
            indices: self.indices.clone(),
        };
        let mut out = serde_json::to_vec_pretty(&raw).unwrap_or_default();
        out.push(b'\n');
        out
    }

    /// Reads `path`, or returns an empty state when it does not exist.
    pub fn load(path: &Path) -> Result<TrustState> {
        match fs::read(path) {
            Ok(bytes) => TrustState::parse(&bytes, path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(TrustState::default()),
            Err(e) => Err(io_error(path, e)),
        }
    }

    /// Applies `change` to the state at `path` under an exclusive lock, and writes the result
    /// atomically when `change` reports a change. Returns what `change` returned.
    pub fn update<T>(
        path: &Path,
        change: impl FnOnce(&mut TrustState) -> Result<(T, bool)>,
    ) -> Result<(T, bool)> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
        let lock_path = sibling(path, "lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| io_error(&lock_path, e))?;
        lock.lock().map_err(|e| io_error(&lock_path, e))?;

        let mut state = TrustState::load(path)?;
        let (value, changed) = change(&mut state)?;
        if changed {
            write_atomically(path, &state.to_json())?;
        }
        drop(lock);
        Ok((value, changed))
    }
}

/// Keeps the higher sequence. An equal sequence keeps the first hash seen; the rollback check
/// refuses a copy that disagrees with it. An equal sequence with the same bytes may update
/// where the copy came from, but only towards a stricter expiry policy.
fn record(slot: std::collections::btree_map::Entry<'_, String, Seen>, seen: Seen) -> bool {
    use std::collections::btree_map::Entry;
    match slot {
        Entry::Vacant(v) => {
            v.insert(seen);
            true
        }
        Entry::Occupied(mut o) => {
            let old = o.get();
            let newer = seen.sequence > old.sequence;
            // A copy with the same content from a source with a different expiry policy may
            // update where it came from, but only from the canonical remote: `check_index`
            // judges a cached copy by its recorded source, so re-recording a remote copy as
            // embedded or mirrored would turn an expired index from an error into a warning.
            let same_but_moved = seen.sequence == old.sequence
                && seen.sha256 == old.sha256
                && seen.source == Some(SourceKind::Remote)
                && old.source != Some(SourceKind::Remote);
            if newer || same_but_moved {
                o.insert(seen);
                true
            } else {
                false
            }
        }
    }
}

/// Writes `bytes` to a temporary file next to `path`, flushes it, and renames it over `path`.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = sibling(path, &format!("{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error(path, e)
    })
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    format: u64,
    // SPEC-QUESTION: ADR-0002 removes the user key list from `trust.json` without saying what
    // happens to a file that still has one. Keeping format 1 and ignoring the list is the
    // least disruptive reading: no command fails on an old file, and the keys stop counting,
    // which only narrows trust. Their contents are never parsed, so a malformed old list
    // cannot fail a command either.
    /// The `jtm trust add` keys of earlier builds: read and ignored, never written.
    #[serde(default, rename = "keys", skip_serializing)]
    _old_keys: IgnoredAny,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys_files: BTreeMap<String, Seen>,
    #[serde(default)]
    indices: BTreeMap<String, BTreeMap<String, Seen>>,
}

#[cfg(test)]
mod tests;
