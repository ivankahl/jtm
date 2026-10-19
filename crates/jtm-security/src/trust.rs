//! `state/trust.json`: keys the user trusts and the highest index sequences seen (SPEC.md
//! sections 9 and 14).
//!
//! ```json
//! {
//!   "format": 1,
//!   "keys": [{ "key": "RW...", "scope": ["acme/flyway"], "added": "2026-10-19T03:00:00Z" }],
//!   "keys_files": { "java": { "sequence": 7, "sha256": "..." } },
//!   "indices": { "java": { "linux-x64": { "sequence": 412, "sha256": "...", "source": "remote" } } }
//! }
//! ```
//!
//! The file lives in the user's data directory, which project files cannot touch. Updates take
//! an exclusive lock on `trust.json.lock`, re-read the file, and replace it atomically, so
//! parallel jtm processes never lose each other's writes or lower a recorded sequence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::key::{KeyGroup, PublicKey, Scope, TrustedKey, plugin_set};
use crate::time::Timestamp;

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

/// A key the user trusts with `jtm trust add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserKey {
    pub key: PublicKey,
    pub scope: BTreeSet<String>,
    pub added: Timestamp,
}

/// The contents of `trust.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustState {
    pub keys: Vec<UserKey>,
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

    /// Whether the user trusts `key` for `plugin`.
    pub fn trusts(&self, key: &PublicKey, plugin: &str) -> bool {
        self.keys
            .iter()
            .any(|k| k.key == *key && k.scope.contains(plugin))
    }

    /// Adds `key` for `scope`, merging with any scopes it already has. Returns whether anything
    /// changed.
    pub fn add_key(&mut self, key: PublicKey, scope: BTreeSet<String>, now: Timestamp) -> bool {
        match self.keys.iter_mut().find(|k| k.key == key) {
            Some(existing) => {
                let before = existing.scope.len();
                existing.scope.extend(scope);
                existing.scope.len() != before
            }
            None => {
                self.keys.push(UserKey {
                    key,
                    scope,
                    added: now,
                });
                true
            }
        }
    }

    /// Removes `scope` from the keys matching `key` (a public key or a key id), or the whole key
    /// when `scope` is empty or covers every plugin it had. Returns whether anything changed.
    pub fn remove_key(&mut self, key: &str, scope: &BTreeSet<String>) -> bool {
        let matches = |k: &UserKey| k.key.as_str() == key || k.key.id().to_string() == key;
        let mut changed = false;
        for k in self.keys.iter_mut().filter(|k| matches(k)) {
            if scope.is_empty() {
                k.scope.clear();
                changed = true;
            } else {
                let before = k.scope.len();
                k.scope.retain(|p| !scope.contains(p));
                changed |= k.scope.len() != before;
            }
        }
        self.keys.retain(|k| !k.scope.is_empty());
        changed
    }

    /// The user's keys as a group that verifies indices on its own.
    pub fn user_group(&self) -> KeyGroup {
        KeyGroup {
            origin: "user trust store".to_owned(),
            keys: self
                .keys
                .iter()
                .map(|k| TrustedKey {
                    key: k.key.clone(),
                    scope: Scope::from_set(k.scope.clone()),
                    expires: None,
                })
                .collect(),
            threshold: 1,
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
        let mut keys = Vec::with_capacity(raw.keys.len());
        for (i, k) in raw.keys.into_iter().enumerate() {
            let key = PublicKey::parse(&k.key).map_err(|e| corrupt(format!("keys[{i}]: {e}")))?;
            let scope = plugin_set(k.scope).map_err(|e| corrupt(format!("keys[{i}]: {e}")))?;
            let added = Timestamp::parse(&k.added)
                .ok_or_else(|| corrupt(format!("keys[{i}].added is not a UTC time")))?;
            keys.push(UserKey { key, scope, added });
        }
        Ok(TrustState {
            keys,
            keys_files: raw.keys_files,
            indices: raw.indices,
        })
    }

    /// Serialises the state as pretty JSON with a trailing newline.
    pub fn to_json(&self) -> Vec<u8> {
        let raw = RawTrust {
            format: TRUST_FORMAT,
            keys: self
                .keys
                .iter()
                .map(|k| RawKey {
                    key: k.key.as_str().to_owned(),
                    scope: k.scope.iter().cloned().collect(),
                    added: k.added.to_string(),
                })
                .collect(),
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
/// refuses a copy that disagrees with it.
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
            // A copy with the same content from a source with a different expiry policy, such
            // as a mirror copy of what was first seen embedded, updates where it came from.
            let same_but_moved = seen.sequence == old.sequence
                && seen.sha256 == old.sha256
                && seen.source != old.source
                && seen.source != Some(SourceKind::Cache);
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
    #[serde(default)]
    keys: Vec<RawKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys_files: BTreeMap<String, Seen>,
    #[serde(default)]
    indices: BTreeMap<String, BTreeMap<String, Seen>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key: String,
    scope: Vec<String>,
    added: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestKey;

    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);

    fn seen(sequence: u64, sha: &str, source: SourceKind) -> Seen {
        Seen {
            sequence,
            sha256: sha.into(),
            source: Some(source),
        }
    }

    fn scope(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn round_trips_through_json() {
        let key = TestKey::generate();
        let mut state = TrustState::default();
        state.add_key(key.public(), scope(&["acme/flyway", "demo"]), NOW);
        state.record_keys_file(
            "demo",
            Seen {
                sequence: 3,
                sha256: "aa".into(),
                source: None,
            },
        );
        state.record_index("demo", "linux-x64", seen(7, "bb", SourceKind::Remote));
        let json = state.to_json();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains(r#""source": "remote""#), "{text}");
        assert_eq!(TrustState::parse(&json, Path::new("t")).unwrap(), state);
    }

    #[test]
    fn corrupt_state_is_an_error_not_a_reset() {
        for bad in [
            &b"{"[..],
            br#"{"format":2}"#,
            br#"{"format":1,"keys":[{"key":"nope","scope":["demo"],"added":"2026-10-19T03:00:00Z"}]}"#,
            br#"{"format":1,"keys":[{"key":"RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB","scope":[],"added":"2026-10-19T03:00:00Z"}]}"#,
            br#"{"format":1,"surprise":true}"#,
        ] {
            let err = TrustState::parse(bad, Path::new("state/trust.json")).unwrap_err();
            assert!(matches!(err, Error::State { .. }), "{err:?}");
        }
    }

    #[test]
    fn records_only_move_forward() {
        let mut state = TrustState::default();
        assert!(state.record_index("demo", "linux-x64", seen(5, "a", SourceKind::Remote)));
        assert!(!state.record_index("demo", "linux-x64", seen(4, "b", SourceKind::Remote)));
        assert!(!state.record_index("demo", "linux-x64", seen(5, "c", SourceKind::Remote)));
        assert!(!state.record_index("demo", "linux-x64", seen(5, "a", SourceKind::Cache)));
        assert!(state.record_index("demo", "linux-x64", seen(5, "a", SourceKind::Mirror)));
        assert!(state.record_index("demo", "linux-x64", seen(6, "d", SourceKind::Embedded)));
        assert_eq!(state.seen_index("demo", "linux-x64").unwrap().sha256, "d");
        assert_eq!(state.seen_index("demo", "macos-x64"), None);

        assert!(state.record_keys_file("demo", seen(2, "k", SourceKind::Remote)));
        assert!(!state.record_keys_file("demo", seen(1, "j", SourceKind::Remote)));
        assert!(state.record_keys_file("other", seen(1, "j", SourceKind::Remote)));
    }

    #[test]
    fn adding_and_removing_keys_is_idempotent() {
        let (a, b) = (TestKey::generate(), TestKey::generate());
        let mut state = TrustState::default();
        assert!(state.add_key(a.public(), scope(&["demo"]), NOW));
        assert!(!state.add_key(a.public(), scope(&["demo"]), NOW));
        assert!(state.add_key(a.public(), scope(&["other"]), NOW));
        assert!(state.add_key(b.public(), scope(&["demo"]), NOW));
        assert_eq!(state.keys[0].scope, scope(&["demo", "other"]));

        assert!(state.remove_key(&a.public_str(), &scope(&["other"])));
        assert_eq!(state.keys[0].scope, scope(&["demo"]));
        assert!(!state.remove_key(&a.public_str(), &scope(&["other"])));
        assert!(state.remove_key(&a.public().id().to_string(), &BTreeSet::new()));
        assert!(!state.remove_key(&a.public_str(), &BTreeSet::new()));
        assert_eq!(state.keys.len(), 1);
        assert_eq!(state.keys[0].key, b.public());
        assert!(state.remove_key(&b.public_str(), &scope(&["demo"])));
        assert!(state.keys.is_empty(), "a key with no scope left is removed");
    }

    #[test]
    fn user_group_is_scoped_and_never_expires() {
        let key = TestKey::generate();
        let mut state = TrustState::default();
        state.add_key(key.public(), scope(&["demo"]), NOW);
        let group = state.user_group();
        assert_eq!(group.threshold, 1);
        assert!(group.keys[0].scope.covers("demo"));
        assert!(!group.keys[0].scope.covers("other"));
        assert!(state.trusts(&key.public(), "demo"));
        assert!(!state.trusts(&key.public(), "other"));
        assert_eq!(group.keys[0].expires, None);
    }

    #[test]
    fn update_persists_under_a_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("trust.json");
        assert_eq!(TrustState::load(&path).unwrap(), TrustState::default());

        let ((), changed) = TrustState::update(&path, |state| {
            Ok((
                (),
                state.record_index("demo", "linux-x64", seen(3, "a", SourceKind::Remote)),
            ))
        })
        .unwrap();
        assert!(changed);
        let ((), changed) = TrustState::update(&path, |state| {
            Ok((
                (),
                state.record_index("demo", "linux-x64", seen(2, "b", SourceKind::Remote)),
            ))
        })
        .unwrap();
        assert!(!changed);
        let state = TrustState::load(&path).unwrap();
        assert_eq!(state.seen_index("demo", "linux-x64").unwrap().sequence, 3);
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn parallel_updates_never_lose_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        std::thread::scope(|s| {
            for i in 0..8u64 {
                let path = &path;
                s.spawn(move || {
                    TrustState::update(path, |state| {
                        let platform = format!("p{i}");
                        let changed =
                            state.record_index("demo", &platform, seen(i, "a", SourceKind::Remote));
                        Ok(((), changed))
                    })
                    .unwrap();
                });
            }
        });
        let state = TrustState::load(&path).unwrap();
        assert_eq!(state.indices["demo"].len(), 8);
    }
}
