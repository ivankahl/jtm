//! `state/trust.json`: keys the user trusts and the highest index sequences seen (SPEC.md
//! sections 9 and 14).
//!
//! ```json
//! {
//!   "format": 2,
//!   "keys": [{ "key": "RW...", "scope": ["acme/flyway"], "added": "2026-10-19T03:00:00Z" }],
//!   "keys_files": { "java": { "A1B2C3D4E5F60708": { "sequence": 7, "sha256": "..." } } },
//!   "indices": {
//!     "java": {
//!       "linux-x64": {
//!         "A1B2C3D4E5F60708": { "sequence": 412, "sha256": "...", "source": "remote" }
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Rollback state is kept per signing key as well as per plugin and platform. A key that is
//! retired (removed from a manifest or keys file, or expired) therefore stops constraining the
//! indices signed by its replacement. A leaked index key that claims `sequence = u64::MAX`
//! poisons only that key's own record; the genuine index signed by the next key is not blocked
//! and no manual state repair is needed. Format 1 kept one record per file with no signer, so it
//! cannot be attributed. It is migrated by dropping those records; the next load records fresh
//! ones per signer.
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
use crate::key::{KeyGroup, KeyId, PublicKey, Scope, TrustedKey, plugin_set};
use crate::time::Timestamp;

/// The only `trust.json` format this build reads and writes.
pub const TRUST_FORMAT: u64 = 2;
/// The first format, read only to migrate the user's trusted keys. Its rollback records carry no
/// signing key, so they are dropped.
const TRUST_FORMAT_LEGACY: u64 = 1;

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
    /// Newest keys file seen per plugin, then per signing key. First-party plugins share one
    /// file, recorded under each of them.
    pub keys_files: BTreeMap<String, BTreeMap<String, Seen>>,
    /// Highest sequence seen per plugin, then platform, then signing key.
    pub indices: BTreeMap<String, BTreeMap<String, BTreeMap<String, Seen>>>,
}

impl TrustState {
    /// The newest index seen for `plugin` on `platform`, across every signing key.
    pub fn seen_index(&self, plugin: &str, platform: &str) -> Option<&Seen> {
        self.index_floors(plugin, platform)
            .max_by_key(|seen| seen.sequence)
    }

    /// Every rollback floor recorded for `plugin` on `platform`, one per signing key.
    pub fn index_floors<'a>(
        &'a self,
        plugin: &str,
        platform: &str,
    ) -> impl Iterator<Item = &'a Seen> + 'a {
        self.indices
            .get(plugin)
            .and_then(|platforms| platforms.get(platform))
            .into_iter()
            .flat_map(|floors| floors.values())
    }

    /// The floor recorded for an index signed by `signer`.
    pub fn index_floor(&self, plugin: &str, platform: &str, signer: &KeyId) -> Option<&Seen> {
        self.indices
            .get(plugin)?
            .get(platform)?
            .get(&signer.to_string())
    }

    /// Records an accepted index for every key that signed it, keeping whichever copy has the
    /// higher sequence per key. A copy with no recorded signer cannot be attributed, so it
    /// records nothing.
    pub fn record_index(
        &mut self,
        plugin: &str,
        platform: &str,
        signers: &[KeyId],
        seen: Seen,
    ) -> bool {
        if signers.is_empty() {
            return false;
        }
        let floors = self
            .indices
            .entry(plugin.to_owned())
            .or_default()
            .entry(platform.to_owned())
            .or_default();
        record_all(floors, signers, seen)
    }

    /// The newest keys file seen for `plugin`, across every signing key.
    pub fn keys_file_newest(&self, plugin: &str) -> Option<&Seen> {
        self.keys_files
            .get(plugin)?
            .values()
            .max_by_key(|seen| seen.sequence)
    }

    /// The floor recorded for a keys file signed by `signer`.
    pub fn keys_file_floor(&self, plugin: &str, signer: &KeyId) -> Option<&Seen> {
        self.keys_files.get(plugin)?.get(&signer.to_string())
    }

    /// Records an accepted keys file for every anchor that signed it.
    pub fn record_keys_file(&mut self, plugin: &str, signers: &[KeyId], seen: Seen) -> bool {
        if signers.is_empty() {
            return false;
        }
        let floors = self.keys_files.entry(plugin.to_owned()).or_default();
        record_all(floors, signers, seen)
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
        let header: RawHeader = serde_json::from_slice(text).map_err(|e| corrupt(e.to_string()))?;
        match header.format {
            TRUST_FORMAT => {
                let raw: RawTrust =
                    serde_json::from_slice(text).map_err(|e| corrupt(e.to_string()))?;
                Ok(TrustState {
                    keys: parse_keys(raw.keys, path)?,
                    keys_files: raw.keys_files,
                    indices: raw.indices,
                })
            }
            TRUST_FORMAT_LEGACY => {
                let raw: RawTrustV1 =
                    serde_json::from_slice(text).map_err(|e| corrupt(e.to_string()))?;
                // Format 1 recorded one floor per file without attributing it to a key. Keeping
                // it as a global floor would let one leaked signer block every later key, which
                // is the poisoning this format exists to prevent. Drop the records; the next
                // load records fresh floors per signer. The trusted keys are preserved.
                Ok(TrustState {
                    keys: parse_keys(raw.keys, path)?,
                    keys_files: BTreeMap::new(),
                    indices: BTreeMap::new(),
                })
            }
            other => Err(corrupt(format!(
                "format {other} is not supported; this jtm reads format {TRUST_FORMAT}"
            ))),
        }
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

/// Records `seen` under every signing key, merging each with that key's existing floor.
fn record_all(floors: &mut BTreeMap<String, Seen>, signers: &[KeyId], seen: Seen) -> bool {
    let mut changed = false;
    for signer in signers {
        changed |= record(floors.entry(signer.to_string()), seen.clone());
    }
    changed
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

/// Just the format tag, read first so the right body can be decoded.
#[derive(Deserialize)]
struct RawHeader {
    format: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    format: u64,
    #[serde(default)]
    keys: Vec<RawKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys_files: BTreeMap<String, BTreeMap<String, Seen>>,
    #[serde(default)]
    indices: BTreeMap<String, BTreeMap<String, BTreeMap<String, Seen>>>,
}

/// Format 1 kept one floor per file, with no signing key. Only `keys` is migrated.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrustV1 {
    #[allow(dead_code)]
    format: u64,
    #[serde(default)]
    keys: Vec<RawKey>,
    #[serde(default)]
    #[allow(dead_code)]
    keys_files: BTreeMap<String, Seen>,
    #[serde(default)]
    #[allow(dead_code)]
    indices: BTreeMap<String, BTreeMap<String, Seen>>,
}

fn parse_keys(keys: Vec<RawKey>, path: &Path) -> Result<Vec<UserKey>> {
    let corrupt = |message: String| Error::State {
        path: path.to_path_buf(),
        message,
    };
    let mut out = Vec::with_capacity(keys.len());
    for (i, k) in keys.into_iter().enumerate() {
        let key = PublicKey::parse(&k.key).map_err(|e| corrupt(format!("keys[{i}]: {e}")))?;
        let scope = plugin_set(k.scope).map_err(|e| corrupt(format!("keys[{i}]: {e}")))?;
        let added = Timestamp::parse(&k.added)
            .ok_or_else(|| corrupt(format!("keys[{i}].added is not a UTC time")))?;
        out.push(UserKey { key, scope, added });
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key: String,
    scope: Vec<String>,
    added: String,
}

#[cfg(test)]
mod tests;
