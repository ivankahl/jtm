//! Keys files: a plugin's list of delegated, short-lived index keys, signed by the plugin's
//! trust anchors (SPEC.md section 9).
//!
//! ```json
//! {
//!   "format": 1,
//!   "sequence": 7,
//!   "threshold": 1,
//!   "keys": [
//!     { "key": "RW...", "scope": ["java", "maven"], "expires": "2027-01-17T00:00:00Z" }
//!   ]
//! }
//! ```
//!
//! A plugin whose manifest sets `[index] keys_url` publishes one. It is verified against the
//! plugin's trust anchors before it is parsed. `threshold` is how many distinct listed keys must
//! sign each index; `sequence` grows with every publish so an old file, which may still list a
//! revoked key, can be refused (rollback checks live with the rest of the trust state). The
//! first-party plugins share one keys file signed by the jtm root keys, so `scope` names which
//! of them each key may sign for; a key is only ever used for a plugin its scope names.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::anchors::TrustAnchors;
use crate::error::{Error, Result};
use crate::key::{KeyGroup, PublicKey, Scope, TrustedKey};
use crate::signature::{self, Subject, Verified};
use crate::time::Timestamp;

/// The only keys file format this build understands.
pub const KEYS_FORMAT: u64 = 1;
/// The file name, used in messages and for the signature next to it.
pub const KEYS_FILE: &str = "keys.json";
/// The largest keys file accepted.
pub const MAX_KEYS_FILE: usize = 1024 * 1024;

/// A verified keys file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysFile {
    // SPEC-QUESTION: section 9 gives every listed key "a scope, a sequence and an expires date".
    // A sequence per key would not stop an old file from being replayed, so the sequence is
    // per file and rollback-checked like an index; each key has its own scope and expiry.
    pub sequence: u64,
    /// How many distinct listed keys must sign an index.
    pub threshold: u32,
    pub keys: Vec<IndexKey>,
    /// Lowercase hex SHA-256 of the raw bytes, for rollback checks.
    pub sha256: String,
    /// Which anchor keys signed it.
    pub verified: Verified,
}

/// One index-signing key listed in a keys file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexKey {
    pub key: PublicKey,
    pub scope: Scope,
    pub expires: Timestamp,
}

impl KeysFile {
    /// Verifies `data` against `anchors`, then parses it. Nothing in `data` is parsed until the
    /// anchor signatures meet their threshold. Delegated keys never sign a keys file.
    pub fn load(
        data: &[u8],
        signatures: &[u8],
        anchors: &TrustAnchors,
        now: Timestamp,
    ) -> Result<KeysFile> {
        let invalid = |message: String| Error::Invalid {
            file: KEYS_FILE.to_owned(),
            message,
        };
        if data.len() > MAX_KEYS_FILE {
            return Err(invalid(format!("larger than {MAX_KEYS_FILE} bytes")));
        }
        let subject = Subject {
            file: KEYS_FILE,
            plugin: &anchors.plugin,
        };
        let anchors_only = crate::key::Keyring::new().with(anchors.group());
        let verified = signature::verify(data, signatures, &anchors_only, subject, now)?;
        let raw: RawKeysFile = serde_json::from_slice(data).map_err(|e| invalid(e.to_string()))?;
        raw.validate(crate::sha256_hex(data), verified)
            .map_err(invalid)
    }

    /// The listed keys as a group that verifies indices. Expired keys stay in the group so a
    /// signature by one is reported as expired rather than unknown; [`signature::verify`]
    /// never accepts it.
    pub fn group(&self) -> KeyGroup {
        KeyGroup {
            origin: KEYS_FILE.to_owned(),
            keys: self
                .keys
                .iter()
                .map(|k| TrustedKey {
                    key: k.key.clone(),
                    scope: k.scope.clone(),
                    expires: Some(k.expires),
                })
                .collect(),
            threshold: self.threshold,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeysFile {
    format: u64,
    sequence: u64,
    threshold: u32,
    keys: Vec<RawKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key: String,
    scope: Vec<String>,
    expires: String,
}

impl RawKeysFile {
    fn validate(self, sha256: String, verified: Verified) -> std::result::Result<KeysFile, String> {
        if self.format != KEYS_FORMAT {
            return Err(format!(
                "format {} is not supported; this jtm reads format {KEYS_FORMAT}",
                self.format
            ));
        }
        if self.keys.is_empty() {
            return Err("lists no keys".to_owned());
        }
        let count = u32::try_from(self.keys.len()).unwrap_or(u32::MAX);
        if self.threshold == 0 || self.threshold > count {
            return Err(format!(
                "threshold {} must be between 1 and the {count} keys listed",
                self.threshold
            ));
        }
        let mut seen = BTreeSet::new();
        let mut keys = Vec::with_capacity(self.keys.len());
        for (i, raw) in self.keys.into_iter().enumerate() {
            let key = PublicKey::parse(&raw.key).map_err(|e| format!("keys[{i}].key: {e}"))?;
            if !seen.insert(key.id()) {
                return Err(format!("keys[{i}].key: key {} is listed twice", key.id()));
            }
            let scope = Scope::plugins(raw.scope).map_err(|e| format!("keys[{i}].scope: {e}"))?;
            let expires = Timestamp::parse(&raw.expires).ok_or_else(|| {
                format!(
                    "keys[{i}].expires: `{}` is not a UTC time like 2026-10-19T03:00:00Z",
                    raw.expires
                )
            })?;
            keys.push(IndexKey {
                key,
                scope,
                expires,
            });
        }
        Ok(KeysFile {
            sequence: self.sequence,
            threshold: self.threshold,
            keys,
            sha256,
            verified,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rotation_tests;
