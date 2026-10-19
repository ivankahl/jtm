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
mod tests {
    use super::*;
    use crate::key::Keyring;
    use crate::testing::TestKey;

    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
    const LATER: &str = "2027-12-31T00:00:00Z";
    const EARLIER: &str = "2026-01-01T00:00:00Z";
    const INDEX: &[u8] = br#"{"plugin":"demo"}"#;

    fn root(keys: &[&TestKey], threshold: u32) -> TrustAnchors {
        TrustAnchors {
            plugin: "demo".into(),
            keys: keys.iter().map(|k| k.public()).collect(),
            threshold,
        }
    }

    fn keys_json(threshold: u32, keys: &[(&TestKey, &[&str], &str)]) -> Vec<u8> {
        let keys: Vec<_> = keys
            .iter()
            .map(|(k, scope, expires)| {
                serde_json::json!({ "key": k.public_str(), "scope": scope, "expires": expires })
            })
            .collect();
        serde_json::to_vec_pretty(&serde_json::json!({
            "format": 1, "sequence": 3, "threshold": threshold, "keys": keys
        }))
        .unwrap()
    }

    fn index_subject() -> Subject<'static> {
        Subject {
            file: "demo-linux-x64.json",
            plugin: "demo",
        }
    }

    #[test]
    fn root_threshold_one() {
        let (r1, idx) = (TestKey::generate(), TestKey::generate());
        let data = keys_json(1, &[(&idx, &["demo"], LATER)]);
        let file = KeysFile::load(&data, &r1.sign(&data), &root(&[&r1], 1), NOW).unwrap();
        assert_eq!(file.sequence, 3);
        assert_eq!(file.threshold, 1);
        assert_eq!(file.keys[0].key, idx.public());
        assert_eq!(file.verified.signers, vec![r1.public().id()]);
    }

    #[test]
    fn root_threshold_two_of_three() {
        let (r1, r2, r3, idx) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let trust = root(&[&r1, &r2, &r3], 2);
        let data = keys_json(1, &[(&idx, &["demo"], LATER)]);

        let err = KeysFile::load(&data, &r2.sign(&data), &trust, NOW).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");

        let sigs = [r1.sign(&data), r3.sign(&data)].concat();
        let file = KeysFile::load(&data, &sigs, &trust, NOW).unwrap();
        assert_eq!(file.verified.signers.len(), 2);
    }

    #[test]
    fn index_threshold_one_and_two() {
        let (r, a, b) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        for threshold in [1, 2] {
            let data = keys_json(threshold, &[(&a, &["demo"], LATER), (&b, &["demo"], LATER)]);
            let file = KeysFile::load(&data, &r.sign(&data), &root(&[&r], 1), NOW).unwrap();
            let ring = Keyring::new().with(file.group());

            let one = signature::verify(INDEX, &a.sign(INDEX), &ring, index_subject(), NOW);
            assert_eq!(one.is_ok(), threshold == 1, "threshold {threshold}");

            let both = [a.sign(INDEX), b.sign(INDEX)].concat();
            signature::verify(INDEX, &both, &ring, index_subject(), NOW).unwrap();
        }
    }

    #[test]
    fn expired_index_key_is_rejected() {
        let (r, old, current) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let data = keys_json(
            1,
            &[(&old, &["demo"], EARLIER), (&current, &["demo"], LATER)],
        );
        let file = KeysFile::load(&data, &r.sign(&data), &root(&[&r], 1), NOW).unwrap();
        let ring = Keyring::new().with(file.group());
        let err =
            signature::verify(INDEX, &old.sign(INDEX), &ring, index_subject(), NOW).unwrap_err();
        assert!(
            err.to_string().contains("expired at 2026-01-01T00:00:00Z"),
            "{err}"
        );
        signature::verify(INDEX, &current.sign(INDEX), &ring, index_subject(), NOW).unwrap();
    }

    #[test]
    fn out_of_scope_index_key_is_rejected() {
        let (r, other) = (TestKey::generate(), TestKey::generate());
        let data = keys_json(1, &[(&other, &["other"], LATER)]);
        let file = KeysFile::load(&data, &r.sign(&data), &root(&[&r], 1), NOW).unwrap();
        let ring = Keyring::new().with(file.group());
        let err =
            signature::verify(INDEX, &other.sign(INDEX), &ring, index_subject(), NOW).unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
    }

    #[test]
    fn index_keys_cannot_sign_keys_json() {
        let (r, idx) = (TestKey::generate(), TestKey::generate());
        let data = keys_json(1, &[(&idx, &["demo"], LATER)]);
        let err = KeysFile::load(&data, &idx.sign(&data), &root(&[&r], 1), NOW).unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
    }

    #[test]
    fn unsigned_garbage_is_rejected_before_parsing() {
        let (r, other) = (TestKey::generate(), TestKey::generate());
        let data = b"{ not json";
        let err = KeysFile::load(data, &other.sign(data), &root(&[&r], 1), NOW).unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
        let err = KeysFile::load(data, b"", &root(&[&r], 1), NOW).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
    }

    #[test]
    fn signed_but_invalid_files_are_rejected() {
        let (r, idx) = (TestKey::generate(), TestKey::generate());
        let trust = root(&[&r], 1);
        let key = idx.public_str();
        for (data, expect) in [
            (r#"{ not json"#.to_owned(), "key must be a string"),
            (
                format!(
                    r#"{{"format":2,"sequence":1,"threshold":1,"keys":[{{"key":"{key}","scope":["demo"],"expires":"{LATER}"}}]}}"#
                ),
                "format 2 is not supported",
            ),
            (
                r#"{"format":1,"sequence":1,"threshold":1,"keys":[]}"#.to_owned(),
                "lists no keys",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":2,"keys":[{{"key":"{key}","scope":["demo"],"expires":"{LATER}"}}]}}"#
                ),
                "threshold 2",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":0,"keys":[{{"key":"{key}","scope":["demo"],"expires":"{LATER}"}}]}}"#
                ),
                "threshold 0",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":1,"keys":[{{"key":"{key}","scope":[],"expires":"{LATER}"}}]}}"#
                ),
                "keys[0].scope",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":1,"keys":[{{"key":"{key}","scope":["demo"],"expires":"tomorrow"}}]}}"#
                ),
                "keys[0].expires",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":1,"keys":[{{"key":"{key}","scope":["demo"],"expires":"{LATER}"}},{{"key":"{key}","scope":["x"],"expires":"{LATER}"}}]}}"#
                ),
                "listed twice",
            ),
            (
                format!(
                    r#"{{"format":1,"sequence":1,"threshold":1,"keys":[{{"key":"{key}","scope":["demo"],"expires":"{LATER}"}}],"extra":1}}"#
                ),
                "unknown field",
            ),
        ] {
            let data = data.into_bytes();
            let err = KeysFile::load(&data, &r.sign(&data), &trust, NOW).unwrap_err();
            assert!(matches!(err, Error::Invalid { .. }), "{expect}: {err:?}");
            assert!(err.to_string().contains(expect), "{expect}: {err}");
        }
    }
}

/// Key rotation, shown for the first-party set: a new keys file signed by the anchors (the jtm
/// root keys) replaces index keys without a jtm release, and a keys file cross-signed by old and
/// new anchors carries old and new releases across an anchor rotation.
#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::checks::check_keys_file;
    use crate::key::Keyring;
    use crate::testing::TestKey;
    use crate::trust::TrustState;

    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
    const LATER: &str = "2027-12-31T00:00:00Z";
    const EARLIER: &str = "2026-01-01T00:00:00Z";
    const INDEX: &[u8] = br#"{"plugin":"demo"}"#;

    fn subject() -> Subject<'static> {
        Subject {
            file: "demo-linux-x64.json",
            plugin: "demo",
        }
    }

    fn keys_json(sequence: u64, keys: &[(&TestKey, &str)]) -> Vec<u8> {
        let keys: Vec<_> = keys
            .iter()
            .map(|(k, expires)| {
                serde_json::json!({ "key": k.public_str(), "scope": ["demo"], "expires": expires })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "format": 1, "sequence": sequence, "threshold": 1, "keys": keys
        }))
        .unwrap()
    }

    /// Loads a `keys.json`, runs the rollback check against `state`, and records it, as a
    /// client does when it accepts one.
    fn accept(
        data: &[u8],
        sig: &[u8],
        root: &TrustAnchors,
        state: &mut TrustState,
    ) -> Result<Keyring> {
        let file = KeysFile::load(data, sig, root, NOW)?;
        let seen = check_keys_file(&file, "demo", state)?;
        state.record_keys_file("demo", seen);
        Ok(Keyring::new().with(file.group()))
    }

    fn root(keys: &[&TestKey]) -> TrustAnchors {
        TrustAnchors {
            plugin: "demo".into(),
            keys: keys.iter().map(|k| k.public()).collect(),
            threshold: 1,
        }
    }

    #[test]
    fn index_key_rotation_needs_no_release() {
        let (r, old, new) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let trust = root(&[&r]);
        let mut state = TrustState::default();
        let verify = |ring: &Keyring, key: &TestKey| {
            signature::verify(INDEX, &key.sign(INDEX), ring, subject(), NOW)
        };

        // Before: only the old key.
        let v1 = keys_json(1, &[(&old, LATER)]);
        let ring = accept(&v1, &r.sign(&v1), &trust, &mut state).unwrap();
        verify(&ring, &old).unwrap();
        assert!(verify(&ring, &new).is_err());

        // Overlap: both keys are listed, so indices signed by either verify.
        let v2 = keys_json(2, &[(&old, LATER), (&new, LATER)]);
        let ring = accept(&v2, &r.sign(&v2), &trust, &mut state).unwrap();
        verify(&ring, &old).unwrap();
        verify(&ring, &new).unwrap();

        // After: the old key is gone and its signatures are no longer trusted.
        let v3 = keys_json(3, &[(&new, LATER)]);
        let ring = accept(&v3, &r.sign(&v3), &trust, &mut state).unwrap();
        verify(&ring, &new).unwrap();
        let err = verify(&ring, &old).unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");

        // Replaying an older keys.json that still lists the old key is refused.
        let err = accept(&v2, &r.sign(&v2), &trust, &mut state).unwrap_err();
        assert!(matches!(err, Error::IndexRollback { .. }), "{err:?}");
        // So is a different file claiming the current sequence.
        let forged = keys_json(3, &[(&old, LATER), (&new, LATER)]);
        let err = accept(&forged, &r.sign(&forged), &trust, &mut state).unwrap_err();
        assert!(matches!(err, Error::IndexRollback { .. }), "{err:?}");
        // The current file itself is accepted again.
        accept(&v3, &r.sign(&v3), &trust, &mut state).unwrap();
    }

    #[test]
    fn an_expired_key_is_replaced_by_its_successor() {
        let (r, old, new) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let mut state = TrustState::default();
        let v = keys_json(4, &[(&old, EARLIER), (&new, LATER)]);
        let ring = accept(&v, &r.sign(&v), &root(&[&r]), &mut state).unwrap();
        signature::verify(INDEX, &new.sign(INDEX), &ring, subject(), NOW).unwrap();
        assert!(signature::verify(INDEX, &old.sign(INDEX), &ring, subject(), NOW).is_err());
    }

    #[test]
    fn cross_signed_keys_json_carries_releases_across_a_root_rotation() {
        let (old_root, new_root, idx) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let data = keys_json(5, &[(&idx, LATER)]);
        let cross_signed = [old_root.sign(&data), new_root.sign(&data)].concat();

        // An older release knows only the old root; a newer one only the new root.
        for trust in [root(&[&old_root]), root(&[&new_root])] {
            let mut state = TrustState::default();
            let ring = accept(&data, &cross_signed, &trust, &mut state).unwrap();
            signature::verify(INDEX, &idx.sign(INDEX), &ring, subject(), NOW).unwrap();
        }

        // Signed by the new root alone, it is refused by a release that predates it.
        let err =
            KeysFile::load(&data, &new_root.sign(&data), &root(&[&old_root]), NOW).unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
    }

    #[test]
    fn a_marketplace_scope_is_accepted() {
        let (r, idx) = (TestKey::generate(), TestKey::generate());
        let data = serde_json::to_vec(&serde_json::json!({
            "format": 1, "sequence": 1, "threshold": 1,
            "keys": [{ "key": idx.public_str(), "scope": ["marketplace"], "expires": LATER }]
        }))
        .unwrap();
        let anchors = TrustAnchors {
            plugin: "marketplace".into(),
            ..root(&[&r])
        };
        let file = KeysFile::load(&data, &r.sign(&data), &anchors, NOW).unwrap();
        let ring = Keyring::new().with(file.group());
        let marketplace = Subject {
            file: "marketplace.json",
            plugin: "marketplace",
        };
        signature::verify(INDEX, &idx.sign(INDEX), &ring, marketplace, NOW).unwrap();
        assert!(signature::verify(INDEX, &idx.sign(INDEX), &ring, subject(), NOW).is_err());
    }
}
