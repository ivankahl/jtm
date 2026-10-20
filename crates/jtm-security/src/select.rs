//! Choosing one index from every available copy (SPEC.md section 8).
//!
//! Each copy, whether embedded, cached, mirrored or freshly downloaded, is verified and checked
//! in exactly the same way. The valid copy with the highest `sequence` wins.

use crate::checks::{Accepted, ExpiryPolicy, IndexRequest, Warning, check_index};
use crate::error::{Error, Result};
use crate::index::{self, LoadedIndex};
use crate::key::Keyring;
use crate::signature::Subject;
use crate::time::Timestamp;
use crate::trust::{SourceKind, TrustState};

/// Warning code for a copy that failed verification while another copy was used.
pub const W_INDEX_COPY_REJECTED: &str = "W_INDEX_COPY_REJECTED";

/// One copy of an index and its detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCopy {
    pub source: SourceKind,
    /// The path or URL it was read from, for messages.
    pub origin: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The copy that was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub loaded: LoadedIndex,
    pub source: SourceKind,
    pub origin: String,
    /// What to record in the trust state.
    pub accepted: Accepted,
    /// The chosen copy's raw bytes and signature, for caching.
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    /// Warnings from the chosen copy and about copies that failed.
    pub warnings: Vec<Warning>,
}

/// What to verify the copies against.
#[derive(Debug, Clone, Copy)]
pub struct Selection<'a> {
    pub request: IndexRequest<'a>,
    /// The index file name, such as `demo-linux-x64.json`, for messages and scope checks.
    pub file: &'a str,
    pub keyring: &'a Keyring,
    pub state: &'a TrustState,
    pub policy: ExpiryPolicy,
    pub now: Timestamp,
}

/// Verifies every copy and returns the valid one with the highest sequence, or `Ok(None)`
/// when there are no copies at all.
///
/// When two valid copies share the highest sequence, they must be byte-identical; two different
/// files signed with the same sequence are refused as a rollback-style conflict. Among
/// identical copies the remote is preferred, then a mirror, the cache and the embedded
/// snapshot. When no copy is valid, the error of the most authoritative source is returned.
pub fn select(copies: Vec<IndexCopy>, sel: Selection<'_>) -> Result<Option<Selected>> {
    if copies.is_empty() {
        return Ok(None);
    }
    let mut valid: Vec<(IndexCopy, LoadedIndex, Accepted)> = Vec::new();
    let mut rejected: Vec<(IndexCopy, Error)> = Vec::new();
    for copy in copies {
        match verify_copy(&copy, sel) {
            Ok((loaded, accepted)) => valid.push((copy, loaded, accepted)),
            Err(err) => rejected.push((copy, err)),
        }
    }

    let Some(top) = valid.iter().map(|(_, l, _)| l.index.sequence).max() else {
        rejected.sort_by_key(|(copy, _)| preference(copy.source));
        let (_, err) = rejected.swap_remove(0);
        return Err(err);
    };
    let mut best: Vec<_> = valid
        .into_iter()
        .filter(|(_, l, _)| l.index.sequence == top)
        .collect();
    if best.iter().any(|(_, l, _)| l.sha256 != best[0].1.sha256) {
        return Err(Error::IndexRollback {
            file: sel.file.to_owned(),
            seen: top,
            got: top,
            reason: format!(
                "but copies from {} differ while claiming the same sequence",
                best.iter()
                    .map(|(c, _, _)| c.origin.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        });
    }
    best.sort_by_key(|(copy, _, _)| preference(copy.source));
    let (copy, loaded, accepted) = best.swap_remove(0);

    let mut warnings = accepted.warnings.clone();
    for (bad, err) in &rejected {
        // An older embedded snapshot or cache is expected after an update; only report copies
        // that look damaged or tampered with.
        let routine = matches!(err, Error::IndexRollback { seen, got, .. } if got < seen);
        if !routine {
            warnings.push(Warning {
                code: W_INDEX_COPY_REJECTED,
                message: format!("ignored the copy from {}: {err}", bad.origin),
            });
        }
    }
    Ok(Some(Selected {
        loaded,
        source: copy.source,
        origin: copy.origin,
        accepted,
        data: copy.data,
        signature: copy.signature,
        warnings,
    }))
}

fn verify_copy(copy: &IndexCopy, sel: Selection<'_>) -> Result<(LoadedIndex, Accepted)> {
    let subject = Subject {
        file: sel.file,
        plugin: sel.request.plugin,
    };
    let loaded = index::load(&copy.data, &copy.signature, sel.keyring, subject, sel.now)?;
    let accepted = check_index(
        &loaded,
        sel.file,
        sel.request,
        copy.source,
        sel.state,
        sel.policy,
        sel.now,
    )?;
    Ok((loaded, accepted))
}

/// Lower is preferred.
fn preference(source: SourceKind) -> u8 {
    match source {
        SourceKind::Remote => 0,
        SourceKind::Mirror => 1,
        SourceKind::Cache => 2,
        SourceKind::Embedded => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyGroup, Scope, TrustedKey};
    use crate::testing::TestKey;
    use crate::trust::Seen;
    use serde_json::json;

    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
    const FUTURE: &str = "2027-06-01T00:00:00Z";
    const PAST: &str = "2027-01-01T00:00:00Z";
    const FILE: &str = "demo-linux-x64.json";

    struct Fixture {
        key: TestKey,
        keyring: Keyring,
        state: TrustState,
    }

    impl Fixture {
        fn new() -> Fixture {
            let key = TestKey::generate();
            let keyring = Keyring::new().with(KeyGroup {
                origin: "test".into(),
                keys: vec![TrustedKey {
                    key: key.public(),
                    scope: Scope::plugins(["demo"]).unwrap(),
                    expires: None,
                }],
                threshold: 1,
            });
            Fixture {
                key,
                keyring,
                state: TrustState::default(),
            }
        }

        fn sel(&self) -> Selection<'_> {
            Selection {
                request: IndexRequest {
                    plugin: "demo",
                    platform: "linux-x64",
                },
                file: FILE,
                keyring: &self.keyring,
                state: &self.state,
                policy: ExpiryPolicy::RemoteOnly,
                now: NOW,
            }
        }

        fn copy(&self, source: SourceKind, sequence: u64, expires: &str) -> IndexCopy {
            self.copy_with(source, sequence, expires, "1.0.0")
        }

        fn copy_with(
            &self,
            source: SourceKind,
            sequence: u64,
            expires: &str,
            version: &str,
        ) -> IndexCopy {
            let data = serde_json::to_vec(&json!({
                "format": 1,
                "plugin": "demo",
                "platform": "linux-x64",
                "sequence": sequence,
                "generated": "2026-01-01T00:00:00Z",
                "expires": expires,
                "entries": [{
                    "variant": "default",
                    "version": version,
                    "url": "https://example.test/demo.zip",
                    "archive": "zip",
                    "size": 1,
                    "sha256": "0".repeat(64)
                }]
            }))
            .unwrap();
            IndexCopy {
                source,
                origin: format!("{}:{sequence}", source.as_str()),
                signature: self.key.sign(&data),
                data,
            }
        }
    }

    fn tampered(mut copy: IndexCopy) -> IndexCopy {
        let n = copy.data.len() - 3;
        copy.data[n] ^= 1;
        copy
    }

    #[test]
    fn no_copies_is_none() {
        let f = Fixture::new();
        assert_eq!(select(Vec::new(), f.sel()).unwrap(), None);
    }

    #[test]
    fn highest_valid_sequence_wins_over_invalid_copies() {
        let f = Fixture::new();
        let other = TestKey::generate();
        let mut forged = f.copy(SourceKind::Mirror, 50, FUTURE);
        forged.signature = other.sign(&forged.data);
        let copies = vec![
            f.copy(SourceKind::Embedded, 3, FUTURE),
            tampered(f.copy(SourceKind::Cache, 40, FUTURE)),
            forged,
            f.copy(SourceKind::Remote, 7, FUTURE),
            f.copy(SourceKind::Cache, 5, FUTURE),
        ];
        let selected = select(copies, f.sel()).unwrap().unwrap();
        assert_eq!(selected.loaded.index.sequence, 7);
        assert_eq!(selected.source, SourceKind::Remote);
        let rejected: Vec<_> = selected
            .warnings
            .iter()
            .filter(|w| w.code == W_INDEX_COPY_REJECTED)
            .collect();
        assert_eq!(rejected.len(), 2, "{:?}", selected.warnings);
        assert!(rejected[0].message.contains("cache:40"));
        assert!(rejected[1].message.contains("mirror:50"));
    }

    #[test]
    fn expired_remote_loses_to_an_older_valid_copy() {
        let f = Fixture::new();
        let copies = vec![
            f.copy(SourceKind::Remote, 9, PAST),
            f.copy(SourceKind::Embedded, 4, FUTURE),
        ];
        let selected = select(copies, f.sel()).unwrap().unwrap();
        assert_eq!(selected.loaded.index.sequence, 4);
        assert_eq!(selected.source, SourceKind::Embedded);
    }

    #[test]
    fn expired_mirror_is_used_with_a_warning() {
        let f = Fixture::new();
        let copies = vec![
            f.copy(SourceKind::Embedded, 2, FUTURE),
            f.copy(SourceKind::Mirror, 6, PAST),
        ];
        let selected = select(copies, f.sel()).unwrap().unwrap();
        assert_eq!(selected.loaded.index.sequence, 6);
        assert_eq!(selected.warnings[0].code, crate::checks::W_INDEX_EXPIRED);
    }

    #[test]
    fn rolled_back_copies_are_skipped_quietly() {
        let mut f = Fixture::new();
        let remote = f.copy(SourceKind::Remote, 8, FUTURE);
        let sha = crate::sha256_hex(&remote.data);
        f.state.record_index(
            "demo",
            "linux-x64",
            Seen {
                sequence: 8,
                sha256: sha,
                source: Some(SourceKind::Remote),
            },
        );
        let cache = IndexCopy {
            source: SourceKind::Cache,
            ..remote.clone()
        };
        let copies = vec![f.copy(SourceKind::Embedded, 3, FUTURE), cache];
        let selected = select(copies, f.sel()).unwrap().unwrap();
        assert_eq!(selected.loaded.index.sequence, 8);
        assert_eq!(selected.source, SourceKind::Cache);
        assert!(selected.warnings.is_empty(), "{:?}", selected.warnings);
    }

    #[test]
    fn identical_copies_prefer_the_most_authoritative_source() {
        let f = Fixture::new();
        let remote = f.copy(SourceKind::Remote, 5, FUTURE);
        let copies = vec![
            IndexCopy {
                source: SourceKind::Embedded,
                ..remote.clone()
            },
            IndexCopy {
                source: SourceKind::Cache,
                ..remote.clone()
            },
            remote,
        ];
        let selected = select(copies, f.sel()).unwrap().unwrap();
        assert_eq!(selected.source, SourceKind::Remote);
    }

    #[test]
    fn different_copies_with_the_same_sequence_are_refused() {
        let f = Fixture::new();
        let copies = vec![
            f.copy_with(SourceKind::Remote, 5, FUTURE, "1.0.0"),
            f.copy_with(SourceKind::Mirror, 5, FUTURE, "6.6.6"),
        ];
        let err = select(copies, f.sel()).unwrap_err();
        assert!(matches!(err, Error::IndexRollback { .. }), "{err:?}");
    }

    #[test]
    fn with_no_valid_copy_the_most_authoritative_error_is_returned() {
        let f = Fixture::new();
        let copies = vec![
            tampered(f.copy(SourceKind::Embedded, 1, FUTURE)),
            f.copy(SourceKind::Remote, 2, PAST),
        ];
        let err = select(copies, f.sel()).unwrap_err();
        assert!(matches!(err, Error::IndexExpired { .. }), "{err:?}");
    }
}
