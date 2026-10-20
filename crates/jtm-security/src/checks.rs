//! Binding, rollback and expiry checks run on every verified index (SPEC.md section 9).
//!
//! These run after [`crate::index::load`] has verified the signature, on embedded, cached,
//! mirrored and freshly downloaded copies alike.

use crate::error::{Error, Result};
use crate::index::LoadedIndex;
use crate::keys_json::{KEYS_FILE, KeysFile};
use crate::time::Timestamp;
use crate::trust::{Seen, SourceKind, TrustState};

/// The value of `security.expiry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryPolicy {
    /// An expired index is an error from the canonical remote and a warning elsewhere, since
    /// air-gapped mirrors go stale by design.
    RemoteOnly,
    /// An expired index is an error from every source.
    Enforce,
}

/// The index that was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexRequest<'a> {
    pub plugin: &'a str,
    pub platform: &'a str,
}

/// A non-fatal finding, reported alongside the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

/// Warning code for an expired index accepted from a source where expiry is not enforced.
pub const W_INDEX_EXPIRED: &str = "W_INDEX_EXPIRED";

/// An index that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// What to record in the trust state once this copy is used.
    pub seen: Seen,
    pub warnings: Vec<Warning>,
}

/// Runs the binding, rollback and expiry checks, in that order, on a verified index copy that
/// came from `source`. `file` names the copy in messages.
pub fn check_index(
    loaded: &LoadedIndex,
    file: &str,
    request: IndexRequest<'_>,
    source: SourceKind,
    state: &TrustState,
    policy: ExpiryPolicy,
    now: Timestamp,
) -> Result<Accepted> {
    let index = &loaded.index;
    if index.plugin != request.plugin || index.platform != request.platform {
        return Err(Error::IndexBinding {
            file: file.to_owned(),
            expected: describe(request.plugin, request.platform),
            got: describe(&index.plugin, &index.platform),
        });
    }

    let previous = state.seen_index(request.plugin, request.platform);
    if let Some(seen) = previous {
        check_rollback(file, seen, index.sequence, &loaded.sha256)?;
    }

    // A cached copy carries the expiry policy of the source it was saved from. A cache file
    // whose origin is not on record is held to the strictest policy.
    let origin = match source {
        SourceKind::Cache => previous
            .filter(|seen| seen.sequence == index.sequence && seen.sha256 == loaded.sha256)
            .and_then(|seen| seen.source)
            .filter(|kind| *kind != SourceKind::Cache)
            .unwrap_or(SourceKind::Remote),
        other => other,
    };

    let mut warnings = Vec::new();
    if now >= index.expires {
        let enforced = policy == ExpiryPolicy::Enforce || origin == SourceKind::Remote;
        if enforced {
            return Err(Error::IndexExpired {
                file: file.to_owned(),
                expires: index.expires.to_string(),
            });
        }
        warnings.push(Warning {
            code: W_INDEX_EXPIRED,
            message: format!(
                "{file} from the {} source expired at {}; using it because expiry is only \
                 enforced for the canonical remote",
                origin.as_str(),
                index.expires
            ),
        });
    }

    Ok(Accepted {
        seen: Seen {
            sequence: index.sequence,
            sha256: loaded.sha256.clone(),
            source: Some(origin),
        },
        warnings,
    })
}

/// Refuses a keys file for `plugin` older than one already seen. Returns what to record.
pub fn check_keys_file(keys: &KeysFile, plugin: &str, state: &TrustState) -> Result<Seen> {
    if let Some(seen) = state.keys_files.get(plugin) {
        check_rollback(KEYS_FILE, seen, keys.sequence, &keys.sha256)?;
    }
    Ok(Seen {
        sequence: keys.sequence,
        sha256: keys.sha256.clone(),
        source: None,
    })
}

/// A lower sequence is a rollback. An equal one is accepted only for the same bytes.
fn check_rollback(file: &str, seen: &Seen, got: u64, sha256: &str) -> Result<()> {
    let reason = if got < seen.sequence {
        "older than the newest copy already seen"
    } else if got == seen.sequence && sha256 != seen.sha256 {
        "the same as the newest copy already seen but with different content"
    } else {
        return Ok(());
    };
    Err(Error::IndexRollback {
        file: file.to_owned(),
        seen: seen.sequence,
        got,
        reason: reason.to_owned(),
    })
}

fn describe(plugin: &str, platform: &str) -> String {
    format!("plugin `{plugin}` on `{platform}`")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{IndexFile, LoadedIndex};
    use crate::signature::Verified;

    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
    const REQUEST: IndexRequest<'static> = IndexRequest {
        plugin: "demo",
        platform: "linux-x64",
    };

    fn loaded(plugin: &str, platform: &str, sequence: u64, sha: &str, expires: i64) -> LoadedIndex {
        LoadedIndex {
            index: IndexFile {
                plugin: plugin.into(),
                platform: platform.into(),
                sequence,
                generated: Timestamp::from_unix(expires - 1000),
                expires: Timestamp::from_unix(expires),
                entries: Vec::new(),
            },
            sha256: sha.into(),
            verified: Verified {
                group: "test".into(),
                signers: Vec::new(),
            },
        }
    }

    fn fresh(sequence: u64, sha: &str) -> LoadedIndex {
        loaded("demo", "linux-x64", sequence, sha, NOW.unix() + 1)
    }

    fn expired(sequence: u64, sha: &str) -> LoadedIndex {
        loaded("demo", "linux-x64", sequence, sha, NOW.unix())
    }

    fn run(
        index: &LoadedIndex,
        source: SourceKind,
        state: &TrustState,
        policy: ExpiryPolicy,
    ) -> Result<Accepted> {
        check_index(
            index,
            "demo-linux-x64.json",
            REQUEST,
            source,
            state,
            policy,
            NOW,
        )
    }

    fn state_with(sequence: u64, sha: &str, source: SourceKind) -> TrustState {
        let mut state = TrustState::default();
        state.record_index(
            "demo",
            "linux-x64",
            Seen {
                sequence,
                sha256: sha.into(),
                source: Some(source),
            },
        );
        state
    }

    #[test]
    fn binding_requires_the_requested_plugin_and_platform() {
        let state = TrustState::default();
        for index in [
            loaded("other", "linux-x64", 1, "a", NOW.unix() + 1),
            loaded("demo", "windows-x64", 1, "a", NOW.unix() + 1),
            loaded("demo", "any", 1, "a", NOW.unix() + 1),
        ] {
            let err =
                run(&index, SourceKind::Remote, &state, ExpiryPolicy::RemoteOnly).unwrap_err();
            assert!(matches!(err, Error::IndexBinding { .. }), "{err:?}");
        }
        run(
            &fresh(1, "a"),
            SourceKind::Remote,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap();
    }

    #[test]
    fn rollback_refuses_older_or_conflicting_copies() {
        let state = state_with(10, "a", SourceKind::Remote);
        let err = run(
            &fresh(9, "b"),
            SourceKind::Mirror,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::IndexRollback {
                    seen: 10,
                    got: 9,
                    ..
                }
            ),
            "{err:?}"
        );

        let err = run(
            &fresh(10, "b"),
            SourceKind::Remote,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::IndexRollback {
                    seen: 10,
                    got: 10,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("different content"), "{err}");

        let same = run(
            &fresh(10, "a"),
            SourceKind::Cache,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap();
        assert_eq!(same.seen.sequence, 10);
        let newer = run(
            &fresh(11, "c"),
            SourceKind::Remote,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap();
        assert_eq!(newer.seen.sequence, 11);
        assert_eq!(newer.seen.source, Some(SourceKind::Remote));
    }

    #[test]
    fn expired_remote_index_is_an_error() {
        let err = run(
            &expired(1, "a"),
            SourceKind::Remote,
            &TrustState::default(),
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(matches!(err, Error::IndexExpired { .. }), "{err:?}");
    }

    #[test]
    fn expired_embedded_or_mirror_index_is_a_warning() {
        for source in [SourceKind::Embedded, SourceKind::Mirror] {
            let accepted = run(
                &expired(1, "a"),
                source,
                &TrustState::default(),
                ExpiryPolicy::RemoteOnly,
            )
            .unwrap();
            assert_eq!(accepted.warnings.len(), 1, "{source:?}");
            assert_eq!(accepted.warnings[0].code, W_INDEX_EXPIRED);
            assert_eq!(accepted.seen.source, Some(source));
        }
    }

    #[test]
    fn enforce_makes_expiry_an_error_everywhere() {
        for source in [
            SourceKind::Embedded,
            SourceKind::Mirror,
            SourceKind::Cache,
            SourceKind::Remote,
        ] {
            let state = state_with(1, "a", SourceKind::Mirror);
            let err = run(&expired(1, "a"), source, &state, ExpiryPolicy::Enforce).unwrap_err();
            assert!(
                matches!(err, Error::IndexExpired { .. }),
                "{source:?}: {err:?}"
            );
        }
    }

    #[test]
    fn cached_copies_keep_the_policy_of_their_origin() {
        let from_mirror = state_with(1, "a", SourceKind::Mirror);
        let accepted = run(
            &expired(1, "a"),
            SourceKind::Cache,
            &from_mirror,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap();
        assert_eq!(accepted.warnings.len(), 1);
        assert_eq!(accepted.seen.source, Some(SourceKind::Mirror));

        let from_remote = state_with(1, "a", SourceKind::Remote);
        let err = run(
            &expired(1, "a"),
            SourceKind::Cache,
            &from_remote,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(matches!(err, Error::IndexExpired { .. }), "{err:?}");

        let unknown = run(
            &expired(1, "a"),
            SourceKind::Cache,
            &TrustState::default(),
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(matches!(unknown, Error::IndexExpired { .. }), "{unknown:?}");
    }

    #[test]
    fn a_remote_record_is_not_downgraded_by_an_embedded_copy() {
        // The same bytes arriving embedded after the canonical remote must not relax the
        // recorded source, or the cached copy of the remote content would only warn on expiry.
        let mut state = state_with(1, "a", SourceKind::Remote);
        state.record_index(
            "demo",
            "linux-x64",
            Seen {
                sequence: 1,
                sha256: "a".into(),
                source: Some(SourceKind::Embedded),
            },
        );
        assert_eq!(
            state.seen_index("demo", "linux-x64").unwrap().source,
            Some(SourceKind::Remote)
        );
        let err = run(
            &expired(1, "a"),
            SourceKind::Cache,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(matches!(err, Error::IndexExpired { .. }), "{err:?}");
    }

    #[test]
    fn checks_run_binding_then_rollback_then_expiry() {
        let state = state_with(10, "a", SourceKind::Remote);
        let both = loaded("other", "linux-x64", 1, "b", NOW.unix());
        let err = run(&both, SourceKind::Remote, &state, ExpiryPolicy::RemoteOnly).unwrap_err();
        assert!(matches!(err, Error::IndexBinding { .. }), "{err:?}");
        let err = run(
            &expired(1, "b"),
            SourceKind::Remote,
            &state,
            ExpiryPolicy::RemoteOnly,
        )
        .unwrap_err();
        assert!(matches!(err, Error::IndexRollback { .. }), "{err:?}");
    }
}
