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
        let err = run(&index, SourceKind::Remote, &state, ExpiryPolicy::RemoteOnly).unwrap_err();
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
