use super::*;

fn seen(sequence: u64, sha: &str, source: SourceKind) -> Seen {
    Seen {
        sequence,
        sha256: sha.into(),
        source: Some(source),
    }
}

#[test]
fn round_trips_through_json() {
    let mut state = TrustState::default();
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
    // Same bytes from a source with a relaxed policy never downgrade a remote record.
    assert!(!state.record_index("demo", "linux-x64", seen(5, "a", SourceKind::Mirror)));
    assert!(!state.record_index("demo", "linux-x64", seen(5, "a", SourceKind::Embedded)));
    assert_eq!(
        state.seen_index("demo", "linux-x64").unwrap().source,
        Some(SourceKind::Remote)
    );
    assert!(state.record_index("demo", "linux-x64", seen(6, "d", SourceKind::Embedded)));
    assert_eq!(state.seen_index("demo", "linux-x64").unwrap().sha256, "d");

    // A copy first seen embedded is promoted when the canonical remote serves it.
    assert!(state.record_index("demo", "macos-x64", seen(3, "e", SourceKind::Embedded)));
    assert!(!state.record_index("demo", "macos-x64", seen(3, "e", SourceKind::Mirror)));
    assert!(state.record_index("demo", "macos-x64", seen(3, "e", SourceKind::Remote)));
    assert_eq!(
        state.seen_index("demo", "macos-x64").unwrap().source,
        Some(SourceKind::Remote)
    );
    assert_eq!(state.seen_index("demo", "macos-x64").unwrap().sha256, "e");
    assert_eq!(state.seen_index("demo", "linux-x64").unwrap().sha256, "d");

    assert!(state.record_keys_file("demo", seen(2, "k", SourceKind::Remote)));
    assert!(!state.record_keys_file("demo", seen(1, "j", SourceKind::Remote)));
    assert!(state.record_keys_file("other", seen(1, "j", SourceKind::Remote)));
}

#[test]
fn holds_only_sequences() {
    let mut state = TrustState::default();
    state.record_index("demo", "linux-x64", seen(7, "bb", SourceKind::Remote));
    let json: serde_json::Value = serde_json::from_slice(&state.to_json()).unwrap();
    let mut fields: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["format", "indices"]);
}

#[test]
fn an_old_file_with_trusted_keys_still_loads_and_drops_them() {
    // `jtm trust add` wrote this list before company keys moved to the user config. Even a
    // list jtm could not have written loads: its contents are never read.
    for keys in [
        r#"[{"key":"RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB","scope":["demo"],"added":"2026-10-19T03:00:00Z"}]"#,
        r#"[{"key":"nope","scope":[],"added":"never"}]"#,
        "[]",
    ] {
        let old = format!(
            r#"{{"format":1,"keys":{keys},"indices":{{"demo":{{"linux-x64":{{"sequence":4,"sha256":"aa","source":"remote"}}}}}}}}"#
        );
        let state = TrustState::parse(old.as_bytes(), Path::new("t")).unwrap();
        assert_eq!(state.seen_index("demo", "linux-x64").unwrap().sequence, 4);
        let text = String::from_utf8(state.to_json()).unwrap();
        assert!(!text.contains(r#""keys""#), "{text}");
    }
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
