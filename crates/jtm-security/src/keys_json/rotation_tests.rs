//! Key rotation, shown for the first-party set: a new keys file signed by the anchors (the jtm
//! root keys) replaces index keys without a jtm release, and a keys file cross-signed by old and
//! new anchors carries old and new releases across an anchor rotation.

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
fn accept(data: &[u8], sig: &[u8], root: &TrustAnchors, state: &mut TrustState) -> Result<Keyring> {
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
    let err = KeysFile::load(&data, &new_root.sign(&data), &root(&[&old_root]), NOW).unwrap_err();
    assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
}
