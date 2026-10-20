use super::*;
use crate::signature::{Subject, verify};
use crate::testing::TestKey;
use crate::time::Timestamp;

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
const DATA: &[u8] = b"index bytes";

fn subject(plugin: &str) -> Subject<'_> {
    Subject {
        file: "index.json",
        plugin,
    }
}

fn trust(state: &mut TrustState, key: &TestKey, plugin: &str) {
    state.add_key(key.public(), [plugin.to_owned()].into_iter().collect(), NOW);
}

#[test]
fn preapproved_anchors_sign_their_plugin_only() {
    let key = TestKey::generate();
    let anchors = TrustAnchors::preapproved("java", &[key.public_str()], 1).unwrap();
    let ring = plugin_keyring(&anchors, None, &TrustState::default());
    verify(DATA, &key.sign(DATA), &ring, subject("java"), NOW).unwrap();
    let err = verify(DATA, &key.sign(DATA), &ring, subject("maven"), NOW).unwrap_err();
    assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
}

#[test]
fn third_party_anchors_need_confirmation() {
    let key = TestKey::generate();
    let keys = [key.public_str()];
    let mut state = TrustState::default();

    let err = TrustAnchors::confirmed("acme/flyway", &keys, 1, &state).unwrap_err();
    match &err {
        Error::KeyUntrusted {
            key_id, resolve, ..
        } => {
            assert_eq!(*key_id, key.public().id().to_string());
            assert_eq!(
                *resolve,
                format!("jtm trust add {} --scope acme/flyway", key.public_str())
            );
        }
        other => panic!("unexpected {other:?}"),
    }

    // Trusting the key for another plugin does not help.
    trust(&mut state, &key, "acme/other");
    assert!(TrustAnchors::confirmed("acme/flyway", &keys, 1, &state).is_err());

    trust(&mut state, &key, "acme/flyway");
    let anchors = TrustAnchors::confirmed("acme/flyway", &keys, 1, &state).unwrap();
    let ring = plugin_keyring(&anchors, None, &state);
    verify(DATA, &key.sign(DATA), &ring, subject("acme/flyway"), NOW).unwrap();
}

#[test]
fn confirmed_anchors_must_meet_the_threshold() {
    let (a, b) = (TestKey::generate(), TestKey::generate());
    let keys = [a.public_str(), b.public_str()];
    let mut state = TrustState::default();
    trust(&mut state, &a, "acme/flyway");

    // One of two keys trusted is enough at threshold 1, not at threshold 2.
    TrustAnchors::confirmed("acme/flyway", &keys, 1, &state).unwrap();
    let err = TrustAnchors::confirmed("acme/flyway", &keys, 2, &state).unwrap_err();
    assert!(
        err.to_string().contains(&b.public().id().to_string()),
        "{err}"
    );

    trust(&mut state, &b, "acme/flyway");
    let anchors = TrustAnchors::confirmed("acme/flyway", &keys, 2, &state).unwrap();
    let ring = plugin_keyring(&anchors, None, &state);
    // Trusted anchors are not also a threshold-1 user group, so one signature fails.
    assert!(verify(DATA, &a.sign(DATA), &ring, subject("acme/flyway"), NOW).is_err());
    let both = [a.sign(DATA), b.sign(DATA)].concat();
    verify(DATA, &both, &ring, subject("acme/flyway"), NOW).unwrap();
}

#[test]
fn trusting_a_keys_file_key_cannot_lower_its_threshold() {
    let (root, a, b, company) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let data = serde_json::to_vec(&serde_json::json!({
        "format": 1, "sequence": 1, "threshold": 2,
        "keys": [
            { "key": a.public_str(), "scope": ["java"], "expires": "2027-06-01T00:00:00Z" },
            { "key": b.public_str(), "scope": ["java"], "expires": "2027-06-01T00:00:00Z" }
        ]
    }))
    .unwrap();
    let anchors = TrustAnchors::preapproved("java", &[root.public_str()], 1).unwrap();
    let file = KeysFile::load(&data, &root.sign(&data), &anchors, NOW).unwrap();

    // Trusting a listed key never turns it into a threshold-1 group.
    let mut state = TrustState::default();
    trust(&mut state, &a, "java");
    let ring = plugin_keyring(&anchors, Some(&file), &state);
    assert!(verify(DATA, &a.sign(DATA), &ring, subject("java"), NOW).is_err());
    let both = [a.sign(DATA), b.sign(DATA)].concat();
    verify(DATA, &both, &ring, subject("java"), NOW).unwrap();

    // A key that counts toward no threshold still re-signs on its own.
    trust(&mut state, &company, "java");
    let ring = plugin_keyring(&anchors, Some(&file), &state);
    let verified = verify(DATA, &company.sign(DATA), &ring, subject("java"), NOW).unwrap();
    assert_eq!(verified.group, "user trust store");
}

#[test]
fn a_user_key_can_re_sign_an_index() {
    let (anchor, company) = (TestKey::generate(), TestKey::generate());
    let anchors = TrustAnchors::preapproved("java", &[anchor.public_str()], 1).unwrap();
    let mut state = TrustState::default();
    trust(&mut state, &company, "java");
    let ring = plugin_keyring(&anchors, None, &state);
    let verified = verify(DATA, &company.sign(DATA), &ring, subject("java"), NOW).unwrap();
    assert_eq!(verified.group, "user trust store");
}
