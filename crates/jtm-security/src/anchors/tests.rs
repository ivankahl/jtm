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

const NO_KEYS: &[PublicKey] = &[];

#[test]
fn preapproved_anchors_sign_their_plugin_only() {
    let key = TestKey::generate();
    let anchors = TrustAnchors::preapproved("java", &[key.public_str()], 1).unwrap();
    let ring = plugin_keyring(&anchors, None, NO_KEYS);
    verify(DATA, &key.sign(DATA), &ring, subject("java"), NOW).unwrap();
    let err = verify(DATA, &key.sign(DATA), &ring, subject("maven"), NOW).unwrap_err();
    assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
}

#[test]
fn third_party_anchors_need_confirmation() {
    let key = TestKey::generate();
    let keys = [key.public_str()];
    let err = TrustAnchors::confirmed("acme/flyway", &keys, 1, NO_KEYS).unwrap_err();
    match &err {
        Error::KeyUntrusted {
            key_id, resolve, ..
        } => {
            assert_eq!(*key_id, key.public().id().to_string());
            assert_eq!(*resolve, "plugins.acme/flyway.signing_keys");
        }
        other => panic!("unexpected {other:?}"),
    }

    let configured = [key.public()];
    let anchors = TrustAnchors::confirmed("acme/flyway", &keys, 1, &configured).unwrap();
    let ring = plugin_keyring(&anchors, None, &configured);
    verify(DATA, &key.sign(DATA), &ring, subject("acme/flyway"), NOW).unwrap();
}

#[test]
fn confirmed_anchors_must_meet_the_threshold() {
    let (a, b) = (TestKey::generate(), TestKey::generate());
    let keys = [a.public_str(), b.public_str()];
    let configured = [a.public()];

    // One of two keys trusted is enough at threshold 1, not at threshold 2.
    TrustAnchors::confirmed("acme/flyway", &keys, 1, &configured).unwrap();
    let err = TrustAnchors::confirmed("acme/flyway", &keys, 2, &configured).unwrap_err();
    assert!(
        err.to_string().contains(&b.public().id().to_string()),
        "{err}"
    );

    let configured = [a.public(), b.public()];
    let anchors = TrustAnchors::confirmed("acme/flyway", &keys, 2, &configured).unwrap();
    let ring = plugin_keyring(&anchors, None, &configured);
    // Trusted anchors are not also a threshold-1 company group, so one signature fails.
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

    // Configuring a listed key never turns it into a threshold-1 group.
    let ring = plugin_keyring(&anchors, Some(&file), &[a.public()]);
    assert!(verify(DATA, &a.sign(DATA), &ring, subject("java"), NOW).is_err());
    let both = [a.sign(DATA), b.sign(DATA)].concat();
    verify(DATA, &both, &ring, subject("java"), NOW).unwrap();

    // A key that counts toward no threshold still re-signs on its own.
    let ring = plugin_keyring(&anchors, Some(&file), &[a.public(), company.public()]);
    let verified = verify(DATA, &company.sign(DATA), &ring, subject("java"), NOW).unwrap();
    assert_eq!(
        verified.group,
        "company keys in `plugins.java.signing_keys`"
    );
    assert!(verify(DATA, &a.sign(DATA), &ring, subject("java"), NOW).is_err());
}

#[test]
fn a_company_key_re_signs_only_its_plugins_indices() {
    let (anchor, company) = (TestKey::generate(), TestKey::generate());
    let anchors = TrustAnchors::preapproved("java", &[anchor.public_str()], 1).unwrap();
    let ring = plugin_keyring(&anchors, None, &[company.public()]);
    let verified = verify(DATA, &company.sign(DATA), &ring, subject("java"), NOW).unwrap();
    assert_eq!(
        verified.group,
        "company keys in `plugins.java.signing_keys`"
    );

    // The same key signing another plugin's index is untrusted, and the error names the
    // setting that would trust it for that plugin.
    let err = verify(DATA, &company.sign(DATA), &ring, subject("maven"), NOW).unwrap_err();
    match err {
        Error::KeyUntrusted { resolve, .. } => assert_eq!(resolve, "plugins.maven.signing_keys"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn configuring_an_anchor_as_a_company_key_cannot_lower_the_threshold() {
    let (a, b) = (TestKey::generate(), TestKey::generate());
    let anchors = TrustAnchors::preapproved("java", &[a.public_str(), b.public_str()], 2).unwrap();
    let ring = plugin_keyring(&anchors, None, &[a.public(), a.public()]);
    assert!(verify(DATA, &a.sign(DATA), &ring, subject("java"), NOW).is_err());
    let both = [a.sign(DATA), b.sign(DATA)].concat();
    verify(DATA, &both, &ring, subject("java"), NOW).unwrap();
}
