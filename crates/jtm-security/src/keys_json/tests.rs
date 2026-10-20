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
    let err = signature::verify(INDEX, &old.sign(INDEX), &ring, index_subject(), NOW).unwrap_err();
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
