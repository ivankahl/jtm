use super::*;
use crate::key::{KeyGroup, Scope, TrustedKey};
use crate::testing::TestKey;
use serde_json::{Value, json};

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn keyring(key: &TestKey) -> Keyring {
    Keyring::new().with(KeyGroup {
        origin: "test".into(),
        keys: vec![TrustedKey {
            key: key.public(),
            scope: Scope::plugins(["demo"]).unwrap(),
            expires: None,
        }],
        threshold: 1,
    })
}

fn subject() -> Subject<'static> {
    Subject {
        file: "demo-linux-x64.json",
        plugin: "demo",
    }
}

fn entry() -> Value {
    json!({
        "variant": "default",
        "version": "1.2.3",
        "tags": ["ga"],
        "url": "https://example.test/demo-1.2.3.tar.gz",
        "archive": "tar.gz",
        "size": 1234,
        "sha256": SHA,
        "provenance": ["upstream", "sidecar"]
    })
}

fn index() -> Value {
    json!({
        "format": 1,
        "plugin": "demo",
        "platform": "linux-x64",
        "sequence": 7,
        "generated": "2026-10-19T03:00:00Z",
        "expires": "2026-11-18T03:00:00Z",
        "entries": [entry()]
    })
}

fn signed(key: &TestKey, value: &Value) -> (Vec<u8>, Vec<u8>) {
    let data = serde_json::to_vec_pretty(value).unwrap();
    let sig = key.sign(&data);
    (data, sig)
}

#[test]
fn loads_a_signed_index() {
    let key = TestKey::generate();
    let (data, sig) = signed(&key, &index());
    let loaded = load(&data, &sig, &keyring(&key), subject(), NOW).unwrap();
    let index = loaded.index;
    assert_eq!(index.plugin, "demo");
    assert_eq!(index.platform, "linux-x64");
    assert_eq!(index.sequence, 7);
    assert_eq!(index.expires.to_string(), "2026-11-18T03:00:00Z");
    let entry = &index.entries[0];
    assert_eq!(entry.archive, ArchiveKind::TarGz);
    assert_eq!(entry.size, 1234);
    assert_eq!(Candidate::version(entry), "1.2.3");
    assert_eq!(Candidate::tags(entry), ["ga"]);
    assert_eq!(loaded.verified.signers, vec![key.public().id()]);
}

#[test]
fn malformed_json_with_a_bad_signature_never_reaches_the_parser() {
    let (key, other) = (TestKey::generate(), TestKey::generate());
    let garbage = b"{ this is not json".as_slice();
    // Each case would be a parse error if parsing ran first; every one must instead fail
    // on the signature.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("no signature", Vec::new()),
        ("untrusted key", other.sign(garbage)),
        ("signature of other bytes", key.sign(b"{}")),
    ];
    for (name, sig) in cases {
        let err = load(garbage, &sig, &keyring(&key), subject(), NOW).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SignatureInvalid { .. } | Error::KeyUntrusted { .. }
            ),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn tampered_index_is_rejected() {
    let key = TestKey::generate();
    let (data, sig) = signed(&key, &index());
    let text = String::from_utf8(data)
        .unwrap()
        .replace(SHA, &"f".repeat(64));
    let err = load(text.as_bytes(), &sig, &keyring(&key), subject(), NOW).unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
}

#[test]
fn signed_but_invalid_indices_are_rejected() {
    let key = TestKey::generate();
    let with = |path: &str, value: Value| {
        let mut index = index();
        let mut target = &mut index;
        let parts: Vec<&str> = path.split('.').collect();
        for part in &parts[..parts.len() - 1] {
            target = match part.parse::<usize>() {
                Ok(i) => &mut target[i],
                Err(_) => &mut target[*part],
            };
        }
        let last = parts[parts.len() - 1];
        if value.is_null() {
            target.as_object_mut().unwrap().remove(last);
        } else {
            target[last] = value;
        }
        index
    };
    let mut duplicate = index();
    duplicate["entries"] = json!([entry(), entry()]);
    let cases = [
        (with("format", json!(2)), "format 2 is not supported"),
        (with("plugin", json!("Demo")), "plugin:"),
        (with("platform", json!("linux x64")), "platform:"),
        (with("sequence", json!(-1)), "invalid value"),
        (
            with("expires", json!("2026-10-19T03:00:00Z")),
            "expires must be later",
        ),
        (with("generated", json!("yesterday")), "generated:"),
        (with("extra", json!(true)), "unknown field"),
        (with("entries.0.extra", json!(true)), "unknown field"),
        (with("entries.0.sha256", Value::Null), "missing field"),
        (
            with("entries.0.sha256", json!(SHA.to_uppercase())),
            "sha256",
        ),
        (with("entries.0.sha256", json!(&SHA[1..])), "sha256"),
        (
            with("entries.0.url", json!("http://example.test/a.zip")),
            "url",
        ),
        (
            with("entries.0.url", json!("https://exa mple.test/a.zip")),
            "url",
        ),
        (with("entries.0.size", json!(0)), "size"),
        (with("entries.0.archive", json!("msi")), "unknown variant"),
        (with("entries.0.version", json!("../1")), "version"),
        (with("entries.0.variant", json!("Temurin")), "variant"),
        (with("entries.0.tags", json!(["LTS"])), "tags[0]"),
        (duplicate, "listed twice"),
    ];
    for (value, expect) in cases {
        let (data, sig) = signed(&key, &value);
        let err = load(&data, &sig, &keyring(&key), subject(), NOW).unwrap_err();
        assert!(matches!(err, Error::Invalid { .. }), "{expect}: {err:?}");
        assert!(err.to_string().contains(expect), "{expect}: {err}");
    }
}

#[test]
fn oversized_files_are_refused_before_verification() {
    let key = TestKey::generate();
    let data = vec![b' '; MAX_INDEX_FILE + 1];
    let err = load(&data, b"", &keyring(&key), subject(), NOW).unwrap_err();
    assert!(matches!(err, Error::Invalid { .. }), "{err:?}");
}

#[test]
fn entries_resolve_with_the_plugin_resolver() {
    let key = TestKey::generate();
    let mut value = index();
    let mut newer = entry();
    newer["version"] = json!("1.10.0");
    value["entries"] = json!([entry(), newer]);
    let (data, sig) = signed(&key, &value);
    let index = load(&data, &sig, &keyring(&key), subject(), NOW)
        .unwrap()
        .index;
    let best = jtm_plugin::select_highest(
        jtm_plugin::VersionScheme::Maven,
        &index.entries,
        "default",
        "1",
        false,
    )
    .unwrap();
    assert_eq!(best.version, "1.10.0");
}
