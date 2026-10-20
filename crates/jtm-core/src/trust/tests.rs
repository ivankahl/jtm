use super::*;
use crate::platform::Os;
use jtm_security::testing::TestKey;

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);

fn dirs(home: &tempfile::TempDir) -> Dirs {
    Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap()
}

fn scopes(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn add_persists_the_key_with_its_scope() {
    let home = tempfile::tempdir().unwrap();
    let dirs = dirs(&home);
    let key = TestKey::generate();
    let (info, changed) = add_key(&dirs, &key.public_str(), &scopes(&["demo"]), NOW).unwrap();
    assert!(changed);
    assert_eq!(info.scope, ["demo"]);
    assert_eq!(info.key_id, key.public().id().to_string());
    assert_eq!(info.added, NOW.to_string());

    let (_, changed) = add_key(&dirs, &key.public_str(), &scopes(&["demo"]), NOW).unwrap();
    assert!(!changed, "adding the same key and scope again is a no-op");
    let (info, changed) =
        add_key(&dirs, &key.public_str(), &scopes(&["acme/flyway"]), NOW).unwrap();
    assert!(changed);
    assert_eq!(info.scope, ["acme/flyway", "demo"]);

    let listed = list_keys(&dirs).unwrap();
    assert_eq!(listed, vec![info]);
}

#[test]
fn add_refuses_bad_keys_and_scopes() {
    let home = tempfile::tempdir().unwrap();
    let dirs = dirs(&home);
    let key = TestKey::generate().public_str();
    for (k, s) in [
        ("RWnotakey", scopes(&["demo"])),
        (key.as_str(), scopes(&[])),
        (key.as_str(), scopes(&["*"])),
        (key.as_str(), scopes(&["Demo"])),
    ] {
        let err = add_key(&dirs, k, &s, NOW).unwrap_err();
        assert_eq!(err.code(), "E_USAGE", "{k} {s:?}");
    }
    assert!(list_keys(&dirs).unwrap().is_empty());
}

#[test]
fn remove_by_key_id_or_scope() {
    let home = tempfile::tempdir().unwrap();
    let dirs = dirs(&home);
    let key = TestKey::generate();
    add_key(&dirs, &key.public_str(), &scopes(&["demo", "other"]), NOW).unwrap();

    let removal = remove_key(&dirs, &key.public_str(), &scopes(&["other"])).unwrap();
    assert!(removal.found && removal.changed);
    assert_eq!(removal.remaining.unwrap().scope, ["demo"]);

    let id = key.public().id().to_string().to_ascii_lowercase();
    let removal = remove_key(&dirs, &id, &[]).unwrap();
    assert!(removal.found && removal.changed);
    assert_eq!(removal.remaining, None);
    assert!(list_keys(&dirs).unwrap().is_empty());

    let removal = remove_key(&dirs, &key.public_str(), &[]).unwrap();
    assert!(!removal.found && !removal.changed);
    assert_eq!(
        remove_key(&dirs, "nonsense", &[]).unwrap_err().code(),
        "E_USAGE"
    );
}

#[test]
fn trust_add_confirms_a_plugins_signing_key_for_that_plugin_only() {
    let home = tempfile::tempdir().unwrap();
    let dirs = dirs(&home);
    let key = TestKey::generate();
    let manifest_keys = [key.public_str()];
    let anchors = |plugin: &str| {
        let state = TrustState::load(&trust_path(&dirs)).unwrap();
        jtm_security::TrustAnchors::confirmed(plugin, &manifest_keys, 1, &state)
            .map(|a| jtm_security::plugin_keyring(&a, None, &state))
    };
    let err = JtmError::from(anchors("acme/demo").unwrap_err());
    assert_eq!(err.code(), "E_KEY_UNTRUSTED");
    assert_eq!(
        err.details()["resolve"],
        format!("jtm trust add {} --scope acme/demo", key.public_str())
    );

    add_key(&dirs, &key.public_str(), &scopes(&["acme/demo"]), NOW).unwrap();
    let keyring = anchors("acme/demo").unwrap();
    let data = b"{}";
    let sig = key.sign(data);
    let subject = |plugin| jtm_security::Subject {
        file: "index.json",
        plugin,
    };
    jtm_security::verify(data, &sig, &keyring, subject("acme/demo"), NOW).unwrap();
    let err = jtm_security::verify(data, &sig, &keyring, subject("acme/other"), NOW).unwrap_err();
    assert!(matches!(err, jtm_security::Error::KeyUntrusted { .. }));
    assert!(anchors("acme/other").is_err());
}
