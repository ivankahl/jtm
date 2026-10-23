//! The first-party manifests compiled into jtm (SPEC.md sections 9, 14 and 15).

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::Fixture;
use jtm_security::testing::TestKey;
use serde_json::json;

const FIRST_PARTY: &[&str] = &["gradle", "java", "kotlin", "maven", "spring-boot-cli"];

fn shipped(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins")
        .join(name)
        .join("plugin.toml");
    fs::read_to_string(path).unwrap()
}

fn old_working_copy(f: &Fixture) -> PathBuf {
    f.home.path().join("plugins").join("builtin")
}

#[test]
fn every_first_party_plugin_is_available_without_installing_anything() {
    let f = Fixture::new(false);
    let (code, value) = f.json(&["current"]);
    assert_eq!(code, 0, "{value}");
    let tools: Vec<&str> = value["data"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool"].as_str().unwrap())
        .collect();
    for name in FIRST_PARTY {
        assert!(tools.contains(name), "{name} in {tools:?}");
    }
}

/// What is in `<data>/plugins`, which holds only the fixture's own external plugin.
fn plugins_dir(f: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(f.home.path().join("plugins"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn no_command_writes_under_the_plugins_dir() {
    let f = Fixture::new(false);
    let before = plugins_dir(&f);
    for args in [&["list"][..], &["current"], &["available", "java"]] {
        f.json(args);
    }
    assert_eq!(plugins_dir(&f), before);
}

/// Older versions unpacked the manifests to `<data>/plugins/builtin`; the first command that
/// opens a session removes that copy, with the lock its repair took.
#[test]
fn an_old_working_copy_is_removed() {
    let f = Fixture::new(false);
    let copy = old_working_copy(&f);
    fs::create_dir_all(copy.join("java")).unwrap();
    fs::write(copy.join("java").join("plugin.toml"), shipped("java")).unwrap();
    let lock = f
        .home
        .path()
        .join("locks")
        .join(".builtin-working-copy.lock");
    fs::create_dir_all(lock.parent().unwrap()).unwrap();
    fs::write(&lock, "").unwrap();

    let (code, value) = f.json(&["list"]);
    assert_eq!(code, 0, "{value}");
    assert!(!copy.exists());
    assert!(!lock.exists());
    assert_eq!(plugins_dir(&f), ["demo@0123abc"]);
}

/// SPEC.md section 9: a manifest on disk never changes a trust decision. A java manifest that
/// trusts an attacker's key is dropped in the old working copy and as an external plugin, and
/// the attacker serves an index signed by it; jtm still verifies against the compiled-in anchors
/// and refuses it.
#[test]
fn a_tampered_manifest_on_disk_never_changes_a_trust_decision() {
    let f = Fixture::new(false);
    let attacker = TestKey::generate();
    let manifest = old_working_copy(&f).join("java").join("plugin.toml");
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    let mut table: toml::Table = toml::from_str(&shipped("java")).unwrap();
    let index = table["index"].as_table_mut().unwrap();
    index["signing_keys"] = vec![attacker.public_str()].into();
    index.remove("threshold");
    index.remove("keys_url");
    fs::write(&manifest, toml::to_string(&table).unwrap()).unwrap();
    // The same edit dropped in as an external plugin is no better: builtin names win.
    let external = f.home.path().join("plugins").join("java@evil");
    fs::create_dir_all(&external).unwrap();
    fs::write(
        external.join("plugin.toml"),
        toml::to_string(&table).unwrap(),
    )
    .unwrap();

    let archive = common::archive("21.0.5");
    let index = serde_json::to_vec(&json!({
        "format": 1,
        "plugin": "java",
        "platform": f.platform,
        "sequence": 1,
        "generated": "2026-01-01T00:00:00Z",
        "expires": "2099-01-01T00:00:00Z",
        "entries": [{
            "variant": "temurin",
            "version": "21.0.5+11",
            "tags": ["lts"],
            "url": "https://dl.example.test/java.tar.gz",
            "archive": "tar.gz",
            "size": archive.len(),
            "sha256": jtm_security::sha256_hex(&archive),
        }],
    }))
    .unwrap();
    f.serve("/evil/java.json.minisig", attacker.sign(&index));
    f.serve("/evil/java.json", index);
    f.serve("/dl/java.tar.gz", archive);
    let uri = f.server.uri();
    let config = format!(
        "[security]\nallow_http_mirrors = true\n\n[mirrors]\n\
         \"https://dl.example.test/\" = \"{uri}/dl/\"\n\
         \"https://github.com/jtm-dev/index/\" = \"{uri}/no-such-file/\"\n\n\
         [plugins.java]\nindex_url = \"{uri}/evil/java.json\"\n"
    );
    fs::write(f.home.path().join("config.toml"), config).unwrap();

    let (code, value) = f.json(&["install", "java@lts"]);
    assert_ne!(code, 0, "{value}");
    let error = value["error"]["code"].as_str().unwrap();
    assert!(
        ["E_SIGNATURE_INVALID", "E_KEY_UNTRUSTED"].contains(&error),
        "{value}"
    );
    assert!(!f.home.path().join("tools").join("java").exists());
    // And the old copy is gone after that same run.
    assert!(!manifest.exists());
}
