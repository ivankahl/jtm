//! The first-party manifests compiled into jtm and their `plugins/builtin` working copy
//! (SPEC.md sections 9, 14 and 15).

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

fn working_copy(f: &Fixture) -> PathBuf {
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

#[test]
fn the_working_copy_is_unpacked_and_repaired_from_the_binary() {
    let f = Fixture::new(false);
    let (code, value) = f.json(&["list"]);
    assert_eq!(code, 0, "{value}");
    let copy = working_copy(&f);
    for name in FIRST_PARTY {
        let text = fs::read_to_string(copy.join(name).join("plugin.toml")).unwrap();
        assert_eq!(text, shipped(name), "{name}");
    }

    // Edited, deleted and extra files are all put back as the binary has them.
    fs::write(copy.join("java").join("plugin.toml"), "edited").unwrap();
    fs::remove_file(copy.join("maven").join("plugin.toml")).unwrap();
    fs::write(copy.join("kotlin").join("plugin.lua"), "function x() end").unwrap();
    fs::create_dir_all(copy.join("stale")).unwrap();
    fs::write(copy.join("stale").join("plugin.toml"), "stale").unwrap();
    let (code, value) = f.json(&["list"]);
    assert_eq!(code, 0, "{value}");
    for name in FIRST_PARTY {
        let text = fs::read_to_string(copy.join(name).join("plugin.toml")).unwrap();
        assert_eq!(text, shipped(name), "{name}");
    }
    assert!(!copy.join("kotlin").join("plugin.lua").exists());
    assert!(!copy.join("stale").exists());
}

#[cfg(unix)]
#[test]
fn repairing_the_working_copy_never_writes_through_a_link() {
    let f = Fixture::new(false);
    f.json(&["list"]);
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, "keep").unwrap();
    let manifest = working_copy(&f).join("java").join("plugin.toml");
    fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(&victim, &manifest).unwrap();

    let (code, value) = f.json(&["list"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    assert!(
        !fs::symlink_metadata(&manifest)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&manifest).unwrap(), shipped("java"));
}

/// SPEC.md section 9: a tampered working copy never changes a trust decision. The copy's java
/// manifest is rewritten to trust an attacker's key, and the attacker serves an index signed
/// by it; jtm still verifies against the compiled-in anchors and refuses it.
#[test]
fn a_tampered_working_copy_never_changes_a_trust_decision() {
    let f = Fixture::new(false);
    f.json(&["list"]);
    let attacker = TestKey::generate();
    let manifest = working_copy(&f).join("java").join("plugin.toml");
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
    // And the copy is repaired again by that same run.
    assert_eq!(fs::read_to_string(&manifest).unwrap(), shipped("java"));
}
