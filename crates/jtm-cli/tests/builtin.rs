//! The first-party manifests compiled into jtm and their `plugins/builtin-<key>` working copy
//! (SPEC.md sections 7, 9, 14 and 15).

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

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

/// The working copies in the fixture's `plugins` directory.
fn working_copies(f: &Fixture) -> Vec<PathBuf> {
    let mut copies: Vec<PathBuf> = fs::read_dir(f.home.path().join("plugins"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("builtin-")
        })
        .collect();
    copies.sort();
    copies
}

/// The working copy of this binary's embedded set, once a command has unpacked it.
fn working_copy(f: &Fixture) -> PathBuf {
    let copies = working_copies(f);
    assert_eq!(copies.len(), 1, "{copies:?}");
    copies[0].clone()
}

/// Plants the working copy of another embedded set, last used `days` ago.
fn plant_copy(f: &Fixture, key: &str, days: u64) -> PathBuf {
    let copy = f.home.path().join("plugins").join(format!("builtin-{key}"));
    fs::create_dir_all(copy.join("java")).unwrap();
    fs::write(copy.join("java").join("plugin.toml"), "another set").unwrap();
    let marker = copy.join(".last-used");
    fs::write(&marker, "").unwrap();
    let used = SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60);
    fs::OpenOptions::new()
        .write(true)
        .open(&marker)
        .unwrap()
        .set_modified(used)
        .unwrap();
    copy
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

#[test]
fn another_sets_copy_in_use_is_left_alone_and_a_stale_one_is_removed() {
    let f = Fixture::new(false);
    let (code, value) = f.json(&["list"]);
    assert_eq!(code, 0, "{value}");
    let ours = working_copy(&f);
    let in_use = plant_copy(&f, "0123456789abcdef", 1);
    let stale = plant_copy(&f, "fedcba9876543210", 31);

    for _ in 0..2 {
        let (code, value) = f.json(&["list"]);
        assert_eq!(code, 0, "{value}");
    }
    assert_eq!(
        fs::read_to_string(in_use.join("java").join("plugin.toml")).unwrap(),
        "another set"
    );
    assert!(!stale.exists());
    let mut expected = vec![in_use, ours.clone()];
    expected.sort();
    assert_eq!(working_copies(&f), expected);
    for name in FIRST_PARTY {
        let text = fs::read_to_string(ours.join(name).join("plugin.toml")).unwrap();
        assert_eq!(text, shipped(name), "{name}");
    }
}
