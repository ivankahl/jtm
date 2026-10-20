//! `jtm sync` end to end.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::{Fixture, exists};
use serde_json::Value;

fn ready() -> Fixture {
    let f = Fixture::new(false);
    f.trust();
    f
}

fn json_in(f: &Fixture, dir: &Path, args: &[&str]) -> (i32, Value) {
    let output = f
        .jtm()
        .current_dir(dir)
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "one envelope: {stdout}");
    (
        output.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap(),
    )
}

fn project(pin: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".jtm.toml"),
        format!("[tools]\ndemo = \"{pin}\"\n"),
    )
    .unwrap();
    dir
}

#[test]
fn sync_installs_the_pins_and_writes_the_lock() {
    let f = ready();
    let p = project("1.0");
    let (code, value) = json_in(&f, p.path(), &["sync"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "sync");
    assert_eq!(value["changed"], true);
    let installed = &value["data"]["installed"][0];
    assert_eq!(installed["tool"], "demo");
    assert_eq!(installed["version"], "1.0.0");
    assert_eq!(installed["status"], "installed");
    assert!(exists(&f.install_dir("1.0.0")));
    assert!(p.path().join("jtm.lock").is_file());

    let (code, again) = json_in(&f, p.path(), &["sync"]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(again["changed"], false);
    assert_eq!(again["data"]["installed"][0]["status"], "already_installed");
}

#[test]
fn dry_run_installs_and_writes_nothing() {
    let f = ready();
    let p = project("1.0");
    let (code, value) = json_in(&f, p.path(), &["sync", "--dry-run"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert_eq!(value["data"]["installed"][0]["status"], "would_install");
    assert!(!exists(&f.install_dir("1.0.0")));
    assert!(!p.path().join("jtm.lock").exists());
}

#[test]
fn frozen_fails_when_the_lock_would_change() {
    let f = ready();
    let p = project("1.0");
    let (code, value) = json_in(&f, p.path(), &["sync", "--frozen"]);
    assert_eq!(code, 6, "{value}");
    assert_eq!(value["error"]["code"], "E_LOCK_OUTDATED");
    assert!(!exists(&f.install_dir("1.0.0")));

    json_in(&f, p.path(), &["lock"]);
    let (code, value) = json_in(&f, p.path(), &["sync", "--frozen"]);
    assert_eq!(code, 0, "{value}");

    fs::write(p.path().join(".jtm.toml"), "[tools]\ndemo = \"1.1\"\n").unwrap();
    let before = fs::read_to_string(p.path().join("jtm.lock")).unwrap();
    let (code, value) = json_in(&f, p.path(), &["sync", "--frozen"]);
    assert_eq!(code, 6, "{value}");
    assert_eq!(value["error"]["code"], "E_LOCK_OUTDATED");
    assert!(!exists(&f.install_dir("1.1.0")));
    assert_eq!(
        fs::read_to_string(p.path().join("jtm.lock")).unwrap(),
        before
    );
}

#[test]
fn the_locked_version_wins_over_a_newer_match() {
    let f = ready();
    let p = project("1.0");
    json_in(&f, p.path(), &["lock"]);
    fs::write(p.path().join(".jtm.toml"), "[tools]\ndemo = \"1\"\n").unwrap();
    let lock = fs::read_to_string(p.path().join("jtm.lock"))
        .unwrap()
        .replace("requested = \"1.0\"", "requested = \"1\"");
    fs::write(p.path().join("jtm.lock"), lock).unwrap();
    let (code, value) = json_in(&f, p.path(), &["sync"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["version"], "1.0.0");
    assert!(!exists(&f.install_dir("1.1.0")));
}

#[test]
fn a_lock_hash_that_disagrees_with_the_index_is_refused() {
    let f = ready();
    let p = project("1.0");
    json_in(&f, p.path(), &["lock"]);
    let real = jtm_security::sha256_hex(&common::archive("1.0.0"));
    let lock = fs::read_to_string(p.path().join("jtm.lock"))
        .unwrap()
        .replace(&real, &"0".repeat(64));
    fs::write(p.path().join("jtm.lock"), lock).unwrap();
    let (code, value) = json_in(&f, p.path(), &["sync"]);
    assert_eq!(code, 6, "{value}");
    assert_eq!(value["error"]["code"], "E_LOCK_INDEX_MISMATCH");
    assert_eq!(value["error"]["details"]["tool"], "demo");
    assert!(!exists(&f.install_dir("1.0.0")));
}

#[test]
fn a_locked_version_gone_from_the_index_installs_from_the_lock() {
    let f = ready();
    let bytes = common::archive("0.9.0");
    f.serve("/dl/demo-0.9.0.tar.gz", bytes.clone());
    let p = project("0.9");
    let lock = format!(
        r#"lock_version = 1
generated_by = "jtm 0.1.0"

[[tool]]
name = "demo"
requested = "0.9"
pin_source = ".jtm.toml"
variant = "default"
version = "0.9.0"

[[tool.artifact]]
platform = "{platform}"
url = "https://dl.example.test/demo-0.9.0.tar.gz"
size = {size}
sha256 = "{sha}"
"#,
        platform = f.platform,
        size = bytes.len(),
        sha = jtm_security::sha256_hex(&bytes),
    );
    fs::write(p.path().join("jtm.lock"), lock).unwrap();
    // The lock has no [[plugin]] entry yet, so this sync completes it, keeping 0.9.0.
    let (code, value) = json_in(&f, p.path(), &["sync"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["version"], "0.9.0");
    assert_eq!(value["data"]["lock"][0]["status"], "kept");
    let codes: Vec<&str> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"W_LOCK_NOT_IN_INDEX"), "{value}");
    assert_eq!(
        fs::read(f.install_dir("0.9.0").join("VERSION")).unwrap(),
        b"0.9.0"
    );
    let (code, value) = json_in(&f, p.path(), &["sync", "--frozen"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["status"], "already_installed");
}

#[test]
fn no_lock_resolves_fresh_and_leaves_the_lock_alone() {
    let f = ready();
    let p = project("1.1");
    let (code, value) = json_in(&f, p.path(), &["--no-lock", "sync"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["version"], "1.1.0");
    assert!(!p.path().join("jtm.lock").exists());
}

#[test]
fn no_lock_prefers_an_installed_match() {
    let f = ready();
    let (code, value) = f.json(&["install", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
    let p = project("1");
    let (code, value) = json_in(&f, p.path(), &["--no-lock", "sync"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["version"], "1.0.0");
    assert_eq!(value["data"]["installed"][0]["status"], "already_installed");
    assert!(!exists(&f.install_dir("1.1.0")));
}
