//! `jtm install`, `uninstall`, `list` and `available` end to end against the shared fixture.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{Fixture, VERSIONS, exists};
use serde_json::{Value, json};

#[test]
fn an_untrusted_plugin_key_needs_a_human() {
    let f = Fixture::new(false);
    let (code, value) = f.json(&["install", "demo@1.0.0"]);
    assert_eq!(code, 7, "{value}");
    assert_eq!(value["error"]["code"], "E_KEY_UNTRUSTED");
    assert!(
        value["error"]["details"]["resolve"]
            .as_str()
            .unwrap()
            .contains("jtm trust add")
    );
    assert!(!exists(&f.install_dir("1.0.0")));
}

#[test]
fn install_verifies_extracts_and_is_idempotent() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "install");
    assert_eq!(value["changed"], true);
    let item = &value["data"]["installed"][0];
    assert_eq!(item["tool"], "demo");
    assert_eq!(item["variant"], "default");
    assert_eq!(item["version"], "1.0.0");
    assert_eq!(item["status"], "installed");
    assert_eq!(value["data"]["failed"], json!([]));

    let dir = f.install_dir("1.0.0");
    assert_eq!(PathBuf::from(item["path"].as_str().unwrap()), dir);
    assert_eq!(std::fs::read(dir.join("VERSION")).unwrap(), b"1.0.0");
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(dir.join(".jtm-receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["plugin"], "demo");
    assert_eq!(receipt["platform"], f.platform.as_str());
    assert_eq!(receipt["index_sequence"], 1);
    assert!(
        receipt["url"]
            .as_str()
            .unwrap()
            .ends_with("/dl/demo-1.0.0.tar.gz")
    );
    assert_eq!(f.downloads(), 1);

    let (code, again) = f.json(&["install", "demo@1.0"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
    assert_eq!(again["data"]["installed"][0]["status"], "already_installed");
    assert_eq!(f.downloads(), 1);
}

#[test]
fn a_bare_tool_installs_its_default_alias() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"][0]["version"], "1.1.0");
}

#[test]
fn dry_run_changes_nothing() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@rc", "--dry-run"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert_eq!(value["data"]["dry_run"], true);
    let item = &value["data"]["installed"][0];
    assert_eq!(item["status"], "would_install");
    assert_eq!(item["version"], "2.0.0-rc-1");
    assert_eq!(item["cached"], false);
    assert_eq!(f.downloads(), 0);
    assert!(!exists(&f.home.path().join("tools")));
}

#[test]
fn a_hash_mismatch_installs_nothing() {
    let f = Fixture::new(true);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0.0"]);
    assert_eq!(code, 5, "{value}");
    assert_eq!(value["error"]["code"], "E_HASH_MISMATCH");
    let details = &value["error"]["details"];
    assert!(
        details["url"]
            .as_str()
            .unwrap()
            .ends_with("/dl/demo-1.0.0.tar.gz")
    );
    assert_ne!(details["expected"], details["actual"]);
    assert!(!exists(&f.install_dir("1.0.0")));
    let downloads = f.home.path().join("cache").join("downloads");
    let leftovers: Vec<_> = std::fs::read_dir(downloads)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".lock"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn some_specs_failing_is_a_partial_success() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.1", "demo@9"]);
    assert_eq!(code, 8, "{value}");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["installed"][0]["version"], "1.1.0");
    assert_eq!(value["data"]["failed"][0]["spec"], "demo@9");
    assert_eq!(value["data"]["failed"][0]["code"], "E_VERSION_NOT_FOUND");
}

#[test]
fn a_single_failing_spec_is_a_failure() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@9"]);
    assert_eq!(code, 3, "{value}");
    assert_eq!(value["error"]["code"], "E_VERSION_NOT_FOUND");
    let (code, value) = f.json(&["install", "nope"]);
    assert_eq!(code, 3, "{value}");
    assert_eq!(value["error"]["code"], "E_TOOL_UNKNOWN");
    let (code, value) = f.json(&["install", "Demo@1"]);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "E_USAGE");
}

#[test]
fn progress_events_go_to_stderr() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value, stderr) = f.run(&["--progress", "install", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
    let events: Vec<String> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v["event"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(events.first().map(String::as_str), Some("resolve"));
    for expected in ["download_progress", "verified", "extracted", "installed"] {
        assert!(
            events.iter().any(|e| e == expected),
            "{expected} in {events:?}"
        );
    }
}

#[test]
fn offline_uses_only_local_data() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["--offline", "install", "demo@1.0.0"]);
    assert_eq!(code, 4, "{value}");
    assert_eq!(value["error"]["code"], "E_OFFLINE");

    // Once the index and archive are cached, offline installs work.
    f.json(&["install", "demo@1.0.0", "--dry-run"]);
    let (code, value) = f.json(&["--offline", "install", "demo@1.0.0", "--dry-run"]);
    assert_eq!(code, 0, "{value}");
    let (code, value) = f.json(&["--offline", "install", "demo@1.0.0"]);
    assert_eq!(code, 4, "the archive is not cached: {value}");
    assert_eq!(value["error"]["code"], "E_OFFLINE");
}

#[test]
fn list_and_uninstall() {
    let f = Fixture::new(false);
    f.trust();
    let (code, empty) = f.json(&["list"]);
    assert_eq!(code, 0);
    assert_eq!(empty["data"]["installed"], json!([]));

    f.json(&["install", "demo@1.0.0", "demo@1.1.0"]);
    let (_, listed) = f.json(&["list", "demo"]);
    let versions: Vec<&str> = listed["data"]["installed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.1.0", "1.0.0"]);

    let (code, plan) = f.json(&["uninstall", "demo@1.0.0", "--dry-run"]);
    assert_eq!(code, 0, "{plan}");
    assert_eq!(plan["changed"], false);
    assert_eq!(plan["data"]["removed"][0]["version"], "1.0.0");
    assert!(exists(&f.install_dir("1.0.0")));

    let (code, removed) = f.json(&["uninstall", "demo@1.0.0"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["changed"], true);
    assert!(!exists(&f.install_dir("1.0.0")));
    assert!(exists(&f.install_dir("1.1.0")));
    let trash = f.home.path().join("tools").join(".trash");
    assert_eq!(std::fs::read_dir(trash).unwrap().count(), 0);

    let (code, again) = f.json(&["uninstall", "demo@1.0.0"]);
    assert_eq!(code, 3, "{again}");
    assert_eq!(again["error"]["code"], "E_VERSION_NOT_FOUND");

    let (code, needs_version) = f.json(&["uninstall", "demo"]);
    assert_eq!(code, 2, "{needs_version}");
}

#[test]
fn available_lists_the_index() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["install", "demo@1.0.0"]);
    let (code, value) = f.json(&["available", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["tool"], "demo");
    assert_eq!(value["data"]["platform"], f.platform.as_str());
    let versions: Vec<(&str, bool)> = value["data"]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["version"].as_str().unwrap(),
                v["installed"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        versions,
        [("2.0.0-rc-1", false), ("1.1.0", false), ("1.0.0", true)]
    );
    assert_eq!(value["data"]["aliases"]["latest"], "1.1.0");
    assert_eq!(value["data"]["aliases"]["rc"], "2.0.0-rc-1");

    let (_, latest) = f.json(&["available", "demo", "--alias", "latest"]);
    assert_eq!(latest["data"]["versions"].as_array().unwrap().len(), 1);
    assert_eq!(latest["data"]["versions"][0]["version"], "1.1.0");

    let (code, unknown) = f.json(&["available", "demo", "--alias", "nope"]);
    assert_eq!(code, 3, "{unknown}");
    assert_eq!(unknown["error"]["code"], "E_ALIAS_UNKNOWN");
}

#[test]
fn human_output_goes_to_stdout() {
    let f = Fixture::new(false);
    f.trust();
    let output = f.jtm().args(["install", "demo@1.0.0"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("installed demo@default:1.0.0 in "),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn uninstalling_the_default_clears_its_current_link() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["install", "demo@1.0.0"]);
    let current = f.home.path().join("current");
    std::fs::create_dir_all(&current).unwrap();
    std::os::unix::fs::symlink(f.install_dir("1.0.0"), current.join("demo")).unwrap();

    let (code, value) = f.json(&["uninstall", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["warnings"][0]["code"], "W_DEFAULT_CLEARED");
    assert!(!exists(&current.join("demo")));
}

#[test]
fn several_specs_install_in_parallel() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0.0", "demo@1.1.0", "demo@rc"]);
    assert_eq!(code, 0, "{value}");
    let versions: Vec<&str> = value["data"]["installed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["version"].as_str().unwrap())
        .collect();
    assert_eq!(
        versions,
        ["1.0.0", "1.1.0", "2.0.0-rc-1"],
        "results keep the order of the specs"
    );
    for version in VERSIONS {
        assert!(
            f.install_dir(version).join("VERSION").is_file(),
            "{version}"
        );
    }
}

#[test]
fn every_failure_is_listed_when_all_specs_fail() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@8", "demo@9"]);
    assert_eq!(code, 3, "{value}");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "E_VERSION_NOT_FOUND");
    let failed = value["error"]["details"]["failed"].as_array().unwrap();
    let specs: Vec<&str> = failed.iter().map(|f| f["spec"].as_str().unwrap()).collect();
    assert_eq!(specs, ["demo@8", "demo@9"]);
}
