//! `jtm default` end to end: current links, the defaults file, and installing on demand.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::PathBuf;

use common::{Fixture, exists};

fn current(f: &Fixture) -> PathBuf {
    f.home.path().join("current").join("demo")
}

fn defaults(f: &Fixture) -> String {
    fs::read_to_string(f.home.path().join("state").join("defaults.toml")).unwrap_or_default()
}

#[test]
fn default_points_the_current_link_at_an_installed_version() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["install", "demo@1.0.0"]);

    let (code, value) = f.json(&["default", "demo@1.0"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "default");
    assert_eq!(value["changed"], true);
    let data = &value["data"];
    assert_eq!(data["tool"], "demo");
    assert_eq!(data["variant"], "default");
    assert_eq!(data["version"], "1.0.0");
    assert_eq!(data["installed"], false);
    assert_eq!(PathBuf::from(data["link"].as_str().unwrap()), current(&f));
    assert!(data["previous"].is_null());
    assert_eq!(fs::read(current(&f).join("VERSION")).unwrap(), b"1.0.0");
    assert_eq!(defaults(&f), "[defaults]\ndemo = \"default:1.0.0\"\n");

    let (code, again) = f.json(&["default", "demo@1.0"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
}

#[test]
fn a_missing_version_needs_install_when_prompts_are_off() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["default", "demo@1.1"]);
    assert_eq!(code, 7, "{value}");
    assert_eq!(value["error"]["code"], "E_INPUT_REQUIRED");
    assert!(
        value["error"]["details"]["resolve"]
            .as_str()
            .unwrap()
            .contains("--install")
    );
    assert!(!exists(&f.install_dir("1.1.0")));
    assert!(!exists(&current(&f)));
}

#[test]
fn install_flag_installs_then_retargets() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["install", "demo@1.0.0"]);
    f.json(&["default", "demo@1.0.0"]);

    let (code, value) = f.json(&["default", "demo@1.1", "--install"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["version"], "1.1.0");
    assert_eq!(value["data"]["installed"], true);
    assert_eq!(value["data"]["previous"], "demo@default:1.0.0");
    assert_eq!(fs::read(current(&f).join("VERSION")).unwrap(), b"1.1.0");
    assert_eq!(defaults(&f), "[defaults]\ndemo = \"default:1.1.0\"\n");
    // The old install stays.
    assert!(exists(&f.install_dir("1.0.0")));
}

#[test]
fn yes_accepts_installing_a_missing_version() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["default", "demo@1.0", "--yes"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["installed"], true);
}

#[test]
fn uninstalling_the_default_clears_the_link_and_the_default() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["default", "demo@1.0.0", "--install"]);
    let (code, value) = f.json(&["uninstall", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["warnings"][0]["code"], "W_DEFAULT_CLEARED");
    assert!(!exists(&current(&f)));
    assert_eq!(defaults(&f), "[defaults]\n");
}
