//! `jtm doctor` end to end: the report, the exit codes and the guarantee that it only reads.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;

use common::Fixture;
use serde_json::Value;

/// Runs `jtm --json doctor --offline` in a clean environment: no proxy variables, and a HOME
/// and SHELL of our own so the real rc files are never read.
fn doctor(f: &Fixture, path: &str) -> (i32, Value) {
    let home = f.home.path().join("user-home");
    fs::create_dir_all(&home).unwrap();
    let output = f
        .jtm()
        .arg("--json")
        .arg("--offline")
        .arg("doctor")
        .env("HOME", &home)
        .env("SHELL", "/bin/bash")
        .env("PATH", path)
        .env_remove("JTM_HOOK_DIR")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "one envelope: {stdout}");
    (
        output.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap(),
    )
}

/// The report of an envelope, whether the run succeeded or failed.
fn report(value: &Value) -> &Value {
    if value["ok"] == true {
        &value["data"]
    } else {
        &value["error"]["details"]["report"]
    }
}

fn check<'a>(value: &'a Value, id: &str) -> &'a Value {
    report(value)["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no check {id} in {value}"))
}

#[test]
fn a_third_party_plugin_with_untrusted_keys_fails_with_exit_7() {
    let f = Fixture::new(false);
    let (code, value) = doctor(&f, "/usr/bin");
    assert_eq!(code, 7, "{value}");
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["error"]["code"], "E_KEY_UNTRUSTED");
    let trust = check(&value, "trust_store");
    assert_eq!(trust["status"], "failed");
    let finding = &trust["findings"][0];
    assert_eq!(finding["code"], "E_KEY_UNTRUSTED");
    assert!(
        finding["hint"].as_str().unwrap().contains("jtm trust add"),
        "{finding}"
    );
}

#[test]
fn a_healthy_home_exits_0_with_the_shell_hook_as_a_warning() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = doctor(&f, "/usr/bin");
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], true);
    assert_eq!(value["changed"], false);
    let ids: Vec<&str> = report(&value)["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "path",
            "current_links",
            "shell_hook",
            "proxy",
            "tls",
            "trust_store",
            "yanked_plugins"
        ]
    );
    assert_eq!(check(&value, "trust_store")["status"], "ok");
    assert_eq!(check(&value, "proxy")["status"], "ok");
    // Offline, so the connection test is skipped with a note, and the marketplace is not read.
    assert!(
        check(&value, "tls")["notes"][0]
            .as_str()
            .unwrap()
            .contains("offline")
    );
    assert_eq!(check(&value, "yanked_plugins")["status"], "skipped");
    // No rc file in the clean HOME loads the hook: a warning, never an error.
    let warnings = value["warnings"].as_array().unwrap();
    let hook = warnings
        .iter()
        .find(|w| w["code"] == "W_SHELL_HOOK_MISSING")
        .unwrap_or_else(|| panic!("{warnings:?}"));
    assert!(
        hook["details"]["hint"]
            .as_str()
            .unwrap()
            .contains("jtm self setup")
    );
}

#[test]
fn a_dangling_current_link_exits_4_and_names_the_fix() {
    let f = Fixture::new(false);
    f.trust();
    f.json(&["install", "demo@1.0.0"]);
    let (code, value) = f.json(&["default", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");

    let link = f.home.path().join("current").join("demo");
    let bin = link.join("bin");
    let (code, value) = doctor(&f, &bin.display().to_string());
    assert_eq!(code, 0, "a default on PATH is healthy: {value}");
    assert_eq!(check(&value, "path")["status"], "ok");
    assert_eq!(check(&value, "current_links")["status"], "ok");

    // The default is on PATH no longer.
    let (_, value) = doctor(&f, "/usr/bin");
    assert_eq!(
        check(&value, "path")["findings"][0]["code"],
        "W_PATH_MISSING"
    );

    fs::remove_dir_all(f.install_dir("1.0.0")).unwrap();
    let (code, value) = doctor(&f, &bin.display().to_string());
    assert_eq!(code, 4, "{value}");
    assert_eq!(value["error"]["code"], "E_IO");
    let finding = &check(&value, "current_links")["findings"][0];
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("does not exist"),
        "{finding}"
    );
    assert!(
        finding["hint"]
            .as_str()
            .unwrap()
            .contains("jtm install demo@default:1.0.0"),
        "{finding}"
    );
}

#[test]
fn an_invalid_proxy_exits_2_without_leaking_the_password() {
    let f = Fixture::new(false);
    f.trust();
    let home = f.home.path().join("user-home");
    fs::create_dir_all(&home).unwrap();
    let output = f
        .jtm()
        .args(["--json", "--offline", "doctor"])
        .env("HOME", &home)
        .env("HTTPS_PROXY", "http://alice:s3cret@[bad")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stdout.contains("s3cret") && !stderr.contains("s3cret"),
        "{stdout}\n{stderr}"
    );
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["error"]["code"], "E_USAGE");
}

#[test]
fn doctor_does_not_prompt_or_change_anything() {
    let f = Fixture::new(false);
    f.trust();
    let before = snapshot(f.home.path());
    let output = f
        .jtm()
        .args(["--offline", "doctor"])
        .env("HOME", f.home.path().join("user-home"))
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[ok] trust_store"), "{stdout}");
    assert_eq!(snapshot(f.home.path()), before, "doctor wrote to the home");
}

/// Every path under `dir` with its size, to see whether anything was written.
fn snapshot(dir: &std::path::Path) -> Vec<(String, u64)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, u64)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            out.push((entry.path().display().to_string(), meta.len()));
            if meta.is_dir() {
                walk(&entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}
