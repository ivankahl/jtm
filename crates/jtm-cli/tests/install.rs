//! `jtm install`, `uninstall`, `list` and `available` end to end: a fixture plugin, an index
//! signed by a key generated here, and archives served by a local mock server reached through
//! `[mirrors]`. Nothing touches the real network.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use jtm_archive::testing::{exe, file, tar_gz};
use jtm_security::testing::TestKey;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERSIONS: &[&str] = &["1.0.0", "1.1.0", "2.0.0-rc-1"];

struct Fixture {
    home: tempfile::TempDir,
    rt: Runtime,
    server: MockServer,
    key: TestKey,
    platform: String,
}

fn archive(version: &str) -> Vec<u8> {
    tar_gz(&[
        exe(
            &format!("demo-{version}/bin/demo"),
            b"#!/bin/sh\necho demo\n",
        ),
        exe(&format!("demo-{version}/bin/demo.cmd"), b"@echo demo\r\n"),
        file(&format!("demo-{version}/VERSION"), version.as_bytes()),
    ])
}

impl Fixture {
    /// A home with the `demo` plugin installed and an index serving [`VERSIONS`]. With
    /// `tamper`, the server sends different bytes than the index promises for `1.0.0`.
    fn new(tamper: bool) -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let key = TestKey::generate();
        let platform = jtm_core::Platform::detect().unwrap().as_str().to_owned();
        let f = Fixture {
            home,
            rt,
            server,
            key,
            platform,
        };
        f.write_plugin();
        f.write_config();

        let mut entries = Vec::new();
        for version in VERSIONS {
            let bytes = archive(version);
            entries.push(json!({
                "variant": "default",
                "version": version,
                "tags": if version.contains("rc") { json!(["rc"]) } else { json!(["ga"]) },
                "url": format!("https://dl.example.test/demo-{version}.tar.gz"),
                "archive": "tar.gz",
                "size": bytes.len(),
                "sha256": jtm_security::sha256_hex(&bytes),
            }));
            let mut served = bytes;
            if tamper && *version == "1.0.0" {
                served[20] ^= 0xff;
            }
            f.serve(&format!("/dl/demo-{version}.tar.gz"), served);
        }
        let index = serde_json::to_vec(&json!({
            "format": 1,
            "plugin": "demo",
            "platform": f.platform,
            "sequence": 1,
            "generated": "2026-01-01T00:00:00Z",
            "expires": "2099-01-01T00:00:00Z",
            "entries": entries,
        }))
        .unwrap();
        let signature = f.key.sign(&index);
        let index_path = format!("/index/demo-{}.json", f.platform);
        f.serve(&format!("{index_path}.minisig"), signature);
        f.serve(&index_path, index);
        f
    }

    fn write_plugin(&self) {
        let dir = self.home.path().join("plugins").join("demo@0123abc");
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = format!(
            r#"schema = 1
name = "demo"
display_name = "Demo"

[versions]
scheme = "semver-loose"
default_alias = "latest"

[aliases]
latest = {{ kind = "highest" }}
rc = {{ kind = "index-tag", tag = "rc" }}

[index]
url = "https://index.example.test/demo-{{os}}-{{arch}}.json"
signing_keys = ["{}"]
format = 1

[layout]
bin_dirs = ["bin"]

[executables]
unix = ["demo"]
windows = ["demo.cmd"]
"#,
            self.key.public_str()
        );
        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();
    }

    fn write_config(&self) {
        let uri = self.server.uri();
        let config = format!(
            r#"[security]
allow_http_mirrors = true

[mirrors]
"https://index.example.test/" = "{uri}/index/"
"https://dl.example.test/" = "{uri}/dl/"
"#
        );
        std::fs::write(self.home.path().join("config.toml"), config).unwrap();
    }

    fn serve(&self, at: &str, body: Vec<u8>) {
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(&self.server),
        );
    }

    fn downloads(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().starts_with("/dl/"))
            .count()
    }

    fn jtm(&self) -> Command {
        let mut cmd = Command::cargo_bin("jtm").unwrap();
        cmd.env_remove("JTM_LOG")
            .env_remove("JTM_CONFIG")
            .env_remove("JTM_OFFLINE")
            .env("JTM_HOME", self.home.path());
        cmd
    }

    /// Runs `args` with `--json`; returns the exit code, the one envelope, and stderr.
    fn run(&self, args: &[&str]) -> (i32, Value, String) {
        let output = self.jtm().arg("--json").args(args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stdout.lines().count(),
            1,
            "one envelope: {stdout}\n{stderr}"
        );
        (
            output.status.code().unwrap(),
            serde_json::from_str(&stdout).unwrap(),
            stderr,
        )
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, value, _) = self.run(args);
        (code, value)
    }

    fn trust(&self) {
        let (code, value) = self.json(&["trust", "add", &self.key.public_str(), "--scope", "demo"]);
        assert_eq!(code, 0, "{value}");
    }

    fn install_dir(&self, version: &str) -> PathBuf {
        self.home
            .path()
            .join("tools")
            .join("demo")
            .join(format!("default-{version}"))
    }
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

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
