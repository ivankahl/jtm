//! A fixture jtm home for end-to-end tests: a plugin, an index signed by a key generated here,
//! and archives served by a local mock server reached through `[mirrors]`. Nothing touches the
//! real network.

#![allow(clippy::unwrap_used, clippy::panic, dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use jtm_archive::testing::{exe, file, tar_gz};
use jtm_security::testing::TestKey;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const VERSIONS: &[&str] = &["1.0.0", "1.1.0", "2.0.0-rc-1"];

pub struct Fixture {
    pub home: tempfile::TempDir,
    pub rt: Runtime,
    pub server: MockServer,
    pub key: TestKey,
    pub platform: String,
}

pub fn archive(version: &str) -> Vec<u8> {
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
    pub fn new(tamper: bool) -> Fixture {
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

    pub fn write_plugin(&self) {
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

[env]
DEMO_HOME = "{{home}}"

[ide]
maven_toolchain = "jdk"
gradle_installations = true
"#,
            self.key.public_str()
        );
        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();
    }

    pub fn write_config(&self) {
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

    pub fn serve(&self, at: &str, body: Vec<u8>) {
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(&self.server),
        );
    }

    pub fn downloads(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().starts_with("/dl/"))
            .count()
    }

    pub fn jtm(&self) -> Command {
        let mut cmd = Command::cargo_bin("jtm").unwrap();
        cmd.env_remove("JTM_LOG")
            .env_remove("JTM_CONFIG")
            .env_remove("JTM_OFFLINE")
            .env("JTM_HOME", self.home.path());
        cmd
    }

    /// Runs `args` with `--json`; returns the exit code, the one envelope, and stderr.
    pub fn run(&self, args: &[&str]) -> (i32, Value, String) {
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

    pub fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, value, _) = self.run(args);
        (code, value)
    }

    pub fn trust(&self) {
        let (code, value) = self.json(&["trust", "add", &self.key.public_str(), "--scope", "demo"]);
        assert_eq!(code, 0, "{value}");
    }

    /// The path of the `jtm` binary under test.
    pub fn exe(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_jtm"))
    }

    pub fn install_dir(&self, version: &str) -> PathBuf {
        self.home
            .path()
            .join("tools")
            .join("demo")
            .join(format!("default-{version}"))
    }
}

pub fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}
