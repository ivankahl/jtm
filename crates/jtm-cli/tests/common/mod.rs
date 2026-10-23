//! A fixture jtm home for end-to-end tests: a plugin, an index signed by a key generated here,
//! and archives served by a local mock server reached through `[mirrors]`. Nothing touches the
//! real network.

#![allow(clippy::unwrap_used, clippy::panic, dead_code, unreachable_pub)]

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    pub key: Arc<TestKey>,
    pub platform: String,
    /// Whether the user config lists [`Fixture::key`] in `plugins.demo.signing_keys`.
    trusted: Cell<bool>,
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
        Fixture::with_key(tamper, Arc::new(TestKey::generate()))
    }

    /// Another home that trusts the same publisher key: a second machine, such as the
    /// air-gapped one an export is carried to.
    pub fn sibling(&self) -> Fixture {
        Fixture::with_key(false, Arc::clone(&self.key))
    }

    fn with_key(tamper: bool, key: Arc<TestKey>) -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let platform = jtm_core::Platform::detect().unwrap().as_str().to_owned();
        let f = Fixture {
            home,
            rt,
            server,
            key,
            platform,
            trusted: Cell::new(false),
        };
        f.write_plugin();
        f.write_config();

        for version in VERSIONS {
            let mut served = archive(version);
            if tamper && *version == "1.0.0" {
                served[20] ^= 0xff;
            }
            f.serve(&format!("/dl/demo-{version}.tar.gz"), served);
        }
        let (index, signature) = f.signed_index();
        let index_path = format!("/index/demo-{}.json", f.platform);
        f.serve(&format!("{index_path}.minisig"), signature);
        f.serve(&index_path, index);
        f
    }

    /// The signed index describing [`VERSIONS`], and its signature.
    pub fn signed_index(&self) -> (Vec<u8>, Vec<u8>) {
        let entries: Vec<_> = VERSIONS
            .iter()
            .map(|version| {
                let bytes = archive(version);
                json!({
                    "variant": "default",
                    "version": version,
                    "tags": if version.contains("rc") { json!(["rc"]) } else { json!(["ga"]) },
                    "url": format!("https://dl.example.test/demo-{version}.tar.gz"),
                    "archive": "tar.gz",
                    "size": bytes.len(),
                    "sha256": jtm_security::sha256_hex(&bytes),
                })
            })
            .collect();
        let index = serde_json::to_vec(&json!({
            "format": 1,
            "plugin": "demo",
            "platform": self.platform,
            "sequence": 1,
            "generated": "2026-01-01T00:00:00Z",
            "expires": "2099-01-01T00:00:00Z",
            "entries": entries,
        }))
        .unwrap();
        let signature = self.key.sign(&index);
        (index, signature)
    }

    /// Lays out `<dir>/index/` and `<dir>/dl/` as a mirror directory holds them, and points
    /// `[mirrors]` at it with `target` (a `file://` URL or a path ending in a slash) instead
    /// of the mock server. With `tamper`, the `1.0.0` archive differs from what the index
    /// promises.
    pub fn use_directory_mirror(&self, dir: &Path, target: &str, tamper: bool) {
        let (index, signature) = self.signed_index();
        std::fs::create_dir_all(dir.join("index")).unwrap();
        std::fs::create_dir_all(dir.join("dl")).unwrap();
        let name = format!("demo-{}.json", self.platform);
        std::fs::write(dir.join("index").join(&name), index).unwrap();
        std::fs::write(dir.join("index").join(format!("{name}.minisig")), signature).unwrap();
        for version in VERSIONS {
            let mut bytes = archive(version);
            if tamper && *version == "1.0.0" {
                bytes[20] ^= 0xff;
            }
            std::fs::write(dir.join("dl").join(format!("demo-{version}.tar.gz")), bytes).unwrap();
        }
        let config = format!(
            "[mirrors]\n\"https://index.example.test/\" = \"{target}index/\"\n\
             \"https://dl.example.test/\" = \"{target}dl/\"\n"
        );
        self.save_config(config);
    }

    /// Points `[mirrors]` at a directory `jtm mirror export` wrote, the way its output
    /// suggests: one entry per host, aimed at that host's directory in the export.
    pub fn use_export_mirror(&self, export: &Path) {
        let root = export.display().to_string().replace('\\', "/");
        let config = format!(
            "[mirrors]\n\"https://index.example.test/\" = \"{root}/index.example.test/\"\n\
             \"https://dl.example.test/\" = \"{root}/dl.example.test/\"\n"
        );
        self.save_config(config);
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
        self.save_config(config);
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

    /// Lists the publisher key in `plugins.demo.signing_keys` in the user config, now and
    /// in every config the fixture writes after this.
    pub fn trust(&self) {
        self.trusted.set(true);
        let path = self.home.path().join("config.toml");
        let config = std::fs::read_to_string(&path).unwrap_or_default();
        self.save_config(config);
    }

    /// The `[plugins.demo]` table that trusts the publisher key, with `extra` lines in it.
    pub fn demo_table(&self, extra: &str) -> String {
        format!(
            "[plugins.demo]\n{extra}signing_keys = [\"{}\"]\n",
            self.key.public_str()
        )
    }

    /// Writes `config` as the user config, trusting the publisher key once [`Fixture::trust`]
    /// was called, unless `config` already has a `[plugins.demo]` table.
    pub fn save_config(&self, mut config: String) {
        if self.trusted.get() && !config.contains("[plugins.demo]") {
            config.push('\n');
            config.push_str(&self.demo_table(""));
        }
        std::fs::write(self.home.path().join("config.toml"), config).unwrap();
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
