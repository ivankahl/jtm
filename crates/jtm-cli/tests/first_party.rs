//! The first-party manifests in `plugins/` end to end (SPEC.md section 15).
//!
//! Each test copies a real manifest into a fixture home under a test name (`fp-<name>`), with
//! its root keys swapped for a key generated here, so it is an external plugin the test can
//! sign indices for. Everything else in the manifest is used as shipped. Indices and archives
//! come from a local mock server; nothing touches the real network.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use jtm_archive::testing::{E, dir, exe, file, tar_gz, zip};
use jtm_security::testing::TestKey;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixture jtm home serving first-party plugins under test names.
struct Home {
    home: tempfile::TempDir,
    rt: Runtime,
    server: MockServer,
    key: TestKey,
    platform: String,
    os: &'static str,
    /// `[plugins.<name>]` sections for the config file.
    plugin_config: Vec<String>,
}

/// One version a fixture index offers.
struct Version<'a> {
    variant: &'a str,
    version: &'a str,
    tags: &'a [&'a str],
    archive: Archive,
}

/// An archive and its kind as the index names it.
struct Archive {
    kind: &'static str,
    bytes: Vec<u8>,
}

/// The manifest shipped for `name`.
fn shipped(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins")
        .join(name)
        .join("plugin.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The test name of first-party plugin `name`.
fn test_name(name: &str) -> String {
    format!("fp-{name}")
}

impl Home {
    fn new() -> Home {
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let platform = jtm_core::Platform::detect().unwrap();
        Home {
            home: tempfile::tempdir().unwrap(),
            rt,
            server,
            key: TestKey::generate(),
            platform: platform.as_str().to_owned(),
            os: platform.os().as_str(),
            plugin_config: Vec::new(),
        }
    }

    /// Installs the shipped manifest for `name` as `fp-<name>`, signed by the test key, with
    /// an index of `versions` for this platform, or for `any` with `any_platform`.
    fn add(&mut self, name: &str, any_platform: bool, versions: &[Version<'_>]) {
        let plugin = test_name(name);
        let mut manifest: toml::Table = toml::from_str(&shipped(name)).unwrap();
        manifest["name"] = plugin.clone().into();
        let index = manifest["index"].as_table_mut().unwrap();
        index["signing_keys"] = vec![self.key.public_str()].into();
        index.remove("threshold");
        index.remove("keys_url");
        // Requirements name other first-party plugins, which carry test names here too.
        if let Some(requires) = manifest.get_mut("requires").and_then(|r| r.as_table_mut()) {
            *requires = requires
                .iter()
                .map(|(tool, req)| (test_name(tool), req.clone()))
                .collect();
        }
        let dir = self
            .home
            .path()
            .join("plugins")
            .join(format!("{plugin}@test"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), toml::to_string(&manifest).unwrap()).unwrap();

        let platform = if any_platform { "any" } else { &self.platform };
        let mut entries = Vec::new();
        for v in versions {
            let file = format!("{plugin}-{}-{}.{}", v.variant, v.version, v.archive.kind);
            entries.push(json!({
                "variant": v.variant,
                "version": v.version,
                "tags": v.tags,
                "url": format!("https://dl.example.test/{file}"),
                "archive": v.archive.kind,
                "size": v.archive.bytes.len(),
                "sha256": jtm_security::sha256_hex(&v.archive.bytes),
            }));
            self.serve(&format!("/dl/{file}"), v.archive.bytes.clone());
        }
        let index = serde_json::to_vec(&json!({
            "format": 1,
            "plugin": plugin,
            "platform": platform,
            "sequence": 1,
            "generated": "2026-01-01T00:00:00Z",
            "expires": "2099-01-01T00:00:00Z",
            "entries": entries,
        }))
        .unwrap();
        let at = format!("/index/{plugin}-{platform}.json");
        self.serve(&format!("{at}.minisig"), self.key.sign(&index));
        self.serve(&at, index);
        self.plugin_config.push(format!(
            "[plugins.{plugin}]\nindex_url = \"{}{at}\"\n",
            self.server.uri()
        ));
        self.write_config();
        let (code, value) = self.json(
            self.home.path(),
            &["trust", "add", &self.key.public_str(), "--scope", &plugin],
        );
        assert_eq!(code, 0, "{value}");
    }

    fn write_config(&self) {
        let config = format!(
            "[security]\nallow_http_mirrors = true\n\n[mirrors]\n\"https://dl.example.test/\" = \
             \"{}/dl/\"\n\n{}",
            self.server.uri(),
            self.plugin_config.join("\n")
        );
        fs::write(self.home.path().join("config.toml"), config).unwrap();
    }

    fn serve(&self, at: &str, body: Vec<u8>) {
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(&self.server),
        );
    }

    fn jtm(&self, cwd: &Path) -> Command {
        let mut cmd = Command::cargo_bin("jtm").unwrap();
        cmd.current_dir(cwd)
            .env_remove("JTM_LOG")
            .env_remove("JTM_CONFIG")
            .env_remove("JTM_OFFLINE")
            .env("JTM_HOME", self.home.path());
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("JTM_SESSION_")
                || key.to_string_lossy().starts_with("JTM_PROJECT_")
            {
                cmd.env_remove(key);
            }
        }
        cmd
    }

    /// Runs `args` with `--json` in `cwd`; returns the exit code and the one envelope.
    fn json(&self, cwd: &Path, args: &[&str]) -> (i32, Value) {
        let output = self.jtm(cwd).arg("--json").args(args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.lines().count(),
            1,
            "one envelope: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (
            output.status.code().unwrap(),
            serde_json::from_str(&stdout).unwrap(),
        )
    }

    /// Runs `args` in the home directory and expects success.
    fn ok(&self, args: &[&str]) -> Value {
        let (code, value) = self.json(self.home.path(), args);
        assert_eq!(code, 0, "{value}");
        value
    }

    fn install_dir(&self, name: &str, variant: &str, version: &str) -> PathBuf {
        self.home
            .path()
            .join("tools")
            .join(test_name(name))
            .join(format!("{variant}-{version}"))
    }

    fn receipt(&self, name: &str, variant: &str, version: &str) -> Value {
        let dir = self.install_dir(name, variant, version);
        serde_json::from_slice(&fs::read(dir.join(".jtm-receipt.json")).unwrap()).unwrap()
    }

    /// A project directory inside the home, with `files` written into it.
    fn project(&self, files: &[(&str, &str)]) -> PathBuf {
        let dir = self.home.path().join("project");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        dir
    }
}

/// The executables `name`'s shipped manifest declares for `os`.
fn executables(name: &str, os: &str) -> Vec<String> {
    let manifest = jtm_plugin::Manifest::parse(&shipped(name)).unwrap();
    manifest.executables.for_os(os).to_vec()
}

/// An archive with `top/` holding `home_prefix` + `bin/<exe>` for each of `name`'s executables
/// on `os`, plus `extra` entries. Windows gets a zip and everything else a tar.gz, as vendors
/// publish them.
fn tool_archive(name: &str, os: &str, top: &str, home_prefix: &str, extra: Vec<E>) -> Archive {
    let mut entries = vec![dir(&format!("{top}/"))];
    for exe_name in executables(name, os) {
        entries.push(exe(
            &format!("{top}/{home_prefix}bin/{exe_name}"),
            format!("#!/bin/sh\necho {exe_name}\n").as_bytes(),
        ));
    }
    entries.extend(extra);
    if os == "windows" {
        Archive {
            kind: "zip",
            bytes: zip(&entries),
        }
    } else {
        Archive {
            kind: "tar.gz",
            bytes: tar_gz(&entries),
        }
    }
}

/// A JDK archive as a vendor ships it for `os`: an app bundle on macOS.
fn jdk(os: &str, version: &str) -> Archive {
    let top = format!("jdk-{version}");
    if os == "macos" {
        tool_archive(
            "java",
            os,
            &top,
            "Contents/Home/",
            vec![
                file(&format!("{top}/Contents/Info.plist"), b"<plist/>"),
                file(&format!("{top}/Contents/Home/release"), version.as_bytes()),
            ],
        )
    } else {
        tool_archive(
            "java",
            os,
            &top,
            "",
            vec![file(&format!("{top}/release"), version.as_bytes())],
        )
    }
}

fn java_home(os: &str, h: &Home, variant: &str, version: &str) -> PathBuf {
    let dir = h.install_dir("java", variant, version);
    if os == "macos" {
        dir.join("Contents").join("Home")
    } else {
        dir
    }
}

fn with_java(h: &mut Home) {
    let os = h.os;
    h.add(
        "java",
        false,
        &[
            Version {
                variant: "temurin",
                version: "21.0.5+11",
                tags: &["lts", "ga"],
                archive: jdk(os, "21.0.5+11"),
            },
            Version {
                variant: "temurin",
                version: "23.0.1+11",
                tags: &["ga"],
                archive: jdk(os, "23.0.1+11"),
            },
            Version {
                variant: "temurin",
                version: "24-ea+3",
                tags: &["ea"],
                archive: jdk(os, "24-ea+3"),
            },
            Version {
                variant: "corretto",
                version: "21.0.5.11.1",
                tags: &["lts", "ga"],
                archive: jdk(os, "21.0.5.11.1"),
            },
            Version {
                variant: "zulu",
                version: "11.0.25+9",
                tags: &["lts", "ga"],
                archive: jdk(os, "11.0.25+9"),
            },
        ],
    );
}

/// The value `name` has in the environment `jtm exec` gives a command in `cwd`.
fn exec_env(h: &Home, cwd: &Path, specs: &[&str], name: &str) -> String {
    let mut args: Vec<String> = vec!["exec".into()];
    args.extend(specs.iter().map(|s| (*s).to_owned()));
    args.push("--".into());
    if cfg!(windows) {
        args.extend(["cmd".into(), "/c".into(), format!("echo %{name}%")]);
    } else {
        args.extend(["sh".into(), "-c".into(), format!("printf %s \"${name}\"")]);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, value) = h.json(cwd, &args);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["exit_code"], 0, "{value}");
    value["data"]["stdout"].as_str().unwrap().trim().to_owned()
}

// --- java (T5.2) ---

#[test]
fn the_java_manifest_declares_variants_aliases_layout_and_interop() {
    let m = jtm_plugin::Manifest::parse(&shipped("java")).unwrap();
    assert_eq!(m.name, "java");
    assert_eq!(m.default_variant(), "temurin");
    assert_eq!(
        m.versions.variants,
        [
            "temurin",
            "corretto",
            "zulu",
            "liberica",
            "microsoft",
            "graalvm-community"
        ]
    );
    assert!(m.aliases.contains_key("lts") && m.aliases.contains_key("latest"));
    assert_eq!(m.layout.home_subdir_for("macos"), Some("Contents/Home"));
    assert_eq!(m.layout.home_subdir_for("linux"), None);
    assert_eq!(m.layout.home_subdir_for("windows"), None);
    assert_eq!(m.env["JAVA_HOME"], "{home}");
    let files: Vec<&str> = m.interop.iter().map(|i| i.file.as_str()).collect();
    assert_eq!(files, [".sdkmanrc", ".tool-versions", ".java-version"]);
    assert_eq!(m.index.threshold(), 2);
    assert!(m.index.keys_url.is_some());
    assert!(m.hooks.post_extract.is_none());
}

#[test]
fn java_installs_the_lts_alias_and_each_variant() {
    let mut h = Home::new();
    with_java(&mut h);

    let value = h.ok(&["install", "fp-java@lts"]);
    assert_eq!(value["data"]["installed"][0]["variant"], "temurin");
    assert_eq!(value["data"]["installed"][0]["version"], "21.0.5+11");

    // A bare `java` is the newest GA version, never an early-access build.
    let value = h.ok(&["install", "fp-java"]);
    assert_eq!(value["data"]["installed"][0]["version"], "23.0.1+11");

    let value = h.ok(&["install", "fp-java@corretto:21", "fp-java@zulu:lts"]);
    assert_eq!(value["data"]["installed"][0]["version"], "21.0.5.11.1");
    assert_eq!(value["data"]["installed"][1]["version"], "11.0.25+9");

    for (variant, version) in [
        ("temurin", "21.0.5+11"),
        ("temurin", "23.0.1+11"),
        ("corretto", "21.0.5.11.1"),
        ("zulu", "11.0.25+9"),
    ] {
        let home = java_home(h.os, &h, variant, version);
        assert_eq!(fs::read(home.join("release")).unwrap(), version.as_bytes());
        let receipt = h.receipt("java", variant, version);
        let expected_home = if h.os == "macos" { "Contents/Home" } else { "" };
        assert_eq!(receipt["home"], expected_home, "{receipt}");
    }
}

#[test]
fn java_home_points_at_the_tool_home() {
    let mut h = Home::new();
    with_java(&mut h);
    h.ok(&["install", "fp-java@21"]);
    let home = h.home.path().to_path_buf();
    let got = exec_env(&h, &home, &["fp-java@21"], "JAVA_HOME");
    assert_eq!(
        PathBuf::from(got),
        java_home(h.os, &h, "temurin", "21.0.5+11")
    );
}

#[test]
fn java_reads_sdkmanrc_tool_versions_and_java_version() {
    let mut h = Home::new();
    with_java(&mut h);
    h.ok(&[
        "install",
        "fp-java@temurin:21",
        "fp-java@corretto:21",
        "fp-java@zulu:11",
    ]);
    for (files, variant, version) in [
        (
            vec![(".sdkmanrc", "java=21.0.5-amzn\n")],
            "corretto",
            "21.0.5.11.1",
        ),
        (
            vec![(".sdkmanrc", "java=21.0.5-tem\n")],
            "temurin",
            "21.0.5+11",
        ),
        (
            vec![(".tool-versions", "java zulu-11\n")],
            "zulu",
            "11.0.25+9",
        ),
        (
            vec![(".java-version", "corretto-21\n")],
            "corretto",
            "21.0.5.11.1",
        ),
        (vec![(".java-version", "21\n")], "temurin", "21.0.5+11"),
        // `.sdkmanrc` wins over `.java-version` in one directory.
        (
            vec![
                (".java-version", "11\n"),
                (".sdkmanrc", "java=21.0.5-tem\n"),
            ],
            "temurin",
            "21.0.5+11",
        ),
    ] {
        let project = h.project(&files);
        let (code, value) = h.json(&project, &["current", "fp-java"]);
        assert_eq!(code, 0, "{value}");
        let item = &value["data"]["tools"][0];
        assert_eq!(item["layer"], "project", "{files:?}: {value}");
        assert_eq!(item["variant"], variant, "{files:?}: {value}");
        assert_eq!(item["version"], version, "{files:?}: {value}");
        let got = exec_env(&h, &project, &[], "JAVA_HOME");
        assert_eq!(PathBuf::from(got), java_home(h.os, &h, variant, version));
    }
}

#[test]
fn an_unknown_sdkman_vendor_is_an_error() {
    let mut h = Home::new();
    with_java(&mut h);
    let project = h.project(&[(".sdkmanrc", "java=21.0.5-nope\n")]);
    let (code, value) = h.json(&project, &["current", "fp-java"]);
    assert_ne!(code, 0, "{value}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("suffix"),
        "{value}"
    );
}

#[test]
fn pin_writes_java_interop_files() {
    let mut h = Home::new();
    with_java(&mut h);
    h.ok(&["install", "fp-java@corretto:21"]);
    let project = h.project(&[]);
    for (format, file, expected) in [
        ("sdkmanrc", ".sdkmanrc", "java=21.0.5.11.1-amzn\n"),
        (
            "tool-versions",
            ".tool-versions",
            "java corretto-21.0.5.11.1\n",
        ),
        ("java-version", ".java-version", "corretto-21.0.5.11.1\n"),
    ] {
        let (code, value) = h.json(
            &project,
            &["pin", "fp-java@corretto:21", "--exact", "--format", format],
        );
        assert_eq!(code, 0, "{value}");
        assert_eq!(fs::read_to_string(project.join(file)).unwrap(), expected);
    }
}

#[test]
fn the_java_layout_finds_each_os_home_on_any_host() {
    use jtm_core::install::layout;
    use jtm_core::platform::Os;

    let manifest = jtm_plugin::Manifest::parse(&shipped("java")).unwrap();
    for os in [Os::Macos, Os::Linux, Os::Windows] {
        let archive = jdk(os.as_str(), "21.0.5+11");
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("jdk");
        fs::write(&path, &archive.bytes).unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        let format = if archive.kind == "zip" {
            jtm_archive::Format::Zip
        } else {
            jtm_archive::Format::TarGz
        };
        let options = jtm_archive::Options {
            strip_components: layout::extract_strip(&manifest.layout),
            ..jtm_archive::Options::default()
        };
        jtm_archive::extract(&path, format, &out, &options).unwrap();
        let placed = layout::apply("java", &out, &manifest.layout, os).unwrap();
        assert_eq!(placed.root, out.join("jdk-21.0.5+11"));
        let home = if os == Os::Macos { "Contents/Home" } else { "" };
        assert_eq!(placed.home, Path::new(home), "{os}");
        layout::check_executables("java", &placed, &manifest.layout, &manifest.executables, os)
            .unwrap_or_else(|e| panic!("{os}: {e}"));
    }
}
