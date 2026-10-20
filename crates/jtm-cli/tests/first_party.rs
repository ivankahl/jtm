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

// --- maven, gradle, kotlin, spring-boot-cli (T5.3) ---

/// The platform-independent first-party plugins, with the top directory and a version of
/// their archives.
const ANY_PLATFORM: &[(&str, &str)] = &[
    ("maven", "apache-maven-{v}"),
    ("gradle", "gradle-{v}"),
    ("kotlin", "kotlinc"),
    ("spring-boot-cli", "spring-{v}"),
];

fn any_archive(name: &str, os: &str, version: &str) -> Archive {
    let top = ANY_PLATFORM
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, top)| top.replace("{v}", version))
        .unwrap();
    tool_archive(
        name,
        os,
        &top,
        "",
        vec![file(&format!("{top}/VERSION"), version.as_bytes())],
    )
}

/// Adds `name` with an `any` index of `versions` (version, tags).
fn with_any(h: &mut Home, name: &str, versions: &[(&str, &[&str])]) {
    let os = h.os;
    let versions: Vec<Version<'_>> = versions
        .iter()
        .map(|(version, tags)| Version {
            variant: "default",
            version,
            tags,
            archive: any_archive(name, os, version),
        })
        .collect();
    h.add(name, true, &versions);
}

#[test]
fn the_build_tool_manifests_are_platform_independent_and_require_java() {
    for (name, java) in [
        ("maven", ">=8"),
        ("gradle", ">=8"),
        ("kotlin", ">=8"),
        ("spring-boot-cli", ">=17"),
    ] {
        let m = jtm_plugin::Manifest::parse(&shipped(name)).unwrap();
        assert_eq!(m.name, name);
        assert!(m.index.platform_independent(), "{name}");
        assert_eq!(m.index.index_platform("linux-x64"), "any");
        assert_eq!(m.requires["java"], java, "{name}");
        assert!(m.versions.variants.is_empty(), "{name}");
        assert!(m.aliases.contains_key("latest"), "{name}");
    }
    let java = jtm_plugin::Manifest::parse(&shipped("java")).unwrap();
    assert!(!java.index.platform_independent());
}

#[test]
fn each_build_tool_installs_from_an_any_index() {
    let mut h = Home::new();
    for (name, _) in ANY_PLATFORM {
        with_any(&mut h, name, &[("1.2.0", &["ga"])]);
    }
    let home = h.home.path().to_path_buf();
    for (name, env) in [
        ("maven", Some("MAVEN_HOME")),
        ("gradle", Some("GRADLE_HOME")),
        ("kotlin", Some("KOTLIN_HOME")),
        ("spring-boot-cli", None),
    ] {
        let spec = format!("{}@1.2.0", test_name(name));
        let value = h.ok(&["install", &spec]);
        assert_eq!(
            value["data"]["installed"][0]["status"], "installed",
            "{value}"
        );
        let dir = h.install_dir(name, "default", "1.2.0");
        assert_eq!(fs::read(dir.join("VERSION")).unwrap(), b"1.2.0");
        for exe_name in executables(name, h.os) {
            assert!(
                dir.join("bin").join(&exe_name).is_file(),
                "{name}: {exe_name}"
            );
        }
        assert_eq!(h.receipt(name, "default", "1.2.0")["platform"], h.platform);
        if let Some(env) = env {
            assert_eq!(
                PathBuf::from(exec_env(&h, &home, &[&spec], env)),
                dir,
                "{name}"
            );
        }
    }
    let maven = h.install_dir("maven", "default", "1.2.0");
    assert_eq!(
        PathBuf::from(exec_env(&h, &home, &["fp-maven@1.2.0"], "M2_HOME")),
        maven
    );
}

#[test]
fn maven_and_gradle_aliases_pick_the_right_line() {
    let mut h = Home::new();
    with_any(
        &mut h,
        "maven",
        &[("3.9.9", &[]), ("3.8.8", &[]), ("4.0.0-rc-2", &[])],
    );
    with_any(
        &mut h,
        "gradle",
        &[("8.10.2", &[]), ("8.11-rc-1", &["rc"]), ("7.6.4", &[])],
    );
    for (spec, version) in [
        ("fp-maven", "3.9.9"),
        ("fp-maven@3", "3.9.9"),
        ("fp-maven@3.8", "3.8.8"),
        ("fp-gradle", "8.10.2"),
        ("fp-gradle@rc", "8.11-rc-1"),
        ("fp-gradle@7", "7.6.4"),
    ] {
        let value = h.ok(&["install", spec, "--dry-run"]);
        assert_eq!(value["data"]["installed"][0]["version"], version, "{spec}");
    }
    // Maven 4 has no release yet, only a release candidate.
    let (code, value) = h.json(h.home.path(), &["install", "fp-maven@4", "--dry-run"]);
    assert_eq!(code, 3, "{value}");
}

#[test]
fn wrapper_files_pin_maven_and_gradle() {
    let mut h = Home::new();
    with_any(&mut h, "maven", &[("3.9.9", &[]), ("3.8.8", &[])]);
    with_any(&mut h, "gradle", &[("8.10.2", &[]), ("7.6.4", &[])]);
    h.ok(&["install", "fp-maven@3.8.8", "fp-gradle@7.6.4"]);
    let project = h.project(&[
        (
            ".mvn/wrapper/maven-wrapper.properties",
            "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/\
             apache-maven/3.8.8/apache-maven-3.8.8-bin.zip\n",
        ),
        (
            "gradle/wrapper/gradle-wrapper.properties",
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-7.6.4-bin.zip\n",
        ),
    ]);
    let (code, value) = h.json(&project, &["current"]);
    assert_eq!(code, 0, "{value}");
    for tool in ["fp-maven", "fp-gradle"] {
        let item = value["data"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["tool"] == tool)
            .unwrap();
        assert_eq!(item["layer"], "project", "{value}");
        assert!(
            item["origin"].as_str().unwrap().contains("wrapper"),
            "{value}"
        );
    }
    assert_eq!(
        PathBuf::from(exec_env(&h, &project, &[], "MAVEN_HOME")),
        h.install_dir("maven", "default", "3.8.8")
    );
    assert_eq!(
        PathBuf::from(exec_env(&h, &project, &[], "GRADLE_HOME")),
        h.install_dir("gradle", "default", "7.6.4")
    );
}

#[test]
fn an_unmet_java_requirement_is_a_warning() {
    let mut h = Home::new();
    with_java(&mut h);
    with_any(&mut h, "spring-boot-cli", &[("3.3.5", &[])]);
    with_any(&mut h, "maven", &[("3.9.9", &[])]);
    h.ok(&[
        "install",
        "fp-java@zulu:11",
        "fp-java@temurin:21",
        "fp-spring-boot-cli@3.3.5",
        "fp-maven@3.9.9",
    ]);
    // The builtin plugins read the same pin files, so only requirement warnings count here.
    let codes = |value: &Value| -> Vec<String> {
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["code"].as_str().unwrap().to_owned())
            .filter(|code| code == "W_REQUIRES_UNMET")
            .collect()
    };

    // Spring Boot CLI 3 needs Java 17, and the project pins Java 11. Maven is fine with 11.
    let project = h.project(&[(
        ".sdkmanrc",
        "java=11.0.25-zulu\nspringboot=3.3.5\nmaven=3.9.9\n",
    )]);
    let (code, value) = h.json(&project, &["current"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(codes(&value), ["W_REQUIRES_UNMET"], "{value}");
    let message = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "W_REQUIRES_UNMET")
        .unwrap()["message"]
        .as_str()
        .unwrap();
    assert!(
        message.contains("fp-spring-boot-cli") && message.contains(">=17"),
        "{message}"
    );

    // `jtm exec` with a newer Java meets it, and still warns for an older one.
    let mut base = vec!["exec", "fp-java@temurin:21", "--"];
    let print = if cfg!(windows) {
        vec!["cmd", "/c", "echo"]
    } else {
        vec!["sh", "-c", "true"]
    };
    base.extend(&print);
    let (code, value) = h.json(&project, &base);
    assert_eq!(code, 0, "{value}");
    assert!(codes(&value).is_empty(), "{value}");
    let mut old = vec!["exec", "fp-java@zulu:11", "--"];
    old.extend(&print);
    let (_, value) = h.json(&project, &old);
    assert_eq!(codes(&value), ["W_REQUIRES_UNMET"], "{value}");

    // Without a jtm-managed Java, jtm cannot tell, so it says nothing.
    let project = h.project(&[(".sdkmanrc", "springboot=3.3.5\n")]);
    let (_, value) = h.json(&project, &["current"]);
    assert!(codes(&value).is_empty(), "{value}");
}

// --- real tools ---

/// The JDK and Maven installed on this machine: `JAVA_HOME`, and `MAVEN_HOME`, `M2_HOME` or
/// the `mvn` on `PATH`.
fn real_tools() -> Option<(PathBuf, PathBuf)> {
    let java_home = PathBuf::from(std::env::var_os("JAVA_HOME")?);
    let java = if cfg!(windows) { "java.exe" } else { "java" };
    if !java_home.join("bin").join(java).is_file() {
        return None;
    }
    let from_env = ["MAVEN_HOME", "M2_HOME"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|home| home.join("boot").is_dir());
    let maven_home = match from_env {
        Some(home) => home,
        None => {
            let os = jtm_core::Platform::detect().ok()?.os();
            let path = std::env::var("PATH").ok();
            let mvn = jtm_core::here::find_on_path("mvn", path.as_deref(), os)?;
            fs::canonicalize(mvn)
                .ok()?
                .parent()?
                .parent()?
                .to_path_buf()
        }
    };
    maven_home
        .join("boot")
        .is_dir()
        .then_some((fs::canonicalize(java_home).ok()?, maven_home))
}

/// A tar.gz of `source` under `top/`. Links to files are stored as copies, and links to
/// directories are left out, so a system JDK whose links point elsewhere packs cleanly. A
/// JDK's `jmods` and `src.zip` are left out too; nothing needs them to run.
fn pack(source: &Path, top: &str) -> Archive {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    builder.follow_symlinks(false);
    let mut pending = vec![(source.to_path_buf(), PathBuf::from(top))];
    while let Some((dir, name)) = pending.pop() {
        builder.append_dir(&name, &dir).unwrap();
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let inside = name.join(entry.file_name());
            if matches!(entry.file_name().to_str(), Some("jmods" | "src.zip")) {
                continue;
            }
            match fs::metadata(&path) {
                Ok(meta) if meta.is_dir() && !entry.file_type().unwrap().is_symlink() => {
                    pending.push((path, inside));
                }
                Ok(meta) if meta.is_file() => {
                    let mut file = fs::File::open(&path).unwrap();
                    builder.append_file(&inside, &mut file).unwrap();
                }
                _ => {}
            }
        }
    }
    Archive {
        kind: "tar.gz",
        bytes: builder.into_inner().unwrap().finish().unwrap(),
    }
}

/// SPEC.md section 18, T5.3: `mvn -v` runs on the Java a project pins. Uses the JDK and Maven
/// already on this machine, packed into fixture archives; skipped where there are none,
/// unless `JTM_REQUIRE_REAL_TOOLS` is set to a non-empty value, as one CI job sets it.
#[test]
fn mvn_runs_with_the_pinned_java() {
    let Some((java_home, maven_home)) = real_tools() else {
        assert!(
            std::env::var("JTM_REQUIRE_REAL_TOOLS").is_ok_and(|v| v.is_empty())
                || std::env::var_os("JTM_REQUIRE_REAL_TOOLS").is_none(),
            "JTM_REQUIRE_REAL_TOOLS is set, but no JAVA_HOME and `mvn` were found"
        );
        return;
    };
    let mut h = Home::new();
    // A macOS JDK is packed as the app bundle around its home, as vendors ship it.
    let bundle = java_home
        .ends_with("Contents/Home")
        .then(|| java_home.parent().and_then(Path::parent))
        .flatten();
    let jdk = pack(bundle.unwrap_or(&java_home), "jdk-real");
    h.add(
        "java",
        false,
        &[Version {
            variant: "temurin",
            version: "21.0.0+1",
            tags: &["lts"],
            archive: jdk,
        }],
    );
    let maven = pack(&maven_home, "apache-maven-real");
    h.add(
        "maven",
        true,
        &[Version {
            variant: "default",
            version: "3.9.0",
            tags: &[],
            archive: maven,
        }],
    );
    let project = h.project(&[(
        ".jtm.toml",
        &format!(
            "[tools]\nfp-java = \"temurin:21.0.0+1\"\nfp-maven = \"3.9.0\"\n\n[lock]\n\
             platforms = [\"{}\"]\n",
            h.platform
        ),
    )]);
    let (code, value) = h.json(&project, &["sync"]);
    assert_eq!(code, 0, "{value}");

    let (code, value) = h.json(&project, &["exec", "--", "mvn", "-v"]);
    assert_eq!(code, 0, "{value}");
    let stdout = value["data"]["stdout"].as_str().unwrap();
    assert_eq!(value["data"]["exit_code"], 0, "{value}");
    assert!(stdout.contains("Apache Maven"), "{stdout}");
    let java_line = stdout
        .lines()
        .find(|l| l.contains("Java home") || l.contains("runtime:"))
        .unwrap_or_else(|| panic!("no Java home in {stdout}"));
    let expected = Path::new("tools")
        .join("fp-java")
        .join("temurin-21.0.0+1")
        .display()
        .to_string();
    assert!(
        java_line.contains(&expected),
        "{java_line} should name {expected}"
    );
    let maven_line = stdout.lines().find(|l| l.contains("Maven home")).unwrap();
    assert!(maven_line.contains("default-3.9.0"), "{maven_line}");
}
