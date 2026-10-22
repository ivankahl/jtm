use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::testing::{Mock, fixture};

fn shipped(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../jtm-cli/plugins")
        .join(name)
}

const MINIMAL_MANIFEST: &str = r#"
schema = 1
name = "demo"
display_name = "Demo"

[versions]
scheme = "semver-loose"

[index]
url = "https://index.example.test/demo-{os}-{arch}.json"
signing_keys = ["RWRysDZolh28UjrMjL/6mCMDPnqfDtDj5Al+TxN8z6RkXGawmRo1ob7K"]
format = 1

[layout]
bin_dirs = ["bin"]
"#;

const GRADLE_SOURCES: &str = r#"
schema = 1

[[source]]
id = "first"
adapter = "gradle"
role = "primary"
hash_from = "versions-api"

[[source]]
id = "second"
adapter = "gradle"
role = "confirm"
hash_from = "versions-api"
"#;

fn plugin_dir(manifest: &str, sources: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("plugin.toml"), manifest).unwrap();
    if let Some(sources) = sources {
        fs::write(dir.path().join("sources.toml"), sources).unwrap();
    }
    dir
}

#[test]
fn a_platform_independent_plugin_binds_to_the_any_index() {
    let plugin = Plugin::load(&shipped("maven")).unwrap();
    assert_eq!(plugin.binding.plugin, "maven");
    assert!(plugin.binding.platform_independent);
    assert!(plugin.binding.variants.is_empty());
}

#[test]
fn a_plugin_with_variants_and_platforms_binds_to_them() {
    let plugin = Plugin::load(&shipped("java")).unwrap();
    assert_eq!(plugin.binding.plugin, "java");
    assert!(!plugin.binding.platform_independent);
    assert!(plugin.binding.variants.contains(&"temurin".to_owned()));
    assert!(plugin.binding.variants.len() > 1);
}

#[test]
fn every_shipped_plugin_loads() {
    for name in ["java", "maven", "gradle", "kotlin", "spring-boot-cli"] {
        let plugin = Plugin::load(&shipped(name)).unwrap();
        assert_eq!(plugin.binding.plugin, name);
    }
}

#[test]
fn the_name_comes_from_the_manifest_not_the_directory() {
    let dir = plugin_dir(MINIMAL_MANIFEST, Some(GRADLE_SOURCES));
    let plugin = Plugin::load(dir.path()).unwrap();
    assert_eq!(plugin.binding.plugin, "demo");
    assert!(!plugin.binding.platform_independent);
}

#[test]
fn a_directory_without_a_manifest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sources.toml"), GRADLE_SOURCES).unwrap();
    let err = Plugin::load(dir.path()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("plugin.toml"), "{err}");
}

#[test]
fn a_directory_without_sources_is_refused() {
    let dir = plugin_dir(MINIMAL_MANIFEST, None);
    let err = Plugin::load(dir.path()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("sources.toml"), "{err}");
}

#[test]
fn an_invalid_manifest_is_refused_with_its_path() {
    let dir = plugin_dir(
        "schema = 1\nname = \"Not A Valid Name\"\n",
        Some(GRADLE_SOURCES),
    );
    let err = Plugin::load(dir.path()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("plugin.toml"), "{err}");
}

#[test]
fn a_missing_key_file_is_refused_rather_than_ignored() {
    let sources = format!(
        "{GRADLE_SOURCES}\n[[source]]\nid = \"third\"\nadapter = \"gradle\"\nrole = \"confirm\"\n\
         hash_from = \"versions-api\"\nsigning_keys = [\"keys/missing.asc\"]\n"
    );
    let dir = plugin_dir(MINIMAL_MANIFEST, Some(&sources));
    let err = Plugin::load(dir.path()).unwrap_err();
    assert!(err.to_string().contains("missing.asc"), "{err}");
}

#[test]
fn discovery_gathers_the_candidates_of_every_source() {
    let dir = plugin_dir(MINIMAL_MANIFEST, Some(GRADLE_SOURCES));
    let plugin = Plugin::load(dir.path()).unwrap();
    let mock = Mock::start();
    mock.serve(
        "/services.gradle.org/versions/all",
        fixture("gradle/versions-all.json"),
    );
    let discovery = plugin.discover(&mock.context()).unwrap();
    let from = |id: &str| {
        discovery
            .candidates
            .iter()
            .filter(|c| c.source == id)
            .count()
    };
    assert!(from("first") > 0);
    assert_eq!(from("first"), from("second"));
}

#[test]
fn a_failing_source_fails_discovery() {
    let dir = plugin_dir(MINIMAL_MANIFEST, Some(GRADLE_SOURCES));
    let plugin = Plugin::load(dir.path()).unwrap();
    let mock = Mock::start();
    mock.status("/services.gradle.org/versions/all", 500);
    assert!(plugin.discover(&mock.context()).is_err());
}
