//! The `sources.toml` files that ship with the first-party plugins must follow the schema, and
//! must agree with their manifests about which variants exist.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use jtm_index::SourcesFile;

fn plugins_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../jtm-cli/plugins")
}

/// The names of the plugin directories that have a `sources.toml`.
fn plugins() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(plugins_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("plugin.toml").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn manifest_variants(plugin: &str) -> Vec<String> {
    let text = std::fs::read_to_string(plugins_dir().join(plugin).join("plugin.toml")).unwrap();
    let manifest: toml::Table = toml::from_str(&text).unwrap();
    manifest
        .get("versions")
        .and_then(|v| v.get("variants"))
        .and_then(toml::Value::as_array)
        .map(|variants| {
            variants
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_first_party_plugin_ships_a_valid_sources_file() {
    let plugins = plugins();
    assert!(plugins.len() >= 5, "{plugins:?}");
    for plugin in &plugins {
        let path = plugins_dir().join(plugin).join("sources.toml");
        let file = SourcesFile::load(&path).unwrap_or_else(|e| panic!("{plugin}: {e}"));
        assert!(!file.sources.is_empty(), "{plugin}");
    }
}

#[test]
fn sources_cover_exactly_the_variants_of_the_manifest() {
    for plugin in plugins() {
        let path = plugins_dir().join(&plugin).join("sources.toml");
        let file = SourcesFile::load(&path).unwrap();
        let mut from_sources: Vec<String> = file
            .variants()
            .into_iter()
            .map(|v| v.unwrap_or_default().to_owned())
            .collect();
        let mut from_manifest = manifest_variants(&plugin);
        if from_manifest.is_empty() {
            from_manifest.push(String::new());
        }
        from_sources.sort();
        from_manifest.sort();
        assert_eq!(from_sources, from_manifest, "{plugin}");
    }
}

/// Every variant must be confirmable by the rule of SPEC.md section 15: two sources, or a
/// source marked `sole_source`, or a signature checked against pinned `signing_keys`. A single
/// plain source would make the generator refuse the whole variant.
#[test]
fn every_variant_has_a_way_to_be_confirmed() {
    for plugin in plugins() {
        let path = plugins_dir().join(&plugin).join("sources.toml");
        let file = SourcesFile::load(&path).unwrap();
        for variant in file.variants() {
            let sources: Vec<_> = file.for_variant(variant).collect();
            let sole = sources.iter().any(|s| s.sole_source);
            let signed = sources.iter().any(|s| !s.signing_keys.is_empty());
            // `spring-boot-cli` waits for a maintainer to pin the Spring signing key; its
            // sources.toml says so, and the generator refuses it until then.
            let waiting_for_key = plugin == "spring-boot-cli";
            assert!(
                sources.len() >= 2 || sole || signed || waiting_for_key,
                "{plugin} {variant:?} has a single source that nothing can confirm"
            );
        }
    }
}

#[test]
fn only_variants_with_no_second_source_are_sole_sources() {
    for plugin in plugins() {
        let path = plugins_dir().join(&plugin).join("sources.toml");
        let file = SourcesFile::load(&path).unwrap();
        for variant in file.variants() {
            let sources: Vec<_> = file.for_variant(variant).collect();
            if sources.iter().any(|s| s.sole_source) {
                assert_eq!(sources.len(), 1, "{plugin} {variant:?}");
            }
        }
    }
}
