use std::path::Path;

use jtm_core::dirs::Dirs;
use jtm_core::indices::ManifestOrigin;
use jtm_core::platform::Os;
use jtm_core::plugins::Registry;

use super::*;

#[test]
fn every_plugin_directory_is_embedded() {
    let plugins = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins");
    let mut dirs: Vec<String> = std::fs::read_dir(plugins)
        .unwrap_or_else(|e| panic!("{e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    dirs.sort();
    let names: Vec<&str> = MANIFESTS.iter().map(|m| m.name).collect();
    assert_eq!(names, dirs);
    assert_eq!(names.len(), 5);
}

#[test]
fn every_embedded_manifest_is_valid_builtin_and_named_after_its_directory() {
    let home = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let dirs = Dirs::resolve(
        Os::host().unwrap_or(Os::Linux),
        Some(home.path()),
        None,
        &|_| None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let registry = Registry {
        dirs: &dirs,
        builtin: MANIFESTS,
    };
    for embedded in MANIFESTS {
        let plugin = registry
            .find(embedded.name)
            .unwrap_or_else(|e| panic!("{}: {e}", embedded.name));
        assert_eq!(plugin.origin, ManifestOrigin::Builtin);
        assert_eq!(plugin.location, "builtin");
    }
}

#[test]
fn every_first_party_plugin_shares_the_root_keys_and_keys_file() {
    // SPEC.md section 15: each lists jtm's root keys with threshold 2 and the shared keys.json.
    let manifests: Vec<jtm_plugin::Manifest> = MANIFESTS
        .iter()
        .map(|m| jtm_plugin::Manifest::parse(m.text).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    let first = &manifests[0].index;
    assert_eq!(first.threshold(), 2);
    assert_eq!(first.signing_keys.len(), 3);
    assert!(first.keys_url.is_some());
    for m in &manifests {
        assert_eq!(m.index.signing_keys, first.signing_keys, "{}", m.name);
        assert_eq!(m.index.threshold, first.threshold, "{}", m.name);
        assert_eq!(m.index.keys_url, first.keys_url, "{}", m.name);
        assert!(
            m.index
                .url
                .starts_with("https://github.com/jtm-dev/index/releases/download/")
        );
    }
}
