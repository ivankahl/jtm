use std::fs;
use std::path::Path;

use jtm_plugin::Manifest;

use super::*;
use crate::indices::ManifestOrigin;

const JAVA: &str = include_str!("../../../jtm-plugin/tests/fixtures/manifests/valid/java.toml");
const WRAPPED: &str =
    include_str!("../../../jtm-plugin/tests/fixtures/manifests/valid/wrapped.toml");

fn plugin(text: &str) -> Plugin {
    Plugin {
        manifest: Manifest::parse(text).unwrap_or_else(|e| panic!("{e}")),
        sha256: String::new(),
        origin: ManifestOrigin::External,
        location: "test".to_owned(),
    }
}

fn plugins() -> Vec<Plugin> {
    vec![plugin(JAVA), plugin(WRAPPED)]
}

fn put(dir: &Path, file: &str, text: &str) {
    let path = dir.join(file);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn found(pins: &ProjectPins) -> Vec<String> {
    pins.pins
        .values()
        .map(|p| {
            format!(
                "{}={} from {}",
                p.tool,
                p.selector,
                p.file.file_name().unwrap().to_string_lossy()
            )
        })
        .collect()
}

#[test]
fn native_file_wins_over_interop_files_in_the_same_directory() {
    let root = tempfile::tempdir().unwrap();
    put(
        root.path(),
        ".jtm.toml",
        "[tools]\njava = \"corretto:17\"\n",
    );
    put(root.path(), ".sdkmanrc", "java=21.0.5-tem\nwrapped=3.9.9\n");
    put(root.path(), ".java-version", "corretto-17\n");
    let pins = discover(root.path(), &plugins()).unwrap();
    assert_eq!(
        found(&pins),
        [
            "java=corretto:17 from .jtm.toml",
            "wrapped=3.9.9 from .sdkmanrc"
        ]
    );
    // .sdkmanrc disagrees with the winner; .java-version agrees.
    assert_eq!(pins.conflicts.len(), 1);
    let conflict = &pins.conflicts[0];
    assert_eq!(conflict.tool, "java");
    assert!(conflict.winner.file.ends_with(".jtm.toml"));
    assert_eq!(conflict.others.len(), 1);
    assert!(conflict.others[0].file.ends_with(".sdkmanrc"));
    assert_eq!(conflict.others[0].value, "temurin:21.0.5");
    assert_eq!(pins.files.len(), 3);
}

#[test]
fn interop_files_are_read_in_parser_order() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), ".java-version", "corretto-17\n");
    put(root.path(), ".tool-versions", "java temurin-21\n");
    put(root.path(), ".sdkmanrc", "java=11-amzn\n");
    let pins = discover(root.path(), &plugins()).unwrap();
    assert_eq!(found(&pins), ["java=corretto:11 from .sdkmanrc"]);
    let losers: Vec<&str> = pins.conflicts[0]
        .others
        .iter()
        .map(|o| o.value.as_str())
        .collect();
    assert_eq!(losers, ["temurin:21", "corretto:17"]);
}

#[test]
fn the_nearest_directory_pinning_a_tool_wins_per_tool() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("service/src");
    fs::create_dir_all(&child).unwrap();
    put(
        root.path(),
        ".jtm.toml",
        "[tools]\njava = \"21\"\nwrapped = \"3.8\"\n",
    );
    put(&root.path().join("service"), ".java-version", "17\n");
    let pins = discover(&child, &plugins()).unwrap();
    assert_eq!(
        found(&pins),
        ["java=17 from .java-version", "wrapped=3.8 from .jtm.toml"]
    );
    assert!(pins.conflicts.is_empty());
}

#[test]
fn equal_values_with_and_without_the_default_variant_do_not_conflict() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), ".jtm.toml", "[tools]\njava = \"temurin:21\"\n");
    put(root.path(), ".java-version", "21\n");
    let pins = discover(root.path(), &plugins()).unwrap();
    assert!(pins.conflicts.is_empty(), "{:?}", pins.conflicts);
}

#[test]
fn wrapper_versions_apply_only_when_no_pin_file_sets_the_tool() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = "distributionUrl=https\\://dl.example.test/wrapped-3.9.9-bin.zip\n\
                   distributionSha256Sum=ab12\n";
    put(
        root.path(),
        "app/wrapped/wrapper/wrapped-wrapper.properties",
        wrapper,
    );
    let app = root.path().join("app");
    let pins = discover(&app, &plugins()).unwrap();
    assert_eq!(
        found(&pins),
        ["wrapped=3.9.9 from wrapped-wrapper.properties"]
    );
    let pin = &pins.pins["wrapped"];
    assert_eq!(pin.kind, PinKind::Wrapper);
    let w = pin.wrapper.as_ref().unwrap();
    assert_eq!(w.sha256.as_deref(), Some("ab12"));
    assert_eq!(w.file_name, "wrapped-3.9.9-bin.zip");

    // A pin file in a parent directory still beats the wrapper.
    put(root.path(), ".sdkmanrc", "wrapped=3.8.1\n");
    let pins = discover(&app, &plugins()).unwrap();
    assert_eq!(found(&pins), ["wrapped=3.8.1 from .sdkmanrc"]);
}

#[test]
fn an_unknown_tool_in_jtm_toml_names_the_plugin_to_add() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), ".jtm.toml", "[tools]\nflyway = \"10\"\n");
    let err = discover(root.path(), &plugins()).unwrap_err();
    assert_eq!(err.code(), "E_TOOL_UNKNOWN");
    assert!(err.to_string().contains("jtm plugin add flyway"), "{err}");
    assert_eq!(err.details()["tool"], "flyway");
}

#[test]
fn an_unmappable_interop_value_suggests_the_jtm_toml_line() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), ".sdkmanrc", "java=21.0.5-zzz\n");
    let err = discover(root.path(), &plugins()).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    let message = err.to_string();
    assert!(message.contains(".sdkmanrc"), "{message}");
    assert!(
        message.contains("java = \"<variant>:<version>\""),
        "{message}"
    );
}

#[test]
fn a_directory_without_pins_has_none() {
    let root = tempfile::tempdir().unwrap();
    let pins = discover(root.path(), &plugins()).unwrap();
    assert!(pins.pins.is_empty());
    assert!(pins.files.is_empty());
}

#[test]
fn ancestor_pin_files_are_not_read_for_tools_a_nearer_directory_decides() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("src").join("app");
    put(&app, ".jtm.toml", "[tools]\njava = \"temurin:21\"\n");
    // Unmappable, but java is already decided below it.
    put(root.path(), ".sdkmanrc", "java=21.0.5-zzz\n");
    let pins = discover(&app, &plugins()).unwrap();
    assert_eq!(found(&pins), ["java=temurin:21 from .jtm.toml"]);
}

#[test]
fn an_unknown_tool_in_an_ancestor_jtm_toml_is_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    put(&app, ".jtm.toml", "[tools]\njava = \"temurin:21\"\n");
    put(root.path(), ".jtm.toml", "[tools]\nflyway = \"10\"\n");
    let pins = discover(&app, &plugins()).unwrap();
    assert_eq!(found(&pins), ["java=temurin:21 from .jtm.toml"]);
    assert_eq!(pins.ignored.len(), 1);
    assert!(pins.ignored[0].contains("flyway"), "{:?}", pins.ignored);
}

#[test]
fn discovery_stops_at_the_top_directory() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    put(&app, ".java-version", "corretto-17\n");
    put(root.path(), ".sdkmanrc", "wrapped=3.9.9\n");
    let pins = discover_within(&app, Some(&app), &plugins()).unwrap();
    assert_eq!(found(&pins), ["java=corretto:17 from .java-version"]);
    let pins = discover(&app, &plugins()).unwrap();
    assert_eq!(pins.pins.len(), 2);
}
