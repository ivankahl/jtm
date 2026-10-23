//! `jtm mirror export`, end to end: a signed fixture is exported to a directory, and a fresh
//! home with `[mirrors]` aimed at that directory installs from it with `--offline`. Nothing
//! touches the real network.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::Path;

use common::{Fixture, VERSIONS, archive, exists};
use serde_json::Value;

fn export_args<'a>(dir: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    // Always `--plugin demo`: the binary also knows the first-party plugins, whose indices a
    // test must not go looking for.
    let mut args = vec!["mirror", "export", dir, "--plugin", "demo"];
    args.extend_from_slice(extra);
    args
}

fn dir_str(dir: &Path) -> String {
    dir.display().to_string()
}

fn files<'a>(value: &'a Value, kind: &str) -> Vec<&'a Value> {
    value["data"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == kind)
        .collect()
}

fn requests_to_the_server(f: &Fixture) -> usize {
    f.rt.block_on(f.server.received_requests())
        .unwrap_or_default()
        .len()
}

/// A platform other than the one the fixture publishes an index for.
fn other_platform(f: &Fixture) -> &'static str {
    ["macos-aarch64", "windows-x64"]
        .into_iter()
        .find(|p| *p != f.platform)
        .unwrap()
}

#[test]
fn an_exported_directory_installs_offline_in_a_fresh_home() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let dir = dir_str(export.path());

    let (code, value) = source.json(&export_args(&dir, &["--artifacts"]));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "mirror export");
    assert_eq!(value["changed"], true);
    assert_eq!(files(&value, "artifact").len(), VERSIONS.len());
    assert_eq!(files(&value, "index").len(), 1);
    assert_eq!(files(&value, "signature").len(), 1);
    assert!(
        files(&value, "artifact")
            .iter()
            .all(|f| f["status"] == "written")
    );

    // The layout is `<host>/<path of the URL>`, and the index and its signature are the bytes
    // the publisher signed.
    let (index, _) = source.signed_index();
    let index_file = export
        .path()
        .join("index.example.test")
        .join(format!("demo-{}.json", source.platform));
    assert_eq!(std::fs::read(&index_file).unwrap(), index);
    // The signature is the one the publisher served, byte for byte: the copy jtm verified and
    // cached on the source machine.
    let served = source
        .home
        .path()
        .join("cache/index/demo")
        .join(format!("{}.json.minisig", source.platform));
    assert_eq!(
        std::fs::read(format!("{}.minisig", index_file.display())).unwrap(),
        std::fs::read(served).unwrap()
    );
    for version in VERSIONS {
        let artifact = export
            .path()
            .join("dl.example.test")
            .join(format!("demo-{version}.tar.gz"));
        assert_eq!(std::fs::read(artifact).unwrap(), archive(version));
    }
    // The output says how to point `[mirrors]` at the directory.
    let mirrors = value["data"]["mirrors"].as_object().unwrap();
    assert_eq!(mirrors.len(), 2, "{mirrors:?}");
    assert!(
        mirrors["https://dl.example.test/"]
            .as_str()
            .unwrap()
            .ends_with("dl.example.test/")
    );

    // Exporting the same thing again changes nothing.
    let (code, again) = source.json(&export_args(&dir, &["--artifacts"]));
    assert_eq!(code, 0, "{again}");
    assert_eq!(again["changed"], false);
    assert!(
        again["data"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["status"] == "unchanged")
    );

    // A fresh home with no network installs from the export.
    let fresh = source.sibling();
    fresh.trust();
    fresh.use_export_mirror(export.path());
    for version in VERSIONS {
        let spec = format!("demo@{version}");
        let (code, value) = fresh.json(&["--offline", "install", &spec]);
        assert_eq!(code, 0, "{value}");
        assert_eq!(value["data"]["installed"][0]["status"], "installed");
        assert_eq!(
            std::fs::read(fresh.install_dir(version).join("VERSION")).unwrap(),
            version.as_bytes()
        );
    }
    assert_eq!(
        requests_to_the_server(&fresh),
        0,
        "the network is never used"
    );
}

#[test]
fn the_exported_index_loads_through_a_plugin_index_url() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &[]));
    assert_eq!(code, 0, "{value}");

    let fresh = source.sibling();
    fresh.trust();
    let root = export.path().display().to_string().replace('\\', "/");
    fresh.save_config(fresh.demo_table(&format!(
        "index_url = \"{root}/index.example.test/demo-{{os}}-{{arch}}.json\"\n"
    )));
    let (code, value) = fresh.json(&["--offline", "available", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        value["data"]["versions"].as_array().unwrap().len(),
        VERSIONS.len()
    );
}

#[test]
fn an_export_without_artifacts_has_only_the_indices() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &[]));
    assert_eq!(code, 0, "{value}");
    assert!(files(&value, "artifact").is_empty());
    assert!(!exists(&export.path().join("dl.example.test")));
    assert_eq!(source.downloads(), 0);

    // The index is there, but no archive: an offline install says so instead of guessing.
    let fresh = source.sibling();
    fresh.trust();
    fresh.use_export_mirror(export.path());
    let (code, value) = fresh.json(&["--offline", "install", "demo@1.0.0"]);
    assert_ne!(code, 0, "{value}");
    assert!(!exists(&fresh.install_dir("1.0.0")));
}

#[test]
fn a_tampered_exported_artifact_is_refused_on_install() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &["--artifacts"]));
    assert_eq!(code, 0, "{value}");

    let victim = export.path().join("dl.example.test/demo-1.0.0.tar.gz");
    let mut bytes = std::fs::read(&victim).unwrap();
    bytes[20] ^= 0xff;
    std::fs::write(&victim, bytes).unwrap();

    let fresh = source.sibling();
    fresh.trust();
    fresh.use_export_mirror(export.path());
    let (code, value) = fresh.json(&["--offline", "install", "demo@1.0.0"]);
    assert_eq!(code, 5, "{value}");
    assert_eq!(value["error"]["code"], "E_HASH_MISMATCH");
    assert!(!exists(&fresh.install_dir("1.0.0")));

    // Exporting again repairs the tampered copy rather than trusting it.
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &["--artifacts"]));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], true);
    let (code, value) = fresh.json(&["--offline", "install", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
}

#[test]
fn a_served_archive_that_does_not_match_the_index_is_never_exported() {
    let source = Fixture::new(true);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &["--artifacts"]));
    assert_eq!(code, 5, "{value}");
    assert_eq!(value["error"]["code"], "E_HASH_MISMATCH");
    assert!(!exists(
        &export.path().join("dl.example.test/demo-1.0.0.tar.gz")
    ));
    // The index is written last, so a directory that failed halfway never advertises
    // archives it does not hold.
    assert!(!exists(&export.path().join("index.example.test")));
}

#[test]
fn a_dry_run_writes_nothing_and_downloads_nothing() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let target = export.path().join("mirror");
    let (code, value) = source.json(&export_args(
        &dir_str(&target),
        &["--artifacts", "--dry-run"],
    ));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert_eq!(value["data"]["dry_run"], true);
    assert!(
        value["data"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["status"] == "would_write")
    );
    assert_eq!(files(&value, "artifact").len(), VERSIONS.len());
    assert!(!exists(&target));
    assert_eq!(source.downloads(), 0);
}

#[test]
fn an_explicit_platform_without_an_index_fails_and_the_default_skips_it() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let dir = dir_str(export.path());

    let (code, value) = source.json(&export_args(&dir, &["--platform", other_platform(&source)]));
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "E_PLATFORM_UNSUPPORTED");
    assert!(!exists(&export.path().join("index.example.test")));

    // With no `--platform`, every platform is tried and those with no index are skipped,
    // each with a warning.
    let (code, value) = source.json(&export_args(&dir, &[]));
    assert_eq!(code, 0, "{value}");
    assert_eq!(files(&value, "index").len(), 1);
    let skipped = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "W_MIRROR_PLATFORM_SKIPPED")
        .count();
    assert_eq!(skipped, 6);

    let (code, value) = source.json(&export_args(&dir, &["--platform", "no-such-platform"]));
    assert_eq!(code, 2, "{value}");
}

#[test]
fn an_unknown_plugin_is_refused() {
    let source = Fixture::new(false);
    source.trust();
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &["--plugin", "nope"]));
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "E_TOOL_UNKNOWN");
}

#[test]
fn an_index_signed_by_an_untrusted_key_is_not_exported() {
    let source = Fixture::new(false);
    // The signing key is not trusted, so the index cannot be verified.
    let export = tempfile::tempdir().unwrap();
    let (code, value) = source.json(&export_args(&dir_str(export.path()), &["--artifacts"]));
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "E_KEY_UNTRUSTED");
    assert!(std::fs::read_dir(export.path()).unwrap().next().is_none());
}
